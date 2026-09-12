#include "cloak/session.h"

#include <stdlib.h>
#include <string.h>

#include "cloak/common.h"

/* Every cloak_stream_t this session creates is actually the first member
 * of this wrapper -- see session.h's "Stream memory ownership" note for
 * why an extra bit of per-stream bookkeeping is needed. Because `stream`
 * is the first member, a plain cloak_stream_t* (what callers receive) is
 * always safely convertible back to cloak_session_stream_entry_t* here --
 * a guarantee C itself makes about a pointer to a struct and a pointer to
 * its first member. */
typedef struct {
    cloak_stream_t stream;
    int retired; /* 1 once tombstoned (actively or passively) -- see session_retire_stream */
} cloak_session_stream_entry_t;

static void session_check_timeout(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    if (sesh->active_stream_count == 0 && !sesh->closed) {
        cloak_session_close(sesh);
    }
}

/* At most one pending inactivity timer at a time -- see this plan's
 * Global Constraints for why an uncancelled predecessor would be a
 * use-after-free once cloak_session_destroy has freed sesh. */
static void session_reschedule_inactivity_timer(cloak_session_t *sesh) {
    cloak_reactor_cancel_timer(sesh->reactor, sesh->inactivity_timer_id);
    sesh->inactivity_timer_id = cloak_reactor_add_timer(sesh->reactor, sesh->inactivity_timeout_ms,
                                                         session_check_timeout, sesh);
}

static int session_stream_sink_adapter(void *userdata, const uint8_t *bytes, size_t len) {
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    return cloak_switchboard_send(&sesh->sb, bytes, len);
}

/* Stops stream from receiving any more routed frames (tombstones its
 * strmtab entry) and stops it counting toward active_stream_count. Does
 * NOT free stream's memory -- see cloak_session_release_stream and this
 * task's own "Stream memory ownership" note (a consumer holding this
 * stream's pointer, e.g. from on_new_stream, may not have read its
 * buffered data yet; freeing here would be a use-after-free the moment
 * they call cloak_stream_read -- this was caught by this plan's own
 * integration test during design verification). Safe to call on an
 * already-retired stream (no-op). */
static void session_retire_stream(cloak_session_t *sesh, cloak_stream_t *stream) {
    cloak_session_stream_entry_t *entry = (cloak_session_stream_entry_t *)stream;
    if (entry->retired) {
        return;
    }
    entry->retired = 1;
    cloak_strmtab_tombstone(&sesh->streams, stream->id);
    sesh->active_stream_count--;
    if (sesh->active_stream_count == 0 && !sesh->closed) {
        session_reschedule_inactivity_timer(sesh);
    }
}

/* Destroys and frees a single stream entry: used both by
 * session_free_all_active_streams (below) and directly (see its own
 * comment for why timing differs between the two call sites). */
static void session_destroy_stream_iter_cb(uint32_t key, void *value, void *userdata) {
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    cloak_stream_t *stream = (cloak_stream_t *)value;
    cloak_session_stream_entry_t *entry = (cloak_session_stream_entry_t *)stream;
    cloak_stream_destroy(stream);
    free(entry);
    cloak_strmtab_tombstone(&sesh->streams, key); /* never grows/reallocates -- safe mid-iteration */
    sesh->active_stream_count--;
}

/* Frees every still-ACTIVE stream's memory. Called from two places with
 * two different timing guarantees -- see each call site's own comment:
 * session_deferred_teardown_cb (always safe -- runs outside any nested
 * call stack) and cloak_session_destroy (safe by that function's own
 * documented calling contract, not by anything here). Never call this
 * synchronously from session_close_internal or from anywhere reachable
 * from a cloak_conn_t/cloak_stream_t callback -- see this plan's Global
 * Constraints for why (this is exactly the fifth and sixth instances of
 * this project's recurring "freed object still has a live pointer above
 * it on the call stack" bug class, both caused by an earlier draft of
 * this exact function running synchronously from session_close_internal). */
static void session_free_all_active_streams(cloak_session_t *sesh) {
    cloak_strmtab_for_each_active(&sesh->streams, session_destroy_stream_iter_cb, sesh);
}

/* Marks the session closed and cancels the inactivity timer. Deliberately
 * does NOT touch any stream's or connection's memory -- see
 * session_schedule_deferred_teardown's own comment for why freeing
 * either must never happen synchronously here. Safe to call from
 * anywhere, including reentrantly from deep inside a cloak_conn_t's or
 * cloak_stream_t's own dispatch/write call chain, for exactly that
 * reason. Returns 1 if this call actually did the work (first call), 0
 * if sesh was already closed (matches Go's errRepeatSessionClosing being
 * surfaced by the caller as appropriate). */
static int session_close_internal(cloak_session_t *sesh) {
    if (sesh->closed) {
        return 0;
    }
    sesh->closed = 1;
    cloak_reactor_cancel_timer(sesh->reactor, sesh->inactivity_timer_id);
    return 1;
}

static void session_send_closing_session_frame(cloak_session_t *sesh) {
    uint8_t len_byte;
    cloak_random_bytes(&len_byte, 1);
    size_t pad_len = (size_t)len_byte + 1;
    /* Clamp so the fully obfuscated frame (header + payload + padding +
     * AEAD tag, bounded by CLOAK_FRAME_MAX_EXTRA_LEN) never exceeds
     * max_on_wire_size -- without this, cloak_conn_send would reject an
     * oversized closing-session frame as a protocol violation and mark
     * the connection broken, meaning the peer would never receive this
     * notification and would only learn of the close from the connection
     * dying instead. Same clamp cloak_stream_send_closing already
     * applies, for the same reason (stream.c, already merged) -- missing
     * here until caught during this plan's own design verification.
     * cloak_session_init already validates max_on_wire_size >
     * CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN, so this
     * subtraction cannot underflow. */
    size_t max_payload = sesh->max_on_wire_size - CLOAK_FRAME_HEADER_LEN - CLOAK_FRAME_MAX_EXTRA_LEN;
    size_t max_pad = max_payload < 256 ? max_payload : 256;
    if (pad_len > max_pad) {
        pad_len = max_pad;
    }
    uint8_t pad[256];
    cloak_random_bytes(pad, pad_len);

    cloak_frame_t frame;
    frame.stream_id = 0xffffffffu; /* matches Go's session-closing sentinel StreamID */
    frame.seq = 0;
    frame.closing = CLOAK_FRAME_CLOSING_SESSION;
    frame.payload = pad;
    frame.payload_len = pad_len;

    uint8_t buf[CLOAK_FRAME_HEADER_LEN + 256 + CLOAK_FRAME_MAX_EXTRA_LEN];
    long written = cloak_frame_obfuscate(&sesh->obfuscator, &frame, buf, sizeof(buf), 0);
    if (written < 0) {
        return; /* best-effort -- local state is already torn down regardless, matching Go */
    }
    cloak_switchboard_send(&sesh->sb, buf, (size_t)written);
}

/* Fired by the SECOND of two chained 0ms timers -- see
 * session_deferred_teardown_cb's own comment for why the actual sweep is
 * split into its own timer instead of running inline after on_broken. */
static void session_teardown_sweep_cb(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    sesh->teardown_timer_id = CLOAK_TIMER_INVALID; /* this timer has now fired -- nothing left to cancel */
    session_free_all_active_streams(sesh);
    cloak_switchboard_close_all(&sesh->sb);
}

/* Fired by a 0ms reactor timer scheduled by session_passive_close/
 * cloak_session_close -- see session_schedule_deferred_teardown's own
 * comment for why every bit of actual teardown work lives here (across
 * this function and session_teardown_sweep_cb) instead of running
 * synchronously in session_close_internal.
 *
 * Schedules the actual sweep as a SEPARATE, second deferred timer
 * (session_teardown_sweep_cb) BEFORE calling on_broken below -- does not
 * do the sweep inline here. This is required, not stylistic:
 * cloak_session_broken_cb's own doc comment says it is safe to call
 * cloak_session_destroy synchronously from within on_broken, including
 * destroying AND freeing sesh's own storage before on_broken returns. If
 * that happens and this function still had code AFTER the on_broken call
 * that touched `sesh` (which an earlier version of this function did --
 * see this plan's Global Constraints, finding 7, the SEVENTH instance of
 * this module's recurring "freed object still has a live pointer above
 * it on the call stack" bug class, found during this plan's own final
 * whole-branch review, introduced by the very fix that closed finding 6),
 * that code would read/write freed memory the instant on_broken returns.
 *
 * Scheduling the sweep as its own timer FIRST closes this: if on_broken
 * destroys (and possibly frees) sesh, cloak_session_destroy's own
 * cloak_reactor_cancel_timer(sesh->reactor, sesh->teardown_timer_id) call
 * cancels THIS freshly-scheduled sweep timer -- synchronously, from
 * within on_broken, before sesh is ever freed and before this function's
 * own single remaining statement (calling on_broken) even returns. If
 * on_broken does NOT destroy sesh, the sweep timer simply fires normally
 * on the reactor's next tick, exactly as session_deferred_teardown_cb
 * used to do inline. Either way, nothing below the on_broken call in
 * THIS function may ever touch `sesh` again -- there is deliberately
 * nothing there. */
static void session_deferred_teardown_cb(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    sesh->teardown_timer_id = cloak_reactor_add_timer(sesh->reactor, 0, session_teardown_sweep_cb, sesh);
    if (sesh->on_broken) {
        sesh->on_broken(sesh, sesh->on_broken_userdata);
    }
    /* Do not add any code here -- see this function's own comment above
     * for why `sesh` must not be touched again past this point. */
}

/* Schedules the actual teardown -- freeing every stream's memory,
 * closing the connection pool, and firing on_broken -- for the reactor's
 * NEXT dispatch loop iteration, rather than performing any of it here.
 *
 * This is required, not just cautious: session_passive_close and
 * cloak_session_close can both be invoked REENTRANTLY, from deep inside
 * either a specific cloak_conn_t's own dispatch call chain (a
 * closing-session frame arriving mid-read, or a connection breaking
 * mid-write -- conn_reactor_cb -> ... -> session_on_envelope or
 * conn_mark_broken -> ... -> session_on_switchboard_broken -> here) OR a
 * specific cloak_stream_t's own write call chain (cloak_stream_write's
 * sink call cascading into a connection failure -- session's own
 * session_stream_sink_adapter -> cloak_switchboard_send -> cloak_conn_send
 * -> conn_mark_broken -> ... -> here -- while cloak_stream_write is still
 * on the stack above it, about to touch that same stream's fields again
 * once the sink call returns) OR from within cloak_session_close_stream/
 * cloak_session_release_stream's own call to cloak_stream_send_closing
 * (identical hazard, one frame later).
 *
 * If EITHER freeing every stream OR closing every connection ran
 * synchronously from any of those call chains, it would free memory a
 * live stack frame above this point still points into -- a
 * heap-use-after-free. This project has hit this exact class of bug six
 * times across this one module (see this plan's Global Constraints for
 * the full list); the first four were each patched at their own call
 * site, but the fifth and sixth (found during this plan's own design
 * verification, after this file's first draft had already "fixed" the
 * first four) are what led to deferring the ENTIRE teardown -- streams
 * included, not just connections -- as a single mechanism, rather than
 * chasing further call sites one at a time. Deferring to a 0ms timer is
 * the standard "close on next tick" pattern any single-threaded event
 * loop needs for this hazard: by the time session_deferred_teardown_cb
 * runs, every nested call from the triggering event has fully unwound
 * back to the reactor's own dispatch loop, so nothing is still holding a
 * live stack frame into anything this call is about to free. As a
 * consequence, on_broken is now ALSO guaranteed to fire outside of any
 * cloak_session_t/cloak_conn_t/cloak_stream_t callback's call stack --
 * safe for a consumer to call cloak_session_destroy synchronously from
 * within it.
 *
 * Because session_close_internal no longer touches any stream, a
 * consumer calling cloak_session_release_stream on a specific stream
 * during the (usually sub-millisecond) window between this call and the
 * deferred callback firing works correctly: that call tombstones and
 * frees just that one stream immediately, and the later deferred sweep's
 * cloak_strmtab_for_each_active simply no longer sees it (tombstoned
 * entries aren't ACTIVE), so it isn't touched twice.
 *
 * sesh->teardown_timer_id IS tracked and must be cancelled by
 * cloak_session_destroy (unlike this reasoning's own first draft, which
 * argued no cancellation was needed here -- that argument was wrong: it
 * assumed cloak_session_destroy always outlives this timer or the
 * reactor is destroyed first, but nothing enforces either. A caller that
 * heap-allocates a cloak_session_t, calls cloak_session_close, then
 * cloak_session_destroy, then frees its own storage -- all before ever
 * running the reactor again -- leaves this timer pointing at freed
 * memory once the reactor finally runs. This was the sixth instance of
 * this same bug class, also found during this plan's own design
 * verification.) */
static void session_schedule_deferred_teardown(cloak_session_t *sesh) {
    sesh->teardown_timer_id = cloak_reactor_add_timer(sesh->reactor, 0, session_deferred_teardown_cb, sesh);
}

static void session_passive_close(cloak_session_t *sesh) {
    if (!session_close_internal(sesh)) {
        return;
    }
    session_schedule_deferred_teardown(sesh);
}

static void session_on_switchboard_broken(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    session_passive_close((cloak_session_t *)userdata);
}

static void session_switchboard_drained_adapter(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    if (sesh->on_writable != NULL) {
        sesh->on_writable(sesh, sesh->on_writable_userdata);
    }
}

static void session_on_envelope(cloak_switchboard_t *sb, const uint8_t *frame_bytes, size_t frame_len, void *userdata) {
    (void)sb;
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    if (sesh->closed) {
        return;
    }

    cloak_frame_t frame;
    /* cloak_frame_deobfuscate decrypts in place -- frame_bytes points
     * into the originating cloak_conn_t's reused recv_scratch buffer,
     * valid only for this call, which is exactly the lifetime we need
     * here (we're done with it by the time this function returns). */
    if (cloak_frame_deobfuscate(&sesh->obfuscator, &frame, (uint8_t *)frame_bytes, frame_len) != 0) {
        return; /* corrupt/garbled frame -- Go just logs and continues (switchboard.deplex), not fatal */
    }

    if (frame.closing == CLOAK_FRAME_CLOSING_SESSION) {
        session_passive_close(sesh);
        return;
    }

    cloak_strmtab_state_t state;
    void *value;
    int found = cloak_strmtab_lookup(&sesh->streams, frame.stream_id, &state, &value);
    if (found && state == CLOAK_STRMTAB_TOMBSTONE) {
        return; /* late frame for an already-closed stream -- drop silently, matching Go */
    }

    if (found && state == CLOAK_STRMTAB_ACTIVE) {
        cloak_stream_t *stream = (cloak_stream_t *)value;
        int rc = cloak_stream_feed_frame(stream, &frame);
        if (rc == 1 || rc == -1) {
            /* rc == 1: closing frame drained into order -- passive
             * close. rc == -1: protocol violation on this one stream --
             * tear it down rather than leave it permanently stuck; does
             * not affect the rest of the session. Go has no equivalent
             * detection to react to here (its ordered-mode ring buffer
             * has no error return path for a bad seq at all) -- this is
             * a deliberate, documented improvement over a literal Go
             * translation, not a behavior Go itself exhibits.
             *
             * Either way: only RETIRE it here (stop routing, stop
             * counting) -- never free it from this call path. See
             * session_retire_stream and this task's own "Stream memory
             * ownership" note. */
            session_retire_stream(sesh, stream);
        }
        /* Notify last, after routing and any retirement, so the consumer
         * sees final state: the bytes are readable, and a stream closed
         * by this frame already reads as ended. Fired even when the frame
         * was a protocol violation (rc == -1) so a consumer holding this
         * stream learns to tear its own side down rather than waiting
         * forever for data that will never come. */
        if (sesh->on_stream_data != NULL) {
            sesh->on_stream_data(sesh, stream, sesh->on_stream_data_userdata);
        }
        return;
    }

    /* Brand new stream_id -- nothing in strmtab yet. */
    cloak_session_stream_entry_t *entry =
        (cloak_session_stream_entry_t *)malloc(sizeof(cloak_session_stream_entry_t));
    if (entry == NULL) {
        return; /* allocation failure -- drop this frame */
    }
    entry->retired = 0;
    cloak_stream_t *stream = &entry->stream;
    if (cloak_stream_init(stream, frame.stream_id, &sesh->obfuscator,
                           sesh->max_on_wire_size, sesh->stream_recv_capacity,
                           sesh->stream_max_pending_frames,
                           session_stream_sink_adapter, sesh) != 0) {
        free(entry);
        return;
    }
    if (cloak_strmtab_insert_active(&sesh->streams, frame.stream_id, stream) != 0) {
        cloak_stream_destroy(stream);
        free(entry);
        return;
    }
    sesh->active_stream_count++;

    /* Feed the revealing frame (and retire this stream immediately if
     * that single frame already closes it or violates the protocol)
     * BEFORE invoking on_new_stream below -- not after. This order is
     * required, not stylistic: on_new_stream may reasonably call
     * cloak_session_release_stream on `stream` synchronously (it's
     * documented as safe to do so), which DOES free its memory right
     * then and there -- so this function must not touch `stream` again
     * once on_new_stream returns. (An earlier version of this comment
     * justified the same ordering by pointing at session_close_internal's
     * stream-freeing sweep, reasoning that on_new_stream might
     * synchronously call cloak_session_close and that sweep ran
     * synchronously too -- that sweep is now deferred (see this plan's
     * Global Constraints, finding 4), so that specific path is no longer
     * the live hazard, but this ordering is still required for the
     * cloak_session_release_stream reason above. Don't let this comment
     * go stale a second time: if you ever change what on_new_stream is
     * allowed to do, re-derive this reasoning from scratch rather than
     * assuming the sweep being deferred makes the ordering unnecessary.)
     * This also still matches Go's own actual ordering, where
     * newStream.recvFrame(frame) always runs (synchronously, in
     * recvDataFromRemote) before any consumer goroutine calling Accept()
     * could possibly observe the new stream via the channel send that
     * precedes it. */
    int rc = cloak_stream_feed_frame(stream, &frame);
    if (rc == 1 || rc == -1) {
        session_retire_stream(sesh, stream);
    }

    if (sesh->on_new_stream) {
        sesh->on_new_stream(sesh, stream, sesh->on_new_stream_userdata);
    }
}

int cloak_session_init(cloak_session_t *sesh, uint32_t id, cloak_reactor_t *reactor,
                        const cloak_session_config_t *config) {
    memset(sesh, 0, sizeof(*sesh));
    if (config->max_on_wire_size <= CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN ||
        config->stream_recv_capacity == 0 ||
        config->stream_recv_capacity < config->max_on_wire_size - CLOAK_FRAME_HEADER_LEN ||
        config->conn_send_queue_cap == 0 ||
        config->max_on_wire_size > 65535) {
        return -1;
    }

    sesh->id = id;
    sesh->reactor = reactor;
    sesh->obfuscator = config->obfuscator;
    sesh->next_stream_id = 1; /* matches Go's MakeSession: nextStreamID starts at 1 */
    sesh->max_on_wire_size = config->max_on_wire_size;
    sesh->stream_recv_capacity = config->stream_recv_capacity;
    sesh->stream_max_pending_frames = config->stream_max_pending_frames;
    sesh->inactivity_timeout_ms = config->inactivity_timeout_ms;
    sesh->on_new_stream = config->on_new_stream;
    sesh->on_new_stream_userdata = config->on_new_stream_userdata;
    sesh->on_broken = config->on_broken;
    sesh->on_broken_userdata = config->on_broken_userdata;
    sesh->on_writable = config->on_writable;
    sesh->on_writable_userdata = config->on_writable_userdata;
    sesh->on_stream_data = config->on_stream_data;
    sesh->on_stream_data_userdata = config->on_stream_data_userdata;

    if (cloak_strmtab_init(&sesh->streams, 16) != 0) {
        return -1;
    }
    if (cloak_switchboard_init(&sesh->sb, reactor, config->max_on_wire_size, config->conn_send_queue_cap,
                                session_on_envelope, sesh, session_on_switchboard_broken, sesh) != 0) {
        cloak_strmtab_destroy(&sesh->streams);
        return -1;
    }
    cloak_switchboard_set_drained_cb(&sesh->sb, session_switchboard_drained_adapter, sesh);

    session_reschedule_inactivity_timer(sesh);
    return 0;
}

void cloak_session_destroy(cloak_session_t *sesh) {
    session_close_internal(sesh); /* idempotent; no-op if already closed or never successfully initialized */
    /* Cancel any still-pending deferred teardown BEFORE freeing anything
     * below -- otherwise, if the reactor runs again later (after this
     * call returns but before it's destroyed), session_deferred_teardown_cb
     * would fire against memory this function is about to free/zero. See
     * session_schedule_deferred_teardown's own comment for the full
     * reasoning (this is what closes the sixth instance of this
     * project's recurring UAF class). */
    cloak_reactor_cancel_timer(sesh->reactor, sesh->teardown_timer_id);
    /* Synchronously free every remaining stream here -- safe only
     * because of this function's own documented calling contract (never
     * from within on_new_stream or any cloak_conn_t/cloak_stream_t
     * callback; only from ordinary code or from within on_broken, which
     * itself always runs outside any such callback's call stack). This
     * is the one place in this file allowed to call
     * session_free_all_active_streams synchronously. */
    session_free_all_active_streams(sesh);
    cloak_switchboard_destroy(&sesh->sb);
    cloak_strmtab_destroy(&sesh->streams);
    memset(sesh, 0, sizeof(*sesh));
}

int cloak_session_add_conn(cloak_session_t *sesh, int fd) {
    if (sesh->closed) {
        return -1;
    }
    return cloak_switchboard_add_conn(&sesh->sb, fd);
}

cloak_stream_t *cloak_session_open_stream(cloak_session_t *sesh, uint32_t *out_id) {
    if (sesh->closed) {
        return NULL;
    }
    uint32_t id = sesh->next_stream_id++;
    cloak_session_stream_entry_t *entry =
        (cloak_session_stream_entry_t *)malloc(sizeof(cloak_session_stream_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->retired = 0;
    cloak_stream_t *stream = &entry->stream;
    if (cloak_stream_init(stream, id, &sesh->obfuscator, sesh->max_on_wire_size,
                           sesh->stream_recv_capacity, sesh->stream_max_pending_frames,
                           session_stream_sink_adapter, sesh) != 0) {
        free(entry);
        return NULL;
    }
    if (cloak_strmtab_insert_active(&sesh->streams, id, stream) != 0) {
        cloak_stream_destroy(stream);
        free(entry);
        return NULL;
    }
    sesh->active_stream_count++;
    if (out_id) {
        *out_id = id;
    }
    return stream;
}

/* Sends the closing frame BEFORE retiring, matching Go's own order
 * (notify the peer, then clean up locally) -- this is safe, including
 * when cloak_stream_send_closing's sink call reentrantly triggers a full
 * session teardown (e.g. the connection it would have gone out on is
 * already dead), specifically BECAUSE session_close_internal no longer
 * touches any stream's memory (see session_schedule_deferred_teardown's
 * own comment) -- such a reentrant teardown only sets sesh->closed and
 * schedules a deferred callback; it cannot free `stream` out from under
 * this function. session_retire_stream below therefore always still
 * operates on valid memory, regardless of what cloak_stream_send_closing
 * triggered. (This was NOT true of an earlier draft of this file, before
 * session_close_internal's stream-freeing sweep was moved into the
 * deferred callback -- see this plan's Global Constraints for the full
 * incident.) */
int cloak_session_close_stream(cloak_session_t *sesh, cloak_stream_t *stream) {
    if (sesh->closed) {
        return -1;
    }
    cloak_session_stream_entry_t *entry = (cloak_session_stream_entry_t *)stream;
    if (entry->retired) {
        return -1; /* matches Go's errRepeatStreamClosing */
    }
    cloak_stream_send_closing(stream, CLOAK_FRAME_CLOSING_STREAM); /* best-effort -- proceed regardless, matching Go */
    session_retire_stream(sesh, stream);
    return 0;
}

void cloak_session_release_stream(cloak_session_t *sesh, cloak_stream_t *stream) {
    cloak_session_stream_entry_t *entry = (cloak_session_stream_entry_t *)stream;
    if (!entry->retired) {
        /* Releasing a still-open stream -- perform an implicit active
         * close first (send the closing frame, retire it), matching this
         * function's documented contract. Safe in the same way
         * cloak_session_close_stream's own comment explains above. */
        cloak_stream_send_closing(stream, CLOAK_FRAME_CLOSING_STREAM);
        session_retire_stream(sesh, stream);
    }
    cloak_stream_destroy(stream);
    free(entry);
}

int cloak_session_close(cloak_session_t *sesh) {
    if (!session_close_internal(sesh)) {
        return -1;
    }
    session_send_closing_session_frame(sesh);
    /* Deferred, not immediate -- see session_schedule_deferred_teardown's
     * own comment. cloak_session_close is documented as callable by
     * ordinary application code, but nothing stops a caller from also
     * calling it from within one of this session's own callbacks (e.g.
     * on_new_stream, reacting to an unwanted stream by closing the whole
     * session on the spot) -- which is exactly the same reentrant-free()
     * hazard passive close already has to guard against, so both paths
     * share the same fix. */
    session_schedule_deferred_teardown(sesh);
    return 0;
}

int cloak_session_is_closed(const cloak_session_t *sesh) {
    return sesh->closed;
}

size_t cloak_session_send_queued(const cloak_session_t *sesh) {
    if (sesh == NULL) {
        return 0;
    }
    return cloak_switchboard_send_queued(&sesh->sb);
}

size_t cloak_session_send_capacity(const cloak_session_t *sesh) {
    if (sesh == NULL) {
        return 0;
    }
    return cloak_switchboard_send_capacity(&sesh->sb);
}

size_t cloak_session_send_min_conn_free(const cloak_session_t *sesh) {
    if (sesh == NULL) {
        return 0;
    }
    return cloak_switchboard_send_min_conn_free(&sesh->sb);
}
