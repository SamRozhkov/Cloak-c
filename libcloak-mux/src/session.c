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

/* Used only by session_close_internal's whole-session teardown sweep.
 * Unlike session_retire_stream, this DOES unconditionally free every
 * still-active stream's memory -- destroying the whole session is a
 * bigger, more final event than one stream closing, and invalidates
 * every stream pointer this session ever handed out, whether previously
 * released or not (this is documented on cloak_session_close/
 * cloak_session_destroy themselves). Streams that were already retired
 * (tombstoned) before this sweep runs are NOT visited by
 * cloak_strmtab_for_each_active (tombstones aren't ACTIVE) -- their
 * memory remains the responsibility of whoever is holding that pointer,
 * via cloak_session_release_stream, exactly as if the session were still
 * alive. */
static void session_destroy_stream_iter_cb(uint32_t key, void *value, void *userdata) {
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    cloak_stream_t *stream = (cloak_stream_t *)value;
    cloak_session_stream_entry_t *entry = (cloak_session_stream_entry_t *)stream;
    cloak_stream_destroy(stream);
    free(entry);
    cloak_strmtab_tombstone(&sesh->streams, key); /* never grows/reallocates -- safe mid-iteration */
    sesh->active_stream_count--;
}

/* Shared teardown for both active Close() and passive close (Go's
 * closeSession): idempotent, frees every still-active stream's memory
 * (see session_destroy_stream_iter_cb), cancels the inactivity timer.
 * Returns 1 if this call actually did the work (first call), 0 if sesh
 * was already closed (matches Go's errRepeatSessionClosing being
 * surfaced by the caller as appropriate). */
static int session_close_internal(cloak_session_t *sesh) {
    if (sesh->closed) {
        return 0;
    }
    sesh->closed = 1;
    cloak_reactor_cancel_timer(sesh->reactor, sesh->inactivity_timer_id);
    cloak_strmtab_for_each_active(&sesh->streams, session_destroy_stream_iter_cb, sesh);
    return 1;
}

static void session_send_closing_session_frame(cloak_session_t *sesh) {
    uint8_t len_byte;
    cloak_random_bytes(&len_byte, 1);
    size_t pad_len = (size_t)len_byte + 1;
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

/* Fired by a 0ms reactor timer scheduled by session_passive_close/
 * cloak_session_close -- see their shared comment for why the actual
 * switchboard teardown must never happen synchronously from within
 * either of those two functions. */
static void session_deferred_teardown_cb(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    cloak_switchboard_close_all(&sesh->sb);
    if (sesh->on_broken) {
        sesh->on_broken(sesh, sesh->on_broken_userdata);
    }
}

/* Schedules the actual connection-pool teardown (cloak_switchboard_close_all)
 * and the on_broken notification for the reactor's NEXT dispatch loop
 * iteration, rather than performing them right here.
 *
 * This is required, not just cautious: session_passive_close and
 * cloak_session_close can both be invoked REENTRANTLY, from deep inside
 * one specific cloak_conn_t's own dispatch call chain --
 * conn_reactor_cb -> conn_handle_readable -> conn_extract_and_dispatch ->
 * (the on_envelope callback) -> switchboard_conn_envelope_adapter ->
 * session_on_envelope -> here (a closing-session frame just arrived), or
 * conn_mark_broken -> c->on_closed -> switchboard_conn_closed_adapter ->
 * session_on_switchboard_broken -> here (a connection just broke). If
 * cloak_switchboard_close_all ran synchronously from within either call
 * chain, it would free() every cloak_conn_t in the pool -- including,
 * whenever there's only one connection (always true in the first
 * reproduction of this bug) or whenever it happens to be the
 * currently-dispatching one, the very cloak_conn_t whose call frames are
 * still unwinding above this point on the stack. conn_extract_and_dispatch's
 * loop touches that pointer again (`if (c->broken)`) the moment the
 * on_envelope call returns -- a heap-use-after-free this plan's own
 * design verification caught deterministically under ASan. Deferring to
 * a 0ms timer is the standard "close on next tick" pattern any
 * single-threaded event loop needs for exactly this hazard: by the time
 * session_deferred_teardown_cb runs, every nested call from the
 * triggering event has fully unwound back to the reactor's own dispatch
 * loop, so nothing is still holding a live stack frame into any
 * cloak_conn_t this call is about to free. As a consequence, on_broken
 * is now ALSO guaranteed to fire outside of any cloak_session_t/
 * cloak_conn_t callback's call stack -- safe for a consumer to call
 * cloak_session_destroy synchronously from within it.
 *
 * No extra timer-id bookkeeping/cancellation is needed here (unlike the
 * inactivity timer): if cloak_session_destroy runs synchronously before
 * this timer fires, it memsets sesh to all zeros WITHOUT freeing sesh's
 * own storage (matching every other _destroy function in this codebase
 * -- the caller owns sesh's storage) and cloak_switchboard_close_all is
 * itself idempotent (a second call iterates zero connections and no-ops)
 * -- so if this timer later fires against an already-zeroed sesh,
 * sesh->sb.conns_len is 0 and sesh->on_broken is NULL, both no-ops. The
 * only way this could be unsafe is sesh's own storage being freed/reused
 * before the timer fires, which cloak_session_destroy never does itself
 * -- and if the owning reactor is destroyed first (the normal test/
 * caller teardown order), cloak_reactor_destroy discards any still-
 * pending timer without invoking it (see the already-merged reactor
 * module's own contract), so this is safe either way. */
static void session_schedule_deferred_teardown(cloak_session_t *sesh) {
    cloak_reactor_add_timer(sesh->reactor, 0, session_deferred_teardown_cb, sesh);
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
     * required, not stylistic: on_new_stream is documented as safe to
     * call cloak_session_close from (see cloak_session_close's own doc
     * comment), and cloak_session_close's stream-teardown sweep
     * (session_close_internal -> cloak_strmtab_for_each_active) runs
     * SYNCHRONOUSLY and unconditionally frees every currently-ACTIVE
     * stream, including this brand new one. If on_new_stream ran first
     * and synchronously closed the whole session this way, the
     * cloak_stream_feed_frame call that used to follow it would read
     * freed memory -- a heap-use-after-free this plan's own additional
     * adversarial verification (beyond this module's own written tests)
     * caught. Feeding first means nothing in this function touches
     * `stream` again after on_new_stream returns, so it no longer
     * matters what on_new_stream does with the session -- matching
     * Go's own actual ordering, where newStream.recvFrame(frame) always
     * runs (synchronously, in recvDataFromRemote) before any consumer
     * goroutine calling Accept() could possibly observe the new stream
     * via the channel send that precedes it. */
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

    if (cloak_strmtab_init(&sesh->streams, 16) != 0) {
        return -1;
    }
    if (cloak_switchboard_init(&sesh->sb, reactor, config->max_on_wire_size, config->conn_send_queue_cap,
                                session_on_envelope, sesh, session_on_switchboard_broken, sesh) != 0) {
        cloak_strmtab_destroy(&sesh->streams);
        return -1;
    }

    session_reschedule_inactivity_timer(sesh);
    return 0;
}

void cloak_session_destroy(cloak_session_t *sesh) {
    session_close_internal(sesh); /* idempotent; no-op if already closed or never successfully initialized */
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
         * function's documented contract. */
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
