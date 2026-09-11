#ifndef CLOAK_SESSION_H
#define CLOAK_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/frame.h"
#include "cloak/reactor.h"
#include "cloak/strmtab.h"
#include "cloak/stream.h"
#include "cloak/switchboard.h"

typedef struct cloak_session cloak_session_t;

/* Fired the moment a frame arrives for a stream_id this session has never
 * seen before (mirrors Go's Session.acceptCh -- a push callback instead
 * of a blocking-channel receive, consistent with this whole project's
 * reactor-callback translation of Go's blocking idioms). stream is
 * already fully initialized and already fed the frame that revealed it;
 * it may already have data available via cloak_stream_read by the time
 * this fires.
 *
 * stream remains valid (safe to call cloak_stream_read/cloak_stream_write
 * on) even after the peer closes it or this session tears it down for
 * any other reason -- its memory is freed ONLY by an explicit
 * cloak_session_release_stream call, never automatically. The recipient
 * of this callback owns that responsibility: call
 * cloak_session_release_stream once done with stream (typically after
 * observing cloak_stream_read return -1), or its memory leaks for the
 * remaining lifetime of the process. See this file's own top-of-task
 * "Stream memory ownership" note for the full reasoning. */
typedef void (*cloak_session_new_stream_cb)(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata);

/* Fired exactly once, the moment sesh becomes closed for ANY reason
 * (active cloak_session_close, a received closing-session frame, any
 * underlying connection failing, or the inactivity timeout).
 *
 * Any stream that is still ACTIVE (never retired, by any means, at the
 * moment this fires) is NOT yet destroyed when this callback runs -- this
 * is deliberately your last chance to call cloak_session_release_stream
 * on any such stream you're still holding a reference to (safe to do so
 * from within this callback). Immediately after this callback returns,
 * every stream that is STILL active (i.e. that neither you nor anything
 * else retired) is automatically destroyed and freed, and every
 * underlying connection is closed.
 *
 * IMPORTANT, and easy to get wrong: this automatic cleanup only ever
 * reaches streams that are still ACTIVE at teardown time. A stream that
 * was retired EARLIER for any reason other than your own explicit
 * cloak_session_release_stream call -- the peer closing it, a protocol
 * violation, or your own prior cloak_session_close_stream call -- is
 * untouched by this sweep (it's no longer reachable through this
 * session's internal routing table at all once retired) and its memory
 * leaks unless you call cloak_session_release_stream on it yourself, at
 * any point up to and including from within this very callback. In
 * short: nothing here reclaims a stream you haven't released UNLESS it
 * was still active and unretired the whole time. See
 * cloak_session_release_stream's own doc comment and this plan's Global
 * Constraints (finding 8) for the full reasoning -- an earlier version
 * of this comment overclaimed that everything gets reclaimed
 * automatically, which is not true and was caught by this plan's own
 * final whole-branch review, reproduced as a real LeakSanitizer-detected
 * leak in the most ordinary possible scenario (a stream opened, used,
 * and normally closed, on either side, without an explicit release).
 *
 * Guaranteed to fire OUTSIDE of any cloak_session_t/cloak_conn_t
 * callback's own call stack (deferred internally to the reactor's next
 * dispatch loop iteration even when the close was triggered from within
 * one) -- so it is always safe to call cloak_session_release_stream
 * synchronously from within this callback. Calling cloak_session_destroy
 * from within this callback is ALSO safe, including freeing sesh's own
 * storage before this callback returns -- but if you do, do not also
 * expect the leak-avoidance advice above to still apply afterward: once
 * sesh is destroyed, any stream pointer you didn't already release is
 * gone regardless, exactly like calling cloak_session_destroy from
 * ordinary application code. */
typedef void (*cloak_session_broken_cb)(cloak_session_t *sesh, void *userdata);

typedef struct {
    cloak_obfuscator_t obfuscator;   /* copied by value into the session -- see this task's own file header comment for why */
    size_t max_on_wire_size;         /* forwarded to every cloak_stream_init and cloak_conn_init this session performs */
    size_t stream_recv_capacity;     /* forwarded to every cloak_stream_init this session performs */
    size_t stream_max_pending_frames;/* forwarded to every cloak_stream_init this session performs */
    size_t conn_send_queue_cap;      /* forwarded to every cloak_conn_init this session performs, via its switchboard */
    uint64_t inactivity_timeout_ms;  /* how long with zero active streams before the session auto-closes */
    cloak_session_new_stream_cb on_new_stream;
    void *on_new_stream_userdata;
    cloak_session_broken_cb on_broken;
    void *on_broken_userdata;
} cloak_session_config_t;

struct cloak_session {
    uint32_t id;
    cloak_reactor_t *reactor;
    cloak_obfuscator_t obfuscator;

    cloak_strmtab_t streams;
    cloak_switchboard_t sb;

    uint32_t next_stream_id;
    size_t active_stream_count;

    size_t max_on_wire_size;
    size_t stream_recv_capacity;
    size_t stream_max_pending_frames;
    uint64_t inactivity_timeout_ms;
    cloak_timer_id_t inactivity_timer_id;
    cloak_timer_id_t teardown_timer_id;

    int closed;

    cloak_session_new_stream_cb on_new_stream;
    void *on_new_stream_userdata;
    cloak_session_broken_cb on_broken;
    void *on_broken_userdata;
};

/* Returns 0 on success, -1 on invalid parameters (same validation
 * cloak_stream_init and cloak_conn_init/cloak_switchboard_init already
 * apply to max_on_wire_size/stream_recv_capacity/conn_send_queue_cap,
 * checked eagerly here as far as is possible without a stream/conn to
 * actually construct) or allocation failure. Schedules the initial
 * inactivity timer as part of construction (matching Go's MakeSession,
 * which does the same immediately after setting up the session). */
int cloak_session_init(cloak_session_t *sesh, uint32_t id, cloak_reactor_t *reactor,
                        const cloak_session_config_t *config);

/* If not already closed, marks the session closed WITHOUT sending a
 * closing-session frame first (there is likely nothing left to send it
 * through, and the caller is discarding this session outright, not
 * notifying a peer). Then, synchronously and unconditionally (whether or
 * not a deferred teardown was already pending -- see cloak_session_close's
 * own doc comment): cancels any pending deferred-teardown timer, destroys
 * and frees every still-ACTIVE stream (see cloak_session_broken_cb's own
 * doc comment for why "still-ACTIVE" is not the same as "every stream" --
 * a stream retired earlier by any means and never released leaks even
 * here, since it's no longer reachable through this session at all once
 * retired), closes every underlying connection, and frees sesh's own
 * resources. Does NOT fire on_broken (this is the caller's own explicit
 * teardown, not a failure notification) -- so this is also NOT your last
 * chance to release a still-ACTIVE stream via cloak_session_release_stream
 * the way on_broken is; release anything you still hold BEFORE calling
 * this, not after.
 *
 * Must NOT be called from within on_new_stream, or from within any
 * cloak_conn_t/cloak_switchboard_t callback -- only from ordinary
 * application code, or from within on_broken (on_broken is documented as
 * always firing outside of any such callback's call stack, which is what
 * makes calling this from there safe). Safe to call on a session left
 * zeroed by a rejected cloak_session_init. */
void cloak_session_destroy(cloak_session_t *sesh);

/* Wraps fd (an open, non-blocking-capable socket) in a new underlying
 * connection and adds it to the session's pool. Returns 0 on success, -1
 * if sesh is closed or on failure adding to the switchboard. */
int cloak_session_add_conn(cloak_session_t *sesh, int fd);

/* Opens a new locally-initiated stream (Go's Session.OpenStream).
 * Returns the new stream and, if out_id is non-NULL, its id. Returns NULL
 * if sesh is closed or on allocation failure. See this file's own
 * top-of-task "Stream memory ownership" note: the returned pointer stays
 * valid (never automatically freed) until an explicit
 * cloak_session_release_stream call. */
cloak_stream_t *cloak_session_open_stream(cloak_session_t *sesh, uint32_t *out_id);

/* Actively closes stream: sends a closing-stream frame to the peer, stops
 * it from receiving any more routed frames, and stops it counting toward
 * the session's active-stream count. Does NOT free stream's memory --
 * see cloak_session_release_stream, and this file's own top-of-task
 * "Stream memory ownership" note. Returns 0 on success, -1 if stream was
 * already closed this way (matches Go's errRepeatStreamClosing) or if
 * sesh is already closed. stream remains valid to read from (and must
 * still be released) after this call. */
int cloak_session_close_stream(cloak_session_t *sesh, cloak_stream_t *stream);

/* Frees stream's memory. Safe to call whether stream was already closed
 * (actively via cloak_session_close_stream, or passively because the
 * peer closed it, or because of a protocol violation) or not -- if not,
 * this performs an implicit active close first (same effect as calling
 * cloak_session_close_stream immediately before this). After this call,
 * stream must never be used again by the caller for any purpose
 * (including passing it to any cloak_session_* or cloak_stream_* function
 * again) -- exactly like calling free() on any other heap pointer. */
void cloak_session_release_stream(cloak_session_t *sesh, cloak_stream_t *stream);

/* Actively closes the whole session (Go's Session.Close): marks the
 * session closed and ENQUEUES one session-level closing frame to be sent
 * to the peer, synchronously, before this call returns -- but "enqueued"
 * is as far as this call guarantees: it does not wait for that frame, or
 * any data queued by an earlier cloak_stream_write, to actually reach the
 * kernel. Destroying every still-ACTIVE stream's memory (see
 * cloak_session_broken_cb's own doc comment for what "still-ACTIVE" does
 * and doesn't cover) and closing every underlying connection are BOTH
 * deferred to the reactor's next dispatch loop iteration, and that
 * deferred step unconditionally discards anything still sitting in a
 * connection's outbound queue at that point -- including the
 * closing-session frame this call just enqueued, if the queue was
 * already backed up. This is a known, deliberate limitation (Go's own
 * Session.Close() avoids it because its send() is a blocking write, so
 * everything queued has genuinely reached the kernel before closeAll()
 * runs -- this port's non-blocking connections have no equivalent
 * built-in guarantee). The peer still learns the session ended either
 * way, just via the connection dying (EOF) instead of the intended
 * graceful notification, in the rare case a substantial amount of data
 * was still queued at the exact moment of this call. If you need every
 * byte to actually go out first, drain each stream's own backpressure
 * signal (there is currently no session-level equivalent) before calling
 * this. Every stream this session ever handed out stays valid (though no
 * longer routable -- no more frames will ever reach it) until the
 * deferred sweep runs; call cloak_session_release_stream on any you
 * still hold if you need deterministic, immediate cleanup of a specific
 * one rather than waiting for that sweep, which (per
 * cloak_session_broken_cb's doc) only reclaims streams that are still
 * ACTIVE when it runs.
 *
 * Returns 0 on success, -1 if already closed (matches Go's
 * errRepeatSessionClosing). Safe to call from within any of this
 * session's own callbacks (on_new_stream, on_broken, etc.), not just from
 * ordinary application code. */
int cloak_session_close(cloak_session_t *sesh);

int cloak_session_is_closed(const cloak_session_t *sesh);

#endif
