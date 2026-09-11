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
 * Streams sesh owned are NOT yet destroyed when this fires -- this is
 * deliberately your last chance to call cloak_session_release_stream on
 * any you're still holding a reference to (safe to do so from within
 * this callback). Immediately after this callback returns, every stream
 * you didn't release yourself is automatically destroyed and freed, and
 * every underlying connection is closed -- so any stream pointer you
 * still have becomes invalid the moment this callback returns, whether
 * or not you released it.
 *
 * Guaranteed to fire OUTSIDE of any cloak_session_t/cloak_conn_t
 * callback's own call stack (deferred internally to the reactor's next
 * dispatch loop iteration even when the close was triggered from within
 * one) -- so it is always safe to call cloak_session_destroy or
 * cloak_session_release_stream synchronously from within this callback. */
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
 * and frees every remaining stream, closes every underlying connection,
 * and frees sesh's own resources. Does NOT fire on_broken (this is the
 * caller's own explicit teardown, not a failure notification).
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
 * session closed and sends one session-level closing frame to the peer
 * synchronously, before this call returns. Destroying every remaining
 * stream's memory, closing every underlying connection, and firing
 * on_broken are ALL deferred to the reactor's next dispatch loop
 * iteration (see cloak_session_broken_cb's own doc comment for why) --
 * every stream this session ever handed out stays valid (though no
 * longer routable -- no more frames will ever reach it) for that brief
 * window; call cloak_session_release_stream on any you still hold if you
 * need deterministic, immediate cleanup of a specific one rather than
 * waiting for the deferred sweep to reclaim it.
 *
 * Returns 0 on success, -1 if already closed (matches Go's
 * errRepeatSessionClosing). Safe to call from within any of this
 * session's own callbacks (on_new_stream, on_broken, etc.), not just from
 * ordinary application code. */
int cloak_session_close(cloak_session_t *sesh);

int cloak_session_is_closed(const cloak_session_t *sesh);

#endif
