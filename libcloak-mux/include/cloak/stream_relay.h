#ifndef CLOAK_STREAM_RELAY_H
#define CLOAK_STREAM_RELAY_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/reactor.h"
#include "cloak/session.h"
#include "cloak/stream.h"

/* Splices one multiplexed stream with one file descriptor: everything
 * readable on the stream is written to the fd, everything readable on the
 * fd is written into the stream. The server dispatcher uses it to connect
 * an accepted stream to an upstream proxy socket; the client uses it to
 * connect a local proxy socket to a stream it opened.
 *
 * Shaped deliberately like cloak_relay_t (cloak/net.h), which does the
 * same job for two sockets: start/stop, a one-shot done callback, a
 * fixed-capacity queue, and read interest dropped when the destination
 * cannot keep up.
 *
 * Two things it does NOT do:
 *
 *  - It never releases or frees the stream. cloak_session_release_stream
 *    is the caller's responsibility, exactly as that function's own doc
 *    comment requires -- this object closes the stream (so the peer
 *    learns) but never frees it.
 *
 *  - It does not subscribe to the session's callbacks itself. One session
 *    multiplexes many streams and only the caller knows which relay a
 *    given stream belongs to, so the caller owns
 *    cloak_session_config_t.on_stream_data and .on_writable and forwards
 *    them in through the two notify functions below. A relay that is
 *    never notified will stall: it has no other way to learn that its
 *    stream became readable or that the session's queue drained.
 *
 * MUST, not just "does not do": every relay bound to a session MUST be
 * stopped (cloak_stream_relay_stop) before or during that session's
 * on_broken, and before either cloak_session_destroy or
 * cloak_session_release_stream is called on anything the relay touches.
 * sr->stream and sr->sesh are raw pointers this object can never validate
 * on its own -- it has no third notification through which it could ever
 * learn the session died. cloak_session_broken_cb's own contract is that
 * immediately after on_broken returns, every still-active stream is
 * destroyed and freed and every connection is closed; a relay left
 * running past that point still has its fd registered in the reactor, so
 * the next byte that arrives on it runs pump_fd_to_stream ->
 * cloak_stream_write on a stream that may already be freed, and touches
 * sr->sesh on a session that may already be freed too. This is the single
 * most likely mistake for a caller wiring up all four session callbacks
 * to make -- stopping every live relay is exactly the "last chance" work
 * on_broken's own doc comment describes doing for streams, and a relay
 * must be added to that same list. */
typedef struct cloak_stream_relay cloak_stream_relay_t;

/* Fired exactly once, when the relay finishes: the stream ended, the fd
 * ended, or either side errored. The fd is already closed and the stream
 * is already closed (but NOT released) by the time this fires. Never
 * fired by cloak_stream_relay_stop, and never before
 * cloak_stream_relay_start returns -- including when the relay turns out
 * to already be finished at start time (see cloak_stream_relay_start's
 * own doc comment): that case still defers to the reactor's next turn
 * rather than firing synchronously. */
typedef void (*cloak_stream_relay_done_cb)(cloak_stream_relay_t *sr, void *userdata);

/* Read pacing, not policy the caller needs to size around: the relay
 * never asks its fd for more bytes than cloak_session_send_min_conn_free
 * -- the minimum free space over every connection in the session's pool
 * -- can currently absorb, re-derived before every single read. That
 * quantity, not the session's aggregate outbound pool, is what actually
 * bounds a safe read: cloak_switchboard_send hands each whole frame to
 * ONE connection chosen uniformly at random, not spread across the pool,
 * so the realistic failure is one congested connection hiding behind
 * many idle ones -- an aggregate bound stays large right up until the
 * random pick lands on the congested connection and its own hard cap
 * fires, which is fatal to the whole pool and the whole session no
 * matter how generous conn_send_queue_cap is. Budgeting off the minimum
 * instead guarantees the frames one read produces fit REGARDLESS of
 * which connection gets picked next, whatever buf_cap or
 * conn_send_queue_cap the caller chose. cloak_stream_write does not fail
 * on a full queue -- an overrun would otherwise surface one layer down as
 * a broken connection, taking the whole pool and every other stream in
 * the session down with it -- so this removes that cross-value sizing
 * constraint by construction rather than asking the caller to leave
 * enough advisory headroom (an earlier version of this file did the
 * latter, with a fixed watermark checked only once per read of up to a
 * fixed internal chunk size; a conn_send_queue_cap chosen too close to
 * that chunk size could still overrun the pool's hard cap in a single
 * step -- exactly the class of defect this exact, per-read bound
 * eliminates. A later version budgeted off the aggregate pool instead of
 * the minimum, which is exact against the aggregate but not against the
 * failure that actually happens in practice -- see
 * cloak_session_send_min_conn_free's own doc comment).
 *
 * cloak_stream_relay_start rejects outright (returns -1) rather than
 * starting a relay that could never move a single byte: see its own doc
 * comment for the exact condition, expressed in terms of this same
 * per-connection quantity so the two can never disagree. */

struct cloak_stream_relay {
    cloak_reactor_t *reactor;
    cloak_session_t *sesh;
    cloak_stream_t *stream;
    int fd;

    /* Bytes read from the stream, awaiting write to the fd. The other
     * direction needs no queue: cloak_stream_write always accepts what it
     * is given, so the fd is only read while the session has room. */
    cloak_bytequeue_t to_fd;

    /* 1 while read interest on fd is deregistered because the session's
     * outbound pool currently has no room at all (see
     * stream_relay_fd_read_budget in stream_relay.c). */
    int fd_read_paused;
    uint32_t interest;
    int stream_ended;
    int done;

    /* Non-CLOAK_TIMER_INVALID while a zero-delay "finish immediately"
     * timer is pending. cloak_stream_relay_start's own initial pump can
     * discover the relay is already finished -- the stream had already
     * ended before this relay even existed -- before start ever returns,
     * and this header promises on_done never fires before that return.
     * This field defers the whole teardown (not just the on_done call)
     * to the reactor's next turn, exactly like cloak_dial_t's own
     * immediate_timer defers cloak_dial_start's immediate-connect-success
     * case (see libcloak-common/src/dial.c). While it is pending, every
     * other entry point (the fd's own reactor callback and both notify
     * functions) treats the relay as already finishing and does nothing,
     * so nothing acts on it a second time before the deferred teardown
     * actually runs. cloak_stream_relay_stop cancels it if the caller
     * stops the relay before it fires. */
    cloak_timer_id_t finish_timer;

    cloak_stream_relay_done_cb on_done;
    void *on_done_userdata;
};

/* Starts splicing stream and fd.
 *
 * OWNERSHIP OF fd, with no exceptions: on SUCCESS the relay owns it and
 * closes it when it finishes or is stopped; on ANY FAILURE the caller
 * still owns it and must close it. There is no return value, and no
 * state on sr, that a caller has to inspect to work out which -- the
 * rule is uniform, and every failure path inside this function is
 * written to keep it that way, including the one that has already
 * registered fd with the reactor by the time it fails (it deregisters
 * before unwinding). An earlier version of this file had a single narrow
 * exception here. It was documented, but it could not be reached from
 * any test, and a caller that got it wrong would double-close a
 * descriptor -- which no sanitizer detects. An interface with no
 * exception beats a documented exception that cannot be tested.
 *
 * buf_cap sizes the stream-to-fd queue. sesh must be the session stream
 * belongs to -- it is consulted for outbound pressure, never written to
 * directly.
 *
 * Like every reactor-driven object in this project, sr must stay live and
 * at a fixed address until its terminal event: the reactor holds its
 * address as callback userdata, so storing relays in a realloc-grown
 * array is a use-after-free.
 *
 * If stream had already ended before this call (e.g. the very frame that
 * revealed it to the session was itself the closing frame), the relay
 * finishes immediately -- but on_done still does not fire synchronously
 * from within this call: it is deferred to a zero-delay reactor timer, so
 * it always fires on a later turn, exactly as it would for a relay that
 * ran for a while first. This still returns 0, since start genuinely did
 * succeed; the relay just also happens to already be done.
 *
 * THREE RETURN VALUES, and the distinction between the two failures is
 * the whole point:
 *
 *   0  Started. (Possibly already finished too -- see the
 *      already-ended-stream paragraph above.)
 *
 *  -1  PERMANENT failure: invalid arguments, allocation failure
 *      (including the exceedingly rare case of failing to arm that
 *      deferred completion timer, which forces an already-finished relay
 *      to fail start outright since it would otherwise have no way left
 *      to ever report completion), or a reactor registration failure.
 *      Nothing about the session or its pool will change to make a later
 *      attempt with the same arguments succeed, so retrying is pure
 *      waste: it holds a connected descriptor and the caller's own
 *      per-stream state open for the whole retry budget and then fails
 *      anyway.
 *
 *  -2  TRANSIENT rejection: the session's pool could not hold even a
 *      single worst-case frame AT THIS MOMENT -- the minimum free space
 *      over the pool (see cloak_session_send_min_conn_free) is smaller
 *      than one frame's full on-wire cost for this stream. This is
 *      caught here rather than left to surface later as a silent stall:
 *      a relay started anyway would compute a read budget of 0 on its
 *      very first read, with nothing ever queued to eventually prompt a
 *      drain-driven resume, and would hang forever holding an open fd
 *      with no error anywhere. It is EXPECTED under ordinary congestion
 *      and says nothing is wrong: a relay already running on this
 *      session deliberately holds min_conn_free below exactly this
 *      threshold whenever its peer is slow to drain (see
 *      stream_relay_fd_read_budget), so a second stream opened during a
 *      bulk transfer sees this routinely, for as long as the congestion
 *      lasts. A caller should wait and try again, not give up.
 *
 * These are separated because a caller that cannot tell them apart has
 * only two options and both are wrong: retry every failure (and hold a
 * descriptor open across a budget that can never succeed) or give up on
 * every failure (and drop streams during ordinary congestion, which is
 * precisely the condition backpressure exists to survive).
 *
 * On any failure sr is left safe to pass to cloak_stream_relay_stop. */
int cloak_stream_relay_start(cloak_stream_relay_t *sr, cloak_reactor_t *r,
                              cloak_session_t *sesh, cloak_stream_t *stream, int fd,
                              size_t buf_cap, cloak_stream_relay_done_cb on_done,
                              void *userdata);

/* Call from the session's on_stream_data callback when the frame was for
 * this relay's stream: drains the stream into the fd. A no-op once the
 * relay has finished, or has a finish already pending (see
 * cloak_stream_relay::finish_timer). */
void cloak_stream_relay_notify_stream_data(cloak_stream_relay_t *sr);

/* Call from the session's on_writable callback: re-arms fd read interest
 * if it was paused for backpressure. A no-op once the relay has
 * finished, has a finish already pending, or if it was not paused. */
void cloak_stream_relay_notify_writable(cloak_stream_relay_t *sr);

/* Tears the relay down without firing on_done: unregisters and closes the
 * fd, closes the stream, frees the queue, and cancels the deferred finish
 * timer if one was pending (so it can never fire afterward, and never
 * reads sr's storage again -- important since sr's memory may be
 * repurposed or freed as soon as this call returns). Does NOT release the
 * stream. Idempotent, and safe on a relay left by a failed start. */
void cloak_stream_relay_stop(cloak_stream_relay_t *sr);

#endif
