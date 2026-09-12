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
 *    stream became readable or that the session's queue drained. */
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

/* The relay stops reading its fd once the session's outbound queue is
 * this fraction full, and resumes when cloak_stream_relay_notify_writable
 * reports it drained. It is deliberately conservative: cloak_stream_write
 * does not fail on a full queue -- the overrun surfaces one layer down as
 * a broken connection pool that kills the entire session, taking every
 * other stream with it -- so the watermark leaves room for the frames
 * already in flight rather than running the queue to its limit.
 *
 * That headroom is checked once per fd read, not continuously, so a
 * single already-permitted read can still add up to about one read's
 * worth of framed bytes (16 KiB, this file's own internal chunk size) to
 * the queue in one step. Configure sesh's conn_send_queue_cap comfortably
 * above that -- tens of KiB of headroom, not a close multiple of it -- or
 * a burst that starts just under the watermark can land past the queue's
 * actual hard cap in that one step and break the session outright, the
 * same failure this watermark exists to avoid. Every conn_send_queue_cap
 * already in use elsewhere in this project's own tests (65536 and up) is
 * safely clear of this; only a deliberately tiny cap is at risk. */
#define CLOAK_STREAM_RELAY_HIGH_WATER_NUM 1
#define CLOAK_STREAM_RELAY_HIGH_WATER_DEN 2

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
     * outbound queue is above the watermark. */
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

/* Starts splicing stream and fd. Ownership of fd passes to the relay,
 * which closes it when it finishes or is stopped; on a FAILED start the
 * caller keeps it and must close it -- except in the extremely narrow
 * case documented below where the relay had already taken ownership of
 * fd before the failure occurred, in which case the relay closes it
 * itself as part of unwinding.
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
 * Returns 0 on success, -1 on invalid arguments, allocation failure
 * (including the exceedingly rare case of failing to arm that deferred
 * completion timer, which forces an already-finished relay to fail start
 * outright since it would otherwise have no way left to ever report
 * completion), or a reactor registration failure. On failure sr is left
 * safe to pass to cloak_stream_relay_stop. */
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
