#ifndef CLOAK_DGRAM_RELAY_H
#define CLOAK_DGRAM_RELAY_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/reactor.h"
#include "cloak/session.h"
#include "cloak/stream.h"

/* Splices one multiplexed stream with one CONNECTED DATAGRAM SOCKET,
 * preserving message boundaries in both directions: every datagram read
 * from the stream leaves as exactly one datagram on the socket, and every
 * datagram the socket delivers becomes exactly one frame on the stream.
 * The server's proxy uses it for a ProxyBook entry declared "udp".
 *
 * WHY THIS IS NOT cloak_stream_relay_t WITH A FLAG. That object is
 * correct for a byte stream and cannot be made correct for datagrams by
 * a mode bit, because its two directions are wrong in two different ways:
 *
 *  1. ITS STREAM-TO-fd QUEUE IS A BYTE QUEUE. It fills cloak_bytequeue_t
 *     from the stream until the queue is full, then drains it with one
 *     send(2) per pass -- so two datagrams that happen to be queued
 *     together leave as ONE datagram of their combined length. On a byte
 *     stream that is not merely harmless, it is the point. Here it is
 *     silent corruption, and it is the most likely state in practice:
 *     several frames arrive in one reactor turn whenever the peer is
 *     sending faster than one datagram per round trip.
 *  2. IT READS THE fd WITH read(2) AND TREATS 0 AS END OF STREAM. On a
 *     datagram socket a return of 0 means an EMPTY DATAGRAM ARRIVED and
 *     the socket is perfectly healthy -- a connected UDP socket has no
 *     end-of-stream condition at all. Reusing that arm would let any peer
 *     on the internet tear down a live stream with one empty packet. The
 *     same read also silently discards everything past the buffer, which
 *     is Go's bug 7 (see the size policy below).
 *
 * Everything ELSE about the two objects is deliberately identical --
 * start/stop, a one-shot done callback, the two notify functions, read
 * interest dropped when the destination cannot keep up, the three return
 * values of start, and the rule that the relay never releases or frees
 * the stream. A caller that already drives a cloak_stream_relay_t drives
 * this the same way, which is what lets libcloak-server/src/proxy.c pick
 * between them on the upstream's socket type alone.
 *
 * THE SIZE POLICY, which is where this port deliberately parts company
 * with Go (the plan's decision D7, settled by measurement against
 * upstream v2.12.0):
 *
 *   A DATAGRAM UP TO max_payload_per_frame IS CARRIED WHOLE, in both
 *   directions. At the max_on_wire_size both ends of a Cloak tunnel use
 *   (16401) that is 16132 bytes. Go loses every one of 8193..16132: its
 *   client reads replies into an 8192-byte buffer
 *   (internal/client/piper.go:60), gets io.ErrShortBuffer from the
 *   datagram pipe (internal/multiplex/datagramBufferedPipe.go:59-60),
 *   and breaks out of the loop (piper.go:63-66) -- tearing the
 *   peer's whole stream down rather than dropping one message (bug 6).
 *
 *   A LARGER DATAGRAM FROM THE SOCKET IS DROPPED WHOLE, and the relay
 *   keeps running. It cannot be carried (one datagram is one frame, and
 *   cloak_stream_write refuses to split -- the far end does no
 *   reassembly), so the only choices are drop it or deliver part of it.
 *   Go delivers part of it: its read buffer silently truncates
 *   (internal/client/piper.go:25-26, an 8192-byte buffer handed
 *   straight to ReadFrom) and the fragment is forwarded as though it
 *   were the message (bug 7), which a
 *   UDP application cannot distinguish from a genuinely short reply.
 *   Dropping is what the network itself would have done with a datagram
 *   too large for a hop.
 *
 *   A ZERO-LENGTH DATAGRAM IS SWALLOWED, matching Go and forced anyway:
 *   cloak_stream_write sends nothing for an empty payload because Go's
 *   frame encoder refuses one outright
 *   (internal/multiplex/obfs.go:64-67, "payload cannot be empty"), so there is no frame in which an
 *   empty datagram could cross. Swallowing is not the same as ignoring --
 *   see point 2 above for what must NOT happen when one arrives.
 *
 * MUST, AND IT IS THE SAME MUST cloak/stream_relay.h STATES: every relay
 * bound to a session MUST be stopped (cloak_dgram_relay_stop) before or
 * during that session's on_broken, and before either cloak_session_destroy
 * or cloak_session_release_stream is called on anything it touches.
 * sr->stream and sr->sesh are raw pointers this object can never validate
 * and it has no notification through which it could learn either died --
 * a relay left running past that point still has its fd registered with
 * the reactor, and the next datagram that arrives runs cloak_stream_write
 * on freed memory. */
typedef struct cloak_dgram_relay cloak_dgram_relay_t;

/* Fired exactly once, when the relay finishes: the stream ended, or the
 * socket errored. The fd is already closed and the stream is already
 * closed (but NOT released) by the time this fires. Never fired by
 * cloak_dgram_relay_stop, and never before cloak_dgram_relay_start
 * returns -- including when the relay turns out to already be finished at
 * start time, which defers to the reactor's next turn exactly as
 * cloak_stream_relay_t does.
 *
 * THERE IS NO "THE SOCKET ENDED" IN THE LIST, and the omission is the
 * point: a connected datagram socket has no orderly close. It finishes
 * only on a real error -- ECONNREFUSED from an ICMP port-unreachable, or
 * anything else recv/send reports that is not EAGAIN. */
typedef void (*cloak_dgram_relay_done_cb)(cloak_dgram_relay_t *dr, void *userdata);

struct cloak_dgram_relay {
    cloak_reactor_t *reactor;
    cloak_session_t *sesh;
    cloak_stream_t *stream;
    int fd;

    /* AT MOST ONE datagram read from the stream and not yet accepted by
     * the socket, held at its own length rather than in a queue.
     *
     * ONE IS THE WHOLE BACKPRESSURE DESIGN, not a simplification. While a
     * datagram is pending this relay stops reading its stream, so the
     * backlog stays in the stream's own receive queue -- which is a
     * cloak_msgqueue_t with a decided overflow policy (drop the NEWEST,
     * and count it: the plan's ruling 2, implemented in
     * cloak_stream_feed_frame). A queue here would be a SECOND place that
     * buffers datagrams with a second, undecided drop policy, and the
     * first thing it would do on overflow is disagree with the first one.
     * It is also exactly the shape the client's own cloak_udp_piper_t
     * chose for the same reason, one module earlier.
     *
     * pending_len > 0 is the only "is one pending" test there is, and it
     * is sound because a zero-length datagram can never get here:
     * cloak_stream_write refuses to send an empty payload, so no frame
     * ever carries one and cloak_stream_read never yields one. */
    uint8_t *pending;
    size_t pending_cap; /* exactly stream->max_payload_per_frame; see start */
    size_t pending_len;

    /* 1 while read interest on fd is deregistered because the session
     * could not accept another frame right now -- either its outbound
     * pool has no room or the user's tx token bucket is empty. Resumed by
     * completely different things; see rate_timer. */
    int fd_read_paused;
    uint32_t interest;
    int stream_ended;
    int done;

    /* Non-CLOAK_TIMER_INVALID while a zero-delay "finish immediately"
     * timer is pending, for the reason cloak_stream_relay_t's field of
     * the same name exists: start's own initial pump can discover the
     * relay is already finished, and this header promises on_done never
     * fires before start returns. While it is pending every other entry
     * point treats the relay as already finishing and does nothing. */
    cloak_timer_id_t finish_timer;

    /* Non-CLOAK_TIMER_INVALID while a resume is pending for a read paused
     * by an EMPTY TX TOKEN BUCKET, as opposed to a full pool. The
     * distinction is the same one cloak_stream_relay_t documents at
     * length: a pool-bound pause is resumed by the session's own drained
     * notification, an event certain to arrive; a rate-bound pause is
     * resumed by nothing whatsoever, because no queue drains, the
     * socket's readiness edge is already spent, and the peer has no
     * reason to act. Only the clock changes. */
    cloak_timer_id_t rate_timer;

    /* OPERATOR-VISIBLE, and the only record that either divergence above
     * actually happened -- both are silent by construction, since a
     * dropped datagram looks exactly like one the network lost.
     * Monotonic, never reset. */
    uint64_t dropped_oversize; /* datagrams too large for one frame */
    uint64_t swallowed_empty;  /* zero-length datagrams */

    cloak_dgram_relay_done_cb on_done;
    void *on_done_userdata;
};

/* Starts splicing stream and fd. fd MUST be a CONNECTED datagram socket
 * (the proxy's is connected by cloak_dial_start, which connect(2)s a
 * SOCK_DGRAM address exactly as it does a SOCK_STREAM one); a
 * non-connected one would deliver datagrams from anybody and have no
 * default destination to answer.
 *
 * OWNERSHIP OF fd, with no exceptions and for the reason
 * cloak_stream_relay_start states: on SUCCESS the relay owns it and
 * closes it when it finishes or is stopped; on ANY FAILURE the caller
 * still owns it and must close it. Every failure path here is written to
 * keep that uniform, including the one that has already registered fd
 * with the reactor by the time it fails.
 *
 * THERE IS NO buf_cap PARAMETER, and its absence is deliberate rather
 * than an oversight. The one buffer this object holds is sized at exactly
 * stream->max_payload_per_frame, because that is simultaneously the
 * largest datagram the stream can deliver and the largest one it can
 * accept -- a caller-chosen value could only be too small, and too small
 * here is not "slower", it is a stream that wedges: cloak_stream_read
 * would answer CLOAK_STREAM_ERR_SHORT_BUFFER forever for a datagram that
 * no amount of draining will ever make fit. cloak_stream_relay_t takes
 * the parameter because its queue is a byte queue, where a small value
 * genuinely only costs turns.
 *
 * Like every reactor-driven object in this project, sr must stay live and
 * at a fixed address until its terminal event.
 *
 * THREE RETURN VALUES, the same three cloak_stream_relay_start has and
 * with the same meanings, so that a caller can drive either object with
 * one retry policy:
 *
 *   0  Started. (Possibly already finished too -- if the stream had
 *      already ended before this call, on_done still fires on a later
 *      reactor turn rather than from inside this one.)
 *
 *  -1  PERMANENT failure: invalid arguments, allocation failure, or a
 *      reactor registration failure. Retrying the identical call is pure
 *      waste.
 *
 *  -2  TRANSIENT rejection: the session's pool could not hold even a
 *      single worst-case frame AT THIS MOMENT (see
 *      cloak_session_send_min_conn_free). Caught here rather than left to
 *      surface later as a silent stall, and EXPECTED under ordinary
 *      congestion. A caller should wait and try again.
 *
 * On any failure sr is left safe to pass to cloak_dgram_relay_stop.
 *
 * NAMED for the reason cloak/stream_relay.h's
 * CLOAK_STREAM_RELAY_ERR_POOL_FULL gives at length: -2 from a relay start
 * and -2 from cloak_stream_read/_write (CLOAK_STREAM_ERR_SHORT_BUFFER)
 * are different conditions with the same number, reached through the same
 * objects. Same value here as there -- this IS the same condition as the
 * stream relay's, checked against the same quantity -- and it keeps its
 * own name so a dgram-relay site reads as a dgram-relay site. */
#define CLOAK_DGRAM_RELAY_ERR_POOL_FULL (-2)

int cloak_dgram_relay_start(cloak_dgram_relay_t *sr, cloak_reactor_t *r, cloak_session_t *sesh,
                             cloak_stream_t *stream, int fd, cloak_dgram_relay_done_cb on_done,
                             void *userdata);

/* Call from the session's on_stream_data callback when the frame was for
 * this relay's stream: moves whatever the stream now holds towards the
 * socket. A no-op once the relay has finished or has a finish pending. */
void cloak_dgram_relay_notify_stream_data(cloak_dgram_relay_t *sr);

/* Call from the session's on_writable callback: re-arms socket read
 * interest if it was paused for backpressure. A no-op once the relay has
 * finished, has a finish pending, or was not paused. */
void cloak_dgram_relay_notify_writable(cloak_dgram_relay_t *sr);

/* Tears the relay down without firing on_done: unregisters and closes the
 * fd, closes the stream, frees the pending buffer, and cancels both
 * timers (so neither can ever fire afterwards against storage that may be
 * freed the instant this returns). Does NOT release the stream.
 * Idempotent, and safe on a relay left by a failed start. */
void cloak_dgram_relay_stop(cloak_dgram_relay_t *sr);

#endif
