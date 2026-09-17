#define _POSIX_C_SOURCE 200809L
#include "cloak/dgram_relay.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/conn.h"         /* CLOAK_CONN_MAX_FRAME_LEN, for the one stack buffer below */
#include "cloak/stream_relay.h" /* cloak_stream_relay_frame_cost: SHARED with the
                                 * stream relay so the two can never disagree about
                                 * what one frame's worth of room means */

static void dgram_relay_teardown(cloak_dgram_relay_t *sr, int fire_done);
static int dgram_relay_arm_rate_timer(cloak_dgram_relay_t *sr, uint64_t delay_ms);

/* True once the relay has finished, or has already decided to finish and
 * is only waiting for its deferred zero-delay timer to run the actual
 * teardown. Every entry point that could otherwise act on the relay a
 * second time before that teardown runs -- the fd's own reactor callback,
 * both notify functions and the rate timer -- checks this first. */
static int dgram_relay_is_finishing(const cloak_dgram_relay_t *sr) {
    return sr->done || sr->finish_timer != CLOAK_TIMER_INVALID;
}

static uint32_t desired_interest(const cloak_dgram_relay_t *sr) {
    uint32_t ev = 0;
    /* Also gated on !stream_ended, for the reason cloak_stream_relay_t
     * gives: once the stream has ended the session has retired it, so
     * anything read from the socket after that point could only become
     * frames the peer drops as tombstoned. */
    if (!sr->fd_read_paused && !sr->stream_ended) {
        ev |= CLOAK_REACTOR_READABLE;
    }
    if (sr->pending_len > 0) {
        ev |= CLOAK_REACTOR_WRITABLE;
    }
    return ev;
}

static void sync_interest(cloak_dgram_relay_t *sr) {
    if (sr->fd < 0) {
        return;
    }
    uint32_t want = desired_interest(sr);
    /* Suppressing the re-issue only when the mask is zero and was already
     * zero, exactly as cloak_stream_relay_t and cloak_relay_t do: epoll
     * delivers ERR/HUP regardless of the registered mask, so re-arming a
     * zero mask every turn re-delivers it forever with no path able to
     * act on it. Any non-zero mask is re-issued unconditionally, because
     * an edge-triggered fd needs the re-arm to re-report a datagram
     * already sitting in the socket buffer. */
    if (want == 0 && sr->interest == 0) {
        return;
    }
    sr->interest = want;
    (void)cloak_reactor_mod_fd(sr->reactor, sr->fd, want);
}

/* Can the session accept ONE MORE WHOLE FRAME right now? 0 means no, and
 * the caller must pause rather than read -- a datagram pulled off the
 * socket with nowhere to put it is simply lost, because unlike a byte
 * stream there is no "read less" that would leave the remainder for
 * later.
 *
 * THAT IMPOSSIBILITY IS THE WHOLE DIFFERENCE FROM
 * stream_relay_fd_read_budget, which answers in BYTES and shrinks its
 * read to whatever the pool and the token bucket will currently take.
 * Here the quantum is a datagram whose size is not known until it has
 * been read, so the only safe question is whether a WORST-CASE one would
 * fit; asking for less would mean discovering mid-read that it does not.
 * Both constraints are therefore evaluated at full frame size:
 *
 *   THE POOL, against cloak_session_send_min_conn_free -- the MINIMUM
 *   free space over every connection in the pool, not the aggregate.
 *   cloak_switchboard_send hands each whole frame to ONE connection
 *   chosen uniformly at random, so an aggregate bound stays comfortable
 *   right up until the random pick lands on the congested connection and
 *   its own hard cap fires, which breaks the whole pool and every other
 *   stream in the session. cloak/stream_relay.h argues this at length;
 *   the argument is identical here and is not repeated.
 *
 *   THE USER'S TX TOKEN BUCKET, asked for one full frame's worth. Go
 *   applies this limit by BLOCKING a goroutine (LimitedValve.txWait);
 *   this reactor has no thread to block, so the limit is applied by not
 *   reading the socket in the first place. A grant is accepted whatever
 *   its size -- cloak_valve_take_tx is advisory, and the tokens are
 *   actually spent by cloak_switchboard_send's own cloak_valve_add_tx
 *   when the frame really goes out -- so a datagram larger than a partial
 *   grant is still sent whole, putting the bucket at most one datagram in
 *   debt. That is unavoidable rather than sloppy: a datagram cannot be
 *   split to fit a byte budget, and the bucket's own debt floor is
 *   designed to absorb exactly this.
 *
 * *out_rate_delay_ms IS THE DIFFERENCE BETWEEN THE TWO ZEROES, and
 * getting it wrong is a permanent stall. A pool-bound pause is resumed by
 * the pool draining, which is an event that will happen and which
 * cloak_dgram_relay_notify_writable already handles. A bucket-bound pause
 * is resumed by nothing at all: no queue drains, the socket's readiness
 * edge is spent, and the peer has no reason to act. So this reports, in
 * milliseconds, how long the caller must arm a timer for -- non-zero if
 * and only if the bucket is the reason the answer was 0, and the caller
 * must arm it BEFORE it pauses. */
static int dgram_relay_can_accept_frame(cloak_dgram_relay_t *sr, uint64_t *out_rate_delay_ms) {
    *out_rate_delay_ms = 0;

    if (cloak_session_send_min_conn_free(sr->sesh) < cloak_stream_relay_frame_cost(sr->stream)) {
        return 0; /* pool-bound: the session's drained path owns this resume */
    }

    /* rx/tx here are the SERVER's directions, NOT the user manager's
     * up/down -- see cloak/valve.h before touching this line. A relay
     * pulling from its socket and pushing into the stream is producing
     * server-to-client traffic, i.e. tx. */
    cloak_valve_t *valve = cloak_session_valve(sr->sesh);
    int64_t allowed = cloak_valve_take_tx(valve, (int64_t)sr->pending_cap);
    if (allowed <= 0) {
        *out_rate_delay_ms = cloak_valve_tx_resume_delay_ms(valve);
        return 0;
    }
    return 1;
}

/* Tries to hand the one pending datagram to the socket. Returns 0 if the
 * relay should carry on (the datagram left, was deliberately dropped, or
 * is still waiting for a writable edge -- pending_len says which), -1 if
 * the socket is broken.
 *
 * A DATAGRAM SEND IS ALL OR NOTHING: send(2) on a SOCK_DGRAM socket never
 * reports a partial write, so a non-negative return means the whole
 * datagram left and there is nothing to retry. Comparing n against
 * pending_len would look more careful and would be dead code. */
static int flush_pending(cloak_dgram_relay_t *sr) {
    while (sr->pending_len > 0) {
        ssize_t n = send(sr->fd, sr->pending, sr->pending_len, MSG_NOSIGNAL);
        if (n >= 0) {
            sr->pending_len = 0;
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* The socket's send buffer is full. It is a CONNECTED socket,
             * so its writable edge is a real event about this one
             * destination and sync_interest's WRITABLE bit is enough to
             * resume -- the reason this needs no retry timer of the kind
             * the client's cloak_udp_piper_t has to carry, where one
             * socket serves many destinations and writability says
             * nothing about any particular one.
             *
             * NOT COVERED BY ANY TEST, and measured to be so rather than
             * assumed: dropping the held datagram here instead of keeping
             * it passes the whole suite. A loopback UDP send does not
             * block at the sizes a Cloak frame permits (task 5 measured 0
             * refusals in 20 000 AF_INET sends), so no test in this tree
             * can reach this branch at all -- the same measurement that
             * made cloak_udp_piper_adopt public so the client's own
             * backpressure cases could use an AF_UNIX socket instead.
             * Holding rather than dropping is the behaviour this module
             * intends; it rests on the reasoning above and on send(2)'s
             * documented semantics, not on a passing assertion. */
            return 0;
        }
        if (errno == EMSGSIZE || errno == ENOBUFS) {
            /* THE DATAGRAM IS UNSENDABLE, NOT THE SOCKET UNUSABLE, and
             * the distinction is what stops one bad message killing a
             * live stream. EMSGSIZE: larger than this path will carry --
             * no amount of waiting shrinks it. ENOBUFS: a device queue
             * (not the socket's own buffer) was full, which Linux reports
             * for UDP without any readiness edge that would ever say it
             * cleared. Both are "this datagram is lost", which is the
             * ordinary fate of a UDP datagram; dropping and moving on is
             * what the network would have done anyway.
             *
             * NOT COVERED BY ANY TEST IN THIS TREE, and said plainly
             * rather than implied: neither can be provoked over loopback
             * at the sizes a Cloak frame permits (the tunnel's own limit,
             * 16132 at max_on_wire_size 16401, is far below loopback's
             * 65535 datagram ceiling). This branch is written from the
             * documented semantics of send(2), not from a measurement. */
            sr->dropped_oversize++;
            sr->pending_len = 0;
            return 0;
        }
        return -1;
    }
    return 0;
}

/* Moves datagrams from the stream to the socket, one at a time, until
 * either the stream has none ready or the socket will not take the one in
 * hand. Returns 0 to continue, -1 if the relay should tear down.
 *
 * THE LOOP IS "FLUSH, THEN FILL", and never fills while something is
 * pending: this object holds exactly one datagram, so the backlog stays
 * in the stream's own receive queue where a decided overflow policy
 * already governs it (see cloak_dgram_relay's `pending` field). It
 * terminates because every iteration that repeats has moved one whole
 * datagram out of a queue that only shrinks within this call. */
static int pump_stream_to_fd(cloak_dgram_relay_t *sr) {
    for (;;) {
        if (flush_pending(sr) != 0) {
            return -1;
        }
        if (sr->pending_len > 0) {
            break; /* the socket is backed up: the writable edge resumes us */
        }
        if (sr->stream_ended) {
            break;
        }

        long n = cloak_stream_read(sr->stream, sr->pending, sr->pending_cap);
        if (n == CLOAK_STREAM_ERR_SHORT_BUFFER) {
            /* A DATAGRAM BIGGER THAN THIS TUNNEL CAN PRODUCE, which means
             * the peer is not configured like us. pending_cap is already
             * max_payload_per_frame -- the largest datagram our own
             * max_on_wire_size can carry -- so nothing will ever make it
             * fit, and no event exists that could change that.
             *
             * MUST NOT PAUSE HERE. cloak_stream_read leaves the datagram
             * queued, so a pause would be a relay that holds an open
             * socket and a live stream and never moves another byte,
             * indistinguishable from a working one until somebody notices
             * the transfer stopped. This is the same judgement
             * cloak_stream_relay_t makes for its own version of the
             * unsatisfiable case ("empty queue and it still does not
             * fit"): finish deliberately, so the owner is told. */
            sr->stream_ended = 1;
            break;
        }
        if (n < 0) {
            sr->stream_ended = 1; /* the peer closed: flush, then finish */
            break;
        }
        if (n == 0) {
            break; /* nothing queued right now */
        }
        sr->pending_len = (size_t)n;
    }

    if (sr->stream_ended && sr->pending_len == 0) {
        /* A one-way teardown trigger, not a half-close, for the reason
         * cloak_stream_relay_t states: a Cloak closing frame closes the
         * stream in BOTH directions at once, so by the time stream_ended
         * is observable here a write on this same stream would be writing
         * into a retired one. */
        return -1;
    }
    return 0;
}

/* Reads datagrams from the socket into the stream while the session can
 * take them. Returns 0 to continue, -1 if the relay should tear down.
 *
 * THE THREE RETURNS FROM recv THAT ARE NOT "A DATAGRAM ARRIVED", and all
 * three are decisions this port made differently from Go -- see
 * cloak/dgram_relay.h's size policy for the measurements behind them. */
static int pump_fd_to_stream(cloak_dgram_relay_t *sr) {
    /* SIZED BY A VALIDATED HARD BOUND, not by a hand-picked constant:
     * cloak_session_init refuses any max_on_wire_size above
     * CLOAK_CONN_MAX_FRAME_LEN, and max_payload_per_frame is that minus
     * two header constants -- so this buffer is provably at least
     * pending_cap for every session that can exist, and the recv below
     * can never be the thing that truncates. */
    uint8_t buf[CLOAK_CONN_MAX_FRAME_LEN];

    for (;;) {
        uint64_t rate_delay = 0;
        if (!dgram_relay_can_accept_frame(sr, &rate_delay)) {
            /* A pool-bound pause is re-armed by
             * cloak_dgram_relay_notify_writable when the pool drains. A
             * rate-bound pause has no such event behind it and MUST arm
             * its own timer before returning. */
            if (rate_delay > 0 && dgram_relay_arm_rate_timer(sr, rate_delay) != 0) {
                /* Could not arm. Pausing anyway is the permanent stall
                 * this mechanism exists to be incapable of, so the relay
                 * finishes instead: a closed stream the owner sees beats
                 * a live one that never moves again. */
                return -1;
            }
            sr->fd_read_paused = 1;
            return 0;
        }

        /* MSG_TRUNC IS LOAD-BEARING: on a datagram socket it makes recv
         * return the datagram's TRUE length even when the buffer was
         * smaller, which is the only way to tell "this message was too
         * big" from "this message was exactly this big". Without it the
         * excess is discarded in silence and the fragment is
         * indistinguishable from a short reply -- which is precisely
         * Go's bug 7. */
        ssize_t n = recv(sr->fd, buf, sr->pending_cap, MSG_TRUNC);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0; /* drained; the next readable edge brings more */
            }
            /* A real error on a connected datagram socket -- typically
             * ECONNREFUSED, delivered from an ICMP port-unreachable when
             * nothing is listening at the upstream address. The upstream
             * is not there; end the stream rather than spin. */
            return -1;
        }
        if (n == 0) {
            /* AN EMPTY DATAGRAM ARRIVED. NOT end of stream: a connected
             * datagram socket has no end of stream, and read()'s 0 ==
             * EOF convention -- which every other relay in this tree is
             * written against -- would let any peer tear a live stream
             * down with one empty packet.
             *
             * Swallowed rather than carried, matching Go: our frame
             * encoder refuses an empty payload (as Go's does), so there
             * is no frame it could cross in. */
            sr->swallowed_empty++;
            continue;
        }
        if ((size_t)n > sr->pending_cap) {
            /* TOO BIG FOR ONE FRAME, and one frame is all a datagram
             * gets -- cloak_stream_write refuses to split in this mode
             * because the far end does no reassembly. The kernel has
             * already discarded everything past the buffer, so the only
             * question left is whether to forward the fragment (Go's
             * answer, bug 7) or to drop the message (ours). A dropped
             * datagram is the ordinary fate of an oversized one on any
             * network; a silently truncated one is a message the
             * application cannot know it misread. */
            sr->dropped_oversize++;
            continue;
        }

        long rc = cloak_stream_write(sr->stream, buf, (size_t)n);
        if (rc == CLOAK_STREAM_ERR_SHORT_BUFFER) {
            /* UNREACHABLE AS WRITTEN -- n <= pending_cap ==
             * max_payload_per_frame is exactly the condition
             * cloak_stream_write refuses on -- and kept anyway, because
             * the alternative is the hazard this module was warned
             * about: three call sites in this tree have already treated
             * "any negative" as fatal and killed a live stream over a
             * size. If a future edit ever loosens the cap above, the
             * cost must be one dropped datagram, not a dead stream. */
            sr->dropped_oversize++;
            continue;
        }
        if (rc < 0) {
            return -1; /* the stream's write side is closed or the sink failed */
        }
    }
}

static void dgram_relay_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    cloak_dgram_relay_t *sr = (cloak_dgram_relay_t *)userdata;
    if (dgram_relay_is_finishing(sr)) {
        return;
    }

    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        if (pump_stream_to_fd(sr) != 0) {
            dgram_relay_teardown(sr, 1);
            return;
        }
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        if (pump_fd_to_stream(sr) != 0) {
            /* Best effort: push whatever the stream already delivered out
             * to the socket before closing, mirroring cloak_relay_t's and
             * cloak_stream_relay_t's teardown drain. */
            (void)pump_stream_to_fd(sr);
            dgram_relay_teardown(sr, 1);
            return;
        }
    }
    sync_interest(sr);
}

static void dgram_relay_teardown(cloak_dgram_relay_t *sr, int fire_done) {
    if (sr->done) {
        return;
    }
    sr->done = 1;

    if (sr->finish_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(sr->reactor, sr->finish_timer);
        sr->finish_timer = CLOAK_TIMER_INVALID;
    }
    if (sr->rate_timer != CLOAK_TIMER_INVALID) {
        /* A resume timer that outlived its relay fires with a dangling
         * userdata. Cancelled unconditionally here, which is the one
         * teardown path this file has. */
        cloak_reactor_cancel_timer(sr->reactor, sr->rate_timer);
        sr->rate_timer = CLOAK_TIMER_INVALID;
    }

    if (sr->fd >= 0) {
        cloak_reactor_remove_fd(sr->reactor, sr->fd);
        close(sr->fd);
        sr->fd = -1;
    }
    free(sr->pending);
    sr->pending = NULL;
    sr->pending_cap = 0;
    sr->pending_len = 0;

    /* Tell the peer the stream is over. Never release it -- that is the
     * caller's, per cloak_session_release_stream's contract. A stream
     * that already closed returns -1 here, which is fine. */
    if (sr->sesh != NULL && sr->stream != NULL) {
        (void)cloak_session_close_stream(sr->sesh, sr->stream);
    }

    if (fire_done && sr->on_done != NULL) {
        sr->on_done(sr, sr->on_done_userdata);
    }
}

/* Resumes a read paused by an empty tx bucket. The only thing that
 * brought us here is the clock.
 *
 * Re-evaluates rather than assuming, exactly as cloak_stream_relay_t's
 * equivalent does: the bucket may still be empty (the delay was a lower
 * bound, and other streams on the same user's valve may have spent what
 * it refilled), in which case this re-arms; or the POOL may have filled
 * up while this relay was paused, in which case the pause is now
 * pool-bound and notify_writable owns the resume -- and this must NOT
 * re-arm, or it would spin a timer against a condition a timer cannot
 * fix. */
static void dgram_relay_on_rate_timer(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_dgram_relay_t *sr = (cloak_dgram_relay_t *)userdata;
    sr->rate_timer = CLOAK_TIMER_INVALID;
    if (dgram_relay_is_finishing(sr) || !sr->fd_read_paused) {
        return;
    }
    uint64_t rate_delay = 0;
    if (!dgram_relay_can_accept_frame(sr, &rate_delay)) {
        if (rate_delay > 0 && dgram_relay_arm_rate_timer(sr, rate_delay) != 0) {
            dgram_relay_teardown(sr, 1);
        }
        return;
    }
    sr->fd_read_paused = 0;
    sync_interest(sr);
    /* Pull now rather than only re-arm the mask: the datagrams waiting on
     * the socket are past their readiness edge, and this mechanism must
     * not depend on a second event to finish what the timer started. */
    if (pump_fd_to_stream(sr) != 0) {
        (void)pump_stream_to_fd(sr);
        dgram_relay_teardown(sr, 1);
        return;
    }
    sync_interest(sr);
}

/* Leaves an already-pending timer alone: it will fire, find the bucket
 * still empty, and re-arm itself, so replacing it could only move the
 * deadline. Returns -1 if the timer could not be armed at all, which is
 * the one outcome the caller must not ignore. */
static int dgram_relay_arm_rate_timer(cloak_dgram_relay_t *sr, uint64_t delay_ms) {
    if (sr->rate_timer != CLOAK_TIMER_INVALID) {
        return 0;
    }
    /* delay_ms is taken verbatim: cloak/valve.h guarantees a rate-limited
     * direction never reports 0, and every caller here has already tested
     * it against 0 to decide the pause is rate-bound. */
    sr->rate_timer = cloak_reactor_add_timer(sr->reactor, delay_ms, dgram_relay_on_rate_timer, sr);
    return sr->rate_timer == CLOAK_TIMER_INVALID ? -1 : 0;
}

/* Fires the deferred teardown for a relay that was already finished by
 * the time cloak_dgram_relay_start's own initial pump ran. Runs the real,
 * full teardown rather than only the on_done call, so there stays exactly
 * one cleanup path in this file. */
static void dgram_relay_on_finish_timer(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_dgram_relay_t *sr = (cloak_dgram_relay_t *)userdata;
    sr->finish_timer = CLOAK_TIMER_INVALID;
    dgram_relay_teardown(sr, 1);
}

int cloak_dgram_relay_start(cloak_dgram_relay_t *sr, cloak_reactor_t *r, cloak_session_t *sesh,
                             cloak_stream_t *stream, int fd, cloak_dgram_relay_done_cb on_done,
                             void *userdata) {
    if (sr == NULL) {
        return -1;
    }
    /* Initialize before validating anything else, so every failure path
     * leaves a struct cloak_dgram_relay_stop can safely be called on --
     * the same ordering cloak_stream_relay_start and cloak_listener_open
     * use. */
    memset(sr, 0, sizeof(*sr));
    sr->fd = -1;
    sr->finish_timer = CLOAK_TIMER_INVALID;
    sr->rate_timer = CLOAK_TIMER_INVALID;

    if (r == NULL || sesh == NULL || stream == NULL || fd < 0 ||
        stream->max_payload_per_frame == 0) {
        return -1;
    }

    /* -2, NOT -1: the one TRANSIENT rejection this function has, and the
     * same check (against the same quantity) cloak_stream_relay_start
     * makes. A relay started against a pool that cannot hold one
     * worst-case frame would compute "no room" on its very first read
     * forever, with nothing ever queued to prompt a drain-driven resume,
     * and would hang holding an open socket with no error anywhere. */
    if (cloak_session_send_min_conn_free(sesh) < cloak_stream_relay_frame_cost(stream)) {
        return -2;
    }

    /* EXACTLY max_payload_per_frame, for the reason cloak/dgram_relay.h
     * gives: it is at once the largest datagram this stream can deliver
     * and the largest it can accept, so a smaller buffer would not be
     * slower, it would wedge. */
    sr->pending = malloc(stream->max_payload_per_frame);
    if (sr->pending == NULL) {
        return -1;
    }
    sr->pending_cap = stream->max_payload_per_frame;

    if (cloak_reactor_add_fd(r, fd, CLOAK_REACTOR_READABLE, dgram_relay_on_event, sr) != 0) {
        free(sr->pending);
        sr->pending = NULL;
        sr->pending_cap = 0;
        return -1;
    }

    sr->reactor = r;
    sr->sesh = sesh;
    sr->stream = stream;
    sr->fd = fd;
    sr->interest = CLOAK_REACTOR_READABLE;
    sr->on_done = on_done;
    sr->on_done_userdata = userdata;

    /* The stream may already hold datagrams delivered before this relay
     * existed -- on_new_stream fires with the first frame already fed,
     * and for a datagram session that frame IS a whole message. */
    if (pump_stream_to_fd(sr) != 0) {
        /* Already finished before this call could even return. on_done
         * must never fire before this function returns, so the actual
         * teardown is deferred to a zero-delay reactor timer; until it
         * fires, dgram_relay_is_finishing() freezes every other entry
         * point. */
        sr->finish_timer = cloak_reactor_add_timer(r, 0, dgram_relay_on_finish_timer, sr);
        if (sr->finish_timer == CLOAK_TIMER_INVALID) {
            /* Can't defer -- tear down for real now rather than leave the
             * relay stuck "finishing" with no way left to report
             * completion. Unwind WITHOUT taking the descriptor: a FAILED
             * start always leaves fd with the caller, and this is the one
             * path that could otherwise have consumed it. */
            cloak_reactor_remove_fd(r, fd);
            sr->fd = -1;
            dgram_relay_teardown(sr, 0);
            return -1;
        }
        return 0;
    }
    sync_interest(sr);
    return 0;
}

void cloak_dgram_relay_notify_stream_data(cloak_dgram_relay_t *sr) {
    if (sr == NULL || dgram_relay_is_finishing(sr)) {
        return;
    }
    if (pump_stream_to_fd(sr) != 0) {
        dgram_relay_teardown(sr, 1);
        return;
    }
    sync_interest(sr);
}

void cloak_dgram_relay_notify_writable(cloak_dgram_relay_t *sr) {
    if (sr == NULL || dgram_relay_is_finishing(sr) || !sr->fd_read_paused) {
        return;
    }
    uint64_t rate_delay = 0;
    if (!dgram_relay_can_accept_frame(sr, &rate_delay)) {
        /* Still no room. If the reason is now the BUCKET rather than the
         * pool, this pause has no event behind it any more and needs the
         * timer -- the drained notification that brought us here will not
         * come again for a bucket. */
        if (rate_delay > 0 && dgram_relay_arm_rate_timer(sr, rate_delay) != 0) {
            dgram_relay_teardown(sr, 1);
        }
        return;
    }
    sr->fd_read_paused = 0;
    sync_interest(sr);
    /* Pull now, for the same reason the rate timer does: the datagrams
     * waiting on the socket are past their readiness edge. */
    if (pump_fd_to_stream(sr) != 0) {
        (void)pump_stream_to_fd(sr);
        dgram_relay_teardown(sr, 1);
        return;
    }
    sync_interest(sr);
}

void cloak_dgram_relay_stop(cloak_dgram_relay_t *sr) {
    if (sr == NULL) {
        return;
    }
    dgram_relay_teardown(sr, 0);
}
