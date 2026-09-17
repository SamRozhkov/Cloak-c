#define _POSIX_C_SOURCE 200809L
#include "cloak/udp_piper.h"

#include "cloak/conn.h" /* CLOAK_CONN_RECORD_HEADER_LEN: a fixed wire-format
                         * constant, used below to compute one frame's
                         * worst-case on-wire cost exactly as
                         * libcloak-mux/src/stream_relay.c does -- not a
                         * reach into any per-connection state. */
#include "cloak/frame.h"
#include "cloak/log.h"
#include "cloak/net.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* The receive scratch buffer, on the stack of the read loop.
 *
 * 65536 IS A PROOF, NOT A GUESS: an IPv4 or IPv6 UDP datagram cannot
 * exceed 65507 bytes (the 16-bit UDP length field), so no datagram this
 * socket can ever receive is larger than this buffer, and the only thing
 * that ever bounds a read below it is the session's own
 * max_payload_per_frame. Sizing it this way removes an allocation and its
 * failure path from the hot path entirely -- and the failure path is the
 * point: a receive buffer that could fail to exist would need a policy
 * for datagrams arriving while it does not, which is a state this module
 * would then have to be correct in for no benefit. */
#define UDP_PIPER_RX_BUF ((size_t)65536)

static uint64_t udp_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int set_err(char *err, size_t cap, const char *fmt, ...) {
    if (err != NULL && cap > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, cap, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* ---- peer identity ------------------------------------------------------
 *
 * Go keys its map by addr.String(). This compares the address itself, and
 * PER FAMILY rather than by memcmp over the sockaddr_storage, because two
 * of the fields in those structures are not part of a peer's identity:
 *
 *   sockaddr_in::sin_zero    padding. The kernel zeroes it on recvfrom
 *                            today, which is exactly what makes a memcmp
 *                            look correct until something (a different
 *                            libc, a VM, a future kernel) stops doing so,
 *                            at which point one peer becomes two silently.
 *   sockaddr_in6::sin6_flowinfo  a traffic-class/flow-label hint the
 *                            sender may vary AT WILL between datagrams of
 *                            the same flow. Comparing it would give one
 *                            peer a new stream whenever it changed.
 *                            sin6_scope_id IS compared: a link-local
 *                            address means nothing without it.
 *
 * Anything else (AF_UNIX, which this module supports because a datagram
 * socket is a datagram socket -- see cloak_udp_piper_adopt) is compared
 * over exactly the bytes recvfrom reported, which for AF_UNIX is the
 * family plus the bound name. */
static int peer_addr_equal(const struct sockaddr_storage *a, socklen_t alen,
                           const struct sockaddr_storage *b, socklen_t blen) {
    if (a->ss_family != b->ss_family) {
        return 0;
    }
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *x = (const struct sockaddr_in *)(const void *)a;
        const struct sockaddr_in *y = (const struct sockaddr_in *)(const void *)b;
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)(const void *)a;
        const struct sockaddr_in6 *y = (const struct sockaddr_in6 *)(const void *)b;
        return x->sin6_port == y->sin6_port && x->sin6_scope_id == y->sin6_scope_id &&
               memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) == 0;
    }
    return alen == blen && memcmp(a, b, (size_t)alen) == 0;
}

/* Whether a source address recvfrom reported can identify a peer at all.
 *
 * AN UNADDRESSED SENDER IS REFUSED RATHER THAN GIVEN A PEER, and this is
 * a correctness guard, not tidiness: an AF_UNIX datagram socket that
 * never bound a name has no address, so recvfrom reports a length of
 * offsetof(sun_path) with no path. EVERY such sender would compare equal
 * to every other, so they would all share one stream and each would
 * receive the others' replies -- the exact cross-peer leak case 1 exists
 * to rule out. There is also nothing to reply to. */
static int peer_addr_usable(const struct sockaddr_storage *a, socklen_t len) {
    if (len == 0 || (size_t)len > sizeof(*a)) {
        return 0;
    }
    if (a->ss_family == AF_INET) {
        return (size_t)len >= sizeof(struct sockaddr_in);
    }
    if (a->ss_family == AF_INET6) {
        return (size_t)len >= sizeof(struct sockaddr_in6);
    }
    if (a->ss_family == AF_UNIX) {
        return (size_t)len > offsetof(struct sockaddr_un, sun_path);
    }
    return 1;
}

/* ---- list bookkeeping ---------------------------------------------------
 *
 * An intrusive list and a linear scan, the same structure
 * cloak_client_piper_t uses and for the same reason: the count is bounded
 * by max_peers, Go's own map is not consulted any more cleverly per
 * datagram than this, and a second structure would be a second thing to
 * keep in step with the list across every teardown path -- which is the
 * one place these modules have historically been fragile. The scan is
 * O(peers) per datagram; at the 256-peer default that is a few hundred
 * pointer comparisons on a path that has just performed a syscall. */
static void peer_link(cloak_udp_piper_t *pp, cloak_udp_piper_peer_t *peer) {
    peer->prev = NULL;
    peer->next = pp->peers;
    if (pp->peers != NULL) {
        pp->peers->prev = peer;
    }
    pp->peers = peer;
    pp->peer_count++;
}

static void peer_unlink(cloak_udp_piper_t *pp, cloak_udp_piper_peer_t *peer) {
    if (peer->prev != NULL) {
        peer->prev->next = peer->next;
    } else {
        pp->peers = peer->next;
    }
    if (peer->next != NULL) {
        peer->next->prev = peer->prev;
    }
    peer->prev = NULL;
    peer->next = NULL;
    pp->peer_count--;
}

static cloak_udp_piper_peer_t *peer_find_addr(cloak_udp_piper_t *pp,
                                              const struct sockaddr_storage *addr,
                                              socklen_t len) {
    for (cloak_udp_piper_peer_t *p = pp->peers; p != NULL; p = p->next) {
        if (peer_addr_equal(&p->addr, p->addr_len, addr, len)) {
            return p;
        }
    }
    return NULL;
}

static cloak_udp_piper_peer_t *peer_find_stream(cloak_udp_piper_t *pp, const cloak_session_t *sesh,
                                                const cloak_stream_t *stream) {
    for (cloak_udp_piper_peer_t *p = pp->peers; p != NULL; p = p->next) {
        if (p->sesh == sesh && p->stream == stream) {
            return p;
        }
    }
    return NULL;
}

/* ---- teardown ----------------------------------------------------------
 *
 * THE ONE COPY, for the same reason cloak_client_piper_t has one: four
 * paths reach it (the deadline, an ended stream, the broken session and
 * cloak_udp_piper_destroy) and two copies of the most lifetime-sensitive
 * code in a module drifting apart is the worst outcome available.
 *
 * `expired` distinguishes the deadline from every other cause, because
 * "the peer count returned to zero" is satisfied by a piper that never
 * created the peer and by one that dropped it for the wrong reason. */
static void peer_retire(cloak_udp_piper_peer_t *peer, int expired) {
    cloak_udp_piper_t *pp = peer->pp;

    if (peer->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(pp->cfg.reactor, peer->deadline);
        peer->deadline = CLOAK_TIMER_INVALID;
    }
    if (peer->send_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(pp->cfg.reactor, peer->send_timer);
        peer->send_timer = CLOAK_TIMER_INVALID;
    }

    if (peer->stream != NULL) {
        /* HARVEST D5'S COUNTER BEFORE THE STREAM GOES AWAY. It lives on
         * the cloak_stream_t and dies with it, and a drop total that fell
         * every time a peer retired would be useless to the operator it
         * exists for -- the peers that drop are exactly the peers that
         * then go away. */
        pp->retired_dropped += peer->stream->recv_dropped_datagrams;
        if (peer->sesh != NULL) {
            /* Performs the active close itself when the stream has not
             * already been closed, so the far end learns now rather than
             * waiting out a timeout. cloak/session.h requires exactly one
             * release per stream; this is the only place this module
             * makes it. */
            cloak_session_release_stream(peer->sesh, peer->stream);
        }
        peer->stream = NULL;
    }
    peer->sesh = NULL;

    free(peer->out);
    peer->out = NULL;
    peer_unlink(pp, peer);
    free(peer);
    if (expired) {
        pp->peers_expired++;
    }
}

/* ---- the outbound half: stream -> local socket -------------------------- */

static void peer_on_send_timer(cloak_reactor_t *r, void *userdata);

static void peer_touch(cloak_udp_piper_peer_t *peer) {
    peer->last_activity_ms = udp_now_ms();
}

/* Tries to hand peer->out to the local socket. Returns 0 if the slot is
 * now free (sent, or discarded because this destination can never take
 * it), -1 if the datagram is still pending and a retry timer is armed.
 *
 * ON -1 THE CALLER MUST STOP DRAINING THAT PEER'S STREAM, which is what
 * makes the backlog land in the stream's own datagram queue -- where D5's
 * drop policy applies, per peer, with no effect on anyone else. */
static int peer_flush(cloak_udp_piper_peer_t *peer) {
    cloak_udp_piper_t *pp = peer->pp;
    if (peer->out_len == 0) {
        return 0;
    }
    if (pp->fd < 0) {
        return -1;
    }
    for (;;) {
        ssize_t n = sendto(pp->fd, peer->out, peer->out_len, MSG_NOSIGNAL,
                           (const struct sockaddr *)&peer->addr, peer->addr_len);
        if (n >= 0) {
            peer->out_len = 0;
            if (peer->send_timer != CLOAK_TIMER_INVALID) {
                cloak_reactor_cancel_timer(pp->cfg.reactor, peer->send_timer);
                peer->send_timer = CLOAK_TIMER_INVALID;
            }
            peer_touch(peer); /* a datagram delivered in either direction */
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
            /* BACKPRESSURE, AND THE ONLY THING THAT WILL CLEAR IT IS
             * TIME. See cloak/udp_piper.h: on a datagram socket sending to
             * many destinations this can mean the DESTINATION's queue is
             * full, which our own socket's writability says nothing about
             * -- so a WRITABLE registration would fire immediately and
             * forever without the condition having changed. The same
             * argument cloak_stream_relay_t's rate_timer makes, and the
             * same consequence if it is skipped: a peer that holds a
             * stream and never moves another byte. */
            pp->send_stalls++;
            if (peer->send_timer == CLOAK_TIMER_INVALID) {
                peer->send_timer = cloak_reactor_add_timer(
                    pp->cfg.reactor, pp->cfg.send_retry_delay_ms, peer_on_send_timer, peer);
                if (peer->send_timer == CLOAK_TIMER_INVALID) {
                    /* No way left to ever retry, so the peer would hold a
                     * stream forever and never move. Retire it instead:
                     * a closed stream the far end sees beats a live one
                     * that is never served again. */
                    peer_retire(peer, 0);
                    return -1;
                }
            }
            /* DELIBERATELY NOT peer_touch: a refused send is not
             * activity. If it counted, a peer that can neither send nor
             * receive would keep its own deadline alive by failing, and
             * the deadline is the only bound on how long this slot may
             * stay occupied. */
            return -1;
        }
        /* A hard, destination-specific error: the AF_UNIX peer's socket
         * is gone (ECONNREFUSED), the datagram is larger than this
         * socket can ever send (EMSGSIZE), a firewall said no (EPERM).
         * Retrying cannot help THIS datagram, so it is discarded and the
         * peer carries on -- its deadline will retire it if nothing ever
         * moves again. Logged once per piper, because a misbehaving local
         * application must not be able to produce one line per
         * datagram. */
        if (!pp->logged_dropped) {
            pp->logged_dropped = 1;
            CLOAK_LOGW("udp piper: sendto to a local peer failed (%s) -- that datagram is "
                       "discarded and the peer kept; further occurrences are not logged",
                       strerror(errno));
        }
        peer->out_len = 0;
        if (peer->send_timer != CLOAK_TIMER_INVALID) {
            cloak_reactor_cancel_timer(pp->cfg.reactor, peer->send_timer);
            peer->send_timer = CLOAK_TIMER_INVALID;
        }
        return 0;
    }
}

/* Moves whole datagrams from one peer's stream to the local socket, one
 * at a time, stopping the instant the socket refuses one. peer may be
 * freed by the time this returns. */
static void peer_drain(cloak_udp_piper_peer_t *peer) {
    cloak_udp_piper_t *pp = peer->pp;
    if (peer->stream == NULL) {
        return;
    }
    if (peer_flush(peer) != 0) {
        return; /* still pending, or the peer is gone */
    }
    for (;;) {
        long n = cloak_stream_read(peer->stream, peer->out, peer->out_cap);
        if (n == 0) {
            return; /* nothing queued right now */
        }
        if (n == CLOAK_STREAM_ERR_SHORT_BUFFER) {
            /* STRUCTURALLY UNREACHABLE, AND HANDLED ANYWAY -- as
             * backpressure, never as EOF. out_cap is the stream's own
             * max_payload_per_frame, and no frame the stream can accept
             * carries more than that, so no queued datagram can be too
             * big for this buffer. It is handled because the cost of
             * being wrong is the exact defect this port exists not to
             * repeat: Go's reader breaks its loop on io.ErrShortBuffer
             * exactly as it does on io.EOF, which silently tears down a
             * live tunnel over a reply of 8193..16132 bytes (scouting
             * report §6.6, bug 6). Returning leaves the datagram queued
             * -- cloak/stream.h guarantees a short buffer consumes
             * nothing -- and the peer's deadline is the bound on how long
             * that can persist, which is the non-wedging answer
             * cloak_stream_relay_t does not have available to it (it
             * holds a descriptor with no deadline behind it and must
             * therefore finish instead). */
            if (!pp->logged_dropped) {
                pp->logged_dropped = 1;
                CLOAK_LOGW("udp piper: a queued datagram did not fit this peer's read buffer -- "
                           "it stays queued; this should be unreachable, please report it");
            }
            return;
        }
        if (n < 0) {
            /* End of stream: the far end closed it, or the session
             * retired it. Go's reader goroutine does exactly this --
             * break, delete its own key, close the stream. */
            peer_retire(peer, 0);
            return;
        }
        peer->out_len = (size_t)n;
        peer_touch(peer); /* Go refreshes the deadline on every read too */
        if (peer_flush(peer) != 0) {
            return;
        }
    }
}

static void peer_on_send_timer(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_udp_piper_peer_t *peer = userdata;
    peer->send_timer = CLOAK_TIMER_INVALID;
    /* Re-attempts the flush AND resumes the drain: the stream may have
     * accumulated more while this peer was stalled, and nothing else will
     * come along to notice -- a frame that arrived during the stall
     * already fired its on_stream_data and found the slot occupied. */
    peer_drain(peer);
}

/* ---- the deadline ------------------------------------------------------- */

static int peer_arm_deadline(cloak_udp_piper_peer_t *peer, uint64_t delay_ms);

/* Go's stream read deadline, expressed as a LAZY timer: refreshing it is
 * a single store to last_activity_ms on the hot path, and this re-checks
 * the clock when it fires. The cost is at most one extra firing per
 * timeout period; the saving is a cancel plus an add per datagram, which
 * at one datagram per timer pair is what a busy VPN peer would otherwise
 * be doing all day. */
static void peer_on_deadline(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_udp_piper_peer_t *peer = userdata;
    cloak_udp_piper_t *pp = peer->pp;
    peer->deadline = CLOAK_TIMER_INVALID;

    uint64_t now = udp_now_ms();
    uint64_t idle = now - peer->last_activity_ms;
    if (idle < pp->cfg.peer_timeout_ms) {
        if (peer_arm_deadline(peer, pp->cfg.peer_timeout_ms - idle) == 0) {
            return;
        }
        /* Could not re-arm: retire now rather than leave a peer with no
         * bound on its life at all, which is the one thing this timer
         * exists to prevent. */
    }
    peer_retire(peer, 1);
}

static int peer_arm_deadline(cloak_udp_piper_peer_t *peer, uint64_t delay_ms) {
    peer->deadline =
        cloak_reactor_add_timer(peer->pp->cfg.reactor, delay_ms, peer_on_deadline, peer);
    return peer->deadline == CLOAK_TIMER_INVALID ? -1 : 0;
}

/* ---- peer creation ------------------------------------------------------ */

static cloak_udp_piper_peer_t *peer_create(cloak_udp_piper_t *pp,
                                           const struct sockaddr_storage *addr, socklen_t len) {
    if (pp->sesh == NULL || pp->peer_count >= pp->cfg.max_peers) {
        return NULL;
    }
    cloak_udp_piper_peer_t *peer = calloc(1, sizeof(*peer));
    if (peer == NULL) {
        return NULL;
    }
    peer->pp = pp;
    peer->deadline = CLOAK_TIMER_INVALID;
    peer->send_timer = CLOAK_TIMER_INVALID;
    memcpy(&peer->addr, addr, sizeof(*addr));
    peer->addr_len = len;

    peer->stream = cloak_session_open_stream(pp->sesh, NULL);
    if (peer->stream == NULL) {
        free(peer);
        return NULL;
    }
    peer->sesh = pp->sesh;
    /* THE BUFFER IS SIZED FROM THE STREAM ITSELF, not from a constant of
     * this module's: it is exactly the largest datagram that stream can
     * ever deliver, which is what makes CLOAK_STREAM_ERR_SHORT_BUFFER
     * unreachable in peer_drain rather than merely unlikely. */
    peer->out_cap = peer->stream->max_payload_per_frame;
    peer->out = malloc(peer->out_cap);
    if (peer->out == NULL) {
        cloak_session_release_stream(peer->sesh, peer->stream);
        free(peer);
        return NULL;
    }
    peer_touch(peer);
    peer_link(pp, peer);
    if (peer_arm_deadline(peer, pp->cfg.peer_timeout_ms) != 0) {
        /* A peer with no deadline is an unbounded resource pin held by an
         * unauthenticated source address -- refuse it rather than admit
         * one. peer_retire performs the whole unwind, so there is one
         * cleanup path here as everywhere else. */
        peer_retire(peer, 0);
        return NULL;
    }
    pp->peers_created++;
    return peer;
}

/* ---- the inbound half: local socket -> stream --------------------------- */

static uint32_t desired_interest(const cloak_udp_piper_t *pp) {
    /* READABLE or nothing. WRITABLE is never registered: a datagram
     * socket is essentially always writable, so an interest in it would
     * fire every turn forever, and its readiness says nothing about
     * whether a particular DESTINATION can take a datagram -- which is
     * the only question this module ever has about sending. See
     * peer_flush. */
    return pp->read_paused ? 0u : CLOAK_REACTOR_READABLE;
}

static void sync_interest(cloak_udp_piper_t *pp) {
    if (pp->fd < 0 || !pp->fd_registered) {
        return;
    }
    uint32_t want = desired_interest(pp);
    /* Suppressed only when the mask is zero and was already zero, the
     * same rule cloak_stream_relay_t applies: epoll reports ERR/HUP
     * regardless of the registered mask, so re-arming a zero mask every
     * turn re-delivers it forever; any non-zero mask is re-issued
     * unconditionally because an edge-triggered fd needs the re-arm to
     * re-report data already sitting in the socket buffer. */
    if (want == 0 && pp->interest == 0) {
        return;
    }
    pp->interest = want;
    (void)cloak_reactor_mod_fd(pp->cfg.reactor, pp->fd, want);
}

/* One frame's worst-case on-wire cost, identical to
 * stream_relay_frame_cost_for by construction rather than by
 * coincidence: that function computes RECORD_HEADER + max_payload +
 * FRAME_HEADER + MAX_EXTRA, and max_payload is defined as
 * max_on_wire_size - FRAME_HEADER - MAX_EXTRA, so the two reduce to the
 * same sum. Written in the session's own terms here because this module
 * needs the number BEFORE it has a stream to ask -- the read that would
 * create the peer is the read being budgeted. */
static size_t piper_frame_cost(const cloak_session_t *sesh) {
    return (size_t)CLOAK_CONN_RECORD_HEADER_LEN + sesh->max_on_wire_size;
}

static size_t piper_read_cap(const cloak_session_t *sesh) {
    size_t overhead = (size_t)CLOAK_FRAME_HEADER_LEN + (size_t)CLOAK_FRAME_MAX_EXTRA_LEN;
    size_t wire = sesh->max_on_wire_size;
    /* A session whose wire size cannot hold a header could not have been
     * constructed (cloak_stream_init rejects it), so this floor is a
     * guarantee that the cap is never 0 rather than a supported
     * configuration -- and a cap of 0 would make every datagram look
     * oversized. */
    size_t cap = wire > overhead ? wire - overhead : 1;
    if (cap > UDP_PIPER_RX_BUF) {
        cap = UDP_PIPER_RX_BUF;
    }
    return cap;
}

/* Drains the local socket into the peers' streams until it is empty, the
 * session's outbound pool is full, or the socket errors.
 *
 * NOTHING HERE EVER STOPS BECAUSE OF ONE PEER. A datagram that cannot be
 * turned into a frame -- oversized, empty, from a peer that cannot be
 * created, or for a stream that just broke -- is accounted for and the
 * loop CONTINUES, because the next datagram in the socket almost
 * certainly belongs to somebody else. The only whole-socket pause is the
 * pool one, which is a session-wide condition and affects every peer
 * equally by definition. */
static void piper_pump_read(cloak_udp_piper_t *pp) {
    uint8_t buf[UDP_PIPER_RX_BUF];

    pp->in_read_loop = 1;
    for (;;) {
        if (pp->fd < 0) {
            break;
        }
        size_t cap = 1;
        if (pp->sesh != NULL) {
            /* THE BUDGET, re-derived before every single read, exactly as
             * cloak_stream_relay_t re-derives its own. One datagram is
             * one frame in this mode, so the question is simply whether
             * the LEAST free connection in the pool could hold one more
             * worst-case frame -- the minimum and not the aggregate,
             * because cloak_switchboard_send hands each whole frame to
             * ONE connection chosen at random and a pool that is roomy on
             * average can still break on the congested one, which is
             * fatal to the whole session. cloak_stream_write cannot fail
             * on a full queue, so there is no second chance after this
             * check. */
            if (cloak_session_send_min_conn_free(pp->sesh) < piper_frame_cost(pp->sesh)) {
                if (!pp->read_paused) {
                    pp->read_paused = 1;
                    pp->pool_pauses++;
                }
                break;
            }
            cap = piper_read_cap(pp->sesh);
        }

        struct sockaddr_storage from;
        socklen_t from_len = sizeof(from);
        memset(&from, 0, sizeof(from));
        /* MSG_TRUNC IS WHAT MAKES D7 POSSIBLE: it returns the datagram's
         * TRUE length even when only `cap` bytes were copied, so an
         * oversized datagram is identified rather than silently truncated
         * -- which is precisely what Go does instead (its 8192-byte
         * buffer, piper.go:25, bug 7). Without it the only evidence would
         * be a read that exactly filled the buffer, which is also what a
         * legitimate maximum-size datagram looks like. */
        ssize_t n = recvfrom(pp->fd, buf, cap, MSG_TRUNC, (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break; /* drained */
            }
            /* Anything else is reported once and the loop stops for this
             * turn. The socket is NOT closed: it is the whole client's
             * local endpoint, shared by every peer, and a transient
             * per-datagram error (an ICMP report delivered to a connected
             * socket, for instance) must not take the listener down. */
            if (!pp->logged_dropped) {
                pp->logged_dropped = 1;
                CLOAK_LOGW("udp piper: recvfrom on the local socket failed (%s); further "
                           "occurrences are not logged",
                           strerror(errno));
            }
            break;
        }

        if (!peer_addr_usable(&from, from_len)) {
            pp->refused_peers++;
            continue;
        }

        if ((size_t)n > cap) {
            /* OVER ONE FRAME'S PAYLOAD: refused WHOLE. Go truncates and
             * sends the front of it, which the application cannot detect;
             * splitting it would be worse still, because the far end does
             * no reassembly in this mode and would deliver two datagrams
             * where one was sent. The peer, if it already exists, is left
             * alive and its deadline refreshed -- it did send something. */
            pp->oversize_datagrams++;
            cloak_udp_piper_peer_t *known = peer_find_addr(pp, &from, from_len);
            if (known != NULL) {
                peer_touch(known);
            }
            continue;
        }

        if (n == 0) {
            /* A ZERO-LENGTH DATAGRAM, which on a datagram socket is a
             * real message and NOT end-of-file -- treating it as EOF here
             * would stop serving every peer on the socket. It is
             * swallowed, matching Go: its Write loop never runs for an
             * empty input and returns (0, nil), and no frame encoder on
             * either side will carry an empty payload. An UNKNOWN sender
             * does not get a peer for it (Go would open a stream and then
             * write nothing into it); a known one is refreshed, because
             * it did speak. */
            pp->empty_datagrams++;
            cloak_udp_piper_peer_t *known = peer_find_addr(pp, &from, from_len);
            if (known != NULL) {
                peer_touch(known);
            }
            continue;
        }

        cloak_udp_piper_peer_t *peer = peer_find_addr(pp, &from, from_len);
        if (peer == NULL) {
            peer = peer_create(pp, &from, from_len);
            if (peer == NULL) {
                pp->refused_peers++;
                if (!pp->logged_refused_peer) {
                    pp->logged_refused_peer = 1;
                    CLOAK_LOGW("udp piper: refusing a local peer -- %zu already held (the "
                               "configured maximum is %zu), or no session is up; further "
                               "refusals are counted but not logged",
                               pp->peer_count, pp->cfg.max_peers);
                }
                continue;
            }
        }
        peer_touch(peer);
        /* ONE DATAGRAM IS ONE WRITE IS ONE FRAME. n is at most cap, which
         * is the stream's max_payload_per_frame, so this can never be the
         * refusal cloak/stream.h describes -- the oversized case was
         * dealt with above, on the socket, where the whole datagram is
         * still available to be refused as a unit. */
        if (cloak_stream_write(peer->stream, buf, (size_t)n) < 0) {
            /* cloak/stream.h: a failed write leaves the stream unusable
             * and the caller must tear it down. One peer dies; the loop
             * carries on with the next datagram, which is almost
             * certainly somebody else's. */
            peer_retire(peer, 0);
            continue;
        }
        peer_touch(peer);
    }
    pp->in_read_loop = 0;
    sync_interest(pp);
}

static void piper_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    (void)events;
    cloak_udp_piper_t *pp = userdata;
    piper_pump_read(pp);
}

/* ---- session callbacks --------------------------------------------------- */

/* THE SERVER OPENED A STREAM TOWARD US, which in this transport is a
 * protocol violation: every stream is client-initiated and the server's
 * data path only ever accepts. The full argument -- why refusing beats
 * ignoring (an ignored stream leaks for the life of the session and keeps
 * its inactivity timeout from ever firing, both under a remote peer's
 * control), why it beats accepting (there is no local peer to splice it
 * to, and inventing one would be a reverse proxy), and why the ceiling is
 * per session -- is in cloak/client_piper.h and is not repeated here. */
static void piper_on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    cloak_udp_piper_t *pp = userdata;
    if (pp == NULL || sesh == NULL || stream == NULL) {
        return;
    }
    pp->rejected_streams++;
    pp->shared_rejected_streams++;
    if (!pp->logged_rejected_stream) {
        pp->logged_rejected_stream = 1;
        CLOAK_LOGW("udp piper: the server opened a stream toward this client -- refusing. Every "
                   "stream in this protocol is client-initiated, so this is a server bug or a "
                   "server that is not the one we think it is; further occurrences on this "
                   "session are counted but not logged");
    }
    cloak_session_release_stream(sesh, stream);

    /* >= rather than ==: an exact-equality trigger is one miscount away
     * from never firing, and never firing is the unbounded tombstone
     * amplification this branch exists to bound. */
    if (pp->shared_rejected_streams >= CLOAK_UDP_PIPER_MAX_REJECTED_STREAMS) {
        CLOAK_LOGW("udp piper: %zu streams opened toward this client on one session and refused "
                   "-- closing that session",
                   pp->shared_rejected_streams);
        (void)cloak_session_close(sesh);
    }
}

static void piper_on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    cloak_udp_piper_t *pp = userdata;
    if (pp == NULL || stream == NULL) {
        return;
    }
    cloak_udp_piper_peer_t *peer = peer_find_stream(pp, sesh, stream);
    if (peer != NULL) {
        peer_drain(peer); /* peer may be freed by this */
    }
}

static void piper_on_writable(cloak_session_t *sesh, void *userdata) {
    cloak_udp_piper_t *pp = userdata;
    if (pp == NULL || pp->sesh != sesh || !pp->read_paused) {
        return;
    }
    pp->read_paused = 0;
    if (pp->in_read_loop) {
        /* Re-entered from inside the read loop's own cloak_stream_write
         * (cloak/session.h permits this callback to fire synchronously
         * from a write). The loop re-derives the budget at the top of
         * every iteration, so clearing the flag is the whole of the
         * resume; calling back into the loop from here would run two
         * copies of it over one socket. */
        return;
    }
    sync_interest(pp);
    /* Pull now rather than only re-arm the mask: the readability edge for
     * whatever is already sitting in the socket is spent, and this
     * mechanism must not depend on a second datagram arriving to finish
     * what the drain started -- the same reason
     * stream_relay_on_rate_timer pumps rather than merely re-arming. */
    piper_pump_read(pp);
}

/* THE ONLY WINDOW IN WHICH A STREAM BOUND TO THIS SESSION CAN STILL BE
 * RELEASED. cloak_session_broken_cb's contract is that immediately after
 * this returns every still-active stream is destroyed and freed, so the
 * walk runs first and the session pointer is cleared only after it --
 * peer_retire needs a live session to release to, and this is the last
 * moment that is true. The chain runs last because cloak/session.h
 * permits a callback in that position to call cloak_session_destroy. */
static void piper_on_broken(cloak_session_t *sesh, void *userdata) {
    cloak_udp_piper_t *pp = userdata;
    if (pp == NULL) {
        return;
    }
    cloak_udp_piper_peer_t *peer = pp->peers;
    while (peer != NULL) {
        cloak_udp_piper_peer_t *next = peer->next;
        if (peer->sesh == sesh) {
            peer_retire(peer, 0);
        }
        peer = next;
    }
    if (pp->sesh == sesh) {
        pp->sesh = NULL;
    }
    if (pp->cfg.chain != NULL) {
        pp->cfg.chain(sesh, pp->cfg.chain_userdata);
    }
}

/* ---- public entry points -------------------------------------------------- */

int cloak_udp_piper_init(cloak_udp_piper_t *pp, const cloak_udp_piper_config_t *cfg) {
    if (pp == NULL) {
        return -1;
    }
    /* Fully initialize BEFORE validating anything else, so every failure
     * return leaves pp safe to pass to cloak_udp_piper_destroy. */
    memset(pp, 0, sizeof(*pp));
    pp->fd = -1;
    pp->port = -1;

    if (cfg == NULL || cfg->reactor == NULL) {
        return -1;
    }
    pp->cfg = *cfg;
    if (pp->cfg.peer_timeout_ms == 0) {
        pp->cfg.peer_timeout_ms = CLOAK_UDP_PIPER_DEFAULT_PEER_TIMEOUT_MS;
    }
    if (pp->cfg.max_peers == 0) {
        pp->cfg.max_peers = CLOAK_UDP_PIPER_DEFAULT_MAX_PEERS;
    }
    if (pp->cfg.send_retry_delay_ms == 0) {
        pp->cfg.send_retry_delay_ms = CLOAK_UDP_PIPER_DEFAULT_SEND_RETRY_MS;
    }
    return 0;
}

void cloak_udp_piper_install(cloak_udp_piper_t *pp, cloak_session_config_t *config) {
    if (pp == NULL || config == NULL) {
        return;
    }
    config->on_new_stream = piper_on_new_stream;
    config->on_new_stream_userdata = pp;
    config->on_stream_data = piper_on_stream_data;
    config->on_stream_data_userdata = pp;
    config->on_writable = piper_on_writable;
    config->on_writable_userdata = pp;
    config->on_broken = piper_on_broken;
    config->on_broken_userdata = pp;
}

void cloak_udp_piper_set_session(cloak_udp_piper_t *pp, cloak_session_t *sesh) {
    if (pp == NULL) {
        return;
    }
    pp->sesh = sesh;
    /* A different session gets a fresh refusal budget and a fresh first
     * log line: the tombstones the ceiling bounds live in ONE session's
     * table, so carrying the count across would leave every session after
     * the first unbounded. The lifetime total is deliberately not
     * reset. */
    pp->shared_rejected_streams = 0;
    pp->logged_rejected_stream = 0;
    if (sesh != NULL && pp->read_paused) {
        /* A pause taken against the PREVIOUS session has no drain behind
         * it any more: nothing will ever fire on_writable for a session
         * that is gone. Clearing it here is what stops a replacement
         * session from inheriting a socket that is never read again. */
        pp->read_paused = 0;
        sync_interest(pp);
    }
}

static int bound_port(int fd) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &len) != 0) {
        return -1;
    }
    if (ss.ss_family == AF_INET) {
        return (int)ntohs(((struct sockaddr_in *)(void *)&ss)->sin_port);
    }
    if (ss.ss_family == AF_INET6) {
        return (int)ntohs(((struct sockaddr_in6 *)(void *)&ss)->sin6_port);
    }
    return -1;
}

int cloak_udp_piper_adopt(cloak_udp_piper_t *pp, int fd) {
    if (pp == NULL || fd < 0 || pp->fd >= 0 || pp->cfg.reactor == NULL) {
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -1;
    }
    if (cloak_reactor_add_fd(pp->cfg.reactor, fd, CLOAK_REACTOR_READABLE, piper_on_event, pp) !=
        0) {
        /* The CALLER still owns fd on every failure, so nothing is closed
         * here -- the uniform rule cloak_stream_relay_start states, kept
         * uniform for the same reason: a documented exception a caller
         * gets wrong is a double close, which no sanitizer detects. */
        return -1;
    }
    pp->fd = fd;
    pp->fd_registered = 1;
    pp->interest = CLOAK_REACTOR_READABLE;
    pp->port = bound_port(fd);
    /* An already-bound socket may have datagrams waiting; EPOLL_CTL_ADD
     * reports an fd that is already readable, but pumping here as well
     * costs one syscall and removes the dependence entirely. */
    piper_pump_read(pp);
    return 0;
}

int cloak_udp_piper_open(cloak_udp_piper_t *pp, const char *addr, char *err, size_t err_cap) {
    if (pp == NULL || addr == NULL) {
        return set_err(err, err_cap, "udp piper: invalid argument");
    }
    if (pp->fd >= 0) {
        return set_err(err, err_cap, "udp piper: already open");
    }

    char host[256];
    char port[16];
    if (cloak_net_split_hostport(addr, host, sizeof(host), port, sizeof(port)) != 0) {
        return set_err(err, err_cap, "udp piper: malformed address %s", addr);
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host[0] != '\0' ? host : NULL, port, &hints, &res);
    if (rc != 0) {
        return set_err(err, err_cap, "udp piper: cannot resolve %s: %s", addr, gai_strerror(rc));
    }

    int last_errno = 0;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                        ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }
        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (ai->ai_family == AF_INET6 && host[0] == '\0') {
            int zero = 0;
            (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
        }
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            last_errno = errno;
            close(fd);
            continue;
        }
        if (cloak_udp_piper_adopt(pp, fd) != 0) {
            last_errno = errno;
            close(fd); /* adopt leaves fd with the caller on failure */
            continue;
        }
        freeaddrinfo(res);
        return 0;
    }
    freeaddrinfo(res);
    return set_err(err, err_cap, "udp piper: cannot bind %s: %s", addr,
                   last_errno != 0 ? strerror(last_errno) : "no usable address");
}

int cloak_udp_piper_port(const cloak_udp_piper_t *pp) {
    return (pp == NULL || pp->fd < 0) ? -1 : pp->port;
}

void cloak_udp_piper_destroy(cloak_udp_piper_t *pp) {
    if (pp == NULL) {
        return;
    }
    /* Idempotent and safe on a zeroed struct: a zeroed piper has no
     * peers, so the loop does not run, and fd is 0 only if init was never
     * called -- which is why init sets it to -1 before validating
     * anything. */
    while (pp->peers != NULL) {
        peer_retire(pp->peers, 0);
    }
    if (pp->fd >= 0) {
        if (pp->fd_registered) {
            cloak_reactor_remove_fd(pp->cfg.reactor, pp->fd);
            pp->fd_registered = 0;
        }
        close(pp->fd);
        pp->fd = -1;
        pp->port = -1;
        pp->interest = 0;
    }
}

size_t cloak_udp_piper_peer_count(const cloak_udp_piper_t *pp) {
    return pp == NULL ? 0 : pp->peer_count;
}

size_t cloak_udp_piper_peers_created(const cloak_udp_piper_t *pp) {
    return pp == NULL ? 0 : pp->peers_created;
}

size_t cloak_udp_piper_peers_expired(const cloak_udp_piper_t *pp) {
    return pp == NULL ? 0 : pp->peers_expired;
}

/* O(peers), and a LIFETIME total: the live peers' streams still hold
 * their own counters, and every retired peer's final value was harvested
 * into retired_dropped by peer_retire. Summing rather than mirroring
 * keeps a single source of truth -- cloak_stream_t is the only thing that
 * knows when it dropped a datagram, and a copy maintained here would be a
 * second one that could disagree. */
uint64_t cloak_udp_piper_dropped_datagrams(const cloak_udp_piper_t *pp) {
    if (pp == NULL) {
        return 0;
    }
    uint64_t total = pp->retired_dropped;
    for (const cloak_udp_piper_peer_t *p = pp->peers; p != NULL; p = p->next) {
        if (p->stream != NULL) {
            total += p->stream->recv_dropped_datagrams;
        }
    }
    return total;
}

uint64_t cloak_udp_piper_oversize_datagrams(const cloak_udp_piper_t *pp) {
    return pp == NULL ? 0 : pp->oversize_datagrams;
}

uint64_t cloak_udp_piper_empty_datagrams(const cloak_udp_piper_t *pp) {
    return pp == NULL ? 0 : pp->empty_datagrams;
}

uint64_t cloak_udp_piper_send_stalls(const cloak_udp_piper_t *pp) {
    return pp == NULL ? 0 : pp->send_stalls;
}

uint64_t cloak_udp_piper_pool_pauses(const cloak_udp_piper_t *pp) {
    return pp == NULL ? 0 : pp->pool_pauses;
}

size_t cloak_udp_piper_refused_peers(const cloak_udp_piper_t *pp) {
    return pp == NULL ? 0 : pp->refused_peers;
}

size_t cloak_udp_piper_rejected_streams(const cloak_udp_piper_t *pp) {
    return pp == NULL ? 0 : pp->rejected_streams;
}
