#define _POSIX_C_SOURCE 200809L
#include "cloak/dgram_relay.h"
#include "cloak/session.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "cloak/common.h"
#include "cloak/conn.h"
#include "cloak/stream_relay.h" /* cloak_stream_relay_frame_cost, shared */
#include "test_framework.h"

/* Unit coverage for cloak_dgram_relay_t, driving the relay DIRECTLY over a
 * descriptor the test owns the other end of -- the same shape
 * test_stream_relay.c uses for its sibling, and for the same reason.
 *
 * WHY THIS FILE EXISTS, stated plainly because it was added a round late:
 * when the datagram relay shipped it was tested only end to end, through
 * libcloak-server's proxy fixture (test_proxy_udp.c). That fixture cannot
 * reach four things the relay's own header argues at length, and a review
 * demonstrated all four by mutation, each surviving the whole 73-test
 * suite:
 *
 *   - the teardown telling the peer the stream ended
 *     (cloak_session_close_stream deleted: nothing noticed);
 *   - budgeting against the MINIMUM free space over the connection pool
 *     rather than the aggregate (a pool of one connection cannot tell
 *     them apart, and the proxy fixture has one);
 *   - notify_writable PULLING rather than only re-arming interest;
 *   - a send refused with EAGAIN holding its datagram instead of dropping
 *     it (a loopback UDP send never refuses, so the proxy fixture cannot
 *     provoke it -- measured at 0 refusals in 20 000 by module 9 task 5,
 *     which is why the client's own piper grew an AF_UNIX seam).
 *
 * All four are reachable here with no new production seam at all:
 * cloak_dgram_relay_start already takes the descriptor, so a
 * socketpair(AF_UNIX, SOCK_DGRAM) -- with its own SO_SNDBUF, its own
 * unread peer, and real datagram boundaries -- is the whole trick. The
 * fifth thing the proxy fixture cannot reach, an upstream that answers
 * with ICMP port-unreachable, needs only an AF_INET datagram socket
 * connected to a closed loopback port.
 *
 * EVERY WAIT IN THIS FILE IS BOUNDED BY THE CLOCK, never by an iteration
 * count: pump_until_ms below spins the reactor until a predicate holds or
 * a wall-clock budget expires. A relay under test can make one descriptor
 * permanently ready (an unread peer is exactly that), and an iteration
 * count then expires in microseconds -- the defect this branch's own
 * pump_until was rewritten to remove. */

/* ---- clock-bounded pumping ---------------------------------------------- */

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

typedef int (*pump_pred_fn)(void *ctx);

/* Spins the reactor until pred(ctx) is true or budget_ms of REAL TIME have
 * passed. Returns 1 if the predicate became true. The iteration ceiling is
 * a backstop against a clock that does not advance, sized far above the
 * spin rate so it can never bind first. */
static int pump_until_ms(cloak_reactor_t *r, pump_pred_fn pred, void *ctx, uint64_t budget_ms) {
    uint64_t start = mono_ms();
    for (uint64_t i = 0; i < budget_ms * 100000u + 1000000u; i++) {
        if (pred(ctx)) {
            return 1;
        }
        if (mono_ms() - start >= budget_ms) {
            break;
        }
        cloak_reactor_run_once(r, 2);
    }
    return pred(ctx);
}

/* The budget every wait in this file uses unless it says otherwise. Four
 * seconds of wall clock, against a ctest TIMEOUT of 60 -- the timeout is a
 * backstop, this is the mechanism. */
#define WAIT_MS ((uint64_t)4000)

/* ---- two sessions, wired to each other ---------------------------------- */

struct endpoint {
    cloak_session_t sesh;
    cloak_stream_t *accepted;
    cloak_dgram_relay_t *dr;
    int new_stream_calls;
    /* Case 5 needs the session's drained notification NOT to reach the
     * relay, so that the test can deliver it by hand and observe what
     * that one call does on its own. Every other case leaves it 0 and
     * gets the wiring a real dispatcher has. */
    int suppress_writable;
};

static void on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct endpoint *ep = userdata;
    ep->new_stream_calls++;
    ep->accepted = stream;
}

static void on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    (void)stream;
    struct endpoint *ep = userdata;
    if (ep->dr != NULL) {
        cloak_dgram_relay_notify_stream_data(ep->dr);
    }
}

static void on_writable(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    struct endpoint *ep = userdata;
    if (ep->dr != NULL && !ep->suppress_writable) {
        cloak_dgram_relay_notify_writable(ep->dr);
    }
}

static void on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    (void)userdata;
}

static void make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

/* UNORDERED, which is the only mode a datagram relay is ever paired with
 * in production -- the proxy picks the relay by the upstream's socket
 * type, but the sizes and the read semantics this file asserts are the
 * unordered stream's. */
static void fill_config(cloak_session_config_t *cfg, struct endpoint *ep,
                        const cloak_obfuscator_t *obfs) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->obfuscator = *obfs;
    cfg->ordering = CLOAK_SESSION_ORDERING_UNORDERED;
    cfg->max_on_wire_size = 16401;
    cfg->stream_recv_capacity = 65536;
    cfg->stream_max_pending_frames = 64;
    cfg->conn_send_queue_cap = 262144;
    cfg->inactivity_timeout_ms = 60000;
    cfg->on_new_stream = on_new_stream;
    cfg->on_new_stream_userdata = ep;
    cfg->on_stream_data = on_stream_data;
    cfg->on_stream_data_userdata = ep;
    cfg->on_writable = on_writable;
    cfg->on_writable_userdata = ep;
    cfg->on_broken = on_broken;
    cfg->on_broken_userdata = ep;
}

/* max_payload_per_frame at the configuration above, and the worst-case
 * on-wire cost of one frame carrying it. Pinned as literals in case 7 so
 * that a change to either constant fails an assertion here rather than
 * silently re-scaling every size in this file. */
#define MAX_PAYLOAD ((size_t)16132)
#define FRAME_COST ((size_t)(5 + 16132 + 14 + 255))

/* The relay's own descriptor pair: `inner` is handed to the relay (which
 * owns and closes it); `outer` is the test's end, playing the upstream.
 * SOCK_DGRAM, so boundaries are real rather than simulated. */
struct dgpair {
    int inner;
    int outer;
};

/* outer_rcvbuf > 0 shrinks the OUTER end's RECEIVE buffer, which is what
 * makes a send on the inner end refuse: on an AF_UNIX datagram socket the
 * sender is bounded by the peer's receive queue, not by its own SO_SNDBUF
 * (which caps the maximum datagram size instead -- setting that small
 * yields EMSGSIZE, a drop, rather than the EAGAIN this file needs). */
static int dgpair_init(struct dgpair *sp, int outer_rcvbuf) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) {
        return -1;
    }
    sp->inner = fds[0];
    sp->outer = fds[1];
    if (outer_rcvbuf > 0 &&
        setsockopt(sp->outer, SOL_SOCKET, SO_RCVBUF, &outer_rcvbuf, sizeof(outer_rcvbuf)) != 0) {
        return -1;
    }
    for (int i = 0; i < 2; i++) {
        int fd = i == 0 ? sp->inner : sp->outer;
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            return -1;
        }
    }
    return 0;
}

struct done_capture {
    int calls;
};

static void on_done(cloak_dgram_relay_t *dr, void *userdata) {
    (void)dr;
    struct done_capture *cap = userdata;
    cap->calls++;
}

/* Everything the cases below share: two sessions over one socketpair, a
 * stream opened by `a` and accepted by `b`, and a relay spliced to b's
 * end. The priming write is what makes b's session produce the stream at
 * all, exactly as a real client's first frame does. */
struct fixture {
    cloak_reactor_t *r;
    struct endpoint a;
    struct endpoint b;
    cloak_stream_t *s; /* a's end of the stream */
    cloak_dgram_relay_t dr;
    int relay_started;
    struct done_capture cap;
    int conn_fds[2];
    int extra_dead[2]; /* case 4's second, never-drained connection */
    int have_extra;
};

static int fx_new_stream(void *ctx) {
    struct fixture *fx = ctx;
    return fx->b.new_stream_calls > 0;
}

/* b_queue_cap 0 means "the default in fill_config". valve may be NULL. */
static int fixture_start(struct fixture *fx, size_t b_queue_cap, cloak_valve_t *valve) {
    memset(fx, 0, sizeof(*fx));
    fx->conn_fds[0] = -1;
    fx->conn_fds[1] = -1;
    fx->extra_dead[0] = -1;
    fx->extra_dead[1] = -1;

    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fx->conn_fds));

    fx->r = cloak_reactor_create();
    ASSERT_TRUE(fx->r != NULL);
    if (fx->r == NULL) {
        return -1;
    }

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    cloak_session_config_t cfg_a;
    cloak_session_config_t cfg_b;
    fill_config(&cfg_a, &fx->a, &obfs);
    fill_config(&cfg_b, &fx->b, &obfs);
    if (b_queue_cap != 0) {
        cfg_b.conn_send_queue_cap = b_queue_cap;
    }
    cfg_b.valve = valve;

    ASSERT_EQ_INT(0, cloak_session_init(&fx->a.sesh, 7, fx->r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&fx->b.sesh, 7, fx->r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&fx->a.sesh, fx->conn_fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&fx->b.sesh, fx->conn_fds[1]));

    fx->s = cloak_session_open_stream(&fx->a.sesh, NULL);
    ASSERT_TRUE(fx->s != NULL);
    if (fx->s == NULL) {
        return -1;
    }
    ASSERT_EQ_INT(1, (int)cloak_stream_write(fx->s, (const uint8_t *)"x", 1));
    ASSERT_TRUE(pump_until_ms(fx->r, fx_new_stream, fx, WAIT_MS));
    ASSERT_EQ_INT(1, fx->b.new_stream_calls);
    return fx->b.accepted == NULL ? -1 : 0;
}

static void fixture_stop(struct fixture *fx) {
    if (fx->relay_started) {
        cloak_dgram_relay_stop(&fx->dr);
        fx->relay_started = 0;
    }
    fx->b.dr = NULL;
    if (fx->b.accepted != NULL && !cloak_session_is_closed(&fx->b.sesh)) {
        cloak_session_release_stream(&fx->b.sesh, fx->b.accepted);
    }
    if (fx->s != NULL && !cloak_session_is_closed(&fx->a.sesh)) {
        cloak_session_release_stream(&fx->a.sesh, fx->s);
    }
    cloak_session_destroy(&fx->a.sesh);
    cloak_session_destroy(&fx->b.sesh);
    if (fx->have_extra && fx->extra_dead[1] >= 0) {
        close(fx->extra_dead[1]);
    }
    if (fx->r != NULL) {
        cloak_reactor_destroy(fx->r);
    }
}

/* ---- reading a's end, one datagram at a time ---------------------------- */

#define RD_MAX 24
#define RD_CAP ((size_t)20000)

struct reader {
    cloak_stream_t *stream;
    size_t count;
    size_t len[RD_MAX];
    uint8_t *bytes[RD_MAX];
    int ended;
    int short_buf;
    uint8_t buf[RD_CAP];
};

static void reader_poll(struct reader *rd) {
    while (!rd->ended && !rd->short_buf && rd->count < RD_MAX) {
        long n = cloak_stream_read(rd->stream, rd->buf, RD_CAP);
        if (n > 0) {
            rd->len[rd->count] = (size_t)n;
            rd->bytes[rd->count] = malloc((size_t)n);
            if (rd->bytes[rd->count] != NULL) {
                memcpy(rd->bytes[rd->count], rd->buf, (size_t)n);
            }
            rd->count++;
            continue;
        }
        if (n == CLOAK_STREAM_ERR_SHORT_BUFFER) {
            rd->short_buf = 1;
        } else if (n < 0) {
            rd->ended = 1;
        }
        return;
    }
}

static void reader_free(struct reader *rd) {
    for (size_t i = 0; i < RD_MAX; i++) {
        free(rd->bytes[i]);
        rd->bytes[i] = NULL;
    }
}

struct reader_wait {
    struct reader *rd;
    size_t want;
};

static int reader_has(void *ctx) {
    struct reader_wait *w = ctx;
    reader_poll(w->rd);
    return w->rd->count >= w->want || w->rd->ended || w->rd->short_buf;
}

static int reader_ended(void *ctx) {
    struct reader *rd = ctx;
    reader_poll(rd);
    return rd->ended;
}

static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + (i * 31u) + (i >> 8));
    }
}

/* Bytes of the next datagram still sitting unread in the relay's own
 * socket. The relay owns that descriptor, but asking the kernel how much
 * it has not yet taken is read-only and is the only way to distinguish
 * "the relay has not read it" from "the relay read it and dropped it". */
static int unread_on(int fd) {
    int n = 0;
    if (ioctl(fd, FIONREAD, &n) != 0) {
        return -1;
    }
    return n;
}

/* ---- 1. both directions, at the sizes that matter ----------------------- */

/* The relay's whole job in one case, at the unit level: a datagram from
 * the stream leaves as exactly one datagram, and a datagram arriving on
 * the socket becomes exactly one datagram at the far end -- including the
 * two the size policy (D7) singles out.
 *
 * 16132 is max_payload_per_frame and is carried; Go loses every reply of
 * 8193..16132 and tears the peer's stream down with it. 8193 is the first
 * byte of that window and 8192 the last that Go survives, so both are
 * driven here rather than left to the end-to-end file's 8191.
 *
 * The two socket-side outcomes that are NOT a datagram are asserted in
 * the same case, because both are indistinguishable from a normal read
 * without the check: an EMPTY datagram (recv returns 0, which on a stream
 * socket would mean end of file and here means a healthy socket carrying
 * nothing) and an OVERSIZE one (recv with MSG_TRUNC returns more than the
 * buffer, which without MSG_TRUNC is indistinguishable from a datagram of
 * exactly the buffer's size -- Go's bug 7). Neither may end the stream and
 * neither may reach the far end; what proves that is the ordinary
 * datagram sent after them arriving as the NEXT one, not merely the
 * absence of a bad one. */
static void test_relay_moves_datagrams_both_ways_at_the_boundary_sizes(void) {
    struct fixture fx;
    if (fixture_start(&fx, 0, NULL) != 0) {
        return;
    }

    struct dgpair sp;
    ASSERT_EQ_INT(0, dgpair_init(&sp, 0));
    ASSERT_EQ_INT(0, cloak_dgram_relay_start(&fx.dr, fx.r, &fx.b.sesh, fx.b.accepted, sp.inner,
                                             on_done, &fx.cap));
    fx.relay_started = 1;
    fx.b.dr = &fx.dr;

    ASSERT_EQ_INT((int)MAX_PAYLOAD, (int)fx.b.accepted->max_payload_per_frame);

    /* The priming "x" the fixture wrote reaches the socket through the
     * relay's own initial pump -- drained here so the sizes below start
     * from a clean socket. */
    uint8_t prime[64];
    ssize_t pn = -1;
    uint64_t t0 = mono_ms();
    while (pn < 0 && mono_ms() - t0 < WAIT_MS) {
        pn = recv(sp.outer, prime, sizeof(prime), 0);
        if (pn < 0) {
            cloak_reactor_run_once(fx.r, 2);
        }
    }
    ASSERT_EQ_INT(1, (int)pn);

    /* stream -> socket, one datagram each, at the exact sizes. */
    const size_t sizes[4] = {1, 8192, 8193, MAX_PAYLOAD};
    uint8_t *out = malloc(MAX_PAYLOAD);
    ASSERT_TRUE(out != NULL);
    if (out == NULL) {
        fixture_stop(&fx);
        return;
    }
    for (int i = 0; i < 4; i++) {
        fill_pattern(out, sizes[i], (uint8_t)(0x30 + i));
        ASSERT_EQ_INT((int)sizes[i], (int)cloak_stream_write(fx.s, out, sizes[i]));
        uint8_t got[MAX_PAYLOAD + 64];
        ssize_t n = -1;
        uint64_t t = mono_ms();
        while (n < 0 && mono_ms() - t < WAIT_MS) {
            n = recv(sp.outer, got, sizeof(got), 0);
            if (n < 0) {
                cloak_reactor_run_once(fx.r, 2);
            }
        }
        ASSERT_EQ_INT((int)sizes[i], (int)n);
        if (n == (ssize_t)sizes[i]) {
            ASSERT_MEM_EQ(got, out, sizes[i]);
        }
    }

    /* socket -> stream: an empty datagram and an oversize one, then a real
     * one. Order is preserved on a socketpair, so the real one can only be
     * the FIRST thing the far end sees if the other two were handled. */
    struct reader rd;
    memset(&rd, 0, sizeof(rd));
    rd.stream = fx.s;

    ASSERT_EQ_INT(0, (int)send(sp.outer, "", 0, 0));
    uint8_t *over = malloc(MAX_PAYLOAD + 1);
    ASSERT_TRUE(over != NULL);
    if (over != NULL) {
        fill_pattern(over, MAX_PAYLOAD + 1, 0x77);
        ASSERT_EQ_INT((int)(MAX_PAYLOAD + 1), (int)send(sp.outer, over, MAX_PAYLOAD + 1, 0));
        free(over);
    }
    fill_pattern(out, MAX_PAYLOAD, 0xC1);
    ASSERT_EQ_INT((int)MAX_PAYLOAD, (int)send(sp.outer, out, MAX_PAYLOAD, 0));

    struct reader_wait rw = {&rd, 1};
    ASSERT_TRUE(pump_until_ms(fx.r, reader_has, &rw, WAIT_MS));
    ASSERT_EQ_INT(0, rd.ended);
    ASSERT_EQ_INT(0, rd.short_buf);
    ASSERT_EQ_INT(1, (int)rd.count);
    if (rd.count >= 1) {
        ASSERT_EQ_INT((int)MAX_PAYLOAD, (int)rd.len[0]);
        ASSERT_TRUE(rd.bytes[0] != NULL);
        if (rd.bytes[0] != NULL) {
            ASSERT_MEM_EQ(rd.bytes[0], out, MAX_PAYLOAD);
        }
    }
    /* And the two that were handled were COUNTED, which is the only
     * record either divergence leaves. */
    ASSERT_EQ_INT(1, (int)fx.dr.swallowed_empty);
    ASSERT_EQ_INT(1, (int)fx.dr.dropped_oversize);
    ASSERT_EQ_INT(0, fx.cap.calls);

    free(out);
    reader_free(&rd);
    close(sp.outer);
    fixture_stop(&fx);
}

/* ---- 2. the socket dies: the far end must learn ------------------------- */

/* THE ONE SOCKET-SIDE ENDING A CONNECTED DATAGRAM SOCKET HAS. There is no
 * orderly close to detect -- recv returning 0 is an empty datagram, not
 * EOF (case 1) -- so the only thing that ends this relay from below is a
 * real error, and in practice that error is ECONNREFUSED delivered from
 * an ICMP port-unreachable when nothing is listening at the upstream
 * address. An AF_INET datagram socket connected to a closed loopback port
 * produces it on the next recv after a send.
 *
 * WHAT THIS CASE IS REALLY FOR is the assertion after on_done: THE FAR
 * END SEES END OF STREAM. Deleting cloak_session_close_stream from the
 * relay's teardown passed the entire 73-test suite when this relay
 * shipped. In production that is a dead tunnel that looks alive: the
 * upstream is gone, the relay is gone, and the client's stream stays open
 * forever waiting for a reply that cannot come. Asserting that the relay
 * finished (cap.calls == 1) does NOT catch it; asserting that a's stream
 * reads -1 does. */
static void test_upstream_error_ends_the_far_end_of_the_stream(void) {
    struct fixture fx;
    if (fixture_start(&fx, 0, NULL) != 0) {
        return;
    }

    /* A closed loopback port: bind one, learn its number, close it. The
     * number is ephemeral, chosen by the kernel, never a literal. */
    int probe = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_TRUE(probe >= 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    ASSERT_EQ_INT(0, bind(probe, (const struct sockaddr *)&sa, sizeof(sa)));
    socklen_t salen = sizeof(sa);
    ASSERT_EQ_INT(0, getsockname(probe, (struct sockaddr *)&sa, &salen));
    close(probe);

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ_INT(0, connect(fd, (const struct sockaddr *)&sa, sizeof(sa)));

    ASSERT_EQ_INT(0, cloak_dgram_relay_start(&fx.dr, fx.r, &fx.b.sesh, fx.b.accepted, fd, on_done,
                                             &fx.cap));
    fx.relay_started = 1;
    fx.b.dr = &fx.dr;

    /* The relay's initial pump sends the priming datagram to a port with
     * nothing on it; the ICMP answer surfaces on the next recv. */
    struct reader rd;
    memset(&rd, 0, sizeof(rd));
    rd.stream = fx.s;
    ASSERT_TRUE(pump_until_ms(fx.r, reader_ended, &rd, WAIT_MS));

    ASSERT_EQ_INT(1, rd.ended);
    ASSERT_EQ_INT(1, fx.cap.calls); /* exactly once, never twice */
    ASSERT_EQ_INT(0, (int)rd.count);

    reader_free(&rd);
    fixture_stop(&fx);
}

/* ---- 3. a refused send holds its datagram ------------------------------- */

/* THE BRANCH NO LOOPBACK UDP TEST CAN REACH. A send on an AF_INET socket
 * to loopback does not refuse at the sizes a Cloak frame permits -- module
 * 9 task 5 measured 0 refusals in 20 000 -- which is why the end-to-end
 * file cannot exercise this and why the client's own piper grew an
 * AF_UNIX seam for it. Here the relay's descriptor is ours to choose, so
 * a socketpair with a deliberately small SO_SNDBUF and a peer that does
 * not read reaches EAGAIN on demand.
 *
 * WHAT MUST HAPPEN: the datagram is HELD, not dropped. The relay carries
 * exactly one pending datagram and stops reading its stream while it has
 * one, so the backlog stays in the stream's own receive queue where a
 * decided overflow policy governs it. Dropping instead would be invisible
 * -- a lost datagram looks like a lost datagram -- which is why this
 * asserts that BOTH datagrams arrive and that they arrive IN ORDER, not
 * merely that the relay survived. */
static void test_a_refused_send_holds_the_datagram_rather_than_dropping_it(void) {
    struct fixture fx;
    if (fixture_start(&fx, 0, NULL) != 0) {
        return;
    }

    enum { DG = 2000 };
    struct dgpair sp;
    ASSERT_EQ_INT(0, dgpair_init(&sp, 0));
    ASSERT_EQ_INT(0, cloak_dgram_relay_start(&fx.dr, fx.r, &fx.b.sesh, fx.b.accepted, sp.inner,
                                             on_done, &fx.cap));
    fx.relay_started = 1;
    fx.b.dr = &fx.dr;

    uint8_t out[DG];
    uint8_t in[DG + 64];

    /* Drain the priming "x" the fixture wrote, so the far end starts
     * empty and every length asserted below is one of ours. */
    ssize_t pn = -1;
    uint64_t t0 = mono_ms();
    while (pn < 0 && mono_ms() - t0 < WAIT_MS) {
        pn = recv(sp.outer, in, sizeof(in), 0);
        if (pn < 0) {
            cloak_reactor_run_once(fx.r, 2);
        }
    }
    ASSERT_EQ_INT(1, (int)pn);

    /* FILL THE FAR END'S QUEUE FIRST, so the relay's very next send is
     * refused rather than hoping enough traffic accumulates to refuse
     * one. The filler datagrams are sent on the relay's OWN descriptor --
     * which the relay owns for closing but which this test created and
     * still knows the number of, the same read-only-ish liberty
     * unread_on() takes. Nothing about the relay's state is touched: the
     * datagrams simply queue at the far end ahead of its own.
     *
     * The limit being reached is the peer's, not ours, and this makes no
     * assumption about what it is (AF_UNIX datagram sockets bound a
     * connected sender by the peer's queue LENGTH, whose default is a
     * sysctl this test cannot set) -- it just sends until refused. */
    memset(out, 0xEE, sizeof(out));
    int filler = 0;
    while (filler < 4096 && send(sp.inner, out, DG, 0) >= 0) {
        filler++;
    }
    ASSERT_TRUE(filler > 0);
    ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);

    /* Now one datagram from the stream side. The relay must read it and
     * find the socket refusing. */
    fill_pattern(out, DG, 0x40);
    ASSERT_EQ_INT((int)DG, (int)cloak_stream_write(fx.s, out, DG));
    t0 = mono_ms();
    while (fx.dr.pending_len == 0 && mono_ms() - t0 < WAIT_MS) {
        cloak_reactor_run_once(fx.r, 2);
    }
    ASSERT_TRUE(fx.dr.pending_len > 0); /* HELD, not dropped */
    ASSERT_EQ_INT((int)DG, (int)fx.dr.pending_len);
    ASSERT_EQ_INT(0, fx.cap.calls); /* backpressure is not an ending */

    /* A second datagram written while the first is still stuck stays in
     * the STREAM's own queue -- the relay carries exactly one -- which is
     * what makes the ordering assertion below meaningful. */
    fill_pattern(out, DG, 0x41);
    ASSERT_EQ_INT((int)DG, (int)cloak_stream_write(fx.s, out, DG));
    cloak_reactor_run_once(fx.r, 2);
    ASSERT_EQ_INT((int)DG, (int)fx.dr.pending_len);

    /* Drain the filler, then the two real datagrams must both come out,
     * in order and whole. A relay that dropped the refused datagram loses
     * exactly one, invisibly. */
    int drained = 0;
    t0 = mono_ms();
    while (drained < filler && mono_ms() - t0 < WAIT_MS) {
        ssize_t n = recv(sp.outer, in, sizeof(in), 0);
        if (n >= 0) {
            drained++;
            continue;
        }
        cloak_reactor_run_once(fx.r, 2);
    }
    ASSERT_EQ_INT(filler, drained);

    for (int i = 0; i < 2; i++) {
        ssize_t n = -1;
        t0 = mono_ms();
        while (n < 0 && mono_ms() - t0 < WAIT_MS) {
            n = recv(sp.outer, in, sizeof(in), 0);
            if (n < 0) {
                cloak_reactor_run_once(fx.r, 2);
            }
        }
        ASSERT_EQ_INT((int)DG, (int)n);
        if (n == (ssize_t)DG) {
            fill_pattern(out, DG, (uint8_t)(0x40 + i));
            ASSERT_MEM_EQ(in, out, DG);
        }
    }
    ASSERT_EQ_INT(0, fx.cap.calls);

    close(sp.outer);
    fixture_stop(&fx);
}

/* ---- 4. one congested connection must not break the pool ---------------- */

/* THE SAME DEFECT CLASS THIS BRANCH ALREADY MEASURED ONCE, one task
 * earlier, in the client's piper -- and it escaped again here, because the
 * end-to-end fixture's session has exactly ONE connection and a pool of
 * one cannot tell the MINIMUM free space over its connections from the
 * AGGREGATE.
 *
 * cloak_switchboard_send hands each whole frame to ONE connection chosen
 * uniformly at random. With two connections and one of them stalled, the
 * aggregate stays comfortable (dominated by the healthy one) right up to
 * the moment a random pick lands on the stalled one past its own hard cap
 * -- which breaks that connection, and a broken connection takes the whole
 * pool and every stream on it. Budgeting off the minimum makes the frames
 * a read produces fit REGARDLESS of which connection is picked next.
 *
 * The assertion is that neither session closed. Substituting
 * send_capacity - send_queued for cloak_session_send_min_conn_free fails
 * it; the relay then simply stops reading once the stalled connection
 * fills, which is the intended behaviour and is why this case detects a
 * STALL and stops rather than burning its whole budget. */
static int either_session_closed(void *ctx) {
    struct fixture *fx = ctx;
    return cloak_session_is_closed(&fx->a.sesh) || cloak_session_is_closed(&fx->b.sesh);
}

static void test_one_congested_connection_does_not_break_the_pool(void) {
    struct fixture fx;
    /* Small enough that the stalled connection's own queue fills well
     * inside the traffic below, on top of whatever the kernel buffers. */
    if (fixture_start(&fx, 65536, NULL) != 0) {
        return;
    }

    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fx.extra_dead));
    fx.have_extra = 1;
    ASSERT_EQ_INT(0, cloak_session_add_conn(&fx.b.sesh, fx.extra_dead[0]));
    /* extra_dead[1] is deliberately never read: a stalled peer on one
     * connection of the pool. */

    struct dgpair sp;
    ASSERT_EQ_INT(0, dgpair_init(&sp, 0));
    ASSERT_EQ_INT(0, cloak_dgram_relay_start(&fx.dr, fx.r, &fx.b.sesh, fx.b.accepted, sp.inner,
                                             on_done, &fx.cap));
    fx.relay_started = 1;
    fx.b.dr = &fx.dr;

    uint8_t *chunk = malloc(MAX_PAYLOAD);
    ASSERT_TRUE(chunk != NULL);
    if (chunk == NULL) {
        fixture_stop(&fx);
        return;
    }
    memset(chunk, 'q', MAX_PAYLOAD);

    /* Feed the relay from the socket side until either something breaks
     * (the regression) or nothing moves any more (the fix taking hold),
     * whichever comes first -- inside one clock budget. */
    uint8_t sink[RD_CAP];
    uint64_t t0 = mono_ms();
    int idle_rounds = 0;
    while (mono_ms() - t0 < WAIT_MS && idle_rounds < 40 && !either_session_closed(&fx)) {
        int moved = 0;
        for (int i = 0; i < 16; i++) {
            if (send(sp.outer, chunk, MAX_PAYLOAD, 0) < 0) {
                break;
            }
            moved = 1;
        }
        cloak_reactor_run_once(fx.r, 2);
        for (;;) {
            long n = cloak_stream_read(fx.s, sink, sizeof(sink));
            if (n <= 0) {
                break;
            }
            moved = 1;
        }
        idle_rounds = moved ? 0 : idle_rounds + 1;
    }

    ASSERT_TRUE(!cloak_session_is_closed(&fx.a.sesh));
    ASSERT_TRUE(!cloak_session_is_closed(&fx.b.sesh));

    free(chunk);
    close(sp.outer);
    fixture_stop(&fx);
}

/* ---- 5. notify_writable must PULL, not merely re-arm -------------------- */

/* The relay's own comment says this mechanism "must not depend on a second
 * event to finish what the timer started", and the end-to-end file pins
 * only that SOMETHING resumes -- removing the pull and leaving the
 * interest re-arm passed all 73 tests, because epoll re-reports data still
 * sitting in an edge-triggered socket on the next EPOLL_CTL_MOD. That is
 * true on Linux today and is not what the code claims.
 *
 * This asserts the claim directly and with no reactor turn in between: the
 * session's drained notification is delivered BY HAND (the fixture's
 * on_writable is suppressed for this case), and the datagram must be out
 * of the socket by the time that one call returns. FIONREAD on the relay's
 * own descriptor is what distinguishes "not read yet" from "read and
 * dropped" -- a read-only question to the kernel about a descriptor the
 * relay owns. */
struct pool_wait {
    struct endpoint *ep;
    cloak_dgram_relay_t *dr;
    int fd;
};

static int relay_paused_with_a_datagram_waiting(void *ctx) {
    struct pool_wait *w = ctx;
    return w->dr->fd_read_paused && unread_on(w->fd) > 0;
}

static int pool_has_room_again(void *ctx) {
    struct pool_wait *w = ctx;
    return cloak_session_send_min_conn_free(&w->ep->sesh) >= FRAME_COST;
}

/* THIS CASE BUILDS ITS OWN, SMALLER WORLD than the rest of the file: one
 * session, one connection whose peer THIS TEST holds and does not read,
 * and a stream the session opens itself. That is what makes the pool's
 * state a thing the test decides rather than observes -- the shared
 * fixture's two sessions both run on the same reactor and drain each
 * other, so its pool never fills at all. The relay does not care who
 * opened the stream it is spliced to. */
static void test_notify_writable_pulls_without_another_readable_edge(void) {
    int conn[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, conn));
    /* A small send buffer on the session's end, so frames it writes stay
     * in the CONNECTION's own queue (which is what
     * cloak_session_send_min_conn_free measures) instead of vanishing
     * into a multi-hundred-kilobyte kernel buffer. */
    int sndbuf = 4096;
    ASSERT_EQ_INT(0, setsockopt(conn[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)));
    /* NON-BLOCKING, and it is load-bearing rather than tidiness: the
     * drain loop below reads this end until it is empty, and a socketpair
     * is blocking by default -- the read that finds it empty would then
     * never return, which is exactly the class of hang this project's
     * suites have paid for twice. */
    {
        int fl = fcntl(conn[1], F_GETFL, 0);
        ASSERT_TRUE(fl != -1);
        ASSERT_EQ_INT(0, fcntl(conn[1], F_SETFL, fl | O_NONBLOCK));
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    struct endpoint b;
    memset(&b, 0, sizeof(b));
    b.suppress_writable = 1; /* the drained notification is delivered BY HAND */

    cloak_session_config_t cfg;
    fill_config(&cfg, &b, &obfs);
    cfg.conn_send_queue_cap = 2 * FRAME_COST;
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 9, r, &cfg));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, conn[0]));

    cloak_stream_t *st = cloak_session_open_stream(&b.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        cloak_session_destroy(&b.sesh);
        close(conn[1]);
        cloak_reactor_destroy(r);
        return;
    }

    struct dgpair sp;
    ASSERT_EQ_INT(0, dgpair_init(&sp, 0));
    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));
    cloak_dgram_relay_t dr;
    ASSERT_EQ_INT(0, cloak_dgram_relay_start(&dr, r, &b.sesh, st, sp.inner, on_done, &cap));
    b.dr = &dr;

    uint8_t *big = malloc(MAX_PAYLOAD);
    ASSERT_TRUE(big != NULL);
    if (big != NULL) {
        memset(big, 'z', MAX_PAYLOAD);
        /* More than a two-frame pool can absorb in one go, so the relay
         * reads some and pauses with at least one still in the socket. */
        for (int i = 0; i < 4; i++) {
            ASSERT_EQ_INT((int)MAX_PAYLOAD, (int)send(sp.outer, big, MAX_PAYLOAD, 0));
        }

        struct pool_wait pw = {&b, &dr, sp.inner};
        ASSERT_TRUE(pump_until_ms(r, relay_paused_with_a_datagram_waiting, &pw, WAIT_MS));

        /* Give the pool its room back, by reading the connection's peer
         * -- the one thing in this world that can. The relay stays paused
         * throughout, because the session's drained notification is
         * suppressed for this case. */
        uint8_t sink[8192];
        uint64_t t0 = mono_ms();
        while (mono_ms() - t0 < WAIT_MS && !pool_has_room_again(&pw)) {
            while (read(conn[1], sink, sizeof(sink)) > 0) {
            }
            cloak_reactor_run_once(r, 2);
        }
        ASSERT_TRUE(pool_has_room_again(&pw));
        ASSERT_TRUE(dr.fd_read_paused);

        ASSERT_TRUE(unread_on(sp.inner) > 0); /* something is still waiting */

        /* WHAT "IT PULLED" IS MEASURED BY, and why not FIONREAD: on a
         * datagram socket FIONREAD reports the size of the FIRST queued
         * datagram, not the total, so consuming one of several identical
         * datagrams leaves it unchanged. What does change, and only if
         * the pull happened, is the session's outbound queue: the
         * datagram becomes a frame, and the connection's socket buffer is
         * full (that is why the pool was backed up at all), so the frame
         * can only be queued. */
        size_t queued_before = cloak_session_send_queued(&b.sesh);

        /* THE ONE CALL, with no reactor turn anywhere near it. */
        cloak_dgram_relay_notify_writable(&dr);

        ASSERT_TRUE(cloak_session_send_queued(&b.sesh) > queued_before);
        /* And it is paused again, correctly: one frame's worth of room is
         * what it had, and it spent it. The pause is not the defect --
         * never pulling is. */
        ASSERT_TRUE(dr.fd_read_paused);
        free(big);
    }

    cloak_dgram_relay_stop(&dr);
    b.dr = NULL;
    cloak_session_release_stream(&b.sesh, st);
    cloak_session_destroy(&b.sesh);
    close(sp.outer);
    close(conn[1]);
    cloak_reactor_destroy(r);
}

/* ---- 6. an empty token bucket pauses, and only the clock resumes -------- */

/* Go applies the user's rate limit by BLOCKING a goroutine
 * (LimitedValve.txWait); this reactor has no thread to block, so the limit
 * is applied by not reading the socket. That pause is resumed by NOTHING
 * -- no queue drains, the socket's readiness edge is spent, the peer has
 * no reason to act -- so the relay must arm its own timer before it
 * returns, and this project has already shipped the version that did not
 * once.
 *
 * 8000 bytes/sec against 16132-byte datagrams: the bucket's one-second
 * burst cannot cover even the first one, so the second read is refused
 * outright and the only thing that can deliver it is the rate timer. The
 * bucket is queried directly (cloak_valve_take_tx is advisory and consumes
 * nothing) to prove the pause was rate-bound rather than pool-bound before
 * the wait that proves it recovered. */
struct bucket_wait {
    cloak_valve_t *v;
    struct fixture *fx;
};

static int bucket_is_empty(void *ctx) {
    struct bucket_wait *w = ctx;
    return cloak_valve_take_tx(w->v, (int64_t)MAX_PAYLOAD) == 0;
}

static void test_an_empty_tx_bucket_pauses_and_the_timer_resumes(void) {
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    cloak_valve_set_rates(&v, 0, 8000);

    struct fixture fx;
    if (fixture_start(&fx, 0, &v) != 0) {
        return;
    }

    struct dgpair sp;
    ASSERT_EQ_INT(0, dgpair_init(&sp, 0));
    ASSERT_EQ_INT(0, cloak_dgram_relay_start(&fx.dr, fx.r, &fx.b.sesh, fx.b.accepted, sp.inner,
                                             on_done, &fx.cap));
    fx.relay_started = 1;
    fx.b.dr = &fx.dr;

    uint8_t *big = malloc(MAX_PAYLOAD);
    ASSERT_TRUE(big != NULL);
    if (big == NULL) {
        fixture_stop(&fx);
        return;
    }
    fill_pattern(big, MAX_PAYLOAD, 0x5A);

    for (int i = 0; i < 2; i++) {
        ASSERT_EQ_INT((int)MAX_PAYLOAD, (int)send(sp.outer, big, MAX_PAYLOAD, 0));
    }

    struct bucket_wait bw = {&v, &fx};
    ASSERT_TRUE(pump_until_ms(fx.r, bucket_is_empty, &bw, WAIT_MS));
    ASSERT_EQ_INT(0, (int)cloak_valve_take_tx(&v, (int64_t)MAX_PAYLOAD));

    /* Both datagrams must still arrive. cloak/valve.h bounds the resume
     * delay at roughly a second for any rate worth configuring, so three
     * seconds on top of the four already spent above is generous; the
     * budget is wall-clock either way and a relay that armed no timer
     * never finishes it. */
    struct reader rd;
    memset(&rd, 0, sizeof(rd));
    rd.stream = fx.s;
    struct reader_wait rw = {&rd, 2};
    ASSERT_TRUE(pump_until_ms(fx.r, reader_has, &rw, 7000));
    ASSERT_EQ_INT(0, rd.ended);
    ASSERT_EQ_INT(2, (int)rd.count);
    for (size_t i = 0; i < rd.count && i < 2; i++) {
        ASSERT_EQ_INT((int)MAX_PAYLOAD, (int)rd.len[i]);
        ASSERT_TRUE(rd.bytes[i] != NULL);
        if (rd.bytes[i] != NULL) {
            ASSERT_MEM_EQ(rd.bytes[i], big, MAX_PAYLOAD);
        }
    }

    free(big);
    reader_free(&rd);
    close(sp.outer);
    fixture_stop(&fx);
}

/* ---- 7. the start verdict, at the exact byte ---------------------------- */

/* cloak_dgram_relay_start refuses with -2 -- the TRANSIENT code, the one
 * its caller retries -- when the session's pool could not hold one
 * worst-case frame at this moment, and returns 0 at exactly that
 * threshold. The quantity is cloak_stream_relay_frame_cost, shared with
 * the stream relay so the two cannot disagree; FRAME_COST above is the
 * same arithmetic written out, so a change to either header constant fails
 * the first assertion here rather than silently re-scaling the rest of
 * this file. */
static int start_verdict_at_cap(size_t cap) {
    struct fixture fx;
    if (fixture_start(&fx, cap, NULL) != 0) {
        return -99;
    }
    struct dgpair sp;
    if (dgpair_init(&sp, 0) != 0) {
        fixture_stop(&fx);
        return -99;
    }
    int rc = cloak_dgram_relay_start(&fx.dr, fx.r, &fx.b.sesh, fx.b.accepted, sp.inner, on_done,
                                     &fx.cap);
    if (rc == 0) {
        fx.relay_started = 1;
        fx.b.dr = &fx.dr;
    } else {
        /* A FAILED start leaves the descriptor with the caller, always. */
        close(sp.inner);
    }
    close(sp.outer);
    fixture_stop(&fx);
    return rc;
}

static void test_start_boundary_is_exactly_one_worst_case_frame(void) {
    ASSERT_EQ_INT((int)FRAME_COST,
                  (int)(CLOAK_CONN_RECORD_HEADER_LEN + MAX_PAYLOAD + CLOAK_FRAME_HEADER_LEN +
                        CLOAK_FRAME_MAX_EXTRA_LEN));
    ASSERT_EQ_INT(-2, start_verdict_at_cap(FRAME_COST - 1));
    ASSERT_EQ_INT(0, start_verdict_at_cap(FRAME_COST));
}

/* ---- 8. a failed start leaves nothing behind ---------------------------- */

/* The ownership rule with no exceptions: on ANY failure the descriptor is
 * still the caller's, and the struct is still safe to hand to
 * cloak_dgram_relay_stop. Both halves asserted -- the descriptor by
 * proving it is still open afterwards (fcntl on a closed fd fails with
 * EBADF), the struct by stopping it twice. */
static void test_failed_start_keeps_the_fd_and_leaves_a_safe_struct(void) {
    struct fixture fx;
    if (fixture_start(&fx, 0, NULL) != 0) {
        return;
    }

    struct dgpair sp;
    ASSERT_EQ_INT(0, dgpair_init(&sp, 0));

    cloak_dgram_relay_t dr;
    /* A NULL session is the argument failure this surface can provoke
     * without an allocator seam. */
    ASSERT_EQ_INT(-1, cloak_dgram_relay_start(&dr, fx.r, NULL, fx.b.accepted, sp.inner, on_done,
                                              &fx.cap));
    ASSERT_TRUE(fcntl(sp.inner, F_GETFD) != -1); /* still ours, still open */
    cloak_dgram_relay_stop(&dr);
    cloak_dgram_relay_stop(&dr); /* idempotent on a failed start */
    ASSERT_EQ_INT(0, fx.cap.calls);

    close(sp.inner);
    close(sp.outer);
    fixture_stop(&fx);
}

TEST_MAIN_BEGIN()
    test_relay_moves_datagrams_both_ways_at_the_boundary_sizes();
    test_upstream_error_ends_the_far_end_of_the_stream();
    test_a_refused_send_holds_the_datagram_rather_than_dropping_it();
    test_one_congested_connection_does_not_break_the_pool();
    test_notify_writable_pulls_without_another_readable_edge();
    test_an_empty_tx_bucket_pauses_and_the_timer_resumes();
    test_start_boundary_is_exactly_one_worst_case_frame();
    test_failed_start_keeps_the_fd_and_leaves_a_safe_struct();
TEST_MAIN_END()
