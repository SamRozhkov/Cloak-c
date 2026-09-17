#define _POSIX_C_SOURCE 200809L
#include "cloak/proxy.h"
#include "cloak/base64.h"
#include "cloak/clienthello.h"
#include "cloak/crypto.h"
#include "cloak/dispatcher.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "test_framework.h"
#include "client_harness.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* End-to-end coverage for the server's DATAGRAM upstream (module 9 task
 * 6): a real client handshake carrying the unordered flag, a real
 * dispatcher, a real unordered cloak_session_t on both sides, a real
 * cloak_proxy_t, and a real AF_INET SOCK_DGRAM socket as the upstream --
 * so a passing case here means datagrams genuinely cross the whole server
 * data path with their boundaries intact, not that a mock agreed with
 * itself.
 *
 * WHY A SEPARATE FILE FROM test_proxy_stream.c. That file's fake upstream
 * is a LISTENER: it accepts stream connections and echoes bytes, and
 * every one of its seventeen cases is written against a byte stream with
 * no boundaries to preserve. A datagram upstream has no accept at all --
 * one bound socket answers every stream's connected socket -- so sharing
 * the fixture would mean a second, disjoint upstream implementation
 * inside a file whose every existing case ignores it.
 *
 * EVERY wait here is a bounded pump_until and every socket is
 * non-blocking, for the reason test_proxy_stream.c states at the same
 * point: two of the three tests that have ever hung in this project's CI
 * were blocking reads on a peer socket, and this file deliberately
 * contains none.
 *
 * THE SIZES IN THIS FILE ARE NOT ARBITRARY, and they are the whole point
 * of cases 2 and 3. At the max_on_wire_size both ends of this tunnel use
 * (16401, which is Go's appDataMaxLength), max_payload_per_frame is
 * 16401 - CLOAK_FRAME_HEADER_LEN(14) - CLOAK_FRAME_MAX_EXTRA_LEN(255) =
 * 16132 -- see cloak/stream.h, which derives it and pins the derivation
 * in libcloak-mux's own suite. 16132 is therefore the largest datagram
 * this tunnel can carry and 16133 the first it cannot, and the plan's
 * decision D7 says exactly what each end must do with those two:
 *
 *   16132 from either side   CARRY IT. Go loses every reply in
 *                            8193..16132 and tears the peer's stream down
 *                            with it (scouting report bug 6).
 *   16133 from the upstream  DROP THE WHOLE DATAGRAM, and keep the stream
 *                            running. Go silently truncates to its read
 *                            buffer and delivers the fragment as if it
 *                            were the message (bug 7).
 *   zero length             SWALLOW IT, matching Go: cloak_stream_write
 *                            sends nothing for an empty payload (Go's
 *                            frame encoder refuses one outright), so a
 *                            zero-length datagram was never carryable.
 *                            What must NOT happen is the reading of it
 *                            being mistaken for end-of-stream, which is
 *                            what recv() == 0 means on a STREAM socket
 *                            and never means on a datagram one.
 */

/* ---- the fake upstream: one bound UDP socket, echo plus injection ----
 *
 * Deliberately NOT a cloak_listener_t: there is nothing to accept. One
 * socket receives from every stream's own connected socket, and
 * remembering the last sender is all that is needed to answer, because
 * each case here drives exactly one stream at a time. */

#define UP_MAX_DGRAMS 16
#define UP_DGRAM_CAP ((size_t)65536)

typedef struct {
    cloak_reactor_t *reactor;
    int fd;
    int port;

    /* The source address of the most recent datagram: what inject()
     * answers to. A connected UDP socket at the other end only accepts
     * datagrams from the address it connected to, so answering the last
     * sender is answering that stream's relay. */
    struct sockaddr_storage peer;
    socklen_t peer_len;
    int have_peer;

    int echo; /* 1: every received datagram is sent straight back */

    /* Every datagram received, in order, with its TRUE length (MSG_TRUNC,
     * so a datagram larger than the scratch buffer is recorded at its
     * real size rather than silently clipped -- the assertion that
     * catches a relay which coalesced two datagrams into one send needs
     * the true length, not the copied one). */
    size_t count;
    size_t len[UP_MAX_DGRAMS];
    uint8_t *bytes[UP_MAX_DGRAMS];

    uint8_t *scratch; /* UP_DGRAM_CAP, heap so the reactor callback's own
                       * frame stays small */
} udp_upstream_t;

static void up_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    (void)events;
    udp_upstream_t *up = userdata;
    for (;;) {
        struct sockaddr_storage from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(up->fd, up->scratch, UP_DGRAM_CAP, MSG_TRUNC,
                             (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break; /* EAGAIN, or a broken socket: the test's assertions report it */
        }
        up->peer = from;
        up->peer_len = from_len;
        up->have_peer = 1;

        if (up->count < UP_MAX_DGRAMS) {
            size_t copied = (size_t)n < UP_DGRAM_CAP ? (size_t)n : UP_DGRAM_CAP;
            up->len[up->count] = (size_t)n;
            up->bytes[up->count] = malloc(copied + 1);
            if (up->bytes[up->count] != NULL) {
                memcpy(up->bytes[up->count], up->scratch, copied);
            }
            up->count++;
        }
        if (up->echo) {
            (void)sendto(up->fd, up->scratch, (size_t)n < UP_DGRAM_CAP ? (size_t)n : UP_DGRAM_CAP,
                         0, (const struct sockaddr *)&from, from_len);
        }
    }
}

/* Sends one datagram of exactly len bytes to the last peer heard from.
 * Used by the cases that need the UPSTREAM to speak first with something
 * the client never asked for -- an oversize reply, an empty one. */
static int up_inject(udp_upstream_t *up, const uint8_t *buf, size_t len) {
    if (!up->have_peer) {
        return -1;
    }
    ssize_t n = sendto(up->fd, buf, len, 0, (const struct sockaddr *)&up->peer, up->peer_len);
    return n == (ssize_t)len ? 0 : -1;
}

static int up_open(udp_upstream_t *up, cloak_reactor_t *r) {
    memset(up, 0, sizeof(*up));
    up->reactor = r;
    up->fd = -1;
    up->echo = 1;
    up->scratch = malloc(UP_DGRAM_CAP);
    if (up->scratch == NULL) {
        return -1;
    }
    up->fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (up->fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0; /* ephemeral, like every other listener in these suites */
    if (bind(up->fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
        return -1;
    }
    struct sockaddr_in bound;
    socklen_t bound_len = sizeof(bound);
    if (getsockname(up->fd, (struct sockaddr *)&bound, &bound_len) != 0) {
        return -1;
    }
    up->port = (int)ntohs(bound.sin_port);
    if (cloak_reactor_add_fd(r, up->fd, CLOAK_REACTOR_READABLE, up_on_readable, up) != 0) {
        return -1;
    }
    return 0;
}

static void up_destroy(udp_upstream_t *up) {
    if (up->fd >= 0) {
        cloak_reactor_remove_fd(up->reactor, up->fd);
        close(up->fd);
        up->fd = -1;
    }
    for (size_t i = 0; i < UP_MAX_DGRAMS; i++) {
        free(up->bytes[i]);
        up->bytes[i] = NULL;
    }
    free(up->scratch);
    up->scratch = NULL;
}

struct up_wait {
    udp_upstream_t *up;
    size_t want;
};

static int up_received(void *ctx) {
    struct up_wait *w = ctx;
    return w->up->count >= w->want;
}

/* ---- fixture ------------------------------------------------------------- */

static void registry_on_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                               const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    (void)reg;
    (void)sesh;
    (void)uid;
    (void)session_id;
    (void)userdata;
}

struct fixture {
    cloak_reactor_t *reactor;

    cover_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;

    udp_upstream_t up;
    int up_ready;

    cloak_server_config_t cfg;
    cloak_server_t srv;
    int srv_ready;

    cloak_server_registry_t registry;
    int registry_ready;

    cloak_proxy_t proxy;
    int proxy_ready;

    cloak_dispatcher_t d;
    int d_ready;
    cloak_listener_t front;
    int have_front;

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_ok[CLOAK_UID_LEN];
};

/* conn_send_queue_cap sizes the SERVER session's outbound pool. Every
 * case but the backpressure one passes the roomy default through
 * fixture_init below; case 5 shrinks it, because the pause it exercises
 * is defined entirely in terms of that pool. */
static int fixture_init_opts(struct fixture *fx, size_t conn_send_queue_cap) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

    fx->cover.reactor = fx->reactor;
    fx->cover.fd = -1;
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->cover_listener, fx->reactor, "127.0.0.1:0",
                                         cover_on_accept, &fx->cover, err, sizeof(err)));
    fx->have_cover_listener = 1;
    int cover_port = cloak_listener_port(&fx->cover_listener);
    ASSERT_TRUE(cover_port > 0);

    ASSERT_EQ_INT(0, up_open(&fx->up, fx->reactor));
    fx->up_ready = 1;
    ASSERT_TRUE(fx->up.port > 0);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, fx->server_pub));

    for (size_t i = 0; i < CLOAK_UID_LEN; i++) {
        fx->uid_ok[i] = (uint8_t)(0x10 + i);
    }

    char priv_b64[64];
    char uidok_b64[32];
    ASSERT_EQ_INT(
        0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64, sizeof(priv_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(fx->uid_ok, CLOAK_UID_LEN, uidok_b64, sizeof(uidok_b64)));

    /* "udp" is the whole point: cloak_server_init resolves this entry to
     * SOCK_DGRAM, which is what selects the datagram relay. */
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"udp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\"]}",
             fx->up.port, cover_port, priv_b64, uidok_b64);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    ASSERT_EQ_INT(0,
                  cloak_server_registry_init(&fx->registry, fx->reactor, registry_on_broken, NULL));
    fx->registry_ready = 1;

    cloak_proxy_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.reactor = fx->reactor;
    pcfg.srv = &fx->srv;
    ASSERT_EQ_INT(0, cloak_proxy_init(&fx->proxy, &pcfg));
    fx->proxy_ready = 1;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.registry = &fx->registry;
    dcfg.session_config_template.max_on_wire_size = 16401;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = conn_send_queue_cap;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;
    dcfg.prepare_session = cloak_proxy_prepare_session;
    dcfg.prepare_session_userdata = &fx->proxy;
    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, "127.0.0.1:0",
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;

    /* The same 8 KiB SO_SNDBUF test_proxy_stream.c sets, for the same
     * reason and with an extra one here: both ends run on one reactor, so
     * with loopback's default multi-megabyte buffers the server's kernel
     * send buffer swallows everything and the session's outbound pool
     * never backs up -- which means the datagram relay's pool-bound pause
     * and its resume through proxy_on_writable would never run at all in
     * this file. At 8 KiB a single 16132-byte datagram is already larger
     * than the socket buffer, so case 2 exercises that pause and its
     * resume by construction rather than by luck. */
    int sndbuf = 8192;
    (void)setsockopt(fx->front.fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    return 0;
}

static int fixture_init(struct fixture *fx) {
    return fixture_init_opts(fx, 262144);
}

/* Destroy order is test_proxy_stream.c's, and for the reasons stated
 * there: the front listener first, the dispatcher next, THE PROXY BEFORE
 * THE REGISTRY (cloak_proxy_destroy stops every live relay, and a relay
 * must be stopped before the session it is bound to is destroyed), then
 * the server, the upstream, the cover site, the reactor. */
static void fixture_destroy(struct fixture *fx) {
    if (fx->have_front) {
        cloak_listener_close(&fx->front);
    }
    if (fx->d_ready) {
        cloak_dispatcher_destroy(&fx->d);
    }
    if (fx->proxy_ready) {
        cloak_proxy_destroy(&fx->proxy);
    }
    if (fx->registry_ready) {
        cloak_server_registry_destroy(&fx->registry);
    }
    if (fx->srv_ready) {
        cloak_server_destroy(&fx->srv);
    }
    if (fx->up_ready) {
        up_destroy(&fx->up);
    }
    if (fx->have_cover_listener) {
        cloak_listener_close(&fx->cover_listener);
    }
    if (fx->cover.fd >= 0) {
        close(fx->cover.fd);
    }
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
    }
}

static int front_port(struct fixture *fx) {
    return cloak_listener_port(&fx->front);
}

/* An UNORDERED client session: the handshake's flag byte AND the client
 * session's own ordering, which must agree -- the flag is what makes the
 * server build an unordered session, and the local ordering is what makes
 * this end frame one datagram per write. */
static int open_unordered_client(struct fixture *fx, client_session_t *cs, uint32_t session_id) {
    cloak_session_config_t ccfg;
    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.ordering = CLOAK_SESSION_ORDERING_UNORDERED;
    ccfg.max_on_wire_size = 16401;
    ccfg.stream_recv_capacity = 65536;
    ccfg.stream_max_pending_frames = 64;
    ccfg.conn_send_queue_cap = 262144;
    ccfg.inactivity_timeout_ms = 60000;
    return client_session_open(cs, fx->reactor, front_port(fx), fx->server_pub, fx->uid_ok, "ss",
                               session_id, 1, &ccfg);
}

/* The same handshake with the flag CLEAR and an ORDERED local session:
 * the other half of the "the upstream's socket type, and nothing else,
 * picks the relay" claim, which case 6 exists to pin. */
static int open_ordered_client(struct fixture *fx, client_session_t *cs, uint32_t session_id) {
    cloak_session_config_t ccfg;
    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.ordering = CLOAK_SESSION_ORDERING_ORDERED;
    ccfg.max_on_wire_size = 16401;
    ccfg.stream_recv_capacity = 65536;
    ccfg.stream_max_pending_frames = 64;
    ccfg.conn_send_queue_cap = 262144;
    ccfg.inactivity_timeout_ms = 60000;
    return client_session_open(cs, fx->reactor, front_port(fx), fx->server_pub, fx->uid_ok, "ss",
                               session_id, 0, &ccfg);
}

/* ---- client-side datagram reader ---------------------------------------
 *
 * Polls cloak_stream_read from inside the pump predicate, exactly as
 * test_proxy_stream.c's reader does and for the same reason (a poll
 * cannot miss an edge, so a predicate built on it is bounded by
 * construction) -- but records one entry PER DATAGRAM rather than
 * appending into one flat buffer, because every assertion in this file is
 * about where the boundaries fell.
 *
 * The read buffer is deliberately LARGER than max_payload_per_frame, so a
 * short-buffer return (-2) here would mean the stream layer produced a
 * datagram this tunnel could not have carried -- recorded as its own
 * outcome rather than folded into "ended", since folding those two
 * together is the exact defect cloak/stream.h's CLOAK_STREAM_ERR_SHORT_
 * BUFFER paragraph exists about. */
#define RD_MAX_DGRAMS 16
#define RD_BUF_CAP ((size_t)20000)

typedef struct {
    cloak_stream_t *stream;
    size_t count;
    size_t len[RD_MAX_DGRAMS];
    uint8_t *bytes[RD_MAX_DGRAMS];
    int ended;      /* cloak_stream_read reported end of stream */
    int short_buf;  /* cloak_stream_read reported -2 */
    uint8_t buf[RD_BUF_CAP];
} reader_t;

static void reader_poll(reader_t *rd) {
    for (;;) {
        if (rd->ended || rd->short_buf || rd->count >= RD_MAX_DGRAMS) {
            return;
        }
        long n = cloak_stream_read(rd->stream, rd->buf, RD_BUF_CAP);
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
            return;
        }
        if (n < 0) {
            rd->ended = 1;
        }
        return; /* n == 0: nothing queued right now */
    }
}

static void reader_free(reader_t *rd) {
    for (size_t i = 0; i < RD_MAX_DGRAMS; i++) {
        free(rd->bytes[i]);
        rd->bytes[i] = NULL;
    }
}

struct reader_wait {
    reader_t *rd;
    size_t want;
};

static int reader_received(void *ctx) {
    struct reader_wait *w = ctx;
    reader_poll(w->rd);
    return w->rd->count >= w->want || w->rd->ended || w->rd->short_buf;
}

static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + (i * 31u) + (i >> 8));
    }
}

/* Every wait in this file: 400 turns of 10 ms = 4 s of WALL CLOCK (see
 * pump_until, which is bounded by the clock and not by the count). That
 * is the same order as test_proxy_stream.c's own waits and far below the
 * file's 60 s ctest TIMEOUT, which is only a backstop. */
#define WAIT_TURNS 400
#define WAIT_MS 10

/* ---- tests ---------------------------------------------------------------
 *
 * 1. THE MODULE IN ONE CASE: three datagrams of different sizes reach a
 *    UDP upstream as three datagrams of exactly those sizes, and their
 *    replies come back the same way.
 *
 *    WHAT THIS CASE DOES AND DOES NOT CATCH, measured rather than
 *    assumed, because the natural claim to write here turned out to be
 *    FALSE. The obvious mutation to fear is a relay that buffers its
 *    stream-to-socket direction in a BYTE queue (which is exactly what
 *    cloak_stream_relay_t does) and concatenates two queued datagrams
 *    into one send(2) -- one 9692-byte datagram where three were sent.
 *    Forcing that mutation (proxy.c selecting the stream relay for a
 *    SOCK_DGRAM upstream) does NOT fail this case: it is killed by cases
 *    3 and 4 instead. The three writes below do happen before any
 *    pumping, and the intent was to have all three sitting in the
 *    server stream's queue when the relay starts -- but they do not get
 *    there. Measured with the stream relay forced: only ONE datagram
 *    reaches the upstream from the relay's own initial pump and the
 *    other two arrive one per on_stream_data notification, one send
 *    each, boundaries intact by accident. The window in which a byte
 *    queue could merge two datagrams end to end is the dial, and it is
 *    not reliably reachable from a test.
 *
 *    So what this case buys is the POSITIVE property stated plainly --
 *    three datagrams in, three datagrams out, each at its own length and
 *    with its own bytes, in both directions -- which is what a reader
 *    needs to see asserted somewhere, and which nothing else in the tree
 *    asserts end to end. The mutation that would merge them is killed
 *    elsewhere in this file, and saying so here is cheaper than leaving
 *    a claim that measurement contradicts.
 *
 *    1, 1500 and 8191 are cloak/stream.h's own worked example of
 *    boundary preservation, and 8191 additionally sits just under the
 *    8192 at which Go's own client starts losing data (bug 6) -- case 2
 *    takes that the rest of the way. */
static void test_datagram_round_trip_preserves_boundaries(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_unordered_client(&fx, &cs, 4101));
    if (cs.sesh.ordering != CLOAK_SESSION_ORDERING_UNORDERED) {
        /* The handshake was refused (redirected) -- every assertion below
         * would be about a session that does not exist, and dereferencing
         * a NULL stream would replace this file's named failure with a
         * segfault. Stop here and let the assertion above be the
         * diagnosis. */
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT((int)CLOAK_SESSION_ORDERING_UNORDERED, (int)cs.sesh.ordering);

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }

    /* 8192 and 8193 are the exact edge of the window Go loses (its
     * client reads replies into an 8192-byte buffer and breaks out of its
     * loop on the short-buffer error), so both are driven rather than
     * approached: the nearest pins used to be 8191 here and 16132 in case
     * 2, leaving the first byte Go actually drops untested. */
    const size_t sizes[5] = {1, 1500, 8191, 8192, 8193};
    uint8_t *sent[5];
    for (int i = 0; i < 5; i++) {
        sent[i] = malloc(sizes[i]);
        ASSERT_TRUE(sent[i] != NULL);
        fill_pattern(sent[i], sizes[i], (uint8_t)(0x40 + i));
        ASSERT_EQ_INT((int)sizes[i], (int)cloak_stream_write(st, sent[i], sizes[i]));
    }

    struct up_wait uw = {&fx.up, 5};
    ASSERT_TRUE(pump_until(fx.reactor, up_received, &uw, WAIT_TURNS, WAIT_MS));
    ASSERT_EQ_INT(5, (int)fx.up.count);
    for (int i = 0; i < 5 && i < (int)fx.up.count; i++) {
        ASSERT_EQ_INT((int)sizes[i], (int)fx.up.len[i]);
        ASSERT_TRUE(fx.up.bytes[i] != NULL);
        ASSERT_MEM_EQ(fx.up.bytes[i], sent[i], sizes[i]);
    }

    reader_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.stream = st;
    struct reader_wait rw = {&rd, 5};
    ASSERT_TRUE(pump_until(fx.reactor, reader_received, &rw, WAIT_TURNS, WAIT_MS));
    ASSERT_EQ_INT(0, rd.ended);
    ASSERT_EQ_INT(0, rd.short_buf);
    ASSERT_EQ_INT(5, (int)rd.count);
    for (int i = 0; i < 5 && i < (int)rd.count; i++) {
        ASSERT_EQ_INT((int)sizes[i], (int)rd.len[i]);
        ASSERT_TRUE(rd.bytes[i] != NULL);
        ASSERT_MEM_EQ(rd.bytes[i], sent[i], sizes[i]);
    }

    for (int i = 0; i < 5; i++) {
        free(sent[i]);
    }
    reader_free(&rd);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 2. 16132 BOTH WAYS, AND 16133 IS THE FIRST REFUSAL -- the size policy
 *    D7 settled, asserted at the exact byte rather than "a big one".
 *
 *    Go loses this datagram in BOTH directions and does it differently in
 *    each: its client's reader breaks out of its loop on the
 *    io.ErrShortBuffer that its 8192-byte read buffer produces (bug 6,
 *    which tears the whole peer stream down), and its server truncates an
 *    upstream datagram to whatever its own read buffer holds and forwards
 *    the fragment (bug 7). This port carries it whole in both directions,
 *    which is a deliberate divergence and is why this case asserts the
 *    length as well as the bytes: a truncating relay would still deliver
 *    a prefix that ASSERT_MEM_EQ over the shorter length would accept.
 *
 *    16133 -- one byte over -- is asserted in the client-to-upstream
 *    direction only, because that is where the refusal is visible as a
 *    return value: cloak_stream_write refuses it outright
 *    (CLOAK_STREAM_ERR_SHORT_BUFFER) having sent nothing, so nothing ever
 *    reaches the relay. The upstream-to-client direction's 16133 is case
 *    3, where the refusal has to be a DROP because the datagram is
 *    already out of the socket by the time its size is known. */
static void test_maximum_datagram_round_trips_and_one_more_is_refused(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_unordered_client(&fx, &cs, 4102));
    if (cs.sesh.ordering != CLOAK_SESSION_ORDERING_UNORDERED) {
        /* The handshake was refused (redirected) -- every assertion below
         * would be about a session that does not exist, and dereferencing
         * a NULL stream would replace this file's named failure with a
         * segfault. Stop here and let the assertion above be the
         * diagnosis. */
        fixture_destroy(&fx);
        return;
    }

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }

    /* Not a literal: the tunnel's own derived limit, so this case cannot
     * silently stop testing the boundary if max_on_wire_size ever moves.
     * It IS 16132 at the 16401 this fixture configures, and the two
     * assertions below say so, so a max_payload_per_frame that quietly
     * became something else fails here rather than passing vacuously. */
    ASSERT_EQ_INT(16132, (int)st->max_payload_per_frame);
    size_t big = st->max_payload_per_frame;

    uint8_t *payload = malloc(big + 1);
    ASSERT_TRUE(payload != NULL);
    fill_pattern(payload, big + 1, 0x9C);

    /* One byte over the limit is refused with nothing sent, and the
     * stream stays usable -- which the successful write below proves. */
    ASSERT_EQ_INT(CLOAK_STREAM_ERR_SHORT_BUFFER, (int)cloak_stream_write(st, payload, big + 1));
    ASSERT_EQ_INT(0, (int)fx.up.count);

    ASSERT_EQ_INT((int)big, (int)cloak_stream_write(st, payload, big));

    struct up_wait uw = {&fx.up, 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_received, &uw, WAIT_TURNS, WAIT_MS));
    ASSERT_EQ_INT(1, (int)fx.up.count);
    ASSERT_EQ_INT((int)big, (int)fx.up.len[0]);
    /* GUARDED, and the guard is not decoration: a regression that fails
     * the count above leaves this pointer NULL, and a segfault here takes
     * every LATER case in the file with it -- including case 5, the one
     * that exists for a mutation that already escaped once. Three
     * assertions in this file died that way under a reviewer's mutation
     * before these guards were added. */
    ASSERT_TRUE(fx.up.bytes[0] != NULL);
    if (fx.up.bytes[0] != NULL) {
        ASSERT_MEM_EQ(fx.up.bytes[0], payload, big);
    }

    reader_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.stream = st;
    struct reader_wait rw = {&rd, 1};
    ASSERT_TRUE(pump_until(fx.reactor, reader_received, &rw, WAIT_TURNS, WAIT_MS));
    ASSERT_EQ_INT(0, rd.ended);
    ASSERT_EQ_INT(0, rd.short_buf);
    ASSERT_EQ_INT(1, (int)rd.count);
    ASSERT_EQ_INT((int)big, (int)rd.len[0]);
    ASSERT_TRUE(rd.bytes[0] != NULL);
    if (rd.bytes[0] != NULL) {
        ASSERT_MEM_EQ(rd.bytes[0], payload, big);
    }

    free(payload);
    reader_free(&rd);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 3. AN OVERSIZE UPSTREAM DATAGRAM IS DROPPED WHOLE AND THE STREAM LIVES.
 *
 *    16133 bytes cannot be carried in one frame and this port will not
 *    split it (splitting is silent corruption in a mode whose far end
 *    does no reassembly). Go's server truncates to its read buffer and
 *    forwards the fragment as though it were the message -- bug 7, and a
 *    UDP application has no way to tell that fragment from a short reply.
 *
 *    WHAT THE FOLLOW-UP DATAGRAM IS FOR, and it is the whole case: the
 *    drop must not be a teardown. Datagrams keep their order on loopback,
 *    so the seven bytes below can only be the reader's SECOND datagram --
 *    which means a relay that forwarded the truncated 16132 fails on
 *    rd.len[1], and a relay that treated the oversize datagram as a fatal
 *    error fails by never delivering it at all (rd.ended, or the wait
 *    expiring). Asserting only "we did not receive 16133" would pass
 *    against both.
 *
 *    THE FIRST EXCHANGE IS NOT DECORATION: the upstream is a bound socket
 *    that has never heard from anyone, and up_inject answers the last
 *    sender. Something has to teach it who the relay is. */
static void test_oversize_upstream_datagram_is_dropped_not_truncated(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_unordered_client(&fx, &cs, 4103));
    if (cs.sesh.ordering != CLOAK_SESSION_ORDERING_UNORDERED) {
        /* The handshake was refused (redirected) -- every assertion below
         * would be about a session that does not exist, and dereferencing
         * a NULL stream would replace this file's named failure with a
         * segfault. Stop here and let the assertion above be the
         * diagnosis. */
        fixture_destroy(&fx);
        return;
    }

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }

    static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
    ASSERT_EQ_INT(5, (int)cloak_stream_write(st, hello, sizeof(hello)));

    reader_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.stream = st;

    struct up_wait uw = {&fx.up, 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_received, &uw, WAIT_TURNS, WAIT_MS));
    struct reader_wait rw = {&rd, 1};
    ASSERT_TRUE(pump_until(fx.reactor, reader_received, &rw, WAIT_TURNS, WAIT_MS));
    ASSERT_EQ_INT(1, (int)rd.count);
    ASSERT_EQ_INT(5, (int)rd.len[0]);

    /* From here the upstream speaks unprompted, so the echo would only
     * confuse the record. */
    fx.up.echo = 0;

    size_t over = st->max_payload_per_frame + 1;
    uint8_t *payload = malloc(over);
    ASSERT_TRUE(payload != NULL);
    fill_pattern(payload, over, 0x11);
    ASSERT_EQ_INT(0, up_inject(&fx.up, payload, over));

    static const uint8_t after[7] = {'a', 'f', 't', 'e', 'r', '!', '!'};
    ASSERT_EQ_INT(0, up_inject(&fx.up, after, sizeof(after)));

    struct reader_wait rw2 = {&rd, 2};
    ASSERT_TRUE(pump_until(fx.reactor, reader_received, &rw2, WAIT_TURNS, WAIT_MS));
    ASSERT_EQ_INT(0, rd.ended);
    ASSERT_EQ_INT(0, rd.short_buf);
    ASSERT_EQ_INT(2, (int)rd.count);
    if (rd.count >= 2) {
        ASSERT_EQ_INT((int)sizeof(after), (int)rd.len[1]);
        ASSERT_TRUE(rd.bytes[1] != NULL);
        if (rd.bytes[1] != NULL) {
            ASSERT_MEM_EQ(rd.bytes[1], after, sizeof(after));
        }
    }

    free(payload);
    reader_free(&rd);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 4. A ZERO-LENGTH UPSTREAM DATAGRAM IS SWALLOWED, NOT READ AS THE END OF
 *    THE UPSTREAM.
 *
 *    recv() returning 0 on a STREAM socket means the peer closed, and
 *    every relay in this tree is written against that. On a DATAGRAM
 *    socket it means an empty datagram arrived and the socket is
 *    perfectly healthy -- a connected UDP socket has no end-of-stream at
 *    all. A relay that reuses the stream reading's `n == 0 -> finish`
 *    would tear a live stream down on a single empty packet, which any
 *    peer on the internet can send.
 *
 *    Swallowing rather than carrying matches Go and is forced anyway:
 *    cloak_stream_write sends nothing for an empty payload because Go's
 *    frame encoder refuses one, so there is no frame in which an empty
 *    datagram could cross.
 *
 *    The follow-up datagram is load-bearing for the same reason as in
 *    case 3: it is the only thing that distinguishes "swallowed" from
 *    "ended the stream", and the assertion that rd.count is exactly 1
 *    afterwards is what distinguishes it from "carried an empty
 *    datagram". */
static void test_zero_length_upstream_datagram_is_swallowed(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_unordered_client(&fx, &cs, 4104));
    if (cs.sesh.ordering != CLOAK_SESSION_ORDERING_UNORDERED) {
        /* The handshake was refused (redirected) -- every assertion below
         * would be about a session that does not exist, and dereferencing
         * a NULL stream would replace this file's named failure with a
         * segfault. Stop here and let the assertion above be the
         * diagnosis. */
        fixture_destroy(&fx);
        return;
    }

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }

    static const uint8_t ping[4] = {'p', 'i', 'n', 'g'};
    fx.up.echo = 0; /* the upstream answers by injection only, below */
    ASSERT_EQ_INT(4, (int)cloak_stream_write(st, ping, sizeof(ping)));

    struct up_wait uw = {&fx.up, 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_received, &uw, WAIT_TURNS, WAIT_MS));
    ASSERT_EQ_INT(4, (int)fx.up.len[0]);

    ASSERT_EQ_INT(0, up_inject(&fx.up, (const uint8_t *)"", 0));

    static const uint8_t pong[4] = {'p', 'o', 'n', 'g'};
    ASSERT_EQ_INT(0, up_inject(&fx.up, pong, sizeof(pong)));

    reader_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.stream = st;
    struct reader_wait rw = {&rd, 1};
    ASSERT_TRUE(pump_until(fx.reactor, reader_received, &rw, WAIT_TURNS, WAIT_MS));
    ASSERT_EQ_INT(0, rd.ended);
    ASSERT_EQ_INT(0, rd.short_buf);
    ASSERT_EQ_INT(1, (int)rd.count);
    if (rd.count >= 1) {
        ASSERT_EQ_INT((int)sizeof(pong), (int)rd.len[0]);
        ASSERT_TRUE(rd.bytes[0] != NULL);
        if (rd.bytes[0] != NULL) {
            ASSERT_MEM_EQ(rd.bytes[0], pong, sizeof(pong));
        }
    }

    reader_free(&rd);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 5. A READ PAUSED BY A FULL OUTBOUND POOL IS RESUMED, AND NOTHING IS
 *    LOST ACROSS THE PAUSE.
 *
 *    WHY THIS CASE EXISTS: MEASUREMENT, not symmetry. With the roomy pool
 *    the other four cases use, deleting the datagram relay's resume
 *    entirely -- making proxy_on_writable skip it -- changed NOTHING: all
 *    four passed against a relay that, once paused, would never read its
 *    socket again. That mutation is the single worst one available here,
 *    because a stalled relay is indistinguishable from a working one
 *    until somebody notices the transfer stopped, and it survived. This
 *    case is what kills it.
 *
 *    HOW THE PAUSE IS FORCED, and it is forced rather than hoped for. The
 *    relay refuses to read a datagram it might not be able to place: it
 *    pauses whenever the MINIMUM free space over the session pool is
 *    below one worst-case frame (16406 on-wire bytes at this
 *    configuration -- see cloak_stream_relay_frame_cost). A pool of two
 *    such frames plus the fixture's deliberately small 8 KiB socket send
 *    buffer means the second large datagram in a burst cannot fit, so the
 *    burst below cannot cross without at least one pause and at least one
 *    resume. The only thing that can deliver that resume is the session's
 *    drained notification reaching this relay: the fd's own read interest
 *    is dropped while paused, no timer is armed (there is no valve in
 *    this fixture), and the upstream has already sent everything it is
 *    going to send.
 *
 *    ORDER IS ASSERTED ALONGSIDE COUNT, because a resume that re-reads
 *    the socket out of order -- or a pause that dropped the datagram it
 *    was holding -- would still deliver six. */
static void test_a_paused_read_is_resumed_when_the_pool_drains(void) {
    struct fixture fx;
    /* Two worst-case frames. Not a round number on purpose: it is
     * 2 * (CLOAK_CONN_RECORD_HEADER_LEN + max_payload_per_frame +
     * CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN) at
     * max_on_wire_size 16401, i.e. exactly the quantity the relay's own
     * pause test is written against. */
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, 2 * 16406));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_unordered_client(&fx, &cs, 4105));
    if (cs.sesh.ordering != CLOAK_SESSION_ORDERING_UNORDERED) {
        fixture_destroy(&fx);
        return;
    }

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }

    fx.up.echo = 0;
    static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
    ASSERT_EQ_INT(5, (int)cloak_stream_write(st, hello, sizeof(hello)));

    struct up_wait uw = {&fx.up, 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_received, &uw, WAIT_TURNS, WAIT_MS));

    /* Six datagrams at the tunnel's maximum, all handed to the socket
     * before the relay has a chance to read any of them: 96 KiB of
     * payload through a 32 KiB pool. */
    const size_t big = st->max_payload_per_frame;
    const int burst = 6;
    uint8_t *payload = malloc(big);
    ASSERT_TRUE(payload != NULL);
    if (payload == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    for (int i = 0; i < burst; i++) {
        fill_pattern(payload, big, (uint8_t)(0x60 + i));
        ASSERT_EQ_INT(0, up_inject(&fx.up, payload, big));
    }

    reader_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.stream = st;
    struct reader_wait rw = {&rd, (size_t)burst};
    ASSERT_TRUE(pump_until(fx.reactor, reader_received, &rw, WAIT_TURNS, WAIT_MS));
    ASSERT_EQ_INT(0, rd.ended);
    ASSERT_EQ_INT(0, rd.short_buf);
    ASSERT_EQ_INT(burst, (int)rd.count);
    for (int i = 0; i < burst && i < (int)rd.count; i++) {
        fill_pattern(payload, big, (uint8_t)(0x60 + i));
        ASSERT_EQ_INT((int)big, (int)rd.len[i]);
        ASSERT_TRUE(rd.bytes[i] != NULL);
        if (rd.bytes[i] != NULL) {
            ASSERT_MEM_EQ(rd.bytes[i], payload, big);
        }
    }

    free(payload);
    reader_free(&rd);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 6. AN ORDERED SESSION AGAINST A DATAGRAM UPSTREAM -- the combination
 *    that pins "the upstream's socket type, and NOTHING ELSE, picks the
 *    relay".
 *
 *    That sentence is this module's headline design decision, argued at
 *    length in proxy.c, in proxy.h and in the commit message, and until
 *    this case it was pinned by nothing: a review swapped the
 *    discriminator for the SESSION's ordering mode -- `is_dgram =
 *    sesh->ordering == UNORDERED`, which is exactly the mistake the prose
 *    argues against -- and all 73 tests passed, because every case that
 *    moved a byte through a datagram upstream also happened to have an
 *    unordered session.
 *
 *    WHAT MAKES THIS CASE DECIDE IT is the zero-length reply, not the
 *    round trip. Bytes cross either relay here: an ordered stream spliced
 *    to a datagram socket works in both, because each read of the byte
 *    stream simply becomes one datagram (which is also what Go does, and
 *    is why this combination is legal rather than refused). What does NOT
 *    survive the wrong relay is an empty datagram: cloak_stream_relay_t
 *    reads its fd with read(2) and treats 0 as END OF STREAM, so under
 *    the swapped discriminator this stream dies on the empty packet and
 *    the reply after it never arrives. The datagram relay swallows it and
 *    carries on.
 *
 *    So the follow-up datagram is the assertion, exactly as in case 4 --
 *    and "we did not receive an empty one" would pass against both. */
static void test_an_ordered_session_against_a_datagram_upstream(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_ordered_client(&fx, &cs, 4106));
    if (cs.sesh.ordering != CLOAK_SESSION_ORDERING_ORDERED) {
        fixture_destroy(&fx);
        return;
    }

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }

    fx.up.echo = 0; /* the upstream answers by injection only */
    static const uint8_t ping[4] = {'p', 'i', 'n', 'g'};
    ASSERT_EQ_INT(4, (int)cloak_stream_write(st, ping, sizeof(ping)));

    /* The ordered stream's bytes reach the upstream as ONE datagram --
     * one read of the byte stream, one send -- which is Go's behaviour
     * for this combination too. */
    struct up_wait uw = {&fx.up, 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_received, &uw, WAIT_TURNS, WAIT_MS));
    ASSERT_EQ_INT(1, (int)fx.up.count);
    ASSERT_EQ_INT(4, (int)fx.up.len[0]);
    ASSERT_TRUE(fx.up.bytes[0] != NULL);
    if (fx.up.bytes[0] != NULL) {
        ASSERT_MEM_EQ(fx.up.bytes[0], ping, sizeof(ping));
    }

    ASSERT_EQ_INT(0, up_inject(&fx.up, (const uint8_t *)"", 0));
    static const uint8_t pong[4] = {'p', 'o', 'n', 'g'};
    ASSERT_EQ_INT(0, up_inject(&fx.up, pong, sizeof(pong)));

    reader_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.stream = st;
    struct reader_wait rw = {&rd, 1};
    ASSERT_TRUE(pump_until(fx.reactor, reader_received, &rw, WAIT_TURNS, WAIT_MS));
    ASSERT_EQ_INT(0, rd.ended);
    ASSERT_EQ_INT(1, (int)rd.count);
    if (rd.count >= 1) {
        ASSERT_EQ_INT((int)sizeof(pong), (int)rd.len[0]);
        ASSERT_TRUE(rd.bytes[0] != NULL);
        if (rd.bytes[0] != NULL) {
            ASSERT_MEM_EQ(rd.bytes[0], pong, sizeof(pong));
        }
    }

    reader_free(&rd);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

TEST_MAIN_BEGIN()
    test_datagram_round_trip_preserves_boundaries();
    test_maximum_datagram_round_trips_and_one_more_is_refused();
    test_oversize_upstream_datagram_is_dropped_not_truncated();
    test_zero_length_upstream_datagram_is_swallowed();
    test_a_paused_read_is_resumed_when_the_pool_drains();
    test_an_ordered_session_against_a_datagram_upstream();
TEST_MAIN_END()
