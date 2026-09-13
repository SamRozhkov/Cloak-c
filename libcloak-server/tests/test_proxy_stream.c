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

/* End-to-end coverage for cloak_proxy_t: a real client handshake (see
 * client_harness.h), a real dispatcher, a real cloak_session_t on both
 * sides, and a real upstream socket -- so a passing test here means the
 * whole server data path genuinely carries bytes, not that the proxy
 * agrees with a mock.
 *
 * EVERY wait in this file is a bounded pump_until and EVERY peer socket
 * is non-blocking (the fake upstream's connections are registered with
 * the reactor, which forces O_NONBLOCK itself). Three tests on this
 * project have hung or flaked in CI and two of them were blocking read()
 * calls on a peer socket; this file deliberately contains none. */

/* test_permanent_start_failure_is_not_retried provokes a PERMANENT
 * cloak_stream_relay_start failure the only way this module's public
 * surface allows: a relay_buf_cap so large that the relay's byte-queue
 * allocation cannot succeed. Under the sanitizer suite an allocation
 * that big is an "allocation-size-too-big" hard error rather than a NULL
 * return, which would abort the whole binary before the code under test
 * ever ran. This is ASan's own documented opt-out hook, linked into the
 * test binary itself so the build needs no ASAN_OPTIONS plumbing and the
 * plain Debug build is unaffected (nothing ever calls it there). It is
 * scoped to allocator behaviour only: every memory-error check ASan
 * performs for this binary is untouched. */
const char *__asan_default_options(void);
const char *__asan_default_options(void) {
    return "allocator_may_return_null=1";
}

/* ---- fake upstream: records everything it receives, echoes it back ---- */

/* UP_MAX_CONNS is sized by the most demanding test in the file, which is
 * test_stream_cap_is_released_when_streams_end: it deliberately opens and
 * closes more streams in sequence than the total cap's worth, and every
 * one of them dials a fresh upstream connection (accept_count only ever
 * grows). Buffers are allocated per ACCEPTED connection, so the headroom
 * costs nothing in the tests that use one or two. */
#define UP_MAX_CONNS 12
#define UP_BUF_CAP ((size_t)(1u << 20))

typedef struct {
    int fd;
    uint8_t *in; /* everything ever read, for byte-for-byte assertions */
    size_t in_len;
    uint8_t *out; /* pending echo bytes not yet accepted by the socket */
    size_t out_len;
    size_t out_head;
    int eof;
} up_conn_t;

/* The reactor callback needs both the owner and which connection fired;
 * each connection therefore carries its own (owner, index) pair, whose
 * address is what gets registered as userdata. Recovering the owner from
 * the conn pointer by arithmetic would work too, and is exactly the kind
 * of cleverness a test should not be spending its reader's attention on. */
struct upstream;
typedef struct {
    struct upstream *up;
    int idx;
} up_slot_t;

typedef struct upstream {
    cloak_reactor_t *reactor;
    int accept_count;
    up_conn_t conns[UP_MAX_CONNS];
    up_slot_t slots[UP_MAX_CONNS];
} upstream_t;

static void up_flush(up_conn_t *c) {
    while (c->out_head < c->out_len) {
        ssize_t n = send(c->fd, c->out + c->out_head, c->out_len - c->out_head, MSG_NOSIGNAL);
        if (n > 0) {
            c->out_head += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break; /* EAGAIN, or the peer is gone: the writable event resumes us */
    }
    if (c->out_head == c->out_len) {
        c->out_head = 0;
        c->out_len = 0;
    }
}

static void up_sync(upstream_t *up, up_conn_t *c) {
    uint32_t ev = CLOAK_REACTOR_READABLE;
    if (c->out_head < c->out_len) {
        ev |= CLOAK_REACTOR_WRITABLE;
    }
    (void)cloak_reactor_mod_fd(up->reactor, c->fd, ev);
}

static void up_on_readable_writable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    up_slot_t *slot = userdata;
    upstream_t *up = slot->up;
    up_conn_t *c = &up->conns[slot->idx];

    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        up_flush(c);
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        /* Edge-triggered: read until EAGAIN or the buffers are full. */
        for (;;) {
            if (c->in_len >= UP_BUF_CAP) {
                break;
            }
            size_t room = UP_BUF_CAP - c->in_len;
            if (UP_BUF_CAP - c->out_len < room) {
                room = UP_BUF_CAP - c->out_len;
            }
            if (room == 0) {
                break;
            }
            ssize_t n = read(c->fd, c->in + c->in_len, room);
            if (n > 0) {
                memcpy(c->out + c->out_len, c->in + c->in_len, (size_t)n);
                c->out_len += (size_t)n;
                c->in_len += (size_t)n;
                up_flush(c);
                continue;
            }
            if (n == 0) {
                c->eof = 1;
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            break;
        }
    }
    up_sync(up, c);
}

static void up_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    upstream_t *up = userdata;
    if (up->accept_count >= UP_MAX_CONNS) {
        close(fd);
        return;
    }
    int idx = up->accept_count++;
    up_conn_t *c = &up->conns[idx];
    c->fd = fd;
    c->in = malloc(UP_BUF_CAP);
    c->out = malloc(UP_BUF_CAP);
    if (c->in == NULL || c->out == NULL) {
        free(c->in);
        free(c->out);
        c->in = NULL;
        c->out = NULL;
        close(fd);
        c->fd = -1;
        return;
    }
    up->slots[idx].up = up;
    up->slots[idx].idx = idx;
    (void)cloak_reactor_add_fd(up->reactor, fd, CLOAK_REACTOR_READABLE, up_on_readable_writable,
                               &up->slots[idx]);
}

static void up_close_conn(upstream_t *up, int idx) {
    up_conn_t *c = &up->conns[idx];
    if (c->fd >= 0) {
        cloak_reactor_remove_fd(up->reactor, c->fd);
        close(c->fd);
        c->fd = -1;
    }
}

static void up_destroy(upstream_t *up) {
    for (int i = 0; i < UP_MAX_CONNS; i++) {
        up_close_conn(up, i);
        free(up->conns[i].in);
        free(up->conns[i].out);
        up->conns[i].in = NULL;
        up->conns[i].out = NULL;
    }
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

    upstream_t up;
    cloak_listener_t up_listener;
    int have_up_listener;
    int up_port;

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

/* transport is the ProxyBook entry's declared transport: "tcp" for every
 * traffic-carrying test, "udp" for the redirect case (test 9).
 *
 * conn_send_queue_cap sizes the SERVER session's outbound pool;
 * relay_buf_cap, retry_delay_ms and max_retries go straight into
 * cloak_proxy_config_t. Every test but the two retry-policy ones passes
 * the defaults (see fixture_init below): test 10 overrides the pool size
 * and the ladder, because the transient rejection it exercises is
 * defined entirely in terms of that pool; test 11 overrides
 * relay_buf_cap, because a permanent failure is the only kind this
 * module's public surface can provoke at all.
 *
 * max_streams_per_session / max_streams_total go straight into
 * cloak_proxy_config_t too, and are left at 0 (the 256/4096 defaults) by
 * every test but the three cap tests -- which set them to values a test
 * can actually reach, since reaching 256 streams would mean 256 upstream
 * connections and prove nothing extra. */
static int fixture_init_opts(struct fixture *fx, const char *transport,
                             size_t conn_send_queue_cap, size_t relay_buf_cap,
                             uint64_t retry_delay_ms, unsigned max_retries,
                             size_t max_streams_per_session, size_t max_streams_total) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    for (int i = 0; i < UP_MAX_CONNS; i++) {
        fx->up.conns[i].fd = -1;
    }

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

    fx->up.reactor = fx->reactor;
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->up_listener, fx->reactor, "127.0.0.1:0", up_on_accept,
                                         &fx->up, err, sizeof(err)));
    fx->have_up_listener = 1;
    fx->up_port = cloak_listener_port(&fx->up_listener);
    ASSERT_TRUE(fx->up_port > 0);

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

    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"%s\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\"]}",
             transport, fx->up_port, cover_port, priv_b64, uidok_b64);
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
    /* Left at 0 by every caller but tests 10 and 11, so the rest exercise
     * the CLOAK_PROXY_DEFAULT_* constants rather than values invented
     * here. */
    pcfg.relay_buf_cap = relay_buf_cap;
    pcfg.retry_delay_ms = retry_delay_ms;
    pcfg.max_retries = max_retries;
    pcfg.max_streams_per_session = max_streams_per_session;
    pcfg.max_streams_total = max_streams_total;
    ASSERT_EQ_INT(0, cloak_proxy_init(&fx->proxy, &pcfg));
    fx->proxy_ready = 1;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.registry = &fx->registry;

    /* The same mux parameters test_dispatcher_auth.c uses; 60000ms of
     * inactivity is generous relative to every bounded pump in this file. */
    dcfg.session_config_template.max_on_wire_size = 16401;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = conn_send_queue_cap;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;

    dcfg.prepare_session = cloak_proxy_prepare_session;
    dcfg.prepare_session_userdata = &fx->proxy;
    dcfg.attached = cloak_proxy_attached;
    dcfg.attached_userdata = &fx->proxy;

    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, "127.0.0.1:0",
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;

    /* Shrink the send buffer of every socket this listener accepts (Linux
     * hands an accepted socket the listener's own SO_SNDBUF), so that the
     * session's outbound pool can ACTUALLY back up.
     *
     * This is not tuning, it is the only way to reach a whole branch.
     * Both ends of these tests run on one reactor and the client's
     * connection drains its socket on every turn, so with loopback's
     * default multi-megabyte buffers the server's kernel send buffer
     * swallows an entire transfer: cloak_conn_t never becomes
     * backpressured, on_drained therefore never fires, and the session's
     * on_writable -- and with it cloak_proxy_t's whole obligation-3
     * forwarding path and cloak_stream_relay_t's paused-read resume --
     * is never invoked at all. Verified by mutation: with a default
     * buffer, making proxy_on_writable a no-op did not fail a single
     * assertion in this file. */
    int sndbuf = 8192;
    (void)setsockopt(fx->front.fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    return 0;
}

/* The ordinary fixture: a roomy server-side pool and cloak_proxy_t's own
 * defaults for everything. */
static int fixture_init(struct fixture *fx, const char *transport) {
    return fixture_init_opts(fx, transport, 262144, 0, 0, 0, 0, 0);
}

/* Destroy order, and why each step is where it is:
 *   - the front listener first, so nothing new arrives mid-teardown;
 *   - the dispatcher next, matching test_dispatcher_auth.c (a connection
 *     dropped mid-authentication can still call into the registry);
 *   - THE PROXY BEFORE THE REGISTRY: cloak_proxy_destroy stops every
 *     live cloak_stream_relay_t, and cloak/stream_relay.h requires that
 *     to happen before the session a relay is bound to is destroyed --
 *     which is exactly what cloak_server_registry_destroy does next;
 *   - then the server, the fake upstream, the cover site, the reactor. */
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
    if (fx->have_up_listener) {
        cloak_listener_close(&fx->up_listener);
    }
    up_destroy(&fx->up);
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

static int open_client(struct fixture *fx, client_session_t *cs, uint32_t session_id) {
    cloak_session_config_t ccfg;
    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.max_on_wire_size = 16401;
    ccfg.stream_recv_capacity = 65536;
    ccfg.stream_max_pending_frames = 64;
    ccfg.conn_send_queue_cap = 262144;
    ccfg.inactivity_timeout_ms = 60000;
    return client_session_open(cs, fx->reactor, front_port(fx), fx->server_pub, fx->uid_ok, "ss",
                               session_id, 0, &ccfg);
}

/* ---- client-side stream helpers -----------------------------------------
 *
 * Reading is done by POLLING cloak_stream_read into an accumulating
 * buffer from inside the pump predicate, rather than by wiring a
 * client-side on_stream_data: the poll cannot miss an edge, so a
 * predicate built on it is bounded by construction. */

typedef struct {
    cloak_stream_t *stream;
    uint8_t *buf;
    size_t cap;
    size_t len;
    int ended; /* cloak_stream_read reported end-of-stream */
} reader_t;

static int reader_poll(reader_t *rd) {
    for (;;) {
        if (rd->len >= rd->cap) {
            return rd->ended;
        }
        long n = cloak_stream_read(rd->stream, rd->buf + rd->len, rd->cap - rd->len);
        if (n > 0) {
            rd->len += (size_t)n;
            continue;
        }
        if (n < 0) {
            rd->ended = 1;
        }
        return rd->ended;
    }
}

struct reader_wait {
    reader_t *rd;
    size_t want;
};

static int reader_has(void *ctx) {
    struct reader_wait *w = ctx;
    reader_poll(w->rd);
    return w->rd->len >= w->want;
}

static int reader_ended(void *ctx) {
    reader_t *rd = ctx;
    return reader_poll(rd);
}

/* Writes a large buffer in frame-sized chunks, pausing whenever the
 * session's own per-connection send budget would not certainly hold one
 * more worst-case frame. cloak_stream_write never fails on a full queue
 * (see cloak/session.h), so an unpaced bulk write does not error -- it
 * overruns a connection's hard cap and breaks the whole pool, which is
 * why this mirrors what cloak_stream_relay_t does internally rather than
 * checking a return value. 2 * max_on_wire_size is deliberately more
 * headroom than one frame can possibly cost. */
typedef struct {
    client_session_t *cs;
    reader_t *rd; /* drained as we go, so the echo cannot back up */
    cloak_stream_t *stream;
    const uint8_t *buf;
    size_t len;
    size_t sent;
} writer_t;

static int writer_step(void *ctx) {
    writer_t *w = ctx;
    if (w->rd != NULL) {
        reader_poll(w->rd);
    }
    while (w->sent < w->len) {
        if (cloak_session_send_min_conn_free(&w->cs->sesh) < 2 * 16401) {
            break;
        }
        size_t chunk = w->stream->max_payload_per_frame;
        if (chunk > w->len - w->sent) {
            chunk = w->len - w->sent;
        }
        if (cloak_stream_write(w->stream, w->buf + w->sent, chunk) < 0) {
            return 1; /* broken: let the caller's assertions report it */
        }
        w->sent += chunk;
    }
    return w->sent >= w->len;
}

struct up_wait {
    upstream_t *up;
    int idx;
    size_t want;
};

static int up_has_len(void *ctx) {
    struct up_wait *w = ctx;
    return w->up->conns[w->idx].in_len >= w->want;
}

static int up_accepted(void *ctx) {
    struct up_wait *w = ctx;
    return w->up->accept_count >= w->idx;
}

static int up_saw_eof(void *ctx) {
    struct up_wait *w = ctx;
    return w->up->conns[w->idx].eof;
}

struct count_wait {
    cloak_proxy_t *p;
    size_t want;
};

static int proxy_streams_eq(void *ctx) {
    struct count_wait *w = ctx;
    return cloak_proxy_stream_count(w->p) == w->want;
}

/* ---- tests ---------------------------------------------------------------- */

/* 1. One stream, bytes both ways: the whole module in one test. */
static void test_one_stream_both_ways(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "tcp"));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1001));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(4, (int)cloak_stream_write(st, (const uint8_t *)"ping", 4));

    struct up_wait uw = {&fx.up, 0, 4};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(1, fx.up.accept_count);
    ASSERT_EQ_INT(4, (int)fx.up.conns[0].in_len);
    ASSERT_MEM_EQ(fx.up.conns[0].in, "ping", 4);

    uint8_t back[16];
    reader_t rd = {st, back, sizeof(back), 0, 0};
    struct reader_wait rw = {&rd, 4};
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rw, 400, 5));
    ASSERT_EQ_INT(4, (int)rd.len);
    ASSERT_MEM_EQ(rd.buf, "ping", 4);

    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 2. Data that arrived before the relay started. "EARLY" is written in
 * the same turn the stream is opened, so it is sitting in the server
 * stream's receive buffer before the dial has even completed; only the
 * relay's own initial pump gets it out. "LATE" is written after the
 * upstream connection exists, so the assertion is about ORDER across the
 * relay-start boundary, not merely delivery. */
static void test_preexisting_bytes_reach_upstream(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "tcp"));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1002));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(5, (int)cloak_stream_write(st, (const uint8_t *)"EARLY", 5));

    struct up_wait uw = {&fx.up, 0, 5};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_MEM_EQ(fx.up.conns[0].in, "EARLY", 5);

    ASSERT_EQ_INT(4, (int)cloak_stream_write(st, (const uint8_t *)"LATE", 4));
    uw.want = 9;
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(9, (int)fx.up.conns[0].in_len);
    ASSERT_MEM_EQ(fx.up.conns[0].in, "EARLYLATE", 9);

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 3. Two streams on one session, interleaved. Each stream is opened and
 * connected one at a time so the (stream -> upstream connection) mapping
 * is deterministic; the TRAFFIC is then interleaved, which is what a
 * routing bug that crossed the two would corrupt. */
static void test_two_streams_do_not_cross(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "tcp"));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1003));

    cloak_stream_t *s1 = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(s1 != NULL);
    if (s1 == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(2, (int)cloak_stream_write(s1, (const uint8_t *)"a1", 2));
    struct up_wait w1 = {&fx.up, 1, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &w1, 400, 5));

    cloak_stream_t *s2 = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(s2 != NULL);
    if (s2 == NULL) {
        cloak_session_release_stream(&cs.sesh, s1);
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(2, (int)cloak_stream_write(s2, (const uint8_t *)"b1", 2));
    struct up_wait w2 = {&fx.up, 2, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &w2, 400, 5));
    ASSERT_EQ_INT(2, fx.up.accept_count);

    ASSERT_EQ_INT(2, (int)cloak_stream_write(s1, (const uint8_t *)"a2", 2));
    ASSERT_EQ_INT(2, (int)cloak_stream_write(s2, (const uint8_t *)"b2", 2));

    struct up_wait c0 = {&fx.up, 0, 4};
    struct up_wait c1 = {&fx.up, 1, 4};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &c0, 400, 5));
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &c1, 400, 5));

    ASSERT_EQ_INT(4, (int)fx.up.conns[0].in_len);
    ASSERT_EQ_INT(4, (int)fx.up.conns[1].in_len);
    ASSERT_MEM_EQ(fx.up.conns[0].in, "a1a2", 4);
    ASSERT_MEM_EQ(fx.up.conns[1].in, "b1b2", 4);

    uint8_t b1[16];
    uint8_t b2[16];
    reader_t r1 = {s1, b1, sizeof(b1), 0, 0};
    reader_t r2 = {s2, b2, sizeof(b2), 0, 0};
    struct reader_wait rw1 = {&r1, 4};
    struct reader_wait rw2 = {&r2, 4};
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rw1, 400, 5));
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rw2, 400, 5));
    ASSERT_EQ_INT(4, (int)r1.len);
    ASSERT_EQ_INT(4, (int)r2.len);
    ASSERT_MEM_EQ(r1.buf, "a1a2", 4);
    ASSERT_MEM_EQ(r2.buf, "b1b2", 4);

    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));

    cloak_session_release_stream(&cs.sesh, s1);
    cloak_session_release_stream(&cs.sesh, s2);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 4. A 512 KiB round trip through one stream, asserted byte for byte,
 * with the session still open and usable afterwards. Broken backpressure
 * fails this by BREAKING the session (cloak_stream_write never reports a
 * full queue -- it overruns a connection's hard cap one layer down), not
 * by corrupting data, which is why liveness is asserted separately at the
 * end via a second stream. */
#define BIG_LEN ((size_t)(512u * 1024u))

static void test_large_transfer_round_trip(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "tcp"));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1004));

    uint8_t *src = malloc(BIG_LEN);
    uint8_t *dst = malloc(BIG_LEN);
    ASSERT_TRUE(src != NULL && dst != NULL);
    if (src == NULL || dst == NULL) {
        free(src);
        free(dst);
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    for (size_t i = 0; i < BIG_LEN; i++) {
        src[i] = (uint8_t)((i * 31u + (i >> 8)) & 0xff);
    }

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        free(src);
        free(dst);
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }

    reader_t rd = {st, dst, BIG_LEN, 0, 0};
    writer_t w = {&cs, &rd, st, src, BIG_LEN, 0};
    ASSERT_TRUE(pump_until(fx.reactor, writer_step, &w, 8000, 2));
    ASSERT_EQ_INT((int)BIG_LEN, (int)w.sent);

    struct up_wait uw = {&fx.up, 0, BIG_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 8000, 2));
    ASSERT_EQ_INT((int)BIG_LEN, (int)fx.up.conns[0].in_len);
    ASSERT_MEM_EQ(fx.up.conns[0].in, src, BIG_LEN);

    struct reader_wait rw = {&rd, BIG_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rw, 8000, 2));
    ASSERT_EQ_INT((int)BIG_LEN, (int)rd.len);
    ASSERT_MEM_EQ(rd.buf, src, BIG_LEN);

    /* Liveness: the session survived the transfer and still carries a
     * brand-new stream end to end. */
    ASSERT_EQ_INT(0, cs.broken);
    cloak_stream_t *st2 = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st2 != NULL);
    if (st2 != NULL) {
        ASSERT_EQ_INT(4, (int)cloak_stream_write(st2, (const uint8_t *)"live", 4));
        struct up_wait uw2 = {&fx.up, 1, 4};
        ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw2, 2000, 5));
        ASSERT_EQ_INT(2, fx.up.accept_count);
        ASSERT_MEM_EQ(fx.up.conns[1].in, "live", 4);
        cloak_session_release_stream(&cs.sesh, st2);
    }

    free(src);
    free(dst);
    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 5. The upstream closing its side ends the stream, and the per-stream
 * context is reclaimed. */
static void test_upstream_close_ends_stream(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "tcp"));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1005));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_stream_write(st, (const uint8_t *)"x", 1));

    struct up_wait uw = {&fx.up, 0, 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    up_close_conn(&fx.up, 0);

    uint8_t back[16];
    reader_t rd = {st, back, sizeof(back), 0, 0};
    ASSERT_TRUE(pump_until(fx.reactor, reader_ended, &rd, 400, 5));
    ASSERT_EQ_INT(1, rd.ended);

    struct count_wait cw = {&fx.proxy, 0};
    ASSERT_TRUE(pump_until(fx.reactor, proxy_streams_eq, &cw, 400, 5));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 6. The client closing its stream closes the upstream connection. */
static void test_client_close_closes_upstream(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "tcp"));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1006));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_stream_write(st, (const uint8_t *)"x", 1));

    struct up_wait uw = {&fx.up, 0, 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));

    ASSERT_EQ_INT(0, cloak_session_close_stream(&cs.sesh, st));

    ASSERT_TRUE(pump_until(fx.reactor, up_saw_eof, &uw, 400, 5));
    ASSERT_EQ_INT(1, fx.up.conns[0].eof);

    struct count_wait cw = {&fx.proxy, 0};
    ASSERT_TRUE(pump_until(fx.reactor, proxy_streams_eq, &cw, 400, 5));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 7. A refused upstream closes that one stream and leaves the session
 * alive. The fake upstream's listener is closed (so the port refuses)
 * and then reopened on the SAME port, so the second stream can prove the
 * session is still usable by actually carrying bytes -- not merely by a
 * counter still reading 1. */
static void test_refused_upstream_closes_only_that_stream(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "tcp"));

    int port = fx.up_port;
    cloak_listener_close(&fx.up_listener);
    fx.have_up_listener = 0;

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1007));

    cloak_stream_t *s1 = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(s1 != NULL);
    if (s1 == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_stream_write(s1, (const uint8_t *)"x", 1));

    uint8_t b1[16];
    reader_t r1 = {s1, b1, sizeof(b1), 0, 0};
    ASSERT_TRUE(pump_until(fx.reactor, reader_ended, &r1, 600, 5));
    ASSERT_EQ_INT(1, r1.ended);
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, cs.broken);
    ASSERT_EQ_INT(0, fx.up.accept_count);

    char addr[64];
    char err[256] = {0};
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
    ASSERT_EQ_INT(0, cloak_listener_open(&fx.up_listener, fx.reactor, addr, up_on_accept, &fx.up,
                                         err, sizeof(err)));
    fx.have_up_listener = 1;

    cloak_stream_t *s2 = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(s2 != NULL);
    if (s2 != NULL) {
        ASSERT_EQ_INT(5, (int)cloak_stream_write(s2, (const uint8_t *)"hello", 5));
        struct up_wait uw = {&fx.up, 0, 5};
        ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 600, 5));
        ASSERT_EQ_INT(1, fx.up.accept_count);
        ASSERT_MEM_EQ(fx.up.conns[0].in, "hello", 5);

        uint8_t b2[16];
        reader_t r2 = {s2, b2, sizeof(b2), 0, 0};
        struct reader_wait rw2 = {&r2, 5};
        ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rw2, 600, 5));
        ASSERT_MEM_EQ(r2.buf, "hello", 5);
        cloak_session_release_stream(&cs.sesh, s2);
    }

    cloak_session_release_stream(&cs.sesh, s1);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 10. NOT one of the brief's nine: the retry ladder. cloak_stream_relay_
 * start returns -1 both for a permanent failure and for "the session's
 * pool could not hold one worst-case frame right now", and cannot say
 * which, so cloak_proxy_t retries every -1 on a timer and gives up only
 * after max_retries -- see cloak_proxy_config_t::retry_delay_ms.
 *
 * The rejection is provoked by SIZING, not by racing a drain. At
 * max_on_wire_size 16401 one worst-case frame costs
 * CLOAK_CONN_LEN_PREFIX_LEN(2) + max_payload_per_frame(16401-14-255) +
 * CLOAK_FRAME_HEADER_LEN(14) + CLOAK_FRAME_MAX_EXTRA_LEN(255) = 16403
 * bytes, and that is the exact quantity cloak_stream_relay_start compares
 * cloak_session_send_min_conn_free against. A pool of 16402 is therefore
 * one byte too small, permanently -- which is what makes this
 * deterministic where the genuinely transient version of the same
 * condition is not: the transient one clears within the same reactor
 * turn it appears in, and the dial completion that would observe it
 * fires on a turn boundary, when the pool has already drained.
 *
 * What this asserts, and why each matters: that the ladder actually RAN
 * (retries reaches max_retries rather than the stream being dropped on
 * the first -1); that the dial genuinely connected first, so the
 * descriptor being retried is a real one; that the upstream then sees
 * EOF, which is the only externally visible proof that the descriptor
 * parked in fd_pending was CLOSED on the give-up path rather than
 * leaked; and that only that one stream died -- the session is still
 * there. */
struct retry_watch {
    struct fixture *fx;
    unsigned max_retries_seen;
    reader_t *rd;
};

static int retry_step(void *ctx) {
    struct retry_watch *rw = ctx;
    for (cloak_proxy_session_t *ps = rw->fx->proxy.sessions; ps != NULL; ps = ps->next) {
        for (cloak_proxy_stream_t *pst = ps->streams; pst != NULL; pst = pst->next) {
            if (pst->retries > rw->max_retries_seen) {
                rw->max_retries_seen = pst->retries;
            }
        }
    }
    return reader_poll(rw->rd);
}

static void test_relay_start_rejection_retries_then_gives_up(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "tcp", 16402, 0, 5, 3, 0, 0));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1010));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_stream_write(st, (const uint8_t *)"x", 1));

    uint8_t back[16];
    reader_t rd = {st, back, sizeof(back), 0, 0};
    struct retry_watch rw = {&fx, 0, &rd};
    ASSERT_TRUE(pump_until(fx.reactor, retry_step, &rw, 2000, 5));

    ASSERT_EQ_INT(1, rd.ended);
    ASSERT_EQ_INT(3, (int)rw.max_retries_seen);
    ASSERT_EQ_INT(1, fx.up.accept_count);

    struct up_wait uw = {&fx.up, 0, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_saw_eof, &uw, 400, 5));
    ASSERT_EQ_INT(1, fx.up.conns[0].eof);
    ASSERT_EQ_INT(0, (int)fx.up.conns[0].in_len);

    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, cs.broken);

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* Shared body for the two redirect cases: a handshake that is valid in
 * every respect the dispatcher itself checks must still be redirected to
 * the cover site, with nothing left in the registry and no proxy session
 * context created. Asserted exactly the way test_dispatcher_auth.c
 * asserts its own redirects: the cover site receives the client's own
 * first packet byte for byte. */
static void expect_redirect(struct fixture *fx, int unordered) {
    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len =
        build_client_record(fx->server_pub, fx->uid_ok, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM, now,
                            9009, unordered, record, sizeof(record), shared_secret);
    ASSERT_TRUE(record_len > 0);

    int client = client_connect(front_port(fx));
    ASSERT_TRUE(client >= 0);
    if (client < 0) {
        return;
    }
    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    struct len_wait w = {&fx->cover, record_len};
    ASSERT_TRUE(pump_until(fx->reactor, cover_has_len, &w, 300, 10));
    ASSERT_EQ_INT((int)record_len, (int)fx->cover.len);
    ASSERT_MEM_EQ(fx->cover.buf, record, record_len);

    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx->registry));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx->proxy));
    ASSERT_EQ_INT(0, fx->up.accept_count);

    close(client);
}

/* 8. Obligation 5: the unordered flag redirects rather than attaching. */
static void test_unordered_redirects(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "tcp"));
    expect_redirect(&fx, 1);
    fixture_destroy(&fx);
}

/* 9. A ProxyBook entry declared "udp" redirects for the same reason: a
 * SOCK_DGRAM upstream has no stream to splice. */
static void test_udp_proxy_book_entry_redirects(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "udp"));
    expect_redirect(&fx, 0);
    fixture_destroy(&fx);
}

/* 11. The other side of the same branch: a PERMANENT
 * cloak_stream_relay_start failure (-1) must NOT enter the retry ladder.
 * Retrying one would hold a connected upstream descriptor and this
 * stream's context open for the whole budget and then fail anyway.
 *
 * `relay_buf_cap = SIZE_MAX` is the only permanent failure this module's
 * public surface can provoke: every other -1 cause is either an argument
 * cloak_proxy_t structurally never passes (a NULL reactor/session/stream,
 * fd < 0, buf_cap 0) or an allocator/epoll_ctl failure with no injection
 * seam. It makes the relay's own byte-queue allocation return NULL, which
 * is a -1 -- and it is reached only after the transient (-2) check has
 * already passed, since this fixture's pool is the roomy default one.
 *
 * `retries == 0` is the assertion that distinguishes the two branches;
 * the upstream's EOF is what proves the descriptor was closed rather
 * than leaked on a path that never armed a timer. */
static void test_permanent_start_failure_is_not_retried(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "tcp", 262144, SIZE_MAX, 5, 3, 0, 0));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1011));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_stream_write(st, (const uint8_t *)"x", 1));

    uint8_t back[16];
    reader_t rd = {st, back, sizeof(back), 0, 0};
    struct retry_watch rw = {&fx, 0, &rd};
    ASSERT_TRUE(pump_until(fx.reactor, retry_step, &rw, 2000, 5));

    ASSERT_EQ_INT(1, rd.ended);
    ASSERT_EQ_INT(0, (int)rw.max_retries_seen);
    ASSERT_EQ_INT(1, fx.up.accept_count);

    struct up_wait uw = {&fx.up, 0, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_saw_eof, &uw, 400, 5));
    ASSERT_EQ_INT(1, fx.up.conns[0].eof);

    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, cs.broken);

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- the stream caps (tests 13-15) ---------------------------------------
 *
 * Nothing caps how many streams a client may open by itself: a stream is
 * created by cloak_session_t for any unseen stream_id, so one frame buys
 * an upstream descriptor, a watcher, a dial timer and a buffer. The two
 * caps exist because running the process out of descriptors does not
 * merely degrade service -- it breaks the DISPATCHER's cover story, since
 * conn_start_redirect's own dial then fails and the connection is dropped
 * instead of redirected. See cloak_proxy_config_t::max_streams_total.
 *
 * All three tests assert the refusal the way test 7 asserts a refused
 * upstream: the refused stream ENDS at the client (the proxy released it,
 * and release performs the active close), and no upstream connection is
 * ever dialed for it. Both of those change if the cap stops firing --
 * a refusal that only showed up as a counter would be satisfied by a
 * proxy that dialed the upstream first and tore it down after. */

/* Helper for the cap tests: opens one client stream, writes `msg` on it,
 * and waits until the fake upstream's `idx`-th connection has the whole
 * message. Returns the stream, or NULL if anything failed (asserted). */
static cloak_stream_t *open_and_confirm(struct fixture *fx, client_session_t *cs, int idx,
                                        const char *msg) {
    cloak_stream_t *st = cloak_session_open_stream(&cs->sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        return NULL;
    }
    size_t len = strlen(msg);
    ASSERT_EQ_INT((int)len, (int)cloak_stream_write(st, (const uint8_t *)msg, len));
    struct up_wait uw = {&fx->up, idx, len};
    ASSERT_TRUE(pump_until(fx->reactor, up_has_len, &uw, 600, 5));
    ASSERT_EQ_INT(idx + 1, fx->up.accept_count);
    ASSERT_MEM_EQ(fx->up.conns[idx].in, msg, len);
    return st;
}

/* Opens one more client stream and asserts it is REFUSED: the client sees
 * it end, no new upstream connection was dialed, and the proxy's stream
 * count did not move. `expect_streams` is what the count must still be --
 * passed in rather than re-read, so this cannot pass by agreeing with
 * whatever the proxy happens to hold. */
static void expect_stream_refused(struct fixture *fx, client_session_t *cs, int expect_accepts,
                                  size_t expect_streams) {
    cloak_stream_t *st = cloak_session_open_stream(&cs->sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_stream_write(st, (const uint8_t *)"x", 1));

    uint8_t back[16];
    reader_t rd = {st, back, sizeof(back), 0, 0};
    ASSERT_TRUE(pump_until(fx->reactor, reader_ended, &rd, 600, 5));
    ASSERT_EQ_INT(1, rd.ended);
    ASSERT_EQ_INT(0, (int)rd.len); /* refused before any upstream existed */
    ASSERT_EQ_INT(expect_accepts, fx->up.accept_count);
    ASSERT_EQ_INT((int)expect_streams, (int)cloak_proxy_stream_count(&fx->proxy));

    cloak_session_release_stream(&cs->sesh, st);
}

/* 13. The PER-SESSION cap: the first N streams work end to end, the
 * (N+1)th is refused, and the N are still carrying afterwards -- the last
 * part being what distinguishes "refused the extra stream" from "broke
 * the session". */
static void test_per_session_stream_cap(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "tcp", 262144, 0, 0, 0, 2, 0));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1013));

    cloak_stream_t *s1 = open_and_confirm(&fx, &cs, 0, "one");
    cloak_stream_t *s2 = open_and_confirm(&fx, &cs, 1, "two");
    if (s1 == NULL || s2 == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));

    expect_stream_refused(&fx, &cs, 2, 2);

    /* Both streams under the cap still carry bytes both ways. */
    ASSERT_EQ_INT(4, (int)cloak_stream_write(s1, (const uint8_t *)"more", 4));
    struct up_wait uw = {&fx.up, 0, 7};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 600, 5));
    ASSERT_MEM_EQ(fx.up.conns[0].in, "onemore", 7);

    uint8_t b2[16];
    reader_t r2 = {s2, b2, sizeof(b2), 0, 0};
    struct reader_wait rw2 = {&r2, 3};
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rw2, 600, 5));
    ASSERT_MEM_EQ(r2.buf, "two", 3);

    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, cs.broken);

    cloak_session_release_stream(&cs.sesh, s1);
    cloak_session_release_stream(&cs.sesh, s2);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 14. The TOTAL cap, which is a different cap and not merely the same one
 * counted twice: two sessions hold one stream each, and the session that
 * then asks for a SECOND one is refused even though its own per-session
 * count (1) is nowhere near the per-session cap, which this fixture
 * leaves at the 256 default. Only the total cap can produce that
 * refusal. */
static void test_total_stream_cap_spans_sessions(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "tcp", 262144, 0, 0, 0, 0, 2));

    client_session_t cs_a;
    client_session_t cs_b;
    ASSERT_EQ_INT(0, open_client(&fx, &cs_a, 1014));
    ASSERT_EQ_INT(0, open_client(&fx, &cs_b, 1015));

    cloak_stream_t *sa = open_and_confirm(&fx, &cs_a, 0, "aaa");
    cloak_stream_t *sb = open_and_confirm(&fx, &cs_b, 1, "bbb");
    if (sa == NULL || sb == NULL) {
        client_session_close(&cs_a);
        client_session_close(&cs_b);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(2, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));

    expect_stream_refused(&fx, &cs_a, 2, 2);

    /* Neither session lost anything: both still carry bytes. */
    ASSERT_EQ_INT(2, (int)cloak_stream_write(sa, (const uint8_t *)"za", 2));
    ASSERT_EQ_INT(2, (int)cloak_stream_write(sb, (const uint8_t *)"zb", 2));
    struct up_wait ua = {&fx.up, 0, 5};
    struct up_wait ub = {&fx.up, 1, 5};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &ua, 600, 5));
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &ub, 600, 5));
    ASSERT_MEM_EQ(fx.up.conns[0].in, "aaaza", 5);
    ASSERT_MEM_EQ(fx.up.conns[1].in, "bbbzb", 5);
    ASSERT_EQ_INT(0, cs_a.broken);
    ASSERT_EQ_INT(0, cs_b.broken);

    cloak_session_release_stream(&cs_a.sesh, sa);
    cloak_session_release_stream(&cs_b.sesh, sb);
    client_session_close(&cs_a);
    client_session_close(&cs_b);
    fixture_destroy(&fx);
}

/* 15. THE ONE THAT CATCHES A LEAKED COUNTER, and the reason the cap is
 * counted off cloak_proxy_t::stream_count rather than a second tally of
 * its own: a cap whose counter only ever rises is not a cap, it is a
 * server-wide ban that arrives silently after N streams have ever been
 * served, which is strictly worse than the exhaustion it was added to
 * prevent.
 *
 * ROUNDS is deliberately several times the total cap, and each round
 * asserts a BRAND-NEW upstream connection carrying that round's own
 * bytes (accept_count only ever grows, so round i can only be satisfied
 * by the i-th accept). A decrement missed anywhere fails the first round
 * past the cap, not merely a count at the end.
 *
 * The upstream side of each round is closed once the proxy has reclaimed
 * its context, so the reactor does not accumulate sockets sitting at EOF
 * -- which are ready on every single turn and would let an
 * iteration-counted pump burn its whole budget in no wall-clock time at
 * all. */
#define CAP_ROUNDS 6

static void test_stream_cap_is_released_when_streams_end(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "tcp", 262144, 0, 0, 0, 0, 2));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1016));

    for (int i = 0; i < CAP_ROUNDS; i++) {
        char msg[16];
        snprintf(msg, sizeof(msg), "r%d", i);
        cloak_stream_t *st = open_and_confirm(&fx, &cs, i, msg);
        if (st == NULL) {
            break;
        }
        ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

        ASSERT_EQ_INT(0, cloak_session_close_stream(&cs.sesh, st));
        struct count_wait cw = {&fx.proxy, 0};
        ASSERT_TRUE(pump_until(fx.reactor, proxy_streams_eq, &cw, 600, 5));
        ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

        cloak_session_release_stream(&cs.sesh, st);
        up_close_conn(&fx.up, i);
    }

    ASSERT_EQ_INT(CAP_ROUNDS, fx.up.accept_count);
    ASSERT_EQ_INT(0, cs.broken);
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 12. Constructor/destructor discipline, the two shapes this project
 * asserts for every such pair (test_dispatcher_redirect.c's rejected-init
 * test and test_server_state.c's idempotent-destroy test are the models).
 *
 * The 0xAA prefill is what makes the init assertions non-vacuous: a
 * freshly zeroed struct would satisfy them whether or not
 * cloak_proxy_init actually re-initializes on its REJECTION paths, rather
 * than only on the one that runs to the end. */
static void test_init_validation_and_destroy_discipline(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    /* Never used for anything but its address: cloak_proxy_init only
     * stores the pointer. */
    cloak_server_t srv;
    memset(&srv, 0, sizeof(srv));

    cloak_proxy_t dirty;
    cloak_proxy_config_t pcfg;

    /* NULL cfg. */
    memset(&dirty, 0xAA, sizeof(dirty));
    ASSERT_EQ_INT(-1, cloak_proxy_init(&dirty, NULL));
    ASSERT_TRUE(dirty.sessions == NULL);
    ASSERT_EQ_INT(0, (int)dirty.session_count);
    ASSERT_EQ_INT(0, (int)dirty.stream_count);
    /* The whole point of initialize-before-validate: destroy must be safe
     * against a struct a rejected constructor left behind. */
    cloak_proxy_destroy(&dirty);

    /* NULL reactor. */
    memset(&dirty, 0xAA, sizeof(dirty));
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.reactor = NULL;
    pcfg.srv = &srv;
    ASSERT_EQ_INT(-1, cloak_proxy_init(&dirty, &pcfg));
    ASSERT_TRUE(dirty.sessions == NULL);
    ASSERT_EQ_INT(0, (int)dirty.session_count);
    cloak_proxy_destroy(&dirty);

    /* NULL srv. */
    memset(&dirty, 0xAA, sizeof(dirty));
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.reactor = r;
    pcfg.srv = NULL;
    ASSERT_EQ_INT(-1, cloak_proxy_init(&dirty, &pcfg));
    ASSERT_TRUE(dirty.sessions == NULL);
    ASSERT_EQ_INT(0, (int)dirty.session_count);
    cloak_proxy_destroy(&dirty);

    /* NULL p is rejected without dereferencing it, and destroy tolerates
     * NULL too. */
    ASSERT_EQ_INT(-1, cloak_proxy_init(NULL, &pcfg));
    cloak_proxy_destroy(NULL);

    /* Idempotent and safe on a zeroed struct. */
    cloak_proxy_t zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    cloak_proxy_destroy(&zeroed);
    cloak_proxy_destroy(&zeroed);

    /* A successful init fills in every CLOAK_PROXY_DEFAULT_*, and destroy
     * on the result is idempotent too. */
    cloak_proxy_t live;
    memset(&live, 0xAA, sizeof(live));
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.reactor = r;
    pcfg.srv = &srv;
    ASSERT_EQ_INT(0, cloak_proxy_init(&live, &pcfg));
    ASSERT_EQ_INT((int)CLOAK_PROXY_DEFAULT_RELAY_BUF_CAP, (int)live.cfg.relay_buf_cap);
    ASSERT_EQ_INT((int)CLOAK_PROXY_DEFAULT_DIAL_TIMEOUT_MS, (int)live.cfg.dial_timeout_ms);
    ASSERT_EQ_INT((int)CLOAK_PROXY_DEFAULT_RETRY_DELAY_MS, (int)live.cfg.retry_delay_ms);
    ASSERT_EQ_INT((int)CLOAK_PROXY_DEFAULT_MAX_RETRIES, (int)live.cfg.max_retries);
    ASSERT_EQ_INT((int)CLOAK_PROXY_DEFAULT_MAX_STREAMS_PER_SESSION,
                  (int)live.cfg.max_streams_per_session);
    ASSERT_EQ_INT((int)CLOAK_PROXY_DEFAULT_MAX_STREAMS_TOTAL, (int)live.cfg.max_streams_total);
    ASSERT_TRUE(live.sessions == NULL);
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&live));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&live));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(NULL));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(NULL));
    cloak_proxy_destroy(&live);
    cloak_proxy_destroy(&live);

    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
test_one_stream_both_ways();
test_preexisting_bytes_reach_upstream();
test_two_streams_do_not_cross();
test_large_transfer_round_trip();
test_upstream_close_ends_stream();
test_client_close_closes_upstream();
test_refused_upstream_closes_only_that_stream();
test_unordered_redirects();
test_udp_proxy_book_entry_redirects();
test_relay_start_rejection_retries_then_gives_up();
test_permanent_start_failure_is_not_retried();
test_per_session_stream_cap();
test_total_stream_cap_spans_sessions();
test_stream_cap_is_released_when_streams_end();
test_init_validation_and_destroy_discipline();
TEST_MAIN_END()
