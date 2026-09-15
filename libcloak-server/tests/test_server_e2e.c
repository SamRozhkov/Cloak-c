#define _POSIX_C_SOURCE 200809L
#include "cloak/proxy.h"
#include "cloak/base64.h"
#include "cloak/clienthello.h"
#include "cloak/conn.h"
#include "cloak/crypto.h"
#include "cloak/dispatcher.h"
#include "cloak/frame.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "cloak/switchboard.h"
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

/* THE WHOLE SERVER, WIRED THE WAY A BINARY WILL WIRE IT. Every other test
 * in this directory builds one module and stubs its neighbours;
 * test_proxy_stream.c comes closest but still installs a do-nothing
 * registry callback and no session_aborted at all. This file builds the
 * five pieces module 7's ck-server will build -- a cloak_server_t from a
 * parsed JSON config, a cloak_proxy_t, a cloak_server_registry_t, a
 * cloak_dispatcher_t and one cloak_listener_t per configured BindAddr --
 * in the order a binary can build them, tears them down in the order a
 * binary must tear them down, and asserts that bytes cross the whole
 * stack.
 *
 * WHAT IS NEW HERE rather than inherited from Tasks 2 and 3:
 *
 *   1. The wiring itself (fixture_init / fixture_shutdown_server), which
 *      is a scouting report for module 7 as much as it is a fixture.
 *   2. A data frame that is already sitting in a connection's receive
 *      buffer when conn_handoff re-registers that connection's fd with a
 *      cloak_session_t -- the "bytes survive the re-registration"
 *      property (test_pipelined_frame_survives_handoff).
 *   3. Two connections on ONE session, with the client's obfuscator built
 *      from the SECOND connection's reply, which is what makes the
 *      live-session-key rule a byte-level property rather than a
 *      comparison of two keys (test_two_connections_one_session).
 *   4. A redirected connection and a proxied one against the same
 *      listener.
 *   5. Shutdown in the binary's order with a bulk transfer mid-flight.
 *
 * EVERY wait is a bounded pump_until and EVERY peer socket is
 * non-blocking, the discipline test_proxy_stream.c and
 * test_proxy_teardown.c both state and for the same reason (three tests
 * on this project have hung or flaked in CI). */

/* ---- fake upstream: records everything it receives, echoes it back ----
 *
 * Byte-for-byte identical in behaviour to test_proxy_stream.c's, which is
 * where it comes from; this project's convention is that each dispatcher
 * test file carries its own fake peers (see client_harness.h's own
 * top-of-file note on what was and was not worth extracting). */

#define UP_MAX_CONNS 8
#define UP_BUF_CAP ((size_t)(2u << 20))

typedef struct {
    int fd;
    uint8_t *in; /* everything ever read, for byte-for-byte assertions */
    size_t in_len;
    uint8_t *out; /* pending echo bytes not yet accepted by the socket */
    size_t out_len;
    size_t out_head;
    int eof;
} up_conn_t;

struct upstream;
typedef struct {
    struct upstream *up;
    int idx;
} up_slot_t;

typedef struct upstream {
    cloak_reactor_t *reactor;
    int accept_count;
    /* While set, this upstream stops reading anything at all -- see
     * test_shutdown_with_traffic_in_flight, which is the only user and
     * explains why. Not re-arming the registration is deliberate: the
     * reactor is edge-triggered, so an unread socket simply stops waking
     * us, which is exactly the stall being modelled. */
    int stall;
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

    if (up->stall) {
        return;
    }
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

/* up_conn_t::in is NULL until that connection has been accepted, so a
 * byte-for-byte assertion against an upstream that was never reached
 * would segfault inside memcmp instead of reporting a failure. That is
 * not hypothetical: it is what both mutation runs used to verify this
 * file's assertions did, since in both the mutation's whole visible
 * effect was that no upstream connection happened at all. The NULL case
 * is still a failure, not a skip. */
#define ASSERT_UP_BYTES(up, idx, expect, len) \
    do { \
        if ((up).conns[idx].in != NULL) { \
            ASSERT_MEM_EQ((up).conns[idx].in, (expect), (len)); \
        } else { \
            ASSERT_TRUE((up).conns[idx].in != NULL); \
        } \
    } while (0)

static void up_destroy(upstream_t *up) {
    for (int i = 0; i < UP_MAX_CONNS; i++) {
        up_conn_t *c = &up->conns[i];
        if (c->fd >= 0) {
            cloak_reactor_remove_fd(up->reactor, c->fd);
            close(c->fd);
            c->fd = -1;
        }
        free(c->in);
        free(c->out);
        c->in = NULL;
        c->out = NULL;
    }
}

/* ---- the fixture: the stack, wired as ck-server will wire it -----------
 *
 * CONSTRUCTION ORDER IS FORCED, and only in one place: the registry needs
 * the proxy's address (cloak_proxy_registry_broken's userdata), so the
 * proxy must exist first; the dispatcher needs both. Everything else
 * follows from "borrowed pointers must already exist":
 *
 *     reactor -> server -> proxy -> registry -> dispatcher -> listeners
 *
 * DESTRUCTION IS NOT THE REVERSE OF THAT, and that is the one thing a
 * binary can get silently wrong: the proxy must be destroyed BEFORE the
 * registry (cloak/proxy.h's LIFETIME paragraph and cloak/stream_relay.h's
 * stop-before-the-session rule), even though it was constructed before
 * it. See fixture_shutdown_server. */

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

    cloak_proxy_t proxy;
    int proxy_ready;

    cloak_server_registry_t registry;
    int registry_ready;

    cloak_dispatcher_t d;
    int d_ready;

    /* One per configured BindAddr, exactly as a binary would open them. */
    cloak_listener_t front[CLOAK_MAX_BIND_ADDR];
    size_t front_count;

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_ok[CLOAK_UID_LEN];

    /* Counting wrappers, so that "the hand-off has not happened yet" is an
     * assertion rather than an assumption -- see
     * test_pipelined_frame_survives_handoff. */
    int attached_calls;
    int attached_created;
};

/* PURELY THE TEST'S OWN PROBE: cloak_proxy_t wires nothing into
 * dcfg.attached (see cloak/proxy.h), so this counts the DISPATCHER's
 * attach notifications and nothing else -- which is exactly what
 * test_pipelined_frame_survives_handoff needs to assert that the hand-off
 * for a given connection has not happened yet. */
static void fx_attached(cloak_dispatcher_t *d, cloak_session_t *sesh,
                        const cloak_server_clientinfo_t *info, int created, void *userdata) {
    (void)d;
    (void)sesh;
    (void)info;
    struct fixture *fx = userdata;
    fx->attached_calls++;
    fx->attached_created += created ? 1 : 0;
}

static int fixture_init(struct fixture *fx) {
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

    /* The two third parties this server talks to, neither of which is
     * part of the stack under test: the cover site a redirect goes to and
     * the upstream a proxied stream is spliced with. */
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

    /* ---- 1. the config, parsed from JSON exactly as a binary parses its
     * config file. BindAddr is a real (ephemeral) address rather than
     * ":443" so the listener loop below can be the binary's own loop
     * rather than a test-only shortcut. */
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\"127.0.0.1:0\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\"]}",
             fx->up_port, cover_port, priv_b64, uidok_b64);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    /* ---- 2. the server state (resolved ProxyBook, bypass set, replay
     * cache). Borrowed by both the proxy and the dispatcher, so it is
     * first. */
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    /* ---- 3. the proxy. Before the registry, because the registry's
     * on_broken userdata IS this object's address. */
    cloak_proxy_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.reactor = fx->reactor;
    pcfg.srv = &fx->srv;
    /* Everything else left at 0: a binary has no reason to override the
     * CLOAK_PROXY_DEFAULT_* constants, and this file exercises them. */
    ASSERT_EQ_INT(0, cloak_proxy_init(&fx->proxy, &pcfg));
    fx->proxy_ready = 1;

    /* ---- 4. the registry, whose broken callback IS the proxy's (not
     * optional: cloak/proxy.h calls an owner that skips this "a
     * use-after-free and a leak, not a working server"). */
    ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor,
                                                cloak_proxy_registry_broken, &fx->proxy));
    fx->registry_ready = 1;

    /* ---- 5. the dispatcher, with both of the proxy's dispatcher
     * callbacks (prepare_session, session_aborted) -- it has no third:
     * cloak/proxy.h explains why dcfg.attached is the owner's to use. */
    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.registry = &fx->registry;

    dcfg.session_config_template.max_on_wire_size = 16401;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = 262144;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;

    dcfg.prepare_session = cloak_proxy_prepare_session;
    dcfg.prepare_session_userdata = &fx->proxy;
    dcfg.attached = fx_attached; /* the test's own hand-off probe */
    dcfg.attached_userdata = fx;
    dcfg.session_aborted = cloak_proxy_session_aborted;
    dcfg.session_aborted_userdata = &fx->proxy;

    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    /* ---- 6. one listener per configured BindAddr. */
    ASSERT_TRUE(fx->cfg.num_bind_addr > 0);
    for (size_t i = 0; i < fx->cfg.num_bind_addr; i++) {
        err[0] = '\0';
        ASSERT_EQ_INT(0, cloak_listener_open(&fx->front[i], fx->reactor, fx->cfg.bind_addr[i],
                                             cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
        fx->front_count++;

        /* NOT a binary's concern, and the one line in this fixture that is
         * not: Linux hands an accepted socket its listener's SO_SNDBUF, and
         * with loopback's default multi-megabyte buffers the server's
         * kernel send buffer swallows an entire transfer -- so the session
         * never becomes backpressured and the relay's paused-read resume
         * path is never reached at all. test_proxy_stream.c's fixture
         * documents the same line, and verified by mutation there that
         * without it a no-op on_writable failed nothing. */
        int sndbuf = 8192;
        (void)setsockopt(fx->front[i].fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }

    return 0;
}

/* THE SHUTDOWN A BINARY PERFORMS, in the order it must perform it. Split
 * out from fixture_destroy so the in-flight-traffic test can run exactly
 * this sequence at a moment of its own choosing and then still clean up
 * its client-side objects (which a binary does not have) afterwards.
 * Idempotent: every step is flag-guarded, so fixture_destroy can call it
 * again unconditionally.
 *
 *   - the listeners first, so nothing new arrives mid-teardown;
 *   - the dispatcher next: a connection still mid-handshake can call into
 *     the registry, and cloak_dispatcher_destroy is what unwinds those;
 *   - THE PROXY BEFORE THE REGISTRY. This is the step that is not the
 *     reverse of construction and the one a binary can get silently
 *     wrong: cloak_proxy_destroy stops every live cloak_stream_relay_t,
 *     and cloak/stream_relay.h requires that to happen before the session
 *     a relay is bound to is destroyed -- which is exactly what
 *     cloak_server_registry_destroy does next;
 *   - then the registry, then the server state the other two borrowed. */
static void fixture_shutdown_server(struct fixture *fx) {
    while (fx->front_count > 0) {
        cloak_listener_close(&fx->front[--fx->front_count]);
    }
    if (fx->d_ready) {
        cloak_dispatcher_destroy(&fx->d);
        fx->d_ready = 0;
    }
    if (fx->proxy_ready) {
        cloak_proxy_destroy(&fx->proxy);
        fx->proxy_ready = 0;
    }
    if (fx->registry_ready) {
        cloak_server_registry_destroy(&fx->registry);
        fx->registry_ready = 0;
    }
    if (fx->srv_ready) {
        cloak_server_destroy(&fx->srv);
        fx->srv_ready = 0;
    }
}

/* The binary's own shutdown, followed by the test-only peers (fake
 * upstream, fake cover site) and the reactor they all share. */
static void fixture_destroy(struct fixture *fx) {
    fixture_shutdown_server(fx);
    if (fx->have_up_listener) {
        cloak_listener_close(&fx->up_listener);
        fx->have_up_listener = 0;
    }
    up_destroy(&fx->up);
    if (fx->have_cover_listener) {
        cloak_listener_close(&fx->cover_listener);
        fx->have_cover_listener = 0;
    }
    if (fx->cover.fd >= 0) {
        close(fx->cover.fd);
        fx->cover.fd = -1;
    }
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
        fx->reactor = NULL;
    }
}

static int front_port(struct fixture *fx) {
    return cloak_listener_port(&fx->front[0]);
}

static void client_config(cloak_session_config_t *ccfg) {
    memset(ccfg, 0, sizeof(*ccfg));
    ccfg->max_on_wire_size = 16401;
    ccfg->stream_recv_capacity = 65536;
    ccfg->stream_max_pending_frames = 64;
    ccfg->conn_send_queue_cap = 262144;
    ccfg->inactivity_timeout_ms = 60000;
}

static int open_client(struct fixture *fx, client_session_t *cs, uint32_t session_id) {
    cloak_session_config_t ccfg;
    client_config(&ccfg);
    return client_session_open(cs, fx->reactor, front_port(fx), fx->server_pub, fx->uid_ok, "ss",
                               session_id, 0, &ccfg);
}

/* ---- client-side stream helpers (test_proxy_stream.c's, same reasons) --- */

typedef struct {
    cloak_stream_t *stream;
    uint8_t *buf;
    size_t cap;
    size_t len;
    int ended;
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

/* Writes a large buffer in frame-sized chunks, pacing against the
 * session's own per-connection send budget: cloak_stream_write never
 * fails on a full queue, it overruns a connection's hard cap and breaks
 * the whole pool (cloak/session.h), so this mirrors what
 * cloak_stream_relay_t does internally rather than checking a return
 * value. */
typedef struct {
    cloak_session_t *sesh;
    reader_t *rd; /* drained as we go, so the echo cannot back up */
    cloak_stream_t *stream;
    const uint8_t *buf;
    size_t len;
    size_t sent;
    /* 0 (the default) means "write as much as the send budget allows",
     * which is what a throughput test wants. A non-zero value paces the
     * writer to that many frames per reactor turn, which is what
     * test_shutdown_with_traffic_in_flight needs: the budget alone does
     * NOT pace anything here -- measured, an unpaced writer pushed an
     * entire 2 MiB transfer into the kernel in its first call, before a
     * single reactor turn had run, so there was never a moment at which
     * the transfer was partly done. */
    size_t max_chunks_per_step;
} writer_t;

static int writer_step(void *ctx) {
    writer_t *w = ctx;
    if (w->rd != NULL) {
        reader_poll(w->rd);
    }
    size_t chunks = 0;
    while (w->sent < w->len) {
        if (w->max_chunks_per_step != 0 && chunks >= w->max_chunks_per_step) {
            break;
        }
        if (cloak_session_send_min_conn_free(w->sesh) < 2 * 16401) {
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
        chunks++;
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

/* ---- test 1: the stack carries bytes ------------------------------------ */

static void test_stack_carries_traffic_end_to_end(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 3001));
    ASSERT_EQ_INT(1, fx.attached_calls);
    ASSERT_EQ_INT(1, fx.attached_created);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(6, (int)cloak_stream_write(st, (const uint8_t *)"e2e-up", 6));

    struct up_wait uw = {&fx.up, 0, 6};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(1, fx.up.accept_count);
    ASSERT_EQ_INT(6, (int)fx.up.conns[0].in_len);
    ASSERT_UP_BYTES(fx.up, 0, "e2e-up", 6);

    uint8_t back[16];
    reader_t rd = {st, back, sizeof(back), 0, 0};
    struct reader_wait rw = {&rd, 6};
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rw, 400, 5));
    ASSERT_EQ_INT(6, (int)rd.len);
    ASSERT_MEM_EQ(rd.buf, "e2e-up", 6);

    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, cs.broken);

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- test 2: a frame buffered across the hand-off ----------------------- */

/* One complete mux envelope exactly as cloak_conn_send puts it on the
 * wire: a TLS application-data record header
 * (CLOAK_CONN_RECORD_HEADER_LEN -- 0x17 0x03 0x03 then a big-endian u16
 * length) around the frame cloak_frame_obfuscate produces. Both are public, stateless
 * APIs -- cloak_frame_obfuscate takes the whole obfuscator by value and
 * nothing else, so a frame built here is indistinguishable from one
 * session.c built (session.c's own session-closing frame is composed with
 * these same two calls). That is what lets this test put a data frame on
 * a socket that no cloak_session_t owns yet, which is the entire point:
 * the client's session cannot be the thing that writes it, because the
 * whole property under test is about bytes that arrive BEFORE the
 * server-side session takes the fd over. */
static size_t build_wire_frame(const uint8_t key[CLOAK_AEAD_KEY_LEN], uint32_t stream_id,
                               uint64_t seq, const void *payload, size_t payload_len, uint8_t *out,
                               size_t out_cap) {
    cloak_obfuscator_t o;
    memset(&o, 0, sizeof(o));
    o.method = CLOAK_AEAD_AES_256_GCM;
    memcpy(o.session_key, key, CLOAK_AEAD_KEY_LEN);

    cloak_frame_t f;
    f.stream_id = stream_id;
    f.seq = seq;
    f.closing = CLOAK_FRAME_CLOSING_NOTHING;
    f.payload = payload;
    f.payload_len = payload_len;

    long n = cloak_frame_obfuscate(&o, &f, out + CLOAK_CONN_RECORD_HEADER_LEN,
                                   out_cap - CLOAK_CONN_RECORD_HEADER_LEN, 0);
    ASSERT_TRUE(n > 0);
    if (n <= 0) {
        return 0;
    }
    out[0] = 0x17;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (uint8_t)(((unsigned long)n >> 8) & 0xff);
    out[4] = (uint8_t)((unsigned long)n & 0xff);
    return CLOAK_CONN_RECORD_HEADER_LEN + (size_t)n;
}

/* The write shim consumes CLOAK_TEST_FORCE_PEER_PORT the instant it fakes
 * a write, so the variable's disappearance is externally visible proof
 * that the dispatcher's reply write really did take the EAGAIN path --
 * i.e. that the hand-off really was deferred to a later reactor turn
 * rather than running in the same one. Without this the test would still
 * pass on a build with no LD_PRELOAD at all, having covered a narrower
 * window than it claims. */
static int shim_fired(void *ctx) {
    (void)ctx;
    return getenv("CLOAK_TEST_FORCE_PEER_PORT") == NULL;
}

/* An id no cloak_session_open_stream will ever hand out here: client
 * stream ids are allocated sequentially from 1 (session.c's
 * next_stream_id), and no test in this file opens tens of thousands. */
#define PIPELINED_STREAM_ID ((uint32_t)0x7000)

/* THE PROPERTY THREE BRANCHES OF THIS PROJECT HAVE REASONED ABOUT ON
 * PAPER AND NONE HAS TESTED: a data frame already sitting in a
 * connection's kernel receive buffer when conn_handoff runs
 * cloak_reactor_remove_fd followed by cloak_session_add_conn must still
 * be delivered. cloak_reactor_add_fd registers EPOLLET, and epoll_ctl(ADD)
 * on a descriptor that already has buffered data reports it immediately
 * -- but that is a prediction about reactor.c, and this is the test of it.
 *
 * HOW THE WINDOW IS CONSTRUCTED, and why it is not the window the
 * original obligation described: a client cannot pipeline a data frame
 * behind the ClientHello of its FIRST connection, because the session key
 * is generated by the server and delivered inside that connection's
 * reply, so the client has nothing to encrypt with until the reply is in
 * hand. A client's SECOND connection to an already-established session is
 * a different matter entirely -- it already holds the live session key --
 * and that is the only shape in which the pipelined frame is real. So:
 *
 *   1. A session is established over connection 1, which gives the client
 *      the live session key.
 *   2. A frame opening a brand-new stream is built with that key and
 *      written to connection 2 immediately behind its ClientHello, with
 *      no reactor turn in between -- so the bytes are in the server's
 *      receive buffer before the server has read even the first byte of
 *      that connection.
 *   3. The reply write is forced to EAGAIN (test_write_shim.c), which
 *      pushes conn_handoff into a LATER reactor turn than the one that
 *      authenticated the connection. The frame therefore sits buffered
 *      across a turn boundary as well as across the hand-off itself.
 *
 * If the bytes do not reach the upstream, the hand-off loses the first
 * frame of every connection whose client is quick off the mark, silently
 * -- there is no error anywhere; the frame is simply never delivered. */
static void test_pipelined_frame_survives_handoff(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 3002));
    ASSERT_EQ_INT(1, fx.attached_calls);

    /* CLOAK_FRAME_MAX_EXTRA_LEN is not slack: cloak_frame_obfuscate pads
     * a frame by a RANDOM amount up to that, so a buffer sized for the
     * average case fails on roughly one run in fifteen -- which is what it
     * did, found by the 50-run repeat loop rather than by the first
     * green run. */
    uint8_t frame[CLOAK_CONN_RECORD_HEADER_LEN + CLOAK_FRAME_HEADER_LEN + 16 +
                  CLOAK_FRAME_MAX_EXTRA_LEN];
    size_t frame_len = build_wire_frame(cs.session_key, PIPELINED_STREAM_ID, 0, "PIPELINED", 9,
                                        frame, sizeof(frame));
    ASSERT_TRUE(frame_len > 0);
    if (frame_len == 0) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len =
        build_client_record(fx.server_pub, fx.uid_ok, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM, now,
                            3002, 0, record, sizeof(record), shared_secret);
    ASSERT_TRUE(record_len > 0);
    if (record_len == 0) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }

    int fd2 = client_connect(front_port(&fx));
    ASSERT_TRUE(fd2 >= 0);
    if (fd2 < 0) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    int cport = client_local_port(fd2);
    ASSERT_TRUE(cport > 0);

    /* Arms the shim for THIS connection's server-side fd only (the shim
     * matches on the peer port, which for that fd is this client's own
     * local port). One-shot: the first faked write consumes it. */
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", cport);
    setenv("CLOAK_TEST_FORCE_PEER_PORT", portbuf, 1);
    setenv("CLOAK_TEST_FORCE_MODE", "eagain", 1);

    ASSERT_TRUE(write(fd2, record, record_len) == (ssize_t)record_len);
    ASSERT_TRUE(write(fd2, frame, frame_len) == (ssize_t)frame_len);

    /* THE PRECONDITION, ASSERTED AT THE MOMENT IT MATTERS. No reactor turn
     * has run since this socket was connected, so the server has not read
     * a byte of it: both writes above are in its receive buffer and the
     * hand-off for this connection has provably not happened (one attach
     * so far, connection 1's). Asserting this after the pump instead would
     * assert nothing -- by then the hand-off has run either way. */
    ASSERT_EQ_INT(1, fx.attached_calls);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    /* Turn 1: the dispatcher reads the first packet, authenticates, and
     * its reply write is faked to EAGAIN -- so it registers for writable
     * and returns, with the hand-off still ahead of it. */
    ASSERT_TRUE(pump_until(fx.reactor, shim_fired, NULL, 400, 5));
    /* Still deferred, with the client's frame still buffered: this is the
     * window itself, and it is open right here. */
    ASSERT_EQ_INT(1, fx.attached_calls);

    /* Turn 2 onwards: the writable event completes the reply, conn_handoff
     * runs cloak_reactor_remove_fd + cloak_session_add_conn, and the
     * buffered frame either survives that or is lost forever. */
    struct up_wait uw = {&fx.up, 0, 9};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 600, 5));

    ASSERT_EQ_INT(2, fx.attached_calls);
    ASSERT_EQ_INT(1, fx.attached_created); /* the second connection JOINED */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));

    /* The assertion this whole test exists for. */
    ASSERT_EQ_INT(1, fx.up.accept_count);
    ASSERT_EQ_INT(9, (int)fx.up.conns[0].in_len);
    ASSERT_UP_BYTES(fx.up, 0, "PIPELINED", 9);

    unsetenv("CLOAK_TEST_FORCE_PEER_PORT");
    unsetenv("CLOAK_TEST_FORCE_MODE");

    close(fd2);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- test 3: two connections, one session ------------------------------- */

/* The handshake half of client_harness.h's client_session_open, stopping
 * at the recovered session key. Needed because this test has to run TWO
 * handshakes against the same (uid, session_id) before either socket is
 * handed to a cloak_session_t -- a shape that helper's single call cannot
 * express, since it builds a session per connection. */
static int handshake_only(struct fixture *fx, uint32_t session_id, int *out_fd,
                          uint8_t out_key[CLOAK_AEAD_KEY_LEN]) {
    *out_fd = -1;

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len =
        build_client_record(fx->server_pub, fx->uid_ok, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM, now,
                            session_id, 0, record, sizeof(record), shared_secret);
    if (record_len == 0) {
        return -1;
    }

    int fd = client_connect(front_port(fx));
    if (fd < 0) {
        return -1;
    }
    if (write(fd, record, record_len) != (ssize_t)record_len) {
        close(fd);
        return -1;
    }

    uint8_t reply[512];
    size_t reply_len = 0;
    if (read_reply(fx->reactor, fd, reply, sizeof(reply), &reply_len) != 0) {
        close(fd);
        return -1;
    }
    if (extract_session_key_from_reply(shared_secret, reply, reply_len, out_key) != 0) {
        close(fd);
        return -1;
    }
    *out_fd = fd;
    return 0;
}

/* Enough frames that "the switchboard picked one connection uniformly at
 * random every time and never once picked the second" has probability
 * 2^-127 -- which is what makes the byte-level assertions below cover
 * BOTH connections rather than only whichever one got lucky.
 * cloak_switchboard_send's uniform-random choice is documented in
 * cloak/switchboard.h; nothing here can pin a frame to a connection, so a
 * statistical bound is the honest one, and this is not a close call. */
#define TWOCONN_FRAMES 128
#define TWOCONN_CHUNK 1024
#define TWOCONN_LEN ((size_t)(TWOCONN_FRAMES * TWOCONN_CHUNK))

/* THE LIVE-SESSION-KEY RULE, END TO END. When a second connection joins an
 * existing session, dispatcher_authenticate must compose its reply with
 * the key that session was CREATED with, not a fresh one. A fresh key
 * there is invisible to every handshake-level check: the connection
 * authenticates, the reply decrypts, the session accepts the connection --
 * and then every frame the client sends over it fails to deobfuscate.
 *
 * The client here therefore builds its obfuscator from the SECOND
 * connection's reply, which is what a client that trusts the server's
 * answer would do. That makes a fresh key not merely unequal to the
 * first, but a session that carries no bytes at all -- so the byte-level
 * assertions below, not just the key comparison, are what distinguish the
 * two. */
static void test_two_connections_one_session(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    int fd1 = -1;
    int fd2 = -1;
    uint8_t key1[CLOAK_AEAD_KEY_LEN];
    uint8_t key2[CLOAK_AEAD_KEY_LEN];
    ASSERT_EQ_INT(0, handshake_only(&fx, 3003, &fd1, key1));
    ASSERT_EQ_INT(0, handshake_only(&fx, 3003, &fd2, key2));
    if (fd1 < 0 || fd2 < 0) {
        if (fd1 >= 0) {
            close(fd1);
        }
        if (fd2 >= 0) {
            close(fd2);
        }
        fixture_destroy(&fx);
        return;
    }

    /* One session, two connections -- asserted on the server's own
     * objects, not inferred. */
    ASSERT_EQ_INT(2, fx.attached_calls);
    ASSERT_EQ_INT(1, fx.attached_created);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    cloak_session_t *server_sesh = cloak_server_registry_find(&fx.registry, fx.uid_ok, 3003);
    ASSERT_TRUE(server_sesh != NULL);
    if (server_sesh != NULL) {
        ASSERT_EQ_INT(2, (int)cloak_switchboard_conn_count(&server_sesh->sb));
    }

    /* The rule stated directly. The byte-level assertions further down are
     * what make it matter. */
    ASSERT_MEM_EQ(key2, key1, CLOAK_AEAD_KEY_LEN);

    cloak_session_config_t ccfg;
    client_config(&ccfg);
    ccfg.obfuscator.method = CLOAK_AEAD_AES_256_GCM;
    memcpy(ccfg.obfuscator.session_key, key2, CLOAK_AEAD_KEY_LEN);

    client_session_t cs;
    memset(&cs, 0, sizeof(cs));
    cs.fd = -1; /* both sockets belong to the session below, not to cs */
    ccfg.on_broken = client_session_on_broken;
    ccfg.on_broken_userdata = &cs;
    ASSERT_EQ_INT(0, cloak_session_init(&cs.sesh, 3003, fx.reactor, &ccfg));
    cs.sesh_ready = 1;
    ASSERT_EQ_INT(0, cloak_session_add_conn(&cs.sesh, fd1));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&cs.sesh, fd2));
    ASSERT_EQ_INT(2, (int)cloak_switchboard_conn_count(&cs.sesh.sb));

    uint8_t *a_src = malloc(TWOCONN_LEN);
    uint8_t *b_src = malloc(TWOCONN_LEN);
    uint8_t *a_dst = malloc(TWOCONN_LEN);
    uint8_t *b_dst = malloc(TWOCONN_LEN);
    ASSERT_TRUE(a_src != NULL && b_src != NULL && a_dst != NULL && b_dst != NULL);
    if (a_src == NULL || b_src == NULL || a_dst == NULL || b_dst == NULL) {
        free(a_src);
        free(b_src);
        free(a_dst);
        free(b_dst);
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    for (size_t i = 0; i < TWOCONN_LEN; i++) {
        a_src[i] = (uint8_t)((i * 7u + 1u) & 0xff);
        b_src[i] = (uint8_t)((i * 11u + 2u) & 0xff);
    }

    cloak_stream_t *sa = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(sa != NULL);
    cloak_stream_t *sb = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(sb != NULL);
    if (sa == NULL || sb == NULL) {
        free(a_src);
        free(b_src);
        free(a_dst);
        free(b_dst);
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }

    /* One stream at a time up to its first upstream connection, so the
     * (stream -> upstream connection) mapping is deterministic; the bulk
     * traffic that follows is what a key that only works on one of the two
     * connections would lose. */
    ASSERT_EQ_INT(1, (int)cloak_stream_write(sa, a_src, 1));
    struct up_wait w1 = {&fx.up, 1, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &w1, 400, 5));
    ASSERT_EQ_INT(1, (int)cloak_stream_write(sb, b_src, 1));
    struct up_wait w2 = {&fx.up, 2, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &w2, 400, 5));
    ASSERT_EQ_INT(2, fx.up.accept_count);

    reader_t ra = {sa, a_dst, TWOCONN_LEN, 0, 0};
    reader_t rb = {sb, b_dst, TWOCONN_LEN, 0, 0};
    writer_t wa = {&cs.sesh, &ra, sa, a_src, TWOCONN_LEN, 1, 0};
    writer_t wb = {&cs.sesh, &rb, sb, b_src, TWOCONN_LEN, 1, 0};
    ASSERT_TRUE(pump_until(fx.reactor, writer_step, &wa, 8000, 2));
    ASSERT_TRUE(pump_until(fx.reactor, writer_step, &wb, 8000, 2));
    ASSERT_EQ_INT((int)TWOCONN_LEN, (int)wa.sent);
    ASSERT_EQ_INT((int)TWOCONN_LEN, (int)wb.sent);

    struct up_wait ua = {&fx.up, 0, TWOCONN_LEN};
    struct up_wait ub = {&fx.up, 1, TWOCONN_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &ua, 8000, 2));
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &ub, 8000, 2));

    /* Byte for byte, both directions, both streams: the only thing that
     * tells a live-session key from a fresh one. */
    ASSERT_EQ_INT((int)TWOCONN_LEN, (int)fx.up.conns[0].in_len);
    ASSERT_EQ_INT((int)TWOCONN_LEN, (int)fx.up.conns[1].in_len);
    ASSERT_UP_BYTES(fx.up, 0, a_src, TWOCONN_LEN);
    ASSERT_UP_BYTES(fx.up, 1, b_src, TWOCONN_LEN);

    struct reader_wait rwa = {&ra, TWOCONN_LEN};
    struct reader_wait rwb = {&rb, TWOCONN_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rwa, 8000, 2));
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rwb, 8000, 2));
    ASSERT_EQ_INT((int)TWOCONN_LEN, (int)ra.len);
    ASSERT_EQ_INT((int)TWOCONN_LEN, (int)rb.len);
    ASSERT_MEM_EQ(ra.buf, a_src, TWOCONN_LEN);
    ASSERT_MEM_EQ(rb.buf, b_src, TWOCONN_LEN);

    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, cs.broken);

    free(a_src);
    free(b_src);
    free(a_dst);
    free(b_dst);
    cloak_session_release_stream(&cs.sesh, sa);
    cloak_session_release_stream(&cs.sesh, sb);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- test 4: both dispatcher paths, one listener ------------------------ */

/* A redirected connection and a proxied one against the same listener, in
 * the same test. The redirect is provoked by a UID that is not in
 * BypassUID -- an ordinary unauthorised client, not a malformed one -- so
 * the dispatcher's own authentication is what routes it, and the cover
 * site receiving the client's first packet byte for byte is what proves
 * where it went (test_dispatcher_auth.c asserts its redirects the same
 * way).
 *
 * The proxied session is brought up FIRST and is asserted to still carry
 * bytes AFTER the redirect, so this is a statement about coexistence
 * rather than about two tests that happen to share a fixture. */
static void test_redirect_and_proxy_coexist(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 3004));
    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(6, (int)cloak_stream_write(st, (const uint8_t *)"before", 6));
    struct up_wait uw = {&fx.up, 0, 6};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_UP_BYTES(fx.up, 0, "before", 6);

    /* An unauthorised UID on the very same listener. */
    uint8_t uid_bad[CLOAK_UID_LEN];
    for (size_t i = 0; i < CLOAK_UID_LEN; i++) {
        uid_bad[i] = (uint8_t)(0xA0 + i);
    }
    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len =
        build_client_record(fx.server_pub, uid_bad, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM, now,
                            3005, 0, record, sizeof(record), shared_secret);
    ASSERT_TRUE(record_len > 0);

    int bad = client_connect(front_port(&fx));
    ASSERT_TRUE(bad >= 0);
    if (bad >= 0 && record_len > 0) {
        ASSERT_TRUE(write(bad, record, record_len) == (ssize_t)record_len);
        struct len_wait lw = {&fx.cover, record_len};
        ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &lw, 400, 5));
        ASSERT_EQ_INT(1, fx.cover.accept_count);
        ASSERT_EQ_INT((int)record_len, (int)fx.cover.len);
        ASSERT_MEM_EQ(fx.cover.buf, record, record_len);
    }

    /* The redirect created nothing: still one session, one proxy context,
     * one attach (the proxied connection's). */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, fx.attached_calls);

    /* And the proxied session is still live and still carrying bytes. */
    ASSERT_EQ_INT(0, cs.broken);
    ASSERT_EQ_INT(5, (int)cloak_stream_write(st, (const uint8_t *)"after", 5));
    uw.want = 11;
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(11, (int)fx.up.conns[0].in_len);
    ASSERT_UP_BYTES(fx.up, 0, "beforeafter", 11);
    ASSERT_EQ_INT(1, fx.up.accept_count);

    if (bad >= 0) {
        close(bad);
    }
    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- test 5: shutdown with traffic in flight ---------------------------- */

#define INFLIGHT_LEN ((size_t)(2u * 1024u * 1024u))
#define INFLIGHT_MIN_DELIVERED ((size_t)(64u * 1024u))
/* Bytes that must be outstanding INSIDE the server at the moment of the
 * teardown. Comfortably more than one of anything (the relay's 16 KiB
 * queue, the stream's 64 KiB reassembly queue) and comfortably less than
 * what the path can hold before the stream's own max_pending_frames cap
 * would reject a frame (64 frames of up to ~16 KiB each, on top of that
 * 64 KiB queue) -- so this is reached long before any layer's limit, and
 * the teardown really does run with a loaded pipeline rather than an
 * empty one. */
#define INFLIGHT_MIN_OUTSTANDING ((size_t)(128u * 1024u))

struct inflight_wait {
    writer_t *w;
    upstream_t *up;
    size_t want;
};

/* Keeps the transfer moving and stops as soon as the upstream has seen
 * enough of it to be certain bytes really are crossing the stack. It does
 * NOT wait for the transfer to finish -- the whole point is to tear down
 * while it is still going. */
static int inflight_ready(void *ctx) {
    struct inflight_wait *w = ctx;
    (void)writer_step(w->w);
    return w->up->conns[0].in_len >= w->want;
}

/* The same, but waiting for bytes to PILE UP rather than to arrive: with
 * the upstream stalled, everything the client keeps writing accumulates
 * between the two ends, and this is the difference. Without this stage
 * the test tears down an empty pipeline: a loopback reactor turn moves
 * megabytes, so on the un-stalled path the whole transfer completes
 * inside the first turn or two and "mid-flight" is not a state this test
 * is ever in (measured: it was not -- the first version of this test
 * delivered all 2 MiB before its own teardown, and its
 * still-in-flight assertions failed). */
static int inflight_outstanding(void *ctx) {
    struct inflight_wait *w = ctx;
    (void)writer_step(w->w);
    size_t delivered = w->up->conns[0].in_len;
    return w->w->sent > delivered && (w->w->sent - delivered) >= w->want;
}

/* CLEAN SHUTDOWN WITH TRAFFIC IN FLIGHT, IN THE BINARY'S OWN ORDER. Most
 * of what this can catch is only visible under ASan: a relay stopped too
 * late holds a freed cloak_stream_t, a relay never stopped leaks its
 * buffers, and a session destroyed before its relays is a
 * heap-use-after-free on the next byte from either side. The plain Debug
 * build sees the counter assertions and nothing else.
 *
 * The teardown runs fixture_shutdown_server -- the exact sequence a
 * binary's signal handler will run -- rather than any order that happens
 * to work here. */
static void test_shutdown_with_traffic_in_flight(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 3006));

    uint8_t *src = malloc(INFLIGHT_LEN);
    uint8_t *dst = malloc(INFLIGHT_LEN);
    ASSERT_TRUE(src != NULL && dst != NULL);
    if (src == NULL || dst == NULL) {
        free(src);
        free(dst);
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    for (size_t i = 0; i < INFLIGHT_LEN; i++) {
        src[i] = (uint8_t)((i * 13u + (i >> 7)) & 0xff);
    }

    cloak_stream_t *s1 = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(s1 != NULL);
    cloak_stream_t *s2 = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(s2 != NULL);
    if (s1 == NULL || s2 == NULL) {
        free(src);
        free(dst);
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }

    /* The bulk stream's upstream connection is brought up FIRST, so it is
     * deterministically fx.up.conns[0] -- the one the in-flight predicate
     * and every assertion below are written against. A second stream,
     * also relaying, follows it so the teardown walks more than one. */
    ASSERT_EQ_INT(1, (int)cloak_stream_write(s1, src, 1));
    struct up_wait uw1 = {&fx.up, 1, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &uw1, 400, 5));
    ASSERT_EQ_INT(4, (int)cloak_stream_write(s2, (const uint8_t *)"idle", 4));
    struct up_wait uw2 = {&fx.up, 2, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &uw2, 400, 5));
    ASSERT_EQ_INT(2, fx.up.accept_count);

    reader_t rd = {s1, dst, INFLIGHT_LEN, 0, 0};
    /* One frame per reactor turn: see writer_t::max_chunks_per_step. */
    writer_t w = {&cs.sesh, &rd, s1, src, INFLIGHT_LEN, 1, 1};
    struct inflight_wait iw = {&w, &fx.up, INFLIGHT_MIN_DELIVERED};
    ASSERT_TRUE(pump_until(fx.reactor, inflight_ready, &iw, 8000, 2));
    ASSERT_TRUE(fx.up.conns[0].in_len >= INFLIGHT_MIN_DELIVERED);

    /* Now load the pipeline: the upstream stops reading, the client keeps
     * writing, and the difference is bytes sitting inside the server. */
    fx.up.stall = 1;
    iw.want = INFLIGHT_MIN_OUTSTANDING;
    ASSERT_TRUE(pump_until(fx.reactor, inflight_outstanding, &iw, 8000, 2));

    /* MID-FLIGHT, ASSERTED AT THE MOMENT OF THE TEARDOWN rather than
     * hoped for: bytes really did cross the whole stack, a substantial
     * quantity is still in transit inside it, and neither end is anywhere
     * near the end of the transfer. Without all of these this would be a
     * shutdown test with no traffic in it. */
    ASSERT_TRUE(fx.up.conns[0].in_len >= INFLIGHT_MIN_DELIVERED);
    ASSERT_TRUE(w.sent > fx.up.conns[0].in_len);
    ASSERT_TRUE(w.sent - fx.up.conns[0].in_len >= INFLIGHT_MIN_OUTSTANDING);
    ASSERT_TRUE(w.sent < INFLIGHT_LEN);
    ASSERT_TRUE(fx.up.conns[0].in_len < INFLIGHT_LEN);
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, cs.broken);

    /* The binary's shutdown, in the binary's order. */
    fixture_shutdown_server(&fx);
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));

    /* Test-only cleanup, and it comes BEFORE the post-teardown pump on
     * purpose: no reactor turn has run since the shutdown, so the client's
     * streams are still ACTIVE and cloak_session_destroy reclaims them
     * (cloak/session.h). Pump first and the client would read the
     * closing-stream frames the proxy's teardown sent and then EOF on its
     * connection -- retiring those streams and then breaking, after which
     * they are neither reclaimed by destroy nor safe to release. */
    client_session_close(&cs);

    /* Nothing may fire into the wreckage afterwards. A fixed number of
     * turns, not a wall-clock window, and deliberately: nothing here is
     * waiting for a timer to expire (cloak_proxy_destroy cancels every
     * dial and retry timer it holds), only for any registration the
     * teardown failed to remove to be dispatched at all. The upstream
     * sockets are still open and still registered with the reactor, so a
     * relay that outlived its session would be handed a byte here. */
    for (int i = 0; i < 200; i++) {
        cloak_reactor_run_once(fx.reactor, 2);
    }

    free(src);
    free(dst);
    fixture_destroy(&fx);
}

TEST_MAIN_BEGIN()
test_stack_carries_traffic_end_to_end();
test_pipelined_frame_survives_handoff();
test_two_connections_one_session();
test_redirect_and_proxy_coexist();
test_shutdown_with_traffic_in_flight();
TEST_MAIN_END()
