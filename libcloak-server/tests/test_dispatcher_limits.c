#define _POSIX_C_SOURCE 200809L
#include "cloak/dispatcher.h"
#include "cloak/base64.h"
#include "cloak/clienthello.h"
#include "cloak/common.h"
#include "cloak/crypto.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "test_framework.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Task 3: limits, teardown and the failure matrix. Everything in this file
 * exercises the dispatcher under conditions Task 1/2's own test files
 * deliberately did not: a connection cap enforced against unauthenticated
 * accepts, cloak_dispatcher_destroy tearing down a connection in EVERY
 * state it can be in (including the one Task 2's review flagged as
 * untested -- mid-reply-write, and the reply-write deadline actually
 * firing), many slow connections being reaped by their deadline together,
 * and a fixed-seed smoke test that the first-packet/redirect state machine
 * never crashes or leaks on arbitrary bytes.
 *
 * Several helpers below (client_connect, cover_site_t and its callbacks,
 * pump_until, build_auth_payload/build_client_record) are copied verbatim
 * from test_dispatcher_redirect.c / test_dispatcher_auth.c rather than
 * shared, matching this project's own existing convention of duplicating
 * small test-only helpers across dispatcher test files instead of adding a
 * shared test-support library for them. */

/* ---- bounded reactor pumping --------------------------------------------
 *
 * Every wait in this file is "poll the reactor for up to N turns of at
 * most MS each", never unbounded -- three tests on this project have hung
 * or flaked in CI, all found only by repetition. */

typedef int (*pump_done_fn)(void *ctx);

static int pump_until(cloak_reactor_t *r, pump_done_fn done, void *ctx, int max_iters,
                      int per_iter_ms) {
    for (int i = 0; i < max_iters; i++) {
        if (done(ctx)) {
            return 1;
        }
        cloak_reactor_run_once(r, per_iter_ms);
    }
    return done(ctx);
}

/* ---- fake cover site ----------------------------------------------------
 *
 * Note this struct's buf/len are shared across every connection the fake
 * cover site accepts: fine for test_dispatcher_redirect.c's one-connection
 * tests, and fine here too, since every use of it below either (a) expects
 * exactly one connection to reach it, or (b) (the fuzz test) only ever
 * checks accept_count, never buf content, across many connections. */

typedef struct {
    cloak_reactor_t *reactor;
    int fd;
    int accept_count;
    uint8_t buf[8192];
    size_t len;
    int eof;
} cover_site_t;

static void cover_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    cover_site_t *cov = userdata;
    for (;;) {
        if (cov->len >= sizeof(cov->buf)) {
            break;
        }
        ssize_t n = read(fd, cov->buf + cov->len, sizeof(cov->buf) - cov->len);
        if (n > 0) {
            cov->len += (size_t)n;
            continue;
        }
        if (n == 0) {
            cov->eof = 1;
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        break;
    }
}

static void cover_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    cover_site_t *cov = userdata;
    cov->fd = fd;
    cov->accept_count++;
    cloak_reactor_add_fd(cov->reactor, fd, CLOAK_REACTOR_READABLE, cover_on_readable, cov);
}

struct len_wait {
    cover_site_t *cov;
    size_t want;
};

static int cover_has_len(void *ctx) {
    struct len_wait *w = ctx;
    return w->cov->len >= w->want;
}

struct count_wait {
    const cloak_dispatcher_t *d;
    size_t want;
};

static int conn_count_is(void *ctx) {
    struct count_wait *w = ctx;
    return cloak_dispatcher_conn_count(w->d) == w->want;
}

/* ---- client helper -------------------------------------------------------
 *
 * A plain blocking socket. A receive timeout bounds every read against a
 * dispatcher that never closes the way it should. */

static int client_connect(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* The client's own local (ephemeral) port -- the PEER port the
 * dispatcher's accepted socket for this same connection will report via
 * getpeername(), used both to target test_write_shim.c's interposition and
 * to find a specific connection inside cloak_dispatcher_t's own conns list
 * below (see find_conn_by_peer_port). Returns -1 on failure. */
static int client_local_port(int fd) {
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        return -1;
    }
    return ntohs(sa.sin_port);
}

/* Reaches directly into cloak_dispatcher_t's own (fully public, not
 * opaque) conns list -- the same thing test_dispatcher_redirect.c's
 * test_init_rejects_undersized_relay_buf_cap already does to d->conns/
 * d->conn_count -- to find the specific in-flight connection whose OWN fd
 * (still valid: c->fd is only ever set to -1 once ownership has passed to
 * a relay or to cloak_session_add_conn, see cloak/dispatcher.h's OWNERSHIP
 * comment) has peer_port as its peer. This is what lets the tests below
 * assert a PRECISE internal state (writing_reply == 1, dialing == 1)
 * rather than guessing how many reactor turns are "enough" -- a test that
 * merely pumped a fixed number of turns and hoped would pass equally
 * whether or not the connection actually reached the state under test. */
static cloak_dispatch_conn_t *find_conn_by_peer_port(cloak_dispatcher_t *d, int peer_port) {
    for (cloak_dispatch_conn_t *c = d->conns; c != NULL; c = c->next) {
        if (c->fd < 0) {
            continue;
        }
        struct sockaddr_in sa;
        socklen_t len = sizeof(sa);
        if (getpeername(c->fd, (struct sockaddr *)&sa, &len) == 0 && sa.sin_family == AF_INET &&
            ntohs(sa.sin_port) == (uint16_t)peer_port) {
            return c;
        }
    }
    return NULL;
}

struct conn_state_wait {
    cloak_dispatcher_t *d;
    int peer_port;
    int want_writing_reply; /* -1 = don't care */
    int want_dialing;       /* -1 = don't care */
};

static int conn_reached_state(void *ctx) {
    struct conn_state_wait *w = ctx;
    cloak_dispatch_conn_t *c = find_conn_by_peer_port(w->d, w->peer_port);
    if (c == NULL) {
        return 0;
    }
    if (w->want_writing_reply >= 0 && c->writing_reply != w->want_writing_reply) {
        return 0;
    }
    if (w->want_dialing >= 0 && c->dialing != w->want_dialing) {
        return 0;
    }
    return 1;
}

/* ---- building a real Cloak ClientHello, and its 48-byte auth payload ----
 *
 * Copied from test_dispatcher_auth.c: see that file's own top-of-file
 * comment for why this uses the project's real crypto primitives rather
 * than a mock, and for the 48-byte payload layout server_auth.h
 * documents. */

static void build_auth_payload(uint8_t out[48], const uint8_t uid[CLOAK_UID_LEN],
                               const char *proxy_method, uint8_t encryption_method,
                               int64_t timestamp, uint32_t session_id, int unordered) {
    memset(out, 0, 48);
    memcpy(out, uid, CLOAK_UID_LEN);

    size_t pmlen = strlen(proxy_method);
    if (pmlen > CLOAK_SERVER_AUTH_PROXY_METHOD_LEN) {
        pmlen = CLOAK_SERVER_AUTH_PROXY_METHOD_LEN;
    }
    memcpy(out + 16, proxy_method, pmlen);

    out[28] = encryption_method;

    uint64_t ts = (uint64_t)timestamp;
    for (int i = 0; i < 8; i++) {
        out[29 + i] = (uint8_t)(ts >> (8 * (7 - i)));
    }
    for (int i = 0; i < 4; i++) {
        out[37 + i] = (uint8_t)(session_id >> (8 * (3 - i)));
    }
    out[41] = unordered ? CLOAK_SERVER_AUTH_UNORDERED_FLAG : 0;
}

static size_t build_client_record(const uint8_t server_pub[CLOAK_X25519_KEY_LEN],
                                  const uint8_t uid[CLOAK_UID_LEN], const char *proxy_method,
                                  uint8_t encryption_method, int64_t timestamp,
                                  uint32_t session_id, int unordered, uint8_t *out_record,
                                  size_t out_cap) {
    uint8_t eph_priv[CLOAK_X25519_KEY_LEN];
    uint8_t eph_pub[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(eph_priv, eph_pub));

    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_shared_secret(eph_priv, server_pub, shared));

    uint8_t payload[48];
    build_auth_payload(payload, uid, proxy_method, encryption_method, timestamp, session_id,
                       unordered);

    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    memcpy(nonce, eph_pub, CLOAK_AEAD_NONCE_LEN);

    uint8_t ct[64];
    size_t ct_len = 0;
    ASSERT_EQ_INT(0, cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, shared, nonce, NULL, 0, payload,
                                     sizeof(payload), ct, &ct_len));
    ASSERT_EQ_INT((int)ct_len, 64);

    uint8_t handshake[CLOAK_CLIENTHELLO_MAX_BYTES];
    long hs_len = cloak_clienthello_build(&cloak_clienthello_chrome, eph_pub, ct, ct + 32,
                                          "www.example.com", handshake, sizeof(handshake));
    ASSERT_TRUE(hs_len > 0);
    if (hs_len <= 0) {
        return 0;
    }

    size_t total = 5 + (size_t)hs_len;
    ASSERT_TRUE(out_cap >= total);

    out_record[0] = 0x16;
    out_record[1] = 0x03;
    out_record[2] = 0x01;
    out_record[3] = (uint8_t)(((size_t)hs_len >> 8) & 0xff);
    out_record[4] = (uint8_t)((size_t)hs_len & 0xff);
    memcpy(out_record + 5, handshake, (size_t)hs_len);
    return total;
}

/* ---- fixture --------------------------------------------------------------
 *
 * One fixture shape serves every test in this file. opts.redir_addr == NULL
 * starts a live cover site of its own (needed for the mid-relay and
 * cap/slow-loris/fuzz tests); a non-NULL redir_addr (this file only ever
 * passes the TEST-NET-1 blackhole "192.0.2.1:9", matching
 * libcloak-common/tests/test_dial.c's own convention for "a SYN that is
 * never answered") is used verbatim instead, for the mid-dial test, which
 * needs a dial that never completes rather than one that succeeds
 * immediately on loopback. opts.with_auth pulls in the registry and a
 * server config that can actually authenticate build_client_record's
 * ClientHellos (BypassUID + ProxyBook); tests that never send a real
 * ClientHello leave it 0 and get the simpler config
 * test_dispatcher_redirect.c's own fixture uses. */

typedef struct {
    const char *redir_addr;
    int with_auth;
    uint64_t handshake_timeout_ms;
    uint64_t redirect_dial_timeout_ms;
    size_t max_pending_conns;
} fixture_opts_t;

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
    cloak_server_config_t cfg;
    cloak_server_t srv;
    int srv_ready;
    cloak_server_registry_t registry;
    int registry_ready;
    cloak_dispatcher_t d;
    int d_ready;
    cloak_listener_t front;
    int have_front;

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_ok[CLOAK_UID_LEN];
};

static int fixture_init(struct fixture *fx, const fixture_opts_t *opts) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

    char redir_buf[64];
    const char *redir = opts->redir_addr;
    if (redir == NULL) {
        fx->cover.reactor = fx->reactor;
        fx->cover.fd = -1;
        ASSERT_EQ_INT(0, cloak_listener_open(&fx->cover_listener, fx->reactor, "127.0.0.1:0",
                                             cover_on_accept, &fx->cover, err, sizeof(err)));
        fx->have_cover_listener = 1;
        int cover_port = cloak_listener_port(&fx->cover_listener);
        ASSERT_TRUE(cover_port > 0);
        snprintf(redir_buf, sizeof(redir_buf), "127.0.0.1:%d", cover_port);
        redir = redir_buf;
    }

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, fx->server_pub));
    for (size_t i = 0; i < CLOAK_UID_LEN; i++) {
        fx->uid_ok[i] = (uint8_t)(0x10 + i);
    }
    char priv_b64[64];
    ASSERT_EQ_INT(0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64,
                                         sizeof(priv_b64)));

    char json[1024];
    if (opts->with_auth) {
        char uidok_b64[32];
        ASSERT_EQ_INT(0,
                     cloak_base64_encode(fx->uid_ok, CLOAK_UID_LEN, uidok_b64, sizeof(uidok_b64)));
        snprintf(json, sizeof(json),
                 "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:1\"]},"
                 "\"BindAddr\":[\":443\"],\"RedirAddr\":\"%s\","
                 "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\"]}",
                 redir, priv_b64, uidok_b64);
    } else {
        snprintf(json, sizeof(json),
                 "{\"BindAddr\":[\":443\"],\"RedirAddr\":\"%s\",\"PrivateKey\":\"%s\"}", redir,
                 priv_b64);
    }
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.handshake_timeout_ms = opts->handshake_timeout_ms;
    dcfg.redirect_dial_timeout_ms = opts->redirect_dial_timeout_ms;
    dcfg.max_pending_conns = opts->max_pending_conns;

    if (opts->with_auth) {
        ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor, registry_on_broken,
                                                    NULL));
        fx->registry_ready = 1;
        dcfg.registry = &fx->registry;

        dcfg.session_config_template.max_on_wire_size = 16401;
        dcfg.session_config_template.stream_recv_capacity = 65536;
        dcfg.session_config_template.stream_max_pending_frames = 64;
        dcfg.session_config_template.conn_send_queue_cap = 262144;
        dcfg.session_config_template.inactivity_timeout_ms = 60000;
        /* prepare_session/attached deliberately left NULL: no test in this
         * file needs a completed handshake to succeed -- every auth-driving
         * test here deliberately stalls the reply write forever instead. */
    }

    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, "127.0.0.1:0",
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;

    return 0;
}

/* Destroys the dispatcher BEFORE the registry, same reasoning
 * test_dispatcher_auth.c's own fixture_destroy documents: a connection
 * dropped by cloak_dispatcher_destroy mid-authentication can still call
 * cloak_server_registry_close. */
static void fixture_destroy(struct fixture *fx) {
    if (fx->have_front) {
        cloak_listener_close(&fx->front);
    }
    if (fx->d_ready) {
        cloak_dispatcher_destroy(&fx->d);
    }
    if (fx->registry_ready) {
        cloak_server_registry_destroy(&fx->registry);
    }
    if (fx->srv_ready) {
        cloak_server_destroy(&fx->srv);
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

/* Clears every env var test_write_shim.c's interposition reads, so a test
 * that used it (one-shot or sticky) never leaks state into the next test
 * in this same process. */
static void clear_shim_env(void) {
    unsetenv("CLOAK_TEST_FORCE_PEER_PORT");
    unsetenv("CLOAK_TEST_FORCE_MODE");
    unsetenv("CLOAK_TEST_FORCE_STICKY");
}

/* ---- test 1: the cap ------------------------------------------------------
 *
 * max_pending_conns + 1 connections that send nothing: the last is closed
 * immediately (never allocated) and the count never exceeds the cap. Then
 * one of the capped connections completes (closes), and a fresh connection
 * is accepted -- the cap is a live limit, not a one-way latch. */
static void test_cap_closes_immediately_and_recovers(void) {
    enum { CAP = 3 };
    fixture_opts_t opts = {0};
    opts.max_pending_conns = CAP;
    opts.handshake_timeout_ms = 60000; /* generous: nothing here should hit it */

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, &opts));

    int clients[CAP];
    for (int i = 0; i < CAP; i++) {
        clients[i] = client_connect(front_port(&fx));
        ASSERT_TRUE(clients[i] >= 0);
    }

    struct count_wait cw = {&fx.d, CAP};
    ASSERT_TRUE(pump_until(fx.reactor, conn_count_is, &cw, 200, 10));
    ASSERT_EQ_INT(CAP, (int)cloak_dispatcher_conn_count(&fx.d));

    /* The (CAP+1)th: accepted at the TCP level (the listener's own accept
     * queue is independent of this cap), but the dispatcher must close it
     * immediately without allocating a connection for it. */
    int extra = client_connect(front_port(&fx));
    ASSERT_TRUE(extra >= 0);

    char c;
    int saw_close = 0;
    for (int i = 0; i < 100 && !saw_close; i++) {
        cloak_reactor_run_once(fx.reactor, 10);
        ssize_t n = recv(extra, &c, 1, MSG_DONTWAIT);
        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            saw_close = 1;
        }
    }
    ASSERT_TRUE(saw_close);
    ASSERT_EQ_INT(CAP, (int)cloak_dispatcher_conn_count(&fx.d)); /* never exceeded */
    close(extra);

    /* Let one of the original CAP connections complete (here: the peer
     * simply goes away), freeing a slot. */
    close(clients[0]);
    struct count_wait cw2 = {&fx.d, CAP - 1};
    ASSERT_TRUE(pump_until(fx.reactor, conn_count_is, &cw2, 200, 10));
    ASSERT_EQ_INT(CAP - 1, (int)cloak_dispatcher_conn_count(&fx.d));

    /* A fresh connection is now accepted (not closed on sight): the cap
     * recovers rather than latching shut forever. */
    int fresh = client_connect(front_port(&fx));
    ASSERT_TRUE(fresh >= 0);
    struct count_wait cw3 = {&fx.d, CAP};
    ASSERT_TRUE(pump_until(fx.reactor, conn_count_is, &cw3, 200, 10));
    ASSERT_EQ_INT(CAP, (int)cloak_dispatcher_conn_count(&fx.d));

    /* fresh must NOT have been closed the way extra was. */
    ssize_t n = recv(fresh, &c, 1, MSG_DONTWAIT);
    ASSERT_TRUE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));

    for (int i = 1; i < CAP; i++) {
        close(clients[i]);
    }
    close(fresh);
    fixture_destroy(&fx);
}

/* ---- test 2a: teardown of mid-first-packet, mid-reply-write and
 * mid-relay, all torn down by the SAME cloak_dispatcher_destroy call ------
 *
 * Mid-dial is deliberately NOT included here: RedirAddr is one value per
 * cloak_server_t (resolved once, in cloak_server_init), so a fixture whose
 * redirect target is a live cover site (needed to reach mid-relay) cannot
 * simultaneously have a redirect target that never answers (needed to
 * reach mid-dial and stay there). test_teardown_mid_dial below covers that
 * state in its own fixture instead. Real assurance that nothing here is
 * leaked, double-freed, or double-closed comes from running this file
 * under ASan/UBSan. */
static void test_teardown_first_packet_reply_write_and_relay(void) {
    fixture_opts_t opts = {0};
    opts.with_auth = 1;
    opts.handshake_timeout_ms = 60000; /* nothing here should hit a deadline */

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, &opts));

    /* Connection A: never sends anything -- mid first-packet. */
    int client_a = client_connect(front_port(&fx));
    ASSERT_TRUE(client_a >= 0);

    /* Connection B: a real, authenticating ClientHello, with
     * test_write_shim.c STICKY-forcing every reply-write attempt to see
     * EAGAIN -- mid reply-write. STICKY, not one-shot, is required here
     * specifically because the test keeps pumping this same reactor
     * afterward to drive connection C's redirect/relay to completion; a
     * one-shot force would be consumed by B's first write attempt and
     * then, the very next time the reactor delivers B's pending WRITABLE
     * event (as a side effect of pumping for C), the real write() would
     * succeed and complete the hand-off, escaping writing_reply before
     * this test ever gets to destroy -- exactly the race this file's
     * choice of STICKY here closes off. */
    int client_b = client_connect(front_port(&fx));
    ASSERT_TRUE(client_b >= 0);
    int port_b = client_local_port(client_b);
    ASSERT_TRUE(port_b > 0);
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port_b);
    ASSERT_EQ_INT(0, setenv("CLOAK_TEST_FORCE_PEER_PORT", port_str, 1));
    unsetenv("CLOAK_TEST_FORCE_MODE"); /* eagain */
    ASSERT_EQ_INT(0, setenv("CLOAK_TEST_FORCE_STICKY", "1", 1));

    int64_t now = (int64_t)time(NULL);
    uint8_t record_b[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    size_t record_b_len = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                              (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 4242, 0,
                                              record_b, sizeof(record_b));
    ASSERT_TRUE(record_b_len > 0);
    ASSERT_TRUE(write(client_b, record_b, record_b_len) == (ssize_t)record_b_len);

    struct conn_state_wait sw = {&fx.d, port_b, 1, -1};
    ASSERT_TRUE(pump_until(fx.reactor, conn_reached_state, &sw, 100, 10));
    /* writing_reply == 1 is only reachable via a forced failure --
     * test_write_shim.c's own top-of-file comment establishes that
     * genuine socket-buffer backpressure cannot produce EAGAIN for a
     * reply this small -- so this assertion alone is proof the shim fired,
     * without relying on CLOAK_TEST_FORCE_PEER_PORT's own liveness, which
     * STICKY mode deliberately never clears. */
    cloak_dispatch_conn_t *cb = find_conn_by_peer_port(&fx.d, port_b);
    ASSERT_TRUE(cb != NULL);
    if (cb == NULL) {
        /* Can only happen if the LD_PRELOAD shim this test depends on was
         * not actually loaded (e.g. this binary run directly rather than
         * via ctest, which wires it in CMakeLists.txt) -- the real write()
         * would then have succeeded immediately and handed this
         * connection off already. ASSERT_TRUE alone does not stop
         * execution (see test_framework.h), so this guard is what turns
         * that misconfiguration into a clean failure instead of a NULL
         * dereference. */
        close(client_a);
        close(client_b);
        clear_shim_env();
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, cb->writing_reply);
    ASSERT_EQ_INT(1, cb->auth_created); /* a brand-new session, never attached */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    /* Connection C: junk byte, pumped all the way to a live relay --
     * mid-relay. */
    int client_c = client_connect(front_port(&fx));
    ASSERT_TRUE(client_c >= 0);
    const char *msg = "HELLO\n";
    ASSERT_TRUE(write(client_c, msg, strlen(msg)) == (ssize_t)strlen(msg));
    struct len_wait lw = {&fx.cover, strlen(msg)};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &lw, 200, 20));
    ASSERT_EQ_INT(1, fx.cover.accept_count);
    /* One extra turn so C's relay is fully wired up (both fds registered)
     * before destroy runs. */
    cloak_reactor_run_once(fx.reactor, 10);
    ASSERT_TRUE(fx.cover.fd >= 0);

    ASSERT_EQ_INT(3, (int)cloak_dispatcher_conn_count(&fx.d));

    /* The destroy under test: one call tearing down all three states at
     * once. */
    cloak_dispatcher_destroy(&fx.d);
    fx.d_ready = 0; /* already torn down; fixture_destroy must not repeat it */
    ASSERT_EQ_INT(0, (int)cloak_dispatcher_conn_count(&fx.d));

    /* auth_created's unwind fired for B: the never-attached session it
     * created is gone from the registry, not leaked in it forever. */
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));

    /* Every fd this module owned is closed: A and B's client-side sockets
     * observe the server side closed... */
    char c;
    ssize_t n = recv(client_a, &c, 1, 0);
    ASSERT_TRUE(n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK));
    n = recv(client_b, &c, 1, 0);
    ASSERT_TRUE(n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK));
    /* ...and C's relay closed BOTH of the fds it itself owned: the
     * client's, and the dispatcher's own outbound socket dialed to the
     * cover site. The cover site's own ACCEPTED fd is the OTHER end of
     * that same TCP connection, owned by this TEST fixture, not by the
     * dispatcher -- closing one end of a socket never closes the other
     * end's fd, it only delivers that end EOF, which is what is checked
     * here instead (pumping the fixture's own reactor, which is what
     * services cover_on_readable, so it notices). */
    n = recv(client_c, &c, 1, 0);
    ASSERT_TRUE(n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK));
    for (int i = 0; i < 100 && !fx.cover.eof; i++) {
        cloak_reactor_run_once(fx.reactor, 10);
    }
    ASSERT_TRUE(fx.cover.eof);

    close(client_a);
    close(client_b);
    close(client_c);
    clear_shim_env();
    fixture_destroy(&fx);
}

/* ---- test 2b: teardown of a mid-dial connection --------------------------
 *
 * RedirAddr is 192.0.2.1:9 (TEST-NET-1, RFC 5737 -- guaranteed unrouteable,
 * matching libcloak-common/tests/test_dial.c's own test_dial_to_
 * blackhole_times_out): the SYN is never answered, so the dial started by
 * conn_start_redirect stays pending indefinitely rather than completing on
 * loopback in well under a millisecond the way it does everywhere else in
 * this file. A generous redirect_dial_timeout_ms keeps that timeout itself
 * from firing before the destroy under test runs. */
static void test_teardown_mid_dial(void) {
    fixture_opts_t opts = {0};
    opts.redir_addr = "192.0.2.1:9";
    opts.handshake_timeout_ms = 60000;
    opts.redirect_dial_timeout_ms = 60000;

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, &opts));

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    const char *msg = "HELLO\n";
    ASSERT_TRUE(write(client, msg, strlen(msg)) == (ssize_t)strlen(msg));

    /* conn_start_redirect runs synchronously inside the same on_readable
     * call that reads "HELLO\n" and reaches CLOAK_FIRSTPACKET_ERROR, and
     * cloak_dial_start's own non-blocking connect() to an unrouteable
     * address returns immediately (EINPROGRESS) rather than blocking -- so
     * one delivered read event is already enough to reach dialing == 1. */
    int done = 0;
    for (int i = 0; i < 50 && !done; i++) {
        cloak_reactor_run_once(fx.reactor, 10);
        if (fx.d.conns != NULL && fx.d.conns->dialing) {
            done = 1;
        }
    }
    ASSERT_TRUE(done);
    ASSERT_TRUE(fx.d.conns != NULL);
    if (fx.d.conns == NULL) {
        /* ASSERT_TRUE alone does not stop execution (see
         * test_framework.h); this guard turns a failed precondition into
         * a clean failure instead of a NULL dereference below. */
        close(client);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, fx.d.conns->dialing);
    ASSERT_EQ_INT(1, (int)cloak_dispatcher_conn_count(&fx.d));

    cloak_dispatcher_destroy(&fx.d);
    fx.d_ready = 0;
    ASSERT_EQ_INT(0, (int)cloak_dispatcher_conn_count(&fx.d));

    char c;
    ssize_t n = recv(client, &c, 1, 0);
    ASSERT_TRUE(n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK));

    close(client);
    fixture_destroy(&fx);
}

/* ---- test 2c (carried-forward item): the reply-write deadline actually
 * firing -----------------------------------------------------------------
 *
 * Distinct from test 2a's mid-reply-write case, which stalls at
 * writing_reply == 1 but is torn down by an explicit destroy before any
 * deadline is involved. Here handshake_timeout_ms (reused, per conn_on_
 * firstpacket_done's own comment, as the reply-write/hand-off deadline
 * too) is short, and test_write_shim.c's STICKY mode keeps every write()
 * to this connection failing with EAGAIN -- not just the first one -- so
 * the write can never drain and the deadline is what has to end it, not a
 * destroy call. Genuine socket-buffer backpressure cannot do this for a
 * reply this small (test_write_shim.c's own top-of-file comment); sticky
 * interposition is the only way to hold this state open long enough for a
 * bounded deadline to elapse against it. */
static void test_reply_write_deadline_fires(void) {
    fixture_opts_t opts = {0};
    opts.with_auth = 1;
    opts.handshake_timeout_ms = 150;

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, &opts));

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    int port = client_local_port(client);
    ASSERT_TRUE(port > 0);
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    ASSERT_EQ_INT(0, setenv("CLOAK_TEST_FORCE_PEER_PORT", port_str, 1));
    unsetenv("CLOAK_TEST_FORCE_MODE"); /* eagain */
    ASSERT_EQ_INT(0, setenv("CLOAK_TEST_FORCE_STICKY", "1", 1));

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    size_t record_len = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                            (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 5252, 0, record,
                                            sizeof(record));
    ASSERT_TRUE(record_len > 0);
    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    /* Confirm it actually reached the stalled write state before waiting
     * for the deadline -- otherwise a dispatcher that (incorrectly) never
     * entered writing_reply at all would still "pass" merely by having no
     * connection left to time out. */
    struct conn_state_wait sw = {&fx.d, port, 1, -1};
    ASSERT_TRUE(pump_until(fx.reactor, conn_reached_state, &sw, 100, 10));
    ASSERT_EQ_INT(1, (int)cloak_dispatcher_conn_count(&fx.d));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    /* Bounded wait for the 150ms deadline to reap it: polled in 10ms
     * steps for up to 3 seconds, comfortably above the deadline itself. */
    struct count_wait cw = {&fx.d, 0};
    ASSERT_TRUE(pump_until(fx.reactor, conn_count_is, &cw, 300, 10));
    ASSERT_EQ_INT(0, (int)cloak_dispatcher_conn_count(&fx.d));

    /* The never-attached session this connection created is unwound too --
     * the same auth_created discrimination conn_teardown documents,
     * exercised here via the deadline rather than via destroy. */
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));

    char c;
    ssize_t n = recv(client, &c, 1, 0);
    ASSERT_TRUE(n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK));

    close(client);
    clear_shim_env();
    fixture_destroy(&fx);
}

/* ---- test 3: slow-loris ---------------------------------------------------
 *
 * Many connections, each dribbling one byte of a declared-but-never-
 * completed TLS record body per turn: none of them ever reaches DONE or
 * ERROR on its own, so the only thing that can ever reap them is the
 * shared first-packet deadline -- and it must reap every one of them, not
 * merely the first or the last, proving the deadline/teardown machinery
 * is not order-dependent when many connections are in flight together. */
static void test_slow_loris_all_reaped_by_deadline(void) {
    enum { N = 20 };
    fixture_opts_t opts = {0};
    opts.handshake_timeout_ms = 200;
    opts.max_pending_conns = 512; /* comfortably above N */

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, &opts));

    int clients[N];
    for (int i = 0; i < N; i++) {
        clients[i] = client_connect(front_port(&fx));
        ASSERT_TRUE(clients[i] >= 0);
    }

    /* A TLS record header declaring a 200-byte body -- comfortably within
     * CLOAK_FIRSTPACKET_MAX -- of which only a handful of bytes are ever
     * actually sent, one per client per turn. */
    uint8_t header[5] = {0x16, 0x03, 0x01, 0x00, 200};
    for (int i = 0; i < N; i++) {
        ASSERT_TRUE(write(clients[i], header, sizeof(header)) == (ssize_t)sizeof(header));
    }
    cloak_reactor_run_once(fx.reactor, 5);

    for (int turn = 0; turn < 10; turn++) {
        uint8_t b = (uint8_t)turn;
        for (int i = 0; i < N; i++) {
            /* Best-effort: a client whose deadline has already fired may
             * see EPIPE/ECONNRESET here, which is fine -- it is already
             * being reaped, exactly what this test is proving happens to
             * every one of them. */
            ssize_t wn = write(clients[i], &b, 1);
            (void)wn;
        }
        cloak_reactor_run_once(fx.reactor, 5);
    }

    /* Still short of the declared 200-byte body (5 header + at most 10
     * dribbled == 15 bytes), so every connection must still be in flight,
     * mid first-packet -- the deadline, not completion, is what ends this. */
    ASSERT_EQ_INT(N, (int)cloak_dispatcher_conn_count(&fx.d));

    struct count_wait cw = {&fx.d, 0};
    ASSERT_TRUE(pump_until(fx.reactor, conn_count_is, &cw, 300, 20));
    ASSERT_EQ_INT(0, (int)cloak_dispatcher_conn_count(&fx.d));

    for (int i = 0; i < N; i++) {
        char c;
        ssize_t n = recv(clients[i], &c, 1, 0);
        ASSERT_TRUE(n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK));
        close(clients[i]);
    }

    fixture_destroy(&fx);
}

/* ---- test 4: fuzz-shaped robustness ---------------------------------------
 *
 * NOT a substitute for the libFuzzer targets the project's own spec calls
 * for: this is a smoke test that the first-packet/redirect state machine
 * survives arbitrary bytes without crashing or leaking, nothing more --
 * it has no coverage feedback, no corpus, and a fixed iteration count.
 *
 * The seed is fixed so any failure this ever finds reproduces exactly.
 * Every odd-indexed connection is fed CLOAK_FIRSTPACKET_MAX random bytes
 * in one write(): tracing cloak_firstpacket_feed (firstpacket.c) shows
 * that this ALWAYS reaches a terminal DONE or ERROR without ever needing
 * the handshake deadline --
 *   - a first byte that is not 0x16 or 'G' fails immediately (the
 *     overwhelming majority of random bytes);
 *   - 0x16 (TLS): whatever 2-byte body length follows, either it makes
 *     the declared total exceed CLOAK_FIRSTPACKET_MAX (fails immediately)
 *     or it does not, in which case the total is <= CLOAK_FIRSTPACKET_MAX
 *     and this connection already supplied that many bytes, so DONE is
 *     reached exactly when the declared length is;
 *   - 'G' (WebSocket): either a CRLFCRLF terminator turns up somewhere in
 *     the CLOAK_FIRSTPACKET_MAX bytes supplied (DONE) or it does not, in
 *     which case the buffer fills completely and push_byte's own capacity
 *     check fails it.
 * So these connections always redirect (dispatcher_authenticate cannot
 * succeed against random bytes) and this test does not need to wait on a
 * deadline for them. Every even-indexed connection instead sends a random
 * SHORT prefix and then closes immediately, exercising the "peer already
 * gone" drop path instead -- so both terminal outcomes the brief calls out
 * ("redirects or drops") are genuinely exercised, not just one of them by
 * construction. */
static void test_fuzz_first_packets_never_crash_or_leak(void) {
    enum { FUZZ_CONNS = 300 };
    unsigned seed = 0xC10A15EDu; /* fixed: any failure here must reproduce */

    fixture_opts_t opts = {0};
    opts.handshake_timeout_ms = 300; /* only reachable by the "drop" half if ever */
    opts.max_pending_conns = 512;

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, &opts));

    uint8_t buf[CLOAK_FIRSTPACKET_MAX];
    int redirect_leaning = 0, drop_leaning = 0;

    for (int i = 0; i < FUZZ_CONNS; i++) {
        int fd = client_connect(front_port(&fx));
        ASSERT_TRUE(fd >= 0);
        if (fd < 0) {
            continue;
        }

        if (i % 2 == 0) {
            for (size_t j = 0; j < sizeof(buf); j++) {
                buf[j] = (uint8_t)rand_r(&seed);
            }
            ssize_t n = write(fd, buf, sizeof(buf));
            ASSERT_TRUE(n == (ssize_t)sizeof(buf));
            redirect_leaning++;
            /* Left open: this connection is expected to end up relaying,
             * torn down later by fixture_destroy along with anything
             * else still in flight -- itself extra teardown-under-load
             * coverage, with many connections in various post-first-
             * packet states at once. */
        } else {
            size_t len = 1 + (size_t)(rand_r(&seed) % (CLOAK_FIRSTPACKET_MAX - 1));
            for (size_t j = 0; j < len; j++) {
                buf[j] = (uint8_t)rand_r(&seed);
            }
            ssize_t n = write(fd, buf, len);
            ASSERT_TRUE(n == (ssize_t)len);
            close(fd);
            drop_leaning++;
        }

        /* Drain periodically rather than after every connection, so the
         * front listener's own accept backlog (128, see
         * libcloak-common/src/listener.c) never fills while this loop is
         * still opening new ones. */
        if (i % 16 == 15) {
            for (int k = 0; k < 5; k++) {
                cloak_reactor_run_once(fx.reactor, 2);
            }
        }
    }
    ASSERT_TRUE(redirect_leaning > 0);
    ASSERT_TRUE(drop_leaning > 0);

    /* Settle: let dials/relays for the "redirect-leaning" half finish
     * starting, and the deadline (if it is ever actually needed by some
     * unlucky "drop-leaning" connection whose bytes happened to look like
     * a valid, incomplete prefix) reap anything still mid-first-packet. */
    for (int i = 0; i < 200; i++) {
        cloak_reactor_run_once(fx.reactor, 10);
    }

    /* No crash and no hang got this far -- the core claim of this test.
     * cover.accept_count > 0 additionally confirms at least some of the
     * "redirect-leaning" connections genuinely reached the cover site,
     * i.e. this exercised the real redirect path, not merely one that
     * closes everything. Explicitly destroying the dispatcher here, with
     * however many connections are still relaying or mid-first-packet at
     * once, is itself a teardown-under-load exercise ASan/UBSan checks. */
    ASSERT_TRUE(fx.cover.accept_count > 0);

    cloak_dispatcher_destroy(&fx.d);
    fx.d_ready = 0;
    ASSERT_EQ_INT(0, (int)cloak_dispatcher_conn_count(&fx.d));

    fixture_destroy(&fx);
}

TEST_MAIN_BEGIN()
    test_cap_closes_immediately_and_recovers();
    test_teardown_first_packet_reply_write_and_relay();
    test_teardown_mid_dial();
    test_reply_write_deadline_fires();
    test_slow_loris_all_reaped_by_deadline();
    test_fuzz_first_packets_never_crash_or_leak();
TEST_MAIN_END()
