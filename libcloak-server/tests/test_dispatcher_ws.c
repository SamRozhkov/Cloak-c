#define _POSIX_C_SOURCE 200809L

/* THE CDN PATH, END TO END, AND THE ORDER IT VALIDATES IN.
 *
 * Tasks 1-3 built a WebSocket frame codec, a framing mode for
 * cloak_conn_t and an upgrade parser; every one of them was reachable
 * from nothing. This file is the first that drives a real socket through
 * cloak_dispatcher_accept carrying an HTTP GET and gets a real
 * cloak_session_t out the other end, so it is also the first that can
 * observe the two things this transport is easy to get wrong:
 *
 *   1. THE REPLY IS FLAT. In CDN mode the server answers with the 101
 *      followed by ONE unmasked binary frame carrying
 *      [12-byte nonce][48 bytes AES-GCM(session key)] -- 60 bytes of
 *      payload, 62 on the wire. The direct path scatters those same 60
 *      bytes across a fake ServerHello and two more records. A test that
 *      only checked "the client recovered a session key" would pass
 *      against either shape, so the bytes themselves are asserted here.
 *
 *   2. THE ORDER OF VALIDATION IS THE POINT OF THE TASK. Go
 *      authenticates on the `Hidden` header alone
 *      (internal/server/websocket.go:22-41) and lets gorilla's
 *      Upgrader.Upgrade check `Connection`, `Sec-WebSocket-Key` and
 *      `Origin` afterwards -- by which time dispatchConnection has
 *      already authorised the UID, made the user active and called
 *      finishHandshake. When that later check fails,
 *      websocketAux.go:129-138 returns WITHOUT sending on an unbuffered
 *      channel that websocket.go:47-50 is already blocked on, so the
 *      goroutine, the socket and the ActiveUser bookkeeping leak
 *      permanently. A CDN that rewrites `Connection`, regenerates a
 *      malformed `Sec-WebSocket-Key` or injects an `Origin` wedges EVERY
 *      connection.
 *
 *      This port validates the whole upgrade -- `Hidden` included -- in
 *      one pass BEFORE the UID is authorised, so a malformed upgrade is
 *      an ordinary redirect to the cover site. test_panel_is_untouched_*
 *      below is what holds that in place, and it asserts on the PANEL'S
 *      OWN COUNTERS rather than on the connection's outcome: "the
 *      connection was redirected" is true for a dozen reasons that have
 *      nothing to do with whether a user was made active.
 *
 * THE TX METER'S OWN FIX IS NOT TESTED HERE, and that is deliberate.
 * cloak_switchboard_send used to bill every frame the TLS record
 * header's five bytes regardless of what the connection actually put on
 * the wire; the CDN envelope is two or four (six or eight from the
 * client, whose mask key is another four). The bracket that pins it
 * lives in libcloak-mux/tests/test_switchboard.c, next to the code it
 * describes, so that anyone editing libcloak-mux and running only its
 * suite sees a regression in cloak_conn_envelope_len. An earlier
 * revision kept it here, on the argument that this is the commit which
 * made the CDN framing mode reachable from a server; true, but it made
 * the regression invisible to the suite that owns the function.
 *
 * EVERY WAIT IS BOUNDED BY THE CLOCK, never by an iteration count, and
 * every port is ephemeral -- the two disciplines this project's test
 * suites have each paid for more than once. */

#include "cloak/base64.h"
#include "cloak/conn.h"
#include "cloak/crypto.h"
#include "cloak/dispatcher.h"
#include "cloak/net.h"
#include "cloak/proxy.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
#include "cloak/ws_handshake.h"
#include "test_framework.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Clocks and bounded pumping                                          */
/* ------------------------------------------------------------------ */

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

/* Every wait in this file is bounded by THIS many milliseconds of real
 * time. Generous on purpose: these suites run four binaries at a time
 * under ctest -j4 and under ASan, and a wait that expires because the
 * machine was busy is a false failure, which is strictly worse than a
 * slow pass. Nothing here depends on the budget being tight -- the
 * timing measurements below take their numbers from how long each probe
 * ACTUALLY took, not from how long it was allowed to take. */
#define WS_PUMP_BUDGET_MS 10000

typedef int (*pump_done_fn)(void *ctx);

/* Pumps the reactor until done(ctx) is true, bounded by REAL TIME. The
 * iteration ceiling is a backstop against a clock that does not advance
 * and is sized so it cannot bind first -- see client_harness.h's own
 * pump_until, whose reasoning (and measurement) this mirrors. */
static int pump_until(cloak_reactor_t *r, pump_done_fn done, void *ctx, int budget_ms,
                      int per_iter_ms) {
    uint64_t start = now_us();
    uint64_t budget_us = (uint64_t)(budget_ms > 0 ? budget_ms : 0) * 1000u;
    for (uint64_t i = 0; i < 50000000u; i++) {
        if (done(ctx)) {
            return 1;
        }
        if (now_us() - start >= budget_us) {
            break;
        }
        cloak_reactor_run_once(r, per_iter_ms);
    }
    return done(ctx);
}

/* ------------------------------------------------------------------ */
/* Fake cover site: answers every connection with the same fixed bytes  */
/* ------------------------------------------------------------------ */

/* WHY THE COVER SITE SENDS A BANNER, and why it is the same one every
 * time: "these three refusals are indistinguishable" is only assertable
 * against something, and the honest something is the bytes a connection
 * the server has no opinion about receives. */
static const char COVER_BANNER[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
#define COVER_BANNER_LEN (sizeof(COVER_BANNER) - 1)

#define COVER_MAX_LIVE 64

typedef struct cover_site {
    cloak_reactor_t *reactor;
    int fds[COVER_MAX_LIVE]; /* -1 == free slot */
    int accept_count;        /* cumulative, never decremented */
    struct cover_site *self;
} cover_site_t;

/* Slots are RECYCLED on the peer's EOF. Without that, a file this size
 * (several dozen redirects, by design -- the timing bracket takes 15
 * samples per arm) would run the process out of descriptors partway
 * through and fail for a reason that has nothing to do with the code
 * under test. */
static void cover_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)events;
    cover_site_t *cov = userdata;
    uint8_t buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n == 0) {
            for (int i = 0; i < COVER_MAX_LIVE; i++) {
                if (cov->fds[i] == fd) {
                    cov->fds[i] = -1;
                    break;
                }
            }
            cloak_reactor_remove_fd(r, fd);
            close(fd);
        }
        return;
    }
}

static void cover_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    cover_site_t *cov = userdata;
    int slot = -1;
    for (int i = 0; i < COVER_MAX_LIVE; i++) {
        if (cov->fds[i] < 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        close(fd);
        return;
    }
    cov->accept_count++;
    cov->fds[slot] = fd;
    /* A blocking write of 39 bytes onto a freshly accepted loopback
     * socket cannot short-write; a partial one would show up as a
     * mismatched length in every probe at once, never as a silent pass. */
    ssize_t n = write(fd, COVER_BANNER, COVER_BANNER_LEN);
    (void)n;
    (void)cloak_reactor_add_fd(cov->reactor, fd, CLOAK_REACTOR_READABLE, cover_on_readable, cov);
}

static void cover_destroy(cover_site_t *cov) {
    for (int i = 0; i < COVER_MAX_LIVE; i++) {
        if (cov->fds[i] >= 0) {
            cloak_reactor_remove_fd(cov->reactor, cov->fds[i]);
            close(cov->fds[i]);
            cov->fds[i] = -1;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Fake upstream: records what it receives                              */
/* ------------------------------------------------------------------ */

#define UP_MAX 8
#define UP_CAP ((size_t)65536)

typedef struct {
    int fd;
    uint8_t in[UP_CAP];
    size_t in_len;
} up_conn_t;

struct upstream;
typedef struct {
    struct upstream *up;
    int idx;
} up_slot_t;

typedef struct upstream {
    cloak_reactor_t *reactor;
    int accept_count;
    up_conn_t conns[UP_MAX];
    up_slot_t slots[UP_MAX];
} upstream_t;

static void up_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    (void)events;
    up_slot_t *slot = userdata;
    up_conn_t *c = &slot->up->conns[slot->idx];
    for (;;) {
        if (c->in_len >= UP_CAP) {
            return;
        }
        ssize_t n = read(c->fd, c->in + c->in_len, UP_CAP - c->in_len);
        if (n > 0) {
            c->in_len += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return;
    }
}

static void up_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    upstream_t *up = userdata;
    if (up->accept_count >= UP_MAX) {
        close(fd);
        return;
    }
    int idx = up->accept_count++;
    up->conns[idx].fd = fd;
    up->slots[idx].up = up;
    up->slots[idx].idx = idx;
    (void)cloak_reactor_add_fd(up->reactor, fd, CLOAK_REACTOR_READABLE, up_on_readable,
                               &up->slots[idx]);
}

static void up_destroy(upstream_t *up) {
    for (int i = 0; i < UP_MAX; i++) {
        if (up->conns[i].fd >= 0) {
            cloak_reactor_remove_fd(up->reactor, up->conns[i].fd);
            close(up->conns[i].fd);
            up->conns[i].fd = -1;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Database scaffolding                                                 */
/* ------------------------------------------------------------------ */

static void tmp_path(char *buf, size_t cap, const char *tag) {
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(buf, cap, "%s/cloak_dws_%ld_%s.db", dir, (long)getpid(), tag);
}

/* WAL leaves sidecars; a survivor would carry committed credit from a
 * previous run into this one. */
static void db_unlink(const char *path) {
    char aux[512];
    unlink(path);
    snprintf(aux, sizeof(aux), "%s-wal", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-shm", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-journal", path);
    unlink(aux);
}

/* The manager's and the panel's clock. Deliberately NOT the wall clock
 * the handshake is timestamped against: expiry is a database property
 * and wants a fixed "now" so that "expired" and "not expired" are never
 * one CI-scheduling hiccup apart. */
#define T_NOW 1600000000
#define T_EXPIRY (T_NOW + 100000)
#define START_CREDIT 10000000

static int64_t db_now(void *userdata) {
    (void)userdata;
    return (int64_t)T_NOW;
}

static void mk_uid(uint8_t *uid, uint8_t seed) {
    memset(uid, 0xA0, CLOAK_UID_LEN);
    uid[0] = seed;
}

static void put_user(cloak_usermanager_t *m, const uint8_t *uid, int32_t cap) {
    cloak_user_info_t u;
    memset(&u, 0, sizeof(u));
    memcpy(u.uid, uid, CLOAK_UID_LEN);
    u.sessions_cap = cap;
    u.up_credit = START_CREDIT;
    u.down_credit = START_CREDIT;
    u.expiry_time = T_EXPIRY;
    ASSERT_EQ_INT(0, cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL));
}

/* ------------------------------------------------------------------ */
/* The fixture                                                          */
/* ------------------------------------------------------------------ */

struct fixture {
    cloak_reactor_t *reactor;

    cover_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;

    upstream_t up;
    cloak_listener_t up_listener;
    int have_up_listener;
    int up_port;

    char db_path[512];
    cloak_usermanager_t *mgr;

    cloak_server_config_t cfg;
    cloak_server_t srv;
    int srv_ready;

    cloak_server_registry_t registry;
    int registry_ready;

    cloak_userpanel_t *panel;

    cloak_proxy_t proxy;
    int proxy_ready;

    cloak_dispatcher_t d;
    int d_ready;

    cloak_listener_t front;
    int have_front;

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_ok[CLOAK_UID_LEN];  /* in the database, metered */
    uint8_t uid_bad[CLOAK_UID_LEN]; /* in no database and no bypass list */

    /* Counts cloak_dispatch_session_aborted_cb firings. A PROBE, and the
     * only evidence available after the fact that a session was created
     * and then unwound -- the unwind is clean, so nothing else it
     * touched is still visible once it has run. See
     * test_panel_is_untouched_by_a_malformed_upgrade for why "the panel
     * shows nothing afterwards" is NOT on its own a test of the
     * validation order. */
    int aborted_calls;
};

/* Counts, then does exactly what the dispatcher would have called
 * directly. Wrapping rather than replacing: the proxy's context for an
 * abandoned session must still be reclaimed, and a test that dropped
 * that to get a counter would be testing a configuration no binary will
 * ever run. */
static void fx_session_aborted(cloak_dispatcher_t *d, const uint8_t uid[CLOAK_UID_LEN],
                               uint32_t session_id, void *userdata) {
    struct fixture *fx = userdata;
    fx->aborted_calls++;
    cloak_proxy_session_aborted(d, uid, session_id, &fx->proxy);
}

static void fx_session_closing(const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    cloak_proxy_session_aborted(NULL, uid, session_id, userdata);
}

static int fixture_init(struct fixture *fx) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    for (int i = 0; i < UP_MAX; i++) {
        fx->up.conns[i].fd = -1;
    }
    for (int i = 0; i < COVER_MAX_LIVE; i++) {
        fx->cover.fds[i] = -1;
    }

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

    fx->cover.reactor = fx->reactor;
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->cover_listener, fx->reactor, "127.0.0.1:0",
                                         cover_on_accept, &fx->cover, err, sizeof(err)));
    fx->have_cover_listener = 1;
    int cover_port = cloak_listener_port(&fx->cover_listener);
    ASSERT_TRUE(cover_port > 0);

    fx->up.reactor = fx->reactor;
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->up_listener, fx->reactor, "127.0.0.1:0",
                                         up_on_accept, &fx->up, err, sizeof(err)));
    fx->have_up_listener = 1;
    fx->up_port = cloak_listener_port(&fx->up_listener);
    ASSERT_TRUE(fx->up_port > 0);

    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(fx->server_priv, fx->server_pub));
    mk_uid(fx->uid_ok, 0x21);
    mk_uid(fx->uid_bad, 0x99);

    char priv_b64[64];
    ASSERT_EQ_INT(0, cloak_base64_encode(fx->server_priv, CLOAK_X25519_KEY_LEN, priv_b64,
                                         sizeof(priv_b64)));

    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\"127.0.0.1:0\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\"}",
             fx->up_port, cover_port, priv_b64);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    tmp_path(fx->db_path, sizeof(fx->db_path), "disp");
    db_unlink(fx->db_path);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_usermanager_open(&fx->mgr, fx->db_path, db_now, NULL, err, sizeof(err)));
    ASSERT_TRUE(fx->mgr != NULL);
    if (fx->mgr == NULL) {
        return -1;
    }
    put_user(fx->mgr, fx->uid_ok, 10);

    ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor,
                                                cloak_proxy_registry_broken, &fx->proxy));
    fx->registry_ready = 1;

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = fx->mgr;
    pcfg.registry = &fx->registry;
    pcfg.reactor = fx->reactor;
    pcfg.upload_interval_ms = 3600000; /* nothing here wants the cycle to fire on its own */
    pcfg.now_fn = db_now;
    pcfg.on_session_closing = fx_session_closing;
    pcfg.on_session_closing_userdata = &fx->proxy;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&fx->panel, &pcfg));
    ASSERT_TRUE(fx->panel != NULL);
    if (fx->panel == NULL) {
        return -1;
    }

    cloak_proxy_config_t pxcfg;
    memset(&pxcfg, 0, sizeof(pxcfg));
    pxcfg.reactor = fx->reactor;
    pxcfg.srv = &fx->srv;
    pxcfg.chain = cloak_userpanel_registry_broken;
    pxcfg.chain_userdata = fx->panel;
    ASSERT_EQ_INT(0, cloak_proxy_init(&fx->proxy, &pxcfg));
    fx->proxy_ready = 1;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.registry = &fx->registry;
    dcfg.panel = fx->panel;
    dcfg.session_config_template.max_on_wire_size = 16401;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = 262144;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;
    dcfg.prepare_session = cloak_proxy_prepare_session;
    dcfg.prepare_session_userdata = &fx->proxy;
    dcfg.session_aborted = fx_session_aborted; /* counts, then forwards */
    dcfg.session_aborted_userdata = fx;
    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, fx->cfg.bind_addr[0],
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;
    return 0;
}

static void fixture_destroy(struct fixture *fx) {
    if (fx->have_front) {
        cloak_listener_close(&fx->front);
        fx->have_front = 0;
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
    if (fx->panel != NULL) {
        cloak_userpanel_close(fx->panel);
        fx->panel = NULL;
    }
    if (fx->mgr != NULL) {
        cloak_usermanager_close(fx->mgr);
        fx->mgr = NULL;
    }
    if (fx->srv_ready) {
        cloak_server_destroy(&fx->srv);
        fx->srv_ready = 0;
    }
    if (fx->have_up_listener) {
        cloak_listener_close(&fx->up_listener);
        fx->have_up_listener = 0;
    }
    up_destroy(&fx->up);
    if (fx->have_cover_listener) {
        cloak_listener_close(&fx->cover_listener);
        fx->have_cover_listener = 0;
    }
    cover_destroy(&fx->cover);
    if (fx->db_path[0] != '\0') {
        db_unlink(fx->db_path);
    }
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
        fx->reactor = NULL;
    }
}

static int front_port(struct fixture *fx) {
    return cloak_listener_port(&fx->front);
}

/* ------------------------------------------------------------------ */
/* Client plumbing                                                      */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Building a real CDN upgrade request                                  */
/* ------------------------------------------------------------------ */

/* THE `Hidden` PAYLOAD IS A REAL CLOAK HANDSHAKE, built from the same
 * primitives the direct path uses: an ephemeral X25519 keypair, the ECDH
 * shared secret against the server's public key, and AES-256-GCM over the
 * 48-byte authentication payload with the ephemeral public key's first
 * twelve bytes as the nonce.
 *
 * Go's own split (internal/server/websocket.go:76-99, unmarshalHidden):
 * hidden[0:32] is randPubKey -- which is both the ECDH input AND the
 * value the replay cache registers -- and hidden[32:96] is the 64-byte
 * ciphertext+tag. The server then feeds exactly those to the SAME
 * decryption the TLS path uses, where the 64 bytes arrive as the
 * ClientHello's session_id and key_share fields concatenated
 * (auth.go:37). So the two transports differ in where the bytes were
 * carried and in nothing else, which is why this helper produces the
 * same 48-byte payload layout cloak/server_auth.h documents. */

/* The 48-byte decrypted-payload layout server_auth.h documents byte for
 * byte: [0:16) UID, [16:28) NUL-padded proxy method, [28] encryption
 * method, [29:37) big-endian Unix timestamp, [37:41) big-endian session
 * id, [41] flags, [42:48) reserved. */
static void build_auth_payload(uint8_t out[48], const uint8_t uid[CLOAK_UID_LEN],
                               const char *proxy_method, uint8_t encryption_method,
                               int64_t timestamp, uint32_t session_id) {
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
}

/* Writes the 128-character base64 of randPubKey || ciphertextWithTag and
 * the shared secret the reply will be sealed under. */
static void make_hidden(const uint8_t server_pub[CLOAK_X25519_KEY_LEN],
                        const uint8_t uid[CLOAK_UID_LEN], const char *proxy_method,
                        uint32_t session_id, char out_b64[CLOAK_WS_HS_HIDDEN_B64_LEN + 1],
                        uint8_t out_shared[CLOAK_AEAD_KEY_LEN]) {
    uint8_t eph_priv[CLOAK_X25519_KEY_LEN];
    uint8_t eph_pub[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(eph_priv, eph_pub));
    ASSERT_EQ_INT(0, cloak_x25519_shared_secret(eph_priv, server_pub, out_shared));

    uint8_t payload[48];
    build_auth_payload(payload, uid, proxy_method, (uint8_t)CLOAK_AEAD_AES_256_GCM,
                       (int64_t)time(NULL), session_id);

    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    memcpy(nonce, eph_pub, CLOAK_AEAD_NONCE_LEN);

    uint8_t hidden[CLOAK_WS_HS_HIDDEN_LEN];
    memcpy(hidden, eph_pub, 32);
    size_t ct_len = 0;
    ASSERT_EQ_INT(0, cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, out_shared, nonce, NULL, 0, payload,
                                     sizeof(payload), hidden + 32, &ct_len));
    ASSERT_EQ_INT(64, (int)ct_len);
    ASSERT_EQ_INT(0, cloak_base64_encode(hidden, sizeof(hidden), out_b64,
                                         CLOAK_WS_HS_HIDDEN_B64_LEN + 1));
}

/* KEY_GO is the `Sec-WebSocket-Key` a real gorilla client emitted; the
 * accept beside it is what a real gorilla Upgrader{} answered with. Both
 * are captured literals, not recomputed here -- test_ws_handshake.c is
 * where the accept computation itself is pinned. */
#define KEY_GO "Q6fJUvdRNbjAgU3LVM25sg=="
#define ACCEPT_GO "fmxopr2FgzOlKg8nTOunDaBh4TU="

typedef struct {
    const char *request_line; /* default: "GET /ws/path HTTP/1.1" */
    const char *hidden_name;  /* default "Hidden" */
    const char *hidden;       /* required unless hidden_name is omitted via NULL */
    const char *conn;         /* default "Upgrade" */
    const char *key;          /* default KEY_GO */
    const char *version;      /* default "13" */
    const char *upgrade;      /* default "websocket" */
    /* `Origin`, omitted when NULL -- which is what a real Cloak client
     * sends, since it is not a browser. Present so that a CDN-injected
     * cross-site Origin can be driven through the whole dispatcher: this
     * port never reads the header, gorilla's default CheckOrigin refuses
     * it with a 403, and that 403 is trigger 3 of the Go wedge described
     * at the top of this file. See cloak/ws_handshake.h's `Origin`
     * paragraph and test_cross_origin_upgrade_is_accepted below. */
    const char *origin;
    size_t pad;               /* bytes of X-Pad value to append, 0 for none */
    /* Rewrite every line ending except the terminating CRLFCRLF as a
     * bare LF. Go's net/http accepts such a request and answers 101
     * (measured); cloak_ws_handshake_parse deliberately refuses it as
     * CLOAK_WS_HS_ERR_MALFORMED -- see test_ws_handshake.c's own
     * test_bare_lf_line_endings_are_refused, and the arm below that
     * exists because of it. The terminator itself stays CRLF because
     * cloak_firstpacket_t frames on CRLFCRLF: a request with no CRLFCRLF
     * anywhere never completes its first packet at all and is dropped on
     * the handshake deadline rather than redirected, which is a
     * different outcome and a different test. */
    int bare_lf;
} ws_req_t;

static void app(char *buf, size_t cap, size_t *n, const char *s) {
    size_t l = strlen(s);
    ASSERT_TRUE(*n + l + 1 <= cap);
    if (*n + l + 1 > cap) {
        return;
    }
    memcpy(buf + *n, s, l);
    *n += l;
    buf[*n] = '\0';
}

static void app_hdr(char *buf, size_t cap, size_t *n, const char *name, const char *val) {
    if (val == NULL) {
        return;
    }
    app(buf, cap, n, name);
    app(buf, cap, n, ": ");
    app(buf, cap, n, val);
    app(buf, cap, n, "\r\n");
}

/* Go's own header order (net/http's sorted-key order for everything
 * Cloak sets), reproduced so a passing test here means the dispatcher
 * agrees with what a real client sends rather than with this file. */
static size_t build_ws_request(char *buf, size_t cap, ws_req_t r) {
    size_t n = 0;
    buf[0] = '\0';
    app(buf, cap, &n, r.request_line != NULL ? r.request_line : "GET /ws/path HTTP/1.1");
    app(buf, cap, &n, "\r\n");
    app_hdr(buf, cap, &n, "Host", "cdn.example.com:443");
    app(buf, cap, &n, "User-Agent: Go-http-client/1.1\r\n");
    app_hdr(buf, cap, &n, "Connection", r.conn != NULL ? r.conn : "Upgrade");
    app_hdr(buf, cap, &n, "Origin", r.origin); /* omitted when NULL */
    app_hdr(buf, cap, &n, r.hidden_name != NULL ? r.hidden_name : "Hidden", r.hidden);
    app_hdr(buf, cap, &n, "Sec-WebSocket-Key", r.key != NULL ? r.key : KEY_GO);
    app_hdr(buf, cap, &n, "Sec-WebSocket-Version", r.version != NULL ? r.version : "13");
    app_hdr(buf, cap, &n, "Upgrade", r.upgrade != NULL ? r.upgrade : "websocket");
    if (r.pad > 0) {
        app(buf, cap, &n, "X-Pad: ");
        ASSERT_TRUE(n + r.pad + 3 <= cap);
        for (size_t i = 0; i < r.pad; i++) {
            buf[n++] = 'a';
        }
        buf[n] = '\0';
        app(buf, cap, &n, "\r\n");
    }
    app(buf, cap, &n, "\r\n");

    if (r.bare_lf && n >= 4) {
        /* Everything before the final CRLFCRLF loses its CR; the
         * terminator keeps both, so cloak_firstpacket_t still frames the
         * request and the parser is the thing that refuses it. */
        size_t keep = n - 4;
        size_t o = 0;
        for (size_t i = 0; i < keep; i++) {
            if (buf[i] == '\r' && i + 1 < keep && buf[i + 1] == '\n') {
                continue;
            }
            buf[o++] = buf[i];
        }
        memcpy(buf + o, "\r\n\r\n", 4);
        n = o + 4;
        buf[n] = '\0';
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Reading what the server answered                                     */
/* ------------------------------------------------------------------ */

/* The 101 response is fixed at CLOAK_WS_HS_101_LEN bytes and the frame
 * that follows it is fixed at 62, so the whole CDN reply is exactly this
 * many bytes and a reader never has to guess. */
#define WS_REPLY_TOTAL (CLOAK_WS_HS_101_LEN + 2 + 60)

typedef struct {
    cloak_reactor_t *r;
    int fd;
    uint8_t buf[512];
    size_t len;
    size_t want;
    /* The size of the FIRST recv that returned anything. The reply is
     * composed into one buffer and written with one send(), so on
     * loopback with the peer not yet reading, the first recv sees all of
     * it -- which is the only externally observable evidence that the
     * 101 and the frame were not two writes. */
    size_t first_chunk;
} reader_t;

static int reader_has(void *ctx) {
    reader_t *rd = ctx;
    if (rd->len >= rd->want) {
        return 1;
    }
    ssize_t n = recv(rd->fd, rd->buf + rd->len, sizeof(rd->buf) - rd->len, MSG_DONTWAIT);
    if (n > 0) {
        if (rd->first_chunk == 0) {
            rd->first_chunk = (size_t)n;
        }
        rd->len += (size_t)n;
    }
    return rd->len >= rd->want;
}

/* Recovers the session key from the flat CDN reply:
 * frame[0:2] header, then [12-byte nonce][48-byte sealed session key]. */
static int ws_reply_session_key(const uint8_t *reply, size_t reply_len,
                                const uint8_t shared_secret[CLOAK_AEAD_KEY_LEN],
                                uint8_t out_key[CLOAK_AEAD_KEY_LEN]) {
    if (reply_len < WS_REPLY_TOTAL) {
        return -1;
    }
    const uint8_t *payload = reply + CLOAK_WS_HS_101_LEN + 2;
    uint8_t out[CLOAK_AEAD_KEY_LEN];
    size_t out_len = 0;
    if (cloak_aead_open(CLOAK_AEAD_AES_256_GCM, shared_secret, payload, NULL, 0, payload + 12, 48,
                        out, &out_len) != 0) {
        return -1;
    }
    if (out_len != CLOAK_AEAD_KEY_LEN) {
        return -1;
    }
    memcpy(out_key, out, CLOAK_AEAD_KEY_LEN);
    return 0;
}

/* Drives one complete CDN upgrade and returns the connected fd (still
 * owned by the caller) with the reply in *out_rd. */
static int ws_handshake_origin(struct fixture *fx, const uint8_t uid[CLOAK_UID_LEN],
                               const char *proxy_method, uint32_t session_id, const char *origin,
                               reader_t *out_rd, uint8_t out_shared[CLOAK_AEAD_KEY_LEN]) {
    char hidden[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
    make_hidden(fx->server_pub, uid, proxy_method, session_id, hidden, out_shared);

    char req[4096];
    ws_req_t r = {0};
    r.hidden = hidden;
    r.origin = origin;
    size_t req_len = build_ws_request(req, sizeof(req), r);

    int fd = client_connect(front_port(fx));
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return -1;
    }
    ASSERT_EQ_INT((int)req_len, (int)write(fd, req, req_len));

    memset(out_rd, 0, sizeof(*out_rd));
    out_rd->r = fx->reactor;
    out_rd->fd = fd;
    out_rd->want = WS_REPLY_TOTAL;
    ASSERT_TRUE(pump_until(fx->reactor, reader_has, out_rd, WS_PUMP_BUDGET_MS, 1));
    return fd;
}

/* The ordinary case: no `Origin` at all, which is what Cloak's own client
 * sends. */
static int ws_handshake(struct fixture *fx, const uint8_t uid[CLOAK_UID_LEN],
                        const char *proxy_method, uint32_t session_id, reader_t *out_rd,
                        uint8_t out_shared[CLOAK_AEAD_KEY_LEN]) {
    return ws_handshake_origin(fx, uid, proxy_method, session_id, NULL, out_rd, out_shared);
}

/* ------------------------------------------------------------------ */
/* 1. A full CDN upgrade reaches an established session                 */
/* ------------------------------------------------------------------ */

/* THE CLIENT SIDE IS A REAL cloak_session_t IN WS_CLIENT FRAMING, and
 * that is what makes this test able to see the one mutation a
 * key-recovery assertion cannot: a dispatcher that handed the socket to
 * cloak_session_add_conn (TLS records) instead of
 * cloak_session_add_conn_framed(..., CLOAK_CONN_FRAMING_WS_SERVER). Both
 * ends agreeing is invisible; here the two ends are chosen
 * independently, so a mismatch is a session over which no byte ever
 * arrives. */
typedef struct {
    cloak_session_t sesh;
    int sesh_ready;
    int broken;
} ws_client_t;

static void ws_client_on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    ws_client_t *cs = userdata;
    cs->broken = 1;
}

typedef struct {
    upstream_t *up;
    int idx;
    size_t want;
} up_wait_t;

static int up_has_len(void *ctx) {
    up_wait_t *w = ctx;
    return w->up->accept_count > w->idx && w->up->conns[w->idx].in_len >= w->want;
}

static void test_cdn_upgrade_establishes_a_session(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    reader_t rd;
    int fd = ws_handshake(&fx, fx.uid_ok, "ss", 7001, &rd, shared);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        fixture_destroy(&fx);
        return;
    }

    /* The reply, byte for byte where it is fixed. */
    ASSERT_EQ_INT(WS_REPLY_TOTAL, (int)rd.len);
    ASSERT_MEM_EQ(rd.buf, "HTTP/1.1 101 Switching Protocols\r\n", 34);
    /* The accept is computed over the key RECEIVED, and this request
     * carried gorilla's own key, so this is gorilla's own answer. */
    {
        static const char want[] = "Sec-WebSocket-Accept: " ACCEPT_GO "\r\n";
        int found = 0;
        for (size_t i = 0; i + sizeof(want) - 1 <= CLOAK_WS_HS_101_LEN; i++) {
            if (memcmp(rd.buf + i, want, sizeof(want) - 1) == 0) {
                found = 1;
                break;
            }
        }
        ASSERT_TRUE(found);
    }

    /* The key the client recovers is the key the session actually holds
     * -- read back out of the registry, not merely "a key that
     * decrypted". */
    uint8_t recovered[CLOAK_AEAD_KEY_LEN];
    ASSERT_EQ_INT(0, ws_reply_session_key(rd.buf, rd.len, shared, recovered));

    cloak_session_t *sesh = cloak_server_registry_find(&fx.registry, fx.uid_ok, 7001);
    ASSERT_TRUE(sesh != NULL);
    if (sesh == NULL) {
        close(fd);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_MEM_EQ(sesh->obfuscator.session_key, recovered, CLOAK_AEAD_KEY_LEN);

    /* The panel made the user active, exactly once. */
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(fx.panel));
    ASSERT_TRUE(cloak_userpanel_find(fx.panel, fx.uid_ok) != NULL);

    /* And now the framing itself: a client session in WS_CLIENT mode
     * over the same socket must be able to move a byte to the upstream. */
    ws_client_t cs;
    memset(&cs, 0, sizeof(cs));
    cloak_session_config_t ccfg;
    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.max_on_wire_size = 16401;
    ccfg.stream_recv_capacity = 65536;
    ccfg.stream_max_pending_frames = 64;
    ccfg.conn_send_queue_cap = 262144;
    ccfg.inactivity_timeout_ms = 60000;
    ccfg.obfuscator.method = CLOAK_AEAD_AES_256_GCM;
    memcpy(ccfg.obfuscator.session_key, recovered, CLOAK_AEAD_KEY_LEN);
    ccfg.on_broken = ws_client_on_broken;
    ccfg.on_broken_userdata = &cs;

    ASSERT_EQ_INT(0, cloak_session_init(&cs.sesh, 7001, fx.reactor, &ccfg));
    cs.sesh_ready = 1;
    ASSERT_EQ_INT(0, cloak_session_add_conn_framed(&cs.sesh, fd, CLOAK_CONN_FRAMING_WS_CLIENT));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st != NULL) {
        ASSERT_EQ_INT(4, (int)cloak_stream_write(st, (const uint8_t *)"ping", 4));
        up_wait_t uw = {&fx.up, 0, 4};
        ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, WS_PUMP_BUDGET_MS, 1));
        ASSERT_EQ_INT(4, (int)fx.up.conns[0].in_len);
        ASSERT_MEM_EQ(fx.up.conns[0].in, "ping", 4);
    }

    if (cs.sesh_ready) {
        cloak_session_destroy(&cs.sesh);
    }
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 2. The reply is ONE coalesced write                                  */
/* ------------------------------------------------------------------ */

static void test_reply_is_one_flat_write(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    reader_t rd;
    int fd = ws_handshake(&fx, fx.uid_ok, "ss", 7002, &rd, shared);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        fixture_destroy(&fx);
        return;
    }

    /* 129 + 62. The literals are here on purpose: a test that wrote
     * CLOAK_WS_HS_101_LEN + 2 + 60 would follow the implementation
     * wherever it went. */
    ASSERT_EQ_INT(191, (int)rd.len);
    ASSERT_EQ_INT(129, CLOAK_WS_HS_101_LEN);
    /* One send() of 191 bytes onto a loopback socket whose peer has not
     * read yet arrives as one recv. */
    ASSERT_EQ_INT(191, (int)rd.first_chunk);

    /* The frame header: FIN + binary opcode, unmasked, 60-byte payload
     * in the inline length form. Not 0x82 0xFE (an extended length a
     * server that padded would emit), not 0x02 (FIN clear), not a mask
     * bit. */
    ASSERT_EQ_INT(0x82, rd.buf[129]);
    ASSERT_EQ_INT(0x3C, rd.buf[130]);

    /* Nothing follows it: the server has not spoken again. */
    uint8_t extra[8];
    ssize_t more = recv(fd, extra, sizeof(extra), MSG_DONTWAIT);
    ASSERT_TRUE(more < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));

    close(fd);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 2b. The reply nonce is fresh per connection                          */
/* ------------------------------------------------------------------ */

/* NONCE REUSE UNDER THE SAME KEY BREAKS AES-GCM OUTRIGHT, and on this
 * path the key is the ECDH shared secret -- which is per connection, so
 * a repeated nonce is only catastrophic if the same client reconnects
 * with the same ephemeral key. That is not a scenario this port can rule
 * out (a client bug, a bad RNG on a router), and the cost of being right
 * is one call to cloak_random_bytes. The reason this test exists at all
 * is that NOTHING ELSE IN THIS FILE CAN SEE A FIXED NONCE: a reply
 * sealed under a constant nonce decrypts perfectly, so every
 * key-recovery assertion passes against it. */
static void test_reply_nonce_is_fresh_per_connection(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    uint8_t nonces[2][CLOAK_AEAD_NONCE_LEN];
    uint8_t sealed[2][48];
    int fds[2] = {-1, -1};
    for (int i = 0; i < 2; i++) {
        uint8_t shared[CLOAK_AEAD_KEY_LEN];
        reader_t rd;
        fds[i] = ws_handshake(&fx, fx.uid_ok, "ss", (uint32_t)(7010 + i), &rd, shared);
        ASSERT_TRUE(fds[i] >= 0);
        ASSERT_EQ_INT(WS_REPLY_TOTAL, (int)rd.len);
        if (rd.len < WS_REPLY_TOTAL) {
            break;
        }
        memcpy(nonces[i], rd.buf + CLOAK_WS_HS_101_LEN + 2, CLOAK_AEAD_NONCE_LEN);
        memcpy(sealed[i], rd.buf + CLOAK_WS_HS_101_LEN + 2 + CLOAK_AEAD_NONCE_LEN, 48);
    }
    ASSERT_MEM_NE(nonces[0], nonces[1], CLOAK_AEAD_NONCE_LEN);
    ASSERT_MEM_NE(sealed[0], sealed[1], 48);

    for (int i = 0; i < 2; i++) {
        if (fds[i] >= 0) {
            close(fds[i]);
        }
    }
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 2c. A replayed CDN first packet is refused                           */
/* ------------------------------------------------------------------ */

/* Go registers the SAME randPubKey for both transports -- AuthFirstPacket
 * calls sta.registerRandom(fragments.randPubKey) after
 * processFirstPacket, whichever transport produced the fragments
 * (internal/server/auth.go:74-78) -- so the CDN path is replay-protected
 * exactly like the TLS one. That is invisible to every other test here,
 * because a first-time handshake and a replayed one differ in nothing
 * but whether the cache already holds those 32 bytes.
 *
 * The SAME REQUEST BYTES, twice, on two connections: the second must
 * reach the cover site. */
static void test_replayed_cdn_request_is_refused(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    char hidden[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    make_hidden(fx.server_pub, fx.uid_ok, "ss", 7020, hidden, shared);
    char req[4096];
    ws_req_t r = {0};
    r.hidden = hidden;
    size_t req_len = build_ws_request(req, sizeof(req), r);

    /* First: a real session. */
    int fd1 = client_connect(front_port(&fx));
    ASSERT_TRUE(fd1 >= 0);
    if (fd1 < 0) {
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT((int)req_len, (int)write(fd1, req, req_len));
    reader_t rd1;
    memset(&rd1, 0, sizeof(rd1));
    rd1.r = fx.reactor;
    rd1.fd = fd1;
    rd1.want = WS_REPLY_TOTAL;
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rd1, WS_PUMP_BUDGET_MS, 1));
    ASSERT_EQ_INT(WS_REPLY_TOTAL, (int)rd1.len);

    /* Second, byte for byte: the cover site, not a second reply. */
    int fd2 = client_connect(front_port(&fx));
    ASSERT_TRUE(fd2 >= 0);
    if (fd2 >= 0) {
        ASSERT_EQ_INT((int)req_len, (int)write(fd2, req, req_len));
        reader_t rd2;
        memset(&rd2, 0, sizeof(rd2));
        rd2.r = fx.reactor;
        rd2.fd = fd2;
        rd2.want = COVER_BANNER_LEN;
        ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rd2, WS_PUMP_BUDGET_MS, 1));
        ASSERT_EQ_INT(COVER_BANNER_LEN, (int)rd2.len);
        ASSERT_MEM_EQ(COVER_BANNER, rd2.buf, COVER_BANNER_LEN);
        close(fd2);
    }

    close(fd1);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 3. The ordering: refusals with one observable outcome                */
/* ------------------------------------------------------------------ */

/* RULING 2, AND WHAT IT REPLACED. The brief asked for "the same modulo
 * the cover site's own variability", which cannot fail and is therefore
 * not a test. What is asserted instead is two falsifiable claims:
 *
 *   (a) BYTE-STREAM EQUALITY. For identical cover-site input -- the
 *       fixed banner, written at accept -- every rejection path produces
 *       byte-identical output at the client, and nothing after it, on
 *       every sample rather than on the first. The positive control is
 *       the successful upgrade in case 1, whose first byte already
 *       differs, so the assertion demonstrably can fail.
 *
 *   (b) A MEASURED TIMING BRACKET. The spread between the four step-1
 *       medians over WS_TIMING_RUNS samples -- and the same spread over
 *       the four MINIMA -- is below WS_TIMING_BOUND_US, a literal
 *       justified by the measurement recorded beside it rather than by
 *       taste.
 *
 * WHAT (b) IS NOT, and this is worth being exact about because an
 * earlier revision of this file over-claimed it: the bracket is a bound
 * on how different these refusals may look, not the detector for a
 * wrongly ordered validation. It cannot see a same-bytes branch costing
 * under about 600 us (measured, by this commit's reviewer, with a
 * deliberately delayed arm), and the ratio that COULD see one flaked on
 * an unmutated tree -- see WS_TIMING_BOUND_US. The ordering is caught by
 * two clock-free assertions instead: the session_aborted counter in
 * case 4 and the replay-cache check in case 4b.
 *
 * EVERY ARM IS THE SAME LENGTH, to the byte. That is load-bearing: the
 * WebSocket first-packet path reads one byte at a time, so a shorter
 * request would be faster for a reason that has nothing to do with which
 * check refused it, and the bracket would be measuring request length. */

/* The arms, each built to the same total length:
 *   - BAD_HIDDEN:   a valid upgrade whose `Hidden` is not base64 of 96
 *                   bytes (one character replaced). Refused by the parse.
 *   - BAD_UPGRADE:  a valid `Hidden` for an AUTHORISED UID -- the one
 *                   arm that would authorise a user if the ordering were
 *                   wrong -- with `Connection: keep-alive`.
 *   - NOT_CLOAK:    a plain HTTP GET with no `Hidden` at all, padded to
 *                   the same length. This is the "unrecognised protocol"
 *                   arm and it is also the shape a real prober sends.
 *   - BARE_LF:      a valid upgrade for an AUTHORISED UID whose line
 *                   endings are bare LFs. This is the ONE input class
 *                   that separates CLOAK_WS_HS_ERR_MALFORMED from
 *                   CLOAK_WS_HS_ERR_BAD_HIDDEN, and it is here because
 *                   Task 3's deliberate strictness about line endings --
 *                   Go answers 101 to this request, measured; this
 *                   parser refuses it -- was waived ON THE CONDITION
 *                   that nothing downstream branches on WHICH code the
 *                   parser returned. If the dispatcher ever did, a
 *                   prober could tell a Cloak origin from a plain web
 *                   server by sending exactly this, and a strictness
 *                   that is harmless today would become a live
 *                   fingerprint. The condition is asserted here rather
 *                   than trusted: this arm's bytes must be
 *                   indistinguishable from BAD_HIDDEN's.
 *   - UNAUTHORISED: a PERFECT upgrade whose `Hidden` decrypts cleanly
 *                   for a UID this server has never heard of. It is
 *                   refused at step 6, not step 1, which makes it the arm
 *                   that actually costs something: the replay check, the
 *                   X25519 shared secret, the AES-GCM open and the user
 *                   lookup all run before it is turned away. Including it
 *                   is what turns the timing bracket from "three cheap
 *                   refusals resemble each other" into a bound on the
 *                   thing a prober would actually try to measure -- and
 *                   it calibrates the bound, since the work the WRONG
 *                   validation order would add to the BAD_UPGRADE arm is
 *                   a subset of the work this arm already does. */
typedef enum {
    ARM_BAD_HIDDEN = 0,
    ARM_BAD_UPGRADE = 1,
    ARM_NOT_CLOAK = 2,
    ARM_BARE_LF = 3,
    ARM_UNAUTHORISED = 4
} arm_t;
#define ARM_COUNT 5
/* The arms refused at step 1, i.e. before any UID is authorised. The
 * timing bracket is taken over exactly these; ARM_UNAUTHORISED is
 * refused at step 6 and is reported separately. */
#define ARM_STEP1_COUNT 4

/* The length every arm is padded to. Above the longest unpadded arm
 * (338) with room for the X-Pad header itself, and comfortably inside
 * CLOAK_FIRSTPACKET_MAX. */
#define ARM_TOTAL_BYTES 512

static size_t build_arm(struct fixture *fx, arm_t arm, char *buf, size_t cap) {
    char hidden[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    make_hidden(fx->server_pub, arm == ARM_UNAUTHORISED ? fx->uid_bad : fx->uid_ok, "ss", 9001,
                hidden, shared);

    ws_req_t r = {0};
    switch (arm) {
    case ARM_UNAUTHORISED:
        r.hidden = hidden;
        break;
    case ARM_BAD_HIDDEN:
        /* '(' is outside the standard base64 alphabet, so this value is
         * refused before any key is derived -- and the string is still
         * 128 characters, so the request length does not move. */
        hidden[10] = '(';
        r.hidden = hidden;
        break;
    case ARM_BAD_UPGRADE:
        r.hidden = hidden;
        r.conn = "keep-alive";
        break;
    case ARM_NOT_CLOAK:
        r.hidden = NULL; /* omitted entirely */
        break;
    case ARM_BARE_LF:
        r.hidden = hidden;
        r.bare_lf = 1;
        break;
    }
    size_t n = build_ws_request(buf, cap, r);

    /* EVERY ARM IS PADDED TO THE SAME TOTAL LENGTH, and it is asserted
     * rather than assumed. The arms differ by 141 bytes unpadded
     * ("Hidden: <128 chars>\r\n" is 138, and "Upgrade" against
     * "keep-alive" is another 3), so a fixed target comfortably above
     * the longest is what makes all three the same size. "X-Pad: " +
     * value + CRLF is 9 + value, hence the arithmetic below. */
    /* The X-Pad header costs a fixed overhead plus one byte per pad
     * character -- 9 with CRLF line endings, 8 with bare LF. MEASURED
     * rather than tabulated: build once with one pad byte and subtract,
     * so an arm that changes how it terminates its lines cannot silently
     * come out a byte short of the others. */
    char probe[4096];
    ws_req_t r1 = r;
    r1.pad = 1;
    size_t n1 = build_ws_request(probe, sizeof(probe), r1);
    size_t overhead = n1 - n - 1;

    ASSERT_TRUE(n + overhead <= ARM_TOTAL_BYTES);
    if (n + overhead > ARM_TOTAL_BYTES) {
        return n;
    }
    r.pad = ARM_TOTAL_BYTES - n - overhead;
    n = build_ws_request(buf, cap, r);
    ASSERT_EQ_INT(ARM_TOTAL_BYTES, (int)n);
    return n;
}

/* Sends one arm, waits for the cover site's banner, records it and how
 * long it took from the moment the request left. */
typedef struct {
    uint8_t got[256];
    size_t len;
    uint64_t elapsed_us;
} probe_result_t;

static void run_arm(struct fixture *fx, arm_t arm, probe_result_t *out) {
    char req[4096];
    size_t req_len = build_arm(fx, arm, req, sizeof(req));

    memset(out, 0, sizeof(*out));
    int fd = client_connect(front_port(fx));
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return;
    }
    uint64_t t0 = now_us();
    ASSERT_EQ_INT((int)req_len, (int)write(fd, req, req_len));

    reader_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.r = fx->reactor;
    rd.fd = fd;
    rd.want = COVER_BANNER_LEN;
    int ok = pump_until(fx->reactor, reader_has, &rd, WS_PUMP_BUDGET_MS, 0);
    out->elapsed_us = now_us() - t0;
    ASSERT_TRUE(ok);

    memcpy(out->got, rd.buf, rd.len < sizeof(out->got) ? rd.len : sizeof(out->got));
    out->len = rd.len;

    /* Nothing beyond the banner, on any arm: a refusal that also wrote
     * something of its own would be a distinguisher no matter how
     * quickly it arrived. */
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(fx->reactor, 1);
    }
    uint8_t extra[64];
    ssize_t more = recv(fd, extra, sizeof(extra), MSG_DONTWAIT);
    ASSERT_TRUE(more < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));

    close(fd);
    /* Let the relay notice and release its descriptors before the next
     * arm runs -- cover_on_readable recycles the slot on EOF. */
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(fx->reactor, 1);
    }
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/* THE TWO BOUNDS, AND THE MEASUREMENTS THAT JUSTIFY THEM. Everything
 * below was measured in this project's dev image over 24 runs of this
 * test (Debug and ASan+UBSan, 31 samples per arm per run), on a busy
 * machine deliberately -- the noisy runs are the ones that set the
 * numbers, not the clean ones:
 *
 *   spread between the four step-1 refusals' medians:   6..256 us
 *   median of the step-6 refusal, as a fraction of the
 *   BAD_UPGRADE arm's median:                     1.54x..1.79x
 *
 * WS_TIMING_BOUND_US is an ABSOLUTE literal, because "no refusal is
 * grossly slower than another" is an absolute claim: a regression that
 * doubled every arm's cost equally would keep a ratio happy and should
 * not keep this happy. 1000 us is about 4x the worst spread ever
 * observed here, which is the margin this measurement needs -- the
 * absolute latency of the whole probe (connect, one-byte-at-a-time read,
 * dial to the cover site, relay, banner) swings by a factor of four with
 * machine load, and the spread swings with it.
 *
 * THE STEP-6 RATIO BELOW IS MEASURED, PRINTED, AND NOT ASSERTED. It was
 * an assertion (BAD_UPGRADE's median against 0.8x UNAUTHORISED's), and
 * on paper it is the sharpest detector in the file: it would read >= 1.0
 * the moment the upgrade were validated after the UID. In practice it
 * FLAKED ON THE UNMUTATED TREE -- 1 failure in 50 isolated Debug runs
 * here (0.807 against the 0.8 bound), 3 in 50 for this commit's reviewer
 * (0.831, 0.933, 0.954). The reason is structural rather than fixable by
 * widening: the step-6 path's extra work is ~100-130 us, while the
 * probe's own cost -- connect, a 512-byte request read one byte at a
 * time, a TCP dial to the cover site, a relay, a banner -- swings from
 * ~190 us to ~800 us with machine load. The denominator is mostly probe,
 * not path, so a loaded run can eat the whole margin. Widening the bound
 * to cover that would put it past the signal it is meant to detect.
 *
 * SO IT IS A DIAGNOSTIC, AND THAT IS THE RIGHT SHAPE HERE rather than a
 * retreat, for one specific reason: it is REDUNDANT AS A DETECTOR. Go's
 * ordering is caught deterministically, twice over and without a clock,
 * by the session_aborted counter across all five malformed-upgrade arms
 * and by test_refused_upgrade_does_not_burn_the_ephemeral_key. A
 * non-deterministic assertion that adds no detection only adds a way for
 * a green tree to go red, and this project treats a flaky test as a bug
 * rather than as noise to be re-run. The number is still worth having on
 * every run: it is how a future reader sees that the step-6 refusal
 * really does cost more, and by how much, which is the measurement the
 * side-channel note in dispatcher.c's step 6 depends on. */
#define WS_TIMING_RUNS 31
#define WS_TIMING_BOUND_US 1000

static void test_three_refusals_are_indistinguishable(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    uint64_t samples[ARM_COUNT][WS_TIMING_RUNS];
    probe_result_t first[ARM_COUNT];
    memset(first, 0, sizeof(first));

    for (int run = 0; run < WS_TIMING_RUNS; run++) {
        for (int a = 0; a < ARM_COUNT; a++) {
            probe_result_t pr;
            run_arm(&fx, (arm_t)a, &pr);
            samples[a][run] = pr.elapsed_us;
            if (run == 0) {
                first[a] = pr;
            } else {
                /* (a) BYTE-STREAM EQUALITY, checked on every single
                 * sample and not only on the first: a refusal that
                 * differed intermittently is still a distinguisher. */
                ASSERT_EQ_INT((int)first[a].len, (int)pr.len);
                ASSERT_MEM_EQ(first[a].got, pr.got, pr.len);
            }
        }
    }

    /* (a), across the arms. */
    ASSERT_EQ_INT(COVER_BANNER_LEN, (int)first[0].len);
    ASSERT_MEM_EQ(COVER_BANNER, first[0].got, COVER_BANNER_LEN);
    for (int a = 1; a < ARM_COUNT; a++) {
        ASSERT_EQ_INT((int)first[0].len, (int)first[a].len);
        ASSERT_MEM_EQ(first[0].got, first[a].got, first[0].len);
    }

    /* (b) THE TIMING BRACKET. */
    uint64_t med[ARM_COUNT];
    uint64_t fastest[ARM_COUNT];
    for (int a = 0; a < ARM_COUNT; a++) {
        qsort(samples[a], WS_TIMING_RUNS, sizeof(uint64_t), cmp_u64);
        med[a] = samples[a][WS_TIMING_RUNS / 2];
        fastest[a] = samples[a][0];
    }
    /* The bracket is over the FOUR step-1 refusals. The fourth arm is
     * refused at step 6 and is genuinely more expensive -- an X25519
     * shared secret, an AES-GCM open and a SQLite lookup that an
     * unparseable request never reaches -- which this file measures and
     * reports rather than papering over. dispatcher.c's own step-6
     * comment already names that as the one difference a prober could in
     * principle measure, and notes that it is inherent to having a user
     * database at all (Go pays the same cost on the same path). */
    uint64_t lo = med[0], hi = med[0];
    for (int a = 1; a < ARM_STEP1_COUNT; a++) {
        if (med[a] < lo) {
            lo = med[a];
        }
        if (med[a] > hi) {
            hi = med[a];
        }
    }
    fprintf(stderr,
            "[timing] medians us: bad_hidden=%llu bad_upgrade=%llu not_cloak=%llu bare_lf=%llu "
            "unauthorised=%llu spread=%llu bound=%d\n",
            (unsigned long long)med[ARM_BAD_HIDDEN], (unsigned long long)med[ARM_BAD_UPGRADE],
            (unsigned long long)med[ARM_NOT_CLOAK], (unsigned long long)med[ARM_BARE_LF],
            (unsigned long long)med[ARM_UNAUTHORISED], (unsigned long long)(hi - lo),
            WS_TIMING_BOUND_US);
    uint64_t flo = fastest[0], fhi = fastest[0];
    for (int a = 1; a < ARM_STEP1_COUNT; a++) {
        if (fastest[a] < flo) {
            flo = fastest[a];
        }
        if (fastest[a] > fhi) {
            fhi = fastest[a];
        }
    }
    fprintf(stderr, "[timing] fastest us: %llu %llu %llu %llu | %llu  spread=%llu\n",
            (unsigned long long)fastest[0], (unsigned long long)fastest[1],
            (unsigned long long)fastest[2], (unsigned long long)fastest[3],
            (unsigned long long)fastest[4], (unsigned long long)(fhi - flo));
    fprintf(stderr, "[timing] step6 gap us: %lld\n",
            (long long)((int64_t)med[ARM_UNAUTHORISED] - (int64_t)hi));
    ASSERT_TRUE(hi - lo < WS_TIMING_BOUND_US);

    /* THE SAME BRACKET ON THE FASTEST SAMPLE OF EACH ARM, which is both
     * a much sharper instrument and the statistic a prober would
     * actually use -- nobody distinguishes two servers on one probe;
     * they take the best of many. It is also far less sensitive to the
     * machine this test runs on, because a scheduling delay can only
     * ever push a sample UP: measured spread 2..110 us across two dozen
     * runs, Debug and ASan, against the same 1000 us bound. */
    ASSERT_TRUE(fhi - flo < WS_TIMING_BOUND_US);

    /* The bare-LF arm carries the other half of that argument: it is
     * the one input that reaches the parser with MALFORMED rather than
     * BAD_HIDDEN, and its median sits inside the same bracket, so the
     * dispatcher demonstrably does not branch on the failure code. */

    /* The step-6 ratio: recorded, never asserted. See WS_TIMING_BOUND_US's
     * own comment for why a number this informative is still the wrong
     * thing to fail a build on, and which two clock-free assertions do
     * the detecting instead. Typical quiet-run value is 550-650; a run
     * reading 1000 or more would mean BAD_UPGRADE had started paying
     * everything UNAUTHORISED pays, which is Go's ordering -- worth
     * looking at by eye, not worth failing a suite on. */
    fprintf(stderr, "[timing] step6 ratio (bad_upgrade/unauthorised): %llu/1000\n",
            (unsigned long long)(med[ARM_UNAUTHORISED] == 0
                                     ? 0
                                     : med[ARM_BAD_UPGRADE] * 1000u / med[ARM_UNAUTHORISED]));

    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 4. The panel is not touched by a malformed upgrade                   */
/* ------------------------------------------------------------------ */

/* THE ASSERTION IS ON THE PANEL'S OWN COUNTERS. "The connection was
 * redirected" is true for a dozen reasons that have nothing to do with
 * whether a user was made active, and a counter scoped to the wrong
 * object is one of this project's named patterns. So: active_count and
 * the panel's own lookup for this exact UID, before and after.
 *
 * Every arm below carries a `Hidden` that decrypts, for an authorised,
 * metered, in-database UID -- which is what makes this a test of ORDER.
 * If the upgrade were validated after step 6, every one of these would
 * leave an active user behind. */
static void expect_upgrade_refused_without_touching_panel(struct fixture *fx, ws_req_t r,
                                                          const char *what) {
    char hidden[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    make_hidden(fx->server_pub, fx->uid_ok, "ss", 9100, hidden, shared);
    if (r.hidden == NULL && r.hidden_name == NULL) {
        r.hidden = hidden;
    }

    char req[4096];
    size_t req_len = build_ws_request(req, sizeof(req), r);

    size_t before = cloak_userpanel_active_count(fx->panel);
    int aborted_before = fx->aborted_calls;
    int fd = client_connect(front_port(fx));
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return;
    }
    ASSERT_EQ_INT((int)req_len, (int)write(fd, req, req_len));

    reader_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.r = fx->reactor;
    rd.fd = fd;
    rd.want = COVER_BANNER_LEN;
    ASSERT_TRUE(pump_until(fx->reactor, reader_has, &rd, WS_PUMP_BUDGET_MS, 1));

    if (rd.len != COVER_BANNER_LEN || memcmp(rd.buf, COVER_BANNER, COVER_BANNER_LEN) != 0) {
        fprintf(stderr, "FAIL: arm '%s' did not reach the cover site\n", what);
        ASSERT_TRUE(0);
    }

    /* THE POINT. Nothing was made active, nothing was created. */
    if (cloak_userpanel_active_count(fx->panel) != before) {
        fprintf(stderr, "FAIL: arm '%s' changed the panel's active count\n", what);
        ASSERT_TRUE(0);
    }
    if (cloak_userpanel_find(fx->panel, fx->uid_ok) != NULL) {
        fprintf(stderr, "FAIL: arm '%s' made uid_ok active\n", what);
        ASSERT_TRUE(0);
    }
    if (cloak_server_registry_find(&fx->registry, fx->uid_ok, 9100) != NULL) {
        fprintf(stderr, "FAIL: arm '%s' created a session\n", what);
        ASSERT_TRUE(0);
    }
    /* NOT EVEN TRANSIENTLY. The three assertions above look at state
     * AFTER the connection is over, and the dispatcher's own unwind is
     * clean -- a session created at step 8 and abandoned at step 9
     * releases its user and closes its session, leaving the panel and
     * the registry looking exactly as they do here. So on their own they
     * would pass against an implementation that validated the upgrade
     * far too late and then tidied up, which is very nearly what Go
     * does. session_aborted is the one trace that survives: it fires
     * exactly when a session this handshake created is thrown away. */
    if (fx->aborted_calls != aborted_before) {
        fprintf(stderr, "FAIL: arm '%s' created and then unwound a session\n", what);
        ASSERT_TRUE(0);
    }

    close(fd);
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(fx->reactor, 1);
    }
}

static void test_panel_is_untouched_by_a_malformed_upgrade(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(fx.panel));

    /* The three headers a CDN is entitled to rewrite, plus the method --
     * gorilla checks all four AFTER Go has already authorised the UID. */
    ws_req_t no_upgrade_token = {0};
    no_upgrade_token.conn = "keep-alive";
    expect_upgrade_refused_without_touching_panel(&fx, no_upgrade_token, "Connection: keep-alive");

    ws_req_t bad_key = {0};
    bad_key.key = "not-base64-of-16";
    expect_upgrade_refused_without_touching_panel(&fx, bad_key, "malformed Sec-WebSocket-Key");

    ws_req_t bad_version = {0};
    bad_version.version = "12";
    expect_upgrade_refused_without_touching_panel(&fx, bad_version, "Sec-WebSocket-Version: 12");

    ws_req_t not_websocket = {0};
    not_websocket.upgrade = "h2c";
    expect_upgrade_refused_without_touching_panel(&fx, not_websocket, "Upgrade: h2c");

    /* Bare LF: the parser's CLOAK_WS_HS_ERR_MALFORMED rather than one of
     * the upgrade codes, and therefore the case that proves the
     * dispatcher refuses on "not OK" and not on a particular diagnosis.
     * Go answers 101 to this request; this port redirects it, and the
     * waiver for that strictness is exactly the property asserted here
     * and in test_three_refusals_are_indistinguishable. */
    ws_req_t bare_lf = {0};
    bare_lf.bare_lf = 1;
    expect_upgrade_refused_without_touching_panel(&fx, bare_lf, "bare LF line endings");

    /* THE POSITIVE CONTROL. The same UID, the same everything, with a
     * well-formed upgrade -- if this did not make the user active, every
     * assertion above would be vacuous. */
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    reader_t rd;
    int fd = ws_handshake(&fx, fx.uid_ok, "ss", 9101, &rd, shared);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ_INT(WS_REPLY_TOTAL, (int)rd.len);
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(fx.panel));
    ASSERT_TRUE(cloak_userpanel_find(fx.panel, fx.uid_ok) != NULL);
    if (fd >= 0) {
        close(fd);
    }

    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 4b. A refused upgrade does not burn the client's ephemeral key       */
/* ------------------------------------------------------------------ */

/* THE PERMANENT TRACE, and the assertion that pins the validation order
 * without depending on a clock.
 *
 * Step 3 registers the client's randPubKey in the replay cache, and that
 * registration is FOREVER (twelve hours, by
 * CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS). Every other trace a
 * too-late validation leaves behind is cleaned up by the dispatcher's
 * own unwind; this one cannot be, because the whole point of a replay
 * cache is that nothing removes an entry.
 *
 * So: send one upgrade that is refused for an UPGRADE reason, carrying
 * `Hidden` H. Then send a well-formed upgrade carrying the SAME H. If
 * the first request never got as far as step 3 -- which is what
 * validating the upgrade first guarantees -- the second succeeds. If it
 * did, H is already spent and the second is refused as a replay.
 *
 * THIS IS ALSO THE PRODUCTION SCENARIO, not a contrived one: a client
 * whose first attempt was mangled by a CDN retries, and a Cloak client
 * that reuses its ephemeral key across an immediate retry would find
 * itself permanently locked out by its own first attempt. */
static void test_refused_upgrade_does_not_burn_the_ephemeral_key(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    char hidden[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    make_hidden(fx.server_pub, fx.uid_ok, "ss", 7030, hidden, shared);

    /* Attempt 1: a CDN that rewrote `Connection`. */
    char req[4096];
    ws_req_t bad = {0};
    bad.hidden = hidden;
    bad.conn = "keep-alive";
    size_t bad_len = build_ws_request(req, sizeof(req), bad);

    int fd1 = client_connect(front_port(&fx));
    ASSERT_TRUE(fd1 >= 0);
    if (fd1 < 0) {
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT((int)bad_len, (int)write(fd1, req, bad_len));
    reader_t rd1;
    memset(&rd1, 0, sizeof(rd1));
    rd1.r = fx.reactor;
    rd1.fd = fd1;
    rd1.want = COVER_BANNER_LEN;
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rd1, WS_PUMP_BUDGET_MS, 1));
    ASSERT_MEM_EQ(COVER_BANNER, rd1.buf, COVER_BANNER_LEN);
    close(fd1);

    /* Attempt 2: the same ephemeral key, a well-formed upgrade. */
    ws_req_t good = {0};
    good.hidden = hidden;
    size_t good_len = build_ws_request(req, sizeof(req), good);

    int fd2 = client_connect(front_port(&fx));
    ASSERT_TRUE(fd2 >= 0);
    if (fd2 < 0) {
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT((int)good_len, (int)write(fd2, req, good_len));
    reader_t rd2;
    memset(&rd2, 0, sizeof(rd2));
    rd2.r = fx.reactor;
    rd2.fd = fd2;
    rd2.want = WS_REPLY_TOTAL;
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rd2, WS_PUMP_BUDGET_MS, 1));
    ASSERT_EQ_INT(WS_REPLY_TOTAL, (int)rd2.len);
    ASSERT_TRUE(cloak_server_registry_find(&fx.registry, fx.uid_ok, 7030) != NULL);

    /* And for completeness, the control that proves the cache is armed
     * at all: a THIRD attempt with the same key, after a handshake that
     * really did reach step 3, is refused. */
    int fd3 = client_connect(front_port(&fx));
    ASSERT_TRUE(fd3 >= 0);
    if (fd3 >= 0) {
        ASSERT_EQ_INT((int)good_len, (int)write(fd3, req, good_len));
        reader_t rd3;
        memset(&rd3, 0, sizeof(rd3));
        rd3.r = fx.reactor;
        rd3.fd = fd3;
        rd3.want = COVER_BANNER_LEN;
        ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rd3, WS_PUMP_BUDGET_MS, 1));
        ASSERT_EQ_INT(COVER_BANNER_LEN, (int)rd3.len);
        ASSERT_MEM_EQ(COVER_BANNER, rd3.buf, COVER_BANNER_LEN);
        close(fd3);
    }

    close(fd2);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 5. The bare GET still reaches the cover site                         */
/* ------------------------------------------------------------------ */

/* test_dispatcher_redirect.c's own case 3 is the canonical version of
 * this and it stays UNMODIFIED; this is the same claim made against a
 * dispatcher that now has a live CDN path behind it, which is the
 * configuration that could have broken it. */
static void test_bare_get_still_reaches_the_cover_site(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    int fd = client_connect(front_port(&fx));
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        fixture_destroy(&fx);
        return;
    }
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    ASSERT_EQ_INT((int)strlen(req), (int)write(fd, req, strlen(req)));

    reader_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.r = fx.reactor;
    rd.fd = fd;
    rd.want = COVER_BANNER_LEN;
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rd, WS_PUMP_BUDGET_MS, 1));
    ASSERT_EQ_INT(COVER_BANNER_LEN, (int)rd.len);
    ASSERT_MEM_EQ(COVER_BANNER, rd.buf, COVER_BANNER_LEN);
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(fx.panel));

    close(fd);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 6. `Origin` IS NOT READ, AND THAT IS THE DIVERGENCE, NOT AN OMISSION  */
/* ------------------------------------------------------------------ */

/* THE THIRD TRIGGER OF THE GO WEDGE, ACCEPTED HERE ON PURPOSE.
 *
 * The other two triggers this file already pins -- a rewritten
 * `Connection` and a malformed `Sec-WebSocket-Key` -- are REFUSALS in this
 * port: test_panel_is_untouched_by_a_malformed_upgrade drives them to the
 * cover site with the panel untouched. `Origin` is not. gorilla's
 * zero-value Upgrader substitutes checkSameOrigin, which answers
 * `403 request origin not allowed by Upgrader.CheckOrigin` to the request
 * below (measured against live gorilla v1.5.3 in this project's image),
 * and in Go that 403 wedges the connection forever. This port has no
 * `Origin` code at all, so the upgrade completes.
 *
 * That was true before anyone wrote it down, which is the problem this
 * test exists to fix: `grep -ri origin` over ws_handshake.c,
 * ws_handshake.h and the three CDN test files returned NOTHING about the
 * header, so the behaviour read as an oversight and the next reader
 * "restoring gorilla parity" would have re-imported the wedge. The
 * reasoning is in cloak/ws_handshake.h's `Origin` paragraph; this is the
 * assertion that fails if the code stops matching it.
 *
 * It asserts the WHOLE upgrade, not just a status line: 101, gorilla's
 * own accept, a session in the registry holding the key the client
 * recovered, and the user made active exactly once -- i.e. that a
 * cross-Origin request is treated as completely ordinary. A dispatcher
 * that grew an Origin check would fail at the very first of those.
 *
 * MEASURED at the built ck-server as well, 200 connections each carrying
 * an authorised `Hidden` and this Origin: 200 x 101, 0 closed without an
 * answer, 0 hung at a 3 s deadline. */
static void test_cross_origin_upgrade_is_accepted(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    reader_t rd;
    /* Host is cdn.example.com:443, so this Origin is cross-site by
     * gorilla's rule (it compares the Origin's host to the request's
     * Host, case-insensitively, and refuses on any difference). */
    int fd = ws_handshake_origin(&fx, fx.uid_ok, "ss", 7301, "https://evil.example.com", &rd,
                                 shared);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        fixture_destroy(&fx);
        return;
    }

    ASSERT_EQ_INT(WS_REPLY_TOTAL, (int)rd.len);
    ASSERT_MEM_EQ(rd.buf, "HTTP/1.1 101 Switching Protocols\r\n", 34);
    {
        static const char want[] = "Sec-WebSocket-Accept: " ACCEPT_GO "\r\n";
        int found = 0;
        for (size_t i = 0; i + sizeof(want) - 1 <= CLOAK_WS_HS_101_LEN; i++) {
            if (memcmp(rd.buf + i, want, sizeof(want) - 1) == 0) {
                found = 1;
                break;
            }
        }
        ASSERT_TRUE(found);
    }

    uint8_t recovered[CLOAK_AEAD_KEY_LEN];
    ASSERT_EQ_INT(0, ws_reply_session_key(rd.buf, rd.len, shared, recovered));

    cloak_session_t *sesh = cloak_server_registry_find(&fx.registry, fx.uid_ok, 7301);
    ASSERT_TRUE(sesh != NULL);
    if (sesh != NULL) {
        ASSERT_MEM_EQ(sesh->obfuscator.session_key, recovered, CLOAK_AEAD_KEY_LEN);
    }
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(fx.panel));

    close(fd);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 7. The first-packet bound, now that it actually binds                */
/* ------------------------------------------------------------------ */

/* A two-sided bracket on CLOAK_FIRSTPACKET_MAX. Until this commit the
 * WebSocket transport had no consumer, so a request that overran the
 * buffer and one that fitted it exactly had the same outcome and the
 * bound could not be observed at all. A CDN adds several hundred bytes
 * of its own headers, so this bound is the difference between a working
 * deployment and one where every connection silently reaches the cover
 * site. */
static void test_firstpacket_max_bracket(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    /* THE CONSTANT ITSELF, BRACKETED ON BOTH SIDES, because everything
     * else in this test derives its probe size FROM the constant and so
     * cannot notice the constant moving. (Measured: changing 3000 to
     * 1500 leaves every assertion below satisfied; only the unrelated
     * test_dispatcher_limits notices, and only incidentally.)
     *
     * The lower bound is the operational claim cloak/firstpacket.h
     * makes: a bare Go client's upgrade request measures 335 bytes and a
     * Cloudflare-shaped one measured 631, so 3000 "holds comfortably".
     * Four times the measured CDN-shaped request is what "comfortably"
     * is worth asserting as -- a CDN that added another 1900 bytes of
     * its own headers would silently redirect every connection to the
     * cover site with no diagnostic anywhere, so the margin is the
     * warning.
     *
     * The upper bound is the other cost: this buffer is embedded in
     * cloak_dispatch_conn_t, one per UNAUTHENTICATED connection, and
     * cloak/dispatcher.h's cap reasoning is written around "~3KB of heap
     * per unauthenticated connection". A constant that grew past 4096
     * would quietly change what max_pending_conns costs an operator in
     * memory, which is a decision, not a tweak. */
    ASSERT_EQ_INT(3000, CLOAK_FIRSTPACKET_MAX);
    ASSERT_TRUE(CLOAK_FIRSTPACKET_MAX >= 4 * 631);
    ASSERT_TRUE(CLOAK_FIRSTPACKET_MAX <= 4096);

    for (int over = 0; over <= 1; over++) {
        char hidden[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
        uint8_t shared[CLOAK_AEAD_KEY_LEN];
        uint32_t sid = over ? 9201u : 9200u;
        make_hidden(fx.server_pub, fx.uid_ok, "ss", sid, hidden, shared);

        char req[4096];
        ws_req_t r = {0};
        r.hidden = hidden;
        size_t base = build_ws_request(req, sizeof(req), r);
        size_t target = (size_t)CLOAK_FIRSTPACKET_MAX + (size_t)over;
        ASSERT_TRUE(base + 9 <= target);
        r.pad = target - base - 9;
        size_t n = build_ws_request(req, sizeof(req), r);
        ASSERT_EQ_INT((int)target, (int)n);

        int fd = client_connect(front_port(&fx));
        ASSERT_TRUE(fd >= 0);
        if (fd < 0) {
            continue;
        }
        ASSERT_EQ_INT((int)n, (int)write(fd, req, n));

        reader_t rd;
        memset(&rd, 0, sizeof(rd));
        rd.r = fx.reactor;
        rd.fd = fd;
        rd.want = over ? COVER_BANNER_LEN : (size_t)WS_REPLY_TOTAL;
        ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rd, WS_PUMP_BUDGET_MS, 1));

        if (over) {
            /* 3001 bytes: the buffer refuses the last one and the whole
             * connection becomes an ordinary redirect. */
            ASSERT_EQ_INT(COVER_BANNER_LEN, (int)rd.len);
            ASSERT_MEM_EQ(COVER_BANNER, rd.buf, COVER_BANNER_LEN);
            ASSERT_TRUE(cloak_server_registry_find(&fx.registry, fx.uid_ok, sid) == NULL);
        } else {
            /* Exactly 3000 bytes: a full session. */
            ASSERT_EQ_INT(WS_REPLY_TOTAL, (int)rd.len);
            ASSERT_EQ_INT(0x82, rd.buf[129]);
            ASSERT_TRUE(cloak_server_registry_find(&fx.registry, fx.uid_ok, sid) != NULL);
        }
        close(fd);
        for (int i = 0; i < 20; i++) {
            cloak_reactor_run_once(fx.reactor, 1);
        }
    }

    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */

TEST_MAIN_BEGIN()
test_cdn_upgrade_establishes_a_session();
test_reply_is_one_flat_write();
test_reply_nonce_is_fresh_per_connection();
test_replayed_cdn_request_is_refused();
test_three_refusals_are_indistinguishable();
test_panel_is_untouched_by_a_malformed_upgrade();
test_refused_upgrade_does_not_burn_the_ephemeral_key();
test_bare_get_still_reaches_the_cover_site();
test_cross_origin_upgrade_is_accepted();
test_firstpacket_max_bracket();
TEST_MAIN_END()
