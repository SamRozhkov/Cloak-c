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
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
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

/* THE AUTHORISATION POLICY, END TO END. Tasks 2-4 built the user
 * database, the per-user meter and the panel that drains it; this file
 * asserts that the dispatcher actually CONSULTS them, and that a
 * connection it refuses is indistinguishable from any other connection
 * this server does not recognise.
 *
 * THE STACK IS REAL AND SO IS EVERY REFUSAL. Nothing here is a mock: a
 * SQLite-backed cloak_usermanager_t, a cloak_userpanel_t over it, a
 * cloak_server_registry_t, a cloak_proxy_t, a cloak_dispatcher_t and a
 * listener, wired exactly as test_server_e2e.c wires them plus the two
 * panel wirings cloak/userpanel.h's WIRING block requires -- the proxy's
 * chain for the bookkeeping, and on_session_closing for the relays. Both
 * of those are load-bearing and both are mutation-verified below (see
 * test_terminated_user_stops_its_relays).
 *
 * WHY THE COVER SITE SENDS A BANNER. "Redirected byte-for-byte like any
 * other unauthenticated connection" is only assertable if there is
 * something to compare, and the honest comparison is not a hand-written
 * expectation but the bytes a connection the server has NO opinion about
 * receives. So the fake cover site answers every connection with a fixed
 * response, and every refusal case asserts it received exactly what a
 * connection carrying plain HTTP garbage received. A refusal that closed
 * the socket (0 bytes) or answered with a ServerHello (127+ bytes)
 * therefore fails, and so does one that simply differs.
 *
 * EVERY WAIT IS A BOUNDED pump_until (client_harness.h), the discipline
 * every other dispatcher test file states: three tests on this project
 * have hung or flaked in CI. */

/* ------------------------------------------------------------------ */
/* Database scaffolding (test_usermanager.c's / test_userpanel.c's)     */
/* ------------------------------------------------------------------ */

static void du_tmp_path(char *buf, size_t cap, const char *tag) {
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(buf, cap, "%s/cloak_du_%ld_%s.db", dir, (long)getpid(), tag);
}

/* WAL leaves sidecars; a survivor would carry committed credit from a
 * previous run into this one and make a billing assertion pass or fail
 * for reasons unrelated to the code under test. */
static void du_unlink(const char *path) {
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
 * the handshake itself is timestamped against (cloak_server_auth_decrypt
 * checks the client's timestamp against time(NULL), and the client
 * harness stamps time(NULL)): expiry is a database property and wants a
 * fixed, unambiguous "now" so that "expired" and "not expired" are not
 * one CI-scheduling hiccup apart. */
#define T_NOW 1600000000
#define T_EXPIRY (T_NOW + 100000)

static int64_t du_now(void *userdata) {
    (void)userdata;
    return (int64_t)T_NOW;
}

#define START_CREDIT 10000000

/* uid[0] is the discriminator; the rest is filler that keeps every UID
 * distinct from the 0x10.. bypass UID the config file carries. */
static void mk_uid(uint8_t *uid, uint8_t seed) {
    memset(uid, 0xA0, CLOAK_UID_LEN);
    uid[0] = seed;
}

static void put_user(cloak_usermanager_t *m, const uint8_t *uid, int32_t cap, int64_t up_credit,
                     int64_t down_credit, int64_t expiry) {
    cloak_user_info_t u;
    memset(&u, 0, sizeof(u));
    memcpy(u.uid, uid, CLOAK_UID_LEN);
    u.sessions_cap = cap;
    u.up_rate = 0;
    u.down_rate = 0;
    u.up_credit = up_credit;
    u.down_credit = down_credit;
    u.expiry_time = expiry;
    ASSERT_EQ_INT(0, cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL));
}

/* ------------------------------------------------------------------ */
/* Fake cover site: answers every connection with the same fixed bytes  */
/* ------------------------------------------------------------------ */

static const char DU_BANNER[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
#define DU_BANNER_LEN (sizeof(DU_BANNER) - 1)

typedef struct {
    cloak_reactor_t *reactor;
    int fds[16];
    int count;
} redir_site_t;

static void redir_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    (void)userdata;
    /* Drain and discard: what the cover site RECEIVES is not what this
     * file asserts on (it necessarily differs -- one probe sends HTTP
     * garbage and the next sends a real ClientHello). What it SENDS is,
     * and that is written once at accept. */
    uint8_t buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
}

static void redir_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    redir_site_t *rs = userdata;
    if (rs->count >= (int)(sizeof(rs->fds) / sizeof(rs->fds[0]))) {
        close(fd);
        return;
    }
    rs->fds[rs->count++] = fd;
    /* A blocking write of 39 bytes onto a freshly accepted loopback
     * socket cannot short-write; a partial one would show up as a
     * mismatched length in every probe at once, not as a silent pass. */
    ssize_t n = write(fd, DU_BANNER, DU_BANNER_LEN);
    (void)n;
    (void)cloak_reactor_add_fd(rs->reactor, fd, CLOAK_REACTOR_READABLE, redir_on_readable, rs);
}

static void redir_destroy(redir_site_t *rs) {
    for (int i = 0; i < rs->count; i++) {
        cloak_reactor_remove_fd(rs->reactor, rs->fds[i]);
        close(rs->fds[i]);
    }
    rs->count = 0;
}

/* ------------------------------------------------------------------ */
/* Fake upstream: records what it gets, sends only when TOLD to         */
/* ------------------------------------------------------------------ */

/* Deliberately NOT test_server_e2e.c's echo upstream. The relay-stopping
 * test has to put bytes on the upstream socket at a moment of its own
 * choosing -- specifically AFTER the user has been terminated -- and an
 * upstream that echoes on its own would have sent them long before that
 * moment arrived. */

#define DU_UP_MAX 8
#define DU_UP_CAP ((size_t)65536)

typedef struct {
    int fd;
    uint8_t in[DU_UP_CAP];
    size_t in_len;
} du_up_conn_t;

struct du_upstream;
typedef struct {
    struct du_upstream *up;
    int idx;
} du_up_slot_t;

typedef struct du_upstream {
    cloak_reactor_t *reactor;
    int accept_count;
    du_up_conn_t conns[DU_UP_MAX];
    du_up_slot_t slots[DU_UP_MAX];
} du_upstream_t;

static void du_up_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    (void)events;
    du_up_slot_t *slot = userdata;
    du_up_conn_t *c = &slot->up->conns[slot->idx];
    for (;;) {
        if (c->in_len >= DU_UP_CAP) {
            return;
        }
        ssize_t n = read(c->fd, c->in + c->in_len, DU_UP_CAP - c->in_len);
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

static void du_up_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    du_upstream_t *up = userdata;
    if (up->accept_count >= DU_UP_MAX) {
        close(fd);
        return;
    }
    int idx = up->accept_count++;
    up->conns[idx].fd = fd;
    up->slots[idx].up = up;
    up->slots[idx].idx = idx;
    (void)cloak_reactor_add_fd(up->reactor, fd, CLOAK_REACTOR_READABLE, du_up_on_readable,
                               &up->slots[idx]);
}

/* Returns what send() returned. Callers that push bytes at an upstream
 * whose relay has already been stopped EXPECT this to fail (the relay
 * closed the socket), so the result is deliberately not asserted there. */
static ssize_t du_up_send(du_upstream_t *up, int idx, const void *data, size_t len) {
    return send(up->conns[idx].fd, data, len, MSG_NOSIGNAL);
}

static void du_up_destroy(du_upstream_t *up) {
    for (int i = 0; i < DU_UP_MAX; i++) {
        if (up->conns[i].fd >= 0) {
            cloak_reactor_remove_fd(up->reactor, up->conns[i].fd);
            close(up->conns[i].fd);
            up->conns[i].fd = -1;
        }
    }
}

/* ------------------------------------------------------------------ */
/* The fixture                                                          */
/* ------------------------------------------------------------------ */

struct fixture {
    cloak_reactor_t *reactor;

    redir_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;

    du_upstream_t up;
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

    cloak_userpanel_t *panel; /* NULL when the fixture was built without one */

    cloak_proxy_t proxy;
    int proxy_ready;

    cloak_dispatcher_t d;
    int d_ready;

    cloak_listener_t front;
    int have_front;

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_bypass[CLOAK_UID_LEN];
};

/* THE TRAMPOLINE cloak/userpanel.h's WIRING block names, and the single
 * most dangerous line in this file to get wrong.
 *
 * cloak_userpanel_terminate closes its user's sessions through
 * cloak_server_registry_close_all_for_uid, which fires NO on_broken --
 * and on_broken is the only window in which a cloak_stream_relay_t bound
 * to the session may still be stopped (cloak/stream_relay.h,
 * cloak/registry.h). on_session_closing is the replacement window, and
 * cloak_proxy_session_aborted is what uses it: it runs the proxy's shared
 * teardown walk for (uid, session_id), stopping every relay and releasing
 * every stream while the session is still alive.
 *
 * It is a trampoline and not a direct assignment only because the two
 * signatures differ by the cloak_dispatcher_t * that
 * cloak_dispatch_session_aborted_cb carries and this hook does not;
 * cloak_proxy_session_aborted ignores that argument (proxy.c casts it to
 * void), so NULL is the honest value to pass. */
static void fx_session_closing(const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    cloak_proxy_session_aborted(NULL, uid, session_id, userdata);
}

/* with_panel == 0 builds the pre-user-manager server: no panel at all, so
 * cloak_server_is_bypass is the whole policy. void_manager == 1 opens the
 * manager with no database file (cloak/usermanager.h's VOID manager), so
 * every non-bypass authentication fails with CLOAK_USER_ERR_VOID. */
static int fixture_init(struct fixture *fx, int with_panel, int void_manager) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    for (int i = 0; i < DU_UP_MAX; i++) {
        fx->up.conns[i].fd = -1;
    }

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

    fx->cover.reactor = fx->reactor;
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->cover_listener, fx->reactor, "127.0.0.1:0",
                                         redir_on_accept, &fx->cover, err, sizeof(err)));
    fx->have_cover_listener = 1;
    int cover_port = cloak_listener_port(&fx->cover_listener);
    ASSERT_TRUE(cover_port > 0);

    fx->up.reactor = fx->reactor;
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->up_listener, fx->reactor, "127.0.0.1:0",
                                         du_up_on_accept, &fx->up, err, sizeof(err)));
    fx->have_up_listener = 1;
    fx->up_port = cloak_listener_port(&fx->up_listener);
    ASSERT_TRUE(fx->up_port > 0);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, fx->server_pub));
    mk_uid(fx->uid_bypass, 0x10);

    char priv_b64[64];
    char uid_b64[32];
    ASSERT_EQ_INT(
        0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64, sizeof(priv_b64)));
    ASSERT_EQ_INT(0,
                  cloak_base64_encode(fx->uid_bypass, CLOAK_UID_LEN, uid_b64, sizeof(uid_b64)));

    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\"127.0.0.1:0\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\"]}",
             fx->up_port, cover_port, priv_b64, uid_b64);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    /* The database, then the manager over it. A void manager takes no
     * path at all and has no file to unlink afterwards. */
    if (void_manager) {
        fx->db_path[0] = '\0';
        err[0] = '\0';
        ASSERT_EQ_INT(0, cloak_usermanager_open(&fx->mgr, NULL, du_now, NULL, err, sizeof(err)));
    } else {
        du_tmp_path(fx->db_path, sizeof(fx->db_path), "disp");
        du_unlink(fx->db_path);
        err[0] = '\0';
        ASSERT_EQ_INT(0,
                      cloak_usermanager_open(&fx->mgr, fx->db_path, du_now, NULL, err, sizeof(err)));
    }
    ASSERT_TRUE(fx->mgr != NULL);
    if (fx->mgr == NULL) {
        return -1;
    }

    /* CONSTRUCTION ORDER, which is circular-looking and is not: the
     * registry's on_broken userdata is the proxy's ADDRESS (stored, never
     * dereferenced until a session breaks), so the registry can be
     * initialised before the proxy itself is; the panel needs the
     * registry; and the proxy's chain userdata needs the panel, which
     * only exists once it has been opened. Hence registry, panel, proxy,
     * dispatcher -- and a binary will have to do the same. */
    ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor,
                                                cloak_proxy_registry_broken, &fx->proxy));
    fx->registry_ready = 1;

    if (with_panel) {
        cloak_userpanel_config_t pcfg;
        memset(&pcfg, 0, sizeof(pcfg));
        pcfg.manager = fx->mgr;
        pcfg.registry = &fx->registry;
        pcfg.reactor = fx->reactor;
        /* An hour: no test here wants the periodic cycle to fire on its
         * own. Every upload and every reap in this file is driven by an
         * explicit cloak_userpanel_upload_now, so nothing depends on a
         * timer landing inside a pump window. */
        pcfg.upload_interval_ms = 3600000;
        pcfg.now_fn = du_now;
        pcfg.on_session_closing = fx_session_closing;
        pcfg.on_session_closing_userdata = &fx->proxy;
        ASSERT_EQ_INT(0, cloak_userpanel_open(&fx->panel, &pcfg));
        ASSERT_TRUE(fx->panel != NULL);
        if (fx->panel == NULL) {
            return -1;
        }
    }

    cloak_proxy_config_t pxcfg;
    memset(&pxcfg, 0, sizeof(pxcfg));
    pxcfg.reactor = fx->reactor;
    pxcfg.srv = &fx->srv;
    /* OBLIGATION 2 of cloak/userpanel.h's WIRING block: the registry has
     * exactly one on_broken and the proxy owns it, so the panel's "a
     * session of this uid went away" bookkeeping arrives through the
     * proxy's chain -- proxy first (its relays must stop while the
     * session is alive), panel second. */
    pxcfg.chain = cloak_userpanel_registry_broken;
    pxcfg.chain_userdata = fx->panel; /* NULL is a no-op chain: see proxy.h */
    ASSERT_EQ_INT(0, cloak_proxy_init(&fx->proxy, &pxcfg));
    fx->proxy_ready = 1;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.registry = &fx->registry;
    dcfg.panel = fx->panel; /* NULL in the no-panel fixture */

    dcfg.session_config_template.max_on_wire_size = 16401;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = 262144;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;

    dcfg.prepare_session = cloak_proxy_prepare_session;
    dcfg.prepare_session_userdata = &fx->proxy;
    dcfg.session_aborted = cloak_proxy_session_aborted;
    dcfg.session_aborted_userdata = &fx->proxy;

    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, fx->cfg.bind_addr[0],
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;

    /* test_proxy_stream.c's and test_server_e2e.c's one non-binary line,
     * for their reason: loopback's default multi-megabyte SO_SNDBUF would
     * swallow a whole transfer, so the session never becomes
     * backpressured. */
    int sndbuf = 8192;
    (void)setsockopt(fx->front.fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    return 0;
}

/* THE SHUTDOWN ORDER A BINARY MUST USE, and it is not the reverse of
 * construction twice over: the proxy before the registry (cloak/proxy.h's
 * LIFETIME paragraph -- relays must stop before their sessions die), and
 * the PANEL AFTER THE REGISTRY (cloak/userpanel.h's cloak_userpanel_close
 * -- it frees every active user's valve without closing anybody's
 * sessions, so a session still alive afterwards meters into freed
 * memory). */
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
    du_up_destroy(&fx->up);
    if (fx->have_cover_listener) {
        cloak_listener_close(&fx->cover_listener);
        fx->have_cover_listener = 0;
    }
    redir_destroy(&fx->cover);
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
        fx->reactor = NULL;
    }
    if (fx->db_path[0] != '\0') {
        du_unlink(fx->db_path);
    }
}

static int front_port(struct fixture *fx) {
    return cloak_listener_port(&fx->front);
}

static void client_config(cloak_session_config_t *ccfg) {
    memset(ccfg, 0, sizeof(*ccfg));
    ccfg->max_on_wire_size = 16401;
    ccfg->stream_recv_capacity = 65536;
    ccfg->stream_max_pending_frames = 64;
    ccfg->conn_send_queue_cap = 262144;
    ccfg->inactivity_timeout_ms = 60000;
}

static int open_client(struct fixture *fx, client_session_t *cs, const uint8_t *uid,
                       uint32_t session_id) {
    cloak_session_config_t ccfg;
    client_config(&ccfg);
    return client_session_open(cs, fx->reactor, front_port(fx), fx->server_pub, uid, "ss",
                               session_id, 0, &ccfg);
}

/* ------------------------------------------------------------------ */
/* The probe: what does this server send back?                          */
/* ------------------------------------------------------------------ */

/* Connects, sends `rec`, and collects up to DU_BANNER_LEN bytes of
 * whatever comes back. DU_BANNER_LEN and not more, deliberately: a
 * SUCCESSFUL handshake answers with a 127-byte ServerHello whose first 39
 * bytes are nothing like the cover site's response, so an
 * accidentally-authorised probe fails the comparison on content rather
 * than escaping it on length. A closed connection yields 0 bytes, which
 * fails on length. Returns the number of bytes collected. */
static size_t probe_response(struct fixture *fx, const uint8_t *rec, size_t rec_len, uint8_t *out,
                             size_t cap) {
    size_t want = DU_BANNER_LEN < cap ? DU_BANNER_LEN : cap;
    memset(out, 0, cap);

    int fd = client_connect(front_port(fx));
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return 0;
    }
    if (write(fd, rec, rec_len) != (ssize_t)rec_len) {
        close(fd);
        return 0;
    }

    size_t got = 0;
    for (int i = 0; i < 400 && got < want; i++) {
        cloak_reactor_run_once(fx->reactor, 5);
        ssize_t n = recv(fd, out + got, want - got, MSG_DONTWAIT);
        if (n > 0) {
            got += (size_t)n;
        } else if (n == 0) {
            break;
        }
    }
    close(fd);
    /* One more turn so the server side observes the close and unwinds
     * before the next probe's assertions read its counters. */
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(fx->reactor, 2);
    }
    return got;
}

/* A real, well-formed Cloak ClientHello for uid -- the only thing that
 * distinguishes the refusal cases below from the success case. */
static size_t make_record_pm(struct fixture *fx, const uint8_t *uid, const char *proxy_method,
                             uint32_t session_id, uint8_t *out, size_t cap) {
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    return build_client_record(fx->server_pub, uid, proxy_method, (uint8_t)CLOAK_AEAD_AES_256_GCM,
                               (int64_t)time(NULL), session_id, 0, out, cap, shared);
}

static size_t make_record(struct fixture *fx, const uint8_t *uid, uint32_t session_id,
                          uint8_t *out, size_t cap) {
    return make_record_pm(fx, uid, "ss", session_id, out, cap);
}

/* ---- client-side stream helpers (test_server_e2e.c's) ------------------ */

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

struct up_wait {
    du_upstream_t *up;
    int idx;
    size_t want;
};

static int up_has_len(void *ctx) {
    struct up_wait *w = ctx;
    return w->up->conns[w->idx].in_len >= w->want;
}

struct uid_wait {
    cloak_server_registry_t *reg;
    const uint8_t *uid;
    size_t want;
};

static int uid_count_is(void *ctx) {
    struct uid_wait *w = ctx;
    return cloak_server_registry_count_for_uid(w->reg, w->uid) == w->want;
}

/* ------------------------------------------------------------------ */
/* 1. A database user authenticates, and its traffic reaches its row     */
/* ------------------------------------------------------------------ */

/* THE ASSERTION TASK 3's REVIEWER ASKED FOR. Until this task,
 * dispatcher.c's session_config_template never set .valve, so every
 * server session was unmetered and every test of the valve, the panel and
 * the manager still passed. The check that a byte count is NON-ZERO is
 * what makes this non-vacuous: without the dispatcher installing the
 * user's valve, rx and tx are both 0 and `credit == START_CREDIT - 0`
 * would still hold. */
static void test_database_user_authenticates_and_is_metered(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 1, 0));

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x21);
    put_user(fx.mgr, uid, 4, START_CREDIT, START_CREDIT, T_EXPIRY);

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, uid, 4001));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, uid));
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(fx.panel));

    cloak_userpanel_user_t *u = cloak_userpanel_find(fx.panel, uid);
    ASSERT_TRUE(u != NULL);
    if (u == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(0, u->bypass);

    /* Real traffic in BOTH directions, because up_credit and down_credit
     * are billed from different counters and a single direction cannot
     * tell a correct mapping from a swapped one. */
    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(9, (int)cloak_stream_write(st, (const uint8_t *)"to-the-up", 9));

    struct up_wait uw = {&fx.up, 0, 9};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_MEM_EQ(fx.up.conns[0].in, "to-the-up", 9);

    ASSERT_EQ_INT(12, (int)du_up_send(&fx.up, 0, "down-to-you\n", 12));
    uint8_t back[32];
    reader_t rd = {st, back, sizeof(back), 0, 0};
    struct reader_wait rw = {&rd, 12};
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rw, 400, 5));
    ASSERT_MEM_EQ(rd.buf, "down-to-you\n", 12);

    /* The valve the dispatcher installed is the one this user's session
     * metered into, and it carries WIRE bytes, so both counters are
     * strictly larger than the payloads above. */
    int64_t rx = cloak_valve_rx(&u->valve);
    int64_t tx = cloak_valve_tx(&u->valve);
    ASSERT_TRUE(rx > 9);
    ASSERT_TRUE(tx > 12);

    /* And the drain settles exactly those counts into the database, in
     * the direction cloak/valve.h names: a user's UPLOAD is the server's
     * RX. */
    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(fx.panel));
    cloak_user_info_t row;
    memset(&row, 0, sizeof(row));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.mgr, uid, &row));
    ASSERT_EQ_INT(START_CREDIT - rx, row.up_credit);
    ASSERT_EQ_INT(START_CREDIT - tx, row.down_credit);

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 2. Every refusal is the same redirect                                */
/* ------------------------------------------------------------------ */

static void test_every_refusal_is_the_same_redirect(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 1, 0));

    uint8_t uid_expired[CLOAK_UID_LEN], uid_nocredit[CLOAK_UID_LEN], uid_capped[CLOAK_UID_LEN];
    uint8_t uid_unknown[CLOAK_UID_LEN];
    mk_uid(uid_expired, 0x31);
    mk_uid(uid_nocredit, 0x32);
    mk_uid(uid_capped, 0x33);
    mk_uid(uid_unknown, 0x34); /* deliberately never written */

    put_user(fx.mgr, uid_expired, 4, START_CREDIT, START_CREDIT, T_NOW - 1);
    put_user(fx.mgr, uid_nocredit, 4, 0, START_CREDIT, T_EXPIRY);
    put_user(fx.mgr, uid_capped, 1, START_CREDIT, START_CREDIT, T_EXPIRY);

    /* THE BASELINE: a connection this server has no opinion about
     * whatsoever. Everything below is compared against what THIS gets,
     * never against a hand-written expectation. */
    uint8_t base[128];
    size_t base_len =
        probe_response(&fx, (const uint8_t *)"GET / HTTP/1.1\r\n\r\n", 18, base, sizeof(base));
    ASSERT_EQ_INT((int)DU_BANNER_LEN, (int)base_len);
    ASSERT_MEM_EQ(base, DU_BANNER, DU_BANNER_LEN);

    uint8_t rec[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t got[128];
    size_t n;

    /* (a) a UID that is not in the database and is not a bypass UID. */
    size_t rec_len = make_record(&fx, uid_unknown, 5001, rec, sizeof(rec));
    ASSERT_TRUE(rec_len > 0);
    n = probe_response(&fx, rec, rec_len, got, sizeof(got));
    ASSERT_EQ_INT((int)base_len, (int)n);
    ASSERT_MEM_EQ(got, base, base_len);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx.registry, uid_unknown));

    /* (b) expired. */
    rec_len = make_record(&fx, uid_expired, 5002, rec, sizeof(rec));
    ASSERT_TRUE(rec_len > 0);
    n = probe_response(&fx, rec, rec_len, got, sizeof(got));
    ASSERT_EQ_INT((int)base_len, (int)n);
    ASSERT_MEM_EQ(got, base, base_len);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx.registry, uid_expired));

    /* (c) no upload credit. */
    rec_len = make_record(&fx, uid_nocredit, 5003, rec, sizeof(rec));
    ASSERT_TRUE(rec_len > 0);
    n = probe_response(&fx, rec, rec_len, got, sizeof(got));
    ASSERT_EQ_INT((int)base_len, (int)n);
    ASSERT_MEM_EQ(got, base, base_len);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx.registry, uid_nocredit));

    /* NONE of the three refusals left an active user behind. A refusal
     * that made a user active and then failed would be a leaked table
     * slot per probe, which is exactly the shape cloak/userpanel.h warns
     * ends in legitimate users being refused with _ERR_FULL. */
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(fx.panel));

    /* (d) THE UNWIND. A perfectly valid user that fails at a LATER step:
     * this one authenticates (step 6 makes it active) and is then refused
     * at step 7 for naming a proxy method this server does not have.
     * That leaves an active user with no session, which the panel's
     * reaper would eventually collect -- up to a whole upload interval
     * later, during which an attacker holding valid credentials can pin
     * one active-table slot per UID per probe. dispatcher_release_user is
     * what closes that window, and this is the assertion that says so:
     * the redirect is still indistinguishable AND the table is empty
     * again immediately, not a minute later. */
    uint8_t uid_good[CLOAK_UID_LEN];
    mk_uid(uid_good, 0x35);
    put_user(fx.mgr, uid_good, 4, START_CREDIT, START_CREDIT, T_EXPIRY);
    rec_len = make_record_pm(&fx, uid_good, "nosuchmethod", 5006, rec, sizeof(rec));
    ASSERT_TRUE(rec_len > 0);
    n = probe_response(&fx, rec, rec_len, got, sizeof(got));
    ASSERT_EQ_INT((int)base_len, (int)n);
    ASSERT_MEM_EQ(got, base, base_len);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx.registry, uid_good));
    ASSERT_TRUE(cloak_userpanel_find(fx.panel, uid_good) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(fx.panel));

    /* (e) at the sessions cap. This one needs a live session first: the
     * cap is not a property of the user's row alone, it is that row's
     * sessions_cap against the sessions the REGISTRY says it holds. */
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, uid_capped, 5004));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, uid_capped));

    rec_len = make_record(&fx, uid_capped, 5005, rec, sizeof(rec));
    ASSERT_TRUE(rec_len > 0);
    n = probe_response(&fx, rec, rec_len, got, sizeof(got));
    ASSERT_EQ_INT((int)base_len, (int)n);
    ASSERT_MEM_EQ(got, base, base_len);
    /* Refused, so the second session was never created -- and the first
     * one is untouched. */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, uid_capped));
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(fx.panel));

    /* An ADDITIONAL connection to a session that already exists is not a
     * new session and must NOT be refused by the cap, or a capped user
     * could never open a second connection to its own session. */
    rec_len = make_record(&fx, uid_capped, 5004, rec, sizeof(rec));
    ASSERT_TRUE(rec_len > 0);
    n = probe_response(&fx, rec, rec_len, got, sizeof(got));
    ASSERT_TRUE(n > 0);
    ASSERT_MEM_NE(got, base, base_len);

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 3. The cap reads live registry state, not a stale count              */
/* ------------------------------------------------------------------ */

static void test_cap_reads_live_registry_state(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 1, 0));

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x41);
    put_user(fx.mgr, uid, 1, START_CREDIT, START_CREDIT, T_EXPIRY);

    client_session_t cs1;
    ASSERT_EQ_INT(0, open_client(&fx, &cs1, uid, 6001));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, uid));

    /* At the cap: refused. */
    uint8_t rec[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t got[128];
    size_t rec_len = make_record(&fx, uid, 6002, rec, sizeof(rec));
    ASSERT_TRUE(rec_len > 0);
    size_t n = probe_response(&fx, rec, rec_len, got, sizeof(got));
    ASSERT_EQ_INT((int)DU_BANNER_LEN, (int)n);
    ASSERT_MEM_EQ(got, DU_BANNER, DU_BANNER_LEN);

    /* Now the first session goes away for real -- the client closes, the
     * server's session breaks, the registry's on_broken fires, the proxy
     * cleans up and its chain tells the panel. */
    client_session_close(&cs1);
    struct uid_wait uw = {&fx.registry, uid, 0};
    ASSERT_TRUE(pump_until(fx.reactor, uid_count_is, &uw, 400, 5));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx.registry, uid));
    /* The chain is what deactivated the user; without it this stays 1
     * and the active table leaks a slot per disconnect. */
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(fx.panel));

    /* Below the cap again: the SAME user, the same row, a new session. */
    client_session_t cs2;
    ASSERT_EQ_INT(0, open_client(&fx, &cs2, uid, 6003));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, uid));

    client_session_close(&cs2);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 4. A bypass UID works with no database at all                        */
/* ------------------------------------------------------------------ */

static void test_bypass_uid_works_with_a_void_manager(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 1, 1)); /* panel over a VOID manager */

    /* The bypass UID is served, is active, and is NOT metered
     * (cloak_userpanel_user_valve returns NULL for it, which is
     * cloak/valve.h's "not metered"). */
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, fx.uid_bypass, 7001));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, fx.uid_bypass));

    cloak_userpanel_user_t *u = cloak_userpanel_find(fx.panel, fx.uid_bypass);
    ASSERT_TRUE(u != NULL);
    if (u != NULL) {
        ASSERT_EQ_INT(1, u->bypass);
        ASSERT_TRUE(cloak_userpanel_user_valve(u) == NULL);
    }

    /* A bypass user is exempt from the sessions cap too -- there is no
     * row to read one from, and the void manager would refuse every
     * question it were asked. A second session proves the dispatcher
     * never asks. */
    client_session_t cs2;
    ASSERT_EQ_INT(0, open_client(&fx, &cs2, fx.uid_bypass, 7002));
    ASSERT_EQ_INT(2, (int)cloak_server_registry_count_for_uid(&fx.registry, fx.uid_bypass));

    /* Anyone else is refused, exactly like any other unrecognised
     * connection. */
    uint8_t other[CLOAK_UID_LEN];
    mk_uid(other, 0x51);
    uint8_t rec[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t got[128];
    size_t rec_len = make_record(&fx, other, 7003, rec, sizeof(rec));
    ASSERT_TRUE(rec_len > 0);
    size_t n = probe_response(&fx, rec, rec_len, got, sizeof(got));
    ASSERT_EQ_INT((int)DU_BANNER_LEN, (int)n);
    ASSERT_MEM_EQ(got, DU_BANNER, DU_BANNER_LEN);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx.registry, other));

    client_session_close(&cs2);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 5. With no panel, the policy is exactly what it was before           */
/* ------------------------------------------------------------------ */

/* This is the property that lets every dispatcher test written before
 * this task pass unmodified, and it is asserted rather than assumed: a
 * dispatcher with panel == NULL serves its bypass UIDs and nobody else,
 * EVEN when a perfectly healthy row for that UID exists in a database the
 * dispatcher was never given. */
static void test_no_panel_keeps_bypass_only_policy(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0, 0)); /* manager opened, panel NOT wired */
    ASSERT_TRUE(fx.panel == NULL);

    uint8_t uid_db[CLOAK_UID_LEN];
    mk_uid(uid_db, 0x61);
    put_user(fx.mgr, uid_db, 4, START_CREDIT, START_CREDIT, T_EXPIRY);

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, fx.uid_bypass, 8001));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, fx.uid_bypass));

    uint8_t rec[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t got[128];
    size_t rec_len = make_record(&fx, uid_db, 8002, rec, sizeof(rec));
    ASSERT_TRUE(rec_len > 0);
    size_t n = probe_response(&fx, rec, rec_len, got, sizeof(got));
    ASSERT_EQ_INT((int)DU_BANNER_LEN, (int)n);
    ASSERT_MEM_EQ(got, DU_BANNER, DU_BANNER_LEN);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx.registry, uid_db));

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 6. Terminating a user stops its relays                               */
/* ------------------------------------------------------------------ */

/* THE USE-AFTER-FREE THIS WHOLE WIRING EXISTS TO PREVENT. Running out of
 * credit terminates a user, which closes its sessions by UID -- a route
 * that fires no on_broken, and on_broken is the only window in which a
 * cloak_stream_relay_t may be stopped. A relay left running past it still
 * has the upstream fd registered with the reactor, and the next byte the
 * upstream sends runs cloak_stream_write against a destroyed session.
 *
 * So this test terminates a user with a live relay and THEN makes the
 * upstream send. Two independent detectors: the proxy's own counters
 * (which go to zero only if the teardown walk ran) and ASan (which is
 * what catches the write itself). Mutation-verified by clearing
 * on_session_closing and setting no_relays -- see the task report. */
static void test_terminated_user_stops_its_relays(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 1, 0));

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x71);
    /* Enough credit to authenticate (both must be > 0) and little enough
     * that one small transfer overdraws it, so the termination is the
     * production path -- the manager ordering it from a real drain --
     * rather than a hand-called terminate. */
    put_user(fx.mgr, uid, 4, 8, 8, T_EXPIRY);

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, uid, 9001));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, uid));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(6, (int)cloak_stream_write(st, (const uint8_t *)"hello!", 6));

    struct up_wait uw = {&fx.up, 0, 6};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(1, fx.up.accept_count);
    /* A live relay exists at this point: that is what makes the
     * termination below dangerous rather than trivial. */
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    /* The drain overdraws the user and the manager orders its
     * termination. */
    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(fx.panel));
    ASSERT_TRUE(cloak_userpanel_find(fx.panel, uid) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx.registry, uid));

    /* THE ASSERTION THE on_session_closing WIRING OWNS: the proxy's
     * context and its relay are gone, which can only have happened
     * through that hook -- close_all_for_uid fires nothing else. */
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

    /* And now the byte that would land on a relay that had NOT been
     * stopped. Expected to fail at the socket level (the relay closed
     * it), which is why the result is not asserted; what is asserted is
     * that pumping afterwards touches nothing freed. */
    (void)du_up_send(&fx.up, 0, "after-the-free", 14);
    for (int i = 0; i < 60; i++) {
        cloak_reactor_run_once(fx.reactor, 5);
    }
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

    /* The user's row carries the debt the drain recorded, so it stays
     * refused on the next attempt rather than reconnecting at zero. */
    cloak_user_info_t row;
    memset(&row, 0, sizeof(row));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.mgr, uid, &row));
    ASSERT_TRUE(row.up_credit <= 0);

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

TEST_MAIN_BEGIN()
test_database_user_authenticates_and_is_metered();
test_every_refusal_is_the_same_redirect();
test_cap_reads_live_registry_state();
test_bypass_uid_works_with_a_void_manager();
test_no_panel_keeps_bypass_only_policy();
test_terminated_user_stops_its_relays();
TEST_MAIN_END()
