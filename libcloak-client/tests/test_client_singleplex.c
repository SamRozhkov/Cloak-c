#define _POSIX_C_SOURCE 200809L

/* SINGLEPLEX: ONE SESSION PER LOCAL CONNECTION, AGAINST THE REAL SERVER.
 *
 * Go's `singleplex` (NumConn <= 0) makes RouteTCP call newSeshFunc() once
 * per accepted connection instead of once per client, and close that
 * session when its one stream ends. This file is the port's version of
 * that, and the far end is the whole merged server stack -- dispatcher,
 * registry, user panel, cloak_proxy_t and a real upstream socket -- so
 * "two sessions" is read off cloak_server_registry_count rather than
 * inferred from anything the client believes about itself.
 *
 * THE FILE IS BUILT AROUND ONE PAIR OF INVERSE CASES, and that is its
 * whole reason to exist separately from test_client_piper.c:
 *
 *   case 1  singleplex on:  two local connections -> TWO server sessions.
 *   case 4  singleplex off: two local connections -> ONE server session.
 *
 * They are written as a pair and mutated as a pair. A mode flag that is
 * read and ignored, or never read at all, cannot satisfy both: pinning it
 * on one side only is exactly the shape of coverage defect this branch
 * has already paid for twice (a deadline asserted only on its "dies
 * eventually" side, and a key check tested at the one array size where
 * every wrong implementation coincides with the right one).
 *
 * THE UPSTREAM DOES NOT ECHO -- it replies with every byte XORed with
 * 0xFF. An echoing upstream would let a client that never opened a stream
 * at all pass by writing the local peer's bytes back at it; XOR cannot be
 * produced anywhere on the client side, so a transformed reply is proof
 * the bytes crossed the tunnel. The two-peer cases use DIFFERENT payloads
 * for the same reason: a crossed route passes a test whose peers send the
 * same thing.
 *
 * EVERY WAIT IS A BOUNDED pump_until, and every wait whose comment names
 * a duration asserts it actually reached that duration. Every peer socket
 * is non-blocking. */

#include "cloak/base64.h"
#include "cloak/client_connector.h"
#include "cloak/client_piper.h"
#include "cloak/conn.h"
#include "cloak/crypto.h"
#include "cloak/dispatcher.h"
#include "cloak/log.h"
#include "cloak/net.h"
#include "cloak/proxy.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
#include "test_framework.h"

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---- bounded reactor pumping ------------------------------------------- */

/* Sized so a BROKEN run fails an ASSERTION rather than the ctest timeout:
 * at SX_MAX_TURNS turns of SX_TURN_MS each, one wait is at most ~2 s, and
 * the waits in this file total well under TIMEOUT 60. */
#define SX_MAX_TURNS 2000
#define SX_TURN_MS 1

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

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Pumps the reactor for at least `ms` of REAL time, and ASSERTS it really
 * did. The first-byte deadline is a wall-clock quantity: a fixed number
 * of one-millisecond turns does not reliably cross it, and a loop that
 * exited early would silently turn the assertions that follow into
 * nothing. The iteration ceiling is a backstop against a clock that does
 * not advance and is sized about forty times above the fastest observed
 * spin rate, so the assertion below is what proves it did not bind. */
static void pump_for_ms(cloak_reactor_t *r, uint64_t ms) {
    uint64_t start = monotonic_ms();
    uint64_t elapsed = 0;
    uint64_t cap = ms * 1000u + 5000000u;
    for (uint64_t i = 0; i < cap; i++) {
        cloak_reactor_run_once(r, 1);
        elapsed = monotonic_ms() - start;
        if (elapsed >= ms) {
            break;
        }
    }
    ASSERT_TRUE(elapsed >= ms);
}

/* Open descriptors, counted from /proc/self/fd. LeakSanitizer tracks
 * memory, not file descriptors: a client that freed every byte it
 * allocated and quietly dropped a local socket is indistinguishable, to
 * ASan and to every counter in this file, from a correct one. Returns -1
 * where /proc is absent, and every call site asserts that did not happen
 * -- a -1 == -1 comparison is how this check silently stopped working on
 * a previous branch. */
static int count_open_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) {
        return -1;
    }
    int n = 0;
    while (readdir(d) != NULL) {
        n++;
    }
    closedir(d);
    return n;
}

/* ---- the fake upstream: records everything, replies with it XORed ------- */

#define UP_MAX_CONNS 8
#define UP_BUF_CAP ((size_t)(1u << 20))

/* NOT an echo. See this file's header. */
#define UP_XOR ((uint8_t)0xFF)

typedef struct {
    int fd;
    uint8_t *in;
    size_t in_len;
    uint8_t *out;
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

static void up_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    up_slot_t *slot = userdata;
    upstream_t *up = slot->up;
    up_conn_t *c = &up->conns[slot->idx];

    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        up_flush(c);
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        for (;;) { /* edge-triggered: read until EAGAIN or the buffers fill */
            size_t room = UP_BUF_CAP - c->in_len;
            if (UP_BUF_CAP - c->out_len < room) {
                room = UP_BUF_CAP - c->out_len;
            }
            if (room == 0) {
                break;
            }
            ssize_t n = read(c->fd, c->in + c->in_len, room);
            if (n > 0) {
                for (ssize_t i = 0; i < n; i++) {
                    c->out[c->out_len + (size_t)i] =
                        (uint8_t)(c->in[c->in_len + (size_t)i] ^ UP_XOR);
                }
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
    (void)cloak_reactor_add_fd(up->reactor, fd, CLOAK_REACTOR_READABLE, up_on_event,
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

/* ---- the fake cover site: where an unrecognised handshake is sent ------- */

typedef struct {
    int fds[8];
    int count;
    int accept_count;
} cover_site_t;

static void cover_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    cover_site_t *cov = userdata;
    cov->accept_count++;
    if (cov->count >= (int)(sizeof(cov->fds) / sizeof(cov->fds[0]))) {
        close(fd);
        return;
    }
    cov->fds[cov->count++] = fd;
}

static void cover_destroy(cover_site_t *cov) {
    for (int i = 0; i < cov->count; i++) {
        close(cov->fds[i]);
    }
    cov->count = 0;
}

/* ---- the database the user manager sits on ------------------------------ */

static void db_tmp_path(char *buf, size_t cap) {
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(buf, cap, "%s/cloak_client_singleplex_%ld.db", dir, (long)getpid());
}

static void db_unlink(const char *path) {
    char aux[600];
    unlink(path);
    snprintf(aux, sizeof(aux), "%s-wal", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-shm", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-journal", path);
    unlink(aux);
}

#define PANEL_NOW 1600000000
static int64_t panel_now(void *userdata) {
    (void)userdata;
    return (int64_t)PANEL_NOW;
}

/* ---- the fixture: the whole merged server stack ------------------------- */

#define SX_WIRE ((size_t)16401)

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

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid[CLOAK_UID_LEN];

    size_t wire;
    int client_port;

    /* SESSIONS THE SERVER ACTUALLY CREATED, as opposed to connections it
     * accepted. This is the client-independent half of cases 1 and 4:
     * cloak_server_registry_count says how many are live NOW, and this
     * says how many were ever made, so a client that made two and lost
     * one cannot look like a client that made one. */
    int attached_calls;
    int attached_created;
};

static void fx_attached(cloak_dispatcher_t *d, cloak_session_t *sesh,
                        const cloak_server_clientinfo_t *info, int created, void *userdata) {
    (void)d;
    (void)sesh;
    (void)info;
    struct fixture *fx = userdata;
    fx->attached_calls++;
    fx->attached_created += created ? 1 : 0;
}

static void fx_session_closing(const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    cloak_proxy_session_aborted(NULL, uid, session_id, userdata);
}

static int fixture_init(struct fixture *fx) {
    memset(fx, 0, sizeof(*fx));
    fx->wire = SX_WIRE;
    char err[256] = {0};

    for (int i = 0; i < UP_MAX_CONNS; i++) {
        fx->up.conns[i].fd = -1;
    }

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

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
        fx->uid[i] = (uint8_t)(0x40 + i);
    }

    char priv_b64[64];
    char uid_b64[32];
    ASSERT_EQ_INT(
        0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64, sizeof(priv_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(fx->uid, CLOAK_UID_LEN, uid_b64, sizeof(uid_b64)));

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

    db_tmp_path(fx->db_path, sizeof(fx->db_path));
    db_unlink(fx->db_path);
    err[0] = '\0';
    ASSERT_EQ_INT(0,
                  cloak_usermanager_open(&fx->mgr, fx->db_path, panel_now, NULL, err, sizeof(err)));
    ASSERT_TRUE(fx->mgr != NULL);
    if (fx->mgr == NULL) {
        return -1;
    }

    ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor,
                                                cloak_proxy_registry_broken, &fx->proxy));
    fx->registry_ready = 1;

    cloak_userpanel_config_t upcfg;
    memset(&upcfg, 0, sizeof(upcfg));
    upcfg.manager = fx->mgr;
    upcfg.registry = &fx->registry;
    upcfg.reactor = fx->reactor;
    upcfg.upload_interval_ms = 3600000;
    upcfg.now_fn = panel_now;
    upcfg.on_session_closing = fx_session_closing;
    upcfg.on_session_closing_userdata = &fx->proxy;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&fx->panel, &upcfg));
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
    dcfg.session_config_template.max_on_wire_size = fx->wire;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = 262144;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;
    dcfg.prepare_session = cloak_proxy_prepare_session;
    dcfg.prepare_session_userdata = &fx->proxy;
    dcfg.attached = fx_attached;
    dcfg.attached_userdata = fx;
    dcfg.session_aborted = cloak_proxy_session_aborted;
    dcfg.session_aborted_userdata = &fx->proxy;
    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, fx->cfg.bind_addr[0],
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;
    fx->client_port = cloak_listener_port(&fx->front);
    return 0;
}

/* The shutdown order a binary must use: listener, dispatcher, PROXY
 * BEFORE REGISTRY, registry, panel, manager, server state. */
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
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
        fx->reactor = NULL;
    }
    if (fx->db_path[0] != '\0') {
        db_unlink(fx->db_path);
    }
}

struct registry_wait {
    struct fixture *fx;
    size_t want;
};

static int registry_count_is(void *ctx) {
    struct registry_wait *w = ctx;
    return cloak_server_registry_count(&w->fx->registry) == w->want;
}

/* ---- the local peer: the "application" the piper serves ------------------ */

#define LP_BUF_CAP ((size_t)(1u << 20))

typedef struct {
    cloak_reactor_t *reactor;
    cloak_dial_t dial;
    int dialing;
    int fd;
    int registered;
    int connected;
    int dial_failed;

    uint8_t *in;
    size_t in_len;
    uint8_t *out;
    size_t out_len;
    size_t out_head;
    int eof; /* the piper closed our side */
} local_peer_t;

static void lp_flush(local_peer_t *lp) {
    while (lp->out_head < lp->out_len) {
        ssize_t n = send(lp->fd, lp->out + lp->out_head, lp->out_len - lp->out_head, MSG_NOSIGNAL);
        if (n > 0) {
            lp->out_head += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (lp->out_head == lp->out_len) {
        lp->out_head = 0;
        lp->out_len = 0;
    }
}

static void lp_sync(local_peer_t *lp) {
    uint32_t ev = CLOAK_REACTOR_READABLE;
    if (lp->out_head < lp->out_len) {
        ev |= CLOAK_REACTOR_WRITABLE;
    }
    (void)cloak_reactor_mod_fd(lp->reactor, lp->fd, ev);
}

static void lp_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    local_peer_t *lp = userdata;
    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        lp_flush(lp);
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        for (;;) {
            if (lp->in_len >= LP_BUF_CAP) {
                break;
            }
            ssize_t n = read(lp->fd, lp->in + lp->in_len, LP_BUF_CAP - lp->in_len);
            if (n > 0) {
                lp->in_len += (size_t)n;
                continue;
            }
            if (n == 0) {
                lp->eof = 1;
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            break;
        }
    }
    lp_sync(lp);
}

static void lp_on_dial(cloak_dial_t *d, int fd, void *userdata) {
    (void)d;
    local_peer_t *lp = userdata;
    lp->dialing = 0;
    if (fd < 0) {
        lp->dial_failed = 1;
        return;
    }
    lp->fd = fd;
    if (cloak_reactor_add_fd(lp->reactor, fd, CLOAK_REACTOR_READABLE, lp_on_event, lp) != 0) {
        close(fd);
        lp->fd = -1;
        lp->dial_failed = 1;
        return;
    }
    lp->registered = 1;
    lp->connected = 1;
    lp_flush(lp);
    lp_sync(lp);
}

static int lp_connected(void *ctx) {
    local_peer_t *lp = ctx;
    return lp->connected || lp->dial_failed;
}

static int lp_open(local_peer_t *lp, cloak_reactor_t *r, int port) {
    memset(lp, 0, sizeof(*lp));
    lp->reactor = r;
    lp->fd = -1;
    lp->in = malloc(LP_BUF_CAP);
    lp->out = malloc(LP_BUF_CAP);
    if (lp->in == NULL || lp->out == NULL) {
        free(lp->in);
        free(lp->out);
        lp->in = NULL;
        lp->out = NULL;
        return -1;
    }
    char addr[64];
    char err[256];
    cloak_addr_t a;
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
    if (cloak_net_resolve(addr, 0, &a, err, sizeof(err)) != 0) {
        return -1;
    }
    if (cloak_dial_start(&lp->dial, r, &a, 5000, lp_on_dial, lp, err, sizeof(err)) != 0) {
        return -1;
    }
    lp->dialing = 1;
    return 0;
}

static void lp_send(local_peer_t *lp, const uint8_t *buf, size_t len) {
    ASSERT_TRUE(lp->out_len + len <= LP_BUF_CAP);
    memcpy(lp->out + lp->out_len, buf, len);
    lp->out_len += len;
    if (lp->connected) {
        lp_flush(lp);
        lp_sync(lp);
    }
}

/* The local application closing its own side of the connection. */
static void lp_shutdown(local_peer_t *lp) {
    if (lp->registered) {
        cloak_reactor_remove_fd(lp->reactor, lp->fd);
        lp->registered = 0;
    }
    if (lp->fd >= 0) {
        close(lp->fd);
        lp->fd = -1;
    }
}

static void lp_destroy(local_peer_t *lp) {
    if (lp->dialing) {
        cloak_dial_cancel(&lp->dial);
        lp->dialing = 0;
    }
    lp_shutdown(lp);
    free(lp->in);
    free(lp->out);
    lp->in = NULL;
    lp->out = NULL;
}

struct lp_wait {
    local_peer_t *lp;
    size_t want;
};

static int lp_has_len(void *ctx) {
    struct lp_wait *w = ctx;
    return w->lp->in_len >= w->want;
}

static int lp_at_eof(void *ctx) {
    local_peer_t *lp = ctx;
    return lp->eof != 0;
}

static void xor_fill(uint8_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = (uint8_t)(src[i] ^ UP_XOR);
    }
}

/* ---- the owner: what a singleplex ck-client would be -------------------- */

/* THE OWNER IS THE PART THE PIPER DOES NOT DO, and writing it here is
 * half the point of this file: cloak_client_piper_t never creates,
 * closes-and-reaps or destroys a session, so the contract it offers
 * (new_session / _conn_session_ready / _conn_session_failed /
 * cancel_session / chain) has to be usable by a plausible caller without
 * that caller having to know anything about the piper's internals. The
 * slot array below is exactly what ck-client will need. */

#define SX_MAX_SESSIONS 8

struct sx;

typedef struct {
    struct sx *owner;
    int in_use;

    /* The piper context this session is being brought up FOR, or NULL
     * once the piper has told us to forget it (cancel_session) or we have
     * already handed it over. Never dereferenced by this harness: it is
     * an opaque key and a callback argument, exactly as the header says. */
    cloak_client_piper_conn_t *ctx;

    cloak_client_connector_t c;
    int connector_ready;
    int held; /* case 5: initialised but deliberately not started yet */

    cloak_session_t sesh;
    int session_live;

    int result_calls;
    cloak_client_connector_status_t status;
    cloak_client_connector_error_t error;

    uint32_t session_id;

    /* THE PIPER'S STATE AT THE INSTANT THIS SESSION'S CHAIN RUNS, which
     * is the only moment at which "the relay bound to a dying session was
     * stopped in the window where that was still possible" is observable
     * at all. After on_broken returns the mux frees the session's streams
     * anyway and any relay dies of its own accord a turn later -- so a
     * piper that did NOTHING in on_broken still reaches a quiet end
     * state, and asserting only on that is a case whose green comes from
     * a path other than the one it names. The third field is the
     * SESSION's own count, and it is what distinguishes "the walk
     * RELEASED its stream" from "the walk dropped it and let the mux's
     * post-on_broken sweep reclaim it": both end at zero, only this is
     * zero BEFORE the sweep. */
    int broken_seen;
    size_t conns_at_broken;
    size_t streams_at_broken;
    size_t active_streams_at_broken;
} sx_sess_t;

typedef struct sx {
    struct fixture *fx;

    cloak_client_piper_t piper;
    int piper_ready;

    cloak_listener_t local;
    int have_local;
    int local_port;

    uint32_t base_session_id;

    /* Set before the accept that should observe it; each is consumed by
     * the next new_session call. */
    int fail_next;
    int hold_next;

    sx_sess_t sessions[SX_MAX_SESSIONS];

    int new_session_calls;
    int cancel_calls;
    int broken_calls;
    int sessions_up;
    int sessions_failed;
    int sessions_destroyed;
} sx_t;

static void sx_conn_done(cloak_client_connector_t *c, cloak_client_connector_status_t status,
                         cloak_session_t *session, void *userdata);

/* Builds and (optionally) starts one connector for one session. ONE
 * function for both modes, so the configuration cannot drift between
 * them -- the only thing that differs between a singleplex session and
 * the shared one is the session id and who asked for it. */
static int sx_start_session(sx_t *sx, sx_sess_t *s, int fail, int start_now);

static int sx_new_session(cloak_client_piper_conn_t *ctx, void *userdata) {
    sx_t *sx = userdata;
    sx->new_session_calls++;

    int idx = -1;
    for (int i = 0; i < SX_MAX_SESSIONS; i++) {
        if (!sx->sessions[i].in_use) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        return -1;
    }
    sx_sess_t *s = &sx->sessions[idx];
    memset(s, 0, sizeof(*s));
    s->owner = sx;
    s->in_use = 1;
    s->ctx = ctx;
    /* A FRESH SESSION ID PER SESSION, and this is not decoration: the
     * server's registry is keyed by (uid, session id), so two singleplex
     * sessions reusing one id would be ATTACHED TO EACH OTHER on the
     * server and case 1 would count one session for a reason that has
     * nothing to do with the mode flag. Go generates a random id per
     * MakeSession for the same reason. */
    s->session_id = sx->base_session_id + (uint32_t)sx->new_session_calls;

    int fail = sx->fail_next;
    int hold = sx->hold_next;
    sx->fail_next = 0;
    sx->hold_next = 0;
    if (sx_start_session(sx, s, fail, !hold) != 0) {
        s->in_use = 0;
        return -1;
    }
    s->held = hold;
    return 0;
}

static void sx_cancel_session(cloak_client_piper_conn_t *ctx, void *userdata) {
    sx_t *sx = userdata;
    sx->cancel_calls++;
    for (int i = 0; i < SX_MAX_SESSIONS; i++) {
        sx_sess_t *s = &sx->sessions[i];
        if (s->in_use && s->ctx == ctx) {
            s->ctx = NULL;
            if (s->connector_ready) {
                cloak_client_connector_destroy(&s->c);
                s->connector_ready = 0;
            }
            s->held = 0;
            s->in_use = 0;
            return;
        }
    }
}

/* cfg.chain: the owner's own bookkeeping, invoked AFTER the piper has
 * stopped every relay bound to this session. In singleplex this is where
 * a session is REAPED -- the piper only ever closes one. */
static void sx_on_broken(cloak_session_t *sesh, void *userdata) {
    sx_t *sx = userdata;
    sx->broken_calls++;
    for (int i = 0; i < SX_MAX_SESSIONS; i++) {
        sx_sess_t *s = &sx->sessions[i];
        if (s->session_live && &s->sesh == sesh) {
            s->broken_seen = 1;
            s->conns_at_broken = cloak_client_piper_conn_count(&sx->piper);
            s->streams_at_broken = cloak_client_piper_stream_count(&sx->piper);
            s->active_streams_at_broken = s->sesh.active_stream_count;
            cloak_session_destroy(&s->sesh);
            s->session_live = 0;
            s->ctx = NULL;
            s->in_use = 0;
            sx->sessions_destroyed++;
            return;
        }
    }
}

static void sx_conn_done(cloak_client_connector_t *c, cloak_client_connector_status_t status,
                         cloak_session_t *session, void *userdata) {
    sx_sess_t *s = userdata;
    sx_t *sx = s->owner;
    s->result_calls++;
    s->status = status;
    s->error = cloak_client_connector_error(c);

    /* Legal from inside on_done, and it never touches a session that has
     * been handed over (cloak/client_connector.h). */
    cloak_client_connector_destroy(c);
    s->connector_ready = 0;
    s->held = 0;

    if (status == CLOAK_CLIENT_CONNECTOR_DONE) {
        s->session_live = 1;
        sx->sessions_up++;
        if (s->ctx != NULL) {
            cloak_client_piper_conn_session_ready(s->ctx, session);
        }
        return;
    }

    sx->sessions_failed++;
    cloak_client_piper_conn_t *ctx = s->ctx;
    s->ctx = NULL;
    s->in_use = 0;
    if (ctx != NULL) {
        cloak_client_piper_conn_session_failed(ctx);
    }
}

static int sx_start_session(sx_t *sx, sx_sess_t *s, int fail, int start_now) {
    char addr[64];
    char err[256];
    cloak_client_connector_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", sx->fx->client_port);
    if (cloak_net_resolve(addr, 0, &cfg.remote, err, sizeof(err)) != 0) {
        return -1;
    }
    cfg.reactor = sx->fx->reactor;
    cfg.num_conn = 1;
    cfg.session = &s->sesh;
    cfg.browser = CLOAK_CLIENT_BROWSER_CHROME;
    cfg.transport = CLOAK_TRANSPORT_DIRECT;
    cfg.server_name = "www.example.com";
    memcpy(cfg.server_pub, sx->fx->server_pub, CLOAK_X25519_KEY_LEN);
    if (fail) {
        memset(cfg.server_pub, 0xAB, CLOAK_X25519_KEY_LEN);
    }
    memcpy(cfg.uid, sx->fx->uid, CLOAK_UID_LEN);
    cfg.proxy_method = "ss";
    cfg.encryption_method = (uint8_t)CLOAK_AEAD_AES_256_GCM;
    cfg.session_id = s->session_id;
    cfg.dial_timeout_ms = 5000;
    cfg.handshake_timeout_ms = fail ? 400 : 10000;
    cfg.max_attempts = fail ? 1 : 0;
    cfg.session_template.max_on_wire_size = sx->fx->wire;
    cfg.session_template.stream_recv_capacity = 65536;
    cfg.session_template.stream_max_pending_frames = 64;
    cfg.session_template.conn_send_queue_cap = 262144;
    cfg.session_template.inactivity_timeout_ms = 60000;
    cfg.on_done = sx_conn_done;
    cfg.on_done_userdata = s;

    cloak_client_piper_install(&sx->piper, &cfg.session_template);

    if (cloak_client_connector_init(&s->c, &cfg) != 0) {
        return -1;
    }
    s->connector_ready = 1;
    if (start_now && cloak_client_connector_start(&s->c) != 0) {
        cloak_client_connector_destroy(&s->c);
        s->connector_ready = 0;
        return -1;
    }
    return 0;
}

/* Starts every connector that was held back. */
static void sx_release_held(sx_t *sx) {
    for (int i = 0; i < SX_MAX_SESSIONS; i++) {
        sx_sess_t *s = &sx->sessions[i];
        if (s->in_use && s->held && s->connector_ready) {
            s->held = 0;
            ASSERT_EQ_INT(0, cloak_client_connector_start(&s->c));
        }
    }
}

/* Brings up the client. In singleplex nothing is dialled here at all --
 * the first session is brought up by the first local connection's first
 * byte. Without it, one shared session is brought up now and handed to
 * the piper, which is the Task 2 wiring unchanged. */
static int sx_up(sx_t *sx, struct fixture *fx, int singleplex, uint32_t base_session_id,
                 const cloak_client_piper_config_t *pcfg_in) {
    memset(sx, 0, sizeof(*sx));
    sx->fx = fx;
    sx->base_session_id = base_session_id;

    cloak_client_piper_config_t pcfg = *pcfg_in;
    pcfg.reactor = fx->reactor;
    pcfg.chain = sx_on_broken;
    pcfg.chain_userdata = sx;
    pcfg.singleplex = singleplex;
    pcfg.new_session = sx_new_session;
    pcfg.cancel_session = sx_cancel_session;
    pcfg.session_userdata = sx;
    ASSERT_EQ_INT(0, cloak_client_piper_init(&sx->piper, &pcfg));
    sx->piper_ready = 1;

    if (!singleplex) {
        sx_sess_t *s = &sx->sessions[0];
        memset(s, 0, sizeof(*s));
        s->owner = sx;
        s->in_use = 1;
        s->ctx = NULL;
        s->session_id = base_session_id;
        ASSERT_EQ_INT(0, sx_start_session(sx, s, 0, 1));
        for (int i = 0; i < SX_MAX_TURNS && s->result_calls == 0; i++) {
            cloak_reactor_run_once(fx->reactor, SX_TURN_MS);
        }
        ASSERT_EQ_INT(1, s->result_calls);
        ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_DONE, (int)s->status);
        if (s->status != CLOAK_CLIENT_CONNECTOR_DONE) {
            return -1;
        }
        cloak_client_piper_set_session(&sx->piper, &s->sesh);
    }

    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_listener_open(&sx->local, fx->reactor, "127.0.0.1:0",
                                         cloak_client_piper_on_accept, &sx->piper, err,
                                         sizeof(err)));
    sx->have_local = 1;
    sx->local_port = cloak_listener_port(&sx->local);
    ASSERT_TRUE(sx->local_port > 0);
    return 0;
}

/* The shutdown order a client binary must use: local listener, PIPER
 * BEFORE ANY SESSION (cloak/stream_relay.h), then every session this
 * owner still holds, then any connector still in flight. */
static void sx_down(sx_t *sx) {
    if (sx->have_local) {
        cloak_listener_close(&sx->local);
        sx->have_local = 0;
    }
    if (sx->piper_ready) {
        cloak_client_piper_destroy(&sx->piper);
        sx->piper_ready = 0;
    }
    for (int i = 0; i < SX_MAX_SESSIONS; i++) {
        sx_sess_t *s = &sx->sessions[i];
        if (s->session_live) {
            cloak_session_destroy(&s->sesh);
            s->session_live = 0;
        }
        if (s->connector_ready) {
            cloak_client_connector_destroy(&s->c);
            s->connector_ready = 0;
        }
        s->in_use = 0;
        s->ctx = NULL;
    }
}

struct sx_int_wait {
    const int *p;
    int want;
};

static int sx_int_is(void *ctx) {
    struct sx_int_wait *w = ctx;
    return *w->p == w->want;
}

struct piper_wait {
    cloak_client_piper_t *pp;
    size_t want;
};

static int piper_conns_are(void *ctx) {
    struct piper_wait *w = ctx;
    return cloak_client_piper_conn_count(w->pp) == w->want;
}

/* Connects one local peer, sends its payload, and waits for the XORed
 * reply -- the whole round trip, which is the only thing that proves a
 * session actually carried bytes. */
static void sx_round_trip(struct fixture *fx, local_peer_t *lp, const uint8_t *payload,
                          size_t len) {
    lp_send(lp, payload, len);
    struct lp_wait w = {lp, len};
    ASSERT_TRUE(pump_until(fx->reactor, lp_has_len, &w, SX_MAX_TURNS, SX_TURN_MS));
    uint8_t want[2048];
    ASSERT_TRUE(len <= sizeof(want));
    xor_fill(want, payload, len);
    ASSERT_EQ_INT((int)len, (int)lp->in_len);
    ASSERT_MEM_EQ(lp->in, want, len);
    lp->in_len = 0;
}

/* ---- case 1: singleplex gives each connection its OWN session ----------- */

#define SID_SPLEX ((uint32_t)7101)

static void test_singleplex_gives_each_connection_its_own_session(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    sx_t sx;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, sx_up(&sx, &fx, 1, SID_SPLEX, &pcfg));

    /* NOTHING HAS BEEN DIALLED YET, which is the first half of what
     * singleplex means: a client with no local connections holds no
     * session and has spent no handshake. */
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(0, sx.new_session_calls);

    local_peer_t a;
    local_peer_t b;
    ASSERT_EQ_INT(0, lp_open(&a, fx.reactor, sx.local_port));
    ASSERT_EQ_INT(0, lp_open(&b, fx.reactor, sx.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &a, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &b, SX_MAX_TURNS, SX_TURN_MS));

    uint8_t pa[301];
    uint8_t pb[457];
    for (size_t i = 0; i < sizeof(pa); i++) {
        pa[i] = (uint8_t)(0x11 + (i * 7u));
    }
    for (size_t i = 0; i < sizeof(pb); i++) {
        pb[i] = (uint8_t)(0x83 + (i * 13u));
    }

    /* DIFFERENT PAYLOADS: a crossed route passes a two-peer test whose
     * peers send the same bytes. Each peer asserts it got ITS OWN payload
     * back transformed. */
    sx_round_trip(&fx, &a, pa, sizeof(pa));
    sx_round_trip(&fx, &b, pb, sizeof(pb));

    /* THE ASSERTION THIS CASE EXISTS FOR, read off the SERVER. Two local
     * connections, two sessions in the server's registry -- not one
     * session with two streams. Its inverse is case 4. */
    struct registry_wait rw = {&fx, 2};
    ASSERT_TRUE(pump_until(fx.reactor, registry_count_is, &rw, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_EQ_INT(2, (int)cloak_server_registry_count(&fx.registry));
    /* And two were CREATED, not one created and one re-attached: a second
     * connection joining the first session would leave this at 1. */
    ASSERT_EQ_INT(2, fx.attached_created);

    /* The client's own view of the same fact, which is what a mode flag
     * that was never read would leave at 0. */
    ASSERT_EQ_INT(2, sx.new_session_calls);
    ASSERT_EQ_INT(2, sx.sessions_up);
    ASSERT_EQ_INT(2, (int)cloak_client_piper_sessions_started(&sx.piper));

    /* One stream per session, not two on either. */
    ASSERT_EQ_INT(2, (int)cloak_client_piper_stream_count(&sx.piper));
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(2, fx.up.accept_count);

    lp_destroy(&a);
    lp_destroy(&b);
    sx_down(&sx);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 2: each session dies with its OWN connection ------------------ */

#define SID_DIES ((uint32_t)7201)

static void test_each_session_dies_with_its_own_connection(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    sx_t sx;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, sx_up(&sx, &fx, 1, SID_DIES, &pcfg));

    local_peer_t a;
    local_peer_t b;
    ASSERT_EQ_INT(0, lp_open(&a, fx.reactor, sx.local_port));
    ASSERT_EQ_INT(0, lp_open(&b, fx.reactor, sx.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &a, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &b, SX_MAX_TURNS, SX_TURN_MS));

    static const uint8_t pa[] = {0xA0, 0xA1, 0xA2, 0xA3};
    static const uint8_t pb[] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4};
    sx_round_trip(&fx, &a, pa, sizeof(pa));
    sx_round_trip(&fx, &b, pb, sizeof(pb));

    struct registry_wait rw = {&fx, 2};
    ASSERT_TRUE(pump_until(fx.reactor, registry_count_is, &rw, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_EQ_INT(0, sx.sessions_destroyed);

    /* A closes. Its session must go with it -- Go's `sesh.Close()` in the
     * singleplex branch of RouteTCP -- and B's must not. */
    lp_shutdown(&a);

    struct sx_int_wait dw = {&sx.sessions_destroyed, 1};
    ASSERT_TRUE(pump_until(fx.reactor, sx_int_is, &dw, SX_MAX_TURNS, SX_TURN_MS));
    /* THE SESSION WAS CLOSED BY THE PIPER, not merely abandoned: the only
     * route to sessions_destroyed is the chain callback, which only runs
     * because on_broken fired, which only happens because something
     * closed the session. A piper that dropped the context and left the
     * session running leaves this at 0 forever. */
    ASSERT_EQ_INT(1, sx.sessions_destroyed);

    rw.want = 1;
    ASSERT_TRUE(pump_until(fx.reactor, registry_count_is, &rw, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    struct piper_wait pw = {&sx.piper, 1};
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&sx.piper));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_stream_count(&sx.piper));

    /* B IS UNDISTURBED, and this is the half that a teardown walking every
     * context on every broken session would fail. */
    static const uint8_t pb2[] = {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6};
    sx_round_trip(&fx, &b, pb2, sizeof(pb2));
    ASSERT_EQ_INT(0, b.eof);

    lp_destroy(&a);
    lp_destroy(&b);
    sx_down(&sx);
    fixture_destroy(&fx);
}

/* ---- case 3: a session that never comes up kills only its own peer ------ */

#define SID_FAIL ((uint32_t)7301)

static void test_a_failing_session_closes_only_its_own_connection(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    sx_t sx;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, sx_up(&sx, &fx, 1, SID_FAIL, &pcfg));

    local_peer_t good;
    ASSERT_EQ_INT(0, lp_open(&good, fx.reactor, sx.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &good, SX_MAX_TURNS, SX_TURN_MS));
    static const uint8_t pg[] = {0x31, 0x41, 0x59, 0x26};
    sx_round_trip(&fx, &good, pg, sizeof(pg));

    struct registry_wait rw = {&fx, 1};
    ASSERT_TRUE(pump_until(fx.reactor, registry_count_is, &rw, SX_MAX_TURNS, SX_TURN_MS));

    /* The NEXT session to be requested cannot succeed. */
    sx.fail_next = 1;

    local_peer_t doomed;
    ASSERT_EQ_INT(0, lp_open(&doomed, fx.reactor, sx.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &doomed, SX_MAX_TURNS, SX_TURN_MS));
    static const uint8_t pd[] = {0x77};
    lp_send(&doomed, pd, sizeof(pd));

    struct sx_int_wait fw = {&sx.sessions_failed, 1};
    ASSERT_TRUE(pump_until(fx.reactor, sx_int_is, &fw, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_EQ_INT(2, sx.new_session_calls);
    /* IT FAILED FOR THE REASON THIS CASE NAMES -- a handshake that never
     * completed -- and not because the dial was refused or the config was
     * rejected, either of which would exercise a different path. */
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_ERR_HANDSHAKE, (int)sx.sessions[1].error);

    /* The doomed local connection is closed CLEANLY: the application
     * learns, rather than hanging on a tunnel that will never come up. */
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &doomed, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_EQ_INT(1, doomed.eof);

    struct piper_wait pw = {&sx.piper, 1};
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&sx.piper));

    /* AND THE OTHER CONNECTION IS UNTOUCHED -- still exactly one session
     * on the server, and it still carries bytes. */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    static const uint8_t pg2[] = {0x53, 0x58, 0x97, 0x93, 0x23};
    sx_round_trip(&fx, &good, pg2, sizeof(pg2));
    ASSERT_EQ_INT(0, good.eof);

    lp_destroy(&good);
    lp_destroy(&doomed);
    sx_down(&sx);
    fixture_destroy(&fx);
}

/* ---- case 4: WITHOUT singleplex, one session is shared ------------------ */

#define SID_SHARED ((uint32_t)7401)

/* THE EXACT INVERSE OF CASE 1, written as its pair. Same fixture, same
 * two peers, same payload shape; only the flag differs. A piper that read
 * the flag and ignored it, or never read it, fails one of the two:
 *
 *   flag always OFF  -> case 1 finds 0 sessions (nothing ever dialled,
 *                       every accept refused for want of a session).
 *   flag always ON   -> case 4 finds 3 sessions (the shared one plus one
 *                       per local connection).
 */
static void test_without_singleplex_two_connections_share_one_session(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    sx_t sx;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, sx_up(&sx, &fx, 0, SID_SHARED, &pcfg));

    /* One session exists before any local connection does -- the whole
     * difference from case 1's starting state. */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    local_peer_t a;
    local_peer_t b;
    ASSERT_EQ_INT(0, lp_open(&a, fx.reactor, sx.local_port));
    ASSERT_EQ_INT(0, lp_open(&b, fx.reactor, sx.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &a, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &b, SX_MAX_TURNS, SX_TURN_MS));

    uint8_t pa[301];
    uint8_t pb[457];
    for (size_t i = 0; i < sizeof(pa); i++) {
        pa[i] = (uint8_t)(0x11 + (i * 7u));
    }
    for (size_t i = 0; i < sizeof(pb); i++) {
        pb[i] = (uint8_t)(0x83 + (i * 13u));
    }
    sx_round_trip(&fx, &a, pa, sizeof(pa));
    sx_round_trip(&fx, &b, pb, sizeof(pb));

    /* THE INVERSE ASSERTION. Two local connections, ONE session, two
     * streams on it. */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(1, fx.attached_created);
    ASSERT_EQ_INT(0, sx.new_session_calls);
    ASSERT_EQ_INT(0, (int)cloak_client_piper_sessions_started(&sx.piper));

    ASSERT_EQ_INT(2, (int)cloak_client_piper_stream_count(&sx.piper));
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(2, fx.up.accept_count);

    lp_destroy(&a);
    lp_destroy(&b);
    sx_down(&sx);
    fixture_destroy(&fx);
}

/* ---- case 5: what a connection does while its session handshakes -------- */

#define SID_WAIT ((uint32_t)7501)

/* THE DECISION THIS CASE PINS (see cloak/client_piper.h): a local
 * connection whose own session is still being brought up holds its
 * descriptor and NOTHING ELSE -- no stream, no bytes copied out of the
 * socket, nothing on the server. The unread bytes stay in the kernel's
 * own receive buffer, which is fixed-size and backpressures the local
 * application, rather than in a buffer this module would have to grow.
 *
 * The bring-up is HELD OPEN by the harness rather than raced against,
 * because the connector's retry ladder means a real handshake can
 * legitimately take seconds and a test that tried to observe the window
 * by timing would be a flake generator. */
static void test_a_connection_waiting_for_its_session_pins_nothing(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    sx_t sx;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, sx_up(&sx, &fx, 1, SID_WAIT, &pcfg));
    sx.hold_next = 1;

    local_peer_t p;
    ASSERT_EQ_INT(0, lp_open(&p, fx.reactor, sx.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &p, SX_MAX_TURNS, SX_TURN_MS));

    struct piper_wait pw = {&sx.piper, 1};
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw, SX_MAX_TURNS, SX_TURN_MS));

    /* NO SESSION IS REQUESTED FOR A CONNECTION THAT HAS SAID NOTHING --
     * D6's saving extended to the handshake, which in singleplex is by
     * far the larger of the two. A port scanner costs a descriptor, not a
     * dial, a TLS-shaped ClientHello and a server session. */
    for (int i = 0; i < 50; i++) {
        cloak_reactor_run_once(fx.reactor, SX_TURN_MS);
    }
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&sx.piper));
    ASSERT_EQ_INT(0, sx.new_session_calls);
    ASSERT_EQ_INT(0, (int)cloak_client_piper_sessions_started(&sx.piper));

    uint8_t payload[1200];
    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(0x05 + (i * 29u));
    }
    lp_send(&p, payload, sizeof(payload));

    struct sx_int_wait nw = {&sx.new_session_calls, 1};
    ASSERT_TRUE(pump_until(fx.reactor, sx_int_is, &nw, SX_MAX_TURNS, SX_TURN_MS));

    /* THE WINDOW. The bring-up is held; pump anyway so that anything the
     * piper WOULD do while waiting has had many turns to do it. */
    for (int i = 0; i < 100; i++) {
        cloak_reactor_run_once(fx.reactor, SX_TURN_MS);
    }
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&sx.piper));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_stream_count(&sx.piper));
    /* THE BOUND, MADE ASSERTABLE: zero local bytes are held by the piper
     * while a handshake runs. An implementation that buffered the first
     * read up front -- the obvious alternative, and the one the brief
     * warns can pin an unbounded amount -- reads non-zero here. */
    ASSERT_EQ_INT(0, (int)cloak_client_piper_buffered_bytes(&sx.piper));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(0, fx.up.accept_count);
    /* The application is not told anything yet: it is waiting, not
     * refused. */
    ASSERT_EQ_INT(0, p.eof);

    /* Released, the connection completes normally -- and the bytes it
     * sent BEFORE its session existed are the ones that arrive. */
    sx_release_held(&sx);
    struct lp_wait lw = {&p, sizeof(payload)};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &lw, SX_MAX_TURNS, SX_TURN_MS));
    uint8_t want[sizeof(payload)];
    xor_fill(want, payload, sizeof(payload));
    ASSERT_EQ_INT((int)sizeof(payload), (int)p.in_len);
    ASSERT_MEM_EQ(p.in, want, sizeof(payload));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    lp_destroy(&p);
    sx_down(&sx);
    fixture_destroy(&fx);
}

/* ---- case 6: the deadline covers the session wait too ------------------- */

#define SID_DEADLINE ((uint32_t)7601)

/* A BOUNDARY, ASSERTED ON BOTH SIDES OF IT. The first-byte deadline is
 * NOT cancelled when the first byte arrives in singleplex mode -- it is
 * cancelled when a stream is actually opened -- so it is also the bound
 * on how long an owner's session bring-up may pin a local connection.
 * That is the time half of the answer case 5 gives for the data half.
 *
 * Asserting only "it eventually dies" would pass against a piper that
 * killed the connection the instant its session was requested, which
 * would make singleplex unusable (a real handshake takes a dial, a
 * ClientHello and a reply, and the connector's retry ladder means seconds
 * are legitimate). Asserting only "it survives" would pass against a
 * piper that cancelled the deadline and pinned the connection forever.
 *
 * The numbers are chosen for margin: alive at 850 ms of a 1000 ms
 * deadline and dead after a further 300 ms, both ~150 ms clear, which is
 * far above any plausible timer jitter. The clock starts slightly AFTER
 * the accept that armed the deadline, which only tightens the first
 * bound and loosens the second. */
#define WAIT_DEADLINE_MS ((uint64_t)1000)
#define WAIT_ALIVE_AT_MS ((uint64_t)850)
#define WAIT_DEAD_AFTER_MS ((uint64_t)300)

static void test_the_deadline_bounds_the_session_wait(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    sx_t sx;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.first_byte_timeout_ms = WAIT_DEADLINE_MS;
    ASSERT_EQ_INT(0, sx_up(&sx, &fx, 1, SID_DEADLINE, &pcfg));
    sx.hold_next = 1;

    local_peer_t p;
    ASSERT_EQ_INT(0, lp_open(&p, fx.reactor, sx.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &p, SX_MAX_TURNS, SX_TURN_MS));
    static const uint8_t one[] = {0x5A};
    lp_send(&p, one, sizeof(one));

    struct sx_int_wait nw = {&sx.new_session_calls, 1};
    ASSERT_TRUE(pump_until(fx.reactor, sx_int_is, &nw, SX_MAX_TURNS, SX_TURN_MS));

    /* SIDE ONE: still waiting at 85% of the deadline. */
    pump_for_ms(fx.reactor, WAIT_ALIVE_AT_MS);
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&sx.piper));
    ASSERT_EQ_INT(0, sx.cancel_calls);
    ASSERT_EQ_INT(0, p.eof);

    /* SIDE TWO: past it. The context is gone, the owner is told to
     * abandon the bring-up it still has in flight, and the application
     * learns rather than hanging. */
    pump_for_ms(fx.reactor, WAIT_DEAD_AFTER_MS);

    struct piper_wait pw = {&sx.piper, 0};
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_conn_count(&sx.piper));
    ASSERT_EQ_INT(1, sx.cancel_calls);
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &p, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_EQ_INT(1, p.eof);
    /* Nothing was ever opened on the server, because no session was ever
     * completed. */
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(0, fx.up.accept_count);

    lp_destroy(&p);
    sx_down(&sx);
    fixture_destroy(&fx);
}

/* ---- case 7: the configuration contract -------------------------------- */

static void test_singleplex_config_contracts(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_client_piper_t pp;
    cloak_client_piper_config_t cfg;

    /* singleplex with no new_session is rejected at init rather than at
     * the first accept, where the only available answer would be to drop
     * a connection the application believes is live. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.reactor = r;
    cfg.singleplex = 1;
    ASSERT_EQ_INT(-1, cloak_client_piper_init(&pp, &cfg));
    /* And a rejected init still leaves pp safe to destroy. */
    cloak_client_piper_destroy(&pp);

    memset(&cfg, 0, sizeof(cfg));
    cfg.reactor = r;
    cfg.singleplex = 1;
    cfg.new_session = sx_new_session;
    ASSERT_EQ_INT(0, cloak_client_piper_init(&pp, &cfg));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_sessions_started(&pp));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_buffered_bytes(&pp));
    cloak_client_piper_destroy(&pp);

    /* The accessors are NULL-safe, as every other one in this module is. */
    ASSERT_EQ_INT(0, (int)cloak_client_piper_sessions_started(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_buffered_bytes(NULL));
    /* And so are the two completion entry points. */
    cloak_client_piper_conn_session_ready(NULL, NULL);
    cloak_client_piper_conn_session_failed(NULL);

    cloak_reactor_destroy(r);
}

/* ---- case 8: a session that DIES UNDER its own connection -------------- */

#define SID_KILL ((uint32_t)7801)

/* THE CASE THE TEARDOWN WAS WRITTEN FOR AND NEVER EXERCISED UNTIL NOW: a
 * session that genuinely dies UNDER a live context, rather than because
 * that context ended. In shared mode the only way to reach it is to kill
 * the whole client's tunnel; in singleplex it is one connection's own
 * session dying while other connections carry on, which is both the
 * ordinary case and the one where a whole-list teardown would be
 * catastrophic.
 *
 * WHAT THIS CASE KILLS, AND WHY NOT THE OBVIOUS THING. Tearing the
 * session down from the SERVER (cloak_proxy_session_aborted +
 * cloak_server_registry_close) looks like the realistic way to do it and
 * MEASURES NOTHING: the proxy's own teardown closes its stream first, so
 * the client's relay learns through an ordinary closing-stream frame and
 * the context is gone through the normal path a turn BEFORE on_broken
 * ever runs. Every assertion below then holds against a piper that does
 * nothing at all in on_broken -- which is precisely what happened here,
 * and both mutations escaped until it was fixed.
 *
 * A session-level death with no per-stream notice is the only thing that
 * reaches the window, and cloak_session_close is it: it marks the session
 * closed, enqueues ONE session-level frame, and defers everything else,
 * so the relay is still live and still bound when on_broken fires. That
 * is the same event an inactivity timeout or a failing underlying
 * connection produces, arriving on demand. */
static void test_a_dying_session_leaves_the_other_alone(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    sx_t sx;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, sx_up(&sx, &fx, 1, SID_KILL, &pcfg));

    local_peer_t a;
    local_peer_t b;
    ASSERT_EQ_INT(0, lp_open(&a, fx.reactor, sx.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &a, SX_MAX_TURNS, SX_TURN_MS));
    static const uint8_t pa[] = {0x10, 0x20, 0x30};
    sx_round_trip(&fx, &a, pa, sizeof(pa));

    ASSERT_EQ_INT(0, lp_open(&b, fx.reactor, sx.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &b, SX_MAX_TURNS, SX_TURN_MS));
    static const uint8_t pb[] = {0x40, 0x50, 0x60, 0x70};
    sx_round_trip(&fx, &b, pb, sizeof(pb));

    struct registry_wait rw = {&fx, 2};
    ASSERT_TRUE(pump_until(fx.reactor, registry_count_is, &rw, SX_MAX_TURNS, SX_TURN_MS));
    /* Slot 0 is A's: it asked first, and sx_new_session numbers session
     * ids from base + 1 in call order. */
    ASSERT_EQ_INT((int)(SID_KILL + 1), (int)sx.sessions[0].session_id);
    ASSERT_EQ_INT(2, (int)cloak_client_piper_stream_count(&sx.piper));

    /* Both relays are IDLE here, deliberately: a relay with bytes in
     * flight self-destructs the moment its session's pool empties, which
     * would leave nothing for the assertions below to observe -- the
     * precise way this shape of case escaped once already on this branch. */
    ASSERT_EQ_INT(0, cloak_session_close(&sx.sessions[0].sesh));

    struct sx_int_wait dw = {&sx.sessions_destroyed, 1};
    ASSERT_TRUE(pump_until(fx.reactor, sx_int_is, &dw, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_EQ_INT(1, sx.sessions[0].broken_seen);

    /* THE WINDOW ITSELF. At the instant A's chain ran: A's context was
     * already gone (one context left, B's), A's stream was already gone
     * (one stream left, B's), and -- the assertion that separates
     * RELEASED from merely dropped -- A's session considered zero streams
     * still active, which is only true if the walk released it while the
     * session was still usable. */
    ASSERT_EQ_INT(1, (int)sx.sessions[0].conns_at_broken);
    ASSERT_EQ_INT(1, (int)sx.sessions[0].streams_at_broken);
    ASSERT_EQ_INT(0, (int)sx.sessions[0].active_streams_at_broken);

    /* A's application learns. */
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &a, SX_MAX_TURNS, SX_TURN_MS));
    ASSERT_EQ_INT(1, a.eof);

    /* AND B IS UNTOUCHED -- same session, same stream, still carrying
     * bytes. This is the half a whole-list teardown walk fails. */
    static const uint8_t pb2[] = {0x81, 0x82, 0x83, 0x84, 0x85};
    sx_round_trip(&fx, &b, pb2, sizeof(pb2));
    ASSERT_EQ_INT(0, b.eof);
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&sx.piper));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_stream_count(&sx.piper));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    lp_destroy(&a);
    lp_destroy(&b);
    sx_down(&sx);
    fixture_destroy(&fx);
}

TEST_MAIN_BEGIN()
test_singleplex_gives_each_connection_its_own_session();
test_each_session_dies_with_its_own_connection();
test_a_failing_session_closes_only_its_own_connection();
test_without_singleplex_two_connections_share_one_session();
test_a_connection_waiting_for_its_session_pins_nothing();
test_the_deadline_bounds_the_session_wait();
test_a_dying_session_leaves_the_other_alone();
test_singleplex_config_contracts();
TEST_MAIN_END()
