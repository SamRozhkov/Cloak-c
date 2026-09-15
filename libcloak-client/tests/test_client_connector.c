#define _POSIX_C_SOURCE 200809L

/* N HANDSHAKES INTO ONE SESSION, against the real merged server.
 *
 * cloak_client_connector_t is the first object in this tree that owns
 * several concurrent handshakes at once, so the things worth testing are
 * not "does a handshake work" (test_client_transport.c and
 * test_client_e2e.c already own that question) but the things that only
 * exist because there are N of them and a retry loop around each:
 *
 *   - N connections really do end up attached to ONE session, asserted on
 *     the SERVER's own switchboard rather than on the client's belief
 *     about what it sent. A client that opened four sockets, handshook
 *     four times and attached one of them to its session would satisfy
 *     every client-side counter; only cloak_switchboard_conn_count on the
 *     server's cloak_session_t separates it from a correct one.
 *   - The retry actually RETRIES, asserted with a counter on both sides
 *     (the gate's accept count and the connector's own attempt count).
 *     "The session came up in the end" is satisfied just as well by an
 *     implementation with no retry at all, against a server that never
 *     refused anything -- a test whose green comes from a path other than
 *     the one it names, which is a defect shape this project has paid for
 *     six times.
 *   - D4's key check FAILS THE SESSION on a disagreement, and -- the
 *     other side of the boundary -- does NOT fail it when the same seam
 *     is installed and corrupts nothing. A one-sided boundary test is the
 *     sharper variant of the same defect, and one such gap in this
 *     project hid a remotely triggerable heap overflow.
 *   - Teardown at three distinct points mid-flight, which is where every
 *     previous module in this project found its worst bug. Run under ASan
 *     as well as Debug; the plain build sees almost none of it.
 *
 * THE GATE. Three of these cases need a server that misbehaves on
 * schedule -- refuses the first connection, or accepts a connection and
 * then never answers. gate_t is a tiny TCP front for the real server: it
 * listens, and per accepted connection either closes it at once (refuse),
 * holds it open forever without forwarding a byte (stall), or splices it
 * to the real dispatcher with cloak_relay_t. Everything the client sees
 * through a forwarding gate is the real server's bytes, so the "it
 * retried and then succeeded" case is a genuine end-to-end success, not a
 * scripted imitation of one.
 *
 * EVERY WAIT IS A BOUNDED pump_until, the discipline every reactor test
 * in this tree states. */

#include "cloak/base64.h"
#include "cloak/client_connector.h"
#include "cloak/conn.h"
#include "cloak/crypto.h"
#include "cloak/dispatcher.h"
#include "cloak/net.h"
#include "cloak/proxy.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/session.h"
#include "cloak/switchboard.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
#include "test_framework.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---- bounded reactor pumping ------------------------------------------- */

/* Sized so that a BROKEN run fails an ASSERTION rather than the ctest
 * timeout, the same reasoning test_client_e2e.c states: at
 * CONN_MAX_TURNS turns of CONN_TURN_MS each, one wait is at most ~1 s,
 * and the ~20 waits in this file total well under this test's TIMEOUT 60.
 * Measured, every wait here settles in a few dozen turns on loopback. */
#define CONN_MAX_TURNS 1000
#define CONN_TURN_MS 1

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

/* Pumps the reactor for at least `ms` of REAL time, and asserts that it
 * really did -- the named duration is the whole point of the call, so a
 * loop that exited early would silently turn the checks that follow into
 * nothing.
 *
 * WHY THE TEARDOWN CASES NEED THIS RATHER THAN A TURN COUNT. A connector
 * torn down mid-flight is holding two kinds of reactor state: fd
 * registrations, which stop mattering the moment the fd is closed, and
 * TIMERS -- each in-flight dial's timeout and each in-flight handshake's
 * deadline -- which do not. A teardown that forgot to cancel them leaves
 * the reactor holding callbacks into the connector's freed
 * per-connection array, and the only thing that reveals it is letting
 * those deadlines actually arrive. A fixed number of one-millisecond
 * turns does not reliably do that; wall-clock time does. */
static void pump_for_ms(cloak_reactor_t *r, uint64_t ms) {
    uint64_t start = monotonic_ms();
    uint64_t elapsed = 0;
    uint64_t cap = ms * 100u + 100000u; /* an iteration ceiling, never the exit condition */
    for (uint64_t i = 0; i < cap; i++) {
        cloak_reactor_run_once(r, 1);
        elapsed = monotonic_ms() - start;
        if (elapsed >= ms) {
            break;
        }
    }
    ASSERT_TRUE(elapsed >= ms);
}

/* Open descriptors, counted from /proc/self/fd.
 *
 * WHY A TEARDOWN TEST NEEDS THIS. LeakSanitizer tracks memory, not file
 * descriptors: a connector that freed every byte it allocated and quietly
 * dropped four sockets is indistinguishable, to ASan and to every
 * counter in this file, from a correct one -- and it is exactly the bug a
 * mid-flight teardown produces, because the fd's owner changes three
 * times (dial, then connector, then session) as one connection
 * progresses. Compared around a whole sub-case, this is a direct
 * assertion that the connector closed every socket it opened. The
 * DIR handle itself is open during the count, so the bias is identical in
 * both measurements and cancels. */
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

/* ---- the fake upstream the server proxies to --------------------------- */

#define UP_MAX_CONNS 8

typedef struct {
    cloak_reactor_t *reactor;
    int accept_count;
    int fds[UP_MAX_CONNS];
    int nfds;
} upstream_t;

static void up_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    upstream_t *up = userdata;
    up->accept_count++;
    if (up->nfds >= UP_MAX_CONNS) {
        close(fd);
        return;
    }
    up->fds[up->nfds++] = fd;
}

static void up_destroy(upstream_t *up) {
    for (int i = 0; i < up->nfds; i++) {
        close(up->fds[i]);
    }
    up->nfds = 0;
}

/* ---- the fake cover site: nothing here should ever reach it ------------- */

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
    snprintf(buf, cap, "%s/cloak_client_connector_%ld.db", dir, (long)getpid());
}

/* WAL leaves sidecars; a survivor would carry a previous run's committed
 * state into this one. */
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

/* The panel's clock, deliberately fixed: its expiry arithmetic must not
 * be one CI scheduling hiccup away from a different answer. NOT the clock
 * the handshake is timestamped against -- that one is real, because
 * cloak_server_auth_decrypt checks it against time(NULL). */
#define PANEL_NOW 1600000000
static int64_t panel_now(void *userdata) {
    (void)userdata;
    return (int64_t)PANEL_NOW;
}

/* ---- the fixture: the whole merged server stack ------------------------- */

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

/* cloak/userpanel.h's WIRING obligation 1: cloak_userpanel_terminate closes
 * sessions through a path that fires no on_broken, so on_session_closing is
 * the window in which relays must be stopped. */
static void fx_session_closing(const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    cloak_proxy_session_aborted(NULL, uid, session_id, userdata);
}

static int fixture_init(struct fixture *fx) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

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
        fx->uid[i] = (uint8_t)(0x20 + i);
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
    dcfg.session_config_template.max_on_wire_size = 16401;
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
    return 0;
}

/* The shutdown order a binary must use: listener, dispatcher, PROXY BEFORE
 * REGISTRY, registry, panel, manager, server state. */
static void fixture_shutdown_server(struct fixture *fx) {
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
}

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
    cover_destroy(&fx->cover);
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
        fx->reactor = NULL;
    }
    if (fx->db_path[0] != '\0') {
        db_unlink(fx->db_path);
    }
}

static int front_port(struct fixture *fx) {
    return cloak_listener_port(&fx->front);
}

/* ---- the gate: a TCP front that misbehaves on schedule ------------------ */

#define GATE_MAX 16

struct gate;

typedef struct {
    struct gate *g;
    int client_fd; /* owned here until the relay takes both ends */
    int registered; /* client_fd is registered with the reactor for inspection */
    uint8_t head[5];
    size_t head_len;
    cloak_dial_t dial;
    int dialing;
    cloak_relay_t relay;
    int relaying;
    int stalled;
} gate_conn_t;

typedef struct gate {
    cloak_reactor_t *reactor;
    cloak_listener_t l;
    int have_listener;
    cloak_addr_t front;

    /* The first refuse_first accepted sockets are closed immediately: the
     * client's dial succeeds and its handshake then dies on EOF (or a
     * reset), which is what a server that declines a client does. */
    int refuse_first;
    /* Accepted connections at index >= stall_from are held open and never
     * forwarded, so their handshakes sit in READ_RECORD_HEADER forever.
     * -1 disables. */
    int stall_from;

    /* THE MIDDLEBOX D3 EXISTS FOR. Non-zero makes the gate read the
     * client's first TLS record header and drop the connection if the
     * whole record is larger than this many bytes, forwarding it
     * otherwise. That is a faithful model of the networks Cloak v2.11.0
     * ran into: they drop a first packet above the 1500-byte Ethernet
     * MTU, which this port's 1720-byte Chrome ClientHello exceeds and its
     * 658-byte Firefox one does not. */
    int max_first_record;

    int accepts;
    int refused;
    int stalls;
    int forwards;
    int dropped_too_big;
    int passed_small;

    int nslots;
    gate_conn_t conns[GATE_MAX];
} gate_t;

static void gate_on_dial(cloak_dial_t *d, int fd, void *userdata) {
    (void)d;
    gate_conn_t *gc = userdata;
    gate_t *g = gc->g;
    gc->dialing = 0;
    if (fd < 0) {
        if (gc->client_fd >= 0) {
            close(gc->client_fd);
            gc->client_fd = -1;
        }
        return;
    }
    /* Whatever the inspector already consumed is handed to the relay as a
     * preload so the server still receives a complete record stream. */
    if (cloak_relay_start(&gc->relay, g->reactor, gc->client_fd, fd, gc->head, gc->head_len, 65536,
                          NULL, NULL) != 0) {
        close(gc->client_fd);
        gc->client_fd = -1;
        close(fd);
        return;
    }
    gc->client_fd = -1; /* the relay owns both descriptors now */
    gc->relaying = 1;
    g->forwards++;
}

static void gate_forward(gate_conn_t *gc) {
    char err[256];
    if (cloak_dial_start(&gc->dial, gc->g->reactor, &gc->g->front, 5000, gate_on_dial, gc, err,
                         sizeof(err)) != 0) {
        close(gc->client_fd);
        gc->client_fd = -1;
        return;
    }
    gc->dialing = 1;
}

/* Reads just the 5-byte TLS record header, then decides. Edge-triggered,
 * so it reads until EAGAIN or the header is complete. */
static void gate_on_inspect(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    gate_conn_t *gc = userdata;
    gate_t *g = gc->g;

    while (gc->head_len < sizeof(gc->head)) {
        ssize_t n = read(fd, gc->head + gc->head_len, sizeof(gc->head) - gc->head_len);
        if (n > 0) {
            gc->head_len += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n == 0) {
            /* The client gave up before sending a header. */
            cloak_reactor_remove_fd(g->reactor, fd);
            gc->registered = 0;
            close(fd);
            gc->client_fd = -1;
            return;
        }
        return; /* EAGAIN: wait for the rest */
    }

    cloak_reactor_remove_fd(g->reactor, fd);
    gc->registered = 0;

    int record_len = 5 + (int)(((unsigned)gc->head[3] << 8) | (unsigned)gc->head[4]);
    if (record_len > g->max_first_record) {
        g->dropped_too_big++;
        close(fd);
        gc->client_fd = -1;
        return;
    }
    g->passed_small++;
    gate_forward(gc);
}

static void gate_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    gate_t *g = userdata;
    int idx = g->accepts++;

    if (idx < g->refuse_first) {
        g->refused++;
        close(fd);
        return;
    }
    if (g->nslots >= GATE_MAX) {
        close(fd);
        return;
    }
    gate_conn_t *gc = &g->conns[g->nslots++];
    gc->g = g;
    gc->client_fd = fd;

    if (g->stall_from >= 0 && idx >= g->stall_from) {
        gc->stalled = 1;
        g->stalls++;
        return; /* held open, never registered, never answered */
    }

    if (g->max_first_record > 0) {
        if (cloak_reactor_add_fd(g->reactor, fd, CLOAK_REACTOR_READABLE, gate_on_inspect, gc) !=
            0) {
            close(fd);
            gc->client_fd = -1;
            return;
        }
        gc->registered = 1;
        return;
    }

    gate_forward(gc);
}

static int gate_open(gate_t *g, cloak_reactor_t *r, int front_tcp_port) {
    memset(g, 0, sizeof(*g));
    g->reactor = r;
    g->stall_from = -1;
    for (int i = 0; i < GATE_MAX; i++) {
        g->conns[i].client_fd = -1;
    }
    char addr[64];
    char err[256];
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", front_tcp_port);
    if (cloak_net_resolve(addr, 0, &g->front, err, sizeof(err)) != 0) {
        return -1;
    }
    if (cloak_listener_open(&g->l, r, "127.0.0.1:0", gate_on_accept, g, err, sizeof(err)) != 0) {
        return -1;
    }
    g->have_listener = 1;
    return 0;
}

static void gate_close(gate_t *g) {
    if (g->have_listener) {
        cloak_listener_close(&g->l);
        g->have_listener = 0;
    }
    for (int i = 0; i < g->nslots; i++) {
        gate_conn_t *gc = &g->conns[i];
        if (gc->dialing) {
            cloak_dial_cancel(&gc->dial);
            gc->dialing = 0;
        }
        if (gc->relaying) {
            cloak_relay_stop(&gc->relay);
            gc->relaying = 0;
        }
        if (gc->registered && gc->client_fd >= 0) {
            cloak_reactor_remove_fd(g->reactor, gc->client_fd);
            gc->registered = 0;
        }
        if (gc->client_fd >= 0) {
            close(gc->client_fd);
            gc->client_fd = -1;
        }
    }
    g->nslots = 0;
}

/* ---- the connector under test ------------------------------------------ */

typedef struct {
    int calls;
    cloak_client_connector_status_t status;
    cloak_client_connector_error_t error;
    cloak_session_t *session;
} conn_result_t;

static void conn_done(cloak_client_connector_t *c, cloak_client_connector_status_t status,
                      cloak_session_t *session, void *userdata) {
    (void)c;
    conn_result_t *res = userdata;
    res->calls++;
    res->status = status;
    res->error = cloak_client_connector_error(c);
    res->session = session;
}

static int conn_fired(void *ctx) {
    conn_result_t *res = ctx;
    return res->calls > 0;
}

typedef struct {
    int calls;
    int corrupt_index; /* -1 corrupts nothing */
} key_hook_ctx_t;

static void key_hook(int conn_index, uint8_t key[CLOAK_AEAD_KEY_LEN], void *userdata) {
    key_hook_ctx_t *k = userdata;
    k->calls++;
    if (conn_index == k->corrupt_index) {
        key[0] = (uint8_t)(key[0] ^ 0x01u);
    }
}

/* Fills cfg with everything every case here shares. The caller overrides
 * num_conn, the port, the retry knobs and the hook. */
static void connector_config(cloak_client_connector_config_t *cfg, struct fixture *fx,
                             cloak_session_t *session, uint32_t session_id, int port,
                             conn_result_t *res) {
    char addr[64];
    char err[256];
    memset(cfg, 0, sizeof(*cfg));
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
    ASSERT_EQ_INT(0, cloak_net_resolve(addr, 0, &cfg->remote, err, sizeof(err)));
    cfg->reactor = fx->reactor;
    cfg->num_conn = 1;
    cfg->session = session;
    cfg->browser = CLOAK_CLIENT_BROWSER_CHROME;
    cfg->transport = CLOAK_TRANSPORT_DIRECT;
    cfg->server_name = "www.example.com";
    memcpy(cfg->server_pub, fx->server_pub, CLOAK_X25519_KEY_LEN);
    memcpy(cfg->uid, fx->uid, CLOAK_UID_LEN);
    cfg->proxy_method = "ss";
    cfg->encryption_method = (uint8_t)CLOAK_AEAD_AES_256_GCM;
    cfg->session_id = session_id;
    cfg->unordered = 0;
    cfg->dial_timeout_ms = 5000;
    /* Long enough that a stalled handshake stays stalled for the whole of
     * a teardown case rather than timing out underneath it. */
    cfg->handshake_timeout_ms = 30000;
    cfg->session_template.max_on_wire_size = 16401;
    cfg->session_template.stream_recv_capacity = 65536;
    cfg->session_template.stream_max_pending_frames = 64;
    cfg->session_template.conn_send_queue_cap = 262144;
    cfg->session_template.inactivity_timeout_ms = 60000;
    cfg->on_done = conn_done;
    cfg->on_done_userdata = res;
}

/* ---- case 1: one connection ------------------------------------------- */

#define SID_ONE ((uint32_t)5101)

/* The key assertion is against the SERVER's own cloak_session_t, not
 * against anything the client inferred: cloak_client_connector_session_key
 * must equal the bytes the dispatcher put in sesh->obfuscator.session_key.
 * A connector that recovered a key, agreed with itself about it, and
 * built a session from a different one would pass every client-side
 * check. */
static void test_connector_one_connection(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    cloak_session_t sesh;
    conn_result_t res;
    memset(&res, 0, sizeof(res));

    cloak_client_connector_config_t cfg;
    connector_config(&cfg, &fx, &sesh, SID_ONE, front_port(&fx), &res);

    cloak_client_connector_t c;
    ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
    ASSERT_EQ_INT(0, cloak_client_connector_start(&c));
    ASSERT_TRUE(pump_until(fx.reactor, conn_fired, &res, CONN_MAX_TURNS, CONN_TURN_MS));

    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_DONE, (int)res.status);
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_ERR_NONE, (int)res.error);
    ASSERT_TRUE(res.session == &sesh);
    /* Nothing was retried, so exactly one attempt was spent. */
    ASSERT_EQ_INT(1, cloak_client_connector_attempts(&c));

    ASSERT_EQ_INT(1, fx.attached_calls);
    ASSERT_EQ_INT(1, fx.attached_created);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(0, fx.cover.accept_count);

    cloak_session_t *server_sesh = cloak_server_registry_find(&fx.registry, fx.uid, SID_ONE);
    ASSERT_TRUE(server_sesh != NULL);
    if (server_sesh == NULL) {
        if (res.status == CLOAK_CLIENT_CONNECTOR_DONE) {
            cloak_session_destroy(&sesh);
        }
        cloak_client_connector_destroy(&c);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_switchboard_conn_count(&server_sesh->sb));

    const uint8_t *key = cloak_client_connector_session_key(&c);
    ASSERT_TRUE(key != NULL);
    if (key != NULL) {
        ASSERT_MEM_EQ(key, server_sesh->obfuscator.session_key, CLOAK_AEAD_KEY_LEN);
        ASSERT_MEM_EQ(sesh.obfuscator.session_key, server_sesh->obfuscator.session_key,
                      CLOAK_AEAD_KEY_LEN);
    }
    ASSERT_EQ_INT(1, (int)cloak_switchboard_conn_count(&sesh.sb));

    if (res.status == CLOAK_CLIENT_CONNECTOR_DONE) {
        cloak_session_destroy(&sesh);
    }
    cloak_client_connector_destroy(&c);
    fixture_destroy(&fx);
}

/* ---- case 2: four connections, one session ----------------------------- */

#define SID_FOUR ((uint32_t)5102)
#define FOUR 4

struct sb_wait {
    struct fixture *fx;
    uint32_t sid;
    size_t want;
};

static int server_sb_count_is(void *ctx) {
    struct sb_wait *w = ctx;
    cloak_session_t *s = cloak_server_registry_find(&w->fx->registry, w->fx->uid, w->sid);
    return s != NULL && cloak_switchboard_conn_count(&s->sb) == w->want;
}

/* THE ASSERTION THAT CARRIES THIS CASE IS ON THE SERVER'S SWITCHBOARD.
 * cloak_switchboard_conn_count(&server_sesh->sb) == 4 is a fact about how
 * many sockets the server has attached to this one session; it cannot be
 * satisfied by a client that merely believes it opened four. The
 * client-side count is asserted too, but only as the weaker companion. */
static void test_connector_four_connections_one_session(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    cloak_session_t sesh;
    conn_result_t res;
    memset(&res, 0, sizeof(res));

    cloak_client_connector_config_t cfg;
    connector_config(&cfg, &fx, &sesh, SID_FOUR, front_port(&fx), &res);
    cfg.num_conn = FOUR;

    cloak_client_connector_t c;
    ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
    ASSERT_EQ_INT(0, cloak_client_connector_start(&c));
    ASSERT_TRUE(pump_until(fx.reactor, conn_fired, &res, CONN_MAX_TURNS, CONN_TURN_MS));

    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_DONE, (int)res.status);
    ASSERT_EQ_INT(FOUR, cloak_client_connector_attempts(&c));

    /* Four connections authenticated; exactly one of them CREATED the
     * session and three JOINED it. */
    ASSERT_EQ_INT(FOUR, fx.attached_calls);
    ASSERT_EQ_INT(1, fx.attached_created);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    cloak_session_t *server_sesh = cloak_server_registry_find(&fx.registry, fx.uid, SID_FOUR);
    ASSERT_TRUE(server_sesh != NULL);
    if (server_sesh == NULL) {
        if (res.status == CLOAK_CLIENT_CONNECTOR_DONE) {
            cloak_session_destroy(&sesh);
        }
        cloak_client_connector_destroy(&c);
        fixture_destroy(&fx);
        return;
    }
    /* The dispatcher attaches each connection as its handshake finishes,
     * which can trail the client's own completion by a turn. Bounded, and
     * asserted afterwards rather than assumed. */
    struct sb_wait sw = {&fx, SID_FOUR, (size_t)FOUR};
    ASSERT_TRUE(pump_until(fx.reactor, server_sb_count_is, &sw, CONN_MAX_TURNS, CONN_TURN_MS));
    ASSERT_EQ_INT(FOUR, (int)cloak_switchboard_conn_count(&server_sesh->sb));
    ASSERT_EQ_INT(FOUR, (int)cloak_switchboard_conn_count(&sesh.sb));

    /* All four agreed, and they agreed with the server. */
    const uint8_t *key = cloak_client_connector_session_key(&c);
    ASSERT_TRUE(key != NULL);
    if (key != NULL) {
        ASSERT_MEM_EQ(key, server_sesh->obfuscator.session_key, CLOAK_AEAD_KEY_LEN);
    }

    if (res.status == CLOAK_CLIENT_CONNECTOR_DONE) {
        cloak_session_destroy(&sesh);
    }
    cloak_client_connector_destroy(&c);
    fixture_destroy(&fx);
}

/* ---- case 3: the retry ------------------------------------------------- */

#define SID_RETRY ((uint32_t)5103)

/* D2's retry, asserted by COUNTING, on both sides.
 *
 * The gate refuses exactly one connection and forwards everything after
 * it. If the connector did not retry, the session would never come up at
 * all -- but "the session came up" is also what a connector with no retry
 * loop produces against a gate that never refused anything, so the test
 * additionally pins WHICH path produced the green: the gate accepted
 * twice and refused once, and the connector spent two attempts on its one
 * connection. Remove the retry and all three of those assertions fail
 * rather than none. */
static void test_connector_retries_a_refused_connection(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    gate_t gate;
    ASSERT_EQ_INT(0, gate_open(&gate, fx.reactor, front_port(&fx)));
    gate.refuse_first = 1;

    cloak_session_t sesh;
    conn_result_t res;
    memset(&res, 0, sizeof(res));

    cloak_client_connector_config_t cfg;
    connector_config(&cfg, &fx, &sesh, SID_RETRY, cloak_listener_port(&gate.l), &res);
    cfg.max_attempts = 3;
    /* Small so the backoff does not dominate the test; the backoff's real
     * values are a production concern, not something this case measures. */
    cfg.retry_base_ms = 20;

    cloak_client_connector_t c;
    ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
    ASSERT_EQ_INT(0, cloak_client_connector_start(&c));
    ASSERT_TRUE(pump_until(fx.reactor, conn_fired, &res, CONN_MAX_TURNS, CONN_TURN_MS));

    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_DONE, (int)res.status);

    /* THE RETRY HAPPENED -- counted, not inferred. */
    ASSERT_EQ_INT(2, cloak_client_connector_attempts(&c));
    ASSERT_EQ_INT(1, gate.refused);
    ASSERT_EQ_INT(2, gate.accepts);
    ASSERT_EQ_INT(1, gate.forwards);

    /* And the session it produced is a real one: the server made exactly
     * one, from the attempt that got through. */
    ASSERT_EQ_INT(1, fx.attached_calls);
    ASSERT_EQ_INT(1, fx.attached_created);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    if (res.status == CLOAK_CLIENT_CONNECTOR_DONE) {
        cloak_session_destroy(&sesh);
    }
    cloak_client_connector_destroy(&c);
    gate_close(&gate);
    fixture_destroy(&fx);
}

/* ---- case 4: the attempt bound ----------------------------------------- */

#define SID_EXHAUST ((uint32_t)5104)

/* D2's bound: a connector that cannot get through REPORTS it, once, with
 * a typed error -- the whole reason this port does not copy Go's infinite
 * loop. The gate refuses everything, so every attempt dies the same way. */
static void test_connector_gives_up_after_the_attempt_bound(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    gate_t gate;
    ASSERT_EQ_INT(0, gate_open(&gate, fx.reactor, front_port(&fx)));
    gate.refuse_first = 1000;

    cloak_session_t sesh;
    conn_result_t res;
    memset(&res, 0, sizeof(res));

    cloak_client_connector_config_t cfg;
    connector_config(&cfg, &fx, &sesh, SID_EXHAUST, cloak_listener_port(&gate.l), &res);
    cfg.max_attempts = 3;
    cfg.retry_base_ms = 20;

    cloak_client_connector_t c;
    ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
    ASSERT_EQ_INT(0, cloak_client_connector_start(&c));
    ASSERT_TRUE(pump_until(fx.reactor, conn_fired, &res, CONN_MAX_TURNS, CONN_TURN_MS));

    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_FAILED, (int)res.status);
    ASSERT_TRUE(res.session == NULL);
    /* The dial SUCCEEDS every time (something is listening); it is the
     * handshake that dies, so the typed error must name the handshake and
     * not the dial. */
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_ERR_HANDSHAKE, (int)res.error);
    /* Whether the close lands as a clean EOF or as a reset depends on
     * whether our ClientHello was already in the kernel's receive queue
     * when the gate closed, which is a kernel scheduling detail; both are
     * "the far end went away mid-handshake" and nothing else is. */
    cloak_client_handshake_error_t he = cloak_client_connector_handshake_error(&c);
    ASSERT_TRUE(he == CLOAK_CLIENT_HANDSHAKE_ERR_EOF || he == CLOAK_CLIENT_HANDSHAKE_ERR_IO);
    /* Exactly the bound: not fewer (it must retry) and not more (it must
     * stop). */
    ASSERT_EQ_INT(3, cloak_client_connector_attempts(&c));
    ASSERT_EQ_INT(3, gate.accepts);
    ASSERT_EQ_INT(3, gate.refused);
    /* Nothing reached the real server. */
    ASSERT_EQ_INT(0, fx.attached_calls);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_TRUE(cloak_client_connector_session(&c) == NULL);

    /* Nothing may fire into the wreckage afterwards, and the callback
     * stays at one. */
    for (int i = 0; i < 100; i++) {
        cloak_reactor_run_once(fx.reactor, 1);
    }
    ASSERT_EQ_INT(1, res.calls);

    cloak_client_connector_destroy(&c);
    gate_close(&gate);
    fixture_destroy(&fx);
}

/* ---- case 5: D4, the key check ----------------------------------------- */

#define SID_KEYBAD ((uint32_t)5105)
#define SID_KEYOK ((uint32_t)5106)

/* BOTH SIDES OF THE BOUNDARY, in one case, because a test that only
 * showed the corrupt key failing would also pass if the mere PRESENCE of
 * the hook broke the session.
 *
 * Part A installs the hook and corrupts connection 1's recovered key:
 * the connector must refuse the whole session with
 * CLOAK_CLIENT_CONNECTOR_ERR_KEY_MISMATCH, rather than doing what Go does
 * -- store each key into an atomic and use whichever landed last, which
 * here would produce a live session whose obfuscator is wrong for one of
 * its two connections.
 *
 * Part B installs the SAME hook, corrupting nothing, and the session must
 * come up. */
static void test_connector_rejects_a_key_disagreement(void) {
    /* ---- A: one connection's key is corrupted ---- */
    {
        struct fixture fx;
        ASSERT_EQ_INT(0, fixture_init(&fx));

        cloak_session_t sesh;
        conn_result_t res;
        memset(&res, 0, sizeof(res));
        key_hook_ctx_t hook = {0, 1};

        cloak_client_connector_config_t cfg;
        connector_config(&cfg, &fx, &sesh, SID_KEYBAD, front_port(&fx), &res);
        cfg.num_conn = 2;
        cfg.key_hook = key_hook;
        cfg.key_hook_userdata = &hook;

        cloak_client_connector_t c;
        ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
        ASSERT_EQ_INT(0, cloak_client_connector_start(&c));
        ASSERT_TRUE(pump_until(fx.reactor, conn_fired, &res, CONN_MAX_TURNS, CONN_TURN_MS));

        ASSERT_EQ_INT(1, res.calls);
        ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_FAILED, (int)res.status);
        ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_ERR_KEY_MISMATCH, (int)res.error);
        ASSERT_TRUE(res.session == NULL);
        ASSERT_TRUE(cloak_client_connector_session(&c) == NULL);
        ASSERT_TRUE(cloak_client_connector_session_key(&c) == NULL);
        /* Both handshakes really did succeed -- the failure is the CHECK,
         * not a connection that never got there. */
        ASSERT_EQ_INT(2, hook.calls);
        ASSERT_EQ_INT(2, cloak_client_connector_attempts(&c));
        ASSERT_EQ_INT(2, fx.attached_calls);

        cloak_client_connector_destroy(&c);
        fixture_destroy(&fx);
    }

    /* ---- B: the same hook, corrupting nothing ---- */
    {
        struct fixture fx;
        ASSERT_EQ_INT(0, fixture_init(&fx));

        cloak_session_t sesh;
        conn_result_t res;
        memset(&res, 0, sizeof(res));
        key_hook_ctx_t hook = {0, -1};

        cloak_client_connector_config_t cfg;
        connector_config(&cfg, &fx, &sesh, SID_KEYOK, front_port(&fx), &res);
        cfg.num_conn = 2;
        cfg.key_hook = key_hook;
        cfg.key_hook_userdata = &hook;

        cloak_client_connector_t c;
        ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
        ASSERT_EQ_INT(0, cloak_client_connector_start(&c));
        ASSERT_TRUE(pump_until(fx.reactor, conn_fired, &res, CONN_MAX_TURNS, CONN_TURN_MS));

        ASSERT_EQ_INT(1, res.calls);
        ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_DONE, (int)res.status);
        ASSERT_EQ_INT(2, hook.calls);
        ASSERT_EQ_INT(2, (int)cloak_switchboard_conn_count(&sesh.sb));

        if (res.status == CLOAK_CLIENT_CONNECTOR_DONE) {
            cloak_session_destroy(&sesh);
        }
        cloak_client_connector_destroy(&c);
        fixture_destroy(&fx);
    }
}

/* ---- case 6: teardown mid-flight --------------------------------------- */

#define SID_TD_DIAL ((uint32_t)5107)
#define SID_TD_HS ((uint32_t)5108)
#define SID_TD_MIX ((uint32_t)5109)

/* The dial timeout / handshake deadline the teardown cases run with, and
 * the window they pump afterwards. TD_TIMER_MS is a thousand times longer
 * than the few milliseconds it takes on loopback to reach the state being
 * torn down, so it cannot fire before the teardown; TD_PUMP_MS outlives
 * it, so a timer the teardown failed to cancel does fire, into the freed
 * per-connection array, where ASan sees it. Measured: mutating away the
 * handshake or dial cancellation in conn_release is NOT caught with a
 * fixed turn count here and IS caught with this. */
#define TD_TIMER_MS 1000u
#define TD_PUMP_MS 1400u

struct td_wait {
    cloak_client_connector_t *c;
    int want;
};

static int td_hs_active_is(void *ctx) {
    struct td_wait *w = ctx;
    int n = 0;
    for (int i = 0; i < w->c->num_conn; i++) {
        n += w->c->conns[i].hs_active;
    }
    return n >= w->want;
}

static int td_done_is(void *ctx) {
    struct td_wait *w = ctx;
    int n = 0;
    for (int i = 0; i < w->c->num_conn; i++) {
        n += w->c->conns[i].done;
    }
    return n >= w->want;
}

/* Destroy at three distinct points, each with a live server on the other
 * end and the reactor pumped afterwards so that anything the teardown
 * failed to deregister has somewhere to fire. Under ASan this is where a
 * leaked fd, a double close, a surviving reactor registration or a freed
 * handshake still on the timer heap shows up; the Debug build sees only
 * the callback counter. Every previous module in this project found its
 * worst bug in exactly this shape. */
static void test_connector_destroy_mid_flight(void) {
    /* ---- A: during the dials ---- */
    {
        int fds_before = count_open_fds();
        struct fixture fx;
        ASSERT_EQ_INT(0, fixture_init(&fx));

        cloak_session_t sesh;
        conn_result_t res;
        memset(&res, 0, sizeof(res));

        cloak_client_connector_config_t cfg;
        connector_config(&cfg, &fx, &sesh, SID_TD_DIAL, front_port(&fx), &res);
        cfg.num_conn = FOUR;
        /* Short enough that the post-teardown pump below outlives it, so
         * a dial this teardown failed to cancel FIRES rather than merely
         * sitting on the timer heap unnoticed. Vastly longer than the
         * single turn it takes to reach the state being torn down. */
        cfg.dial_timeout_ms = TD_TIMER_MS;

        cloak_client_connector_t c;
        ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
        ASSERT_EQ_INT(0, cloak_client_connector_start(&c));

        /* One turn is exactly enough for the kickoff timer to fire and
         * every dial to be issued and registered, and not enough for any
         * dial's completion to be dispatched: a non-blocking connect() to
         * a listening loopback socket returns EINPROGRESS, so the dial
         * callback needs a further epoll turn. Asserted, not assumed. */
        cloak_reactor_run_once(fx.reactor, 0);
        ASSERT_EQ_INT(FOUR, cloak_client_connector_attempts(&c));
        int dialing = 0;
        for (int i = 0; i < FOUR; i++) {
            dialing += c.conns[i].dial_active;
        }
        ASSERT_EQ_INT(FOUR, dialing);
        ASSERT_EQ_INT(0, c.completed);
        ASSERT_EQ_INT(0, res.calls);

        cloak_client_connector_destroy(&c);
        /* Destroy fires no callback, and nothing fires afterwards --
         * pumped past TD_TIMER_MS so that a dial timeout this teardown
         * failed to cancel would fire into the freed array rather than
         * staying quietly on the heap. */
        pump_for_ms(fx.reactor, TD_PUMP_MS);
        ASSERT_EQ_INT(0, res.calls);
        /* Idempotent, including on an object that has already released
         * everything. */
        cloak_client_connector_destroy(&c);

        fixture_destroy(&fx);
        ASSERT_EQ_INT(fds_before, count_open_fds());
    }

    /* ---- B: during the handshakes ---- */
    {
        int fds_before = count_open_fds();
        struct fixture fx;
        ASSERT_EQ_INT(0, fixture_init(&fx));

        gate_t gate;
        ASSERT_EQ_INT(0, gate_open(&gate, fx.reactor, front_port(&fx)));
        gate.stall_from = 0; /* accept everything, answer nothing */

        cloak_session_t sesh;
        conn_result_t res;
        memset(&res, 0, sizeof(res));

        cloak_client_connector_config_t cfg;
        connector_config(&cfg, &fx, &sesh, SID_TD_HS, cloak_listener_port(&gate.l), &res);
        cfg.num_conn = FOUR;
        /* See TD_TIMER_MS: short enough that the post-teardown pump
         * outlives it, long enough that it cannot fire beforehand. */
        cfg.handshake_timeout_ms = TD_TIMER_MS;

        cloak_client_connector_t c;
        ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
        ASSERT_EQ_INT(0, cloak_client_connector_start(&c));

        struct td_wait tw = {&c, FOUR};
        ASSERT_TRUE(pump_until(fx.reactor, td_hs_active_is, &tw, CONN_MAX_TURNS, CONN_TURN_MS));
        int hs = 0;
        for (int i = 0; i < FOUR; i++) {
            hs += c.conns[i].hs_active;
        }
        ASSERT_EQ_INT(FOUR, hs);
        ASSERT_EQ_INT(0, c.completed);
        ASSERT_EQ_INT(0, res.calls);
        ASSERT_EQ_INT(FOUR, gate.stalls);

        cloak_client_connector_destroy(&c);
        /* Past TD_TIMER_MS, so a handshake deadline this teardown failed
         * to cancel fires into the freed array instead of going
         * unnoticed. */
        pump_for_ms(fx.reactor, TD_PUMP_MS);
        ASSERT_EQ_INT(0, res.calls);

        gate_close(&gate);
        fixture_destroy(&fx);
        ASSERT_EQ_INT(fds_before, count_open_fds());
    }

    /* ---- C: after some connections have completed ---- */
    {
        int fds_before = count_open_fds();
        struct fixture fx;
        ASSERT_EQ_INT(0, fixture_init(&fx));

        gate_t gate;
        ASSERT_EQ_INT(0, gate_open(&gate, fx.reactor, front_port(&fx)));
        /* The first two are forwarded to the real server and complete;
         * the last two are held open and never answered. */
        gate.stall_from = 2;

        cloak_session_t sesh;
        conn_result_t res;
        memset(&res, 0, sizeof(res));

        cloak_client_connector_config_t cfg;
        connector_config(&cfg, &fx, &sesh, SID_TD_MIX, cloak_listener_port(&gate.l), &res);
        cfg.num_conn = FOUR;
        cfg.handshake_timeout_ms = TD_TIMER_MS;

        cloak_client_connector_t c;
        ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
        ASSERT_EQ_INT(0, cloak_client_connector_start(&c));

        struct td_wait tw = {&c, 2};
        ASSERT_TRUE(pump_until(fx.reactor, td_done_is, &tw, CONN_MAX_TURNS, CONN_TURN_MS));

        int done = 0;
        int hs = 0;
        int held = 0;
        for (int i = 0; i < FOUR; i++) {
            done += c.conns[i].done;
            hs += c.conns[i].hs_active;
            held += c.conns[i].fd >= 0 ? 1 : 0;
        }
        /* THE POINT OF THIS SUB-CASE: a genuinely mixed state. Two
         * connections finished and are sitting on completed handshakes
         * holding their sockets; two are still handshaking. All four
         * sockets are owned by the connector and must be closed exactly
         * once by the teardown. */
        ASSERT_EQ_INT(2, done);
        ASSERT_EQ_INT(2, hs);
        ASSERT_EQ_INT(FOUR, held);
        ASSERT_EQ_INT(2, c.completed);
        ASSERT_EQ_INT(0, res.calls);
        ASSERT_EQ_INT(2, gate.stalls);
        ASSERT_EQ_INT(2, gate.forwards);

        cloak_client_connector_destroy(&c);
        /* Past TD_TIMER_MS, so a handshake deadline this teardown failed
         * to cancel fires into the freed array instead of going
         * unnoticed. */
        pump_for_ms(fx.reactor, TD_PUMP_MS);
        ASSERT_EQ_INT(0, res.calls);

        gate_close(&gate);
        fixture_destroy(&fx);
        ASSERT_EQ_INT(fds_before, count_open_fds());
    }
}

/* ---- case 7: the callback never fires from inside start ---------------- */

#define SID_SYNC ((uint32_t)5110)

/* The guarantee Go gets for free from its runtime and this port has to
 * build: on_done never runs re-entrantly from
 * cloak_client_connector_start, so a caller can finish initializing its
 * own state after start without racing its own completion. Asserted on
 * the ONE case that could plausibly complete inline -- a single
 * connection to a loopback server that is already listening, where the
 * connect can succeed immediately. */
static void test_connector_never_completes_from_inside_start(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    cloak_session_t sesh;
    conn_result_t res;
    memset(&res, 0, sizeof(res));

    cloak_client_connector_config_t cfg;
    connector_config(&cfg, &fx, &sesh, SID_SYNC, front_port(&fx), &res);

    cloak_client_connector_t c;
    ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
    ASSERT_EQ_INT(0, res.calls);
    ASSERT_EQ_INT(0, cloak_client_connector_start(&c));
    /* The whole assertion: start has returned and nothing has been
     * reported. Not even a dial has been issued yet -- start defers even
     * that to a reactor turn. */
    ASSERT_EQ_INT(0, res.calls);
    ASSERT_EQ_INT(0, cloak_client_connector_attempts(&c));
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_PENDING, (int)cloak_client_connector_status(&c));

    ASSERT_TRUE(pump_until(fx.reactor, conn_fired, &res, CONN_MAX_TURNS, CONN_TURN_MS));
    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_DONE, (int)res.status);

    if (res.status == CLOAK_CLIENT_CONNECTOR_DONE) {
        cloak_session_destroy(&sesh);
    }
    cloak_client_connector_destroy(&c);
    fixture_destroy(&fx);
}

/* ---- case 8: rejected configurations ----------------------------------- */

/* Constructor discipline: every rejected init leaves c safe to destroy,
 * and no rejection fires the callback. Both sides of the num_conn bound
 * are checked -- 0 and MAX+1 are rejected, 1 and MAX are not -- because a
 * bound tested on one side only is the sharper of this project's
 * recurring coverage defects. */
static void test_connector_rejects_bad_configs(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    cloak_session_t sesh;
    conn_result_t res;
    memset(&res, 0, sizeof(res));

    cloak_client_connector_config_t base;
    connector_config(&base, &fx, &sesh, 5111, front_port(&fx), &res);

    cloak_client_connector_t c;

    /* A zeroed connector is safe to destroy, and so is one left by a
     * rejected init. */
    memset(&c, 0, sizeof(c));
    cloak_client_connector_destroy(&c);

    cloak_client_connector_config_t cfg = base;
    cfg.reactor = NULL;
    ASSERT_EQ_INT(-1, cloak_client_connector_init(&c, &cfg));
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_ERR_CONFIG, (int)cloak_client_connector_error(&c));
    cloak_client_connector_destroy(&c);

    cfg = base;
    cfg.session = NULL;
    ASSERT_EQ_INT(-1, cloak_client_connector_init(&c, &cfg));
    cloak_client_connector_destroy(&c);

    cfg = base;
    cfg.on_done = NULL;
    ASSERT_EQ_INT(-1, cloak_client_connector_init(&c, &cfg));
    cloak_client_connector_destroy(&c);

    cfg = base;
    cfg.num_conn = 0;
    ASSERT_EQ_INT(-1, cloak_client_connector_init(&c, &cfg));
    cloak_client_connector_destroy(&c);

    cfg = base;
    cfg.num_conn = CLOAK_CLIENT_CONNECTOR_MAX_CONN + 1;
    ASSERT_EQ_INT(-1, cloak_client_connector_init(&c, &cfg));
    cloak_client_connector_destroy(&c);

    /* The other side of the same bound: both ends of the legal range are
     * accepted. Nothing is started, so nothing is dialed. */
    cfg = base;
    cfg.num_conn = 1;
    ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
    cloak_client_connector_destroy(&c);

    cfg = base;
    cfg.num_conn = CLOAK_CLIENT_CONNECTOR_MAX_CONN;
    ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
    cloak_client_connector_destroy(&c);

    /* CDN is a transport this build cannot speak; it must be refused
     * rather than silently downgraded to direct TLS. */
    cfg = base;
    cfg.transport = CLOAK_TRANSPORT_CDN;
    ASSERT_EQ_INT(-1, cloak_client_connector_init(&c, &cfg));
    cloak_client_connector_destroy(&c);

    /* Nothing above may ever have reported anything to the caller. */
    ASSERT_EQ_INT(0, res.calls);
    ASSERT_EQ_INT(0, fx.attached_calls);

    fixture_destroy(&fx);
}

/* ---- case 9: D3, the Chrome-to-Firefox fallback ------------------------ */

#define SID_FALLBACK ((uint32_t)5112)
#define SID_FIREFOX ((uint32_t)5113)
#define MTU_LIMIT 1500

/* D3, against the hazard it was written for rather than against the
 * branch that implements it.
 *
 * The gate drops any connection whose first TLS record exceeds 1500
 * bytes. This port's Chrome ClientHello is 1720 (chrome_template in
 * clienthello.c) and its Firefox one is 658, so a Chrome-configured
 * connector CANNOT get through without falling back, and a
 * Firefox-configured one gets through on its first try. That is the exact
 * failure Cloak v2.11.0 shipped into (cbeuw/Cloak#306) and the reason the
 * fallback is in the reference at all.
 *
 * Both sides of the boundary, in one case: part A shows Chrome failing
 * once, switching, and succeeding, with the connection's fingerprint
 * observably STUCK on Firefox afterwards; part B shows that the gate is
 * not simply hostile to everything. Without part B, an implementation
 * that retried with any fingerprint at all -- or that always used Firefox
 * -- would pass part A. */
static void test_connector_falls_back_from_chrome_to_firefox(void) {
    /* ---- A: configured for Chrome, gets through as Firefox ---- */
    {
        struct fixture fx;
        ASSERT_EQ_INT(0, fixture_init(&fx));

        gate_t gate;
        ASSERT_EQ_INT(0, gate_open(&gate, fx.reactor, front_port(&fx)));
        gate.max_first_record = MTU_LIMIT;

        cloak_session_t sesh;
        conn_result_t res;
        memset(&res, 0, sizeof(res));

        cloak_client_connector_config_t cfg;
        connector_config(&cfg, &fx, &sesh, SID_FALLBACK, cloak_listener_port(&gate.l), &res);
        cfg.browser = CLOAK_CLIENT_BROWSER_CHROME;
        cfg.max_attempts = 3;
        cfg.retry_base_ms = 20;

        cloak_client_connector_t c;
        ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
        /* The fingerprint every connection starts on is the configured
         * one -- the fallback is a reaction, not a default. */
        ASSERT_EQ_INT((int)CLOAK_CLIENT_BROWSER_CHROME, (int)c.conns[0].browser);
        ASSERT_EQ_INT(0, cloak_client_connector_start(&c));
        ASSERT_TRUE(pump_until(fx.reactor, conn_fired, &res, CONN_MAX_TURNS, CONN_TURN_MS));

        ASSERT_EQ_INT(1, res.calls);
        ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_DONE, (int)res.status);
        /* One oversized ClientHello dropped, one small one through. */
        ASSERT_EQ_INT(1, gate.dropped_too_big);
        ASSERT_EQ_INT(1, gate.passed_small);
        ASSERT_EQ_INT(2, cloak_client_connector_attempts(&c));
        /* Sticky: the connection stays on Firefox rather than reverting. */
        ASSERT_EQ_INT((int)CLOAK_CLIENT_BROWSER_FIREFOX, (int)c.conns[0].browser);
        ASSERT_EQ_INT(1, fx.attached_created);

        if (res.status == CLOAK_CLIENT_CONNECTOR_DONE) {
            cloak_session_destroy(&sesh);
        }
        cloak_client_connector_destroy(&c);
        gate_close(&gate);
        fixture_destroy(&fx);
    }

    /* ---- B: configured for Firefox, no fallback needed ---- */
    {
        struct fixture fx;
        ASSERT_EQ_INT(0, fixture_init(&fx));

        gate_t gate;
        ASSERT_EQ_INT(0, gate_open(&gate, fx.reactor, front_port(&fx)));
        gate.max_first_record = MTU_LIMIT;

        cloak_session_t sesh;
        conn_result_t res;
        memset(&res, 0, sizeof(res));

        cloak_client_connector_config_t cfg;
        connector_config(&cfg, &fx, &sesh, SID_FIREFOX, cloak_listener_port(&gate.l), &res);
        cfg.browser = CLOAK_CLIENT_BROWSER_FIREFOX;
        cfg.max_attempts = 3;
        cfg.retry_base_ms = 20;

        cloak_client_connector_t c;
        ASSERT_EQ_INT(0, cloak_client_connector_init(&c, &cfg));
        ASSERT_EQ_INT(0, cloak_client_connector_start(&c));
        ASSERT_TRUE(pump_until(fx.reactor, conn_fired, &res, CONN_MAX_TURNS, CONN_TURN_MS));

        ASSERT_EQ_INT(1, res.calls);
        ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_DONE, (int)res.status);
        ASSERT_EQ_INT(0, gate.dropped_too_big);
        ASSERT_EQ_INT(1, gate.passed_small);
        ASSERT_EQ_INT(1, cloak_client_connector_attempts(&c));
        ASSERT_EQ_INT((int)CLOAK_CLIENT_BROWSER_FIREFOX, (int)c.conns[0].browser);

        if (res.status == CLOAK_CLIENT_CONNECTOR_DONE) {
            cloak_session_destroy(&sesh);
        }
        cloak_client_connector_destroy(&c);
        gate_close(&gate);
        fixture_destroy(&fx);
    }
}

TEST_MAIN_BEGIN()
test_connector_one_connection();
test_connector_four_connections_one_session();
test_connector_retries_a_refused_connection();
test_connector_gives_up_after_the_attempt_bound();
test_connector_rejects_a_key_disagreement();
test_connector_destroy_mid_flight();
test_connector_never_completes_from_inside_start();
test_connector_rejects_bad_configs();
test_connector_falls_back_from_chrome_to_firefox();
TEST_MAIN_END()
