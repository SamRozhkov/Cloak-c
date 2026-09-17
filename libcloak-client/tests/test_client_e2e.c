#define _POSIX_C_SOURCE 200809L

/* BOTH HALVES OF THIS PROTOCOL, AS LIBRARY CODE, ON BOTH SIDES.
 *
 * Every other end-to-end test in this tree (libcloak-server's
 * test_server_e2e.c and its siblings) drives a real server with a
 * HAND-ROLLED client: client_harness.h's build_client_record assembles
 * the ClientHello field by field and extract_session_key_from_reply
 * un-splices the reply by literal offsets. This file is the first test in
 * which the client side is a real cloak_client_handshake_t and a real
 * cloak_session_t -- the library a ck-client binary will use -- talking to
 * the merged server stack (cloak_server_t, cloak_usermanager_t,
 * cloak_userpanel_t, cloak_server_registry_t, cloak_proxy_t,
 * cloak_dispatcher_t, one cloak_listener_t).
 *
 * WHAT THIS PROVES AND WHAT IT DOES NOT. It proves the two halves agree
 * WITH EACH OTHER: the client's ClientHello is one the server
 * authenticates, and the session key it recovers from the reply is
 * byte-for-byte the key the server put into the session (asserted
 * directly against the server's own cloak_session_t, not inferred from
 * traffic). It does NOT prove either half agrees with Go -- the record
 * layer was checked against Go's own vectors separately (Task 1), and
 * full wire compatibility with ck-client is out of scope for this module
 * by spec. No Go binary is involved here.
 *
 * WHY THE BYTE-LEVEL ASSERTIONS ARE THE POINT. A session that establishes
 * cleanly and then silently drops every frame is a failure mode this
 * project has hit before, and it is invisible to every counter: the
 * handshake completes, the dispatcher attaches, the registry holds a
 * session, and nothing ever crosses. Only "the upstream received exactly
 * these bytes" and "the client read exactly those bytes back" separate
 * the two, so every test below ends in an ASSERT_MEM_EQ on real payload.
 *
 * THE UPSTREAM DOES NOT ECHO VERBATIM, deliberately: it answers each byte
 * b with (uint8_t)~b. A plain echo would make the up-path payload and the
 * down-path payload the same bytes, so a down-path assertion would also
 * be satisfied by a client that somehow read its own write back -- it
 * would be an assertion on the wrong side of the connection, which is one
 * of the six defect shapes this project has already paid for. The
 * complement makes the returning bytes producible ONLY by something that
 * received the request at the far end of the tunnel and sent an answer
 * back through it.
 *
 * EVERY WAIT IS A BOUNDED pump_until, the discipline every reactor test
 * in this tree states: three tests on this project have hung or flaked in
 * CI, all found by repetition. */

#include "cloak/base64.h"
#include "cloak/client_transport.h"
#include "cloak/conn.h"
#include "cloak/crypto.h"
#include "cloak/dispatcher.h"
#include "cloak/frame.h"
#include "cloak/net.h"
#include "cloak/proxy.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "cloak/switchboard.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
#include "test_framework.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---- bounded reactor pumping ------------------------------------------- */

/* THE ONE BOUND EVERY WAIT IN THIS FILE USES, and it is sized so that a
 * BROKEN run fails an ASSERTION rather than the ctest timeout. There are
 * eleven waits across the three tests; at E2E_MAX_TURNS turns of
 * E2E_TURN_MS each they total at most ~11 s against this file's TIMEOUT
 * 60, so a genuinely broken data path reports WHICH assertion it broke
 * instead of being killed partway through with no diagnostic. Measured,
 * the whole of this file's traffic needs a few dozen turns on loopback (a
 * green run takes well under a tenth of a second), so this is orders of
 * magnitude of headroom. Not hypothetical: the first version of this file
 * used per-wait bounds totalling over a minute, and mutation M1 (a
 * one-bit corruption of the recovered session key) killed it by TIMEOUT
 * rather than by assertion -- a failure that says nothing about what
 * broke. Measured again after the change: the same mutation now fails in
 * 22 s, Debug and ASan alike. */
#define E2E_MAX_TURNS 1000
#define E2E_TURN_MS 1

typedef int (*pump_done_fn)(void *ctx);

/* Local to pump_until so that files which define their own monotonic_ms
 * later (or not at all) both work; see pump_until's own comment. */
static uint64_t pump_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Pumps the reactor until done(ctx) is true, bounded by REAL TIME:
 * max_iters * per_iter_ms milliseconds, which is what every caller's
 * (turns, ms-per-turn) pair was always documented to mean. Returns 1 if
 * done became true, 0 if the budget ran out.
 *
 * THE BOUND IS WALL-CLOCK AND NOT AN ITERATION COUNT, and that
 * distinction is a defect these suites already paid for.
 * cloak_reactor_run_once blocks for its full per_iter_ms only when
 * NOTHING is ready; one permanently-ready descriptor makes every turn
 * return immediately and a loop of max_iters turns then expires in
 * milliseconds. The usual such descriptor is an EOF-readable peer left
 * registered after a teardown: its handler reads 0, then re-arms
 * edge-triggered interest, and the hangup is re-reported every single
 * turn. Measured on this branch: a caller asking for "2000 turns of 1 ms"
 * and believing it had asked for two seconds got 4.2 ms, with a dispatch
 * histogram showing exactly two such fds serviced 2000 times each and
 * nothing else in between. Every wait in these suites was one busy
 * descriptor away from a false negative, and one of them had already
 * become one -- see case 7D's neighbours in test_client_piper.c.
 *
 * THE ITERATION CEILING IS A BACKSTOP AGAINST A CLOCK THAT DOES NOT
 * ADVANCE, sized so it cannot bind first: a busy descriptor spins at
 * roughly 600k turns per second and this sits about forty times above
 * that, which is how pump_for_ms sizes its own ceiling for the same
 * reason. Do not shrink it back toward the spin rate; that turns this
 * back into an iteration bound wearing a clock. */
static int pump_until(cloak_reactor_t *r, pump_done_fn done, void *ctx, int max_iters,
                      int per_iter_ms) {
    uint64_t budget_ms = (uint64_t)(max_iters > 0 ? max_iters : 0) *
                         (uint64_t)(per_iter_ms > 0 ? per_iter_ms : 0);
    uint64_t start = pump_monotonic_ms();
    uint64_t ceiling = budget_ms * 1000u + 5000000u;
    for (uint64_t i = 0; i < ceiling; i++) {
        if (done(ctx)) {
            return 1;
        }
        if (pump_monotonic_ms() - start >= budget_ms) {
            break;
        }
        cloak_reactor_run_once(r, per_iter_ms);
    }
    return done(ctx);
}

/* ---- the fake upstream: records, and answers with the complement ------- */

#define UP_MAX_CONNS 8
#define UP_BUF_CAP ((size_t)65536)

typedef struct {
    int fd;
    uint8_t in[UP_BUF_CAP];  /* everything ever read, for byte-for-byte assertions */
    size_t in_len;
    uint8_t out[UP_BUF_CAP]; /* the complement of `in`, pending on the socket */
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
        /* Edge-triggered: read until EAGAIN or the buffers are full. */
        for (;;) {
            size_t room = UP_BUF_CAP - c->in_len;
            if (UP_BUF_CAP - c->out_len < room) {
                room = UP_BUF_CAP - c->out_len;
            }
            if (room == 0) {
                break;
            }
            ssize_t n = read(c->fd, c->in + c->in_len, room);
            if (n > 0) {
                /* THE COMPLEMENT, not an echo -- see this file's header. */
                for (ssize_t i = 0; i < n; i++) {
                    c->out[c->out_len + (size_t)i] = (uint8_t)~c->in[c->in_len + (size_t)i];
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
    up->conns[idx].fd = fd;
    up->slots[idx].up = up;
    up->slots[idx].idx = idx;
    (void)cloak_reactor_add_fd(up->reactor, fd, CLOAK_REACTOR_READABLE, up_on_event,
                               &up->slots[idx]);
}

static void up_destroy(upstream_t *up) {
    for (int i = 0; i < UP_MAX_CONNS; i++) {
        if (up->conns[i].fd >= 0) {
            cloak_reactor_remove_fd(up->reactor, up->conns[i].fd);
            close(up->conns[i].fd);
            up->conns[i].fd = -1;
        }
    }
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

/* ---- the fake cover site: nothing here should ever reach it ------------- */

typedef struct {
    cloak_reactor_t *reactor;
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
    snprintf(buf, cap, "%s/cloak_client_e2e_%ld.db", dir, (long)getpid());
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

/* The panel's and the manager's clock. Deliberately NOT the wall clock the
 * handshake is timestamped against (the client stamps time(NULL) and
 * cloak_server_auth_decrypt checks it against time(NULL)): the panel's
 * expiry arithmetic wants a fixed "now" so nothing here is one CI
 * scheduling hiccup away from a different answer. */
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
 * the window in which relays must be stopped. The signatures differ only by
 * the cloak_dispatcher_t * the other hook carries and proxy.c ignores. */
static void fx_session_closing(const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    cloak_proxy_session_aborted(NULL, uid, session_id, userdata);
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

    fx->cover.reactor = fx->reactor;
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
        fx->uid[i] = (uint8_t)(0x10 + i);
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
    ASSERT_EQ_INT(0, cloak_usermanager_open(&fx->mgr, fx->db_path, panel_now, NULL, err,
                                            sizeof(err)));
    ASSERT_TRUE(fx->mgr != NULL);
    if (fx->mgr == NULL) {
        return -1;
    }

    /* registry -> panel -> proxy -> dispatcher: the registry's on_broken
     * userdata is the proxy's ADDRESS (stored, never dereferenced until a
     * session breaks), so it can be built first; the panel needs the
     * registry; the proxy's chain userdata needs the panel. */
    ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor,
                                                cloak_proxy_registry_broken, &fx->proxy));
    fx->registry_ready = 1;

    cloak_userpanel_config_t upcfg;
    memset(&upcfg, 0, sizeof(upcfg));
    upcfg.manager = fx->mgr;
    upcfg.registry = &fx->registry;
    upcfg.reactor = fx->reactor;
    /* An hour: nothing here wants the periodic upload cycle to fire on its
     * own inside a pump window. */
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
 * REGISTRY (relays must stop while their sessions are alive), registry,
 * then the panel (it frees every active user's valve without closing any
 * session, so a session still alive afterwards would meter into freed
 * memory), then the manager and the server state they all borrowed. */
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

/* ---- the client: cloak_client_handshake_t, then cloak_session_t --------- */

static int connect_nonblocking(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

typedef struct {
    int calls;
    cloak_client_handshake_status_t status;
    cloak_client_handshake_error_t error;
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    int have_key;
} hs_result_t;

static void hs_done(cloak_client_handshake_t *h, cloak_client_handshake_status_t status,
                    void *userdata) {
    hs_result_t *res = userdata;
    res->calls++;
    res->status = status;
    res->error = cloak_client_handshake_error(h);
    const uint8_t *k = cloak_client_handshake_session_key(h);
    if (k != NULL) {
        memcpy(res->key, k, CLOAK_AEAD_KEY_LEN);
        res->have_key = 1;
    }
}

static int hs_fired(void *ctx) {
    hs_result_t *res = ctx;
    return res->calls > 0;
}

/* One complete client handshake against the fixture's front listener, run
 * on the SAME reactor as the server -- one pump drives both ends. The
 * cloak_client_handshake_t lives in the caller's frame and stays at a
 * fixed address for the whole of it, as cloak/client_transport.h requires.
 *
 * Returns the connected fd (still owned by the caller: this object never
 * closes it, on any path) with the recovered key in out_key, or -1. */
static int client_handshake(struct fixture *fx, uint32_t session_id,
                            uint8_t out_key[CLOAK_AEAD_KEY_LEN]) {
    int fd = connect_nonblocking(front_port(fx));
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return -1;
    }

    hs_result_t res;
    memset(&res, 0, sizeof(res));

    cloak_client_handshake_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.reactor = fx->reactor;
    cfg.fd = fd;
    cfg.browser = CLOAK_CLIENT_BROWSER_CHROME;
    cfg.server_name = "www.example.com";
    memcpy(cfg.server_pub, fx->server_pub, CLOAK_X25519_KEY_LEN);
    memcpy(cfg.uid, fx->uid, CLOAK_UID_LEN);
    cfg.proxy_method = "ss";
    cfg.encryption_method = (uint8_t)CLOAK_AEAD_AES_256_GCM;
    cfg.session_id = session_id;
    cfg.unordered = 0;
    cfg.now_unix = (int64_t)time(NULL);
    cfg.timeout_ms = 5000;
    cfg.on_done = hs_done;
    cfg.on_done_userdata = &res;

    cloak_client_handshake_t h;
    if (cloak_client_handshake_init(&h, &cfg) != 0) {
        ASSERT_EQ_INT(0, (int)cloak_client_handshake_error(&h));
        cloak_client_handshake_destroy(&h);
        close(fd);
        return -1;
    }
    if (cloak_client_handshake_start(&h) != 0) {
        ASSERT_TRUE(0);
        cloak_client_handshake_destroy(&h);
        close(fd);
        return -1;
    }

    ASSERT_TRUE(pump_until(fx->reactor, hs_fired, &res, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT((int)CLOAK_CLIENT_HANDSHAKE_DONE, (int)res.status);
    ASSERT_EQ_INT((int)CLOAK_CLIENT_HS_STATE_DONE, (int)h.state);
    ASSERT_EQ_INT(1, res.have_key);
    cloak_client_handshake_destroy(&h);

    if (res.status != CLOAK_CLIENT_HANDSHAKE_DONE || !res.have_key) {
        close(fd);
        return -1;
    }
    memcpy(out_key, res.key, CLOAK_AEAD_KEY_LEN);
    return fd;
}

typedef struct {
    cloak_session_t sesh;
    int sesh_ready;
    int broken;
    uint8_t key[CLOAK_AEAD_KEY_LEN];
} client_t;

static void client_on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    client_t *c = userdata;
    c->broken = 1;
}

static void client_session_config(cloak_session_config_t *ccfg) {
    memset(ccfg, 0, sizeof(*ccfg));
    ccfg->ordering = CLOAK_SESSION_ORDERING_ORDERED;
    ccfg->max_on_wire_size = 16401;
    ccfg->stream_recv_capacity = 65536;
    ccfg->stream_max_pending_frames = 64;
    ccfg->conn_send_queue_cap = 262144;
    ccfg->inactivity_timeout_ms = 60000;
}

/* Brings up the client side of a session over an already-handshaken fd.
 * The fd becomes the session's on success. */
static int client_session_start(client_t *c, struct fixture *fx, uint32_t session_id, int fd,
                                const uint8_t key[CLOAK_AEAD_KEY_LEN]) {
    memset(c, 0, sizeof(*c));
    memcpy(c->key, key, CLOAK_AEAD_KEY_LEN);

    cloak_session_config_t ccfg;
    client_session_config(&ccfg);
    ccfg.obfuscator.method = CLOAK_AEAD_AES_256_GCM;
    memcpy(ccfg.obfuscator.session_key, key, CLOAK_AEAD_KEY_LEN);
    ccfg.on_broken = client_on_broken;
    ccfg.on_broken_userdata = c;

    if (cloak_session_init(&c->sesh, session_id, fx->reactor, &ccfg) != 0) {
        close(fd);
        return -1;
    }
    c->sesh_ready = 1;
    if (cloak_session_add_conn(&c->sesh, fd) != 0) {
        /* cloak_session_add_conn's contract: the caller still owns fd on
         * failure. */
        close(fd);
        cloak_session_destroy(&c->sesh);
        c->sesh_ready = 0;
        return -1;
    }
    return 0;
}

static void client_close(client_t *c) {
    if (c->sesh_ready) {
        cloak_session_destroy(&c->sesh);
        c->sesh_ready = 0;
    }
}

/* Handshake + session in one call, for the tests that need only one
 * connection. */
static int client_open(client_t *c, struct fixture *fx, uint32_t session_id) {
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    int fd = client_handshake(fx, session_id, key);
    if (fd < 0) {
        return -1;
    }
    return client_session_start(c, fx, session_id, fd, key);
}

/* ---- client-side stream reading ---------------------------------------- */

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

/* ---- test 1: the handshake, the session, and the bytes ------------------ */

#define E2E_SID ((uint32_t)4101)

static const uint8_t E2E_PAYLOAD[] = {
    'c', 'l', 'o', 'a', 'k', '-', 'c', 'l', 'i', 'e', 'n', 't', '-', 'e', '2', 'e',
    0x00, 0xff, 0x7f, 0x80, 0x01, 0xfe, 0x55, 0xaa,
};
#define E2E_PAYLOAD_LEN (sizeof(E2E_PAYLOAD))

/* A REAL cloak_client_handshake_t against the merged server, then a real
 * client-side cloak_session_t over the same socket, then bytes.
 *
 * The three assertions that carry this test, in increasing strength:
 *
 *   1. The handshake completed and the dispatcher created a session --
 *      counters, which a broken data path would still satisfy.
 *   2. The key the CLIENT recovered equals the key the SERVER stored in
 *      its own cloak_session_t, compared byte for byte against
 *      sesh->obfuscator.session_key. Nothing is inferred from traffic
 *      here and nothing is hand-computed: it is the server's own memory.
 *   3. The payload arrived at the upstream byte for byte, and its
 *      complement came back to the client byte for byte. THIS is the
 *      assertion that separates a working session from one that
 *      establishes cleanly and silently drops every frame -- the failure
 *      mode this project has hit before, which every counter above
 *      reports as success. */
static void test_client_transport_carries_bytes_end_to_end(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t c;
    ASSERT_EQ_INT(0, client_open(&c, &fx, E2E_SID));

    ASSERT_EQ_INT(1, fx.attached_calls);
    ASSERT_EQ_INT(1, fx.attached_created);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    /* The panel really is in the path: a bypass UID still becomes an
     * active user, and it is the panel's valve the session was given. */
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(fx.panel));
    ASSERT_EQ_INT(0, fx.cover.accept_count);

    /* THE KEY, against the server's own session object. */
    cloak_session_t *server_sesh = cloak_server_registry_find(&fx.registry, fx.uid, E2E_SID);
    ASSERT_TRUE(server_sesh != NULL);
    if (server_sesh == NULL) {
        client_close(&c);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_MEM_EQ(c.key, server_sesh->obfuscator.session_key, CLOAK_AEAD_KEY_LEN);

    cloak_stream_t *st = cloak_session_open_stream(&c.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_close(&c);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT((int)E2E_PAYLOAD_LEN,
                  (int)cloak_stream_write(st, E2E_PAYLOAD, E2E_PAYLOAD_LEN));

    struct up_wait uw = {&fx.up, 0, E2E_PAYLOAD_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_EQ_INT(1, fx.up.accept_count);
    ASSERT_EQ_INT((int)E2E_PAYLOAD_LEN, (int)fx.up.conns[0].in_len);
    ASSERT_MEM_EQ(fx.up.conns[0].in, E2E_PAYLOAD, E2E_PAYLOAD_LEN);

    uint8_t expect_back[E2E_PAYLOAD_LEN];
    for (size_t i = 0; i < E2E_PAYLOAD_LEN; i++) {
        expect_back[i] = (uint8_t)~E2E_PAYLOAD[i];
    }
    uint8_t back[E2E_PAYLOAD_LEN];
    reader_t rd = {st, back, sizeof(back), 0, 0};
    struct reader_wait rw = {&rd, E2E_PAYLOAD_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rw, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_EQ_INT((int)E2E_PAYLOAD_LEN, (int)rd.len);
    ASSERT_MEM_EQ(rd.buf, expect_back, E2E_PAYLOAD_LEN);

    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, c.broken);

    cloak_session_release_stream(&c.sesh, st);
    client_close(&c);
    fixture_destroy(&fx);
}

/* ---- test 2: two client connections, one session ------------------------ */

#define TWO_SID ((uint32_t)4102)
#define TWO_LEN ((size_t)(64u * 1024u))

/* TWO REAL CLIENT HANDSHAKES joining ONE session, each carrying a stream.
 *
 * Both handshakes run to completion BEFORE either socket is handed to a
 * cloak_session_t, which is the shape a single "open a client" helper
 * cannot express. The second connection's recovered key must equal the
 * first's -- the live-session-key rule -- and the client builds its
 * obfuscator from the SECOND connection's key, which is what a client
 * that trusts the server's answer would do. A fresh key on the join
 * therefore does not merely differ: it produces a session that carries no
 * bytes at all, which the byte assertions below are what detect.
 *
 * TWO_LEN of traffic per stream is enough that "the switchboard picked
 * one connection uniformly at random every time and never once picked the
 * other" is not a live possibility (cloak_switchboard_send's choice is
 * documented as uniform-random per frame, and this is tens of frames), so
 * the byte assertions cover BOTH connections rather than whichever one
 * got lucky. */
static void test_two_client_connections_one_session(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    uint8_t key1[CLOAK_AEAD_KEY_LEN];
    uint8_t key2[CLOAK_AEAD_KEY_LEN];
    int fd1 = client_handshake(&fx, TWO_SID, key1);
    ASSERT_TRUE(fd1 >= 0);
    int fd2 = client_handshake(&fx, TWO_SID, key2);
    ASSERT_TRUE(fd2 >= 0);
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

    ASSERT_EQ_INT(2, fx.attached_calls);
    ASSERT_EQ_INT(1, fx.attached_created); /* the second JOINED */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(fx.panel));
    ASSERT_MEM_EQ(key2, key1, CLOAK_AEAD_KEY_LEN);

    cloak_session_t *server_sesh = cloak_server_registry_find(&fx.registry, fx.uid, TWO_SID);
    ASSERT_TRUE(server_sesh != NULL);
    if (server_sesh == NULL) {
        close(fd1);
        close(fd2);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(2, (int)cloak_switchboard_conn_count(&server_sesh->sb));
    ASSERT_MEM_EQ(key2, server_sesh->obfuscator.session_key, CLOAK_AEAD_KEY_LEN);

    client_t c;
    ASSERT_EQ_INT(0, client_session_start(&c, &fx, TWO_SID, fd1, key2));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&c.sesh, fd2));
    ASSERT_EQ_INT(2, (int)cloak_switchboard_conn_count(&c.sesh.sb));

    uint8_t *a_src = malloc(TWO_LEN);
    uint8_t *b_src = malloc(TWO_LEN);
    uint8_t *a_dst = malloc(TWO_LEN);
    uint8_t *b_dst = malloc(TWO_LEN);
    ASSERT_TRUE(a_src != NULL && b_src != NULL && a_dst != NULL && b_dst != NULL);
    if (a_src == NULL || b_src == NULL || a_dst == NULL || b_dst == NULL) {
        free(a_src);
        free(b_src);
        free(a_dst);
        free(b_dst);
        client_close(&c);
        fixture_destroy(&fx);
        return;
    }
    for (size_t i = 0; i < TWO_LEN; i++) {
        a_src[i] = (uint8_t)((i * 7u + 1u) & 0xff);
        b_src[i] = (uint8_t)((i * 11u + 2u) & 0xff);
    }

    cloak_stream_t *sa = cloak_session_open_stream(&c.sesh, NULL);
    cloak_stream_t *sb = cloak_session_open_stream(&c.sesh, NULL);
    ASSERT_TRUE(sa != NULL && sb != NULL);
    if (sa == NULL || sb == NULL) {
        free(a_src);
        free(b_src);
        free(a_dst);
        free(b_dst);
        client_close(&c);
        fixture_destroy(&fx);
        return;
    }

    /* One stream at a time up to its first upstream connection, so the
     * (stream -> upstream connection) mapping is deterministic and the
     * byte assertions below name a definite peer. */
    ASSERT_EQ_INT(1, (int)cloak_stream_write(sa, a_src, 1));
    struct up_wait w1 = {&fx.up, 1, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &w1, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_stream_write(sb, b_src, 1));
    struct up_wait w2 = {&fx.up, 2, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &w2, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_EQ_INT(2, fx.up.accept_count);

    reader_t ra = {sa, a_dst, TWO_LEN, 0, 0};
    reader_t rb = {sb, b_dst, TWO_LEN, 0, 0};

    /* The rest of each buffer, written in frame-sized chunks paced against
     * the session's own per-connection send budget: cloak_stream_write
     * never fails on a full queue, it overruns the connection's hard cap
     * and breaks the whole pool (cloak/session.h), so this mirrors what
     * cloak_stream_relay_t does internally. The readers are drained as we
     * go so the returning complement cannot back up. */
    size_t a_sent = 1;
    size_t b_sent = 1;
    int stalled = 0;
    for (int turn = 0; turn < E2E_MAX_TURNS && (a_sent < TWO_LEN || b_sent < TWO_LEN); turn++) {
        reader_poll(&ra);
        reader_poll(&rb);
        int moved = 0;
        while (a_sent < TWO_LEN && cloak_session_send_min_conn_free(&c.sesh) >= 2 * 16401) {
            size_t chunk = sa->max_payload_per_frame;
            if (chunk > TWO_LEN - a_sent) {
                chunk = TWO_LEN - a_sent;
            }
            if (cloak_stream_write(sa, a_src + a_sent, chunk) < 0) {
                stalled = 1;
                break;
            }
            a_sent += chunk;
            moved = 1;
        }
        while (b_sent < TWO_LEN && cloak_session_send_min_conn_free(&c.sesh) >= 2 * 16401) {
            size_t chunk = sb->max_payload_per_frame;
            if (chunk > TWO_LEN - b_sent) {
                chunk = TWO_LEN - b_sent;
            }
            if (cloak_stream_write(sb, b_src + b_sent, chunk) < 0) {
                stalled = 1;
                break;
            }
            b_sent += chunk;
            moved = 1;
        }
        (void)moved;
        if (stalled) {
            break;
        }
        cloak_reactor_run_once(fx.reactor, E2E_TURN_MS);
    }
    ASSERT_EQ_INT(0, stalled);
    ASSERT_EQ_INT((int)TWO_LEN, (int)a_sent);
    ASSERT_EQ_INT((int)TWO_LEN, (int)b_sent);

    struct up_wait ua = {&fx.up, 0, TWO_LEN};
    struct up_wait ub = {&fx.up, 1, TWO_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &ua, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &ub, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_EQ_INT((int)TWO_LEN, (int)fx.up.conns[0].in_len);
    ASSERT_EQ_INT((int)TWO_LEN, (int)fx.up.conns[1].in_len);
    ASSERT_MEM_EQ(fx.up.conns[0].in, a_src, TWO_LEN);
    ASSERT_MEM_EQ(fx.up.conns[1].in, b_src, TWO_LEN);

    struct reader_wait rwa = {&ra, TWO_LEN};
    struct reader_wait rwb = {&rb, TWO_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rwa, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rwb, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_EQ_INT((int)TWO_LEN, (int)ra.len);
    ASSERT_EQ_INT((int)TWO_LEN, (int)rb.len);
    for (size_t i = 0; i < TWO_LEN; i++) {
        a_src[i] = (uint8_t)~a_src[i];
        b_src[i] = (uint8_t)~b_src[i];
    }
    ASSERT_MEM_EQ(ra.buf, a_src, TWO_LEN);
    ASSERT_MEM_EQ(rb.buf, b_src, TWO_LEN);

    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, c.broken);

    free(a_src);
    free(b_src);
    free(a_dst);
    free(b_dst);
    cloak_session_release_stream(&c.sesh, sa);
    cloak_session_release_stream(&c.sesh, sb);
    client_close(&c);
    fixture_destroy(&fx);
}

/* ---- test 3: the client's own teardown --------------------------------- */

#define TD_SID ((uint32_t)4103)

struct reg_wait {
    struct fixture *fx;
    size_t want;
};

static int registry_count_is(void *ctx) {
    struct reg_wait *w = ctx;
    return cloak_server_registry_count(&w->fx->registry) == w->want;
}

/* THE CLIENT SIDE TEARS ITSELF DOWN, AND THE SERVER NOTICES. Most of what
 * this can catch is only visible under ASan: a stream still reachable
 * from a destroyed session, a connection whose reactor registration
 * outlived it, a relay holding a freed stream on the far side. The plain
 * Debug build sees the counters and nothing else, which is why this test
 * is run under the sanitizer suite as well.
 *
 * The client is torn down FIRST, while the whole server is still live and
 * still registered with the shared reactor -- the order a real client
 * exiting produces, and the one in which a dangling registration has
 * somewhere to fire. The reactor is then pumped so the server observes
 * every close and unwinds, and only then is the server shut down. */
static void test_client_teardown_frees_everything(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t c;
    ASSERT_EQ_INT(0, client_open(&c, &fx, TD_SID));

    cloak_stream_t *s1 = cloak_session_open_stream(&c.sesh, NULL);
    cloak_stream_t *s2 = cloak_session_open_stream(&c.sesh, NULL);
    ASSERT_TRUE(s1 != NULL && s2 != NULL);
    if (s1 == NULL || s2 == NULL) {
        client_close(&c);
        fixture_destroy(&fx);
        return;
    }

    /* Both streams relaying, with bytes genuinely across the stack --
     * otherwise this would be a teardown test with nothing to tear down. */
    ASSERT_EQ_INT(5, (int)cloak_stream_write(s1, (const uint8_t *)"one--", 5));
    struct up_wait u1 = {&fx.up, 0, 5};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &u1, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_EQ_INT(5, (int)cloak_stream_write(s2, (const uint8_t *)"two--", 5));
    struct up_wait u2 = {&fx.up, 1, 5};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &u2, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_EQ_INT(2, fx.up.accept_count);
    ASSERT_MEM_EQ(fx.up.conns[0].in, "one--", 5);
    ASSERT_MEM_EQ(fx.up.conns[1].in, "two--", 5);
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    /* THE TEARDOWN UNDER TEST. cloak_session_destroy reclaims the two
     * still-active streams, closes the connection and deregisters its fd;
     * nothing else on the client side is left to free. No stream is
     * released by hand first, on purpose: reclaiming active streams is
     * part of what is being exercised. */
    client_close(&c);
    ASSERT_EQ_INT(0, c.sesh_ready);

    /* The server observes the close and unwinds the session, the proxy's
     * context and both relays. Bounded, and asserted rather than assumed. */
    struct reg_wait rw = {&fx, 0};
    ASSERT_TRUE(pump_until(fx.reactor, registry_count_is, &rw, E2E_MAX_TURNS, E2E_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

    /* Nothing may fire into the wreckage afterwards. A fixed number of
     * turns rather than a wall-clock window: nothing here waits for a
     * timer, only for any registration the teardown failed to remove to be
     * dispatched at all. The upstream sockets are still open and still
     * registered, so a relay that outlived its session would be handed a
     * byte here. */
    for (int i = 0; i < 200; i++) {
        cloak_reactor_run_once(fx.reactor, 2);
    }
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

    fixture_destroy(&fx);
}

TEST_MAIN_BEGIN()
test_client_transport_carries_bytes_end_to_end();
test_two_client_connections_one_session();
test_client_teardown_frees_everything();
TEST_MAIN_END()
