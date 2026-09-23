#define _POSIX_C_SOURCE 200809L

/* THE WHOLE THING, WIRED AS TWO BINARIES WILL BE.
 *
 * An application socket at the near end; a cloak_client_piper_t over a
 * cloak_client_connector_t; N underlying TCP connections; the merged
 * server -- listener, dispatcher, registry, server state, user manager,
 * user panel, cloak_proxy_t; and a fake upstream beyond that. Every
 * object on both sides is library code. Nothing here is a mock except
 * the upstream and the "application", which are the two things a real
 * deployment supplies from outside.
 *
 * FOUR CONSTRUCTIONS CARRY THIS FILE, and each exists to keep a case
 * from passing through a path other than the one it names.
 *
 * 1. THE UPSTREAM DOES NOT ECHO. It replies with every byte it received
 *    XORed with 0xFF. An echoing upstream would let case 1 pass against
 *    a client that never opened a stream at all and simply wrote the
 *    local connection's own bytes back at it. XOR cannot be produced
 *    anywhere on the client side, so a reply that arrives transformed is
 *    proof the bytes crossed the tunnel, reached the upstream and came
 *    back. THIS IS THE POINT OF CASE 1: a session built on a WRONG key
 *    establishes cleanly and then drops every frame silently, so "the
 *    connection was accepted" proves nothing at all about the data path.
 *    Only bytes do.
 *
 * 2. CONCURRENT CONNECTIONS USE DIFFERENT PAYLOADS. A crossed route --
 *    connection A's bytes arriving on B's stream -- passes a
 *    single-connection test and passes a multi-connection test with
 *    identical payloads. Because the reply is derived from what arrived,
 *    one assertion per peer ("I got back MY OWN payload, transformed")
 *    pins both directions at once.
 *
 * 3. A TCP SPLICE SHIM, so a case can kill ONE underlying connection.
 *    Every other test in this tree has the client dial the in-process
 *    server's own listener, which means the accepted socket belongs to
 *    the dispatcher and no case holds a descriptor for it -- so a
 *    session dying from a real network failure on one connection of
 *    several was, until this file, unreachable. shim_t sits between the
 *    client and the front door, one splice per underlying connection,
 *    and shim_kill_client_side closes exactly one of them while leaving
 *    the SERVER's end of that splice open and the server unaware. That
 *    isolation is what makes case 4's answer meaningful: the client
 *    loses one connection out of two while the other is demonstrably
 *    healthy and the far end has noticed nothing.
 *
 * 4. THE OUT-OF-CREDIT USER IS A REAL DATABASE USER. Every other client
 *    test in this directory authenticates a BypassUID, which is exempt
 *    from accounting and can therefore never be terminated. Case 3 uses
 *    a second, metered UID with a real row, real credit, and a real
 *    cloak_userpanel_upload_now cycle -- so the termination is the
 *    server's own policy firing, not a test poking a registry.
 *
 * EVERY WAIT IS A BOUNDED pump_until whose result is asserted. No case
 * in this file asserts a TIMING property -- there is no deadline under
 * test here -- so there is no wall-clock bound to bracket; the bounds
 * that exist are liveness bounds ("this happened rather than hanging"),
 * and asserting pump_until's return value is what enforces them. Every
 * peer socket is non-blocking. */

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
#include "cloak/switchboard.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
#include "cloak/valve.h"
#include "test_framework.h"

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- bounded reactor pumping ------------------------------------------- */

/* Sized so a BROKEN run fails an ASSERTION rather than the ctest timeout:
 * at FE2E_MAX_TURNS turns of FE2E_TURN_MS each, one wait is at most ~2 s,
 * and the waits in this file total well under TIMEOUT 60. The 512 KiB
 * transfers are the ones that need the headroom; the rest settle in a few
 * dozen turns on loopback. */
#define FE2E_MAX_TURNS 2000
#define FE2E_TURN_MS 1

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

/* Open descriptors, counted from /proc/self/fd. LeakSanitizer tracks
 * memory, not file descriptors: a stack that freed every byte it
 * allocated and quietly dropped a socket is indistinguishable, to ASan
 * and to every counter in this file, from a correct one. Returns -1 where
 * /proc is absent, and every call site asserts that did not happen -- a
 * -1 == -1 comparison is how this check silently stopped working on a
 * previous branch. */
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
#define UP_BUF_CAP ((size_t)(4u << 20))

/* NOT an echo. See this file's header. */
#define UP_XOR ((uint8_t)0xFF)

typedef struct {
    int fd;
    uint8_t *in; /* everything ever read, for byte-for-byte assertions */
    size_t in_len;
    uint8_t *out; /* pending reply bytes not yet accepted by the socket */
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

struct up_wait {
    upstream_t *up;
    int idx;
    size_t want;
};

static int up_has_len(void *ctx) {
    struct up_wait *w = ctx;
    return w->up->accept_count > w->idx && w->up->conns[w->idx].in_len >= w->want;
}

static int up_saw_eof(void *ctx) {
    struct up_wait *w = ctx;
    return w->up->accept_count > w->idx && w->up->conns[w->idx].eof != 0;
}

/* Everything every upstream connection has received, summed. */
static size_t up_total_in(upstream_t *up) {
    size_t n = 0;
    for (int i = 0; i < up->accept_count; i++) {
        n += up->conns[i].in_len;
    }
    return n;
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
    snprintf(buf, cap, "%s/cloak_client_full_e2e_%ld.db", dir, (long)getpid());
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

/* THE METERED USER'S UPLOAD CREDIT. Small enough that case 3's transfer
 * overruns it several times over -- a user's UPLOAD is the server's RX
 * (cloak/usermanager.h says so), and case 3 pushes 256 KiB client-to-
 * server. Not zero, because zero denies at AUTHENTICATION time
 * (cloak_usermanager_authenticate checks up_credit > 0 before a session
 * exists at all) and case 3 needs a user who gets in and is then cut
 * off mid-transfer, which is a different code path entirely. */
#define METERED_UP_CREDIT ((int64_t)4096)
#define METERED_DOWN_CREDIT ((int64_t)(1 << 30))
#define METERED_SESSIONS_CAP 4

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
    uint8_t uid[CLOAK_UID_LEN];  /* the BypassUID: exempt from accounting */
    uint8_t muid[CLOAK_UID_LEN]; /* a real, metered row in the database */

    /* The max_on_wire_size BOTH ends are built with. Both must agree -- a
     * connection whose peer frames larger than its own max_frame_len is
     * broken by the connection layer, not tolerated. */
    size_t wire;

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

/* The wire size every case here uses -- the value the rest of this
 * project's tests are built with. */
#define FE2E_WIRE ((size_t)16401)

static int fixture_init(struct fixture *fx) {
    memset(fx, 0, sizeof(*fx));
    fx->wire = FE2E_WIRE;
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
        fx->muid[i] = (uint8_t)(0x90 + i);
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

    /* The metered user. Every gate in cloak_usermanager_write defaults to
     * DENY, so all four have to be named explicitly or this user cannot
     * authenticate at all -- and a case 3 that silently never connected
     * would still "pass" a test that only asserted the client went away. */
    cloak_user_info_t mu;
    memset(&mu, 0, sizeof(mu));
    memcpy(mu.uid, fx->muid, CLOAK_UID_LEN);
    mu.sessions_cap = METERED_SESSIONS_CAP;
    mu.up_rate = 0;
    mu.down_rate = 0;
    mu.up_credit = METERED_UP_CREDIT;
    mu.down_credit = METERED_DOWN_CREDIT;
    mu.expiry_time = (int64_t)PANEL_NOW + 86400;
    ASSERT_EQ_INT(0, cloak_usermanager_write(fx->mgr, &mu, CLOAK_USER_FIELD_ALL));

    ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor,
                                                cloak_proxy_registry_broken, &fx->proxy));
    fx->registry_ready = 1;

    cloak_userpanel_config_t upcfg;
    memset(&upcfg, 0, sizeof(upcfg));
    upcfg.manager = fx->mgr;
    upcfg.registry = &fx->registry;
    upcfg.reactor = fx->reactor;
    /* An hour: every case that needs an upload cycle drives it by hand
     * with cloak_userpanel_upload_now, so no case depends on when a timer
     * happens to fire. */
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
    return 0;
}

static int front_port(struct fixture *fx) {
    return cloak_listener_port(&fx->front);
}

/* The shutdown order a server binary must use: listener, dispatcher,
 * PROXY BEFORE REGISTRY, registry, panel, manager, server state. Case 5B
 * calls this on its own, mid-session. */
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

/* ---- the TCP splice shim ------------------------------------------------
 *
 * THE FIXTURE FEATURE THE PREVIOUS TASK'S REVIEW ASKED FOR. Every test in
 * this tree has the client dial the in-process server's own listener, so
 * the accepted socket belongs to cloak_dispatcher_accept and no case
 * holds a descriptor for it. That makes "one underlying connection of
 * several dies of a network fault" unreachable: the only levers available
 * are killing the WHOLE server (which kills every connection at once) and
 * killing a session from the inside (which is not a network fault at
 * all). Neither answers case 4's question.
 *
 * So the client dials this instead: one plain TCP splice per underlying
 * connection, forwarding both directions verbatim. It is deliberately
 * dumb -- it parses nothing, and neither end can tell it is there.
 *
 * shim_kill_client_side(sh, i) closes ONLY the client's end of splice i.
 * The server's end stays open and registered, and the shim goes on
 * draining and DISCARDING whatever the server sends down it, so the
 * server never blocks and never learns. That asymmetry is the whole
 * point: after the kill the client has lost exactly one connection, the
 * other is provably healthy (shim_conn_t::c2s_bytes still climbing, no
 * EOF seen), and the far end has noticed nothing. Anything the client
 * does next is a decision the client made on its own. */

#define SHIM_MAX_CONNS 4
#define SHIM_BUF ((size_t)65536)

struct shim;
typedef struct {
    struct shim *sh;
    int idx;
} shim_slot_t;

typedef struct {
    int cfd; /* the client's side of this splice */
    int sfd; /* the real server's side */
    int cfd_reg;
    int sfd_reg;
    cloak_dial_t dial;
    int dialing;

    uint8_t c2s[SHIM_BUF];
    size_t c2s_len;
    uint8_t s2c[SHIM_BUF];
    size_t s2c_len;

    /* Bytes forwarded in each direction since this splice was accepted.
     * What makes "both underlying connections are really carrying this
     * session's traffic" an assertion rather than an assumption. */
    size_t c2s_bytes;
    size_t s2c_bytes;

    int client_eof; /* the CLIENT closed or reset its end */
    int killed;     /* this test closed the client end on purpose */
} shim_conn_t;

typedef struct shim {
    cloak_reactor_t *reactor;
    cloak_listener_t l;
    int have_listener;
    cloak_addr_t front;
    int port;

    int count;
    shim_conn_t conns[SHIM_MAX_CONNS];
    shim_slot_t cslots[SHIM_MAX_CONNS];
    shim_slot_t sslots[SHIM_MAX_CONNS];
} shim_t;

static void shim_sync(shim_t *sh, int idx);

static size_t shim_drain(int fd, uint8_t *buf, size_t *len) {
    size_t sent = 0;
    while (sent < *len) {
        ssize_t n = send(fd, buf + sent, *len - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (sent > 0) {
        memmove(buf, buf + sent, *len - sent);
        *len -= sent;
    }
    return sent;
}

static void shim_fill(int fd, uint8_t *buf, size_t *len, int *eof) {
    while (*len < SHIM_BUF) {
        ssize_t n = read(fd, buf + *len, SHIM_BUF - *len);
        if (n > 0) {
            *len += (size_t)n;
            continue;
        }
        if (n == 0) {
            if (eof != NULL) {
                *eof = 1;
            }
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        break;
    }
}

static void shim_on_client(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    shim_slot_t *slot = userdata;
    shim_t *sh = slot->sh;
    shim_conn_t *c = &sh->conns[slot->idx];

    if ((events & CLOAK_REACTOR_WRITABLE) != 0 && c->cfd >= 0) {
        c->s2c_bytes += shim_drain(c->cfd, c->s2c, &c->s2c_len);
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0 && c->cfd >= 0) {
        shim_fill(c->cfd, c->c2s, &c->c2s_len, &c->client_eof);
        if (c->sfd >= 0) {
            c->c2s_bytes += shim_drain(c->sfd, c->c2s, &c->c2s_len);
        }
    }
    shim_sync(sh, slot->idx);
}

static void shim_on_server(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    shim_slot_t *slot = userdata;
    shim_t *sh = slot->sh;
    shim_conn_t *c = &sh->conns[slot->idx];

    if ((events & CLOAK_REACTOR_WRITABLE) != 0 && c->sfd >= 0) {
        c->c2s_bytes += shim_drain(c->sfd, c->c2s, &c->c2s_len);
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0 && c->sfd >= 0) {
        shim_fill(c->sfd, c->s2c, &c->s2c_len, NULL);
        if (c->cfd >= 0) {
            c->s2c_bytes += shim_drain(c->cfd, c->s2c, &c->s2c_len);
        } else {
            /* The client's end is gone (killed). DISCARD rather than
             * accumulate, so the server keeps writing happily and never
             * discovers that anything is wrong -- see this section's
             * header for why that asymmetry is the point. */
            c->s2c_len = 0;
        }
    }
    shim_sync(sh, slot->idx);
}

static void shim_sync(shim_t *sh, int idx) {
    shim_conn_t *c = &sh->conns[idx];
    if (c->cfd_reg && c->cfd >= 0) {
        uint32_t ev = 0;
        if (c->c2s_len < SHIM_BUF) {
            ev |= CLOAK_REACTOR_READABLE;
        }
        if (c->s2c_len > 0) {
            ev |= CLOAK_REACTOR_WRITABLE;
        }
        (void)cloak_reactor_mod_fd(sh->reactor, c->cfd, ev);
    }
    if (c->sfd_reg && c->sfd >= 0) {
        uint32_t ev = CLOAK_REACTOR_READABLE;
        if (c->c2s_len > 0) {
            ev |= CLOAK_REACTOR_WRITABLE;
        }
        (void)cloak_reactor_mod_fd(sh->reactor, c->sfd, ev);
    }
}

static void shim_on_dial(cloak_dial_t *d, int fd, void *userdata) {
    (void)d;
    shim_slot_t *slot = userdata;
    shim_t *sh = slot->sh;
    shim_conn_t *c = &sh->conns[slot->idx];
    c->dialing = 0;
    if (fd < 0) {
        return;
    }
    c->sfd = fd;
    if (cloak_reactor_add_fd(sh->reactor, fd, CLOAK_REACTOR_READABLE, shim_on_server,
                             &sh->sslots[slot->idx]) != 0) {
        close(fd);
        c->sfd = -1;
        return;
    }
    c->sfd_reg = 1;
    shim_sync(sh, slot->idx);
}

static void shim_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    shim_t *sh = userdata;
    if (sh->count >= SHIM_MAX_CONNS) {
        close(fd);
        return;
    }
    int idx = sh->count++;
    shim_conn_t *c = &sh->conns[idx];
    c->cfd = fd;
    sh->cslots[idx].sh = sh;
    sh->cslots[idx].idx = idx;
    sh->sslots[idx].sh = sh;
    sh->sslots[idx].idx = idx;
    if (cloak_reactor_add_fd(sh->reactor, fd, CLOAK_REACTOR_READABLE, shim_on_client,
                             &sh->cslots[idx]) != 0) {
        close(fd);
        c->cfd = -1;
        return;
    }
    c->cfd_reg = 1;
    char err[256];
    if (cloak_dial_start(&c->dial, sh->reactor, &sh->front, 5000, shim_on_dial, &sh->sslots[idx],
                         err, sizeof(err)) != 0) {
        return;
    }
    c->dialing = 1;
}

static int shim_open(shim_t *sh, cloak_reactor_t *r, int front_tcp_port) {
    memset(sh, 0, sizeof(*sh));
    sh->reactor = r;
    for (int i = 0; i < SHIM_MAX_CONNS; i++) {
        sh->conns[i].cfd = -1;
        sh->conns[i].sfd = -1;
    }
    char addr[64];
    char err[256];
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", front_tcp_port);
    if (cloak_net_resolve(addr, 0, &sh->front, err, sizeof(err)) != 0) {
        return -1;
    }
    if (cloak_listener_open(&sh->l, r, "127.0.0.1:0", shim_on_accept, sh, err, sizeof(err)) != 0) {
        return -1;
    }
    sh->have_listener = 1;
    sh->port = cloak_listener_port(&sh->l);
    return sh->port > 0 ? 0 : -1;
}

/* Closes ONE splice's client end and nothing else. The server's end stays
 * open, registered and draining. */
static void shim_kill_client_side(shim_t *sh, int idx) {
    shim_conn_t *c = &sh->conns[idx];
    c->killed = 1;
    if (c->cfd_reg) {
        cloak_reactor_remove_fd(sh->reactor, c->cfd);
        c->cfd_reg = 0;
    }
    if (c->cfd >= 0) {
        close(c->cfd);
        c->cfd = -1;
    }
    c->s2c_len = 0;
}

static void shim_close(shim_t *sh) {
    if (sh->have_listener) {
        cloak_listener_close(&sh->l);
        sh->have_listener = 0;
    }
    for (int i = 0; i < SHIM_MAX_CONNS; i++) {
        shim_conn_t *c = &sh->conns[i];
        if (c->dialing) {
            cloak_dial_cancel(&c->dial);
            c->dialing = 0;
        }
        if (c->cfd_reg) {
            cloak_reactor_remove_fd(sh->reactor, c->cfd);
            c->cfd_reg = 0;
        }
        if (c->cfd >= 0) {
            close(c->cfd);
            c->cfd = -1;
        }
        if (c->sfd_reg) {
            cloak_reactor_remove_fd(sh->reactor, c->sfd);
            c->sfd_reg = 0;
        }
        if (c->sfd >= 0) {
            close(c->sfd);
            c->sfd = -1;
        }
    }
}

struct shim_wait {
    shim_t *sh;
    int want;
};

static int shim_spliced(void *ctx) {
    struct shim_wait *w = ctx;
    if (w->sh->count < w->want) {
        return 0;
    }
    for (int i = 0; i < w->want; i++) {
        if (w->sh->conns[i].sfd < 0) {
            return 0;
        }
    }
    return 1;
}

/* Both splices have forwarded client-to-server bytes past the marks taken
 * when the session came up -- i.e. this session's frames really are
 * spread across both underlying connections, which is what makes
 * "killing one of two live connections" a true description of case 4. */
struct shim_growth_wait {
    shim_t *sh;
    int n;
    size_t marks[SHIM_MAX_CONNS];
};

static int shim_all_grew(void *ctx) {
    struct shim_growth_wait *w = ctx;
    for (int i = 0; i < w->n; i++) {
        if (w->sh->conns[i].c2s_bytes <= w->marks[i]) {
            return 0;
        }
    }
    return 1;
}

/* ---- the local peer: the "application" the piper serves ------------------ */

#define LP_BUF_CAP ((size_t)(4u << 20))

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

/* Byte-for-byte against one upstream connection's received bytes.
 * Separate from an inline ASSERT_MEM_EQ because memcmp against a NULL
 * pointer is undefined and a FAILING run is precisely when the upstream
 * may have accepted nothing at all -- a test that crashes on its own
 * first failure hides every assertion after it, which is how a mutation
 * run stops being informative. */
static void assert_up_bytes(upstream_t *up, int idx, const uint8_t *want, size_t len) {
    ASSERT_TRUE(up->accept_count > idx);
    if (up->accept_count <= idx || up->conns[idx].in == NULL) {
        return;
    }
    ASSERT_EQ_INT((int)len, (int)up->conns[idx].in_len);
    ASSERT_MEM_EQ(up->conns[idx].in, want, len);
}

static void xor_fill(uint8_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = (uint8_t)(src[i] ^ UP_XOR);
    }
}

/* ---- the client side: connector + piper + a local listener -------------- */

typedef struct {
    int calls;
    cloak_client_connector_status_t status;
    cloak_session_t *session;
} conn_result_t;

static void conn_done(cloak_client_connector_t *c, cloak_client_connector_status_t status,
                      cloak_session_t *session, void *userdata) {
    (void)c;
    conn_result_t *res = userdata;
    res->calls++;
    res->status = status;
    res->session = session;
}

static int conn_fired(void *ctx) {
    conn_result_t *res = ctx;
    return res->calls > 0;
}

typedef struct {
    struct fixture *fx;
    cloak_session_t sesh;
    int session_live;

    conn_result_t res;
    cloak_client_connector_t c;
    int connector_ready;

    cloak_client_piper_t piper;
    int piper_ready;

    cloak_listener_t local;
    int have_local;
    int local_port;

    /* cfg.chain: the owner's own bookkeeping, invoked AFTER the piper has
     * stopped every relay. */
    int broken_calls;
    /* THE CLIENT'S STATE AT THE INSTANT THE CHAIN RUNS, which is the only
     * moment at which several of these questions are answerable at all --
     * after on_broken returns the mux frees the session's streams and
     * closes its pool anyway, so every counter below reaches zero
     * eventually whether or not anything did its job. */
    size_t conns_at_broken;
    size_t streams_at_broken;
    size_t session_active_streams_at_broken;
    /* How many UNDERLYING connections the session's pool still held when
     * it declared itself broken. READ THIS NUMBER FOR WHAT IT IS: the
     * pool's array does NOT shrink when one connection dies (only
     * cloak_switchboard_close_all empties it), so this says the pool was
     * never drained, and NOT by itself that a healthy connection
     * remained. The evidence for THAT is probe_shim below, taken from
     * outside the client entirely. */
    size_t pool_conns_at_broken;

    /* CASE 4'S REAL WITNESS, sampled at the one instant it means
     * anything. probe_shim/probe_idx name the splice this case did NOT
     * touch; the two samples say whether, at the moment the session
     * declared itself broken, that splice's client end had still sent no
     * EOF and its server end was still connected. Sampled here rather
     * than read after the fact because the session's own sweep closes
     * every remaining connection a turn later, at which point both
     * become false for reasons that have nothing to do with the
     * question. */
    shim_t *probe_shim;
    int probe_idx;
    int survivor_eof_at_broken;
    int survivor_sfd_at_broken;
} client_t;

static void cl_on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    client_t *cl = userdata;
    cl->broken_calls++;
    cl->conns_at_broken = cloak_client_piper_conn_count(&cl->piper);
    cl->streams_at_broken = cloak_client_piper_stream_count(&cl->piper);
    cl->session_active_streams_at_broken = cl->sesh.active_stream_count;
    cl->pool_conns_at_broken = cloak_switchboard_conn_count(&cl->sesh.sb);
    if (cl->probe_shim != NULL) {
        cl->survivor_eof_at_broken = cl->probe_shim->conns[cl->probe_idx].client_eof;
        cl->survivor_sfd_at_broken = cl->probe_shim->conns[cl->probe_idx].sfd;
    }
}

static int cl_broken(void *ctx) {
    client_t *cl = ctx;
    return cl->broken_calls > 0;
}

/* Brings up the whole client: a piper, a connector wired to its session
 * template, num_conn underlying connections to `port`, then the local
 * listener. `uid` picks which user authenticates -- the BypassUID for
 * every case but case 3. */
static int client_up(client_t *cl, struct fixture *fx, uint32_t session_id, int num_conn, int port,
                     const uint8_t uid[CLOAK_UID_LEN]) {
    memset(cl, 0, sizeof(*cl));
    cl->fx = fx;

    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.reactor = fx->reactor;
    pcfg.chain = cl_on_broken;
    pcfg.chain_userdata = cl;
    ASSERT_EQ_INT(0, cloak_client_piper_init(&cl->piper, &pcfg));
    cl->piper_ready = 1;

    char addr[64];
    char err[256];
    cloak_client_connector_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
    ASSERT_EQ_INT(0, cloak_net_resolve(addr, 0, &cfg.remote, err, sizeof(err)));
    cfg.reactor = fx->reactor;
    cfg.num_conn = num_conn;
    cfg.session = &cl->sesh;
    cfg.browser = CLOAK_CLIENT_BROWSER_CHROME;
    cfg.transport = CLOAK_TRANSPORT_DIRECT;
    cfg.server_name = "www.example.com";
    memcpy(cfg.server_pub, fx->server_pub, CLOAK_X25519_KEY_LEN);
    memcpy(cfg.uid, uid, CLOAK_UID_LEN);
    cfg.proxy_method = "ss";
    cfg.encryption_method = (uint8_t)CLOAK_AEAD_AES_256_GCM;
    cfg.session_id = session_id;
    cfg.dial_timeout_ms = 5000;
    cfg.handshake_timeout_ms = 10000;
    cfg.session_template.max_on_wire_size = fx->wire;
    cfg.session_template.stream_recv_capacity = 65536;
    cfg.session_template.stream_max_pending_frames = 64;
    cfg.session_template.conn_send_queue_cap = 262144;
    cfg.session_template.inactivity_timeout_ms = 60000;
    cfg.on_done = conn_done;
    cfg.on_done_userdata = &cl->res;

    /* THE ORDER MATTERS: the four session callbacks have to be in the
     * template before cloak_session_init consumes it, which is why this
     * runs before the connector is even initialized. */
    cloak_client_piper_install(&cl->piper, &cfg.session_template);

    ASSERT_EQ_INT(0, cloak_client_connector_init(&cl->c, &cfg));
    cl->connector_ready = 1;
    ASSERT_EQ_INT(0, cloak_client_connector_start(&cl->c));
    ASSERT_TRUE(pump_until(fx->reactor, conn_fired, &cl->res, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_DONE, (int)cl->res.status);
    if (cl->res.status != CLOAK_CLIENT_CONNECTOR_DONE) {
        return -1;
    }
    cl->session_live = 1;

    /* All N really joined ONE session, on the client's own side. */
    ASSERT_EQ_INT(num_conn, (int)cloak_switchboard_conn_count(&cl->sesh.sb));

    cloak_client_piper_set_session(&cl->piper, &cl->sesh);

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&cl->local, fx->reactor, "127.0.0.1:0",
                                         cloak_client_piper_on_accept, &cl->piper, err,
                                         sizeof(err)));
    cl->have_local = 1;
    cl->local_port = cloak_listener_port(&cl->local);
    ASSERT_TRUE(cl->local_port > 0);
    return 0;
}

/* The shutdown order a client binary must use: local listener, PIPER
 * BEFORE SESSION (cloak/stream_relay.h: every relay bound to a session
 * must be stopped before the session goes away), session, connector. */
static void client_down(client_t *cl) {
    if (cl->have_local) {
        cloak_listener_close(&cl->local);
        cl->have_local = 0;
    }
    if (cl->piper_ready) {
        cloak_client_piper_destroy(&cl->piper);
        cl->piper_ready = 0;
    }
    if (cl->session_live) {
        cloak_session_destroy(&cl->sesh);
        cl->session_live = 0;
    }
    if (cl->connector_ready) {
        cloak_client_connector_destroy(&cl->c);
        cl->connector_ready = 0;
    }
}

struct piper_wait {
    cloak_client_piper_t *pp;
    size_t want;
};

static int piper_streams_are(void *ctx) {
    struct piper_wait *w = ctx;
    return cloak_client_piper_stream_count(w->pp) == w->want;
}

struct proxy_wait {
    cloak_proxy_t *p;
    size_t want;
};

static int proxy_streams_are(void *ctx) {
    struct proxy_wait *w = ctx;
    return cloak_proxy_stream_count(w->p) == w->want;
}

struct registry_wait {
    struct fixture *fx;
    size_t want;
};

static int registry_count_is(void *ctx) {
    struct registry_wait *w = ctx;
    return cloak_server_registry_count(&w->fx->registry) == w->want;
}

struct valve_wait {
    cloak_valve_t *v;
    int64_t want;
};

static int valve_rx_at_least(void *ctx) {
    struct valve_wait *w = ctx;
    return cloak_valve_rx(w->v) >= w->want;
}

/* ---- case 1: an application's bytes reach the upstream and come back ---- */

#define SID_ROUNDTRIP ((uint32_t)7101)

/* THE FIRST TIME an application socket at one end and a fake upstream at
 * the other are connected by library code on BOTH sides. The assertion is
 * byte-for-byte in both directions and nothing weaker, because the
 * failure mode this project has actually hit is a session built on the
 * WRONG KEY: it establishes cleanly, every counter says "connected", and
 * then every frame is dropped silently. "The connection was accepted"
 * and "a stream exists" are both satisfied by that client. Only the
 * upstream's own received bytes, and the transformed reply arriving back
 * at the application, are not. */
static void test_a_round_trip_through_the_whole_stack(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_ROUNDTRIP, 1, front_port(&fx), fx.uid));

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, lp.connected);

    static const uint8_t req[] = "GET /secret HTTP/1.1\r\nHost: example.invalid\r\n"
                                 "X-Filler: 0123456789abcdef\r\n\r\n";
    const size_t req_len = sizeof(req) - 1;
    lp_send(&lp, req, req_len);

    /* OUTBOUND, byte for byte, at the far side of four sockets and two
     * sessions' worth of machinery. */
    struct up_wait uw = {&fx.up, 0, req_len};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, fx.up.accept_count);
    assert_up_bytes(&fx.up, 0, req, req_len);

    /* INBOUND, byte for byte, and TRANSFORMED -- which no client-side
     * short circuit can produce. */
    uint8_t want[sizeof(req)];
    xor_fill(want, req, req_len);
    struct lp_wait lw = {&lp, req_len};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &lw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT((int)req_len, (int)lp.in_len);
    ASSERT_MEM_EQ(lp.in, want, req_len);
    /* And the reply is not merely a copy of the request: the XOR really
     * happened, so this cannot pass against a loopback anywhere. */
    ASSERT_MEM_NE(lp.in, req, req_len);

    /* ONE session, one stream, on both sides -- and nothing was ever
     * redirected to the cover site. */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(1, fx.attached_created);
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_stream_count(&cl.piper));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, fx.cover.accept_count);
    ASSERT_EQ_INT(0, cl.broken_calls);

    lp_destroy(&lp);
    client_down(&cl);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 2: four concurrent applications over ONE session -------------- */

#define SID_CONCURRENT ((uint32_t)7102)
#define CONC_N 4

/* DIFFERENT PAYLOADS AND DIFFERENT LENGTHS PER PEER, because a crossed
 * route -- peer A's bytes arriving on B's stream -- passes a
 * single-connection test and passes a multi-connection test whose peers
 * send the same thing. The reply each peer gets is derived from what the
 * upstream actually received on THAT connection, so "peer i got back its
 * own payload, transformed" pins the outbound route and the inbound one
 * at once, for all four. */
static void test_four_concurrent_connections_over_one_session(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_CONCURRENT, 1, front_port(&fx), fx.uid));

    local_peer_t peers[CONC_N];
    uint8_t *payload[CONC_N];
    size_t plen[CONC_N];
    for (int i = 0; i < CONC_N; i++) {
        plen[i] = (size_t)(1000 + 137 * i);
        payload[i] = malloc(plen[i]);
        ASSERT_TRUE(payload[i] != NULL);
        if (payload[i] == NULL) {
            return;
        }
        for (size_t j = 0; j < plen[i]; j++) {
            payload[i][j] = (uint8_t)(0x11 * (i + 1) + j * (2 * i + 3));
        }
        ASSERT_EQ_INT(0, lp_open(&peers[i], fx.reactor, cl.local_port));
    }
    for (int i = 0; i < CONC_N; i++) {
        ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &peers[i], FE2E_MAX_TURNS, FE2E_TURN_MS));
        ASSERT_EQ_INT(1, peers[i].connected);
    }
    /* All four in flight at once, not one at a time. */
    for (int i = 0; i < CONC_N; i++) {
        lp_send(&peers[i], payload[i], plen[i]);
    }

    for (int i = 0; i < CONC_N; i++) {
        struct lp_wait w = {&peers[i], plen[i]};
        ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &w, FE2E_MAX_TURNS, FE2E_TURN_MS));
        uint8_t *want = malloc(plen[i]);
        ASSERT_TRUE(want != NULL);
        if (want == NULL) {
            return;
        }
        xor_fill(want, payload[i], plen[i]);
        ASSERT_EQ_INT((int)plen[i], (int)peers[i].in_len);
        ASSERT_MEM_EQ(peers[i].in, want, plen[i]);
        free(want);
    }

    /* FOUR streams and FOUR upstream connections, carried by ONE session:
     * the server's registry holds exactly one, and the dispatcher created
     * exactly one. A client that opened a session per local connection
     * would satisfy every byte assertion above and fail here. */
    ASSERT_EQ_INT(CONC_N, fx.up.accept_count);
    ASSERT_EQ_INT(CONC_N, (int)cloak_client_piper_stream_count(&cl.piper));
    ASSERT_EQ_INT(CONC_N, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(1, fx.attached_created);
    ASSERT_EQ_INT(0, cl.broken_calls);

    for (int i = 0; i < CONC_N; i++) {
        lp_destroy(&peers[i]);
        free(payload[i]);
    }
    client_down(&cl);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 3: the server terminates the user out from under the client --- */

#define SID_CREDIT ((uint32_t)7103)
#define CREDIT_BULK ((size_t)(1024u * 1024u))
/* Where this case stops waiting and pulls the trigger: far enough past
 * METERED_UP_CREDIT that the upload cycle cannot fail to bill an overrun,
 * and far enough short of CREDIT_BULK that the transfer is still running
 * when it does. Eight times the credit and an eighth of the payload. */
#define CREDIT_TRIGGER_AT ((int64_t)(32 * 1024))

/* A SESSION DEATH THE CLIENT DID NOT INITIATE, produced by the server's
 * own policy rather than by a test reaching into a registry. The user is
 * a real metered row; the traffic really overruns its upload credit; the
 * upload cycle really runs; cloak_userpanel_terminate really closes the
 * session. The client is told by nothing more than its connections going
 * away.
 *
 * TWO LOCAL CONNECTIONS, AND ONE OF THEM IS IDLE. When the far end
 * vanishes the client's pool empties, so any relay that tries to WRITE
 * fails immediately and tears itself down a turn before the session's
 * on_broken even fires. A case built only from busy relays therefore
 * reaches "every context freed" whether or not the piper's broken walk
 * does anything at all. An idle relay has nothing to write and no
 * readable edge coming, so it is still live when on_broken runs -- the
 * only window in which stopping it is still legal, and the only
 * arrangement in which a piper that skipped the walk is distinguishable
 * from one that performed it. */
static void test_the_server_terminating_the_user_tears_the_client_down(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    /* THE METERED UID, not the bypass one: a bypass user is exempt from
     * accounting and can never be terminated, so this case run against
     * fx.uid would be green and empty. */
    client_t cl;
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_CREDIT, 1, front_port(&fx), fx.muid));

    /* The user really did authenticate against the database row, and the
     * panel really is metering it. */
    ASSERT_TRUE(cloak_userpanel_find(fx.panel, fx.muid) != NULL);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, fx.muid));

    local_peer_t idle;
    ASSERT_EQ_INT(0, lp_open(&idle, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &idle, FE2E_MAX_TURNS, FE2E_TURN_MS));
    static const uint8_t ping[] = "ping";
    const size_t ping_len = sizeof(ping) - 1;
    lp_send(&idle, ping, ping_len);
    /* Waited for, so this peer really is IDLE-BUT-LIVE at the break: its
     * relay exists, has pumped in both directions, and has nothing left
     * to do. */
    struct lp_wait iw = {&idle, ping_len};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &iw, FE2E_MAX_TURNS, FE2E_TURN_MS));

    local_peer_t busy;
    ASSERT_EQ_INT(0, lp_open(&busy, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &busy, FE2E_MAX_TURNS, FE2E_TURN_MS));
    uint8_t *bulk = malloc(CREDIT_BULK);
    ASSERT_TRUE(bulk != NULL);
    if (bulk == NULL) {
        return;
    }
    for (size_t i = 0; i < CREDIT_BULK; i++) {
        bulk[i] = (uint8_t)(i * 5u);
    }
    lp_send(&busy, bulk, CREDIT_BULK);

    struct piper_wait pw = {&cl.piper, 2};
    ASSERT_TRUE(pump_until(fx.reactor, piper_streams_are, &pw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(2, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(2, (int)cloak_client_piper_stream_count(&cl.piper));

    /* THE TRIGGER IS THE METER ITSELF, not a byte count read anywhere
     * else. cloak_valve_rx on this user's own valve is the exact quantity
     * cloak_userpanel_upload_now will bill against up_credit, so waiting
     * on it is what makes "the credit really ran out" true before the
     * cycle is asked to notice. Reading the upstream's byte count instead
     * would be an approximation of it from the wrong side of the tunnel. */
    cloak_userpanel_user_t *mu = cloak_userpanel_find(fx.panel, fx.muid);
    ASSERT_TRUE(mu != NULL);
    if (mu == NULL) {
        return;
    }
    cloak_valve_t *mv = cloak_userpanel_user_valve(mu);
    ASSERT_TRUE(mv != NULL);
    struct valve_wait vw = {mv, CREDIT_TRIGGER_AT};
    ASSERT_TRUE(pump_until(fx.reactor, valve_rx_at_least, &vw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_TRUE(cloak_valve_rx(mv) >= CREDIT_TRIGGER_AT);
    ASSERT_TRUE(cloak_valve_rx(mv) > METERED_UP_CREDIT);

    /* AND STILL MID-TRANSFER: the bulk peer's payload has not finished
     * crossing, so the relays being torn down below are live ones. */
    ASSERT_TRUE(up_total_in(&fx.up) < CREDIT_BULK);
    ASSERT_EQ_INT(0, cl.broken_calls);
    /* The client has NOT closed its own session -- everything that
     * follows is something the server did to it. */
    ASSERT_EQ_INT(0, cl.sesh.closed);

    /* THE SERVER'S OWN POLICY, driven by hand so the case does not
     * depend on a timer. */
    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(fx.panel));

    /* The termination really was out-of-credit: the row's upload credit
     * is now spent, and the user is gone from the panel and the registry. */
    cloak_user_info_t after;
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.mgr, fx.muid, &after));
    ASSERT_TRUE(after.up_credit <= 0);
    ASSERT_TRUE(cloak_userpanel_find(fx.panel, fx.muid) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx.registry, fx.muid));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));

    /* THE CLIENT LEARNS, within the bound -- this is the "rather than
     * hanging it" half, and the bounded pump's own result is what
     * enforces it. */
    ASSERT_TRUE(pump_until(fx.reactor, cl_broken, &cl, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, cl.broken_calls);
    /* And by the time the owner's chain ran, every relay was already
     * stopped and every context freed -- including the IDLE one, which
     * nothing else would ever have ended. */
    ASSERT_EQ_INT(0, (int)cl.conns_at_broken);
    ASSERT_EQ_INT(0, (int)cl.streams_at_broken);
    /* RELEASED, not merely dropped: the session itself already considers
     * none of them active. Dropping them would also reach zero -- one
     * sweep later, outside the window in which the release is legal --
     * which is why this is sampled inside the chain. */
    ASSERT_EQ_INT(0, (int)cl.session_active_streams_at_broken);

    /* Both applications learn, rather than hanging. */
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &idle, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &busy, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, idle.eof);
    ASSERT_EQ_INT(1, busy.eof);

    /* The server reaped its half too: no stream contexts, and every
     * upstream socket saw EOF rather than being abandoned. */
    struct proxy_wait xw = {&fx.proxy, 0};
    ASSERT_TRUE(pump_until(fx.reactor, proxy_streams_are, &xw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    for (int i = 0; i < fx.up.accept_count; i++) {
        struct up_wait uw = {&fx.up, i, 0};
        ASSERT_TRUE(pump_until(fx.reactor, up_saw_eof, &uw, FE2E_MAX_TURNS, FE2E_TURN_MS));
        ASSERT_EQ_INT(1, fx.up.conns[i].eof);
    }

    free(bulk);
    lp_destroy(&idle);
    lp_destroy(&busy);
    client_down(&cl);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 4: NumConn > 1, and one underlying connection dies ------------ */

#define SID_MULTI ((uint32_t)7104)
#define MULTI_CONN 2
#define MULTI_BULK ((size_t)(512u * 1024u))

/* WHAT THIS IMPLEMENTATION ACTUALLY DOES, measured rather than assumed:
 * IT DOES NOT SURVIVE. One underlying connection's failure is fatal to
 * the whole session, exactly as cloak/switchboard.h's broken callback
 * says ("the moment ANY connection in the pool becomes broken ... a
 * single connection's failure is fatal to the whole pool, not just that
 * connection"), and exactly as Go's switchboard behaves. NumConn > 1
 * buys throughput and traffic spreading, NOT redundancy. This case
 * asserts that, and it is written so that it would FAIL if the behaviour
 * ever changed in either direction.
 *
 * WHAT MAKES THE ANSWER MEANINGFUL RATHER THAN CIRCULAR, and it is the
 * splice shim: only the CLIENT's end of one splice is closed. The
 * server's end stays open and is still being drained, so the far end has
 * noticed nothing; the other splice is untouched and demonstrably still
 * moving bytes. So this is not "the server went away" wearing a
 * disguise. The client lost exactly one of two connections, and:
 *
 *   - pool_conns_at_broken is asserted to be NON-ZERO. The session
 *     declared itself broken while its pool still held a connection --
 *     the surviving, healthy one. That single number is the difference
 *     between "fails because one connection failed" and "fails because
 *     everything failed", and it is the assertion a resilient
 *     implementation could not satisfy.
 *   - the survivor is asserted to still be alive at that instant, from
 *     OUTSIDE the client: shim splice 1 saw no client EOF and its
 *     client-to-server byte count had grown since the session came up.
 *
 * FAILS CLEANLY, not merely fails: on_broken fires exactly once, every
 * relay is already stopped and released by the time the owner's chain
 * runs, both applications get EOF inside the bound rather than hanging,
 * and there is no descriptor or memory left over. */
static void test_one_underlying_connection_dying_kills_the_session(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    shim_t *sh = malloc(sizeof(*sh));
    ASSERT_TRUE(sh != NULL);
    if (sh == NULL) {
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(0, shim_open(sh, fx.reactor, front_port(&fx)));

    client_t cl;
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_MULTI, MULTI_CONN, sh->port, fx.uid));

    /* Both underlying connections went through the shim and both are
     * spliced through to the real server. */
    struct shim_wait sw = {sh, MULTI_CONN};
    ASSERT_TRUE(pump_until(fx.reactor, shim_spliced, &sw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(MULTI_CONN, sh->count);
    ASSERT_EQ_INT(MULTI_CONN, (int)cloak_switchboard_conn_count(&cl.sesh.sb));
    /* ONE server session, fed by two connections. */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(MULTI_CONN, fx.attached_calls);
    ASSERT_EQ_INT(1, fx.attached_created);

    /* The marks: everything after this is post-handshake session
     * traffic. */
    struct shim_growth_wait gw;
    memset(&gw, 0, sizeof(gw));
    gw.sh = sh;
    gw.n = MULTI_CONN;
    for (int i = 0; i < MULTI_CONN; i++) {
        gw.marks[i] = sh->conns[i].c2s_bytes;
    }

    local_peer_t idle;
    ASSERT_EQ_INT(0, lp_open(&idle, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &idle, FE2E_MAX_TURNS, FE2E_TURN_MS));
    static const uint8_t ping[] = "ping";
    const size_t ping_len = sizeof(ping) - 1;
    lp_send(&idle, ping, ping_len);
    struct lp_wait iw = {&idle, ping_len};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &iw, FE2E_MAX_TURNS, FE2E_TURN_MS));

    local_peer_t busy;
    ASSERT_EQ_INT(0, lp_open(&busy, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &busy, FE2E_MAX_TURNS, FE2E_TURN_MS));
    uint8_t *bulk = malloc(MULTI_BULK);
    ASSERT_TRUE(bulk != NULL);
    if (bulk == NULL) {
        return;
    }
    for (size_t i = 0; i < MULTI_BULK; i++) {
        bulk[i] = (uint8_t)((i * 31u) ^ (i >> 8));
    }
    lp_send(&busy, bulk, MULTI_BULK);

    /* TRAFFIC IN FLIGHT ON BOTH UNDERLYING CONNECTIONS. The session
     * spreads frames across the pool at random, so this is waited for and
     * then asserted rather than assumed -- "kill one of two live
     * connections" is only a true description of this case if both were
     * live. */
    ASSERT_TRUE(pump_until(fx.reactor, shim_all_grew, &gw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    for (int i = 0; i < MULTI_CONN; i++) {
        ASSERT_TRUE(sh->conns[i].c2s_bytes > gw.marks[i]);
    }
    /* And still mid-transfer. */
    ASSERT_TRUE(up_total_in(&fx.up) < MULTI_BULK);
    ASSERT_EQ_INT(0, cl.broken_calls);
    ASSERT_EQ_INT(0, cl.sesh.closed);

    cl.probe_shim = sh;
    cl.probe_idx = 1;

    /* ONE CONNECTION DIES. The client's end of splice 0 only: the
     * server's end of it stays open and draining, and splice 1 is not
     * touched at all. */
    shim_kill_client_side(sh, 0);

    ASSERT_TRUE(pump_until(fx.reactor, cl_broken, &cl, FE2E_MAX_TURNS, FE2E_TURN_MS));

    /* ------- THE ANSWER ------- */

    /* The session died. Had one connection's failure been absorbed and
     * the session carried on over the survivor, broken_calls would still
     * be 0 here and every assertion below would fail with it. */
    ASSERT_EQ_INT(1, cl.broken_calls);
    /* AND IT DIED WHILE A HEALTHY CONNECTION WAS STILL THERE, judged
     * from OUTSIDE the client at the instant it happened: the splice
     * this case never touched had sent no EOF and was still spliced
     * through to the real server. This is the finding. */
    ASSERT_EQ_INT(0, cl.survivor_eof_at_broken);
    ASSERT_TRUE(cl.survivor_sfd_at_broken >= 0);
    ASSERT_EQ_INT(0, sh->conns[1].killed);
    /* No "the survivor carried at least as many bytes as before" check
     * here: c2s_bytes only ever rises and the mark was sampled moments
     * earlier, so such a line cannot fail -- the same vacuous shape as
     * the `accept_count >= idx` predicate this branch already recorded
     * once. The two samples above, taken INSIDE the broken callback, are
     * this case's real witnesses. */
    /* The pool was never drained either -- but see pool_conns_at_broken's
     * own comment: the array does not shrink, so this is the weaker
     * companion to the two samples above, not a substitute for them. */
    ASSERT_EQ_INT(MULTI_CONN, (int)cl.pool_conns_at_broken);
    /* And the server, whose end of the dead splice is still open and
     * whose other splice was never touched, did not cause any of this. */
    ASSERT_TRUE(sh->conns[0].sfd >= 0);

    /* ------- AND IT FAILED CLEANLY ------- */

    /* Every relay stopped and released before the owner's chain ran,
     * including the idle one that nothing else would have ended. */
    ASSERT_EQ_INT(0, (int)cl.conns_at_broken);
    ASSERT_EQ_INT(0, (int)cl.streams_at_broken);
    ASSERT_EQ_INT(0, (int)cl.session_active_streams_at_broken);
    /* Both applications are told, inside the bound, rather than left
     * hanging on a tunnel that no longer exists. */
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &idle, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &busy, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, idle.eof);
    ASSERT_EQ_INT(1, busy.eof);
    /* The transfer did NOT complete -- "fails cleanly" is not "finishes
     * anyway", and asserting it keeps this case honest if the answer ever
     * becomes resilience. */
    ASSERT_TRUE(up_total_in(&fx.up) < MULTI_BULK);
    /* The pool is empty once the session's own sweep has run. */
    ASSERT_EQ_INT(0, (int)cloak_switchboard_conn_count(&cl.sesh.sb));

    free(bulk);
    lp_destroy(&idle);
    lp_destroy(&busy);
    client_down(&cl);
    shim_close(sh);
    free(sh);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 5A: the CLIENT shuts down first ------------------------------- */

#define SID_SHUT_CLIENT ((uint32_t)7105)

/* Every other case in this directory ends by tearing the client down and
 * then tearing the server down immediately afterwards, so nothing has
 * ever checked that the SERVER reaps a client that simply went away. It
 * is the ordinary end of a ck-client process, and a server that leaked a
 * session, a stream context or an upstream socket per departed client
 * would pass every existing test in this tree. */
static void test_clean_shutdown_from_the_client_end(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_SHUT_CLIENT, MULTI_CONN, front_port(&fx), fx.uid));

    local_peer_t a;
    local_peer_t b;
    ASSERT_EQ_INT(0, lp_open(&a, fx.reactor, cl.local_port));
    ASSERT_EQ_INT(0, lp_open(&b, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &a, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &b, FE2E_MAX_TURNS, FE2E_TURN_MS));
    static const uint8_t pa[] = "alpha";
    static const uint8_t pb[] = "bravo!";
    lp_send(&a, pa, sizeof(pa) - 1);
    lp_send(&b, pb, sizeof(pb) - 1);
    struct lp_wait aw = {&a, sizeof(pa) - 1};
    struct lp_wait bw = {&b, sizeof(pb) - 1};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &aw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &bw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));

    /* The client goes away in the order a binary must use. The local
     * applications are still connected at this point, deliberately: a
     * process exiting does not first ask its users to disconnect. */
    client_down(&cl);

    /* The applications are told. */
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &a, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &b, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, a.eof);
    ASSERT_EQ_INT(1, b.eof);

    /* AND THE SERVER REAPS. The session leaves the registry, both stream
     * contexts are freed, and both upstream sockets see EOF -- which is
     * the only one of the three an upstream service would actually
     * notice. */
    struct registry_wait rw = {&fx, 0};
    ASSERT_TRUE(pump_until(fx.reactor, registry_count_is, &rw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));
    struct proxy_wait xw = {&fx.proxy, 0};
    ASSERT_TRUE(pump_until(fx.reactor, proxy_streams_are, &xw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(2, fx.up.accept_count);
    for (int i = 0; i < 2; i++) {
        struct up_wait uw = {&fx.up, i, 0};
        ASSERT_TRUE(pump_until(fx.reactor, up_saw_eof, &uw, FE2E_MAX_TURNS, FE2E_TURN_MS));
        ASSERT_EQ_INT(1, fx.up.conns[i].eof);
    }

    /* AND THE SERVER STILL WORKS. A second client, on the same stack,
     * gets its own session and its own round trip -- which a server that
     * had wedged something on the way out could not provide. */
    client_t cl2;
    ASSERT_EQ_INT(0, client_up(&cl2, &fx, SID_SHUT_CLIENT + 1, 1, front_port(&fx), fx.uid));
    local_peer_t c;
    ASSERT_EQ_INT(0, lp_open(&c, fx.reactor, cl2.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &c, FE2E_MAX_TURNS, FE2E_TURN_MS));
    static const uint8_t pc[] = "charlie";
    const size_t pc_len = sizeof(pc) - 1;
    lp_send(&c, pc, pc_len);
    struct lp_wait cw = {&c, pc_len};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &cw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    uint8_t want_c[sizeof(pc)];
    xor_fill(want_c, pc, pc_len);
    ASSERT_EQ_INT((int)pc_len, (int)c.in_len);
    ASSERT_MEM_EQ(c.in, want_c, pc_len);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(0, cl2.broken_calls);

    lp_destroy(&a);
    lp_destroy(&b);
    lp_destroy(&c);
    client_down(&cl2);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 5B: the SERVER shuts down first ------------------------------- */

#define SID_SHUT_SERVER ((uint32_t)7106)

/* The other direction, and the one an operator actually performs: the
 * server process stops while clients are connected. The client must tear
 * down through its ordinary broken path rather than wedging, and the
 * whole thing must be clean under ASan with no descriptor left behind. */
static void test_clean_shutdown_from_the_server_end(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_SHUT_SERVER, MULTI_CONN, front_port(&fx), fx.uid));

    local_peer_t a;
    ASSERT_EQ_INT(0, lp_open(&a, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &a, FE2E_MAX_TURNS, FE2E_TURN_MS));
    static const uint8_t pa[] = "delta";
    const size_t pa_len = sizeof(pa) - 1;
    lp_send(&a, pa, pa_len);
    struct lp_wait aw = {&a, pa_len};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &aw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    uint8_t want_a[sizeof(pa)];
    xor_fill(want_a, pa, pa_len);
    ASSERT_MEM_EQ(a.in, want_a, pa_len);
    ASSERT_EQ_INT(0, cl.broken_calls);

    /* The server goes away in the order a binary must use. */
    fixture_shutdown_server(&fx);

    ASSERT_TRUE(pump_until(fx.reactor, cl_broken, &cl, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, cl.broken_calls);
    ASSERT_EQ_INT(0, (int)cl.conns_at_broken);
    ASSERT_EQ_INT(0, (int)cl.streams_at_broken);
    ASSERT_EQ_INT(0, (int)cl.session_active_streams_at_broken);

    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &a, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, a.eof);

    /* A local connection arriving AFTER the tunnel is gone is refused
     * promptly rather than accepted and hung. */
    local_peer_t late;
    ASSERT_EQ_INT(0, lp_open(&late, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &late, FE2E_MAX_TURNS, FE2E_TURN_MS));
    static const uint8_t hello[] = "hello?";
    lp_send(&late, hello, sizeof(hello) - 1);
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &late, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, late.eof);
    ASSERT_EQ_INT(0, (int)cloak_client_piper_stream_count(&cl.piper));

    lp_destroy(&a);
    lp_destroy(&late);
    client_down(&cl);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 6: a client that VANISHES is reaped by the server ------------- */

#define SID_VANISH ((uint32_t)7107)

/* THE HOLE CASE 5A DOES NOT COVER, and it was found by mutating rather
 * than by reading. A client that shuts down in order closes each stream
 * as its relays stop, so the server reaps through the ordinary
 * per-stream close path and its SESSION-broken path is never entered:
 * disabling cloak_proxy_registry_broken's teardown walk outright leaves
 * case 5A entirely green (measured -- the mutation is caught only by
 * libcloak-server's own test_proxy_teardown).
 *
 * A client whose sockets simply disappear -- a laptop lid, a killed
 * process, a dropped route -- gives the server no stream closes at all,
 * only dead connections, and that is the path this case takes. The
 * splice shim is what makes it expressible: closing every splice at once
 * is indistinguishable, from the server's side, from the client host
 * going away. */
static void test_a_vanished_client_is_reaped_by_the_server(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    shim_t *sh = malloc(sizeof(*sh));
    ASSERT_TRUE(sh != NULL);
    if (sh == NULL) {
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(0, shim_open(sh, fx.reactor, front_port(&fx)));

    client_t cl;
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_VANISH, MULTI_CONN, sh->port, fx.uid));
    struct shim_wait sw = {sh, MULTI_CONN};
    ASSERT_TRUE(pump_until(fx.reactor, shim_spliced, &sw, FE2E_MAX_TURNS, FE2E_TURN_MS));

    local_peer_t a;
    local_peer_t b;
    ASSERT_EQ_INT(0, lp_open(&a, fx.reactor, cl.local_port));
    ASSERT_EQ_INT(0, lp_open(&b, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &a, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &b, FE2E_MAX_TURNS, FE2E_TURN_MS));
    static const uint8_t pa[] = "echo one";
    static const uint8_t pb[] = "echo two!!";
    lp_send(&a, pa, sizeof(pa) - 1);
    lp_send(&b, pb, sizeof(pb) - 1);
    struct lp_wait aw = {&a, sizeof(pa) - 1};
    struct lp_wait bw = {&b, sizeof(pb) - 1};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &aw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &bw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(2, fx.up.accept_count);

    /* EVERY underlying connection vanishes at once, with no stream close
     * and no session-closing frame ahead of it. */
    shim_close(sh);

    /* THE SERVER REAPS THROUGH ITS SESSION-BROKEN PATH: the session
     * leaves the registry, both stream contexts are freed, and both
     * upstream sockets are closed rather than left dangling for the life
     * of the process. */
    struct registry_wait rw = {&fx, 0};
    ASSERT_TRUE(pump_until(fx.reactor, registry_count_is, &rw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));
    struct proxy_wait xw = {&fx.proxy, 0};
    ASSERT_TRUE(pump_until(fx.reactor, proxy_streams_are, &xw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    for (int i = 0; i < 2; i++) {
        struct up_wait uw = {&fx.up, i, 0};
        ASSERT_TRUE(pump_until(fx.reactor, up_saw_eof, &uw, FE2E_MAX_TURNS, FE2E_TURN_MS));
        ASSERT_EQ_INT(1, fx.up.conns[i].eof);
    }

    /* And the client's own half tore down through its ordinary broken
     * path, so both applications are told rather than left hanging. */
    ASSERT_TRUE(pump_until(fx.reactor, cl_broken, &cl, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, cl.broken_calls);
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &a, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &b, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, a.eof);
    ASSERT_EQ_INT(1, b.eof);

    lp_destroy(&a);
    lp_destroy(&b);
    client_down(&cl);
    shim_close(sh); /* idempotent: everything is already closed */
    free(sh);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}


/* ---- case 8: a bulk transfer, which nothing in this suite ever did ------
 *
 * WHY THIS CASE EXISTS. The end-to-end benchmark (tools/bench) found that
 * this stack cannot sustain a bulk transfer: against Go's server our client
 * received exactly 16132 bytes -- one maxStreamUnitWrite, one frame's
 * payload -- and then nothing, while ours against ours wedged at ~32 KB and
 * ours against Go's client at ~878 KB. Sixty seconds later the session died
 * of the inactivity timeout, correctly, because nothing had moved.
 *
 * The reason it took a benchmark to find is the point of this case: the
 * largest payload anywhere in these 85 test binaries is a few kilobytes.
 * Every case above proves the ROUTE -- that a byte gets there, transformed,
 * on the right stream -- and not one of them proves the stack can keep a
 * stream moving past the first frame or two. "Volume" was an unmeasured
 * axis in exactly the way "architecture" was until x86_64 ran the suite.
 *
 * ONE MEGABYTE, and the size is chosen rather than picked: it is 65x the
 * 16132 the client stopped at, 32x where ours-against-ours wedged, and it
 * still fits both 4 MiB harness buffers with room to spare. A payload that
 * merely exceeded one frame would not distinguish "the second frame works"
 * from "the stack keeps going".
 *
 * A COUNTER, NOT A CONSTANT FILL. The payload is an LCG stream, so a block
 * delivered twice, a block dropped, or two blocks transposed all fail the
 * comparison -- none of which a memset(0x5a) payload can tell apart from a
 * correct transfer. */

#define SID_BULK ((uint32_t)7108)
#define BULK_LEN ((size_t)(3u << 20))

static void test_a_megabyte_survives_the_whole_stack(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    /* FOUR CONNECTIONS, NOT ONE, AND THAT IS THE WHOLE DIFFERENCE.
     *
     * This case first shipped with one, and it passed against a stack the
     * real binaries still could not get a megabyte through -- a false
     * green found by tools/bench, not by the suite. NumConn defaults to 4
     * in ckclient.json and multiplexing across several connections is
     * what Cloak is FOR, so one connection tests the configuration nobody
     * runs.
     *
     * The difference is not subtle. At NumConn=1 a megabyte arrives
     * intact; at 4 the transfer stops around 26 KB, run after run.
     *
     * AND THE SIZE IS THREE MEGABYTES, NOT ONE, FOR THE SAME REASON THE
     * CONNECTION COUNT IS FOUR. One megabyte over four connections passes
     * against a stack the real binaries still cannot move 8 MiB through
     * -- tools/bench, ours against ours, gets 1,143,141 bytes and then
     * the peer closes. Three reproduces the product's behaviour in
     * seconds: outbound stops at 26,624 bytes, three runs out of three,
     * with the harness proven not to be the one stalling (lp.out_head
     * and lp.out_len are both 0 at the failure, so all 3 MiB reached the
     * socket). It still fits both 4 MiB harness buffers. */
    client_t cl;
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_BULK, 4, front_port(&fx), fx.uid));

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT(1, lp.connected);

    uint8_t *payload = malloc(BULK_LEN);
    uint8_t *want = malloc(BULK_LEN);
    ASSERT_TRUE(payload != NULL && want != NULL);
    uint32_t lcg = 0x1234567u;
    for (size_t i = 0; i < BULK_LEN; i++) {
        lcg = lcg * 1664525u + 1013904223u;
        payload[i] = (uint8_t)(lcg >> 24);
    }
    xor_fill(want, payload, BULK_LEN);

    lp_send(&lp, payload, BULK_LEN);

    /* Outbound first, so a failure says which direction stalled rather
     * than only that the round trip did. */
    struct up_wait uw = {&fx.up, 0, BULK_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT((int)BULK_LEN, (int)fx.up.conns[0].in_len);
    assert_up_bytes(&fx.up, 0, payload, BULK_LEN);

    struct lp_wait lw = {&lp, BULK_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &lw, FE2E_MAX_TURNS, FE2E_TURN_MS));
    ASSERT_EQ_INT((int)BULK_LEN, (int)lp.in_len);
    ASSERT_MEM_EQ(lp.in, want, BULK_LEN);
    ASSERT_MEM_NE(lp.in, payload, BULK_LEN);

    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_stream_count(&cl.piper));
    ASSERT_EQ_INT(0, fx.cover.accept_count);
    ASSERT_EQ_INT(0, cl.broken_calls);

    free(payload);
    free(want);
    lp_destroy(&lp);
    client_down(&cl);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

TEST_MAIN_BEGIN()
test_a_round_trip_through_the_whole_stack();
test_four_concurrent_connections_over_one_session();
test_the_server_terminating_the_user_tears_the_client_down();
test_one_underlying_connection_dying_kills_the_session();
test_clean_shutdown_from_the_client_end();
test_clean_shutdown_from_the_server_end();
test_a_vanished_client_is_reaped_by_the_server();
test_a_megabyte_survives_the_whole_stack();
TEST_MAIN_END()
