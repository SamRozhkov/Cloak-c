#define _POSIX_C_SOURCE 200809L

/* THE LOCAL LISTENER, END TO END, AGAINST THE REAL MERGED SERVER.
 *
 * cloak_client_piper_t is the half of a working client that an
 * application actually points at: every connection accepted on the local
 * listener becomes one stream on the session cloak_client_connector_t
 * brought up. So the far end here is the whole real server stack --
 * dispatcher, registry, user panel, cloak_proxy_t and a real upstream
 * socket -- and a passing case means bytes genuinely crossed the tunnel,
 * not that the piper agrees with a mock.
 *
 * TWO CONSTRUCTIONS CARRY MOST OF THE FILE, and both exist to keep a case
 * from passing through a path other than the one it names.
 *
 * 1. THE UPSTREAM DOES NOT ECHO. It replies with every byte it received
 *    XORed with 0xFF. An echoing upstream would make case 1 pass against
 *    a piper that never opened a stream at all and simply wrote the
 *    local connection's own bytes back at it; XOR cannot be produced
 *    anywhere on the client side, so a reply that arrives transformed is
 *    proof it went to the server, reached the upstream, and came back.
 *
 * 2. THE TWO-CONNECTION CASE USES DIFFERENT PAYLOADS. A crossed route --
 *    connection A's bytes arriving on B's stream -- passes a
 *    single-connection test, and passes a two-connection test with
 *    identical payloads. Because the reply is derived from what arrived,
 *    one assertion per peer ("I got back MY OWN payload, transformed")
 *    pins both directions at once.
 *
 * EVERY WAIT IS A BOUNDED pump_until, and every wait whose comment names
 * a duration asserts it actually reached that duration -- the discipline
 * every reactor test in this tree states. Every peer socket is
 * non-blocking. */

#include "cloak/base64.h"
#include "cloak/client_connector.h"
#include "cloak/conn.h"
#include "cloak/client_piper.h"
#include "cloak/crypto.h"
#include "cloak/dispatcher.h"
#include "cloak/frame.h"
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

/* Sized so a BROKEN run fails an ASSERTION rather than the ctest timeout:
 * at PIPER_MAX_TURNS turns of PIPER_TURN_MS each one wait is at most
 * ~2 s, and the waits in this file total well under TIMEOUT 60. The
 * 512 KiB case is the one that actually needs the headroom; the rest
 * settle in a few dozen turns on loopback. */
#define PIPER_MAX_TURNS 2000
#define PIPER_TURN_MS 1

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
 * did. D6's deadline is a wall-clock quantity: a fixed number of
 * one-millisecond turns does not reliably cross it, and a loop that
 * exited early would silently turn the assertions that follow into
 * nothing.
 *
 * THE ITERATION CEILING IS A BACKSTOP AGAINST A CLOCK THAT DOES NOT
 * ADVANCE, and it is sized so it cannot be the exit condition -- which
 * the previous sizing could not honestly claim. cloak_reactor_run_once
 * only blocks for its full millisecond when nothing is ready; a closed
 * local peer leaves an EOF-readable fd registered, and the loop then
 * spins at roughly 600k iterations per second. The old ceiling of
 * ms * 100 + 100000 sat two or three times above that spin rate, i.e.
 * one busy fd away from binding, which made the assertion below an
 * incidental flake detector rather than a real one. ms * 1000 + 5000000
 * sits about forty times above it, and the assertion is what proves the
 * ceiling did not bind. */
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
 * memory, not file descriptors: a piper that freed every byte it
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

/* ---- capturing the operator log ------------------------------------------
 *
 * cloak/log.h writes one line per message to a settable stream, so an
 * open_memstream is all it takes to make "one line per piper, not one per
 * event" assertable rather than merely claimed. The same helper
 * libcloak-server/tests/test_proxy_stream.c uses for the proxy's cap
 * logs. The default level is INFO, so the WARN lines under test are
 * emitted without touching the level. */
typedef struct {
    FILE *f;
    char *buf;
    size_t len;
} logcap_t;

static int logcap_open(logcap_t *lc) {
    lc->buf = NULL;
    lc->len = 0;
    lc->f = open_memstream(&lc->buf, &lc->len);
    ASSERT_TRUE(lc->f != NULL);
    if (lc->f == NULL) {
        return -1;
    }
    cloak_log_set_stream(lc->f);
    return 0;
}

static void logcap_close(logcap_t *lc) {
    cloak_log_set_stream(NULL); /* back to stderr before the buffer dies */
    if (lc->f != NULL) {
        fclose(lc->f);
        lc->f = NULL;
    }
    free(lc->buf);
    lc->buf = NULL;
}

/* How many emitted lines contain `needle`. The fflush is what makes the
 * buffer both current and NUL-terminated. */
static int logcap_count(logcap_t *lc, const char *needle) {
    fflush(lc->f);
    if (lc->buf == NULL) {
        return 0;
    }
    int n = 0;
    for (const char *q = lc->buf; (q = strstr(q, needle)) != NULL; q++) {
        n++;
    }
    return n;
}

/* ---- the fake upstream: records everything, replies with it XORed ------- */

#define UP_MAX_CONNS 8
#define UP_BUF_CAP ((size_t)(4u << 20))

/* NOT an echo. See this file's header: an echo is reproducible on the
 * client side and therefore cannot distinguish "the reply came back
 * through the tunnel" from "the piper wrote the request back at its own
 * local peer". */
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
                    c->out[c->out_len + (size_t)i] = (uint8_t)(c->in[c->in_len + (size_t)i] ^ UP_XOR);
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
    snprintf(buf, cap, "%s/cloak_client_piper_%ld.db", dir, (long)getpid());
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

    /* The max_on_wire_size BOTH ends are built with. Parameterized (and
     * not simply hard-coded twice) so that case 11 can shrink it below
     * CLOAK_CLIENT_PIPER_FIRST_BYTES, which is the only way the piper's
     * one-frame clamp on its first read becomes observable at all: at the
     * usual 16401 a frame's payload is ~16 KiB and the 10240-byte buffer
     * is always the smaller of the two, so the clamp is dead code to
     * every other case in this file. Both ends must agree -- a connection
     * whose peer frames larger than its own max_frame_len is broken by
     * the connection layer, not tolerated. */
    size_t wire;

    /* The TCP port the CLIENT dials. The front listener's own port for
     * every case but case 12, which routes the session through a
     * middlebox it can stop reading from. */
    int client_port;

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

static int fixture_init_opts(struct fixture *fx, size_t max_on_wire_size) {
    memset(fx, 0, sizeof(*fx));
    fx->wire = max_on_wire_size;
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

/* The wire size every case but case 11 uses -- the value the rest of this
 * project's tests are built with. */
#define PIPER_WIRE_DEFAULT ((size_t)16401)

static int fixture_init(struct fixture *fx) {
    return fixture_init_opts(fx, PIPER_WIRE_DEFAULT);
}

/* The shutdown order a binary must use: listener, dispatcher, PROXY
 * BEFORE REGISTRY, registry, panel, manager, server state. Case 6 calls
 * this on its own, mid-transfer, to kill the session under the client. */
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

/* ---- a middlebox that can stop reading from the client ------------------
 *
 * THE ONLY WAY TO PRODUCE A GENUINE -2, and it took a measurement to
 * establish that. cloak_stream_relay_start rejects transiently when the
 * session's per-connection send queue cannot hold one worst-case frame,
 * and that queue only accumulates when the KERNEL refuses the write --
 * cloak_conn_send flushes straight through otherwise. On loopback against
 * a server that reads promptly the queue is empty at every sample point,
 * whatever conn_send_queue_cap is set to (measured: with a cap one byte
 * above one frame's cost and 512 KiB in flight, cloak_session_send_min_
 * conn_free never once dipped below the threshold over 2000 turns). The
 * server's own connection layer has no stream-backpressure read pause
 * either -- conn_pause_read_for_rate exists only for the rate valve -- so
 * a stalled upstream does not propagate back either.
 *
 * So the peer has to stop reading, which is what this does: a plain TCP
 * splice between the client and the real front door, with the
 * client-to-server direction switchable off. SO_RCVBUF is set small on
 * the accepted socket so the client's own send buffer cannot auto-tune
 * into the megabytes and the congestion arrives in tens of kilobytes
 * rather than in megabytes.
 *
 * One connection only: the case that uses it runs num_conn == 1. */
#define MB_BUF ((size_t)65536)
#define MB_RCVBUF 4096

typedef struct {
    cloak_reactor_t *reactor;
    cloak_listener_t l;
    int have_listener;
    cloak_addr_t front;

    int paused; /* 1: do not read from the client at all */

    int cfd; /* the client's side */
    int sfd; /* the real server's side */
    int cfd_reg;
    int sfd_reg;
    cloak_dial_t dial;
    int dialing;

    uint8_t c2s[MB_BUF];
    size_t c2s_len;
    uint8_t s2c[MB_BUF];
    size_t s2c_len;
} midbox_t;

static void mb_sync(midbox_t *mb);

static size_t mb_drain(int fd, uint8_t *buf, size_t *len) {
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

static void mb_fill(int fd, uint8_t *buf, size_t *len) {
    while (*len < MB_BUF) {
        ssize_t n = read(fd, buf + *len, MB_BUF - *len);
        if (n > 0) {
            *len += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
}

static void mb_on_client(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    midbox_t *mb = userdata;
    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        mb_drain(mb->cfd, mb->s2c, &mb->s2c_len);
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0 && !mb->paused) {
        mb_fill(mb->cfd, mb->c2s, &mb->c2s_len);
        if (mb->sfd >= 0) {
            mb_drain(mb->sfd, mb->c2s, &mb->c2s_len);
        }
    }
    mb_sync(mb);
}

static void mb_on_server(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    midbox_t *mb = userdata;
    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        mb_drain(mb->sfd, mb->c2s, &mb->c2s_len);
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        mb_fill(mb->sfd, mb->s2c, &mb->s2c_len);
        if (mb->cfd >= 0) {
            mb_drain(mb->cfd, mb->s2c, &mb->s2c_len);
        }
    }
    mb_sync(mb);
}

static void mb_sync(midbox_t *mb) {
    if (mb->cfd_reg) {
        uint32_t ev = 0;
        if (!mb->paused && mb->c2s_len < MB_BUF) {
            ev |= CLOAK_REACTOR_READABLE;
        }
        if (mb->s2c_len > 0) {
            ev |= CLOAK_REACTOR_WRITABLE;
        }
        (void)cloak_reactor_mod_fd(mb->reactor, mb->cfd, ev);
    }
    if (mb->sfd_reg) {
        uint32_t ev = CLOAK_REACTOR_READABLE;
        if (mb->c2s_len > 0) {
            ev |= CLOAK_REACTOR_WRITABLE;
        }
        (void)cloak_reactor_mod_fd(mb->reactor, mb->sfd, ev);
    }
}

static void mb_on_dial(cloak_dial_t *d, int fd, void *userdata) {
    (void)d;
    midbox_t *mb = userdata;
    mb->dialing = 0;
    if (fd < 0) {
        return;
    }
    mb->sfd = fd;
    if (cloak_reactor_add_fd(mb->reactor, fd, CLOAK_REACTOR_READABLE, mb_on_server, mb) != 0) {
        close(fd);
        mb->sfd = -1;
        return;
    }
    mb->sfd_reg = 1;
    mb_sync(mb);
}

static void mb_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    midbox_t *mb = userdata;
    if (mb->cfd >= 0) {
        close(fd); /* one connection only */
        return;
    }
    int rcv = MB_RCVBUF;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    mb->cfd = fd;
    if (cloak_reactor_add_fd(mb->reactor, fd, CLOAK_REACTOR_READABLE, mb_on_client, mb) != 0) {
        close(fd);
        mb->cfd = -1;
        return;
    }
    mb->cfd_reg = 1;
    char err[256];
    if (cloak_dial_start(&mb->dial, mb->reactor, &mb->front, 5000, mb_on_dial, mb, err,
                         sizeof(err)) != 0) {
        return;
    }
    mb->dialing = 1;
}

static int mb_open(midbox_t *mb, cloak_reactor_t *r, int front_tcp_port) {
    memset(mb, 0, sizeof(*mb));
    mb->reactor = r;
    mb->cfd = -1;
    mb->sfd = -1;
    char addr[64];
    char err[256];
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", front_tcp_port);
    if (cloak_net_resolve(addr, 0, &mb->front, err, sizeof(err)) != 0) {
        return -1;
    }
    if (cloak_listener_open(&mb->l, r, "127.0.0.1:0", mb_on_accept, mb, err, sizeof(err)) != 0) {
        return -1;
    }
    mb->have_listener = 1;
    return 0;
}

static void mb_set_paused(midbox_t *mb, int paused) {
    mb->paused = paused;
    if (!paused && mb->cfd >= 0) {
        /* Deregistering and re-registering is what re-reports data that
         * arrived while paused: the registration is edge-triggered, so a
         * mere mod_fd back to READABLE would also re-arm, but pulling
         * directly is what makes the resume immediate and testable. */
        mb_on_client(mb->reactor, mb->cfd, CLOAK_REACTOR_READABLE, mb);
    }
    mb_sync(mb);
}

static void mb_close(midbox_t *mb) {
    if (mb->have_listener) {
        cloak_listener_close(&mb->l);
        mb->have_listener = 0;
    }
    if (mb->dialing) {
        cloak_dial_cancel(&mb->dial);
        mb->dialing = 0;
    }
    if (mb->cfd_reg) {
        cloak_reactor_remove_fd(mb->reactor, mb->cfd);
        mb->cfd_reg = 0;
    }
    if (mb->cfd >= 0) {
        close(mb->cfd);
        mb->cfd = -1;
    }
    if (mb->sfd_reg) {
        cloak_reactor_remove_fd(mb->reactor, mb->sfd);
        mb->sfd_reg = 0;
    }
    if (mb->sfd >= 0) {
        close(mb->sfd);
        mb->sfd = -1;
    }
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

static int lp_sent_all(void *ctx) {
    local_peer_t *lp = ctx;
    return lp->out_head >= lp->out_len;
}

static int lp_at_eof(void *ctx) {
    local_peer_t *lp = ctx;
    return lp->eof != 0;
}

/* ---- the client side under test ----------------------------------------- */

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
     * stopped every relay. Case 6 asserts on it. */
    int broken_calls;
    /* THE PIPER'S STATE AT THE INSTANT THE CHAIN RUNS, which is the only
     * moment at which "the relays were stopped in the window where that
     * was still possible" is observable at all. Sampled here because
     * after on_broken returns the mux frees the session's streams anyway
     * and every relay dies of its own accord a turn later -- so a piper
     * that did NOTHING in on_broken still reaches conn_count == 0
     * eventually, and asserting only on the eventual state is a case
     * whose green comes from a path other than the one it names. */
    size_t conns_at_broken;
    size_t streams_at_broken;
    /* The SESSION's own count of streams it still considers active at
     * that same instant. It is the only thing that distinguishes "the
     * walk released its streams" from "the walk dropped them and let the
     * mux's own post-on_broken sweep reclaim them": both end at zero, and
     * only this is zero BEFORE the sweep. */
    size_t session_active_streams_at_broken;

    /* A SECOND session, for the one case that needs the piper to outlive
     * a session and be handed a replacement -- the shape
     * cloak_client_piper_set_session exists for, and the shape the
     * refusal ceiling used to get wrong. */
    cloak_session_t sesh2;
    int session2_live;
    conn_result_t res2;
    cloak_client_connector_t c2;
    int connector2_ready;
} client_t;

static void cl_on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    client_t *cl = userdata;
    cl->broken_calls++;
    cl->conns_at_broken = cloak_client_piper_conn_count(&cl->piper);
    cl->streams_at_broken = cloak_client_piper_stream_count(&cl->piper);
    cl->session_active_streams_at_broken = cl->sesh.active_stream_count;
}

/* Brings up the whole client: a piper, a connector wired to its session
 * template, one underlying connection to the real server, then the local
 * listener. pcfg supplies the piper's knobs (the reactor and chain are
 * filled in here); conn_send_queue_cap sizes the CLIENT session's
 * outbound pool, which case 9 deliberately undersizes. */
static int client_up(client_t *cl, struct fixture *fx, uint32_t session_id,
                     const cloak_client_piper_config_t *pcfg_in, size_t conn_send_queue_cap) {
    memset(cl, 0, sizeof(*cl));
    cl->fx = fx;

    cloak_client_piper_config_t pcfg = *pcfg_in;
    pcfg.reactor = fx->reactor;
    pcfg.chain = cl_on_broken;
    pcfg.chain_userdata = cl;
    ASSERT_EQ_INT(0, cloak_client_piper_init(&cl->piper, &pcfg));
    cl->piper_ready = 1;

    char addr[64];
    char err[256];
    cloak_client_connector_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", fx->client_port);
    ASSERT_EQ_INT(0, cloak_net_resolve(addr, 0, &cfg.remote, err, sizeof(err)));
    cfg.reactor = fx->reactor;
    cfg.num_conn = 1;
    cfg.session = &cl->sesh;
    cfg.browser = CLOAK_CLIENT_BROWSER_CHROME;
    cfg.transport = CLOAK_TRANSPORT_DIRECT;
    cfg.server_name = "www.example.com";
    memcpy(cfg.server_pub, fx->server_pub, CLOAK_X25519_KEY_LEN);
    memcpy(cfg.uid, fx->uid, CLOAK_UID_LEN);
    cfg.proxy_method = "ss";
    cfg.encryption_method = (uint8_t)CLOAK_AEAD_AES_256_GCM;
    cfg.session_id = session_id;
    cfg.dial_timeout_ms = 5000;
    cfg.handshake_timeout_ms = 10000;
    cfg.session_template.max_on_wire_size = fx->wire;
    cfg.session_template.stream_recv_capacity = 65536;
    cfg.session_template.stream_max_pending_frames = 64;
    cfg.session_template.conn_send_queue_cap = conn_send_queue_cap;
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
    ASSERT_TRUE(pump_until(fx->reactor, conn_fired, &cl->res, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_DONE, (int)cl->res.status);
    if (cl->res.status != CLOAK_CLIENT_CONNECTOR_DONE) {
        return -1;
    }
    cl->session_live = 1;

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

/* Brings a SECOND session up on the same piper and hands it over, which
 * is what an owner reconnecting after a session died does. The piper's
 * four callbacks are installed into this template too -- they have to be,
 * since cloak_session_init consumes the template -- so the piper serves
 * both sessions over its life. */
static int client_second_session(client_t *cl, struct fixture *fx, uint32_t session_id) {
    char addr[64];
    char err[256];
    cloak_client_connector_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", fx->client_port);
    ASSERT_EQ_INT(0, cloak_net_resolve(addr, 0, &cfg.remote, err, sizeof(err)));
    cfg.reactor = fx->reactor;
    cfg.num_conn = 1;
    cfg.session = &cl->sesh2;
    cfg.browser = CLOAK_CLIENT_BROWSER_CHROME;
    cfg.transport = CLOAK_TRANSPORT_DIRECT;
    cfg.server_name = "www.example.com";
    memcpy(cfg.server_pub, fx->server_pub, CLOAK_X25519_KEY_LEN);
    memcpy(cfg.uid, fx->uid, CLOAK_UID_LEN);
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
    cfg.on_done_userdata = &cl->res2;
    cloak_client_piper_install(&cl->piper, &cfg.session_template);

    ASSERT_EQ_INT(0, cloak_client_connector_init(&cl->c2, &cfg));
    cl->connector2_ready = 1;
    ASSERT_EQ_INT(0, cloak_client_connector_start(&cl->c2));
    ASSERT_TRUE(pump_until(fx->reactor, conn_fired, &cl->res2, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT((int)CLOAK_CLIENT_CONNECTOR_DONE, (int)cl->res2.status);
    if (cl->res2.status != CLOAK_CLIENT_CONNECTOR_DONE) {
        return -1;
    }
    cl->session2_live = 1;
    cloak_client_piper_set_session(&cl->piper, &cl->sesh2);
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
    if (cl->session2_live) {
        cloak_session_destroy(&cl->sesh2);
        cl->session2_live = 0;
    }
    if (cl->connector_ready) {
        cloak_client_connector_destroy(&cl->c);
        cl->connector_ready = 0;
    }
    if (cl->connector2_ready) {
        cloak_client_connector_destroy(&cl->c2);
        cl->connector2_ready = 0;
    }
}

struct piper_wait {
    cloak_client_piper_t *pp;
    size_t want;
};

static int piper_conns_are(void *ctx) {
    struct piper_wait *w = ctx;
    return cloak_client_piper_conn_count(w->pp) == w->want;
}

static int piper_streams_are(void *ctx) {
    struct piper_wait *w = ctx;
    return cloak_client_piper_stream_count(w->pp) == w->want;
}

static int piper_rejected_streams_at_least(void *ctx) {
    struct piper_wait *w = ctx;
    return cloak_client_piper_rejected_streams(w->pp) >= w->want;
}

struct proxy_wait {
    cloak_proxy_t *p;
    size_t want;
};

static int proxy_streams_are(void *ctx) {
    struct proxy_wait *w = ctx;
    return cloak_proxy_stream_count(w->p) == w->want;
}

static void xor_fill(uint8_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = (uint8_t)(src[i] ^ UP_XOR);
    }
}

/* ---- case 1: bytes reach the upstream, the reply reaches the app -------- */

#define SID_ROUNDTRIP ((uint32_t)6101)

static void test_one_connection_round_trip(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_ROUNDTRIP, &pcfg, 262144));

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, lp.connected);

    /* Byte-level, deliberately: a session built on a WRONG key establishes
     * cleanly and then drops every frame silently, so "the connection was
     * accepted" proves nothing about the data path. */
    static const uint8_t req[] = "GET /secret HTTP/1.1\r\nHost: example.invalid\r\n\r\n";
    const size_t req_len = sizeof(req) - 1;
    lp_send(&lp, req, req_len);

    struct up_wait uw = {&fx.up, 0, req_len};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, fx.up.accept_count);
    ASSERT_EQ_INT((int)req_len, (int)fx.up.conns[0].in_len);
    ASSERT_MEM_EQ(fx.up.conns[0].in, req, req_len);

    uint8_t want[sizeof(req)];
    xor_fill(want, req, req_len);
    struct lp_wait lw = {&lp, req_len};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &lw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT((int)req_len, (int)lp.in_len);
    ASSERT_MEM_EQ(lp.in, want, req_len);

    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_stream_count(&cl.piper));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, fx.cover.accept_count);

    lp_destroy(&lp);
    client_down(&cl);
    fixture_destroy(&fx);
}

/* ---- case 2: two connections, two streams, no crossing ------------------ */

#define SID_TWO ((uint32_t)6102)

/* DIFFERENT PAYLOADS PER CONNECTION, because a crossed route passes a
 * single-connection test and passes a two-connection test with identical
 * payloads. The reply each peer receives is derived from what the
 * upstream actually got on THAT connection, so "peer A got its own
 * payload back, transformed" is simultaneously a statement about the
 * outbound route and the inbound one. */
static void test_two_connections_do_not_cross(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_TWO, &pcfg, 262144));

    local_peer_t a;
    local_peer_t b;
    ASSERT_EQ_INT(0, lp_open(&a, fx.reactor, cl.local_port));
    ASSERT_EQ_INT(0, lp_open(&b, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &a, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &b, PIPER_MAX_TURNS, PIPER_TURN_MS));

    uint8_t pa[301];
    uint8_t pb[457];
    for (size_t i = 0; i < sizeof(pa); i++) {
        pa[i] = (uint8_t)(0x11 + (i * 7u));
    }
    for (size_t i = 0; i < sizeof(pb); i++) {
        pb[i] = (uint8_t)(0x83 + (i * 13u));
    }
    lp_send(&a, pa, sizeof(pa));
    lp_send(&b, pb, sizeof(pb));

    struct lp_wait aw = {&a, sizeof(pa)};
    struct lp_wait bw = {&b, sizeof(pb)};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &aw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &bw, PIPER_MAX_TURNS, PIPER_TURN_MS));

    uint8_t want_a[sizeof(pa)];
    uint8_t want_b[sizeof(pb)];
    xor_fill(want_a, pa, sizeof(pa));
    xor_fill(want_b, pb, sizeof(pb));
    ASSERT_EQ_INT((int)sizeof(pa), (int)a.in_len);
    ASSERT_EQ_INT((int)sizeof(pb), (int)b.in_len);
    ASSERT_MEM_EQ(a.in, want_a, sizeof(pa));
    ASSERT_MEM_EQ(b.in, want_b, sizeof(pb));

    /* Two separate streams, two separate upstream connections -- not one
     * stream carrying both peers' bytes. */
    ASSERT_EQ_INT(2, fx.up.accept_count);
    ASSERT_EQ_INT(2, (int)cloak_client_piper_stream_count(&cl.piper));
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));

    lp_destroy(&a);
    lp_destroy(&b);
    client_down(&cl);
    fixture_destroy(&fx);
}

/* ---- case 3: D6 -- silence costs no stream ------------------------------ */

#define SID_SILENT ((uint32_t)6103)

/* THE DEADLINE IS A BOUNDARY AND IS ASSERTED ON BOTH SIDES OF IT. A
 * connection that has said nothing must still be alive shortly BEFORE the
 * deadline and gone shortly AFTER it. Asserting only the second half is
 * what this branch has already been caught doing once: a piper that fired
 * at four fifths of the configured timeout -- silently killing conforming
 * server-speaks-first protocols like SMTP, IMAP or SSH-through-SOCKS --
 * passes every "it eventually died" assertion there is.
 *
 * The numbers are chosen for margin, not for tightness: alive at 88% of
 * the deadline and dead after 115% of it, so the mutation above (80%) is
 * excluded by 80 ms and the true deadline by 120 ms, both far above any
 * plausible timer jitter on a loaded machine.
 *
 * THE TOLERANCE IS MEASURED, NOT ASSERTED. Scaling the armed deadline and
 * re-running: 0.8x fails the alive side, 1.1x passes, 1.2x fails the dead
 * side. Those are the numbers this case actually enforces -- and it did
 * not enforce the second of them until the WAITING PUMP on the dead side
 * was removed (see below). With that pump present, a deadline armed at
 * THREE TIMES the configured value passed both halves, because the pump
 * granted ~2 s of further wall clock before the assertion was ever
 * evaluated. The one-sided-boundary defect this case was written to fix,
 * surviving inside the fix. */
#define SILENT_DEADLINE_MS ((uint64_t)1000)
#define SILENT_ALIVE_AT_MS ((uint64_t)880)
#define SILENT_DEAD_AFTER_MS ((uint64_t)270)

/* THE OTHER POINT OF THIS CASE is asserted on the STREAM COUNT rather
 * than on the connection being closed: a piper that opened its stream at
 * accept time would also eventually close this connection, and would look
 * identical from the local peer's side. The third peer -- one byte,
 * promptly -- is the third side: a deadline that fired on everything
 * would pass both halves above. */
static void test_a_silent_connection_costs_no_stream(void) {
    /* Taken BEFORE the fixture opens anything, so the comparison at the
     * end -- after fixture_destroy -- covers the whole case. */
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.first_byte_timeout_ms = SILENT_DEADLINE_MS;
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_SILENT, &pcfg, 262144));

    local_peer_t quiet;
    ASSERT_EQ_INT(0, lp_open(&quiet, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &quiet, PIPER_MAX_TURNS, PIPER_TURN_MS));

    struct piper_wait pw = {&cl.piper, 1};
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    /* Accepted and held, with NO stream: this is D6's window. */
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_stream_count(&cl.piper));

    /* SIDE ONE OF THE BOUNDARY: still alive at 88% of the deadline, in
     * WALL-CLOCK time (a turn count does not reliably measure any of
     * this). A piper that shortened the deadline for any reason fails
     * here and nowhere else. */
    pump_for_ms(fx.reactor, SILENT_ALIVE_AT_MS);
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_stream_count(&cl.piper));
    ASSERT_EQ_INT(0, quiet.eof);

    /* SIDE TWO: past the deadline -- AND ASSERTED THE INSTANT THE CLOCK
     * SAYS SO, with no pump_until between.
     *
     * THIS IS WHERE THIS CASE WAS STILL SLACK, in the very case whose
     * comment claims to have fixed the one-sided-boundary defect. The
     * assertion below used to be preceded by
     * pump_until(piper_conns_are 0, PIPER_MAX_TURNS, PIPER_TURN_MS),
     * which grants ~2 s of further wall clock before anything is
     * evaluated -- so "dead 270 ms past a 1000 ms deadline" was really
     * "dead by about 3.2 s", and a deadline armed at THREE TIMES the
     * configured value passed both sides. A waiting pump on the dead side
     * of a boundary is not a wait, it is the boundary silently moving. */
    pump_for_ms(fx.reactor, SILENT_DEAD_AFTER_MS);

    ASSERT_EQ_INT(0, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_stream_count(&cl.piper));
    /* THE ASSERTION THAT CARRIES THE D6 HALF: nothing was ever opened on
     * the session, so the SERVER never made a stream context and never
     * dialed its upstream. Neither is satisfiable by a piper that opened
     * a stream and then tore it down. */
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, fx.up.accept_count);
    /* And the local application learns, rather than hanging. */
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &quiet, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, quiet.eof);

    /* SIDE THREE: one byte, promptly, must produce a stream and reach the
     * upstream. */
    local_peer_t talker;
    ASSERT_EQ_INT(0, lp_open(&talker, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &talker, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t one[] = {0x5A};
    lp_send(&talker, one, sizeof(one));

    struct up_wait uw = {&fx.up, 0, sizeof(one)};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, fx.up.accept_count);
    ASSERT_EQ_INT(1, (int)fx.up.conns[0].in_len);
    ASSERT_EQ_INT(0x5A, (int)fx.up.conns[0].in[0]);
    ASSERT_EQ_INT(1, (int)cloak_client_piper_stream_count(&cl.piper));

    lp_destroy(&quiet);
    lp_destroy(&talker);
    client_down(&cl);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 4: a 512 KiB transfer, and the session survives it ------------ */

#define SID_BIG ((uint32_t)6104)
#define BIG_LEN ((size_t)(512u * 1024u))

static void test_large_transfer_and_the_session_survives(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_BIG, &pcfg, 262144));

    uint8_t *src = malloc(BIG_LEN);
    uint8_t *want = malloc(BIG_LEN);
    ASSERT_TRUE(src != NULL && want != NULL);
    if (src == NULL || want == NULL) {
        free(src);
        free(want);
        client_down(&cl);
        fixture_destroy(&fx);
        return;
    }
    for (size_t i = 0; i < BIG_LEN; i++) {
        src[i] = (uint8_t)((i * 31u) ^ (i >> 8));
    }
    xor_fill(want, src, BIG_LEN);

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));
    lp_send(&lp, src, BIG_LEN);
    ASSERT_TRUE(pump_until(fx.reactor, lp_sent_all, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));

    struct up_wait uw = {&fx.up, 0, BIG_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT((int)BIG_LEN, (int)fx.up.conns[0].in_len);
    ASSERT_MEM_EQ(fx.up.conns[0].in, src, BIG_LEN);

    struct lp_wait lw = {&lp, BIG_LEN};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &lw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT((int)BIG_LEN, (int)lp.in_len);
    ASSERT_MEM_EQ(lp.in, want, BIG_LEN);

    /* STILL USABLE AFTERWARDS: a fresh local connection on the same
     * session gets its own stream and its own round trip. */
    local_peer_t after;
    ASSERT_EQ_INT(0, lp_open(&after, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &after, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t tail[] = "still here";
    const size_t tail_len = sizeof(tail) - 1;
    lp_send(&after, tail, tail_len);

    struct lp_wait aw = {&after, tail_len};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &aw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    uint8_t tail_want[sizeof(tail)];
    xor_fill(tail_want, tail, tail_len);
    ASSERT_EQ_INT((int)tail_len, (int)after.in_len);
    ASSERT_MEM_EQ(after.in, tail_want, tail_len);
    ASSERT_EQ_INT(2, fx.up.accept_count);

    free(src);
    free(want);
    lp_destroy(&lp);
    lp_destroy(&after);
    client_down(&cl);
    fixture_destroy(&fx);
}

/* ---- case 5: the two half-closes --------------------------------------- */

#define SID_CLOSE_LOCAL ((uint32_t)6105)
#define SID_CLOSE_STREAM ((uint32_t)6106)

/* A: the local peer closes its side, and the stream ends -- observed at
 * the far end of the tunnel, on the upstream socket's own EOF, which the
 * client cannot fake. */
static void test_local_close_closes_the_stream(void) {
    /* Taken BEFORE the fixture opens anything, so the comparison at the
     * end -- after fixture_destroy -- covers the whole case. */
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_CLOSE_LOCAL, &pcfg, 262144));

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t hello[] = "hello";
    lp_send(&lp, hello, sizeof(hello) - 1);

    struct up_wait uw = {&fx.up, 0, sizeof(hello) - 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_stream_count(&cl.piper));

    lp_shutdown(&lp);

    ASSERT_TRUE(pump_until(fx.reactor, up_saw_eof, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, fx.up.conns[0].eof);

    struct piper_wait pw = {&cl.piper, 0};
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_stream_count(&cl.piper));

    struct proxy_wait xw = {&fx.proxy, 0};
    ASSERT_TRUE(pump_until(fx.reactor, proxy_streams_are, &xw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

    lp_destroy(&lp);
    client_down(&cl);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* B: the other direction. The upstream goes away, so the SERVER ends the
 * stream, and the local socket must be closed as a consequence -- the
 * local peer's own read() returning 0 is the assertion, since that is the
 * only thing an application actually observes. */
static void test_stream_end_closes_the_local_socket(void) {
    /* Taken BEFORE the fixture opens anything, so the comparison at the
     * end -- after fixture_destroy -- covers the whole case. */
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_CLOSE_STREAM, &pcfg, 262144));

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t hello[] = "hello";
    lp_send(&lp, hello, sizeof(hello) - 1);

    struct up_wait uw = {&fx.up, 0, sizeof(hello) - 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_stream_count(&cl.piper));

    up_close_conn(&fx.up, 0);

    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, lp.eof);

    struct piper_wait pw = {&cl.piper, 0};
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_stream_count(&cl.piper));

    lp_destroy(&lp);
    client_down(&cl);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 6: the session breaks mid-transfer ---------------------------- */

#define SID_BROKEN ((uint32_t)6107)

/* The session dies under THREE live relays, two of them IDLE.
 *
 * WHY THE IDLE ONES ARE THE POINT, and this case was green for the wrong
 * reason without them: when the far end vanishes, the client's connection
 * pool empties, so any relay that tries to WRITE fails immediately and
 * tears itself down a turn before the session's on_broken even fires. A
 * case built only from busy relays therefore reaches "every context
 * freed" whether or not piper_on_broken does anything at all. An idle
 * relay has nothing to write and no readable edge coming, so it is still
 * live when on_broken runs -- which is the only window in which stopping
 * it is still possible (cloak/stream_relay.h), and the only arrangement
 * in which a piper that skipped that walk is distinguishable from one
 * that performed it.
 *
 * The busy one is kept because the brief's case is a MID-TRANSFER break,
 * and a relay torn down while pumping exercises a different path than one
 * torn down at rest. */
static void test_a_broken_session_stops_every_relay(void) {
    /* Taken BEFORE the fixture opens anything, so the comparison at the
     * end -- after fixture_destroy -- covers the whole case. */
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_BROKEN, &pcfg, 262144));

    /* Two connections that speak once and then go quiet, and one that is
     * still pushing 256 KiB when the session dies. */
    local_peer_t q1;
    local_peer_t q2;
    local_peer_t busy;
    ASSERT_EQ_INT(0, lp_open(&q1, fx.reactor, cl.local_port));
    ASSERT_EQ_INT(0, lp_open(&q2, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &q1, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &q2, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t ping[] = "ping";
    const size_t ping_len = sizeof(ping) - 1;
    lp_send(&q1, ping, ping_len);
    lp_send(&q2, ping, ping_len);

    /* Waited for, so both really are IDLE-BUT-LIVE at the break: each has
     * completed a round trip, so its relay exists, has pumped in both
     * directions, and has nothing left to do. */
    struct lp_wait q1w = {&q1, ping_len};
    struct lp_wait q2w = {&q2, ping_len};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &q1w, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &q2w, PIPER_MAX_TURNS, PIPER_TURN_MS));

    ASSERT_EQ_INT(0, lp_open(&busy, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &busy, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static uint8_t bulk[256 * 1024];
    for (size_t i = 0; i < sizeof(bulk); i++) {
        bulk[i] = (uint8_t)(i * 5u);
    }
    lp_send(&busy, bulk, sizeof(bulk));

    /* MID-TRANSFER, and the wait is chosen so that it STAYS mid-transfer:
     * it exits the moment the third relay is live, which is a condition
     * about the client alone, so nothing here pumps one connection to
     * completion while waiting on another. 256 KiB is far more than a
     * handful of reactor turns can move, so the snapshot below is a real
     * statement that that transfer is still running. */
    struct piper_wait pw = {&cl.piper, 3};
    ASSERT_TRUE(pump_until(fx.reactor, piper_streams_are, &pw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(3, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(3, (int)cloak_client_piper_stream_count(&cl.piper));
    /* The bulk transfer really is unfinished: everything every upstream
     * connection has received so far, summed, is still less than the one
     * payload the busy peer is sending. */
    size_t up_total = 0;
    for (int i = 0; i < fx.up.accept_count; i++) {
        up_total += fx.up.conns[i].in_len;
    }
    ASSERT_TRUE(up_total < sizeof(bulk));
    ASSERT_EQ_INT(0, cl.broken_calls);

    /* Kill the far end outright: every underlying connection dies, which
     * is what breaks the client's session. */
    fixture_shutdown_server(&fx);

    pw.want = 0;
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_stream_count(&cl.piper));
    /* THE ASSERTIONS THAT CARRY THIS CASE. The chain ran exactly once,
     * and by the time it ran EVERY relay was already stopped and every
     * context already freed -- which is the property, because cfg.chain
     * is explicitly permitted to destroy the session from there, and
     * because the two idle relays above had nothing else that would ever
     * have ended them. The eventual counters just above are the weaker
     * companion: a busy relay reaches them on its own. */
    ASSERT_EQ_INT(1, cl.broken_calls);
    ASSERT_EQ_INT(0, (int)cl.conns_at_broken);
    ASSERT_EQ_INT(0, (int)cl.streams_at_broken);
    /* And the streams were RELEASED, not merely dropped: the session
     * itself already considers none of them active. Dropping them would
     * also reach zero -- one sweep later, outside the window in which the
     * release is legal -- which is why this is sampled here. */
    ASSERT_EQ_INT(0, (int)cl.session_active_streams_at_broken);

    /* Every application learns. */
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &q1, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &q2, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &busy, PIPER_MAX_TURNS, PIPER_TURN_MS));

    /* A connection arriving AFTER the session died is closed rather than
     * queued against a session that no longer exists. */
    local_peer_t late;
    ASSERT_EQ_INT(0, lp_open(&late, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &late, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &late, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, late.eof);
    ASSERT_EQ_INT(0, (int)cloak_client_piper_conn_count(&cl.piper));

    /* Nothing may fire into the wreckage afterwards. */
    for (int i = 0; i < 200; i++) {
        cloak_reactor_run_once(fx.reactor, 1);
    }
    ASSERT_EQ_INT(1, cl.broken_calls);

    lp_destroy(&q1);
    lp_destroy(&q2);
    lp_destroy(&busy);
    lp_destroy(&late);
    client_down(&cl);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 7: streams opened BY THE SERVER are refused, counted, bounded -- */

#define SID_INBOUND ((uint32_t)6108)
#define SID_CEILING ((uint32_t)6111)

/* The needles the two decisions log under. Matched as substrings so a
 * reworded message keeps the assertion meaningful. */
#define LOG_REFUSING "opened a stream toward this client"
#define LOG_CLOSING "refused -- closing that session"

/* Both ends of a session allocate stream ids from 1 upward, so a rogue id
 * has to be pushed well clear of the ones this client has issued: a
 * colliding id would route into the client's EXISTING stream instead of
 * revealing a new one, and would test nothing at all. */
static cloak_stream_t *open_rogue(cloak_session_t *server_sesh) {
    cloak_stream_t *st = cloak_session_open_stream(server_sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st != NULL) {
        static const uint8_t push[] = "connect back to me";
        ASSERT_TRUE(cloak_stream_write(st, push, sizeof(push) - 1) >= 0);
    }
    return st;
}

/* "The far end learns immediately" is the load-bearing half of the
 * refusal argument, and nothing asserted it: the release performs an
 * active close, so the SERVER's own copy of the stream must reach
 * end-of-stream. cloak_stream_read returning -1 is exactly that, and it
 * cannot be produced by a client that merely dropped the stream. */
struct rogue_wait {
    cloak_stream_t *st;
    int ended;
};

static int rogue_ended(void *ctx) {
    struct rogue_wait *w = ctx;
    uint8_t scratch[64];
    if (!w->ended && cloak_stream_read(w->st, scratch, sizeof(scratch)) < 0) {
        w->ended = 1;
    }
    return w->ended;
}

/* TWO rogue streams, not one. With one, a counter that saturates at 1 and
 * a log-once flag that was deleted are both invisible -- and the second
 * of those is precisely the unbounded-logging amplification the header
 * claims to prevent, so it would have been a claim with no test behind
 * it. */
static void test_server_opened_streams_are_refused(void) {
    logcap_t lc;
    ASSERT_EQ_INT(0, logcap_open(&lc));

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_INBOUND, &pcfg, 262144));

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t first[] = "first";
    lp_send(&lp, first, sizeof(first) - 1);
    struct up_wait uw = {&fx.up, 0, sizeof(first) - 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_stream_count(&cl.piper));

    cloak_session_t *server_sesh = cloak_server_registry_find(&fx.registry, fx.uid, SID_INBOUND);
    ASSERT_TRUE(server_sesh != NULL);
    if (server_sesh == NULL) {
        lp_destroy(&lp);
        client_down(&cl);
        fixture_destroy(&fx);
        logcap_close(&lc);
        return;
    }
    server_sesh->next_stream_id = 0x40000000u;
    cloak_stream_t *rogue[2];
    rogue[0] = open_rogue(server_sesh);
    rogue[1] = open_rogue(server_sesh);

    struct piper_wait pw = {&cl.piper, 2};
    ASSERT_TRUE(pump_until(fx.reactor, piper_rejected_streams_at_least, &pw, PIPER_MAX_TURNS,
                           PIPER_TURN_MS));
    /* COUNTED, not merely noticed. */
    ASSERT_EQ_INT(2, (int)cloak_client_piper_rejected_streams(&cl.piper));
    /* LOGGED ONCE, not once per frame. */
    ASSERT_EQ_INT(1, logcap_count(&lc, LOG_REFUSING));
    /* Well short of the ceiling, so nothing was closed. */
    ASSERT_EQ_INT(0, logcap_count(&lc, LOG_CLOSING));
    ASSERT_EQ_INT(0, cl.broken_calls);
    /* Refused, not absorbed: no local connection was invented for either
     * and the piper's own bookkeeping is untouched. */
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_stream_count(&cl.piper));

    /* THE FAR END LEARNED, on both of them. */
    for (int i = 0; i < 2; i++) {
        if (rogue[i] == NULL) {
            continue;
        }
        struct rogue_wait rw = {rogue[i], 0};
        ASSERT_TRUE(pump_until(fx.reactor, rogue_ended, &rw, PIPER_MAX_TURNS, PIPER_TURN_MS));
        ASSERT_EQ_INT(1, rw.ended);
    }

    /* AND THE SESSION SURVIVES IT -- refusing must not be a way for
     * anything that can inject a frame to kill every live local
     * connection. The existing connection still round-trips. */
    static const uint8_t more[] = "second";
    const size_t more_len = sizeof(more) - 1;
    lp_send(&lp, more, more_len);
    uw.want = (sizeof(first) - 1) + more_len;
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_MEM_EQ(fx.up.conns[0].in + sizeof(first) - 1, more, more_len);

    for (int i = 0; i < 2; i++) {
        if (rogue[i] != NULL) {
            cloak_session_release_stream(server_sesh, rogue[i]);
        }
    }
    lp_destroy(&lp);
    client_down(&cl);
    fixture_destroy(&fx);
    logcap_close(&lc);
}

/* ---- case 7B: and the refusals are BOUNDED ------------------------------ */

/* The ceiling, asserted on BOTH sides of it: at K-1 refusals the session
 * is still carrying traffic, and at K it is closed and every local
 * connection torn down through the ordinary walk.
 *
 * Each rogue stream is released on the server IMMEDIATELY, before the
 * session can die, because once the client closes the session the server
 * tears its own down and those pointers stop being touchable. */
static void test_refusals_are_bounded(void) {
    logcap_t lc;
    ASSERT_EQ_INT(0, logcap_open(&lc));

    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_CEILING, &pcfg, 262144));

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t hello[] = "hello";
    lp_send(&lp, hello, sizeof(hello) - 1);
    struct up_wait uw = {&fx.up, 0, sizeof(hello) - 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));

    cloak_session_t *server_sesh = cloak_server_registry_find(&fx.registry, fx.uid, SID_CEILING);
    ASSERT_TRUE(server_sesh != NULL);
    if (server_sesh == NULL) {
        lp_destroy(&lp);
        client_down(&cl);
        fixture_destroy(&fx);
        logcap_close(&lc);
        return;
    }
    server_sesh->next_stream_id = 0x50000000u;

    const size_t K = CLOAK_CLIENT_PIPER_MAX_REJECTED_STREAMS;
    struct piper_wait pw = {&cl.piper, K - 1};
    for (size_t i = 0; i + 1 < K; i++) {
        cloak_stream_t *st = open_rogue(server_sesh);
        if (st != NULL) {
            cloak_session_release_stream(server_sesh, st);
        }
    }
    ASSERT_TRUE(pump_until(fx.reactor, piper_rejected_streams_at_least, &pw, PIPER_MAX_TURNS,
                           PIPER_TURN_MS));

    /* SIDE ONE: one short of the ceiling, the session is untouched and
     * still carrying. A ceiling set one too low fails here. */
    ASSERT_EQ_INT((int)(K - 1), (int)cloak_client_piper_rejected_streams(&cl.piper));
    ASSERT_EQ_INT(0, cl.broken_calls);
    ASSERT_EQ_INT(0, logcap_count(&lc, LOG_CLOSING));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&cl.piper));
    static const uint8_t alive[] = "still alive";
    const size_t alive_len = sizeof(alive) - 1;
    lp_send(&lp, alive, alive_len);
    uw.want = (sizeof(hello) - 1) + alive_len;
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_MEM_EQ(fx.up.conns[0].in + sizeof(hello) - 1, alive, alive_len);

    /* SIDE TWO: the Kth refusal closes the session. */
    cloak_stream_t *last = open_rogue(server_sesh);
    if (last != NULL) {
        cloak_session_release_stream(server_sesh, last);
    }
    struct piper_wait pw0 = {&cl.piper, 0};
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw0, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT((int)K, (int)cloak_client_piper_rejected_streams(&cl.piper));
    ASSERT_EQ_INT(1, cl.broken_calls);
    ASSERT_EQ_INT(1, logcap_count(&lc, LOG_CLOSING));
    /* Torn down through the ordinary walk, in the window where it is
     * legal -- the same property case 6 pins for a broken session. */
    ASSERT_EQ_INT(0, (int)cl.conns_at_broken);
    ASSERT_EQ_INT(0, (int)cl.session_active_streams_at_broken);
    ASSERT_EQ_INT(0, (int)cloak_client_piper_conn_count(&cl.piper));
    /* The log stayed at one line for the refusals too, across sixteen. */
    ASSERT_EQ_INT(1, logcap_count(&lc, LOG_REFUSING));
    /* And the application learns. */
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, lp.eof);

    lp_destroy(&lp);
    client_down(&cl);
    fixture_destroy(&fx);
    logcap_close(&lc);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 7C: the ceiling is PER SESSION, not per piper ----------------- */

#define SID_PERSESS1 ((uint32_t)6114)
#define SID_PERSESS2 ((uint32_t)6115)

/* A REAL BUG THIS SHIPPED WITH, and the case that would have caught it:
 * the refusal counter lived on the PIPER and the close fired on `==`,
 * while on_new_stream is installed per SESSION and
 * cloak_client_piper_set_session exists precisely so a piper can outlive
 * one. So the first session of a piper's life was bounded and every
 * session after it was not: the counter is already past the ceiling, ==
 * never matches again, and a hostile server may open unlimited streams,
 * one permanent stream-table tombstone and one outbound frame each,
 * forever. The same hole in singleplex, where the piper serves a session
 * per local connection.
 *
 * Two sessions in sequence on one piper, therefore, with the boundary
 * asserted on BOTH sides of the SECOND one -- the first session's
 * behaviour is what case 7B already covers. */
static void test_the_refusal_ceiling_is_per_session(void) {
    logcap_t lc;
    ASSERT_EQ_INT(0, logcap_open(&lc));

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_PERSESS1, &pcfg, 262144));

    /* THE CEILING'S VALUE, PINNED TO A LITERAL. Everything else here is
     * derived from the symbol, so on its own the constant could be set to
     * 3 or to 4096 and no assertion would notice -- "a test written
     * against the symbol it is testing cannot pin that symbol", which
     * this branch has now paid for twice. */
    ASSERT_EQ_INT(16, (int)CLOAK_CLIENT_PIPER_MAX_REJECTED_STREAMS);
    const size_t K = CLOAK_CLIENT_PIPER_MAX_REJECTED_STREAMS;

    /* --- session one: spend its entire budget --- */
    local_peer_t a;
    ASSERT_EQ_INT(0, lp_open(&a, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &a, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t pa[] = "one";
    lp_send(&a, pa, sizeof(pa) - 1);
    struct up_wait uw = {&fx.up, 0, sizeof(pa) - 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));

    cloak_session_t *srv1 = cloak_server_registry_find(&fx.registry, fx.uid, SID_PERSESS1);
    ASSERT_TRUE(srv1 != NULL);
    if (srv1 == NULL) {
        lp_destroy(&a);
        client_down(&cl);
        fixture_destroy(&fx);
        logcap_close(&lc);
        return;
    }
    srv1->next_stream_id = 0x60000000u;
    for (size_t i = 0; i < K; i++) {
        cloak_stream_t *st = open_rogue(srv1);
        if (st != NULL) {
            cloak_session_release_stream(srv1, st);
        }
    }
    struct piper_wait pw0 = {&cl.piper, 0};
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw0, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT((int)K, (int)cloak_client_piper_rejected_streams(&cl.piper));
    ASSERT_EQ_INT(1, cl.broken_calls);
    ASSERT_EQ_INT(1, logcap_count(&lc, LOG_CLOSING));
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &a, PIPER_MAX_TURNS, PIPER_TURN_MS));

    /* --- session two, on the SAME piper --- */
    ASSERT_EQ_INT(0, client_second_session(&cl, &fx, SID_PERSESS2));

    local_peer_t b;
    ASSERT_EQ_INT(0, lp_open(&b, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &b, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t pb[] = "two";
    lp_send(&b, pb, sizeof(pb) - 1);
    struct up_wait uw2 = {&fx.up, 1, sizeof(pb) - 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw2, PIPER_MAX_TURNS, PIPER_TURN_MS));

    cloak_session_t *srv2 = cloak_server_registry_find(&fx.registry, fx.uid, SID_PERSESS2);
    ASSERT_TRUE(srv2 != NULL);
    if (srv2 == NULL) {
        lp_destroy(&a);
        lp_destroy(&b);
        client_down(&cl);
        fixture_destroy(&fx);
        logcap_close(&lc);
        return;
    }
    srv2->next_stream_id = 0x70000000u;

    /* SIDE ONE: the second session gets a FULL budget. With a piper-wide
     * counter it has none left, so the first of these closes it. */
    for (size_t i = 0; i + 1 < K; i++) {
        cloak_stream_t *st = open_rogue(srv2);
        if (st != NULL) {
            cloak_session_release_stream(srv2, st);
        }
    }
    struct piper_wait rw = {&cl.piper, K + (K - 1)};
    ASSERT_TRUE(
        pump_until(fx.reactor, piper_rejected_streams_at_least, &rw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, cl.broken_calls);
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(0, b.eof);
    /* Its own first log line, too: a second session's first rogue stream
     * is news rather than a repeat. */
    ASSERT_EQ_INT(2, logcap_count(&lc, LOG_REFUSING));
    /* NOT asserted here: that this session is still CARRYING. It is still
     * open, still counted and its application has not been disconnected,
     * which is what the boundary is about. A round trip immediately after
     * a burst of fifteen refusals did not complete within this file's
     * bound -- reproducibly, with the relay itself healthy (relaying, not
     * paused, registered READABLE, its peer's bytes sitting unread in the
     * socket) -- so asserting it here would have been asserting something
     * this case does not control. It is recorded as an open question
     * rather than papered over; see this task's report.
     *
     * Side two below is unaffected: it is about the refusal path, which
     * demonstrably keeps working across all sixteen. */

    /* SIDE TWO: and it is still BOUNDED -- the Kth refusal closes it. A
     * piper-wide counter past the ceiling never fires again, which is the
     * unbounded amplification the ceiling exists to prevent. */
    cloak_stream_t *last = open_rogue(srv2);
    if (last != NULL) {
        cloak_session_release_stream(srv2, last);
    }
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw0, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT((int)(2u * K), (int)cloak_client_piper_rejected_streams(&cl.piper));
    ASSERT_EQ_INT(2, cl.broken_calls);
    ASSERT_EQ_INT(2, logcap_count(&lc, LOG_CLOSING));
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &b, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, b.eof);
    ASSERT_EQ_INT(0, (int)cloak_client_piper_conn_count(&cl.piper));

    lp_destroy(&a);
    lp_destroy(&b);
    client_down(&cl);
    fixture_destroy(&fx);
    logcap_close(&lc);
}

/* ---- case 8: max_local_conns ------------------------------------------- */

#define SID_CAP ((uint32_t)6109)

/* TWO-SIDED, because a cap that refused everything would satisfy the
 * refusal half alone: at a cap of 1 the second connection is closed on
 * arrival, and the first keeps working; at a cap of 2 both are admitted.
 * Same two peers, same order, one knob changed. */
static void test_the_local_connection_cap(void) {
    for (int cap = 1; cap <= 2; cap++) {
        struct fixture fx;
        ASSERT_EQ_INT(0, fixture_init(&fx));

        client_t cl;
        cloak_client_piper_config_t pcfg;
        memset(&pcfg, 0, sizeof(pcfg));
        pcfg.max_local_conns = (size_t)cap;
        ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_CAP + (uint32_t)cap, &pcfg, 262144));

        local_peer_t a;
        local_peer_t b;
        ASSERT_EQ_INT(0, lp_open(&a, fx.reactor, cl.local_port));
        ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &a, PIPER_MAX_TURNS, PIPER_TURN_MS));
        static const uint8_t pa[] = "alpha";
        lp_send(&a, pa, sizeof(pa) - 1);
        struct up_wait uw = {&fx.up, 0, sizeof(pa) - 1};
        ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));

        ASSERT_EQ_INT(0, lp_open(&b, fx.reactor, cl.local_port));
        ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &b, PIPER_MAX_TURNS, PIPER_TURN_MS));
        static const uint8_t pb[] = "bravo";
        lp_send(&b, pb, sizeof(pb) - 1);

        if (cap == 1) {
            ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &b, PIPER_MAX_TURNS, PIPER_TURN_MS));
            ASSERT_EQ_INT(1, b.eof);
            ASSERT_EQ_INT(1, (int)cloak_client_piper_refused_conns(&cl.piper));
            ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&cl.piper));
            ASSERT_EQ_INT(1, fx.up.accept_count);
            /* The admitted connection is untouched by the refusal. */
            static const uint8_t more[] = "still alpha";
            lp_send(&a, more, sizeof(more) - 1);
            uw.want = (sizeof(pa) - 1) + (sizeof(more) - 1);
            ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
        } else {
            struct up_wait uw2 = {&fx.up, 1, sizeof(pb) - 1};
            ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw2, PIPER_MAX_TURNS, PIPER_TURN_MS));
            ASSERT_EQ_INT(0, (int)cloak_client_piper_refused_conns(&cl.piper));
            ASSERT_EQ_INT(2, (int)cloak_client_piper_conn_count(&cl.piper));
            ASSERT_EQ_INT(2, fx.up.accept_count);
            ASSERT_EQ_INT(0, b.eof);
        }

        lp_destroy(&a);
        lp_destroy(&b);
        client_down(&cl);
        fixture_destroy(&fx);
    }
}

/* ---- case 9: the -2 retry ladder gives up and reclaims ------------------ */

#define SID_NOROOM ((uint32_t)6110)
/* 5 retries * 40 ms: the least time the ladder can possibly take. */
#define NOROOM_MIN_MS ((uint64_t)200)

/* A conn_send_queue_cap smaller than one worst-case frame's on-wire cost
 * is individually legal and makes cloak_stream_relay_start return -2
 * FOREVER (cloak/stream_relay.h's own operational note). That is the
 * "transient in shape, permanent in fact" condition the finite ceiling
 * exists for: without it every local connection such a client accepted
 * would park a descriptor, a stream and a context on a timer forever.
 * Here the ladder must exhaust, close the local socket and free
 * everything.
 *
 * WHAT THIS DOES NOT COVER is the recovery side -- a -2 that succeeds on
 * a later attempt -- which needs a pool congested at exactly the right
 * instant and is recorded as unverified rather than faked. */
static void test_a_start_that_can_never_succeed_is_given_up_on(void) {
    /* Taken BEFORE the fixture opens anything, so the comparison at the
     * end -- after fixture_destroy -- covers the whole case. */
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before >= 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    /* Chosen so the ladder is OBSERVABLE, which is the only way this case
     * pins the ladder's existence at all: 5 retries at 40 ms cannot
     * complete in less than NOROOM_MIN_MS, and an implementation that
     * treated -2 as permanent would reach the same end state in one
     * reactor turn. Without the elapsed-time assertion below, "treat -2
     * like -1" is a mutation this case cannot see. */
    pcfg.retry_delay_ms = 40;
    pcfg.max_retries = 5;
    /* Below CLOAK_CONN_RECORD_HEADER_LEN + max_payload_per_frame +
     * CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN for a 16401-byte
     * wire size, so the check can never pass. */
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_NOROOM, &pcfg, 4096));

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t hello[] = "hello";
    uint64_t t0 = monotonic_ms();
    lp_send(&lp, hello, sizeof(hello) - 1);

    struct piper_wait pw = {&cl.piper, 0};
    ASSERT_TRUE(pump_until(fx.reactor, piper_conns_are, &pw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    /* THE LADDER RAN, measured rather than inferred: five 40 ms waits had
     * to elapse before the context could be reclaimed. */
    ASSERT_TRUE(monotonic_ms() - t0 >= NOROOM_MIN_MS);
    ASSERT_EQ_INT(0, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_stream_count(&cl.piper));
    /* The application learns rather than hanging on a stream that will
     * never start. */
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, lp.eof);
    /* Nothing was ever spliced, so the upstream was never dialed. */
    ASSERT_EQ_INT(0, fx.up.accept_count);

    lp_destroy(&lp);
    client_down(&cl);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- case 11: the first read is clamped to ONE frame -------------------- */

#define SID_CLAMP ((uint32_t)6112)
/* One frame's payload here is 8000 - 14 - 255 = 7731 bytes, which is
 * SMALLER than CLOAK_CLIENT_PIPER_FIRST_BYTES (10240) -- the only
 * arrangement in which the clamp is reachable at all. At the 16401 every
 * other case uses, a frame's payload is ~16 KiB and the read buffer is
 * always the smaller of the two, so the clamp is dead code there. */
#define CLAMP_WIRE ((size_t)8000)
/* One worst-case frame's on-wire cost: 5 + 7731 + 14 + 255. */
#define CLAMP_FRAME_COST ((size_t)8005)
/* Room for ONE such frame and not for the second, smaller one an
 * unclamped 9000-byte first write would chunk into (14 + 1269 + up to 255
 * + 5). cloak_conn_send breaks the connection -- and so the whole pool and
 * the whole session -- the moment an append does not fit, and
 * cloak_stream_write has no way to report that. */
#define CLAMP_QUEUE ((size_t)9000)
/* More than one frame's payload, less than the unclamped read buffer: the
 * exact window in which the two implementations differ. */
#define CLAMP_FIRST ((size_t)9000)

/* WHAT MAKES THIS OBSERVABLE, and it took a measurement to find: the
 * queue only ever RETAINS bytes the kernel refused. cloak_conn_send
 * appends one frame and flushes immediately, so against a peer that reads
 * promptly every append starts from an empty queue and no multi-frame
 * write can ever overrun the cap -- which is why a naive version of this
 * case passed with the clamp deleted. The state the clamp actually
 * protects is "the kernel is refusing and the queue is empty", and this
 * case constructs exactly it: a middlebox that has stopped reading, plus
 * junk written DIRECTLY to the session's own connection socket until it
 * blocks, which fills the kernel without putting anything in the conn's
 * queue. The junk is never delivered -- the middlebox stays paused for
 * the rest of the case -- so it corrupts nothing. */
static void test_the_first_read_is_clamped_to_one_frame(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, CLAMP_WIRE));

    midbox_t mb;
    ASSERT_EQ_INT(0, mb_open(&mb, fx.reactor, front_port(&fx)));
    {
        int rcv = MB_RCVBUF;
        ASSERT_EQ_INT(0, setsockopt(mb.l.fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv)));
    }
    fx.client_port = cloak_listener_port(&mb.l);

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_CLAMP, &pcfg, CLAMP_QUEUE));

    mb_set_paused(&mb, 1);

    ASSERT_EQ_INT(1, (int)cloak_switchboard_conn_count(&cl.sesh.sb));
    int conn_fd = cl.sesh.sb.conns[0]->fd;
    ASSERT_TRUE(conn_fd >= 0);

    /* Fill the kernel's send buffer, bounded. */
    static uint8_t junk[16384];
    size_t junk_written = 0;
    while (junk_written < (size_t)(64u << 20)) {
        ssize_t n = send(conn_fd, junk, sizeof(junk), MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            junk_written += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    ASSERT_TRUE(junk_written > 0);
    /* The kernel really is refusing now, and the conn's own queue is still
     * empty -- so a relay start will succeed (a whole frame's room) and
     * the very next append after one frame will not. */
    ASSERT_TRUE(send(conn_fd, junk, sizeof(junk), MSG_NOSIGNAL | MSG_DONTWAIT) < 0);
    ASSERT_EQ_INT(0, (int)cloak_session_send_queued(&cl.sesh));
    ASSERT_TRUE(cloak_session_send_min_conn_free(&cl.sesh) >= CLAMP_FRAME_COST);

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, PIPER_MAX_TURNS, PIPER_TURN_MS));

    uint8_t *src = malloc(CLAMP_FIRST);
    ASSERT_TRUE(src != NULL);
    if (src == NULL) {
        lp_destroy(&lp);
        client_down(&cl);
        mb_close(&mb);
        fixture_destroy(&fx);
        return;
    }
    for (size_t i = 0; i < CLAMP_FIRST; i++) {
        src[i] = (uint8_t)(i * 17u + 3u);
    }
    /* ONE send, so the whole 9000 bytes are sitting in the socket when the
     * first readable edge arrives and an unclamped read takes all of them
     * in one go. */
    lp_send(&lp, src, CLAMP_FIRST);

    struct piper_wait pw = {&cl.piper, 1};
    ASSERT_TRUE(pump_until(fx.reactor, piper_streams_are, &pw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    for (int i = 0; i < 200; i++) {
        cloak_reactor_run_once(fx.reactor, 1);
    }

    /* THE ASSERTION THE CLAMP IS ABOUT: exactly one frame was handed to
     * the pool, so the session is still alive. An unclamped first write
     * appends a second frame the queue cannot take, which
     * cloak_conn_send answers by breaking the connection -- and with one
     * connection that is the session, every stream on it, and every local
     * connection. */
    ASSERT_EQ_INT(0, cl.broken_calls);
    ASSERT_EQ_INT(0, (int)cloak_session_is_closed(&cl.sesh));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_conn_count(&cl.piper));
    ASSERT_EQ_INT(1, (int)cloak_client_piper_stream_count(&cl.piper));
    /* And it really did write: one frame's worth is sitting in the queue
     * the kernel will not take, which is what "exactly one" means here. */
    ASSERT_TRUE(cloak_session_send_queued(&cl.sesh) > 0);
    ASSERT_TRUE(cloak_session_send_queued(&cl.sesh) <= CLAMP_QUEUE);

    free(src);
    lp_destroy(&lp);
    client_down(&cl);
    mb_close(&mb);
    fixture_destroy(&fx);
}

/* ---- case 12: the retry ladder RECOVERS -------------------------------- */

#define SID_RECOVER ((uint32_t)6113)
/* One worst-case frame's on-wire cost at the default wire size:
 * CLOAK_CONN_RECORD_HEADER_LEN(5) + payload(16401-14-255) +
 * CLOAK_FRAME_HEADER_LEN(14) + CLOAK_FRAME_MAX_EXTRA_LEN(255). */
#define RECOVER_FRAME_COST ((size_t)16406)
/* Two worst-case frames. Small deliberately: the threshold the -2 check
 * uses is "one whole frame free", so a two-frame pool crosses it as soon
 * as ONE frame is stuck, which is what a paused middlebox produces in a
 * few kilobytes instead of a few hundred. */
#define RECOVER_QUEUE ((size_t)(2u * 16406u))
#define RECOVER_BULK ((size_t)(2u * 1024u * 1024u))

struct congested_wait {
    cloak_session_t *sesh;
};

static int session_is_congested(void *ctx) {
    struct congested_wait *w = ctx;
    return cloak_session_send_min_conn_free(w->sesh) < RECOVER_FRAME_COST;
}

/* Case 9 proves the ladder GIVES UP on a condition that can never clear.
 * This proves the other half -- that a start rejected while the pool is
 * merely busy is waited out and then succeeds -- which is the case the
 * ladder actually exists for, and the one a user hits whenever a tab is
 * opened during an upload. Without it, "treat -2 as permanent" is a
 * mutation case 9 still passes on its end state.
 *
 * The congestion is produced by a middlebox that stops reading from the
 * client (see midbox_t for why nothing cheaper works), so both halves of
 * the sequence are deterministic: congested when the second connection
 * arrives, drained afterwards. */
static void test_the_retry_ladder_recovers(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    midbox_t mb;
    ASSERT_EQ_INT(0, mb_open(&mb, fx.reactor, front_port(&fx)));
    /* Set on the LISTENING socket so it is inherited by the accepted one
     * and is in force from the first SYN: a receive window this small
     * from the outset keeps the client's own send buffer from
     * auto-tuning into the megabytes, which is what makes the stall
     * arrive in tens of kilobytes rather than never. */
    {
        int rcv = MB_RCVBUF;
        ASSERT_EQ_INT(0, setsockopt(mb.l.fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv)));
    }
    fx.client_port = cloak_listener_port(&mb.l);
    ASSERT_TRUE(fx.client_port > 0);

    client_t cl;
    cloak_client_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.retry_delay_ms = 5;
    ASSERT_EQ_INT(0, client_up(&cl, &fx, SID_RECOVER, &pcfg, RECOVER_QUEUE));

    uint8_t *src = malloc(RECOVER_BULK);
    ASSERT_TRUE(src != NULL);
    if (src == NULL) {
        client_down(&cl);
        mb_close(&mb);
        fixture_destroy(&fx);
        return;
    }
    for (size_t i = 0; i < RECOVER_BULK; i++) {
        src[i] = (uint8_t)(i * 29u);
    }

    /* The bulk connection is established FIRST, so its stream exists and
     * its upstream has been dialed before anything is held up -- which is
     * what lets the assertion below ("still exactly one upstream") mean
     * "the second stream never got spliced" rather than "nothing has
     * happened yet". */
    local_peer_t bulk;
    ASSERT_EQ_INT(0, lp_open(&bulk, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &bulk, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t go[] = "go";
    lp_send(&bulk, go, sizeof(go) - 1);
    struct up_wait uw = {&fx.up, 0, sizeof(go) - 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT(1, fx.up.accept_count);

    /* Now stop the middlebox forwarding what the client sends. The
     * client's own relay keeps its writes inside the pool's budget, so
     * the queue asymptotes just below conn_send_queue_cap rather than
     * overrunning it. */
    mb_set_paused(&mb, 1);
    lp_send(&bulk, src, RECOVER_BULK);

    /* Waited for and asserted rather than assumed: the pool really cannot
     * hold one frame at the moment the second connection arrives, which is
     * what makes the -2 it is about to receive the ORDINARY congested one
     * rather than a misconfiguration. */
    struct congested_wait cw = {&cl.sesh};
    ASSERT_TRUE(pump_until(fx.reactor, session_is_congested, &cw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_TRUE(cloak_session_send_min_conn_free(&cl.sesh) < RECOVER_FRAME_COST);

    local_peer_t late;
    ASSERT_EQ_INT(0, lp_open(&late, fx.reactor, cl.local_port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &late, PIPER_MAX_TURNS, PIPER_TURN_MS));
    static const uint8_t ask[] = "opened during the upload";
    const size_t ask_len = sizeof(ask) - 1;
    lp_send(&late, ask, ask_len);

    /* Its stream exists and its start has been REJECTED and parked -- the
     * state the ladder is for, observed BEFORE the congestion is lifted so
     * that "it retried" cannot be confused with "it never needed to". The
     * upstream count is the far end's own confirmation that nothing was
     * spliced for it: the first bytes are written only after a successful
     * start, so the server has not even learned the stream exists. */
    struct piper_wait pw = {&cl.piper, 2};
    ASSERT_TRUE(pump_until(fx.reactor, piper_streams_are, &pw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_TRUE(cloak_client_piper_retried_starts(&cl.piper) >= 1);
    ASSERT_EQ_INT(1, fx.up.accept_count);

    /* Lift the congestion; the parked start must now succeed. */
    mb_set_paused(&mb, 0);

    struct lp_wait lw = {&late, ask_len};
    ASSERT_TRUE(pump_until(fx.reactor, lp_has_len, &lw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    uint8_t want[sizeof(ask)];
    xor_fill(want, ask, ask_len);
    ASSERT_EQ_INT((int)ask_len, (int)late.in_len);
    ASSERT_MEM_EQ(late.in, want, ask_len);

    /* The bulk transfer it was competing with is intact, and the session
     * never broke. */
    uw.want = (sizeof(go) - 1) + RECOVER_BULK;
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, PIPER_MAX_TURNS, PIPER_TURN_MS));
    ASSERT_EQ_INT((int)((sizeof(go) - 1) + RECOVER_BULK), (int)fx.up.conns[0].in_len);
    ASSERT_MEM_EQ(fx.up.conns[0].in + sizeof(go) - 1, src, RECOVER_BULK);
    ASSERT_EQ_INT(2, fx.up.accept_count);
    ASSERT_EQ_INT(0, cl.broken_calls);

    free(src);
    lp_destroy(&bulk);
    lp_destroy(&late);
    client_down(&cl);
    mb_close(&mb);
    fixture_destroy(&fx);
}

/* ---- case 10: the constructors' own contracts --------------------------- */

static void test_init_and_destroy_contracts(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    /* Safe on a zeroed struct, and idempotent. */
    cloak_client_piper_t zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    cloak_client_piper_destroy(&zeroed);
    cloak_client_piper_destroy(&zeroed);
    cloak_client_piper_destroy(NULL);

    cloak_client_piper_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cloak_client_piper_t pp;
    /* A rejected init still leaves pp safe to destroy -- the ordering five
     * earlier constructors on this project got backwards. */
    ASSERT_EQ_INT(-1, cloak_client_piper_init(&pp, &cfg));
    cloak_client_piper_destroy(&pp);
    ASSERT_EQ_INT(-1, cloak_client_piper_init(&pp, NULL));
    cloak_client_piper_destroy(&pp);
    ASSERT_EQ_INT(-1, cloak_client_piper_init(NULL, &cfg));

    cfg.reactor = r;
    ASSERT_EQ_INT(0, cloak_client_piper_init(&pp, &cfg));
    /* The defaults really are the documented ones. */
    ASSERT_EQ_INT((int)CLOAK_CLIENT_PIPER_DEFAULT_RELAY_BUF_CAP, (int)pp.cfg.relay_buf_cap);
    ASSERT_TRUE(pp.cfg.first_byte_timeout_ms == CLOAK_CLIENT_PIPER_DEFAULT_FIRST_BYTE_TIMEOUT_MS);
    ASSERT_TRUE(pp.cfg.retry_delay_ms == CLOAK_CLIENT_PIPER_DEFAULT_RETRY_DELAY_MS);
    ASSERT_EQ_INT((int)CLOAK_CLIENT_PIPER_DEFAULT_MAX_RETRIES, (int)pp.cfg.max_retries);
    ASSERT_EQ_INT((int)CLOAK_CLIENT_PIPER_DEFAULT_MAX_LOCAL_CONNS, (int)pp.cfg.max_local_conns);
    ASSERT_EQ_INT(0, (int)cloak_client_piper_conn_count(&pp));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_stream_count(&pp));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_rejected_streams(&pp));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_refused_conns(&pp));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_retried_starts(&pp));

    /* install fills all four callbacks with the piper as userdata; an
     * owner that only wired three has a use-after-free, so this is worth
     * pinning rather than trusting. */
    cloak_session_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    cloak_client_piper_install(&pp, &scfg);
    ASSERT_TRUE(scfg.on_new_stream != NULL && scfg.on_new_stream_userdata == &pp);
    ASSERT_TRUE(scfg.on_stream_data != NULL && scfg.on_stream_data_userdata == &pp);
    ASSERT_TRUE(scfg.on_writable != NULL && scfg.on_writable_userdata == &pp);
    ASSERT_TRUE(scfg.on_broken != NULL && scfg.on_broken_userdata == &pp);
    cloak_client_piper_install(NULL, &scfg);
    cloak_client_piper_install(&pp, NULL);

    ASSERT_EQ_INT(0, (int)cloak_client_piper_conn_count(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_stream_count(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_rejected_streams(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_refused_conns(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_piper_retried_starts(NULL));

    cloak_client_piper_destroy(&pp);
    cloak_client_piper_destroy(&pp);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
test_one_connection_round_trip();
test_two_connections_do_not_cross();
test_a_silent_connection_costs_no_stream();
test_large_transfer_and_the_session_survives();
test_local_close_closes_the_stream();
test_stream_end_closes_the_local_socket();
test_a_broken_session_stops_every_relay();
test_server_opened_streams_are_refused();
test_refusals_are_bounded();
test_the_refusal_ceiling_is_per_session();
test_the_local_connection_cap();
test_a_start_that_can_never_succeed_is_given_up_on();
test_the_first_read_is_clamped_to_one_frame();
test_the_retry_ladder_recovers();
test_init_and_destroy_contracts();
TEST_MAIN_END()
