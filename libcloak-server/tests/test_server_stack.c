#define _POSIX_C_SOURCE 200809L
#include "cloak/server_stack.h"

#include "cloak/base64.h"
#include "cloak/clienthello.h"
#include "cloak/crypto.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
#include "test_framework.h"
#include "client_harness.h"

#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* THE WHOLE SERVER THROUGH cloak_server_stack_t, which is the object a
 * binary uses instead of the 129 lines of wiring test_server_e2e.c and
 * test_admin_e2e.c spell out by hand. Those two files remain the
 * hand-wired prototype and are deliberately unchanged: what is new here
 * is that the wiring itself is under test rather than merely duplicated.
 *
 * NOTHING HERE TOUCHES A MEMBER OF THE STACK, because there are none to
 * touch: the handle is opaque and every assertion below goes through a
 * counter accessor or an opaque sub-object. That is the module's main
 * enforcement and this file is written to be evidence that a binary can
 * do its job without the struct.
 *
 * WHAT EACH CASE IS FOR:
 *
 *   1. A stack built from a parsed config serves a real handshake and
 *      moves bytes both ways.
 *   2. THE FOUR-LINK CHAIN, pinned link by link, over three breaks.
 *   3. A TERMINATION stops BOTH modules -- the on_session_closing
 *      trampoline, both halves, reached twice: once through a real
 *      credit exhaustion and once through a user holding an admin
 *      session and a proxy session at the same time.
 *   4. AN ABANDONED HANDSHAKE reclaims BOTH modules -- the dispatcher's
 *      session_aborted trampoline, both halves, through a forced
 *      reply-write failure.
 *   5. Teardown in the stack's own order with traffic outstanding.
 *   6. Ten enforced edges, one case each, asserting the typed code, the
 *      code's exact name, and that the message names the edge.
 *   7. Every configured BindAddr accepts.
 *   8. Built and destroyed twice, descriptors counted via /proc/self/fd.
 *   9. The caller's cloak_server_config_t may die the moment open
 *      returns.
 *  10. cloak_server_stack_strerror, compared exactly.
 *  11. The replay cache the stack actually allocated.
 *
 * EVERY WAIT IS A BOUNDED pump_until (client_harness.h), which is a real
 * time bound. */

/* ------------------------------------------------------------------ */
/* Descriptor accounting                                                */
/* ------------------------------------------------------------------ */

/* LeakSanitizer tracks allocations, not descriptors, so a stack that
 * leaked a listener or a SQLite handle would pass a clean ASan run and
 * exhaust a long-running server's descriptor budget instead. This is the
 * only detector for that, and it is exact rather than approximate: the
 * count includes opendir's own descriptor in every sample, so successive
 * samples are directly comparable.
 *
 * Returns -1 if /proc/self/fd is unavailable, which the callers treat as
 * a FAILURE rather than as a skip -- a detector that silently stops
 * detecting is the defect this project has paid for most often. */
static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) {
        return -1;
    }
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') {
            continue;
        }
        n++;
    }
    closedir(d);
    return n;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* A FIXED CLOCK for the user manager and the panel, so credit and expiry
 * behave the same in every run. It does not affect the handshake's own
 * timestamp check, which reads the wall clock inside server_auth. */
#define T_NOW    ((int64_t)1600000000)
#define T_EXPIRY (T_NOW + 100000)

static int64_t fixed_now(void *userdata) {
    (void)userdata;
    return T_NOW;
}

/* ------------------------------------------------------------------ */
/* The fake upstream                                                    */
/* ------------------------------------------------------------------ */

#define UP_MAX  8
#define UP_CAP  ((size_t)(512u * 1024u))

typedef struct {
    int fd;
    uint8_t *in;
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
    /* While set this upstream reads nothing at all, so everything the
     * client keeps writing accumulates INSIDE the server. The reactor is
     * edge-triggered, so simply not reading stops the wakeups, which is
     * exactly the stall being modelled (test_server_e2e.c's own upstream
     * does this for the same reason). */
    int stall;
    up_conn_t conns[UP_MAX];
    up_slot_t slots[UP_MAX];
} upstream_t;

static void up_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    (void)events;
    up_slot_t *slot = userdata;
    up_conn_t *c = &slot->up->conns[slot->idx];
    if (slot->up->stall) {
        return;
    }
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
    up_conn_t *c = &up->conns[idx];
    c->in = malloc(UP_CAP);
    if (c->in == NULL) {
        close(fd);
        up->accept_count--;
        return;
    }
    c->fd = fd;
    up->slots[idx].up = up;
    up->slots[idx].idx = idx;
    (void)cloak_reactor_add_fd(up->reactor, fd, CLOAK_REACTOR_READABLE, up_on_readable,
                               &up->slots[idx]);
}

/* Callers that push at an upstream whose relay is already gone EXPECT
 * this to fail, so the result is deliberately not asserted there. */
static ssize_t up_send(upstream_t *up, int idx, const void *data, size_t len) {
    return send(up->conns[idx].fd, data, len, MSG_NOSIGNAL);
}

/* One accepted upstream connection, released. Case 8 needs this: each
 * cycle's relay leaves an accepted socket behind that belongs to the
 * TEST, not to the stack, so without closing it the descriptor count
 * grows by one per cycle for a reason that has nothing to do with the
 * stack -- which is exactly the kind of drift that makes a count
 * assertion meaningless. */
static void up_close_conn(upstream_t *up, int idx) {
    if (idx < 0 || idx >= UP_MAX || up->conns[idx].fd < 0) {
        return;
    }
    cloak_reactor_remove_fd(up->reactor, up->conns[idx].fd);
    close(up->conns[idx].fd);
    up->conns[idx].fd = -1;
}

static void up_destroy(upstream_t *up) {
    for (int i = 0; i < UP_MAX; i++) {
        if (up->conns[i].fd >= 0) {
            cloak_reactor_remove_fd(up->reactor, up->conns[i].fd);
            close(up->conns[i].fd);
            up->conns[i].fd = -1;
        }
        free(up->conns[i].in);
        up->conns[i].in = NULL;
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

/* in is NULL until that connection has been accepted, so a byte-for-byte
 * assertion against an upstream that was never reached would segfault
 * inside memcmp instead of reporting a failure. test_server_e2e.c states
 * the same reasoning; the NULL case is a failure, not a skip. */
#define ASSERT_UP_BYTES(up, idx, expect, len) \
    do { \
        if ((up).conns[idx].in != NULL) { \
            ASSERT_MEM_EQ((up).conns[idx].in, (expect), (len)); \
        } else { \
            ASSERT_TRUE((up).conns[idx].in != NULL); \
        } \
    } while (0)

/* ------------------------------------------------------------------ */
/* The environment the stack is built INTO                              */
/* ------------------------------------------------------------------ */

/* Everything genuinely outside the server process: the reactor, the cover
 * site a redirect goes to, the upstream a relay is spliced with, and the
 * parsed config. The stack is deliberately NOT part of this struct --
 * every case opens its own handle, which is what makes case 8's "twice in
 * one process" a plain loop. */
struct env {
    cloak_reactor_t *reactor;

    cover_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;

    upstream_t up;
    cloak_listener_t up_listener;
    int have_up_listener;
    int up_port;

    char db_path[512];

    cloak_server_config_t cfg;
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_user[CLOAK_UID_LEN];  /* BypassUID */
    uint8_t uid_admin[CLOAK_UID_LEN]; /* AdminUID (always bypass too) */
    uint8_t uid_db[CLOAK_UID_LEN];    /* neither: a metered database user */
};

static void env_tmp_path(char *buf, size_t cap, const char *tag) {
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(buf, cap, "%s/cloak_stack_%ld_%s.db", dir, (long)getpid(), tag);
}

/* WAL leaves sidecars; a survivor would carry a previous run's rows into
 * this one and make a credit assertion pass or fail for reasons unrelated
 * to the code under test. */
static void env_unlink(const char *path) {
    char aux[600];
    unlink(path);
    snprintf(aux, sizeof(aux), "%s-wal", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-shm", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-journal", path);
    unlink(aux);
}

static void mk_uid(uint8_t *uid, uint8_t seed) {
    memset(uid, 0xC0, CLOAK_UID_LEN);
    uid[0] = seed;
}

static int env_init(struct env *e, const char *tag, size_t num_bind) {
    memset(e, 0, sizeof(*e));
    char err[256] = {0};

    for (int i = 0; i < UP_MAX; i++) {
        e->up.conns[i].fd = -1;
    }
    e->cover.fd = -1;

    e->reactor = cloak_reactor_create();
    ASSERT_TRUE(e->reactor != NULL);
    if (e->reactor == NULL) {
        return -1;
    }

    e->cover.reactor = e->reactor;
    ASSERT_EQ_INT(0, cloak_listener_open(&e->cover_listener, e->reactor, "127.0.0.1:0",
                                         cover_on_accept, &e->cover, err, sizeof(err)));
    e->have_cover_listener = 1;
    int cover_port = cloak_listener_port(&e->cover_listener);
    ASSERT_TRUE(cover_port > 0);

    e->up.reactor = e->reactor;
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&e->up_listener, e->reactor, "127.0.0.1:0", up_on_accept,
                                         &e->up, err, sizeof(err)));
    e->have_up_listener = 1;
    e->up_port = cloak_listener_port(&e->up_listener);
    ASSERT_TRUE(e->up_port > 0);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, e->server_pub));
    mk_uid(e->uid_user, 0x11);
    mk_uid(e->uid_admin, 0x22);
    mk_uid(e->uid_db, 0x33);

    char priv_b64[64];
    char user_b64[32];
    char admin_b64[32];
    ASSERT_EQ_INT(
        0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64, sizeof(priv_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(e->uid_user, CLOAK_UID_LEN, user_b64, sizeof(user_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(e->uid_admin, CLOAK_UID_LEN, admin_b64, sizeof(admin_b64)));

    env_tmp_path(e->db_path, sizeof(e->db_path), tag);
    env_unlink(e->db_path);

    char bind_list[256];
    size_t off = 0;
    ASSERT_TRUE(num_bind >= 1 && num_bind <= 4);
    for (size_t i = 0; i < num_bind; i++) {
        off += (size_t)snprintf(bind_list + off, sizeof(bind_list) - off, "%s\"127.0.0.1:0\"",
                                i == 0 ? "" : ",");
    }

    /* The config a real deployment writes, parsed from JSON exactly as a
     * binary parses its config file. Three UIDs with three different
     * standings: a BypassUID, the AdminUID (which cloak_server_t always
     * folds into the bypass set), and a UID that is in neither and is
     * therefore a metered database user. */
    char json[2048];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[%s],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"AdminUID\":\"%s\",\"BypassUID\":[\"%s\"],"
             "\"DatabasePath\":\"%s\"}",
             e->up_port, bind_list, cover_port, priv_b64, admin_b64, user_b64, e->db_path);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &e->cfg, err, sizeof(err)));
    ASSERT_EQ_INT((int)num_bind, (int)e->cfg.num_bind_addr);
    return 0;
}

static void env_destroy(struct env *e) {
    if (e->have_up_listener) {
        cloak_listener_close(&e->up_listener);
        e->have_up_listener = 0;
    }
    up_destroy(&e->up);
    if (e->have_cover_listener) {
        cloak_listener_close(&e->cover_listener);
        e->have_cover_listener = 0;
    }
    if (e->cover.fd >= 0) {
        cloak_reactor_remove_fd(e->reactor, e->cover.fd);
        close(e->cover.fd);
        e->cover.fd = -1;
    }
    if (e->reactor != NULL) {
        cloak_reactor_destroy(e->reactor);
        e->reactor = NULL;
    }
    if (e->db_path[0] != '\0') {
        env_unlink(e->db_path);
    }
}

/* Writes one user row through a manager of its OWN, opened and closed
 * BEFORE the stack exists. Deliberately not through the stack's manager:
 * a second live writer on a WAL database is how test_admin_e2e.c
 * provokes SQLITE_BUSY on purpose, and that is not what this file is
 * about. */
static void seed_user(const char *db_path, const uint8_t uid[CLOAK_UID_LEN], int32_t sessions_cap,
                      int64_t up_credit, int64_t down_credit) {
    cloak_usermanager_t *m = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, db_path, fixed_now, NULL, err, sizeof(err)));
    ASSERT_TRUE(m != NULL);
    if (m == NULL) {
        return;
    }
    cloak_user_info_t row;
    memset(&row, 0, sizeof(row));
    memcpy(row.uid, uid, CLOAK_UID_LEN);
    row.sessions_cap = sessions_cap;
    row.up_rate = 0;
    row.down_rate = 0;
    row.up_credit = up_credit;
    row.down_credit = down_credit;
    row.expiry_time = T_EXPIRY;
    ASSERT_EQ_INT(0, cloak_usermanager_write(m, &row, CLOAK_USER_FIELD_ALL));
    cloak_usermanager_close(m);
}

/* ------------------------------------------------------------------ */
/* The owner's link of the chain -- the probe                           */
/* ------------------------------------------------------------------ */

/* THE ORDER ASSERTION LIVES HERE. This is link 4, the last one, so
 * everything it can see has already happened. Recording the other three
 * modules' state AT THIS INSTANT is therefore a statement about ORDER,
 * not merely about outcome -- an outcome recorded after the pump would be
 * equally green whichever order the links ran in. */
struct chain_probe {
    cloak_server_stack_t *st;
    int calls;
    uint8_t last_uid[CLOAK_UID_LEN];
    uint32_t last_session_id;
    int last_sesh_null;

    size_t proxy_sessions;
    size_t proxy_streams;
    size_t api_sessions;
    size_t api_streams;
    int panel_still_has_uid;
};

static void probe_chain(cloak_server_registry_t *reg, cloak_session_t *sesh,
                        const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id, void *userdata) {
    (void)reg;
    struct chain_probe *p = userdata;
    p->calls++;
    p->last_session_id = session_id;
    p->last_sesh_null = (sesh == NULL);
    memset(p->last_uid, 0, sizeof(p->last_uid));
    if (uid != NULL) {
        memcpy(p->last_uid, uid, CLOAK_UID_LEN);
    }
    p->proxy_sessions = cloak_server_stack_proxy_session_count(p->st);
    p->proxy_streams = cloak_server_stack_proxy_stream_count(p->st);
    p->api_sessions = cloak_server_stack_admin_session_count(p->st);
    p->api_streams = cloak_server_stack_admin_stream_count(p->st);
    p->panel_still_has_uid =
        (uid != NULL && cloak_userpanel_find(cloak_server_stack_panel(p->st), uid) != NULL) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Building a stack out of an env                                       */
/* ------------------------------------------------------------------ */

static void stack_config(struct env *e, cloak_server_stack_config_t *sc) {
    memset(sc, 0, sizeof(*sc));
    sc->reactor = e->reactor;
    sc->config = &e->cfg;
    sc->now_fn = fixed_now;
    /* Long enough that no periodic tick lands inside a case: every cycle
     * in this file is driven by an explicit cloak_server_stack_upload_now,
     * which runs the identical panel cycle the tick runs. */
    sc->upload_interval_ms = 3600000;
    /* Everything else left at 0, which is what a binary with no operator
     * overrides passes. */
}

static int front_port(const cloak_server_stack_t *st) {
    return cloak_server_stack_listener_port(st, 0);
}

static void client_config(cloak_session_config_t *ccfg) {
    memset(ccfg, 0, sizeof(*ccfg));
    ccfg->ordering = CLOAK_SESSION_ORDERING_ORDERED;
    ccfg->max_on_wire_size = CLOAK_SERVER_STACK_DEFAULT_MAX_ON_WIRE_SIZE;
    ccfg->stream_recv_capacity = CLOAK_SERVER_STACK_DEFAULT_STREAM_RECV_CAPACITY;
    ccfg->stream_max_pending_frames = CLOAK_SERVER_STACK_DEFAULT_STREAM_MAX_PENDING;
    ccfg->conn_send_queue_cap = CLOAK_SERVER_STACK_DEFAULT_CONN_SEND_QUEUE_CAP;
    ccfg->inactivity_timeout_ms = CLOAK_SERVER_STACK_DEFAULT_INACTIVITY_TIMEOUT_MS;
}

static int open_client_at(struct env *e, client_session_t *cs, const uint8_t *uid,
                          const char *proxy_method, uint32_t session_id, int port) {
    cloak_session_config_t ccfg;
    client_config(&ccfg);
    return client_session_open(cs, e->reactor, port, e->server_pub, uid, proxy_method, session_id,
                               0, &ccfg);
}

static int open_proxy_client(struct env *e, const cloak_server_stack_t *st, client_session_t *cs,
                             uint32_t session_id) {
    return open_client_at(e, cs, e->uid_user, "ss", session_id, front_port(st));
}

/* The ADMIN client: the admin UID, session id 0 (both halves are what
 * makes the dispatcher call it admin), and a proxy method this server
 * does not offer -- which is what a real `ck-client -a` sends. */
static int open_admin_client(struct env *e, const cloak_server_stack_t *st, client_session_t *cs) {
    return open_client_at(e, cs, e->uid_admin, "nosuch", 0, front_port(st));
}

/* ---- reading downstream bytes off a stream ---- */

typedef struct {
    cloak_stream_t *stream;
    uint8_t *buf;
    size_t cap;
    size_t len;
} reader_t;

static int reader_has(void *ctx) {
    reader_t *rd = ctx;
    for (;;) {
        if (rd->len >= rd->cap) {
            return 1;
        }
        long n = cloak_stream_read(rd->stream, rd->buf + rd->len, rd->cap - rd->len);
        if (n > 0) {
            rd->len += (size_t)n;
            continue;
        }
        return rd->len >= rd->cap;
    }
}

struct count_wait {
    cloak_server_stack_t *st;
    const uint8_t *uid;
    size_t want;
};

static int registry_uid_count_is(void *ctx) {
    struct count_wait *w = ctx;
    return cloak_server_stack_session_count_for_uid(w->st, w->uid) == w->want;
}

struct api_wait {
    cloak_server_stack_t *st;
    size_t want;
};

static int api_stream_count_is(void *ctx) {
    struct api_wait *w = ctx;
    return cloak_server_stack_admin_stream_count(w->st) >= w->want;
}

/* An admin request that STOPS MID-HEADERS: parser, stream context and
 * deadline all stay live for as long as the session does. */
static const char ADMIN_PARTIAL[] = "GET /admin/users HTTP/1.1\r\nHost: admin\r\n";

/* ------------------------------------------------------------------ */
/* 1. A stack from a parsed config carries traffic                      */
/* ------------------------------------------------------------------ */

/* THE PROPERTY test_server_e2e.c ASSERTS, NOW THROUGH THE HELPER. Nothing
 * here knows the names of the nine objects: a config, a reactor, one
 * cloak_server_stack_open, and the server works. Both directions are
 * asserted, because a relay spliced one way only is a thing this project
 * has shipped. */
static void test_stack_carries_traffic_end_to_end(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "e2e", 1));

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    cloak_server_stack_t *st = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        env_destroy(&e);
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_server_stack_listener_count(st));
    ASSERT_TRUE(front_port(st) > 0);

    client_session_t cs;
    ASSERT_EQ_INT(0, open_proxy_client(&e, st, &cs, 101));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_session_count(st));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_proxy_session_count(st));
    /* The panel really is wired into the dispatcher (E8): an authorised
     * session made this UID active. */
    ASSERT_TRUE(cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_user) != NULL);

    cloak_stream_t *sstream = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(sstream != NULL);
    if (sstream == NULL) {
        client_session_close(&cs);
        cloak_server_stack_close(st);
        env_destroy(&e);
        return;
    }

    ASSERT_EQ_INT(8, (int)cloak_stream_write(sstream, (const uint8_t *)"upstream", 8));
    struct up_wait uw = {&e.up, 0, 8};
    ASSERT_TRUE(pump_until(e.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(1, e.up.accept_count);
    ASSERT_EQ_INT(8, (int)e.up.conns[0].in_len);
    ASSERT_UP_BYTES(e.up, 0, "upstream", 8);
    ASSERT_EQ_INT(1, (int)cloak_server_stack_proxy_stream_count(st));

    uint8_t back[10];
    reader_t rd = {sstream, back, 10, 0};
    ASSERT_EQ_INT(10, (int)up_send(&e.up, 0, "downstream", 10));
    ASSERT_TRUE(pump_until(e.reactor, reader_has, &rd, 400, 5));
    ASSERT_EQ_INT(10, (int)rd.len);
    ASSERT_MEM_EQ(rd.buf, "downstream", 10);
    ASSERT_EQ_INT(0, cs.broken);

    cloak_session_release_stream(&cs.sesh, sstream);
    client_session_close(&cs);
    cloak_server_stack_close(st);
    env_destroy(&e);
}

/* ------------------------------------------------------------------ */
/* 2. The four-link chain, link by link                                 */
/* ------------------------------------------------------------------ */

/* THE CHAIN IS THE REASON THIS MODULE EXISTS, and the previous module
 * established that the only way it gets pinned is by mutating each link
 * individually -- a test that merely observes "the chain ran" is worth
 * very little, because three of the four links are silent for any given
 * session.
 *
 * THE SHAPE. THREE sessions are live at once: TWO proxy sessions for the
 * SAME user, each with a running relay, and an ADMIN session with a
 * half-sent request. Each is then broken with the others still live, and
 * each break is checked against the link that has visible work for it:
 *
 *   L1 proxy    -- pinned by BREAK A, which breaks ONE OF TWO sessions
 *                  the same proxy user holds. That detail is the whole
 *                  case and was found by mutation, not by reading: when
 *                  the broken session is the user's LAST one, the panel
 *                  terminates that user, and termination runs
 *                  close_all_for_uid whose on_closing hook ALSO calls
 *                  cloak_proxy_session_aborted -- so the proxy's context
 *                  is reclaimed on that path even with link 1 wired to
 *                  the wrong module. Measured: with the head pointed at
 *                  the admin API instead of the proxy, a last-session
 *                  break left every assertion green. With a second
 *                  session still open there is no termination and link 1
 *                  is the only thing that can reclaim anything.
 *   L2 adminapi -- pinned by BREAK C (the admin session), for the mirror
 *                  reason: the proxy holds no context for it.
 *   L3 panel    -- pinned by BREAK B, the proxy user's LAST session,
 *                  where notify_session_closed deactivates that user.
 *                  cloak/userpanel.h calls this "the one call that is
 *                  easy to forget and impossible to notice".
 *   L4 owner    -- its own call count, and the snapshots above.
 *
 * WHAT THIS DOES NOT ASSERT, stated rather than implied: the relative
 * order of L1 and L2 is NOT load-bearing -- verified by mutation, since
 * neither module reads the other's contexts and the session is live
 * through both. What is load-bearing, and is asserted, is that the
 * panel's link runs after both and the owner's runs last of all. */
static void test_broken_session_runs_the_whole_chain(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "chain", 1));

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    struct chain_probe probe;
    memset(&probe, 0, sizeof(probe));
    sc.on_session_broken = probe_chain;
    sc.on_session_broken_userdata = &probe;
    /* Far beyond this case's runtime: an expiring request deadline would
     * tear the admin stream context down for a reason that has nothing to
     * do with the chain, and the L2 assertion would then be green
     * whatever link 2 did. */
    sc.adminapi_request_timeout_ms = 600000;

    cloak_server_stack_t *st = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        env_destroy(&e);
        return;
    }
    probe.st = st;

    /* ---- TWO live proxy relays, on TWO sessions of the SAME user ----
     * One at a time up to its own upstream connection, so the (session ->
     * upstream connection) mapping is deterministic rather than lucky. */
    client_session_t user_a;
    client_session_t user_b;
    ASSERT_EQ_INT(0, open_proxy_client(&e, st, &user_a, 201));
    cloak_stream_t *psa = cloak_session_open_stream(&user_a.sesh, NULL);
    ASSERT_TRUE(psa != NULL);
    if (psa == NULL) {
        client_session_close(&user_a);
        cloak_server_stack_close(st);
        env_destroy(&e);
        return;
    }
    ASSERT_EQ_INT(6, (int)cloak_stream_write(psa, (const uint8_t *)"relayA", 6));
    struct up_wait uwa = {&e.up, 0, 6};
    ASSERT_TRUE(pump_until(e.reactor, up_has_len, &uwa, 400, 5));

    ASSERT_EQ_INT(0, open_proxy_client(&e, st, &user_b, 202));
    cloak_stream_t *psb = cloak_session_open_stream(&user_b.sesh, NULL);
    ASSERT_TRUE(psb != NULL);
    if (psb == NULL) {
        client_session_close(&user_b);
        client_session_close(&user_a);
        cloak_server_stack_close(st);
        env_destroy(&e);
        return;
    }
    ASSERT_EQ_INT(6, (int)cloak_stream_write(psb, (const uint8_t *)"relayB", 6));
    struct up_wait uwb = {&e.up, 1, 6};
    ASSERT_TRUE(pump_until(e.reactor, up_has_len, &uwb, 400, 5));

    ASSERT_EQ_INT(2, e.up.accept_count);
    ASSERT_EQ_INT(2, (int)cloak_server_stack_proxy_session_count(st));
    ASSERT_EQ_INT(2, (int)cloak_server_stack_proxy_stream_count(st));
    ASSERT_EQ_INT(2, (int)cloak_server_stack_session_count_for_uid(st, e.uid_user));

    /* ---- a live admin stream, stopped mid-headers ---- */
    client_session_t admin;
    ASSERT_EQ_INT(0, open_admin_client(&e, st, &admin));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_admin_session_count(st));
    cloak_stream_t *ast = cloak_session_open_stream(&admin.sesh, NULL);
    ASSERT_TRUE(ast != NULL);
    if (ast == NULL) {
        client_session_close(&admin);
        client_session_close(&user_b);
        client_session_close(&user_a);
        cloak_server_stack_close(st);
        env_destroy(&e);
        return;
    }
    ASSERT_EQ_INT((int)(sizeof(ADMIN_PARTIAL) - 1),
                  (int)cloak_stream_write(ast, (const uint8_t *)ADMIN_PARTIAL,
                                          sizeof(ADMIN_PARTIAL) - 1));
    struct api_wait aw = {st, 1};
    ASSERT_TRUE(pump_until(e.reactor, api_stream_count_is, &aw, 400, 5));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_admin_stream_count(st));

    ASSERT_TRUE(cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_user) != NULL);
    ASSERT_TRUE(cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_admin) != NULL);
    ASSERT_EQ_INT(0, probe.calls);

    /* ========== BREAK A: one of the proxy user's TWO sessions ==========
     * The client's session is destroyed WITHOUT releasing its stream
     * first, deliberately: cloak_session_destroy reclaims active streams
     * without sending anything (cloak/session.h), so the server sees a
     * plain EOF with the relay still running. Releasing first would end
     * the relay before the session broke and L1 would have nothing left
     * to do.
     *
     * THE USER KEEPS A SECOND SESSION, so the panel does NOT terminate it
     * -- which means its on_session_closing hook, the other thing in this
     * stack that calls cloak_proxy_session_aborted, never runs. Link 1 is
     * therefore the only thing that can have reclaimed the proxy's
     * context for session 201. */
    client_session_close(&user_a);
    struct count_wait cw_a = {st, e.uid_user, 1};
    ASSERT_TRUE(pump_until(e.reactor, registry_uid_count_is, &cw_a, 600, 5));

    ASSERT_EQ_INT(1, probe.calls);                              /* L4 ran */
    ASSERT_EQ_INT(201, (int)probe.last_session_id);
    ASSERT_MEM_EQ(probe.last_uid, e.uid_user, CLOAK_UID_LEN);
    ASSERT_EQ_INT(1, (int)probe.proxy_sessions);                /* L1 ran, for 201 only */
    ASSERT_EQ_INT(1, (int)probe.proxy_streams);
    ASSERT_EQ_INT(1, probe.panel_still_has_uid);                /* 202 keeps it active */
    ASSERT_EQ_INT(1, (int)probe.api_sessions);                  /* untouched */
    ASSERT_EQ_INT(1, (int)probe.api_streams);

    ASSERT_EQ_INT(1, (int)cloak_server_stack_proxy_session_count(st));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_proxy_stream_count(st));
    ASSERT_TRUE(cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_user) != NULL);
    ASSERT_EQ_INT(0, user_b.broken);

    /* ========== BREAK B: the proxy user's LAST session ========== */
    client_session_close(&user_b);
    struct count_wait cw_b = {st, e.uid_user, 0};
    ASSERT_TRUE(pump_until(e.reactor, registry_uid_count_is, &cw_b, 600, 5));

    ASSERT_EQ_INT(2, probe.calls);
    ASSERT_EQ_INT(202, (int)probe.last_session_id);
    ASSERT_MEM_EQ(probe.last_uid, e.uid_user, CLOAK_UID_LEN);
    ASSERT_EQ_INT(0, (int)probe.proxy_sessions);                /* L1 again */
    ASSERT_EQ_INT(0, (int)probe.proxy_streams);
    ASSERT_EQ_INT(0, probe.panel_still_has_uid);                /* L3 ran first */
    ASSERT_EQ_INT(1, (int)probe.api_sessions);
    ASSERT_EQ_INT(1, (int)probe.api_streams);

    ASSERT_TRUE(cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_user) == NULL);
    ASSERT_TRUE(cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_admin) != NULL);
    ASSERT_EQ_INT(1, (int)cloak_server_stack_admin_session_count(st));

    /* ========== BREAK C: the admin session ========== */
    client_session_close(&admin);
    struct count_wait cw_c = {st, e.uid_admin, 0};
    ASSERT_TRUE(pump_until(e.reactor, registry_uid_count_is, &cw_c, 600, 5));

    ASSERT_EQ_INT(3, probe.calls);                              /* L4 ran again */
    ASSERT_EQ_INT(0, (int)probe.last_session_id);
    ASSERT_MEM_EQ(probe.last_uid, e.uid_admin, CLOAK_UID_LEN);
    ASSERT_EQ_INT(0, (int)probe.api_sessions);                  /* L2 ran first */
    ASSERT_EQ_INT(0, (int)probe.api_streams);                   /* L2 ran first */
    ASSERT_EQ_INT(0, probe.panel_still_has_uid);                /* L3 ran first */
    ASSERT_EQ_INT(0, (int)probe.proxy_sessions);

    ASSERT_TRUE(cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_admin) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_server_stack_session_count(st));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_admin_session_count(st));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_proxy_session_count(st));

    /* Nothing may fire into the wreckage: both upstream sockets are still
     * open and still registered, so a relay that outlived its session
     * would be handed a byte here. ASan is the detector. */
    (void)up_send(&e.up, 0, "after-the-free", 14);
    (void)up_send(&e.up, 1, "after-the-free", 14);
    for (int i = 0; i < 60; i++) {
        cloak_reactor_run_once(e.reactor, 2);
    }
    ASSERT_EQ_INT(3, probe.calls);

    cloak_server_stack_close(st);
    env_destroy(&e);
}

/* ------------------------------------------------------------------ */
/* 3. A termination stops BOTH modules                                  */
/* ------------------------------------------------------------------ */

/* EDGE E5, WHICH HAD NO TEST AT ALL UNTIL REVIEW SAID SO. Emptying
 * stack_session_closing survived the whole suite, and so did each half
 * of it, because nothing anywhere terminated a user: on_session_closing
 * fires ONLY from cloak_server_registry_close_all_for_uid, which only
 * cloak_userpanel_terminate reaches.
 *
 * WHY IT MATTERS MORE THAN THE CHAIN DOES. A termination closes sessions
 * WITHOUT firing the registry's on_broken, so the whole four-link chain
 * is silent for it. This hook is the only notification either module
 * gets, and cloak/userpanel.h names the consequence exactly: "a
 * use-after-free on the first upstream byte after the first
 * out-of-credit user is terminated".
 *
 * TWO PHASES, because one covers the real trigger and the other covers
 * the "both" property:
 *
 *   PHASE 1 -- a metered database user runs out of credit and is
 *   terminated by an ordinary upload cycle, which is the production
 *   trigger, driven here through cloak_server_stack_upload_now (the same
 *   panel cycle the periodic timer runs). Only the proxy half is visible:
 *   a database user cannot hold an admin session.
 *
 *   PHASE 2 -- ONE UID holding an admin session AND a proxy session at
 *   the same time, terminated in one walk. That shape is reachable and is
 *   not a contrivance: the dispatcher calls a session admin only when the
 *   UID is the admin UID AND session_id == 0, so every OTHER session id
 *   the admin UID opens is an ordinary proxy session. Both halves of the
 *   trampoline have visible work in the same termination, so dropping
 *   either one fails here. */
static void test_termination_stops_both_modules(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "terminate", 1));

    /* Credit far below what the transfer below moves, so the very first
     * upload cycle after it finds the user out of credit. */
    seed_user(e.db_path, e.uid_db, 4, 1000, 1000);

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    sc.adminapi_request_timeout_ms = 600000;

    cloak_server_stack_t *st = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        env_destroy(&e);
        return;
    }

    /* =================== PHASE 1: credit exhaustion =================== */
    client_session_t dbuser;
    ASSERT_EQ_INT(0, open_client_at(&e, &dbuser, e.uid_db, "ss", 301, front_port(st)));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_proxy_session_count(st));
    cloak_userpanel_user_t *pu = cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_db);
    ASSERT_TRUE(pu != NULL);
    /* A DATABASE user is metered; the contrast with the bypass admin user
     * in phase 2 is what makes "metered" mean something here. */
    ASSERT_TRUE(pu != NULL && cloak_userpanel_user_valve(pu) != NULL);

    cloak_stream_t *dbs = cloak_session_open_stream(&dbuser.sesh, NULL);
    ASSERT_TRUE(dbs != NULL);
    if (dbs == NULL) {
        client_session_close(&dbuser);
        cloak_server_stack_close(st);
        env_destroy(&e);
        return;
    }
    uint8_t burn[4096];
    memset(burn, 'x', sizeof(burn));
    ASSERT_EQ_INT((int)sizeof(burn), (int)cloak_stream_write(dbs, burn, sizeof(burn)));
    struct up_wait uw = {&e.up, 0, sizeof(burn)};
    ASSERT_TRUE(pump_until(e.reactor, up_has_len, &uw, 800, 5));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_proxy_stream_count(st));

    /* The cycle the periodic timer runs, taken at a deterministic moment.
     * It drains the valve, settles it into the database, finds the credit
     * exhausted and terminates the user -- which is what reaches
     * on_session_closing. */
    ASSERT_EQ_INT(0, cloak_server_stack_upload_now(st));

    ASSERT_TRUE(cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_db) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_server_stack_session_count_for_uid(st, e.uid_db));
    /* THE ASSERTION THE TRAMPOLINE'S PROXY HALF OWNS. close_all_for_uid
     * fires no on_broken, so these counters can only have been cleared
     * through the hook. */
    ASSERT_EQ_INT(0, (int)cloak_server_stack_proxy_session_count(st));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_proxy_stream_count(st));

    /* THE CLIENT IS TORN DOWN BEFORE THE PUMP BELOW, and the order is
     * not incidental: the server has just closed this session, so a
     * reactor turn would deliver the closing-stream frames to the client,
     * which RETIRES its streams -- after which cloak_session_destroy no
     * longer reclaims them and releasing them by hand is not safe either
     * (test_server_e2e.c documents the same hazard for the same reason).
     * Found by LeakSanitizer during mutation work, not by reading: a
     * teardown-order mutation shifted that timing and 12 client-side
     * streams leaked, which would have been read as a finding about the
     * server. */
    client_session_close(&dbuser);

    /* The byte that would land on a relay that had NOT been stopped.
     * Expected to fail at the socket level, so the result is not
     * asserted; what is asserted is that pumping afterwards touches
     * nothing freed, and ASan is the detector. */
    (void)up_send(&e.up, 0, "after-the-free", 14);
    for (int i = 0; i < 60; i++) {
        cloak_reactor_run_once(e.reactor, 2);
    }
    ASSERT_EQ_INT(0, (int)cloak_server_stack_proxy_stream_count(st));

    /* ============ PHASE 2: one UID, an admin session AND a proxy ======= */
    client_session_t admin;
    ASSERT_EQ_INT(0, open_admin_client(&e, st, &admin));
    cloak_stream_t *ast = cloak_session_open_stream(&admin.sesh, NULL);
    ASSERT_TRUE(ast != NULL);
    if (ast == NULL) {
        client_session_close(&admin);
        cloak_server_stack_close(st);
        env_destroy(&e);
        return;
    }
    ASSERT_EQ_INT((int)(sizeof(ADMIN_PARTIAL) - 1),
                  (int)cloak_stream_write(ast, (const uint8_t *)ADMIN_PARTIAL,
                                          sizeof(ADMIN_PARTIAL) - 1));
    struct api_wait aw = {st, 1};
    ASSERT_TRUE(pump_until(e.reactor, api_stream_count_is, &aw, 400, 5));

    /* The SAME UID, a different session id: an ordinary proxy session. */
    client_session_t adminproxy;
    ASSERT_EQ_INT(0, open_client_at(&e, &adminproxy, e.uid_admin, "ss", 302, front_port(st)));
    cloak_stream_t *aps = cloak_session_open_stream(&adminproxy.sesh, NULL);
    ASSERT_TRUE(aps != NULL);
    if (aps == NULL) {
        client_session_close(&adminproxy);
        client_session_close(&admin);
        cloak_server_stack_close(st);
        env_destroy(&e);
        return;
    }
    ASSERT_EQ_INT(6, (int)cloak_stream_write(aps, (const uint8_t *)"both!!", 6));
    struct up_wait uw2 = {&e.up, 1, 6};
    ASSERT_TRUE(pump_until(e.reactor, up_has_len, &uw2, 400, 5));

    /* BOTH modules hold a context for this ONE uid, at the same time. */
    ASSERT_EQ_INT(2, (int)cloak_server_stack_session_count_for_uid(st, e.uid_admin));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_admin_session_count(st));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_admin_stream_count(st));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_proxy_session_count(st));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_proxy_stream_count(st));

    /* The termination itself -- the same function an out-of-credit cycle
     * calls, applied to a bypass user that no cycle would ever pick. */
    cloak_userpanel_user_t *au = cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_admin);
    ASSERT_TRUE(au != NULL);
    /* A bypass user is NOT metered, which is the other half of phase 1's
     * contrast and is what makes credit exhaustion inapplicable here. */
    ASSERT_TRUE(au == NULL || cloak_userpanel_user_valve(au) == NULL);
    cloak_userpanel_terminate(cloak_server_stack_panel(st), au, "test");

    /* BOTH HALVES, ASSERTED SEPARATELY. Dropping the proxy call leaves
     * the first pair non-zero; dropping the adminapi call leaves the
     * second pair non-zero; emptying the trampoline leaves all four. */
    ASSERT_EQ_INT(0, (int)cloak_server_stack_proxy_session_count(st));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_proxy_stream_count(st));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_admin_session_count(st));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_admin_stream_count(st));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_session_count_for_uid(st, e.uid_admin));
    ASSERT_TRUE(cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_admin) == NULL);

    /* Both clients down before the pump, for the reason phase 1 gives. */
    client_session_close(&adminproxy);
    client_session_close(&admin);

    (void)up_send(&e.up, 1, "after-the-free", 14);
    for (int i = 0; i < 60; i++) {
        cloak_reactor_run_once(e.reactor, 2);
    }
    ASSERT_EQ_INT(0, (int)cloak_server_stack_proxy_stream_count(st));

    cloak_server_stack_close(st);
    env_destroy(&e);
}

/* ------------------------------------------------------------------ */
/* 4. An abandoned handshake reclaims BOTH modules                      */
/* ------------------------------------------------------------------ */

/* EDGE E6, WHICH ALSO HAD NO TEST. Emptying stack_session_aborted
 * survived the whole suite: nothing anywhere reached the dispatcher's
 * abandoned-session hook, because every handshake in every other case
 * succeeds.
 *
 * WHAT IT GUARDS: prepare_session allocates a per-session context BEFORE
 * the cloak_session_t exists. If the session never comes to exist, or is
 * unwound after being created, the registry's broken callback never fires
 * for it and nothing else would ever free that context -- one leak per
 * abandoned handshake, remotely reachable and unbounded. Both
 * cloak/proxy.h and cloak/adminapi.h say so and neither can enforce it,
 * because the dispatcher has ONE hook and two modules need it.
 *
 * HOW THE WINDOW IS FORCED: test_write_shim.c (LD_PRELOAD) makes the
 * dispatcher's step-10 reply write fail for one specific connection,
 * which is the only deterministic way to reach the post-creation unwind
 * -- the reply is far smaller than any socket buffer floor, so genuine
 * backpressure cannot produce it. The shim consumes its environment
 * variable the instant it fires, so its disappearance is EXTERNAL PROOF
 * that the intended path ran; without that proof this case would pass
 * vacuously on a build with no LD_PRELOAD, having covered nothing. */
static int shim_fired(void *ctx) {
    (void)ctx;
    return getenv("CLOAK_TEST_FORCE_PEER_PORT") == NULL;
}

/* Drives one connection whose reply write is forced to fail, for the
 * (uid, session_id, proxy_method) given. Returns 0 on success. */
static int abandon_one_handshake(struct env *e, const cloak_server_stack_t *st, const uint8_t *uid,
                                 const char *method, uint32_t session_id) {
    int fd = client_connect(front_port(st));
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return -1;
    }
    int cport = client_local_port(fd);
    ASSERT_TRUE(cport > 0);
    if (cport <= 0) {
        close(fd);
        return -1;
    }

    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", cport);
    ASSERT_EQ_INT(0, setenv("CLOAK_TEST_FORCE_PEER_PORT", portbuf, 1));
    ASSERT_EQ_INT(0, setenv("CLOAK_TEST_FORCE_MODE", "error", 1));
    unsetenv("CLOAK_TEST_FORCE_STICKY");

    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    size_t record_len =
        build_client_record(e->server_pub, uid, method, (uint8_t)CLOAK_AEAD_AES_256_GCM,
                            (int64_t)time(NULL), session_id, 0, record, sizeof(record), shared);
    ASSERT_TRUE(record_len > 0);
    if (record_len == 0) {
        close(fd);
        unsetenv("CLOAK_TEST_FORCE_PEER_PORT");
        unsetenv("CLOAK_TEST_FORCE_MODE");
        return -1;
    }
    ASSERT_TRUE(write(fd, record, record_len) == (ssize_t)record_len);

    /* THE PROOF THAT THE FORCED PATH RAN, not that some earlier refusal
     * did: the shim consumed the variable. */
    ASSERT_TRUE(pump_until(e->reactor, shim_fired, NULL, 600, 5));
    for (int i = 0; i < 40; i++) {
        cloak_reactor_run_once(e->reactor, 2);
    }

    unsetenv("CLOAK_TEST_FORCE_PEER_PORT");
    unsetenv("CLOAK_TEST_FORCE_MODE");
    close(fd);
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(e->reactor, 2);
    }
    return 0;
}

static void test_aborted_handshake_reclaims_both_modules(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "abort", 1));

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    cloak_server_stack_t *st = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        env_destroy(&e);
        return;
    }

    /* ---- the PROXY half: an ordinary bypass user's handshake ---- */
    ASSERT_EQ_INT(0, abandon_one_handshake(&e, st, e.uid_user, "ss", 401));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_session_count(st));
    /* The context cloak_proxy_prepare_session allocated before the
     * session existed. Only the trampoline's proxy half frees it. */
    ASSERT_EQ_INT(0, (int)cloak_server_stack_proxy_session_count(st));
    /* And the panel was told too, so the user is not left active
     * forever -- the other silent leak on this path. */
    ASSERT_TRUE(cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_user) == NULL);

    /* ---- the ADMIN half: the admin UID on session id 0 ---- */
    ASSERT_EQ_INT(0, abandon_one_handshake(&e, st, e.uid_admin, "nosuch", 0));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_session_count(st));
    /* The context cloak_adminapi_prepare_session allocated. Only the
     * trampoline's adminapi half frees it. */
    ASSERT_EQ_INT(0, (int)cloak_server_stack_admin_session_count(st));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_admin_stream_count(st));
    ASSERT_TRUE(cloak_userpanel_find(cloak_server_stack_panel(st), e.uid_admin) == NULL);

    /* The server is still healthy afterwards: an abandoned handshake is
     * not allowed to poison the next good one. */
    client_session_t cs;
    ASSERT_EQ_INT(0, open_proxy_client(&e, st, &cs, 402));
    cloak_stream_t *s = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s != NULL) {
        ASSERT_EQ_INT(6, (int)cloak_stream_write(s, (const uint8_t *)"after!", 6));
        struct up_wait uw = {&e.up, 0, 6};
        ASSERT_TRUE(pump_until(e.reactor, up_has_len, &uw, 400, 5));
        ASSERT_UP_BYTES(e.up, 0, "after!", 6);
        cloak_session_release_stream(&cs.sesh, s);
    }
    client_session_close(&cs);

    cloak_server_stack_close(st);
    env_destroy(&e);
}

/* ------------------------------------------------------------------ */
/* 5. Teardown in the stack's own order, with traffic in flight         */
/* ------------------------------------------------------------------ */

#define INFLIGHT_CHUNK ((size_t)4096)
#define INFLIGHT_CHUNKS 16
/* Bytes that must be outstanding INSIDE the server at the moment of the
 * teardown -- comfortably more than one relay queue (16 KiB) so this is
 * a loaded pipeline rather than an empty one, and comfortably less than
 * what the path holds before any layer's cap would refuse a frame. */
#define INFLIGHT_MIN_OUTSTANDING ((size_t)(32u * 1024u))

struct inflight {
    cloak_session_t *sesh;
    cloak_stream_t *stream;
    const uint8_t *buf;
    size_t sent;
    upstream_t *up;
    size_t want_outstanding;
};

/* Keeps writing, one chunk per reactor turn, and stops once enough bytes
 * are stuck between the client and the stalled upstream. Paced
 * deliberately: an unpaced writer pushes everything into the kernel
 * before a single reactor turn runs, and there is then no moment at which
 * the transfer is partly done. */
static int inflight_ready(void *ctx) {
    struct inflight *w = ctx;
    if (w->sent < INFLIGHT_CHUNKS * INFLIGHT_CHUNK &&
        cloak_session_send_min_conn_free(w->sesh) >= 2 * 16401) {
        if (cloak_stream_write(w->stream, w->buf + w->sent, INFLIGHT_CHUNK) < 0) {
            return 1;
        }
        w->sent += INFLIGHT_CHUNK;
    }
    size_t delivered = w->up->conns[0].in_len;
    return w->sent > delivered && (w->sent - delivered) >= w->want_outstanding;
}

/* CLEAN SHUTDOWN IN THE STACK'S OWN ORDER, with work outstanding at
 * every layer: a running relay with bytes stuck inside the server, an
 * admin session context, and a half-sent admin request whose deadline is
 * ARMED. Most of what this can catch is visible only under ASan -- a
 * relay stopped too late holds a freed cloak_stream_t, a deadline never
 * cancelled fires against freed memory. Mutation-verified: destroying the
 * registry BEFORE the proxy is a heap-use-after-free here.
 *
 * THE DEADLINE IS GIVEN A REAL CHANCE: the request timeout is 300 ms and
 * the reactor is pumped PAST it after the whole stack is gone, with the
 * elapsed time asserted rather than assumed. */
static void test_teardown_with_traffic_in_flight(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "shutdown", 1));

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    sc.adminapi_request_timeout_ms = 300;

    cloak_server_stack_t *st = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        env_destroy(&e);
        return;
    }

    client_session_t user;
    ASSERT_EQ_INT(0, open_proxy_client(&e, st, &user, 501));
    cloak_stream_t *pst = cloak_session_open_stream(&user.sesh, NULL);
    ASSERT_TRUE(pst != NULL);
    if (pst == NULL) {
        client_session_close(&user);
        cloak_server_stack_close(st);
        env_destroy(&e);
        return;
    }

    uint8_t *src = malloc(INFLIGHT_CHUNKS * INFLIGHT_CHUNK);
    ASSERT_TRUE(src != NULL);
    if (src == NULL) {
        cloak_session_release_stream(&user.sesh, pst);
        client_session_close(&user);
        cloak_server_stack_close(st);
        env_destroy(&e);
        return;
    }
    for (size_t i = 0; i < INFLIGHT_CHUNKS * INFLIGHT_CHUNK; i++) {
        src[i] = (uint8_t)((i * 13u + (i >> 7)) & 0xff);
    }

    /* Bring the relay up and prove bytes really cross the whole stack
     * BEFORE anything is stalled -- otherwise "in flight" would be
     * indistinguishable from "never started". */
    ASSERT_EQ_INT(6, (int)cloak_stream_write(pst, (const uint8_t *)"start!", 6));
    struct up_wait uw = {&e.up, 0, 6};
    ASSERT_TRUE(pump_until(e.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(6, (int)e.up.conns[0].in_len);
    ASSERT_EQ_INT(1, (int)cloak_server_stack_proxy_stream_count(st));

    /* Now the upstream stops reading and the client keeps writing: the
     * difference is bytes sitting inside the server. */
    e.up.stall = 1;
    struct inflight fl = {&user.sesh, pst, src, 0, &e.up, INFLIGHT_MIN_OUTSTANDING};
    ASSERT_TRUE(pump_until(e.reactor, inflight_ready, &fl, 4000, 2));

    client_session_t admin;
    ASSERT_EQ_INT(0, open_admin_client(&e, st, &admin));
    cloak_stream_t *ast = cloak_session_open_stream(&admin.sesh, NULL);
    ASSERT_TRUE(ast != NULL);
    if (ast == NULL) {
        free(src);
        client_session_close(&admin);
        client_session_close(&user);
        cloak_server_stack_close(st);
        env_destroy(&e);
        return;
    }
    ASSERT_EQ_INT((int)(sizeof(ADMIN_PARTIAL) - 1),
                  (int)cloak_stream_write(ast, (const uint8_t *)ADMIN_PARTIAL,
                                          sizeof(ADMIN_PARTIAL) - 1));
    struct api_wait aw = {st, 1};
    ASSERT_TRUE(pump_until(e.reactor, api_stream_count_is, &aw, 400, 5));

    /* MID-FLIGHT, ASSERTED AT THE MOMENT OF THE TEARDOWN rather than
     * hoped for. */
    ASSERT_TRUE(e.up.conns[0].in_len >= 6);
    ASSERT_TRUE(fl.sent > e.up.conns[0].in_len);
    ASSERT_TRUE(fl.sent - e.up.conns[0].in_len >= INFLIGHT_MIN_OUTSTANDING);
    ASSERT_EQ_INT(1, (int)cloak_server_stack_proxy_stream_count(st));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_proxy_session_count(st));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_admin_session_count(st));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_admin_stream_count(st));
    ASSERT_EQ_INT(0, user.broken);

    /* ---- the shutdown, in the stack's order ---- */
    uint64_t t0 = now_ms();
    cloak_server_stack_close(st);
    st = NULL;

    /* The client sessions are still live on the reactor, exactly as a
     * remote client would be when a server exits. They are destroyed
     * BEFORE the post-teardown pump for the reason test_server_e2e.c
     * gives: no reactor turn has run yet, so their streams are still
     * active and cloak_session_destroy reclaims them. */
    client_session_close(&admin);
    client_session_close(&user);

    /* PAST THE 300 ms DEADLINE, with the stack gone: a deadline the admin
     * API failed to cancel would fire here against a freed stream and a
     * freed context. The elapsed time is asserted, not assumed. */
    while (now_ms() - t0 < 500) {
        cloak_reactor_run_once(e.reactor, 10);
    }
    ASSERT_TRUE(now_ms() - t0 >= 300);

    /* And the byte that would land on a relay that was never stopped. */
    e.up.stall = 0;
    (void)up_send(&e.up, 0, "after-the-free", 14);
    for (int i = 0; i < 60; i++) {
        cloak_reactor_run_once(e.reactor, 2);
    }

    /* Closing a NULL handle is a no-op, which is what makes a caller's
     * unconditional cleanup path correct. */
    cloak_server_stack_close(NULL);

    free(src);
    env_destroy(&e);
}

/* ------------------------------------------------------------------ */
/* 6. The enforced edges -- one case each                               */
/* ------------------------------------------------------------------ */

/* Every case here asserts FOUR things: the typed code, the code's EXACT
 * name (a strlen > 0 check would be satisfied by the strerror default
 * arm's "unknown" for every code, which is a test written against the
 * symbol it tests rather than against the behaviour), that the message
 * names the edge, and that nothing was left open. */
static void assert_rejected(const cloak_server_stack_config_t *sc, int expect_code,
                            const char *expect_name, const char *expect_in_message) {
    char err[256];
    memset(err, 0xAA, sizeof(err));
    cloak_server_stack_t *st = (cloak_server_stack_t *)(void *)&err; /* deliberately non-NULL */
    int before = fd_count();
    ASSERT_TRUE(before > 0);

    int rc = cloak_server_stack_open(&st, sc, err, sizeof(err));
    ASSERT_EQ_INT(expect_code, rc);
    /* *out is NULL on EVERY failure path, including the ones that reject
     * before allocating: a caller's cleanup closes NULL, not a stale
     * pointer it never wrote. */
    ASSERT_TRUE(st == NULL);
    ASSERT_EQ_INT(0, strcmp(cloak_server_stack_strerror(rc), expect_name));
    ASSERT_TRUE(strlen(err) > 0 && strlen(err) < sizeof(err));
    ASSERT_TRUE(strstr(err, expect_in_message) != NULL);
    /* THE UNWIND, measured with no destroy of our own in between: a
     * rejected open must release everything it had already built. */
    ASSERT_EQ_INT(before, fd_count());

    cloak_server_stack_close(st); /* NULL: a no-op */
}

/* EDGE 1: no reactor. */
static void test_edge_null_reactor(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "edge1", 1));
    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    sc.reactor = NULL;
    assert_rejected(&sc, CLOAK_SERVER_STACK_ERR_ARG, "argument", "reactor");
    env_destroy(&e);
}

/* EDGE 2: no config. */
static void test_edge_null_config(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "edge2", 1));
    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    sc.config = NULL;
    assert_rejected(&sc, CLOAK_SERVER_STACK_ERR_ARG, "argument", "server config");
    env_destroy(&e);
}

/* EDGE 3: a config that binds nothing. Not a degraded server -- a silent
 * one: it would start, log nothing and answer no client ever. */
static void test_edge_no_bind_address(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "edge3", 1));
    e.cfg.num_bind_addr = 0;
    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    assert_rejected(&sc, CLOAK_SERVER_STACK_ERR_CONFIG, "server config", "BindAddr");
    env_destroy(&e);
}

/* EDGE 4: more bind addresses than the array holds. cloak_server_config_t
 * is a POD a caller can build by hand, so an out-of-range count is
 * realistic rather than merely a violated invariant. */
static void test_edge_too_many_bind_addresses(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "edge4", 1));
    e.cfg.num_bind_addr = CLOAK_MAX_BIND_ADDR + 1;
    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    assert_rejected(&sc, CLOAK_SERVER_STACK_ERR_CONFIG, "server config", "BindAddr");
    env_destroy(&e);
}

/* EDGE 5: a session template the mux layer will not accept. 70000 is far
 * past CLOAK_CONN_MAX_FRAME_LEN, which cloak/conn.h explains is a
 * wire-format constant. Without this check the first REJECTION happens on
 * the first client's connection, where the dispatcher turns it into a
 * cover-site redirect -- every client redirected, forever, silently. */
static void test_edge_session_template_rejected(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "edge5", 1));
    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    sc.session_config_template.max_on_wire_size = 70000;
    assert_rejected(&sc, CLOAK_SERVER_STACK_ERR_TEMPLATE, "session template", "session template");
    env_destroy(&e);
}

/* EDGE 6a: the retry ladder outlasting the session it belongs to, with
 * the ladder CONFIGURED EXPLICITLY.
 *
 * A MEASURED BRACKET, NOT A CLAIMED MARGIN: the rejected side sits one
 * millisecond below the ladder and the accepted side one millisecond
 * above it, so the boundary itself is pinned. A comparison the wrong way
 * round, or off by one, fails one of the two halves. */
static void test_edge_retry_ladder_explicit(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "edge6a", 1));

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    sc.proxy_retry_delay_ms = 10;
    sc.proxy_max_retries = 100; /* ladder = 1000 ms */

    sc.session_config_template.inactivity_timeout_ms = 1000;
    assert_rejected(&sc, CLOAK_SERVER_STACK_ERR_RETRY_LADDER, "proxy retry ladder", "retry ladder");

    sc.session_config_template.inactivity_timeout_ms = 1001;
    cloak_server_stack_t *st = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    cloak_server_stack_close(st);

    env_destroy(&e);
}

/* EDGE 6b: THE SAME EDGE ON THE PATH EVERY BINARY ACTUALLY TAKES, and the
 * reason 6a alone is not enough. A binary that accepts the proxy's
 * defaults writes ZERO in both retry fields, so a check that used the raw
 * config would compute a ladder of zero and accept everything -- which is
 * the only case most deployments are in. Here both fields are left at 0
 * and the bracket is drawn around the proxy's REAL ladder
 * (CLOAK_PROXY_DEFAULT_RETRY_DELAY_MS x _MAX_RETRIES = 20000 ms), spelled
 * as a literal so that a change to either constant fails here rather than
 * being absorbed by an expression that moves with it. */
static void test_edge_retry_ladder_defaults(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "edge6b", 1));

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    ASSERT_EQ_INT(0, (int)sc.proxy_retry_delay_ms);
    ASSERT_EQ_INT(0, (int)sc.proxy_max_retries);

    sc.session_config_template.inactivity_timeout_ms = 20000;
    assert_rejected(&sc, CLOAK_SERVER_STACK_ERR_RETRY_LADDER, "proxy retry ladder", "20000 ms");

    sc.session_config_template.inactivity_timeout_ms = 20001;
    cloak_server_stack_t *st = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    cloak_server_stack_close(st);

    env_destroy(&e);
}

/* EDGE 7: a config the layer below rejects. cloak_server_init checks this
 * count itself; what the stack adds is that the failure is named and
 * typed rather than a bare -1 from somewhere in a binary's startup. */
static void test_edge_config_rejected_by_server_state(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "edge7", 1));
    e.cfg.num_proxy_entries = CLOAK_MAX_PROXY_BOOK + 1;
    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    assert_rejected(&sc, CLOAK_SERVER_STACK_ERR_SERVER, "server state", "server state");
    env_destroy(&e);
}

/* EDGE 8: a DatabasePath that cannot be opened. An EMPTY one is NOT this
 * -- that is the void manager, and it is a legitimate deployment; the
 * accepted half below is what keeps this case from being green on an
 * implementation that rejected both. */
static void test_edge_database_cannot_be_opened(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "edge8", 1));

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);

    snprintf(e.cfg.database_path, sizeof(e.cfg.database_path),
             "/nonexistent-cloak-stack-dir/users.db");
    assert_rejected(&sc, CLOAK_SERVER_STACK_ERR_DATABASE, "user database", "user database");

    e.cfg.database_path[0] = '\0';
    cloak_server_stack_t *st = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    ASSERT_TRUE(cloak_server_stack_manager(st) != NULL);
    cloak_server_stack_close(st);

    env_destroy(&e);
}

/* EDGE 9: a bind address that cannot be opened -- and, because it is the
 * SECOND of two, the unwind path as well: the listener already opened
 * must be released by the failing open itself. assert_rejected measures
 * descriptors with no destroy of its own in between, which is the only
 * way to see that (an earlier version measured after its own destroy and
 * the missing-unwind mutation survived). */
static void test_edge_bind_address_cannot_be_opened(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "edge9", 1));

    ASSERT_EQ_INT(1, (int)e.cfg.num_bind_addr);
    e.cfg.num_bind_addr = 2;
    /* TEST-NET-1 (RFC 5737): a syntactically valid address guaranteed not
     * to be assigned to any interface here, so bind(2) fails with
     * EADDRNOTAVAIL. Deterministic and local -- no DNS, and no dependence
     * on whether this process happens to be root (a privileged port would
     * bind fine inside a container that runs as root, which is what made
     * the first attempt at this case pass for the wrong reason). */
    snprintf(e.cfg.bind_addr[1], sizeof(e.cfg.bind_addr[1]), "192.0.2.1:1234");

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    assert_rejected(&sc, CLOAK_SERVER_STACK_ERR_LISTEN, "bind address", "192.0.2.1:1234");

    env_destroy(&e);
}

/* ------------------------------------------------------------------ */
/* 7. Every configured BindAddr accepts                                 */
/* ------------------------------------------------------------------ */

/* Three listeners, three DIFFERENT ports, and a real handshake plus real
 * bytes through each -- not merely "three listeners exist". One
 * dispatcher serves them all (cloak/dispatcher.h), so a stack that opened
 * three sockets but wired only the first would pass a count assertion and
 * fail this one. */
static void test_every_bind_address_accepts(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "binds", 3));

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    cloak_server_stack_t *st = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        env_destroy(&e);
        return;
    }
    ASSERT_EQ_INT(3, (int)cloak_server_stack_listener_count(st));

    int ports[3];
    for (size_t i = 0; i < 3; i++) {
        ports[i] = cloak_server_stack_listener_port(st, i);
        ASSERT_TRUE(ports[i] > 0);
    }
    ASSERT_TRUE(ports[0] != ports[1] && ports[1] != ports[2] && ports[0] != ports[2]);
    ASSERT_EQ_INT(-1, cloak_server_stack_listener_port(st, 3));

    client_session_t cs[3];
    cloak_stream_t *sts[3];
    for (size_t i = 0; i < 3; i++) {
        sts[i] = NULL;
        ASSERT_EQ_INT(0,
                      open_client_at(&e, &cs[i], e.uid_user, "ss", (uint32_t)(600 + i), ports[i]));
        sts[i] = cloak_session_open_stream(&cs[i].sesh, NULL);
        ASSERT_TRUE(sts[i] != NULL);
        if (sts[i] == NULL) {
            continue;
        }
        char payload[8];
        snprintf(payload, sizeof(payload), "bind-%d", (int)i);
        ASSERT_EQ_INT(6, (int)cloak_stream_write(sts[i], (const uint8_t *)payload, 6));
        struct up_wait uw = {&e.up, (int)i, 6};
        ASSERT_TRUE(pump_until(e.reactor, up_has_len, &uw, 600, 5));
        ASSERT_UP_BYTES(e.up, (int)i, payload, 6);
    }
    ASSERT_EQ_INT(3, e.up.accept_count);
    ASSERT_EQ_INT(3, (int)cloak_server_stack_session_count(st));
    ASSERT_EQ_INT(3, (int)cloak_server_stack_proxy_stream_count(st));

    for (size_t i = 0; i < 3; i++) {
        if (sts[i] != NULL) {
            cloak_session_release_stream(&cs[i].sesh, sts[i]);
        }
        client_session_close(&cs[i]);
    }
    cloak_server_stack_close(st);
    env_destroy(&e);
}

/* ------------------------------------------------------------------ */
/* 8. Built and destroyed twice, with descriptors counted               */
/* ------------------------------------------------------------------ */

/* TWO FULL CYCLES IN ONE PROCESS, each carrying real traffic, with the
 * descriptor count measured after each and compared. The comparison is
 * cycle to cycle, never against a cold baseline, so whatever a process
 * allocates once (SQLite's page cache, the resolver) is warm in both.
 *
 * LeakSanitizer does not track descriptors: a stack that leaked a
 * listener, an accepted socket or a SQLite file handle per cycle would
 * pass the sanitizer run and exhaust a long-running server instead. */
static void test_build_and_destroy_twice_leaves_nothing(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "twice", 2));

    ASSERT_TRUE(fd_count() > 0); /* /proc/self/fd is the detector; no skip */

    int after_cycle[2] = {0, 0};
    for (int cycle = 0; cycle < 2; cycle++) {
        cloak_server_stack_config_t sc;
        stack_config(&e, &sc);
        cloak_server_stack_t *st = NULL;
        char err[256] = {0};
        ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
        ASSERT_TRUE(st != NULL);
        if (st == NULL) {
            env_destroy(&e);
            return;
        }
        ASSERT_EQ_INT(2, (int)cloak_server_stack_listener_count(st));

        client_session_t cs;
        ASSERT_EQ_INT(0, open_proxy_client(&e, st, &cs, (uint32_t)(700 + cycle)));
        cloak_stream_t *s = cloak_session_open_stream(&cs.sesh, NULL);
        ASSERT_TRUE(s != NULL);
        if (s != NULL) {
            ASSERT_EQ_INT(6, (int)cloak_stream_write(s, (const uint8_t *)"cycle!", 6));
            struct up_wait uw = {&e.up, cycle, 6};
            ASSERT_TRUE(pump_until(e.reactor, up_has_len, &uw, 600, 5));
            ASSERT_UP_BYTES(e.up, cycle, "cycle!", 6);
            cloak_session_release_stream(&cs.sesh, s);
        }
        client_session_close(&cs);
        cloak_server_stack_close(st);
        /* The upstream connection this cycle's relay produced belongs to
         * the TEST, not to the stack; released here so that what is
         * compared below is the stack's own footprint and nothing else.
         * Measured: without this the count grows by exactly one per
         * cycle, which is this socket and not a leak. */
        up_close_conn(&e.up, cycle);

        for (int i = 0; i < 20; i++) {
            cloak_reactor_run_once(e.reactor, 2);
        }
        after_cycle[cycle] = fd_count();
        ASSERT_TRUE(after_cycle[cycle] > 0);
    }

    ASSERT_EQ_INT(after_cycle[0], after_cycle[1]);

    env_destroy(&e);
}

/* ------------------------------------------------------------------ */
/* 9. The caller's config may die the moment open returns               */
/* ------------------------------------------------------------------ */

/* THE STACK TAKES A COPY, and this is what that buys. cloak_server_t
 * borrows its cloak_server_config_t for its whole life and AUTHENTICATION
 * READS IT ON EVERY HANDSHAKE -- cloak_server_lookup_proxy walks the
 * ProxyBook names, cloak_server_is_admin compares admin_uid -- so a
 * binary that parsed its config into a local and returned, or reused the
 * struct for a reload, would have a dangling read on the hot path. An
 * earlier revision of the header listed this as unenforceable; it was one
 * memcpy.
 *
 * The config here is HEAP allocated, scribbled and then FREED, so ASan
 * reports a heap-use-after-free rather than the test depending on what a
 * dead stack frame happens to still contain. Both readers are exercised
 * afterwards: a proxy client (the ProxyBook lookup) and an admin client
 * (the admin_uid comparison). */
static void test_config_may_die_after_open(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "cfglife", 1));

    cloak_server_config_t *heap_cfg = malloc(sizeof(*heap_cfg));
    ASSERT_TRUE(heap_cfg != NULL);
    if (heap_cfg == NULL) {
        env_destroy(&e);
        return;
    }
    *heap_cfg = e.cfg;

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    sc.config = heap_cfg;

    cloak_server_stack_t *st = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        free(heap_cfg);
        env_destroy(&e);
        return;
    }

    /* The caller's config is gone from this line onward. */
    memset(heap_cfg, 0xEE, sizeof(*heap_cfg));
    free(heap_cfg);
    heap_cfg = NULL;

    /* A PROXY client: dispatcher step 7 calls cloak_server_lookup_proxy,
     * which reads the ProxyBook entry NAMES out of the config. */
    client_session_t cs;
    ASSERT_EQ_INT(0, open_proxy_client(&e, st, &cs, 801));
    cloak_stream_t *s = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s != NULL) {
        ASSERT_EQ_INT(7, (int)cloak_stream_write(s, (const uint8_t *)"cfgfree", 7));
        struct up_wait uw = {&e.up, 0, 7};
        ASSERT_TRUE(pump_until(e.reactor, up_has_len, &uw, 400, 5));
        ASSERT_UP_BYTES(e.up, 0, "cfgfree", 7);
        cloak_session_release_stream(&cs.sesh, s);
    }

    /* AN ADMIN client: step 6a calls cloak_server_is_admin, which
     * compares against admin_uid in the config. A wrong answer here is
     * not a crash but a category error -- the session would be prepared
     * by the proxy instead -- so the admin-side counter is what is
     * asserted. */
    client_session_t admin;
    ASSERT_EQ_INT(0, open_admin_client(&e, st, &admin));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_admin_session_count(st));

    client_session_close(&admin);
    client_session_close(&cs);
    cloak_server_stack_close(st);
    env_destroy(&e);
}

/* ------------------------------------------------------------------ */
/* 10. strerror, compared exactly                                       */
/* ------------------------------------------------------------------ */

/* ONE EXACT COMPARISON PER CODE. The obvious version of this -- assert
 * the string is non-empty -- is satisfied by the default arm's "unknown"
 * for every code in the table, so it would pass on an implementation with
 * no table at all. These strings reach an operator's log next to the
 * message, so they are contract. */
static void test_strerror_names_every_code(void) {
    ASSERT_EQ_INT(0, strcmp(cloak_server_stack_strerror(0), "ok"));
    ASSERT_EQ_INT(0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_ARG), "argument"));
    ASSERT_EQ_INT(
        0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_CONFIG), "server config"));
    ASSERT_EQ_INT(
        0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_TEMPLATE), "session template"));
    ASSERT_EQ_INT(0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_RETRY_LADDER),
                            "proxy retry ladder"));
    ASSERT_EQ_INT(
        0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_SERVER), "server state"));
    ASSERT_EQ_INT(
        0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_DATABASE), "user database"));
    ASSERT_EQ_INT(
        0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_REGISTRY), "session registry"));
    ASSERT_EQ_INT(
        0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_PANEL), "user panel"));
    ASSERT_EQ_INT(
        0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_ADMINAPI), "admin API"));
    ASSERT_EQ_INT(0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_PROXY), "proxy"));
    ASSERT_EQ_INT(
        0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_DISPATCHER), "dispatcher"));
    ASSERT_EQ_INT(
        0, strcmp(cloak_server_stack_strerror(CLOAK_SERVER_STACK_ERR_LISTEN), "bind address"));
    /* And the default arm, which is the thing every other assertion here
     * exists to distinguish itself from. */
    ASSERT_EQ_INT(0, strcmp(cloak_server_stack_strerror(-9999), "unknown"));
    ASSERT_EQ_INT(0, strcmp(cloak_server_stack_strerror(1), "unknown"));
}

/* ------------------------------------------------------------------ */
/* 11. The replay cache the stack actually allocated                    */
/* ------------------------------------------------------------------ */

/* THE DEFAULT IS SPELLED AS A LITERAL, deliberately. Asserting against
 * CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY would derive both
 * sides of the comparison from the same symbol, so the constant could be
 * changed by a factor of 256 without this failing -- a defect this
 * project has shipped before. The accessor reports what
 * cloak_server_init really allocated, not this module's copy of the
 * request, so a substitution that never reached the allocation is
 * visible. */
static void test_replay_cache_capacity(void) {
    struct env e;
    ASSERT_EQ_INT(0, env_init(&e, "replay", 1));
    char err[256] = {0};

    cloak_server_stack_config_t sc;
    stack_config(&e, &sc);
    cloak_server_stack_t *st = NULL;
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    /* 2097152. It was 1024 until the replay cache was keyed and resized,
     * and 524288 until the SESSION CAP was lifted from 256 to 1024 --
     * cloak/server_stack.h derives this capacity from
     * CLOAK_REGISTRY_MAX_SESSIONS * 4 connections turning over every
     * 120 s, so a fourfold cap is a fourfold sized handshake rate and a
     * fourfold capacity. THE ONLY THING THAT CHANGED HERE, BOTH TIMES,
     * IS THE LITERAL: the assertion still spells the number out rather
     * than deriving it from
     * CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY, for the reason
     * above, and still reads it back through the accessor that reports
     * what cloak_server_init really allocated. A substitution that never
     * reached the allocation is still visible, and so is a future change
     * to the constant that nobody meant -- INCLUDING THIS ONE: this
     * assertion is what failed when the cap was raised, which is the
     * whole point of spelling it out. */
    ASSERT_EQ_INT(2097152, (int)cloak_server_stack_replay_cache_capacity(st));
    cloak_server_stack_close(st);

    /* An explicit value is honoured verbatim, which is what makes the
     * assertion above a statement about the DEFAULT rather than about a
     * hard-coded allocation. */
    st = NULL;
    sc.replay_cache_capacity = 64;
    ASSERT_EQ_INT(0, cloak_server_stack_open(&st, &sc, err, sizeof(err)));
    ASSERT_EQ_INT(64, (int)cloak_server_stack_replay_cache_capacity(st));
    cloak_server_stack_close(st);

    /* A closed or absent stack reports 0 rather than reading freed
     * memory. */
    ASSERT_EQ_INT(0, (int)cloak_server_stack_replay_cache_capacity(NULL));

    env_destroy(&e);
}

TEST_MAIN_BEGIN()
test_stack_carries_traffic_end_to_end();
test_broken_session_runs_the_whole_chain();
test_termination_stops_both_modules();
test_aborted_handshake_reclaims_both_modules();
test_teardown_with_traffic_in_flight();
test_edge_null_reactor();
test_edge_null_config();
test_edge_no_bind_address();
test_edge_too_many_bind_addresses();
test_edge_session_template_rejected();
test_edge_retry_ladder_explicit();
test_edge_retry_ladder_defaults();
test_edge_config_rejected_by_server_state();
test_edge_database_cannot_be_opened();
test_edge_bind_address_cannot_be_opened();
test_every_bind_address_accepts();
test_build_and_destroy_twice_leaves_nothing();
test_config_may_die_after_open();
test_strerror_names_every_code();
test_replay_cache_capacity();
TEST_MAIN_END()
