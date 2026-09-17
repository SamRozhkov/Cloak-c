#define _POSIX_C_SOURCE 200809L
#include "cloak/adminapi.h"
#include "cloak/base64.h"
#include "cloak/clienthello.h"
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
#include "cloak/user_json.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
#include "test_framework.h"
#include "client_harness.h"

#include "sqlite3.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* THE WHOLE SERVER, DRIVEN THE WAY ck-server WILL DRIVE IT.
 *
 * Every other test in this module isolates one part. This one assembles
 * all of them at once -- a listener, a dispatcher, a registry, a
 * cloak_server_t built from parsed JSON config, a SQLite-backed
 * cloak_usermanager_t, a cloak_userpanel_t, a cloak_proxy_t AND a
 * cloak_adminapi_t -- and then makes the two halves of the server meet:
 * an admin client CREATES a user through the REST API, and a proxy
 * client then authenticates as that user and moves bytes. Nothing here
 * is a mock except the cover site and the upstream, which are the two
 * things that are genuinely outside this process.
 *
 * WHY THAT MEETING IS THE POINT. Until this file, the admin API's writes
 * and the dispatcher's authorisation decisions were tested against the
 * same database by two different test binaries, each seeding the rows the
 * other would have written. A row written by cloak_usermanager_write from
 * an HTTP handler and a row written by a test's put_user are the same row
 * only if the whole path from base64url UID through the JSON decoder
 * through the field mask lands where authentication looks -- and that is
 * exactly the composition no single-module test can assert.
 *
 * EVERY WAIT IS A BOUNDED pump_until (client_harness.h), and every bound
 * whose comment names a duration asserts that the duration was reached.
 *
 * REFUSALS ARE ASSERTED AGAINST THE COVER SITE'S OWN BYTES, the
 * discipline test_dispatcher_users.c states: "refused" means "received
 * exactly what a connection this server has no opinion about receives". */

/* ------------------------------------------------------------------ */
/* Database scaffolding                                                 */
/* ------------------------------------------------------------------ */

static void ae_tmp_path(char *buf, size_t cap, const char *tag) {
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(buf, cap, "%s/cloak_ae2e_%ld_%s.db", dir, (long)getpid(), tag);
}

/* WAL leaves sidecars; a survivor would carry committed credit from a
 * previous run into this one and make a billing assertion pass or fail
 * for reasons unrelated to the code under test. */
static void ae_unlink(const char *path) {
    char aux[512];
    unlink(path);
    snprintf(aux, sizeof(aux), "%s-wal", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-shm", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-journal", path);
    unlink(aux);
}

#define T_NOW    1600000000
#define T_EXPIRY (T_NOW + 100000)

static int64_t ae_now(void *userdata) {
    (void)userdata;
    return (int64_t)T_NOW;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* uid[0] is the discriminator; the rest is filler that keeps every UID in
 * this file distinct from every other. */
static void mk_uid(uint8_t *uid, uint8_t seed) {
    memset(uid, 0xE0, CLOAK_UID_LEN);
    uid[0] = seed;
}

/* ------------------------------------------------------------------ */
/* Fake cover site: answers every connection with the same fixed bytes   */
/* ------------------------------------------------------------------ */

static const char AE_BANNER[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
#define AE_BANNER_LEN (sizeof(AE_BANNER) - 1)

typedef struct {
    cloak_reactor_t *reactor;
    int fds[16];
    int count;
} redir_site_t;

static void redir_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    (void)userdata;
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
    ssize_t n = write(fd, AE_BANNER, AE_BANNER_LEN);
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
/* Fake upstream: the proxy path's far end                              */
/* ------------------------------------------------------------------ */

#define AE_UP_MAX 8
#define AE_UP_CAP ((size_t)16384)

typedef struct {
    int fd;
    uint8_t in[AE_UP_CAP];
    size_t in_len;
} ae_up_conn_t;

struct ae_upstream;
typedef struct {
    struct ae_upstream *up;
    int idx;
} ae_up_slot_t;

typedef struct ae_upstream {
    cloak_reactor_t *reactor;
    int accept_count;
    ae_up_conn_t conns[AE_UP_MAX];
    ae_up_slot_t slots[AE_UP_MAX];
} ae_upstream_t;

static void ae_up_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    (void)events;
    ae_up_slot_t *slot = userdata;
    ae_up_conn_t *c = &slot->up->conns[slot->idx];
    for (;;) {
        if (c->in_len >= AE_UP_CAP) {
            return;
        }
        ssize_t n = read(c->fd, c->in + c->in_len, AE_UP_CAP - c->in_len);
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

static void ae_up_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    ae_upstream_t *up = userdata;
    if (up->accept_count >= AE_UP_MAX) {
        close(fd);
        return;
    }
    int idx = up->accept_count++;
    up->conns[idx].fd = fd;
    up->slots[idx].up = up;
    up->slots[idx].idx = idx;
    (void)cloak_reactor_add_fd(up->reactor, fd, CLOAK_REACTOR_READABLE, ae_up_on_readable,
                               &up->slots[idx]);
}

/* Callers that push bytes at an upstream whose relay has already been
 * stopped EXPECT this to fail (the relay closed the socket), so the
 * result is deliberately not asserted there. */
static ssize_t ae_up_send(ae_upstream_t *up, int idx, const void *data, size_t len) {
    return send(up->conns[idx].fd, data, len, MSG_NOSIGNAL);
}

static void ae_up_destroy(ae_upstream_t *up) {
    for (int i = 0; i < AE_UP_MAX; i++) {
        if (up->conns[i].fd >= 0) {
            cloak_reactor_remove_fd(up->reactor, up->conns[i].fd);
            close(up->conns[i].fd);
            up->conns[i].fd = -1;
        }
    }
}

struct up_wait {
    ae_upstream_t *up;
    int idx;
    size_t want;
};

static int up_has_len(void *ctx) {
    struct up_wait *w = ctx;
    return w->up->conns[w->idx].in_len >= w->want;
}

/* ------------------------------------------------------------------ */
/* What the owner's prepare_session saw                                 */
/* ------------------------------------------------------------------ */

struct prep_record {
    int calls;
    int admin_calls;
    int proxy_calls;
    int last_is_admin;
    const cloak_valve_t *last_valve;
    const cloak_valve_t *last_admin_valve;
    const cloak_valve_t *last_proxy_valve;
};

/* The OWNER'S own (last) link of the broken-session chain. It exists here
 * for the same reason a binary will have one -- cloak_userpanel_config_t
 * ::chain is the slot reserved for it -- and because its call count is
 * the only externally visible proof that the three module links ahead of
 * it were reached at all. */
struct chain_probe {
    int calls;
};

static void owner_chain_cb(cloak_server_registry_t *reg, cloak_session_t *sesh,
                           const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id, void *userdata) {
    (void)reg;
    (void)sesh;
    (void)uid;
    (void)session_id;
    struct chain_probe *pr = userdata;
    pr->calls++;
}

/* ------------------------------------------------------------------ */
/* The fixture -- one whole server                                      */
/* ------------------------------------------------------------------ */

struct fixture {
    cloak_reactor_t *reactor;

    redir_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;

    ae_upstream_t up;
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

    cloak_adminapi_t api;
    int api_ready;

    cloak_dispatcher_t d;
    int d_ready;

    cloak_listener_t front;
    int have_front;

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_admin[CLOAK_UID_LEN];

    struct prep_record prep;
    struct chain_probe chain;
};

/* THE OWNER'S prepare_session, in exactly the shape cloak/adminapi.h's
 * WIRING block gives: one branch on the dispatcher's own is_admin flag,
 * and no second definition of "admin" anywhere in this file. */
static int fx_prepare_session(cloak_dispatcher_t *d, const cloak_server_clientinfo_t *info,
                              cloak_session_config_t *config, void *userdata) {
    struct fixture *fx = userdata;
    fx->prep.calls++;
    fx->prep.last_is_admin = info->is_admin;
    fx->prep.last_valve = config->valve;
    if (info->is_admin) {
        fx->prep.admin_calls++;
        fx->prep.last_admin_valve = config->valve;
        return cloak_adminapi_prepare_session(&fx->api, info->uid, info->session_id, config);
    }
    fx->prep.proxy_calls++;
    fx->prep.last_proxy_valve = config->valve;
    return cloak_proxy_prepare_session(d, info, config, &fx->proxy);
}

/* The dispatcher has ONE abandoned-session hook and two modules that need
 * it; cloak/adminapi.h's cloak_adminapi_session_aborted paragraph says an
 * owner running both calls both. */
static void fx_session_aborted(cloak_dispatcher_t *d, const uint8_t uid[CLOAK_UID_LEN],
                               uint32_t session_id, void *userdata) {
    struct fixture *fx = userdata;
    cloak_proxy_session_aborted(d, uid, session_id, &fx->proxy);
    cloak_adminapi_session_aborted(&fx->api, uid, session_id);
}

/* cloak/userpanel.h's WIRING obligation 3: a termination closes sessions
 * by UID, which fires no on_broken, so both modules must be told here
 * instead. Case 2 is what makes the adminapi half of this line matter as
 * much as the proxy half -- a delete evicts through exactly this path. */
static void fx_session_closing(const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    struct fixture *fx = userdata;
    cloak_proxy_session_aborted(NULL, uid, session_id, &fx->proxy);
    cloak_adminapi_session_aborted(&fx->api, uid, session_id);
}

typedef struct {
    uint64_t request_timeout_ms; /* 0 -> cloak_adminapi_t's own default */
} fixture_opts_t;

/* ============ THE WIRING A ck-server BINARY MUST REPRODUCE ============
 *
 * Everything between the "STACK BEGINS" and "STACK ENDS" markers below is
 * production wiring, not test scaffolding: the same calls in the same
 * order, with the same cross-pointers. The markers are there so the
 * module-7 scouting report can count it honestly. */
static int fixture_init_opts(struct fixture *fx, const char *tag, const fixture_opts_t *o) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    for (int i = 0; i < AE_UP_MAX; i++) {
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
                                         ae_up_on_accept, &fx->up, err, sizeof(err)));
    fx->have_up_listener = 1;
    fx->up_port = cloak_listener_port(&fx->up_listener);
    ASSERT_TRUE(fx->up_port > 0);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, fx->server_pub));
    mk_uid(fx->uid_admin, 0x01);

    char priv_b64[64];
    char admin_b64[32];
    ASSERT_EQ_INT(
        0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64, sizeof(priv_b64)));
    ASSERT_EQ_INT(
        0, cloak_base64_encode(fx->uid_admin, CLOAK_UID_LEN, admin_b64, sizeof(admin_b64)));

    /* The config a real deployment writes: one proxy method, a redirect
     * target, a private key and an admin UID. No BypassUID at all -- every
     * proxy user in this file has to come from the DATABASE, which is
     * what makes "the admin API created it" the only way one can exist. */
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\"127.0.0.1:0\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"AdminUID\":\"%s\"}",
             fx->up_port, cover_port, priv_b64, admin_b64);

    ae_tmp_path(fx->db_path, sizeof(fx->db_path), tag);
    ae_unlink(fx->db_path);

    /* ---------------- STACK BEGINS ---------------- */
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_usermanager_open(&fx->mgr, fx->db_path, ae_now, NULL, err, sizeof(err)));
    ASSERT_TRUE(fx->mgr != NULL);
    if (fx->mgr == NULL) {
        return -1;
    }

    /* CONSTRUCTION ORDER. The registry's on_broken userdata is the
     * proxy's ADDRESS -- stored, never dereferenced until a session
     * breaks -- so the registry may be built before the proxy exists. The
     * panel needs the registry; the adminapi's chain needs the panel; the
     * proxy's chain needs the adminapi; the dispatcher needs all of them.
     * NOTHING IN THE BUILD ENFORCES ANY OF THAT; see the scouting report. */
    ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor,
                                                cloak_proxy_registry_broken, &fx->proxy));
    fx->registry_ready = 1;

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = fx->mgr;
    pcfg.registry = &fx->registry;
    pcfg.reactor = fx->reactor;
    /* Long enough that no periodic tick can land inside a case. Every
     * cycle in this file is driven by an explicit cloak_userpanel_upload_
     * now, which runs the identical panel_run_cycle the tick runs -- so
     * the behaviour under test is the production cycle, taken at a
     * deterministic moment instead of a racy one. */
    pcfg.upload_interval_ms = 3600000;
    pcfg.now_fn = ae_now;
    pcfg.on_session_closing = fx_session_closing;
    pcfg.on_session_closing_userdata = fx;
    pcfg.chain = owner_chain_cb; /* LINK 4: panel -> owner */
    pcfg.chain_userdata = &fx->chain;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&fx->panel, &pcfg));
    ASSERT_TRUE(fx->panel != NULL);
    if (fx->panel == NULL) {
        return -1;
    }

    cloak_adminapi_config_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.reactor = fx->reactor;
    acfg.manager = fx->mgr;
    acfg.request_timeout_ms = o->request_timeout_ms;
    acfg.chain = cloak_userpanel_registry_broken; /* LINK 3: adminapi -> panel */
    acfg.chain_userdata = fx->panel;
    ASSERT_EQ_INT(0, cloak_adminapi_init(&fx->api, &acfg));
    fx->api_ready = 1;

    cloak_proxy_config_t pxcfg;
    memset(&pxcfg, 0, sizeof(pxcfg));
    pxcfg.reactor = fx->reactor;
    pxcfg.srv = &fx->srv;
    pxcfg.chain = cloak_adminapi_registry_broken; /* LINK 2: proxy -> adminapi */
    pxcfg.chain_userdata = &fx->api;
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
    dcfg.prepare_session = fx_prepare_session;
    dcfg.prepare_session_userdata = fx;
    dcfg.session_aborted = fx_session_aborted;
    dcfg.session_aborted_userdata = fx;
    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, fx->cfg.bind_addr[0],
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;
    /* ---------------- STACK ENDS ---------------- */
    return 0;
}

static int fixture_init(struct fixture *fx, const char *tag) {
    fixture_opts_t o;
    memset(&o, 0, sizeof(o));
    return fixture_init_opts(fx, tag, &o);
}

/* THE SERVER'S OWN SHUTDOWN, in the order a binary must use -- which is
 * NOT the reverse of construction. The proxy and the adminapi come BEFORE
 * the registry (both hold stream pointers into live sessions and
 * releasing a stream needs a live session), and the PANEL comes AFTER it
 * (it frees every active user's valve without closing anybody's
 * sessions). The reactor is deliberately NOT destroyed here: case 5 keeps
 * pumping it after the stack is gone, which is the only way a leaked
 * deadline timer can be caught. */
static void fixture_destroy_stack(struct fixture *fx) {
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
    if (fx->api_ready) {
        cloak_adminapi_destroy(&fx->api);
        fx->api_ready = 0;
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

static void fixture_destroy_rest(struct fixture *fx) {
    if (fx->have_up_listener) {
        cloak_listener_close(&fx->up_listener);
        fx->have_up_listener = 0;
    }
    ae_up_destroy(&fx->up);
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
        ae_unlink(fx->db_path);
    }
}

static void fixture_destroy(struct fixture *fx) {
    fixture_destroy_stack(fx);
    fixture_destroy_rest(fx);
}

static int front_port(struct fixture *fx) {
    return cloak_listener_port(&fx->front);
}

static void client_config(cloak_session_config_t *ccfg) {
    memset(ccfg, 0, sizeof(*ccfg));
    ccfg->ordering = CLOAK_SESSION_ORDERING_ORDERED;
    ccfg->max_on_wire_size = 16401;
    ccfg->stream_recv_capacity = 65536;
    ccfg->stream_max_pending_frames = 64;
    ccfg->conn_send_queue_cap = 262144;
    ccfg->inactivity_timeout_ms = 60000;
}

static int open_client_pm(struct fixture *fx, client_session_t *cs, const uint8_t *uid,
                          const char *proxy_method, uint32_t session_id) {
    cloak_session_config_t ccfg;
    client_config(&ccfg);
    return client_session_open(cs, fx->reactor, front_port(fx), fx->server_pub, uid, proxy_method,
                               session_id, 0, &ccfg);
}

/* The ADMIN client: the admin UID, session id 0, and a proxy method this
 * server does not offer -- which is what a real `ck-client -a` sends,
 * since admin mode leaves ProxyMethod at whatever the client's config
 * file names. */
static int open_admin(struct fixture *fx, client_session_t *cs) {
    return open_client_pm(fx, cs, fx->uid_admin, "nosuch", 0);
}

/* ---- the refusal probe (test_dispatcher_users.c's) ---------------------- */

static size_t probe_response(struct fixture *fx, const uint8_t *rec, size_t rec_len, uint8_t *out,
                             size_t cap) {
    size_t want = AE_BANNER_LEN < cap ? AE_BANNER_LEN : cap;
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
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(fx->reactor, 2);
    }
    return got;
}

/* Asserts that this UID is REFUSED, and refused the way every other
 * unrecognised connection is: the cover site's own bytes, byte for byte.
 *
 * expect_sessions is how many sessions this UID is ALREADY entitled to
 * hold -- 0 for a UID this server has never heard of, and 1 in case 2,
 * where an existing session is deliberately still running while a fresh
 * connection for the same UID is turned away. Asserting the count rather
 * than hard-coding 0 is what keeps this probe from quietly stopping at
 * the one place it has something interesting to say. */
static void assert_refused(struct fixture *fx, const uint8_t *uid, uint32_t session_id,
                           int expect_sessions) {
    uint8_t rec[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t got[128];
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    size_t rec_len =
        build_client_record(fx->server_pub, uid, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM,
                            (int64_t)time(NULL), session_id, 0, rec, sizeof(rec), shared);
    ASSERT_TRUE(rec_len > 0);
    size_t n = probe_response(fx, rec, rec_len, got, sizeof(got));
    ASSERT_EQ_INT((int)AE_BANNER_LEN, (int)n);
    ASSERT_MEM_EQ(got, AE_BANNER, AE_BANNER_LEN);
    ASSERT_EQ_INT(expect_sessions,
                  (int)cloak_server_registry_count_for_uid(&fx->registry, uid));
}

/* ---- reading one admin HTTP response off a stream ------------------------ */

#define RESP_CAP ((size_t)(1u << 16))

typedef struct {
    cloak_stream_t *stream;
    uint8_t *buf;
    size_t len;
    int ended;
} resp_t;

static void resp_init(resp_t *r, cloak_stream_t *st) {
    r->stream = st;
    r->buf = malloc(RESP_CAP);
    r->len = 0;
    r->ended = 0;
}

static void resp_free(resp_t *r) {
    free(r->buf);
    r->buf = NULL;
}

static void resp_poll(resp_t *r) {
    if (r->buf == NULL) {
        return;
    }
    for (;;) {
        if (r->len >= RESP_CAP) {
            return;
        }
        long n = cloak_stream_read(r->stream, r->buf + r->len, RESP_CAP - r->len);
        if (n > 0) {
            r->len += (size_t)n;
            continue;
        }
        if (n < 0) {
            r->ended = 1;
        }
        return;
    }
}

static long resp_header_end(const resp_t *r) {
    for (size_t i = 0; i + 4 <= r->len; i++) {
        if (memcmp(r->buf + i, "\r\n\r\n", 4) == 0) {
            return (long)(i + 4);
        }
    }
    return -1;
}

/* An EXACT-SPELLING search, like test_adminapi.c's: a change to the
 * header's spelling should fail here rather than be absorbed. */
static long resp_content_length(const resp_t *r, long hdr_end) {
    static const char key[] = "\r\nContent-Length: ";
    size_t klen = sizeof(key) - 1;
    for (size_t i = 0; i + klen < (size_t)hdr_end; i++) {
        if (memcmp(r->buf + i, key, klen) == 0) {
            long v = 0;
            size_t j = i + klen;
            if (j >= (size_t)hdr_end || r->buf[j] < '0' || r->buf[j] > '9') {
                return -1;
            }
            while (j < (size_t)hdr_end && r->buf[j] >= '0' && r->buf[j] <= '9') {
                v = v * 10 + (r->buf[j] - '0');
                j++;
            }
            return v;
        }
    }
    return -1;
}

static int resp_complete(void *ctx) {
    resp_t *r = ctx;
    resp_poll(r);
    long he = resp_header_end(r);
    if (he < 0) {
        return 0;
    }
    long cl = resp_content_length(r, he);
    if (cl < 0) {
        return 1;
    }
    return r->len >= (size_t)he + (size_t)cl;
}

static int resp_status(const resp_t *r) {
    if (r->len < 12 || memcmp(r->buf, "HTTP/1.1 ", 9) != 0) {
        return -1;
    }
    return (r->buf[9] - '0') * 100 + (r->buf[10] - '0') * 10 + (r->buf[11] - '0');
}

static const char *resp_body(const resp_t *r, size_t *out_len) {
    long he = resp_header_end(r);
    if (he < 0) {
        *out_len = 0;
        return NULL;
    }
    *out_len = r->len - (size_t)he;
    return (const char *)r->buf + he;
}

/* Sends one whole request on a fresh stream and waits for a complete
 * response. One stream is one request (cloak/adminapi.h), so every call
 * opens its own. The caller owns the returned stream. */
static cloak_stream_t *request(struct fixture *fx, client_session_t *cs, const char *req,
                               resp_t *out) {
    cloak_stream_t *st = cloak_session_open_stream(&cs->sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        return NULL;
    }
    resp_init(out, st);
    ASSERT_TRUE(out->buf != NULL);
    ASSERT_EQ_INT((int)strlen(req), (int)cloak_stream_write(st, (const uint8_t *)req, strlen(req)));
    ASSERT_TRUE(pump_until(fx->reactor, resp_complete, out, 600, 5));
    return st;
}

static void finish(client_session_t *cs, cloak_stream_t *st, resp_t *r) {
    resp_free(r);
    if (st != NULL) {
        cloak_session_release_stream(&cs->sesh, st);
    }
}

/* ---- the admin client's own operations, as HTTP ------------------------- */

static void uid_url(const uint8_t uid[CLOAK_UID_LEN], char *out, size_t cap) {
    ASSERT_EQ_INT(0, cloak_base64url_encode(uid, CLOAK_UID_LEN, out, cap));
}

/* POST /admin/users/{uid}. Returns the status code. */
static int admin_create_user(struct fixture *fx, client_session_t *admin,
                             const uint8_t uid[CLOAK_UID_LEN], const char *body,
                             char *out_body, size_t out_cap) {
    char up[64];
    char reqbuf[1024];
    uid_url(uid, up, sizeof(up));
    snprintf(reqbuf, sizeof(reqbuf),
             "POST /admin/users/%s HTTP/1.1\r\nHost: admin\r\nContent-Type: application/json\r\n"
             "Content-Length: %zu\r\n\r\n%s",
             up, strlen(body), body);
    resp_t r;
    cloak_stream_t *st = request(fx, admin, reqbuf, &r);
    int status = resp_status(&r);
    if (out_body != NULL && out_cap > 0) {
        size_t blen = 0;
        const char *b = resp_body(&r, &blen);
        if (blen >= out_cap) {
            blen = out_cap - 1;
        }
        if (b != NULL && blen > 0) {
            memcpy(out_body, b, blen);
        }
        out_body[blen] = '\0';
    }
    finish(admin, st, &r);
    return status;
}

/* DELETE /admin/users/{uid}. Returns the status code. */
static int admin_delete_user(struct fixture *fx, client_session_t *admin,
                             const uint8_t uid[CLOAK_UID_LEN]) {
    char up[64];
    char reqbuf[256];
    uid_url(uid, up, sizeof(up));
    snprintf(reqbuf, sizeof(reqbuf), "DELETE /admin/users/%s HTTP/1.1\r\nHost: admin\r\n\r\n", up);
    resp_t r;
    cloak_stream_t *st = request(fx, admin, reqbuf, &r);
    int status = resp_status(&r);
    finish(admin, st, &r);
    return status;
}

/* "There is no row for this UID" -- asserted as the manager's OWN
 * not-found code, never as "get returned non-zero". cloak_usermanager_get
 * returns CLOAK_USER_ERR_ARG for a NULL out and CLOAK_USER_ERR_VOID for a
 * manager with no database, so a `!= 0` test here would be green for two
 * reasons that have nothing to do with the row's absence. */
static int user_row_absent(cloak_usermanager_t *m, const uint8_t uid[CLOAK_UID_LEN]) {
    cloak_user_info_t row;
    memset(&row, 0, sizeof(row));
    return cloak_usermanager_get(m, uid, &row) == CLOAK_USER_ERR_NOT_FOUND;
}

static int user_row_present(cloak_usermanager_t *m, const uint8_t uid[CLOAK_UID_LEN]) {
    cloak_user_info_t row;
    memset(&row, 0, sizeof(row));
    return cloak_usermanager_get(m, uid, &row) == 0;
}

/* The JSON body every case here creates a user with: four sessions, full
 * credit in both directions, and an expiry far past the fixed clock. */
#define AE_USER_CREDIT 10000000
static const char AE_USER_JSON[] = "{\"SessionsCap\":4,\"UpRate\":0,\"DownRate\":0,"
                                   "\"UpCredit\":10000000,\"DownCredit\":10000000,"
                                   "\"ExpiryTime\":1600100000}";

/* ------------------------------------------------------------------ */
/* 1. THE TWO HALVES MEETING                                            */
/* ------------------------------------------------------------------ */

/* THE CASE THIS WHOLE MODULE EXISTS FOR. An admin client creates a user
 * through the REST API; a proxy client then authenticates as that user
 * and moves bytes in both directions.
 *
 * THE NEGATIVE CONTROL IS HALF THE ASSERTION. The very same UID is probed
 * BEFORE the POST and must be refused with the cover site's own bytes.
 * Without it, every assertion after the POST would also be green on a
 * server that authorised everyone, and the case would be measuring the
 * proxy rather than the admin API's write.
 *
 * WHAT FAILS IT: anything that breaks the path from the base64url UID in
 * the request line, through the JSON decoder and its field mask, into the
 * row cloak_usermanager_authenticate reads. Mutation-verified two ways --
 * a POST handler that answers 201 without calling cloak_usermanager_write,
 * and one that writes a UID one bit different from the path's. See the
 * task report. */
static void test_admin_creates_a_user_who_then_proxies(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "meet"));

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x41);

    /* ---- the negative control ---- */
    assert_refused(&fx, uid, 1, 0);
    ASSERT_TRUE(user_row_absent(fx.mgr, uid));

    /* ---- the admin half ---- */
    client_session_t admin;
    ASSERT_EQ_INT(0, open_admin(&fx, &admin));
    ASSERT_EQ_INT(1, fx.prep.last_is_admin);
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&fx.api));
    /* D6: an admin session carries no meter. Asserted here because this
     * case is also the one that proves a PROXY session does carry one. */
    ASSERT_TRUE(fx.prep.last_admin_valve == NULL);

    ASSERT_EQ_INT(201, admin_create_user(&fx, &admin, uid, AE_USER_JSON, NULL, 0));

    /* The row the API wrote, read back through the manager the dispatcher
     * will authenticate against -- the same handle, not a second one. */
    cloak_user_info_t row;
    memset(&row, 0, sizeof(row));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.mgr, uid, &row));
    ASSERT_EQ_INT(4, row.sessions_cap);
    ASSERT_EQ_INT(AE_USER_CREDIT, (int)row.up_credit);
    ASSERT_EQ_INT(AE_USER_CREDIT, (int)row.down_credit);
    ASSERT_EQ_INT(T_EXPIRY, (int)row.expiry_time);

    /* ---- the proxy half, as the user the admin just created ---- */
    client_session_t user;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &user, uid, "ss", 1));
    ASSERT_EQ_INT(0, fx.prep.last_is_admin);
    ASSERT_EQ_INT(1, fx.prep.proxy_calls);
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, uid));
    /* A DATABASE user, not a bypass one: it is metered, and the admin
     * session in the same fixture is not. Both halves of that contrast
     * are needed -- "valve == NULL" alone would stay green on a server
     * that had stopped installing valves at all. */
    ASSERT_TRUE(fx.prep.last_proxy_valve != NULL);
    cloak_userpanel_user_t *pu = cloak_userpanel_find(fx.panel, uid);
    ASSERT_TRUE(pu != NULL);
    if (pu != NULL) {
        ASSERT_EQ_INT(0, pu->bypass);
        ASSERT_TRUE(cloak_userpanel_user_valve(pu) != NULL);
    }

    /* ---- and it really carries traffic, both ways ---- */
    cloak_stream_t *st = cloak_session_open_stream(&user.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&user);
        client_session_close(&admin);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(9, (int)cloak_stream_write(st, (const uint8_t *)"upstream!", 9));
    struct up_wait uw = {&fx.up, 0, 9};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(1, fx.up.accept_count);
    ASSERT_MEM_EQ(fx.up.conns[0].in, "upstream!", 9);
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    resp_t down;
    resp_init(&down, st);
    ASSERT_TRUE(down.buf != NULL);
    ASSERT_EQ_INT(11, (int)ae_up_send(&fx.up, 0, "downstream!", 11));
    for (int i = 0; i < 400 && down.len < 11; i++) {
        cloak_reactor_run_once(fx.reactor, 5);
        resp_poll(&down);
    }
    ASSERT_EQ_INT(11, (int)down.len);
    ASSERT_MEM_EQ(down.buf, "downstream!", 11);

    /* The admin session is still there and still answering, side by side
     * with the proxy session it created. */
    resp_t lr;
    cloak_stream_t *lst = request(&fx, &admin, "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n",
                                  &lr);
    ASSERT_EQ_INT(200, resp_status(&lr));
    finish(&admin, lst, &lr);

    resp_free(&down);
    cloak_session_release_stream(&user.sesh, st);
    client_session_close(&user);
    client_session_close(&admin);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 2. THE DOCUMENTED LAG                                                */
/* ------------------------------------------------------------------ */

/* THE USER-MANAGER MODULE RECORDED THIS AS DELIBERATE, and it is asserted
 * here rather than discovered later: "delete, or zeroing a credit, does
 * not evict an active user until the next upload cycle -- up to one
 * interval of free service."
 *
 * BOTH HALVES ARE ASSERTED, and the first one is the one that would be
 * missing from a careless version of this test:
 *
 *   HALF 1 -- immediately after the DELETE the existing session still
 *   works. New bytes written after the delete reach the upstream, the
 *   registry still holds the session and the panel still holds the user.
 *   A test that asserted only half 2 would be equally green on an
 *   implementation that evicted instantly, which is NOT what this code
 *   does and not what an operator is told to expect.
 *
 *   HALF 2 -- one upload cycle later the session is gone: the manager
 *   reports CLOAK_USER_TERMINATE_NO_SUCH_USER for a UID with no row, the
 *   panel terminates the user, close_all_for_uid closes its sessions, and
 *   on_session_closing stops its relays. Bytes written after that reach
 *   nobody.
 *
 * THE NEW-SESSION CONTRAST separates "the delete did nothing" from "the
 * delete took effect at the authorisation boundary only": a FRESH
 * connection for the same UID is refused the instant the row is gone,
 * while the existing session keeps running. That is precisely the
 * documented shape, and it is what makes half 1 a statement about
 * eviction rather than about the delete having failed.
 *
 * Mutation-verified in both directions; see the task report. */
static void test_delete_does_not_evict_until_the_next_upload_cycle(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "lag"));

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x42);

    client_session_t admin;
    ASSERT_EQ_INT(0, open_admin(&fx, &admin));
    ASSERT_EQ_INT(201, admin_create_user(&fx, &admin, uid, AE_USER_JSON, NULL, 0));

    client_session_t user;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &user, uid, "ss", 5));
    cloak_stream_t *st = cloak_session_open_stream(&user.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&user);
        client_session_close(&admin);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(7, (int)cloak_stream_write(st, (const uint8_t *)"before!", 7));
    struct up_wait uw = {&fx.up, 0, 7};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    /* ---- the delete ---- */
    ASSERT_EQ_INT(200, admin_delete_user(&fx, &admin, uid));
    ASSERT_TRUE(user_row_absent(fx.mgr, uid)); /* the row is gone */

    /* ---- HALF 1: the existing session is untouched ---- */
    ASSERT_TRUE(cloak_userpanel_find(fx.panel, uid) != NULL);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, uid));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, user.broken);
    /* And it is not merely REGISTERED -- it still moves bytes. */
    ASSERT_EQ_INT(6, (int)cloak_stream_write(st, (const uint8_t *)"after!", 6));
    uw.want = 13;
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_MEM_EQ(fx.up.conns[0].in, "before!after!", 13);

    /* THE CONTRAST: a NEW connection for the same UID is refused at once.
     * The delete did take effect -- on authorisation, not on eviction. */
    assert_refused(&fx, uid, 6, 1);

    /* ---- HALF 2: one upload cycle, and the free service ends ---- */
    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(fx.panel));
    ASSERT_TRUE(cloak_userpanel_find(fx.panel, uid) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx.registry, uid));
    /* on_session_closing did its job: close_all_for_uid fires no
     * on_broken, so these counters can only have been cleared through
     * that hook. */
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

    /* Bytes written now reach nobody: the upstream's tally does not move
     * again. Bounded, then asserted unchanged. */
    size_t before_len = fx.up.conns[0].in_len;
    (void)cloak_stream_write(st, (const uint8_t *)"ghost!", 6);
    for (int i = 0; i < 60; i++) {
        cloak_reactor_run_once(fx.reactor, 2);
    }
    ASSERT_EQ_INT((int)before_len, (int)fx.up.conns[0].in_len);
    /* And the byte that would land on a relay that had NOT been stopped.
     * Expected to fail at the socket level, which is why the result is
     * not asserted; what is asserted is that pumping afterwards touches
     * nothing freed (ASan is the detector). */
    (void)ae_up_send(&fx.up, 0, "after-the-free", 14);
    for (int i = 0; i < 40; i++) {
        cloak_reactor_run_once(fx.reactor, 2);
    }
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

    /* The ADMIN session survived the cycle that killed the proxy user --
     * it is a bypass user with no row to lose. */
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&fx.api));
    resp_t r;
    cloak_stream_t *ast = request(&fx, &admin, "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n",
                                  &r);
    ASSERT_EQ_INT(200, resp_status(&r));
    size_t blen = 0;
    const char *body = resp_body(&r, &blen);
    ASSERT_EQ_INT(2, (int)blen); /* the database really is empty now */
    if (blen == 2) {
        ASSERT_MEM_EQ(body, "[]", 2);
    }
    finish(&admin, ast, &r);

    cloak_session_release_stream(&user.sesh, st);
    client_session_close(&user);
    client_session_close(&admin);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 3. AN ADMIN SESSION AND PROXY SESSIONS, CONCURRENTLY                 */
/* ------------------------------------------------------------------ */

/* Two proxy sessions for two different database users and one admin
 * session, all live at the same time on one reactor, one registry and one
 * cloak_usermanager_t.
 *
 * WHAT THIS ASSERTS THAT CASE 1 DOES NOT: that the admin API's work is
 * interleaved with proxy traffic rather than serialised behind it (a GET
 * issued while two relays are live is answered, and the relays carry
 * bytes after it), that each relay keeps its OWN bytes (the two upstream
 * connections are compared separately -- a crossed pair would be a
 * catastrophic and otherwise invisible bug), and that the accounting
 * separates them: after one cycle both database users are charged and the
 * admin UID still has no row at all. */
static void test_admin_and_proxy_sessions_run_concurrently(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "concur"));

    uint8_t uid_a[CLOAK_UID_LEN];
    uint8_t uid_b[CLOAK_UID_LEN];
    mk_uid(uid_a, 0x51);
    mk_uid(uid_b, 0x52);

    client_session_t admin;
    ASSERT_EQ_INT(0, open_admin(&fx, &admin));
    ASSERT_EQ_INT(201, admin_create_user(&fx, &admin, uid_a, AE_USER_JSON, NULL, 0));
    ASSERT_EQ_INT(201, admin_create_user(&fx, &admin, uid_b, AE_USER_JSON, NULL, 0));

    client_session_t ca, cb;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &ca, uid_a, "ss", 11));
    ASSERT_EQ_INT(0, open_client_pm(&fx, &cb, uid_b, "ss", 12));
    ASSERT_EQ_INT(2, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&fx.api));
    /* A, B and the admin UID (a bypass user). */
    ASSERT_EQ_INT(3, (int)cloak_userpanel_active_count(fx.panel));

    cloak_stream_t *sa = cloak_session_open_stream(&ca.sesh, NULL);
    cloak_stream_t *sb = cloak_session_open_stream(&cb.sesh, NULL);
    ASSERT_TRUE(sa != NULL);
    ASSERT_TRUE(sb != NULL);
    if (sa == NULL || sb == NULL) {
        client_session_close(&cb);
        client_session_close(&ca);
        client_session_close(&admin);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(6, (int)cloak_stream_write(sa, (const uint8_t *)"AAAAAA", 6));
    ASSERT_EQ_INT(6, (int)cloak_stream_write(sb, (const uint8_t *)"BBBBBB", 6));
    struct up_wait ua = {&fx.up, 0, 6};
    struct up_wait ub = {&fx.up, 1, 6};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &ua, 400, 5));
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &ub, 400, 5));
    ASSERT_EQ_INT(2, fx.up.accept_count);
    ASSERT_MEM_EQ(fx.up.conns[0].in, "AAAAAA", 6);
    ASSERT_MEM_EQ(fx.up.conns[1].in, "BBBBBB", 6);

    /* An admin request WHILE both relays are live. */
    resp_t r;
    cloak_stream_t *ast = request(&fx, &admin, "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n",
                                  &r);
    ASSERT_EQ_INT(200, resp_status(&r));
    size_t blen = 0;
    const char *body = resp_body(&r, &blen);
    /* The listing is exactly the codec's own rendering of the two rows,
     * bracketed and comma-joined -- byte for byte, which is what a real
     * `ck-client -a` compares. */
    cloak_user_info_t rows[2];
    size_t got = 0;
    memset(rows, 0, sizeof(rows));
    ASSERT_EQ_INT(0, cloak_usermanager_list(fx.mgr, rows, 2, &got));
    ASSERT_EQ_INT(2, (int)got);
    char want[2 * CLOAK_USER_JSON_MAX + 4];
    size_t wlen = 0;
    want[wlen++] = '[';
    for (size_t i = 0; i < got; i++) {
        char one[CLOAK_USER_JSON_MAX];
        size_t one_len = 0;
        if (i > 0) {
            want[wlen++] = ',';
        }
        ASSERT_EQ_INT(0, cloak_user_json_encode(&rows[i], CLOAK_USER_FIELD_ALL, one, sizeof(one),
                                                &one_len));
        memcpy(want + wlen, one, one_len);
        wlen += one_len;
    }
    want[wlen++] = ']';
    ASSERT_EQ_INT((int)wlen, (int)blen);
    if (blen == wlen) {
        ASSERT_MEM_EQ(body, want, wlen);
    }
    finish(&admin, ast, &r);

    /* Both relays still carry their own bytes AFTER the admin request. */
    ASSERT_EQ_INT(4, (int)cloak_stream_write(sa, (const uint8_t *)"aaaa", 4));
    ASSERT_EQ_INT(4, (int)cloak_stream_write(sb, (const uint8_t *)"bbbb", 4));
    ua.want = 10;
    ub.want = 10;
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &ua, 400, 5));
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &ub, 400, 5));
    ASSERT_MEM_EQ(fx.up.conns[0].in, "AAAAAAaaaa", 10);
    ASSERT_MEM_EQ(fx.up.conns[1].in, "BBBBBBbbbb", 10);

    /* The accounting separates the three. One cycle charges A and B for
     * the bytes they moved; the admin UID is a bypass user and has no row
     * for the cycle to write to -- not a full-credit row, NONE. */
    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(fx.panel));
    cloak_user_info_t ra, rb;
    memset(&ra, 0, sizeof(ra));
    memset(&rb, 0, sizeof(rb));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.mgr, uid_a, &ra));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.mgr, uid_b, &rb));
    ASSERT_TRUE(ra.up_credit < AE_USER_CREDIT);
    ASSERT_TRUE(rb.up_credit < AE_USER_CREDIT);
    ASSERT_TRUE(ra.up_credit > 0); /* still authorised -- not a termination */
    ASSERT_TRUE(rb.up_credit > 0);
    ASSERT_TRUE(user_row_absent(fx.mgr, fx.uid_admin));
    /* Nothing was terminated by that cycle. */
    ASSERT_EQ_INT(3, (int)cloak_userpanel_active_count(fx.panel));
    ASSERT_EQ_INT(2, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&fx.api));

    cloak_session_release_stream(&ca.sesh, sa);
    cloak_session_release_stream(&cb.sesh, sb);
    client_session_close(&cb);
    client_session_close(&ca);
    client_session_close(&admin);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 4. THE SECOND SQLITE WRITER                                          */
/* ------------------------------------------------------------------ */

/* WHY THIS MODULE IS THE REASON usermanager.c KEEPS ITS BUSY BRANCHES.
 * cloak_usermanager_t opens with busy_timeout = 0 on purpose: a second
 * writer must cost one drain of metering, never an authorisation outage
 * and never a reactor stall. Before this module existed the only second
 * writer was an operator's sqlite3 CLI; the admin API makes it a
 * first-class, in-process, attacker-triggerable one.
 *
 * WHAT THIS CASE ACTUALLY REACHES, stated honestly because "SQLITE_BUSY
 * on COMMIT" is what the user-manager branch's annotated ROLLBACK and
 * self-heal branches guard, and this does NOT reach them:
 *   - cloak_usermanager_write -> um_run(UM_ST_WRITE) -> SQLITE_BUSY ->
 *     CLOAK_USER_ERR_DB, surfacing as the admin API's 500 "user database
 *     error" path in adminapi_handle_post. THIS is what the case drives.
 *   - cloak_usermanager_upload_status -> um_run(UM_ST_BEGIN) fails and
 *     RETURNS BEFORE the transaction is open, so neither the `fail:`
 *     ROLLBACK nor the next call's self-heal is entered.
 * Neither annotated branch is reachable from a second writer at all: an
 * external BEGIN IMMEDIATE holds the write lock for its whole life, so
 * this manager's own BEGIN IMMEDIATE never succeeds and there is no open
 * transaction for a COMMIT to fail out of. usermanager.c says so itself
 * ("SQLite abandons the transaction by itself for every failure this
 * statement set can actually produce"), and this case confirms it from
 * the composition rather than contradicting it.
 *
 * WHAT DEGRADING CLEANLY MEANS, all four asserted:
 *   - a clean error to the client: 500 with the module's own body, not a
 *     dropped stream and not a lie;
 *   - the reactor never stalled: a proxy relay keeps moving bytes DURING
 *     the locked window, and the admin exchange completes inside a
 *     bounded pump whose elapsed time is measured;
 *   - no corruption: the refused POST left no row, and the failed upload
 *     kept its queue -- the very next successful cycle charges the whole
 *     amount, not a partial one;
 *   - recovery: once the lock is released the same request succeeds. */
static void test_second_writer_degrades_cleanly(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "busy"));

    uint8_t uid_live[CLOAK_UID_LEN];
    uint8_t uid_new[CLOAK_UID_LEN];
    mk_uid(uid_live, 0x61);
    mk_uid(uid_new, 0x62);

    client_session_t admin;
    ASSERT_EQ_INT(0, open_admin(&fx, &admin));
    ASSERT_EQ_INT(201, admin_create_user(&fx, &admin, uid_live, AE_USER_JSON, NULL, 0));

    client_session_t user;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &user, uid_live, "ss", 21));
    cloak_stream_t *st = cloak_session_open_stream(&user.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&user);
        client_session_close(&admin);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(6, (int)cloak_stream_write(st, (const uint8_t *)"pre!!!", 6));
    struct up_wait uw = {&fx.up, 0, 6};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));

    /* ---- the second writer takes the lock ---- */
    sqlite3 *other = NULL;
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_open(fx.db_path, &other));
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_exec(other, "BEGIN IMMEDIATE", NULL, NULL, NULL));

    /* A WRITE is refused, cleanly and immediately. */
    uint64_t t0 = now_ms();
    char body[256];
    int status = admin_create_user(&fx, &admin, uid_new, AE_USER_JSON, body, sizeof(body));
    uint64_t elapsed = now_ms() - t0;
    ASSERT_EQ_INT(500, status);
    ASSERT_EQ_INT(0, strcmp(body, "user database error\n"));
    /* NO HANG. busy_timeout is 0, so the refusal is immediate; this bound
     * is three orders of magnitude above what it costs and is here to
     * fail loudly if a busy_timeout ever appears. */
    ASSERT_TRUE(elapsed < 3000);

    /* A READ is unaffected: WAL readers never block on a writer, so the
     * API is not down -- only the write is refused. */
    resp_t lr;
    cloak_stream_t *lst = request(&fx, &admin, "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n",
                                  &lr);
    ASSERT_EQ_INT(200, resp_status(&lr));
    finish(&admin, lst, &lr);

    /* THE REACTOR NEVER STALLED: the proxy relay moves bytes inside the
     * same locked window, on the same single thread that just took a
     * SQLITE_BUSY. */
    ASSERT_EQ_INT(6, (int)cloak_stream_write(st, (const uint8_t *)"mid!!!", 6));
    uw.want = 12;
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_MEM_EQ(fx.up.conns[0].in, "pre!!!mid!!!", 12);
    ASSERT_EQ_INT(0, user.broken);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, uid_live));

    /* The panel's own upload is locked out in the same window -- fails
     * fast, keeps its queue, and evicts nobody. */
    ASSERT_TRUE(cloak_userpanel_upload_now(fx.panel) != 0);
    cloak_userpanel_user_t *lu = cloak_userpanel_find(fx.panel, uid_live);
    ASSERT_TRUE(lu != NULL);
    /* The DRAIN ran even though the COMMIT did not: this user's valve is
     * empty and its bytes are sitting in the panel's queue. That is what
     * makes the recovery assertion at the end of this case exact -- no
     * traffic passes between here and the successful cycle, so the credit
     * can only fall if the failed upload's queue survived it. */
    ASSERT_TRUE(lu != NULL && cloak_userpanel_user_valve(lu) != NULL);
    if (lu != NULL && cloak_userpanel_user_valve(lu) != NULL) {
        ASSERT_EQ_INT(0, (int)cloak_valve_rx(cloak_userpanel_user_valve(lu)));
        ASSERT_EQ_INT(0, (int)cloak_valve_tx(cloak_userpanel_user_valve(lu)));
    }
    cloak_user_info_t mid;
    memset(&mid, 0, sizeof(mid));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.mgr, uid_live, &mid));
    ASSERT_EQ_INT(AE_USER_CREDIT, (int)mid.up_credit); /* nothing was charged */
    /* NO CORRUPTION: the refused POST wrote nothing at all. */
    ASSERT_TRUE(user_row_absent(fx.mgr, uid_new));

    /* ---- the lock goes away ---- */
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_exec(other, "ROLLBACK", NULL, NULL, NULL));
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_close(other));

    /* RECOVERY: the identical request now succeeds. */
    ASSERT_EQ_INT(201, admin_create_user(&fx, &admin, uid_new, AE_USER_JSON, NULL, 0));
    ASSERT_TRUE(user_row_present(fx.mgr, uid_new));

    /* THE KEPT QUEUE IS NOT LOST. No proxy traffic has passed since the
     * failed cycle drained this user's valve to zero (asserted above), so
     * the only bytes the cycle below can charge are the ones that failed
     * cycle queued. A queue discarded on failure -- which is what Go does
     * -- leaves this credit exactly where it started. */
    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(fx.panel));
    cloak_user_info_t after;
    memset(&after, 0, sizeof(after));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.mgr, uid_live, &after));
    ASSERT_TRUE(after.up_credit < AE_USER_CREDIT);
    ASSERT_TRUE(after.up_credit > 0);
    ASSERT_TRUE(cloak_userpanel_find(fx.panel, uid_live) != NULL);

    cloak_session_release_stream(&user.sesh, st);
    client_session_close(&user);
    client_session_close(&admin);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 5. CLEAN SHUTDOWN WITH A REQUEST IN FLIGHT                           */
/* ------------------------------------------------------------------ */

/* THE SHUTDOWN A BINARY PERFORMS, with work still outstanding at every
 * layer: an admin session context, a half-sent admin request (a live
 * parser and an ARMED deadline timer), a second admin stream the server
 * has already answered and closed but the client has not yet released,
 * and a live proxy relay with an accepted upstream connection.
 *
 * WHAT IS *NOT* HERE, said plainly rather than implied by a comment that
 * overclaims: no response is mid-drain. Producing that state needs a
 * 20 KiB connection pool, a shrunken client SO_RCVBUF and a seeded
 * thousand-row listing, and test_adminapi.c already drives exactly that
 * against both a broken session and a write-half deadline. Reproducing
 * it here would buy a third copy of the same coverage at the price of
 * this file's only socket-buffer-sensitive assertion.
 *
 * THE ORDER IS THE POINT and it is not the reverse of construction:
 *
 *     listener -> dispatcher -> proxy -> adminapi -> registry -> panel
 *              -> usermanager -> server
 *
 * The proxy and the adminapi must come BEFORE the registry, because
 * releasing a stream requires a live session (cloak/adminapi.h and
 * cloak/proxy.h both say so); the panel must come AFTER it, because it
 * frees every active user's valve without closing anybody's sessions.
 *
 * THE DETECTOR IS ASAN, AND IT IS GIVEN A REAL CHANCE. The request
 * timeout is set to 300 ms and the reactor is pumped past it AFTER the
 * whole stack is gone: a deadline the adminapi failed to cancel would
 * fire here, against a cloak_stream_t and a context both freed. The pump
 * asserts that it really did outrun the deadline rather than assuming
 * it. With the teardown correct nothing happens at all. */
static void test_clean_shutdown_with_a_request_in_flight(void) {
    struct fixture fx;
    fixture_opts_t o;
    memset(&o, 0, sizeof(o));
    /* Short enough that the post-teardown pump below provably outruns it,
     * long enough that it cannot expire before the teardown in a slow
     * run: everything between the writes below and the teardown is a
     * bounded pump of a few tens of milliseconds. */
    o.request_timeout_ms = 300;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "shutdown", &o));

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x71);

    client_session_t admin;
    ASSERT_EQ_INT(0, open_admin(&fx, &admin));
    ASSERT_EQ_INT(201, admin_create_user(&fx, &admin, uid, AE_USER_JSON, NULL, 0));

    /* A live proxy relay. */
    client_session_t user;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &user, uid, "ss", 31));
    cloak_stream_t *pst = cloak_session_open_stream(&user.sesh, NULL);
    ASSERT_TRUE(pst != NULL);
    if (pst == NULL) {
        client_session_close(&user);
        client_session_close(&admin);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(6, (int)cloak_stream_write(pst, (const uint8_t *)"live!!", 6));
    struct up_wait uw = {&fx.up, 0, 6};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    /* ONE ADMIN SESSION IS ALL THERE CAN EVER BE, and it is worth stating
     * here because a reader looking for "a second admin session" will not
     * find one: the admin decision is (uid == AdminUID AND session_id ==
     * 0), so the admin UID has exactly one session id that reaches this
     * module and every other session id it opens is an ordinary proxy
     * session. Concurrency for the admin API is therefore many STREAMS on
     * one session, which is what this case holds. */
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&fx.api));

    /* An admin request that STOPS MID-HEADERS: parser, context and
     * deadline all stay live for as long as the session does. */
    cloak_stream_t *a1 = cloak_session_open_stream(&admin.sesh, NULL);
    ASSERT_TRUE(a1 != NULL);
    if (a1 == NULL) {
        client_session_close(&user);
        client_session_close(&admin);
        fixture_destroy(&fx);
        return;
    }
    const char *partial = "GET /admin/users HTTP/1.1\r\nHost: admin\r\n";
    ASSERT_EQ_INT((int)strlen(partial),
                  (int)cloak_stream_write(a1, (const uint8_t *)partial, strlen(partial)));

    /* A second admin stream carrying a COMPLETE request. It is driven to
     * completion below, which is what makes the stream-context count at
     * teardown exact rather than "at least one": the server answers this
     * one and tears its context down, leaving precisely the half-sent
     * request's context behind. */
    cloak_stream_t *a2 = cloak_session_open_stream(&admin.sesh, NULL);
    ASSERT_TRUE(a2 != NULL);
    if (a2 == NULL) {
        cloak_session_release_stream(&admin.sesh, a1);
        client_session_close(&user);
        client_session_close(&admin);
        fixture_destroy(&fx);
        return;
    }
    resp_t r2;
    resp_init(&r2, a2);
    ASSERT_TRUE(r2.buf != NULL);
    const char *whole = "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n";
    ASSERT_EQ_INT((int)strlen(whole),
                  (int)cloak_stream_write(a2, (const uint8_t *)whole, strlen(whole)));

    /* Driving a2 to a complete response settles it: its context is gone.
     * What remains is EXACTLY the half-sent request's context, asserted
     * as a number so that a future change which quietly leaves a second
     * one behind fails here instead of being absorbed. */
    ASSERT_TRUE(pump_until(fx.reactor, resp_complete, &r2, 600, 5));
    ASSERT_EQ_INT(200, resp_status(&r2));
    ASSERT_EQ_INT(1, (int)cloak_adminapi_stream_count(&fx.api));
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&fx.api));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    /* ---- THE SHUTDOWN, with all of that outstanding ---- */
    uint64_t t0 = now_ms();
    fixture_destroy_stack(&fx);
    ASSERT_EQ_INT(0, (int)cloak_adminapi_stream_count(&fx.api));
    ASSERT_EQ_INT(0, (int)cloak_adminapi_session_count(&fx.api));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

    /* PAST THE 300 ms DEADLINE, deliberately, with the stack gone. The
     * elapsed time is asserted, not assumed. */
    while (now_ms() - t0 < 500) {
        cloak_reactor_run_once(fx.reactor, 10);
    }
    ASSERT_TRUE(now_ms() - t0 >= 300);

    /* The upstream pushing at a relay that is gone, for the same reason
     * as above: nothing freed may be touched. */
    (void)ae_up_send(&fx.up, 0, "after-the-free", 14);
    for (int i = 0; i < 40; i++) {
        cloak_reactor_run_once(fx.reactor, 2);
    }

    /* The client sessions are still alive on the reactor, exactly as a
     * remote client would be when a server exits; they are destroyed
     * before the reactor is. */
    resp_free(&r2);
    cloak_session_release_stream(&admin.sesh, a2);
    cloak_session_release_stream(&admin.sesh, a1);
    cloak_session_release_stream(&user.sesh, pst);
    client_session_close(&user);
    client_session_close(&admin);
    fixture_destroy_rest(&fx);
}

TEST_MAIN_BEGIN()
    test_admin_creates_a_user_who_then_proxies();
    test_delete_does_not_evict_until_the_next_upload_cycle();
    test_admin_and_proxy_sessions_run_concurrently();
    test_second_writer_degrades_cleanly();
    test_clean_shutdown_with_a_request_in_flight();
TEST_MAIN_END()
