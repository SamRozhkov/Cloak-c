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
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
#include "test_framework.h"
#include "client_harness.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* THE ADMIN SESSION, DECIDED IN THE DISPATCHER AND ASSEMBLED BY AN OWNER.
 *
 * Task 5's whole subject is one branch: a connection whose UID is the
 * server's AdminUID AND whose session id is 0 is an ADMIN session, and
 * that decision is made BEFORE dispatcher_authenticate's step 7 (the
 * proxy-method check) so that an admin session skips it entirely. Go
 * takes the same branch at internal/server/dispatcher.go:202, before its
 * own ProxyBook lookup at :217, and the position is load-bearing there
 * for the reason it is here: ck-client in admin mode (-a) sends whatever
 * ProxyMethod its config file names -- "shadowsocks" by default -- so an
 * operator whose client config names a method THIS server does not offer
 * would otherwise be locked out of administering it.
 *
 * THE STACK IS REAL. A SQLite-backed cloak_usermanager_t, a
 * cloak_userpanel_t over it, a cloak_server_registry_t, a cloak_proxy_t,
 * a cloak_adminapi_t, a cloak_dispatcher_t, a listener, a fake upstream
 * and a fake cover site -- wired exactly as cloak/adminapi.h's WIRING
 * block says a binary must wire them, including the four-link
 * broken-session chain. Nothing here is a mock.
 *
 * EVERY REFUSAL IS ASSERTED AGAINST THE COVER SITE'S OWN BYTES, the
 * discipline test_dispatcher_users.c states: "refused" means "received
 * exactly what a connection this server has no opinion about receives",
 * not "received something other than a ServerHello".
 *
 * EVERY WAIT IS A BOUNDED pump_until (client_harness.h). */

/* ------------------------------------------------------------------ */
/* Database scaffolding (test_usermanager.c's / test_dispatcher_users.c's)*/
/* ------------------------------------------------------------------ */

static void da_tmp_path(char *buf, size_t cap, const char *tag) {
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(buf, cap, "%s/cloak_da_%ld_%s.db", dir, (long)getpid(), tag);
}

/* WAL leaves sidecars; a survivor would carry committed credit from a
 * previous run into this one and make a billing assertion pass or fail
 * for reasons unrelated to the code under test. */
static void da_unlink(const char *path) {
    char aux[512];
    unlink(path);
    snprintf(aux, sizeof(aux), "%s-wal", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-shm", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-journal", path);
    unlink(aux);
}

#define T_NOW 1600000000
#define T_EXPIRY (T_NOW + 100000)
#define START_CREDIT 10000000

static int64_t da_now(void *userdata) {
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
    memset(uid, 0xC0, CLOAK_UID_LEN);
    uid[0] = seed;
}

static void put_user(cloak_usermanager_t *m, const uint8_t *uid, int32_t cap, int64_t up_credit,
                     int64_t down_credit, int64_t expiry) {
    cloak_user_info_t u;
    memset(&u, 0, sizeof(u));
    memcpy(u.uid, uid, CLOAK_UID_LEN);
    u.sessions_cap = cap;
    u.up_credit = up_credit;
    u.down_credit = down_credit;
    u.expiry_time = expiry;
    ASSERT_EQ_INT(0, cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL));
}

/* ------------------------------------------------------------------ */
/* Fake cover site: answers every connection with the same fixed bytes   */
/* ------------------------------------------------------------------ */

static const char DA_BANNER[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
#define DA_BANNER_LEN (sizeof(DA_BANNER) - 1)

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
    ssize_t n = write(fd, DA_BANNER, DA_BANNER_LEN);
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

#define DA_UP_MAX 8
#define DA_UP_CAP ((size_t)16384)

typedef struct {
    int fd;
    uint8_t in[DA_UP_CAP];
    size_t in_len;
} da_up_conn_t;

struct da_upstream;
typedef struct {
    struct da_upstream *up;
    int idx;
} da_up_slot_t;

typedef struct da_upstream {
    cloak_reactor_t *reactor;
    int accept_count;
    da_up_conn_t conns[DA_UP_MAX];
    da_up_slot_t slots[DA_UP_MAX];
} da_upstream_t;

static void da_up_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    (void)events;
    da_up_slot_t *slot = userdata;
    da_up_conn_t *c = &slot->up->conns[slot->idx];
    for (;;) {
        if (c->in_len >= DA_UP_CAP) {
            return;
        }
        ssize_t n = read(c->fd, c->in + c->in_len, DA_UP_CAP - c->in_len);
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

static void da_up_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    da_upstream_t *up = userdata;
    if (up->accept_count >= DA_UP_MAX) {
        close(fd);
        return;
    }
    int idx = up->accept_count++;
    up->conns[idx].fd = fd;
    up->slots[idx].up = up;
    up->slots[idx].idx = idx;
    (void)cloak_reactor_add_fd(up->reactor, fd, CLOAK_REACTOR_READABLE, da_up_on_readable,
                               &up->slots[idx]);
}

/* Callers that push bytes at an upstream whose relay has already been
 * stopped EXPECT this to fail (the relay closed the socket), so the
 * result is deliberately not asserted there. */
static ssize_t da_up_send(da_upstream_t *up, int idx, const void *data, size_t len) {
    return send(up->conns[idx].fd, data, len, MSG_NOSIGNAL);
}

static void da_up_destroy(da_upstream_t *up) {
    for (int i = 0; i < DA_UP_MAX; i++) {
        if (up->conns[i].fd >= 0) {
            cloak_reactor_remove_fd(up->reactor, up->conns[i].fd);
            close(up->conns[i].fd);
            up->conns[i].fd = -1;
        }
    }
}

struct up_wait {
    da_upstream_t *up;
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

/* THE FLAG'S CONTRACT, RECORDED AT ITS ONLY CONSUMER. is_admin is the
 * dispatcher's own answer, computed once in dispatcher_authenticate and
 * handed to the owner rather than re-derived by it -- so this record is
 * what proves the two never disagree: every case below asserts the branch
 * the owner took AND the end-to-end behaviour the dispatcher produced for
 * the same connection. */
struct prep_record {
    int calls;
    int admin_calls;
    int proxy_calls;
    int last_is_admin;
    uint32_t last_session_id;
    uint8_t last_uid[CLOAK_UID_LEN];
    /* config->valve as it stood when prepare_session ran: the dispatcher
     * has already installed the authorised user's meter by then (step
     * 8b), so this is where "the admin session is not metered" is
     * observable at all. */
    const cloak_valve_t *last_valve;
    const cloak_valve_t *last_admin_valve;
};

/* ------------------------------------------------------------------ */
/* The owner's own link of the broken-session chain                     */
/* ------------------------------------------------------------------ */

/* THE LAST LINK, and the probe that makes the other three observable.
 *
 * cloak_userpanel_config_t::chain is the slot cloak/userpanel.h reserves
 * for the owner, so a probe here is the wiring a binary uses and not an
 * inserted trampoline. It samples, AT THE MOMENT IT RUNS, everything the
 * three module links ahead of it were supposed to have already done:
 * every count it reads being at its expected value is what "the chain ran
 * before the owner did" means, and a link that had been skipped leaves
 * its own count untouched.
 *
 * Note that it samples the whole module's counts, not this session's:
 * neither module exposes a per-(uid, session_id) accessor. The chain case
 * below therefore breaks its two sessions one at a time, so that each
 * call's expected counts are exact rather than "whatever else is still
 * alive". */
struct chain_probe {
    int calls;
    cloak_proxy_t *proxy;
    cloak_adminapi_t *api;
    cloak_userpanel_t *panel;

    size_t proxy_sessions_at_call[4];
    size_t proxy_streams_at_call[4];
    size_t api_sessions_at_call[4];
    size_t api_streams_at_call[4];
    size_t active_users_at_call[4];
    uint32_t session_id_at_call[4];
    uint8_t uid_at_call[4][CLOAK_UID_LEN];
    /* Was this link handed a session pointer at all? cloak/userpanel.h:
     * the panel NULLs it whenever its own termination destroyed that
     * session, which is exactly the case a broken LAST session produces.
     * Recorded rather than dereferenced -- the point is that there is
     * nothing here to dereference. */
    int sesh_null_at_call[4];
};

static void owner_chain_cb(cloak_server_registry_t *reg, cloak_session_t *sesh,
                           const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id, void *userdata) {
    (void)reg;
    struct chain_probe *pr = userdata;
    int i = pr->calls;
    pr->calls++;
    if (i < 0 || i >= 4) {
        return;
    }
    pr->proxy_sessions_at_call[i] = cloak_proxy_session_count(pr->proxy);
    pr->proxy_streams_at_call[i] = cloak_proxy_stream_count(pr->proxy);
    pr->api_sessions_at_call[i] = cloak_adminapi_session_count(pr->api);
    pr->api_streams_at_call[i] = cloak_adminapi_stream_count(pr->api);
    pr->active_users_at_call[i] = cloak_userpanel_active_count(pr->panel);
    pr->session_id_at_call[i] = session_id;
    pr->sesh_null_at_call[i] = sesh == NULL;
    if (uid != NULL) {
        memcpy(pr->uid_at_call[i], uid, CLOAK_UID_LEN);
    }
}

struct chain_calls_wait {
    struct chain_probe *pr;
    int want;
};

static int chain_calls_at_least(void *ctx) {
    struct chain_calls_wait *w = ctx;
    return w->pr->calls >= w->want;
}

struct api_count_wait {
    cloak_adminapi_t *api;
    size_t want;
};

static int api_streams_eq(void *ctx) {
    struct api_count_wait *w = ctx;
    return cloak_adminapi_stream_count(w->api) == w->want;
}

/* ------------------------------------------------------------------ */
/* The fixture                                                          */
/* ------------------------------------------------------------------ */

struct fixture {
    cloak_reactor_t *reactor;

    redir_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;

    da_upstream_t up;
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

    cloak_userpanel_t *panel; /* NULL in the no-panel fixture */

    cloak_proxy_t proxy;
    int proxy_ready;

    cloak_adminapi_t api;
    int api_ready; /* 0 in the pre-adminapi fixture */

    cloak_dispatcher_t d;
    int d_ready;

    cloak_listener_t front;
    int have_front;

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_admin[CLOAK_UID_LEN];
    uint8_t uid_bypass[CLOAK_UID_LEN];

    struct prep_record prep;
    struct chain_probe chain;
};

/* THE OWNER'S prepare_session, in exactly the shape cloak/adminapi.h's
 * WIRING block gives -- one branch on the dispatcher's own flag, no
 * second definition of what "admin" means anywhere in this file. */
static int fx_prepare_session(cloak_dispatcher_t *d, const cloak_server_clientinfo_t *info,
                              cloak_session_config_t *config, void *userdata) {
    struct fixture *fx = userdata;
    fx->prep.calls++;
    fx->prep.last_is_admin = info->is_admin;
    fx->prep.last_session_id = info->session_id;
    fx->prep.last_valve = config->valve;
    memcpy(fx->prep.last_uid, info->uid, CLOAK_UID_LEN);
    if (info->is_admin) {
        fx->prep.admin_calls++;
        fx->prep.last_admin_valve = config->valve;
        return cloak_adminapi_prepare_session(&fx->api, info->uid, info->session_id, config);
    }
    fx->prep.proxy_calls++;
    return cloak_proxy_prepare_session(d, info, config, &fx->proxy);
}

/* The PRE-ADMINAPI owner: the exact prepare_session every caller used
 * before this module existed, recording the flag but ignoring it. Case 8
 * is what it exists for. */
static int fx_prepare_session_proxy_only(cloak_dispatcher_t *d,
                                         const cloak_server_clientinfo_t *info,
                                         cloak_session_config_t *config, void *userdata) {
    struct fixture *fx = userdata;
    fx->prep.calls++;
    fx->prep.last_is_admin = info->is_admin;
    fx->prep.last_session_id = info->session_id;
    fx->prep.last_valve = config->valve;
    memcpy(fx->prep.last_uid, info->uid, CLOAK_UID_LEN);
    fx->prep.proxy_calls++;
    return cloak_proxy_prepare_session(d, info, config, &fx->proxy);
}

/* Both modules' abandoned-session reclaimers, from the one dispatcher
 * hook there is: cloak/adminapi.h's cloak_adminapi_session_aborted
 * paragraph requires an owner running both to call both. */
static void fx_session_aborted(cloak_dispatcher_t *d, const uint8_t uid[CLOAK_UID_LEN],
                               uint32_t session_id, void *userdata) {
    struct fixture *fx = userdata;
    cloak_proxy_session_aborted(d, uid, session_id, &fx->proxy);
    if (fx->api_ready) {
        cloak_adminapi_session_aborted(&fx->api, uid, session_id);
    }
}

/* cloak/userpanel.h's WIRING obligation 3: a termination closes sessions
 * by UID, which fires no on_broken, so the proxy's relays must be stopped
 * through this hook instead. */
static void fx_session_closing(const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    struct fixture *fx = userdata;
    cloak_proxy_session_aborted(NULL, uid, session_id, &fx->proxy);
    if (fx->api_ready) {
        cloak_adminapi_session_aborted(&fx->api, uid, session_id);
    }
}

typedef struct {
    /* Omits AdminUID from the config entirely; uid_admin is then listed
     * in BypassUID instead, so it still authenticates and the ONLY thing
     * that changed is whether the server has an admin identity at all. */
    int no_admin_uid;
    /* No cloak_adminapi_t and no admin branch in prepare_session: the
     * owner every pre-adminapi caller was. */
    int no_api;
    /* No panel at all: cloak_server_is_bypass is the whole authorisation
     * policy, as it was before a user manager existed. */
    int no_panel;
    /* 0 -> cloak_adminapi_t's own default. */
    uint64_t request_timeout_ms;
} fixture_opts_t;

static int fixture_init_opts(struct fixture *fx, const char *tag, const fixture_opts_t *o) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    for (int i = 0; i < DA_UP_MAX; i++) {
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
                                         da_up_on_accept, &fx->up, err, sizeof(err)));
    fx->have_up_listener = 1;
    fx->up_port = cloak_listener_port(&fx->up_listener);
    ASSERT_TRUE(fx->up_port > 0);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, fx->server_pub));
    mk_uid(fx->uid_admin, 0x11);
    mk_uid(fx->uid_bypass, 0x22);

    char priv_b64[64];
    char admin_b64[32];
    char bypass_b64[32];
    ASSERT_EQ_INT(
        0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64, sizeof(priv_b64)));
    ASSERT_EQ_INT(
        0, cloak_base64_encode(fx->uid_admin, CLOAK_UID_LEN, admin_b64, sizeof(admin_b64)));
    ASSERT_EQ_INT(
        0, cloak_base64_encode(fx->uid_bypass, CLOAK_UID_LEN, bypass_b64, sizeof(bypass_b64)));

    /* ONE proxy method is offered, "ss". Every case that wants the
     * proxy-method check to refuse asks for "nosuch" instead -- which is
     * precisely the shape of the lock-out D1 describes: a real ck-client
     * -a sends whatever ProxyMethod its config names, and this server
     * does not offer it. */
    char json[1024];
    if (o->no_admin_uid) {
        snprintf(json, sizeof(json),
                 "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:%d\"]},"
                 "\"BindAddr\":[\"127.0.0.1:0\"],\"RedirAddr\":\"127.0.0.1:%d\","
                 "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\",\"%s\"]}",
                 fx->up_port, cover_port, priv_b64, bypass_b64, admin_b64);
    } else {
        snprintf(json, sizeof(json),
                 "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:%d\"]},"
                 "\"BindAddr\":[\"127.0.0.1:0\"],\"RedirAddr\":\"127.0.0.1:%d\","
                 "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\"],\"AdminUID\":\"%s\"}",
                 fx->up_port, cover_port, priv_b64, bypass_b64, admin_b64);
    }
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    da_tmp_path(fx->db_path, sizeof(fx->db_path), tag);
    da_unlink(fx->db_path);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_usermanager_open(&fx->mgr, fx->db_path, da_now, NULL, err, sizeof(err)));
    ASSERT_TRUE(fx->mgr != NULL);
    if (fx->mgr == NULL) {
        return -1;
    }

    /* CONSTRUCTION ORDER, the one a binary must use and the one
     * test_dispatcher_users.c explains: the registry's on_broken userdata
     * is the proxy's ADDRESS (stored, never dereferenced until a session
     * breaks), so the registry comes first; the panel needs the registry;
     * the proxy's chain userdata needs the adminapi's address and the
     * adminapi's chain userdata needs the panel. */
    ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor,
                                                cloak_proxy_registry_broken, &fx->proxy));
    fx->registry_ready = 1;

    if (!o->no_panel) {
        cloak_userpanel_config_t pcfg;
        memset(&pcfg, 0, sizeof(pcfg));
        pcfg.manager = fx->mgr;
        pcfg.registry = &fx->registry;
        pcfg.reactor = fx->reactor;
        pcfg.upload_interval_ms = 3600000; /* nothing here wants the periodic cycle */
        pcfg.now_fn = da_now;
        pcfg.on_session_closing = fx_session_closing;
        pcfg.on_session_closing_userdata = fx;
        /* THE OWNER'S OWN LINK -- the last one, and the probe every
         * assertion about the chain's order reads. */
        pcfg.chain = owner_chain_cb;
        pcfg.chain_userdata = &fx->chain;
        ASSERT_EQ_INT(0, cloak_userpanel_open(&fx->panel, &pcfg));
        ASSERT_TRUE(fx->panel != NULL);
        if (fx->panel == NULL) {
            return -1;
        }
    }

    fx->chain.proxy = &fx->proxy;
    fx->chain.api = &fx->api;
    fx->chain.panel = fx->panel;

    if (!o->no_api) {
        cloak_adminapi_config_t acfg;
        memset(&acfg, 0, sizeof(acfg));
        acfg.reactor = fx->reactor;
        acfg.manager = fx->mgr;
        acfg.request_timeout_ms = o->request_timeout_ms;
        /* LINK 3: adminapi -> panel. */
        acfg.chain = cloak_userpanel_registry_broken;
        acfg.chain_userdata = fx->panel;
        ASSERT_EQ_INT(0, cloak_adminapi_init(&fx->api, &acfg));
        fx->api_ready = 1;
    }

    cloak_proxy_config_t pxcfg;
    memset(&pxcfg, 0, sizeof(pxcfg));
    pxcfg.reactor = fx->reactor;
    pxcfg.srv = &fx->srv;
    /* LINK 2: proxy -> adminapi, or straight to the panel on a server
     * that has no admin API (cloak/userpanel.h's WIRING block says so in
     * as many words). */
    if (fx->api_ready) {
        pxcfg.chain = cloak_adminapi_registry_broken;
        pxcfg.chain_userdata = &fx->api;
    } else {
        pxcfg.chain = cloak_userpanel_registry_broken;
        pxcfg.chain_userdata = fx->panel;
    }
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

    dcfg.prepare_session = fx->api_ready ? fx_prepare_session : fx_prepare_session_proxy_only;
    dcfg.prepare_session_userdata = fx;
    dcfg.session_aborted = fx_session_aborted;
    dcfg.session_aborted_userdata = fx;

    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, fx->cfg.bind_addr[0],
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;
    return 0;
}

static int fixture_init(struct fixture *fx, const char *tag) {
    fixture_opts_t o;
    memset(&o, 0, sizeof(o));
    return fixture_init_opts(fx, tag, &o);
}

/* SHUTDOWN ORDER, which is not the reverse of construction: the proxy and
 * the adminapi BEFORE the registry (both hold stream pointers into live
 * sessions), and the PANEL AFTER the registry (it frees every active
 * user's valve without closing anybody's sessions). */
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
    if (fx->have_up_listener) {
        cloak_listener_close(&fx->up_listener);
        fx->have_up_listener = 0;
    }
    da_up_destroy(&fx->up);
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
        da_unlink(fx->db_path);
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

static int open_client_pm(struct fixture *fx, client_session_t *cs, const uint8_t *uid,
                          const char *proxy_method, uint32_t session_id) {
    cloak_session_config_t ccfg;
    client_config(&ccfg);
    return client_session_open(cs, fx->reactor, front_port(fx), fx->server_pub, uid, proxy_method,
                               session_id, 0, &ccfg);
}

/* ---- the refusal probe (test_dispatcher_users.c's) ---------------------- */

static size_t probe_response(struct fixture *fx, const uint8_t *rec, size_t rec_len, uint8_t *out,
                             size_t cap) {
    size_t want = DA_BANNER_LEN < cap ? DA_BANNER_LEN : cap;
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

static size_t make_record(struct fixture *fx, const uint8_t *uid, const char *proxy_method,
                          uint32_t session_id, uint8_t *out, size_t cap) {
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    return build_client_record(fx->server_pub, uid, proxy_method, (uint8_t)CLOAK_AEAD_AES_256_GCM,
                               (int64_t)time(NULL), session_id, 0, out, cap, shared);
}

/* Asserts that this (uid, proxy_method, session_id) is REFUSED, and
 * refused the way every other unrecognised connection is: the cover
 * site's own bytes, byte for byte. */
static void assert_refused(struct fixture *fx, const uint8_t *uid, const char *proxy_method,
                           uint32_t session_id) {
    uint8_t rec[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t got[128];
    size_t rec_len = make_record(fx, uid, proxy_method, session_id, rec, sizeof(rec));
    ASSERT_TRUE(rec_len > 0);
    size_t n = probe_response(fx, rec, rec_len, got, sizeof(got));
    ASSERT_EQ_INT((int)DA_BANNER_LEN, (int)n);
    ASSERT_MEM_EQ(got, DA_BANNER, DA_BANNER_LEN);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx->registry, uid));
}

/* ---- reading one admin HTTP response off a stream (test_adminapi.c's) --- */

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

static int resp_headers_done(void *ctx) {
    resp_t *r = ctx;
    resp_poll(r);
    return resp_header_end(r) >= 0;
}

static int resp_status(const resp_t *r) {
    if (r->len < 12 || memcmp(r->buf, "HTTP/1.1 ", 9) != 0) {
        return -1;
    }
    return (r->buf[9] - '0') * 100 + (r->buf[10] - '0') * 10 + (r->buf[11] - '0');
}

/* ------------------------------------------------------------------ */
/* 1. D1: the admin UID with session id 0 and an UNOFFERED proxy method */
/* ------------------------------------------------------------------ */

/* THE CASE THE WHOLE TASK EXISTS FOR, and the one that fails if the admin
 * decision is made anywhere at or after dispatcher_authenticate's step 7.
 * "nosuch" is not in this server's ProxyBook, so step 7 would refuse this
 * connection -- and a real `ck-client -a` sends exactly this, because
 * admin mode leaves ProxyMethod at whatever the client's config file
 * says (cmd/ck-client/ck-client.go:159-167).
 *
 * The assertion is not merely "the handshake completed": the admin API
 * answers a real request over the resulting session, so a routing that
 * authenticated the connection and then handed it to the PROXY (whose own
 * prepare_session would have refused an unoffered method, redirecting)
 * fails here too. */
static void test_admin_uid_session_zero_skips_the_proxy_method_check(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "d1"));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &cs, fx.uid_admin, "nosuch", 0));

    /* The dispatcher told the owner, and the owner took the admin
     * branch. */
    ASSERT_EQ_INT(1, fx.prep.calls);
    ASSERT_EQ_INT(1, fx.prep.last_is_admin);
    ASSERT_EQ_INT(1, fx.prep.admin_calls);
    ASSERT_EQ_INT(0, fx.prep.proxy_calls);
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&fx.api));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&fx.registry, fx.uid_admin));

    /* And the session really is the admin API: a real request, answered
     * with a real status line. */
    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    resp_t resp;
    resp_init(&resp, st);
    const char *req = "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n";
    ASSERT_EQ_INT((int)strlen(req),
                  (int)cloak_stream_write(st, (const uint8_t *)req, strlen(req)));
    ASSERT_TRUE(pump_until(fx.reactor, resp_headers_done, &resp, 600, 5));
    ASSERT_EQ_INT(200, resp_status(&resp));

    resp_free(&resp);
    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 2. The admin UID with a NON-ZERO session id is an ordinary session    */
/* ------------------------------------------------------------------ */

/* Go says so in a comment at dispatcher.go:200-202 ("the distinction
 * between going into the admin mode and normal proxy mode is that
 * sessionID needs == 0"), and it is half of the decision: an
 * implementation that tested only the UID would give an administrator's
 * every ordinary session the admin API instead of a proxy.
 *
 * BOTH HALVES OF "ORDINARY" ARE ASSERTED: it is subject to the
 * proxy-method check (an unoffered method is refused, byte for byte like
 * any unrecognised connection), and with an offered method it genuinely
 * proxies -- bytes written to a stream arrive at the upstream. */
static void test_admin_uid_nonzero_session_is_ordinary(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "sid"));

    assert_refused(&fx, fx.uid_admin, "nosuch", 1);
    /* The refusal came from step 7, not from the owner: prepare_session
     * is never reached when step 7 refuses. */
    ASSERT_EQ_INT(0, fx.prep.calls);

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &cs, fx.uid_admin, "ss", 7));
    ASSERT_EQ_INT(1, fx.prep.calls);
    ASSERT_EQ_INT(0, fx.prep.last_is_admin);
    ASSERT_EQ_INT(1, fx.prep.proxy_calls);
    ASSERT_EQ_INT(0, fx.prep.admin_calls);
    ASSERT_EQ_INT(0, (int)cloak_adminapi_session_count(&fx.api));

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
    ASSERT_MEM_EQ(fx.up.conns[0].in, "hello!", 6);
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 3. A NON-admin UID with session id 0 is ordinary                     */
/* ------------------------------------------------------------------ */

/* The other half of the decision. An implementation that tested only the
 * session id would hand the admin API -- every user's credentials, and
 * the power to rewrite them -- to any authenticated user who happened to
 * open session 0, which every client does for its first session. */
static void test_non_admin_uid_session_zero_is_ordinary(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "nonadmin"));

    assert_refused(&fx, fx.uid_bypass, "nosuch", 0);
    ASSERT_EQ_INT(0, fx.prep.calls);

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &cs, fx.uid_bypass, "ss", 0));
    ASSERT_EQ_INT(1, fx.prep.calls);
    ASSERT_EQ_INT(0, fx.prep.last_is_admin);
    ASSERT_EQ_INT(1, fx.prep.proxy_calls);
    ASSERT_EQ_INT(0, (int)cloak_adminapi_session_count(&fx.api));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 4. With no AdminUID configured, nothing takes the admin path         */
/* ------------------------------------------------------------------ */

/* cloak_server_is_admin already returns 0 when has_admin_uid is unset,
 * but "already" is not coverage: this asserts it with the SAME UID that
 * is the admin identity in every other case here, so the only difference
 * between green and red is the config key. */
static void test_no_admin_uid_configured(void) {
    struct fixture fx;
    fixture_opts_t o;
    memset(&o, 0, sizeof(o));
    o.no_admin_uid = 1;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "noadmin", &o));

    assert_refused(&fx, fx.uid_admin, "nosuch", 0);
    ASSERT_EQ_INT(0, fx.prep.calls);

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &cs, fx.uid_admin, "ss", 0));
    ASSERT_EQ_INT(1, fx.prep.calls);
    ASSERT_EQ_INT(0, fx.prep.last_is_admin);
    ASSERT_EQ_INT(0, fx.prep.admin_calls);
    ASSERT_EQ_INT(0, (int)cloak_adminapi_session_count(&fx.api));

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 5. The admin session is not metered and not rate-limited             */
/* ------------------------------------------------------------------ */

/* D6, AND THERE IS NOTHING TO BUILD FOR IT -- which is exactly why it is
 * asserted. Step 6 routes the admin UID (which cloak_server_init folds
 * into the bypass set) through cloak_userpanel_get_bypass_user, whose
 * user carries bypass == 1 and, through cloak_userpanel_user_valve, a
 * NULL valve; cloak/valve.h defines NULL as "not metered", which is also
 * "not rate-limited" since the valve is the only thing either would be
 * expressed in. Go says the same at dispatcher.go:198 ("adminUID can use
 * the server as normal with unlimited QoS credits. The adminUID is not
 * added to the userinfo database").
 *
 * THE CONTRAST IS PART OF THE ASSERTION: a metered database user
 * connecting to the same fixture gets a NON-NULL valve at the same
 * observation point. Without it, "valve == NULL" would also be green if
 * the dispatcher had stopped installing valves altogether. */
static void test_admin_session_is_not_metered(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "meter"));

    uint8_t uid_db[CLOAK_UID_LEN];
    mk_uid(uid_db, 0x33);
    put_user(fx.mgr, uid_db, 4, START_CREDIT, START_CREDIT, T_EXPIRY);

    client_session_t admin;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &admin, fx.uid_admin, "nosuch", 0));
    ASSERT_EQ_INT(1, fx.prep.last_is_admin);
    /* THE ASSERTION: no meter was installed into the admin session's
     * config. */
    ASSERT_TRUE(fx.prep.last_admin_valve == NULL);

    /* The panel agrees, from its own side: the admin UID is active as a
     * BYPASS user, so nothing about it is ever drained or uploaded. */
    cloak_userpanel_user_t *au = cloak_userpanel_find(fx.panel, fx.uid_admin);
    ASSERT_TRUE(au != NULL);
    if (au != NULL) {
        ASSERT_EQ_INT(1, au->bypass);
        ASSERT_TRUE(cloak_userpanel_user_valve(au) == NULL);
    }

    /* The contrast. */
    client_session_t metered;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &metered, uid_db, "ss", 1));
    ASSERT_EQ_INT(0, fx.prep.last_is_admin);
    ASSERT_TRUE(fx.prep.last_valve != NULL);

    /* Traffic through the admin session, and then a real upload cycle. */
    cloak_stream_t *st = cloak_session_open_stream(&admin.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&metered);
        client_session_close(&admin);
        fixture_destroy(&fx);
        return;
    }
    resp_t resp;
    resp_init(&resp, st);
    const char *req = "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n";
    ASSERT_EQ_INT((int)strlen(req),
                  (int)cloak_stream_write(st, (const uint8_t *)req, strlen(req)));
    ASSERT_TRUE(pump_until(fx.reactor, resp_headers_done, &resp, 600, 5));
    ASSERT_EQ_INT(200, resp_status(&resp));

    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(fx.panel));

    /* THE DATABASE IS UNTOUCHED BY THE ADMIN SESSION: the admin UID has
     * no row at all -- not one with full credit, none -- and the only row
     * that exists is the metered user's, which the seed put there. */
    cloak_user_info_t row;
    memset(&row, 0, sizeof(row));
    ASSERT_TRUE(cloak_usermanager_get(fx.mgr, fx.uid_admin, &row) != 0);
    memset(&row, 0, sizeof(row));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.mgr, uid_db, &row));

    resp_free(&resp);
    cloak_session_release_stream(&admin.sesh, st);
    client_session_close(&metered);
    client_session_close(&admin);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 6. THE WHOLE BROKEN-SESSION CHAIN, END TO END                        */
/* ------------------------------------------------------------------ */

/* THE POINT OF THIS TASK, CARRIED FORWARD FROM THE MODULE THAT CREATED
 * THE CHAIN.
 *
 *     registry -> proxy -> adminapi -> panel -> (owner)
 *
 * is assembled by the OWNER, at three separate `chain` assignments plus
 * the registry's own callback, and nothing in the build detects an
 * omission. An owner who writes
 *
 *     cloak_server_registry_init(&reg, r, cloak_userpanel_registry_broken, panel);
 *
 * -- the shape every pre-adminapi caller used, and what a careless
 * copy-paste from the user-manager module produces -- silently skips both
 * the proxy's relay stop and the adminapi's stream release. The symptom
 * is a deadline timer firing on a freed cloak_stream_t under load; the
 * cause is four lines of wiring nobody asserts.
 *
 * ONE cloak_session_t CANNOT BE BOTH a proxy session and an admin one --
 * prepare_session installs ONE set of stream callbacks -- so this case
 * holds both KINDS at once (a live relay to the upstream on one, a live
 * HTTP request with an armed deadline on the other) and breaks them one
 * at a time. Breaking them one at a time is what makes each link's
 * expected counts exact: neither module exposes a per-session accessor,
 * so the owner-link probe reads whole-module counts, and with two
 * simultaneous teardowns "0" would be ambiguous.
 *
 * WHAT EACH ASSERTION DETECTS, link by link (all four mutation-verified;
 * see the task report):
 *   registry -> proxy   : proxy counts still 1 after the relay session
 *                         breaks.
 *   proxy -> adminapi   : adminapi counts still 1 after the admin session
 *                         breaks (and the deadline below then fires on a
 *                         freed stream).
 *   adminapi -> panel   : the panel never learns; its active-user count
 *                         stays put.
 *   panel -> owner      : the probe is never called.
 * "IN ORDER" is asserted as far as it is observable: every count the
 * owner's link reads is already at its post-cleanup value, which is what
 * makes "the three module links ran, and ran before the owner's" true
 * rather than assumed. The relative order of the proxy's link and the
 * adminapi's is NOT observable from here -- both are correct on a live
 * session and neither leaves a trace the other could see -- and it is
 * stated here rather than left to be inferred from a green test. */
static void test_broken_session_chain_runs_every_link(void) {
    struct fixture fx;
    fixture_opts_t o;
    memset(&o, 0, sizeof(o));
    /* A deadline short enough that an adminapi link which never ran would
     * fire its timer against a freed cloak_stream_t inside this case's
     * own final pump (ASan is the detector there), and long enough that
     * it cannot expire before the break in a slow run: everything between
     * the request below and the break is a bounded pump of a few tens of
     * milliseconds. */
    o.request_timeout_ms = 1500;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "chain", &o));

    /* ---- a live PROXY relay ---- */
    client_session_t proxy_cs;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &proxy_cs, fx.uid_bypass, "ss", 3));
    cloak_stream_t *pst = cloak_session_open_stream(&proxy_cs.sesh, NULL);
    ASSERT_TRUE(pst != NULL);
    if (pst == NULL) {
        client_session_close(&proxy_cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(6, (int)cloak_stream_write(pst, (const uint8_t *)"relay!", 6));
    struct up_wait uw = {&fx.up, 0, 6};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    /* ---- a live ADMIN stream, with its deadline armed ---- */
    client_session_t admin_cs;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &admin_cs, fx.uid_admin, "nosuch", 0));
    ASSERT_EQ_INT(1, fx.prep.last_is_admin);
    cloak_stream_t *ast = cloak_session_open_stream(&admin_cs.sesh, NULL);
    ASSERT_TRUE(ast != NULL);
    if (ast == NULL) {
        client_session_close(&admin_cs);
        client_session_close(&proxy_cs);
        fixture_destroy(&fx);
        return;
    }
    /* A request that STOPS mid-headers: the parser, its context and its
     * deadline stay live for as long as the session does, which is what
     * makes the adminapi's link load-bearing at the break. */
    const char *partial = "GET /admin/users HTTP/1.1\r\nHost: admin\r\n";
    ASSERT_EQ_INT((int)strlen(partial),
                  (int)cloak_stream_write(ast, (const uint8_t *)partial, strlen(partial)));

    /* Bounded, and the predicate POLLS the module's own counter, so it
     * cannot miss an edge. */
    struct api_count_wait aw = {&fx.api, 1};
    ASSERT_TRUE(pump_until(fx.reactor, api_streams_eq, &aw, 400, 5));
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&fx.api));
    ASSERT_EQ_INT(1, (int)cloak_adminapi_stream_count(&fx.api));

    /* Both users are active, and nothing has broken yet. */
    ASSERT_EQ_INT(2, (int)cloak_userpanel_active_count(fx.panel));
    ASSERT_EQ_INT(0, fx.chain.calls);

    /* ---- BREAK 1: the proxy session ---- */
    cloak_session_release_stream(&proxy_cs.sesh, pst);
    client_session_close(&proxy_cs);
    struct chain_calls_wait cw = {&fx.chain, 1};
    ASSERT_TRUE(pump_until(fx.reactor, chain_calls_at_least, &cw, 600, 5));
    ASSERT_EQ_INT(1, fx.chain.calls);
    /* LINK 1 (registry -> proxy) ran, and before the owner's link. */
    ASSERT_EQ_INT(0, (int)fx.chain.proxy_sessions_at_call[0]);
    ASSERT_EQ_INT(0, (int)fx.chain.proxy_streams_at_call[0]);
    /* LINK 3 (adminapi -> panel) ran: the panel dropped this UID, whose
     * last session just went away. The admin user is untouched. */
    ASSERT_EQ_INT(1, (int)fx.chain.active_users_at_call[0]);
    ASSERT_TRUE(cloak_userpanel_find(fx.panel, fx.uid_bypass) == NULL);
    ASSERT_TRUE(cloak_userpanel_find(fx.panel, fx.uid_admin) != NULL);
    /* LINK 4 (panel -> owner) ran, for this session. Reading the uid at
     * all is the assertion: it is a COPY the panel took before its own
     * termination freed the registry entry the earlier links were handed
     * a pointer into, and reading the original here is a use-after-free
     * ASan reports (it did, which is how that defect was found). sesh is
     * NULL for the same reason -- the termination destroyed it. */
    ASSERT_EQ_INT(3, (int)fx.chain.session_id_at_call[0]);
    ASSERT_MEM_EQ(fx.chain.uid_at_call[0], fx.uid_bypass, CLOAK_UID_LEN);
    ASSERT_EQ_INT(1, fx.chain.sesh_null_at_call[0]);
    /* The admin session is untouched by the other session's teardown. */
    ASSERT_EQ_INT(1, (int)fx.chain.api_sessions_at_call[0]);
    ASSERT_EQ_INT(1, (int)fx.chain.api_streams_at_call[0]);

    /* The byte that would land on a relay that had NOT been stopped.
     * Expected to fail at the socket level (the relay closed it), which
     * is why the result is not asserted; what is asserted is that
     * pumping afterwards touches nothing freed. */
    (void)da_up_send(&fx.up, 0, "after-the-free", 14);
    for (int i = 0; i < 40; i++) {
        cloak_reactor_run_once(fx.reactor, 2);
    }
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

    /* ---- BREAK 2: the admin session ---- */
    uint64_t t0 = now_ms();
    cloak_session_release_stream(&admin_cs.sesh, ast);
    client_session_close(&admin_cs);
    cw.want = 2;
    ASSERT_TRUE(pump_until(fx.reactor, chain_calls_at_least, &cw, 600, 5));
    ASSERT_EQ_INT(2, fx.chain.calls);
    /* LINK 2 (proxy -> adminapi) ran, and before the owner's link: the
     * stream context and its armed deadline are gone. */
    ASSERT_EQ_INT(0, (int)fx.chain.api_sessions_at_call[1]);
    ASSERT_EQ_INT(0, (int)fx.chain.api_streams_at_call[1]);
    /* LINK 1 still holds. */
    ASSERT_EQ_INT(0, (int)fx.chain.proxy_sessions_at_call[1]);
    /* LINK 3: the admin user was the last active one. */
    ASSERT_EQ_INT(0, (int)fx.chain.active_users_at_call[1]);
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(fx.panel));
    /* LINK 4, for this session. */
    ASSERT_EQ_INT(0, (int)fx.chain.session_id_at_call[1]);
    ASSERT_MEM_EQ(fx.chain.uid_at_call[1], fx.uid_admin, CLOAK_UID_LEN);
    ASSERT_EQ_INT(1, fx.chain.sesh_null_at_call[1]);

    /* PAST THE DEADLINE, deliberately: a stream context the adminapi link
     * never released still owns an armed 1500 ms timer pointing at a
     * cloak_stream_t the broken session has already freed. This pump runs
     * until the deadline has demonstrably passed -- the elapsed time is
     * asserted, not assumed -- so that ASan gets the chance to see that
     * use. With the chain wired correctly the timer was cancelled at the
     * break and nothing happens here at all. */
    while (now_ms() - t0 < 1700) {
        cloak_reactor_run_once(fx.reactor, 10);
    }
    ASSERT_TRUE(now_ms() - t0 >= 1500);
    ASSERT_EQ_INT(0, (int)cloak_adminapi_stream_count(&fx.api));
    ASSERT_EQ_INT(0, (int)cloak_adminapi_session_count(&fx.api));
    ASSERT_EQ_INT(2, fx.chain.calls);

    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 7. panel == NULL keeps today's behaviour                             */
/* ------------------------------------------------------------------ */

/* cloak_dispatcher_config_t::panel may be NULL, and that is a POLICY (a
 * server with no user database), not a degraded mode. The admin decision
 * must not have quietly acquired a dependency on the panel: with no panel
 * at all, an admin session still authenticates, still skips the
 * proxy-method check, and still reaches the admin API. */
static void test_no_panel_keeps_todays_behaviour(void) {
    struct fixture fx;
    fixture_opts_t o;
    memset(&o, 0, sizeof(o));
    o.no_panel = 1;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "nopanel", &o));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &cs, fx.uid_admin, "nosuch", 0));
    ASSERT_EQ_INT(1, fx.prep.last_is_admin);
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&fx.api));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    resp_t resp;
    resp_init(&resp, st);
    const char *req = "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n";
    ASSERT_EQ_INT((int)strlen(req),
                  (int)cloak_stream_write(st, (const uint8_t *)req, strlen(req)));
    ASSERT_TRUE(pump_until(fx.reactor, resp_headers_done, &resp, 600, 5));
    ASSERT_EQ_INT(200, resp_status(&resp));

    /* And a UID this server has never heard of is still refused, with no
     * panel to ask -- cloak_server_is_bypass is the whole policy. */
    uint8_t uid_unknown[CLOAK_UID_LEN];
    mk_uid(uid_unknown, 0x44);
    assert_refused(&fx, uid_unknown, "ss", 0);

    resp_free(&resp);
    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 8. An owner with NO admin API is unchanged                           */
/* ------------------------------------------------------------------ */

/* THE REGRESSION THIS TASK COULD HAVE INTRODUCED. Skipping step 7 for an
 * admin session means an admin connection now reaches the owner's
 * prepare_session with a proxy method this server does not offer. An
 * owner that does not know about admin sessions -- every pre-adminapi
 * caller, and the shape test_dispatcher_auth.c and test_server_e2e.c
 * still use -- hands it straight to cloak_proxy_prepare_session, which
 * refuses an unresolvable method (proxy.c's own upstream == NULL branch)
 * and redirects.
 *
 * So the connection is still refused, and still refused identically: the
 * cover site's own bytes. What moved is WHERE the refusal happens, and
 * this case is what pins that the move is invisible from outside. */
static void test_no_adminapi_owner_still_refuses_unknown_method(void) {
    struct fixture fx;
    fixture_opts_t o;
    memset(&o, 0, sizeof(o));
    o.no_api = 1;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "noapi", &o));

    assert_refused(&fx, fx.uid_admin, "nosuch", 0);
    /* The proof that the refusal moved rather than vanished: the owner's
     * prepare_session DID run for this connection (step 7 no longer
     * refused it) and was told it was an admin session; it is
     * cloak_proxy_prepare_session that turned it away. */
    ASSERT_EQ_INT(1, fx.prep.calls);
    ASSERT_EQ_INT(1, fx.prep.last_is_admin);
    ASSERT_EQ_INT(1, fx.prep.proxy_calls);
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&fx.registry, fx.uid_admin));

    /* An offered method through the same owner is unaffected. */
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client_pm(&fx, &cs, fx.uid_admin, "ss", 0));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));

    client_session_close(&cs);
    fixture_destroy(&fx);
}

TEST_MAIN_BEGIN()
    test_admin_uid_session_zero_skips_the_proxy_method_check();
    test_admin_uid_nonzero_session_is_ordinary();
    test_non_admin_uid_session_zero_is_ordinary();
    test_no_admin_uid_configured();
    test_admin_session_is_not_metered();
    test_broken_session_chain_runs_every_link();
    test_no_panel_keeps_todays_behaviour();
    test_no_adminapi_owner_still_refuses_unknown_method();
TEST_MAIN_END()
