#define _POSIX_C_SOURCE 200809L
#include "cloak/userpanel.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>

#include "cloak/common.h"
#include "test_framework.h"

/* The panel sits between a real SQLite-backed cloak_usermanager_t and
 * real cloak_session_t's in a real cloak_server_registry_t, and the
 * things worth testing about it (billing, termination, re-entrancy) are
 * all about how those two interact -- so nothing here is faked. Sessions
 * are built the way test_registry.c builds them (a registry session plus
 * a plain peer session over a socketpair, or a raw fd whose close()
 * breaks the session), and every database assertion reads the database
 * back through the manager.
 *
 * EVERY WAIT IS BOUNDED BY MEASURED WALL TIME, not by an iteration count
 * that merely looks like a duration: this project shipped a pump whose
 * comment claimed 400 ms and whose bound measured 84. pump_until_ms below
 * polls a monotonic clock, and the one place a test claims "at least N
 * milliseconds elapsed" asserts that elapsed time explicitly. */

/* ------------------------------------------------------------------ */
/* Database scaffolding (same discipline as test_usermanager.c)         */
/* ------------------------------------------------------------------ */

static void up_tmp_path(char *buf, size_t cap, const char *tag) {
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(buf, cap, "%s/cloak_up_%ld_%s.db", dir, (long)getpid(), tag);
}

/* WAL leaves sidecars; a survivor would carry committed credit from a
 * previous run into this one and make a billing assertion pass or fail
 * for reasons unrelated to the code under test. */
static void up_unlink(const char *path) {
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

static int64_t fake_now(void *userdata) {
    return *(const int64_t *)userdata;
}

/* All bytes equal to seed: distinct per seed and trivially recognisable
 * in a failure message. */
static void mk_uid(uint8_t *uid, uint8_t seed) {
    memset(uid, seed, CLOAK_UID_LEN);
}

/* A wider generator for the cap test, which needs more distinct UIDs than
 * mk_uid can produce. The 0xC0 prefix cannot collide with any mk_uid
 * value: an all-equal UID starting 0xC0 would need n == 0xC0C0, far above
 * the number generated here. */
static void mk_uid_n(uint8_t *uid, unsigned n) {
    memset(uid, 0, CLOAK_UID_LEN);
    uid[0] = 0xC0;
    uid[1] = (uint8_t)(n >> 8);
    uid[2] = (uint8_t)(n & 0xff);
}

static void put_user(cloak_usermanager_t *m, uint8_t seed, int32_t cap, int64_t up_rate,
                     int64_t down_rate, int64_t up_credit, int64_t down_credit) {
    cloak_user_info_t u;
    memset(&u, 0, sizeof(u));
    mk_uid(u.uid, seed);
    u.sessions_cap = cap;
    u.up_rate = up_rate;
    u.down_rate = down_rate;
    u.up_credit = up_credit;
    u.down_credit = down_credit;
    u.expiry_time = T_EXPIRY;
    ASSERT_EQ_INT(0, cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL));
}

static cloak_user_info_t get_user_row(cloak_usermanager_t *m, uint8_t seed) {
    cloak_user_info_t got;
    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, seed);
    memset(&got, 0, sizeof(got));
    ASSERT_EQ_INT(0, cloak_usermanager_get(m, uid, &got));
    return got;
}

/* ------------------------------------------------------------------ */
/* Bounded pumping                                                      */
/* ------------------------------------------------------------------ */

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

typedef int (*pump_done_fn)(void *ctx);

/* Polls the reactor until done(ctx) is true or budget_ms of MEASURED wall
 * time has passed, whichever comes first. Returns done(ctx): every caller
 * asserts that return value, so an expired budget is a test failure and
 * never a silent pass. *out_elapsed_ms, when non-NULL, is the measured
 * elapsed time -- the callers that make a claim about duration assert
 * against it rather than against a loop count. */
static int pump_until_ms(cloak_reactor_t *r, pump_done_fn done, void *ctx, uint64_t budget_ms,
                         uint64_t *out_elapsed_ms) {
    uint64_t start = mono_ms();
    while (!done(ctx) && mono_ms() - start < budget_ms) {
        cloak_reactor_run_once(r, 5);
    }
    if (out_elapsed_ms != NULL) {
        *out_elapsed_ms = mono_ms() - start;
    }
    return done(ctx);
}

/* Pumps for at least ms milliseconds of measured wall time, unconditionally.
 * Used where the point is "give the reactor every chance to do the wrong
 * thing" -- a sweep that should not double-free, a timer that should not
 * have fired yet. Returns the measured elapsed time so the caller can
 * assert the duration it claims. */
static uint64_t pump_for_ms(cloak_reactor_t *r, uint64_t ms) {
    uint64_t start = mono_ms();
    uint64_t elapsed;
    while ((elapsed = mono_ms() - start) < ms) {
        cloak_reactor_run_once(r, 5);
    }
    return elapsed;
}

/* ------------------------------------------------------------------ */
/* Session scaffolding                                                  */
/* ------------------------------------------------------------------ */

static void make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

/* 60000 ms of inactivity timeout is far beyond every bound in this file,
 * so no session here can break because of the inactivity timer and be
 * mistaken for a break this file caused deliberately. */
static void base_config(cloak_session_config_t *cfg, const cloak_obfuscator_t *obfs) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->obfuscator = *obfs;
    cfg->max_on_wire_size = 16401;
    cfg->stream_recv_capacity = 65536;
    cfg->stream_max_pending_frames = 64;
    cfg->conn_send_queue_cap = 262144;
    cfg->inactivity_timeout_ms = 60000;
}

typedef struct {
    cloak_stream_t *accepted;
    int new_stream_calls;
    long bytes_read;
} srv_ep_t;

static void srv_drain(srv_ep_t *ep, cloak_stream_t *stream) {
    /* Drains on BOTH callbacks. on_new_stream carries the first frame's
     * bytes and on_stream_data is only fired for later ones, so a
     * new-stream handler that merely records the stream leaves the first
     * frame unread -- and every wait below, which is expressed in bytes
     * delivered, would then time out on the first transfer of each link. */
    uint8_t buf[8192];
    for (;;) {
        long n = cloak_stream_read(stream, buf, sizeof(buf));
        if (n <= 0) {
            return;
        }
        ep->bytes_read += n;
    }
}

static void srv_on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    srv_ep_t *ep = userdata;
    ep->new_stream_calls++;
    ep->accepted = stream;
    srv_drain(ep, stream);
}

static void srv_on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    srv_drain(userdata, stream);
}

/* One (uid, session_id) in the registry, plus the plain peer session on
 * the other end of a socketpair that makes real traffic possible. */
typedef struct {
    cloak_session_t *srv; /* owned by the registry */
    cloak_session_t peer;
    int peer_inited;
    srv_ep_t ep;
    cloak_stream_t *peer_stream;
} link_t;

static void link_open(link_t *L, cloak_reactor_t *r, cloak_server_registry_t *reg,
                      const cloak_obfuscator_t *obfs, const uint8_t *uid, uint32_t sid,
                      cloak_valve_t *valve) {
    memset(L, 0, sizeof(*L));

    cloak_session_config_t scfg;
    base_config(&scfg, obfs);
    scfg.valve = valve; /* the whole point: this session meters into the panel's user */
    scfg.on_new_stream = srv_on_new_stream;
    scfg.on_new_stream_userdata = &L->ep;
    scfg.on_stream_data = srv_on_stream_data;
    scfg.on_stream_data_userdata = &L->ep;

    int created = 0;
    L->srv = cloak_server_registry_get_or_create(reg, uid, sid, &scfg, &created);
    ASSERT_TRUE(L->srv != NULL);
    ASSERT_EQ_INT(1, created);

    cloak_session_config_t pcfg;
    base_config(&pcfg, obfs);
    ASSERT_EQ_INT(0, cloak_session_init(&L->peer, sid, r, &pcfg));
    L->peer_inited = 1;

    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    ASSERT_EQ_INT(0, cloak_session_add_conn(L->srv, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&L->peer, fds[1]));
}

static void link_destroy_peer(link_t *L) {
    if (L->peer_inited) {
        cloak_session_destroy(&L->peer);
        L->peer_inited = 0;
    }
}

struct read_wait {
    srv_ep_t *ep;
    long want;
};

static int ep_read_at_least(void *ctx) {
    struct read_wait *w = ctx;
    return w->ep->bytes_read >= w->want;
}

/* Client -> server: the user's UPLOAD, i.e. the server's RX. */
static void drive_client_to_server(link_t *L, cloak_reactor_t *r, size_t n) {
    if (L->peer_stream == NULL) {
        L->peer_stream = cloak_session_open_stream(&L->peer, NULL);
        ASSERT_TRUE(L->peer_stream != NULL);
    }
    uint8_t *buf = malloc(n);
    ASSERT_TRUE(buf != NULL);
    memset(buf, 0x5A, n);
    long want = L->ep.bytes_read + (long)n;
    ASSERT_EQ_INT((long)n, cloak_stream_write(L->peer_stream, buf, n));
    free(buf);

    struct read_wait w = {&L->ep, want};
    ASSERT_TRUE(pump_until_ms(r, ep_read_at_least, &w, 3000, NULL));
}

/* Server -> client: the user's DOWNLOAD, i.e. the server's TX. Counted at
 * send time (cloak/valve.h), so there is nothing to wait for on the peer
 * side beyond letting the reactor flush. */
static void drive_server_to_client(link_t *L, cloak_reactor_t *r, size_t n) {
    ASSERT_TRUE(L->ep.accepted != NULL);
    uint8_t *buf = malloc(n);
    ASSERT_TRUE(buf != NULL);
    memset(buf, 0xA5, n);
    ASSERT_EQ_INT((long)n, cloak_stream_write(L->ep.accepted, buf, n));
    free(buf);
    pump_for_ms(r, 20);
}

/* ------------------------------------------------------------------ */
/* Registry broken wiring                                              */
/* ------------------------------------------------------------------ */

/* Stands in for cloak_proxy_registry_broken plus its chain, in exactly
 * the order the real wiring uses: the data path's own cleanup first
 * (here, nothing to clean), then cloak_userpanel_registry_broken as the
 * chain. Wiring the panel directly as the registry's on_broken would test
 * a configuration the server can never have, since the proxy owns that
 * slot. */
typedef struct {
    cloak_userpanel_t *panel;
    int broken_calls;
} chain_ctx_t;

static void on_registry_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                               const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    chain_ctx_t *ctx = userdata;
    ctx->broken_calls++;
    /* ... the proxy's own relay teardown would run here ... */
    cloak_userpanel_registry_broken(reg, sesh, uid, session_id, ctx->panel);
}

/* ------------------------------------------------------------------ */
/* 1. get_user activates, returns the stored rates, and creates nothing  */
/*    for a UID the manager refuses.                                    */
/* ------------------------------------------------------------------ */
static void test_get_user_activates_and_returns_rates(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    up_tmp_path(path, sizeof(path), "getuser");
    up_unlink(path);

    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)));
    put_user(m, 0x01, 4, 1234, 5678, 1000000, 2000000);
    put_user(m, 0x02, 4, 11, 22, 0, 2000000); /* no upload credit left */

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    chain_ctx_t chain = {NULL, 0};
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &chain));

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = r;
    pcfg.upload_interval_ms = 60000; /* long: nothing here wants a tick */
    pcfg.now_fn = fake_now;
    pcfg.now_userdata = &now;

    cloak_userpanel_t *panel = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));
    chain.panel = panel;

    uint8_t uid1[CLOAK_UID_LEN], uid2[CLOAK_UID_LEN], uid9[CLOAK_UID_LEN];
    mk_uid(uid1, 0x01);
    mk_uid(uid2, 0x02);
    mk_uid(uid9, 0x09); /* never written to the database */

    cloak_userpanel_user_t *u = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_get_user(panel, uid1, &u));
    ASSERT_TRUE(u != NULL);
    ASSERT_MEM_EQ(u->uid, uid1, CLOAK_UID_LEN);
    ASSERT_EQ_INT(1234, u->up_rate);   /* the rates Task 6 will consume */
    ASSERT_EQ_INT(5678, u->down_rate);
    ASSERT_EQ_INT(0, u->bypass);
    ASSERT_TRUE(cloak_userpanel_user_valve(u) == &u->valve); /* metered */
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(panel));

    /* Already active: the same object, no second entry, no second
     * authenticate. */
    cloak_userpanel_user_t *again = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_get_user(panel, uid1, &again));
    ASSERT_TRUE(again == u);
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(panel));
    ASSERT_TRUE(cloak_userpanel_find(panel, uid1) == u);

    /* Unknown UID: the manager's own code, nothing created, *out NULL. */
    cloak_userpanel_user_t *bad = (cloak_userpanel_user_t *)0x1;
    ASSERT_EQ_INT(CLOAK_USER_ERR_NOT_FOUND, cloak_userpanel_get_user(panel, uid9, &bad));
    ASSERT_TRUE(bad == NULL);
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(panel));
    ASSERT_TRUE(cloak_userpanel_find(panel, uid9) == NULL);

    /* Known UID the manager refuses: same rule. A panel that activated
     * first and authorised afterwards would leave this one active. */
    bad = (cloak_userpanel_user_t *)0x1;
    ASSERT_EQ_INT(CLOAK_USER_ERR_NO_UP_CREDIT, cloak_userpanel_get_user(panel, uid2, &bad));
    ASSERT_TRUE(bad == NULL);
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(panel));
    ASSERT_TRUE(cloak_userpanel_find(panel, uid2) == NULL);

    cloak_server_registry_destroy(&reg);
    cloak_userpanel_close(panel);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(r);
    up_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 2. get_bypass_user never consults the manager -- proven by running    */
/*    the whole panel over a VOID one, where any consultation fails.     */
/* ------------------------------------------------------------------ */
static void test_bypass_user_never_touches_the_manager(void) {
    char err[256];
    int64_t now = T_NOW;

    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, NULL, fake_now, &now, err, sizeof(err)));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    chain_ctx_t chain = {NULL, 0};
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &chain));

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = r;
    pcfg.upload_interval_ms = 60000;
    pcfg.now_fn = fake_now;
    pcfg.now_userdata = &now;

    cloak_userpanel_t *panel = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));
    chain.panel = panel;

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x33);

    /* Everything that asks the manager fails against a void one... */
    cloak_userpanel_user_t *u = NULL;
    ASSERT_EQ_INT(CLOAK_USER_ERR_VOID, cloak_userpanel_get_user(panel, uid, &u));
    ASSERT_TRUE(u == NULL);
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(panel));

    /* ... and the bypass path still works, which it could not if it asked. */
    ASSERT_EQ_INT(0, cloak_userpanel_get_bypass_user(panel, uid, &u));
    ASSERT_TRUE(u != NULL);
    ASSERT_EQ_INT(1, u->bypass);
    ASSERT_TRUE(cloak_userpanel_user_valve(u) == NULL); /* not metered */
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(panel));

    /* An upload cycle with a bypass user active must send NOTHING: a
     * panel that queued bypass users would call upload_status on a void
     * manager here and get CLOAK_USER_ERR_VOID back. */
    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(panel));

    cloak_server_registry_destroy(&reg);
    cloak_userpanel_close(panel);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(r);
}

/* ------------------------------------------------------------------ */
/* 3. Metered traffic on a session reaches the DATABASE, on the timer,   */
/*    with upload and download landing on the right credits.             */
/* ------------------------------------------------------------------ */

struct credit_wait {
    cloak_usermanager_t *m;
    uint8_t seed;
    int64_t was_up;
};

static int up_credit_changed(void *ctx) {
    struct credit_wait *w = ctx;
    cloak_user_info_t got;
    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, w->seed);
    if (cloak_usermanager_get(w->m, uid, &got) != 0) {
        return 0;
    }
    return got.up_credit != w->was_up;
}

#define CASE3_INTERVAL_MS 400

static void test_usage_reaches_the_database_on_the_timer(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    up_tmp_path(path, sizeof(path), "timer");
    up_unlink(path);

    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)));
    put_user(m, 0x11, 4, 0, 0, 10000000, 10000000);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    chain_ctx_t chain = {NULL, 0};
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &chain));

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = r;
    pcfg.upload_interval_ms = CASE3_INTERVAL_MS;
    pcfg.now_fn = fake_now;
    pcfg.now_userdata = &now;

    cloak_userpanel_t *panel = NULL;
    uint64_t opened_at = mono_ms();
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));
    chain.panel = panel;

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x11);
    cloak_userpanel_user_t *u = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_get_user(panel, uid, &u));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    link_t L;
    link_open(&L, r, &reg, &obfs, uid, 7, cloak_userpanel_user_valve(u));

    /* DELIBERATELY ASYMMETRIC. If the two directions carried the same
     * number of bytes, an implementation that billed RX against the
     * download credit (and TX against the upload credit) would produce
     * exactly the same database rows as a correct one -- the mechanism
     * and its absence would be indistinguishable, which is not coverage.
     * cloak/valve.h names this conversion as the single silent-failure
     * point in the whole metering path. */
    drive_client_to_server(&L, r, 64);
    drive_server_to_client(&L, r, 6000);

    int64_t rx = cloak_valve_rx(&u->valve);
    int64_t tx = cloak_valve_tx(&u->valve);
    ASSERT_TRUE(rx > 0);
    ASSERT_TRUE(tx > 0);
    ASSERT_TRUE(tx > rx * 4); /* the asymmetry the assertions below rely on */

    /* Nothing in this test calls cloak_userpanel_upload_now: the only
     * thing that can move these credits is the panel's own timer. */
    struct credit_wait w = {m, 0x11, 10000000};
    uint64_t elapsed = 0;
    ASSERT_TRUE(pump_until_ms(r, up_credit_changed, &w, 5000, &elapsed));

    /* The timer honoured its interval: measured wall time since the panel
     * was opened is at least one full interval. An implementation that
     * armed the timer at 0 ms, or that uploaded from get_user, fails
     * here -- and this asserts the duration it names rather than an
     * iteration count that merely resembles one. */
    ASSERT_TRUE(mono_ms() - opened_at >= CASE3_INTERVAL_MS);

    cloak_user_info_t row = get_user_row(m, 0x11);
    ASSERT_EQ_INT(10000000 - rx, row.up_credit);   /* user's UPLOAD == server's RX */
    ASSERT_EQ_INT(10000000 - tx, row.down_credit); /* user's DOWNLOAD == server's TX */

    /* The drain is a nullify, not a read: a second tick must not bill the
     * same bytes again. */
    ASSERT_EQ_INT(0, cloak_valve_rx(&u->valve));
    ASSERT_EQ_INT(0, cloak_valve_tx(&u->valve));

    link_destroy_peer(&L);
    cloak_server_registry_destroy(&reg);
    cloak_userpanel_close(panel);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(r);
    up_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 4. A user whose credit runs out mid-session is terminated: every one  */
/*    of its sessions is closed and it leaves the active table.          */
/* ------------------------------------------------------------------ */

typedef struct {
    int calls;
    uint32_t session_ids[8];
} closing_ctx_t;

static void on_session_closing(const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    (void)uid;
    closing_ctx_t *c = userdata;
    if (c->calls < (int)(sizeof(c->session_ids) / sizeof(c->session_ids[0]))) {
        c->session_ids[c->calls] = session_id;
    }
    c->calls++;
}

static void test_user_out_of_credit_is_terminated(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    up_tmp_path(path, sizeof(path), "terminate");
    up_unlink(path);

    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)));
    /* 40 bytes of upload credit: a single small frame overruns it. */
    put_user(m, 0x21, 4, 0, 0, 40, 10000000);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    chain_ctx_t chain = {NULL, 0};
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &chain));

    closing_ctx_t closing;
    memset(&closing, 0, sizeof(closing));

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = r;
    pcfg.upload_interval_ms = 60000; /* this case drives the cycle by hand */
    pcfg.now_fn = fake_now;
    pcfg.now_userdata = &now;
    pcfg.on_session_closing = on_session_closing;
    pcfg.on_session_closing_userdata = &closing;

    cloak_userpanel_t *panel = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));
    chain.panel = panel;

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x21);
    cloak_userpanel_user_t *u = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_get_user(panel, uid, &u));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    link_t l1, l2;
    link_open(&l1, r, &reg, &obfs, uid, 11, cloak_userpanel_user_valve(u));
    link_open(&l2, r, &reg, &obfs, uid, 12, cloak_userpanel_user_valve(u));
    ASSERT_EQ_INT(2, (int)cloak_server_registry_count_for_uid(&reg, uid));

    drive_client_to_server(&l1, r, 200); /* > 40 bytes of upload credit */
    ASSERT_TRUE(cloak_valve_rx(&u->valve) > 40);

    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(panel));

    /* The user is gone from the table and BOTH of its sessions are gone
     * from the registry -- including the one that carried no traffic. */
    ASSERT_TRUE(cloak_userpanel_find(panel, uid) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(panel));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&reg, uid));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&reg));

    /* Every closed session was offered to the owner first, which is the
     * only window in which a relay bound to it could still be stopped. */
    ASSERT_EQ_INT(2, closing.calls);
    ASSERT_TRUE((closing.session_ids[0] == 11 && closing.session_ids[1] == 12) ||
                (closing.session_ids[0] == 12 && closing.session_ids[1] == 11));

    /* The debt is written back, which is what keeps authenticate refusing
     * this user on the next connection attempt. */
    cloak_user_info_t row = get_user_row(m, 0x21);
    ASSERT_TRUE(row.up_credit <= 0);
    ASSERT_EQ_INT(CLOAK_USER_ERR_NO_UP_CREDIT,
                  cloak_usermanager_authenticate(m, uid, NULL, NULL));

    /* Let every deferred sweep run: a session freed twice shows up here. */
    ASSERT_TRUE(pump_for_ms(r, 50) >= 50);

    link_destroy_peer(&l1);
    link_destroy_peer(&l2);
    cloak_server_registry_destroy(&reg);
    cloak_userpanel_close(panel);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(r);
    up_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 5. Usage accrued by a user who disconnects BEFORE the next upload is  */
/*    still billed. This is the case the separate queue exists for.      */
/* ------------------------------------------------------------------ */

struct active_wait {
    cloak_userpanel_t *panel;
    const uint8_t *uid;
};

static int user_went_inactive(void *ctx) {
    struct active_wait *w = ctx;
    return cloak_userpanel_find(w->panel, w->uid) == NULL;
}

static void test_usage_of_a_disconnected_user_is_still_billed(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    up_tmp_path(path, sizeof(path), "queue");
    up_unlink(path);

    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)));
    put_user(m, 0x31, 4, 0, 0, 10000000, 10000000);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    chain_ctx_t chain = {NULL, 0};
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &chain));

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = r;
    pcfg.upload_interval_ms = 60000; /* the upload happens by hand, AFTER the disconnect */
    pcfg.now_fn = fake_now;
    pcfg.now_userdata = &now;

    cloak_userpanel_t *panel = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));
    chain.panel = panel;

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x31);
    cloak_userpanel_user_t *u = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_get_user(panel, uid, &u));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    link_t L;
    link_open(&L, r, &reg, &obfs, uid, 21, cloak_userpanel_user_valve(u));

    drive_client_to_server(&L, r, 64);
    drive_server_to_client(&L, r, 6000);
    int64_t rx = cloak_valve_rx(&u->valve);
    int64_t tx = cloak_valve_tx(&u->valve);
    ASSERT_TRUE(rx > 0);
    ASSERT_TRUE(tx > rx * 4); /* asymmetric, for the reason case 3 states */

    /* The client vanishes. The session breaks, the registry's broken path
     * runs, the chain tells the panel, and with no sessions left the user
     * stops being active -- all before any upload has happened. */
    cloak_session_destroy(&L.peer);
    L.peer_inited = 0;

    struct active_wait aw = {panel, uid};
    ASSERT_TRUE(pump_until_ms(r, user_went_inactive, &aw, 3000, NULL));
    ASSERT_EQ_INT(1, chain.broken_calls);
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(panel));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&reg, uid));

    /* Nothing has been settled yet: termination queues, it does not
     * upload. (This is a precondition for the discriminating assertion
     * below, not a substitute for it.) */
    cloak_user_info_t before = get_user_row(m, 0x31);
    ASSERT_EQ_INT(10000000, before.up_credit);
    ASSERT_EQ_INT(10000000, before.down_credit);

    /* The user is long gone -- there is no valve left to drain and no
     * active entry to report -- and it is billed anyway. A panel that
     * kept the usage on the active user rather than on a separate queue
     * has nothing to send here. */
    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(panel));
    cloak_user_info_t after = get_user_row(m, 0x31);
    ASSERT_EQ_INT(10000000 - rx, after.up_credit);
    ASSERT_EQ_INT(10000000 - tx, after.down_credit);

    cloak_server_registry_destroy(&reg);
    cloak_userpanel_close(panel);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(r);
    up_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 6. The two registry accessors, over several users with several        */
/*    sessions each, including a UID with none.                          */
/* ------------------------------------------------------------------ */

typedef struct {
    int calls;
    uint8_t uids[8][CLOAK_UID_LEN];
    uint32_t session_ids[8];
    cloak_session_t *seshs[8];
} reg_closing_ctx_t;

static void reg_on_closing(cloak_server_registry_t *reg, cloak_session_t *sesh,
                           const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                           void *userdata) {
    (void)reg;
    reg_closing_ctx_t *c = userdata;
    if (c->calls < 8) {
        memcpy(c->uids[c->calls], uid, CLOAK_UID_LEN);
        c->session_ids[c->calls] = session_id;
        c->seshs[c->calls] = sesh;
    }
    c->calls++;
}

static void test_registry_accessors_count_and_close_by_uid(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    chain_ctx_t chain = {NULL, 0};
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &chain));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    cloak_session_config_t cfg;
    base_config(&cfg, &obfs);

    uint8_t a[CLOAK_UID_LEN], b[CLOAK_UID_LEN], c[CLOAK_UID_LEN];
    mk_uid(a, 0xA1);
    mk_uid(b, 0xB2);
    mk_uid(c, 0xC3); /* never given a session */

    int created = 0;
    ASSERT_TRUE(cloak_server_registry_get_or_create(&reg, a, 1, &cfg, &created) != NULL);
    ASSERT_TRUE(cloak_server_registry_get_or_create(&reg, a, 2, &cfg, &created) != NULL);
    ASSERT_TRUE(cloak_server_registry_get_or_create(&reg, a, 3, &cfg, &created) != NULL);
    ASSERT_TRUE(cloak_server_registry_get_or_create(&reg, b, 1, &cfg, &created) != NULL);

    ASSERT_EQ_INT(3, (int)cloak_server_registry_count_for_uid(&reg, a));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&reg, b));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&reg, c));
    ASSERT_EQ_INT(4, (int)cloak_server_registry_count(&reg));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(NULL, a));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&reg, NULL));

    /* A UID with no sessions closes nothing and disturbs nothing. */
    reg_closing_ctx_t rc;
    memset(&rc, 0, sizeof(rc));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_close_all_for_uid(&reg, c, reg_on_closing, &rc));
    ASSERT_EQ_INT(0, rc.calls);
    ASSERT_EQ_INT(4, (int)cloak_server_registry_count(&reg));

    /* A's three go, B's one stays. */
    ASSERT_EQ_INT(3, (int)cloak_server_registry_close_all_for_uid(&reg, a, reg_on_closing, &rc));
    ASSERT_EQ_INT(3, rc.calls);
    for (int i = 0; i < 3; i++) {
        ASSERT_MEM_EQ(rc.uids[i], a, CLOAK_UID_LEN);
        ASSERT_TRUE(rc.seshs[i] != NULL);
    }
    /* The callback saw all three ids exactly once (order is the table's,
     * which is not a contract, so this checks the set). */
    int seen = 0;
    for (int i = 0; i < 3; i++) {
        seen |= 1 << (rc.session_ids[i] - 1);
    }
    ASSERT_EQ_INT(0x7, seen);

    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&reg, a));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&reg, b));
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&reg));
    ASSERT_TRUE(cloak_server_registry_find(&reg, a, 1) == NULL);
    ASSERT_TRUE(cloak_server_registry_find(&reg, b, 1) != NULL);

    /* Idempotent: a second close finds nothing left to close. */
    ASSERT_EQ_INT(0, (int)cloak_server_registry_close_all_for_uid(&reg, a, reg_on_closing, &rc));
    ASSERT_EQ_INT(3, rc.calls);

    /* A NULL on_closing is accepted (a caller with nothing bound). */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_close_all_for_uid(&reg, b, NULL, NULL));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&reg));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_close_all_for_uid(NULL, a, NULL, NULL));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_close_all_for_uid(&reg, NULL, NULL, NULL));

    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
}

/* ------------------------------------------------------------------ */
/* 7a. Re-entrancy: the owner's on_session_closing hook calls back into  */
/*     the panel, from the middle of terminate. Run under ASan.          */
/* ------------------------------------------------------------------ */

typedef struct {
    cloak_userpanel_t *panel;
    cloak_userpanel_user_t *user; /* captured BEFORE terminate frees it */
    uint8_t uid[CLOAK_UID_LEN];
    int calls;
} reenter_ctx_t;

static void on_closing_reenters(const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                void *userdata) {
    (void)uid;
    (void)session_id;
    reenter_ctx_t *c = userdata;
    c->calls++;
    /* Both shapes the real wiring can produce, from inside the window
     * where the panel is halfway through freeing this user:
     *   - indirectly, the way a proxy unwinding a session does;
     *   - directly, holding a pointer captured before terminate began. */
    cloak_userpanel_notify_session_closed(c->panel, c->uid);
    cloak_userpanel_terminate(c->panel, c->user, "reentrant");
}

static void test_terminate_survives_a_reentrant_close_hook(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    up_tmp_path(path, sizeof(path), "reenter");
    up_unlink(path);

    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)));
    put_user(m, 0x41, 8, 0, 0, 10000000, 10000000);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    chain_ctx_t chain = {NULL, 0};
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &chain));

    reenter_ctx_t rx_ctx;
    memset(&rx_ctx, 0, sizeof(rx_ctx));
    mk_uid(rx_ctx.uid, 0x41);

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = r;
    pcfg.upload_interval_ms = 60000;
    pcfg.now_fn = fake_now;
    pcfg.now_userdata = &now;
    pcfg.on_session_closing = on_closing_reenters;
    pcfg.on_session_closing_userdata = &rx_ctx;

    cloak_userpanel_t *panel = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));
    chain.panel = panel;
    rx_ctx.panel = panel;

    cloak_userpanel_user_t *u = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_get_user(panel, rx_ctx.uid, &u));
    rx_ctx.user = u;

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    link_t l1, l2, l3;
    link_open(&l1, r, &reg, &obfs, rx_ctx.uid, 31, cloak_userpanel_user_valve(u));
    link_open(&l2, r, &reg, &obfs, rx_ctx.uid, 32, cloak_userpanel_user_valve(u));
    link_open(&l3, r, &reg, &obfs, rx_ctx.uid, 33, cloak_userpanel_user_valve(u));
    ASSERT_EQ_INT(3, (int)cloak_server_registry_count_for_uid(&reg, rx_ctx.uid));

    drive_client_to_server(&l1, r, 128);
    int64_t rx = cloak_valve_rx(&u->valve);
    ASSERT_TRUE(rx > 0);

    cloak_userpanel_terminate(panel, u, "test");

    /* The hook ran once per session -- so the nested calls neither
     * skipped sessions nor re-closed them -- and the user is gone exactly
     * once (a second free is what ASan reports if the guard is removed). */
    ASSERT_EQ_INT(3, rx_ctx.calls);
    ASSERT_TRUE(cloak_userpanel_find(panel, rx_ctx.uid) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(panel));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&reg, rx_ctx.uid));

    /* The panel is still usable, and the usage survived the storm: it was
     * queued exactly once and settles on the next cycle. */
    cloak_userpanel_user_t *other = NULL;
    uint8_t other_uid[CLOAK_UID_LEN];
    mk_uid(other_uid, 0x42);
    ASSERT_EQ_INT(0, cloak_userpanel_get_bypass_user(panel, other_uid, &other));
    ASSERT_EQ_INT(1, (int)cloak_userpanel_active_count(panel));

    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(panel));
    cloak_user_info_t row = get_user_row(m, 0x41);
    ASSERT_EQ_INT(10000000 - rx, row.up_credit);

    ASSERT_TRUE(pump_for_ms(r, 50) >= 50);

    link_destroy_peer(&l1);
    link_destroy_peer(&l2);
    link_destroy_peer(&l3);
    cloak_server_registry_destroy(&reg);
    cloak_userpanel_close(panel);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(r);
    up_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 7b. Re-entrancy, the shape the real server produces: a session        */
/*     breaks, the chain tells the panel, and terminate runs from        */
/*     inside that session's own broken callback -- destroying the       */
/*     session whose callback is on the stack. Run under ASan.           */
/* ------------------------------------------------------------------ */
static void test_terminate_from_inside_the_broken_path(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    up_tmp_path(path, sizeof(path), "broken");
    up_unlink(path);

    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)));
    put_user(m, 0x51, 8, 0, 0, 10000000, 10000000);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    chain_ctx_t chain = {NULL, 0};
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &chain));

    closing_ctx_t closing;
    memset(&closing, 0, sizeof(closing));

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = r;
    pcfg.upload_interval_ms = 60000;
    pcfg.now_fn = fake_now;
    pcfg.now_userdata = &now;
    pcfg.on_session_closing = on_session_closing;
    pcfg.on_session_closing_userdata = &closing;

    cloak_userpanel_t *panel = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));
    chain.panel = panel;

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x51);
    cloak_userpanel_user_t *u = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_get_user(panel, uid, &u));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    link_t l1, l2;
    link_open(&l1, r, &reg, &obfs, uid, 41, cloak_userpanel_user_valve(u));
    link_open(&l2, r, &reg, &obfs, uid, 42, cloak_userpanel_user_valve(u));
    drive_client_to_server(&l1, r, 128);
    drive_client_to_server(&l2, r, 128);
    int64_t rx = cloak_valve_rx(&u->valve);
    ASSERT_TRUE(rx > 0);

    /* First session dies. ONE session left, so the user must stay active:
     * a panel that deactivated on any session close rather than the last
     * one fails right here. */
    cloak_session_destroy(&l1.peer);
    l1.peer_inited = 0;
    struct read_wait unused = {&l1.ep, 0};
    (void)unused;
    {
        struct active_wait aw = {panel, uid};
        uint64_t elapsed = 0;
        /* Deliberately expects the predicate NOT to be satisfied, so this
         * one is a full 300 ms of measured waiting rather than a
         * short-circuit -- and the elapsed time is asserted, because a
         * bound that did not actually wait would make the assertion below
         * pass for the wrong reason. */
        (void)pump_until_ms(r, user_went_inactive, &aw, 300, &elapsed);
        ASSERT_TRUE(elapsed >= 300);
    }
    ASSERT_EQ_INT(1, chain.broken_calls);
    ASSERT_TRUE(cloak_userpanel_find(panel, uid) != NULL);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&reg, uid));

    /* Second session dies: now the panel terminates the user from inside
     * that session's own broken callback, which destroys the session
     * whose callback is still on the stack above. */
    cloak_session_destroy(&l2.peer);
    l2.peer_inited = 0;
    struct active_wait aw = {panel, uid};
    ASSERT_TRUE(pump_until_ms(r, user_went_inactive, &aw, 3000, NULL));
    ASSERT_EQ_INT(2, chain.broken_calls);
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(panel));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&reg));

    /* The still-breaking session was closed by the terminate, not left for
     * the sweep: the hook fired for it. Leaving it to the sweep would
     * leave a session metering into a freed valve for one reactor turn. */
    ASSERT_EQ_INT(1, closing.calls);
    ASSERT_EQ_INT(42, (int)closing.session_ids[0]);

    /* Nothing double-freed when the deferred sweeps finally run. */
    ASSERT_TRUE(pump_for_ms(r, 60) >= 60);

    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(panel));
    cloak_user_info_t row = get_user_row(m, 0x51);
    ASSERT_EQ_INT(10000000 - rx, row.up_credit);

    cloak_server_registry_destroy(&reg);
    cloak_userpanel_close(panel);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(r);
    up_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 8. Bypass users are never metered and never uploaded, even when the   */
/*    same UID also has a row in the database.                           */
/* ------------------------------------------------------------------ */
static void test_bypass_user_is_never_metered_or_uploaded(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    up_tmp_path(path, sizeof(path), "bypass");
    up_unlink(path);

    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)));
    /* The same UID exists in the database, so "unchanged credit" below is
     * a real observation and not merely a missing row. */
    put_user(m, 0x61, 4, 0, 0, 777777, 888888);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    chain_ctx_t chain = {NULL, 0};
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &chain));

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = r;
    pcfg.upload_interval_ms = 60000;
    pcfg.now_fn = fake_now;
    pcfg.now_userdata = &now;

    cloak_userpanel_t *panel = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));
    chain.panel = panel;

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x61);
    cloak_userpanel_user_t *u = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_get_bypass_user(panel, uid, &u));
    ASSERT_TRUE(cloak_userpanel_user_valve(u) == NULL);

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    link_t L;
    link_open(&L, r, &reg, &obfs, uid, 51, cloak_userpanel_user_valve(u));

    drive_client_to_server(&L, r, 512);
    drive_server_to_client(&L, r, 4096);

    /* Nothing was counted anywhere... */
    ASSERT_EQ_INT(0, cloak_valve_rx(&u->valve));
    ASSERT_EQ_INT(0, cloak_valve_tx(&u->valve));

    /* ... and nothing is billed, twice over: once through the periodic
     * cycle, and once through the drain that termination performs. */
    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(panel));
    cloak_user_info_t row = get_user_row(m, 0x61);
    ASSERT_EQ_INT(777777, row.up_credit);
    ASSERT_EQ_INT(888888, row.down_credit);

    cloak_userpanel_terminate(panel, u, "test");
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(panel));
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&reg, uid));
    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(panel));
    row = get_user_row(m, 0x61);
    ASSERT_EQ_INT(777777, row.up_credit);
    ASSERT_EQ_INT(888888, row.down_credit);

    link_destroy_peer(&L);
    cloak_server_registry_destroy(&reg);
    cloak_userpanel_close(panel);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(r);
    up_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 9. A failed upload is RETRIED, not discarded: the whole accumulated   */
/*    amount lands once the database is writable again.                  */
/* ------------------------------------------------------------------ */
static void test_failed_upload_is_retried_not_discarded(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    up_tmp_path(path, sizeof(path), "retry");
    up_unlink(path);

    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)));
    put_user(m, 0x71, 4, 0, 0, 10000000, 10000000);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    chain_ctx_t chain = {NULL, 0};
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &chain));

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = r;
    pcfg.upload_interval_ms = 60000;
    pcfg.now_fn = fake_now;
    pcfg.now_userdata = &now;

    cloak_userpanel_t *panel = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));
    chain.panel = panel;

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x71);
    cloak_userpanel_user_t *u = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_get_user(panel, uid, &u));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    link_t L;
    link_open(&L, r, &reg, &obfs, uid, 61, cloak_userpanel_user_valve(u));

    /* A SECOND WRITER, exactly the situation the manager's busy_timeout
     * of 0 is chosen for: an operator's sqlite3 CLI, or the admin API.
     * BEGIN IMMEDIATE takes the write lock; the panel's upload then fails
     * fast instead of stalling the reactor. */
    sqlite3 *other = NULL;
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_open(path, &other));
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_exec(other, "BEGIN IMMEDIATE", NULL, NULL, NULL));

    drive_client_to_server(&L, r, 96);
    drive_server_to_client(&L, r, 3000);
    int64_t rx1 = cloak_valve_rx(&u->valve);
    int64_t tx1 = cloak_valve_tx(&u->valve);
    ASSERT_TRUE(rx1 > 0);
    ASSERT_TRUE(tx1 > 0);

    ASSERT_TRUE(cloak_userpanel_upload_now(panel) != 0); /* locked out */
    cloak_user_info_t mid = get_user_row(m, 0x71);
    ASSERT_EQ_INT(10000000, mid.up_credit); /* nothing was written */
    ASSERT_EQ_INT(10000000, mid.down_credit);

    /* More traffic in the next interval. The first interval's bytes are
     * no longer in the valve -- the drain took them -- so if the failed
     * upload had discarded the queue they would be gone for good. */
    ASSERT_EQ_INT(0, cloak_valve_rx(&u->valve));
    drive_client_to_server(&L, r, 96);
    drive_server_to_client(&L, r, 3000);
    int64_t rx2 = cloak_valve_rx(&u->valve);
    int64_t tx2 = cloak_valve_tx(&u->valve);
    ASSERT_TRUE(rx2 > 0);
    ASSERT_TRUE(tx2 > 0);

    ASSERT_EQ_INT(SQLITE_OK, sqlite3_exec(other, "ROLLBACK", NULL, NULL, NULL));
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_close(other));

    ASSERT_EQ_INT(0, cloak_userpanel_upload_now(panel));
    cloak_user_info_t row = get_user_row(m, 0x71);
    /* BOTH intervals, not just the second. */
    ASSERT_EQ_INT(10000000 - (rx1 + rx2), row.up_credit);
    ASSERT_EQ_INT(10000000 - (tx1 + tx2), row.down_credit);

    link_destroy_peer(&L);
    cloak_server_registry_destroy(&reg);
    cloak_userpanel_close(panel);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(r);
    up_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 10. At the cap the panel refuses the NEWEST user and keeps every one  */
/*     it is already billing.                                            */
/* ------------------------------------------------------------------ */
static void test_active_table_refuses_the_newest_at_the_cap(void) {
    char err[256];
    int64_t now = T_NOW;

    /* A void manager: this case is about the table, and bypass users
     * fill it without needing a row each. */
    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, NULL, fake_now, &now, err, sizeof(err)));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    chain_ctx_t chain = {NULL, 0};
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &chain));

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = r;
    pcfg.upload_interval_ms = 60000;
    pcfg.now_fn = fake_now;
    pcfg.now_userdata = &now;

    cloak_userpanel_t *panel = NULL;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));
    chain.panel = panel;

    uint8_t first[CLOAK_UID_LEN];
    mk_uid_n(first, 0);
    for (unsigned i = 0; i < CLOAK_USERPANEL_MAX_ACTIVE_USERS; i++) {
        uint8_t uid[CLOAK_UID_LEN];
        mk_uid_n(uid, i);
        cloak_userpanel_user_t *u = NULL;
        ASSERT_EQ_INT(0, cloak_userpanel_get_bypass_user(panel, uid, &u));
        ASSERT_TRUE(u != NULL);
    }
    ASSERT_EQ_INT((int)CLOAK_USERPANEL_MAX_ACTIVE_USERS,
                  (int)cloak_userpanel_active_count(panel));

    uint8_t extra[CLOAK_UID_LEN];
    mk_uid_n(extra, CLOAK_USERPANEL_MAX_ACTIVE_USERS);
    cloak_userpanel_user_t *u = (cloak_userpanel_user_t *)0x1;
    ASSERT_EQ_INT(CLOAK_USERPANEL_ERR_FULL, cloak_userpanel_get_bypass_user(panel, extra, &u));
    ASSERT_TRUE(u == NULL);
    u = (cloak_userpanel_user_t *)0x1;
    ASSERT_EQ_INT(CLOAK_USERPANEL_ERR_FULL, cloak_userpanel_get_user(panel, extra, &u));
    ASSERT_TRUE(u == NULL);

    /* THE DECISION UNDER TEST: refuse the newest, never evict an older
     * one. An eviction policy would have dropped the first user (and the
     * traffic accumulated in its valve) to make room. */
    ASSERT_TRUE(cloak_userpanel_find(panel, first) != NULL);
    ASSERT_EQ_INT((int)CLOAK_USERPANEL_MAX_ACTIVE_USERS,
                  (int)cloak_userpanel_active_count(panel));
    ASSERT_TRUE(cloak_userpanel_find(panel, extra) == NULL);

    /* A slot freed by a termination is reusable. */
    cloak_userpanel_terminate(panel, cloak_userpanel_find(panel, first), "make room");
    ASSERT_EQ_INT((int)CLOAK_USERPANEL_MAX_ACTIVE_USERS - 1,
                  (int)cloak_userpanel_active_count(panel));
    ASSERT_EQ_INT(0, cloak_userpanel_get_bypass_user(panel, extra, &u));
    ASSERT_TRUE(u != NULL);

    cloak_server_registry_destroy(&reg);
    cloak_userpanel_close(panel);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(r);
}

/* ------------------------------------------------------------------ */
/* 11. Argument handling: every entry point survives NULLs, and open     */
/*     leaves *out safe for a caller's own cleanup.                      */
/* ------------------------------------------------------------------ */
static void test_null_arguments(void) {
    cloak_userpanel_t *panel = (cloak_userpanel_t *)0x1;
    ASSERT_EQ_INT(CLOAK_USER_ERR_ARG, cloak_userpanel_open(&panel, NULL));
    ASSERT_TRUE(panel == NULL);
    cloak_userpanel_close(panel); /* must be safe on the rejected path */
    ASSERT_EQ_INT(CLOAK_USER_ERR_ARG, cloak_userpanel_open(NULL, NULL));

    uint8_t uid[CLOAK_UID_LEN];
    mk_uid(uid, 0x77);
    cloak_userpanel_user_t *u = (cloak_userpanel_user_t *)0x1;
    ASSERT_EQ_INT(CLOAK_USER_ERR_ARG, cloak_userpanel_get_user(NULL, uid, &u));
    ASSERT_TRUE(u == NULL);
    u = (cloak_userpanel_user_t *)0x1;
    ASSERT_EQ_INT(CLOAK_USER_ERR_ARG, cloak_userpanel_get_bypass_user(NULL, uid, &u));
    ASSERT_TRUE(u == NULL);
    ASSERT_TRUE(cloak_userpanel_find(NULL, uid) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_userpanel_active_count(NULL));
    ASSERT_EQ_INT(CLOAK_USER_ERR_ARG, cloak_userpanel_upload_now(NULL));
    ASSERT_TRUE(cloak_userpanel_user_valve(NULL) == NULL);
    cloak_userpanel_terminate(NULL, NULL, "x");
    cloak_userpanel_notify_session_closed(NULL, uid);
    cloak_userpanel_registry_broken(NULL, NULL, uid, 0, NULL);
    cloak_userpanel_close(NULL);
}

TEST_MAIN_BEGIN()
test_get_user_activates_and_returns_rates();
test_bypass_user_never_touches_the_manager();
test_usage_reaches_the_database_on_the_timer();
test_user_out_of_credit_is_terminated();
test_usage_of_a_disconnected_user_is_still_billed();
test_registry_accessors_count_and_close_by_uid();
test_terminate_survives_a_reentrant_close_hook();
test_terminate_from_inside_the_broken_path();
test_bypass_user_is_never_metered_or_uploaded();
test_failed_upload_is_retried_not_discarded();
test_active_table_refuses_the_newest_at_the_cap();
test_null_arguments();
TEST_MAIN_END()
