#define _POSIX_C_SOURCE 200809L
#include "cloak/adminapi.h"
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
#include "cloak/user_json.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
#include "test_framework.h"
#include "client_harness.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* End-to-end coverage for cloak_adminapi_t: a real client handshake (see
 * client_harness.h), a real dispatcher, a real cloak_session_t on both
 * sides, a real SQLite user database -- so a passing test here means the
 * admin API genuinely answers bytes on a stream, not that it agrees with
 * a mock.
 *
 * EVERY wait is a bounded pump_until, exactly as test_proxy_stream.c
 * requires of itself and for the same reason (three tests on this project
 * have hung or flaked in CI).
 *
 * THE DATABASE IS ASSERTED, NOT JUST THE STATUS CODE, wherever a request
 * is supposed to change it or supposed not to. The authorisation case
 * (case 4) is the reason that rule is written down: a handler that
 * answered 400 and performed the write anyway -- which is precisely what
 * Go's writeUserInfoHlr does -- would be green under a status-only
 * assertion. */

/* ---- temp database, per case ------------------------------------------- */

/* Same discipline as test_usermanager.c: a per-case file unlinked BOTH
 * before opening and after closing, because a case that dies on an
 * assertion otherwise leaves rows behind that make the next run's
 * "listing is empty" green or red for reasons unrelated to the code. */
static void db_tmp_path(char *buf, size_t cap, const char *tag) {
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(buf, cap, "%s/cloak_adminapi_%ld_%s.db", dir, (long)getpid(), tag);
}

static void db_unlink(const char *path) {
    char aux[512];
    unlink(path);
    snprintf(aux, sizeof(aux), "%s-wal", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-shm", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-journal", path);
    unlink(aux);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ---- fixture ------------------------------------------------------------ */

/* The chain link that follows this module. It records the ORDER as well
 * as the fact: cloak_adminapi_stream_count at the moment it runs must be
 * 0, because the chain is documented to run only after this module's
 * cleanup. A chain invoked first would see a non-zero count here. */
struct chain_record {
    int calls;
    size_t streams_at_call;
    size_t sessions_at_call;
    cloak_adminapi_t *api;
};

static void chain_cb(cloak_server_registry_t *reg, cloak_session_t *sesh,
                     const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id, void *userdata) {
    (void)reg;
    (void)sesh;
    (void)uid;
    (void)session_id;
    struct chain_record *rec = userdata;
    rec->calls++;
    rec->streams_at_call = cloak_adminapi_stream_count(rec->api);
    rec->sessions_at_call = cloak_adminapi_session_count(rec->api);
}

struct fixture {
    cloak_reactor_t *reactor;

    cover_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;

    char db_path[512];
    cloak_usermanager_t *manager;

    cloak_server_config_t cfg;
    cloak_server_t srv;
    int srv_ready;

    cloak_server_registry_t registry;
    int registry_ready;

    cloak_adminapi_t api;
    int api_ready;
    struct chain_record chain;

    cloak_dispatcher_t d;
    int d_ready;
    cloak_listener_t front;
    int have_front;

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_ok[CLOAK_UID_LEN];
};

/* Task 5's job, modelled here in the one line this module's header says
 * it should be: the owner's prepare_session chooses between the proxy and
 * the admin API. This fixture has no proxy, so every session is an admin
 * session. */
static int fx_prepare_session(cloak_dispatcher_t *d, const cloak_server_clientinfo_t *info,
                              cloak_session_config_t *config, void *userdata) {
    (void)d;
    return cloak_adminapi_prepare_session(userdata, info->uid, info->session_id, config);
}

/* conn_send_queue_cap sizes the SERVER session's outbound pool, which is
 * the quantity the backpressure case (10) is defined entirely in terms
 * of; request_timeout_ms is what the deadline case (11) shortens. Every
 * other case passes 0 for both and therefore exercises this module's own
 * defaults. */
static int fixture_init_opts(struct fixture *fx, const char *tag, size_t conn_send_queue_cap,
                             uint64_t request_timeout_ms, size_t max_list_users,
                             size_t max_streams_per_session) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    db_tmp_path(fx->db_path, sizeof(fx->db_path), tag);
    db_unlink(fx->db_path);

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

    ASSERT_EQ_INT(0, cloak_usermanager_open(&fx->manager, fx->db_path, NULL, NULL, err,
                                            sizeof(err)));
    if (fx->manager == NULL) {
        return -1;
    }

    fx->cover.reactor = fx->reactor;
    fx->cover.fd = -1;
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->cover_listener, fx->reactor, "127.0.0.1:0",
                                         cover_on_accept, &fx->cover, err, sizeof(err)));
    fx->have_cover_listener = 1;
    int cover_port = cloak_listener_port(&fx->cover_listener);
    ASSERT_TRUE(cover_port > 0);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, fx->server_pub));

    for (size_t i = 0; i < CLOAK_UID_LEN; i++) {
        fx->uid_ok[i] = (uint8_t)(0xA0 + i);
    }

    char priv_b64[64];
    char uidok_b64[32];
    ASSERT_EQ_INT(
        0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64, sizeof(priv_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(fx->uid_ok, CLOAK_UID_LEN, uidok_b64, sizeof(uidok_b64)));

    /* A ProxyBook entry still has to exist for the dispatcher to accept
     * the client's proxy method, even though nothing in this file
     * proxies: the admin session is chosen by the owner's
     * prepare_session, after the dispatcher has already validated the
     * method. 127.0.0.1:9 is the discard port and is never dialled here. */
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:9\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\"]}",
             cover_port, priv_b64, uidok_b64);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    /* The chain's middle link IS the registry's callback here, because
     * this fixture runs no proxy. In a full server the registry's own is
     * cloak_proxy_registry_broken and this one sits behind it; the
     * ordering property under test (cleanup before chain) is the same
     * either way. */
    ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor,
                                                cloak_adminapi_registry_broken, &fx->api));
    fx->registry_ready = 1;

    fx->chain.api = &fx->api;

    cloak_adminapi_config_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.reactor = fx->reactor;
    acfg.manager = fx->manager;
    acfg.request_timeout_ms = request_timeout_ms;
    acfg.max_list_users = max_list_users;
    acfg.max_streams_per_session = max_streams_per_session;
    acfg.chain = chain_cb;
    acfg.chain_userdata = &fx->chain;
    ASSERT_EQ_INT(0, cloak_adminapi_init(&fx->api, &acfg));
    fx->api_ready = 1;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.registry = &fx->registry;
    dcfg.session_config_template.max_on_wire_size = 16401;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = conn_send_queue_cap;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;
    dcfg.prepare_session = fx_prepare_session;
    dcfg.prepare_session_userdata = &fx->api;
    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, "127.0.0.1:0",
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;

    /* Shrink the send buffer of every socket this listener accepts, for
     * exactly the reason test_proxy_stream.c gives: with loopback's
     * default multi-megabyte buffers the kernel swallows a whole
     * response, cloak_conn_t never becomes backpressured, the session's
     * on_writable never fires, and case 10's entire pause/resume path is
     * never reached. Verified by mutation -- see this file's case 10. */
    int sndbuf = 8192;
    (void)setsockopt(fx->front.fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    return 0;
}

static int fixture_init(struct fixture *fx, const char *tag) {
    return fixture_init_opts(fx, tag, 262144, 0, 0, 0);
}

/* Destroy order mirrors test_proxy_stream.c's, and for the same reason:
 * THE ADMINAPI BEFORE THE REGISTRY, because releasing a stream needs a
 * live session. The manager goes last of the state, after nothing can
 * still route a request into it. */
static void fixture_destroy(struct fixture *fx) {
    if (fx->have_front) {
        cloak_listener_close(&fx->front);
    }
    if (fx->d_ready) {
        cloak_dispatcher_destroy(&fx->d);
    }
    if (fx->api_ready) {
        cloak_adminapi_destroy(&fx->api);
    }
    if (fx->registry_ready) {
        cloak_server_registry_destroy(&fx->registry);
    }
    if (fx->srv_ready) {
        cloak_server_destroy(&fx->srv);
    }
    if (fx->have_cover_listener) {
        cloak_listener_close(&fx->cover_listener);
    }
    if (fx->cover.fd >= 0) {
        close(fx->cover.fd);
    }
    if (fx->manager != NULL) {
        cloak_usermanager_close(fx->manager);
        fx->manager = NULL;
    }
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
    }
    db_unlink(fx->db_path);
}

static int open_client(struct fixture *fx, client_session_t *cs, uint32_t session_id) {
    cloak_session_config_t ccfg;
    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.max_on_wire_size = 16401;
    ccfg.stream_recv_capacity = 65536;
    ccfg.stream_max_pending_frames = 64;
    ccfg.conn_send_queue_cap = 262144;
    ccfg.inactivity_timeout_ms = 60000;
    return client_session_open(cs, fx->reactor, cloak_listener_port(&fx->front), fx->server_pub,
                               fx->uid_ok, "ss", session_id, 0, &ccfg);
}

/* ---- response accumulation ----------------------------------------------
 *
 * Reading is done by POLLING cloak_stream_read from inside the pump
 * predicate, the same construction test_proxy_stream.c uses: a poll
 * cannot miss an edge, so the wait is bounded by construction. */

#define RESP_CAP ((size_t)(1u << 20))

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

/* Offset just past the blank line ending the header block, or -1. */
static long resp_header_end(const resp_t *r) {
    for (size_t i = 0; i + 4 <= r->len; i++) {
        if (memcmp(r->buf + i, "\r\n\r\n", 4) == 0) {
            return (long)(i + 4);
        }
    }
    return -1;
}

/* The declared body length, or -1 if no Content-Length is present. This
 * is deliberately an EXACT-SPELLING search: this file is asserting the
 * bytes this module emits, so a change to the header's spelling should
 * fail here rather than be absorbed by a tolerant parser. */
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

/* Has the server closed the stream? cloak_stream_read reports
 * end-of-stream once the closing frame has drained into order. */
static int reader_ended_fn(void *ctx) {
    resp_t *r = ctx;
    resp_poll(r);
    return r->ended;
}

static int resp_status(const resp_t *r) {
    if (r->len < 12 || memcmp(r->buf, "HTTP/1.1 ", 9) != 0) {
        return -1;
    }
    return (r->buf[9] - '0') * 100 + (r->buf[10] - '0') * 10 + (r->buf[11] - '0');
}

/* Does the header block carry this exact line? */
static int resp_has_header(const resp_t *r, const char *line) {
    long he = resp_header_end(r);
    if (he < 0) {
        return 0;
    }
    size_t llen = strlen(line);
    for (size_t i = 0; i + llen + 2 <= (size_t)he; i++) {
        if (memcmp(r->buf + i, line, llen) == 0 && memcmp(r->buf + i + llen, "\r\n", 2) == 0) {
            return 1;
        }
    }
    return 0;
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
 * response. The caller owns the returned stream and must release it. */
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

static void finish(struct fixture *fx, client_session_t *cs, cloak_stream_t *st, resp_t *r) {
    (void)fx;
    resp_free(r);
    if (st != NULL) {
        cloak_session_release_stream(&cs->sesh, st);
    }
}

struct api_count_wait {
    cloak_adminapi_t *api;
    size_t want;
};

static int api_streams_eq(void *ctx) {
    struct api_count_wait *w = ctx;
    return cloak_adminapi_stream_count(w->api) == w->want;
}

static int api_streams_ge(void *ctx) {
    struct api_count_wait *w = ctx;
    return cloak_adminapi_stream_count(w->api) >= w->want;
}

/* ---- request builders ---------------------------------------------------- */

static void uid_url(const uint8_t uid[CLOAK_UID_LEN], char *out, size_t cap) {
    ASSERT_EQ_INT(0, cloak_base64url_encode(uid, CLOAK_UID_LEN, out, cap));
}

static void uid_std(const uint8_t uid[CLOAK_UID_LEN], char *out, size_t cap) {
    ASSERT_EQ_INT(0, cloak_base64_encode(uid, CLOAK_UID_LEN, out, cap));
}

static void make_uid(uint8_t uid[CLOAK_UID_LEN], uint8_t seed) {
    for (size_t i = 0; i < CLOAK_UID_LEN; i++) {
        uid[i] = (uint8_t)(seed + i);
    }
}

/* ---- 1. GET /admin/users on an empty database ---------------------------- */

static void test_list_empty(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "list_empty"));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 1));

    resp_t r;
    cloak_stream_t *st =
        request(&fx, &cs, "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n", &r);

    ASSERT_EQ_INT(200, resp_status(&r));
    /* Vestigial over a tunnel with no browser origin -- ported because Go
     * emits it, pinned here so the port stays faithful. */
    ASSERT_TRUE(resp_has_header(&r, "Access-Control-Allow-Origin: *"));
    ASSERT_TRUE(resp_has_header(&r, "Content-Type: application/json"));
    size_t blen = 0;
    const char *body = resp_body(&r, &blen);
    ASSERT_EQ_INT(2, (int)blen);
    ASSERT_MEM_EQ(body, "[]", 2);

    /* ONE STREAM IS ONE REQUEST. The stream is CLOSED once its response
     * is written, never reset for a second request -- cloak_http_parser_
     * destroy re-initializes rather than poisons, so a handler that
     * "destroyed and carried on" would start a second request from
     * whatever bytes came next. Both halves of that are asserted here:
     * the server's context is gone, and the client sees end-of-stream. */
    struct api_count_wait w0 = {&fx.api, 0};
    ASSERT_TRUE(pump_until(fx.reactor, api_streams_eq, &w0, 200, 5));
    ASSERT_EQ_INT(0, (int)cloak_adminapi_stream_count(&fx.api));
    ASSERT_TRUE(pump_until(fx.reactor, reader_ended_fn, &r, 200, 5));
    ASSERT_EQ_INT(1, r.ended);

    finish(&fx, &cs, st, &r);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 2. POST creates; a following GET returns exactly what was written --- */

static void test_post_then_get_round_trip(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "round_trip"));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 2));

    uint8_t uid[CLOAK_UID_LEN];
    make_uid(uid, 0x11);
    char up[64];
    uid_url(uid, up, sizeof(up));

    char reqbuf[1024];
    const char *json = "{\"SessionsCap\":4,\"UpRate\":100,\"DownRate\":200,"
                       "\"UpCredit\":3000,\"DownCredit\":4000,\"ExpiryTime\":1789000000}";
    snprintf(reqbuf, sizeof(reqbuf),
             "POST /admin/users/%s HTTP/1.1\r\nHost: admin\r\nContent-Type: application/json\r\n"
             "Content-Length: %zu\r\n\r\n%s",
             up, strlen(json), json);

    resp_t r;
    cloak_stream_t *st = request(&fx, &cs, reqbuf, &r);
    ASSERT_EQ_INT(201, resp_status(&r));
    finish(&fx, &cs, st, &r);

    /* The database, not merely the status. */
    cloak_user_info_t got;
    memset(&got, 0, sizeof(got));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.manager, uid, &got));
    ASSERT_EQ_INT(4, got.sessions_cap);
    ASSERT_EQ_INT(100, (int)got.up_rate);
    ASSERT_EQ_INT(200, (int)got.down_rate);
    ASSERT_EQ_INT(3000, (int)got.up_credit);
    ASSERT_EQ_INT(4000, (int)got.down_credit);
    ASSERT_EQ_INT(1789000000, (int)got.expiry_time);

    /* And the GET's bytes are exactly the codec's own rendering of that
     * row -- byte-for-byte, which is what a real `ck-client -a` compares. */
    char req2[256];
    snprintf(req2, sizeof(req2), "GET /admin/users/%s HTTP/1.1\r\nHost: admin\r\n\r\n", up);
    resp_t r2;
    cloak_stream_t *st2 = request(&fx, &cs, req2, &r2);
    ASSERT_EQ_INT(200, resp_status(&r2));

    char want[CLOAK_USER_JSON_MAX];
    size_t want_len = 0;
    ASSERT_EQ_INT(0, cloak_user_json_encode(&got, CLOAK_USER_FIELD_ALL, want, sizeof(want),
                                            &want_len));
    size_t blen = 0;
    const char *body = resp_body(&r2, &blen);
    ASSERT_EQ_INT((int)want_len, (int)blen);
    if (blen == want_len) {
        ASSERT_MEM_EQ(body, want, want_len);
    }

    finish(&fx, &cs, st2, &r2);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 3. A partial field set modifies only those fields ------------------- */

static void test_post_partial_update(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "partial"));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 3));

    uint8_t uid[CLOAK_UID_LEN];
    make_uid(uid, 0x22);
    cloak_user_info_t seed;
    memset(&seed, 0, sizeof(seed));
    memcpy(seed.uid, uid, CLOAK_UID_LEN);
    seed.sessions_cap = 7;
    seed.up_rate = 11;
    seed.down_rate = 22;
    seed.up_credit = 33;
    seed.down_credit = 44;
    seed.expiry_time = 55;
    ASSERT_EQ_INT(0, cloak_usermanager_write(fx.manager, &seed, CLOAK_USER_FIELD_ALL));

    char up[64];
    uid_url(uid, up, sizeof(up));
    const char *json = "{\"UpCredit\":9999}";
    char reqbuf[512];
    snprintf(reqbuf, sizeof(reqbuf),
             "POST /admin/users/%s HTTP/1.1\r\nHost: admin\r\nContent-Length: %zu\r\n\r\n%s", up,
             strlen(json), json);

    resp_t r;
    cloak_stream_t *st = request(&fx, &cs, reqbuf, &r);
    ASSERT_EQ_INT(201, resp_status(&r));
    finish(&fx, &cs, st, &r);

    cloak_user_info_t got;
    memset(&got, 0, sizeof(got));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.manager, uid, &got));
    ASSERT_EQ_INT(9999, (int)got.up_credit);
    /* Everything the body did not name is untouched: a mask that leaked
     * extra bits, or a router that zeroed the struct and wrote ALL, would
     * flatten every one of these to 0. */
    ASSERT_EQ_INT(7, got.sessions_cap);
    ASSERT_EQ_INT(11, (int)got.up_rate);
    ASSERT_EQ_INT(22, (int)got.down_rate);
    ASSERT_EQ_INT(44, (int)got.down_credit);
    ASSERT_EQ_INT(55, (int)got.expiry_time);

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 4. Path UID vs body UID: REFUSED, and nothing is written ------------
 *
 * THIS IS GO'S AUTHORISATION BUG (writeUserInfoHlr writes "UID mismatch"
 * and then performs the write anyway, with the BODY's UID -- so a POST to
 * /admin/users/<A> carrying a body naming <B> modifies <B>, and the path
 * is decorative). The assertions below are on the DATABASE, both that A
 * was not modified and that B was not created, because a status-only
 * assertion is green under exactly that bug. */

static void test_uid_mismatch_is_refused_and_writes_nothing(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "mismatch"));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 4));

    uint8_t uid_a[CLOAK_UID_LEN], uid_b[CLOAK_UID_LEN];
    make_uid(uid_a, 0x31);
    make_uid(uid_b, 0x71);

    cloak_user_info_t seed;
    memset(&seed, 0, sizeof(seed));
    memcpy(seed.uid, uid_a, CLOAK_UID_LEN);
    seed.sessions_cap = 1;
    seed.up_credit = 100;
    seed.down_credit = 100;
    seed.expiry_time = 12345;
    ASSERT_EQ_INT(0, cloak_usermanager_write(fx.manager, &seed, CLOAK_USER_FIELD_ALL));

    char path_a[64], body_b[64];
    uid_url(uid_a, path_a, sizeof(path_a));
    uid_std(uid_b, body_b, sizeof(body_b)); /* the BODY's UID is standard base64 */

    char json[256];
    snprintf(json, sizeof(json), "{\"UID\":\"%s\",\"UpCredit\":999999}", body_b);
    char reqbuf[512];
    snprintf(reqbuf, sizeof(reqbuf),
             "POST /admin/users/%s HTTP/1.1\r\nHost: admin\r\nContent-Length: %zu\r\n\r\n%s",
             path_a, strlen(json), json);

    resp_t r;
    cloak_stream_t *st = request(&fx, &cs, reqbuf, &r);
    ASSERT_EQ_INT(400, resp_status(&r));
    finish(&fx, &cs, st, &r);

    /* A is untouched. */
    cloak_user_info_t got_a;
    memset(&got_a, 0, sizeof(got_a));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.manager, uid_a, &got_a));
    ASSERT_EQ_INT(100, (int)got_a.up_credit);
    ASSERT_EQ_INT(1, got_a.sessions_cap);
    ASSERT_EQ_INT(12345, (int)got_a.expiry_time);

    /* B was never created -- this is the half that catches Go's actual
     * behaviour, which writes the BODY's user. */
    cloak_user_info_t got_b;
    memset(&got_b, 0, sizeof(got_b));
    ASSERT_EQ_INT(CLOAK_USER_ERR_NOT_FOUND, cloak_usermanager_get(fx.manager, uid_b, &got_b));

    /* And the whole database still holds exactly one row. */
    size_t n = 0;
    ASSERT_EQ_INT(0, cloak_usermanager_list(fx.manager, NULL, 0, &n));
    ASSERT_EQ_INT(1, (int)n);

    /* A body UID that AGREES with the path is accepted -- so the refusal
     * above is about disagreement, not about the field being present. */
    char body_a[64];
    uid_std(uid_a, body_a, sizeof(body_a));
    snprintf(json, sizeof(json), "{\"UID\":\"%s\",\"UpCredit\":4242}", body_a);
    snprintf(reqbuf, sizeof(reqbuf),
             "POST /admin/users/%s HTTP/1.1\r\nHost: admin\r\nContent-Length: %zu\r\n\r\n%s",
             path_a, strlen(json), json);
    resp_t r2;
    cloak_stream_t *st2 = request(&fx, &cs, reqbuf, &r2);
    ASSERT_EQ_INT(201, resp_status(&r2));
    finish(&fx, &cs, st2, &r2);

    memset(&got_a, 0, sizeof(got_a));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.manager, uid_a, &got_a));
    ASSERT_EQ_INT(4242, (int)got_a.up_credit);

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 5. DELETE removes; the following GET is 404 ------------------------- */

static void test_delete(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "delete"));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 5));

    uint8_t uid[CLOAK_UID_LEN];
    make_uid(uid, 0x41);
    cloak_user_info_t seed;
    memset(&seed, 0, sizeof(seed));
    memcpy(seed.uid, uid, CLOAK_UID_LEN);
    seed.sessions_cap = 2;
    ASSERT_EQ_INT(0, cloak_usermanager_write(fx.manager, &seed, CLOAK_USER_FIELD_ALL));

    char up[64];
    uid_url(uid, up, sizeof(up));
    char reqbuf[256];

    snprintf(reqbuf, sizeof(reqbuf), "DELETE /admin/users/%s HTTP/1.1\r\nHost: admin\r\n\r\n", up);
    resp_t r;
    cloak_stream_t *st = request(&fx, &cs, reqbuf, &r);
    ASSERT_EQ_INT(200, resp_status(&r));
    finish(&fx, &cs, st, &r);

    cloak_user_info_t got;
    ASSERT_EQ_INT(CLOAK_USER_ERR_NOT_FOUND, cloak_usermanager_get(fx.manager, uid, &got));

    snprintf(reqbuf, sizeof(reqbuf), "GET /admin/users/%s HTTP/1.1\r\nHost: admin\r\n\r\n", up);
    resp_t r2;
    cloak_stream_t *st2 = request(&fx, &cs, reqbuf, &r2);
    ASSERT_EQ_INT(404, resp_status(&r2));
    finish(&fx, &cs, st2, &r2);

    /* A second DELETE is 404 too, not 200 and not 500: Go answers 500
     * here (and then writes 200 over it, which is its own bug). */
    snprintf(reqbuf, sizeof(reqbuf), "DELETE /admin/users/%s HTTP/1.1\r\nHost: admin\r\n\r\n", up);
    resp_t r3;
    cloak_stream_t *st3 = request(&fx, &cs, reqbuf, &r3);
    ASSERT_EQ_INT(404, resp_status(&r3));
    finish(&fx, &cs, st3, &r3);

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 6. Unknown user 404; malformed UID 400 ------------------------------
 *
 * The malformed case uses the SAME 16 bytes rendered in the STANDARD
 * alphabet, which is the one mistake this path can actually make (the UID
 * travels standard-base64 in the JSON body of the very same request, and
 * url-safe in the path). The two renderings are asserted DIFFERENT first,
 * so the case cannot pass on a UID that encodes identically under both. */

static void test_unknown_and_malformed_uid(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "badpath"));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 6));

    /* 0xFB repeated encodes to "+/v7..." in standard base64 and
     * "-_v7..." in url-safe -- both substituted characters present. */
    uint8_t uid[CLOAK_UID_LEN];
    memset(uid, 0xFB, sizeof(uid));
    char url[64], std[64];
    uid_url(uid, url, sizeof(url));
    uid_std(uid, std, sizeof(std));
    ASSERT_TRUE(strcmp(url, std) != 0);
    ASSERT_TRUE(strchr(std, '+') != NULL);
    ASSERT_TRUE(strchr(std, '/') != NULL);

    char reqbuf[256];
    /* Well-formed url-safe UID of a user that does not exist: 404. */
    snprintf(reqbuf, sizeof(reqbuf), "GET /admin/users/%s HTTP/1.1\r\nHost: admin\r\n\r\n", url);
    resp_t r;
    cloak_stream_t *st = request(&fx, &cs, reqbuf, &r);
    ASSERT_EQ_INT(404, resp_status(&r));
    finish(&fx, &cs, st, &r);

    /* The standard-alphabet rendering of the same bytes is NOT a valid
     * path UID: 400, and no 404, because it never decoded at all. A
     * router that used cloak_base64_decode here would answer 404. */
    snprintf(reqbuf, sizeof(reqbuf), "GET /admin/users/%s HTTP/1.1\r\nHost: admin\r\n\r\n", std);
    resp_t r2;
    cloak_stream_t *st2 = request(&fx, &cs, reqbuf, &r2);
    ASSERT_EQ_INT(400, resp_status(&r2));
    finish(&fx, &cs, st2, &r2);

    /* Valid alphabet, wrong decoded length: 400, never a lookup. */
    resp_t r3;
    cloak_stream_t *st3 = request(
        &fx, &cs, "GET /admin/users/QUJD HTTP/1.1\r\nHost: admin\r\n\r\n", &r3);
    ASSERT_EQ_INT(400, resp_status(&r3));
    finish(&fx, &cs, st3, &r3);

    /* An EMPTY UID is 400 and nothing else -- Go's getUserInfoHlr writes
     * that error and then carries on to decode "" anyway. */
    resp_t r4;
    cloak_stream_t *st4 =
        request(&fx, &cs, "GET /admin/users/ HTTP/1.1\r\nHost: admin\r\n\r\n", &r4);
    ASSERT_EQ_INT(400, resp_status(&r4));
    finish(&fx, &cs, st4, &r4);

    /* An unrelated path is 404, not 405: there is no such resource at
     * all, so no method would have worked. */
    resp_t r5;
    cloak_stream_t *st5 = request(&fx, &cs, "GET /nope HTTP/1.1\r\nHost: admin\r\n\r\n", &r5);
    ASSERT_EQ_INT(404, resp_status(&r5));
    finish(&fx, &cs, st5, &r5);

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 7. Wrong method on a known path is 405 ------------------------------ */

static void test_wrong_method(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "method"));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 7));

    uint8_t uid[CLOAK_UID_LEN];
    make_uid(uid, 0x51);
    char up[64];
    uid_url(uid, up, sizeof(up));
    char reqbuf[256];

    /* The collection accepts GET only. */
    resp_t r;
    cloak_stream_t *st =
        request(&fx, &cs, "DELETE /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n", &r);
    ASSERT_EQ_INT(405, resp_status(&r));
    ASSERT_TRUE(resp_has_header(&r, "Allow: GET,OPTIONS"));
    finish(&fx, &cs, st, &r);

    resp_t r2;
    cloak_stream_t *st2 = request(&fx, &cs, "POST /admin/users HTTP/1.1\r\nHost: admin\r\n"
                                            "Content-Length: 2\r\n\r\n{}",
                                  &r2);
    ASSERT_EQ_INT(405, resp_status(&r2));
    finish(&fx, &cs, st2, &r2);

    /* An item accepts GET, POST and DELETE; PUT is CLOAK_HTTP_METHOD_OTHER
     * and is the router's 405 to answer, not the parser's error. */
    snprintf(reqbuf, sizeof(reqbuf), "PUT /admin/users/%s HTTP/1.1\r\nHost: admin\r\n\r\n", up);
    resp_t r3;
    cloak_stream_t *st3 = request(&fx, &cs, reqbuf, &r3);
    ASSERT_EQ_INT(405, resp_status(&r3));
    ASSERT_TRUE(resp_has_header(&r3, "Allow: GET,POST,DELETE,OPTIONS"));
    finish(&fx, &cs, st3, &r3);

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 8. OPTIONS returns the allow header --------------------------------- */

static void test_options(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "options"));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 8));

    resp_t r;
    cloak_stream_t *st =
        request(&fx, &cs, "OPTIONS /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n", &r);
    ASSERT_EQ_INT(200, resp_status(&r));
    ASSERT_TRUE(resp_has_header(&r, "Access-Control-Allow-Methods: GET,POST,DELETE,OPTIONS"));
    ASSERT_TRUE(resp_has_header(&r, "Access-Control-Allow-Origin: *"));
    finish(&fx, &cs, st, &r);

    /* Go registers OPTIONS on the router itself, not per route, so it
     * answers for ANY path -- including one that would otherwise 404. */
    resp_t r2;
    cloak_stream_t *st2 =
        request(&fx, &cs, "OPTIONS /whatever HTTP/1.1\r\nHost: admin\r\n\r\n", &r2);
    ASSERT_EQ_INT(200, resp_status(&r2));
    ASSERT_TRUE(resp_has_header(&r2, "Access-Control-Allow-Methods: GET,POST,DELETE,OPTIONS"));
    finish(&fx, &cs, st2, &r2);

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 9. A request split across many small writes ------------------------- */

static void test_request_split_into_single_bytes(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "split"));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 9));

    uint8_t uid[CLOAK_UID_LEN];
    make_uid(uid, 0x61);
    char up[64];
    uid_url(uid, up, sizeof(up));
    const char *json = "{\"SessionsCap\":3,\"UpCredit\":77}";
    char req[512];
    snprintf(req, sizeof(req),
             "POST /admin/users/%s HTTP/1.1\r\nHost: admin\r\nContent-Length: %zu\r\n\r\n%s", up,
             strlen(json), json);

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    resp_t r;
    resp_init(&r, st);

    /* ONE BYTE PER REACTOR TURN. Each byte crosses the tunnel in its own
     * frame, so the server's parser is genuinely resumed from every
     * intermediate state -- mid request line, mid header name, mid value,
     * mid body. */
    size_t n = strlen(req);
    for (size_t i = 0; i < n; i++) {
        ASSERT_EQ_INT(1, (int)cloak_stream_write(st, (const uint8_t *)req + i, 1));
        cloak_reactor_run_once(fx.reactor, 1);
        resp_poll(&r);
        if (i + 1 < n) {
            /* Nothing may be answered before the request is complete --
             * a parser that terminated early would show up right here. */
            ASSERT_EQ_INT(0, (int)r.len);
        }
    }
    ASSERT_TRUE(pump_until(fx.reactor, resp_complete, &r, 600, 5));
    ASSERT_EQ_INT(201, resp_status(&r));

    cloak_user_info_t got;
    memset(&got, 0, sizeof(got));
    ASSERT_EQ_INT(0, cloak_usermanager_get(fx.manager, uid, &got));
    ASSERT_EQ_INT(3, got.sessions_cap);
    ASSERT_EQ_INT(77, (int)got.up_credit);

    finish(&fx, &cs, st, &r);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 10. A response larger than the session's outbound room --------------
 *
 * THE CASE THAT BREAKS THE WHOLE SESSION IF WRONG. cloak_stream_write
 * never fails on a full queue, so a handler that wrote this listing in
 * one call would not report anything -- it would overrun a connection's
 * own send-queue cap and take the pool, and therefore every stream on
 * this session, down with it.
 *
 * The pool is deliberately smaller than the listing (32 KiB against a
 * response of roughly 55 KiB), so the write CANNOT complete in one pass
 * and the delivery depends on the pause/resume path. The assertion is
 * that every byte arrives and the document is intact. */

/* The listing both this case and case 12 provoke. Every numeric field is
 * given a long value on purpose: the response has to be several times
 * everything the two ends can buffer between them, and a row of zeroes
 * would be half the size. */
#define BIG_USERS 800

static void seed_many_users(struct fixture *fx) {
    for (int i = 0; i < BIG_USERS; i++) {
        cloak_user_info_t u;
        memset(&u, 0, sizeof(u));
        for (size_t k = 0; k < CLOAK_UID_LEN; k++) {
            u.uid[k] = (uint8_t)((i * 7 + (int)k * 13) & 0xff);
        }
        u.uid[0] = (uint8_t)(i & 0xff);
        u.uid[1] = (uint8_t)((i >> 8) & 0xff);
        u.sessions_cap = 1000000 + i;
        u.up_rate = 1234567890123LL + i;
        u.down_rate = 9876543210987LL - i;
        u.up_credit = 1000000000000LL + i;
        u.down_credit = 2000000000000LL + i;
        u.expiry_time = 1789000000 + i;
        ASSERT_EQ_INT(0, cloak_usermanager_write(fx->manager, &u, CLOAK_USER_FIELD_ALL));
    }
}

static void test_large_response_is_delivered_completely(void) {
    struct fixture fx;
    /* A 20 KiB pool holds exactly ONE worst-case frame, so the write
     * budget hits zero after every frame the kernel will not take
     * immediately. */
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "backpressure", 20000, 0, 0, 0));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 10));

    /* SHRINKING THE CLIENT'S RECEIVE BUFFER IS WHAT MAKES THIS CASE REAL,
     * and it was added because the first version of it did not: with
     * loopback's default buffers the whole listing fits between the two
     * kernels, so cloak_stream_write never backs the pool up, the write
     * pump never pauses, and on_writable is never called at all.
     * Verified by mutation -- making adminapi_on_writable a no-op passed
     * that version of this case and fails this one. */
    int rcvbuf = 8192;
    (void)setsockopt(cs.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    seed_many_users(&fx);
    size_t n_rows = 0;
    ASSERT_EQ_INT(0, cloak_usermanager_list(fx.manager, NULL, 0, &n_rows));
    ASSERT_EQ_INT(BIG_USERS, (int)n_rows);

    resp_t r;
    cloak_stream_t *st = request(&fx, &cs, "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n", &r);
    ASSERT_EQ_INT(200, resp_status(&r));

    long he = resp_header_end(&r);
    ASSERT_TRUE(he > 0);
    long cl = resp_content_length(&r, he);
    /* The response really is several times everything between the two
     * ends -- the 20 KiB pool, the server's 8 KiB send buffer and the
     * client's 8 KiB receive buffer -- so this case cannot silently
     * degrade into "one write was enough". */
    ASSERT_TRUE(cl > 4 * 20000);
    size_t blen = 0;
    const char *body = resp_body(&r, &blen);
    ASSERT_EQ_INT((int)cl, (int)blen);

    /* Every byte, and a document that is actually intact: one object per
     * user, correctly bracketed. A truncated delivery would fail the
     * length check above; a delivery that dropped a middle chunk and
     * still ended correctly would fail this count. */
    ASSERT_TRUE(blen >= 2);
    if (blen >= 2) {
        ASSERT_EQ_INT('[', body[0]);
        ASSERT_EQ_INT(']', body[blen - 1]);
    }
    int objects = 0, commas = 0;
    for (size_t i = 0; i < blen; i++) {
        if (body[i] == '{') {
            objects++;
        } else if (body[i] == ',' && i + 1 < blen && body[i + 1] == '{') {
            commas++;
        }
    }
    ASSERT_EQ_INT(BIG_USERS, objects);
    ASSERT_EQ_INT(BIG_USERS - 1, commas);

    finish(&fx, &cs, st, &r);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 11. A stream abandoned mid-request is closed by its deadline -------- */

#define DEADLINE_MS 300

static void test_abandoned_stream_hits_its_deadline(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "deadline", 262144, DEADLINE_MS, 0, 0));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 11));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    /* Half a request: a complete request line and one header, and then
     * nothing -- the header block is never terminated, so the parser
     * stays CLOAK_HTTP_INCOMPLETE forever. */
    const char *half = "GET /admin/users HTTP/1.1\r\nHost: admin\r\n";
    ASSERT_EQ_INT((int)strlen(half),
                  (int)cloak_stream_write(st, (const uint8_t *)half, strlen(half)));

    struct api_count_wait w = {&fx.api, 1};
    ASSERT_TRUE(pump_until(fx.reactor, api_streams_ge, &w, 400, 5));
    ASSERT_EQ_INT(1, (int)cloak_adminapi_stream_count(&fx.api));

    uint64_t t0 = now_ms();
    w.want = 0;
    /* 400 turns of up to 5 ms is at least 2000 ms of budget, comfortably
     * more than DEADLINE_MS. */
    ASSERT_TRUE(pump_until(fx.reactor, api_streams_eq, &w, 400, 5));
    uint64_t elapsed = now_ms() - t0;

    /* THE DURATION IS THE ASSERTION. Without it this case would pass
     * identically if the context were freed immediately for some other
     * reason -- and then it would be a test of nothing, named after a
     * deadline it never waited for. */
    ASSERT_TRUE(elapsed + 20 >= (uint64_t)DEADLINE_MS);
    ASSERT_EQ_INT(0, (int)cloak_adminapi_stream_count(&fx.api));
    /* The session context survives: one stream timing out is not the
     * session ending. */
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&fx.api));

    /* The stream really was closed by the server, not merely forgotten. */
    resp_t r;
    resp_init(&r, st);
    ASSERT_TRUE(pump_until(fx.reactor, resp_complete, &r, 200, 5) || r.ended);
    resp_free(&r);

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 12. The session breaking mid-response frees everything -------------- */

static void test_session_broken_mid_response(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "broken", 20000, 0, 0, 0));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 12));

    /* THE CLIENT IS MADE TO STOP READING, and that is what makes
     * "mid-response" a deterministic state rather than a race. Left to
     * itself the client drains the tunnel as fast as the server fills it,
     * the server's pool never stays saturated, and the whole response is
     * handed to cloak_stream_write -- at which point the stream context
     * is already gone and this case would be testing an idle session
     * teardown while claiming to test a broken one.
     *
     * Unregistering the client's socket stops its reads; shrinking its
     * receive buffer bounds what the kernel will absorb without them. The
     * response below (roughly 150 KiB) is then several times everything
     * between the two ends -- the server's 20 KiB pool, its send buffer
     * and the client's receive buffer, both shrunk -- so the server is
     * certain to still be holding an undelivered remainder. */
    int rcvbuf = 8192;
    (void)setsockopt(cs.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    ASSERT_EQ_INT(0, cloak_reactor_remove_fd(fx.reactor, cs.fd));

    seed_many_users(&fx);

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    const char *req = "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n";
    ASSERT_EQ_INT((int)strlen(req),
                  (int)cloak_stream_write(st, (const uint8_t *)req, strlen(req)));

    /* Give the server every chance to finish. 300 turns is far more than
     * the handful this response would need against a client that was
     * reading, so a stream context still alive at the end of it is one
     * that is genuinely blocked on a full pool. */
    for (int i = 0; i < 300; i++) {
        cloak_reactor_run_once(fx.reactor, 2);
    }

    /* MID-RESPONSE IS ASSERTED, NOT ASSUMED, from BOTH sides: the server
     * still holds the stream context (so it still holds an undelivered
     * response buffer and an armed deadline), and bytes of that response
     * really did leave the server -- so this is a half-written response
     * and not a request the parser never finished. MSG_PEEK looks at the
     * client's own socket without consuming anything, which is the only
     * way to observe delivery on a connection this case has deliberately
     * stopped reading. */
    ASSERT_EQ_INT(1, (int)cloak_adminapi_stream_count(&fx.api));
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&fx.api));
    uint8_t peek[1];
    ASSERT_TRUE(recv(cs.fd, peek, sizeof(peek), MSG_PEEK | MSG_DONTWAIT) == 1);

    /* Kill the client side outright. The server's connection sees EOF,
     * the session breaks, and the registry's broken callback -- this
     * module's, in this fixture -- is the ONE window in which the stream
     * can still be released and the deadline cancelled. */
    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);

    struct api_count_wait w = {&fx.api, 0};
    ASSERT_TRUE(pump_until(fx.reactor, api_streams_eq, &w, 600, 5));
    ASSERT_EQ_INT(0, (int)cloak_adminapi_stream_count(&fx.api));
    ASSERT_EQ_INT(0, (int)cloak_adminapi_session_count(&fx.api));

    /* The chain ran, and it ran AFTER the cleanup: a chain invoked first
     * would have seen a live stream context here. */
    ASSERT_EQ_INT(1, fx.chain.calls);
    ASSERT_EQ_INT(0, (int)fx.chain.streams_at_call);
    ASSERT_EQ_INT(0, (int)fx.chain.sessions_at_call);

    /* Pump on: a deadline timer left armed against the freed stream
     * would fire in this window and ASan would report the use. */
    for (int i = 0; i < 60; i++) {
        cloak_reactor_run_once(fx.reactor, 5);
    }

    fixture_destroy(&fx);
}

/* ---- 13. Parser errors become response statuses --------------------------
 *
 * The router does not re-derive these; it forwards what the parser
 * decided, which is the only way 501 and 431 can ever be answered. */

static void test_parser_errors_are_forwarded(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, "parsererr"));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 13));

    /* Transfer-Encoding of any value is 501, never ignored. */
    resp_t r;
    cloak_stream_t *st = request(&fx, &cs,
                                 "POST /admin/users/AAAAAAAAAAAAAAAAAAAAAA== HTTP/1.1\r\n"
                                 "Host: admin\r\nTransfer-Encoding: chunked\r\n\r\n",
                                 &r);
    ASSERT_EQ_INT(501, resp_status(&r));
    finish(&fx, &cs, st, &r);

    /* A Content-Length over CLOAK_HTTP_MAX_BODY is 413, decided at the
     * header, before any allocation. */
    resp_t r2;
    cloak_stream_t *st2 = request(&fx, &cs,
                                  "POST /admin/users/AAAAAAAAAAAAAAAAAAAAAA== HTTP/1.1\r\n"
                                  "Host: admin\r\nContent-Length: 999999\r\n\r\n",
                                  &r2);
    ASSERT_EQ_INT(413, resp_status(&r2));
    finish(&fx, &cs, st2, &r2);

    /* A bare LF is a hard 400. */
    resp_t r3;
    cloak_stream_t *st3 = request(&fx, &cs, "GET /admin/users HTTP/1.1\nHost: admin\r\n\r\n", &r3);
    ASSERT_EQ_INT(400, resp_status(&r3));
    finish(&fx, &cs, st3, &r3);

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 14. The per-session stream cap -------------------------------------- */

static void test_stream_cap(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "streamcap", 262144, 5000, 0, 2));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 14));

    /* Three streams that each start a request and never finish it, so
     * every context that IS created stays alive. The cap is 2. */
    cloak_stream_t *sts[3];
    const char *half = "GET /admin/users HTTP/1.1\r\nHost: admin\r\n";
    for (int i = 0; i < 3; i++) {
        sts[i] = cloak_session_open_stream(&cs.sesh, NULL);
        ASSERT_TRUE(sts[i] != NULL);
        if (sts[i] == NULL) {
            client_session_close(&cs);
            fixture_destroy(&fx);
            return;
        }
        ASSERT_EQ_INT((int)strlen(half),
                      (int)cloak_stream_write(sts[i], (const uint8_t *)half, strlen(half)));
        struct api_count_wait w = {&fx.api, (size_t)(i < 2 ? i + 1 : 2)};
        ASSERT_TRUE(pump_until(fx.reactor, api_streams_ge, &w, 200, 5));
    }
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(fx.reactor, 2);
    }
    ASSERT_EQ_INT(2, (int)cloak_adminapi_stream_count(&fx.api));

    for (int i = 0; i < 3; i++) {
        cloak_session_release_stream(&cs.sesh, sts[i]);
    }
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 15. The listing cap refuses rather than truncating ------------------- */

static void test_listing_cap_refuses(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, "listcap", 262144, 0, 3, 0));
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 15));

    for (int i = 0; i < 3; i++) {
        cloak_user_info_t u;
        memset(&u, 0, sizeof(u));
        u.uid[0] = (uint8_t)i;
        ASSERT_EQ_INT(0, cloak_usermanager_write(fx.manager, &u, CLOAK_USER_FIELD_ALL));
    }
    /* Exactly at the cap: still listed. */
    resp_t r;
    cloak_stream_t *st = request(&fx, &cs, "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n", &r);
    ASSERT_EQ_INT(200, resp_status(&r));
    finish(&fx, &cs, st, &r);

    cloak_user_info_t u4;
    memset(&u4, 0, sizeof(u4));
    u4.uid[0] = 99;
    ASSERT_EQ_INT(0, cloak_usermanager_write(fx.manager, &u4, CLOAK_USER_FIELD_ALL));

    /* One past it: REFUSED, not truncated. A truncating implementation
     * would answer 200 with three of the four users and nothing would
     * say so. */
    resp_t r2;
    cloak_stream_t *st2 =
        request(&fx, &cs, "GET /admin/users HTTP/1.1\r\nHost: admin\r\n\r\n", &r2);
    ASSERT_EQ_INT(500, resp_status(&r2));
    size_t blen = 0;
    const char *body = resp_body(&r2, &blen);
    ASSERT_TRUE(blen > 0 && body != NULL);
    if (body != NULL && blen > 0) {
        /* The body names the true count, so an operator can tell this
         * apart from a database failure. */
        ASSERT_TRUE(memchr(body, '4', blen) != NULL);
    }
    finish(&fx, &cs, st2, &r2);

    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* ---- 16. cloak_userpanel_config_t::chain ---------------------------------
 *
 * The panel is the LAST link of the broken-session chain, which is why it
 * needed a chain of its own: the owner's bookkeeping used to live in
 * cloak_proxy_config_t::chain, and that slot is now the admin API's. This
 * asserts the panel forwards -- including for the NULL uid the earlier
 * links forward when they have no key, which the panel itself ignores. */

struct panel_chain_record {
    int calls;
    int saw_null_uid;
};

static void panel_chain_cb(cloak_server_registry_t *reg, cloak_session_t *sesh,
                           const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                           void *userdata) {
    (void)reg;
    (void)sesh;
    (void)session_id;
    struct panel_chain_record *rec = userdata;
    rec->calls++;
    if (uid == NULL) {
        rec->saw_null_uid = 1;
    }
}

static void test_userpanel_chain_forwards(void) {
    cloak_reactor_t *reactor = cloak_reactor_create();
    ASSERT_TRUE(reactor != NULL);
    if (reactor == NULL) {
        return;
    }
    cloak_usermanager_t *m = NULL;
    /* A VOID manager: this case is about the chain, not the database. */
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, NULL, NULL, NULL, NULL, 0));

    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, reactor, cloak_userpanel_registry_broken,
                                                NULL));

    struct panel_chain_record rec = {0, 0};
    cloak_userpanel_t *panel = NULL;
    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = reactor;
    pcfg.no_relays = 1;
    pcfg.chain = panel_chain_cb;
    pcfg.chain_userdata = &rec;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));

    uint8_t uid[CLOAK_UID_LEN];
    make_uid(uid, 0x81);
    cloak_userpanel_registry_broken(&reg, NULL, uid, 77, panel);
    ASSERT_EQ_INT(1, rec.calls);

    /* A NULL uid is a no-op for the panel's own bookkeeping but must
     * still reach the chain -- a link that swallowed it would strand the
     * owner's notification. */
    cloak_userpanel_registry_broken(&reg, NULL, NULL, 78, panel);
    ASSERT_EQ_INT(2, rec.calls);
    ASSERT_EQ_INT(1, rec.saw_null_uid);

    /* A NULL panel has nowhere to find a chain and must do nothing. */
    cloak_userpanel_registry_broken(&reg, NULL, uid, 79, NULL);
    ASSERT_EQ_INT(2, rec.calls);

    cloak_userpanel_close(panel);
    cloak_server_registry_destroy(&reg);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(reactor);
}

/* ---- 17. Argument handling and idempotent destroy ------------------------- */

static void test_argument_and_lifetime_edges(void) {
    cloak_adminapi_t a;
    cloak_adminapi_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    /* Fully initialized before validation: every failure return leaves a
     * destroyable struct. */
    ASSERT_EQ_INT(-1, cloak_adminapi_init(&a, NULL));
    cloak_adminapi_destroy(&a);
    ASSERT_EQ_INT(0, (int)cloak_adminapi_session_count(&a));

    ASSERT_EQ_INT(-1, cloak_adminapi_init(NULL, &cfg));

    cloak_reactor_t *reactor = cloak_reactor_create();
    ASSERT_TRUE(reactor != NULL);
    if (reactor == NULL) {
        return;
    }
    cfg.reactor = reactor;
    ASSERT_EQ_INT(-1, cloak_adminapi_init(&a, &cfg)); /* no manager */
    cloak_adminapi_destroy(&a);

    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, NULL, NULL, NULL, NULL, 0));
    cfg.manager = m;
    ASSERT_EQ_INT(0, cloak_adminapi_init(&a, &cfg));

    ASSERT_EQ_INT(-1, cloak_adminapi_prepare_session(&a, NULL, 0, NULL));
    ASSERT_EQ_INT(0, (int)cloak_adminapi_session_count(&a));

    uint8_t uid[CLOAK_UID_LEN];
    make_uid(uid, 0x91);
    cloak_session_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    ASSERT_EQ_INT(0, cloak_adminapi_prepare_session(&a, uid, 5, &scfg));
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&a));
    ASSERT_TRUE(scfg.on_new_stream != NULL);
    ASSERT_TRUE(scfg.on_stream_data != NULL);
    ASSERT_TRUE(scfg.on_writable != NULL);
    /* on_broken belongs to the registry and must not be touched. */
    ASSERT_TRUE(scfg.on_broken == NULL);

    /* The abort path reclaims a context whose session never came to be. */
    cloak_adminapi_session_aborted(&a, uid, 4); /* wrong session id: no-op */
    ASSERT_EQ_INT(1, (int)cloak_adminapi_session_count(&a));
    cloak_adminapi_session_aborted(&a, uid, 5);
    ASSERT_EQ_INT(0, (int)cloak_adminapi_session_count(&a));

    /* A broken notification this module has no context for still reaches
     * the chain rather than being swallowed. */
    struct chain_record rec;
    memset(&rec, 0, sizeof(rec));
    rec.api = &a;
    a.cfg.chain = chain_cb;
    a.cfg.chain_userdata = &rec;
    cloak_adminapi_registry_broken(NULL, NULL, uid, 5, &a);
    ASSERT_EQ_INT(1, rec.calls);
    cloak_adminapi_registry_broken(NULL, NULL, NULL, 5, &a);
    ASSERT_EQ_INT(2, rec.calls);
    /* NULL userdata: not this module's callback at all. */
    cloak_adminapi_registry_broken(NULL, NULL, uid, 5, NULL);
    ASSERT_EQ_INT(2, rec.calls);

    cloak_adminapi_destroy(&a);
    cloak_adminapi_destroy(&a); /* idempotent */
    cloak_adminapi_destroy(NULL);

    cloak_usermanager_close(m);
    cloak_reactor_destroy(reactor);
}

TEST_MAIN_BEGIN()
    test_list_empty();
    test_post_then_get_round_trip();
    test_post_partial_update();
    test_uid_mismatch_is_refused_and_writes_nothing();
    test_delete();
    test_unknown_and_malformed_uid();
    test_wrong_method();
    test_options();
    test_request_split_into_single_bytes();
    test_large_response_is_delivered_completely();
    test_abandoned_stream_hits_its_deadline();
    test_session_broken_mid_response();
    test_parser_errors_are_forwarded();
    test_stream_cap();
    test_listing_cap_refuses();
    test_userpanel_chain_forwards();
    test_argument_and_lifetime_edges();
TEST_MAIN_END()
