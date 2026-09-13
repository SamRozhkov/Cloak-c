#define _POSIX_C_SOURCE 200809L
#include "cloak/dispatcher.h"
#include "cloak/base64.h"
#include "cloak/clienthello.h"
#include "cloak/common.h"
#include "cloak/crypto.h"
#include "cloak/firstpacket.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "test_framework.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* This test client builds a REAL Cloak handshake from primitives already
 * merged elsewhere in this project -- cloak_x25519_generate_keypair/
 * cloak_x25519_shared_secret, cloak_aead_seal, and cloak_clienthello_build
 * -- rather than a mock, so a passing test here means the dispatcher's
 * authentication path genuinely agrees with the rest of this codebase
 * about wire format, not merely with itself.
 *
 * cloak_clienthello_build's own header (cloak/clienthello.h) documents
 * that it "Builds a ClientHello handshake message (no TLS record layer)":
 * it returns ONLY the handshake_type(1)+length(3)+body bytes, never the
 * 5-byte TLS record header. cloak_clienthello_parse (and therefore
 * cloak_firstpacket_t, which is what actually frames a connection's first
 * packet) expects that 5-byte record header to already be present -- see
 * libcloak-server/tests/test_clienthello_parse.c's own GOOD_HEX vector,
 * which starts with the record header {0x16, 0x03, 0x01, len_hi, len_lo}
 * before the handshake message begins. This test's build_client_record
 * therefore prepends that header itself; the dispatcher's own first-packet
 * framing is what requires it. */

/* ---- bounded reactor pumping (same discipline test_dispatcher_redirect.c
 * uses: every wait here is "poll for up to N turns of at most MS each",
 * never unbounded). ---------------------------------------------------- */

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

/* ---- fake cover site (same shape as test_dispatcher_redirect.c's) ------- */

typedef struct {
    cloak_reactor_t *reactor;
    int fd;
    int accept_count;
    uint8_t buf[8192];
    size_t len;
    int eof;
} cover_site_t;

static void cover_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    cover_site_t *cov = userdata;
    for (;;) {
        if (cov->len >= sizeof(cov->buf)) {
            break;
        }
        ssize_t n = read(fd, cov->buf + cov->len, sizeof(cov->buf) - cov->len);
        if (n > 0) {
            cov->len += (size_t)n;
            continue;
        }
        if (n == 0) {
            cov->eof = 1;
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        break;
    }
}

static void cover_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    cover_site_t *cov = userdata;
    cov->fd = fd;
    cov->accept_count++;
    cloak_reactor_add_fd(cov->reactor, fd, CLOAK_REACTOR_READABLE, cover_on_readable, cov);
}

struct len_wait {
    cover_site_t *cov;
    size_t want;
};

static int cover_has_len(void *ctx) {
    struct len_wait *w = ctx;
    return w->cov->len >= w->want;
}

/* ---- client helper (same shape as test_dispatcher_redirect.c's) -------- */

static int client_connect(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* ---- building a real Cloak ClientHello ---------------------------------- */

/* The 48-byte decrypted-payload layout server_auth.h documents byte for
 * byte: [0:16) UID, [16:28) NUL-padded proxy method, [28] encryption
 * method, [29:37) big-endian Unix timestamp, [37:41) big-endian session
 * id, [41] flags, [42:48) reserved. */
static void build_auth_payload(uint8_t out[48], const uint8_t uid[CLOAK_UID_LEN],
                               const char *proxy_method, uint8_t encryption_method,
                               int64_t timestamp, uint32_t session_id, int unordered) {
    memset(out, 0, 48);
    memcpy(out, uid, CLOAK_UID_LEN);

    size_t pmlen = strlen(proxy_method);
    if (pmlen > CLOAK_SERVER_AUTH_PROXY_METHOD_LEN) {
        pmlen = CLOAK_SERVER_AUTH_PROXY_METHOD_LEN;
    }
    memcpy(out + 16, proxy_method, pmlen);

    out[28] = encryption_method;

    uint64_t ts = (uint64_t)timestamp;
    for (int i = 0; i < 8; i++) {
        out[29 + i] = (uint8_t)(ts >> (8 * (7 - i)));
    }
    for (int i = 0; i < 4; i++) {
        out[37 + i] = (uint8_t)(session_id >> (8 * (3 - i)));
    }
    out[41] = unordered ? CLOAK_SERVER_AUTH_UNORDERED_FLAG : 0;
    /* [42:48) reserved -- already zero from the memset above. */
}

/* Builds one complete, framed ClientHello record (5-byte TLS record
 * header + the handshake message cloak_clienthello_build returns) for a
 * fresh ephemeral keypair, encrypting the auth payload exactly the way a
 * real Cloak client does: cloak_aead_seal with AES-256-GCM, key = the
 * ECDH shared secret against server_pub, nonce = the first 12 bytes of
 * the ephemeral public key (this is also, byte-for-byte, the same
 * "random" field cloak_server_auth_decrypt uses as ITS nonce -- see
 * server_auth.c, which passes the ClientHello's random field straight
 * through to cloak_aead_open as the nonce).
 *
 * Returns the total record length and writes the derived shared secret to
 * out_shared_secret, needed later to decrypt this connection's own reply. */
static size_t build_client_record(const uint8_t server_pub[CLOAK_X25519_KEY_LEN],
                                  const uint8_t uid[CLOAK_UID_LEN], const char *proxy_method,
                                  uint8_t encryption_method, int64_t timestamp,
                                  uint32_t session_id, int unordered, uint8_t *out_record,
                                  size_t out_cap, uint8_t out_shared_secret[CLOAK_AEAD_KEY_LEN]) {
    uint8_t eph_priv[CLOAK_X25519_KEY_LEN];
    uint8_t eph_pub[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(eph_priv, eph_pub));

    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_shared_secret(eph_priv, server_pub, shared));
    memcpy(out_shared_secret, shared, CLOAK_AEAD_KEY_LEN);

    uint8_t payload[48];
    build_auth_payload(payload, uid, proxy_method, encryption_method, timestamp, session_id,
                       unordered);

    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    memcpy(nonce, eph_pub, CLOAK_AEAD_NONCE_LEN);

    uint8_t ct[64];
    size_t ct_len = 0;
    ASSERT_EQ_INT(0, cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, shared, nonce, NULL, 0, payload,
                                     sizeof(payload), ct, &ct_len));
    ASSERT_EQ_INT((int)ct_len, 64);

    uint8_t handshake[CLOAK_CLIENTHELLO_MAX_BYTES];
    long hs_len = cloak_clienthello_build(&cloak_clienthello_chrome, eph_pub, ct, ct + 32,
                                          "www.example.com", handshake, sizeof(handshake));
    ASSERT_TRUE(hs_len > 0);
    if (hs_len <= 0) {
        return 0;
    }

    size_t total = 5 + (size_t)hs_len;
    ASSERT_TRUE(out_cap >= total);

    out_record[0] = 0x16;
    out_record[1] = 0x03;
    out_record[2] = 0x01;
    out_record[3] = (uint8_t)(((size_t)hs_len >> 8) & 0xff);
    out_record[4] = (uint8_t)((size_t)hs_len & 0xff);
    memcpy(out_record + 5, handshake, (size_t)hs_len);
    return total;
}

/* Reads a dispatcher reply off fd, pumping r as needed. The ServerHello
 * portion of any reply is always exactly 127 bytes (5-byte record header
 * + a 122-byte handshake message: cloak/server_auth.h's own
 * CLOAK_SERVER_AUTH_REPLY_MAX_BYTES comment derives the same fixed 127),
 * followed by a fixed 6-byte ChangeCipherSpec record, followed by a fake
 * Certificate record whose own 2-byte length field (at byte offset
 * [136:138) -- 127 + 6 + 3 bytes into that record's own header) tells us
 * exactly how many more bytes to expect. Once we can see that field, the
 * total reply length is fully determined and this stops pumping. */
static int read_reply(cloak_reactor_t *r, int fd, uint8_t *buf, size_t cap, size_t *out_len) {
    size_t got = 0;
    for (int i = 0; i < 300; i++) {
        cloak_reactor_run_once(r, 10);
        if (got < cap) {
            ssize_t n = recv(fd, buf + got, cap - got, MSG_DONTWAIT);
            if (n > 0) {
                got += (size_t)n;
            } else if (n == 0) {
                break;
            }
        }
        if (got >= 138) {
            size_t cert_len = ((size_t)buf[136] << 8) | (size_t)buf[137];
            size_t target = 138 + cert_len;
            if (got >= target) {
                got = target;
                break;
            }
        }
    }
    *out_len = got;
    return got > 0 ? 0 : -1;
}

/* Undoes cloak_server_auth_compose_reply's split of the 48-byte sealed
 * session key across the ServerHello's random field (bytes [11:23) =
 * reply_nonce, [23:43) = ciphertext[0:20)) and its key_share extension
 * ([89:117) = ciphertext[20:48), the offsets server_auth.c's own
 * cloak_server_auth_compose_reply writes to, then AEAD-opens it with the
 * caller's own shared secret -- exactly what a real Cloak client does to
 * recover its session key. */
static int extract_session_key_from_reply(const uint8_t shared_secret[CLOAK_AEAD_KEY_LEN],
                                          const uint8_t *reply, size_t reply_len,
                                          uint8_t out_session_key[CLOAK_AEAD_KEY_LEN]) {
    if (reply_len < 127) {
        return -1;
    }
    uint8_t reply_nonce[CLOAK_AEAD_NONCE_LEN];
    memcpy(reply_nonce, reply + 11, CLOAK_AEAD_NONCE_LEN);

    uint8_t ct[48];
    memcpy(ct, reply + 23, 20);
    memcpy(ct + 20, reply + 89, 28);

    uint8_t out[CLOAK_AEAD_KEY_LEN];
    size_t out_len = 0;
    if (cloak_aead_open(CLOAK_AEAD_AES_256_GCM, shared_secret, reply_nonce, NULL, 0, ct,
                        sizeof(ct), out, &out_len) != 0) {
        return -1;
    }
    if (out_len != CLOAK_AEAD_KEY_LEN) {
        return -1;
    }
    memcpy(out_session_key, out, CLOAK_AEAD_KEY_LEN);
    return 0;
}

/* ---- fixture: reactor + cover site + server + registry + dispatcher ---- */

typedef struct {
    int calls;
    int last_created;
    uint8_t last_uid[CLOAK_UID_LEN];
    uint32_t last_session_id;
    uint8_t last_encryption_method;
    cloak_session_t *last_sesh;
} attached_record_t;

static void attached_cb(cloak_dispatcher_t *d, cloak_session_t *sesh,
                        const cloak_server_clientinfo_t *info, int created, void *userdata) {
    (void)d;
    attached_record_t *rec = userdata;
    rec->calls++;
    rec->last_created = created;
    memcpy(rec->last_uid, info->uid, CLOAK_UID_LEN);
    rec->last_session_id = info->session_id;
    rec->last_encryption_method = info->encryption_method;
    rec->last_sesh = sesh;
}

typedef struct {
    int calls;
    int reject;
} prepare_record_t;

static int prepare_cb(cloak_dispatcher_t *d, const cloak_server_clientinfo_t *info,
                      cloak_session_config_t *config, void *userdata) {
    (void)d;
    (void)info;
    (void)config;
    prepare_record_t *rec = userdata;
    rec->calls++;
    return rec->reject ? -1 : 0;
}

/* Never expected to fire in this file: nothing here ever breaks a
 * session. Required anyway -- cloak_server_registry_init rejects a NULL
 * on_broken. */
static void registry_on_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                               const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    (void)reg;
    (void)sesh;
    (void)uid;
    (void)session_id;
    (void)userdata;
}

struct fixture {
    cloak_reactor_t *reactor;
    cover_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;
    cloak_server_config_t cfg;
    cloak_server_t srv;
    int srv_ready;
    cloak_server_registry_t registry;
    int registry_ready;
    attached_record_t attached;
    prepare_record_t prepare;
    cloak_dispatcher_t d;
    int d_ready;
    cloak_listener_t front;
    int have_front;

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_ok[CLOAK_UID_LEN];
    uint8_t uid_admin[CLOAK_UID_LEN];
    uint8_t uid_bad[CLOAK_UID_LEN];
};

/* reject_prepare: 1 makes the fixture's prepare_session callback abandon
 * every handshake that would create a new session (test case 8). */
static int fixture_init(struct fixture *fx, int reject_prepare) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

    fx->cover.reactor = fx->reactor;
    fx->cover.fd = -1;
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->cover_listener, fx->reactor, "127.0.0.1:0",
                                         cover_on_accept, &fx->cover, err, sizeof(err)));
    fx->have_cover_listener = 1;
    int cover_port = cloak_listener_port(&fx->cover_listener);
    ASSERT_TRUE(cover_port > 0);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, fx->server_pub));

    for (size_t i = 0; i < CLOAK_UID_LEN; i++) {
        fx->uid_ok[i] = (uint8_t)(0x10 + i);
        fx->uid_admin[i] = (uint8_t)(0xA0 + i);
        fx->uid_bad[i] = (uint8_t)(0x70 + i);
    }

    char priv_b64[64];
    char uidok_b64[32];
    char uidadmin_b64[32];
    ASSERT_EQ_INT(0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64,
                                         sizeof(priv_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(fx->uid_ok, CLOAK_UID_LEN, uidok_b64, sizeof(uidok_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(fx->uid_admin, CLOAK_UID_LEN, uidadmin_b64,
                                         sizeof(uidadmin_b64)));

    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"AdminUID\":\"%s\",\"BypassUID\":[\"%s\"]}",
             cover_port, priv_b64, uidadmin_b64, uidok_b64);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    ASSERT_EQ_INT(
        0, cloak_server_registry_init(&fx->registry, fx->reactor, registry_on_broken, NULL));
    fx->registry_ready = 1;

    fx->prepare.reject = reject_prepare;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.registry = &fx->registry;

    /* An inactivity_timeout_ms of 60000ms is generous relative to every
     * reactor loop bound in this file (at most a few seconds of simulated
     * time each), matching test_registry.c's own reasoning for the same
     * constant. */
    dcfg.session_config_template.max_on_wire_size = 16401;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = 262144;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;
    /* obfuscator, on_new_stream, on_stream_data, on_writable and their
     * userdata are deliberately left zeroed: obfuscator is always
     * overwritten by dispatcher_authenticate for a newly created session,
     * and no test in this file exercises stream traffic. */

    dcfg.prepare_session = prepare_cb;
    dcfg.prepare_session_userdata = &fx->prepare;
    dcfg.attached = attached_cb;
    dcfg.attached_userdata = &fx->attached;

    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, "127.0.0.1:0",
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;

    return 0;
}

/* Destroys the dispatcher BEFORE the registry: a connection dropped by
 * cloak_dispatcher_destroy mid-authentication can still call
 * cloak_server_registry_close (see dispatcher.c's conn_teardown), so the
 * registry must still be alive when that runs. */
static void fixture_destroy(struct fixture *fx) {
    if (fx->have_front) {
        cloak_listener_close(&fx->front);
    }
    if (fx->d_ready) {
        cloak_dispatcher_destroy(&fx->d);
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
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
    }
}

static int front_port(struct fixture *fx) {
    return cloak_listener_port(&fx->front);
}

/* ---- tests --------------------------------------------------------------- */

/* 1. A valid handshake attaches: the attached callback fires with
 * created == 1, the registry holds one session, and the client receives a
 * plausibly-sized reply. Not asserted on exact bytes -- the reply
 * contains random padding by design. */
static void test_valid_handshake_attaches(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0));

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                            (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 1001, 0, record,
                                            sizeof(record), shared_secret);
    ASSERT_TRUE(record_len > 0);

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    uint8_t reply[512];
    size_t reply_len = 0;
    ASSERT_EQ_INT(0, read_reply(fx.reactor, client, reply, sizeof(reply), &reply_len));

    /* 138 + min(cert_lens)=27 to 138 + max(cert_lens)=68, per
     * cloak_server_auth_cert_lens (server_auth.c). */
    ASSERT_TRUE(reply_len >= 165);
    ASSERT_TRUE(reply_len <= 206);

    ASSERT_EQ_INT(1, fx.attached.calls);
    ASSERT_EQ_INT(1, fx.attached.last_created);
    ASSERT_MEM_EQ(fx.attached.last_uid, fx.uid_ok, CLOAK_UID_LEN);
    ASSERT_EQ_INT(1001, (int)fx.attached.last_session_id);
    ASSERT_TRUE(fx.attached.last_sesh != NULL);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));
    ASSERT_EQ_INT(0, fx.cover.accept_count);

    close(client);
    fixture_destroy(&fx);
}

/* 2. THE LIVE-KEY RULE. A second connection with the same UID and session
 * id attaches to the SAME session (created == 0, registry count still 1)
 * -- and the reply it receives decrypts, with the client's OWN shared
 * secret, to the SAME session key as the first connection's reply. A
 * dispatcher that (incorrectly) composed the second reply with a freshly
 * generated key instead of sesh->obfuscator's live one would still pass
 * every other assertion in this function -- both handshakes would
 * "succeed" -- so the ASSERT_MEM_EQ on the two decrypted keys is the one
 * assertion in this whole file that actually catches that bug; a fresh
 * key differs from the first connection's key with overwhelming
 * probability (2^-256), so this does not rely on the second key
 * "happening" to differ, only on genuine random key generation. */
static void test_existing_session_uses_live_key(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0));

    int64_t now = (int64_t)time(NULL);

    uint8_t record1[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared1[CLOAK_AEAD_KEY_LEN];
    size_t len1 = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                      (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 2002, 0, record1,
                                      sizeof(record1), shared1);
    ASSERT_TRUE(len1 > 0);

    int client1 = client_connect(front_port(&fx));
    ASSERT_TRUE(client1 >= 0);
    ASSERT_TRUE(write(client1, record1, len1) == (ssize_t)len1);

    uint8_t reply1[512];
    size_t reply1_len = 0;
    ASSERT_EQ_INT(0, read_reply(fx.reactor, client1, reply1, sizeof(reply1), &reply1_len));
    ASSERT_EQ_INT(1, fx.attached.calls);
    ASSERT_EQ_INT(1, fx.attached.last_created);

    uint8_t key1[CLOAK_AEAD_KEY_LEN];
    ASSERT_EQ_INT(0, extract_session_key_from_reply(shared1, reply1, reply1_len, key1));

    /* A different ephemeral keypair (and therefore a different shared
     * secret) each build -- the same (uid, session_id) is what makes this
     * attach to the same session, not anything about the ephemeral key. */
    uint8_t record2[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared2[CLOAK_AEAD_KEY_LEN];
    size_t len2 = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                      (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 2002, 0, record2,
                                      sizeof(record2), shared2);
    ASSERT_TRUE(len2 > 0);

    int client2 = client_connect(front_port(&fx));
    ASSERT_TRUE(client2 >= 0);
    ASSERT_TRUE(write(client2, record2, len2) == (ssize_t)len2);

    uint8_t reply2[512];
    size_t reply2_len = 0;
    ASSERT_EQ_INT(0, read_reply(fx.reactor, client2, reply2, sizeof(reply2), &reply2_len));

    ASSERT_EQ_INT(2, fx.attached.calls);
    ASSERT_EQ_INT(0, fx.attached.last_created);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    uint8_t key2[CLOAK_AEAD_KEY_LEN];
    ASSERT_EQ_INT(0, extract_session_key_from_reply(shared2, reply2, reply2_len, key2));

    ASSERT_MEM_EQ(key1, key2, CLOAK_AEAD_KEY_LEN);

    close(client1);
    close(client2);
    fixture_destroy(&fx);
}

/* 3. A different session id for the same UID creates a second session. */
static void test_different_session_id_creates_second_session(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0));

    int64_t now = (int64_t)time(NULL);

    uint8_t record1[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared1[CLOAK_AEAD_KEY_LEN];
    size_t len1 = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                      (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 3003, 0, record1,
                                      sizeof(record1), shared1);
    int client1 = client_connect(front_port(&fx));
    ASSERT_TRUE(client1 >= 0);
    ASSERT_TRUE(write(client1, record1, len1) == (ssize_t)len1);
    uint8_t reply1[512];
    size_t reply1_len = 0;
    ASSERT_EQ_INT(0, read_reply(fx.reactor, client1, reply1, sizeof(reply1), &reply1_len));
    ASSERT_EQ_INT(1, fx.attached.calls);
    ASSERT_EQ_INT(1, fx.attached.last_created);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    uint8_t record2[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared2[CLOAK_AEAD_KEY_LEN];
    size_t len2 = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                      (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 3004, 0, record2,
                                      sizeof(record2), shared2);
    int client2 = client_connect(front_port(&fx));
    ASSERT_TRUE(client2 >= 0);
    ASSERT_TRUE(write(client2, record2, len2) == (ssize_t)len2);
    uint8_t reply2[512];
    size_t reply2_len = 0;
    ASSERT_EQ_INT(0, read_reply(fx.reactor, client2, reply2, sizeof(reply2), &reply2_len));

    ASSERT_EQ_INT(2, fx.attached.calls);
    ASSERT_EQ_INT(1, fx.attached.last_created);
    ASSERT_EQ_INT(2, (int)cloak_server_registry_count(&fx.registry));

    close(client1);
    close(client2);
    fixture_destroy(&fx);
}

/* 4. Replay: sending the exact same ClientHello bytes twice must redirect
 * the second attempt, and the cover site must receive them whole. */
static void test_replay_is_redirected(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0));

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                            (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 4004, 0, record,
                                            sizeof(record), shared_secret);

    int client1 = client_connect(front_port(&fx));
    ASSERT_TRUE(client1 >= 0);
    ASSERT_TRUE(write(client1, record, record_len) == (ssize_t)record_len);
    uint8_t reply[512];
    size_t reply_len = 0;
    ASSERT_EQ_INT(0, read_reply(fx.reactor, client1, reply, sizeof(reply), &reply_len));
    ASSERT_EQ_INT(1, fx.attached.calls);

    /* A NEW connection replaying the exact same bytes. */
    int client2 = client_connect(front_port(&fx));
    ASSERT_TRUE(client2 >= 0);
    ASSERT_TRUE(write(client2, record, record_len) == (ssize_t)record_len);

    struct len_wait w = {&fx.cover, record_len};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &w, 200, 20));
    ASSERT_EQ_INT((int)record_len, (int)fx.cover.len);
    ASSERT_MEM_EQ(fx.cover.buf, record, record_len);

    ASSERT_EQ_INT(1, fx.attached.calls); /* still just the first */
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    close(client1);
    close(client2);
    fixture_destroy(&fx);
}

/* 5. An unauthorised UID redirects, and the cover site receives the whole
 * ClientHello. */
static void test_unauthorised_uid_redirects(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0));

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len = build_client_record(fx.server_pub, fx.uid_bad, "ss",
                                            (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 5005, 0, record,
                                            sizeof(record), shared_secret);

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    struct len_wait w = {&fx.cover, record_len};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &w, 200, 20));
    ASSERT_EQ_INT((int)record_len, (int)fx.cover.len);
    ASSERT_MEM_EQ(fx.cover.buf, record, record_len);

    ASSERT_EQ_INT(0, fx.attached.calls);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));

    close(client);
    fixture_destroy(&fx);
}

/* 6. An unknown proxy method redirects. */
static void test_unknown_proxy_method_redirects(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0));

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len = build_client_record(fx.server_pub, fx.uid_ok, "unknownpm",
                                            (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 6006, 0, record,
                                            sizeof(record), shared_secret);

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    struct len_wait w = {&fx.cover, record_len};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &w, 200, 20));
    ASSERT_EQ_INT((int)record_len, (int)fx.cover.len);
    ASSERT_MEM_EQ(fx.cover.buf, record, record_len);

    ASSERT_EQ_INT(0, fx.attached.calls);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));

    close(client);
    fixture_destroy(&fx);
}

/* 7. A stale timestamp (outside the +/-180s tolerance window) redirects. */
static void test_stale_timestamp_redirects(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0));

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                            (uint8_t)CLOAK_AEAD_AES_256_GCM, now - 1000, 7007, 0,
                                            record, sizeof(record), shared_secret);

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    struct len_wait w = {&fx.cover, record_len};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &w, 200, 20));
    ASSERT_EQ_INT((int)record_len, (int)fx.cover.len);
    ASSERT_MEM_EQ(fx.cover.buf, record, record_len);

    ASSERT_EQ_INT(0, fx.attached.calls);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));

    close(client);
    fixture_destroy(&fx);
}

/* 8. The prepare callback returning -1 redirects, and no session is left
 * in the registry. */
static void test_prepare_rejection_redirects(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 1)); /* reject_prepare */

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                            (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 8008, 0, record,
                                            sizeof(record), shared_secret);

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    struct len_wait w = {&fx.cover, record_len};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &w, 200, 20));
    ASSERT_EQ_INT((int)record_len, (int)fx.cover.len);
    ASSERT_MEM_EQ(fx.cover.buf, record, record_len);

    ASSERT_TRUE(fx.prepare.calls >= 1);
    ASSERT_EQ_INT(0, fx.attached.calls);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));

    close(client);
    fixture_destroy(&fx);
}

/* 9. The admin UID with session id 0 is recognised -- asserted via the
 * info the attached callback captured, since the admin API itself is a
 * later module: cloak_server_is_admin on that captured UID must agree. */
static void test_admin_uid_session_zero_is_recognised(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0));

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len = build_client_record(fx.server_pub, fx.uid_admin, "ss",
                                            (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 0, 0, record,
                                            sizeof(record), shared_secret);

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    uint8_t reply[512];
    size_t reply_len = 0;
    ASSERT_EQ_INT(0, read_reply(fx.reactor, client, reply, sizeof(reply), &reply_len));

    ASSERT_EQ_INT(1, fx.attached.calls);
    ASSERT_EQ_INT(0, (int)fx.attached.last_session_id);
    ASSERT_MEM_EQ(fx.attached.last_uid, fx.uid_admin, CLOAK_UID_LEN);
    ASSERT_EQ_INT(1, cloak_server_is_admin(&fx.srv, fx.attached.last_uid));
    ASSERT_EQ_INT(1, cloak_server_is_bypass(&fx.srv, fx.attached.last_uid));

    close(client);
    fixture_destroy(&fx);
}

TEST_MAIN_BEGIN()
    test_valid_handshake_attaches();
    test_existing_session_uses_live_key();
    test_different_session_id_creates_second_session();
    test_replay_is_redirected();
    test_unauthorised_uid_redirects();
    test_unknown_proxy_method_redirects();
    test_stale_timestamp_redirects();
    test_prepare_rejection_redirects();
    test_admin_uid_session_zero_is_recognised();
TEST_MAIN_END()
