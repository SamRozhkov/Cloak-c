#define _POSIX_C_SOURCE 200809L
#include "cloak/dispatcher.h"
#include "cloak/base64.h"
#include "cloak/clienthello.h"
#include "cloak/common.h"
#include "cloak/crypto.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "test_framework.h"
#include "client_harness.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

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

/* 10. Step 10's resume path: a forced EAGAIN on the dispatcher's FIRST
 * attempt to write the reply (via test_write_shim.c's LD_PRELOAD
 * interposition -- genuine socket-buffer backpressure cannot be forced
 * for a reply this small; see that file's own top-of-file comment for
 * why, and what was tried before settling on this) must not lose or
 * corrupt anything: the connection still attaches, and the client still
 * receives a complete, correctly-encrypted reply. This is what actually
 * exercises conn_continue_reply_write's cloak_reactor_mod_fd-to-WRITABLE
 * branch and on_readable's writing_reply dispatch -- every other test in
 * this file only ever exercises the single-write-succeeds-immediately
 * path, which is the common case on loopback but not the one this test
 * targets. */
static void test_write_resumes_after_eagain(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0));

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                            (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 9009, 0, record,
                                            sizeof(record), shared_secret);

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);

    int local_port = client_local_port(client);
    ASSERT_TRUE(local_port > 0);
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", local_port);
    ASSERT_EQ_INT(0, setenv("CLOAK_TEST_FORCE_PEER_PORT", port_str, 1));
    unsetenv("CLOAK_TEST_FORCE_MODE"); /* default mode: eagain */

    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    uint8_t reply[512];
    size_t reply_len = 0;
    ASSERT_EQ_INT(0, read_reply(fx.reactor, client, reply, sizeof(reply), &reply_len));

    /* The shim consumes the env var on the one write() call it fakes --
     * if it's still set, the forced EAGAIN never actually matched
     * anything (e.g. a peer-port mismatch) and this test would otherwise
     * silently exercise only the ordinary, already-covered path. */
    ASSERT_TRUE(getenv("CLOAK_TEST_FORCE_PEER_PORT") == NULL);

    ASSERT_TRUE(reply_len >= 165);
    ASSERT_TRUE(reply_len <= 206);
    ASSERT_EQ_INT(1, fx.attached.calls);
    ASSERT_EQ_INT(1, fx.attached.last_created);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&fx.registry));

    uint8_t key[CLOAK_AEAD_KEY_LEN];
    ASSERT_EQ_INT(0, extract_session_key_from_reply(shared_secret, reply, reply_len, key));

    close(client);
    fixture_destroy(&fx);
}

/* 11. Step 10's failure path: a forced write error (ECONNRESET, via the
 * same shim) must close the connection, NOT redirect it -- the exact
 * asymmetry conn_reply_write_failed's own comment argues for and warns
 * against "fixing". A regression that redirected here instead would
 * still pass every other test in this file (none of them force a write
 * failure at all), so this is the one assertion that would actually catch
 * it: the cover site must see NOTHING (no connection, no bytes), and
 * nothing must be left attached or registered. */
static void test_write_error_closes_not_redirect(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0));

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                            (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 10010, 0, record,
                                            sizeof(record), shared_secret);

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);

    int local_port = client_local_port(client);
    ASSERT_TRUE(local_port > 0);
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", local_port);
    ASSERT_EQ_INT(0, setenv("CLOAK_TEST_FORCE_PEER_PORT", port_str, 1));
    ASSERT_EQ_INT(0, setenv("CLOAK_TEST_FORCE_MODE", "error", 1));

    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    /* Bounded wait for the dispatcher to process the (immediately
     * failing) write and tear the connection down. */
    int done = 0;
    for (int i = 0; i < 200 && !done; i++) {
        cloak_reactor_run_once(fx.reactor, 10);
        if (cloak_dispatcher_conn_count(&fx.d) == 0) {
            done = 1;
        }
    }
    ASSERT_TRUE(done);
    ASSERT_EQ_INT(0, (int)cloak_dispatcher_conn_count(&fx.d));

    ASSERT_TRUE(getenv("CLOAK_TEST_FORCE_PEER_PORT") == NULL);

    /* Not redirected: the cover site never saw this connection at all. */
    ASSERT_EQ_INT(0, fx.cover.accept_count);
    ASSERT_EQ_INT(0, (int)fx.cover.len);
    ASSERT_EQ_INT(0, fx.attached.calls);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));

    /* The client observes the connection closed, not merely idle. */
    char c;
    ssize_t n = recv(client, &c, 1, 0);
    ASSERT_TRUE(n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK));

    close(client);
    /* This test runs last in TEST_MAIN_BEGIN below, which is the only
     * reason leaving CLOAK_TEST_FORCE_MODE=error set past this point has
     * been harmless -- clear it explicitly anyway rather than rely on
     * being last, so this file stays safe to reorder or extend. */
    unsetenv("CLOAK_TEST_FORCE_MODE");
    fixture_destroy(&fx);
}

/* 12. M4: an out-of-range encryption-method byte (step 5's
 * cloak_aead_method_is_valid check) redirects, exactly like every other
 * authentication failure in this file -- cloak_aead_overhead/_key_len are
 * switch/default, not array indexing, so skipping this check would not
 * read out of bounds, but it would silently let an attacker pick a
 * session obfuscator.method no cloak_aead_seal/open call was ever
 * validated against (see dispatcher.c's step-5 comment). */
static void test_invalid_encryption_method_redirects(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, 0));

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    /* 99 is out of range for cloak_aead_method_t (valid values are 0-3) --
     * only the payload's own encryption-method byte, never the outer
     * handshake AEAD (always AES-256-GCM; see build_client_record's own
     * comment), so this reaches step 5 rather than failing to decrypt. */
    size_t record_len = build_client_record(fx.server_pub, fx.uid_ok, "ss", 99, now, 11011, 0,
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

/* 13. THE UNORDERED FLAG DECIDES THE SESSION'S ORDERING MODE. The flag
 * byte of the auth record has been parsed since module 3
 * (cloak_server_clientinfo_t::unordered) and, until this module, was read
 * by nothing that built a session -- so a client asking for datagrams got
 * a byte-stream session and no part of this suite noticed.
 *
 * Both values are driven, and the assertion is on the session the
 * dispatcher actually created, not on info: a dispatcher that ignored the
 * flag and left every session in whichever mode a template carried would
 * pass every other case in this file, including the one above that
 * already builds a session and inspects its obfuscator. Measured against
 * exactly that mutation (dispatcher.c step 8b replaced by a fixed
 * CLOAK_SESSION_ORDERING_ORDERED), which this case is what fails.
 *
 * This file's prepare_cb accepts everything, which is what lets an
 * unordered handshake get as far as a session here -- the real
 * cloak_proxy_prepare_session refuses one (cloak/proxy.h obligation 5)
 * because this port has no datagram data path yet. That refusal is a
 * policy one layer above this one, and it is tested where it lives. */
static void test_unordered_flag_selects_the_session_ordering(void) {
    const int cases[2] = {0, 1};
    for (int i = 0; i < 2; i++) {
        struct fixture fx;
        ASSERT_EQ_INT(0, fixture_init(&fx, 0));

        int64_t now = (int64_t)time(NULL);
        uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
        uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
        size_t record_len =
            build_client_record(fx.server_pub, fx.uid_ok, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM,
                                now, (uint32_t)(3101 + i), cases[i], record, sizeof(record),
                                shared_secret);
        ASSERT_TRUE(record_len > 0);

        int client = client_connect(front_port(&fx));
        ASSERT_TRUE(client >= 0);
        ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

        uint8_t reply[512];
        size_t reply_len = 0;
        ASSERT_EQ_INT(0, read_reply(fx.reactor, client, reply, sizeof(reply), &reply_len));

        ASSERT_EQ_INT(1, fx.attached.calls);
        ASSERT_EQ_INT(1, fx.attached.last_created);
        ASSERT_TRUE(fx.attached.last_sesh != NULL);
        if (fx.attached.last_sesh != NULL) {
            ASSERT_EQ_INT((int)(cases[i] ? CLOAK_SESSION_ORDERING_UNORDERED
                                         : CLOAK_SESSION_ORDERING_ORDERED),
                          (int)fx.attached.last_sesh->ordering);
        }

        close(client);
        fixture_destroy(&fx);
    }
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
    test_write_resumes_after_eagain();
    test_write_error_closes_not_redirect();
    test_invalid_encryption_method_redirects();
    test_unordered_flag_selects_the_session_ordering();
TEST_MAIN_END()
