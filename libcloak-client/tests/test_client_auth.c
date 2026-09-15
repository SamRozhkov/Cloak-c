/* The test oracle here is the MERGED, well-tested server-side verifier
 * (cloak_server_auth_decrypt, cloak/server_auth.h) -- not a hand-computed
 * literal. Every case below builds a payload with cloak_client_auth_build
 * and feeds it straight to the real decrypter with the matching private
 * key: a round trip the real verifier accepts is stronger evidence than a
 * literal, and it cannot drift if either side changes. cloak-server is
 * linked here as a test-only dependency (see this directory's
 * CMakeLists.txt) -- cloak-client itself never links it. */
#include "cloak/client_auth.h"
#include "cloak/config.h"
#include "cloak/crypto.h"
#include "cloak/server_auth.h"
#include "test_framework.h"

#include <string.h>

#define FIXED_NOW 1700000000LL

static void make_server_keypair(uint8_t priv[CLOAK_X25519_KEY_LEN], uint8_t pub[CLOAK_X25519_KEY_LEN]) {
    int rc = cloak_x25519_generate_keypair(priv, pub);
    ASSERT_EQ_INT(rc, 0);
}

static void fill_uid(uint8_t uid[CLOAK_UID_LEN], uint8_t seed) {
    for (int i = 0; i < CLOAK_UID_LEN; i++) {
        uid[i] = (uint8_t)(seed + i);
    }
}

/* Case 1 + 2: full round trip through the real server verifier. Every
 * field the client put in must come back out exactly, and the shared
 * secret the builder returned must equal the one the verifier derives
 * independently (D4 -- the primary test). */
static void test_round_trip_matches_server_verifier(void) {
    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    make_server_keypair(server_priv, server_pub);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0xa0);

    cloak_client_auth_payload_t payload;
    uint8_t client_shared_secret[CLOAK_AEAD_KEY_LEN];
    int rc = cloak_client_auth_build(uid, "shadowsocks", (uint8_t)CLOAK_AEAD_AES_256_GCM,
                                      0x12345678u, 1, FIXED_NOW, server_pub,
                                      &payload, client_shared_secret);
    ASSERT_EQ_INT(rc, 0);

    cloak_server_clientinfo_t info;
    uint8_t server_shared_secret[CLOAK_AEAD_KEY_LEN];
    rc = cloak_server_auth_decrypt(payload.random, payload.ciphertext, 32, payload.ciphertext + 32,
                                    server_priv, FIXED_NOW, &info, server_shared_secret);
    ASSERT_EQ_INT(rc, 0);

    ASSERT_MEM_EQ(info.uid, uid, CLOAK_UID_LEN);
    ASSERT_TRUE(strcmp(info.proxy_method, "shadowsocks") == 0);
    ASSERT_EQ_INT(info.encryption_method, CLOAK_AEAD_AES_256_GCM);
    ASSERT_EQ_INT(info.session_id, 0x12345678);
    ASSERT_TRUE(info.unordered);
    ASSERT_EQ_INT(info.is_admin, 0);

    /* The shared secret the builder returned to the client must be the
     * SAME value the server independently derives -- the reply decryption
     * later depends on this equality. */
    ASSERT_MEM_EQ(client_shared_secret, server_shared_secret, CLOAK_AEAD_KEY_LEN);
}

/* Case 3: the unordered flag round-trips in both states. A builder that
 * always set (or always cleared) bit 0 would pass the other test above
 * but fail one half of this one. */
static void test_unordered_flag_round_trips_both_states(void) {
    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    make_server_keypair(server_priv, server_pub);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0xb0);

    for (int unordered = 0; unordered <= 1; unordered++) {
        cloak_client_auth_payload_t payload;
        uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
        int rc = cloak_client_auth_build(uid, "ss", (uint8_t)CLOAK_AEAD_CHACHA20_POLY1305,
                                          42u, unordered, FIXED_NOW, server_pub,
                                          &payload, shared_secret);
        ASSERT_EQ_INT(rc, 0);

        cloak_server_clientinfo_t info;
        uint8_t server_shared_secret[CLOAK_AEAD_KEY_LEN];
        rc = cloak_server_auth_decrypt(payload.random, payload.ciphertext, 32, payload.ciphertext + 32,
                                        server_priv, FIXED_NOW, &info, server_shared_secret);
        ASSERT_EQ_INT(rc, 0);
        ASSERT_EQ_INT(info.unordered, unordered);
    }
}

/* Case 4a: a proxy method shorter than 12 bytes is NUL-padded -- the
 * server's own bytes.Trim-equivalent strips the padding back off, so a
 * short name must come back exactly as given. */
static void test_short_proxy_method_is_nul_padded(void) {
    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    make_server_keypair(server_priv, server_pub);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0xc0);

    cloak_client_auth_payload_t payload;
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    int rc = cloak_client_auth_build(uid, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM,
                                      1u, 0, FIXED_NOW, server_pub, &payload, shared_secret);
    ASSERT_EQ_INT(rc, 0);

    cloak_server_clientinfo_t info;
    uint8_t server_shared_secret[CLOAK_AEAD_KEY_LEN];
    rc = cloak_server_auth_decrypt(payload.random, payload.ciphertext, 32, payload.ciphertext + 32,
                                    server_priv, FIXED_NOW, &info, server_shared_secret);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_TRUE(strcmp(info.proxy_method, "ss") == 0);
}

/* Case 4b: a proxy method of exactly 12 bytes fills the field with no room
 * for a NUL terminator on the wire, and must NOT be truncated. */
static void test_full_length_proxy_method_is_not_truncated(void) {
    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    make_server_keypair(server_priv, server_pub);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0xd0);

    ASSERT_EQ_INT(CLOAK_PROXY_METHOD_LEN, 12);
    const char *method12 = "abcdefghijkl"; /* exactly 12 bytes */
    ASSERT_EQ_INT((int)strlen(method12), 12);

    cloak_client_auth_payload_t payload;
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    int rc = cloak_client_auth_build(uid, method12, (uint8_t)CLOAK_AEAD_AES_256_GCM,
                                      1u, 0, FIXED_NOW, server_pub, &payload, shared_secret);
    ASSERT_EQ_INT(rc, 0);

    cloak_server_clientinfo_t info;
    uint8_t server_shared_secret[CLOAK_AEAD_KEY_LEN];
    rc = cloak_server_auth_decrypt(payload.random, payload.ciphertext, 32, payload.ciphertext + 32,
                                    server_priv, FIXED_NOW, &info, server_shared_secret);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_TRUE(strcmp(info.proxy_method, method12) == 0);
}

/* Case 4c: a proxy method longer than 12 bytes is REJECTED rather than
 * silently cut down to fit. */
static void test_overlong_proxy_method_is_rejected(void) {
    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    make_server_keypair(server_priv, server_pub);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0xe0);

    cloak_client_auth_payload_t payload;
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    int rc = cloak_client_auth_build(uid, "abcdefghijklm" /* 13 bytes */, (uint8_t)CLOAK_AEAD_AES_256_GCM,
                                      1u, 0, FIXED_NOW, server_pub, &payload, shared_secret);
    ASSERT_EQ_INT(rc, -1);

    /* Both outputs must be left zeroed -- this rejection happens before
     * any key material is even generated. */
    uint8_t zero32[CLOAK_AEAD_KEY_LEN];
    memset(zero32, 0, sizeof(zero32));
    ASSERT_MEM_EQ(shared_secret, zero32, CLOAK_AEAD_KEY_LEN);
    ASSERT_MEM_EQ(payload.random, zero32, CLOAK_X25519_KEY_LEN);
}

/* Case 5: two calls with IDENTICAL inputs must produce DIFFERENT output,
 * because the ephemeral key pair is generated fresh every call. A builder
 * that cached, zeroed, or otherwise fixed its ephemeral key would pass
 * every other test in this file but fail this one. */
static void test_identical_inputs_produce_different_output(void) {
    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    make_server_keypair(server_priv, server_pub);
    (void)server_priv;

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0xf0);

    cloak_client_auth_payload_t payload_a, payload_b;
    uint8_t secret_a[CLOAK_AEAD_KEY_LEN], secret_b[CLOAK_AEAD_KEY_LEN];

    int rc_a = cloak_client_auth_build(uid, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM,
                                        7u, 0, FIXED_NOW, server_pub, &payload_a, secret_a);
    int rc_b = cloak_client_auth_build(uid, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM,
                                        7u, 0, FIXED_NOW, server_pub, &payload_b, secret_b);
    ASSERT_EQ_INT(rc_a, 0);
    ASSERT_EQ_INT(rc_b, 0);

    ASSERT_MEM_NE(payload_a.random, payload_b.random, CLOAK_X25519_KEY_LEN);
    ASSERT_MEM_NE(payload_a.ciphertext, payload_b.ciphertext, sizeof(payload_a.ciphertext));
    /* Different ephemeral keys against the same server key still derive
     * different ECDH shared secrets. */
    ASSERT_MEM_NE(secret_a, secret_b, CLOAK_AEAD_KEY_LEN);
}

/* Case 6: a timestamp outside the server's tolerance window is rejected BY
 * THE SERVER -- not merely "some byte was written somewhere", but
 * specifically the timestamp field at [29:37) that the server reads.
 * CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS is 180; embed a timestamp
 * far outside that window relative to the server's clock. */
static void test_stale_timestamp_rejected_by_server(void) {
    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    make_server_keypair(server_priv, server_pub);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0x01);

    /* Client embeds FIXED_NOW; the server's clock is far in the future. */
    cloak_client_auth_payload_t payload;
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    int rc = cloak_client_auth_build(uid, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM,
                                      1u, 0, FIXED_NOW, server_pub, &payload, shared_secret);
    ASSERT_EQ_INT(rc, 0);

    int64_t server_now = FIXED_NOW + CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS + 1000;
    cloak_server_clientinfo_t info;
    uint8_t server_shared_secret[CLOAK_AEAD_KEY_LEN];
    rc = cloak_server_auth_decrypt(payload.random, payload.ciphertext, 32, payload.ciphertext + 32,
                                    server_priv, server_now, &info, server_shared_secret);
    ASSERT_EQ_INT(rc, -1);

    /* Sanity check on the positive side: the very same payload, decrypted
     * against a server clock inside the window, succeeds -- proving the
     * rejection above is really about the timestamp and not about the
     * payload being generally invalid. */
    rc = cloak_server_auth_decrypt(payload.random, payload.ciphertext, 32, payload.ciphertext + 32,
                                    server_priv, FIXED_NOW, &info, server_shared_secret);
    ASSERT_EQ_INT(rc, 0);
}

/* A payload built for one server public key must not authenticate against
 * a different server's private key -- otherwise the ECDH step would be a
 * no-op and this whole module would provide no authentication at all. */
static void test_wrong_server_key_rejected(void) {
    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    make_server_keypair(server_priv, server_pub);

    uint8_t other_priv[CLOAK_X25519_KEY_LEN];
    uint8_t other_pub[CLOAK_X25519_KEY_LEN];
    make_server_keypair(other_priv, other_pub);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0x33);

    cloak_client_auth_payload_t payload;
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    int rc = cloak_client_auth_build(uid, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM,
                                      1u, 0, FIXED_NOW, server_pub, &payload, shared_secret);
    ASSERT_EQ_INT(rc, 0);

    cloak_server_clientinfo_t info;
    uint8_t server_shared_secret[CLOAK_AEAD_KEY_LEN];
    /* Decrypt with the WRONG private key (other_priv, not server_priv). */
    rc = cloak_server_auth_decrypt(payload.random, payload.ciphertext, 32, payload.ciphertext + 32,
                                    other_priv, FIXED_NOW, &info, server_shared_secret);
    ASSERT_EQ_INT(rc, -1);
}

/* proxy_method == NULL is rejected the same way an overlong one is. */
static void test_null_proxy_method_rejected(void) {
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    make_server_keypair(server_priv, server_pub);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0x44);

    cloak_client_auth_payload_t payload;
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    int rc = cloak_client_auth_build(uid, NULL, (uint8_t)CLOAK_AEAD_AES_256_GCM,
                                      1u, 0, FIXED_NOW, server_pub, &payload, shared_secret);
    ASSERT_EQ_INT(rc, -1);
}

TEST_MAIN_BEGIN()
    test_round_trip_matches_server_verifier();
    test_unordered_flag_round_trips_both_states();
    test_short_proxy_method_is_nul_padded();
    test_full_length_proxy_method_is_not_truncated();
    test_overlong_proxy_method_is_rejected();
    test_identical_inputs_produce_different_output();
    test_stale_timestamp_rejected_by_server();
    test_wrong_server_key_rejected();
    test_null_proxy_method_rejected();
TEST_MAIN_END()
