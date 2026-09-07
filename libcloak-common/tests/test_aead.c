#include "cloak/common.h"
#include "cloak/crypto.h"
#include "test_framework.h"
#include <string.h>

static void test_overhead(void) {
    ASSERT_EQ_INT(cloak_aead_overhead(CLOAK_AEAD_NONE), 0);
    ASSERT_EQ_INT(cloak_aead_overhead(CLOAK_AEAD_AES_256_GCM), CLOAK_AEAD_TAG_LEN);
}

static void test_none_is_passthrough(void) {
    uint8_t key[CLOAK_AEAD_KEY_LEN] = {0};
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN] = {0};
    const uint8_t plaintext[] = "hello cloak";
    uint8_t out[64];
    size_t out_len = 0;

    int rc = cloak_aead_seal(CLOAK_AEAD_NONE, key, nonce, plaintext, sizeof(plaintext), out, &out_len);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(out_len, sizeof(plaintext));
    ASSERT_MEM_EQ(out, plaintext, sizeof(plaintext));
}

static void test_aes256gcm_round_trip(void) {
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[] = "the quick brown fox jumps over the lazy dog";
    uint8_t ciphertext[sizeof(plaintext) + CLOAK_AEAD_TAG_LEN];
    size_t ciphertext_len = 0;

    int rc = cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, key, nonce, plaintext, sizeof(plaintext),
                              ciphertext, &ciphertext_len);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(ciphertext_len, sizeof(plaintext) + CLOAK_AEAD_TAG_LEN);

    uint8_t decrypted[sizeof(plaintext)];
    size_t decrypted_len = 0;
    rc = cloak_aead_open(CLOAK_AEAD_AES_256_GCM, key, nonce, ciphertext, ciphertext_len,
                          decrypted, &decrypted_len);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(decrypted_len, sizeof(plaintext));
    ASSERT_MEM_EQ(decrypted, plaintext, sizeof(plaintext));
}

static void test_aes256gcm_tamper_detection(void) {
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[] = "tamper me if you can";
    uint8_t ciphertext[sizeof(plaintext) + CLOAK_AEAD_TAG_LEN];
    size_t ciphertext_len = 0;
    cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, key, nonce, plaintext, sizeof(plaintext),
                     ciphertext, &ciphertext_len);

    ciphertext[0] ^= 0x01; /* flip a bit in the ciphertext */

    uint8_t decrypted[sizeof(plaintext)];
    size_t decrypted_len = 0;
    int rc = cloak_aead_open(CLOAK_AEAD_AES_256_GCM, key, nonce, ciphertext, ciphertext_len,
                              decrypted, &decrypted_len);
    ASSERT_EQ_INT(rc, -1);
}

static void test_aes256gcm_wrong_key_fails(void) {
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    uint8_t wrong_key[CLOAK_AEAD_KEY_LEN];
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(wrong_key, sizeof(wrong_key));
    cloak_random_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[] = "secret";
    uint8_t ciphertext[sizeof(plaintext) + CLOAK_AEAD_TAG_LEN];
    size_t ciphertext_len = 0;
    cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, key, nonce, plaintext, sizeof(plaintext),
                     ciphertext, &ciphertext_len);

    uint8_t decrypted[sizeof(plaintext)];
    size_t decrypted_len = 0;
    int rc = cloak_aead_open(CLOAK_AEAD_AES_256_GCM, wrong_key, nonce, ciphertext, ciphertext_len,
                              decrypted, &decrypted_len);
    ASSERT_EQ_INT(rc, -1);
}

static void round_trip_for_method(cloak_aead_method_t method) {
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[] = "round trip across every supported AEAD method";
    uint8_t ciphertext[sizeof(plaintext) + CLOAK_AEAD_TAG_LEN];
    size_t ciphertext_len = 0;

    int rc = cloak_aead_seal(method, key, nonce, plaintext, sizeof(plaintext), ciphertext, &ciphertext_len);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(ciphertext_len, sizeof(plaintext) + CLOAK_AEAD_TAG_LEN);

    uint8_t decrypted[sizeof(plaintext)];
    size_t decrypted_len = 0;
    rc = cloak_aead_open(method, key, nonce, ciphertext, ciphertext_len, decrypted, &decrypted_len);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(decrypted_len, sizeof(plaintext));
    ASSERT_MEM_EQ(decrypted, plaintext, sizeof(plaintext));
}

static void test_aes128gcm_round_trip(void) {
    round_trip_for_method(CLOAK_AEAD_AES_128_GCM);
}

static void test_chacha20poly1305_round_trip(void) {
    round_trip_for_method(CLOAK_AEAD_CHACHA20_POLY1305);
}

static void test_unknown_method_fails(void) {
    uint8_t key[CLOAK_AEAD_KEY_LEN] = {0};
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN] = {0};
    uint8_t plaintext[8] = {0};
    uint8_t out[8 + CLOAK_AEAD_TAG_LEN];
    size_t out_len = 0;

    int rc = cloak_aead_seal((cloak_aead_method_t)99, key, nonce, plaintext, sizeof(plaintext), out, &out_len);
    ASSERT_EQ_INT(rc, -1);
}

static void test_key_len_matches_effective_key_size(void) {
    ASSERT_EQ_INT(cloak_aead_key_len(CLOAK_AEAD_AES_128_GCM), 16);
    ASSERT_EQ_INT(cloak_aead_key_len(CLOAK_AEAD_AES_256_GCM), CLOAK_AEAD_KEY_LEN);
    ASSERT_EQ_INT(cloak_aead_key_len(CLOAK_AEAD_CHACHA20_POLY1305), CLOAK_AEAD_KEY_LEN);
    ASSERT_EQ_INT(cloak_aead_key_len(CLOAK_AEAD_NONE), 0);
}

static void test_aes128gcm_ignores_key_bytes_16_31(void) {
    uint8_t key_a[CLOAK_AEAD_KEY_LEN];
    uint8_t key_b[CLOAK_AEAD_KEY_LEN];
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    cloak_random_bytes(key_a, sizeof(key_a));
    cloak_random_bytes(nonce, sizeof(nonce));

    memcpy(key_b, key_a, sizeof(key_a));
    cloak_random_bytes(key_b + 16, 16); /* bytes 0-15 identical, 16-31 differ */

    const uint8_t plaintext[] = "same first 16 key bytes, different tail";
    uint8_t ciphertext_a[sizeof(plaintext) + CLOAK_AEAD_TAG_LEN];
    uint8_t ciphertext_b[sizeof(plaintext) + CLOAK_AEAD_TAG_LEN];
    size_t ciphertext_a_len = 0;
    size_t ciphertext_b_len = 0;

    int rc = cloak_aead_seal(CLOAK_AEAD_AES_128_GCM, key_a, nonce, plaintext, sizeof(plaintext),
                              ciphertext_a, &ciphertext_a_len);
    ASSERT_EQ_INT(rc, 0);
    rc = cloak_aead_seal(CLOAK_AEAD_AES_128_GCM, key_b, nonce, plaintext, sizeof(plaintext),
                          ciphertext_b, &ciphertext_b_len);
    ASSERT_EQ_INT(rc, 0);

    ASSERT_EQ_INT(ciphertext_a_len, ciphertext_b_len);
    ASSERT_MEM_EQ(ciphertext_a, ciphertext_b, ciphertext_a_len);
}

static void test_method_is_valid(void) {
    ASSERT_EQ_INT(cloak_aead_method_is_valid(CLOAK_AEAD_NONE), 1);
    ASSERT_EQ_INT(cloak_aead_method_is_valid(CLOAK_AEAD_AES_256_GCM), 1);
    ASSERT_EQ_INT(cloak_aead_method_is_valid(CLOAK_AEAD_CHACHA20_POLY1305), 1);
    ASSERT_EQ_INT(cloak_aead_method_is_valid(CLOAK_AEAD_AES_128_GCM), 1);
    ASSERT_EQ_INT(cloak_aead_method_is_valid((cloak_aead_method_t)99), 0);
}

TEST_MAIN_BEGIN()
    test_overhead();
    test_none_is_passthrough();
    test_aes256gcm_round_trip();
    test_aes256gcm_tamper_detection();
    test_aes256gcm_wrong_key_fails();
    test_aes128gcm_round_trip();
    test_chacha20poly1305_round_trip();
    test_unknown_method_fails();
    test_key_len_matches_effective_key_size();
    test_aes128gcm_ignores_key_bytes_16_31();
    test_method_is_valid();
TEST_MAIN_END()
