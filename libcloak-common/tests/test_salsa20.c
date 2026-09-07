#include "cloak/common.h"
#include "cloak/crypto.h"
#include "test_framework.h"
#include <string.h>

static void test_round_trip_short_buffer(void) {
    uint8_t key[CLOAK_SALSA20_KEY_LEN];
    uint8_t nonce[CLOAK_SALSA20_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[14] = "cloak-frame-hd"; /* 14 bytes: frame header size */
    uint8_t ciphertext[14];
    uint8_t roundtrip[14];

    cloak_salsa20_xor(ciphertext, plaintext, sizeof(plaintext), nonce, key);
    ASSERT_MEM_NE(ciphertext, plaintext, sizeof(plaintext));

    cloak_salsa20_xor(roundtrip, ciphertext, sizeof(ciphertext), nonce, key);
    ASSERT_MEM_EQ(roundtrip, plaintext, sizeof(plaintext));
}

static void test_round_trip_multi_block(void) {
    uint8_t key[CLOAK_SALSA20_KEY_LEN];
    uint8_t nonce[CLOAK_SALSA20_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    uint8_t plaintext[100];
    for (size_t i = 0; i < sizeof(plaintext); i++) {
        plaintext[i] = (uint8_t)i;
    }
    uint8_t ciphertext[100];
    uint8_t roundtrip[100];

    cloak_salsa20_xor(ciphertext, plaintext, sizeof(plaintext), nonce, key);
    cloak_salsa20_xor(roundtrip, ciphertext, sizeof(ciphertext), nonce, key);
    ASSERT_MEM_EQ(roundtrip, plaintext, sizeof(plaintext));
}

static void test_in_place_xor(void) {
    uint8_t key[CLOAK_SALSA20_KEY_LEN];
    uint8_t nonce[CLOAK_SALSA20_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    uint8_t buf[14] = "in-place-test!";
    uint8_t original[14];
    memcpy(original, buf, sizeof(buf));

    cloak_salsa20_xor(buf, buf, sizeof(buf), nonce, key);
    ASSERT_MEM_NE(buf, original, sizeof(buf));

    cloak_salsa20_xor(buf, buf, sizeof(buf), nonce, key);
    ASSERT_MEM_EQ(buf, original, sizeof(buf));
}

static void test_different_nonces_give_different_keystreams(void) {
    uint8_t key[CLOAK_SALSA20_KEY_LEN];
    uint8_t nonce_a[CLOAK_SALSA20_NONCE_LEN];
    uint8_t nonce_b[CLOAK_SALSA20_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce_a, sizeof(nonce_a));
    cloak_random_bytes(nonce_b, sizeof(nonce_b));

    uint8_t zeros[32];
    memset(zeros, 0, sizeof(zeros));

    uint8_t keystream_a[32];
    uint8_t keystream_b[32];
    cloak_salsa20_xor(keystream_a, zeros, sizeof(zeros), nonce_a, key);
    cloak_salsa20_xor(keystream_b, zeros, sizeof(zeros), nonce_b, key);

    ASSERT_MEM_NE(keystream_a, keystream_b, sizeof(keystream_a));
}

static void test_deterministic_for_same_inputs(void) {
    uint8_t key[CLOAK_SALSA20_KEY_LEN];
    uint8_t nonce[CLOAK_SALSA20_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    uint8_t zeros[32];
    memset(zeros, 0, sizeof(zeros));

    uint8_t out_a[32];
    uint8_t out_b[32];
    cloak_salsa20_xor(out_a, zeros, sizeof(zeros), nonce, key);
    cloak_salsa20_xor(out_b, zeros, sizeof(zeros), nonce, key);

    ASSERT_MEM_EQ(out_a, out_b, sizeof(out_a));
}

TEST_MAIN_BEGIN()
    test_round_trip_short_buffer();
    test_round_trip_multi_block();
    test_in_place_xor();
    test_different_nonces_give_different_keystreams();
    test_deterministic_for_same_inputs();
TEST_MAIN_END()
