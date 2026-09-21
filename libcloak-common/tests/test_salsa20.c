#include "cloak/common.h"
#include "cloak/crypto.h"
#include "test_framework.h"
#include <string.h>

static void test_round_trip_short_buffer(void) {
    uint8_t key[CLOAK_SALSA20_KEY_LEN];
    uint8_t nonce[CLOAK_SALSA20_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[14] = "cloak-frame-h"; /* 14 bytes: frame header size */
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

    uint8_t buf[14] = "in-place-test";
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

/* Known-answer vectors. Both were verified twice: once against
 * golang.org/x/crypto/salsa20 (the exact library Go Cloak depends on --
 * imported at internal/multiplex/obfs.go:12 and called at :108 and
 * :123) via
 * `go run`, and once by compiling and running this exact cloak_salsa20_xor
 * implementation standalone against the same inputs. Both runs produced
 * byte-identical output to what's below. */
static void test_known_answer_vectors(void) {
    /* Vector 1: all-zero key/nonce/input, so output is the raw keystream. */
    {
        uint8_t key[CLOAK_SALSA20_KEY_LEN];
        uint8_t nonce[CLOAK_SALSA20_NONCE_LEN];
        uint8_t input[64];
        memset(key, 0, sizeof(key));
        memset(nonce, 0, sizeof(nonce));
        memset(input, 0, sizeof(input));

        const uint8_t expected[64] = {
            0x9a, 0x97, 0xf6, 0x5b, 0x9b, 0x4c, 0x72, 0x1b,
            0x96, 0x0a, 0x67, 0x21, 0x45, 0xfc, 0xa8, 0xd4,
            0xe3, 0x2e, 0x67, 0xf9, 0x11, 0x1e, 0xa9, 0x79,
            0xce, 0x9c, 0x48, 0x26, 0x80, 0x6a, 0xee, 0xe6,
            0x3d, 0xe9, 0xc0, 0xda, 0x2b, 0xd7, 0xf9, 0x1e,
            0xbc, 0xb2, 0x63, 0x9b, 0xf9, 0x89, 0xc6, 0x25,
            0x1b, 0x29, 0xbf, 0x38, 0xd3, 0x9a, 0x9b, 0xdc,
            0xe7, 0xc5, 0x5f, 0x4b, 0x2a, 0xc1, 0x2a, 0x39,
        };

        uint8_t output[64];
        cloak_salsa20_xor(output, input, sizeof(input), nonce, key);
        ASSERT_MEM_EQ(output, expected, sizeof(expected));
    }

    /* Vector 2: non-trivial key/nonce/input, 200 bytes (multiple blocks;
     * exercises the counter-increment path across all 4 keystream blocks,
     * i.e. counter values 0, 1, 2, 3). The full 200-byte output is checked
     * against the known answer, not just a prefix. */
    {
        uint8_t key[CLOAK_SALSA20_KEY_LEN];
        uint8_t nonce[CLOAK_SALSA20_NONCE_LEN] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t input[200];
        for (size_t i = 0; i < sizeof(key); i++) {
            key[i] = (uint8_t)(i * 7 + 3);
        }
        for (size_t i = 0; i < sizeof(input); i++) {
            input[i] = (uint8_t)i;
        }

        const uint8_t expected[200] = {
            0x38, 0xcd, 0xc1, 0xd8, 0xd0, 0xb2, 0x1c, 0x34,
            0x4c, 0x90, 0x4e, 0xf4, 0x85, 0x13, 0x53, 0xd7,
            0x79, 0xf6, 0x2b, 0x1e, 0x67, 0x74, 0x4c, 0xe1,
            0xfb, 0x38, 0xde, 0xaa, 0x9e, 0x16, 0xc9, 0x48,
            0x2f, 0xe2, 0x44, 0xe2, 0x63, 0xc5, 0xf1, 0x58,
            0x40, 0x2c, 0x48, 0xd7, 0xfc, 0x40, 0xb2, 0xf4,
            0x6d, 0xb2, 0x7d, 0x5a, 0xb6, 0x58, 0x9d, 0xbc,
            0x6c, 0x3d, 0x27, 0x6f, 0x49, 0x98, 0x9d, 0xa2,
            0xc9, 0xa9, 0x4d, 0xa5, 0xe8, 0x32, 0x16, 0xe8,
            0xf1, 0x2b, 0x7a, 0x71, 0xaf, 0xa9, 0xf4, 0x2a,
            0xb4, 0x21, 0x70, 0x0d, 0x49, 0x06, 0xc6, 0xc7,
            0xd4, 0xbf, 0xc5, 0x10, 0xb6, 0x9c, 0xc2, 0x1f,
            0x05, 0x31, 0xd1, 0x79, 0x3e, 0xd5, 0xdc, 0x54,
            0xd9, 0xa8, 0x17, 0xdb, 0x4a, 0x79, 0xc5, 0x31,
            0xd0, 0xda, 0xe3, 0x5b, 0xf1, 0x7e, 0x21, 0x20,
            0x22, 0x2c, 0x3a, 0x56, 0xa2, 0xf5, 0x99, 0x7c,
            0xcf, 0x2c, 0xbf, 0x93, 0x9f, 0xfb, 0xb9, 0xbd,
            0x37, 0x67, 0xb6, 0x5b, 0xd5, 0xb1, 0x3e, 0xd3,
            0x41, 0x8d, 0x1f, 0x64, 0x74, 0x53, 0x09, 0x6a,
            0x46, 0xbd, 0x38, 0x32, 0x78, 0x66, 0x0e, 0x5e,
            0x4e, 0x14, 0x9f, 0x0a, 0xae, 0xc3, 0x6e, 0x9e,
            0xaa, 0x5c, 0x4b, 0x53, 0xb0, 0x8e, 0x95, 0xa2,
            0xef, 0x2a, 0x3e, 0x67, 0xe4, 0xc1, 0xcd, 0xfb,
            0x25, 0xad, 0x87, 0x75, 0x39, 0x84, 0xb8, 0xa3,
            0xfa, 0x68, 0xb0, 0xa1, 0x0d, 0x33, 0x36, 0x06,
        };

        uint8_t output[200];
        cloak_salsa20_xor(output, input, sizeof(input), nonce, key);
        ASSERT_MEM_EQ(output, expected, sizeof(expected));
    }
}

TEST_MAIN_BEGIN()
    test_round_trip_short_buffer();
    test_round_trip_multi_block();
    test_in_place_xor();
    test_different_nonces_give_different_keystreams();
    test_deterministic_for_same_inputs();
    test_known_answer_vectors();
TEST_MAIN_END()
