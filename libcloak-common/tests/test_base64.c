#include "cloak/base64.h"
#include "test_framework.h"

static void test_encode_rfc4648_vectors(void) {
    struct {
        const char *plain;
        const char *encoded;
    } cases[] = {
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        size_t plain_len = strlen(cases[i].plain);
        char out[32];
        ASSERT_EQ_INT(0, cloak_base64_encode((const uint8_t *)cases[i].plain,
                                             plain_len, out, sizeof(out)));
        ASSERT_EQ_INT(0, strcmp(out, cases[i].encoded));
        ASSERT_EQ_INT(strlen(cases[i].encoded) + 1,
                      cloak_base64_encoded_size(plain_len));
    }
}

static void test_decode_rfc4648_vectors(void) {
    struct {
        const char *encoded;
        const char *plain;
    } cases[] = {
        {"", ""},
        {"Zg==", "f"},
        {"Zm8=", "fo"},
        {"Zm9v", "foo"},
        {"Zm9vYg==", "foob"},
        {"Zm9vYmE=", "fooba"},
        {"Zm9vYmFy", "foobar"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t out[32];
        size_t out_len = 12345;
        ASSERT_EQ_INT(0, cloak_base64_decode(cases[i].encoded, out,
                                             sizeof(out), &out_len));
        ASSERT_EQ_INT(strlen(cases[i].plain), out_len);
        if (out_len > 0) {
            ASSERT_MEM_EQ(out, cases[i].plain, out_len);
        }
    }
}

static void test_round_trip_all_byte_values(void) {
    uint8_t plain[256];
    for (size_t i = 0; i < sizeof(plain); i++) {
        plain[i] = (uint8_t)i;
    }
    char buf[512];
    ASSERT_EQ_INT(0, cloak_base64_encode(plain, sizeof(plain), buf, sizeof(buf)));

    uint8_t decoded[256];
    size_t decoded_len = 0;
    ASSERT_EQ_INT(0, cloak_base64_decode(buf, decoded, sizeof(decoded), &decoded_len));
    ASSERT_EQ_INT(sizeof(plain), decoded_len);
    ASSERT_MEM_EQ(plain, decoded, sizeof(plain));
}

static void test_decode_rejects_malformed(void) {
    uint8_t out[32];
    size_t out_len = 0;

    /* length not a multiple of 4 */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Zm9", out, sizeof(out), &out_len));
    /* character outside the standard alphabet ('-' is URL-safe, not standard) */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Zm9-", out, sizeof(out), &out_len));
    /* whitespace is not accepted */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Zm9v Zm9v", out, sizeof(out), &out_len));
    /* padding in a non-final quantum */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Zg==Zg==", out, sizeof(out), &out_len));
    /* '=' at position 1: caught by the "'=' at position 0 or 1 is never
     * legal" rule before the count of padding characters ever matters */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Z===", out, sizeof(out), &out_len));
    /* '=' at position 1 again, for the same reason -- despite appearances
     * this never reaches the "data character after padding" check below */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Z=g=", out, sizeof(out), &out_len));
    /* '=' legally at position 2, followed by a data character at position
     * 3: the only input in this suite that reaches the j == 2 look-ahead
     * check (a data byte can't follow a single padding character) */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Zg=g", out, sizeof(out), &out_len));
    /* NULL input */
    ASSERT_EQ_INT(-1, cloak_base64_decode(NULL, out, sizeof(out), &out_len));
}

static void test_respects_output_capacity(void) {
    uint8_t out[2];
    size_t out_len = 0;
    /* "foobar" decodes to 6 bytes, which does not fit in 2 */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Zm9vYmFy", out, sizeof(out), &out_len));

    char small[4];
    const uint8_t plain[] = {1, 2, 3};
    /* needs 4 characters + NUL = 5 */
    ASSERT_EQ_INT(-1, cloak_base64_encode(plain, sizeof(plain), small, sizeof(small)));
}

static void test_decodes_a_16_byte_uid(void) {
    /* the shape every config file uses: 16 raw bytes as 24 base64 characters */
    const char *uid_b64 = "SGVsbG9DbG9ha1VJRCEhIQ==";
    uint8_t uid[16];
    size_t uid_len = 0;
    ASSERT_EQ_INT(0, cloak_base64_decode(uid_b64, uid, sizeof(uid), &uid_len));
    ASSERT_EQ_INT(16, uid_len);

    char back[64];
    ASSERT_EQ_INT(0, cloak_base64_encode(uid, uid_len, back, sizeof(back)));
    ASSERT_EQ_INT(0, strcmp(back, uid_b64));
}

TEST_MAIN_BEGIN()
    test_encode_rfc4648_vectors();
    test_decode_rfc4648_vectors();
    test_round_trip_all_byte_values();
    test_decode_rejects_malformed();
    test_respects_output_capacity();
    test_decodes_a_16_byte_uid();
TEST_MAIN_END()
