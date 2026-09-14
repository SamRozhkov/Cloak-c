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

/* --- URL-safe alphabet (cloak_base64url_*) --- */

static void test_url_round_trip_all_byte_values(void) {
    /* Case 1: every byte value round-trips through the URL alphabet. */
    uint8_t plain[256];
    for (size_t i = 0; i < sizeof(plain); i++) {
        plain[i] = (uint8_t)i;
    }
    char buf[512];
    ASSERT_EQ_INT(0, cloak_base64url_encode(plain, sizeof(plain), buf, sizeof(buf)));

    uint8_t decoded[256];
    size_t decoded_len = 0;
    ASSERT_EQ_INT(0, cloak_base64url_decode(buf, decoded, sizeof(decoded), &decoded_len));
    ASSERT_EQ_INT(sizeof(plain), decoded_len);
    ASSERT_MEM_EQ(plain, decoded, sizeof(plain));
}

static void test_url_encode_uses_dash_and_underscore(void) {
    /* Case 2: bytes chosen so the standard alphabet's output is "+/AA"
     * (0xFB,0xF0,0x00 -> six-bit groups 62,63,0,0) -- the URL alphabet
     * must produce "-_AA" instead. This is asserted as an exact literal:
     * an implementation that just forwards to cloak_base64_encode and
     * swaps characters after the fact could pass a round-trip test but
     * not this one, and an implementation that simply calls the standard
     * encoder verbatim fails it outright. */
    const uint8_t plain[] = {0xFB, 0xF0, 0x00};
    char out[8];
    ASSERT_EQ_INT(0, cloak_base64url_encode(plain, sizeof(plain), out, sizeof(out)));
    ASSERT_EQ_INT(0, strcmp(out, "-_AA"));

    /* the same bytes under the standard alphabet must be "+/AA", so this
     * case really is exercising two different alphabets, not one */
    char std_out[8];
    ASSERT_EQ_INT(0, cloak_base64_encode(plain, sizeof(plain), std_out, sizeof(std_out)));
    ASSERT_EQ_INT(0, strcmp(std_out, "+/AA"));
}

static void test_url_decode_round_trips_the_forcing_vector(void) {
    uint8_t out[8];
    size_t out_len = 0;
    ASSERT_EQ_INT(0, cloak_base64url_decode("-_AA", out, sizeof(out), &out_len));
    ASSERT_EQ_INT(3, out_len);
    const uint8_t expected[] = {0xFB, 0xF0, 0x00};
    ASSERT_MEM_EQ(out, expected, sizeof(expected));
}

static void test_alphabets_reject_each_others_characters(void) {
    /* Case 3: each decoder rejects the other alphabet's two special
     * characters, in both directions. If encode/decode shared a single
     * table across both alphabets and something edited it carelessly,
     * exactly one of these four checks would silently start passing input
     * it must reject. */
    uint8_t out[8];
    size_t out_len = 0;

    /* the URL decoder rejects '+' and '/' */
    ASSERT_EQ_INT(-1, cloak_base64url_decode("+_AA", out, sizeof(out), &out_len));
    ASSERT_EQ_INT(-1, cloak_base64url_decode("-/AA", out, sizeof(out), &out_len));

    /* the standard decoder still rejects '-' and '_' (regression check:
     * this must keep holding after this task adds the URL alphabet) */
    ASSERT_EQ_INT(-1, cloak_base64_decode("-_AA", out, sizeof(out), &out_len));
    ASSERT_EQ_INT(-1, cloak_base64_decode("+_AA", out, sizeof(out), &out_len));
}

static void test_url_decode_padding_leniency(void) {
    /* Case 4: the padding decision, asserted both ways. cloak_base64url_decode
     * accepts the padded form (matching Go's base64.URLEncoding, what
     * api_router.go actually sends)... */
    uint8_t out[8];
    size_t out_len = 0;
    ASSERT_EQ_INT(0, cloak_base64url_decode("-_AA", out, sizeof(out), &out_len));
    ASSERT_EQ_INT(3, out_len);

    /* single-byte input: "-g==" padded */
    out_len = 0;
    ASSERT_EQ_INT(0, cloak_base64url_decode("-g==", out, sizeof(out), &out_len));
    ASSERT_EQ_INT(1, out_len);
    ASSERT_EQ_INT(0xFA, out[0]);

    /* ... and ALSO the unpadded form (Go's base64.RawURLEncoding), because
     * an operator pasting a UID by hand very often drops the '='. */
    out_len = 0;
    ASSERT_EQ_INT(0, cloak_base64url_decode("-g", out, sizeof(out), &out_len));
    ASSERT_EQ_INT(1, out_len);
    ASSERT_EQ_INT(0xFA, out[0]);

    out_len = 0;
    ASSERT_EQ_INT(0, cloak_base64url_decode("-_A", out, sizeof(out), &out_len));
    ASSERT_EQ_INT(2, out_len);
    const uint8_t expected2[] = {0xFB, 0xF0};
    ASSERT_MEM_EQ(out, expected2, sizeof(expected2));

    /* but leniency is a well-defined larger set, not guessing: a length
     * of 4n+1 is invalid under either scheme and must still be rejected,
     * and mixing padding into what claims to be an unpadded tail (a
     * six-character input, so length % 4 == 2 selects the "unpadded tail"
     * branch, yet the first quantum still carries a literal '=') must
     * still be rejected too. */
    out_len = 0;
    ASSERT_EQ_INT(-1, cloak_base64url_decode("-_AAA", out, sizeof(out), &out_len));
    ASSERT_EQ_INT(-1, cloak_base64url_decode("-_A=AA", out, sizeof(out), &out_len));
}

static void test_url_respects_output_capacity(void) {
    /* Case 5: out_cap exactly large enough, and one byte too small. */
    uint8_t out_exact[3];
    size_t out_len = 0;
    ASSERT_EQ_INT(0, cloak_base64url_decode("-_AA", out_exact, sizeof(out_exact), &out_len));
    ASSERT_EQ_INT(3, out_len);

    uint8_t out_short[2];
    ASSERT_EQ_INT(-1, cloak_base64url_decode("-_AA", out_short, sizeof(out_short), &out_len));

    const uint8_t plain[] = {0xFB, 0xF0, 0x00};
    char enc_exact[5];
    ASSERT_EQ_INT(0, cloak_base64url_encode(plain, sizeof(plain), enc_exact, sizeof(enc_exact)));
    ASSERT_EQ_INT(0, strcmp(enc_exact, "-_AA"));

    char enc_short[4];
    ASSERT_EQ_INT(-1, cloak_base64url_encode(plain, sizeof(plain), enc_short, sizeof(enc_short)));
}

TEST_MAIN_BEGIN()
    test_encode_rfc4648_vectors();
    test_decode_rfc4648_vectors();
    test_round_trip_all_byte_values();
    test_decode_rejects_malformed();
    test_respects_output_capacity();
    test_decodes_a_16_byte_uid();

    test_url_round_trip_all_byte_values();
    test_url_encode_uses_dash_and_underscore();
    test_url_decode_round_trips_the_forcing_vector();
    test_alphabets_reject_each_others_characters();
    test_url_decode_padding_leniency();
    test_url_respects_output_capacity();
TEST_MAIN_END()
