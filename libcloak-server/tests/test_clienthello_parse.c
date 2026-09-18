#include "cloak/clienthello_parse.h"
#include "cloak/clienthello.h"
#include "cloak/common.h"
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t hex_decode(const char *hex, uint8_t *out) {
    size_t n = 0;
    size_t hlen = strlen(hex);
    for (size_t i = 0; i + 1 < hlen; i += 2) {
        unsigned int byte;
        int matched = sscanf(hex + i, "%2x", &byte);
        if (matched != 1) {
            /* Malformed hex literal in test-vector-decoding code -- fail
             * loudly during development rather than silently produce
             * garbage bytes. Not reachable via attacker input; these are
             * fixed, in-source test vectors. */
            fprintf(stderr, "hex_decode: malformed hex literal at offset %zu\n", i);
            abort();
        }
        out[n++] = (uint8_t)byte;
    }
    return n;
}

/* Real, working Cloak ClientHello -- copied verbatim from Go Cloak's own
 * internal/server/TLSAux_test.go TestParseClientHello "good Cloak
 * ClientHello" case. */
static const char *GOOD_HEX =
    "1603010200010001fc03034986187cfaf4c55866a0d9b68f82505fd694a3f0fbf21ca3dcf260baad91d75e20c10e2d2c66f4f9366296678550ed769aa0c41cae7e5f480f59bd929b747ee48d0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f00000011000f00000c7777772e62696e672e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d00208d7d5a544a72e67adb1bacde46aa147b086f714c073f8335688dc13b2a032986001700414e06fb9a27480a93159f3d6273afebb4d307c4a734d7107d883b6edacb58f7d289a95ad8aaedef1b5f76fe09267a14e6bee2b6db4506b43cf0a410a4645105f79f002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/* Go's "Malformed ClientHello" test case: verified by diffing against
 * GOOD_HEX that this is not a same-length byte substitution but an inserted
 * extra hex nibble (1035 hex chars vs GOOD_HEX's 1034), which desyncs every
 * byte boundary from that point on -- a genuine structural corruption, not
 * just a semantic one, so this MUST be rejected the same way Go's own
 * parser rejects it. */
static const char *CORRUPTED_RANDOM_HEX =
    "1603010200010001fc03034986187cfaf4c55866a0d9b68f82505fd694a3f0fb2f21ca3dcf260baad91d75e20c10e2d2c66f4f9366296678550ed769aa0c41cae7e5f480f59bd929b747ee48d0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f00000011000f00000c7777772e62696e672e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d00208d7d5a544a72e67adb1bacde46aa147b086f714c073f8335688dc13b2a032986001700414e06fb9a27480a93159f3d6273afebb4d307c4a734d7107d883b6edacb58f7d289a95ad8aaedef1b5f76fe09267a14e6bee2b6db4506b43cf0a410a4645105f79f002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/* First byte 0xff instead of 0x16 -- not a handshake record. */
static const char *NOT_HANDSHAKE_HEX =
    "ff03010200010001fc03034986187cfaf4c55866a0d9b68f82505fd694a3f0fbf21ca3dcf260baad91d75e20c10e2d2c66f4f9366296678550ed769aa0c41cae7e5f480f59bd929b747ee48d0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f00000011000f00000c7777772e62696e672e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d00208d7d5a544a72e67adb1bacde46aa147b086f714c073f8335688dc13b2a032986001700414e06fb9a27480a93159f3d6273afebb4d307c4a734d7107d883b6edacb58f7d289a95ad8aaedef1b5f76fe09267a14e6bee2b6db4506b43cf0a410a4645105f79f002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/* Record-layer version 0xff01 instead of 0x0301. */
static const char *WRONG_RECORD_VERSION_HEX =
    "16ff010200010001fc03034986187cfaf4c55866a0d9b68f82505fd694a3f0fbf21ca3dcf260baad91d75e20c10e2d2c66f4f9366296678550ed769aa0c41cae7e5f480f59bd929b747ee48d0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f00000011000f00000c7777772e62696e672e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d00208d7d5a544a72e67adb1bacde46aa147b086f714c073f8335688dc13b2a032986001700414e06fb9a27480a93159f3d6273afebb4d307c4a734d7107d883b6edacb58f7d289a95ad8aaedef1b5f76fe09267a14e6bee2b6db4506b43cf0a410a4645105f79f002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/* A genuine TLS 1.2 ClientHello. Its record layer is {0x16, 0x03, 0x03} --
 * it fails this parser's magic-byte check (which requires {0x16, 0x03,
 * 0x01}) for that reason, not because of anything TLS-1.2-specific; Go's
 * parser rejects it for the same underlying reason (its own magic-byte
 * check). Both implementations agree it's an error either way. */
static const char *TLS12_HEX =
    "16030300bd010000b903035d5741ed86719917a932db1dc59a22c7166bf90f5bd693564341d091ffbac5db00002ac02cc02bc030c02f009f009ec024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a0100006600000022002000001d6e61762e736d61727473637265656e2e6d6963726f736f66742e636f6d000500050100000000000a00080006001d00170018000b00020100000d001400120401050102010403050302030202060106030023000000170000ff01000100";

static void test_good(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(GOOD_HEX, buf);
    cloak_clienthello_parsed_t out;
    int rc = cloak_clienthello_parse(buf, n, &out);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_TRUE(out.random != NULL);
    ASSERT_TRUE(out.session_id != NULL);
    ASSERT_EQ_INT(out.session_id_len, 32);
    ASSERT_TRUE(out.x25519_key_share != NULL);
    ASSERT_TRUE(out.sni != NULL);
    ASSERT_EQ_INT(out.sni_len, 12);
    ASSERT_MEM_EQ(out.sni, "www.bing.com", 12);
}

static void test_corrupted_random_rejected(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(CORRUPTED_RANDOM_HEX, buf);
    cloak_clienthello_parsed_t out;
    int rc = cloak_clienthello_parse(buf, n, &out);
    ASSERT_EQ_INT(rc, -1);
}

static void test_not_handshake(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(NOT_HANDSHAKE_HEX, buf);
    cloak_clienthello_parsed_t out;
    ASSERT_EQ_INT(cloak_clienthello_parse(buf, n, &out), -1);
}

static void test_wrong_record_version(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(WRONG_RECORD_VERSION_HEX, buf);
    cloak_clienthello_parsed_t out;
    ASSERT_EQ_INT(cloak_clienthello_parse(buf, n, &out), -1);
}

static void test_tls12(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(TLS12_HEX, buf);
    cloak_clienthello_parsed_t out;
    ASSERT_EQ_INT(cloak_clienthello_parse(buf, n, &out), -1);
}

static void test_empty(void) {
    cloak_clienthello_parsed_t out;
    ASSERT_EQ_INT(cloak_clienthello_parse(NULL, 0, &out), -1);
}

/* The critical safety property: truncate the good ClientHello at every
 * possible length from 0 to full, and confirm the parser never crashes and
 * never reads outside the buffer (this whole test binary is also run under
 * ASan+UBSan in Step 6 below). Every truncation must return -1 except the
 * one at full length.
 *
 * Each iteration's prefix is copied into a freshly `malloc`'d buffer sized
 * to *exactly* n bytes (not a fixed oversized stack array) so that ASan's
 * redzone sits immediately past the last valid byte -- an overread of even
 * one byte past the intended prefix is then a `heap-buffer-overflow`,
 * where the same overread landing inside a 4096-byte stack array would be
 * invisible to ASan. */
static void test_truncation_sweep(void) {
    uint8_t full[4096];
    size_t full_len = hex_decode(GOOD_HEX, full);
    for (size_t n = 0; n <= full_len; n++) {
        uint8_t *buf = (uint8_t *)malloc(n > 0 ? n : 1);
        memcpy(buf, full, n);
        cloak_clienthello_parsed_t out;
        int rc = cloak_clienthello_parse(buf, n, &out);
        if (n < full_len) {
            ASSERT_TRUE(rc == -1);
        } else {
            ASSERT_EQ_INT(rc, 0);
        }
        free(buf);
    }
}

/* Same sweep but flipping every single bit of every byte of the good
 * ClientHello one at a time and confirming no crash -- broader adversarial
 * coverage than truncation alone (catches bugs where an inflated
 * *interior* length field causes an OOB read while len(data) itself is
 * untouched). Not a correctness check (many single-bit mutations of a
 * valid ClientHello are still structurally well-formed, e.g. mutating a
 * byte inside `random` or the SNI hostname), so this only needs to run to
 * completion without ASan/UBSan reporting anything.
 *
 * Parses out of a `malloc`'d buffer that stays exactly full_len bytes for
 * the same ASan-redzone reason as test_truncation_sweep above. When a
 * mutation happens to still parse successfully, the output fields are
 * actually read (XORed into a volatile sink) so that a parser bug
 * returning an out-of-bounds pointer would be dereferenced -- and caught
 * by ASan -- rather than silently ignored. */
static void test_byte_flip_sweep(void) {
    uint8_t full[4096];
    size_t full_len = hex_decode(GOOD_HEX, full);
    uint8_t *buf = (uint8_t *)malloc(full_len);
    memcpy(buf, full, full_len);
    volatile uint8_t sink = 0;
    for (size_t i = 0; i < full_len; i++) {
        uint8_t saved = buf[i];
        for (int bit = 0; bit < 8; bit++) {
            buf[i] = (uint8_t)(saved ^ (1u << bit));
            cloak_clienthello_parsed_t out;
            int rc = cloak_clienthello_parse(buf, full_len, &out); /* must not crash */
            if (rc == 0) {
                sink ^= out.random[0];
                sink ^= out.random[CLOAK_CLIENTHELLO_PARSE_RANDOM_LEN - 1];
                if (out.session_id_len > 0) {
                    sink ^= out.session_id[0];
                    sink ^= out.session_id[out.session_id_len - 1];
                }
                if (out.sni != NULL && out.sni_len > 0) {
                    sink ^= out.sni[0];
                    sink ^= out.sni[out.sni_len - 1];
                }
                if (out.x25519_key_share != NULL) {
                    sink ^= out.x25519_key_share[0];
                    sink ^= out.x25519_key_share[CLOAK_CLIENTHELLO_PARSE_X25519_LEN - 1];
                }
            }
        }
        buf[i] = saved;
    }
    free(buf);
    /* `sink` must be READ somewhere, not only written, or clang 14 reports
     * `variable 'sink' set but not used` [-Wunused-but-set-variable] and
     * this project's build is required to be warning-free under BOTH gcc
     * and clang (module 10a added clang to the dev image for libFuzzer).
     *
     * This load is the fix, and it deliberately does not weaken what the
     * `volatile` is for. The XORs in the loop above are volatile STORES,
     * which the compiler may not elide, so the reads of out.random /
     * out.session_id / out.sni / out.x25519_key_share that feed them must
     * still be performed -- that is the whole point of the sink, and it is
     * unchanged by this line. Initialising a non-volatile local from a
     * volatile lvalue is an unambiguous volatile load (unlike `(void)sink;`,
     * whose access is implementation-defined), so it always executes.
     *
     * Nothing can be asserted about the VALUE: which bytes get XORed in
     * depends on which single-bit mutations happen to still parse, so the
     * value is data-dependent and carries no expectation. */
    const uint8_t sink_value = sink;
    (void)sink_value;
    ASSERT_TRUE(1); /* reaching here without an ASan/UBSan abort is the test */
}

/* Locks in the header's documented contract: a missing server_name
 * extension is NOT a parse failure, only structural malformation is. This
 * rewrites the SNI extension's 2-byte type field (server_name == 0x0000,
 * matched via its exact ext_type/ext_len byte sequence for this fixed
 * vector) to an unused value so the parser's extension walk skips over it
 * without recognizing it as server_name -- everything else, including the
 * key_share extension, stays intact and should still be found. */
static void test_missing_sni_is_not_a_failure(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(GOOD_HEX, buf);
    /* server_name extension type is 0x0000 at some offset within the
     * extensions block; rewrite its 2-byte type field to an unused value
     * (0xfff0) so the parser's extension walk skips over it without
     * recognizing it as server_name. Locate it by scanning for the exact
     * 4-byte sequence {0x00, 0x00, 0x00, 0x11} (ext_type=0x0000,
     * ext_len=0x0011=17, matching this vector's SNI extension) since this
     * is a fixed, known-good test vector, not attacker input. */
    int found = 0;
    for (size_t i = 0; i + 4 <= n; i++) {
        if (buf[i] == 0x00 && buf[i + 1] == 0x00 && buf[i + 2] == 0x00 && buf[i + 3] == 0x11) {
            buf[i] = 0xff;
            buf[i + 1] = 0xf0;
            found = 1;
            break;
        }
    }
    ASSERT_TRUE(found);
    cloak_clienthello_parsed_t out;
    int rc = cloak_clienthello_parse(buf, n, &out);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_TRUE(out.sni == NULL);
    ASSERT_TRUE(out.x25519_key_share != NULL); /* untouched, should still be found */
}

/* Same contract, for the key_share extension: rewrite its 2-byte type
 * field (0x0033) to an unused value so the parser doesn't recognize it,
 * leaving the SNI extension untouched. */
static void test_missing_key_share_is_not_a_failure(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(GOOD_HEX, buf);
    /* key_share extension type is 0x0033; rewrite it the same way. Note
     * 0x0033 also appears earlier in this vector as a plain cipher-suite
     * value (TLS_DHE_RSA_WITH_AES_128_CBC_SHA in the cipher_suites list),
     * so anchor on the 4-byte {ext_type=0x0033, ext_len=0x006b} sequence
     * that is unique to this vector's actual key_share extension header,
     * rather than the bare 2-byte type alone. */
    int found = 0;
    for (size_t i = 0; i + 4 <= n; i++) {
        if (buf[i] == 0x00 && buf[i + 1] == 0x33 && buf[i + 2] == 0x00 && buf[i + 3] == 0x6b) {
            buf[i] = 0xff;
            buf[i + 1] = 0xf1;
            found = 1;
            break;
        }
    }
    ASSERT_TRUE(found);
    cloak_clienthello_parsed_t out;
    int rc = cloak_clienthello_parse(buf, n, &out);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_TRUE(out.x25519_key_share == NULL);
    ASSERT_TRUE(out.sni != NULL); /* untouched, should still be found */
}

/* Same contract, one level deeper: the key_share extension itself is
 * present and well-formed, it just doesn't contain an X25519 (group
 * 0x001d) entry -- rewrite that one group id to 0x0017 (secp256r1) so no
 * group-0x001d entry exists. */
static void test_key_share_without_x25519_group_is_not_a_failure(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(GOOD_HEX, buf);
    /* Within the key_share extension's entry list, this vector's X25519
     * entry has group 0x001d. Rewrite that one group id to 0x0017
     * (secp256r1) so no group-0x001d entry exists -- the key_share
     * extension itself is still present and well-formed, it just doesn't
     * contain an X25519 entry. Note 0x001d also appears earlier in this
     * vector inside the supported_groups extension's list of *advertised*
     * groups (which this parser doesn't even inspect), so anchor on the
     * 6-byte {client_shares list_len=0x0069, group=0x001d, key_len=0x0020}
     * sequence that is unique to this vector's actual key_share entry,
     * rather than the bare 2-byte group id alone. */
    int found = 0;
    for (size_t i = 0; i + 6 <= n; i++) {
        if (buf[i] == 0x00 && buf[i + 1] == 0x69 && buf[i + 2] == 0x00 && buf[i + 3] == 0x1d &&
            buf[i + 4] == 0x00 && buf[i + 5] == 0x20) {
            buf[i + 3] = 0x17;
            found = 1;
            break;
        }
    }
    ASSERT_TRUE(found);
    cloak_clienthello_parsed_t out;
    int rc = cloak_clienthello_parse(buf, n, &out);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_TRUE(out.x25519_key_share == NULL);
}

static void store_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* Round-trip against this repository's own client-side ClientHello
 * builder: build a real ClientHello (record layer prepended), parse it
 * back, and confirm every field this parser extracts matches exactly what
 * was spliced in during building. Proves the client and server halves of
 * this project agree on wire format -- this is the only place this test
 * file (or the library) touches libcloak-common. */
static void round_trip_one(const cloak_clienthello_template_t *tmpl, const char *sni) {
    uint8_t random[32], session_id[32], keyshare[32];
    cloak_random_bytes(random, 32);
    cloak_random_bytes(session_id, 32);
    cloak_random_bytes(keyshare, 32);

    uint8_t built[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    long n = cloak_clienthello_build(tmpl, random, session_id, keyshare, sni,
                                      built + 5, sizeof(built) - 5);
    ASSERT_TRUE(n > 0);
    if (n <= 0) {
        return;
    }
    built[0] = 0x16;
    built[1] = 0x03;
    built[2] = 0x01;
    store_be16(built + 3, (uint16_t)n);

    cloak_clienthello_parsed_t out;
    int rc = cloak_clienthello_parse(built, (size_t)n + 5, &out);
    ASSERT_EQ_INT(rc, 0);
    if (rc != 0) {
        return;
    }
    ASSERT_TRUE(out.random != NULL);
    ASSERT_MEM_EQ(out.random, random, 32);
    ASSERT_TRUE(out.session_id != NULL);
    ASSERT_EQ_INT(out.session_id_len, 32);
    ASSERT_MEM_EQ(out.session_id, session_id, 32);
    ASSERT_TRUE(out.x25519_key_share != NULL);
    ASSERT_MEM_EQ(out.x25519_key_share, keyshare, 32);
    ASSERT_TRUE(out.sni != NULL);
    ASSERT_EQ_INT(out.sni_len, strlen(sni));
    ASSERT_MEM_EQ(out.sni, sni, strlen(sni));
}

static void test_round_trip_against_client_builder(void) {
    char long_sni[254];
    memset(long_sni, 'a', 253);
    long_sni[253] = '\0';

    const char *sni_cases[5];
    sni_cases[0] = "a.co";
    sni_cases[1] = "www.example.com";
    sni_cases[2] = "a-considerably-longer-hostname.example.com";
    sni_cases[3] = "x";
    sni_cases[4] = long_sni;

    for (size_t i = 0; i < 5; i++) {
        round_trip_one(&cloak_clienthello_chrome, sni_cases[i]);
        round_trip_one(&cloak_clienthello_firefox, sni_cases[i]);
        round_trip_one(&cloak_clienthello_safari, sni_cases[i]);
    }
}

TEST_MAIN_BEGIN()
    test_good();
    test_corrupted_random_rejected();
    test_not_handshake();
    test_wrong_record_version();
    test_tls12();
    test_empty();
    test_truncation_sweep();
    test_byte_flip_sweep();
    test_missing_sni_is_not_a_failure();
    test_missing_key_share_is_not_a_failure();
    test_key_share_without_x25519_group_is_not_a_failure();
    test_round_trip_against_client_builder();
TEST_MAIN_END()
