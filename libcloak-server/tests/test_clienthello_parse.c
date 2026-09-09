#include "cloak/clienthello_parse.h"
#include "cloak/clienthello.h"
#include "cloak/common.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>

static size_t hex_decode(const char *hex, uint8_t *out) {
    size_t n = 0;
    size_t hlen = strlen(hex);
    for (size_t i = 0; i + 1 < hlen; i += 2) {
        unsigned int byte;
        sscanf(hex + i, "%2x", &byte);
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
 * one at full length. */
static void test_truncation_sweep(void) {
    uint8_t full[4096];
    size_t full_len = hex_decode(GOOD_HEX, full);
    for (size_t n = 0; n <= full_len; n++) {
        cloak_clienthello_parsed_t out;
        int rc = cloak_clienthello_parse(full, n, &out);
        if (n < full_len) {
            ASSERT_TRUE(rc == -1);
        } else {
            ASSERT_EQ_INT(rc, 0);
        }
    }
}

/* Same sweep but flipping every single bit of every byte of the good
 * ClientHello one at a time and confirming no crash -- broader adversarial
 * coverage than truncation alone (catches bugs where an inflated
 * *interior* length field causes an OOB read while len(data) itself is
 * untouched). Not a correctness check (many single-bit mutations of a
 * valid ClientHello are still structurally well-formed, e.g. mutating a
 * byte inside `random` or the SNI hostname), so this only needs to run to
 * completion without ASan/UBSan reporting anything. */
static void test_byte_flip_sweep(void) {
    uint8_t full[4096];
    size_t full_len = hex_decode(GOOD_HEX, full);
    for (size_t i = 0; i < full_len; i++) {
        uint8_t saved = full[i];
        for (int bit = 0; bit < 8; bit++) {
            full[i] = (uint8_t)(saved ^ (1u << bit));
            cloak_clienthello_parsed_t out;
            cloak_clienthello_parse(full, full_len, &out); /* must not crash */
        }
        full[i] = saved;
    }
    ASSERT_TRUE(1); /* reaching here without an ASan/UBSan abort is the test */
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
    test_round_trip_against_client_builder();
TEST_MAIN_END()
