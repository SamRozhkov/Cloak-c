#include "cloak/clienthello.h"
#include "cloak/common.h"
#include "test_framework.h"

#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

/* Minimal from-scratch structural walk of a built ClientHello, independent
 * of clienthello.c's own logic, used only to verify structural integrity
 * (extensions_length actually equals the sum of the extensions that
 * follow, and the server_name extension's own nested lengths are
 * internally consistent). Mirrors the exact walk used to derive the
 * offsets in the first place (see the plan's Provenance section). */
typedef struct {
    int ok;
    size_t sni_host_off;
    size_t sni_host_len;
    size_t extensions_length_off;
    size_t sni_ext_length_off;
    size_t sni_list_length_off;
    size_t sni_host_length_off;
} walk_result_t;

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static walk_result_t walk_and_verify(const uint8_t *buf, size_t len) {
    walk_result_t r;
    memset(&r, 0, sizeof(r));

    if (len < 4) {
        return r;
    }
    size_t hs_len = ((size_t)buf[1] << 16) | ((size_t)buf[2] << 8) | buf[3];
    if (hs_len != len - 4) {
        return r; /* handshake_length must equal everything after the 4-byte header */
    }

    size_t off = 4;
    off += 2; /* client_version */
    off += 32; /* random */
    if (off >= len) return r;
    size_t sid_len = buf[off];
    off += 1 + sid_len;
    if (off + 2 > len) return r;
    size_t cs_len = read_be16(buf + off);
    off += 2 + cs_len;
    if (off >= len) return r;
    size_t cm_len = buf[off];
    off += 1 + cm_len;
    if (off + 2 > len) return r;

    r.extensions_length_off = off;
    size_t ext_len = read_be16(buf + off);
    off += 2;
    size_t ext_end = off + ext_len;
    if (ext_end != len) {
        return r; /* extensions_length must account for exactly the rest of the buffer */
    }

    while (off < ext_end) {
        if (off + 4 > ext_end) return r;
        uint16_t ext_type = read_be16(buf + off);
        uint16_t ext_data_len = read_be16(buf + off + 2);
        if (off + 4 + ext_data_len > ext_end) return r;

        if (ext_type == 0x0000) { /* server_name */
            r.sni_ext_length_off = off + 2;
            size_t data_off = off + 4;
            if (data_off + 5 > ext_end) return r;
            size_t list_len = read_be16(buf + data_off);
            r.sni_list_length_off = data_off;
            uint8_t name_type = buf[data_off + 2];
            size_t host_len = read_be16(buf + data_off + 3);
            r.sni_host_length_off = data_off + 3;
            r.sni_host_off = data_off + 5;
            r.sni_host_len = host_len;
            if (name_type != 0x00) return r;
            if (list_len != 3 + host_len) return r; /* name_type(1) + host_name_length(2) + hostname */
            if (data_off + 5 + host_len > ext_end) return r;
        }

        off += 4 + ext_data_len;
    }

    r.ok = 1;
    return r;
}

static void fill_marker(uint8_t *buf, uint8_t seed) {
    for (int i = 0; i < 32; i++) {
        buf[i] = (uint8_t)(seed + i);
    }
}

static int is_valid_secp256r1_point(const uint8_t point[65]) {
    int ok = 0;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group == NULL) {
        return 0;
    }
    EC_POINT *pt = EC_POINT_new(group);
    if (pt == NULL) {
        EC_GROUP_free(group);
        return 0;
    }
    if (EC_POINT_oct2point(group, pt, point, 65, NULL) == 1) {
        if (EC_POINT_is_on_curve(group, pt, NULL) == 1) {
            ok = 1;
        }
    }
    EC_POINT_free(pt);
    EC_GROUP_free(group);
    return ok;
}

static void test_build_chrome_round_trip_and_structural_integrity(void) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    uint8_t out[2048];
    long n = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                      "www.example.com", out, sizeof(out));
    ASSERT_TRUE(n > 0);
    ASSERT_EQ_INT(n, (long)cloak_clienthello_chrome.len); /* same-length SNI: total length unchanged */

    ASSERT_MEM_EQ(out + cloak_clienthello_chrome.random_off, random, 32);
    ASSERT_MEM_EQ(out + cloak_clienthello_chrome.session_id_off, session_id, 32);
    ASSERT_MEM_EQ(out + cloak_clienthello_chrome.keyshare_off, key_share, 32);
    ASSERT_MEM_EQ(out + cloak_clienthello_chrome.sni_host_off, "www.example.com", 16); /* incl. NUL, harmless */

    walk_result_t w = walk_and_verify(out, (size_t)n);
    ASSERT_TRUE(w.ok);
    ASSERT_EQ_INT(w.sni_host_off, cloak_clienthello_chrome.sni_host_off);
    ASSERT_EQ_INT(w.sni_host_len, 15); /* strlen("www.example.com") */
}

static void test_build_shorter_sni_shrinks_and_shifts_keyshare(void) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    const char *short_name = "a.co"; /* 4 bytes, vs. the 15-byte placeholder -- delta = -11 */
    long expected_delta = (long)4 - (long)cloak_clienthello_chrome.sni_host_len;

    uint8_t out[2048];
    long n = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                      short_name, out, sizeof(out));
    ASSERT_TRUE(n > 0);
    ASSERT_EQ_INT(n, (long)cloak_clienthello_chrome.len + expected_delta);

    /* The key share must have moved: it sits after the SNI in every
     * supported template, so its position in the output is
     * keyshare_off + delta, NOT the raw template offset. This is the
     * direct regression test for the delta-adjustment logic. */
    long shifted_keyshare_off = (long)cloak_clienthello_chrome.keyshare_off + expected_delta;
    ASSERT_MEM_EQ(out + shifted_keyshare_off, key_share, 32);

    walk_result_t w = walk_and_verify(out, (size_t)n);
    ASSERT_TRUE(w.ok);
    ASSERT_EQ_INT(w.sni_host_len, 4);
    ASSERT_MEM_EQ(out + w.sni_host_off, short_name, 4);
}

static void test_build_longer_sni_grows_and_shifts_keyshare(void) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    const char *long_name = "a-considerably-longer-hostname.example.com"; /* 42 bytes */
    long expected_delta = (long)42 - (long)cloak_clienthello_chrome.sni_host_len;

    uint8_t out[2048];
    long n = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                      long_name, out, sizeof(out));
    ASSERT_TRUE(n > 0);
    ASSERT_EQ_INT(n, (long)cloak_clienthello_chrome.len + expected_delta);

    long shifted_keyshare_off = (long)cloak_clienthello_chrome.keyshare_off + expected_delta;
    ASSERT_MEM_EQ(out + shifted_keyshare_off, key_share, 32);

    walk_result_t w = walk_and_verify(out, (size_t)n);
    ASSERT_TRUE(w.ok);
    ASSERT_EQ_INT(w.sni_host_len, 42);
    ASSERT_MEM_EQ(out + w.sni_host_off, long_name, 42);
}

static void test_build_rejects_empty_server_name(void) {
    uint8_t random[32] = {0};
    uint8_t session_id[32] = {0};
    uint8_t key_share[32] = {0};
    uint8_t out[2048];

    long n = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                      "", out, sizeof(out));
    ASSERT_EQ_INT(n, -1);
}

static void test_build_rejects_server_name_too_long(void) {
    uint8_t random[32] = {0};
    uint8_t session_id[32] = {0};
    uint8_t key_share[32] = {0};
    uint8_t out[4096];

    char too_long[255];
    memset(too_long, 'a', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0'; /* 254 chars, exceeds the 253-byte DNS limit */

    long n = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                      too_long, out, sizeof(out));
    ASSERT_EQ_INT(n, -1);
}

static void test_build_rejects_buffer_too_small(void) {
    uint8_t random[32] = {0};
    uint8_t session_id[32] = {0};
    uint8_t key_share[32] = {0};
    uint8_t out[10]; /* far smaller than any real template */

    long n = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                      "www.example.com", out, sizeof(out));
    ASSERT_EQ_INT(n, -1);
}

static void round_trip_and_structural_integrity_for(const cloak_clienthello_template_t *tmpl) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    uint8_t out[2048];
    long n = cloak_clienthello_build(tmpl, random, session_id, key_share,
                                      "www.example.com", out, sizeof(out));
    ASSERT_TRUE(n > 0);
    ASSERT_EQ_INT(n, (long)tmpl->len);

    ASSERT_MEM_EQ(out + tmpl->random_off, random, 32);
    ASSERT_MEM_EQ(out + tmpl->session_id_off, session_id, 32);
    ASSERT_MEM_EQ(out + tmpl->keyshare_off, key_share, 32);

    walk_result_t w = walk_and_verify(out, (size_t)n);
    ASSERT_TRUE(w.ok);
    ASSERT_EQ_INT(w.sni_host_off, tmpl->sni_host_off);
    ASSERT_EQ_INT(w.sni_host_len, 15); /* strlen("www.example.com") */
}

static void shorter_sni_shifts_keyshare_for(const cloak_clienthello_template_t *tmpl) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    const char *short_name = "a.co";
    long expected_delta = (long)4 - (long)tmpl->sni_host_len;

    uint8_t out[2048];
    long n = cloak_clienthello_build(tmpl, random, session_id, key_share,
                                      short_name, out, sizeof(out));
    ASSERT_TRUE(n > 0);
    ASSERT_EQ_INT(n, (long)tmpl->len + expected_delta);

    long shifted_keyshare_off = (long)tmpl->keyshare_off + expected_delta;
    ASSERT_MEM_EQ(out + shifted_keyshare_off, key_share, 32);

    walk_result_t w = walk_and_verify(out, (size_t)n);
    ASSERT_TRUE(w.ok);
    ASSERT_EQ_INT(w.sni_host_len, 4);
}

static void test_firefox_round_trip_and_structural_integrity(void) {
    round_trip_and_structural_integrity_for(&cloak_clienthello_firefox);
}

static void test_firefox_shorter_sni_shifts_keyshare(void) {
    shorter_sni_shifts_keyshare_for(&cloak_clienthello_firefox);
}

static void test_safari_round_trip_and_structural_integrity(void) {
    round_trip_and_structural_integrity_for(&cloak_clienthello_safari);
}

/* NOTE: unlike Chrome and Firefox, Safari's padding extension is recomputed
 * on every build (see test_safari_padding_recomputed_for_various_sni_lengths
 * below), so shorter_sni_shifts_keyshare_for's exact-delta-length assertion
 * (n == tmpl->len + expected_delta) does NOT hold for Safari: shrinking the
 * SNI by 11 bytes ("a.co") grows the padding by 11 bytes to compensate, so
 * the total length stays at 512 instead of shrinking. Deliberately not
 * calling shorter_sni_shifts_keyshare_for(&cloak_clienthello_safari) here --
 * Safari's shorter-SNI behavior is covered correctly by
 * test_safari_padding_recomputed_for_various_sni_lengths instead. */

static void test_chrome_random_regions_differ_between_builds(void) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    uint8_t out1[2048];
    long n1 = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                       "www.example.com", out1, sizeof(out1));
    ASSERT_TRUE(n1 > 0);

    uint8_t out2[2048];
    long n2 = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                       "www.example.com", out2, sizeof(out2));
    ASSERT_TRUE(n2 > 0);
    ASSERT_EQ_INT(n1, n2);

    for (size_t i = 0; i < cloak_clienthello_chrome.random_region_count; i++) {
        size_t off = cloak_clienthello_chrome.random_regions[i].off; /* SNI unchanged, delta=0, no shift needed */
        size_t len = cloak_clienthello_chrome.random_regions[i].len;
        ASSERT_MEM_NE(out1 + off, out2 + off, len);
    }
}

static void test_firefox_random_regions_differ_between_builds(void) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    uint8_t out1[2048];
    long n1 = cloak_clienthello_build(&cloak_clienthello_firefox, random, session_id, key_share,
                                       "www.example.com", out1, sizeof(out1));
    ASSERT_TRUE(n1 > 0);

    uint8_t out2[2048];
    long n2 = cloak_clienthello_build(&cloak_clienthello_firefox, random, session_id, key_share,
                                       "www.example.com", out2, sizeof(out2));
    ASSERT_TRUE(n2 > 0);
    ASSERT_EQ_INT(n1, n2);

    for (size_t i = 0; i < cloak_clienthello_firefox.random_region_count; i++) {
        size_t off = cloak_clienthello_firefox.random_regions[i].off;
        size_t len = cloak_clienthello_firefox.random_regions[i].len;
        ASSERT_MEM_NE(out1 + off, out2 + off, len);
    }
}

static void test_firefox_secp256r1_keyshare_is_valid_and_fresh(void) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    uint8_t out1[2048];
    long n1 = cloak_clienthello_build(&cloak_clienthello_firefox, random, session_id, key_share,
                                       "www.example.com", out1, sizeof(out1));
    ASSERT_TRUE(n1 > 0);

    uint8_t out2[2048];
    long n2 = cloak_clienthello_build(&cloak_clienthello_firefox, random, session_id, key_share,
                                       "www.example.com", out2, sizeof(out2));
    ASSERT_TRUE(n2 > 0);
    ASSERT_EQ_INT(n1, n2);

    /* server_name unchanged (delta=0), so secp256r1_keyshare_off needs no shift. */
    const uint8_t *point1 = out1 + cloak_clienthello_firefox.secp256r1_keyshare_off;
    const uint8_t *point2 = out2 + cloak_clienthello_firefox.secp256r1_keyshare_off;

    ASSERT_TRUE(is_valid_secp256r1_point(point1));
    ASSERT_TRUE(is_valid_secp256r1_point(point2));
    ASSERT_MEM_NE(point1, point2, 65);
}

static void test_safari_padding_recomputed_for_various_sni_lengths(void) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    /* {sni_len, expected_total_len, expect_padding_present, expected_pad_data_len} --
     * independently verified against github.com/refraction-networking/utls
     * v1.8.0's HelloSafari_Auto padding behavior across all SNI lengths
     * 1..253 (these 5 are representative boundary/interior cases). */
    struct {
        int sni_len;
        long expected_total;
        int expect_padding;
        int expected_pad_data_len;
    } cases[5] = {
        {1, 512, 1, 205},
        {205, 512, 1, 1},
        {206, 513, 1, 1},
        {210, 512, 0, 0},
        {253, 555, 0, 0},
    };

    for (size_t c = 0; c < 5; c++) {
        char sni[254];
        for (int i = 0; i < cases[c].sni_len; i++) {
            sni[i] = (char)('a' + (i % 26));
        }
        sni[cases[c].sni_len] = '\0';

        uint8_t out[2048];
        long n = cloak_clienthello_build(&cloak_clienthello_safari, random, session_id, key_share,
                                          sni, out, sizeof(out));
        ASSERT_TRUE(n > 0);
        ASSERT_EQ_INT(n, cases[c].expected_total);

        walk_result_t w = walk_and_verify(out, (size_t)n);
        ASSERT_TRUE(w.ok);
        ASSERT_EQ_INT(w.sni_host_len, cases[c].sni_len);

        if (cases[c].expect_padding) {
            long shifted_padding_off = (long)cloak_clienthello_safari.padding_ext_off
                + ((long)cases[c].sni_len - (long)cloak_clienthello_safari.sni_host_len);
            uint16_t pad_type = (uint16_t)((out[shifted_padding_off] << 8) | out[shifted_padding_off + 1]);
            uint16_t pad_len = (uint16_t)((out[shifted_padding_off + 2] << 8) | out[shifted_padding_off + 3]);
            ASSERT_EQ_INT(pad_type, 0x0015);
            ASSERT_EQ_INT(pad_len, cases[c].expected_pad_data_len);
        }
    }
}

TEST_MAIN_BEGIN()
    test_build_chrome_round_trip_and_structural_integrity();
    test_build_shorter_sni_shrinks_and_shifts_keyshare();
    test_build_longer_sni_grows_and_shifts_keyshare();
    test_build_rejects_empty_server_name();
    test_build_rejects_server_name_too_long();
    test_build_rejects_buffer_too_small();
    test_firefox_round_trip_and_structural_integrity();
    test_firefox_shorter_sni_shifts_keyshare();
    test_safari_round_trip_and_structural_integrity();
    test_chrome_random_regions_differ_between_builds();
    test_firefox_random_regions_differ_between_builds();
    test_firefox_secp256r1_keyshare_is_valid_and_fresh();
    test_safari_padding_recomputed_for_various_sni_lengths();
TEST_MAIN_END()
