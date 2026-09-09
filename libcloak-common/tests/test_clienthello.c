#include "cloak/clienthello.h"
#include "cloak/common.h"
#include "cloak/crypto.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
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

    /* encrypted_client_hello (0xfe0d), if present. The walk verifies the
     * extension's own ext_data_len accounts for exactly
     * ech_type(1) | kdf_id(2) | aead_id(2) | config_id(1) | enc<2+n> |
     * payload<2+n>, so a mis-sized ECH payload resize fails ok. */
    int ech_present;
    uint16_t ech_kdf_id;
    uint16_t ech_aead_id;
    size_t ech_config_id_off;
    size_t ech_enc_off;
    size_t ech_enc_len;
    size_t ech_payload_len_off;
    size_t ech_payload_off;
    size_t ech_payload_len;
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

        if (ext_type == 0xfe0d) { /* encrypted_client_hello */
            size_t d = off + 4;
            if (ext_data_len < 10) return r; /* 1+2+2+1+2 header, plus a 2-byte payload length */
            size_t enc_len = read_be16(buf + d + 6);
            if (enc_len + 10 > ext_data_len) return r;
            size_t payload_len = read_be16(buf + d + 8 + enc_len);
            if (enc_len + 10 + payload_len != ext_data_len) {
                return r; /* the ECH extension's length must cover exactly its content */
            }
            r.ech_present = 1;
            r.ech_kdf_id = read_be16(buf + d + 1);
            r.ech_aead_id = read_be16(buf + d + 3);
            r.ech_config_id_off = d + 5;
            r.ech_enc_off = d + 8;
            r.ech_enc_len = enc_len;
            r.ech_payload_len_off = d + 8 + enc_len;
            r.ech_payload_off = r.ech_payload_len_off + 2;
            r.ech_payload_len = payload_len;
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

/* Chrome re-draws its ECH payload length on every build, so a Chrome
 * ClientHello's total length is not a single fixed number: it is the
 * post-SNI-shift base length plus one of the candidate growth amounts
 * (0/32/64/96). base is what the total would be if the shortest candidate
 * -- the one baked into the template -- were drawn. */
static int chrome_len_is_expected(long n, long base) {
    const cloak_clienthello_template_t *t = &cloak_clienthello_chrome;
    for (size_t i = 0; i < t->ech_payload_candidate_count; i++) {
        long grown = base + (long)t->ech_payload_candidate_lens[i]
                          - (long)t->ech_payload_candidate_lens[0];
        if (n == grown) {
            return 1;
        }
    }
    return 0;
}

/* ML-KEM-768 packed-coefficient decoder, written independently of
 * clienthello.c's encoder: unpacks data as 768 ByteEncode_12 coefficients
 * (FIPS 203) and returns how many are >= q. A genuine ML-KEM-768
 * encapsulation key always yields 0; 1152 uniformly random bytes yield
 * ~145. */
#define MLKEM768_Q 3329
#define MLKEM768_EK_PACKED_LEN 1152

static size_t count_out_of_range_mlkem_coeffs(const uint8_t *data) {
    size_t count = 0;
    for (size_t i = 0; i + 3 <= MLKEM768_EK_PACKED_LEN; i += 3) {
        uint16_t b0 = data[i], b1 = data[i + 1], b2 = data[i + 2];
        uint16_t c0 = (uint16_t)(b0 | ((b1 & 0x0f) << 8));
        uint16_t c1 = (uint16_t)((b1 >> 4) | (b2 << 4));
        if (c0 >= MLKEM768_Q) count++;
        if (c1 >= MLKEM768_Q) count++;
    }
    return count;
}

static long build_with_sni_len(const cloak_clienthello_template_t *tmpl, int sni_len,
                               uint8_t *out, size_t out_cap, long *sni_delta_out) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    char sni[254];
    for (int i = 0; i < sni_len; i++) {
        sni[i] = (char)('a' + (i % 26));
    }
    sni[sni_len] = '\0';

    if (sni_delta_out != NULL) {
        *sni_delta_out = (long)sni_len - (long)tmpl->sni_host_len;
    }
    return cloak_clienthello_build(tmpl, random, session_id, key_share, sni, out, out_cap);
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

/* Returns 1 if u_le (a 32-byte little-endian X25519 wire encoding) is the
 * u-coordinate of a point on Curve25519 -- i.e. u^3 + 486662*u^2 + u is a
 * quadratic residue mod p = 2^255-19, checked by Legendre symbol -- and 0
 * if it lies on the quadratic twist or is not a canonically reduced field
 * element.
 *
 * A genuine X25519 public key is a multiple of the base point, so it is on
 * the curve 100% of the time. A uniform random 255-bit value only is ~50%
 * of the time; this is the distinguisher this check exists to catch. (The
 * stronger prime-order-subgroup property -- a further ~1/8 filter on random
 * values -- would need scalar multiplication, so it is not reimplemented
 * here; it was verified out-of-tree against an RFC 7748 implementation
 * during review, and the on-curve check alone already rejects a
 * masked-random fill within a couple of loop iterations.) */
static int is_on_curve25519(const uint8_t u_le[32]) {
    int ok = 0;
    uint8_t be[32];
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *u = NULL, *t = NULL, *a = NULL, *rhs = NULL, *e = NULL;

    /* RFC 7748 masks the top bit before use; mirror that, then require what
     * remains to be a canonically reduced field element. */
    for (size_t i = 0; i < 32; i++) {
        be[i] = u_le[31 - i];
    }
    be[0] &= 0x7f;

    ctx = BN_CTX_new();
    p = BN_new();
    t = BN_new();
    a = BN_new();
    rhs = BN_new();
    e = BN_new();
    u = BN_bin2bn(be, 32, NULL);
    if (ctx == NULL || p == NULL || t == NULL || a == NULL || rhs == NULL ||
        e == NULL || u == NULL) {
        goto done;
    }

    /* p = 2^255 - 19 */
    if (!BN_lshift(p, BN_value_one(), 255) || !BN_set_word(t, 19) ||
        !BN_sub(p, p, t)) {
        goto done;
    }
    if (BN_cmp(u, p) >= 0) {
        goto done; /* not a canonical field element */
    }

    /* rhs = u * (u^2 + 486662*u + 1) mod p */
    if (!BN_mod_sqr(t, u, p, ctx) || !BN_set_word(a, 486662) ||
        !BN_mod_mul(a, a, u, p, ctx) || !BN_mod_add(t, t, a, p, ctx) ||
        !BN_mod_add(t, t, BN_value_one(), p, ctx) ||
        !BN_mod_mul(rhs, t, u, p, ctx)) {
        goto done;
    }
    if (BN_is_zero(rhs)) {
        ok = 1; /* v == 0: a point of order 2, still on the curve */
        goto done;
    }

    /* Legendre symbol: rhs^((p-1)/2) mod p == 1 iff rhs is a square. */
    if (!BN_sub(e, p, BN_value_one()) || !BN_rshift1(e, e) ||
        !BN_mod_exp(t, rhs, e, p, ctx)) {
        goto done;
    }
    ok = BN_is_one(t);

done:
    BN_free(u);
    BN_free(e);
    BN_free(rhs);
    BN_free(a);
    BN_free(t);
    BN_free(p);
    BN_CTX_free(ctx);
    return ok;
}

static void test_build_chrome_round_trip_and_structural_integrity(void) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    long n = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                      "www.example.com", out, sizeof(out));
    ASSERT_TRUE(n > 0);
    /* Same-length SNI, so the only length variation left is the re-drawn
     * ECH payload. */
    ASSERT_TRUE(chrome_len_is_expected(n, (long)cloak_clienthello_chrome.len));

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

    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    long n = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                      short_name, out, sizeof(out));
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(chrome_len_is_expected(n, (long)cloak_clienthello_chrome.len + expected_delta));

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

    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    long n = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                      long_name, out, sizeof(out));
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(chrome_len_is_expected(n, (long)cloak_clienthello_chrome.len + expected_delta));

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
    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];

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

    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
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

    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
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

    uint8_t out1[CLOAK_CLIENTHELLO_MAX_BYTES];
    long n1 = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                       "www.example.com", out1, sizeof(out1));
    ASSERT_TRUE(n1 > 0);

    uint8_t out2[CLOAK_CLIENTHELLO_MAX_BYTES];
    long n2 = cloak_clienthello_build(&cloak_clienthello_chrome, random, session_id, key_share,
                                       "www.example.com", out2, sizeof(out2));
    ASSERT_TRUE(n2 > 0);
    /* n1 and n2 need NOT be equal any more: Chrome's ECH payload length is
     * re-drawn per build (see test_chrome_ech_payload_length_varies). */

    for (size_t i = 0; i < cloak_clienthello_chrome.random_region_count; i++) {
        size_t off = cloak_clienthello_chrome.random_regions[i].off; /* SNI unchanged, delta=0, no shift needed */
        size_t len = cloak_clienthello_chrome.random_regions[i].len;
        /* Skip the 1-byte config_id: two random bytes collide 1/256 of the
         * time, far too flaky for a two-build comparison. Its freshness is
         * covered over many builds by test_ech_config_id_varies_between_builds. */
        if (len < 4) {
            continue;
        }
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

    uint8_t out1[CLOAK_CLIENTHELLO_MAX_BYTES];
    long n1 = cloak_clienthello_build(&cloak_clienthello_firefox, random, session_id, key_share,
                                       "www.example.com", out1, sizeof(out1));
    ASSERT_TRUE(n1 > 0);

    uint8_t out2[CLOAK_CLIENTHELLO_MAX_BYTES];
    long n2 = cloak_clienthello_build(&cloak_clienthello_firefox, random, session_id, key_share,
                                       "www.example.com", out2, sizeof(out2));
    ASSERT_TRUE(n2 > 0);
    ASSERT_EQ_INT(n1, n2);

    for (size_t i = 0; i < cloak_clienthello_firefox.random_region_count; i++) {
        size_t off = cloak_clienthello_firefox.random_regions[i].off;
        size_t len = cloak_clienthello_firefox.random_regions[i].len;
        if (len < 4) {
            continue; /* 1-byte config_id: see the note in the Chrome variant */
        }
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

    uint8_t out1[CLOAK_CLIENTHELLO_MAX_BYTES];
    long n1 = cloak_clienthello_build(&cloak_clienthello_firefox, random, session_id, key_share,
                                       "www.example.com", out1, sizeof(out1));
    ASSERT_TRUE(n1 > 0);

    uint8_t out2[CLOAK_CLIENTHELLO_MAX_BYTES];
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

        uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
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

/* SNI lengths used by the multi-build tests below: the two extremes plus a
 * shorter-than-placeholder, an equal-length and a longer-than-placeholder
 * case, so every build exercises a different sni_delta (negative, zero and
 * positive) through the offset-shifting logic. */
static const int sni_len_cases[] = {1, 4, 15, 42, 253};
#define SNI_LEN_CASE_COUNT (sizeof(sni_len_cases) / sizeof(sni_len_cases[0]))

static void test_chrome_mlkem_key_is_structurally_valid_and_fresh(void) {
    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    uint8_t prev[MLKEM768_EK_PACKED_LEN];
    int have_prev = 0;
    int saw_difference = 0;

    for (int iter = 0; iter < 120; iter++) {
        int sni_len = sni_len_cases[(size_t)iter % SNI_LEN_CASE_COUNT];
        long sni_delta = 0;
        long n = build_with_sni_len(&cloak_clienthello_chrome, sni_len, out, sizeof(out), &sni_delta);
        ASSERT_TRUE(n > 0);

        size_t ek_off = (size_t)((long)cloak_clienthello_chrome.mlkem_ek_off + sni_delta);
        /* A real ML-KEM-768 encapsulation key never has a single
         * coefficient >= q; 1152 raw random bytes have ~145 of them. */
        ASSERT_EQ_INT(count_out_of_range_mlkem_coeffs(out + ek_off), 0);

        if (have_prev && memcmp(prev, out + ek_off, MLKEM768_EK_PACKED_LEN) != 0) {
            saw_difference = 1;
        }
        memcpy(prev, out + ek_off, MLKEM768_EK_PACKED_LEN);
        have_prev = 1;
    }
    ASSERT_TRUE(saw_difference); /* fresh key material every build, not frozen */
}

/* Every X25519-kind region must hold a value a real client could actually
 * have sent: a genuine X25519 public key. That means both the cheap
 * encoding property (top bit of the last byte clear, which plain random
 * bytes get wrong half the time) and, more importantly, the structural one
 * -- an actual point on Curve25519, which even top-bit-masked random bytes
 * only manage ~52% of the time. */
static void x25519_regions_are_valid_public_keys_for(const cloak_clienthello_template_t *tmpl) {
    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    uint8_t prev[32];
    int have_prev = 0;
    int saw_difference = 0;
    int saw_x25519_region = 0;

    for (int iter = 0; iter < 120; iter++) {
        int sni_len = sni_len_cases[(size_t)iter % SNI_LEN_CASE_COUNT];
        long sni_delta = 0;
        long n = build_with_sni_len(tmpl, sni_len, out, sizeof(out), &sni_delta);
        ASSERT_TRUE(n > 0);

        for (size_t i = 0; i < tmpl->random_region_count; i++) {
            if (tmpl->random_regions[i].kind != CLOAK_CH_REGION_X25519) {
                continue;
            }
            saw_x25519_region = 1;
            ASSERT_EQ_INT(tmpl->random_regions[i].len, 32);
            size_t off = tmpl->random_regions[i].off;
            if (off > tmpl->sni_host_off) {
                off = (size_t)((long)off + sni_delta);
            }
            ASSERT_EQ_INT(out[off + 31] & 0x80, 0);
            ASSERT_TRUE(is_on_curve25519(out + off));

            if (i == 0) {
                if (have_prev && memcmp(prev, out + off, 32) != 0) {
                    saw_difference = 1;
                }
                memcpy(prev, out + off, 32);
                have_prev = 1;
            }
        }
    }
    ASSERT_TRUE(saw_x25519_region);
    ASSERT_TRUE(saw_difference);
}

static void test_chrome_x25519_regions_are_valid_public_keys(void) {
    x25519_regions_are_valid_public_keys_for(&cloak_clienthello_chrome);
}

static void test_firefox_x25519_regions_are_valid_public_keys(void) {
    x25519_regions_are_valid_public_keys_for(&cloak_clienthello_firefox);
}

/* Guards the check above against silently passing on a broken
 * is_on_curve25519: the old masked-random construction this fix replaced
 * must be rejected, and a genuine key must be accepted. */
static void test_on_curve25519_check_discriminates(void) {
    int rejected_masked_random = 0;

    for (int iter = 0; iter < 60; iter++) {
        uint8_t masked[32];
        cloak_random_bytes(masked, sizeof(masked));
        masked[31] &= 0x7f;
        if (!is_on_curve25519(masked)) {
            rejected_masked_random = 1;
        }

        uint8_t priv[32], pub[32];
        ASSERT_EQ_INT(cloak_x25519_generate_keypair(priv, pub), 0);
        ASSERT_TRUE(is_on_curve25519(pub));
    }
    /* ~50% rejection per draw; 60 draws makes a false failure here about a
     * 1-in-10^18 event. */
    ASSERT_TRUE(rejected_masked_random);
}

/* ECH's config_id is a uniform random byte in real clients and its aead_id
 * is a coin flip between AES-128-GCM and ChaCha20-Poly1305, while its
 * kdf_id stays fixed at HKDF-SHA256. */
static void ech_config_id_and_aead_id_for(const cloak_clienthello_template_t *tmpl) {
    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    uint8_t first_config_id = 0;
    int config_id_varies = 0;
    int saw_aes = 0;
    int saw_chacha = 0;

    for (int iter = 0; iter < 64; iter++) {
        int sni_len = sni_len_cases[(size_t)iter % SNI_LEN_CASE_COUNT];
        long n = build_with_sni_len(tmpl, sni_len, out, sizeof(out), NULL);
        ASSERT_TRUE(n > 0);

        walk_result_t w = walk_and_verify(out, (size_t)n);
        ASSERT_TRUE(w.ok);
        ASSERT_TRUE(w.ech_present);

        ASSERT_EQ_INT(w.ech_kdf_id, 0x0001); /* HKDF-SHA256, correctly frozen */
        if (w.ech_aead_id == 0x0001) {
            saw_aes = 1;
        } else if (w.ech_aead_id == 0x0003) {
            saw_chacha = 1;
        } else {
            ASSERT_TRUE(0); /* no other AEAD id may ever appear */
        }

        uint8_t config_id = out[w.ech_config_id_off];
        if (iter == 0) {
            first_config_id = config_id;
        } else if (config_id != first_config_id) {
            config_id_varies = 1;
        }
    }

    /* 64 identical uniform bytes in a row would be a 1/256^63 event. */
    ASSERT_TRUE(config_id_varies);
    ASSERT_TRUE(saw_aes);
    ASSERT_TRUE(saw_chacha);
}

static void test_chrome_ech_config_id_and_aead_id_vary(void) {
    ech_config_id_and_aead_id_for(&cloak_clienthello_chrome);
}

static void test_firefox_ech_config_id_and_aead_id_vary(void) {
    ech_config_id_and_aead_id_for(&cloak_clienthello_firefox);
}

static void test_chrome_ech_payload_length_varies_and_stays_consistent(void) {
    /* The 9 bytes that follow the ECH extension in the Chrome template: an
     * empty signed_certificate_timestamp plus a 1-byte GREASE extension.
     * They must survive being shifted by the ECH payload resize. */
    static const uint8_t chrome_tail[9] = {0x00, 0x12, 0x00, 0x00, 0x2a, 0x2a, 0x00, 0x01, 0x00};

    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    int seen[CLOAK_CLIENTHELLO_MAX_ECH_PAYLOAD_CANDIDATES] = {0};
    int distinct = 0;

    for (int iter = 0; iter < 120; iter++) {
        int sni_len = sni_len_cases[(size_t)iter % SNI_LEN_CASE_COUNT];
        long sni_delta = 0;
        long n = build_with_sni_len(&cloak_clienthello_chrome, sni_len, out, sizeof(out), &sni_delta);
        ASSERT_TRUE(n > 0);

        /* walk_and_verify itself checks handshake_length == n - 4, that
         * extensions_length covers exactly the remaining bytes, and that
         * the ECH extension's ext_data_len covers exactly its content. */
        walk_result_t w = walk_and_verify(out, (size_t)n);
        ASSERT_TRUE(w.ok);
        ASSERT_TRUE(w.ech_present);
        ASSERT_EQ_INT(w.ech_enc_len, 32);

        int matched = -1;
        for (size_t c = 0; c < cloak_clienthello_chrome.ech_payload_candidate_count; c++) {
            if (w.ech_payload_len == cloak_clienthello_chrome.ech_payload_candidate_lens[c]) {
                matched = (int)c;
            }
        }
        ASSERT_TRUE(matched >= 0); /* only the four candidate lengths may appear */
        if (!seen[matched]) {
            seen[matched] = 1;
            distinct++;
        }

        /* Total length must match the drawn payload length exactly. */
        long expected_total = (long)cloak_clienthello_chrome.len + sni_delta
                              + (long)w.ech_payload_len
                              - (long)cloak_clienthello_chrome.ech_payload_candidate_lens[0];
        ASSERT_EQ_INT(n, expected_total);

        /* The trailing SCT + GREASE extensions must still be present,
         * unchanged, and end exactly at the returned length. */
        ASSERT_EQ_INT(w.ech_payload_off + w.ech_payload_len + sizeof(chrome_tail), (size_t)n);
        ASSERT_MEM_EQ(out + (size_t)n - sizeof(chrome_tail), chrome_tail, sizeof(chrome_tail));
    }

    ASSERT_TRUE(distinct >= 2);
}

static void test_firefox_ech_payload_length_is_fixed(void) {
    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];

    for (int iter = 0; iter < 60; iter++) {
        int sni_len = sni_len_cases[(size_t)iter % SNI_LEN_CASE_COUNT];
        long sni_delta = 0;
        long n = build_with_sni_len(&cloak_clienthello_firefox, sni_len, out, sizeof(out), &sni_delta);
        ASSERT_TRUE(n > 0);
        ASSERT_EQ_INT(n, (long)cloak_clienthello_firefox.len + sni_delta);

        walk_result_t w = walk_and_verify(out, (size_t)n);
        ASSERT_TRUE(w.ok);
        ASSERT_TRUE(w.ech_present);
        ASSERT_EQ_INT(w.ech_payload_len, 239); /* genuinely fixed in real Firefox */
    }
}

/* Stress the write paths with output buffers sized to exactly the largest
 * extent a build can ever touch, so any overflow from the SNI splice, the
 * padding recomputation or the ECH payload resize trips ASan. */
static void test_exact_size_output_buffer_stress(void) {
    const cloak_clienthello_template_t *tmpls[3] = {
        &cloak_clienthello_chrome, &cloak_clienthello_firefox, &cloak_clienthello_safari,
    };

    for (size_t t = 0; t < 3; t++) {
        const cloak_clienthello_template_t *tmpl = tmpls[t];
        for (size_t s = 0; s < SNI_LEN_CASE_COUNT; s++) {
            int sni_len = sni_len_cases[s];
            long sni_delta = (long)sni_len - (long)tmpl->sni_host_len;
            long base = (long)tmpl->len + sni_delta;

            /* The tightest cap that always succeeds: the post-SNI-shift
             * length (phase 1 writes that much verbatim) or, if larger,
             * the biggest final length any draw can produce. */
            long tight = base;
            for (size_t c = 0; c < tmpl->ech_payload_candidate_count; c++) {
                long grown = base + (long)tmpl->ech_payload_candidate_lens[c]
                                  - (long)tmpl->ech_payload_candidate_lens[0];
                if (grown > tight) {
                    tight = grown;
                }
            }
            if (tmpl->padding_ext_off != 0) {
                /* Safari's padding can grow the message up to 512 bytes. */
                if (tight < 512) {
                    tight = 512;
                }
            }
            ASSERT_TRUE(tight <= (long)CLOAK_CLIENTHELLO_MAX_BYTES);

            for (int rep = 0; rep < 40; rep++) {
                uint8_t *buf = (uint8_t *)malloc((size_t)tight);
                ASSERT_TRUE(buf != NULL);
                long n = build_with_sni_len(tmpl, sni_len, buf, (size_t)tight, NULL);
                ASSERT_TRUE(n > 0);
                ASSERT_TRUE(n <= tight);
                walk_result_t w = walk_and_verify(buf, (size_t)n);
                ASSERT_TRUE(w.ok);
                ASSERT_EQ_INT(w.sni_host_len, sni_len);
                free(buf);
            }
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
    test_chrome_mlkem_key_is_structurally_valid_and_fresh();
    test_on_curve25519_check_discriminates();
    test_chrome_x25519_regions_are_valid_public_keys();
    test_firefox_x25519_regions_are_valid_public_keys();
    test_chrome_ech_config_id_and_aead_id_vary();
    test_firefox_ech_config_id_and_aead_id_vary();
    test_chrome_ech_payload_length_varies_and_stays_consistent();
    test_firefox_ech_payload_length_is_fixed();
    test_exact_size_output_buffer_stress();
TEST_MAIN_END()
