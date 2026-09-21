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

/* The GREASE seeds that reproduce each template's CAPTURED codepoints,
 * so the byte-exact assertions in this file stay byte-exact now that
 * cloak_clienthello_build re-draws GREASE per call. Only the high nibble
 * of each byte is used; the order is CLOAK_CH_GREASE_{CIPHER, GROUP,
 * EXT1, EXT2, VERSION}.
 *
 * These are NOT the shipping behaviour and no test may use them to
 * assert what a real handshake looks like -- they exist so that a test
 * about the ECH resize, or about a fingerprint's cipher list, is not
 * also a test about GREASE. The GREASE behaviour itself is asserted by
 * test_grease_* below, which never pins a seed. */
static const uint8_t chrome_capture_grease_seed[CLOAK_CLIENTHELLO_GREASE_ROLES] = {
    0xf0, /* CIPHER  -> 0xfafa */
    0xa0, /* GROUP   -> 0xaaaa */
    0xf0, /* EXT1    -> 0xfafa */
    0x20, /* EXT2    -> 0x2a2a */
    0xf0, /* VERSION -> 0xfafa */
};
static const uint8_t safari_capture_grease_seed[CLOAK_CLIENTHELLO_GREASE_ROLES] = {
    0x20, /* CIPHER  -> 0x2a2a */
    0x70, /* GROUP   -> 0x7a7a */
    0x20, /* EXT1    -> 0x2a2a */
    0x10, /* EXT2    -> 0x1a1a */
    0x30, /* VERSION -> 0x3a3a */
};
/* Firefox has no GREASE positions at all, so any seed produces the same
 * bytes; this one is passed for uniformity. */
static const uint8_t firefox_capture_grease_seed[CLOAK_CLIENTHELLO_GREASE_ROLES] = {0, 0, 0, 0, 0};

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

/* build_with_sni_len with GREASE pinned to the template's captured
 * values -- see chrome_capture_grease_seed above for why that is allowed
 * here and where it is not. */
static long build_with_sni_len_pinned_grease(const cloak_clienthello_template_t *tmpl, int sni_len,
                                             uint8_t *out, size_t out_cap, long *sni_delta_out,
                                             const uint8_t *grease_seed) {
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
    return cloak_clienthello_build_with_grease_seed(tmpl, random, session_id, key_share, sni,
                                                    grease_seed, out, out_cap);
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
        /* GREASE pinned to the capture so chrome_tail stays byte-exact:
         * the tail's last five bytes ARE a GREASE extension header, and
         * this case is about the ECH resize shifting it intact, not
         * about what value it carries. */
        long n = build_with_sni_len_pinned_grease(&cloak_clienthello_chrome, sni_len, out,
                                                  sizeof(out), &sni_delta,
                                                  chrome_capture_grease_seed);
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

/* ===================================================================== */
/* THE FINGERPRINT PIN: a disguise property with NO ORACLE, so the        */
/* literals below ARE the oracle.                                        */
/* ===================================================================== */

/* WHY THIS EXISTS, AND WHY NOTHING ELSE IN THIS TREE CAN DO ITS JOB.
 *
 * Module 9 task 1 put Go Cloak's own ck-client and ck-server in front of
 * this port and proved the direct path interoperates. Its review then
 * measured what that oracle CANNOT see, and this was the headline:
 * replacing the Chrome template's three TLS 1.3 cipher suites
 * (0x1301/0x1302/0x1303) with TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a) left
 * the ENTIRE 69-test suite green (69 was the count in module 9; the
 * suite is larger now, and the measurement has not been re-run since).
 * Go's server reads the record header, the `random`, the session id and
 * the key share, and ACTS on nothing else in the ClientHello
 * (internal/server/TLS.go:73-99 consumes ch.random, ch.sessionId and
 * extension 0x0033 and nothing more; internal/server/TLSAux.go:133-141
 * walks past the cipher-suite and compression lists for their LENGTHS
 * without ever examining their contents) -- so no interoperability
 * test, against any Go peer, present or future, can ever notice that
 * these templates stopped looking like a browser.
 *
 * But the one reader that is not in this repository -- a censor's
 * fingerprinter -- reads all of it. Offering 3DES where Chrome offers
 * TLS 1.3 is a JA3-visible, single-packet giveaway, and mimicking Chrome
 * is the ENTIRE POINT of these templates. A defect of that shape is
 * invisible to every other assertion in this tree and fatal to the
 * program's purpose.
 *
 * THERE IS THEREFORE NO ORACLE FOR THIS PROPERTY AND THE LITERALS BELOW
 * ARE THE ORACLE. That is stated plainly rather than dressed up: these
 * arrays are not derived from the templates (that would be a tautology --
 * a test that reads its expectation out of the thing it is testing, which
 * is the defect the review flagged in test_frame). They are the published
 * cipher-suite lists and extension orders of the three browsers the
 * templates were captured from, and each was cross-checked against the
 * captured template when written. Their job is to make ANY edit to a
 * template's shape -- deliberate or accidental, by a human or by a
 * regeneration script -- show up as a named failing assertion rather than
 * as a changed fingerprint nobody looks at.
 *
 * WHEN A BROWSER'S REAL FINGERPRINT CHANGES, these literals are updated
 * IN THE SAME COMMIT as the regenerated template, from the same uTLS
 * capture, and never by copying whatever the new template happens to say.
 * See cloak/clienthello.h's maintenance note.
 *
 * WHAT IS PINNED, and why exactly this much:
 *   - the handshake's legacy_version, the session-id length, the cipher
 *     suite list IN ORDER, the compression-method list, and the extension
 *     type list IN ORDER. Every one of those is part of a JA3 digest and
 *     none of them varies between handshakes of a real browser.
 *   - NOT extension CONTENTS or LENGTHS: the SNI is caller-chosen, the
 *     ECH payload length is deliberately re-drawn per build (see
 *     test_chrome_ech_payload_length_varies_and_stays_consistent), and
 *     the key shares are fresh every time. Pinning those would pin the
 *     randomness this file elsewhere asserts must exist.
 *   - The GREASE values (0xfafa, 0x2a2a, 0x1a1a, 0x44cd) ARE pinned,
 *     because these templates freeze them rather than re-draw them. That
 *     is a known property of the capture, not an oversight of this test;
 *     if a future module makes GREASE per-connection (real browsers do),
 *     this test is where that change must be reflected, deliberately.
 *
 * The assertion runs on a BUILT hello, not on the raw template, so it
 * also covers a build step that reorders or rewrites any of this. */

#define MAX_PINNED_SUITES 32
#define MAX_PINNED_EXTS 32

typedef struct {
    int ok;
    uint16_t legacy_version;
    size_t session_id_len;
    uint16_t suites[MAX_PINNED_SUITES];
    size_t suite_count;
    uint8_t compression[8];
    size_t compression_count;
    uint16_t ext_types[MAX_PINNED_EXTS];
    size_t ext_count;
} fingerprint_t;

/* A second, deliberately separate structural walk from walk_and_verify
 * above: that one checks internal consistency, this one extracts the
 * fingerprint-bearing fields. Kept apart so neither grows a dependency on
 * the other's bookkeeping. */
static fingerprint_t read_fingerprint(const uint8_t *buf, size_t len) {
    fingerprint_t f;
    memset(&f, 0, sizeof(f));
    if (len < 4 + 2 + 32 + 1) {
        return f;
    }
    size_t off = 4;
    f.legacy_version = read_be16(buf + off);
    off += 2;
    off += 32; /* random */
    f.session_id_len = buf[off];
    off += 1 + f.session_id_len;
    if (off + 2 > len) {
        return f;
    }
    size_t cs_len = read_be16(buf + off);
    off += 2;
    if (off + cs_len > len || (cs_len % 2) != 0 || cs_len / 2 > MAX_PINNED_SUITES) {
        return f;
    }
    for (size_t i = 0; i < cs_len / 2; i++) {
        f.suites[i] = read_be16(buf + off + 2 * i);
    }
    f.suite_count = cs_len / 2;
    off += cs_len;
    if (off >= len) {
        return f;
    }
    size_t cm_len = buf[off];
    off += 1;
    if (off + cm_len > len || cm_len > sizeof(f.compression)) {
        return f;
    }
    memcpy(f.compression, buf + off, cm_len);
    f.compression_count = cm_len;
    off += cm_len;
    if (off + 2 > len) {
        return f;
    }
    size_t ext_len = read_be16(buf + off);
    off += 2;
    size_t ext_end = off + ext_len;
    if (ext_end != len) {
        return f;
    }
    while (off < ext_end) {
        if (off + 4 > ext_end || f.ext_count >= MAX_PINNED_EXTS) {
            return f;
        }
        f.ext_types[f.ext_count++] = read_be16(buf + off);
        uint16_t dlen = read_be16(buf + off + 2);
        if (off + 4 + dlen > ext_end) {
            return f;
        }
        off += 4 + (size_t)dlen;
    }
    f.ok = 1;
    return f;
}

/* `report` is 0 only for test_the_fingerprint_pin_can_fail below, which
 * drives this function with deliberately wrong literals: it must still
 * COUNT the mismatches (that is what it is asserting) but must not print
 * FAIL lines, because a file that prints expected FAILs teaches a reader
 * to skim past real ones. It returns the number of mismatches so that
 * case can assert on it. */
static int assert_fingerprint_reported(const char *who,
                                       const cloak_clienthello_template_t *tmpl,
                                       const uint8_t *grease_seed,
                                       const uint16_t *want_suites, size_t want_suite_count,
                                       const uint16_t *want_exts, size_t want_ext_count,
                                       int report) {
    int mismatches = 0;
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t keyshare[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x40);
    fill_marker(keyshare, 0x70);

    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    long n = cloak_clienthello_build_with_grease_seed(tmpl, random, session_id, keyshare,
                                                      "www.bing.com", grease_seed, out,
                                                      sizeof(out));
    ASSERT_TRUE(n > 0);
    if (n <= 0) {
        return mismatches;
    }

    fingerprint_t f = read_fingerprint(out, (size_t)n);
    ASSERT_TRUE(f.ok);
    if (!f.ok) {
        return mismatches;
    }

    /* TLS 1.2 in the handshake's legacy_version field for all three
     * browsers; the real version lives in supported_versions. */
    if (report) {
        ASSERT_EQ_INT(0x0303, f.legacy_version);
    }
    /* A 32-byte session id, which is also where Cloak hides half its auth
     * payload -- a template that stopped carrying one would break both the
     * disguise and the protocol. */
    if (report) {
        ASSERT_EQ_INT(32, (long long)f.session_id_len);
        /* null compression only. Anything else is a 1990s fingerprint. */
        ASSERT_EQ_INT(1, (long long)f.compression_count);
        ASSERT_EQ_INT(0, f.compression[0]);
        ASSERT_EQ_INT((long long)want_suite_count, (long long)f.suite_count);
    }
    for (size_t i = 0; i < want_suite_count && i < f.suite_count; i++) {
        if (f.suites[i] != want_suites[i]) {
            mismatches++;
            if (!report) {
                continue;
            }
            fprintf(stderr,
                    "FAIL %s:%d: %s cipher suite %zu is 0x%04x, pinned 0x%04x -- the "
                    "ClientHello fingerprint changed, and NO interoperability test can see "
                    "that. If this was deliberate, update the template and these literals "
                    "together, from the same uTLS capture.\n",
                    __FILE__, __LINE__, who, i, f.suites[i], want_suites[i]);
            cloak_test_failures++;
        }
    }

    if (report) {
        ASSERT_EQ_INT((long long)want_ext_count, (long long)f.ext_count);
    }
    for (size_t i = 0; i < want_ext_count && i < f.ext_count; i++) {
        if (f.ext_types[i] != want_exts[i]) {
            mismatches++;
            if (!report) {
                continue;
            }
            fprintf(stderr,
                    "FAIL %s:%d: %s extension %zu is 0x%04x, pinned 0x%04x -- the extension "
                    "ORDER is part of the fingerprint and no interoperability test can see "
                    "it change.\n",
                    __FILE__, __LINE__, who, i, f.ext_types[i], want_exts[i]);
            cloak_test_failures++;
        }
    }
    return mismatches;
}

static void assert_fingerprint(const char *who, const cloak_clienthello_template_t *tmpl,
                               const uint8_t *grease_seed,
                               const uint16_t *want_suites, size_t want_suite_count,
                               const uint16_t *want_exts, size_t want_ext_count) {
    (void)assert_fingerprint_reported(who, tmpl, grease_seed, want_suites, want_suite_count,
                                      want_exts, want_ext_count, 1);
}

/* Chrome, as uTLS's HelloChrome_Auto offers them: one GREASE value, the
 * three TLS 1.3 suites, then the TLS 1.2 ECDHE set. THE THREE 0x13xx
 * ENTRIES ARE THE ONES THE REVIEW'S ESCAPING MUTATION REPLACED. */
static const uint16_t chrome_suites[] = {
    0xfafa, /* GREASE, frozen by this capture */
    0x1301, 0x1302, 0x1303,
    0xc02b, 0xc02f, 0xc02c, 0xc030,
    0xcca9, 0xcca8,
    0xc013, 0xc014,
    0x009c, 0x009d,
    0x002f, 0x0035,
};
static const uint16_t chrome_exts[] = {
    0xfafa, /* GREASE */
    0x0000, /* server_name */
    0x0005, /* status_request */
    0xff01, /* renegotiation_info */
    0x001b, /* compress_certificate */
    0x0010, /* application_layer_protocol_negotiation */
    0x44cd, /* application_settings (Chrome's private codepoint) */
    0x0017, /* extended_master_secret */
    0x0033, /* key_share */
    0x000b, /* ec_point_formats */
    0x0023, /* session_ticket */
    0x002d, /* psk_key_exchange_modes */
    0x000a, /* supported_groups */
    0x002b, /* supported_versions */
    0x000d, /* signature_algorithms */
    0xfe0d, /* encrypted_client_hello */
    0x0012, /* signed_certificate_timestamp */
    0x2a2a, /* GREASE */
};

static const uint16_t firefox_suites[] = {
    0x1301, 0x1303, 0x1302, /* note the 1303/1302 swap -- Firefox, not Chrome */
    0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
    0xc00a, 0xc009, 0xc013, 0xc014,
    0x009c, 0x009d,
    0x002f, 0x0035,
};
static const uint16_t firefox_exts[] = {
    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005,
    0x0022, /* delegated_credentials -- Firefox only */
    0x0033, 0x002b, 0x000d, 0x002d,
    0x001c, /* record_size_limit -- Firefox only */
    0xfe0d,
};

static const uint16_t safari_suites[] = {
    0x2a2a, /* GREASE */
    0x1301, 0x1302, 0x1303,
    0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8,
    0xc00a, 0xc009, 0xc014, 0xc013,
    0x009d, 0x009c, 0x0035, 0x002f,
    0xc008, 0xc012, 0x000a, /* the 3DES tail Safari really does still offer */
};
static const uint16_t safari_exts[] = {
    0x2a2a, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005,
    0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b,
    0x1a1a, /* GREASE */
    0x0015, /* padding -- always last */
};

static void test_chrome_fingerprint_is_pinned(void) {
    assert_fingerprint("chrome", &cloak_clienthello_chrome, chrome_capture_grease_seed,
                       chrome_suites,
                       sizeof(chrome_suites) / sizeof(chrome_suites[0]), chrome_exts,
                       sizeof(chrome_exts) / sizeof(chrome_exts[0]));
}

static void test_firefox_fingerprint_is_pinned(void) {
    assert_fingerprint("firefox", &cloak_clienthello_firefox, firefox_capture_grease_seed,
                       firefox_suites,
                       sizeof(firefox_suites) / sizeof(firefox_suites[0]), firefox_exts,
                       sizeof(firefox_exts) / sizeof(firefox_exts[0]));
}

static void test_safari_fingerprint_is_pinned(void) {
    assert_fingerprint("safari", &cloak_clienthello_safari, safari_capture_grease_seed,
                       safari_suites,
                       sizeof(safari_suites) / sizeof(safari_suites[0]), safari_exts,
                       sizeof(safari_exts) / sizeof(safari_exts[0]));
}

/* The pin must be able to FAIL, and a pin that only ever compares a list
 * to itself cannot. This drives the same comparison with two entries
 * deliberately wrong and asserts exactly two mismatches come back --
 * which is the only way to show, from inside the suite, that
 * assert_fingerprint_reported's loops are reachable and discriminating.
 *
 * THE WRONG VALUES ARE DERIVED FROM WHAT THE TEMPLATE ACTUALLY PRODUCED,
 * NOT FROM THE PINNED LITERALS. An earlier draft flipped chrome_suites[1]
 * to 0x000a, and then the review's own 3DES mutation -- which sets the
 * template to exactly that -- turned a deliberate mismatch into a match
 * and this case failed with a confusing off-by-one instead of the
 * fingerprint case failing cleanly. A self-check must not have an opinion
 * about the template's contents; it only checks the comparison machinery.
 * Flipping the low bit of an observed value is wrong by construction
 * whatever the template says. */
static void test_the_fingerprint_pin_can_fail(void) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t keyshare[32];
    fill_marker(random, 0x11);
    fill_marker(session_id, 0x41);
    fill_marker(keyshare, 0x71);

    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    /* Pinned GREASE in BOTH builds -- this one and the one
     * assert_fingerprint_reported does below -- so the only differences
     * between them are the two bits deliberately flipped. With GREASE
     * re-drawn per call the two hellos would differ in up to four more
     * places and this case would count the wrong number of mismatches. */
    long n = cloak_clienthello_build_with_grease_seed(&cloak_clienthello_chrome, random,
                                                      session_id, keyshare, "www.bing.com",
                                                      chrome_capture_grease_seed, out,
                                                      sizeof(out));
    ASSERT_TRUE(n > 0);
    if (n <= 0) {
        return;
    }
    fingerprint_t f = read_fingerprint(out, (size_t)n);
    ASSERT_TRUE(f.ok);
    if (!f.ok || f.suite_count < 2 || f.ext_count < 2) {
        return;
    }

    uint16_t bad_suites[MAX_PINNED_SUITES];
    uint16_t bad_exts[MAX_PINNED_EXTS];
    memcpy(bad_suites, f.suites, sizeof(bad_suites));
    memcpy(bad_exts, f.ext_types, sizeof(bad_exts));
    bad_suites[1] = (uint16_t)(f.suites[1] ^ 0x0001u);
    bad_exts[1] = (uint16_t)(f.ext_types[1] ^ 0x0001u);

    int mismatches = assert_fingerprint_reported("chrome(deliberately wrong)",
                                                 &cloak_clienthello_chrome,
                                                 chrome_capture_grease_seed, bad_suites,
                                                 f.suite_count, bad_exts, f.ext_count, 0);
    ASSERT_EQ_INT(2, mismatches);
}


/* ------------------------------------------------------------------ */
/* GREASE is drawn per connection                                       */
/* ------------------------------------------------------------------ */

/* WHY THIS EXISTS. Until this change the templates carried ONE frozen
 * GREASE draw each -- 0xfafa/0xaaaa/0x2a2a for Chrome,
 * 0x2a2a/0x7a7a/0x3a3a/0x1a1a for Safari -- baked into the captured byte
 * arrays. A frozen GREASE codepoint is not a missing randomisation, it
 * is a STATIC PER-BUILD DISTINGUISHER: every Cloak-C client in the world
 * shipped the same bytes, so every Chrome-profile connection anywhere
 * offered cipher suite 0xfafa, in the one field of a ClientHello whose
 * entire purpose is to be meaningless and unstable. Real Chrome, real
 * Safari and Go Cloak (via utls.UClient, internal/client/TLS.go:66-80)
 * all draw fresh values every handshake.
 *
 * WHAT IS ASSERTED, and each of these can fail on its own:
 *  1. two successive handshakes do not carry the same GREASE values;
 *  2. every drawn value has the RFC 8701 0x?A?A form, over the whole
 *     seed space, not just the seeds a few random builds happen to hit;
 *  3. the two positions that share the GROUP role (supported_groups and
 *     key_share) always agree -- a key_share naming a group that is not
 *     offered is an illegal hello and a distinguisher in itself;
 *  4. the two GREASE extension types always differ, which is BoringSSL's
 *     and uTLS's rule (measured: 0 collisions in 200 uTLS builds);
 *  5. over many builds each GREASE position really does take many
 *     distinct values, which is what a frozen template would fail. */

/* Where a TEMPLATE offset ends up in a built hello, given that build's
 * SNI and ECH-payload deltas. Shared with
 * grease_positions_are_complete_for below, which needs the same mapping
 * to compare the declared positions against the offsets a structural
 * walk of the same hello finds. */
static size_t grease_wire_off(const cloak_clienthello_template_t *tmpl, size_t off,
                              long sni_delta, long ech_delta) {
    if (off > tmpl->sni_host_off) {
        off = (size_t)((long)off + sni_delta);
    }
    /* Chrome's trailing GREASE extension lies past the ECH payload, so
     * the payload resize moves it too. */
    if (tmpl->ech_payload_candidate_count > 0) {
        size_t tail_start = (size_t)((long)tmpl->ech_payload_off + sni_delta)
                            + tmpl->ech_payload_candidate_lens[0];
        if (off >= tail_start) {
            off = (size_t)((long)off + ech_delta);
        }
    }
    return off;
}

static uint16_t read_grease_at(const uint8_t *out, long n, const cloak_clienthello_template_t *tmpl,
                               size_t i, long sni_delta, long ech_delta) {
    size_t off = grease_wire_off(tmpl, tmpl->grease_positions[i].off, sni_delta, ech_delta);
    ASSERT_TRUE((long)off + 2 <= n);
    if ((long)off + 2 > n) {
        return 0;
    }
    return read_be16(out + off);
}

static int is_grease_codepoint(uint16_t v) {
    return (v & 0x0f0fu) == 0x0a0au && (uint8_t)(v >> 8) == (uint8_t)(v & 0xffu);
}

/* 2 and 3 and 4, over the WHOLE seed space rather than over whatever a
 * handful of builds drew: 256 values for the role's own seed byte,
 * crossed with 256 for EXT1's, which is every input the EXT2 correction
 * can see. */
static void test_grease_values_have_the_rfc8701_form(void) {
    for (int role = 0; role < CLOAK_CLIENTHELLO_GREASE_ROLES; role++) {
        int seen[16] = {0};
        int distinct = 0;
        for (int b = 0; b < 256; b++) {
            for (int e1 = 0; e1 < 256; e1 += 17) { /* 17 is coprime with 16: hits every nibble */
                uint8_t seed[CLOAK_CLIENTHELLO_GREASE_ROLES] = {0, 0, 0, 0, 0};
                seed[role] = (uint8_t)b;
                seed[CLOAK_CH_GREASE_EXT1] = (uint8_t)e1;
                if (role == CLOAK_CH_GREASE_EXT1) {
                    seed[role] = (uint8_t)b;
                }
                uint16_t v = cloak_clienthello_grease_value(
                    seed, (cloak_clienthello_grease_role_t)role);
                ASSERT_TRUE(is_grease_codepoint(v));
                if (role == CLOAK_CH_GREASE_EXT2) {
                    uint16_t e = cloak_clienthello_grease_value(seed, CLOAK_CH_GREASE_EXT1);
                    ASSERT_TRUE(v != e); /* BoringSSL's rule, and uTLS's */
                }
                if (!seen[(v >> 12) & 0xf]) {
                    seen[(v >> 12) & 0xf] = 1;
                    distinct++;
                }
            }
        }
        /* All sixteen legal GREASE values reachable for every role --
         * except EXT2, which is pushed off one of them whenever it would
         * collide with EXT1. */
        ASSERT_TRUE(distinct >= 15);
    }
    printf("clienthello: GREASE derivation checked over the whole seed space, all five roles\n");
}

/* 1 and 5: the SHIPPING entry point, with no seed pinned anywhere. */
static void grease_varies_for(const char *who, const cloak_clienthello_template_t *tmpl) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    ASSERT_TRUE(tmpl->grease_position_count > 0);

    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    uint16_t first[CLOAK_CLIENTHELLO_MAX_GREASE_POSITIONS];
    uint16_t distinct_seen[CLOAK_CLIENTHELLO_MAX_GREASE_POSITIONS][16];
    size_t distinct_count[CLOAK_CLIENTHELLO_MAX_GREASE_POSITIONS] = {0};
    int any_differs_from_first = 0;
    int consecutive_pairs_all_equal = 1;
    uint16_t prev[CLOAK_CLIENTHELLO_MAX_GREASE_POSITIONS];

    for (int iter = 0; iter < 200; iter++) {
        long n = cloak_clienthello_build(tmpl, random, session_id, key_share, "www.bing.com", out,
                                         sizeof(out));
        ASSERT_TRUE(n > 0);
        if (n <= 0) {
            return;
        }
        long sni_delta = (long)strlen("www.bing.com") - (long)tmpl->sni_host_len;
        long ech_delta = 0;
        if (tmpl->ech_payload_candidate_count > 0) {
            /* n = template + sni_delta + (chosen - candidate[0]). */
            ech_delta = n - (long)tmpl->len - sni_delta;
        }

        uint16_t v[CLOAK_CLIENTHELLO_MAX_GREASE_POSITIONS];
        uint16_t group_value = 0;
        int group_seen = 0;
        uint16_t ext1 = 0, ext2 = 0;
        for (size_t i = 0; i < tmpl->grease_position_count; i++) {
            v[i] = read_grease_at(out, n, tmpl, i, sni_delta, ech_delta);
            /* 2, on the wire this time. */
            ASSERT_TRUE(is_grease_codepoint(v[i]));
            switch (tmpl->grease_positions[i].role) {
            case CLOAK_CH_GREASE_GROUP:
                /* 3: every position sharing the GROUP role carries the
                 * same value in one hello. */
                if (group_seen) {
                    ASSERT_EQ_INT(group_value, v[i]);
                } else {
                    group_value = v[i];
                    group_seen = 1;
                }
                break;
            case CLOAK_CH_GREASE_EXT1:
                ext1 = v[i];
                break;
            case CLOAK_CH_GREASE_EXT2:
                ext2 = v[i];
                break;
            default:
                break;
            }
            int known = 0;
            for (size_t k = 0; k < distinct_count[i]; k++) {
                if (distinct_seen[i][k] == v[i]) {
                    known = 1;
                }
            }
            if (!known && distinct_count[i] < 16) {
                distinct_seen[i][distinct_count[i]++] = v[i];
            }
        }
        ASSERT_TRUE(group_seen);
        /* 4, on the wire. */
        ASSERT_TRUE(ext1 != ext2);

        if (iter == 0) {
            memcpy(first, v, sizeof(v));
        } else {
            if (memcmp(first, v, sizeof(uint16_t) * tmpl->grease_position_count) != 0) {
                any_differs_from_first = 1;
            }
            if (memcmp(prev, v, sizeof(uint16_t) * tmpl->grease_position_count) != 0) {
                consecutive_pairs_all_equal = 0;
            }
        }
        memcpy(prev, v, sizeof(v));
    }

    /* 1. Not "some build somewhere differed" -- two SUCCESSIVE builds
     * must differ, which is what an eavesdropper on one client sees. The
     * chance of a false failure is the chance that all 199 consecutive
     * pairs collide, which for five independent 1-in-16 draws is
     * (1/16^4)^199 -- there is no flake here. (Four, not five: EXT2 is
     * constrained by EXT1.) */
    ASSERT_TRUE(!consecutive_pairs_all_equal);
    ASSERT_TRUE(any_differs_from_first);

    /* 5. A frozen template gives exactly 1 here for every position. */
    for (size_t i = 0; i < tmpl->grease_position_count; i++) {
        ASSERT_TRUE(distinct_count[i] >= 8);
    }
    printf("clienthello: %s GREASE over 200 builds, distinct values per position:", who);
    for (size_t i = 0; i < tmpl->grease_position_count; i++) {
        printf(" %zu", distinct_count[i]);
    }
    printf("\n");
}

static void test_chrome_grease_varies_between_handshakes(void) {
    grease_varies_for("chrome", &cloak_clienthello_chrome);
}

static void test_safari_grease_varies_between_handshakes(void) {
    grease_varies_for("safari", &cloak_clienthello_safari);
}

/* ------------------------------------------------------------------ */
/* What the hello SAYS, not what the template DECLARES                 */
/* ------------------------------------------------------------------ */

/* A third structural walk, and the only one that opens extension
 * BODIES: walk_and_verify checks internal consistency, read_fingerprint
 * extracts the JA3-bearing lists, and this one enumerates every 2-byte
 * slot of a ClientHello that can legally carry a codepoint -- cipher
 * suites, extension types, the supported_groups list, the key_share
 * client_shares' group ids, and the supported_versions list -- recording
 * each slot's OFFSET and VALUE.
 *
 * WHY IT EXISTS. The two properties asserted below cannot be read off
 * tmpl->grease_positions, because a check that asks the template where
 * its GREASE is and then compares those bytes to each other can only
 * confirm that the template agrees with itself. Both were measured to be
 * blind that way, by mutation. That the PRE-FIX tree passed all 85
 * binaries under each of them is the re-review's measurement, read here
 * rather than re-taken; what was measured here is the other half, below:
 *
 *   MUT-E: re-tag chrome offset 1478 and safari offset 162 (the
 *   supported_groups GREASE) as CLOAK_CH_GREASE_CIPHER. 15 of every 16
 *   hellos then offer a key_share naming a GREASE group that
 *   supported_groups does not list -- an illegal ClientHello, and the
 *   property clienthello.h calls load-bearing. Caught only by
 *   key_share_groups_are_offered_for below.
 *
 *   MUT-D: chrome grease_position_count 6 -> 5. The trailing GREASE
 *   extension type refreezes at 0x2a2a for every client in the world --
 *   the original defect, narrowed to one codepoint -- and nothing
 *   notices, because the dropped position is simply never read. Caught
 *   only by grease_positions_are_complete_for below.
 *
 * Both mutations were applied to libcloak-common/src/clienthello.c,
 * rebuilt, and run through the WHOLE suite with these cases in place:
 * each fails test_clienthello and no other binary -- 84 of 85 pass --
 * so each gap is closed by exactly the case named above it and by
 * nothing that already existed. Both were then reverted. Nothing in this
 * section consults tmpl->grease_positions to decide WHERE to look. */

#define MAX_CH_SLOTS 64

typedef struct {
    size_t off[MAX_CH_SLOTS];
    uint16_t val[MAX_CH_SLOTS];
    size_t count;
} ch_slots_t;

typedef struct {
    int ok;
    ch_slots_t suites;
    ch_slots_t ext_types;
    ch_slots_t groups;    /* supported_groups (0x000a) body */
    ch_slots_t ks_groups; /* key_share (0x0033) client_shares' group ids */
    ch_slots_t versions;  /* supported_versions (0x002b) body */
} ch_codepoints_t;

static int slots_push(ch_slots_t *s, size_t off, uint16_t v) {
    if (s->count >= MAX_CH_SLOTS) {
        return 0;
    }
    s->off[s->count] = off;
    s->val[s->count] = v;
    s->count++;
    return 1;
}

static int slots_hold_value(const ch_slots_t *s, uint16_t v) {
    for (size_t i = 0; i < s->count; i++) {
        if (s->val[i] == v) {
            return 1;
        }
    }
    return 0;
}

static ch_codepoints_t read_codepoints(const uint8_t *buf, size_t len) {
    ch_codepoints_t c;
    memset(&c, 0, sizeof(c));
    if (len < 4 + 2 + 32 + 1) {
        return c;
    }
    size_t off = 4 + 2 + 32; /* header | client_version | random */
    size_t sid_len = buf[off];
    off += 1 + sid_len;
    if (off + 2 > len) {
        return c;
    }
    size_t cs_len = read_be16(buf + off);
    off += 2;
    /* The cipher-list LENGTH field is deliberately NOT a slot. Safari's
     * is 0x002a, so a byte-wise hunt for 0x?A?A finds a phantom GREASE
     * straddling its low byte and the first byte of the real GREASE
     * suite that follows it (template offset 72, where the suite is at
     * 73). Walking the structure cannot make that mistake; that is the
     * whole reason this walk exists rather than a scan. */
    if (off + cs_len > len || (cs_len % 2) != 0) {
        return c;
    }
    for (size_t i = 0; i + 1 < cs_len; i += 2) {
        if (!slots_push(&c.suites, off + i, read_be16(buf + off + i))) {
            return c;
        }
    }
    off += cs_len;
    if (off >= len) {
        return c;
    }
    size_t cm_len = buf[off];
    off += 1 + cm_len;
    if (off + 2 > len) {
        return c;
    }
    size_t ext_len = read_be16(buf + off);
    off += 2;
    size_t ext_end = off + ext_len;
    if (ext_end != len) {
        return c;
    }
    while (off < ext_end) {
        if (off + 4 > ext_end) {
            return c;
        }
        uint16_t ext_type = read_be16(buf + off);
        size_t dlen = read_be16(buf + off + 2);
        if (off + 4 + dlen > ext_end) {
            return c;
        }
        if (!slots_push(&c.ext_types, off, ext_type)) {
            return c;
        }
        size_t d = off + 4;
        if (ext_type == 0x000a) { /* supported_groups */
            if (dlen < 2) {
                return c;
            }
            size_t list_len = read_be16(buf + d);
            if (list_len + 2 != dlen || (list_len % 2) != 0) {
                return c;
            }
            for (size_t i = 0; i + 1 < list_len; i += 2) {
                if (!slots_push(&c.groups, d + 2 + i, read_be16(buf + d + 2 + i))) {
                    return c;
                }
            }
        } else if (ext_type == 0x0033) { /* key_share */
            if (dlen < 2) {
                return c;
            }
            size_t list_len = read_be16(buf + d);
            if (list_len + 2 != dlen) {
                return c;
            }
            size_t p = d + 2;
            size_t list_end = p + list_len;
            while (p < list_end) {
                if (p + 4 > list_end) {
                    return c;
                }
                if (!slots_push(&c.ks_groups, p, read_be16(buf + p))) {
                    return c;
                }
                size_t kx_len = read_be16(buf + p + 2);
                if (p + 4 + kx_len > list_end) {
                    return c;
                }
                p += 4 + kx_len;
            }
        } else if (ext_type == 0x002b) { /* supported_versions */
            if (dlen < 1) {
                return c;
            }
            size_t list_len = buf[d];
            if (list_len + 1 != dlen || (list_len % 2) != 0) {
                return c;
            }
            for (size_t i = 0; i + 1 < list_len; i += 2) {
                if (!slots_push(&c.versions, d + 1 + i, read_be16(buf + d + 1 + i))) {
                    return c;
                }
            }
        }
        off += 4 + dlen;
    }
    c.ok = 1;
    return c;
}

/* Every group the key_share extension carries a share for must also
 * appear in the supported_groups list -- RFC 8446 4.2.8, and a hello
 * that breaks it is both illegal and a distinguisher in itself.
 *
 * The comparison is against the supported_groups list PARSED OUT OF THE
 * EMITTED BYTES. grease_varies_for's clause 3 compares the positions the
 * template TAGS CLOAK_CH_GREASE_GROUP against each other, which is true
 * by construction (one role yields one value) and stayed true under
 * MUT-E while the emitted hellos went illegal. */
static void key_share_groups_are_offered_for(const char *who,
                                             const cloak_clienthello_template_t *tmpl) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    ch_codepoints_t c;
    memset(&c, 0, sizeof(c));
    int builds_with_a_grease_share = 0;

    for (int iter = 0; iter < 200; iter++) {
        long n = cloak_clienthello_build(tmpl, random, session_id, key_share, "www.bing.com", out,
                                         sizeof(out));
        ASSERT_TRUE(n > 0);
        if (n <= 0) {
            return;
        }
        c = read_codepoints(out, (size_t)n);
        ASSERT_TRUE(c.ok);
        if (!c.ok) {
            return;
        }
        ASSERT_TRUE(c.ks_groups.count > 0);
        ASSERT_TRUE(c.groups.count > 0);

        int grease_share_here = 0;
        for (size_t i = 0; i < c.ks_groups.count; i++) {
            if (!slots_hold_value(&c.groups, c.ks_groups.val[i])) {
                /* Reported once, not 200 times: a wall of identical FAIL
                 * lines teaches a reader to skim past real ones. */
                fprintf(stderr,
                        "FAIL %s:%d: %s key_share offers group 0x%04x, absent from "
                        "supported_groups (build %d)\n",
                        __FILE__, __LINE__, who, c.ks_groups.val[i], iter);
                cloak_test_failures++;
                return;
            }
            if (is_grease_codepoint(c.ks_groups.val[i])) {
                grease_share_here = 1;
            }
        }
        builds_with_a_grease_share += grease_share_here;
    }

    /* Non-vacuity: for a GREASE-bearing template the subset check must
     * actually be exercised on the group that is RE-DRAWN per
     * connection, not only on the fixed ones. Both templates put a
     * GREASE group in key_share on every build. */
    ASSERT_EQ_INT(200, builds_with_a_grease_share);
    printf("clienthello: %s key_share groups all present in the emitted supported_groups over "
           "200 builds (%zu shares, %zu groups offered)\n",
           who, c.ks_groups.count, c.groups.count);
}

static void test_chrome_key_share_group_is_actually_offered(void) {
    key_share_groups_are_offered_for("chrome", &cloak_clienthello_chrome);
}

static void test_safari_key_share_group_is_actually_offered(void) {
    key_share_groups_are_offered_for("safari", &cloak_clienthello_safari);
}

/* The mirror of test_firefox_offers_no_grease, for the templates that DO
 * carry GREASE: every 0x?A?A the emitted hello actually contains must be
 * a position the template declares, and must vary across builds.
 *
 * grease_varies_for iterates tmpl->grease_positions, so a codepoint the
 * table forgets is never looked at -- which is exactly how MUT-D refroze
 * Chrome's trailing GREASE extension type with the suite green. This
 * case never iterates the table to find bytes; it finds the bytes
 * structurally and then requires the table to account for all of them.
 * The offsets in clienthello.c are hand-written constants against
 * templates the headers expect to be REGENERATED, so this is the check
 * that survives a regeneration: it compares against the wire, and a
 * regenerated template that moves or adds a GREASE codepoint without
 * updating the table fails here. */
static void grease_positions_are_complete_for(const char *who,
                                              const cloak_clienthello_template_t *tmpl) {
    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);

    ASSERT_TRUE(tmpl->grease_position_count > 0);

    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    uint16_t distinct_seen[MAX_CH_SLOTS][16];
    size_t distinct_count[MAX_CH_SLOTS];
    size_t found_count = 0;
    memset(distinct_count, 0, sizeof(distinct_count));

    for (int iter = 0; iter < 200; iter++) {
        long n = cloak_clienthello_build(tmpl, random, session_id, key_share, "www.bing.com", out,
                                         sizeof(out));
        ASSERT_TRUE(n > 0);
        if (n <= 0) {
            return;
        }
        ch_codepoints_t c = read_codepoints(out, (size_t)n);
        ASSERT_TRUE(c.ok);
        if (!c.ok) {
            return;
        }

        /* Every GREASE codepoint the hello carries, in a fixed
         * enumeration order, so index j means the same slot on every
         * build (guaranteed by the set equality asserted just below). */
        const ch_slots_t *kinds[5] = {&c.suites, &c.ext_types, &c.groups, &c.ks_groups,
                                      &c.versions};
        size_t found_off[MAX_CH_SLOTS];
        uint16_t found_val[MAX_CH_SLOTS];
        size_t fc = 0;
        for (size_t k = 0; k < 5; k++) {
            for (size_t i = 0; i < kinds[k]->count; i++) {
                if (is_grease_codepoint(kinds[k]->val[i]) && fc < MAX_CH_SLOTS) {
                    found_off[fc] = kinds[k]->off[i];
                    found_val[fc] = kinds[k]->val[i];
                    fc++;
                }
            }
        }

        /* COMPLETENESS: the table's count is the hello's count. This is
         * the assertion MUT-D fails. */
        ASSERT_EQ_INT((long long)tmpl->grease_position_count, (long long)fc);
        if (fc != tmpl->grease_position_count) {
            fprintf(stderr, "       (%s build %d carries %zu GREASE codepoints, table declares %zu)\n",
                    who, iter, fc, tmpl->grease_position_count);
            return;
        }

        /* SOUNDNESS: every declared position lands on one of them. With
         * the counts equal and slot offsets distinct, this is set
         * equality -- no declared offset points at a byte pair the wire
         * structure does not treat as a codepoint. */
        long sni_delta = (long)strlen("www.bing.com") - (long)tmpl->sni_host_len;
        long ech_delta = 0;
        if (tmpl->ech_payload_candidate_count > 0) {
            ech_delta = n - (long)tmpl->len - sni_delta;
        }
        for (size_t i = 0; i < tmpl->grease_position_count; i++) {
            size_t want = grease_wire_off(tmpl, tmpl->grease_positions[i].off, sni_delta,
                                          ech_delta);
            int seen = 0;
            for (size_t j = 0; j < fc; j++) {
                if (found_off[j] == want) {
                    seen = 1;
                }
            }
            ASSERT_TRUE(seen);
            if (!seen) {
                fprintf(stderr, "       (%s declares GREASE at template offset %zu, wire offset "
                                "%zu, which is not a codepoint slot)\n",
                        who, tmpl->grease_positions[i].off, want);
                return;
            }
        }

        for (size_t j = 0; j < fc; j++) {
            int known = 0;
            for (size_t k = 0; k < distinct_count[j]; k++) {
                if (distinct_seen[j][k] == found_val[j]) {
                    known = 1;
                }
            }
            if (!known && distinct_count[j] < 16) {
                distinct_seen[j][distinct_count[j]++] = found_val[j];
            }
        }
        found_count = fc;
    }

    /* And none of them is frozen. A refrozen codepoint gives exactly 1;
     * 200 builds of a real 1-in-16 draw give 16 with overwhelming
     * probability, so 8 is far below anything reachable by chance. */
    for (size_t j = 0; j < found_count; j++) {
        ASSERT_TRUE(distinct_count[j] >= 8);
    }
    printf("clienthello: %s hello carries %zu GREASE codepoints, all declared, distinct values "
           "per wire slot over 200 builds:",
           who, found_count);
    for (size_t j = 0; j < found_count; j++) {
        printf(" %zu", distinct_count[j]);
    }
    printf("\n");
}

static void test_chrome_grease_position_table_is_complete(void) {
    grease_positions_are_complete_for("chrome", &cloak_clienthello_chrome);
}

static void test_safari_grease_position_table_is_complete(void) {
    grease_positions_are_complete_for("safari", &cloak_clienthello_safari);
}

/* Real Firefox offers NO GREASE -- measured over 200 utls.HelloFirefox_Auto
 * builds, zero 0x?A?A codepoints anywhere. Adding some would be the
 * distinguisher, so this pins the absence. */
static void test_firefox_offers_no_grease(void) {
    ASSERT_EQ_INT(0, (int)cloak_clienthello_firefox.grease_position_count);

    uint8_t random[32];
    uint8_t session_id[32];
    uint8_t key_share[32];
    fill_marker(random, 0x10);
    fill_marker(session_id, 0x30);
    fill_marker(key_share, 0x50);
    uint8_t out[CLOAK_CLIENTHELLO_MAX_BYTES];
    long n = cloak_clienthello_build(&cloak_clienthello_firefox, random, session_id, key_share,
                                     "www.bing.com", out, sizeof(out));
    ASSERT_TRUE(n > 0);
    if (n <= 0) {
        return;
    }
    fingerprint_t f = read_fingerprint(out, (size_t)n);
    ASSERT_TRUE(f.ok);
    for (size_t i = 0; i < f.suite_count; i++) {
        ASSERT_TRUE(!is_grease_codepoint(f.suites[i]));
    }
    for (size_t i = 0; i < f.ext_count; i++) {
        ASSERT_TRUE(!is_grease_codepoint(f.ext_types[i]));
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
    test_chrome_fingerprint_is_pinned();
    test_firefox_fingerprint_is_pinned();
    test_safari_fingerprint_is_pinned();
    test_the_fingerprint_pin_can_fail();
    test_grease_values_have_the_rfc8701_form();
    test_chrome_grease_varies_between_handshakes();
    test_safari_grease_varies_between_handshakes();
    test_chrome_key_share_group_is_actually_offered();
    test_safari_key_share_group_is_actually_offered();
    test_chrome_grease_position_table_is_complete();
    test_safari_grease_position_table_is_complete();
    test_firefox_offers_no_grease();
TEST_MAIN_END()
