/* Tests for the admin API's user JSON codec (cloak/user_json.h).
 *
 * Two things shape every assertion in this file.
 *
 * THE CONTRACT IS SOMEONE ELSE'S. A real `ck-client -a` speaks Go's
 * encoding/json applied to an untagged UserInfo struct, so the exact
 * bytes matter -- field order, no spaces, standard-alphabet base64 for
 * the UID, `null` for an unset field. The exact-string assertions below
 * are not pedantry; they are the only way a port can tell it still
 * interoperates.
 *
 * THE INPUT IS HOSTILE AND AUTHENTICATED. Every rejection case pins the
 * SPECIFIC error code, and every boundary is tested from BOTH sides --
 * one value in and one value out. A test that only rejects something far
 * outside the range passes with the bound set anywhere, which is not
 * coverage, it is decoration.
 */
#include "cloak/user_json.h"
#include "test_framework.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The UID from the plan's worked example: bytes 0x10..0x1f, which is
 * "EBESExQVFhcYGRobHB0eHw==" in standard base64. NOTE that this value
 * encodes IDENTICALLY under both alphabets -- none of its sextets is 62
 * or 63 -- so it cannot by itself tell standard base64 from URL-safe.
 * kAlphaUID below exists precisely because it cannot; see
 * test_uid_alphabet_is_standard_not_url_safe. */
static const uint8_t kUID[CLOAK_UID_LEN] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

#define UID_B64 "EBESExQVFhcYGRobHB0eHw=="

/* A UID chosen so its standard base64 contains BOTH characters the two
 * alphabets disagree about, '+' (62) and '/' (63). Without one of these
 * the encoder could quietly use base64.URLEncoding -- the alphabet the
 * request PATH uses -- and every assertion in this file would still
 * pass, which is exactly the shape of bug that hides until a real UID
 * happens to contain the offending sextet. */
static const uint8_t kAlphaUID[CLOAK_UID_LEN] = {
    0xFB, 0xF0, 0x00, 0xFB, 0xF0, 0x00, 0xFB, 0xF0,
    0x00, 0xFB, 0xF0, 0x00, 0xFB, 0xF0, 0x00, 0xFB
};
#define ALPHA_UID_STD "+/AA+/AA+/AA+/AA+/AA+w=="
#define ALPHA_UID_URL "-_AA-_AA-_AA-_AA-_AA-w=="

/* The one string this whole module exists to produce. */
static const char kGolden[] =
    "{\"UID\":\"" UID_B64 "\",\"SessionsCap\":10,\"UpRate\":0,"
    "\"DownRate\":0,\"UpCredit\":1000000,\"DownCredit\":1000000,"
    "\"ExpiryTime\":1789000000}";

/* Sentinels: values no test document ever contains, so "untouched" is
 * distinguishable from "written with the document's value" AND from
 * "zeroed". */
#define SENT_CAP    ((int32_t)-1010101)
#define SENT_UP_R   ((int64_t)-2020202)
#define SENT_DOWN_R ((int64_t)-3030303)
#define SENT_UP_C   ((int64_t)-4040404)
#define SENT_DOWN_C ((int64_t)-5050505)
#define SENT_EXP    ((int64_t)-6060606)

static void seed(cloak_user_info_t *u) {
    memset(u->uid, 0xAB, sizeof(u->uid));
    u->sessions_cap = SENT_CAP;
    u->up_rate = SENT_UP_R;
    u->down_rate = SENT_DOWN_R;
    u->up_credit = SENT_UP_C;
    u->down_credit = SENT_DOWN_C;
    u->expiry_time = SENT_EXP;
}

static void assert_all_sentinel(const cloak_user_info_t *u) {
    uint8_t untouched[CLOAK_UID_LEN];
    memset(untouched, 0xAB, sizeof(untouched));
    ASSERT_MEM_EQ(u->uid, untouched, sizeof(untouched));
    ASSERT_EQ_INT(SENT_CAP, u->sessions_cap);
    ASSERT_EQ_INT(SENT_UP_R, u->up_rate);
    ASSERT_EQ_INT(SENT_DOWN_R, u->down_rate);
    ASSERT_EQ_INT(SENT_UP_C, u->up_credit);
    ASSERT_EQ_INT(SENT_DOWN_C, u->down_credit);
    ASSERT_EQ_INT(SENT_EXP, u->expiry_time);
}

static int decode_str(const char *json, cloak_user_info_t *io,
                      uint32_t *fields, int *have_uid) {
    return cloak_user_json_decode((const uint8_t *)json, strlen(json), io,
                                  fields, have_uid);
}

/* Decodes into a seeded struct and reports only the return code; used by
 * the many rejection cases, all of which also assert nothing moved. */
static int reject(const char *json) {
    cloak_user_info_t u;
    uint32_t fields = 0xFFFFFFFFu;
    int have_uid = 42;
    int rc;
    seed(&u);
    rc = decode_str(json, &u, &fields, &have_uid);
    /* On failure NOTHING is written -- not the struct, not the mask, not
     * the uid flag. Pinning all three here means every rejection case in
     * this file doubles as a "no partial application" case. */
    assert_all_sentinel(&u);
    ASSERT_EQ_INT(0xFFFFFFFFu, fields);
    ASSERT_EQ_INT(42, have_uid);
    return rc;
}

static void expect_reject(const char *what, const char *json, int want) {
    int got = reject(json);
    if (got != want) {
        fprintf(stderr, "FAIL %s: decode(%s) -> %d, want %d\n", what, json,
                got, want);
        cloak_test_failures++;
    }
}

/* ---------------------------------------------------------------- */
/* 1. The exact bytes                                               */
/* ---------------------------------------------------------------- */

static void full_user(cloak_user_info_t *u) {
    memcpy(u->uid, kUID, sizeof(kUID));
    u->sessions_cap = 10;
    u->up_rate = 0;
    u->down_rate = 0;
    u->up_credit = 1000000;
    u->down_credit = 1000000;
    u->expiry_time = 1789000000;
}

static void test_encode_exact_bytes(void) {
    cloak_user_info_t u;
    char out[CLOAK_USER_JSON_MAX];
    size_t len = 0;

    full_user(&u);
    memset(out, 0x7f, sizeof(out));
    ASSERT_EQ_INT(0, cloak_user_json_encode(&u, CLOAK_USER_FIELD_ALL, out,
                                            sizeof(out), &len));
    ASSERT_EQ_INT(strlen(kGolden), len);
    ASSERT_EQ_INT(0, strcmp(out, kGolden));
    if (strcmp(out, kGolden) != 0) {
        fprintf(stderr, "  got:  %s\n  want: %s\n", out, kGolden);
    }
    /* out_len is the length EXCLUDING the NUL, and the NUL is there. */
    ASSERT_EQ_INT(0, out[len]);
}

/* An unset field is `null`, in place, not omitted -- Go marshals a nil
 * pointer that way and a client reading positionally would otherwise
 * silently shift. */
static void test_encode_null_for_unset_fields(void) {
    cloak_user_info_t u;
    char out[CLOAK_USER_JSON_MAX];
    static const char want[] =
        "{\"UID\":\"" UID_B64 "\",\"SessionsCap\":null,\"UpRate\":null,"
        "\"DownRate\":null,\"UpCredit\":1000000,\"DownCredit\":null,"
        "\"ExpiryTime\":null}";

    full_user(&u);
    ASSERT_EQ_INT(0, cloak_user_json_encode(&u, CLOAK_USER_FIELD_UP_CREDIT,
                                            out, sizeof(out), NULL));
    ASSERT_EQ_INT(0, strcmp(out, want));
    if (strcmp(out, want) != 0) {
        fprintf(stderr, "  got:  %s\n  want: %s\n", out, want);
    }

    /* And with no bits at all every number is null. */
    ASSERT_EQ_INT(0, cloak_user_json_encode(&u, 0, out, sizeof(out), NULL));
    ASSERT_EQ_INT(0, strcmp(out,
        "{\"UID\":\"" UID_B64 "\",\"SessionsCap\":null,\"UpRate\":null,"
        "\"DownRate\":null,\"UpCredit\":null,\"DownCredit\":null,"
        "\"ExpiryTime\":null}"));
}

static void test_encode_rejects_unknown_mask_bits(void) {
    cloak_user_info_t u;
    char out[CLOAK_USER_JSON_MAX];
    full_user(&u);
    memset(out, 0x7f, sizeof(out));
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_ARG,
                  cloak_user_json_encode(&u, CLOAK_USER_FIELD_ALL | (1u << 6),
                                         out, sizeof(out), NULL));
    ASSERT_EQ_INT(0x7f, (unsigned char)out[0]); /* nothing written */
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_ARG,
                  cloak_user_json_encode(NULL, 0, out, sizeof(out), NULL));
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_ARG,
                  cloak_user_json_encode(&u, 0, NULL, sizeof(out), NULL));
}

/* ---------------------------------------------------------------- */
/* 2. Round trip                                                    */
/* ---------------------------------------------------------------- */

static void roundtrip_once(const char *what, const cloak_user_info_t *u,
                           uint32_t fields) {
    char first[CLOAK_USER_JSON_MAX], second[CLOAK_USER_JSON_MAX];
    cloak_user_info_t back;
    uint32_t got_fields = 0;
    int have_uid = 0;

    ASSERT_EQ_INT(0, cloak_user_json_encode(u, fields, first, sizeof(first),
                                            NULL));
    seed(&back);
    ASSERT_EQ_INT(0, decode_str(first, &back, &got_fields, &have_uid));
    ASSERT_EQ_INT(1, have_uid);
    ASSERT_EQ_INT(fields, got_fields);
    ASSERT_EQ_INT(0, cloak_user_json_encode(&back, got_fields, second,
                                            sizeof(second), NULL));
    if (strcmp(first, second) != 0) {
        fprintf(stderr, "FAIL round trip %s:\n  1st: %s\n  2nd: %s\n", what,
                first, second);
        cloak_test_failures++;
    }
}

static void test_round_trip_is_stable(void) {
    cloak_user_info_t u;
    full_user(&u);
    roundtrip_once("all fields", &u, CLOAK_USER_FIELD_ALL);
    roundtrip_once("one field", &u, CLOAK_USER_FIELD_DOWN_RATE);
    roundtrip_once("no fields", &u, 0);

    /* Extremes that still fit the decoder's range, so the round trip is
     * genuinely exercising the formatter and not just small numbers. */
    u.sessions_cap = 2147483647;
    u.up_rate = CLOAK_USER_JSON_MAX_SAFE_INT;
    u.down_rate = -CLOAK_USER_JSON_MAX_SAFE_INT;
    u.up_credit = 1000000000000LL;
    u.down_credit = 0;
    u.expiry_time = -1;
    roundtrip_once("extremes", &u, CLOAK_USER_FIELD_ALL);
}

/* ---------------------------------------------------------------- */
/* 3 & 4. Absent and null map to a clear bit, value untouched        */
/* ---------------------------------------------------------------- */

typedef struct {
    const char *name;    /* JSON field name */
    uint32_t bit;
    int64_t present_val; /* the value the "present" document carries */
} field_case_t;

static const field_case_t kFields[] = {
    { "SessionsCap", CLOAK_USER_FIELD_SESSIONS_CAP, 7 },
    { "UpRate", CLOAK_USER_FIELD_UP_RATE, 111 },
    { "DownRate", CLOAK_USER_FIELD_DOWN_RATE, 222 },
    { "UpCredit", CLOAK_USER_FIELD_UP_CREDIT, 333 },
    { "DownCredit", CLOAK_USER_FIELD_DOWN_CREDIT, 444 },
    { "ExpiryTime", CLOAK_USER_FIELD_EXPIRY_TIME, 555 },
};
#define N_FIELDS ((int)(sizeof(kFields) / sizeof(kFields[0])))

static int64_t field_value(const cloak_user_info_t *u, uint32_t bit) {
    switch (bit) {
        case CLOAK_USER_FIELD_SESSIONS_CAP: return u->sessions_cap;
        case CLOAK_USER_FIELD_UP_RATE:      return u->up_rate;
        case CLOAK_USER_FIELD_DOWN_RATE:    return u->down_rate;
        case CLOAK_USER_FIELD_UP_CREDIT:    return u->up_credit;
        case CLOAK_USER_FIELD_DOWN_CREDIT:  return u->down_credit;
        default:                            return u->expiry_time;
    }
}

static int64_t field_sentinel(uint32_t bit) {
    switch (bit) {
        case CLOAK_USER_FIELD_SESSIONS_CAP: return SENT_CAP;
        case CLOAK_USER_FIELD_UP_RATE:      return SENT_UP_R;
        case CLOAK_USER_FIELD_DOWN_RATE:    return SENT_DOWN_R;
        case CLOAK_USER_FIELD_UP_CREDIT:    return SENT_UP_C;
        case CLOAK_USER_FIELD_DOWN_CREDIT:  return SENT_DOWN_C;
        default:                            return SENT_EXP;
    }
}

/* Builds a document containing every field EXCEPT `skip`, which is
 * either omitted (mode 0) or explicitly null (mode 1). */
static void build_doc(char *buf, size_t cap, int skip, int mode) {
    int i;
    size_t n = 0;
    n += (size_t)snprintf(buf + n, cap - n, "{\"UID\":\"" UID_B64 "\"");
    for (i = 0; i < N_FIELDS; i++) {
        if (i == skip) {
            if (mode == 1) {
                n += (size_t)snprintf(buf + n, cap - n, ",\"%s\":null",
                                      kFields[i].name);
            }
            continue;
        }
        n += (size_t)snprintf(buf + n, cap - n, ",\"%s\":%" PRId64,
                              kFields[i].name, kFields[i].present_val);
    }
    snprintf(buf + n, cap - n, "}");
}

static void test_absent_and_null_clear_the_bit(void) {
    int skip, mode, i;
    for (mode = 0; mode <= 1; mode++) {
        for (skip = 0; skip < N_FIELDS; skip++) {
            char doc[512];
            cloak_user_info_t u;
            uint32_t fields = 0;
            int have_uid = 0;

            build_doc(doc, sizeof(doc), skip, mode);
            seed(&u);
            ASSERT_EQ_INT(0, decode_str(doc, &u, &fields, &have_uid));
            ASSERT_EQ_INT(1, have_uid);
            ASSERT_MEM_EQ(u.uid, kUID, sizeof(kUID));

            /* The skipped field: bit clear AND value still the caller's,
             * which is neither 0 nor what the document would have said. */
            if ((fields & kFields[skip].bit) != 0) {
                fprintf(stderr, "FAIL %s %s: bit set\n",
                        mode ? "null" : "absent", kFields[skip].name);
                cloak_test_failures++;
            }
            ASSERT_EQ_INT(field_sentinel(kFields[skip].bit),
                          field_value(&u, kFields[skip].bit));

            /* Every OTHER field: bit set AND the document's value, so a
             * mutation that simply never sets a bit cannot pass. */
            for (i = 0; i < N_FIELDS; i++) {
                if (i == skip) {
                    continue;
                }
                if ((fields & kFields[i].bit) == 0) {
                    fprintf(stderr, "FAIL %s %s: sibling %s bit clear\n",
                            mode ? "null" : "absent", kFields[skip].name,
                            kFields[i].name);
                    cloak_test_failures++;
                }
                ASSERT_EQ_INT(kFields[i].present_val,
                              field_value(&u, kFields[i].bit));
            }
        }
    }
}

static void test_all_absent_is_an_empty_mask(void) {
    cloak_user_info_t u;
    uint32_t fields = 0xFFFFFFFFu;
    int have_uid = 7;
    seed(&u);
    ASSERT_EQ_INT(0, decode_str("{}", &u, &fields, &have_uid));
    ASSERT_EQ_INT(0, fields);
    ASSERT_EQ_INT(0, have_uid);
    assert_all_sentinel(&u); /* including the uid: absent means untouched */
}

static void test_unknown_fields_are_ignored(void) {
    cloak_user_info_t u;
    uint32_t fields = 0;
    int have_uid = 0;
    seed(&u);
    ASSERT_EQ_INT(0, decode_str(
        "{\"Nonsense\":{\"deep\":[1,2,3]},\"UpCredit\":9,\"Later\":\"x\"}",
        &u, &fields, &have_uid));
    ASSERT_EQ_INT(CLOAK_USER_FIELD_UP_CREDIT, fields);
    ASSERT_EQ_INT(9, u.up_credit);
    ASSERT_EQ_INT(0, have_uid);
}

static void test_field_names_are_case_sensitive(void) {
    cloak_user_info_t u;
    uint32_t fields = 0xFFFFFFFFu;
    int have_uid = 7;
    seed(&u);
    /* Go's encoding/json would bind these; this codec must not, and the
     * proof is that the mask comes back EMPTY rather than partly set. */
    ASSERT_EQ_INT(0, decode_str("{\"upcredit\":9,\"uid\":\"" UID_B64 "\"}",
                                &u, &fields, &have_uid));
    ASSERT_EQ_INT(0, fields);
    ASSERT_EQ_INT(0, have_uid);
    assert_all_sentinel(&u);
}

/* ---------------------------------------------------------------- */
/* 5 & 6. The UID                                                   */
/* ---------------------------------------------------------------- */

static void test_uid_cases(void) {
    cloak_user_info_t u;
    uint32_t fields = 0;
    int have_uid = 0;

    /* Good. */
    seed(&u);
    ASSERT_EQ_INT(0, decode_str("{\"UID\":\"" UID_B64 "\"}", &u, &fields,
                                &have_uid));
    ASSERT_EQ_INT(1, have_uid);
    ASSERT_MEM_EQ(u.uid, kUID, sizeof(kUID));
    ASSERT_EQ_INT(0, fields);

    /* Explicit null: absent, not an error. */
    seed(&u);
    have_uid = 9;
    ASSERT_EQ_INT(0, decode_str("{\"UID\":null}", &u, &fields, &have_uid));
    ASSERT_EQ_INT(0, have_uid);
    assert_all_sentinel(&u);

    /* 15 bytes: one short. This is the case the user-manager branch
     * learned the hard way -- a length that looks right in characters is
     * not a length in bytes -- so both sides of 16 are pinned. */
    expect_reject("uid 15 bytes", "{\"UID\":\"EBESExQVFhcYGRobHB0e\"}",
                  CLOAK_USER_JSON_ERR_UID);
    /* 17 bytes: one long. */
    expect_reject("uid 17 bytes",
                  "{\"UID\":\"EBESExQVFhcYGRobHB0eHyA=\"}",
                  CLOAK_USER_JSON_ERR_UID);
    /* 0 bytes. */
    expect_reject("uid empty", "{\"UID\":\"\"}", CLOAK_USER_JSON_ERR_UID);
    /* Not base64 at all. */
    expect_reject("uid not base64", "{\"UID\":\"not base64 at all!!\"}",
                  CLOAK_USER_JSON_ERR_UID);
    /* URL-safe alphabet in the BODY, where standard is required. The two
     * alphabets meet in one request and this is the seam. */
    expect_reject("uid url-safe alphabet",
                  "{\"UID\":\"-_-_-_-_-_-_-_-_-_-_-A==\"}",
                  CLOAK_USER_JSON_ERR_UID);
    /* Right length, wrong type. */
    expect_reject("uid number", "{\"UID\":16}", CLOAK_USER_JSON_ERR_TYPE);
    expect_reject("uid array", "{\"UID\":[1,2,3]}", CLOAK_USER_JSON_ERR_TYPE);
}

/* A standard-base64 string whose decoded length is exactly 16 is the
 * only accepted length -- prove the boundary is a boundary by walking
 * every decoded length from 0 to 24. */
static void test_uid_length_boundary_is_exact(void) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n;
    for (n = 0; n <= 24; n++) {
        uint8_t raw[24];
        char b64[64];
        char doc[128];
        size_t i, j = 0;
        cloak_user_info_t u;
        uint32_t fields = 0;
        int have_uid = 0;
        int rc;

        for (i = 0; i < n; i++) {
            raw[i] = (uint8_t)(0x10 + i);
        }
        /* Hand-rolled standard base64 so this test does not depend on
         * the same encoder the implementation uses. */
        for (i = 0; i + 3 <= n; i += 3) {
            uint32_t v = ((uint32_t)raw[i] << 16) | ((uint32_t)raw[i + 1] << 8) |
                         raw[i + 2];
            b64[j++] = alphabet[(v >> 18) & 63];
            b64[j++] = alphabet[(v >> 12) & 63];
            b64[j++] = alphabet[(v >> 6) & 63];
            b64[j++] = alphabet[v & 63];
        }
        if (n - i == 1) {
            uint32_t v = (uint32_t)raw[i] << 16;
            b64[j++] = alphabet[(v >> 18) & 63];
            b64[j++] = alphabet[(v >> 12) & 63];
            b64[j++] = '=';
            b64[j++] = '=';
        } else if (n - i == 2) {
            uint32_t v = ((uint32_t)raw[i] << 16) | ((uint32_t)raw[i + 1] << 8);
            b64[j++] = alphabet[(v >> 18) & 63];
            b64[j++] = alphabet[(v >> 12) & 63];
            b64[j++] = alphabet[(v >> 6) & 63];
            b64[j++] = '=';
        }
        b64[j] = '\0';

        snprintf(doc, sizeof(doc), "{\"UID\":\"%s\"}", b64);
        seed(&u);
        rc = decode_str(doc, &u, &fields, &have_uid);
        if (n == CLOAK_UID_LEN) {
            ASSERT_EQ_INT(0, rc);
            ASSERT_EQ_INT(1, have_uid);
            ASSERT_MEM_EQ(u.uid, raw, CLOAK_UID_LEN);
        } else if (rc != CLOAK_USER_JSON_ERR_UID) {
            fprintf(stderr, "FAIL uid of %zu bytes -> %d, want %d\n", n, rc,
                    CLOAK_USER_JSON_ERR_UID);
            cloak_test_failures++;
        }
    }
}

/* The body's UID is base64 STANDARD, because Go's encoding/json marshals
 * a []byte with StdEncoding -- while the very same UID travels URL-SAFE
 * in the request path. One request, two alphabets. */
static void test_uid_alphabet_is_standard_not_url_safe(void) {
    cloak_user_info_t u;
    char out[CLOAK_USER_JSON_MAX];
    uint32_t fields = 0;
    int have_uid = 0;

    full_user(&u);
    memcpy(u.uid, kAlphaUID, sizeof(kAlphaUID));
    ASSERT_EQ_INT(0, cloak_user_json_encode(&u, 0, out, sizeof(out), NULL));
    ASSERT_TRUE(strstr(out, "\"UID\":\"" ALPHA_UID_STD "\"") != NULL);
    ASSERT_TRUE(strstr(out, ALPHA_UID_URL) == NULL);
    if (strstr(out, "\"UID\":\"" ALPHA_UID_STD "\"") == NULL) {
        fprintf(stderr, "  got: %s\n", out);
    }

    /* And the decoder takes the standard form... */
    seed(&u);
    ASSERT_EQ_INT(0, decode_str("{\"UID\":\"" ALPHA_UID_STD "\"}", &u,
                                &fields, &have_uid));
    ASSERT_EQ_INT(1, have_uid);
    ASSERT_MEM_EQ(u.uid, kAlphaUID, sizeof(kAlphaUID));

    /* ...and refuses the URL-safe one, which is the same 16 bytes spelled
     * in the path's alphabet. Accepting both would make the seam between
     * them invisible. */
    expect_reject("url-safe uid in the body", "{\"UID\":\"" ALPHA_UID_URL "\"}",
                  CLOAK_USER_JSON_ERR_UID);
}

/* ---------------------------------------------------------------- */
/* 7. Numbers                                                       */
/* ---------------------------------------------------------------- */

static void accept_number(const char *json, int64_t want) {
    cloak_user_info_t u;
    uint32_t fields = 0;
    int have_uid = 0;
    int rc;
    seed(&u);
    rc = decode_str(json, &u, &fields, &have_uid);
    if (rc != 0) {
        fprintf(stderr, "FAIL accept %s -> %d\n", json, rc);
        cloak_test_failures++;
        return;
    }
    ASSERT_EQ_INT(CLOAK_USER_FIELD_UP_CREDIT, fields);
    ASSERT_EQ_INT(want, u.up_credit);
}

static void test_number_boundary_from_both_sides(void) {
    /* 2^53 - 1 is the largest integer a double carries UNAMBIGUOUSLY:
     * 2^53 itself is representable, but so is nothing between it and
     * 2^53 + 2, so the token 9007199254740993 rounds onto 2^53 and the
     * two become indistinguishable after the parse. Accepting 2^53 would
     * therefore mean silently accepting 2^53 + 1 as 2^53. Both sides of
     * the bound are pinned, in both signs, or the bound could sit
     * anywhere. */
    accept_number("{\"UpCredit\":9007199254740991}", 9007199254740991LL);
    accept_number("{\"UpCredit\":-9007199254740991}", -9007199254740991LL);
    accept_number("{\"UpCredit\":9007199254740990}", 9007199254740990LL);

    expect_reject("2^53", "{\"UpCredit\":9007199254740992}",
                  CLOAK_USER_JSON_ERR_RANGE);
    expect_reject("-2^53", "{\"UpCredit\":-9007199254740992}",
                  CLOAK_USER_JSON_ERR_RANGE);
    /* The token that rounds ONTO 2^53. If the bound were >= 2^53 this
     * would come back as 9007199254740992, a silent truncation of an
     * attacker-supplied number. */
    expect_reject("2^53+1", "{\"UpCredit\":9007199254740993}",
                  CLOAK_USER_JSON_ERR_RANGE);
    expect_reject("-2^53-1", "{\"UpCredit\":-9007199254740993}",
                  CLOAK_USER_JSON_ERR_RANGE);
    expect_reject("int64 max", "{\"UpCredit\":9223372036854775807}",
                  CLOAK_USER_JSON_ERR_RANGE);
    expect_reject("int64 min", "{\"UpCredit\":-9223372036854775808}",
                  CLOAK_USER_JSON_ERR_RANGE);
}

static void test_number_shapes_rejected(void) {
    expect_reject("1e300", "{\"UpCredit\":1e300}", CLOAK_USER_JSON_ERR_RANGE);
    expect_reject("1e999 (infinity)", "{\"UpCredit\":1e999}",
                  CLOAK_USER_JSON_ERR_RANGE);
    expect_reject("-1e999", "{\"UpCredit\":-1e999}",
                  CLOAK_USER_JSON_ERR_RANGE);
    expect_reject("1.5", "{\"UpCredit\":1.5}",
                  CLOAK_USER_JSON_ERR_NOT_INTEGER);
    expect_reject("-0.5", "{\"UpCredit\":-0.5}",
                  CLOAK_USER_JSON_ERR_NOT_INTEGER);
    /* A fractional part that only shows up at full precision. */
    expect_reject("0.000001", "{\"UpCredit\":0.000001}",
                  CLOAK_USER_JSON_ERR_NOT_INTEGER);
    expect_reject("string", "{\"UpCredit\":\"123\"}",
                  CLOAK_USER_JSON_ERR_TYPE);
    expect_reject("true", "{\"UpCredit\":true}", CLOAK_USER_JSON_ERR_TYPE);
    expect_reject("false", "{\"UpCredit\":false}", CLOAK_USER_JSON_ERR_TYPE);
    expect_reject("object", "{\"UpCredit\":{\"a\":1}}",
                  CLOAK_USER_JSON_ERR_TYPE);
    expect_reject("array", "{\"UpCredit\":[1]}", CLOAK_USER_JSON_ERR_TYPE);

    /* Exponential and .0 forms ARE integers and are accepted -- JSON
     * says 1e3 and 1000 are the same number, and a client that formats
     * that way is not malformed. */
    accept_number("{\"UpCredit\":1e3}", 1000);
    accept_number("{\"UpCredit\":1000.0}", 1000);
    accept_number("{\"UpCredit\":-0}", 0);
}

/* SessionsCap is an int32 in both Go (MaybeInt32 = *int32) and here, so
 * its bound is int32's, not 2^53's -- and a cast of 2^31 into an int32_t
 * is implementation-defined, which is exactly why this is checked rather
 * than truncated. */
static void test_sessions_cap_is_int32(void) {
    cloak_user_info_t u;
    uint32_t fields = 0;
    int have_uid = 0;

    seed(&u);
    ASSERT_EQ_INT(0, decode_str("{\"SessionsCap\":2147483647}", &u, &fields,
                                &have_uid));
    ASSERT_EQ_INT(2147483647, u.sessions_cap);
    seed(&u);
    ASSERT_EQ_INT(0, decode_str("{\"SessionsCap\":-2147483648}", &u, &fields,
                                &have_uid));
    ASSERT_EQ_INT(-2147483648LL, u.sessions_cap);

    expect_reject("cap 2^31", "{\"SessionsCap\":2147483648}",
                  CLOAK_USER_JSON_ERR_RANGE);
    expect_reject("cap -2^31-1", "{\"SessionsCap\":-2147483649}",
                  CLOAK_USER_JSON_ERR_RANGE);
    /* Well inside 2^53 but outside int32: proves the cap uses its own
     * bound rather than borrowing the 64-bit one. */
    expect_reject("cap 10^12", "{\"SessionsCap\":1000000000000}",
                  CLOAK_USER_JSON_ERR_RANGE);
}

/* ---------------------------------------------------------------- */
/* 8. Large integers print as integers, not as 1e+12                */
/* ---------------------------------------------------------------- */

static void encode_one(int64_t credit, char *out, size_t cap) {
    cloak_user_info_t u;
    full_user(&u);
    u.up_credit = credit;
    ASSERT_EQ_INT(0, cloak_user_json_encode(&u, CLOAK_USER_FIELD_UP_CREDIT,
                                            out, cap, NULL));
}

static void test_large_integers_are_literal(void) {
    char out[CLOAK_USER_JSON_MAX];

    /* One terabyte of quota. cJSON_CreateNumber would emit 1e+12 here
     * (10^12 exceeds INT_MAX, so its valueint != valuedouble fallback
     * takes the %g path) and a real Go client's json.Unmarshal into an
     * *int64 rejects that outright. */
    encode_one(1000000000000LL, out, sizeof(out));
    ASSERT_TRUE(strstr(out, "\"UpCredit\":1000000000000,") != NULL);
    ASSERT_TRUE(strstr(out, "e+") == NULL);
    ASSERT_TRUE(strstr(out, "E+") == NULL);
    if (strstr(out, "\"UpCredit\":1000000000000,") == NULL) {
        fprintf(stderr, "  got: %s\n", out);
    }

    /* Just over INT_MAX, the exact point cJSON's %d fallback stops. */
    encode_one(2147483648LL, out, sizeof(out));
    ASSERT_TRUE(strstr(out, "\"UpCredit\":2147483648,") != NULL);

    /* The encoder carries the WHOLE int64 range even though the decoder
     * will not take it back: a row sitting at the credit saturation's
     * resting place has to be reportable to the operator. This asymmetry
     * is documented in user_json.h and pinned here so it is a decision
     * rather than a surprise. */
    encode_one(-9223372036854775807LL - 1, out, sizeof(out));
    ASSERT_TRUE(strstr(out, "\"UpCredit\":-9223372036854775808,") != NULL);
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_RANGE,
                  reject("{\"UpCredit\":-9223372036854775808}"));

    encode_one(9223372036854775807LL, out, sizeof(out));
    ASSERT_TRUE(strstr(out, "\"UpCredit\":9223372036854775807,") != NULL);
}

/* CLOAK_USER_JSON_MAX must actually cover the worst case, and one byte
 * less must actually fail -- otherwise the constant could be anything. */
static void test_worst_case_fits_the_documented_buffer(void) {
    cloak_user_info_t u;
    char out[CLOAK_USER_JSON_MAX * 2];
    char sentinel[CLOAK_USER_JSON_MAX * 2];
    size_t len = 0;

    memcpy(u.uid, kUID, sizeof(kUID));
    u.sessions_cap = -2147483647 - 1;
    u.up_rate = -9223372036854775807LL - 1;
    u.down_rate = -9223372036854775807LL - 1;
    u.up_credit = -9223372036854775807LL - 1;
    u.down_credit = -9223372036854775807LL - 1;
    u.expiry_time = -9223372036854775807LL - 1;

    ASSERT_EQ_INT(0, cloak_user_json_encode(&u, CLOAK_USER_FIELD_ALL, out,
                                            sizeof(out), &len));
    ASSERT_TRUE(len + 1 <= CLOAK_USER_JSON_MAX);
    if (len + 1 > CLOAK_USER_JSON_MAX) {
        fprintf(stderr, "  worst case is %zu+1 bytes, CLOAK_USER_JSON_MAX=%d\n",
                len, (int)CLOAK_USER_JSON_MAX);
    }

    /* Exactly enough succeeds; one byte less is ARG and writes nothing. */
    ASSERT_EQ_INT(0, cloak_user_json_encode(&u, CLOAK_USER_FIELD_ALL, out,
                                            len + 1, NULL));
    memset(out, 0x7f, sizeof(out));
    memset(sentinel, 0x7f, sizeof(sentinel));
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_ARG,
                  cloak_user_json_encode(&u, CLOAK_USER_FIELD_ALL, out, len,
                                         NULL));
    ASSERT_MEM_EQ(out, sentinel, sizeof(out));
}

/* ---------------------------------------------------------------- */
/* 9. Documents that are not user objects                           */
/* ---------------------------------------------------------------- */

static void test_malformed_documents(void) {
    expect_reject("empty", "", CLOAK_USER_JSON_ERR_SYNTAX);
    expect_reject("whitespace only", "   \t\n ", CLOAK_USER_JSON_ERR_SYNTAX);
    expect_reject("unterminated", "{\"UpCredit\": ",
                  CLOAK_USER_JSON_ERR_SYNTAX);
    expect_reject("garbage", "not json", CLOAK_USER_JSON_ERR_SYNTAX);
    expect_reject("trailing garbage", "{\"UpCredit\":1}trailing",
                  CLOAK_USER_JSON_ERR_SYNTAX);
    expect_reject("two documents", "{\"UpCredit\":1}{\"UpCredit\":2}",
                  CLOAK_USER_JSON_ERR_SYNTAX);
    expect_reject("bare array", "[]", CLOAK_USER_JSON_ERR_NOT_OBJECT);
    expect_reject("array of users", "[{\"UpCredit\":1}]",
                  CLOAK_USER_JSON_ERR_NOT_OBJECT);
    expect_reject("bare string", "\"UpCredit\"",
                  CLOAK_USER_JSON_ERR_NOT_OBJECT);
    expect_reject("bare number", "1", CLOAK_USER_JSON_ERR_NOT_OBJECT);
    expect_reject("bare null", "null", CLOAK_USER_JSON_ERR_NOT_OBJECT);
    expect_reject("bare true", "true", CLOAK_USER_JSON_ERR_NOT_OBJECT);

    /* Trailing whitespace is NOT garbage. */
    {
        cloak_user_info_t u;
        uint32_t fields = 0;
        int have_uid = 0;
        seed(&u);
        ASSERT_EQ_INT(0, decode_str(" \r\n\t{\"UpCredit\":1} \r\n\t", &u,
                                    &fields, &have_uid));
        ASSERT_EQ_INT(CLOAK_USER_FIELD_UP_CREDIT, fields);
    }
}

/* A document that is good right up to its last field applies NONE of it.
 * Every rejection case in this file runs through reject(), which pins
 * all seven fields at their sentinels -- these two exist so that at
 * least one rejection is reached AFTER a UID and a number have already
 * been successfully parsed into the working copy, which is the only
 * arrangement in which a commit-as-you-go implementation would differ
 * from a commit-at-the-end one. */
static void test_failure_applies_nothing(void) {
    expect_reject("good uid, then a bad number",
                  "{\"UID\":\"" UID_B64 "\",\"UpCredit\":1e300}",
                  CLOAK_USER_JSON_ERR_RANGE);
    expect_reject("good number, then a bad one",
                  "{\"UpRate\":5,\"DownRate\":1e300}",
                  CLOAK_USER_JSON_ERR_RANGE);
    expect_reject("good uid and numbers, then a bad uid... in a duplicate",
                  "{\"UpRate\":5,\"UID\":\"" UID_B64 "\",\"UpRate\":6}",
                  CLOAK_USER_JSON_ERR_DUPLICATE);
}

static void test_embedded_nul_is_rejected(void) {
    static const char doc[] = "{\"UpCredit\":1}\0{\"UpCredit\":2}";
    cloak_user_info_t u;
    uint32_t fields = 0xFFFFFFFFu;
    int have_uid = 42;
    seed(&u);
    /* sizeof - 1 so the trailing NUL of the literal is excluded but the
     * embedded one is included. A parser that stopped at the NUL would
     * accept this and silently drop the second half. */
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_SYNTAX,
                  cloak_user_json_decode((const uint8_t *)doc,
                                         sizeof(doc) - 1, &u, &fields,
                                         &have_uid));
    assert_all_sentinel(&u);
    ASSERT_EQ_INT(0xFFFFFFFFu, fields);

    /* A NUL as the very last byte is equally not a terminator. */
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_SYNTAX,
                  cloak_user_json_decode((const uint8_t *)"{}\0", 3, &u,
                                         &fields, &have_uid));
}

static void test_duplicate_fields_are_rejected(void) {
    expect_reject("duplicate UpCredit",
                  "{\"UpCredit\":1,\"UpCredit\":999999999}",
                  CLOAK_USER_JSON_ERR_DUPLICATE);
    expect_reject("duplicate UID",
                  "{\"UID\":\"" UID_B64 "\",\"UID\":\"" UID_B64 "\"}",
                  CLOAK_USER_JSON_ERR_DUPLICATE);
    /* Even when the second one is null, because "last wins" and "first
     * wins" disagree about the result and nothing legitimate emits it. */
    expect_reject("duplicate with null",
                  "{\"UpCredit\":1,\"UpCredit\":null}",
                  CLOAK_USER_JSON_ERR_DUPLICATE);
    /* A repeated UNKNOWN field is not our business. */
    {
        cloak_user_info_t u;
        uint32_t fields = 0;
        int have_uid = 0;
        seed(&u);
        ASSERT_EQ_INT(0, decode_str("{\"X\":1,\"X\":2,\"UpCredit\":3}", &u,
                                    &fields, &have_uid));
        ASSERT_EQ_INT(CLOAK_USER_FIELD_UP_CREDIT, fields);
        ASSERT_EQ_INT(3, u.up_credit);
    }
}

/* cJSON's recursive descent is bounded by CJSON_NESTING_LIMIT (1000 in
 * the vendored build), which 64 KiB of '[' reaches easily. The point of
 * this case is that the depth is refused rather than crashed on. */
static void test_deep_nesting_is_rejected(void) {
    const int depth = 3000;
    size_t cap = (size_t)depth * 2 + 32;
    char *doc = (char *)malloc(cap);
    int i;
    size_t n = 0;
    if (doc == NULL) {
        abort();
    }

    /* Nested arrays at the top level. */
    for (i = 0; i < depth; i++) {
        doc[n++] = '[';
    }
    for (i = 0; i < depth; i++) {
        doc[n++] = ']';
    }
    doc[n] = '\0';
    expect_reject("deep arrays", doc, CLOAK_USER_JSON_ERR_SYNTAX);

    /* And nested inside a recognised field's value, where the type check
     * would otherwise be what refuses it. */
    n = 0;
    n += (size_t)snprintf(doc + n, cap - n, "{\"UpCredit\":");
    for (i = 0; i < depth; i++) {
        doc[n++] = '[';
    }
    for (i = 0; i < depth; i++) {
        doc[n++] = ']';
    }
    doc[n++] = '}';
    doc[n] = '\0';
    expect_reject("deep value", doc, CLOAK_USER_JSON_ERR_SYNTAX);

    free(doc);
}

static void test_argument_errors(void) {
    cloak_user_info_t u;
    uint32_t fields = 0;
    int have_uid = 0;
    seed(&u);
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_ARG,
                  cloak_user_json_decode((const uint8_t *)"{}", 2, NULL,
                                         &fields, &have_uid));
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_ARG,
                  cloak_user_json_decode((const uint8_t *)"{}", 2, &u, NULL,
                                         &have_uid));
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_ARG,
                  cloak_user_json_decode((const uint8_t *)"{}", 2, &u,
                                         &fields, NULL));
    /* NULL body with a non-zero length is a caller bug, not a parse. */
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_ARG,
                  cloak_user_json_decode(NULL, 4, &u, &fields, &have_uid));
    /* NULL body with zero length is simply an empty document. */
    ASSERT_EQ_INT(CLOAK_USER_JSON_ERR_SYNTAX,
                  cloak_user_json_decode(NULL, 0, &u, &fields, &have_uid));
    assert_all_sentinel(&u);
}

/* 10. A smoke fuzz over mutations of the golden document. The value here
 * is entirely in what ASan says about the allocations the failure paths
 * leave behind; the decoder's answer is unconstrained. */
static uint32_t rng_state = 0x13579bdfu;
static uint32_t rng_next(void) {
    rng_state = rng_state * 1664525u + 1013904223u;
    return rng_state >> 8;
}

static void test_fuzz_smoke(void) {
    int iter;
    for (iter = 0; iter < 4000; iter++) {
        char mut[sizeof(kGolden)];
        cloak_user_info_t u;
        uint32_t fields = 0;
        int have_uid = 0;
        int k;

        memcpy(mut, kGolden, sizeof(kGolden));
        for (k = 0; k < 1 + (int)(rng_next() % 4); k++) {
            size_t pos = (size_t)(rng_next() % (sizeof(kGolden) - 1));
            mut[pos] = (char)(rng_next() & 0x7f);
        }
        seed(&u);
        (void)cloak_user_json_decode((const uint8_t *)mut, sizeof(kGolden) - 1,
                                     &u, &fields, &have_uid);
    }
}

TEST_MAIN_BEGIN()
    test_encode_exact_bytes();
    test_encode_null_for_unset_fields();
    test_encode_rejects_unknown_mask_bits();
    test_round_trip_is_stable();
    test_absent_and_null_clear_the_bit();
    test_all_absent_is_an_empty_mask();
    test_unknown_fields_are_ignored();
    test_field_names_are_case_sensitive();
    test_uid_cases();
    test_uid_length_boundary_is_exact();
    test_uid_alphabet_is_standard_not_url_safe();
    test_number_boundary_from_both_sides();
    test_number_shapes_rejected();
    test_sessions_cap_is_int32();
    test_large_integers_are_literal();
    test_worst_case_fits_the_documented_buffer();
    test_malformed_documents();
    test_failure_applies_nothing();
    test_embedded_nul_is_rejected();
    test_duplicate_fields_are_rejected();
    test_deep_nesting_is_rejected();
    test_argument_errors();
    test_fuzz_smoke();
TEST_MAIN_END()
