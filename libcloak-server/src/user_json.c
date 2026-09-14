#define _POSIX_C_SOURCE 200809L

#include "cloak/user_json.h"

#include "cJSON.h"
#include "cloak/base64.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The field names, verbatim from Go's UserInfo struct, IN ITS
 * DECLARATION ORDER. This one array is what makes both directions agree:
 * the encoder inserts in this order (so cJSON_PrintUnformatted emits it,
 * and the byte-exact assertion in the tests means something), and the
 * decoder scans for exactly these spellings. Adding a field means adding
 * it here and in both switches below, and the compiler will not remind
 * you -- which is why the test asserts the whole string rather than
 * field by field. */
#define F_UID          0
#define F_SESSIONS_CAP 1
#define F_UP_RATE      2
#define F_DOWN_RATE    3
#define F_UP_CREDIT    4
#define F_DOWN_CREDIT  5
#define F_EXPIRY_TIME  6
#define F_COUNT        7

static const char *const kNames[F_COUNT] = {
    "UID", "SessionsCap", "UpRate", "DownRate",
    "UpCredit", "DownCredit", "ExpiryTime"
};

/* The mask bit each numeric slot carries. F_UID has none -- the UID is
 * not part of cloak_usermanager_write's mask -- and is reported through
 * out_have_uid instead. */
static const uint32_t kBits[F_COUNT] = {
    0,
    CLOAK_USER_FIELD_SESSIONS_CAP,
    CLOAK_USER_FIELD_UP_RATE,
    CLOAK_USER_FIELD_DOWN_RATE,
    CLOAK_USER_FIELD_UP_CREDIT,
    CLOAK_USER_FIELD_DOWN_CREDIT,
    CLOAK_USER_FIELD_EXPIRY_TIME
};

/* ------------------------------------------------------------------ */
/* Encode                                                              */
/* ------------------------------------------------------------------ */

/* Adds one numeric field as either a RAW integer token we formatted
 * ourselves or a JSON null.
 *
 * cJSON_CreateRaw, not cJSON_CreateNumber, and this is the single most
 * important line in the file. cJSON keeps a number as a double plus a
 * deprecated `int valueint`, and print_number emits "%d" of valueint
 * ONLY when the double compares equal to it; otherwise it falls back to
 * "%1.15g". So an ordinary one-terabyte credit -- 10^12, comfortably
 * above INT_MAX -- would print as "1e+12", and a real Go client's
 * json.Unmarshal into an *int64 refuses that outright ("cannot unmarshal
 * number 1e+12 into Go value of type int64"). Formatting the integer
 * here and handing cJSON the finished token sidesteps the double
 * entirely: what we print is what we were given, for every value an
 * int64 can hold.
 *
 * Returns 0, or -1 on an allocation failure (the item is deleted rather
 * than leaked -- cJSON_AddItemToObject takes ownership only when it
 * succeeds). */
static int add_number_or_null(cJSON *root, const char *name, uint32_t fields,
                              uint32_t bit, int64_t value) {
    cJSON *item;

    if ((fields & bit) != 0) {
        /* 20 digits and a sign for INT64_MIN, plus the NUL. */
        char raw[32];
        int n = snprintf(raw, sizeof(raw), "%" PRId64, value);
        if (n < 0 || (size_t)n >= sizeof(raw)) {
            return -1;
        }
        item = cJSON_CreateRaw(raw);
    } else {
        item = cJSON_CreateNull();
    }
    if (item == NULL) {
        return -1;
    }
    if (!cJSON_AddItemToObject(root, name, item)) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

int cloak_user_json_encode(const cloak_user_info_t *info, uint32_t fields,
                           char *out, size_t out_cap, size_t *out_len) {
    char uid_b64[25]; /* 16 bytes -> 24 chars + NUL */
    cJSON *root = NULL;
    cJSON *uid_item = NULL;
    char *text = NULL;
    size_t len;
    int rc = CLOAK_USER_JSON_ERR_MEMORY;

    if (info == NULL || out == NULL) {
        return CLOAK_USER_JSON_ERR_ARG;
    }
    if ((fields & ~(uint32_t)CLOAK_USER_FIELD_ALL) != 0) {
        return CLOAK_USER_JSON_ERR_ARG;
    }

    /* STANDARD alphabet, not URL-safe: Go's encoding/json marshals a
     * []byte with base64.StdEncoding, and the URL-safe form belongs to
     * the request PATH of the same request. See cloak/base64.h. */
    if (cloak_base64_encode(info->uid, CLOAK_UID_LEN, uid_b64,
                            sizeof(uid_b64)) != 0) {
        return CLOAK_USER_JSON_ERR_MEMORY; /* unreachable: the size is fixed */
    }

    root = cJSON_CreateObject();
    if (root == NULL) {
        return CLOAK_USER_JSON_ERR_MEMORY;
    }

    uid_item = cJSON_CreateString(uid_b64);
    if (uid_item == NULL) {
        goto done;
    }
    if (!cJSON_AddItemToObject(root, kNames[F_UID], uid_item)) {
        cJSON_Delete(uid_item);
        goto done;
    }

    /* Go's struct order. Insertion order IS output order for
     * cJSON_PrintUnformatted, which is why this sequence is spelled out
     * rather than looped over an array of offsets: the order is the
     * contract, and it should be readable as one. */
    if (add_number_or_null(root, kNames[F_SESSIONS_CAP], fields,
                           CLOAK_USER_FIELD_SESSIONS_CAP,
                           info->sessions_cap) != 0 ||
        add_number_or_null(root, kNames[F_UP_RATE], fields,
                           CLOAK_USER_FIELD_UP_RATE, info->up_rate) != 0 ||
        add_number_or_null(root, kNames[F_DOWN_RATE], fields,
                           CLOAK_USER_FIELD_DOWN_RATE, info->down_rate) != 0 ||
        add_number_or_null(root, kNames[F_UP_CREDIT], fields,
                           CLOAK_USER_FIELD_UP_CREDIT, info->up_credit) != 0 ||
        add_number_or_null(root, kNames[F_DOWN_CREDIT], fields,
                           CLOAK_USER_FIELD_DOWN_CREDIT,
                           info->down_credit) != 0 ||
        add_number_or_null(root, kNames[F_EXPIRY_TIME], fields,
                           CLOAK_USER_FIELD_EXPIRY_TIME,
                           info->expiry_time) != 0) {
        goto done;
    }

    text = cJSON_PrintUnformatted(root);
    if (text == NULL) {
        goto done;
    }

    len = strlen(text);
    if (len + 1 > out_cap) {
        /* A caller buffer too small is a caller bug, not an OOM, and out
         * stays untouched so a caller that ignores the return code
         * cannot ship a truncated reply. CLOAK_USER_JSON_MAX makes this
         * unreachable. */
        rc = CLOAK_USER_JSON_ERR_ARG;
        goto done;
    }
    memcpy(out, text, len + 1);
    if (out_len != NULL) {
        *out_len = len;
    }
    rc = 0;

done:
    if (text != NULL) {
        cJSON_free(text);
    }
    cJSON_Delete(root);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Decode                                                              */
/* ------------------------------------------------------------------ */

/* Turns one cJSON number into an int64, or says exactly why it will not.
 *
 * THE ORDER OF THESE CHECKS IS THE CONTRACT, because each one is only
 * sound once the previous has passed:
 *
 *   1. It must be a number at all (_TYPE).
 *   2. Its magnitude must be at most 2^53 - 1 (_RANGE). This is the
 *      cJSON-imposed bound explained at length in user_json.h -- the
 *      parse keeps only a double, and 2^53 - 1 is the largest integer a
 *      double carries unambiguously.
 *   3. It must have no fractional part (_NOT_INTEGER). This comes AFTER
 *      the magnitude test, not before, because the cast it relies on is
 *      only defined once the value is known to fit: (int64_t)1e300 is
 *      undefined behaviour, not a large number. Once the magnitude is
 *      under 2^53 the round trip through int64_t is exact, so this is a
 *      true equality test and not an epsilon.
 *
 * STEP 2 IS WRITTEN AS A NEGATED IN-RANGE TEST, `!(d >= -MAX && d <=
 * MAX)`, and not as the more obvious `d > MAX || d < -MAX`. The two
 * differ on exactly one input: a NaN, which compares false against
 * everything and so passes the obvious form straight into the undefined
 * cast below. Writing it this way means NaN and both infinities are
 * refused by the SAME line that enforces the bound, instead of by a
 * separate isfinite() guard that no test could ever reach -- cJSON's
 * number scanner accepts only [0-9+-.eE], so no input it parses can
 * produce a NaN, and a guard nothing can exercise is not a defence, it
 * is decoration that outlives the assumption it was written under. Here
 * the line is exercised by every out-of-range test in the suite and is
 * NaN-safe as a property of its shape. */
static int number_to_int64(const cJSON *item, int64_t *out) {
    double d;
    int64_t v;

    if (!cJSON_IsNumber(item)) {
        return CLOAK_USER_JSON_ERR_TYPE;
    }
    d = cJSON_GetNumberValue(item);
    if (!(d >= -(double)CLOAK_USER_JSON_MAX_SAFE_INT &&
          d <= (double)CLOAK_USER_JSON_MAX_SAFE_INT)) {
        return CLOAK_USER_JSON_ERR_RANGE;
    }
    v = (int64_t)d;
    if ((double)v != d) {
        return CLOAK_USER_JSON_ERR_NOT_INTEGER;
    }
    *out = v;
    return 0;
}

/* The UID, standard-alphabet base64, decoding to exactly CLOAK_UID_LEN
 * bytes.
 *
 * THE LENGTH IS CHECKED HERE AND NOT LEFT TO THE DATABASE, even though
 * the users table has a CHECK constraint that also enforces it. Two
 * reasons. The constraint reports a generic SQLite failure, so an
 * operator who mistyped a UID would be sent looking for a disk problem;
 * and CREATE TABLE IF NOT EXISTS does not add a constraint to a database
 * an older build already created, so the constraint is not a guarantee
 * this layer can lean on. The user-manager branch spent a round
 * discovering that a 16-CHARACTER value is not a 16-BYTE one; this is
 * the byte test, at the edge, where the bytes arrive. */
static int decode_uid(const cJSON *item, uint8_t out[CLOAK_UID_LEN]) {
    /* THE DECODED LENGTH IS THE ONLY TEST, deliberately. An obvious
     * "reject anything that is not 24 characters" pre-check would be
     * correct -- 24 is the only encoded length that can yield 16 bytes
     * -- and it would also be poison, because it makes the SHORT half of
     * the length test below unreachable: with it in place no input can
     * ever arrive here having decoded to fewer than 16 bytes, and a
     * mutation that changed `!=` into `>` would pass the whole suite.
     * The cheap guard would have hidden the real one. There is nothing
     * to buy with it either: cloak_base64_decode is bounded by the
     * out_cap below and gives up at the first quantum that would exceed
     * it, so even a 64 KiB string costs a few quanta.
     *
     * buf is sized for the most 24 base64 characters can produce, which
     * is 18 bytes; anything longer is refused by cloak_base64_decode on
     * capacity, and anything shorter by the length test. */
    uint8_t buf[18];
    const char *s;
    size_t n = 0;

    if (!cJSON_IsString(item)) {
        return CLOAK_USER_JSON_ERR_TYPE;
    }
    s = cJSON_GetStringValue(item);
    if (s == NULL) {
        return CLOAK_USER_JSON_ERR_UID;
    }
    if (cloak_base64_decode(s, buf, sizeof(buf), &n) != 0) {
        return CLOAK_USER_JSON_ERR_UID;
    }
    if (n != CLOAK_UID_LEN) {
        return CLOAK_USER_JSON_ERR_UID;
    }
    memcpy(out, buf, CLOAK_UID_LEN);
    return 0;
}

int cloak_user_json_decode(const uint8_t *body, size_t body_len,
                           cloak_user_info_t *io_info, uint32_t *out_fields,
                           int *out_have_uid) {
    const cJSON *found[F_COUNT];
    cloak_user_info_t local;
    cJSON *root = NULL;
    char *copy = NULL;
    const cJSON *child;
    uint32_t fields = 0;
    int have_uid = 0;
    int rc = 0;
    int i;

    if (io_info == NULL || out_fields == NULL || out_have_uid == NULL) {
        return CLOAK_USER_JSON_ERR_ARG;
    }
    if (body == NULL && body_len > 0) {
        return CLOAK_USER_JSON_ERR_ARG;
    }
    if (body_len == 0) {
        return CLOAK_USER_JSON_ERR_SYNTAX;
    }
    /* A NUL anywhere is refused BEFORE the parse. JSON has no use for
     * one, and it is the classic way to make two readers disagree about
     * where a document ends: cJSON's own null-terminated check would see
     * the embedded NUL as the end and silently ignore everything after
     * it. */
    if (memchr(body, 0, body_len) != NULL) {
        return CLOAK_USER_JSON_ERR_SYNTAX;
    }

    /* Everything below works on a local copy and is committed to the
     * caller's struct only at the very end, so a document that fails on
     * its last field applies none of its earlier ones. */
    local = *io_info;
    for (i = 0; i < F_COUNT; i++) {
        found[i] = NULL;
    }

    /* cJSON needs a NUL-terminated buffer to be able to prove there is
     * no trailing garbage (require_null_terminated below); the body from
     * cloak_http_parser is not terminated. This is the module's only
     * allocation, and its size is bounded by the HTTP parser's
     * CLOAK_HTTP_MAX_BODY rather than by anything here -- see the
     * header. */
    copy = (char *)malloc(body_len + 1);
    if (copy == NULL) {
        return CLOAK_USER_JSON_ERR_MEMORY;
    }
    memcpy(copy, body, body_len);
    copy[body_len] = '\0';

    /* require_null_terminated = 1 is what makes "{}garbage" a syntax
     * error. Plain cJSON_Parse accepts it. */
    root = cJSON_ParseWithLengthOpts(copy, body_len + 1, NULL, 1);
    if (root == NULL) {
        rc = CLOAK_USER_JSON_ERR_SYNTAX;
        goto done;
    }
    if (!cJSON_IsObject(root)) {
        rc = CLOAK_USER_JSON_ERR_NOT_OBJECT;
        goto done;
    }

    /* One pass over the members, both to find the recognised ones and to
     * catch a repeat of any of them. cJSON's own lookup would return the
     * FIRST of a repeated key while Go's encoding/json takes the LAST,
     * and rather than own that differential on a body an attacker wrote,
     * the document is refused. Unrecognised names are ignored, matching
     * encoding/json's default, so a newer client is never refused for
     * saying more than this build understands. */
    for (child = root->child; child != NULL; child = child->next) {
        if (child->string == NULL) {
            continue;
        }
        for (i = 0; i < F_COUNT; i++) {
            if (strcmp(child->string, kNames[i]) == 0) {
                if (found[i] != NULL) {
                    rc = CLOAK_USER_JSON_ERR_DUPLICATE;
                    goto done;
                }
                found[i] = child;
                break;
            }
        }
    }

    /* An explicitly null field is exactly an absent one: Go's Maybe*
     * pointers marshal nil as null, and both mean "do not touch this". */
    for (i = 0; i < F_COUNT; i++) {
        if (found[i] != NULL && cJSON_IsNull(found[i])) {
            found[i] = NULL;
        }
    }

    if (found[F_UID] != NULL) {
        rc = decode_uid(found[F_UID], local.uid);
        if (rc != 0) {
            goto done;
        }
        have_uid = 1;
    }

    for (i = F_SESSIONS_CAP; i < F_COUNT; i++) {
        int64_t v = 0;
        if (found[i] == NULL) {
            continue;
        }
        rc = number_to_int64(found[i], &v);
        if (rc != 0) {
            goto done;
        }
        /* SessionsCap is the one field narrower than the shared bound:
         * Go's MaybeInt32 is an *int32 and this struct's field is an
         * int32_t, so int32's range is the real one. It is checked here
         * rather than folded into number_to_int64 so there is exactly
         * ONE place each bound is spelled -- a second, wider copy of the
         * same limit is a guard that can never fire, and this file has
         * already been bitten once by that shape. Casting 2^31 into an
         * int32_t is implementation-defined; refusing it is not. */
        if (i == F_SESSIONS_CAP && (v < INT32_MIN || v > INT32_MAX)) {
            rc = CLOAK_USER_JSON_ERR_RANGE;
            goto done;
        }
        switch (i) {
            case F_SESSIONS_CAP: local.sessions_cap = (int32_t)v; break;
            case F_UP_RATE:      local.up_rate = v; break;
            case F_DOWN_RATE:    local.down_rate = v; break;
            case F_UP_CREDIT:    local.up_credit = v; break;
            case F_DOWN_CREDIT:  local.down_credit = v; break;
            default:             local.expiry_time = v; break;
        }
        fields |= kBits[i];
    }

    *io_info = local;
    *out_fields = fields;
    *out_have_uid = have_uid;
    rc = 0;

done:
    cJSON_Delete(root);
    free(copy);
    return rc;
}
