#ifndef CLOAK_USER_JSON_H
#define CLOAK_USER_JSON_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/usermanager.h"

/* The admin API's wire format for one user: a cloak_user_info_t in, the
 * exact bytes a real `ck-client -a` expects out, and the same bytes back
 * in again as a cloak_user_info_t plus the field mask
 * cloak_usermanager_write takes.
 *
 * THE CONTRACT IS GO'S, NOT OURS. Go Cloak marshals
 * internal/server/usermanager.UserInfo with encoding/json and no struct
 * tags at all, so the field names are the Go identifiers verbatim and the
 * order is the struct's declaration order:
 *
 *   {"UID":"EBESExQVFhcYGRobHB0eHw==","SessionsCap":10,"UpRate":0,
 *    "DownRate":0,"UpCredit":1000000,"DownCredit":1000000,
 *    "ExpiryTime":1789000000}
 *
 * (one line, no spaces -- broken here only to fit this comment).
 *
 * Two consequences of that being Go's contract rather than a format we
 * chose, both of which look like mistakes until you know why:
 *
 *   - THE UID TRAVELS IN TWO DIFFERENT ALPHABETS IN ONE REQUEST. Here it
 *     is base64 STANDARD with padding, because encoding/json marshals a
 *     []byte with base64.StdEncoding. In the URL path of the very same
 *     request it is base64 URL-SAFE, because api_router.go decodes that
 *     with base64.URLEncoding. Same 16 bytes, two alphabets. See
 *     cloak/base64.h and the admin-API plan's decision D3. Using the
 *     wrong one here produces a '+' or '/' where a real client sends '-'
 *     or '_' and the mismatch is silent until a UID happens to contain
 *     the offending sextet.
 *   - AN UNSET FIELD IS `null`, NOT ABSENT AND NOT ZERO. Go's Maybe*
 *     fields are pointers, so a nil one marshals as null. Decoding maps
 *     "present and non-null" to a set mask bit and "absent or null" to a
 *     clear one, and THAT mapping is the entire reason
 *     cloak_usermanager_write takes a mask: a partial update must leave
 *     the fields it did not name alone, and 0 is a legitimate value for
 *     every one of them (0 credit denies, 0 rate means unthrottled).
 *     Collapsing null to 0 would turn "don't touch the rate" into "set
 *     the rate to unlimited".
 *
 * THREAT MODEL, and it is not the same as the rest of this project's
 * parsers. cloak_user_json_decode is fed a body that is
 * attacker-controlled AND AUTHENTICATED AS THE OPERATOR: reaching it
 * costs an attacker only the admin UID, a 16-byte secret in a config
 * file, and on the far side of it is the process holding every user's
 * credentials. Everywhere else in libcloak-server a parser bug costs a
 * fingerprint; here it costs the machine. Nothing below is trusted
 * because it authenticated. Every rejection is a distinct code so the
 * router can answer honestly, and no input is ever silently coerced --
 * truncating a number or a UID into something that "looks right" is the
 * failure mode this file exists to make impossible.
 *
 * WE RELY ON TASK 2'S BOUND AND DO NOT IMPOSE OUR OWN. cloak_http_parser
 * refuses any Content-Length above CLOAK_HTTP_MAX_BODY (64 KiB) at the
 * header, before a byte is allocated, so every body that reaches
 * cloak_user_json_decode is already bounded. This decoder therefore does
 * not re-impose a length cap; it makes exactly one allocation, of
 * body_len + 1 bytes, to give cJSON a NUL-terminated copy (see
 * cloak_user_json_decode). A caller that feeds this function a body from
 * somewhere OTHER than a bounded HTTP parser must bound it first.
 *
 * cJSON's own nesting limit is part of that reliance and is left at its
 * vendored default of 1000 (CJSON_NESTING_LIMIT, third_party/cjson,
 * compile-time, with no runtime knob). It is not set explicitly here
 * because it cannot be: it is baked into the cjson static library, which
 * this project keeps byte-identical to the upstream release. 1000 is
 * comfortably reached inside 64 KiB -- "[[[[..." costs one byte per
 * level -- so the limit, not the body cap, is what stops the recursive
 * descent, and it stops it as a clean parse failure rather than a stack
 * overflow. If cJSON is ever revendored with that limit raised, this
 * file's deep-nesting rejection is the thing that changes behaviour.
 */

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

/* NULL argument, an out_cap too small, or a `fields` mask carrying bits
 * outside CLOAK_USER_FIELD_ALL. A caller bug, never a wire condition:
 * the router must not report it as a client error. */
#define CLOAK_USER_JSON_ERR_ARG        (-1)
/* The bytes are not one well-formed JSON document: unparseable, empty,
 * containing a NUL, or carrying trailing garbage after the value. */
#define CLOAK_USER_JSON_ERR_SYNTAX     (-2)
/* Well-formed JSON whose top level is not an object -- a bare array, a
 * string, a number, a bool, a null. Distinct from _SYNTAX because the
 * sender's mistake is completely different: they sent valid JSON of the
 * wrong shape, not a broken document. */
#define CLOAK_USER_JSON_ERR_NOT_OBJECT (-3)
/* A recognised field is present with the wrong JSON type: a string, a
 * bool, an object or an array where a number belongs, or a non-string
 * UID. */
#define CLOAK_USER_JSON_ERR_TYPE       (-4)
/* A recognised numeric field is a JSON number with a fractional part:
 * 1.5. The sender meant a quantity this codec has no way to store, and
 * rounding it would be the silent coercion this file exists to refuse. */
#define CLOAK_USER_JSON_ERR_NOT_INTEGER (-5)
/* A recognised numeric field is an integral value this codec will not
 * carry: outside +/-CLOAK_USER_JSON_MAX_SAFE_INT for the 64-bit fields,
 * outside int32 for SessionsCap, or not finite at all -- 1e999 is a
 * well-formed JSON number that strtod hands back as infinity, and "too
 * large" is the honest thing to call it. See the number contract below;
 * this is the code that says "your value is a whole number, and we still
 * refuse it", which is emphatically not the same answer as
 * _NOT_INTEGER. */
#define CLOAK_USER_JSON_ERR_RANGE      (-6)
/* The UID field is present but unusable: not valid standard-alphabet
 * base64, or not exactly CLOAK_UID_LEN bytes once decoded. */
#define CLOAK_USER_JSON_ERR_UID        (-7)
/* A recognised field name appears more than once in the object. */
#define CLOAK_USER_JSON_ERR_DUPLICATE  (-8)
/* Out of memory. The only allocation on the decode path is one copy of
 * the body (already bounded by the HTTP parser), plus whatever cJSON
 * allocates for the parse tree. */
#define CLOAK_USER_JSON_ERR_MEMORY     (-9)

/* ------------------------------------------------------------------ */
/* The number contract                                                 */
/* ------------------------------------------------------------------ */

/* THE LARGEST MAGNITUDE THIS CODEC WILL DECODE, and the reason is cJSON,
 * not JSON and not us.
 *
 * cJSON stores every parsed number as a `double` and nothing else. There
 * is no raw-token accessor anywhere in its API: by the time we see a
 * number, the decimal text the client sent is gone. So the only integers
 * a decode can faithfully recover are the ones a double represents
 * exactly and unambiguously, and the largest of those is 2^53 - 1.
 *
 * NOT 2^53, and the off-by-one is load-bearing rather than timid. 2^53
 * (9007199254740992) IS exactly representable, but so is nothing between
 * it and 2^53 + 2: the decimal token 9007199254740993 rounds to the very
 * same double, ties-to-even, and after the parse the two are
 * indistinguishable. Accepting 2^53 would therefore mean accepting
 * 9007199254740993 AS 9007199254740992 -- a silent one-off truncation of
 * an attacker-supplied number, which is exactly the class of bug this
 * file refuses to have. Stopping one integer lower makes every accepted
 * value provably the value that was sent. This is the same bound, for
 * the same reason, that JavaScript names Number.MAX_SAFE_INTEGER.
 *
 * WHAT IT COSTS: nothing operational. As a credit it is about 9
 * petabytes, and as an expiry_time it is some 285 million years past the
 * epoch.
 *
 * WHAT IT BUYS, beyond honesty: it means the admin API cannot hand
 * INT64_MIN or INT64_MAX to cloak_usermanager_write. The user manager's
 * credit arithmetic saturates rather than wrapping precisely because
 * those two values were reachable once this module existed (see
 * cloak_usermanager_upload_status); with this bound they are no longer
 * reachable FROM THE WIRE at all. The saturation stays -- an operator
 * can still write such a row with a direct SQLite tool -- but the remote
 * path to it is closed here rather than defended there.
 *
 * THE ENCODER IS DELIBERATELY NOT SYMMETRIC WITH THIS. It emits any
 * int64 exactly, because it must: a row already holding INT64_MIN (the
 * credit saturation's own resting place) has to be reportable to the
 * operator who needs to see it, and printing it as anything else would
 * be a lie about the database's contents. The visible consequence is
 * that a GET of such a user returns a document that a POST would refuse
 * -- which is the correct direction for the asymmetry to run, and is
 * pinned by a test rather than left to be rediscovered. */
#define CLOAK_USER_JSON_MAX_SAFE_INT ((int64_t)9007199254740991) /* 2^53 - 1 */

/* Buffer size that always suffices for cloak_user_json_encode, including
 * the terminating NUL. The worst case is every field present and every
 * value at its longest:
 *
 *   {"UID":"<24 base64 chars>"        33
 *   ,"SessionsCap":-2147483648        15 + 11
 *   ,"UpRate":-9223372036854775808    10 + 20
 *   ,"DownRate":...                   12 + 20
 *   ,"UpCredit":...                   12 + 20
 *   ,"DownCredit":...                 14 + 20
 *   ,"ExpiryTime":...                 14 + 20
 *   }                                  1
 *                                    ----
 *                                     222, plus the NUL
 *
 * 256 leaves a margin without pretending to a precision the arithmetic
 * above does not have. A test encodes exactly that worst case and pins
 * both that it fits and that one byte less does not, so shrinking this
 * constant or lengthening a field name fails the suite rather than
 * truncating a reply. */
#define CLOAK_USER_JSON_MAX 256

/* ------------------------------------------------------------------ */
/* Encode                                                              */
/* ------------------------------------------------------------------ */

/* Writes info as the JSON object above into out, NUL-terminated, and
 * sets *out_len (optional) to the length excluding that NUL.
 *
 * `fields` says which of the six numeric fields carry a value; every bit
 * that is CLEAR emits `null`, exactly as a nil Go pointer marshals.
 * CLOAK_USER_FIELD_ALL is what a GET of a stored user uses, because a
 * stored row always has all six. Bits outside CLOAK_USER_FIELD_ALL are
 * CLOAK_USER_JSON_ERR_ARG, mirroring cloak_usermanager_write: an unknown
 * bit means the caller and this build disagree about what the mask says,
 * and emitting the rest anyway would describe a different user than the
 * one asked for. The UID is not maskable and is always emitted.
 *
 * FIELD ORDER IS PART OF THE CONTRACT: UID, SessionsCap, UpRate,
 * DownRate, UpCredit, DownCredit, ExpiryTime -- Go's struct order, which
 * is what encoding/json emits. It is fixed here because a client
 * comparing bytes is a real consumer, and because a test asserting an
 * exact string is only meaningful if insertion order is controlled.
 *
 * INTEGERS ARE FORMATTED BY US, NOT BY cJSON. Every number is built with
 * cJSON_CreateRaw over a PRId64/PRId32 rendering. cJSON_CreateNumber
 * would be a correctness bug, not a style choice: cJSON stores a double
 * and prints "%d" of a deprecated int field only when the two compare
 * equal, so any magnitude above INT_MAX -- a credit of 10^12, one
 * terabyte, an ordinary quota -- comes out as "1e+12", and a real Go
 * client's json.Unmarshal into an *int64 rejects that outright
 * ("cannot unmarshal number 1e+12 into Go value of type int64"). The
 * whole quota would be unreadable by the only client that exists.
 *
 * Returns 0 on success. CLOAK_USER_JSON_ERR_ARG if info or out is NULL,
 * `fields` has unknown bits, or out_cap is too small for the result
 * (pass CLOAK_USER_JSON_MAX and it never can be);
 * CLOAK_USER_JSON_ERR_MEMORY if cJSON could not allocate. On any failure
 * out is not written and *out_len is not set. */
int cloak_user_json_encode(const cloak_user_info_t *info, uint32_t fields,
                           char *out, size_t out_cap, size_t *out_len);

/* ------------------------------------------------------------------ */
/* Decode                                                              */
/* ------------------------------------------------------------------ */

/* Parses body[0..body_len) as one of the objects above.
 *
 * io_info IS AN IN/OUT PARAMETER AND THE CALLER MUST INITIALIZE IT. Only
 * the fields actually present and non-null in the document are written;
 * everything else keeps whatever the caller put there. That is what
 * makes a partial update work: the router seeds io_info from
 * cloak_usermanager_get (or zeroes it for a create) and this applies the
 * delta. A field whose bit comes back clear in *out_fields was NOT
 * written, and reading it is reading the caller's own value.
 *
 * *out_fields receives exactly the CLOAK_USER_FIELD_* bits for the
 * fields that were present and non-null. It is not optional.
 *
 * *out_have_uid receives 1 if the document carried a usable UID (written
 * into io_info->uid) and 0 if the UID field was absent or null (io_info
 * ->uid untouched). It is not optional either, deliberately: a caller
 * that ignored it would hand cloak_usermanager_write whatever happened
 * to be in the struct. Note that the admin router takes the UID from the
 * request PATH, and a body UID is at most a cross-check -- which of the
 * two wins is the router's decision, not this codec's, so this function
 * only reports what it found.
 *
 * ON FAILURE NOTHING IS WRITTEN: not io_info, not *out_fields, not
 * *out_have_uid. The parse runs against a local copy and is committed
 * only once every field has validated, so a document that is good up to
 * its last field applies none of it. A half-applied update is worse than
 * a rejected one.
 *
 * STRICTNESS, and where it deliberately diverges from Go:
 *
 *   - UNKNOWN FIELDS ARE IGNORED, matching encoding/json's default. A
 *     newer client sending a field this build does not know must not be
 *     refused.
 *   - FIELD NAMES ARE MATCHED CASE-SENSITIVELY. encoding/json falls back
 *     to a case-insensitive match, so Go would bind "uid" to UID; this
 *     does not. The real client emits the exact names, and a codec in
 *     which "upcredit" and "UpCredit" are the same key is a codec where
 *     two of them can appear in one object with only one of them seen.
 *   - A REPEATED RECOGNISED FIELD IS REJECTED (_DUPLICATE). Go takes the
 *     last occurrence; cJSON's lookup returns the first. Rather than
 *     pick a winner and own a parser differential on
 *     {"UpCredit":1,"UpCredit":999999999}, this refuses the document.
 *     Nothing legitimate emits one.
 *   - A NUL BYTE ANYWHERE IN THE BODY IS _SYNTAX, before parsing. JSON
 *     has no use for one, and a NUL is the classic way to make two
 *     readers disagree about where a document ends.
 *   - TRAILING GARBAGE AFTER THE VALUE IS _SYNTAX. cJSON_Parse would
 *     accept it.
 *
 * Returns 0 on success or a negative CLOAK_USER_JSON_ERR_*. body may be
 * NULL only when body_len is 0, which is _SYNTAX (an empty document is
 * not a user). */
int cloak_user_json_decode(const uint8_t *body, size_t body_len,
                           cloak_user_info_t *io_info, uint32_t *out_fields,
                           int *out_have_uid);

#endif
