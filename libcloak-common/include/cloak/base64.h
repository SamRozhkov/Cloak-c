#ifndef CLOAK_BASE64_H
#define CLOAK_BASE64_H

#include <stddef.h>
#include <stdint.h>

/* Standard-alphabet base64 (RFC 4648 section 4: '+' and '/', padding
 * required), matching Go's encoding/base64.StdEncoding -- the encoding
 * Go Cloak's config files use for UIDs and keys.
 *
 * Decoding is strict about structure: the input length must be a multiple
 * of 4, every character must be in the alphabet (no whitespace, no
 * URL-safe '-'/'_'), and '=' padding may appear only as the last one or
 * two characters of the final quantum. It is deliberately NOT strict about
 * non-canonical trailing bits (e.g. "Zg==" and "Zh==" both decode), which
 * matches Go's default StdEncoding behaviour. */

/* Number of bytes cloak_base64_encode writes for in_len input bytes,
 * including the terminating NUL. */
size_t cloak_base64_encoded_size(size_t in_len);

/* Encodes in_len bytes into out as a NUL-terminated base64 string.
 * out_cap must be at least cloak_base64_encoded_size(in_len).
 * Returns 0 on success, -1 if out is NULL, out_cap is too small, or in is
 * NULL with in_len > 0. On failure out is left untouched. */
int cloak_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

/* Decodes the NUL-terminated base64 string in into out, writing the number
 * of decoded bytes to *out_len.
 * Returns 0 on success, -1 if in or out_len is NULL, the input is
 * malformed per the strictness rules above, or the decoded output would
 * exceed out_cap. On failure *out_len is not written and out may have been
 * partially overwritten -- callers must not read out after a failure.
 * An empty input string is valid and decodes to zero bytes. */
int cloak_base64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len);

/* URL-safe alphabet (RFC 4648 section 5: '-' and '_' instead of '+' and
 * '/'). This is what Go's base64.URLEncoding produces, and what the admin
 * API's path component uses -- note that the SAME uid travels
 * base64-STANDARD inside the JSON body of the same request, because Go's
 * encoding/json marshals a []byte with StdEncoding. Two alphabets, one
 * request; see this project's admin-API plan, decision D3.
 *
 * Encoding always pads, matching Go's base64.URLEncoding (the variant
 * api_router.go actually uses) -- there is exactly one canonical output
 * for a given input, so there is no reason to produce anything else.
 *
 * Decoding is LENIENT about padding, unlike cloak_base64_decode: it
 * accepts both the padded form above and the common unpadded convention
 * (Go's base64.RawURLEncoding), because URL-safe base64 is routinely
 * typed or pasted by hand without trailing '='. This is not guessing --
 * it is the deterministic union of two well-known RFC 4648 encodings,
 * selected purely by input length (length % 4 == 0 means "padded rules
 * apply"; length % 4 == 2 or 3 means "unpadded final group, no '='
 * anywhere is accepted"; length % 4 == 1 is invalid under both and is
 * always rejected). It remains strict about the alphabet itself: '+' and
 * '/' are rejected exactly as '-' and '_' are rejected by
 * cloak_base64_decode, because this decoder is reached with
 * attacker-controlled input from the admin API's URL path. */

/* Encodes in_len bytes into out as a NUL-terminated URL-safe base64
 * string, with '=' padding. out_cap must be at least
 * cloak_base64_encoded_size(in_len) (the size formula does not depend on
 * the alphabet). Returns 0 on success, -1 if out is NULL, out_cap is too
 * small, or in is NULL with in_len > 0. On failure out is left untouched. */
int cloak_base64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

/* Decodes the NUL-terminated URL-safe base64 string in into out, writing
 * the number of decoded bytes to *out_len, per the padding leniency
 * described above.
 * Returns 0 on success, -1 if in or out_len is NULL, the input is
 * malformed, or the decoded output would exceed out_cap. On failure
 * *out_len is not written and out may have been partially overwritten --
 * callers must not read out after a failure. An empty input string is
 * valid and decodes to zero bytes. */
int cloak_base64url_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len);

#endif
