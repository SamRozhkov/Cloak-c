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

#endif
