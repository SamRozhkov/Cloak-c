#ifndef CLOAK_CLIENTHELLO_PARSE_H
#define CLOAK_CLIENTHELLO_PARSE_H

#include <stddef.h>
#include <stdint.h>

#define CLOAK_CLIENTHELLO_PARSE_RANDOM_LEN 32
#define CLOAK_CLIENTHELLO_PARSE_X25519_LEN 32

typedef struct {
    const uint8_t *random; /* always exactly CLOAK_CLIENTHELLO_PARSE_RANDOM_LEN bytes, points into data */
    const uint8_t *session_id; /* points into data; NULL if session_id_len == 0 */
    size_t session_id_len;     /* 0-255 (whatever the wire said; no TLS-legal-range enforcement here) */
    const uint8_t *x25519_key_share; /* points into data, always exactly CLOAK_CLIENTHELLO_PARSE_X25519_LEN bytes; NULL if no group 0x001d key_share entry was present */
    const uint8_t *sni;   /* points into data; NULL if no server_name/host_name extension was present.
                           * Note: a server_name extension whose host_name entry has name_len == 0
                           * produces sni != NULL with sni_len == 0 -- callers checking "is SNI
                           * present" should test sni != NULL, not assume a non-NULL sni implies
                           * sni_len > 0. */
    size_t sni_len;
} cloak_clienthello_parsed_t;

/* Parses a single TLS record (5-byte record header + one ClientHello
 * handshake message) out of data[0,len). Populates *out with pointers INTO
 * data -- no copying, no allocation; data must outlive out. out must be
 * non-NULL; this function does not check.
 *
 * Returns 0 on success, -1 if data is not a structurally valid ClientHello
 * this function can parse (wrong record type, wrong record-layer version,
 * wrong handshake type, or any length field -- handshake length, session_id
 * length, cipher_suites length, compression_methods length, extensions
 * length, or any individual extension's length -- that is inconsistent with
 * the actual bytes present). Absence of the SNI or X25519 key_share
 * extensions is NOT a parse failure -- out->sni and out->x25519_key_share
 * are simply left NULL; a real Cloak client always sends both, but this
 * function has no opinion on that, since arbitrary non-Cloak traffic
 * reaching this function (e.g. during the server's redirect-on-fail sniff)
 * is not malformed just because it isn't Cloak's traffic.
 *
 * This is a MINIMAL, DEFENSIVE parser, not a TLS stack: no cryptographic or
 * semantic validation, and it never reads outside data[0,len) regardless of
 * how adversarial the input is -- this function runs on unauthenticated,
 * attacker-controlled bytes from the network. It does not validate the
 * record layer's own declared length field against len; it assumes the
 * caller has already delivered exactly one un-fragmented ClientHello
 * record (matching Go Cloak's own parser, which makes the same
 * assumption).
 *
 * The extensions block is parsed strictly within its declared
 * extensions_len -- a deliberate, stricter divergence from Go Cloak's
 * reference parser, which never checks that extensions actually stop at
 * the declared boundary (see clienthello_parse.c for details). */
int cloak_clienthello_parse(const uint8_t *data, size_t len, cloak_clienthello_parsed_t *out);

#endif
