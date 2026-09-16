#ifndef CLOAK_KEYGEN_H
#define CLOAK_KEYGEN_H

#include <stddef.h>

/* Key and UID generation for Cloak config files, mirroring Go Cloak's
 * cmd/ck-server/keygen.go: a 16-byte random UID and an X25519 key pair,
 * each returned standard-base64-encoded (matching Go's
 * base64.StdEncoding, the encoding Cloak's JSON configs use) so callers
 * can write the result straight into a config file or print it for a
 * human to copy. This file is assembly, not invention -- every primitive
 * it calls (cloak_random_bytes, cloak_x25519_generate_keypair,
 * cloak_base64_encode) already exists; its only value is that both the
 * server and client binaries, and any test, share one implementation
 * instead of three. */

#define CLOAK_KEYGEN_UID_LEN 16

/* Generates a fresh CLOAK_KEYGEN_UID_LEN-byte UID and writes its
 * standard-base64 encoding (NUL-terminated) to out. out_cap must be at
 * least cloak_base64_encoded_size(CLOAK_KEYGEN_UID_LEN).
 *
 * Returns 0 on success. Returns -1, leaving out untouched, if out is
 * NULL or out_cap is too small. */
int cloak_keygen_uid(char *out, size_t out_cap);

/* Generates a fresh X25519 key pair and writes each half's
 * standard-base64 encoding (NUL-terminated) to pub_out and priv_out
 * respectively -- matching the (public, private) return order of Go's
 * generateKeyPair(). Both _cap arguments must be at least
 * cloak_base64_encoded_size(CLOAK_X25519_KEY_LEN) (see cloak/crypto.h).
 *
 * Returns 0 on success. Returns -1, leaving pub_out/priv_out untouched,
 * if either pointer is NULL, either buffer is too small, or the
 * underlying key generation fails. */
int cloak_keygen_keypair(char *pub_out, size_t pub_cap, char *priv_out, size_t priv_cap);

#endif
