#ifndef CLOAK_CRYPTO_H
#define CLOAK_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    CLOAK_AEAD_NONE = 0,
    CLOAK_AEAD_AES_256_GCM = 1,
    CLOAK_AEAD_CHACHA20_POLY1305 = 2,
    CLOAK_AEAD_AES_128_GCM = 3,
} cloak_aead_method_t;

#define CLOAK_AEAD_KEY_LEN 32
#define CLOAK_AEAD_NONCE_LEN 12
#define CLOAK_AEAD_TAG_LEN 16

/* key is always CLOAK_AEAD_KEY_LEN (32) bytes regardless of method, so a
 * single derived session key can be passed for any method. Note:
 * CLOAK_AEAD_AES_128_GCM only consumes the first 16 bytes of key; bytes
 * 16-31 are ignored entirely (not mixed into the cipher in any way). Use
 * cloak_aead_key_len() if you need to know how many bytes of key actually
 * matter for a given method.
 *
 * On success returns 0 and writes plaintext_len + cloak_aead_overhead(method)
 * bytes to out, setting *out_len. Returns -1 on an unknown method or an
 * OpenSSL-level failure. */
int cloak_aead_seal(cloak_aead_method_t method,
                     const uint8_t key[CLOAK_AEAD_KEY_LEN],
                     const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                     const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *out, size_t *out_len);

/* key is always CLOAK_AEAD_KEY_LEN (32) bytes regardless of method, so a
 * single derived session key can be passed for any method. Note:
 * CLOAK_AEAD_AES_128_GCM only consumes the first 16 bytes of key; bytes
 * 16-31 are ignored entirely (not mixed into the cipher in any way). Use
 * cloak_aead_key_len() if you need to know how many bytes of key actually
 * matter for a given method.
 *
 * in is ciphertext||tag for non-NONE methods (in_len includes the tag).
 * On success returns 0 and writes in_len - cloak_aead_overhead(method) bytes
 * to out, setting *out_len. Returns -1 on authentication failure, an unknown
 * method, or in_len too short to contain a tag. */
int cloak_aead_open(cloak_aead_method_t method,
                     const uint8_t key[CLOAK_AEAD_KEY_LEN],
                     const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len);

/* Returns the number of key bytes actually used by method: 16 for
 * CLOAK_AEAD_AES_128_GCM, 0 for CLOAK_AEAD_NONE, and CLOAK_AEAD_KEY_LEN (32)
 * for CLOAK_AEAD_AES_256_GCM and CLOAK_AEAD_CHACHA20_POLY1305. Callers still
 * always pass a full CLOAK_AEAD_KEY_LEN buffer to cloak_aead_seal/open;
 * this just tells you how much of it matters. */
size_t cloak_aead_key_len(cloak_aead_method_t method);

/* Returns 1 if method is one of the defined cloak_aead_method_t values,
 * 0 otherwise. The method byte can arrive from untrusted/wire input (e.g.
 * a future auth handshake); callers that read a method ID from such input
 * must validate it with this function before doing anything else with it,
 * including calling cloak_aead_overhead() below. */
int cloak_aead_method_is_valid(cloak_aead_method_t method);

/* Return value is unspecified (though never a crash) for a method that
 * fails cloak_aead_method_is_valid(). Callers reading a method ID from
 * untrusted/wire input must validate it with cloak_aead_method_is_valid()
 * before relying on this return value, e.g. to size a buffer. */
size_t cloak_aead_overhead(cloak_aead_method_t method);

#define CLOAK_SALSA20_KEY_LEN 32
#define CLOAK_SALSA20_NONCE_LEN 8

/* XORs len bytes of src with the Salsa20 keystream (starting at block
 * counter 0) into dst. dst and src may alias (in-place XOR). */
void cloak_salsa20_xor(uint8_t *dst, const uint8_t *src, size_t len,
                        const uint8_t nonce[CLOAK_SALSA20_NONCE_LEN],
                        const uint8_t key[CLOAK_SALSA20_KEY_LEN]);

#define CLOAK_X25519_KEY_LEN 32

/* Generates a fresh X25519 keypair. Returns 0 on success, -1 on failure. */
int cloak_x25519_generate_keypair(uint8_t priv[CLOAK_X25519_KEY_LEN],
                                   uint8_t pub[CLOAK_X25519_KEY_LEN]);

/* Computes the ECDH shared secret between priv and peer_pub. Returns 0 on
 * success, -1 on failure. */
int cloak_x25519_shared_secret(const uint8_t priv[CLOAK_X25519_KEY_LEN],
                                const uint8_t peer_pub[CLOAK_X25519_KEY_LEN],
                                uint8_t out_secret[CLOAK_X25519_KEY_LEN]);

#endif
