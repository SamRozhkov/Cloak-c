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

/* On success returns 0 and writes plaintext_len + cloak_aead_overhead(method)
 * bytes to out, setting *out_len. Returns -1 on an unknown method or an
 * OpenSSL-level failure. */
int cloak_aead_seal(cloak_aead_method_t method,
                     const uint8_t key[CLOAK_AEAD_KEY_LEN],
                     const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                     const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *out, size_t *out_len);

/* in is ciphertext||tag for non-NONE methods (in_len includes the tag).
 * On success returns 0 and writes in_len - cloak_aead_overhead(method) bytes
 * to out, setting *out_len. Returns -1 on authentication failure, an unknown
 * method, or in_len too short to contain a tag. */
int cloak_aead_open(cloak_aead_method_t method,
                     const uint8_t key[CLOAK_AEAD_KEY_LEN],
                     const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len);

size_t cloak_aead_overhead(cloak_aead_method_t method);

#endif
