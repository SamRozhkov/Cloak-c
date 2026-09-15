#include "cloak/client_auth.h"
#include "cloak/config.h"
#include "cloak/crypto.h"

#include <string.h>

/* Bit 0 of the flags byte at plaintext[41]. Matches
 * CLOAK_SERVER_AUTH_UNORDERED_FLAG (cloak/server_auth.h) and Go's
 * UNORDERED_FLAG (internal/client/auth.go) -- not shared as a public
 * macro here because this module does not otherwise depend on
 * cloak/server_auth.h at all, and a caller of cloak_client_auth_build
 * never needs the raw bit: it passes `unordered` as a plain 0/1. */
#define CLOAK_CLIENT_AUTH_UNORDERED_FLAG 0x01

/* The 48-byte plaintext this module builds and seals -- see
 * cloak/client_auth.h's own doc comment for the field-by-field layout. */
#define CLOAK_CLIENT_AUTH_PLAINTEXT_LEN 48

static void store_be64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

int cloak_client_auth_build(const uint8_t uid[CLOAK_UID_LEN],
                             const char *proxy_method,
                             uint8_t encryption_method,
                             uint32_t session_id,
                             int unordered,
                             int64_t now_unix,
                             const uint8_t server_pub[CLOAK_X25519_KEY_LEN],
                             cloak_client_auth_payload_t *out,
                             uint8_t out_shared_secret[CLOAK_AEAD_KEY_LEN]) {
    /* Fully initialize both outputs BEFORE validating anything else, so a
     * rejected call (proxy_method NULL or too long, checked next) leaves
     * them in a defined, zeroed state rather than uninitialized. */
    memset(out, 0, sizeof(*out));
    memset(out_shared_secret, 0, CLOAK_AEAD_KEY_LEN);

    if (proxy_method == NULL) {
        return -1;
    }
    size_t proxy_method_len = strlen(proxy_method);
    if (proxy_method_len > CLOAK_PROXY_METHOD_LEN) {
        /* Rejected, not truncated -- see cloak/client_auth.h. */
        return -1;
    }

    /* A fresh ephemeral key pair every call: this is what makes two calls
     * with identical arguments produce different output, and it is the
     * only source of the AEAD nonce (below) and of the shared secret. */
    uint8_t eph_priv[CLOAK_X25519_KEY_LEN];
    uint8_t eph_pub[CLOAK_X25519_KEY_LEN];
    if (cloak_x25519_generate_keypair(eph_priv, eph_pub) != 0) {
        return -1;
    }

    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    if (cloak_x25519_shared_secret(eph_priv, server_pub, shared_secret) != 0) {
        return -1;
    }

    uint8_t plaintext[CLOAK_CLIENT_AUTH_PLAINTEXT_LEN];
    memset(plaintext, 0, sizeof(plaintext));
    memcpy(plaintext, uid, CLOAK_UID_LEN);
    memcpy(plaintext + 16, proxy_method, proxy_method_len);
    /* plaintext[16 + proxy_method_len : 28) is already zero (NUL padding)
     * from the memset above; when proxy_method_len == 12 that range is
     * empty and nothing is overwritten past the field. */
    plaintext[28] = encryption_method;
    store_be64(plaintext + 29, (uint64_t)now_unix);
    store_be32(plaintext + 37, session_id);
    if (unordered) {
        plaintext[41] |= CLOAK_CLIENT_AUTH_UNORDERED_FLAG;
    }
    /* plaintext[42:48) reserved, already zero. */

    /* The nonce is the first 12 bytes of the ephemeral PUBLIC key, not
     * random bytes of its own -- load-bearing, see cloak/client_auth.h:
     * the server recovers this same nonce from the ClientHello's `random`
     * field, which is exactly eph_pub. cloak_aead_seal only reads the
     * first CLOAK_AEAD_NONCE_LEN (12) of the 32 bytes eph_pub provides. */
    size_t ciphertext_len = 0;
    if (cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, shared_secret, eph_pub, NULL, 0,
                         plaintext, sizeof(plaintext),
                         out->ciphertext, &ciphertext_len) != 0) {
        return -1;
    }
    if (ciphertext_len != sizeof(out->ciphertext)) {
        return -1;
    }

    memcpy(out->random, eph_pub, CLOAK_X25519_KEY_LEN);
    memcpy(out_shared_secret, shared_secret, CLOAK_AEAD_KEY_LEN);
    return 0;
}
