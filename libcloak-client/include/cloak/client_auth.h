#ifndef CLOAK_CLIENT_AUTH_H
#define CLOAK_CLIENT_AUTH_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/config.h"
#include "cloak/crypto.h"

/* Builds the 48-byte authenticated payload a client hides inside its
 * ClientHello, and the two wire pieces it turns into. This is the
 * encrypting half of the handshake the merged cloak_server_auth_decrypt
 * (cloak/server_auth.h) decrypts -- that header documents the 48-byte wire
 * layout byte for byte because the decrypting half was written first; this
 * module builds exactly that layout and nothing else. Go's reference is
 * internal/client/auth.go's makeAuthenticationPayload.
 *
 * Wire layout of the 48-byte plaintext (matches cloak/server_auth.h
 * exactly, byte for byte):
 *   [0:16)  UID
 *   [16:28) proxy method (NUL-padded ASCII)
 *   [28]    encryption method
 *   [29:37) Unix timestamp, big-endian int64
 *   [37:41) session ID, big-endian uint32
 *   [41]    flags (bit 0 = unordered)
 *   [42:48) reserved, zero
 *
 * That plaintext is never exposed to a caller: cloak_client_auth_build
 * generates a fresh ephemeral X25519 key pair, derives the shared secret
 * against the server's public key, and AES-256-GCM-seals the plaintext
 * under that secret -- with the first 12 bytes of the ephemeral PUBLIC key
 * as the nonce. That nonce choice is load-bearing, not arbitrary: the
 * ephemeral public key is the only thing this handshake sends that becomes
 * the ClientHello's `random` field, and cloak_server_auth_decrypt recovers
 * the nonce from exactly that field -- there is nowhere else for it to
 * come from, and reusing a different nonce here would make every payload
 * this function builds unauthenticatable by the merged decrypter. */
typedef struct {
    /* The ephemeral X25519 public key. Becomes the ClientHello's `random`
     * field verbatim -- the server recovers both the ECDH shared secret
     * and (its first 12 bytes) the AEAD nonce from this value alone. */
    uint8_t random[CLOAK_X25519_KEY_LEN];

    /* The 48-byte plaintext, AES-256-GCM-sealed (48 bytes ciphertext + a
     * 16-byte tag = 64). Becomes session_id_field (bytes [0:32)) ++
     * key_share_field (bytes [32:64)) -- exactly the two fields
     * cloak_clienthello_parse extracts and cloak_server_auth_decrypt
     * expects, split at the 32-byte boundary matching Go's `len(ctxTag) !=
     * 64` check split across the two constituent fields. */
    uint8_t ciphertext[64];
} cloak_client_auth_payload_t;

/* Builds *out and the shared secret needed to decrypt the server's reply
 * later (cloak_server_auth_compose_reply's counterpart on the client side,
 * not yet ported).
 *
 * uid must point to CLOAK_UID_LEN bytes; proxy_method must be a
 * NUL-terminated ASCII string of at most CLOAK_PROXY_METHOD_LEN (12) bytes
 * (the same constant, and the same 12-byte wire field, as the server's
 * CLOAK_SERVER_AUTH_PROXY_METHOD_LEN) -- a longer one is REJECTED rather
 * than silently truncated,
 * matching this project's config-parsing convention (see
 * cloak/config.h's CLOAK_PROXY_METHOD_LEN) rather than Go's
 * makeAuthenticationPayload, whose `copy` into a fixed-size slice would
 * silently truncate. A proxy method shorter than 12 bytes is NUL-padded;
 * one of exactly 12 bytes fills the field with no room for a terminator,
 * which is fine -- the field is fixed-width on the wire and never
 * NUL-terminated there. encryption_method is written to the wire as a raw
 * byte and is not validated against cloak_aead_method_is_valid -- the
 * caller is expected to pass an already-valid method, exactly as
 * cloak_server_auth_decrypt does not validate the byte it reads back.
 *
 * *out and out_shared_secret are fully zeroed as the FIRST action of this
 * function, before proxy_method (the one argument whose validity this
 * function cannot assume) is validated -- so a rejected call leaves both
 * outputs in a defined, zeroed state rather than uninitialized.
 *
 * Generates a fresh ephemeral X25519 key pair on every call (never cached,
 * never derived from a fixed value): two calls with identical arguments
 * MUST produce different *out values, because the ephemeral key -- and
 * therefore both the nonce and the ciphertext -- is fresh each time.
 *
 * On success returns 0, fills *out, and writes the ECDH shared secret
 * (server_pub x the fresh ephemeral private key -- the same value
 * cloak_server_auth_decrypt derives on the other end) to out_shared_secret.
 * On failure returns -1; out_shared_secret and out->random are untouched
 * past their initial zeroing on every failure path (they are only written
 * together, at the very end, once sealing has already succeeded), but
 * out->ciphertext may contain partial AEAD output if cloak_aead_seal
 * itself fails (an OpenSSL-internal failure this function's own inputs
 * cannot otherwise provoke, since CLOAK_AEAD_AES_256_GCM is always a valid
 * method here). Failure causes: proxy_method NULL or longer than 12
 * bytes, or an OpenSSL-level key generation/ECDH/AEAD failure. */
int cloak_client_auth_build(const uint8_t uid[CLOAK_UID_LEN],
                             const char *proxy_method,
                             uint8_t encryption_method,
                             uint32_t session_id,
                             int unordered,
                             int64_t now_unix,
                             const uint8_t server_pub[CLOAK_X25519_KEY_LEN],
                             cloak_client_auth_payload_t *out,
                             uint8_t out_shared_secret[CLOAK_AEAD_KEY_LEN]);

#endif
