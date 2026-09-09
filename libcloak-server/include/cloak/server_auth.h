#ifndef CLOAK_SERVER_AUTH_H
#define CLOAK_SERVER_AUTH_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/crypto.h"

#define CLOAK_SERVER_AUTH_UID_LEN 16
#define CLOAK_SERVER_AUTH_PROXY_METHOD_LEN 12
#define CLOAK_SERVER_AUTH_UNORDERED_FLAG 0x01
#define CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS 180

/* The replay cache's age_limit_seconds (see cloak/replay_cache.h) MUST
 * exceed 2 * CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS: a client's
 * clock may legitimately run up to the tolerance ahead of the server's, so
 * a captured ciphertext can remain within the timestamp window for up to
 * twice the tolerance -- not just the tolerance itself -- and the replay
 * cache must stay populated for at least that long to catch a resend
 * within that window. Go Cloak's own replay cache uses a 12-hour age
 * limit for exactly this reason; this constant matches it. */
#define CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS (12 * 60 * 60)

typedef struct {
    uint8_t uid[CLOAK_SERVER_AUTH_UID_LEN];
    /* NUL-terminated. The wire field is a fixed 12-byte, NUL-padded ASCII
     * string; leading and trailing NUL padding is stripped (matching Go's
     * bytes.Trim(s, "\x00") exactly), so this is always
     * <= CLOAK_SERVER_AUTH_PROXY_METHOD_LEN bytes plus the terminator.
     * Unlike Go's string(bytes.Trim(...)), a NUL byte anywhere before the
     * end of the field's meaningful content (not just as trailing padding)
     * truncates this C string early -- callers needing exact byte-for-byte
     * parity with Go's semantics for a proxy method containing embedded
     * NULs (not a realistic scenario for any real proxy method name) should
     * be aware of this divergence. */
    char proxy_method[CLOAK_SERVER_AUTH_PROXY_METHOD_LEN + 1];
    uint8_t encryption_method;
    uint32_t session_id;
    int unordered; /* 0 or 1 */
} cloak_server_clientinfo_t;

/* Validates that data was encrypted by someone who knows the server's
 * public key, with a fresh timestamp -- it does NOT authorize the UID
 * inside the decrypted payload. `uid`, `proxy_method`, `encryption_method`,
 * `session_id`, and `unordered` in `*out` are all attacker-chosen values on
 * success; the caller (a future dispatcher/user-management module) is
 * responsible for validating and authorizing `uid` before trusting anything
 * else in `*out`.
 *
 * Derives the ECDH shared secret (server_priv x the client's ephemeral
 * public key, carried in the ClientHello's `random` field), uses it to
 * AES-256-GCM-decrypt the 64-byte ciphertext (session_id_field ||
 * key_share_field -- exactly the `session_id` and X25519 `key_share` fields
 * cloak_clienthello_parse extracts) into the 48-byte ClientInfo payload, and
 * validates both AEAD authentication and that the embedded timestamp is
 * within +/- CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS of now_unix.
 *
 * session_id_field/session_id_field_len and key_share_field mirror how
 * cloak_clienthello_parse exposes those fields: session_id_field may be
 * NULL (pass NULL with session_id_field_len == 0 when cloak_clienthello_parse
 * returned a NULL session_id); key_share_field may be NULL. This function
 * returns -1 immediately if session_id_field == NULL,
 * session_id_field_len != 32, or key_share_field == NULL -- mirroring Go
 * Cloak's combined `len(ctxTag) != 64` check (internal/server/TLS.go),
 * split across the two constituent 32-byte fields (Go's keyShare is always
 * exactly 32 bytes by the time it reaches that check -- parseKeyShare
 * itself enforces that -- so the only real variable in Go's check is the
 * session_id half, making this split check exactly equivalent to Go's
 * combined one).
 *
 * Wire layout of the 48-byte decrypted payload (matches Go Cloak's
 * authenticationPayload exactly, byte for byte):
 *   [0:16)  UID
 *   [16:28) proxy method (NUL-padded ASCII)
 *   [28]    encryption method (see cloak_aead_method_t -- the wire byte
 *           values are numerically identical to that enum, but this
 *           function does NOT validate that the byte is a legal member of
 *           it -- the caller MUST call
 *           cloak_aead_method_is_valid(info.encryption_method) before using
 *           it, the same requirement crypto.h already documents for any
 *           wire-sourced method byte)
 *   [29:37) Unix timestamp, big-endian int64
 *   [37:41) session ID, big-endian uint32
 *   [41]    flags (bit 0 = CLOAK_SERVER_AUTH_UNORDERED_FLAG)
 *   [42:48) reserved, ignored
 *
 * On success returns 0, populates *out, and writes the derived shared
 * secret to out_shared_secret (needed later by
 * cloak_server_auth_compose_reply to encrypt the session key -- the same
 * shared secret authenticates both directions of this handshake). On
 * failure (NULL/wrong-length session_id_field or key_share_field, AEAD
 * authentication failure, or timestamp outside the tolerance window)
 * returns -1 and leaves both outputs unspecified.
 *
 * This function does NOT check for replayed `random` values -- call
 * cloak_replay_cache_check_and_insert (cloak/replay_cache.h) on `random`
 * separately, BEFORE calling this function, mirroring Go Cloak's own
 * AuthFirstPacket (which checks replay first, against the raw
 * not-yet-authenticated random, then decrypts). */
int cloak_server_auth_decrypt(const uint8_t random[32],
                               const uint8_t *session_id_field, size_t session_id_field_len,
                               const uint8_t *key_share_field,
                               const uint8_t server_priv[CLOAK_X25519_KEY_LEN],
                               int64_t now_unix,
                               cloak_server_clientinfo_t *out,
                               uint8_t out_shared_secret[CLOAK_AEAD_KEY_LEN]);

/* The set of plausible filler lengths for the reply's trailing fake
 * "Certificate" record, matching Go Cloak's possibleCertLengths. The real
 * Cloak client never parses this record's content -- it only needs to
 * consume the right number of TLS records -- so this is purely a
 * DPI-plausibility size choice (an abbreviated-handshake certificate
 * message's length varies connection to connection on a real server, and a
 * constant length here would be a fingerprint). */
#define CLOAK_SERVER_AUTH_CERT_LEN_COUNT 7
extern const size_t cloak_server_auth_cert_lens[CLOAK_SERVER_AUTH_CERT_LEN_COUNT];

/* Maximum bytes cloak_server_auth_compose_reply can ever write: the
 * ServerHello record (5 + 122 = 127 bytes, fixed) + ChangeCipherSpec record
 * (5 + 1 = 6 bytes, fixed) + the fake cert record (5 +
 * max(cloak_server_auth_cert_lens) = 5 + 68 = 73 bytes) = 206, rounded up. */
#define CLOAK_SERVER_AUTH_REPLY_MAX_BYTES 256

/* Composes the ServerHello + ChangeCipherSpec + fake Certificate reply: the
 * bytes the server writes back to the client after a successful
 * cloak_server_auth_decrypt, mirroring Go Cloak's composeReply/
 * composeServerHello (same wire shape -- an abbreviated/session-resumption-
 * style TLS 1.2 handshake -- verified byte-for-byte against a faithful
 * reproduction of Go's own implementation; see the plan's Provenance
 * section).
 *
 * AES-256-GCM-encrypts session_key (the caller's freshly chosen frame
 * encryption key) with shared_secret (from cloak_server_auth_decrypt) using
 * reply_nonce, then splits the 48-byte ciphertext+tag across the
 * ServerHello's `random` field (bytes reply_nonce || ciphertext[0:20)) and
 * its key_share extension (ciphertext[20:48) followed by 4 bytes of
 * caller-supplied padding -- a real X25519 key share is 32 bytes and only
 * 28 remain after the split, so pad4 fills the rest; it carries no meaning
 * and is never read back).
 *
 * client_session_id must be the same 32 bytes the client's ClientHello
 * carried (echoed back, matching real TLS session-resumption semantics).
 *
 * fake_cert/fake_cert_len is the trailing filler record's content -- its
 * length MUST be one of cloak_server_auth_cert_lens (checked; anything else
 * fails). Its bytes are opaque filler, not a real certificate.
 *
 * reply_nonce and pad4 are single-use values that MUST be freshly random
 * per call (e.g. via cloak_random_bytes) -- reusing a nonce with the same
 * shared_secret breaks AES-GCM's security guarantees, exactly as elsewhere
 * in this project (cloak_aead_seal has the same requirement).
 *
 * Returns bytes written (> 0) on success, or -1 on failure (fake_cert_len
 * not in cloak_server_auth_cert_lens, out_cap too small, or an AEAD
 * failure). out_cap should be at least CLOAK_SERVER_AUTH_REPLY_MAX_BYTES to
 * always succeed. */
long cloak_server_auth_compose_reply(const uint8_t shared_secret[CLOAK_AEAD_KEY_LEN],
                                      const uint8_t session_key[CLOAK_AEAD_KEY_LEN],
                                      const uint8_t reply_nonce[CLOAK_AEAD_NONCE_LEN],
                                      const uint8_t client_session_id[32],
                                      const uint8_t pad4[4],
                                      const uint8_t *fake_cert, size_t fake_cert_len,
                                      uint8_t *out, size_t out_cap);

#endif
