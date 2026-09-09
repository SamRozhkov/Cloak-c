# libcloak-server Auth Handshake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the server-side auth handshake core: given the fields a `cloak_clienthello_parse` call already extracted from an incoming ClientHello (`random`, `session_id`, `x25519_key_share`), authenticate the connection (ECDH + AES-256-GCM decrypt + timestamp window + replay check) and compose the TLS-shaped reply (ServerHello + ChangeCipherSpec + fake Certificate) that lets a real Cloak client complete its side of the handshake -- mirroring Go Cloak's `internal/server/TLS.go` (`unmarshalClientHello`/`makeResponder`) and `internal/server/auth.go`.

**Architecture:** Two small, independent modules in the existing `libcloak-server` library. `server_auth.{h,c}` holds the crypto core -- decrypt-and-validate the incoming payload, and compose the outgoing reply -- both pure functions (no I/O, no hidden state, no internal randomness; callers supply time and any single-use random values). `replay_cache.{h,c}` is a separate, generic, fixed-capacity direct-mapped set keyed by the 32-byte client random, used by the future dispatcher to reject replayed handshakes before calling into `server_auth`. Neither module touches sockets, epoll, or session state -- those depend on infrastructure (`session_t`/switchboard, the epoll reactor's connection dispatcher) that doesn't exist yet in this port; this plan only builds the self-contained crypto/auth core those future modules will call into, the same scoping boundary Go Cloak itself draws between `TLS.go`/`auth.go` and `dispatcher.go`.

**Tech Stack:** C11, OpenSSL via the already-built `libcloak-common` (`cloak_x25519_shared_secret`, `cloak_aead_open`/`cloak_aead_seal`). CMake + CTest, Docker-only build/test (`Dockerfile.dev`, image `cloak-c-dev`) -- Linux-only project.

## Global Constraints

- Linux-only; all builds and test runs happen via Docker, matching every prior module.
- Zero compiler warnings (`-Wall -Wextra`).
- `server_auth.c`'s two public functions are pure/deterministic given their inputs: no calls to `cloak_random_bytes` or any wall-clock function inside this module. `cloak_server_auth_decrypt` takes `now_unix` as a parameter (not `time()`); `cloak_server_auth_compose_reply` takes `reply_nonce` and `pad4` as parameters (not internally generated) -- callers (a future dispatcher module) are responsible for sourcing fresh randomness for `reply_nonce`/`pad4` per call via `cloak_random_bytes`, exactly the same caller-supplies-the-nonce convention `cloak_aead_seal` itself already uses elsewhere in this project. This keeps both functions fully deterministic and testable against fixed vectors.
- `replay_cache.c` is single-threaded (no locking) -- this project's reactor is a single-threaded epoll loop, matching every other stateful module built so far (the reactor's timer heap, the frame codec).
- The 48-byte decrypted auth payload's wire layout, the ServerHello/ChangeCipherSpec/fake-Certificate reply's wire layout, and the replay cache's semantics are all specified exactly in this plan's Provenance section below and verified against real, running code (not transcribed from memory) -- copy the code verbatim, do not redesign it.

---

## Provenance and verification (read this before touching any code)

Every byte layout and boundary condition below was verified against real, running code before being written into this plan -- either against Go Cloak's actual source (`internal/server/auth.go`, `internal/server/TLS.go`, `internal/server/TLSAux.go`, `internal/client/auth.go`, `internal/common/crypto.go`, `internal/common/tls.go`, `internal/ecdh/curve25519.go`, `internal/server/state.go`) or by writing a Go program that faithfully reproduces Go's unexported logic and cross-checking its output against a C program linked against this repository's own already-merged, already-tested `libcloak-common` primitives (`cloak_x25519_shared_secret`, `cloak_aead_open`, `cloak_aead_seal`).

**The 48-byte auth payload.** Read directly from Go's own doc comment in `internal/client/auth.go`:
```
+----------+----------------+---------------------+-------------+--------------+--------+------------+
|  _UID_   | _Proxy Method_ | _Encryption Method_ | _Timestamp_ | _Session Id_ | _Flag_ | _reserved_ |
+----------+----------------+---------------------+-------------+--------------+--------+------------+
| 16 bytes | 12 bytes       | 1 byte              | 8 bytes     | 4 bytes      | 1 byte | 6 bytes    |
+----------+----------------+---------------------+-------------+--------------+--------+------------+
```
Cross-checked byte-index-for-byte-index against both `internal/client/auth.go`'s `makeAuthenticationPayload` (the encoder) and `internal/server/auth.go`'s `decryptClientInfo` (the decoder) -- both agree exactly: `[0:16)` UID, `[16:28)` proxy method (NUL-padded ASCII, trimmed with Go's `bytes.Trim(s, "\x00")`, which strips from BOTH ends -- matched exactly, not just trailing-trim), `[28]` encryption method (Go's `mux.EncryptionMethod*` byte values -- 0=Plain, 1=AES256GCM, 2=ChaCha20Poly1305, 3=AES128GCM -- confirmed numerically IDENTICAL to this project's own `cloak_aead_method_t` enum in `libcloak-common/include/cloak/crypto.h`, so the wire byte can be used as that enum directly, no translation table needed), `[29:37)` Unix timestamp (big-endian `int64`), `[37:41)` session ID (big-endian `uint32`), `[41]` flags (bit `0x01` = unordered), `[42:48)` reserved/unused.

**The ECDH + AEAD envelope.** `internal/server/auth.go`'s `decryptClientInfo` and `internal/server/TLS.go`'s `unmarshalClientHello`: the client's ephemeral X25519 public key is the ClientHello's `random` field (32 bytes); the server derives `shared_secret = ECDH(server_static_priv, client_random)`; the 64-byte ciphertext-with-tag is `ClientHello.session_id (32 bytes) || the X25519 key_share entry's data (32 bytes)` concatenated (`ctxTag := append(ch.sessionId, keyShare...)` in Go) -- i.e. exactly the two fields `cloak_clienthello_parse` (already merged) extracts as `session_id`/`x25519_key_share`. AEAD is AES-256-GCM (`internal/common/crypto.go`'s `AESGCMDecrypt`, key = 32-byte shared secret, nonce = the first 12 bytes of `random`, no AAD) -- this is exactly this project's own `CLOAK_AEAD_AES_256_GCM` (already implemented and tested in `libcloak-common`). X25519 itself (`internal/ecdh/curve25519.go`) is standard RFC 7748 X25519 with internal scalar clamping, the same standard this project's own `cloak_x25519_shared_secret` already implements -- confirmed interoperable, not just "should be the same algorithm," by an actual cross-implementation test: a Go program generated a real server/client X25519 keypair pair, AES-256-GCM-encrypted the exact 48-byte payload format above, and a C program linked against this repo's real `cloak_x25519_shared_secret`+`cloak_aead_open` decrypted it and recovered the byte-identical shared secret and plaintext. The same test also drove `cloak_aead_seal` the other direction (encrypting a session key with the same shared secret and a fixed nonce) and got byte-for-byte identical ciphertext to Go's own `crypto/aes`+`cipher.NewGCM`. This confirms full wire-level interop of the primitive crypto operations, not merely "both use a standard algorithm."

**The timestamp window.** `internal/server/state.go`: `timestampTolerance = 180 * time.Second`. `internal/server/auth.go`'s check is `clientTime.After(serverTime.Add(-tolerance)) && clientTime.Before(serverTime.Add(tolerance))` -- Go's `After`/`Before` are STRICT inequalities, so the boundary values (exactly -180s or +180s away) are REJECTED, not accepted. Verified directly: a C reimplementation of this check was tested at delta -179 (accept), -180 (reject), +179 (accept), +180 (reject) against the real decrypt path, all four matching Go's strict-inequality semantics exactly.

**The reply's wire shape.** `internal/server/TLSAux.go`'s `composeServerHello`/`addRecordLayer`/`composeReply`, cross-checked against `internal/client/TLS.go`'s `Handshake` (the consumer) and `internal/common/tls.go`'s `TLSConn.Read` (which strips the 5-byte record layer before the caller sees the buffer -- this resolves what would otherwise look like an off-by-5 discrepancy between the composer's byte offsets and the consumer's `buf[6:38]`/`buf[84:116]` extraction offsets: both are relative to the record-layer-STRIPPED handshake message, not the raw wire bytes). Verified by writing a Go program that faithfully reproduces `composeServerHello`/`addRecordLayer`/`composeReply` verbatim (with the one necessary adaptation: `common.CryptoRandRead`'s internal randomness for the key_share's 4 padding bytes is a testable parameter instead, since a real RNG can't produce a reproducible test vector) with a real, `cloak_aead_seal`-cross-verified encrypted session key, producing a complete expected 174-byte reply -- AND simulating the real client-side extraction logic (`buf[6:38]`+`buf[84:116]`, AES-GCM decrypt) against that reply to confirm it recovers the exact original session key, closing the loop end-to-end. A C implementation of the same composer, linked against this repo's real `cloak_aead_seal`, was then confirmed to produce this exact 174-byte sequence byte-for-byte.

**A discrepancy worth knowing about, deliberately NOT replicated:** `internal/server/TLS.go`'s `makeResponder` has a comment claiming `sessionKey` is used "as a seed" for choosing the fake certificate's length, implying per-session consistency. Tracing the actual code (`common.RandInt`, `internal/common/crypto.go`) shows this is false -- `RandInt` always calls `crypto/rand.Int` (the real OS CSPRNG), completely ignoring any session-derived seed; `common.WorldState.Rand` (the `io.Reader` actually threaded through) is likewise always `crypto/rand.Reader` in production (`internal/common/worldstate.go`). The comment describes an intention that was never implemented. This C port does not attempt to replicate the (nonexistent) session-seeded behavior -- `fake_cert`/`fake_cert_len` and `reply_nonce`/`pad4` are simply caller-supplied fresh randomness, matching what Go's code actually does, not what its comment claims.

**A real bug this verification caught in the plan author's own first draft:** an initial hand-transcription of several 32/48-byte hex test-vector literals had wrong lengths (one 47 bytes, one 35 bytes) from manual typing errors. Every hex literal below was instead generated programmatically (sequential byte patterns or real Go crypto output captured via `fmt.Printf`, never hand-typed into the vectors) specifically to eliminate this class of error, and every vector's byte length was asserted before use.

---

## File Structure

Two new files in the existing `libcloak-server` library (alongside the already-merged `clienthello_parse.{h,c}`):

- `libcloak-server/include/cloak/server_auth.h` / `libcloak-server/src/server_auth.c` -- `cloak_server_clientinfo_t`, `cloak_server_auth_decrypt`, `cloak_server_auth_compose_reply`, `cloak_server_auth_cert_lens`.
- `libcloak-server/include/cloak/replay_cache.h` / `libcloak-server/src/replay_cache.c` -- `cloak_replay_cache_t`, `cloak_replay_cache_init`/`_destroy`/`_check_and_insert`.
- `libcloak-server/tests/test_server_auth.c`, `libcloak-server/tests/test_replay_cache.c` -- new test executables.
- `libcloak-server/CMakeLists.txt` -- modify: add the two new `.c` files to the library, add `target_link_libraries(cloak-server PUBLIC cloak-common)` (the library itself now needs `libcloak-common`'s crypto -- unlike `clienthello_parse.c`, which didn't).
- `libcloak-server/tests/CMakeLists.txt` -- modify: register the two new test executables.

---

### Task 1: `server_auth` -- decrypt/authenticate incoming, compose outgoing reply

**Files:**
- Create: `libcloak-server/include/cloak/server_auth.h`
- Create: `libcloak-server/src/server_auth.c`
- Create: `libcloak-server/tests/test_server_auth.c`
- Modify: `libcloak-server/CMakeLists.txt`
- Modify: `libcloak-server/tests/CMakeLists.txt`

**Interfaces:**
- Produces: `cloak_server_clientinfo_t`, `cloak_server_auth_decrypt(...)`, `cloak_server_auth_compose_reply(...)`, `cloak_server_auth_cert_lens[]`, `CLOAK_SERVER_AUTH_CERT_LEN_COUNT`, `CLOAK_SERVER_AUTH_REPLY_MAX_BYTES`, `CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS`, `CLOAK_SERVER_AUTH_UNORDERED_FLAG`, `CLOAK_SERVER_AUTH_UID_LEN`, `CLOAK_SERVER_AUTH_PROXY_METHOD_LEN`.
- Consumes (from the already-merged `libcloak-common`): `cloak_x25519_shared_secret`, `cloak_aead_open`, `cloak_aead_seal`, `CLOAK_AEAD_AES_256_GCM`, `CLOAK_AEAD_KEY_LEN`, `CLOAK_AEAD_NONCE_LEN`, `CLOAK_X25519_KEY_LEN` (all from `cloak/crypto.h`).

- [ ] **Step 1: Write the header**

Create `libcloak-server/include/cloak/server_auth.h`:

```c
#ifndef CLOAK_SERVER_AUTH_H
#define CLOAK_SERVER_AUTH_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/crypto.h"

#define CLOAK_SERVER_AUTH_UID_LEN 16
#define CLOAK_SERVER_AUTH_PROXY_METHOD_LEN 12
#define CLOAK_SERVER_AUTH_UNORDERED_FLAG 0x01
#define CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS 180

typedef struct {
    uint8_t uid[CLOAK_SERVER_AUTH_UID_LEN];
    /* NUL-terminated. The wire field is a fixed 12-byte, NUL-padded ASCII
     * string; leading and trailing NUL padding is stripped (matching Go's
     * bytes.Trim(s, "\x00") exactly), so this is always
     * <= CLOAK_SERVER_AUTH_PROXY_METHOD_LEN bytes plus the terminator. */
    char proxy_method[CLOAK_SERVER_AUTH_PROXY_METHOD_LEN + 1];
    uint8_t encryption_method;
    uint32_t session_id;
    int unordered; /* 0 or 1 */
} cloak_server_clientinfo_t;

/* Authenticates one Cloak client connection attempt: derives the ECDH
 * shared secret (server_priv x the client's ephemeral public key, carried
 * in the ClientHello's `random` field), uses it to AES-256-GCM-decrypt the
 * 64-byte ciphertext (session_id_field || key_share_field -- exactly the
 * `session_id` and X25519 `key_share` fields cloak_clienthello_parse
 * extracts) into the 48-byte ClientInfo payload, and validates both AEAD
 * authentication and that the embedded timestamp is within
 * +/- CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS of now_unix.
 *
 * Wire layout of the 48-byte decrypted payload (matches Go Cloak's
 * authenticationPayload exactly, byte for byte):
 *   [0:16)  UID
 *   [16:28) proxy method (NUL-padded ASCII)
 *   [28]    encryption method (see cloak_aead_method_t -- the wire byte
 *           values are numerically identical to that enum)
 *   [29:37) Unix timestamp, big-endian int64
 *   [37:41) session ID, big-endian uint32
 *   [41]    flags (bit 0 = CLOAK_SERVER_AUTH_UNORDERED_FLAG)
 *   [42:48) reserved, ignored
 *
 * On success returns 0, populates *out, and writes the derived shared
 * secret to out_shared_secret (needed later by
 * cloak_server_auth_compose_reply to encrypt the session key -- the same
 * shared secret authenticates both directions of this handshake). On
 * failure (AEAD authentication failure, or timestamp outside the tolerance
 * window) returns -1 and leaves both outputs unspecified.
 *
 * This function does NOT check for replayed `random` values -- call
 * cloak_replay_cache_check_and_insert (cloak/replay_cache.h) on `random`
 * separately, BEFORE calling this function, mirroring Go Cloak's own
 * AuthFirstPacket (which checks replay first, against the raw
 * not-yet-authenticated random, then decrypts). */
int cloak_server_auth_decrypt(const uint8_t random[32], const uint8_t session_id_field[32],
                               const uint8_t key_share_field[32],
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
```

- [ ] **Step 2: Write the implementation**

Create `libcloak-server/src/server_auth.c`:

```c
#include "cloak/server_auth.h"
#include "cloak/crypto.h"

#include <string.h>

const size_t cloak_server_auth_cert_lens[CLOAK_SERVER_AUTH_CERT_LEN_COUNT] = {
    42, 27, 68, 59, 36, 44, 46,
};

static int64_t load_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return (int64_t)v;
}

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* Trims leading and trailing NUL bytes, matching Go's bytes.Trim(s, "\x00")
 * exactly. Writes a NUL-terminated result to out (capacity out_cap, which
 * must be > in_len). */
static void trim_nul_copy(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    size_t start = 0;
    while (start < in_len && in[start] == 0) {
        start++;
    }
    size_t end = in_len;
    while (end > start && in[end - 1] == 0) {
        end--;
    }
    size_t n = end - start;
    if (n >= out_cap) {
        n = out_cap - 1;
    }
    memcpy(out, in + start, n);
    out[n] = '\0';
}

int cloak_server_auth_decrypt(const uint8_t random[32], const uint8_t session_id_field[32],
                               const uint8_t key_share_field[32],
                               const uint8_t server_priv[CLOAK_X25519_KEY_LEN],
                               int64_t now_unix,
                               cloak_server_clientinfo_t *out,
                               uint8_t out_shared_secret[CLOAK_AEAD_KEY_LEN]) {
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    if (cloak_x25519_shared_secret(server_priv, random, shared_secret) != 0) {
        return -1;
    }

    uint8_t ciphertext[64];
    memcpy(ciphertext, session_id_field, 32);
    memcpy(ciphertext + 32, key_share_field, 32);

    uint8_t plaintext[48];
    size_t plaintext_len = 0;
    if (cloak_aead_open(CLOAK_AEAD_AES_256_GCM, shared_secret, random, NULL, 0,
                         ciphertext, sizeof(ciphertext), plaintext, &plaintext_len) != 0) {
        return -1;
    }
    if (plaintext_len != 48) {
        return -1;
    }

    int64_t timestamp = load_be64(plaintext + 29);
    int64_t delta = timestamp - now_unix;
    if (delta <= -CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS ||
        delta >= CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS) {
        return -1;
    }

    memcpy(out->uid, plaintext, CLOAK_SERVER_AUTH_UID_LEN);
    trim_nul_copy(plaintext + 16, CLOAK_SERVER_AUTH_PROXY_METHOD_LEN, out->proxy_method,
                  sizeof(out->proxy_method));
    out->encryption_method = plaintext[28];
    out->session_id = load_be32(plaintext + 37);
    out->unordered = (plaintext[41] & CLOAK_SERVER_AUTH_UNORDERED_FLAG) != 0;

    memcpy(out_shared_secret, shared_secret, CLOAK_AEAD_KEY_LEN);
    return 0;
}

static int cert_len_is_valid(size_t len) {
    for (size_t i = 0; i < CLOAK_SERVER_AUTH_CERT_LEN_COUNT; i++) {
        if (cloak_server_auth_cert_lens[i] == len) {
            return 1;
        }
    }
    return 0;
}

long cloak_server_auth_compose_reply(const uint8_t shared_secret[CLOAK_AEAD_KEY_LEN],
                                      const uint8_t session_key[CLOAK_AEAD_KEY_LEN],
                                      const uint8_t reply_nonce[CLOAK_AEAD_NONCE_LEN],
                                      const uint8_t client_session_id[32],
                                      const uint8_t pad4[4],
                                      const uint8_t *fake_cert, size_t fake_cert_len,
                                      uint8_t *out, size_t out_cap) {
    if (!cert_len_is_valid(fake_cert_len)) {
        return -1;
    }

    size_t sh_len = 122;
    size_t total_len = (5 + sh_len) + (5 + 1) + (5 + fake_cert_len);
    if (out_cap < total_len) {
        return -1;
    }

    uint8_t encrypted_session_key[48];
    size_t encrypted_len = 0;
    if (cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, shared_secret, reply_nonce, NULL, 0,
                         session_key, CLOAK_AEAD_KEY_LEN, encrypted_session_key, &encrypted_len) != 0) {
        return -1;
    }
    if (encrypted_len != 48) {
        return -1;
    }

    uint8_t *p = out;

    /* --- ServerHello record --- */
    uint8_t *rec = p;
    rec[0] = 0x16;
    rec[1] = 0x03;
    rec[2] = 0x03;
    store_be16(rec + 3, (uint16_t)sh_len);
    uint8_t *sh = rec + 5;

    sh[0] = 0x02; /* handshake type: ServerHello */
    sh[1] = 0x00;
    sh[2] = 0x00;
    sh[3] = 0x76; /* length = 118 */
    sh[4] = 0x03;
    sh[5] = 0x03; /* version */

    memcpy(sh + 6, reply_nonce, CLOAK_AEAD_NONCE_LEN);            /* random[0:12) */
    memcpy(sh + 6 + 12, encrypted_session_key, 20);               /* random[12:32) */

    sh[38] = 0x20; /* session_id length = 32 */
    memcpy(sh + 39, client_session_id, 32);

    sh[71] = 0x13;
    sh[72] = 0x02; /* cipher suite TLS_AES_256_GCM_SHA384 */
    sh[73] = 0x00; /* compression method */
    store_be16(sh + 74, 0x002e); /* extensions length = 46 */

    store_be16(sh + 76, 0x0033); /* key_share ext type */
    store_be16(sh + 78, 0x0024); /* ext data length = 36 */
    store_be16(sh + 80, 0x001d); /* group X25519 */
    store_be16(sh + 82, 0x0020); /* key exchange length = 32 */
    memcpy(sh + 84, encrypted_session_key + 20, 28);              /* ciphertext[20:48) */
    memcpy(sh + 84 + 28, pad4, 4);                                 /* [112:116) */

    store_be16(sh + 116, 0x002b); /* supported_versions ext type */
    store_be16(sh + 118, 0x0002); /* ext data length = 2 */
    sh[120] = 0x03;
    sh[121] = 0x04; /* TLS 1.3 */

    p += 5 + sh_len;

    /* --- ChangeCipherSpec record --- */
    p[0] = 0x14;
    p[1] = 0x03;
    p[2] = 0x03;
    store_be16(p + 3, 1);
    p[5] = 0x01;
    p += 6;

    /* --- fake Certificate (ApplicationData) record --- */
    p[0] = 0x17;
    p[1] = 0x03;
    p[2] = 0x03;
    store_be16(p + 3, (uint16_t)fake_cert_len);
    memcpy(p + 5, fake_cert, fake_cert_len);
    p += 5 + fake_cert_len;

    return (long)(p - out);
}
```

- [ ] **Step 3: Write the tests**

Create `libcloak-server/tests/test_server_auth.c`. This exercises both functions against the exact, real-crypto-verified test vectors from the Provenance section:

```c
#include "cloak/server_auth.h"
#include "cloak/crypto.h"
#include "test_framework.h"

#include <string.h>
#include <stdio.h>

static size_t hex_decode(const char *hex, uint8_t *out) {
    size_t n = 0;
    size_t hlen = strlen(hex);
    for (size_t i = 0; i + 1 < hlen; i += 2) {
        unsigned int b;
        sscanf(hex + i, "%2x", &b);
        out[n++] = (uint8_t)b;
    }
    return n;
}

/* All vectors below were generated by a Go program using real X25519/AES-256-GCM
 * (golang.org/x/crypto/curve25519, crypto/aes, cipher.NewGCM) and cross-verified
 * against this project's own cloak_x25519_shared_secret/cloak_aead_open/
 * cloak_aead_seal before being written here -- see the plan's Provenance section. */
static const char *SERVER_PRIV_HEX = "25857d6ad7bc967ecb51af16ec15b935bfe3770993acbffe22827bfb6c16bbbd";
static const char *CLIENT_PUB_RANDOM_HEX = "30f47e7ebd1e40e0f69cb739489db3537567983d112c815d6c0a270cec5a7071";
static const char *EXPECTED_SHARED_SECRET_HEX = "6c88df40f5ca673aa30d56850ca3b4f9de2fc7c89de5eb1d2f7cf17fcad43512";
static const char *SESSION_ID_FIELD_HEX = "1d7d86d906f9826efa3c430158e7f824a5044be1f6e76133fe87b2ba98587fef";
static const char *KEY_SHARE_FIELD_HEX = "56e3210d8f44e4a2926bb7d8c3df40eb003b017b075fd6a752e7bb57fb40e9a9";

static const char *SESSION_KEY_HEX = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
static const char *REPLY_NONCE_HEX = "0102030405060708090a0b0c";
static const char *CLIENT_ECHOED_SESSION_ID_HEX = "0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c";
static const char *PAD4_HEX = "2d2e2f30";
static const char *CERT_HEX = "3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051525354";
static const char *EXPECTED_REPLY_HEX =
    "160303007a0200007603030102030405060708090a0b0cd8d8c60aba318b6015f1799a4c6bcad999fc3d84200d0e0f10111213141516171819"
    "1a1b1c1d1e1f202122232425262728292a2b2c130200002e00330024001d002028cdcb21df410ea8d8abefb79f8fc1338f56ba0072696a8ce8"
    "8cf5272d2e2f30002b0002030414030300010117030300243132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505"
    "1525354";

static uint8_t g_server_priv[32];
static uint8_t g_client_pub_random[32];
static uint8_t g_session_id_field[32];
static uint8_t g_key_share_field[32];
static uint8_t g_expected_shared_secret[32];

static void load_shared_vectors(void) {
    hex_decode(SERVER_PRIV_HEX, g_server_priv);
    hex_decode(CLIENT_PUB_RANDOM_HEX, g_client_pub_random);
    hex_decode(SESSION_ID_FIELD_HEX, g_session_id_field);
    hex_decode(KEY_SHARE_FIELD_HEX, g_key_share_field);
    hex_decode(EXPECTED_SHARED_SECRET_HEX, g_expected_shared_secret);
}

/* Embedded timestamp in this vector's plaintext is exactly 1799999999
 * (verified during vector generation); NOW_EXACT has delta 0. */
#define NOW_EXACT 1799999999LL

static void test_decrypt_matches_real_go_vector(void) {
    load_shared_vectors();
    cloak_server_clientinfo_t info;
    uint8_t shared_secret[32];
    int rc = cloak_server_auth_decrypt(g_client_pub_random, g_session_id_field, g_key_share_field,
                                        g_server_priv, NOW_EXACT, &info, shared_secret);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_MEM_EQ(shared_secret, g_expected_shared_secret, 32);

    uint8_t expected_uid[16];
    hex_decode("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", expected_uid);
    ASSERT_MEM_EQ(info.uid, expected_uid, 16);
    ASSERT_TRUE(strcmp(info.proxy_method, "shadowsocks") == 0);
    ASSERT_EQ_INT(info.encryption_method, 1);
    ASSERT_EQ_INT(info.session_id, 0x12345678);
    ASSERT_TRUE(info.unordered);
}

static void test_timestamp_window_is_strict(void) {
    load_shared_vectors();
    cloak_server_clientinfo_t info;
    uint8_t shared_secret[32];

    ASSERT_EQ_INT(cloak_server_auth_decrypt(g_client_pub_random, g_session_id_field, g_key_share_field,
                                             g_server_priv, NOW_EXACT - 179, &info, shared_secret), 0);
    ASSERT_EQ_INT(cloak_server_auth_decrypt(g_client_pub_random, g_session_id_field, g_key_share_field,
                                             g_server_priv, NOW_EXACT - 180, &info, shared_secret), -1);
    ASSERT_EQ_INT(cloak_server_auth_decrypt(g_client_pub_random, g_session_id_field, g_key_share_field,
                                             g_server_priv, NOW_EXACT + 179, &info, shared_secret), 0);
    ASSERT_EQ_INT(cloak_server_auth_decrypt(g_client_pub_random, g_session_id_field, g_key_share_field,
                                             g_server_priv, NOW_EXACT + 180, &info, shared_secret), -1);
}

static void test_tampered_key_share_rejected(void) {
    load_shared_vectors();
    uint8_t tampered[32];
    memcpy(tampered, g_key_share_field, 32);
    tampered[0] ^= 0xff;

    cloak_server_clientinfo_t info;
    uint8_t shared_secret[32];
    int rc = cloak_server_auth_decrypt(g_client_pub_random, g_session_id_field, tampered,
                                        g_server_priv, NOW_EXACT, &info, shared_secret);
    ASSERT_EQ_INT(rc, -1);
}

static void test_tampered_session_id_rejected(void) {
    load_shared_vectors();
    uint8_t tampered[32];
    memcpy(tampered, g_session_id_field, 32);
    tampered[31] ^= 0x01;

    cloak_server_clientinfo_t info;
    uint8_t shared_secret[32];
    int rc = cloak_server_auth_decrypt(g_client_pub_random, tampered, g_key_share_field,
                                        g_server_priv, NOW_EXACT, &info, shared_secret);
    ASSERT_EQ_INT(rc, -1);
}

static void test_wrong_server_key_rejected(void) {
    load_shared_vectors();
    uint8_t wrong_priv[32];
    memset(wrong_priv, 0x42, 32);

    cloak_server_clientinfo_t info;
    uint8_t shared_secret[32];
    int rc = cloak_server_auth_decrypt(g_client_pub_random, g_session_id_field, g_key_share_field,
                                        wrong_priv, NOW_EXACT, &info, shared_secret);
    ASSERT_EQ_INT(rc, -1);
}

static void test_compose_reply_matches_real_go_vector(void) {
    uint8_t session_key[32], reply_nonce[12], client_session_id[32], pad4[4], cert[36];
    hex_decode(SESSION_KEY_HEX, session_key);
    hex_decode(REPLY_NONCE_HEX, reply_nonce);
    hex_decode(CLIENT_ECHOED_SESSION_ID_HEX, client_session_id);
    hex_decode(PAD4_HEX, pad4);
    hex_decode(CERT_HEX, cert);

    uint8_t expected_reply[256];
    size_t expected_len = hex_decode(EXPECTED_REPLY_HEX, expected_reply);
    ASSERT_EQ_INT(expected_len, 174);

    load_shared_vectors(); /* for g_expected_shared_secret */
    uint8_t out[CLOAK_SERVER_AUTH_REPLY_MAX_BYTES];
    long n = cloak_server_auth_compose_reply(g_expected_shared_secret, session_key, reply_nonce,
                                              client_session_id, pad4, cert, sizeof(cert), out, sizeof(out));
    ASSERT_EQ_INT(n, 174);
    ASSERT_MEM_EQ(out, expected_reply, 174);
}

static void test_compose_reply_rejects_invalid_cert_len(void) {
    load_shared_vectors();
    uint8_t session_key[32] = {0};
    uint8_t reply_nonce[12] = {0};
    uint8_t client_session_id[32] = {0};
    uint8_t pad4[4] = {0};
    uint8_t cert[10] = {0}; /* 10 is not in cloak_server_auth_cert_lens */

    uint8_t out[CLOAK_SERVER_AUTH_REPLY_MAX_BYTES];
    long n = cloak_server_auth_compose_reply(g_expected_shared_secret, session_key, reply_nonce,
                                              client_session_id, pad4, cert, sizeof(cert), out, sizeof(out));
    ASSERT_EQ_INT(n, -1);
}

static void test_compose_reply_rejects_undersized_buffer(void) {
    load_shared_vectors();
    uint8_t session_key[32] = {0};
    uint8_t reply_nonce[12] = {0};
    uint8_t client_session_id[32] = {0};
    uint8_t pad4[4] = {0};
    uint8_t cert[27] = {0}; /* valid length */

    uint8_t out[10]; /* too small for any valid reply (min total is 5+122+5+1+5+27=165) */
    long n = cloak_server_auth_compose_reply(g_expected_shared_secret, session_key, reply_nonce,
                                              client_session_id, pad4, cert, sizeof(cert), out, sizeof(out));
    ASSERT_EQ_INT(n, -1);
}

static void test_compose_reply_all_cert_lens_succeed(void) {
    load_shared_vectors();
    uint8_t session_key[32] = {0};
    uint8_t reply_nonce[12] = {0};
    uint8_t client_session_id[32] = {0};
    uint8_t pad4[4] = {0};
    uint8_t cert[68] = {0}; /* max cert len */

    for (size_t i = 0; i < CLOAK_SERVER_AUTH_CERT_LEN_COUNT; i++) {
        size_t cert_len = cloak_server_auth_cert_lens[i];
        uint8_t out[CLOAK_SERVER_AUTH_REPLY_MAX_BYTES];
        long n = cloak_server_auth_compose_reply(g_expected_shared_secret, session_key, reply_nonce,
                                                  client_session_id, pad4, cert, cert_len, out, sizeof(out));
        ASSERT_TRUE(n > 0);
        ASSERT_EQ_INT((size_t)n, 5 + 122 + 5 + 1 + 5 + cert_len);
        ASSERT_TRUE((size_t)n <= CLOAK_SERVER_AUTH_REPLY_MAX_BYTES);
    }
}

TEST_MAIN_BEGIN()
    test_decrypt_matches_real_go_vector();
    test_timestamp_window_is_strict();
    test_tampered_key_share_rejected();
    test_tampered_session_id_rejected();
    test_wrong_server_key_rejected();
    test_compose_reply_matches_real_go_vector();
    test_compose_reply_rejects_invalid_cert_len();
    test_compose_reply_rejects_undersized_buffer();
    test_compose_reply_all_cert_lens_succeed();
TEST_MAIN_END()
```

- [ ] **Step 4: Update the library's CMakeLists.txt**

Modify `libcloak-server/CMakeLists.txt` to:

```cmake
add_library(cloak-server STATIC
    src/clienthello_parse.c
    src/server_auth.c
)

target_include_directories(cloak-server PUBLIC include)
target_link_libraries(cloak-server PUBLIC cloak-common)

add_subdirectory(tests)
```

(`target_link_libraries(cloak-server PUBLIC cloak-common)` is new here -- `clienthello_parse.c` never needed it, but `server_auth.c` calls `cloak_x25519_shared_secret`/`cloak_aead_open`/`cloak_aead_seal` directly, so the library itself now has a real dependency on `libcloak-common`.)

- [ ] **Step 5: Register the new test**

Modify `libcloak-server/tests/CMakeLists.txt` to add:

```cmake
add_executable(test_server_auth test_server_auth.c)
target_include_directories(test_server_auth PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_server_auth PRIVATE cloak-server)
add_test(NAME test_server_auth COMMAND test_server_auth)
```

(`cloak-server` alone is enough here -- it now PUBLIC-links `cloak-common`, so `cloak_x25519_shared_secret`/`cloak_aead_open`/`cloak_aead_seal` and their headers come along transitively, the same pattern `test_clienthello_parse` already uses via `cloak-server`.)

- [ ] **Step 6: Build and test in Docker**

```bash
docker build -q -f Dockerfile.dev -t cloak-c-dev .
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "rm -rf build && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure"
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build-asan -DCMAKE_C_FLAGS='-fsanitize=address,undefined -g' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' && cmake --build build-asan && ctest --test-dir build-asan --output-on-failure"
```

Expected: all tests pass (plain and ASan/UBSan), zero compiler warnings, including `test_server_auth`'s byte-exact matches against the real-crypto-verified vectors.

- [ ] **Step 7: Commit**

```bash
git add libcloak-server/include/cloak/server_auth.h libcloak-server/src/server_auth.c \
        libcloak-server/tests/test_server_auth.c libcloak-server/CMakeLists.txt libcloak-server/tests/CMakeLists.txt
git commit -m "Add server_auth: decrypt/authenticate incoming ClientHello, compose TLS reply"
```

---

### Task 2: `replay_cache` -- bounded, single-threaded replay detection

**Files:**
- Create: `libcloak-server/include/cloak/replay_cache.h`
- Create: `libcloak-server/src/replay_cache.c`
- Create: `libcloak-server/tests/test_replay_cache.c`
- Modify: `libcloak-server/CMakeLists.txt`
- Modify: `libcloak-server/tests/CMakeLists.txt`

**Interfaces:**
- Produces: `cloak_replay_slot_t`, `cloak_replay_cache_t`, `cloak_replay_cache_init`, `cloak_replay_cache_destroy`, `cloak_replay_cache_check_and_insert`.
- Consumes: nothing from `libcloak-common` or Task 1 -- this module is fully standalone (only `<stddef.h>`/`<stdint.h>`/`<stdlib.h>`/`<string.h>`).

- [ ] **Step 1: Write the header**

Create `libcloak-server/include/cloak/replay_cache.h`:

```c
#ifndef CLOAK_REPLAY_CACHE_H
#define CLOAK_REPLAY_CACHE_H

#include <stddef.h>
#include <stdint.h>

/* A fixed-capacity, direct-mapped cache of recently-seen 32-byte values
 * (client ClientHello.random / auth ephemeral public keys), used to reject
 * replayed authentication attempts. Single-threaded (matches this project's
 * single-threaded epoll reactor design -- no locking).
 *
 * This is a DELIBERATE bounded-memory tradeoff, not a full replay-proof
 * set: it is direct-mapped (one slot per hash bucket, no chaining), so two
 * different keys that hash to the same slot within the same age window
 * will evict one another -- the older entry silently stops being tracked.
 * With 32 bytes of real entropy per key and a reasonably sized table, an
 * accidental collision between two legitimate clients is astronomically
 * unlikely; an attacker deliberately flooding collisions can at most cause
 * some replay-window entries to be forgotten early, which only weakens
 * (never strengthens) an attacker's ability to replay a key they don't
 * already possess a valid, not-yet-expired ciphertext for -- and the
 * timestamp window (CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS) bounds
 * how long a captured ciphertext remains replayable regardless of this
 * cache. This mirrors the "bounded hash set" design the project's spec
 * calls for. */
typedef struct {
    uint8_t key[32];
    int64_t inserted_at; /* 0 = empty slot (never used) */
} cloak_replay_slot_t;

typedef struct {
    cloak_replay_slot_t *slots;
    size_t capacity;
} cloak_replay_cache_t;

/* Allocates a zeroed table of `capacity` slots (capacity must be > 0).
 * Returns 0 on success, -1 on allocation failure. */
int cloak_replay_cache_init(cloak_replay_cache_t *cache, size_t capacity);

/* Frees the table. Safe to call on an already-destroyed (or never
 * successfully initialized) cache. */
void cloak_replay_cache_destroy(cloak_replay_cache_t *cache);

/* Looks up key's slot (hash(key) % capacity). If that slot currently holds
 * `key` itself AND its age (now_unix - inserted_at) is within
 * [0, age_limit_seconds), this is a replay: returns 1, WITHOUT updating the
 * slot (a replay does not refresh its own timestamp -- an attacker
 * resending the exact same ciphertext repeatedly should not be able to
 * keep extending its own window).
 *
 * Otherwise (slot empty, held a different key, or held the same key but
 * aged out) this is not a replay: stores key at its slot with
 * inserted_at = now_unix (overwriting whatever was there), and returns 0.
 *
 * now_unix going backwards between calls (a clock adjustment) is handled
 * safely: age is computed as now_unix - inserted_at and treated as
 * expired (not a replay) whenever it falls outside [0, age_limit_seconds),
 * which includes negative values from a clock that moved backwards. */
int cloak_replay_cache_check_and_insert(cloak_replay_cache_t *cache, const uint8_t key[32],
                                         int64_t now_unix, int64_t age_limit_seconds);

#endif
```

- [ ] **Step 2: Write the implementation**

Create `libcloak-server/src/replay_cache.c`:

```c
#include "cloak/replay_cache.h"

#include <stdlib.h>
#include <string.h>

int cloak_replay_cache_init(cloak_replay_cache_t *cache, size_t capacity) {
    if (capacity == 0) {
        return -1;
    }
    cloak_replay_slot_t *slots = (cloak_replay_slot_t *)calloc(capacity, sizeof(cloak_replay_slot_t));
    if (slots == NULL) {
        return -1;
    }
    cache->slots = slots;
    cache->capacity = capacity;
    return 0;
}

void cloak_replay_cache_destroy(cloak_replay_cache_t *cache) {
    free(cache->slots);
    cache->slots = NULL;
    cache->capacity = 0;
}

/* FNV-1a, 64-bit. Not a cryptographic hash -- doesn't need to be: keys are
 * always 32 bytes of real entropy, and this is a fixed-capacity direct-map
 * bucket selector, not a security boundary in itself (see the header's
 * doc comment on the collision tradeoff). */
static uint64_t fnv1a(const uint8_t *data, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

int cloak_replay_cache_check_and_insert(cloak_replay_cache_t *cache, const uint8_t key[32],
                                         int64_t now_unix, int64_t age_limit_seconds) {
    size_t slot_idx = (size_t)(fnv1a(key, 32) % cache->capacity);
    cloak_replay_slot_t *slot = &cache->slots[slot_idx];

    if (slot->inserted_at != 0 && memcmp(slot->key, key, 32) == 0) {
        int64_t age = now_unix - slot->inserted_at;
        if (age >= 0 && age < age_limit_seconds) {
            return 1; /* replay -- do not refresh */
        }
    }

    memcpy(slot->key, key, 32);
    slot->inserted_at = now_unix;
    /* Zero is reserved as "empty"; a real Unix timestamp of exactly 0
     * (1970-01-01T00:00:00Z) is not a value this project's clock will ever
     * legitimately produce, so this ambiguity is intentionally accepted:
     * an insert at now_unix == 0 will be indistinguishable from an empty
     * slot on the next lookup and can be immediately replayed. */
    return 0;
}
```

- [ ] **Step 3: Write the tests**

Create `libcloak-server/tests/test_replay_cache.c`:

```c
#include "cloak/replay_cache.h"
#include "test_framework.h"

#include <string.h>

static void fill_key(uint8_t key[32], uint32_t seed) {
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(seed >> (8 * (i % 4))) ^ (uint8_t)i;
    }
}

static void test_insert_then_replay_then_ages_out(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 1024), 0);
    uint8_t k1[32];
    fill_key(k1, 1);

    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k1, 1000, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k1, 1001, 180), 1);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k1, 1179, 180), 1);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k1, 1180, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k1, 1181, 180), 1);

    cloak_replay_cache_destroy(&cache);
}

static void test_distinct_keys_dont_interfere(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 1024), 0);
    uint8_t k2[32], k3[32];
    fill_key(k2, 2);
    fill_key(k3, 3);

    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k2, 5000, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k3, 5000, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k2, 5001, 180), 1);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k3, 5001, 180), 1);

    cloak_replay_cache_destroy(&cache);
}

static void test_direct_mapped_collision_evicts(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 1), 0); /* capacity 1 forces every key into the same slot */
    uint8_t k2[32], k3[32];
    fill_key(k2, 2);
    fill_key(k3, 3);

    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k2, 100, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k3, 101, 180), 0); /* k3 evicts k2 */
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k2, 102, 180), 0); /* k2 no longer tracked -- not a replay */
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k3, 103, 180), 0); /* k3 was itself evicted just above */
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k3, 104, 180), 1); /* k3 is now in the slot, unevicted since */

    cloak_replay_cache_destroy(&cache);
}

static void test_backwards_clock_not_a_replay(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 1024), 0);
    uint8_t k4[32];
    fill_key(k4, 4);

    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k4, 10000, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k4, 9999, 180), 0); /* clock moved backwards: treated as expired */

    cloak_replay_cache_destroy(&cache);
}

static void test_stress_low_collision_rate(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 65536), 0);

    int replay_hits = 0;
    const int n = 50000;
    for (int i = 0; i < n; i++) {
        uint8_t key[32];
        fill_key(key, (uint32_t)(i * 2654435761u)); /* Knuth multiplicative hash: decent spread */
        int rc1 = cloak_replay_cache_check_and_insert(&cache, key, 1000000 + i, 180);
        int rc2 = cloak_replay_cache_check_and_insert(&cache, key, 1000000 + i, 180);
        ASSERT_EQ_INT(rc1, 0);
        if (rc2 == 1) {
            replay_hits++;
        }
    }
    ASSERT_TRUE(replay_hits > n * 9 / 10);

    cloak_replay_cache_destroy(&cache);
}

static void test_init_rejects_zero_capacity(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 0), -1);
}

TEST_MAIN_BEGIN()
    test_insert_then_replay_then_ages_out();
    test_distinct_keys_dont_interfere();
    test_direct_mapped_collision_evicts();
    test_backwards_clock_not_a_replay();
    test_stress_low_collision_rate();
    test_init_rejects_zero_capacity();
TEST_MAIN_END()
```

- [ ] **Step 4: Update the library's CMakeLists.txt**

Modify `libcloak-server/CMakeLists.txt` to add the new source file:

```cmake
add_library(cloak-server STATIC
    src/clienthello_parse.c
    src/server_auth.c
    src/replay_cache.c
)

target_include_directories(cloak-server PUBLIC include)
target_link_libraries(cloak-server PUBLIC cloak-common)

add_subdirectory(tests)
```

- [ ] **Step 5: Register the new test**

Modify `libcloak-server/tests/CMakeLists.txt` to add:

```cmake
add_executable(test_replay_cache test_replay_cache.c)
target_include_directories(test_replay_cache PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_replay_cache PRIVATE cloak-server)
add_test(NAME test_replay_cache COMMAND test_replay_cache)
```

- [ ] **Step 6: Build and test in Docker**

```bash
docker build -q -f Dockerfile.dev -t cloak-c-dev .
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "rm -rf build && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure"
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build-asan -DCMAKE_C_FLAGS='-fsanitize=address,undefined -g' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' && cmake --build build-asan && ctest --test-dir build-asan --output-on-failure"
```

Expected: all tests pass (plain and ASan/UBSan), zero compiler warnings, including the 50000-entry stress test with a >90% no-collision rate.

- [ ] **Step 7: Commit**

```bash
git add libcloak-server/include/cloak/replay_cache.h libcloak-server/src/replay_cache.c \
        libcloak-server/tests/test_replay_cache.c libcloak-server/CMakeLists.txt libcloak-server/tests/CMakeLists.txt
git commit -m "Add replay_cache: bounded, single-threaded replay detection"
```

---

## What comes after this plan

Not started here, deliberately out of scope:

- **The server dispatcher's connection state machine** (design spec section 7): sniffing the first byte to distinguish TLS from WebSocket traffic, buffering incrementally under epoll readiness, calling `cloak_clienthello_parse` + `cloak_replay_cache_check_and_insert` + `cloak_server_auth_decrypt` + `cloak_server_auth_compose_reply` in sequence on a real connection, and `goWeb()` redirect-on-fail (non-blocking dial to `RedirAddr`, forward the buffered first packet, splice bidirectionally) -- this needs the epoll reactor (already built) wired up to a real per-connection state machine, which this plan does not build.
- **`libcloak-mux`'s session/stream/switchboard** (design spec section 6): `session_t`, `stream_t`, the switchboard's `uniformSpread` distribution -- needed before a successfully authenticated connection can actually be attached to a session and relayed anywhere. Once a session exists, `MakeObfuscator`-equivalent construction from `cloak_server_clientinfo_t.encryption_method` and the session key chosen at `cloak_server_auth_compose_reply` time slots directly into the already-built `libcloak-mux` frame codec (`cloak_obfuscator_t`).
- **User management / admin API / SQLite** (design spec section 8): `sta.ProxyBook` lookup, per-UID rate limiting, the admin HTTP-over-mux API -- all downstream of a successful auth, not part of the auth core itself.
- **WebSocket/CDN transport parity** (design spec section 9): Go's `internal/server/websocket.go` reuses this exact same `authFragments`/`decryptClientInfo` pipeline (confirmed during this plan's research) with a different `processFirstPacket` front-end -- so `cloak_server_auth_decrypt` and `cloak_replay_cache_check_and_insert` are already transport-agnostic and reusable for a future WebSocket parser, once one exists. Not built here.

## Self-Review

**Spec coverage:** The spec's ask ("Server computes the ECDH shared secret with its static private key, decrypts, checks the timestamp window, and checks a replay cache keyed by random") is fully covered: Task 1 does ECDH+decrypt+timestamp, Task 2 does the replay cache, and Task 1's `compose_reply` covers the server's half of the handshake response the spec's wire-protocol section implies is needed for the client to derive its session key.

**Placeholder scan:** No TBD/TODO-style steps; every step has complete, already-verified code.

**Type consistency:** `cloak_server_clientinfo_t`, `cloak_server_auth_decrypt`, `cloak_server_auth_compose_reply` are defined once (Task 1, Step 1) and used identically in the implementation (Step 2) and tests (Step 3). `cloak_replay_cache_t` and its three functions are defined once (Task 2, Step 1) and used identically thereafter. No cross-task signature drift (Task 2 doesn't depend on Task 1's types or vice versa -- confirmed independent, matching the file structure's stated boundary).
