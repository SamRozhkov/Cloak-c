#include "cloak/server_auth.h"
/* cloak_random_bytes, for cloak_server_auth_compose_ws_reply's nonce --
 * the one thing in this file that is not a pure function of its
 * arguments. See that function's own header comment for why the nonce is
 * drawn here rather than by the caller. */
#include "cloak/common.h"
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

int cloak_server_auth_decrypt(const uint8_t random[32],
                               const uint8_t *session_id_field, size_t session_id_field_len,
                               const uint8_t *key_share_field,
                               const uint8_t server_priv[CLOAK_X25519_KEY_LEN],
                               int64_t now_unix,
                               cloak_server_clientinfo_t *out,
                               uint8_t out_shared_secret[CLOAK_AEAD_KEY_LEN]) {
    if (session_id_field == NULL || session_id_field_len != 32 || key_share_field == NULL) {
        return -1;
    }

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
    int64_t lower = (now_unix > INT64_MIN + CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS)
                         ? now_unix - CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS
                         : INT64_MIN;
    int64_t upper = (now_unix < INT64_MAX - CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS)
                         ? now_unix + CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS
                         : INT64_MAX;
    if (timestamp <= lower || timestamp >= upper) {
        return -1;
    }

    memcpy(out->uid, plaintext, CLOAK_SERVER_AUTH_UID_LEN);
    trim_nul_copy(plaintext + 16, CLOAK_SERVER_AUTH_PROXY_METHOD_LEN, out->proxy_method,
                  sizeof(out->proxy_method));
    out->encryption_method = plaintext[28];
    out->session_id = load_be32(plaintext + 37);
    out->unordered = (plaintext[41] & CLOAK_SERVER_AUTH_UNORDERED_FLAG) != 0;
    /* NOT a wire field: there is no admin bit in the payload and there
     * must not be one -- an attacker would set it. It is the dispatcher's
     * verdict about the UID this function just decrypted, and it is
     * written here only so that no caller can ever read it uninitialized:
     * this function assigns every other field rather than zeroing *out,
     * so an unassigned field would be whatever the caller's stack held.
     * See cloak/server_auth.h's own comment on the field. */
    out->is_admin = 0;

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

int cloak_server_auth_compose_ws_reply(uint8_t out[CLOAK_SERVER_AUTH_WS_REPLY_LEN],
                                        const uint8_t session_key[CLOAK_AEAD_KEY_LEN],
                                        const uint8_t shared_secret[CLOAK_AEAD_KEY_LEN]) {
    if (out == NULL || session_key == NULL || shared_secret == NULL) {
        return -1;
    }

    /* SEALED INTO A LOCAL, THEN COPIED, AND THE ORDER IS THE WHOLE
     * POINT -- this is the shape cloak_server_auth_compose_reply already
     * uses (its own encrypted_session_key[48]) and the reason it uses
     * it.
     *
     * cloak_aead_seal TAKES NO OUTPUT CAPACITY (cloak/crypto.h): it
     * writes whatever the cipher produces into whatever buffer it is
     * handed, and reports the count afterwards. So a length check after
     * the call can only ever DETECT a mismatch -- the write has already
     * happened. An earlier revision of this function sealed straight
     * into out + 12 and then compared, with a comment claiming it
     * prevented an overflow of the caller's 60 bytes. It could not: it
     * would have detected that overflow, from inside the wreckage.
     *
     * What this shape actually buys, stated exactly, because the
     * previous comment's overclaim is the defect being fixed:
     *   - The buffer any surprise lands in is OURS, one stack frame
     *     wide, not the caller's cloak_dispatch_conn_t::reply -- the
     *     same blast-radius argument that makes the sibling's local
     *     correct.
     *   - The only write into the caller's buffer is a memcpy of a
     *     COMPILE-TIME length, reached only after sealed_len has been
     *     checked, so the caller's 60 bytes cannot be overrun by a
     *     runtime value at all.
     *   - A refusal leaves `out` BYTE-FOR-BYTE UNTOUCHED, which is now
     *     part of this function's contract (see the header) rather than
     *     an accident. The old shape handed a caller that got -1 a
     *     buffer already full of plausible-looking reply bytes.
     *
     * The nonce is a local for the same reason and is copied with the
     * rest, so "the nonce in out is the nonce that sealed this" stays
     * one assignment rather than two. */
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    cloak_random_bytes(nonce, sizeof(nonce));

    uint8_t sealed[CLOAK_SERVER_AUTH_WS_REPLY_LEN - CLOAK_AEAD_NONCE_LEN];
    size_t sealed_len = 0;
    if (cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, shared_secret, nonce, NULL, 0, session_key,
                        CLOAK_AEAD_KEY_LEN, sealed, &sealed_len) != 0) {
        return -1;
    }
    /* Not defensive decoration: this is what gates the memcpy below.
     * AES-256-GCM sealing 32 bytes always yields 48, so no input reaches
     * it -- libcloak-server/tests/test_server_auth.c reaches it by
     * interposing on cloak_aead_seal through -Wl,--wrap, and asserts
     * both halves of what it promises (refusal, and `out` untouched). */
    if (sealed_len != sizeof(sealed)) {
        return -1;
    }

    memcpy(out, nonce, sizeof(nonce));
    memcpy(out + CLOAK_AEAD_NONCE_LEN, sealed, sizeof(sealed));
    return 0;
}
