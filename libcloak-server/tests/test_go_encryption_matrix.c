#define _POSIX_C_SOURCE 200809L
/* memmem, which case 3 uses to ask whether the application's own bytes
 * are lying in the open on the wire. It is a GNU extension, not POSIX;
 * this file is built only in this project's glibc development image. */
#define _GNU_SOURCE

/* ALL FOUR ENCRYPTION METHODS, IN BOTH ROLES, AGAINST GO'S OWN BINARIES --
 * AND THE ASSERTION THAT SAYS WHICH METHOD ACTUALLY SEALED THE FRAMES.
 *
 * WHY THIS FILE EXISTS. Until it, exactly ONE of Cloak's four encryption
 * methods had ever met an implementation nobody here wrote: aes-256-gcm,
 * the default, which test_go_interop.c and test_go_clienthello_matrix.c
 * both configure. `aes-128-gcm`, `chacha20-poly1305` and `plain` were
 * exercised only between two copies of our own code.
 *
 * That is the exact shape of the defect module 8 found: cloak_frame_obfuscate
 * passed two header bytes as AES-GCM associated data where Go passes nil.
 * The handshake succeeded, the session key was correct, and every data
 * frame was silently dropped -- invisible for five modules because both
 * ends of every test were ours, and a round trip between two copies of one
 * mistake always agrees. The per-method surface has the same property and
 * more of it: key material is handled DIFFERENTLY per method --
 * cloak/crypto.h states that CLOAK_AEAD_AES_128_GCM "only consumes the
 * first 16 bytes of key; bytes 16-31 are ignored entirely" -- so a port
 * that took, say, the LAST 16 bytes instead would interoperate perfectly
 * with itself and with nothing else alive.
 *
 * WHAT IS HERE, and what each part is for:
 *
 *   1. THE MATRIX. Four methods x two roles = eight end-to-end sessions,
 *      each moving 128 KiB in both directions through an upstream that
 *      XORs rather than echoes, compared byte for byte. BOTH ROLES,
 *      because they are not symmetric: our ck-client against Go's
 *      ck-server proves our ENCRYPT path is one Go can open, and Go's
 *      ck-client against our ck-server proves our DECRYPT path can open
 *      foreign ciphertext -- which is the side a key-length or nonce
 *      divergence would actually bite. (Unlike the ClientHello matrix,
 *      which could only run one role because Go's client cannot emit our
 *      templates, nothing here is asymmetric: a Go client takes any of
 *      the four methods from its own configuration.)
 *
 *   2. WHICH METHOD IS ACTUALLY IN USE, read off the wire. This is the
 *      case that decides whether case 1 is worth anything, and it is
 *      described at length above wire_method_of_frame below.
 *
 *   3. WHAT `plain` MEANS ON THE WIRE, asserted rather than assumed --
 *      see test_plain_is_cleartext_on_the_wire.
 *
 *   4. A NEGATIVE CONTROL PER METHOD, with the proof that it bites for
 *      the right reason -- see test_one_flipped_bit_per_method.
 *
 * WHAT THIS FILE DOES NOT COVER. Unordered (datagram) mode, which
 * test_unordered_proof.c owns; the CDN/WebSocket leg, which
 * test_ws_interop.c owns; and ClientHello templates other than chrome,
 * which test_go_clienthello_matrix.c owns. It says nothing about the
 * SERVER's choice of method either, because neither implementation has
 * one: both take the method from byte 28 of the client's authentication
 * payload (see auth_method_byte below).
 *
 * Every wait is bounded by CLOCK_MONOTONIC, every port is ephemeral, and
 * the oracle binaries are checked for before any case runs. */

#include "go_oracle_harness.h"

/* HEADERS, NOT CODE. CLOAK_FRAME_HEADER_LEN and CLOAK_CONN_MAX_FRAME_LEN
 * are the wire format's own constants and are taken from the port's
 * headers so that a change to either shows up here as a compile-time
 * change rather than as a silently wrong literal. What is NOT taken from
 * the port is the frame logic: wire_method_of_frame below re-implements
 * the header decrypt and the payload open rather than calling
 * cloak_frame_deobfuscate, deliberately, because an assertion that calls
 * the code it is judging cannot catch that code agreeing with itself --
 * which is precisely how the AAD defect survived five modules. */
#include "cloak/conn.h"
#include "cloak/frame.h"

/* ------------------------------------------------------------------ */
/* The four methods                                                    */
/* ------------------------------------------------------------------ */

/* THE CONFIGURATION SPELLINGS ARE SHARED BY BOTH IMPLEMENTATIONS, and
 * this table pins the ones this file measured both binaries accepting.
 * Ours are libcloak-common/src/config_client.c's parse_encryption_method;
 * Go's are internal/client/state.go's ParseConfig switch (read, not
 * measured -- the image ships only the two built binaries, not the source
 * tree they came from; what IS measured here is that go-ck-client starts
 * and completes a session under each of these four strings, which is the
 * property that matters).
 *
 * `enc` is the value this port assigns the method in cloak_aead_method_t,
 * and it is ALSO the value that must appear as byte 28 of the
 * authentication payload -- those are the same wire constant, which is
 * why auth_method_byte can compare against it. */
typedef struct {
    const char *name; /* the EncryptionMethod string in both configurations */
    cloak_aead_method_t enc;
} method_t;

static const method_t methods[] = {
    {"aes-256-gcm", CLOAK_AEAD_AES_256_GCM},
    {"aes-128-gcm", CLOAK_AEAD_AES_128_GCM},
    {"chacha20-poly1305", CLOAK_AEAD_CHACHA20_POLY1305},
    {"plain", CLOAK_AEAD_NONE},
};

#define NMETHODS (sizeof(methods) / sizeof(methods[0]))

/* The three methods that actually authenticate. Kept separate from
 * `methods` because "which method sealed this frame" is answered by
 * trying to OPEN it under each of them, and CLOAK_AEAD_NONE opens
 * anything (there is no tag to check), so including it would turn the
 * discriminator into a constant. */
static const cloak_aead_method_t aead_methods[] = {
    CLOAK_AEAD_AES_256_GCM,
    CLOAK_AEAD_AES_128_GCM,
    CLOAK_AEAD_CHACHA20_POLY1305,
};

#define NAEAD (sizeof(aead_methods) / sizeof(aead_methods[0]))

static const char *enc_name(cloak_aead_method_t m) {
    for (size_t i = 0; i < NMETHODS; i++) {
        if (methods[i].enc == m) {
            return methods[i].name;
        }
    }
    return "?";
}

/* ------------------------------------------------------------------ */
/* Recovering the session key from the wire                             */
/* ------------------------------------------------------------------ */

/* THE SESSION KEY, TAKEN OFF THE WIRE WITH THE SERVER PRIVATE KEY THIS
 * TEST GENERATED THE CONFIGURATION WITH -- not asked of either binary.
 *
 * Cloak's reply is a ServerHello record whose "random" and whose
 * key_share extension carry one 48-byte AES-256-GCM ciphertext split
 * across two places, sealed to the same X25519 shared secret the
 * ClientHello's auth payload was sealed to, containing the 32-byte
 * session key the server chose. The split and every offset below are
 * cloak_server_auth_compose_reply's (libcloak-server/src/server_auth.c),
 * plus the 5-byte record header this function is given:
 *
 *   record[11 : 23)  reply_nonce           (sh + 6,       random[0:12))
 *   record[23 : 43)  ciphertext[0  : 20)   (sh + 6 + 12,  random[12:32))
 *   record[89 :117)  ciphertext[20 : 48)   (sh + 84,      key_share data)
 *
 * The SAME offsets are used against Go's reply, and that is the point:
 * this is the protocol, not our layout. If Go split it anywhere else the
 * open would fail and every case in this file would say so.
 *
 * Returns 0 on success. */
static int session_key_from_reply(const uint8_t *s2c, size_t s2c_len,
                                  const uint8_t shared[CLOAK_AEAD_KEY_LEN],
                                  uint8_t out_key[CLOAK_AEAD_KEY_LEN]) {
    if (s2c_len < 127) {
        return -1;
    }
    if (s2c[0] != 0x16 || s2c[5] != 0x02) {
        return -2; /* not a handshake record carrying a ServerHello */
    }
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    memcpy(nonce, s2c + 11, CLOAK_AEAD_NONCE_LEN);
    uint8_t ct[48];
    memcpy(ct, s2c + 23, 20);
    memcpy(ct + 20, s2c + 89, 28);
    uint8_t out[CLOAK_AEAD_KEY_LEN];
    size_t out_len = 0;
    if (cloak_aead_open(CLOAK_AEAD_AES_256_GCM, shared, nonce, NULL, 0, ct, sizeof(ct), out,
                        &out_len) != 0) {
        return -3;
    }
    if (out_len != CLOAK_AEAD_KEY_LEN) {
        return -4;
    }
    memcpy(out_key, out, CLOAK_AEAD_KEY_LEN);
    return 0;
}

/* Byte 28 of the decrypted authentication payload: the encryption method
 * the CLIENT declared to the server, which is the only place either
 * implementation learns it (neither server is configured with one).
 *
 * This is read off the wire, but it is the WEAKER of this file's two
 * method assertions and is deliberately not the one case 2 rests on: it
 * says what the client ANNOUNCED, not what it then did. A client that
 * announced chacha20-poly1305 and sealed with aes-256-gcm would satisfy
 * it and be unable to exchange a frame with anything. wire_method_of_frame
 * is the assertion that catches that; this one catches the complementary
 * bug -- sealing correctly and announcing wrongly -- which the same
 * untested configuration path could equally produce.
 *
 * Returns the byte, or -1 if the payload could not be recovered (the
 * negative code from auth_payload_from_hello is printed by the caller). */
static int auth_method_byte(const uint8_t *hello, size_t hello_len,
                            const uint8_t priv[CLOAK_X25519_KEY_LEN], int *err_out) {
    uint8_t payload[48];
    int rc = auth_payload_from_hello(hello, hello_len, priv, payload);
    if (rc != 0) {
        *err_out = rc;
        return -1;
    }
    *err_out = 0;
    return (int)payload[28];
}

/* ------------------------------------------------------------------ */
/* Reading the method off a data frame                                  */
/* ------------------------------------------------------------------ */

/* CASE 2, AND THE REASON THIS FILE IS WORTH RUNNING.
 *
 * Ask yourself what would happen if our client silently used aes-256-gcm
 * whenever it was asked for chacha20-poly1305. The configuration would
 * parse. The handshake would complete -- the auth payload is sealed with
 * AES-256-GCM regardless of the session's method, so nothing there would
 * change. The server would take the method from byte 28 and agree with
 * whatever the client put there. If the client also announced 256 (a
 * single wrong assignment does both), the two ends would agree, 128 KiB
 * would cross byte for byte, and EVERY OTHER ASSERTION IN THIS FILE WOULD
 * PASS while three quarters of the matrix silently tested aes-256-gcm
 * four times. That is not hypothetical: Task 1 of this module forced the
 * browser selection to chrome for all three templates and 78 of 78 other
 * tests in this suite passed.
 *
 * A configuration field cannot answer it, because the configuration field
 * is the thing under suspicion. So the answer is taken from the
 * ciphertext.
 *
 * HOW. On the direct path a Cloak connection after its handshake is a
 * sequence of TLS application-data records, one obfuscated mux frame
 * apiece (libcloak-mux/include/cloak/conn.h, CLOAK_CONN_FRAMING_TLS_RECORD).
 * A frame is a 14-byte header Salsa20-XORed under the session key with
 * the frame's own last 8 bytes as the nonce, followed by
 * payload || padding || tag, sealed with the session method under a nonce
 * that is the FIRST TWELVE BYTES OF THE PLAINTEXT HEADER (stream_id and
 * seq). This test has the session key -- recovered above from the reply,
 * with the private key it wrote into the server's configuration -- so it
 * can undo the header and then try the payload under each of the three
 * AEAD methods in turn.
 *
 * WHY THAT DISCRIMINATES, and it is not a matter of degree: an AEAD tag
 * is a 128-bit MAC. A frame sealed under AES-256-GCM does not open under
 * AES-128-GCM or ChaCha20-Poly1305 except with probability 2^-128, and
 * AES-128-GCM in particular is NOT "AES-256-GCM with a shorter key" --
 * different key schedule, different round count, different ciphertext.
 * So "exactly one of the three opens, and it is the one that was asked
 * for" is a statement about the bytes that no configuration field can
 * satisfy and no agreement between two copies of one mistake can fake.
 *
 * Returns a bitmask over the index into aead_methods[] of every method
 * that opened this frame, and sets *hdr_ok to 0 if the frame's header did
 * not even decrypt into something structurally sane. */
static unsigned wire_method_of_frame(const uint8_t *body, size_t body_len,
                                     const uint8_t key[CLOAK_AEAD_KEY_LEN], int *hdr_ok,
                                     uint64_t *seq_out, size_t *useful_out) {
    *hdr_ok = 0;
    *seq_out = 0;
    *useful_out = 0;
    if (body_len < CLOAK_FRAME_HEADER_LEN + CLOAK_SALSA20_NONCE_LEN) {
        return 0;
    }
    uint8_t hdr[CLOAK_FRAME_HEADER_LEN];
    const uint8_t *header_nonce = body + body_len - CLOAK_SALSA20_NONCE_LEN;
    cloak_salsa20_xor(hdr, body, CLOAK_FRAME_HEADER_LEN, header_nonce, key);

    uint64_t seq = 0;
    for (int i = 0; i < 8; i++) {
        seq = (seq << 8) | (uint64_t)hdr[4 + i];
    }
    size_t extra_len = hdr[13];
    size_t region = body_len - CLOAK_FRAME_HEADER_LEN;
    if (extra_len > region) {
        return 0; /* the header did not decrypt to anything coherent */
    }
    *hdr_ok = 1;
    *seq_out = seq;
    *useful_out = region - extra_len;

    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    memcpy(nonce, hdr, CLOAK_AEAD_NONCE_LEN);

    static uint8_t opened[CLOAK_CONN_MAX_FRAME_LEN];
    unsigned mask = 0;
    for (size_t m = 0; m < NAEAD; m++) {
        size_t opened_len = 0;
        if (region > sizeof(opened)) {
            continue;
        }
        if (cloak_aead_open(aead_methods[m], key, nonce, NULL, 0,
                            body + CLOAK_FRAME_HEADER_LEN, region, opened, &opened_len) == 0) {
            mask |= 1u << m;
        }
    }
    return mask;
}

/* ------------------------------------------------------------------ */
/* Walking the captured client -> server stream                         */
/* ------------------------------------------------------------------ */

/* What one run's captured frames turned out to be. */
typedef struct {
    size_t records;        /* whole application-data records walked */
    size_t frames_checked; /* those whose method was tested */
    size_t opened_by[NAEAD];
    size_t header_bad;
    size_t cleartext_frames; /* frames whose payload was found in send_buf */
    size_t plaintext_bytes;  /* total payload bytes matched in the clear */
} wire_walk_t;

/* Walks every whole TLS application-data record in the captured
 * client -> server stream and, for each, asks which AEAD method opens it
 * and whether its payload is legible.
 *
 * `plain_expect` is the buffer the application actually sent. A frame
 * counts as cleartext if its useful payload appears verbatim in that
 * buffer. `memmem` rather than an offset comparison because frame
 * boundaries are the mux's business, not this file's -- what "plain"
 * claims is that the bytes are THERE, unchanged, which is what a censor
 * reading the wire would see. */
static wire_walk_t walk_c2s(const wire_capture_t *w, const uint8_t key[CLOAK_AEAD_KEY_LEN],
                            const uint8_t *plain_expect, size_t plain_expect_len) {
    wire_walk_t r;
    memset(&r, 0, sizeof(r));
    size_t off = 0;
    while (off + 5 <= w->c2s_len) {
        size_t body_len = ((size_t)w->c2s[off + 3] << 8) | (size_t)w->c2s[off + 4];
        if (off + 5 + body_len > w->c2s_len) {
            break; /* a record the capture buffer cut in half */
        }
        uint8_t rec_type = w->c2s[off];
        const uint8_t *body = w->c2s + off + 5;
        off += 5 + body_len;
        if (rec_type != 0x17) {
            /* Not an application-data record. A Cloak client sends its
             * ClientHello and then nothing but these, so this counts
             * rather than asserts -- the floor on frames_checked below is
             * what would fail if the stream were something else. */
            continue;
        }
        r.records++;

        int hdr_ok = 0;
        uint64_t seq = 0;
        size_t useful = 0;
        unsigned mask = wire_method_of_frame(body, body_len, key, &hdr_ok, &seq, &useful);
        if (!hdr_ok) {
            r.header_bad++;
            continue;
        }
        r.frames_checked++;
        for (size_t m = 0; m < NAEAD; m++) {
            if ((mask & (1u << m)) != 0) {
                r.opened_by[m]++;
            }
        }
        if (useful > 0 && useful <= plain_expect_len &&
            memmem(plain_expect, plain_expect_len, body + CLOAK_FRAME_HEADER_LEN, useful) !=
                NULL) {
            r.cleartext_frames++;
            r.plaintext_bytes += useful;
        }
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* The payload, reproduced                                              */
/* ------------------------------------------------------------------ */

/* The harness fills its own send buffer with fill_payload(..., 0x9e3779b9)
 * and never hands it back, so this file reproduces it to ask whether those
 * exact bytes appear on the wire. Reproduced from the SAME generator with
 * the SAME seed -- if run_scenario's seed ever changes, the plain case
 * fails loudly rather than quietly comparing against the wrong bytes. */
static uint8_t expected_payload[PAYLOAD_LEN];

/* ------------------------------------------------------------------ */
/* Case 1 + case 2: the matrix, with the method read off the wire        */
/* ------------------------------------------------------------------ */

static wire_capture_t wire; /* 128 KiB; one run at a time, so one is enough */

/* Runs one point of the matrix and makes every wire assertion about it.
 * `c_is_client` picks the role: 1 is our ck-client against Go's
 * ck-server, 0 is Go's ck-client against our ck-server. */
static void run_one(const method_t *m, int c_is_client) {
    char name[96];
    snprintf(name, sizeof(name), "%s_%s", m->name, c_is_client ? "c_to_go" : "go_to_c");

    static captured_hellos_t caps;
    scenario_t sc = {
        .name = name,
        .server_path = c_is_client ? GO_CK_SERVER_PATH : CK_SERVER_PATH,
        .server_ready = c_is_client ? "Listening on" : "ck-server ready",
        .server_is_go = c_is_client,
        .client_path = c_is_client ? CK_CLIENT_PATH : GO_CK_CLIENT_PATH,
        .client_ready = c_is_client ? "session up" : "Listening on",
        .client_is_go = !c_is_client,
        .corrupt_at = -1,
        /* ONE CONNECTION, so that every frame of the transfer is on the
         * connection whose bytes are captured. With 2 the mux spreads
         * frames across both and the walk below would see half of them --
         * which is not wrong, but it makes "how many frames were checked"
         * depend on scheduling, and a case whose coverage varies run to
         * run cannot state a floor. */
        .num_conn = 1,
        .encryption = m->name,
        .wire_out = &wire,
    };
    run_scenario(&sc, &caps);

    /* ---- what the client announced ---- */
    uint8_t priv[CLOAK_X25519_KEY_LEN];
    char pub_b64[64];
    derive_keys(priv, pub_b64, sizeof(pub_b64));

    if (caps.n == 0) {
        fprintf(stderr,
                "FAIL %s:%d: %s: the relay never saw a whole ClientHello, so nothing can be "
                "said about the method\n",
                __FILE__, __LINE__, name);
        cloak_test_failures++;
        return;
    }
    int err = 0;
    int announced = auth_method_byte(caps.hellos[0], caps.lens[0], priv, &err);
    if (announced < 0) {
        fprintf(stderr,
                "FAIL %s:%d: %s: the authentication payload could not be recovered from the "
                "ClientHello (step %d)\n",
                __FILE__, __LINE__, name, err);
        cloak_test_failures++;
    } else if (announced != (int)m->enc) {
        fprintf(stderr,
                "FAIL %s:%d: %s: the client announced encryption method %d (%s) in its "
                "authentication payload, but was configured with %s (%d) -- the method "
                "byte is what the SERVER uses, so this client and this configuration "
                "disagree about what the session is\n",
                __FILE__, __LINE__, name, announced, enc_name((cloak_aead_method_t)announced),
                m->name, (int)m->enc);
        cloak_test_failures++;
    }

    /* ---- the session key, off the wire ---- */
    cloak_clienthello_parsed_t ph;
    if (cloak_clienthello_parse(caps.hellos[0], caps.lens[0], &ph) != 0) {
        fprintf(stderr, "FAIL %s:%d: %s: the captured ClientHello does not parse\n", __FILE__,
                __LINE__, name);
        cloak_test_failures++;
        return;
    }
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    if (cloak_x25519_shared_secret(priv, ph.random, shared) != 0) {
        fprintf(stderr, "FAIL %s:%d: %s: X25519 with the client's ephemeral key failed\n",
                __FILE__, __LINE__, name);
        cloak_test_failures++;
        return;
    }
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    int krc = session_key_from_reply(wire.s2c, wire.s2c_len, shared, key);
    if (krc != 0) {
        fprintf(stderr,
                "FAIL %s:%d: %s: the session key could not be recovered from the %zu "
                "captured reply byte(s) (step %d)\n",
                __FILE__, __LINE__, name, wire.s2c_len, krc);
        cloak_test_failures++;
        return;
    }

    /* ---- which method sealed the frames ---- */
    wire_walk_t wk = walk_c2s(&wire, key, expected_payload, sizeof(expected_payload));

    /* A FLOOR ON COVERAGE. "Every frame agreed" is satisfied by zero
     * frames, which is exactly how a walk that returned early looks. */
    if (wk.frames_checked < 3) {
        fprintf(stderr,
                "FAIL %s:%d: %s: only %zu frame(s) could be read off the wire (%zu record(s), "
                "%zu with an unreadable header, %zu captured byte(s)%s); at least 3 are "
                "needed before agreement means anything\n",
                __FILE__, __LINE__, name, wk.frames_checked, wk.records, wk.header_bad,
                wire.c2s_len, wire.c2s_truncated ? ", capture buffer full" : "");
        cloak_test_failures++;
        return;
    }
    if (wk.header_bad > 0) {
        fprintf(stderr,
                "FAIL %s:%d: %s: %zu frame header(s) did not decrypt under the session key "
                "recovered from the reply -- either the key is wrong or the header is not "
                "Salsa20 under it\n",
                __FILE__, __LINE__, name, wk.header_bad);
        cloak_test_failures++;
    }

    for (size_t a = 0; a < NAEAD; a++) {
        int should = (aead_methods[a] == m->enc);
        if (should && wk.opened_by[a] != wk.frames_checked) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: only %zu of %zu frames opened under %s, the method this "
                    "session was configured for\n",
                    __FILE__, __LINE__, name, wk.opened_by[a], wk.frames_checked,
                    enc_name(aead_methods[a]));
            cloak_test_failures++;
        }
        if (!should && wk.opened_by[a] != 0) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: %zu of %zu frames opened under %s, which is NOT the "
                    "method this session was configured for (%s) -- the client sealed with "
                    "the wrong method, and both ends agreeing about it is exactly the "
                    "failure this assertion exists to catch\n",
                    __FILE__, __LINE__, name, wk.opened_by[a], wk.frames_checked,
                    enc_name(aead_methods[a]), m->name);
            cloak_test_failures++;
        }
    }

    /* ---- what `plain` means on the wire ---- */
    if (m->enc == CLOAK_AEAD_NONE) {
        if (wk.cleartext_frames != wk.frames_checked) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: only %zu of %zu frames carried the application's own "
                    "bytes verbatim; with EncryptionMethod plain every one of them must\n",
                    __FILE__, __LINE__, name, wk.cleartext_frames, wk.frames_checked);
            cloak_test_failures++;
        }
    } else {
        if (wk.cleartext_frames != 0) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: %zu frame(s) carried the application's bytes in the "
                    "clear under %s\n",
                    __FILE__, __LINE__, name, wk.cleartext_frames, m->name);
            cloak_test_failures++;
        }
    }

    printf("   wire: %zu record(s)%s, %zu frame(s) checked; opened by [%s %zu, %s %zu, "
           "%s %zu]; %zu cleartext frame(s), %zu plaintext byte(s)\n",
           wk.records, wire.c2s_truncated ? " (capture full -- the session sent more)" : "",
           wk.frames_checked, enc_name(aead_methods[0]), wk.opened_by[0],
           enc_name(aead_methods[1]), wk.opened_by[1], enc_name(aead_methods[2]),
           wk.opened_by[2], wk.cleartext_frames, wk.plaintext_bytes);
}

static void test_every_method_both_roles(void) {
    for (size_t i = 0; i < NMETHODS; i++) {
        run_one(&methods[i], 1);
        run_one(&methods[i], 0);
    }
}

/* ------------------------------------------------------------------ */
/* Case 4: one flipped bit, per method                                  */
/* ------------------------------------------------------------------ */

/* WHICH RECORD AND WHICH BYTE, and why both are safe.
 *
 * Record 2 of the post-ClientHello client -> server stream. MEASURED:
 * the eight positive runs above each filled the 64 KiB capture buffer,
 * within which Go's ck-client produced 7 whole records and ours 4 (Go
 * caps one on-wire message at appDataMaxLength = 16401 bytes; ours sends
 * larger ones), and EVERY ONE of those records was a walkable data frame
 * -- 0 with an unreadable header and 0 of any other TLS content type. So
 * a Cloak client really does send its ClientHello and then nothing but
 * frames in this direction, and record 2 is simply "a frame that is
 * certain to exist". That it exists is not taken on trust either:
 * run_scenario fails a corrupting run in which no byte was flipped, and
 * all four runs below report exactly 1.
 *
 * Byte 14 of the record BODY -- that is, the first byte after the 14-byte
 * frame header, which is payload[0]. That offset is safe for every frame
 * regardless of its sequence number, and the reason matters: padding is
 * appended AFTER the payload (cloak_frame_obfuscate writes
 * payload || padding || tag), so the first payload byte exists in every
 * frame -- cloak_frame_obfuscate refuses a zero-length payload outright.
 * An offset chosen inside the padding would corrupt nothing the
 * application ever sees, and a control that corrupts nothing passes for
 * the wrong reason.
 *
 * WHY THE GO CLIENT AND OUR SERVER. This is the direction in which OUR
 * decrypt path is the one under test, which is where a per-method key or
 * nonce divergence would bite: the ciphertext is foreign.
 *
 * WHAT MAKES IT BITE FOR THE RIGHT REASON. For the three AEAD methods the
 * flipped bit is inside the authenticated span, so the receiving mux must
 * drop the frame and the transfer must stall part-way. For `plain` the
 * SAME BIT AT THE SAME PLACE is inside nothing -- there is no tag -- so
 * the transfer must COMPLETE and exactly one delivered byte must differ.
 * That pair is the whole control: if the three stalls came from
 * "corruption breaks things" rather than from the AEAD tag, the plain run
 * would stall too. It does not, and the assertion is a count of one, not
 * a "differs". */
#define CORRUPT_RECORD 2
#define CORRUPT_BODY_OFFSET CLOAK_FRAME_HEADER_LEN

static void test_one_flipped_bit_per_method(void) {
    for (size_t i = 0; i < NMETHODS; i++) {
        const method_t *m = &methods[i];
        char name[96];
        snprintf(name, sizeof(name), "flip_%s_go_to_c", m->name);
        scenario_t sc = {
            .name = name,
            .server_path = CK_SERVER_PATH,
            .server_ready = "ck-server ready",
            .server_is_go = 0,
            .client_path = GO_CK_CLIENT_PATH,
            .client_ready = "Listening on",
            .client_is_go = 1,
            .corrupt_at = -1,
            .num_conn = 1,
            .encryption = m->name,
            .wire_out = &wire,
            .corrupt_c2s = 1,
            .corrupt_c2s_rec = CORRUPT_RECORD,
            .corrupt_c2s_off = CORRUPT_BODY_OFFSET,
            .expect = (m->enc == CLOAK_AEAD_NONE) ? CLOAK_EXPECT_ONE_BYTE_OFF
                                                  : CLOAK_EXPECT_STALL,
        };
        run_scenario(&sc, NULL);
    }
}

int main(void) {
    /* The relay writes to sockets whose peer may already have gone -- a
     * stalled session closes one under it by design. Without this the
     * negative controls would kill the test process instead of
     * asserting. */
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (!oracle_binaries_present()) {
        return 1;
    }
    fill_payload(expected_payload, sizeof(expected_payload), 0x9e3779b9u);

    test_every_method_both_roles();
    test_one_flipped_bit_per_method();

    if (cloak_test_failures > 0) {
        fprintf(stderr, "%d assertion(s) failed\n", cloak_test_failures);
        return 1;
    }
    printf("All tests passed\n");
    return 0;
}
