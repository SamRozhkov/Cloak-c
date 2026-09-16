#include "cloak/frame.h"
#include "cloak/common.h"

#include <string.h>

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint64_t load_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static void store_be64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

/* tag_len is the number of trailing bytes reserved after the payload+padding:
 * the real AEAD tag for any non-NONE method, or CLOAK_SALSA20_NONCE_LEN
 * bytes of random filler in NONE mode (used purely as the Salsa20 header
 * nonce, since there is no AEAD tag to borrow bytes from). */
static size_t tag_len_for_method(cloak_aead_method_t method) {
    if (method == CLOAK_AEAD_NONE) {
        return CLOAK_SALSA20_NONCE_LEN;
    }
    return cloak_aead_overhead(method);
}

/* Uniform over [0, max_inclusive], REJECTION-SAMPLED, because this value
 * is an on-wire length and nothing else in this file is allowed to be a
 * distinguisher.
 *
 * Go: `padLen = common.RandInt(maxExtraLen - tagLen + 1)`
 * (internal/multiplex/obfs.go:77), and common.RandInt is crypto/rand.Int
 * over a big.Int bound -- unbiased. This port drew ONE byte and took
 * `b % 240` for five modules. 256 = 240 + 16, so the sixteen smallest pad
 * lengths came out twice as often as the other 224: MEASURED over 200,000
 * frames, P(pad in [0,15]) was 12.547 % here against Go's 6.667 %, a
 * per-value ratio of 2.009.
 *
 * That is not a rounding wart. `useful_len = 14 + payload_len + pad_len +
 * tag_len`, so pad_len is added straight into the length of the first
 * CLOAK_FRAME_PAD_FIRST_N_FRAMES frames of every stream, in both
 * directions, on both transports -- and a passive observer aggregating
 * first-five-frame lengths across sessions separated this port from the
 * reference implementation on a 2x effect over 6.25 % of the length space.
 * In the padding whose stated purpose, in Go's own comment above the draw,
 * is "Pad to avoid size side channel leak".
 *
 * It survived because it is the AAD defect's exact shape: both ends of
 * every round-trip test are our own code, so both agree, and the Go
 * interop oracle checks that frames DECODE, never how long they are.
 * cloak_random_below is the fix and libcloak-mux/tests/test_frame.c's
 * test_first_frame_pad_length_is_uniform is the assertion that now fails
 * if anyone reintroduces it -- a chi-square, because "the lengths vary"
 * and "every length appears" both pass under a 2x bias. */
static uint8_t random_pad_len(size_t max_inclusive) {
    return (uint8_t)cloak_random_below((uint32_t)(max_inclusive + 1));
}

long cloak_frame_obfuscate(const cloak_obfuscator_t *o, const cloak_frame_t *frame,
                            uint8_t *buf, size_t buf_cap, size_t payload_offset_in_buf) {
    if (frame->payload_len == 0) {
        return -1;
    }
    if (frame->payload_len > buf_cap) {
        return -1;
    }

    size_t tag_len = tag_len_for_method(o->method);

    size_t pad_len = 0;
    if (frame->seq < CLOAK_FRAME_PAD_FIRST_N_FRAMES) {
        pad_len = random_pad_len(CLOAK_FRAME_MAX_EXTRA_LEN - tag_len);
    }

    size_t useful_len = CLOAK_FRAME_HEADER_LEN + frame->payload_len + pad_len + tag_len;
    if (buf_cap < useful_len) {
        return -1;
    }

    uint8_t *payload_region = buf + CLOAK_FRAME_HEADER_LEN;
    if (payload_offset_in_buf != CLOAK_FRAME_HEADER_LEN) {
        memmove(payload_region, frame->payload, frame->payload_len);
    }

    store_be32(buf + 0, frame->stream_id);
    store_be64(buf + 4, frame->seq);
    buf[12] = frame->closing;
    buf[13] = (uint8_t)(pad_len + tag_len);

    /* Random padding plus the trailing tag_len bytes that either become the
     * real AEAD tag (overwritten below) or, in NONE mode, stay as the
     * Salsa20 nonce source. */
    cloak_random_bytes(payload_region + frame->payload_len, pad_len + tag_len);

    if (o->method != CLOAK_AEAD_NONE) {
        uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
        memcpy(nonce, buf, CLOAK_AEAD_NONCE_LEN); /* plaintext stream_id+seq, before header encryption */
        size_t sealed_len = 0;
        /* NO ASSOCIATED DATA, AND THAT IS A WIRE-FORMAT REQUIREMENT, NOT A
         * SECURITY PREFERENCE.
         *
         * Go seals with a nil AAD (internal/multiplex/obfs.go:
         * `o.payloadCipher.Seal(payload[:0], header[:NonceSize()], payload,
         * nil)`), and AES-GCM's tag covers the AAD, so a peer that passes
         * ANY AAD produces a different tag for the same plaintext and its
         * frames fail authentication at every implementation but its own.
         *
         * This port did pass one -- `buf + 12, 2`, the closing flag and
         * the extra-length byte -- for five modules. It is invisible to
         * every test that has our code on both ends, because both ends
         * passed the same AAD and agreed; the round trip is perfect and
         * the product does not work. MEASURED, not read: a real Go client
         * built on cbeuw/Cloak's own obfs.go completes the CDN handshake
         * against ck-server, sends one frame, and the server drops it
         * silently -- the session establishes and then carries nothing
         * (libcloak-server/tests/test_ws_interop.c, case 1, which is the
         * test that found this).
         *
         * WHAT THIS COSTS, STATED PLAINLY, BECAUSE AN EARLIER VERSION OF
         * THIS COMMENT OVERSTATED IT AND THAT IS THE WORSE FAILURE. It
         * claimed bytes 12-13 were "covered by the Salsa20 layer". THEY
         * ARE NOT. Salsa20 is a raw XOR stream cipher and provides ZERO
         * INTEGRITY: the unforgeable nonce stops an attacker fabricating a
         * whole new frame, and does nothing at all to stop one flipping
         * bits in an existing frame. Go's own comment above its Seal call
         * ("Because the frame header ... is fed into the AEAD, it is also
         * authenticated") is inaccurate for the same reason -- only
         * header[:12] is the nonce, and only header[:12] is thereby
         * authenticated.
         *
         * So: BYTES 12 AND 13 ARE UNAUTHENTICATED, exactly as in Go, and
         * an on-path attacker WITHOUT THE SESSION KEY can XOR chosen bits
         * into them. Concretely, and this is a real capability, not a
         * theoretical one:
         *
         *   - byte 12, `closing`: setting CLOAK_FRAME_CLOSING_SESSION (2)
         *     makes session.c's frame path run session_passive_close and
         *     KILL THE WHOLE MUX SESSION, taking every stream with it.
         *     This is NOT the same as a RST, which kills one TCP
         *     connection of a multi-connection session and which the mux
         *     survives by redialling; a forged closing=2 is above the
         *     transport and the redial does not recover it. `closing` is 0
         *     on essentially every data frame, so the attacker needs no
         *     knowledge of the plaintext -- one blind bit-flip per
         *     session, undetectable and unattributable.
         *   - byte 13, `extra_len`: both implementations authenticate the
         *     whole payload||padding||tag region and then SLICE it at
         *     len - extra_len, so raising it silently truncates delivered
         *     stream bytes and lowering it delivers random padding to the
         *     application as stream data. Integrity and availability only
         *     -- the value is bounds-checked, so there is no
         *     memory-safety or confidentiality consequence.
         *
         *     WHICH HALVES OF THAT ARE MEASURED, AND THE ONE THAT WAS
         *     WRONG. Measured on this tree by keyless on-wire XOR of
         *     header byte 13, 64-byte payload: 16 -> 17 delivers 63 bytes
         *     of the 64 sent and 16 -> 20 delivers 60 (TRUNCATION, two
         *     sided); seq 0 with 181 -> 16 delivers 229 bytes for 64 sent
         *     (PADDING-AS-DATA). Both hold.
         *
         *     "BOTH IMPLEMENTATIONS ... SLICE IT" DOES NOT, and an earlier
         *     version of this comment said it did. cloak_frame_deobfuscate
         *     below applies an `extra_len >= tag_len_for_method()` FLOOR
         *     that Go has no counterpart for: measured here, 16 -> 15,
         *     16 -> 0 and 16 -> -1 all return rc -1, whereas obfs.go:135-150
         *     (read, not measured -- no Go harness reaches this path) at
         *     extraLen 15 computes usefulPayloadLen = len - 15, opens
         *     successfully into len - 16 bytes, and slices ONE BYTE PAST
         *     the opened region, handing the application a raw tag byte as
         *     stream data. The divergence is C being stricter, i.e. the
         *     safe direction, and it is a REJECTION where Go delivers --
         *     not a wire-format difference, since no honest peer ever
         *     sends an extra_len below the tag size.
         *
         * What IS still protected: the payload ciphertext and its tag;
         * bytes 0-11 (stream_id and seq), because they are the AEAD nonce,
         * which RFC 5116 section 2.1 authenticates internally; and the
         * CONFIDENTIALITY of 12-13, which Salsa20 does provide.
         *
         * THIS IS INHERITED FIDELITY, NOT A DESIGN WE CHOSE. The Cloak
         * frame format has a two-byte malleable region and this port has
         * it because the reference implementation has it. Closing it
         * unilaterally is what the AAD was, and the price was a peer that
         * could not exchange one frame with Go -- and, separately, a peer
         * that behaves differently from the reference implementation under
         * a bit-flip probe, which is a behavioural distinguisher in the
         * one product that cannot afford one. If the format is to be
         * fixed, it is fixed upstream and on both sides at once.
         *
         * WHAT THE FIX COST, AND IT IS NOT NOTHING: THIS IS A WIRE-FORMAT
         * BREAK WITH OUR OWN PRIOR BUILDS. The per-task notes accompanying
         * the CDN work say "the direct path is provably untouched". That
         * is true of libcloak-mux/src/conn.c and
         * libcloak-server/src/dispatcher.c, which really do branch on the
         * transport. IT IS NOT TRUE OF THIS FILE. frame.c has no framing
         * branch -- it is pure mux, below the transport -- so the AAD
         * change above is UNCONDITIONAL and altered the direct TLS path's
         * bytes exactly as much as the CDN path's.
         *
         * MEASURED, same key, same stream/seq, same 32-byte payload, seq
         * >= CLOAK_FRAME_PAD_FIRST_N_FRAMES so the length is
         * deterministic: a new-AAD frame (tag acc18821) deobfuscates rc=0
         * here; the old-AAD frame for the same inputs (tag d71f6aba) is
         * REFUSED, rc=-1. So a pre-fix build of this port cannot exchange
         * ONE FRAME with a post-fix build of this port, on EITHER
         * transport -- not the CDN path, not the direct TLS path.
         *
         * That is deliberate and it is the right trade: the break is with
         * five modules of our own binaries, none of them released, and it
         * is what buys compatibility with every real Cloak peer that
         * exists. But both halves belong in the record, because a reader
         * who takes "the direct path is untouched" at face value will
         * conclude a module-7 client still talks to a module-8 server, and
         * it does not. */
        int rc = cloak_aead_seal(o->method, o->session_key, nonce,
                                  NULL, 0,
                                  payload_region, frame->payload_len + pad_len,
                                  payload_region, &sealed_len);
        if (rc != 0) {
            return -1;
        }
    }

    const uint8_t *header_nonce = buf + useful_len - CLOAK_SALSA20_NONCE_LEN;
    cloak_salsa20_xor(buf, buf, CLOAK_FRAME_HEADER_LEN, header_nonce, o->session_key);

    return (long)useful_len;
}

int cloak_frame_deobfuscate(const cloak_obfuscator_t *o, cloak_frame_t *out_frame,
                             uint8_t *buf, size_t buf_len) {
    if (buf_len < CLOAK_FRAME_HEADER_LEN + CLOAK_SALSA20_NONCE_LEN) {
        return -1;
    }

    const uint8_t *header_nonce = buf + buf_len - CLOAK_SALSA20_NONCE_LEN;
    cloak_salsa20_xor(buf, buf, CLOAK_FRAME_HEADER_LEN, header_nonce, o->session_key);

    uint32_t stream_id = load_be32(buf + 0);
    uint64_t seq = load_be64(buf + 4);
    uint8_t closing = buf[12];
    uint8_t extra_len = buf[13];

    uint8_t *pld_with_overhead = buf + CLOAK_FRAME_HEADER_LEN;
    size_t pld_with_overhead_len = buf_len - CLOAK_FRAME_HEADER_LEN;

    size_t min_extra_len = tag_len_for_method(o->method);
    if ((size_t)extra_len < min_extra_len) {
        return -1;
    }
    if ((size_t)extra_len > pld_with_overhead_len) {
        return -1;
    }
    size_t useful_payload_len = pld_with_overhead_len - extra_len;

    if (o->method != CLOAK_AEAD_NONE) {
        uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
        memcpy(nonce, buf, CLOAK_AEAD_NONCE_LEN); /* now-decrypted plaintext stream_id+seq */
        size_t opened_len = 0;
        /* No AAD, for the reason cloak_frame_obfuscate states at length:
         * Go passes nil, the tag covers the AAD, and the two must match or
         * nothing interoperates. */
        int rc = cloak_aead_open(o->method, o->session_key, nonce,
                                  NULL, 0,
                                  pld_with_overhead, pld_with_overhead_len,
                                  pld_with_overhead, &opened_len);
        if (rc != 0) {
            return -1;
        }
        if (useful_payload_len > opened_len) {
            return -1;
        }
    }

    out_frame->stream_id = stream_id;
    out_frame->seq = seq;
    out_frame->closing = closing;
    out_frame->payload = pld_with_overhead;
    out_frame->payload_len = useful_payload_len;
    return 0;
}
