#include "cloak/frame.h"
#include "cloak/common.h"
#include "test_framework.h"

#include <string.h>

static void make_plain_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_NONE;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

static void test_round_trip_plain(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    const uint8_t payload[] = "hello frame";
    cloak_frame_t frame;
    frame.stream_id = 7;
    frame.seq = 100; /* >= CLOAK_FRAME_PAD_FIRST_N_FRAMES, so no padding -- deterministic length */
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[128];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);
    /* seq >= 5 means pad_len == 0; plain mode's tag_len is CLOAK_SALSA20_NONCE_LEN (8). */
    ASSERT_EQ_INT(n, CLOAK_FRAME_HEADER_LEN + (long)frame.payload_len + CLOAK_SALSA20_NONCE_LEN);

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(out.stream_id, frame.stream_id);
    ASSERT_EQ_INT(out.seq, frame.seq);
    ASSERT_EQ_INT(out.closing, frame.closing);
    ASSERT_EQ_INT(out.payload_len, frame.payload_len);
    ASSERT_MEM_EQ(out.payload, payload, frame.payload_len);
}

static void test_padding_varies_for_first_n_frames_only(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    const uint8_t payload[] = "x";
    uint8_t buf[512];

    /* seq >= CLOAK_FRAME_PAD_FIRST_N_FRAMES: length must be identical every time. */
    long first_len = -1;
    for (int i = 0; i < 10; i++) {
        cloak_frame_t frame;
        frame.stream_id = 1;
        frame.seq = 5 + (uint64_t)i;
        frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
        frame.payload = payload;
        frame.payload_len = sizeof(payload);
        long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
        ASSERT_TRUE(n > 0);
        if (first_len < 0) {
            first_len = n;
        } else {
            ASSERT_EQ_INT(n, first_len);
        }
    }

    /* seq < CLOAK_FRAME_PAD_FIRST_N_FRAMES: across enough samples, length
     * must vary at least once (padding is randomized). Not fully
     * deterministic by construction, but with a 240-value range and 40
     * samples the chance every single call lands on the exact same pad
     * length is astronomically small (this only asserts "at least two
     * distinct lengths seen", not a specific distribution). */
    int distinct_lengths_seen = 0;
    long seen_len = -1;
    for (int i = 0; i < 40; i++) {
        cloak_frame_t frame;
        frame.stream_id = 1;
        frame.seq = 0; /* always within the padded range */
        frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
        frame.payload = payload;
        frame.payload_len = sizeof(payload);
        long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
        ASSERT_TRUE(n > 0);
        ASSERT_TRUE(n >= first_len); /* padding only adds bytes, never removes */
        if (seen_len < 0) {
            seen_len = n;
        } else if (n != seen_len) {
            distinct_lengths_seen = 1;
        }
    }
    ASSERT_TRUE(distinct_lengths_seen);
}

static void test_payload_offset_optimization_skips_copy(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    uint8_t buf[128];
    const uint8_t payload[] = "preplaced";
    memcpy(buf + CLOAK_FRAME_HEADER_LEN, payload, sizeof(payload));

    cloak_frame_t frame;
    frame.stream_id = 2;
    frame.seq = 50;
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = NULL; /* must be unused when payload_offset_in_buf == CLOAK_FRAME_HEADER_LEN */
    frame.payload_len = sizeof(payload);

    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), CLOAK_FRAME_HEADER_LEN);
    ASSERT_TRUE(n > 0);

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_MEM_EQ(out.payload, payload, sizeof(payload));
}

static void test_obfuscate_rejects_empty_payload(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 10;
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = (const uint8_t *)"";
    frame.payload_len = 0;

    uint8_t buf[64];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_EQ_INT(n, -1);
}

static void test_obfuscate_rejects_buffer_too_small(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    const uint8_t payload[32] = {0};
    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 10; /* no padding, so required size is exactly known */
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    /* Required: CLOAK_FRAME_HEADER_LEN + 32 + CLOAK_SALSA20_NONCE_LEN (plain mode). One byte short. */
    uint8_t buf[CLOAK_FRAME_HEADER_LEN + 32 + CLOAK_SALSA20_NONCE_LEN - 1];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_EQ_INT(n, -1);
}

static void test_deobfuscate_rejects_short_buffer(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    uint8_t buf[10]; /* shorter than CLOAK_FRAME_HEADER_LEN + CLOAK_SALSA20_NONCE_LEN (22) */
    memset(buf, 0, sizeof(buf));

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, sizeof(buf));
    ASSERT_EQ_INT(rc, -1);
}

static void test_deobfuscate_rejects_corrupt_extra_len(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    const uint8_t payload[] = "short";
    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 100; /* no padding, deterministic layout */
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[128];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);

    /* Decrypt the header, corrupt extra_len to an implausibly large value,
     * then re-encrypt the header (Salsa20 XOR is its own inverse under the
     * same nonce/key) so deobfuscate will "successfully" decrypt the
     * header but find a corrupt extra_len pointing past the available
     * payload+overhead region. */
    const uint8_t *header_nonce = buf + n - CLOAK_SALSA20_NONCE_LEN;
    cloak_salsa20_xor(buf, buf, CLOAK_FRAME_HEADER_LEN, header_nonce, o.session_key);
    buf[13] = 255;
    cloak_salsa20_xor(buf, buf, CLOAK_FRAME_HEADER_LEN, header_nonce, o.session_key);

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, -1);
}

static void round_trip_for_method(cloak_aead_method_t method) {
    cloak_obfuscator_t o;
    o.method = method;
    cloak_random_bytes(o.session_key, sizeof(o.session_key));

    const uint8_t payload[] = "round trip across every AEAD method the frame codec supports";
    cloak_frame_t frame;
    frame.stream_id = 42;
    frame.seq = 1000; /* no padding, deterministic layout */
    frame.closing = CLOAK_FRAME_CLOSING_STREAM;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[256];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);
    ASSERT_EQ_INT(n, CLOAK_FRAME_HEADER_LEN + (long)frame.payload_len + CLOAK_AEAD_TAG_LEN);

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(out.stream_id, frame.stream_id);
    ASSERT_EQ_INT(out.seq, frame.seq);
    ASSERT_EQ_INT(out.closing, frame.closing);
    ASSERT_EQ_INT(out.payload_len, frame.payload_len);
    ASSERT_MEM_EQ(out.payload, payload, frame.payload_len);
}

static void test_aes256gcm_round_trip(void) {
    round_trip_for_method(CLOAK_AEAD_AES_256_GCM);
}

static void test_aes128gcm_round_trip(void) {
    round_trip_for_method(CLOAK_AEAD_AES_128_GCM);
}

static void test_chacha20poly1305_round_trip(void) {
    round_trip_for_method(CLOAK_AEAD_CHACHA20_POLY1305);
}

static void test_tamper_detected_after_obfuscate(void) {
    cloak_obfuscator_t o;
    o.method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o.session_key, sizeof(o.session_key));

    const uint8_t payload[] = "tamper with me if you can";
    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 1000;
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[256];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);

    /* Flip a bit inside the encrypted payload region (well after the
     * header, well before the very end) -- must break AEAD authentication. */
    buf[CLOAK_FRAME_HEADER_LEN] ^= 0x01;

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, -1);
}

static void test_wrong_key_rejected(void) {
    cloak_obfuscator_t sender;
    sender.method = CLOAK_AEAD_CHACHA20_POLY1305;
    cloak_random_bytes(sender.session_key, sizeof(sender.session_key));

    cloak_obfuscator_t wrong_receiver;
    wrong_receiver.method = CLOAK_AEAD_CHACHA20_POLY1305;
    cloak_random_bytes(wrong_receiver.session_key, sizeof(wrong_receiver.session_key));

    const uint8_t payload[] = "secret";
    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 1000;
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[256];
    long n = cloak_frame_obfuscate(&sender, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&wrong_receiver, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, -1);
}

/* THIS CASE WAS REVERSED, AND THE REVERSAL IS THE POINT.
 *
 * It used to be test_closing_byte_tamper_detected_with_aead, and it
 * passed, because cloak_frame_obfuscate fed header bytes 12-13 (the
 * closing flag and the extra-length byte) to AES-GCM as ASSOCIATED DATA.
 * That made those two bytes authenticated -- genuinely better than what
 * the frame format offers -- and it made this port unable to exchange a
 * single data frame with the implementation it is a port of.
 *
 * AES-GCM's tag covers the AAD. Go seals with a nil AAD
 * (internal/multiplex/obfs.go: `Seal(payload[:0], header[:NonceSize()],
 * payload, nil)`), so the same plaintext under the same key and nonce
 * produces a DIFFERENT tag on each side and every frame fails
 * authentication at the other end. It was invisible for five modules
 * because every test of it had this project's code on both ends, passing
 * the same AAD and agreeing with itself -- the same shape as the
 * two-byte-length-prefix defect cloak/conn.h's header describes.
 *
 * MEASURED, NOT ARGUED: a Go client built on cbeuw/Cloak's own obfs.go
 * completed the CDN handshake against a real ck-server, sent one frame,
 * and the server dropped it silently; the session established and then
 * carried nothing. libcloak-server/tests/test_ws_interop.c case 1 is that
 * measurement, and its
 * test_a_go_produced_frame_deobfuscates_byte_for_byte pins a frame that
 * the Go original actually emitted, so this cannot silently regress
 * without a Go toolchain present.
 *
 * So the AAD is gone and the malleability is back, deliberately, and this
 * case now asserts the behaviour Go has:
 *
 *   - Flipping the closing byte is NOT detected. An on-path attacker can
 *     do it WITHOUT THE SESSION KEY, because Salsa20 is a raw XOR stream
 *     cipher and provides no integrity whatsoever -- these two bytes are
 *     unauthenticated, full stop, and this case is the demonstration.
 *     Go can be attacked in exactly the same way, which is the reason
 *     this port must be: a peer that is fussier than the reference
 *     implementation is a behavioural distinguisher, which is the one
 *     thing a circumvention tool cannot afford (the same argument
 *     cloak/conn.h makes for not validating the TLS record's type byte,
 *     and ws_handshake.c for reproducing gorilla's token-list quirks).
 *
 *     WHAT THE ATTACKER GAINS IS NOT SMALL, and an earlier version of
 *     this comment said it was ("a capability an on-path attacker
 *     already has with a RST"). That is wrong. The value flipped in
 *     below is 0x02, which IS CLOAK_FRAME_CLOSING_SESSION, and
 *     session.c's frame path answers it with session_passive_close --
 *     the whole mux session, every stream on it, gone. A RST kills one
 *     TCP connection of a multi-connection session and the mux redials
 *     around it; this is above the transport and the redial does not
 *     recover it. Flipping byte 13 (extra_len) instead truncates the
 *     delivered stream or injects padding bytes into it as data. The
 *     port inherits a real upstream weakness here, deliberately; it is
 *     not covered by something else.
 *   - The PAYLOAD is still authenticated, and bytes 0-11 of the header
 *     still are: they are the AEAD nonce, which RFC 5116 section 2.1
 *     authenticates internally. test_tamper_detected_after_obfuscate
 *     above is what holds that half in place, and it is unchanged. The
 *     payload assertions at the end of this case hold it here too: the
 *     malleability is exactly two bytes wide and this pins that width.
 *
 * If you are about to re-add the AAD: it will make this case and case 1
 * of test_ws_interop fail together, and the second of those is the one
 * that matters. */
static void test_closing_byte_tamper_matches_go_and_is_not_detected(void) {
    cloak_obfuscator_t o;
    o.method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o.session_key, sizeof(o.session_key));

    const uint8_t payload[] = "authenticated header test";
    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 1000;
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[256];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);

    /* Flip the closing byte in the wire-format header. It is
     * Salsa20-obfuscated, so this is an on-path attacker who does NOT know
     * the session key: Salsa20-XOR is malleable and no key is needed to
     * flip a bit. */
    buf[12] ^= 0x02;

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    /* Accepted, with the flipped value delivered -- exactly what Go does,
     * and asserted rather than merely tolerated so that re-adding the AAD
     * fails here as well as against a real Go peer. */
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(CLOAK_FRAME_CLOSING_NOTHING ^ 0x02, out.closing);
    /* The PAYLOAD is untouched by the flip: only the two bytes outside the
     * AEAD's nonce are malleable, and this is what says so. */
    ASSERT_EQ_INT((long long)sizeof(payload), (long long)out.payload_len);
    ASSERT_MEM_EQ(out.payload, payload, sizeof(payload));
}

static void test_obfuscate_rejects_payload_larger_than_buf_cap(void) {
    cloak_obfuscator_t o;
    o.method = CLOAK_AEAD_NONE;
    cloak_random_bytes(o.session_key, sizeof(o.session_key));

    uint8_t payload[1000] = {0};
    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 100;
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[10]; /* far smaller than payload_len -- must be rejected immediately */
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_EQ_INT(n, -1);
}

static void test_deobfuscate_rejects_extra_len_below_minimum(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    const uint8_t payload[] = "short";
    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 100;
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[128];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);

    /* Corrupt extra_len to a value below CLOAK_SALSA20_NONCE_LEN (8) -- the
     * minimum for plain mode -- using the same decrypt/corrupt/re-encrypt
     * technique as test_deobfuscate_rejects_corrupt_extra_len. */
    const uint8_t *header_nonce = buf + n - CLOAK_SALSA20_NONCE_LEN;
    cloak_salsa20_xor(buf, buf, CLOAK_FRAME_HEADER_LEN, header_nonce, o.session_key);
    buf[13] = 3; /* below the minimum of 8 for plain mode */
    cloak_salsa20_xor(buf, buf, CLOAK_FRAME_HEADER_LEN, header_nonce, o.session_key);

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, -1);
}

/* THE ON-WIRE QUANTITY, NOT THE HELPER. libcloak-common/tests/test_random.c
 * pins cloak_random_below's distribution; this pins the thing an observer
 * on the network actually sees, end to end through cloak_frame_obfuscate --
 * because the defect that made this test necessary was not in a sampler
 * anybody had written down, it was `b % 240` inlined into the padding draw,
 * and the length it produced went straight onto the wire.
 *
 * useful_len = CLOAK_FRAME_HEADER_LEN(14) + payload_len(10) + pad_len +
 * tag_len(16 for AES-GCM), so pad_len = n - 40 and the observable range is
 * [0, 239] -- exactly CLOAK_FRAME_MAX_EXTRA_LEN - 16 + 1 = 240 values.
 * seq < CLOAK_FRAME_PAD_FIRST_N_FRAMES, because that is when padding is
 * applied at all.
 *
 * MEASURED BRACKET, in the dev image, 40 runs of each sampler at 200,000
 * draws (the same measurement test_random.c records, since the same
 * function is underneath):
 *
 *   rejection    chi2 202.6 .. 292.7      pad in [0,15]: 13103 .. 13592
 *   `b % 240`    chi2 10260.4 .. 11724.5  pad in [0,15]: 24513 .. 25297
 *
 * with the threshold at 420.0 in the gap. Watched to fail end to end:
 * with the byte-modulo restored, THIS test -- the one that goes through
 * cloak_frame_obfuscate rather than through the sampler -- printed
 * "chi2 = 10989.1, not < 420.0" and "24908 not in [12664, 14003]".
 * See test_random.c for why that threshold, and for why "the lengths
 * vary" and "every length appears" are not assertions. */
#define PAD_DIST_FRAMES 200000ul
#define PAD_DIST_BINS 240
#define PAD_DIST_CHI2_THRESHOLD 420.0

static void test_first_frame_pad_length_is_uniform(void) {
    cloak_obfuscator_t o;
    o.method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o.session_key, sizeof(o.session_key));

    const uint8_t payload[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const long base = CLOAK_FRAME_HEADER_LEN + (long)sizeof(payload) + 16;

    static unsigned long counts[PAD_DIST_BINS];
    memset(counts, 0, sizeof(counts));

    uint8_t buf[CLOAK_FRAME_HEADER_LEN + sizeof(payload) + CLOAK_FRAME_MAX_EXTRA_LEN];
    int out_of_range = 0;
    for (unsigned long i = 0; i < PAD_DIST_FRAMES; i++) {
        cloak_frame_t frame;
        frame.stream_id = 3;
        frame.seq = i % CLOAK_FRAME_PAD_FIRST_N_FRAMES; /* always a padded frame */
        frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
        frame.payload = payload;
        frame.payload_len = sizeof(payload);
        long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
        long pad = n - base;
        if (n <= 0 || pad < 0 || pad >= PAD_DIST_BINS) {
            out_of_range++;
            continue;
        }
        counts[pad]++;
    }
    ASSERT_EQ_INT(out_of_range, 0);

    ASSERT_UNIFORM_CHI_SQUARE(counts, PAD_DIST_BINS, PAD_DIST_FRAMES, PAD_DIST_CHI2_THRESHOLD);

    /* The defect named rather than merely detected: the sixteen shortest
     * padded frames must carry 16/240 = 6.667 % of the mass. The shipped
     * byte-modulo gave them 12.547 %. Expected 13333.3 with sigma 111.5;
     * the bracket is +/- 6 sigma, the fixed build measured 13103..13592
     * over 40 runs and the biased one 24513..25297. */
    unsigned long low = 0;
    for (int v = 0; v < 16; v++) {
        low += counts[v];
    }
    ASSERT_COUNT_IN_RANGE("first-five-frame pad lengths in [0,15]", low, 12664ul, 14003ul);
}


/* ---- the window-update type carries its four bytes intact ------------- */

/* THE TYPE IS JUST A BYTE, AND THAT IS WHAT THIS PINS. The frame layer
 * must not treat CLOAK_FRAME_TYPE_WINDOW_UPDATE specially: it obfuscates
 * and deobfuscates like any other frame, and the four payload bytes must
 * survive byte for byte, because a corrupted delta is a credit error that
 * would show up much later as a stall with no evident cause.
 *
 * Also pins that the type is distinguishable from the three that existed
 * before it -- a decoder that folded unknown values into NOTHING would
 * pass every other test in this file. */
static void test_window_update_round_trip(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    /* 0xDEADBEEF little-endian, and deliberately not a palindrome: a
     * byte-order slip reads back 0xEFBEADDE and fails here rather than
     * silently granting the wrong credit. */
    const uint8_t payload[CLOAK_FRAME_WINDOW_UPDATE_LEN] = {0xEF, 0xBE, 0xAD, 0xDE};
    cloak_frame_t frame;
    frame.stream_id = 9;
    frame.seq = 100;
    frame.closing = CLOAK_FRAME_TYPE_WINDOW_UPDATE;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[128];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);
    ASSERT_EQ_INT(n, CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_WINDOW_UPDATE_LEN +
                         CLOAK_SALSA20_NONCE_LEN);

    cloak_frame_t out;
    ASSERT_EQ_INT(0, cloak_frame_deobfuscate(&o, &out, buf, (size_t)n));
    ASSERT_EQ_INT(out.stream_id, frame.stream_id);
    ASSERT_EQ_INT(out.seq, frame.seq);
    ASSERT_EQ_INT(out.closing, CLOAK_FRAME_TYPE_WINDOW_UPDATE);
    ASSERT_TRUE(out.closing != CLOAK_FRAME_CLOSING_NOTHING);
    ASSERT_TRUE(out.closing != CLOAK_FRAME_CLOSING_STREAM);
    ASSERT_TRUE(out.closing != CLOAK_FRAME_CLOSING_SESSION);
    ASSERT_EQ_INT(out.payload_len, CLOAK_FRAME_WINDOW_UPDATE_LEN);
    ASSERT_MEM_EQ(out.payload, payload, CLOAK_FRAME_WINDOW_UPDATE_LEN);

    uint32_t delta = (uint32_t)out.payload[0] | ((uint32_t)out.payload[1] << 8) |
                     ((uint32_t)out.payload[2] << 16) | ((uint32_t)out.payload[3] << 24);
    ASSERT_EQ_INT((int)delta, (int)0xDEADBEEFu);
}

/* An update is a frame like any other under a real AEAD too, including
 * the padding the first few sequence numbers carry. Cheap, and it is the
 * combination -- new type, low seq, real cipher -- that no other case in
 * this file covers. */
static void test_window_update_survives_padding_and_aead(void) {
    cloak_obfuscator_t o;
    o.method = CLOAK_AEAD_AES_256_GCM;
    memset(o.session_key, 0x5c, sizeof(o.session_key));

    const uint8_t payload[CLOAK_FRAME_WINDOW_UPDATE_LEN] = {0x01, 0x00, 0x00, 0x00};
    cloak_frame_t frame;
    frame.stream_id = 0x01020304u;
    frame.seq = 0; /* inside CLOAK_FRAME_PAD_FIRST_N_FRAMES, so padded */
    frame.closing = CLOAK_FRAME_TYPE_WINDOW_UPDATE;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[512];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);

    cloak_frame_t out;
    ASSERT_EQ_INT(0, cloak_frame_deobfuscate(&o, &out, buf, (size_t)n));
    ASSERT_EQ_INT(out.closing, CLOAK_FRAME_TYPE_WINDOW_UPDATE);
    ASSERT_EQ_INT(out.stream_id, frame.stream_id);
    ASSERT_EQ_INT(out.payload_len, CLOAK_FRAME_WINDOW_UPDATE_LEN);
    ASSERT_MEM_EQ(out.payload, payload, CLOAK_FRAME_WINDOW_UPDATE_LEN);
}

TEST_MAIN_BEGIN()
    test_round_trip_plain();
    test_window_update_round_trip();
    test_window_update_survives_padding_and_aead();
    test_padding_varies_for_first_n_frames_only();
    test_payload_offset_optimization_skips_copy();
    test_obfuscate_rejects_empty_payload();
    test_obfuscate_rejects_buffer_too_small();
    test_deobfuscate_rejects_short_buffer();
    test_deobfuscate_rejects_corrupt_extra_len();
    test_aes256gcm_round_trip();
    test_aes128gcm_round_trip();
    test_chacha20poly1305_round_trip();
    test_tamper_detected_after_obfuscate();
    test_wrong_key_rejected();
    test_closing_byte_tamper_matches_go_and_is_not_detected();
    test_obfuscate_rejects_payload_larger_than_buf_cap();
    test_deobfuscate_rejects_extra_len_below_minimum();
    test_first_frame_pad_length_is_uniform();
TEST_MAIN_END()
