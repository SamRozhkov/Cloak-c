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

TEST_MAIN_BEGIN()
    test_round_trip_plain();
    test_padding_varies_for_first_n_frames_only();
    test_payload_offset_optimization_skips_copy();
    test_obfuscate_rejects_empty_payload();
    test_obfuscate_rejects_buffer_too_small();
    test_deobfuscate_rejects_short_buffer();
    test_deobfuscate_rejects_corrupt_extra_len();
TEST_MAIN_END()
