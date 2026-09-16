/* Pins the RFC 6455 FRAME CODEC at the byte.
 *
 * This codec sits on the CDN path where cloak/conn.h's five-byte TLS
 * record header sits on the direct path -- it is the thing that replaces
 * those five bytes when a session arrives as a CDN-fronted WebSocket
 * upgrade. Read the 46-line warning at the top of cloak/conn.h before
 * changing anything here: that header exists because this port once
 * reinvented a framing prefix of its own and, in doing so, dropped the
 * disguise one round trip into every connection. The lesson transfers
 * directly. A WebSocket peer -- the CDN, the browser stack behind it, or
 * Go's gorilla on the other end of an interop run -- will reject a frame
 * that is off by one byte, and "off by one byte" is exactly what an
 * implementation derived from prose rather than from measurement produces.
 *
 * So EVERY on-wire expectation in this file is written as a LITERAL byte
 * array. Nothing is computed from CLOAK_WS_FRAME_MAX_HEADER_LEN, from the
 * length-form thresholds, or from any other constant the code under test
 * owns. A test that derives its expectation from the implementation cannot
 * observe the implementation changing, which is the only thing a test of a
 * wire format is for.
 *
 * The vectors come from two places, both outside this tree:
 *
 *   - RFC 6455 section 5.7's own worked examples, quoted verbatim
 *     (the masked and unmasked "Hello" frames, the fragmented pair, the
 *     ping/pong pair, the 256-byte 0x7E frame and the 64 KiB 0x7F frame).
 *   - The module-8 scouting report's live measurements of Go + gorilla
 *     (docs/superpowers/plans/2026-09-16-module-8-scouting.md section 1.6):
 *     a 5-byte client message is `82 85 <4-byte mask> <5 masked bytes>`
 *     and a 200-byte one is `82 fe 00 c8 <4-byte mask> <200 bytes>`.
 *
 * Two structural choices in here are deliberate and should survive edits:
 *
 *   - parse_exact() copies each input into a heap allocation of EXACTLY
 *     its declared length, so a parser that reads one byte past buf + len
 *     is an ASan heap-buffer-overflow rather than a result that happens to
 *     be right. This parser is attacker-controlled -- module 10 fuzzes it
 *     -- and "never reads past buf + len" is the whole reason it has the
 *     shape it has, so it is checked mechanically rather than by reading.
 *   - write_exact() does the same for the encode side, and additionally
 *     prefills with 0xAA so that a rejected-for-capacity call can be shown
 *     to have written NOTHING, not merely to have returned -1.
 *
 * Every boundary below is bracketed on BOTH sides: the largest value that
 * takes the narrower form AND the smallest that takes the wider one. A
 * boundary pinned on one side only is the single most common defect this
 * project has recorded. */

#include "cloak/ws_frame.h"

#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#include "cloak/common.h"
#include "test_framework.h"

/* ------------------------------------------------------------------ */
/* Interposition on cloak_random_bytes                                 */
/* ------------------------------------------------------------------ */

/* This binary supplies its OWN cloak_random_bytes, and that is not an
 * accident of linking -- it is the only way to test the property that
 * actually matters about a key generator.
 *
 * Every statistical check on generated keys has the same blind spot: it
 * tests the OUTPUT, so any source whose output looks random enough passes,
 * however predictable it is to someone who knows the algorithm. An
 * independent reviewer demonstrated this by replacing the draw with an
 * incrementing counter, and a linear congruential generator defeats a
 * stride check the same way. What the header actually promises is not "the
 * keys look random" but "the keys come from cloak_random_bytes", and only
 * an interposed definition can observe that.
 *
 * How it resolves: cloak-mux and cloak-common are STATIC archives, so the
 * linker takes this object's definition first and then never has an
 * unresolved cloak_random_bytes left for libcloak-common's random.o to
 * satisfy -- so random.o is not pulled in and there is no duplicate
 * symbol. Nothing else in this binary draws random bytes; if that ever
 * changes, this file will fail to link rather than silently divert
 * somebody else's entropy, which is the failure mode to prefer.
 *
 * The bytes handed back are still OpenSSL's, from the same RAND_bytes
 * libcloak-common calls, so the statistical checks further down remain
 * meaningful rather than testing a fixture. */
static int rng_calls;
static size_t rng_last_len;
static uint8_t rng_last[64];

void cloak_random_bytes(uint8_t *buf, size_t len) {
    if (len == 0) {
        return;
    }
    if (RAND_bytes(buf, (int)len) != 1) {
        fprintf(stderr, "test: RAND_bytes failed\n");
        abort();
    }
    rng_calls++;
    rng_last_len = len;
    if (len <= sizeof(rng_last)) {
        memcpy(rng_last, buf, len);
    }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Parses from a heap buffer of exactly n bytes. See the file comment for
 * why the allocation is exact. malloc(0) returns a non-NULL, zero-usable
 * pointer under both glibc and ASan, so the len == 0 case is still a
 * buffer any read at all overflows. */
static ssize_t parse_exact(const uint8_t *bytes, size_t n, cloak_ws_frame_header_t *out) {
    uint8_t *p = (uint8_t *)malloc(n);
    ssize_t r;
    ASSERT_TRUE(p != NULL);
    if (n > 0) {
        memcpy(p, bytes, n);
    }
    r = cloak_ws_frame_parse_header(p, n, out);
    free(p);
    return r;
}

/* Writes a header into a heap buffer of exactly cap bytes, prefilled with
 * 0xAA. On return, copy_out (cap bytes, may be NULL) holds the buffer as
 * the function left it -- so a caller can assert both what was written and
 * what was not. */
static ssize_t write_exact(uint8_t *copy_out, size_t cap, cloak_ws_opcode_t op, int fin,
                           const uint8_t *mask_key, uint64_t payload_len) {
    uint8_t *p = (uint8_t *)malloc(cap);
    ssize_t r;
    ASSERT_TRUE(p != NULL);
    if (cap > 0) {
        memset(p, 0xAA, cap);
    }
    r = cloak_ws_frame_write_header(p, cap, op, fin, mask_key, payload_len);
    if (copy_out != NULL && cap > 0) {
        memcpy(copy_out, p, cap);
    }
    free(p);
    return r;
}

/* The mask key from RFC 6455 section 5.7's masked examples. Used wherever
 * a test needs a key whose masked output the RFC itself publishes. */
static const uint8_t rfc_key[4] = {0x37, 0xfa, 0x21, 0x3d};

/* ------------------------------------------------------------------ */
/* 1. RFC 6455 section 5.7's own frames, quoted verbatim               */
/* ------------------------------------------------------------------ */

static void test_rfc_sample_frames(void) {
    /* "A single-frame masked text message":
     *   0x81 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58  ("Hello") */
    const uint8_t masked_hello[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d,
                                    0x7f, 0x9f, 0x4d, 0x51, 0x58};
    /* "A single-frame unmasked text message":
     *   0x81 0x05 0x48 0x65 0x6c 0x6c 0x6f  ("Hello") */
    const uint8_t unmasked_hello[] = {0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};

    cloak_ws_frame_header_t h;
    uint8_t payload[5];

    memset(&h, 0, sizeof(h));
    ASSERT_EQ_INT(parse_exact(masked_hello, sizeof(masked_hello), &h), 6);
    ASSERT_EQ_INT(h.header_len, 6);
    ASSERT_EQ_INT(h.fin, 1);
    ASSERT_EQ_INT(h.masked, 1);
    ASSERT_EQ_INT(h.opcode, CLOAK_WS_OP_TEXT);
    ASSERT_EQ_INT(h.payload_len, 5);
    ASSERT_MEM_EQ(h.mask_key, rfc_key, 4);

    /* Unmask the RFC's own masked bytes and expect the RFC's own
     * plaintext. This is an outside oracle for cloak_ws_frame_mask, not a
     * round trip through our own encoder. */
    memcpy(payload, masked_hello + 6, 5);
    ASSERT_EQ_INT(cloak_ws_frame_mask(payload, 5, h.mask_key, 0), 1);
    ASSERT_MEM_EQ(payload, "Hello", 5);

    memset(&h, 0, sizeof(h));
    ASSERT_EQ_INT(parse_exact(unmasked_hello, sizeof(unmasked_hello), &h), 2);
    ASSERT_EQ_INT(h.header_len, 2);
    ASSERT_EQ_INT(h.fin, 1);
    ASSERT_EQ_INT(h.masked, 0);
    ASSERT_EQ_INT(h.opcode, CLOAK_WS_OP_TEXT);
    ASSERT_EQ_INT(h.payload_len, 5);
    /* Unmasked: the key field is zeroed, never left holding payload bytes. */
    ASSERT_MEM_EQ(h.mask_key, "\0\0\0\0", 4);
    ASSERT_MEM_EQ(unmasked_hello + 2, "Hello", 5);

    /* "A fragmented unmasked text message":
     *   0x01 0x03 0x48 0x65 0x6c  ("Hel")
     *   0x80 0x02 0x6c 0x6f       ("lo")
     * Reassembly is the next layer's job; classifying these correctly so
     * that layer CAN do it is this one's. */
    {
        const uint8_t frag1[] = {0x01, 0x03, 0x48, 0x65, 0x6c};
        const uint8_t frag2[] = {0x80, 0x02, 0x6c, 0x6f};

        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(frag1, sizeof(frag1), &h), 2);
        ASSERT_EQ_INT(h.fin, 0);
        ASSERT_EQ_INT(h.opcode, CLOAK_WS_OP_TEXT);
        ASSERT_EQ_INT(h.payload_len, 3);

        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(frag2, sizeof(frag2), &h), 2);
        ASSERT_EQ_INT(h.fin, 1);
        ASSERT_EQ_INT(h.opcode, CLOAK_WS_OP_CONTINUATION);
        ASSERT_EQ_INT(h.payload_len, 2);
    }

    /* "Unmasked Ping request and masked Pong response". */
    {
        const uint8_t ping[] = {0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};
        const uint8_t pong[] = {0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d,
                                0x7f, 0x9f, 0x4d, 0x51, 0x58};

        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(ping, sizeof(ping), &h), 2);
        ASSERT_EQ_INT(h.opcode, CLOAK_WS_OP_PING);
        ASSERT_EQ_INT(h.fin, 1);
        ASSERT_EQ_INT(h.masked, 0);
        ASSERT_EQ_INT(h.payload_len, 5);

        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(pong, sizeof(pong), &h), 6);
        ASSERT_EQ_INT(h.opcode, CLOAK_WS_OP_PONG);
        ASSERT_EQ_INT(h.fin, 1);
        ASSERT_EQ_INT(h.masked, 1);
        ASSERT_EQ_INT(h.payload_len, 5);
        ASSERT_MEM_EQ(h.mask_key, rfc_key, 4);
    }

    /* A close frame, for completeness of the opcode set. */
    {
        const uint8_t close[] = {0x88, 0x02, 0x03, 0xe8};

        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(close, sizeof(close), &h), 2);
        ASSERT_EQ_INT(h.opcode, CLOAK_WS_OP_CLOSE);
        ASSERT_EQ_INT(h.payload_len, 2);
    }
}

/* ------------------------------------------------------------------ */
/* 2. Length-form boundaries, bracketed on both sides                  */
/* ------------------------------------------------------------------ */

/* The decode half of the bracket. Each expectation is a literal frame
 * header; nothing here names a threshold constant. */
static void test_length_brackets_decode(void) {
    cloak_ws_frame_header_t h;

    /* Zero-length: still the inline form, still a two-byte header. */
    {
        const uint8_t b[] = {0x82, 0x00};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 2);
        ASSERT_EQ_INT(h.payload_len, 0);
        ASSERT_EQ_INT(h.header_len, 2);
    }
    /* 125 -- the largest inline length. Header is 2 bytes. */
    {
        const uint8_t b[] = {0x82, 0x7d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 2);
        ASSERT_EQ_INT(h.payload_len, 125);
        ASSERT_EQ_INT(h.header_len, 2);
    }
    /* 126 -- the smallest u16 length. Header is 4 bytes, and the second
     * byte is 0x7e (the marker), NOT 0x7e-the-length. */
    {
        const uint8_t b[] = {0x82, 0x7e, 0x00, 0x7e};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 4);
        ASSERT_EQ_INT(h.payload_len, 126);
        ASSERT_EQ_INT(h.header_len, 4);
    }
    /* RFC 6455 section 5.7: "256 bytes binary message in a single unmasked
     * frame: 0x82 0x7E 0x0100". */
    {
        const uint8_t b[] = {0x82, 0x7e, 0x01, 0x00};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 4);
        ASSERT_EQ_INT(h.payload_len, 256);
    }
    /* The Go measurement: a 200-byte client message is
     * `82 fe 00 c8 <4-byte mask>`. */
    {
        const uint8_t b[] = {0x82, 0xfe, 0x00, 0xc8, 0x37, 0xfa, 0x21, 0x3d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 8);
        ASSERT_EQ_INT(h.payload_len, 200);
        ASSERT_EQ_INT(h.header_len, 8);
        ASSERT_EQ_INT(h.masked, 1);
        ASSERT_MEM_EQ(h.mask_key, rfc_key, 4);
    }
    /* 65535 -- the largest u16 length. */
    {
        const uint8_t b[] = {0x82, 0x7e, 0xff, 0xff};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 4);
        ASSERT_EQ_INT(h.payload_len, 65535);
        ASSERT_EQ_INT(h.header_len, 4);
    }
    /* 65536 -- the smallest u64 length. RFC 6455 section 5.7's own 64 KiB
     * example: "0x82 0x7F 0x0000000000010000". */
    {
        const uint8_t b[] = {0x82, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 10);
        ASSERT_EQ_INT(h.payload_len, 65536);
        ASSERT_EQ_INT(h.header_len, 10);
    }
    /* The masked 64-bit form: 14 bytes, the longest header that exists. */
    {
        const uint8_t b[] = {0x82, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                             0x00, 0x00, 0x37, 0xfa, 0x21, 0x3d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 14);
        ASSERT_EQ_INT(h.payload_len, 65536);
        ASSERT_EQ_INT(h.header_len, 14);
        ASSERT_MEM_EQ(h.mask_key, rfc_key, 4);
    }
    /* The masked inline form: 6 bytes. Go's measured 5-byte message. */
    {
        const uint8_t b[] = {0x82, 0x85, 0x37, 0xfa, 0x21, 0x3d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 6);
        ASSERT_EQ_INT(h.payload_len, 5);
        ASSERT_EQ_INT(h.header_len, 6);
    }
    /* The masked inline form at its own ceiling: 0xfd is MASK | 125. */
    {
        const uint8_t b[] = {0x82, 0xfd, 0x37, 0xfa, 0x21, 0x3d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 6);
        ASSERT_EQ_INT(h.payload_len, 125);
        ASSERT_EQ_INT(h.header_len, 6);
    }
}

/* The encode half of the same bracket. Expected bytes are literals, so a
 * change to the implementation's own thresholds cannot move them. */
static void test_length_brackets_encode(void) {
    uint8_t got[16];

    {
        const uint8_t want[] = {0x82, 0x00};
        ASSERT_EQ_INT(write_exact(got, 2, CLOAK_WS_OP_BINARY, 1, NULL, 0), 2);
        ASSERT_MEM_EQ(got, want, 2);
    }
    {
        const uint8_t want[] = {0x82, 0x7d};
        ASSERT_EQ_INT(write_exact(got, 2, CLOAK_WS_OP_BINARY, 1, NULL, 125), 2);
        ASSERT_MEM_EQ(got, want, 2);
    }
    {
        const uint8_t want[] = {0x82, 0x7e, 0x00, 0x7e};
        ASSERT_EQ_INT(write_exact(got, 4, CLOAK_WS_OP_BINARY, 1, NULL, 126), 4);
        ASSERT_MEM_EQ(got, want, 4);
    }
    {
        const uint8_t want[] = {0x82, 0x7e, 0xff, 0xff};
        ASSERT_EQ_INT(write_exact(got, 4, CLOAK_WS_OP_BINARY, 1, NULL, 65535), 4);
        ASSERT_MEM_EQ(got, want, 4);
    }
    {
        const uint8_t want[] = {0x82, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
        ASSERT_EQ_INT(write_exact(got, 10, CLOAK_WS_OP_BINARY, 1, NULL, 65536), 10);
        ASSERT_MEM_EQ(got, want, 10);
    }

    /* The client direction: MASK set, key appended after the length. These
     * two are the scouting report's live Go measurements, byte for byte. */
    {
        const uint8_t want[] = {0x82, 0x85, 0x37, 0xfa, 0x21, 0x3d};
        ASSERT_EQ_INT(write_exact(got, 6, CLOAK_WS_OP_BINARY, 1, rfc_key, 5), 6);
        ASSERT_MEM_EQ(got, want, 6);
    }
    {
        const uint8_t want[] = {0x82, 0xfe, 0x00, 0xc8, 0x37, 0xfa, 0x21, 0x3d};
        ASSERT_EQ_INT(write_exact(got, 8, CLOAK_WS_OP_BINARY, 1, rfc_key, 200), 8);
        ASSERT_MEM_EQ(got, want, 8);
    }
    /* The masked bracket, both sides. */
    {
        const uint8_t want[] = {0x82, 0xfd, 0x37, 0xfa, 0x21, 0x3d};
        ASSERT_EQ_INT(write_exact(got, 6, CLOAK_WS_OP_BINARY, 1, rfc_key, 125), 6);
        ASSERT_MEM_EQ(got, want, 6);
    }
    {
        const uint8_t want[] = {0x82, 0xfe, 0x00, 0x7e, 0x37, 0xfa, 0x21, 0x3d};
        ASSERT_EQ_INT(write_exact(got, 8, CLOAK_WS_OP_BINARY, 1, rfc_key, 126), 8);
        ASSERT_MEM_EQ(got, want, 8);
    }
    {
        const uint8_t want[] = {0x82, 0xfe, 0xff, 0xff, 0x37, 0xfa, 0x21, 0x3d};
        ASSERT_EQ_INT(write_exact(got, 8, CLOAK_WS_OP_BINARY, 1, rfc_key, 65535), 8);
        ASSERT_MEM_EQ(got, want, 8);
    }
    {
        const uint8_t want[] = {0x82, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                                0x00, 0x00, 0x37, 0xfa, 0x21, 0x3d};
        ASSERT_EQ_INT(write_exact(got, 14, CLOAK_WS_OP_BINARY, 1, rfc_key, 65536), 14);
        ASSERT_MEM_EQ(got, want, 14);
    }

    /* FIN clear clears exactly one bit and nothing else. */
    {
        const uint8_t want[] = {0x02, 0x05};
        ASSERT_EQ_INT(write_exact(got, 2, CLOAK_WS_OP_BINARY, 0, NULL, 5), 2);
        ASSERT_MEM_EQ(got, want, 2);
    }
    /* A continuation frame's opcode really is 0x0 and not "absent". */
    {
        const uint8_t want[] = {0x80, 0x05};
        ASSERT_EQ_INT(write_exact(got, 2, CLOAK_WS_OP_CONTINUATION, 1, NULL, 5), 2);
        ASSERT_MEM_EQ(got, want, 2);
    }
    /* Control opcodes encode too -- the pong we owe a CDN's idle ping. */
    {
        const uint8_t want[] = {0x8a, 0x00};
        ASSERT_EQ_INT(write_exact(got, 2, CLOAK_WS_OP_PONG, 1, NULL, 0), 2);
        ASSERT_MEM_EQ(got, want, 2);
    }
}

/* ------------------------------------------------------------------ */
/* 3. The 64-bit length's high bit                                     */
/* ------------------------------------------------------------------ */

static void test_u64_high_bit(void) {
    cloak_ws_frame_header_t h;

    /* RFC 6455 section 5.2: "the most significant bit MUST be 0". Exactly
     * at the bit: 0x7fffffffffffffff is legal, 0x8000000000000000 is not.
     * Both sides, because "rejects huge lengths" is a different (and
     * wrong) property from "rejects the high bit". */
    {
        const uint8_t ok[] = {0x82, 0x7f, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(ok, sizeof(ok), &h), 10);
        ASSERT_TRUE(h.payload_len == UINT64_C(0x7fffffffffffffff));
    }
    {
        const uint8_t bad[] = {0x82, 0x7f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(bad, sizeof(bad), &h), -1);
    }
    /* And with the MASK bit on, so the rejection is not accidentally
     * coupled to the unmasked path. */
    {
        const uint8_t bad[] = {0x82, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0x37, 0xfa, 0x21, 0x3d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(bad, sizeof(bad), &h), -1);
    }
    /* The high bit is rejected as soon as the eight length bytes are in
     * hand -- it does not wait for the four mask bytes that follow. */
    {
        const uint8_t bad[] = {0x82, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(bad, sizeof(bad), &h), -1);
    }
    /* write_header refuses to emit what parse_header would reject. */
    ASSERT_EQ_INT(write_exact(NULL, 14, CLOAK_WS_OP_BINARY, 1, NULL,
                              UINT64_C(0x8000000000000000)), -1);
    ASSERT_EQ_INT(write_exact(NULL, 14, CLOAK_WS_OP_BINARY, 1, NULL,
                              UINT64_C(0x7fffffffffffffff)), 10);
}

/* ------------------------------------------------------------------ */
/* 4. RSV1, RSV2, RSV3 -- each alone                                   */
/* ------------------------------------------------------------------ */

static void test_rsv_bits(void) {
    cloak_ws_frame_header_t h;
    /* No extension is ever negotiated (no permessage-deflate, no
     * Sec-WebSocket-Extensions on either side), so all three reserved bits
     * are always zero on the wire and a set one is a protocol error.
     * Three separate cases: a check written as `b0 & 0x70` and a check
     * written as `b0 & 0x40` are indistinguishable from one case. */
    {
        const uint8_t rsv1[] = {0xc2, 0x05}; /* FIN | RSV1 | BINARY */
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(rsv1, sizeof(rsv1), &h), -1);
    }
    {
        const uint8_t rsv2[] = {0xa2, 0x05}; /* FIN | RSV2 | BINARY */
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(rsv2, sizeof(rsv2), &h), -1);
    }
    {
        const uint8_t rsv3[] = {0x92, 0x05}; /* FIN | RSV3 | BINARY */
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(rsv3, sizeof(rsv3), &h), -1);
    }
    /* The other side of the bracket: the same frame with the reserved bits
     * clear is accepted, so the three rejections above are attributable to
     * the bits and not to the rest of the frame. */
    {
        const uint8_t clean[] = {0x82, 0x05};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(clean, sizeof(clean), &h), 2);
    }
    /* A reserved bit is rejected before the length bytes are demanded --
     * an error beats "need more bytes", or a hostile peer could hold a
     * connection open by never completing a header it has already
     * invalidated. */
    {
        const uint8_t rsv1_long[] = {0xc2, 0x7f};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(rsv1_long, sizeof(rsv1_long), &h), -1);
    }
}

/* ------------------------------------------------------------------ */
/* 5. Control-frame constraints                                        */
/* ------------------------------------------------------------------ */

static void test_control_frame_constraints(void) {
    cloak_ws_frame_header_t h;

    /* RFC 6455 section 5.5: "All control frames MUST have a payload length
     * of 125 bytes or less and MUST NOT be fragmented." Both sides of the
     * 125/126 boundary, for each of the three control opcodes. */
    {
        const uint8_t close125[] = {0x88, 0x7d};
        const uint8_t close126[] = {0x88, 0x7e, 0x00, 0x7e};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(close125, sizeof(close125), &h), 2);
        ASSERT_EQ_INT(h.payload_len, 125);
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(close126, sizeof(close126), &h), -1);
    }
    {
        const uint8_t ping125[] = {0x89, 0x7d};
        const uint8_t ping200[] = {0x89, 0xfe, 0x00, 0xc8, 0x37, 0xfa, 0x21, 0x3d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(ping125, sizeof(ping125), &h), 2);
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(ping200, sizeof(ping200), &h), -1);
    }
    {
        const uint8_t pong126[] = {0x8a, 0x7e, 0x00, 0x7e};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(pong126, sizeof(pong126), &h), -1);
    }
    /* The 64-bit form is equally forbidden for a control frame, even
     * though its declared length could in principle be small. */
    {
        const uint8_t close64[] = {0x88, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(close64, sizeof(close64), &h), -1);
    }

    /* FIN clear, each control opcode. And the matching FIN-set frame, so
     * the rejection is attributable to FIN. */
    {
        const uint8_t no_fin[] = {0x08, 0x00};
        const uint8_t fin[] = {0x88, 0x00};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(no_fin, sizeof(no_fin), &h), -1);
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(fin, sizeof(fin), &h), 2);
    }
    {
        const uint8_t no_fin[] = {0x09, 0x00};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(no_fin, sizeof(no_fin), &h), -1);
    }
    {
        const uint8_t no_fin[] = {0x0a, 0x00};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(no_fin, sizeof(no_fin), &h), -1);
    }
    /* A DATA frame with FIN clear is legal -- that is what a fragment is.
     * Without this the FIN check above could be "FIN must always be set". */
    {
        const uint8_t frag[] = {0x02, 0x7e, 0x00, 0xc8};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(frag, sizeof(frag), &h), 4);
        ASSERT_EQ_INT(h.fin, 0);
        ASSERT_EQ_INT(h.payload_len, 200);
    }
    /* And a data frame with a 126-byte payload is legal, so the control
     * length check is attributable to the opcode and not to the length. */
    {
        const uint8_t data126[] = {0x82, 0x7e, 0x00, 0x7e};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(data126, sizeof(data126), &h), 4);
    }

    /* write_header will not produce a control frame parse_header rejects. */
    ASSERT_EQ_INT(write_exact(NULL, 14, CLOAK_WS_OP_PING, 1, NULL, 125), 2);
    ASSERT_EQ_INT(write_exact(NULL, 14, CLOAK_WS_OP_PING, 1, NULL, 126), -1);
    ASSERT_EQ_INT(write_exact(NULL, 14, CLOAK_WS_OP_CLOSE, 0, NULL, 0), -1);
    ASSERT_EQ_INT(write_exact(NULL, 14, CLOAK_WS_OP_CLOSE, 1, NULL, 0), 2);
}

/* ------------------------------------------------------------------ */
/* 6. Unknown opcodes                                                  */
/* ------------------------------------------------------------------ */

static void test_unknown_opcodes(void) {
    cloak_ws_frame_header_t h;
    /* RFC 6455 section 5.2 reserves 0x3-0x7 and 0xB-0xF; gorilla rejects
     * them ("unknown opcode", conn.go). Every one of the ten, so that a
     * check written as a range and a check written as a set cannot be
     * confused, and so that the accepted set below is exactly six. */
    static const uint8_t reserved[] = {0x3, 0x4, 0x5, 0x6, 0x7, 0xb, 0xc, 0xd, 0xe, 0xf};
    static const uint8_t valid[] = {0x0, 0x1, 0x2, 0x8, 0x9, 0xa};
    size_t i;

    for (i = 0; i < sizeof(reserved); i++) {
        uint8_t b[2];
        b[0] = (uint8_t)(0x80 | reserved[i]);
        b[1] = 0x00;
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, 2, &h), -1);
    }
    for (i = 0; i < sizeof(valid); i++) {
        uint8_t b[2];
        b[0] = (uint8_t)(0x80 | valid[i]);
        b[1] = 0x00;
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, 2, &h), 2);
        ASSERT_EQ_INT(h.opcode, valid[i]);
    }
    /* write_header refuses a reserved opcode too. */
    ASSERT_EQ_INT(write_exact(NULL, 14, (cloak_ws_opcode_t)0x3, 1, NULL, 0), -1);
    ASSERT_EQ_INT(write_exact(NULL, 14, (cloak_ws_opcode_t)0xf, 1, NULL, 0), -1);
}

/* ------------------------------------------------------------------ */
/* 7. Partial input                                                    */
/* ------------------------------------------------------------------ */

/* Feeds prefix lengths 0..n-1 of an n-byte header and requires 0 at every
 * one of them, then n itself and requires exactly n. The "not one earlier"
 * half is the part that matters: a parser that returns its header length
 * as soon as it has the first two bytes looks completely correct to any
 * test that only ever hands it a whole header, and then reads uninitialised
 * memory the moment a TCP segment boundary lands mid-header. */
static void expect_needs_exactly(const uint8_t *header, size_t n) {
    cloak_ws_frame_header_t h;
    size_t i;
    for (i = 0; i < n; i++) {
        memset(&h, 0xAA, sizeof(h));
        ASSERT_EQ_INT(parse_exact(header, i, &h), 0);
    }
    memset(&h, 0xAA, sizeof(h));
    ASSERT_EQ_INT(parse_exact(header, n, &h), (ssize_t)n);
    ASSERT_EQ_INT(h.header_len, n);
}

static void test_partial_input(void) {
    cloak_ws_frame_header_t h;

    /* The brief's case: a masked 200-byte message, header fed one byte at
     * a time. Eight bytes: 82 fe 00 c8 <4-byte mask>. */
    {
        const uint8_t masked200[] = {0x82, 0xfe, 0x00, 0xc8, 0x37, 0xfa, 0x21, 0x3d};
        expect_needs_exactly(masked200, 8);
    }
    /* Every other header length the format admits: 2, 4, 6, 10, 14. */
    {
        const uint8_t inline_unmasked[] = {0x82, 0x05};
        const uint8_t inline_masked[] = {0x82, 0x85, 0x37, 0xfa, 0x21, 0x3d};
        const uint8_t u16_unmasked[] = {0x82, 0x7e, 0x00, 0xc8};
        const uint8_t u64_unmasked[] = {0x82, 0x7f, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x01, 0x00, 0x00};
        const uint8_t u64_masked[] = {0x82, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                                      0x00, 0x00, 0x37, 0xfa, 0x21, 0x3d};
        expect_needs_exactly(inline_unmasked, 2);
        expect_needs_exactly(inline_masked, 6);
        expect_needs_exactly(u16_unmasked, 4);
        expect_needs_exactly(u64_unmasked, 10);
        expect_needs_exactly(u64_masked, 14);
    }

    /* Extra bytes beyond the header are ignored: the parser reports the
     * header length, never "all the bytes I was given". */
    {
        uint8_t buf[8 + 200];
        memset(buf, 0x5a, sizeof(buf));
        buf[0] = 0x82;
        buf[1] = 0xfe;
        buf[2] = 0x00;
        buf[3] = 0xc8;
        memcpy(buf + 4, rfc_key, 4);
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(buf, sizeof(buf), &h), 8);
        ASSERT_EQ_INT(h.header_len, 8);
        ASSERT_EQ_INT(h.payload_len, 200);
        /* One byte past the header, too -- the off-by-one on the other
         * side of "exactly enough". */
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(buf, 9, &h), 8);
    }

    /* The output struct is not touched when the answer is "not yet" or
     * "malformed". A caller that keeps one header struct across reactor
     * wakeups must not find it half-overwritten by a short read.
     *
     * There are THREE distinct "not yet" returns inside the parser -- one
     * before the two fixed bytes, one before the extended length, one
     * before the mask key -- and a prefix that stops at the first of them
     * says nothing about the other two. A mutation that zeroed *out on the
     * third path survived an earlier version of this test that fed only a
     * three-byte prefix. All three are fed here, plus both malformed
     * paths (one decided from the fixed bytes, one from the 64-bit
     * length). */
    {
        const uint8_t stops_at_fixed[] = {0x82};
        const uint8_t stops_at_ext[] = {0x82, 0xfe, 0x00};
        const uint8_t stops_at_maskkey[] = {0x82, 0xfe, 0x00, 0xc8, 0x37};
        const uint8_t bad_rsv[] = {0xc2, 0x05};
        const uint8_t bad_u64[] = {0x82, 0x7f, 0x80, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00};
        cloak_ws_frame_header_t untouched;

        memset(&untouched, 0x5a, sizeof(untouched));
        memset(&h, 0x5a, sizeof(h));

        ASSERT_EQ_INT(parse_exact(stops_at_fixed, sizeof(stops_at_fixed), &h), 0);
        ASSERT_MEM_EQ(&h, &untouched, sizeof(h));
        ASSERT_EQ_INT(parse_exact(stops_at_ext, sizeof(stops_at_ext), &h), 0);
        ASSERT_MEM_EQ(&h, &untouched, sizeof(h));
        ASSERT_EQ_INT(parse_exact(stops_at_maskkey, sizeof(stops_at_maskkey), &h), 0);
        ASSERT_MEM_EQ(&h, &untouched, sizeof(h));
        ASSERT_EQ_INT(parse_exact(bad_rsv, sizeof(bad_rsv), &h), -1);
        ASSERT_MEM_EQ(&h, &untouched, sizeof(h));
        ASSERT_EQ_INT(parse_exact(bad_u64, sizeof(bad_u64), &h), -1);
        ASSERT_MEM_EQ(&h, &untouched, sizeof(h));
    }
}

/* ------------------------------------------------------------------ */
/* 8. Masking                                                          */
/* ------------------------------------------------------------------ */

static void test_masking(void) {
    /* An independent oracle: the mask is payload[i] ^= key[i & 3] with i
     * counted from the START OF THE PAYLOAD, so the expected result is
     * computed here, in the test, from that formula -- never by calling
     * the function under test twice and observing that it is its own
     * inverse (which every constant function also is). */
    static const uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
    static const uint8_t plain[7] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    uint8_t ref[7];
    uint8_t buf[7];
    size_t i, split, pos;

    for (i = 0; i < 7; i++) {
        ref[i] = (uint8_t)(plain[i] ^ key[i & 3]);
    }

    /* One shot from pos 0 must equal the oracle. */
    memcpy(buf, plain, 7);
    ASSERT_EQ_INT(cloak_ws_frame_mask(buf, 7, key, 0), 3);
    ASSERT_MEM_EQ(buf, ref, 7);
    /* ...and masking again returns the plaintext. */
    ASSERT_EQ_INT(cloak_ws_frame_mask(buf, 7, key, 0), 3);
    ASSERT_MEM_EQ(buf, plain, 7);

    /* Split at every offset, carrying pos across the chunk boundary. This
     * is the case the scouting report singles out: a partial-write loop
     * that restarts pos at 0 for each chunk produces a stream that decodes
     * correctly for the first chunk and garbage after it, and every
     * whole-buffer test passes anyway. */
    for (split = 0; split <= 7; split++) {
        size_t p;
        memcpy(buf, plain, 7);
        p = cloak_ws_frame_mask(buf, split, key, 0);
        ASSERT_EQ_INT(p, split & 3);
        p = cloak_ws_frame_mask(buf + split, 7 - split, key, p);
        ASSERT_EQ_INT(p, 7 & 3);
        ASSERT_MEM_EQ(buf, ref, 7);
    }

    /* Three-way splits, so a two-chunk-only carry cannot pass. */
    for (split = 0; split <= 7; split++) {
        size_t second;
        for (second = split; second <= 7; second++) {
            size_t p;
            memcpy(buf, plain, 7);
            p = cloak_ws_frame_mask(buf, split, key, 0);
            p = cloak_ws_frame_mask(buf + split, second - split, key, p);
            p = cloak_ws_frame_mask(buf + second, 7 - second, key, p);
            ASSERT_EQ_INT(p, 3);
            ASSERT_MEM_EQ(buf, ref, 7);
        }
    }

    /* Every starting pos in 0..3 round-trips, and the key byte actually
     * used at pos p is key[p]: a single byte masked at pos p must come out
     * as plain ^ key[p] and nothing else. */
    for (pos = 0; pos < 4; pos++) {
        uint8_t one = 0x5a;
        ASSERT_EQ_INT(cloak_ws_frame_mask(&one, 1, key, pos), (pos + 1) & 3);
        ASSERT_EQ_INT(one, (uint8_t)(0x5a ^ key[pos]));
        ASSERT_EQ_INT(cloak_ws_frame_mask(&one, 1, key, pos), (pos + 1) & 3);
        ASSERT_EQ_INT(one, 0x5a);
    }

    /* The returned pos is reduced mod 4, so it can be fed straight back in
     * without a caller having to remember to reduce it. Literal answers,
     * not an expression sharing the implementation's arithmetic. */
    {
        uint8_t scratch[16];
        memset(scratch, 0, sizeof(scratch));
        ASSERT_EQ_INT(cloak_ws_frame_mask(scratch, 0, key, 2), 2);
        ASSERT_EQ_INT(cloak_ws_frame_mask(scratch, 1, key, 3), 0);
        ASSERT_EQ_INT(cloak_ws_frame_mask(scratch, 4, key, 1), 1);
        ASSERT_EQ_INT(cloak_ws_frame_mask(scratch, 5, key, 0), 1);
        ASSERT_EQ_INT(cloak_ws_frame_mask(scratch, 16, key, 2), 2);
        /* A pos far above 3 is reduced on the way in as well as out. */
        ASSERT_EQ_INT(cloak_ws_frame_mask(scratch, 1, key, 4002), 3);
    }

    /* A pos above 3 selects the same key byte as pos & 3. */
    {
        uint8_t a = 0x5a, b = 0x5a;
        cloak_ws_frame_mask(&a, 1, key, 2);
        cloak_ws_frame_mask(&b, 1, key, 4002); /* 4002 & 3 == 2 */
        ASSERT_EQ_INT(a, b);
    }

    /* The RFC's own vector, from the other direction: masking "Hello" with
     * 37 fa 21 3d must produce exactly 7f 9f 4d 51 58. */
    {
        uint8_t hello[5];
        const uint8_t want[5] = {0x7f, 0x9f, 0x4d, 0x51, 0x58};
        memcpy(hello, "Hello", 5);
        ASSERT_EQ_INT(cloak_ws_frame_mask(hello, 5, rfc_key, 0), 1);
        ASSERT_MEM_EQ(hello, want, 5);
    }

    /* A zero-length call touches nothing and is safe on a NULL payload --
     * an empty frame's payload pointer is legitimately one-past-the-end.
     *
     * The contract is "returns pos & 3, ALWAYS", including on this
     * early-out path -- not "returns whatever you passed in, which happens
     * to work because the next call reduces on the way in". The two are
     * indistinguishable for pos in 0..3, which is why an earlier version
     * of this test, whose zero-length cases all used pos 1 and 2, let a
     * mutation that dropped the reduction here escape. Every case below
     * uses a pos ABOVE 3, where the two differ. */
    {
        uint8_t scratch[4];
        memset(scratch, 0, sizeof(scratch));
        /* len == 0, via each of the three conditions that take the
         * early-out: zero length with a real buffer, a NULL payload, and a
         * NULL key. All three must reduce. */
        ASSERT_EQ_INT(cloak_ws_frame_mask(scratch, 0, key, 4), 0);
        ASSERT_EQ_INT(cloak_ws_frame_mask(scratch, 0, key, 7), 3);
        ASSERT_EQ_INT(cloak_ws_frame_mask(scratch, 0, key, 4002), 2);
        ASSERT_EQ_INT(cloak_ws_frame_mask(NULL, 0, key, 4002), 2);
        ASSERT_EQ_INT(cloak_ws_frame_mask(NULL, 9, key, 4002), 2);
        ASSERT_EQ_INT(cloak_ws_frame_mask(scratch, 4, NULL, 4002), 2);
        /* The low-pos cases the old test had, kept: they pin that the
         * reduction does not disturb an already-reduced pos. */
        ASSERT_EQ_INT(cloak_ws_frame_mask(NULL, 0, key, 1), 1);
        ASSERT_EQ_INT(cloak_ws_frame_mask(NULL, 0, key, 0), 0);
        /* Nothing was written on any of those paths. */
        ASSERT_MEM_EQ(scratch, "\0\0\0\0", 4);
    }

    /* Masking runs over exactly len bytes: the byte after the region is
     * untouched. Checked on an exact-sized heap buffer so ASan catches the
     * overrun as well. */
    {
        uint8_t *heap = (uint8_t *)malloc(5);
        ASSERT_TRUE(heap != NULL);
        memcpy(heap, plain, 5);
        cloak_ws_frame_mask(heap, 5, key, 0);
        ASSERT_MEM_EQ(heap, ref, 5);
        free(heap);
    }
}

/* ------------------------------------------------------------------ */
/* 9. write_header capacity                                            */
/* ------------------------------------------------------------------ */

static void test_write_header_capacity(void) {
    /* For each of the six header lengths the format admits, cap == n - 1
     * must fail AND must leave the buffer untouched, and cap == n must
     * succeed. A short-buffer check placed after the bytes are written is
     * a buffer overflow that returns -1, and returning -1 is all a test
     * that only checks the return value can see. */
    struct {
        size_t n;
        int masked;
        uint64_t payload_len;
    } cases[] = {
        {2, 0, 5},
        {4, 0, 200},
        {10, 0, 65536},
        {6, 1, 5},
        {8, 1, 200},
        {14, 1, 65536},
    };
    size_t c;

    for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        const uint8_t *key = cases[c].masked ? rfc_key : NULL;
        size_t n = cases[c].n;
        uint8_t got[16];
        size_t i;

        /* Exactly enough. */
        memset(got, 0, sizeof(got));
        ASSERT_EQ_INT(write_exact(got, n, CLOAK_WS_OP_BINARY, 1, key, cases[c].payload_len),
                      (ssize_t)n);

        /* One byte short: refused, and nothing written. */
        memset(got, 0, sizeof(got));
        ASSERT_EQ_INT(write_exact(got, n - 1, CLOAK_WS_OP_BINARY, 1, key,
                                  cases[c].payload_len), -1);
        for (i = 0; i + 1 < n; i++) {
            ASSERT_EQ_INT(got[i], 0xAA);
        }

        /* Zero capacity, and one byte, are refused the same way. */
        ASSERT_EQ_INT(write_exact(NULL, 0, CLOAK_WS_OP_BINARY, 1, key,
                                  cases[c].payload_len), -1);
        ASSERT_EQ_INT(write_exact(NULL, 1, CLOAK_WS_OP_BINARY, 1, key,
                                  cases[c].payload_len), -1);
    }
}

/* ------------------------------------------------------------------ */
/* 10. Round trip, and the mask-key source                             */
/* ------------------------------------------------------------------ */

static void test_round_trip(void) {
    /* Encode then decode across the whole interesting range of lengths,
     * both directions. This is the weakest test in the file -- a codec
     * wrong in the same way in both halves passes it -- which is why every
     * byte-level expectation above is a literal instead. It is here to
     * catch disagreement between the two halves, nothing more. */
    static const uint64_t lens[] = {0, 1, 125, 126, 127, 200, 16401, 16640,
                                    65534, 65535, 65536, 65537, UINT64_C(4294967296)};
    size_t i;
    int masked;

    for (masked = 0; masked <= 1; masked++) {
        for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            uint8_t buf[CLOAK_WS_FRAME_MAX_HEADER_LEN];
            cloak_ws_frame_header_t h;
            ssize_t n = write_exact(buf, sizeof(buf), CLOAK_WS_OP_BINARY, 1,
                                    masked ? rfc_key : NULL, lens[i]);
            ASSERT_TRUE(n > 0);
            if (n <= 0) {
                continue;
            }
            memset(&h, 0, sizeof(h));
            ASSERT_EQ_INT(parse_exact(buf, (size_t)n, &h), n);
            ASSERT_EQ_INT(h.fin, 1);
            ASSERT_EQ_INT(h.masked, masked);
            ASSERT_EQ_INT(h.opcode, CLOAK_WS_OP_BINARY);
            ASSERT_TRUE(h.payload_len == lens[i]);
            if (masked) {
                ASSERT_MEM_EQ(h.mask_key, rfc_key, 4);
            }
        }
    }
}

#define MASK_KEY_DRAWS 64

static void test_mask_key_source(void) {
    /* cloak_ws_frame_mask_key draws from cloak_random_bytes (OpenSSL
     * RAND_bytes), where gorilla draws from math/rand. Randomness itself
     * has no unit test, but three specific failure modes do, and all three
     * have actually been shipped by somebody:
     *
     *   (1) a hardcoded constant -- the exact defect that passed an entire
     *       suite on the previous branch;
     *   (2) a generator that fills fewer than four bytes;
     *   (3) a PREDICTABLE generator that is nevertheless fresh every call
     *       -- a counter, or an LCG. This is the one an earlier version of
     *       this test missed: an independent reviewer's incrementing
     *       counter passed the all-identical check while producing keys an
     *       observer can extrapolate, which is precisely what RFC 6455
     *       section 5.3 forbids ("the masking key MUST be derived from a
     *       strong source of entropy"). A predictable mask key is a cheap
     *       DPI distinguisher, and DPI is this project's threat model.
     *
     * (3) is pinned two ways, because a counter can be built to defeat
     * either one alone:
     *
     *   - No constant stride. Read each key as a big-endian u32 and take
     *     the differences between consecutive draws: if EVERY difference
     *     is the same value, the source is an arithmetic progression. That
     *     kills any `key += k` counter, including `+= 0x01010101`, which
     *     varies every byte position and would survive the check below.
     *   - Variety in every byte position. Over 64 draws each of the four
     *     byte positions must take at least 8 distinct values. A counter
     *     of modest stride leaves its high bytes nearly constant, which
     *     kills it here even though its low byte marches through 64
     *     values. For a real source the expected count is about 57 of a
     *     possible 256, and the chance of landing at 8 or below is far
     *     past any rate this suite could ever flake at.
     *
     * Both of those are still OUTPUT checks, though, and an output check
     * cannot see a predictable source whose output happens to look fine:
     * a linear congruential generator walks straight through both. That
     * was measured, not assumed. So they are the second line of defence,
     * not the first -- check (0) below interposes on cloak_random_bytes
     * and pins that the key is DERIVED from it, which is what the header
     * actually promises and what no statistical test can establish. The
     * statistical checks are kept anyway: they also cover the shape of
     * what gets copied out, and a future edit that drops the
     * interposition should not drop all the coverage with it. */
    uint8_t keys[MASK_KEY_DRAWS][4];
    uint32_t words[MASK_KEY_DRAWS];
    int i, all_same = 1;

    memset(keys, 0, sizeof(keys));
    for (i = 0; i < MASK_KEY_DRAWS; i++) {
        /* (0) DERIVATION, the check the three below cannot make: every
         * draw is exactly one cloak_random_bytes call, for exactly four
         * bytes, and the key IS those bytes. A constant, a counter and an
         * LCG all fail at rng_calls == 0, whatever their output looks
         * like; a generator that asks for three bytes fails on the length;
         * one that draws four and then doctors one fails on the compare.
         * See the interposition at the top of this file. */
        rng_calls = 0;
        rng_last_len = 0;
        memset(rng_last, 0, sizeof(rng_last));
        cloak_ws_frame_mask_key(keys[i]);
        ASSERT_EQ_INT(rng_calls, 1);
        ASSERT_EQ_INT(rng_last_len, 4);
        ASSERT_MEM_EQ(keys[i], rng_last, 4);

        words[i] = ((uint32_t)keys[i][0] << 24) | ((uint32_t)keys[i][1] << 16) |
                   ((uint32_t)keys[i][2] << 8) | (uint32_t)keys[i][3];
    }

    /* (1) Not a constant. */
    for (i = 1; i < MASK_KEY_DRAWS; i++) {
        if (memcmp(keys[i], keys[0], 4) != 0) {
            all_same = 0;
        }
    }
    ASSERT_EQ_INT(all_same, 0);

    /* (2) All four bytes are filled: a generator that writes three and
     * leaves the fourth alone leaves a zero in every key. */
    {
        int b, nonzero[4] = {0, 0, 0, 0};
        for (i = 0; i < MASK_KEY_DRAWS; i++) {
            for (b = 0; b < 4; b++) {
                if (keys[i][b] != 0) {
                    nonzero[b] = 1;
                }
            }
        }
        for (b = 0; b < 4; b++) {
            ASSERT_EQ_INT(nonzero[b], 1);
        }
    }

    /* (3a) Not an arithmetic progression. Unsigned wraparound is defined,
     * so a counter that rolls over is caught the same as one that does
     * not. */
    {
        uint32_t stride = words[1] - words[0];
        int constant_stride = 1;
        for (i = 2; i < MASK_KEY_DRAWS; i++) {
            if ((uint32_t)(words[i] - words[i - 1]) != stride) {
                constant_stride = 0;
            }
        }
        ASSERT_EQ_INT(constant_stride, 0);
    }

    /* (3b) Every byte position varies. */
    {
        int b;
        for (b = 0; b < 4; b++) {
            unsigned char seen[256];
            int distinct = 0;
            memset(seen, 0, sizeof(seen));
            for (i = 0; i < MASK_KEY_DRAWS; i++) {
                if (!seen[keys[i][b]]) {
                    seen[keys[i][b]] = 1;
                    distinct++;
                }
            }
            ASSERT_TRUE(distinct >= 8);
        }
    }
}

/* ------------------------------------------------------------------ */
/* 12. Non-minimal length encodings are ACCEPTED, deliberately         */
/* ------------------------------------------------------------------ */

static void test_non_minimal_lengths_accepted(void) {
    /* RFC 6455 section 5.2 says the minimal number of bytes MUST be used
     * to encode a length. gorilla v1.5.3 does not enforce that on receipt,
     * and neither does this parser -- ON PURPOSE, and this test is what
     * stops a later "hardening" pass from quietly undoing it.
     *
     * The reasoning is cloak/conn.h's, applied here: a peer that is
     * FUSSIER than the reference implementation is itself a behavioural
     * distinguisher. If a censor can send `82 fe 00 05 ...` and watch
     * cbeuw/Cloak accept it while this port hangs up, the two are
     * telling apart by a single probe -- which is the exact class of leak
     * the whole product exists to close. Being permissive costs nothing
     * here, because the AEAD one layer up is the real authenticator.
     *
     * This is not an assumption about gorilla. All four frames below were
     * fed to a live gorilla v1.5.3 server, which accepted the first three
     * (type=2, len 5 / 5 / 0) and rejected the fourth with
     * "len > 125 for control" -- the same four verdicts asserted here.
     *
     * The encoder never emits a non-minimal form; see
     * test_length_brackets_encode, which pins every ceiling as a literal.
     * Accepting one on receive and emitting only the minimal one on send
     * is the combination that matches gorilla in both directions. */
    cloak_ws_frame_header_t h;

    /* The 126 form declaring 5 -- a length that would fit inline. */
    {
        const uint8_t b[] = {0x82, 0xfe, 0x00, 0x05, 0x37, 0xfa, 0x21, 0x3d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 8);
        ASSERT_EQ_INT(h.payload_len, 5);
        ASSERT_EQ_INT(h.header_len, 8);
        ASSERT_EQ_INT(h.opcode, CLOAK_WS_OP_BINARY);
        ASSERT_EQ_INT(h.masked, 1);
    }
    /* The 126 form declaring 0. */
    {
        const uint8_t b[] = {0x82, 0xfe, 0x00, 0x00, 0x37, 0xfa, 0x21, 0x3d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 8);
        ASSERT_EQ_INT(h.payload_len, 0);
        ASSERT_EQ_INT(h.header_len, 8);
    }
    /* The 126 form declaring 125 -- the last length the inline form could
     * have carried, so the two brackets touch. */
    {
        const uint8_t b[] = {0x82, 0x7e, 0x00, 0x7d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 4);
        ASSERT_EQ_INT(h.payload_len, 125);
        ASSERT_EQ_INT(h.header_len, 4);
    }
    /* The 127 form declaring 5 -- a length two forms too wide. */
    {
        const uint8_t b[] = {0x82, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x05, 0x37, 0xfa, 0x21, 0x3d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 14);
        ASSERT_EQ_INT(h.payload_len, 5);
        ASSERT_EQ_INT(h.header_len, 14);
    }
    /* The 127 form declaring 65535 -- the last length the u16 form could
     * have carried. The other side of the same bracket. */
    {
        const uint8_t b[] = {0x82, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0xff, 0xff};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 10);
        ASSERT_EQ_INT(h.payload_len, 65535);
        ASSERT_EQ_INT(h.header_len, 10);
    }
    /* The counter-bracket, and the subtle half of the rule: permissiveness
     * about the FORM does not extend to control frames, because the
     * control-length rule is applied to the 7-bit field rather than to the
     * decoded value. A ping declaring 5 bytes in the 126 form is rejected
     * -- by gorilla and by us -- even though 5 is a legal control payload.
     * Without this case, "accept non-minimal forms" could have been
     * implemented as "skip the control-length check when the form is
     * extended", which gorilla would not match. */
    {
        const uint8_t b[] = {0x89, 0xfe, 0x00, 0x05, 0x37, 0xfa, 0x21, 0x3d};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), -1);
    }
}

/* ------------------------------------------------------------------ */
/* 13. This layer does not bound payload_len -- the caller owes it      */
/* ------------------------------------------------------------------ */

static void test_payload_len_is_not_bounded_here(void) {
    /* A DECLARED length is reported as declared, however large. Nothing in
     * this file compares payload_len against CLOAK_CONN_MAX_FRAME_LEN
     * (16640) or against anything else, and that is deliberate: this layer
     * has no buffer, so it cannot know what the caller can hold, and a
     * parser that silently rejected a large declaration would hide a
     * hostile peer instead of reporting it.
     *
     * The consequence is an obligation, not an absence: whoever buffers
     * the payload -- the CDN-path conn in task 2 -- must compare
     * payload_len against CLOAK_CONN_MAX_FRAME_LEN itself. The existing
     * enforcement points (cloak_conn_init, cloak_session_init,
     * cloak_switchboard_init) are all on the DIRECT TLS-record path and do
     * not see a byte of this one.
     *
     * A measured bracket around the bound that is NOT applied here: 16640
     * is CLOAK_CONN_MAX_FRAME_LEN itself and 16641 is one past it, and
     * both parse identically. A well-meaning "hardening" edit that added
     * the check to this layer would fail on 16641 -- and it should fail,
     * because it would be enforcing a mimicry bound in a place that cannot
     * report it to the layer that has to act on it. */
    cloak_ws_frame_header_t h;

    /* 16640 == CLOAK_CONN_MAX_FRAME_LEN, written as a literal u16. */
    {
        const uint8_t b[] = {0x82, 0x7e, 0x41, 0x00};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 4);
        ASSERT_EQ_INT(h.payload_len, 16640);
    }
    /* 16641 == one past it. Parsed exactly the same way. */
    {
        const uint8_t b[] = {0x82, 0x7e, 0x41, 0x01};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 4);
        ASSERT_EQ_INT(h.payload_len, 16641);
    }
    /* And far past it, in the 64-bit form: 4 GiB. */
    {
        const uint8_t b[] = {0x82, 0x7f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                             0x00, 0x00};
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(parse_exact(b, sizeof(b), &h), 10);
        ASSERT_TRUE(h.payload_len == UINT64_C(4294967296));
    }
    /* The encoder is equally unbounded: it will frame a 4 GiB payload if
     * asked. Only the RFC's own high-bit rule stops it, and that is
     * asserted in test_u64_high_bit. */
    ASSERT_EQ_INT(write_exact(NULL, 14, CLOAK_WS_OP_BINARY, 1, NULL,
                              UINT64_C(4294967296)), 10);
}

/* ------------------------------------------------------------------ */
/* 14. The NULL-argument contract                                      */
/* ------------------------------------------------------------------ */

static void test_null_arguments(void) {
    /* The header promises -1, and the difference between -1 and 0 is not
     * cosmetic: 0 means "call me again with more bytes", so a caller
     * looping on 0 against a NULL buffer spins forever. These are the only
     * calls in this file that do not go through parse_exact/write_exact,
     * because the whole point of them is that there is no buffer; the
     * one case that does pass a buffer gets a heap-exact one anyway, so
     * the file's "every input is allocated to exactly its length"
     * discipline is unbroken. */
    cloak_ws_frame_header_t h;
    cloak_ws_frame_header_t untouched;
    uint8_t *two;

    memset(&h, 0x5a, sizeof(h));
    memset(&untouched, 0x5a, sizeof(untouched));

    /* NULL buf, with a length that would otherwise be a complete header,
     * and with zero length. Both -1, never 0. */
    ASSERT_EQ_INT(cloak_ws_frame_parse_header(NULL, 8, &h), -1);
    ASSERT_MEM_EQ(&h, &untouched, sizeof(h));
    ASSERT_EQ_INT(cloak_ws_frame_parse_header(NULL, 0, &h), -1);
    ASSERT_MEM_EQ(&h, &untouched, sizeof(h));

    /* NULL out, with a buffer holding a perfectly good header: still -1,
     * and nothing is dereferenced. */
    two = (uint8_t *)malloc(2);
    ASSERT_TRUE(two != NULL);
    two[0] = 0x82;
    two[1] = 0x00;
    ASSERT_EQ_INT(cloak_ws_frame_parse_header(two, 2, NULL), -1);
    /* Both NULL at once. */
    ASSERT_EQ_INT(cloak_ws_frame_parse_header(NULL, 2, NULL), -1);
    /* The same buffer with both arguments valid still parses, so the four
     * rejections above are attributable to the NULLs and not to the
     * input. */
    memset(&h, 0, sizeof(h));
    ASSERT_EQ_INT(cloak_ws_frame_parse_header(two, 2, &h), 2);
    ASSERT_EQ_INT(h.payload_len, 0);
    free(two);

    /* write_header's NULL buffer, for each of the two directions and at a
     * capacity that would otherwise be ample. */
    ASSERT_EQ_INT(cloak_ws_frame_write_header(NULL, 14, CLOAK_WS_OP_BINARY, 1,
                                              NULL, 5), -1);
    ASSERT_EQ_INT(cloak_ws_frame_write_header(NULL, 14, CLOAK_WS_OP_BINARY, 1,
                                              rfc_key, 5), -1);
    /* ...and with zero capacity, where the capacity check would also have
     * refused: the NULL must be what decides it, so this is only a
     * consistency check, not the bracket. */
    ASSERT_EQ_INT(cloak_ws_frame_write_header(NULL, 0, CLOAK_WS_OP_BINARY, 1,
                                              NULL, 5), -1);
}

TEST_MAIN_BEGIN()
    test_rfc_sample_frames();
    test_length_brackets_decode();
    test_length_brackets_encode();
    test_u64_high_bit();
    test_rsv_bits();
    test_control_frame_constraints();
    test_unknown_opcodes();
    test_partial_input();
    test_masking();
    test_write_header_capacity();
    test_round_trip();
    test_mask_key_source();
    test_non_minimal_lengths_accepted();
    test_payload_len_is_not_bounded_here();
    test_null_arguments();
TEST_MAIN_END()
