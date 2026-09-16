#define _POSIX_C_SOURCE 200809L

#include "cloak/ws_frame.h"

#include <string.h>

#include "cloak/common.h"

/* Bit positions in the first header byte. RFC 6455 section 5.2. */
#define WS_FIN_BIT   0x80
#define WS_RSV1_BIT  0x40
#define WS_RSV2_BIT  0x20
#define WS_RSV3_BIT  0x10
#define WS_OPCODE_MASK 0x0f

/* Bit positions in the second header byte. */
#define WS_MASK_BIT  0x80
#define WS_LEN7_MASK 0x7f

/* The two length-form markers. 126 means "a big-endian u16 follows", 127
 * means "a big-endian u64 follows"; anything below is the length itself.
 * Deliberately NOT shared with the test file -- an expectation derived
 * from the same constant as the implementation cannot observe the
 * implementation changing. */
#define WS_LEN7_U16 126
#define WS_LEN7_U64 127

/* RFC 6455 section 5.2: the 64-bit length's "most significant bit MUST be
 * 0". A peer setting it is malformed, not merely asking for too much. */
#define WS_U64_LEN_HIGH_BIT UINT64_C(0x8000000000000000)

/* Whether an opcode is one of the six RFC 6455 defines. 0x3-0x7 and
 * 0xB-0xF are reserved; gorilla's advanceFrame rejects them outright, so
 * accepting them here would be a divergence in the direction of leniency
 * -- which is just as detectable as one in the direction of strictness. */
static int ws_opcode_is_known(unsigned op) {
    switch (op) {
    case CLOAK_WS_OP_CONTINUATION:
    case CLOAK_WS_OP_TEXT:
    case CLOAK_WS_OP_BINARY:
    case CLOAK_WS_OP_CLOSE:
    case CLOAK_WS_OP_PING:
    case CLOAK_WS_OP_PONG:
        return 1;
    default:
        return 0;
    }
}

/* Control frames are the opcodes with the high bit of the nibble set
 * (RFC 6455 section 5.5); data frames are the rest. */
static int ws_opcode_is_control(unsigned op) {
    return (op & 0x8) != 0;
}

static uint16_t ws_load_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint64_t ws_load_be64(const uint8_t *p) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static void ws_store_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void ws_store_be64(uint8_t *p, uint64_t v) {
    int i;
    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

ssize_t cloak_ws_frame_parse_header(const uint8_t *buf, size_t len,
                                    cloak_ws_frame_header_t *out) {
    cloak_ws_frame_header_t h;
    unsigned b0, b1, op, len7;
    size_t ext_len, need;

    if (buf == NULL || out == NULL) {
        return -1;
    }
    /* The two fixed bytes carry everything needed to decide malformedness
     * and everything needed to compute how much more to wait for, so
     * nothing at all can be decided before they are both present. */
    if (len < 2) {
        return 0;
    }

    b0 = buf[0];
    b1 = buf[1];
    op = b0 & WS_OPCODE_MASK;
    len7 = b1 & WS_LEN7_MASK;

    /* Every rejection below is made here, from these two bytes, BEFORE any
     * "need more bytes" return. A peer that has already invalidated its
     * header must not be able to hold the connection open by never
     * finishing it. */
    if ((b0 & (WS_RSV1_BIT | WS_RSV2_BIT | WS_RSV3_BIT)) != 0) {
        return -1;
    }
    if (!ws_opcode_is_known(op)) {
        return -1;
    }
    if (ws_opcode_is_control(op)) {
        /* RFC 6455 section 5.5. Note this tests len7, not the decoded
         * length: a control frame using the extended form at all is
         * malformed even if the value it would decode to is small, which
         * is what gorilla checks (p[1]&0x7f > maxControlFramePayloadSize)
         * and what closes the "declare 1 byte in the 64-bit form" gap. */
        if (len7 > CLOAK_WS_FRAME_MAX_CONTROL_PAYLOAD) {
            return -1;
        }
        if ((b0 & WS_FIN_BIT) == 0) {
            return -1;
        }
    }

    if (len7 == WS_LEN7_U16) {
        ext_len = 2;
    } else if (len7 == WS_LEN7_U64) {
        ext_len = 8;
    } else {
        ext_len = 0;
    }

    /* The extended length is examined before the mask key is waited for,
     * so that an illegal 64-bit length is rejected at byte 10 rather than
     * at byte 14. Same argument as above. */
    if (len < 2 + ext_len) {
        return 0;
    }
    if (ext_len == 2) {
        h.payload_len = ws_load_be16(buf + 2);
    } else if (ext_len == 8) {
        h.payload_len = ws_load_be64(buf + 2);
        if ((h.payload_len & WS_U64_LEN_HIGH_BIT) != 0) {
            return -1;
        }
    } else {
        h.payload_len = len7;
    }

    need = 2 + ext_len + (((b1 & WS_MASK_BIT) != 0) ? 4u : 0u);
    if (len < need) {
        return 0;
    }

    h.opcode = (cloak_ws_opcode_t)op;
    h.fin = ((b0 & WS_FIN_BIT) != 0) ? 1 : 0;
    h.masked = ((b1 & WS_MASK_BIT) != 0) ? 1 : 0;
    if (h.masked) {
        memcpy(h.mask_key, buf + 2 + ext_len, 4);
    } else {
        /* Zeroed rather than left indeterminate: a caller that masks
         * unconditionally with whatever is in this field would otherwise
         * corrupt an unmasked payload with stack garbage, and an all-zero
         * key is at least the identity. */
        memset(h.mask_key, 0, sizeof(h.mask_key));
    }
    h.header_len = need;

    /* Committed only now, so that a 0 or -1 return leaves *out exactly as
     * the caller left it. See the header's contract. */
    *out = h;
    return (ssize_t)need;
}

size_t cloak_ws_frame_mask(uint8_t *payload, size_t len,
                           const uint8_t key[4], size_t pos) {
    size_t i;

    if (len == 0 || payload == NULL || key == NULL) {
        return pos & 3;
    }
    /* pos counts from the start of the WHOLE payload, so the key byte for
     * this chunk's byte i is key[(pos + i) & 3]. Reducing pos on the way
     * in as well as on the way out means a caller that accumulated an
     * absolute offset rather than the returned residue still gets the
     * right answer. */
    for (i = 0; i < len; i++) {
        payload[i] ^= key[(pos + i) & 3];
    }
    return (pos + len) & 3;
}

ssize_t cloak_ws_frame_write_header(uint8_t *buf, size_t cap,
                                    cloak_ws_opcode_t op, int fin,
                                    const uint8_t mask_key[4], uint64_t payload_len) {
    size_t ext_len, need;
    uint8_t b1;

    if (buf == NULL) {
        return -1;
    }
    /* Refuse to emit anything this file's own parser would reject: the two
     * halves of a codec disagreeing is the defect that survives every
     * round-trip test, since both ends agree with each other. */
    if (!ws_opcode_is_known((unsigned)op)) {
        return -1;
    }
    if (ws_opcode_is_control((unsigned)op)) {
        if (payload_len > CLOAK_WS_FRAME_MAX_CONTROL_PAYLOAD || !fin) {
            return -1;
        }
    }
    if ((payload_len & WS_U64_LEN_HIGH_BIT) != 0) {
        return -1;
    }

    /* Always the minimal form. A non-minimal encoding is legal on the wire
     * and this port accepts one on receipt, but emitting one would be a
     * gratuitous difference from what gorilla puts on the wire, and this
     * layer exists to be indistinguishable from gorilla. */
    if (payload_len <= 125) {
        ext_len = 0;
    } else if (payload_len <= 0xffff) {
        ext_len = 2;
    } else {
        ext_len = 8;
    }

    need = 2 + ext_len + ((mask_key != NULL) ? 4u : 0u);
    /* Checked before the first store, so a short buffer is a refusal and
     * never a partially-written one. */
    if (cap < need) {
        return -1;
    }

    buf[0] = (uint8_t)((fin ? WS_FIN_BIT : 0u) | ((unsigned)op & WS_OPCODE_MASK));

    if (ext_len == 0) {
        b1 = (uint8_t)payload_len;
    } else if (ext_len == 2) {
        b1 = WS_LEN7_U16;
        ws_store_be16(buf + 2, (uint16_t)payload_len);
    } else {
        b1 = WS_LEN7_U64;
        ws_store_be64(buf + 2, payload_len);
    }
    if (mask_key != NULL) {
        /* RFC 6455 section 5.1: only a client masks. gorilla rejects a
         * masking server with "bad MASK", and so does every browser. */
        b1 = (uint8_t)(b1 | WS_MASK_BIT);
        memcpy(buf + 2 + ext_len, mask_key, 4);
    }
    buf[1] = b1;

    return (ssize_t)need;
}

void cloak_ws_frame_mask_key(uint8_t key[4]) {
    /* OpenSSL RAND_bytes, which aborts rather than returning weak output.
     * One four-byte draw per frame -- never one per byte. See the header
     * for why this deviates from gorilla's math/rand, and why that is
     * recorded rather than defended. */
    cloak_random_bytes(key, 4);
}
