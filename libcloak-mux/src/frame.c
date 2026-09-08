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

static uint8_t random_pad_len(size_t max_inclusive) {
    uint8_t b;
    cloak_random_bytes(&b, 1);
    return (uint8_t)(b % (max_inclusive + 1));
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
        int rc = cloak_aead_seal(o->method, o->session_key, nonce,
                                  buf + 12, 2,
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
        int rc = cloak_aead_open(o->method, o->session_key, nonce,
                                  buf + 12, 2,
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
