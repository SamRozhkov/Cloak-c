#ifndef CLOAK_FRAME_H
#define CLOAK_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/crypto.h"

#define CLOAK_FRAME_HEADER_LEN 14
#define CLOAK_FRAME_MAX_EXTRA_LEN 255
#define CLOAK_FRAME_PAD_FIRST_N_FRAMES 5

#define CLOAK_FRAME_CLOSING_NOTHING 0
#define CLOAK_FRAME_CLOSING_STREAM 1
#define CLOAK_FRAME_CLOSING_SESSION 2

/* A WINDOW UPDATE, AND WHY IT LIVES IN THE `closing` BYTE.
 *
 * That byte is already a frame-type selector in everything but name --
 * every receiver switches on it before looking at the payload -- and it
 * has 253 unused values. Putting a type here costs nothing on the wire:
 * no header change, no length change, and the existing stream-id routing
 * delivers it to the right stream with no new dispatch path.
 *
 * Payload: exactly CLOAK_FRAME_WINDOW_UPDATE_LEN bytes, little-endian,
 * the number of ADDITIONAL bytes the sender of this frame can now accept
 * on this stream. A delta rather than an absolute level, so a reordered
 * update cannot make a window go backwards.
 *
 * NOTHING PRODUCES OR CONSUMES THIS YET. It is declared and its encoding
 * is pinned first, on its own, because the previous attempt landed the
 * whole mechanism in one step and left 14 tests red with no way to tell
 * which of five changes was at fault. See
 * docs/superpowers/plans/2026-09-24-per-stream-credit-plan.md.
 *
 * A deliberate divergence from Go, which has no flow control at all and
 * pays for it with an unbounded reassembly buffer. Parity is no longer a
 * requirement. */
#define CLOAK_FRAME_TYPE_WINDOW_UPDATE 3
#define CLOAK_FRAME_WINDOW_UPDATE_LEN 4

typedef struct {
    uint32_t stream_id;
    uint64_t seq;
    uint8_t closing;
    const uint8_t *payload;
    size_t payload_len;
} cloak_frame_t;

typedef struct {
    cloak_aead_method_t method;
    uint8_t session_key[CLOAK_AEAD_KEY_LEN];
} cloak_obfuscator_t;

/* Serializes and encrypts frame into buf (capacity buf_cap). frame->payload_len
 * must be nonzero.
 *
 * If payload_offset_in_buf == CLOAK_FRAME_HEADER_LEN, the caller has already
 * written frame->payload_len bytes at buf[CLOAK_FRAME_HEADER_LEN:] and this
 * function skips copying frame->payload (frame->payload itself is then
 * unused). Any other value causes frame->payload to be copied into place.
 *
 * Returns the number of bytes written to buf (> 0) on success, or -1 on
 * failure (empty payload, buf_cap too small, or an AEAD failure). */
long cloak_frame_obfuscate(const cloak_obfuscator_t *o, const cloak_frame_t *frame,
                            uint8_t *buf, size_t buf_cap, size_t payload_offset_in_buf);

/* Decrypts and parses a frame from buf IN PLACE: the header is decrypted in
 * place, and on success out_frame->payload points into buf (no copy, no
 * separate output buffer). buf must not be read again as ciphertext after
 * this call.
 *
 * Returns 0 on success, -1 on failure (buf_len too short, a corrupt
 * extra_len field pointing past the available data, or an AEAD
 * authentication failure). */
int cloak_frame_deobfuscate(const cloak_obfuscator_t *o, cloak_frame_t *out_frame,
                             uint8_t *buf, size_t buf_len);

#endif
