/* TARGET #5: cloak_ws_frame_parse_header (libcloak-mux/src/ws_frame.c).
 *
 * WHY THIS TARGET EXISTS, STATED HONESTLY: IT IS REGRESSION INSURANCE,
 * NOT A BUG HUNT. Module 8 specified this target and deferred it, and
 * this module's plan says why writing it now is still worth doing and
 * what it is NOT expected to deliver. Module 10's scouting run did 11.3
 * MILLION executions against this very parser and cloak_ws_handshake_parse
 * and found zero crashes (READ from the scout's report, not re-measured
 * here). This parser has been read, bounded and tested hard:
 * libcloak-mux/tests/test_ws_frame.c drives every length form, every
 * reserved opcode, every truncation. So the expected outcome of running
 * this target on the tree as it stands is GREEN, and a green run proves
 * nothing at all.
 *
 * What it buys is the day somebody edits ws_frame.c -- a new length form,
 * a bound moved, a "the caller already checked this" simplification. On
 * that day this target is already written, already seeded and already in
 * the build, and the oracles below check the parser's ANSWER rather than
 * merely whether it crashed. That is the whole claim. Anyone reading this
 * expecting a finding today should read the previous paragraph again.
 *
 * WHY "DID NOT CRASH" IS A WEAK ORACLE HERE, and what is done instead.
 * This function reads at most 14 bytes and writes a caller-owned struct,
 * so an out-of-bounds access is already hard to produce and ASan would be
 * watching a very small surface. Every interesting failure of this parser
 * is a WRONG ANSWER, not a crash: a payload_len decoded from the wrong
 * offset, a header_len that does not match the bytes the header actually
 * occupies (which desynchronises the stream one layer up and is
 * indistinguishable from a crash to the peer), a mask key copied from the
 * wrong place, a "need more bytes" where a rejection was owed. So:
 *
 *   O1  The return value is -1, 0, or a header length in {2,4,6,8,10,14},
 *       and on success it equals out.header_len exactly.
 *   O2  A SECOND, INDEPENDENT DECODE. ws_expect() below re-derives the
 *       whole answer from the raw bytes, written from RFC 6455 section
 *       5.2 and cloak/ws_frame.h's contract rather than from ws_frame.c,
 *       and every field is compared. This is deliberately a mirror: it is
 *       the only oracle that notices a subtly wrong answer, and a mirror
 *       written from the spec is exactly what a differential test is.
 *   O3  THE PREFIX LADDER, which is the one an incremental caller depends
 *       on. Every prefix of the input is parsed, and the sequence of
 *       answers must be a run of 0s ("need more") followed by ONE stable
 *       terminal answer that never changes as more bytes arrive. A parser
 *       that says "need more" and then rejects, or that returns one
 *       header length at 10 bytes and a different one at 14, breaks a
 *       socket accumulator in a way no single-length test would see.
 *   O4  *out is untouched on 0 and -1 (the header promises a struct held
 *       across reactor wakeups is never found half-overwritten): the
 *       struct is pre-filled with a sentinel and memcmp'd.
 *   O5  masked == 0 implies mask_key is zeroed, never stale bytes.
 *   O6  ENCODE/DECODE ARE INVERSES. A successfully parsed header is
 *       re-emitted with cloak_ws_frame_write_header and re-parsed; every
 *       field must survive. When the input already used the minimal
 *       length form the re-emitted BYTES must be identical to the input's
 *       header too -- non-minimal forms are accepted on purpose (see
 *       ws_frame.h), so the byte comparison is made only where it is owed.
 *
 * INPUT FORMAT: none. The input is the wire bytes. -max_len can be small
 * (64 is ample for a 14-byte header plus slack); the corpus is sized for
 * that.
 *
 * GATE ANALYSIS: there is none. Every rejection is decided from the first
 * two bytes, each check is its own short-circuited branch with its own
 * coverage edge, and no field of the input is ever compared against
 * another field of the input -- which is precisely the shape module 10a
 * task 1 measured as unclimbable (a 2^64-wide equality with no gradient)
 * and this parser does not have. The corpus below is convenience, not
 * reachability.
 *
 * The copy into an exact-sized allocation is the same device
 * fuzz_clienthello.c uses and is here for the same reason: ASan redzones
 * immediately before and after the bytes, so a one-byte overrun in either
 * direction is a report rather than a read of libFuzzer's own buffer.
 */

#include "cloak/ws_frame.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_CHECK(cond, msg)                                                  \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "fuzz_ws_frame: oracle failed: %s\n", (msg));       \
            abort();                                                           \
        }                                                                      \
    } while (0)

/* The independent decode of O2. Returns the same three-valued answer
 * cloak_ws_frame_parse_header does and fills *exp on success. Written
 * from RFC 6455 section 5.2 and the contract in cloak/ws_frame.h. */
static ssize_t ws_expect(const uint8_t *buf, size_t len,
                         cloak_ws_frame_header_t *exp) {
    unsigned b0, b1, op, len7;
    size_t ext, need;

    if (len < 2) {
        return 0;
    }
    b0 = buf[0];
    b1 = buf[1];
    op = b0 & 0x0fu;
    len7 = b1 & 0x7fu;

    if ((b0 & 0x70u) != 0) {          /* RSV1/RSV2/RSV3 */
        return -1;
    }
    if (!(op == 0x0u || op == 0x1u || op == 0x2u || op == 0x8u || op == 0x9u ||
          op == 0xAu)) {
        return -1;
    }
    if ((op & 0x8u) != 0) {           /* control frame */
        if (len7 > CLOAK_WS_FRAME_MAX_CONTROL_PAYLOAD) {
            return -1;
        }
        if ((b0 & 0x80u) == 0) {      /* FIN must be set */
            return -1;
        }
    }

    ext = (len7 == 126) ? 2u : (len7 == 127) ? 8u : 0u;
    if (len < 2 + ext) {
        return 0;
    }
    if (ext == 2) {
        exp->payload_len = ((uint64_t)buf[2] << 8) | (uint64_t)buf[3];
    } else if (ext == 8) {
        uint64_t v = 0;
        int i;
        for (i = 0; i < 8; i++) {
            v = (v << 8) | (uint64_t)buf[2 + i];
        }
        if ((v >> 63) != 0) {
            return -1;
        }
        exp->payload_len = v;
    } else {
        exp->payload_len = len7;
    }

    need = 2 + ext + (((b1 & 0x80u) != 0) ? 4u : 0u);
    if (len < need) {
        return 0;
    }
    exp->opcode = (cloak_ws_opcode_t)op;
    exp->fin = ((b0 & 0x80u) != 0) ? 1 : 0;
    exp->masked = ((b1 & 0x80u) != 0) ? 1 : 0;
    memset(exp->mask_key, 0, sizeof(exp->mask_key));
    if (exp->masked) {
        memcpy(exp->mask_key, buf + 2 + ext, 4);
    }
    exp->header_len = need;
    return (ssize_t)need;
}

static int header_len_is_legal(size_t n) {
    return n == 2 || n == 4 || n == 6 || n == 8 || n == 10 || n == 14;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *buf;
    cloak_ws_frame_header_t out, sentinel, exp;
    ssize_t r, want;
    size_t prefix;
    int terminal_seen = 0;
    ssize_t terminal = 0;

    buf = (uint8_t *)malloc(size == 0 ? 1 : size);
    if (buf == NULL) {
        return 0;
    }
    if (size > 0) {
        memcpy(buf, data, size);
    }

    /* A recognisable pattern, so O4 can tell "untouched" from "written
     * with something that happens to look plausible". */
    memset(&sentinel, 0xA5, sizeof(sentinel));
    out = sentinel;

    r = cloak_ws_frame_parse_header(buf, size, &out);

    /* O1 */
    FUZZ_CHECK(r >= -1, "parse returned something below -1");
    if (r > 0) {
        FUZZ_CHECK(header_len_is_legal((size_t)r), "header length is not one of 2/4/6/8/10/14");
        FUZZ_CHECK((size_t)r == out.header_len, "return value disagrees with out.header_len");
        FUZZ_CHECK((size_t)r <= size, "header longer than the bytes supplied");
    } else {
        /* O4 */
        FUZZ_CHECK(memcmp(&out, &sentinel, sizeof(out)) == 0,
                   "non-success parse wrote to *out");
    }

    /* O2 */
    memset(&exp, 0, sizeof(exp));
    want = ws_expect(buf, size, &exp);
    FUZZ_CHECK(r == want, "parse disagrees with the independent decode on the return value");
    if (r > 0) {
        FUZZ_CHECK(out.opcode == exp.opcode, "opcode disagrees with the independent decode");
        FUZZ_CHECK(out.fin == exp.fin, "fin disagrees with the independent decode");
        FUZZ_CHECK(out.masked == exp.masked, "masked disagrees with the independent decode");
        FUZZ_CHECK(out.payload_len == exp.payload_len,
                   "payload_len disagrees with the independent decode");
        FUZZ_CHECK(out.header_len == exp.header_len,
                   "header_len disagrees with the independent decode");
        FUZZ_CHECK(memcmp(out.mask_key, exp.mask_key, sizeof(out.mask_key)) == 0,
                   "mask_key disagrees with the independent decode");
        /* O5 */
        if (!out.masked) {
            static const uint8_t zero4[4] = {0, 0, 0, 0};
            FUZZ_CHECK(memcmp(out.mask_key, zero4, 4) == 0,
                       "unmasked frame left a non-zero mask key");
        }
    }

    /* O3: the prefix ladder. */
    for (prefix = 0; prefix <= size; prefix++) {
        cloak_ws_frame_header_t p_out = sentinel;
        ssize_t pr = cloak_ws_frame_parse_header(buf, prefix, &p_out);
        FUZZ_CHECK(pr >= -1, "prefix parse returned something below -1");
        if (!terminal_seen) {
            if (pr != 0) {
                terminal_seen = 1;
                terminal = pr;
            }
        } else {
            FUZZ_CHECK(pr == terminal,
                       "a terminal answer changed as more bytes arrived");
        }
        if (pr == 0) {
            FUZZ_CHECK(memcmp(&p_out, &sentinel, sizeof(p_out)) == 0,
                       "an incomplete parse wrote to *out");
        }
    }
    if (terminal_seen) {
        FUZZ_CHECK(terminal == r, "the ladder's terminal answer is not the full-input answer");
    }

    /* O6: encode and decode are inverses. */
    if (r > 0) {
        uint8_t enc[CLOAK_WS_FRAME_MAX_HEADER_LEN];
        ssize_t w = cloak_ws_frame_write_header(enc, sizeof(enc), out.opcode, out.fin,
                                                out.masked ? out.mask_key : NULL,
                                                out.payload_len);
        FUZZ_CHECK(w > 0, "a header this parser accepted cannot be re-emitted");
        FUZZ_CHECK(header_len_is_legal((size_t)w), "re-emitted header has an illegal length");
        {
            cloak_ws_frame_header_t back = sentinel;
            ssize_t rr = cloak_ws_frame_parse_header(enc, (size_t)w, &back);
            FUZZ_CHECK(rr == w, "re-emitted header does not re-parse to its own length");
            FUZZ_CHECK(back.opcode == out.opcode, "opcode lost in the round trip");
            FUZZ_CHECK(back.fin == out.fin, "fin lost in the round trip");
            FUZZ_CHECK(back.masked == out.masked, "masked lost in the round trip");
            FUZZ_CHECK(back.payload_len == out.payload_len, "payload_len lost in the round trip");
            FUZZ_CHECK(memcmp(back.mask_key, out.mask_key, 4) == 0,
                       "mask_key lost in the round trip");
        }
        /* Byte-for-byte only where the input was already minimal:
         * cloak/ws_frame.h accepts a non-minimal length form on purpose
         * (gorilla does), and the writer always emits the minimal one, so
         * a non-minimal input legitimately re-emits shorter. */
        if ((size_t)w == (size_t)r) {
            FUZZ_CHECK(memcmp(enc, buf, (size_t)w) == 0,
                       "a minimal header did not re-emit byte for byte");
        } else {
            FUZZ_CHECK((size_t)w < (size_t)r,
                       "the minimal form is longer than the form on the wire");
        }
    }

    free(buf);
    return 0;
}
