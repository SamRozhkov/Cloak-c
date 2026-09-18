/* TARGET #4: cloak_ws_handshake_parse and cloak_ws_handshake_compose_101
 * (libcloak-server/src/ws_handshake.c), the server's CDN front door --
 * unauthenticated, reached by anything that can open a TCP connection to
 * the origin and send a GET.
 *
 * WHY THIS TARGET EXISTS, STATED HONESTLY: IT IS REGRESSION INSURANCE,
 * NOT A BUG HUNT. Module 8 specified this target and deferred it. Module
 * 10's scouting run did 11.3 MILLION executions against this parser and
 * cloak_ws_frame_parse_header and found ZERO crashes (READ from the
 * scout's report, not re-measured here), and
 * libcloak-server/tests/test_ws_handshake.c already drives the CDN-shaped
 * request, the case-folded header names, the truncations and the golden
 * Go vector. The expected outcome of running this target on the tree as
 * it stands is GREEN, and a green run proves nothing. What it buys is the
 * day somebody edits ws_handshake.c; on that day the target is already
 * written, seeded and in the build.
 *
 * WHAT THE ORACLES CHECK BEYOND "DID NOT CRASH". The failure mode that
 * matters here is not a segfault, it is HANDING THE AUTHENTICATOR THE
 * WRONG 96 BYTES -- bytes from the wrong header, from the wrong offset,
 * or from uninitialised storage -- because those 96 bytes are the
 * ciphertext the whole session's authentication is decided from.
 *
 *   O1  THE 96 BYTES MUST ACTUALLY BE IN THE REQUEST. On OK, out.hidden
 *       is re-encoded with the same standard-alphabet base64 the parser
 *       decoded it with, and the resulting 128 characters must appear
 *       VERBATIM somewhere in the request buffer. A parser that returned
 *       a shifted, stale or partly-uninitialised payload passes every
 *       "did not crash" check and fails this one. This is the oracle that
 *       makes the target worth running, and it is the analogue of task
 *       2's O7: check the answer against the bytes that produced it, not
 *       merely that the answer is in range.
 *   O2  out.accept is 28 characters, NUL-terminated, drawn from the
 *       standard base64 alphabet, and decodes to EXACTLY 20 bytes -- the
 *       length of the SHA-1 digest it is defined to be. Independent of
 *       the parser's own arithmetic.
 *   O3  The accept is safe to put in a response header: no CR, no LF, no
 *       byte below 0x20. A value carrying either splits the 101 into
 *       headers of an attacker's choosing, which is the reason
 *       compose_101 validates its argument at all.
 *   O4  compose_101 accepts what parse produced, returns exactly
 *       CLOAK_WS_HS_101_LEN into an EXACT-SIZED heap buffer (so ASan's
 *       redzone catches a one-byte overrun), and the accept appears in
 *       the bytes it wrote.
 *   O5  compose_101 with one byte less capacity returns -1, again into an
 *       exact-sized buffer, so "refused" is checked to mean "wrote
 *       nothing" rather than "overflowed and then returned -1".
 *   O6  On any non-OK result *out is byte-for-byte untouched: the header
 *       promises there is no half-filled `hidden` for a caller to mistake
 *       for an authenticated payload. Pre-filled with a sentinel and
 *       memcmp'd.
 *   O7  The result is one of the enumerated codes, and OK is never
 *       returned for an empty or NULL request.
 *
 * INPUT FORMAT: none. The input is the request bytes exactly as
 * cloak_firstpacket_t would hand them over. The copy into an exact-sized
 * allocation puts ASan redzones either side, so "never reads past
 * req + len" -- the property the header claims can be checked
 * mechanically -- actually is.
 *
 * GATE ANALYSIS, AND WHY THE CORPUS IS HERE. This target has the deepest
 * gate of the four in this task: reaching CLOAK_WS_HS_OK needs a
 * well-formed request line, a blank-line-terminated header block, a
 * `Connection: Upgrade`, an `Upgrade: websocket`, a
 * `Sec-WebSocket-Version: 13`, a `Sec-WebSocket-Key` that is base64 of
 * exactly 16 bytes, and a `Hidden` header that is base64 of EXACTLY 96
 * bytes -- 128 alphabet characters, all of which must survive every
 * mutation together. Unlike task 1's 2^64 equality there IS a coverage
 * gradient here: each header is matched by its own loop with its own
 * edges, so the mutator is rewarded byte by byte. The measurement is in
 * this module's task 3 report; what is NOT claimed is that the corpus is
 * merely a speed-up, because it was not measured to be one.
 */

#include "cloak/ws_handshake.h"

#include "cloak/base64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_CHECK(cond, msg)                                                  \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "fuzz_ws_handshake: oracle failed: %s\n", (msg));   \
            abort();                                                           \
        }                                                                      \
    } while (0)

/* strlen with a hard bound, written out rather than calling strnlen:
 * strnlen is POSIX, not C11, and this file is built as C11. */
static size_t bounded_len(const char *s, size_t cap) {
    size_t i;
    for (i = 0; i < cap; i++) {
        if (s[i] == '\0') {
            break;
        }
    }
    return i;
}

static int is_std_b64_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

/* Plain substring search over a non-NUL-terminated haystack. */
static int contains(const uint8_t *hay, size_t hay_len, const char *needle,
                    size_t needle_len) {
    size_t i;
    if (needle_len == 0 || hay_len < needle_len) {
        return 0;
    }
    for (i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *buf;
    cloak_ws_hs_t out, sentinel;
    cloak_ws_hs_result_t rc;

    buf = (uint8_t *)malloc(size == 0 ? 1 : size);
    if (buf == NULL) {
        return 0;
    }
    if (size > 0) {
        memcpy(buf, data, size);
    }

    memset(&sentinel, 0xA5, sizeof(sentinel));
    out = sentinel;

    rc = cloak_ws_handshake_parse(buf, size, &out);

    /* O7 */
    FUZZ_CHECK(rc == CLOAK_WS_HS_OK || rc == CLOAK_WS_HS_ERR_BAD_HIDDEN ||
                   rc == CLOAK_WS_HS_ERR_NOT_UPGRADE ||
                   rc == CLOAK_WS_HS_ERR_BAD_VERSION ||
                   rc == CLOAK_WS_HS_ERR_BAD_KEY ||
                   rc == CLOAK_WS_HS_ERR_MALFORMED ||
                   rc == CLOAK_WS_HS_ERR_INTERNAL,
               "result is not one of the enumerated codes");
    if (size == 0) {
        FUZZ_CHECK(rc == CLOAK_WS_HS_ERR_MALFORMED, "empty request was not MALFORMED");
    }

    if (rc != CLOAK_WS_HS_OK) {
        /* O6 */
        FUZZ_CHECK(memcmp(&out, &sentinel, sizeof(out)) == 0,
                   "a failed parse wrote to *out");
        free(buf);
        return 0;
    }

    /* O2: shape of the accept, checked before it is used anywhere. */
    {
        size_t n = bounded_len(out.accept, sizeof(out.accept));
        size_t i;
        FUZZ_CHECK(n == CLOAK_WS_HS_ACCEPT_LEN, "accept is not 28 characters");
        for (i = 0; i < n; i++) {
            /* O3 is subsumed by the alphabet check, but is stated
             * separately because it is the property that matters: a CR or
             * LF here is a response-splitting bug, not a cosmetic one. */
            FUZZ_CHECK(out.accept[i] >= 0x20 && out.accept[i] != 0x7f,
                       "accept contains a control byte");
            FUZZ_CHECK(is_std_b64_char(out.accept[i]),
                       "accept contains a character outside the base64 alphabet");
        }
        {
            uint8_t digest[32];
            size_t got = 0;
            FUZZ_CHECK(cloak_base64_decode(out.accept, digest, sizeof(digest), &got) == 0,
                       "accept is not decodable base64");
            FUZZ_CHECK(got == 20, "accept does not decode to a 20-byte SHA-1 digest");
        }
    }

    /* O1: the 96 bytes must be the ones that were on the wire. 96 is a
     * multiple of 3, so the encoding is exactly 128 characters with no
     * padding -- which is what CLOAK_WS_HS_HIDDEN_B64_LEN says the header
     * value has to be, so a verbatim match against the request is owed. */
    {
        char enc[CLOAK_WS_HS_HIDDEN_LEN * 4 / 3 + 4];
        FUZZ_CHECK(cloak_base64_encode(out.hidden, CLOAK_WS_HS_HIDDEN_LEN, enc,
                                       sizeof(enc)) == 0,
                   "the decoded hidden payload could not be re-encoded");
        FUZZ_CHECK(strlen(enc) == 128, "re-encoded hidden is not 128 characters");
        FUZZ_CHECK(contains(buf, size, enc, 128),
                   "the returned hidden payload is not in the request");
    }

    /* O4/O5: the response side, into exact-sized allocations. */
    {
        uint8_t *resp = (uint8_t *)malloc(CLOAK_WS_HS_101_LEN);
        if (resp != NULL) {
            ssize_t n = cloak_ws_handshake_compose_101(resp, CLOAK_WS_HS_101_LEN, out.accept);
            FUZZ_CHECK(n == CLOAK_WS_HS_101_LEN,
                       "compose_101 refused an accept this parser produced");
            FUZZ_CHECK(contains(resp, (size_t)n, out.accept, CLOAK_WS_HS_ACCEPT_LEN),
                       "the 101 does not carry the accept it was given");
            FUZZ_CHECK(memcmp(resp, "HTTP/1.1 101 ", 13) == 0,
                       "the 101 does not begin with its status line");
            free(resp);
        }
        resp = (uint8_t *)malloc(CLOAK_WS_HS_101_LEN - 1);
        if (resp != NULL) {
            ssize_t n = cloak_ws_handshake_compose_101(resp, CLOAK_WS_HS_101_LEN - 1,
                                                       out.accept);
            FUZZ_CHECK(n == -1, "compose_101 wrote 129 bytes into 128 bytes of room");
            free(resp);
        }
    }

    free(buf);
    return 0;
}
