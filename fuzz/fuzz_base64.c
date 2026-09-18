/* TARGET #9: cloak_base64_decode and cloak_base64url_decode
 * (libcloak-common/src/base64.c), with their encoders as the oracle.
 *
 * WHY THIS TARGET EXISTS: BECAUSE IT COSTS NOTHING AND SITS ON THE
 * UNAUTHENTICATED PATH. It is not here because base64 is where the bugs
 * are expected; it is 334 lines of table lookup with its own test file.
 * It is here because it is reached, without authentication, from two
 * directions -- cloak_ws_handshake_parse decodes the `Hidden` header and
 * the `Sec-WebSocket-Key` with it (target #4 above drives exactly that),
 * and every UID and key in a config file arrives through it -- and
 * because a decoder is the classic place for an off-by-one in an output
 * length that a caller then trusts. Adding it to the build is a few
 * minutes; leaving it out and being wrong is a heap overflow in the
 * server's front door. Like #4 and #5 this is insurance, and a green run
 * is the expected result.
 *
 * WHAT THE ORACLES CHECK BEYOND "DID NOT CRASH". The interesting failure
 * of a decoder is never a crash in the decoder -- it is a WRONG *out_len
 * handed back to a caller who then reads or copies that many bytes. So
 * the output length is checked against an independently computed one
 * every time, and the buffers are sized to the exact theoretical maximum
 * so that a decoder writing even one byte more meets an ASan redzone
 * instead of slack.
 *
 *   O1  ROUND TRIP, BOTH ALPHABETS. The input is encoded and decoded
 *       back; the result must equal the input byte for byte and length
 *       for length. This is the oracle that would notice a subtly wrong
 *       answer from either side of the pair.
 *   O2  cloak_base64_encoded_size agrees with what the encoder actually
 *       wrote (strlen + 1), for every input length the fuzzer produces.
 *   O3  DECODING AN ARBITRARY STRING: the length rule is re-derived here,
 *       not asked of the implementation. A standard decode may succeed
 *       only if the length is a multiple of 4; a URL-safe decode only if
 *       the length mod 4 is not 1. On success, *out_len must equal the
 *       length the encoding's own arithmetic demands, computed in this
 *       file from the string length and the padding count.
 *   O4  ALPHABET. On a successful decode every character of the input
 *       must be in that decoder's alphabet -- '+' and '/' for the
 *       standard one, '-' and '_' for the URL-safe one, and never the
 *       other pair. Both decoders are documented as strict about this,
 *       and the URL-safe one says why: it is reached with
 *       attacker-controlled bytes from the admin API's URL path.
 *   O5  CANONICAL RE-ENCODE: decoded bytes are re-encoded and decoded
 *       again and must produce the same bytes. Non-canonical trailing
 *       bits are accepted on purpose (Go's StdEncoding does), so the
 *       STRING is not required to round-trip -- the BYTES are.
 *   O6  The decoders never write more than the theoretical maximum: the
 *       output buffer is malloc'd at exactly that size, so ASan is the
 *       check rather than an assertion.
 *
 * INPUT FORMAT: none, and deliberately none. The same input bytes are
 * used twice in two different roles -- as a binary payload to encode
 * (O1/O2) and as a candidate encoded string to decode (O3..O6) -- rather
 * than being split by a control byte, so that every mutation exercises
 * both directions and there is no decoder between the mutator and the
 * code under test. The string role stops at the first NUL, which is what
 * every real caller does: these functions take a C string.
 *
 * GATE ANALYSIS: none. Both decoders reject on the first byte outside the
 * alphabet, each rejection is its own edge, and nothing is compared
 * against anything else in the input. The corpus exists to start from
 * valid strings of each shape rather than to reach anything unreachable.
 */

#include "cloak/base64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_CHECK(cond, msg)                                                  \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "fuzz_base64: oracle failed: %s\n", (msg));         \
            abort();                                                           \
        }                                                                      \
    } while (0)

/* Bound this target's work so one pathological input cannot dominate a
 * run; -max_len is passed on the command line as well, and this is the
 * belt to that's braces. */
#define FUZZ_B64_MAX_IN 4096

static int in_alphabet(char c, int url) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
        return 1;
    }
    if (c == '=') {
        return 1;
    }
    return url ? (c == '-' || c == '_') : (c == '+' || c == '/');
}

/* The largest number of bytes any input of this length can legitimately
 * decode to, under either alphabet's rules. Used as the EXACT allocation
 * size, so ASan catches a decoder that writes more. */
static size_t max_decoded(size_t n) {
    size_t full = (n / 4) * 3;
    size_t rem = n % 4;
    if (rem == 2) {
        return full + 1;
    }
    if (rem == 3) {
        return full + 2;
    }
    return full;
}

/* Independently computed exact output length for a string the decoder
 * accepted: full quanta minus the padding, or the unpadded tail. */
static size_t expected_decoded(const char *s, size_t n) {
    size_t full = (n / 4) * 3;
    size_t rem = n % 4;
    if (rem == 2) {
        return full + 1;
    }
    if (rem == 3) {
        return full + 2;
    }
    if (n == 0) {
        return 0;
    }
    if (s[n - 1] == '=') {
        return (s[n - 2] == '=') ? full - 2 : full - 1;
    }
    return full;
}

/* One decoder, one input, every oracle that applies to it. */
static void drive_decode(const char *s, size_t n, int url) {
    size_t cap = max_decoded(n);
    uint8_t *out = (uint8_t *)malloc(cap == 0 ? 1 : cap);
    size_t out_len = (size_t)-1;
    int rc;
    size_t i;

    if (out == NULL) {
        return;
    }
    rc = url ? cloak_base64url_decode(s, out, cap, &out_len)
             : cloak_base64_decode(s, out, cap, &out_len);
    if (rc != 0) {
        /* The header says *out_len is not written on failure and that out
         * may have been partly overwritten, so nothing is read here. */
        free(out);
        return;
    }

    /* O3 */
    if (url) {
        FUZZ_CHECK(n % 4 != 1, "url decoder accepted a length of 4k+1");
    } else {
        FUZZ_CHECK(n % 4 == 0, "std decoder accepted a length that is not a multiple of 4");
    }
    FUZZ_CHECK(out_len == expected_decoded(s, n),
               "decoded length disagrees with the length the encoding demands");
    FUZZ_CHECK(out_len <= cap, "decoded length exceeds the theoretical maximum");

    /* O4 */
    for (i = 0; i < n; i++) {
        FUZZ_CHECK(in_alphabet(s[i], url), "decoder accepted a character outside its alphabet");
        if (url) {
            FUZZ_CHECK(s[i] != '+' && s[i] != '/', "url decoder accepted a standard-alphabet character");
        } else {
            FUZZ_CHECK(s[i] != '-' && s[i] != '_', "std decoder accepted a url-alphabet character");
        }
    }

    /* O5: the bytes must survive a canonical re-encode. */
    {
        size_t enc_cap = cloak_base64_encoded_size(out_len);
        char *enc = (char *)malloc(enc_cap);
        if (enc != NULL) {
            int erc = url ? cloak_base64url_encode(out, out_len, enc, enc_cap)
                          : cloak_base64_encode(out, out_len, enc, enc_cap);
            FUZZ_CHECK(erc == 0, "re-encoding decoded bytes failed");
            {
                size_t enc_len = strlen(enc);
                size_t back_cap = max_decoded(enc_len);
                uint8_t *back = (uint8_t *)malloc(back_cap == 0 ? 1 : back_cap);
                if (back != NULL) {
                    size_t back_len = (size_t)-1;
                    int brc = url ? cloak_base64url_decode(enc, back, back_cap, &back_len)
                                  : cloak_base64_decode(enc, back, back_cap, &back_len);
                    FUZZ_CHECK(brc == 0, "canonical re-encoding did not decode");
                    FUZZ_CHECK(back_len == out_len, "canonical round trip changed the length");
                    FUZZ_CHECK(out_len == 0 || memcmp(back, out, out_len) == 0,
                               "canonical round trip changed the bytes");
                    free(back);
                }
            }
            free(enc);
        }
    }

    free(out);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t n = size > FUZZ_B64_MAX_IN ? FUZZ_B64_MAX_IN : size;
    int url;

    /* Role 1: the input is a binary payload. O1 and O2. */
    for (url = 0; url <= 1; url++) {
        size_t enc_cap = cloak_base64_encoded_size(n);
        char *enc = (char *)malloc(enc_cap);
        if (enc == NULL) {
            continue;
        }
        {
            int rc = url ? cloak_base64url_encode(data, n, enc, enc_cap)
                         : cloak_base64_encode(data, n, enc, enc_cap);
            FUZZ_CHECK(rc == 0, "encoding into a correctly sized buffer failed");
            /* O2 */
            FUZZ_CHECK(strlen(enc) + 1 == enc_cap,
                       "encoded_size disagrees with what the encoder wrote");
        }
        {
            /* O1/O6: exact-sized output, so an overrun meets a redzone. */
            uint8_t *back = (uint8_t *)malloc(n == 0 ? 1 : n);
            if (back != NULL) {
                size_t back_len = (size_t)-1;
                int rc = url ? cloak_base64url_decode(enc, back, n, &back_len)
                             : cloak_base64_decode(enc, back, n, &back_len);
                FUZZ_CHECK(rc == 0, "a string this encoder produced did not decode");
                FUZZ_CHECK(back_len == n, "round trip changed the length");
                FUZZ_CHECK(n == 0 || memcmp(back, data, n) == 0, "round trip changed the bytes");
                free(back);
            }
        }
        free(enc);
    }

    /* Role 2: the input is a candidate encoded string. O3..O6. It stops
     * at the first NUL because that is what a C-string API does. */
    {
        char *s = (char *)malloc(n + 1);
        if (s != NULL) {
            size_t slen;
            if (n > 0) {
                memcpy(s, data, n);
            }
            s[n] = '\0';
            slen = strlen(s);
            drive_decode(s, slen, 0);
            drive_decode(s, slen, 1);
            free(s);
        }
    }

    return 0;
}
