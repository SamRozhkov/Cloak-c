/* TARGET #3: cloak_clienthello_parse (libcloak-server/src/clienthello_parse.c),
 * the spec's own first named fuzz target and the second thing the server
 * runs on unauthenticated bytes -- cloak_firstpacket_t (target #2) frames
 * the packet, this parses it, and only after that does any key appear.
 * Six nested length fields (handshake, session_id, cipher_suites,
 * compression_methods, extensions, and each extension's own, plus the
 * list length inside server_name and key_share), all attacker-chosen, all
 * parsed before anything has been authenticated.
 *
 * WHAT THIS TARGET CAN FIND THAT ASan ALONE CANNOT, which is the reason
 * it is not merely "call the parser and let the sanitizer watch". Every
 * read this parser makes goes through cursor_take, so an out-of-bounds
 * READ is already hard here and test_clienthello_parse.c's truncation and
 * byte-flip sweeps already hunt for one. What neither sanitizers nor
 * those sweeps check is the parser's OUTPUT: it returns POINTERS INTO THE
 * CALLER'S BUFFER with implied lengths (`random` and `x25519_key_share`
 * are documented as "always exactly 32 bytes"), and a pointer that is
 * in-bounds for the parser but whose implied length runs off the end is
 * an out-of-bounds read IN THE CALLER, in code the parser never executes.
 * ASan sees nothing; the caller (cloak_server_auth_decrypt, reading the
 * 32-byte key share) reads past the packet. O1..O4 below are exactly that
 * check, and the planted bug this target was validated against was of
 * precisely this shape.
 *
 * IS THERE A GATE LIBFUZZER CANNOT CLIMB? Yes -- one, and this target is
 * seeded because of it. Module 10a task 1's measurement is the reason the
 * question gets asked at all: a dropped `% q->cap` behind a 2^64-wide
 * equality with no coverage gradient was not found in 623,089 blind
 * executions and was found in about 8 seconds from a seeded corpus. The
 * gates here, in the order the parser applies them:
 *
 *   - record_hdr[0] != 0x16 || record_hdr[1] != 0x03 || record_hdr[2] != 0x01,
 *     and handshake_type != 0x01. FOUR magic bytes, but each is a
 *     separate short-circuited branch with its own coverage edge, so the
 *     mutator climbs them one byte at a time by feedback. Not a wall.
 *   - `(size_t)handshake_len != c.remaining`. THIS IS THE ONE THAT COSTS:
 *     a 24-bit field of the input that must EQUAL the input's own length
 *     minus nine. One comparison, one edge, no coverage gradient --
 *     passing it halfway looks exactly like failing it -- and everything
 *     structural beyond it (the whole extensions walk, both nested
 *     parsers) is unreachable until it is passed.
 *
 *     IT IS NOT, HOWEVER, A WALL, AND THIS COMMENT SAID IT WAS UNTIL THE
 *     MEASUREMENT CONTRADICTED IT. SanitizerCoverage's trace-cmp feeds
 *     libFuzzer an automatic dictionary of recently-compared values, and
 *     that side channel is enough: with a bug planted behind this gate
 *     (see step 4 in this module's task 2 report) and NO corpus at all,
 *     libFuzzer reached it after roughly 2.4M executions on -seed=1 and
 *     1.4M on -seed=3, and failed to reach it at all in 13.7M executions
 *     on -seed=2. From the corpus below it reached the same bug in about
 *     21,000 executions. So the honest claim is a factor of ~100 in
 *     executions and a run-to-run reliability of 2 in 3, not a gate that
 *     cannot be climbed -- a materially weaker claim than this file's
 *     first draft made, and the true one. The corpus is worth keeping for
 *     that factor of 100; it is not load-bearing the way module 10a task
 *     1's generated corpus was.
 *
 * The seeds are four records: a real Chrome ClientHello (the same vector
 * test_clienthello_parse.c uses), a real TLS 1.2 one that this parser
 * REJECTS at the record-version check, and two minimal hand-built hellos
 * -- one with no extensions at all, one with a server_name and an X25519
 * key_share. The two minimal ones matter more than the real one: they are
 * 52 and 112 bytes, so a mutation that changes a length field changes a
 * large fraction of the record, where the same mutation in a 517-byte
 * capture changes almost nothing.
 *
 * INPUT FORMAT: none. The input is the record, byte for byte, exactly as
 * it arrives from the network -- this is a pure function of one buffer,
 * so there is nothing for a harness format to steer and adding one would
 * only put a decoder between the mutator and the parser.
 *
 * THE COPY INTO AN EXACT-SIZED ALLOCATION is deliberate and matches what
 * test_clienthello_parse.c does for the same reason: it puts ASan's
 * redzones immediately before and after the record, so a one-byte overrun
 * in either direction is a report rather than a read of whatever libFuzzer
 * happens to keep next to its input buffer.
 */

#include "cloak/clienthello_parse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_CHECK(cond, msg)                                                  \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "fuzz_clienthello: oracle failed: %s\n", (msg));    \
            abort();                                                           \
        }                                                                      \
    } while (0)

/* p..p+n must lie inside buf..buf+len. Written with pointer differences
 * rather than pointer comparisons on unrelated objects so it is defined
 * behaviour for any p the parser can return. */
static int within(const uint8_t *buf, size_t len, const uint8_t *p, size_t n) {
    if (p == NULL) {
        return 0;
    }
    if (p < buf || p > buf + len) {
        return 0;
    }
    return (size_t)((buf + len) - p) >= n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *buf = (uint8_t *)malloc(size == 0 ? 1 : size);
    if (buf == NULL) {
        return 0;
    }
    if (size > 0) {
        memcpy(buf, data, size);
    }

    cloak_clienthello_parsed_t out;
    int rc = cloak_clienthello_parse(buf, size, &out);

    if (rc == 0) {
        /* O1: `random` is documented as always exactly 32 bytes. */
        FUZZ_CHECK(within(buf, size, out.random, CLOAK_CLIENTHELLO_PARSE_RANDOM_LEN),
                   "random points outside the record");
        /* O2: session_id is NULL exactly when its length is zero, and
         * otherwise spans session_id_len bytes of the record. */
        if (out.session_id_len == 0) {
            FUZZ_CHECK(out.session_id == NULL, "empty session_id is not NULL");
        } else {
            FUZZ_CHECK(within(buf, size, out.session_id, out.session_id_len),
                       "session_id runs past the record");
        }
        /* O3: the 32-byte key share, which is the field a caller reads
         * without a length and the one an out-of-range pointer hurts. */
        if (out.x25519_key_share != NULL) {
            FUZZ_CHECK(within(buf, size, out.x25519_key_share, CLOAK_CLIENTHELLO_PARSE_X25519_LEN),
                       "x25519_key_share runs past the record");
        }
        /* O4: SNI, whose length is returned but whose span must still be
         * inside the record (sni_len == 0 with sni != NULL is explicitly
         * legal per the header, so it is not treated as an error here). */
        if (out.sni != NULL) {
            FUZZ_CHECK(within(buf, size, out.sni, out.sni_len), "sni runs past the record");
        } else {
            FUZZ_CHECK(out.sni_len == 0, "NULL sni with a non-zero length");
        }

        /* O7: EVERY SPAN MUST AGREE WITH THE LENGTH PREFIX THAT PRODUCED
         * IT. Each of these three fields is returned by a cursor_take
         * whose count came from a length field sitting IMMEDIATELY before
         * the field on the wire -- session_id from a 1-byte prefix, SNI's
         * host_name and the key share from 2-byte ones -- so in a correct
         * parse the bytes just before the returned pointer always spell
         * the length that was returned with it (32, for the key share,
         * whose length the caller does not get told).
         *
         * THIS IS THE ORACLE THAT MAKES THE OTHERS WORTH RUNNING, and it
         * was added because measurement said it was needed: with only the
         * in-range checks O1..O4, a planted `klen == 32` -> `klen <= 32`
         * in parse_key_share_ext -- the exact bug that hands a caller a
         * short key share to read 32 bytes out of -- survived 25,402,060
         * executions in 60 seconds. An over-long span is only OUT OF
         * RANGE when it happens to sit within 32 bytes of the end of the
         * record, so a range check alone waits for a coincidence of
         * placement; this checks the disagreement itself, wherever in the
         * record it occurs, and catches that same planted bug in the
         * corpus-loading pass. */
        if (out.session_id_len > 0) {
            FUZZ_CHECK(out.session_id > buf, "session_id has no room for its length prefix");
            FUZZ_CHECK((size_t)out.session_id[-1] == out.session_id_len,
                       "session_id_len disagrees with its length prefix");
        }
        if (out.sni != NULL) {
            FUZZ_CHECK(out.sni >= buf + 2, "sni has no room for its length prefix");
            FUZZ_CHECK((((size_t)out.sni[-2] << 8) | (size_t)out.sni[-1]) == out.sni_len,
                       "sni_len disagrees with its length prefix");
        }
        if (out.x25519_key_share != NULL) {
            FUZZ_CHECK(out.x25519_key_share >= buf + 2,
                       "key share has no room for its length prefix");
            FUZZ_CHECK((((size_t)out.x25519_key_share[-2] << 8) |
                        (size_t)out.x25519_key_share[-1]) == CLOAK_CLIENTHELLO_PARSE_X25519_LEN,
                       "key share length prefix is not 32");
        }

        /* O5: actually READ the extremes of every span the parser
         * returned. O1..O4 catch a bad pointer by arithmetic; this
         * catches, via ASan, anything they got wrong about what "inside"
         * means -- and it is what the real caller does with these fields. */
        volatile uint8_t sink = 0;
        sink ^= out.random[0];
        sink ^= out.random[CLOAK_CLIENTHELLO_PARSE_RANDOM_LEN - 1];
        if (out.session_id_len > 0) {
            sink ^= out.session_id[0];
            sink ^= out.session_id[out.session_id_len - 1];
        }
        if (out.sni != NULL && out.sni_len > 0) {
            sink ^= out.sni[0];
            sink ^= out.sni[out.sni_len - 1];
        }
        if (out.x25519_key_share != NULL) {
            sink ^= out.x25519_key_share[0];
            sink ^= out.x25519_key_share[CLOAK_CLIENTHELLO_PARSE_X25519_LEN - 1];
        }
        const uint8_t sink_value = sink;
        (void)sink_value;
    } else {
        /* O6: no partial results on failure. This is READ FROM THE
         * IMPLEMENTATION, not from the header: cloak_clienthello_parse
         * NULLs every output field before it parses anything and assigns
         * them only on the success path, so a caller that ignores the
         * return value still sees nothing. The header does not promise
         * this, so if it is ever deliberately changed, this oracle is the
         * thing to change with it -- it is here because a parser that
         * leaves a dangling half-result behind on the error path is a
         * bug worth hearing about either way. */
        FUZZ_CHECK(out.random == NULL, "failed parse left random set");
        FUZZ_CHECK(out.session_id == NULL && out.session_id_len == 0,
                   "failed parse left session_id set");
        FUZZ_CHECK(out.x25519_key_share == NULL, "failed parse left key_share set");
        FUZZ_CHECK(out.sni == NULL && out.sni_len == 0, "failed parse left sni set");
    }

    free(buf);
    return 0;
}
