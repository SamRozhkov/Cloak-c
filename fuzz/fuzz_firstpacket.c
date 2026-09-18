/* TARGET #2: the server's front door -- cloak_firstpacket_feed
 * (libcloak-server/src/firstpacket.c) driven through
 * cloak_firstpacket_want, on bytes nobody has authenticated and nobody
 * can authenticate, since this object runs BEFORE any key is involved.
 *
 * THIS IS GO'S first_packet_fuzz.go. Go's Fuzz(data []byte) hands the
 * whole slice to ReadFirstPacket via a net.Pipe; this target instead
 * SPLITS the input into feeds whose sizes come out of the input itself,
 * and that difference is the entire reason the target exists.
 *
 * WHY THE CHUNKING AXIS IS THE VALUE, AND NOT THE BYTES. A target that
 * always hands over the whole buffer is strictly weaker than
 * libcloak-server/tests/test_dispatcher_limits.c:812
 * (test_fuzz_first_packets_never_crash_or_leak), which already pushes 300
 * connections' worth of CLOAK_FIRSTPACKET_MAX random bytes through a real
 * socket and a real dispatcher. What that test -- and every other test of
 * this object -- does NOT vary is where the feeds are cut, because they
 * all call the same GREEDY discipline: ask want(), hand over exactly that
 * many bytes. cloak_firstpacket_t is a resumable state machine, and the
 * two things a resumable state machine gets wrong are the split boundary
 * and the caller who ignores the limit. Concretely, what a greedy caller
 * can never produce here:
 *
 *   - THE CLAMP. cloak_firstpacket_feed's contract is that `len` beyond
 *     want() is "ignored rather than buffered" (firstpacket.h). A greedy
 *     caller never passes len > want, so `if (len > want) len = want;`
 *     is dead code under every existing test. It is also the one line
 *     standing between this object and the over-read its whole existence
 *     is justified by: a byte consumed past the end of the first packet
 *     is a byte cloak_session_add_conn will never see, and the session
 *     desynchronises on its first frame.
 *   - THE HEADER SPLIT. On the TLS path want() is 1 for the deciding
 *     byte and then 4 for the rest of the record header, so a greedy
 *     caller ALWAYS cuts the 5-byte header as 1+4 and never as 1+1+1+1+1,
 *     1+2+2, 1+3+1 or 1+2+1+1. record_total is computed exactly once, on
 *     the byte that makes fp->len reach 5, from inside the per-byte loop;
 *     which feed that byte arrives in is precisely the variable no
 *     existing test moves.
 *
 * On the WebSocket path want() is permanently 1, so honest chunking there
 * is identical to greedy chunking and only the clamp axis is new. That is
 * stated rather than glossed: the chunking axis is real but it is narrow,
 * and it is worth knowing which half of this object it actually reaches.
 *
 * INPUT FORMAT -- the whole input is a sequence of feeds, and every byte
 * of it is meaningful:
 *
 *     repeated: one control byte C, then the bytes of that feed.
 *               bits 0..6 of C are the requested feed size (0..127).
 *               bit 7 of C, when set, makes this an ABUSIVE feed: the
 *               size is passed to cloak_firstpacket_feed WITHOUT being
 *               clamped to want(), which is the caller bug the object
 *               promises to survive. When clear the feed is HONEST and
 *               the size is min(requested, want()), i.e. exactly what the
 *               dispatcher does.
 *               A requested size longer than the input's remainder is
 *               clamped to the remainder, so no input byte is ever
 *               ignored and truncating an input never changes the meaning
 *               of the bytes before the truncation point.
 *
 * A one-byte mutation of a control byte re-cuts every feed after it and
 * flips honest/abusive -- the move libFuzzer makes constantly, and the
 * one that no fixed-size framing would offer it. 127 is the largest size
 * this encoding can express; a 3000-byte record therefore arrives in at
 * least 24 feeds, which is a cost in input length and a gain in split
 * boundaries, and the trade is deliberate.
 *
 * IS THERE A GATE LIBFUZZER CANNOT CLIMB? No, and that is why this
 * target's corpus is three hand-written seeds rather than a generator.
 * The only gate here is the first byte: 0x16 (TLS) or 'G' (WebSocket),
 * anything else fails immediately. That is one byte wide, and the two
 * comparisons are separate branches with their own coverage edges, so the
 * mutator climbs it by feedback in a few hundred executions -- unlike the
 * gate module 10a task 1 measured, an equality over a 2^64 space with no
 * gradient at all, which 623,089 blind executions did not pass and a
 * seeded corpus passed in about 8 seconds. Nothing here is that shape.
 * The TLS length field is a 16-bit value compared against a CONSTANT
 * (CLOAK_FIRSTPACKET_MAX), not against another part of the input, so
 * there is no equality for the mutator to hit. The seeds exist only so
 * the first minute is not spent rediscovering 0x16.
 *
 * THE ORACLES. Every one of these is a line of firstpacket.h's or
 * firstpacket.c's own contract; none is invented here.
 *
 *   O1  A feed must never buffer more than want() bytes. This is the
 *       no-over-read guarantee, and it is the only oracle that the
 *       abusive feeds above can trip.
 *   O2  want() must never exceed the room left in the buffer. A caller
 *       that believes want() overflows fp->buf if this is false; note
 *       that record_total is a size_t and `record_total - fp->len`
 *       underflows to SIZE_MAX if record_total is ever left unset while
 *       the transport is TLS.
 *   O3  Once terminal, a cloak_firstpacket_t is frozen: further feeds
 *       return the same status and change neither the length nor the
 *       buffer ("Once DONE or ERROR is returned, further feeds change
 *       nothing and return that same status").
 *   O4  DONE on the TLS path means the buffer holds exactly the record
 *       its own header declared: 5 + be16(buf[3..5]).
 *   O5  DONE on the WebSocket path means the buffer ends in CRLFCRLF.
 *       (Derived from the crlf_state automaton -- state 2 is reachable
 *       only from state 1 + '\n', state 1 only from '\r', state 3 only
 *       from state 2 + '\r' -- rather than from a comment asserting it.)
 *   O6  THE SPLIT-BOUNDARY ORACLE, and the reason the chunking axis is
 *       checked rather than merely exercised: feeding the accepted bytes
 *       one at a time must reach a BYTE-FOR-BYTE identical state --
 *       status, transport, length, record_total, crlf_state,
 *       redirect_on_error and buffer contents. This object frames a byte
 *       stream, so where the feeds were cut may not survive into its
 *       state, and a coverage-guided mutator that has just re-cut the
 *       feeds is the only thing that will ever check it.
 *
 * WHAT THIS TARGET DOES NOT DO: it does not read from an fd, and it does
 * not arm the 15-second handshake deadline firstpacket.h requires of its
 * caller. Both belong to the dispatcher, which has its own tests
 * (test_dispatcher_limits.c) and is another target's subject; this one
 * drives the object exactly as the dispatcher's read callback drives it,
 * with the reads replaced by the input.
 */

#include "cloak/firstpacket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Not <assert.h>: assert() is a no-op under NDEBUG, and a fuzz target
 * whose oracles silently vanish in a release-flavoured build is the
 * failure mode this whole module exists to avoid. abort() is what
 * libFuzzer reports as a crash. */
#define FUZZ_CHECK(cond, msg)                                                  \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "fuzz_firstpacket: oracle failed: %s\n", (msg));    \
            abort();                                                           \
        }                                                                      \
    } while (0)

/* Replays the bytes fp accepted, one at a time, into a fresh object and
 * checks that every field of the two states agrees. See O6. */
static void check_byte_at_a_time_equivalence(const cloak_firstpacket_t *fp) {
    cloak_firstpacket_t ref;
    cloak_firstpacket_init(&ref);

    size_t i = 0;
    size_t n = cloak_firstpacket_len(fp);
    while (i < n) {
        if (cloak_firstpacket_want(&ref) == 0) {
            break; /* terminal earlier than the chunked run: caught below */
        }
        cloak_firstpacket_feed(&ref, fp->buf + i, 1);
        i++;
    }

    FUZZ_CHECK(i == n, "byte-at-a-time replay stopped early");
    FUZZ_CHECK(ref.status == fp->status, "replay status differs");
    FUZZ_CHECK(ref.transport == fp->transport, "replay transport differs");
    FUZZ_CHECK(ref.len == fp->len, "replay length differs");
    FUZZ_CHECK(ref.record_total == fp->record_total, "replay record_total differs");
    FUZZ_CHECK(ref.crlf_state == fp->crlf_state, "replay crlf_state differs");
    FUZZ_CHECK(ref.redirect_on_error == fp->redirect_on_error, "replay redirect flag differs");
    FUZZ_CHECK(memcmp(ref.buf, fp->buf, fp->len) == 0, "replay buffer differs");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    size_t pos = 0;
    while (pos < size) {
        uint8_t control = data[pos++];
        size_t remaining = size - pos;

        size_t want_before = cloak_firstpacket_want(&fp);
        size_t len_before = cloak_firstpacket_len(&fp);
        cloak_firstpacket_status_t status_before = fp.status;

        size_t n = (size_t)(control & 0x7fu);
        if (n > remaining) {
            n = remaining;
        }
        if ((control & 0x80u) == 0 && n > want_before) {
            n = want_before; /* the honest caller: never more than want() */
        }

        cloak_firstpacket_status_t st = cloak_firstpacket_feed(&fp, data + pos, n);
        pos += n;

        size_t len_after = cloak_firstpacket_len(&fp);

        /* O1: no over-read, however much the caller offered. */
        FUZZ_CHECK(len_after >= len_before, "length went backwards");
        FUZZ_CHECK(len_after - len_before <= want_before, "fed more than want() allowed");
        FUZZ_CHECK(len_after <= CLOAK_FIRSTPACKET_MAX, "buffer overfilled");

        /* O2: want() never asks for more than the buffer can still hold. */
        FUZZ_CHECK(cloak_firstpacket_want(&fp) <= CLOAK_FIRSTPACKET_MAX - len_after,
                   "want() exceeds remaining buffer room");

        /* O3: terminal states are frozen. */
        if (status_before != CLOAK_FIRSTPACKET_NEED_MORE) {
            FUZZ_CHECK(st == status_before, "status changed after terminal");
            FUZZ_CHECK(len_after == len_before, "length changed after terminal");
        }

        if (st == CLOAK_FIRSTPACKET_DONE) {
            const uint8_t *buf = cloak_firstpacket_data(&fp);
            if (fp.transport == CLOAK_FIRSTPACKET_TRANSPORT_TLS) {
                /* O4 */
                FUZZ_CHECK(len_after >= 5, "TLS DONE shorter than a record header");
                FUZZ_CHECK(len_after == 5u + (((size_t)buf[3] << 8) | (size_t)buf[4]),
                           "TLS DONE length disagrees with the declared record length");
            } else {
                /* O5 */
                FUZZ_CHECK(fp.transport == CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET,
                           "DONE with no transport decided");
                FUZZ_CHECK(len_after >= 4, "WebSocket DONE shorter than CRLFCRLF");
                FUZZ_CHECK(memcmp(buf + len_after - 4, "\r\n\r\n", 4) == 0,
                           "WebSocket DONE without a terminating blank line");
            }
        }
    }

    /* O6, once per input: the chunking must not have changed the result. */
    check_byte_at_a_time_equivalence(&fp);
    return 0;
}
