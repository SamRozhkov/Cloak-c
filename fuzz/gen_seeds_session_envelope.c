/* THE SEED CORPUS FOR fuzz_session_envelope, AND WHY IT IS NOT OPTIONAL.
 *
 * Almost every fuzz target in a codebase like this one wants no seeds:
 * the mutator finds its own way in, and hand-made seeds only bias it.
 * This target is the exception, and the reason is one comparison.
 *
 * cloak_stream_feed_frame buffers a frame in a heap and delivers nothing
 * until try_drain finds `s->heap[0].seq == s->next_recv_seq`. A fresh
 * stream's next_recv_seq is 0, so the FIRST byte of application data a
 * stream ever delivers requires a frame whose 64-bit seq field is exactly
 * zero. That field is bytes 4..11 of a header that cloak_frame_deobfuscate
 * has just Salsa20-decrypted, so the mutator is not being asked to write
 * eight zero bytes -- it is being asked to write the eight keystream bytes
 * that decrypt to zero, for whichever nonce the envelope's own last eight
 * bytes happen to be. There is no partial credit and no coverage signal on
 * the way: every wrong seq takes the identical path (buffer it, deliver
 * nothing), so libFuzzer cannot climb toward the right one. 2^64, blind.
 *
 * Without seeds this target still exercises cloak_frame_deobfuscate,
 * cloak_strmtab_t, heap_push/heap_grow and every rejection path -- which
 * is not nothing -- but cloak_bytequeue_t, try_drain's delivery and
 * resumption, heap_pop, and the unordered cloak_msgqueue_t ring stay
 * unreached, and those are the parts of the tree that actually allocate,
 * wrap and free. THIS WAS MEASURED, not assumed: see this task's report
 * for the planted-bug run that a from-scratch corpus did not find and a
 * seeded one did.
 *
 * Nothing here weakens the target. A seed is a starting point, not a
 * constraint: libFuzzer mutates these freely, and a mutation that
 * scrambles a seq simply lands back in the rejection paths it would have
 * explored anyway. What the seeds buy is that some fraction of the corpus
 * is always on the far side of that one comparison.
 *
 * These are produced by CODE rather than checked in as opaque blobs
 * because the encoding depends on cloak_frame_obfuscate -- change the
 * frame format and hand-written blobs become 12 files of noise that still
 * look like a corpus. Regenerate with:
 *
 *   cmake --build <fuzzbuild> --target gen_seeds_session_envelope -j4
 *   <fuzzbuild>/fuzz/gen_seeds_session_envelope fuzz/corpus/session_envelope
 *
 * then re-minimise (`-merge=1`) before committing.
 *
 * Note that the emitted seeds are NOT byte-stable between runs: a frame
 * with seq < CLOAK_FRAME_PAD_FIRST_N_FRAMES carries a random amount of
 * padding, by design (frame.c's random_pad_len). Two runs produce
 * corpora that are equivalent, not identical, which is why the committed
 * corpus is the artifact and this program is only how to rebuild one.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "cloak/frame.h"

/* The harness's own envelope ceiling: fuzz_session_envelope.c frames each
 * envelope with a single length byte. A generated frame longer than this
 * could not be expressed in that format, so it is redrawn (the only
 * variable part is the random padding on the first five seqs). */
#define SEED_MAX_ENVELOPE 255

static cloak_obfuscator_t g_obf;

/* Appends one [length byte][envelope] record. Returns 0 on success. */
static int emit(uint8_t *buf, size_t cap, size_t *len, uint32_t stream_id, uint64_t seq,
                uint8_t closing, const uint8_t *payload, size_t payload_len) {
    cloak_frame_t frame;
    frame.stream_id = stream_id;
    frame.seq = seq;
    frame.closing = closing;
    frame.payload = payload;
    frame.payload_len = payload_len;

    uint8_t envelope[SEED_MAX_ENVELOPE];
    long n = -1;
    for (int attempt = 0; attempt < 64 && n < 0; attempt++) {
        n = cloak_frame_obfuscate(&g_obf, &frame, envelope, sizeof(envelope), 0);
    }
    if (n <= 0) {
        return -1; /* payload genuinely too large for the format -- a bug in this file */
    }
    if (*len + 1 + (size_t)n > cap) {
        return -1;
    }
    buf[(*len)++] = (uint8_t)n;
    memcpy(buf + *len, envelope, (size_t)n);
    *len += (size_t)n;
    return 0;
}

static int write_seed(const char *dir, const char *name, const uint8_t *buf, size_t len) {
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        return -1;
    }
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    size_t w = fwrite(buf, 1, len, f);
    if (fclose(f) != 0 || w != len) {
        return -1;
    }
    printf("%s  %zu bytes\n", name, len);
    return 0;
}

#define BUF_CAP 65536
#define BEGIN(mode_byte)      \
    do {                      \
        len = 0;              \
        buf[len++] = (mode_byte); \
    } while (0)
#define EMIT(sid, seq, closing, pl, pll)                              \
    do {                                                              \
        if (emit(buf, BUF_CAP, &len, (sid), (seq), (closing), (pl), (pll)) != 0) { \
            fprintf(stderr, "emit failed at line %d\n", __LINE__);     \
            return 1;                                                 \
        }                                                             \
    } while (0)
#define WRITE(name)                                       \
    do {                                                  \
        if (write_seed(dir, (name), buf, len) != 0) {      \
            fprintf(stderr, "cannot write %s\n", (name)); \
            return 1;                                     \
        }                                                 \
    } while (0)

/* Mode byte values, matching fuzz_session_envelope.c's `data[0] & 1`. */
#define ORDERED   0x00
#define UNORDERED 0x01

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <corpus-directory>\n", argv[0]);
        return 2;
    }
    const char *dir = argv[1];
    mkdir(dir, 0755); /* already-exists is fine; the fopen below is the real check */

    memset(&g_obf, 0, sizeof(g_obf));
    g_obf.method = CLOAK_AEAD_NONE; /* EncryptionMethodPlain, all-zero key */

    static uint8_t buf[BUF_CAP];
    size_t len = 0;

    uint8_t small[16];
    uint8_t large[233]; /* the largest payload a 255-byte envelope can carry:
                         * 255 - CLOAK_FRAME_HEADER_LEN - 8 tag/nonce bytes */
    uint8_t medium[100];
    uint8_t wide[200]; /* larger than the harness's 64-byte read buffer */
    for (size_t i = 0; i < sizeof(small); i++) small[i] = (uint8_t)(0x40 + i);
    for (size_t i = 0; i < sizeof(large); i++) large[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(medium); i++) medium[i] = (uint8_t)(0x80 + i);
    for (size_t i = 0; i < sizeof(wide); i++) wide[i] = (uint8_t)(i * 3u);

    /* 1. The base case: four in-order data frames. Delivers on every
     *    frame, so it is the shortest path past the seq gate. */
    BEGIN(ORDERED);
    for (uint64_t seq = 0; seq < 4; seq++) EMIT(1, seq, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    WRITE("ordered_in_order");

    /* 2. The same four, reversed: nothing is delivered until the last one
     *    arrives, and then try_drain empties the whole heap in one pass.
     *    This is the seed that makes heap_pop's sift-down run. */
    BEGIN(ORDERED);
    for (uint64_t seq = 4; seq-- > 0;) EMIT(1, seq, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    WRITE("ordered_reversed");

    /* 3. Forty frames, seq 40 down to 1, then seq 0. Crosses heap_grow's
     *    8 -> 16 -> 32 reallocs, hits heap_push's
     *    `heap_len >= max_pending_frames` refusal at 32, and then drains
     *    everything that did fit. */
    BEGIN(ORDERED);
    for (uint64_t seq = 41; seq-- > 1;) EMIT(1, seq, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    EMIT(1, 0, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    WRITE("ordered_heap_refusal");

    /* 4. Maximum-size payloads in order. 233 bytes each against a
     *    256-byte receive queue, so try_drain delivers one, breaks for
     *    lack of room, and resumes from inside the harness's
     *    cloak_stream_read -- repeatedly.
     *
     *    THE FIRST FIVE SEQS CARRY A SMALL PAYLOAD AND THAT IS FORCED,
     *    not a choice: cloak_frame_obfuscate pads any frame with
     *    seq < CLOAK_FRAME_PAD_FIRST_N_FRAMES by a random 0..247 bytes,
     *    so a 233-byte payload at seq 0 produces an envelope of 255..502
     *    bytes and only the single draw pad_len == 0 fits the harness's
     *    one-byte length field. (Measured, not reasoned: emitting it
     *    unconditionally failed here after 64 redraws.) Frames from seq 5
     *    on are unpadded and deterministic at 14 + payload + 8. */
    BEGIN(ORDERED);
    for (uint64_t seq = 0; seq < 5; seq++) EMIT(1, seq, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    for (uint64_t seq = 5; seq < 9; seq++) EMIT(1, seq, CLOAK_FRAME_CLOSING_NOTHING, large, sizeof(large));
    WRITE("ordered_backpressure");

    /* 5. Data then a closing-stream frame, then a late frame for the same
     *    id: the stream is retired and the strmtab entry tombstoned, so
     *    the late frame must be dropped rather than reopen anything. */
    BEGIN(ORDERED);
    EMIT(1, 0, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    EMIT(1, 1, CLOAK_FRAME_CLOSING_STREAM, small, sizeof(small));
    EMIT(1, 2, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    WRITE("ordered_close_then_late");

    /* 6. A duplicate seq, which heap_contains_seq must catch -- the one
     *    protocol violation this port detects and Go does not. */
    BEGIN(ORDERED);
    EMIT(1, 3, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    EMIT(1, 3, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    EMIT(1, 0, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    WRITE("ordered_duplicate_seq");

    /* 7. Eight streams interleaved, so the strmtab actually has to grow
     *    past its initial 16 entries' worth of activity and route by id. */
    BEGIN(ORDERED);
    for (uint32_t sid = 1; sid <= 8; sid++) EMIT(sid, 0, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    for (uint32_t sid = 1; sid <= 8; sid++) EMIT(sid, 1, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    WRITE("ordered_multi_stream");

    /* 8. A session-closing frame in the middle: everything after it must
     *    be ignored, because session_on_envelope returns early on a
     *    closed session. */
    BEGIN(ORDERED);
    EMIT(1, 0, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    EMIT(0xffffffffu, 0, CLOAK_FRAME_CLOSING_SESSION, small, sizeof(small));
    EMIT(2, 0, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    WRITE("ordered_session_close");

    /* 9. Unordered: twelve 100-byte datagrams through a 256-byte ring.
     *    Each carries a 4-byte length prefix, so the ring's head and tail
     *    wrap several times and all three `% q->cap` sites run with a
     *    split copy. */
    BEGIN(UNORDERED);
    for (uint64_t seq = 0; seq < 12; seq++) EMIT(1, seq, CLOAK_FRAME_CLOSING_NOTHING, medium, sizeof(medium));
    WRITE("unordered_ring_wrap");

    /* 10. Unordered datagrams larger than the harness's 64-byte read
     *     buffer, which is what drives cloak_msgqueue_read's
     *     SHORT_BUFFER-without-popping path. */
    BEGIN(UNORDERED);
    for (uint64_t seq = 0; seq < 6; seq++) EMIT(1, seq, CLOAK_FRAME_CLOSING_NOTHING, wide, sizeof(wide));
    WRITE("unordered_short_buffer");

    /* 11. Unordered close, which unlike the ordered one takes effect
     *     immediately and ahead of any data still queued. */
    BEGIN(UNORDERED);
    EMIT(1, 0, CLOAK_FRAME_CLOSING_NOTHING, medium, sizeof(medium));
    EMIT(1, 1, CLOAK_FRAME_CLOSING_STREAM, small, sizeof(small));
    EMIT(1, 2, CLOAK_FRAME_CLOSING_NOTHING, medium, sizeof(medium));
    WRITE("unordered_close");

    /* 12. Out-of-order arrivals spread over several streams at once, so
     *     more than one heap is non-empty simultaneously -- the state the
     *     single-stream seeds above never produce. */
    BEGIN(ORDERED);
    for (uint32_t sid = 1; sid <= 4; sid++) {
        EMIT(sid, 2, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
        EMIT(sid, 1, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    }
    for (uint32_t sid = 1; sid <= 4; sid++) {
        EMIT(sid, 0, CLOAK_FRAME_CLOSING_NOTHING, small, sizeof(small));
    }
    WRITE("ordered_concurrent_heaps");

    return 0;
}
