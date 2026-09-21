#define _POSIX_C_SOURCE 200809L

/* THE UNORDERED (DATAGRAM) PATH -- module 9 tasks 3 (receive) and 4
 * (send).
 *
 * This file exercises cloak_stream_t with ordering ==
 * CLOAK_SESSION_ORDERING_UNORDERED, i.e. the port of Go Cloak's
 * datagramBufferedPipe (/Users/sam/Cloak/internal/multiplex/
 * datagramBufferedPipe.go). test_stream.c already covers the ordered
 * path; nothing here duplicates it, and several cases here deliberately
 * run the SAME fixture through BOTH modes, because a test that only ever
 * saw one mode would pass against an implementation that ignored the mode
 * field entirely -- which is exactly the implementation module 9's task 2
 * built the field to rule out and this task is the first code to disprove.
 *
 * FOUR OF THE BEHAVIOURS ASSERTED BELOW LOOK LIKE BUGS AND ARE NOT. An
 * out-of-order frame is delivered immediately, out of order. A duplicate
 * frame is accepted and delivered a second time. A closing frame closes
 * the stream before an earlier data frame that is still in flight. A read
 * buffer one byte short fails without consuming anything. Every one of
 * those is what Go does, and three of them are what a real Go peer
 * spreading one stream over NumConn connections will actually produce. */

#include "cloak/stream.h"

#include "cloak/common.h"
#include "cloak/frame.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>

/* Go's real MsgOnWireSizeLimit, so max_payload_per_frame here is Go's
 * real maxStreamUnitWrite of 16132 (16401 - 14 header - 255 padding) and
 * the 8191-byte datagram of the boundary case travels in one frame
 * exactly as it would on the wire. */
#define MAX_ON_WIRE 16401u
#define RECV_CAP 65536u
#define MAX_PENDING 64u

/* --- the same length-prefixed "wire" collector test_stream.c uses: each
 * obfuscated frame is appended as a record so a test can replay them into
 * a receiving stream in any order, including twice. --- */
typedef struct {
    uint8_t *frames_data;
    size_t frames_data_len;
    size_t frames_data_cap;
    size_t *frame_lens;
    size_t frame_count;
    size_t frame_lens_cap;
} wire_t;

static void wire_init(wire_t *w) { memset(w, 0, sizeof(*w)); }

static void wire_free(wire_t *w) {
    free(w->frames_data);
    free(w->frame_lens);
}

static int wire_sink(void *userdata, const uint8_t *bytes, size_t len) {
    wire_t *w = (wire_t *)userdata;
    if (w->frames_data_len + len > w->frames_data_cap) {
        size_t new_cap = (w->frames_data_cap + len) * 2 + 64;
        w->frames_data = (uint8_t *)realloc(w->frames_data, new_cap);
        w->frames_data_cap = new_cap;
    }
    memcpy(w->frames_data + w->frames_data_len, bytes, len);
    w->frames_data_len += len;

    if (w->frame_count == w->frame_lens_cap) {
        w->frame_lens_cap = w->frame_lens_cap * 2 + 8;
        w->frame_lens = (size_t *)realloc(w->frame_lens, w->frame_lens_cap * sizeof(size_t));
    }
    w->frame_lens[w->frame_count++] = len;
    return 0;
}

static size_t wire_offset(const wire_t *w, size_t idx) {
    size_t off = 0;
    for (size_t i = 0; i < idx; i++) {
        off += w->frame_lens[i];
    }
    return off;
}

/* Deobfuscates frame `idx` into a fresh copy (deobfuscation is in-place,
 * so replaying one frame twice needs a fresh copy each time -- which is
 * also precisely how a duplicate arrives in reality) and feeds it.
 * Returns cloak_stream_feed_frame's value. */
static int feed(const wire_t *w, const cloak_obfuscator_t *o, cloak_stream_t *dst, size_t idx) {
    size_t len = w->frame_lens[idx];
    uint8_t *copy = (uint8_t *)malloc(len);
    memcpy(copy, w->frames_data + wire_offset(w, idx), len);
    cloak_frame_t frame;
    ASSERT_EQ_INT(cloak_frame_deobfuscate(o, &frame, copy, len), 0);
    int rc = cloak_stream_feed_frame(dst, &frame);
    free(copy);
    return rc;
}

static void make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, CLOAK_AEAD_KEY_LEN);
}

static void init_stream(cloak_stream_t *s, uint32_t id, const cloak_obfuscator_t *o,
                        cloak_session_ordering_t ordering, wire_t *w) {
    ASSERT_EQ_INT(cloak_stream_init(s, id, o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING, ordering,
                                    wire_sink, w),
                  0);
}

/* ------------------------------------------------------------------ 1 --
 * Out-of-order arrival: unordered delivers both frames IMMEDIATELY, in
 * ARRIVAL order; ordered sorts them back. One fixture, both modes --
 * without the ordered half, an implementation that simply deleted the
 * sorter would pass.
 *
 * Go: datagramBufferedPipe.Write looks at no sequence number at all
 * (datagramBufferedPipe.go:89-91 appends the payload as it lands), where
 * streamBuffer.Write pushes onto a sorterHeap and pops only while
 * sh[0].Seq == nextRecvSeq (streamBuffer.go:64-94). */
static void test_out_of_order_is_arrival_order_unordered_sorted_ordered(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    const char *first = "FIRST";            /* seq 0, 5 bytes */
    const char *second = "SECOND-PAYLOAD";  /* seq 1, 14 bytes */

    cloak_stream_t tx;
    init_stream(&tx, 3, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);
    ASSERT_EQ_INT(cloak_stream_write(&tx, (const uint8_t *)first, 5), 5);
    ASSERT_EQ_INT(cloak_stream_write(&tx, (const uint8_t *)second, 14), 14);
    ASSERT_EQ_INT(w.frame_count, 2);

    uint8_t out[64];

    /* UNORDERED: seq 1 arrives first and is handed over first. */
    cloak_stream_t rx_u;
    init_stream(&rx_u, 3, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);
    ASSERT_EQ_INT(feed(&w, &o, &rx_u, 1), 0);
    ASSERT_EQ_INT(feed(&w, &o, &rx_u, 0), 0);
    ASSERT_EQ_INT(cloak_stream_read(&rx_u, out, sizeof(out)), 14);
    ASSERT_MEM_EQ(out, second, 14);
    ASSERT_EQ_INT(cloak_stream_read(&rx_u, out, sizeof(out)), 5);
    ASSERT_MEM_EQ(out, first, 5);
    ASSERT_EQ_INT(cloak_stream_read(&rx_u, out, sizeof(out)), 0);
    cloak_stream_destroy(&rx_u);

    /* ORDERED, same two frames in the same arrival order: the sorter puts
     * them back and the boundary between them is gone (one byte stream). */
    cloak_stream_t rx_o;
    init_stream(&rx_o, 3, &o, CLOAK_SESSION_ORDERING_ORDERED, &w);
    ASSERT_EQ_INT(feed(&w, &o, &rx_o, 1), 0);
    ASSERT_EQ_INT(feed(&w, &o, &rx_o, 0), 0);
    ASSERT_EQ_INT(cloak_stream_read(&rx_o, out, sizeof(out)), 19);
    ASSERT_MEM_EQ(out, "FIRSTSECOND-PAYLOAD", 19);
    ASSERT_EQ_INT(cloak_stream_read(&rx_o, out, sizeof(out)), 0);
    cloak_stream_destroy(&rx_o);

    cloak_stream_destroy(&tx);
    wire_free(&w);
}

/* ------------------------------------------------------------------ 2 --
 * A duplicate frame. Unordered ACCEPTS it and delivers it twice (Go's
 * datagramBufferedPipe has no duplicate check whatsoever); ordered drops
 * it with -1.
 *
 * AND THE RETURN VALUES ARE THE POINT, not the payloads.
 * cloak_session_on_envelope retires a stream on `rc == 1 || rc == -1`
 * (libcloak-mux/src/session.c:320-337, :393-396), so a duplicate that
 * returned -1 in unordered mode would kill a stream that Go keeps alive
 * -- over traffic a real Go peer produces routinely once one stream's
 * frames are spread across NumConn connections. Asserting rc == 0 here is
 * asserting the exact expression session.c branches on.
 *
 * NOTE, because the task brief says otherwise: in ORDERED mode the
 * duplicate DOES retire the stream, and that is pre-existing, deliberate
 * and pinned by test_stream.c's test_duplicate_seq_rejected. This case
 * asserts -1 there rather than pretending it does not happen. */
static void test_duplicate_accepted_twice_unordered_rejected_ordered(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    cloak_stream_t tx;
    init_stream(&tx, 9, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);
    ASSERT_EQ_INT(cloak_stream_write(&tx, (const uint8_t *)"dup", 3), 3);
    ASSERT_EQ_INT(w.frame_count, 1);

    uint8_t out[16];

    cloak_stream_t rx_u;
    init_stream(&rx_u, 9, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);
    ASSERT_EQ_INT(feed(&w, &o, &rx_u, 0), 0);
    ASSERT_EQ_INT(feed(&w, &o, &rx_u, 0), 0); /* neither 1 nor -1: NOT retired */
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx_u), 6);
    ASSERT_EQ_INT(cloak_stream_read(&rx_u, out, sizeof(out)), 3);
    ASSERT_MEM_EQ(out, "dup", 3);
    ASSERT_EQ_INT(cloak_stream_read(&rx_u, out, sizeof(out)), 3);
    ASSERT_MEM_EQ(out, "dup", 3);
    ASSERT_EQ_INT(cloak_stream_read(&rx_u, out, sizeof(out)), 0);
    cloak_stream_destroy(&rx_u);

    cloak_stream_t rx_o;
    init_stream(&rx_o, 9, &o, CLOAK_SESSION_ORDERING_ORDERED, &w);
    ASSERT_EQ_INT(feed(&w, &o, &rx_o, 0), 0);
    ASSERT_EQ_INT(feed(&w, &o, &rx_o, 0), -1);
    ASSERT_EQ_INT(cloak_stream_read(&rx_o, out, sizeof(out)), 3);
    ASSERT_MEM_EQ(out, "dup", 3);
    ASSERT_EQ_INT(cloak_stream_read(&rx_o, out, sizeof(out)), 0);
    cloak_stream_destroy(&rx_o);

    cloak_stream_destroy(&tx);
    wire_free(&w);
}

/* ------------------------------------------------------------------ 3 --
 * THE MUTATION THIS FILE EXISTS FOR. A read buffer one byte short returns
 * CLOAK_STREAM_ERR_SHORT_BUFFER and DOES NOT CONSUME the datagram.
 *
 * A test that stopped at the error code would pass against an
 * implementation that popped the datagram first and discovered the
 * problem afterwards -- and that implementation is Go's own bug 6 in
 * embryo (piper.go's 8192-byte reader against a 16132-byte datagram;
 * scouting report §6.6, measured against ck-client v2.12.0). So the
 * assertion is the SECOND read: the same bytes must still be there.
 * Go returns at datagramBufferedPipe.go:58-60, one line before the pop at
 * :62, which is the whole of the fix. */
static void test_short_read_buffer_does_not_consume_the_datagram(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    cloak_stream_t tx;
    init_stream(&tx, 4, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);
    ASSERT_EQ_INT(cloak_stream_write(&tx, (const uint8_t *)"HELLO", 5), 5);

    cloak_stream_t rx;
    init_stream(&rx, 4, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);
    ASSERT_EQ_INT(feed(&w, &o, &rx, 0), 0);

    uint8_t out[8];
    memset(out, 0, sizeof(out));

    /* One byte short. */
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, 4), CLOAK_STREAM_ERR_SHORT_BUFFER);
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx), 5);
    /* Nothing was copied out either -- a partial fill would be a
     * half-delivered datagram, which is not a legal state. */
    ASSERT_MEM_EQ(out, "\0\0\0\0", 4);

    /* Repeatable: a second undersized read still fails and still keeps it. */
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, 4), CLOAK_STREAM_ERR_SHORT_BUFFER);
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx), 5);

    /* out_cap == 0: the one deliberate divergence from Go's Stream.Read,
     * which short-circuits to (0, nil) before consulting the pipe
     * (internal/multiplex/stream.go:87-89). See cloak/stream.h. */
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, 0), CLOAK_STREAM_ERR_SHORT_BUFFER);
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx), 5);

    /* And now, with exactly enough room, it is still there in full. */
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, 5), 5);
    ASSERT_MEM_EQ(out, "HELLO", 5);
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx), 0);
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, sizeof(out)), 0);

    cloak_stream_destroy(&rx);
    cloak_stream_destroy(&tx);
    wire_free(&w);
}

/* ------------------------------------------------------------------ 4 --
 * A closing frame closes the stream IMMEDIATELY on arrival, ahead of an
 * earlier data frame still in flight. Go sets d.closed the moment the
 * frame lands (datagramBufferedPipe.go:83-87) without looking at Seq;
 * ordered mode instead holds the close until it reaches next_recv_seq.
 * Divergence (c) of the scouting report's §6.3, asserted in both modes
 * off one fixture.
 *
 * Also asserted: datagrams that arrived BEFORE the close survive it and
 * are readable until drained -- Go's recvBuffer contract in so many words
 * ("Read should NOT return error on a closed streamBuffer with a
 * non-empty buffer", recvBuffer.go:12-16). Without that half, an
 * implementation that threw the queue away on close would pass. */
static void test_closing_frame_closes_immediately_unordered(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    cloak_stream_t tx;
    init_stream(&tx, 12, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);
    ASSERT_EQ_INT(cloak_stream_write(&tx, (const uint8_t *)"AAA", 3), 3); /* seq 0 */
    ASSERT_EQ_INT(cloak_stream_write(&tx, (const uint8_t *)"BBB", 3), 3); /* seq 1 */
    ASSERT_EQ_INT(cloak_stream_send_closing(&tx, CLOAK_FRAME_CLOSING_STREAM), 0); /* seq 2 */
    ASSERT_EQ_INT(w.frame_count, 3);

    uint8_t out[16];

    /* UNORDERED, close first: the stream is at end of stream at once,
     * even though seq 0 and seq 1 have not been seen. */
    cloak_stream_t rx_u;
    init_stream(&rx_u, 12, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);
    ASSERT_EQ_INT(feed(&w, &o, &rx_u, 2), 1);
    ASSERT_EQ_INT(cloak_stream_read(&rx_u, out, sizeof(out)), -1);
    /* A data frame arriving after the close is discarded and reported as
     * "already closing" -- Go's ErrClosedPipe with toBeClosed set
     * (datagramBufferedPipe.go:73-75). It does NOT become readable. */
    ASSERT_EQ_INT(feed(&w, &o, &rx_u, 0), 1);
    ASSERT_EQ_INT(cloak_stream_read(&rx_u, out, sizeof(out)), -1);
    cloak_stream_destroy(&rx_u);

    /* UNORDERED, data first: already-queued datagrams outlive the close. */
    cloak_stream_t rx_d;
    init_stream(&rx_d, 12, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);
    ASSERT_EQ_INT(feed(&w, &o, &rx_d, 0), 0);
    ASSERT_EQ_INT(feed(&w, &o, &rx_d, 2), 1);
    ASSERT_EQ_INT(cloak_stream_read(&rx_d, out, sizeof(out)), 3);
    ASSERT_MEM_EQ(out, "AAA", 3);
    ASSERT_EQ_INT(cloak_stream_read(&rx_d, out, sizeof(out)), -1);
    cloak_stream_destroy(&rx_d);

    /* ORDERED, same close-first fixture: the close waits its turn. Not
     * end of stream, not an error -- just nothing to read yet. */
    cloak_stream_t rx_o;
    init_stream(&rx_o, 12, &o, CLOAK_SESSION_ORDERING_ORDERED, &w);
    ASSERT_EQ_INT(feed(&w, &o, &rx_o, 2), 0);
    ASSERT_EQ_INT(cloak_stream_read(&rx_o, out, sizeof(out)), 0);
    cloak_stream_destroy(&rx_o);

    cloak_stream_destroy(&tx);
    wire_free(&w);
}

/* ------------------------------------------------------------------ 5 --
 * Message boundaries survive end to end: three writes of 1, 1500 and 8191
 * bytes come back as exactly three reads of exactly those sizes. The
 * frame count is asserted too, because a sender that split one of these
 * into two frames would produce two datagrams at the far end and this
 * case is where that shows up first (module 9 task 4 owns the refusal
 * itself; 8191 is well under Go's 16132 limit, so nothing here should
 * split in either mode today). */
static void test_message_boundaries_survive(void) {
    static const size_t sizes[3] = {1, 1500, 8191};

    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    uint8_t *msg[3];
    for (int i = 0; i < 3; i++) {
        msg[i] = (uint8_t *)malloc(sizes[i]);
        for (size_t j = 0; j < sizes[i]; j++) {
            msg[i][j] = (uint8_t)(i * 31 + j); /* distinct per message and per offset */
        }
    }

    cloak_stream_t tx;
    init_stream(&tx, 21, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ_INT(cloak_stream_write(&tx, msg[i], sizes[i]), (long)sizes[i]);
    }
    ASSERT_EQ_INT(w.frame_count, 3);

    cloak_stream_t rx;
    init_stream(&rx, 21, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);
    for (size_t i = 0; i < 3; i++) {
        ASSERT_EQ_INT(feed(&w, &o, &rx, i), 0);
    }
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx), 1 + 1500 + 8191);

    uint8_t *out = (uint8_t *)malloc(16384);
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ_INT(cloak_stream_read(&rx, out, 16384), (long)sizes[i]);
        ASSERT_MEM_EQ(out, msg[i], sizes[i]);
    }
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, 16384), 0);
    free(out);

    cloak_stream_destroy(&rx);
    cloak_stream_destroy(&tx);
    for (int i = 0; i < 3; i++) free(msg[i]);
    wire_free(&w);
}

/* --------------------------------------------------------------- extra --
 * A full queue DROPS THE NEWEST datagram, counts it, and does not retire
 * the stream. This is the plan's Ruling 2 and this port's one declared
 * receive-path divergence from Go, which blocks the writing goroutine
 * instead (datagramBufferedPipe.go:72-81) -- impossible on a
 * single-threaded reactor.
 *
 * Asserted, in order of how easy each is to get wrong: that the drop is
 * COUNTED (an uncounted drop is undiagnosable packet loss); that what
 * survives is the OLDEST datagrams, in order, contiguously from the front
 * -- which is what distinguishes "drop the newest" from "drop the oldest"
 * and from "drop an arbitrary one"; and that the queue RECOVERS, so a
 * burst of overflow is transient rather than a wedge. */
static void test_full_queue_drops_newest_and_counts(void) {
    /* 4-byte payloads and a queue small enough to overflow inside one
     * test: max_payload_per_frame = 273 - 14 - 255 = 4, and
     * cloak_stream_init's floor makes recv_capacity 259 the smallest
     * legal choice. */
    const size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 4;
    const size_t recv_cap = max_on_wire - CLOAK_FRAME_HEADER_LEN;
    const size_t n_frames = 40;

    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    uint8_t payload[160];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)i;

    cloak_stream_t tx;
    ASSERT_EQ_INT(cloak_stream_init(&tx, 31, &o, max_on_wire, recv_cap, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_UNORDERED, wire_sink, &w),
                  0);
    /* ONE WRITE PER FRAME, and it has to be: this tx stream is UNORDERED
     * and its max_payload_per_frame is 4, so the single 160-byte write
     * this case was originally written with is exactly the write module 9
     * task 4 now REFUSES (cloak_stream_write returns
     * CLOAK_STREAM_ERR_SHORT_BUFFER and emits nothing). Forty 4-byte
     * writes produce the identical wire: the same forty frames, the same
     * seq 0..39, the same payload bytes. See
     * test_oversize_write_refused_unordered_split_ordered below for the
     * refusal itself. */
    for (size_t i = 0; i < n_frames; i++) {
        ASSERT_EQ_INT(cloak_stream_write(&tx, payload + i * 4, 4), 4);
    }
    ASSERT_EQ_INT(w.frame_count, n_frames);

    cloak_stream_t rx;
    ASSERT_EQ_INT(cloak_stream_init(&rx, 31, &o, max_on_wire, recv_cap, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_UNORDERED, wire_sink, &w),
                  0);
    for (size_t i = 0; i < n_frames; i++) {
        ASSERT_EQ_INT(feed(&w, &o, &rx, i), 0); /* a drop is NOT a protocol violation */
    }
    ASSERT_TRUE(rx.recv_dropped_datagrams > 0);

    uint8_t out[8];
    size_t delivered = 0;
    /* Capped at n_frames rather than written as `for (;;)`: a mutant that
     * never consumes a datagram would otherwise spin here until the
     * ctest TIMEOUT, reporting a timeout where an assertion should name
     * the defect. Nothing legal can deliver more than was fed. */
    for (size_t guard = 0; guard <= n_frames; guard++) {
        long n = cloak_stream_read(&rx, out, sizeof(out));
        if (n == 0) break;
        ASSERT_TRUE(guard < n_frames);
        ASSERT_EQ_INT(n, 4);
        /* The i-th surviving datagram must be the i-th one WRITTEN --
         * contiguous from the front, nothing skipped. */
        ASSERT_MEM_EQ(out, payload + delivered * 4, 4);
        delivered++;
    }
    ASSERT_TRUE(delivered > 0);
    ASSERT_EQ_INT(delivered + rx.recv_dropped_datagrams, n_frames);

    /* Drained: the queue takes traffic again. A drop must not wedge it. */
    ASSERT_EQ_INT(feed(&w, &o, &rx, 0), 0);
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, sizeof(out)), 4);
    ASSERT_MEM_EQ(out, payload, 4);

    cloak_stream_destroy(&rx);
    cloak_stream_destroy(&tx);
    wire_free(&w);
}

/* --------------------------------------------------------------- extra --
 * The ONE thing that still returns -1 in unordered mode: a payload that
 * can never fit in the queue however much the reader drains. Asserted at
 * the boundary from both sides, because "too large" and "full" have
 * opposite consequences -- one retires the stream
 * (session.c:320-337), the other is a counted drop -- and an
 * off-by-one between them turns ordinary backpressure into a killed
 * stream.
 *
 * The frames are hand-built rather than obfuscated: cloak_stream_feed_frame
 * takes an already-deobfuscated frame, and no sender in this tree can
 * produce a payload this large for this configuration, which is the point
 * -- it models a peer that does not respect our size limit. */
static void test_payload_larger_than_the_queue_is_rejected(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    /* The largest datagram this queue can ever hold is recv_capacity
     * minus the queue's own 4-byte length prefix.
     *
     * THE 4 IS WRITTEN OUT, NOT TAKEN FROM CLOAK_MSGQUEUE_LEN_PREFIX, and
     * that is deliberate. A test that derives its expected boundary from
     * the shipped constant it is testing follows that constant wherever
     * it goes -- this project has had two of those, one of which let a
     * ceiling be set 256 times too high without a single assertion
     * noticing. The literal is checked against the symbol on the next
     * line, so a deliberate change to the prefix width fails HERE, loudly,
     * with a reader who then has to decide what the new boundary should
     * be, instead of silently re-deriving one. */
    ASSERT_EQ_INT(CLOAK_MSGQUEUE_LEN_PREFIX, 4);
    const size_t largest = RECV_CAP - 4;

    uint8_t *buf = (uint8_t *)malloc(largest + 1);
    memset(buf, 0xA5, largest + 1);

    cloak_stream_t rx;
    init_stream(&rx, 44, &o, CLOAK_SESSION_ORDERING_UNORDERED, &w);

    cloak_frame_t f;
    f.stream_id = 44;
    f.seq = 0;
    f.closing = CLOAK_FRAME_CLOSING_NOTHING;
    f.payload = buf;
    f.payload_len = largest + 1;
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx, &f), -1);
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx), 0);
    ASSERT_EQ_INT(rx.recv_dropped_datagrams, 0); /* rejected, not "dropped" */

    /* Exactly at the boundary it is accepted and read back whole. */
    f.payload_len = largest;
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx, &f), 0);
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx), largest);
    uint8_t *out = (uint8_t *)malloc(largest);
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, largest), (long)largest);
    ASSERT_MEM_EQ(out, buf, largest);
    free(out);

    cloak_stream_destroy(&rx);
    free(buf);
    wire_free(&w);
}

/* Deobfuscates frame `idx` into `scratch` (which must be at least
 * w->frame_lens[idx] bytes) and returns the decoded header and payload --
 * `feed`'s twin, for cases that want to look at a frame rather than
 * deliver it. The returned frame's payload points into `scratch`. */
static cloak_frame_t peek(const wire_t *w, const cloak_obfuscator_t *o, uint8_t *scratch,
                          size_t idx) {
    size_t len = w->frame_lens[idx];
    memcpy(scratch, w->frames_data + wire_offset(w, idx), len);
    cloak_frame_t f;
    memset(&f, 0, sizeof(f));
    ASSERT_EQ_INT(cloak_frame_deobfuscate(o, &f, scratch, len), 0);
    return f;
}

/* ------------------------------------------------------------------ 6 --
 * THE WHOLE OF THE SEND SIDE OF UNORDERED MODE -- module 9 task 4, and
 * Go's other one-line difference between the two modes
 * (stream.go:127-137: `if s.session.Unordered { err = io.ErrShortBuffer;
 * return }` where the ordered path would have split).
 *
 * THE BRACKET IS 16132/16133 AND IT WAS MEASURED, not read off a comment.
 * Go's maxStreamUnitWrite is MsgOnWireSizeLimit - frameHeaderLength -
 * maxExtraLen (session.go:111), and both ck-client and ck-server set
 * MsgOnWireSizeLimit to appDataMaxLength == 16401 (internal/client/TLS.go
 * :11, internal/server/TLS.go:16), so 16401 - 14 - 255 = 16132. Run
 * against unmodified upstream v2.12.0 with that configuration, Go's
 * Stream.Write reports:
 *
 *   unordered  Write(16132) -> n=16132, err=nil,             1 frame sent
 *   unordered  Write(16133) -> n=0,     err=short buffer,    0 frames sent
 *   unordered  Write(0)     -> n=0,     err=nil,             0 frames sent
 *   ordered    Write(16132) -> n=16132, err=nil,             1 frame sent
 *   ordered    Write(16133) -> n=16133, err=nil,             2 frames sent
 *
 * (measured with a counting net.Conn attached to a real MakeSession, see
 * this task's report; the numbers below are those numbers.)
 *
 * WHY THE FRAME COUNT IS ASSERTED AND NOT JUST THE RETURN CODE. The
 * mutation this case exists to kill is a refusal that discovers the
 * problem AFTER handing the first 16132 bytes to the sink -- returning
 * the right error, having already put half a datagram on the wire and
 * consumed a sequence number. Every return-code-only assertion passes
 * against that implementation, and the far end then reassembles a
 * truncated datagram out of it, silently. So: w.frame_count before and
 * after, and then a following write whose seq must still be the next one.
 *
 * MAX_ON_WIRE here is 16401, the real one, which is why this case can
 * name 16132 as a literal at all: the derivation itself is asserted on
 * the line above the bracket, so a change to CLOAK_FRAME_HEADER_LEN or
 * CLOAK_FRAME_MAX_EXTRA_LEN fails here rather than silently moving the
 * boundary this case claims to be testing. */
static void test_oversize_write_refused_unordered_split_ordered(void) {
    const size_t limit = 16132; /* 16401 - 14 - 255 */

    cloak_obfuscator_t o;
    make_obfuscator(&o);

    uint8_t *buf = (uint8_t *)malloc(limit + 1);
    for (size_t i = 0; i < limit + 1; i++) buf[i] = (uint8_t)(i * 7 + 1);
    uint8_t *scratch = (uint8_t *)malloc(MAX_ON_WIRE);

    /* --- UNORDERED: the boundary fits, one past it is refused outright. */
    wire_t wu;
    wire_init(&wu);
    cloak_stream_t u;
    init_stream(&u, 51, &o, CLOAK_SESSION_ORDERING_UNORDERED, &wu);
    ASSERT_EQ_INT(u.max_payload_per_frame, limit);

    ASSERT_EQ_INT(cloak_stream_write(&u, buf, limit), (long)limit);
    ASSERT_EQ_INT(wu.frame_count, 1);
    {
        cloak_frame_t f = peek(&wu, &o, scratch, 0);
        ASSERT_EQ_INT(f.payload_len, limit); /* ONE frame, whole -- not the first of two */
        ASSERT_EQ_INT(f.seq, 0);
    }

    /* One byte more. Nothing on the wire, and NOT -1: -1 is "this stream
     * is broken", and a refused oversize datagram breaks nothing. */
    ASSERT_EQ_INT(cloak_stream_write(&u, buf, limit + 1), CLOAK_STREAM_ERR_SHORT_BUFFER);
    ASSERT_EQ_INT(wu.frame_count, 1); /* still 1: not a partial write, not a split */

    /* The refusal consumed no sequence number and did not close the write
     * side -- the stream is still usable, and the next frame is seq 1.
     * This is what catches an implementation that obfuscates the first
     * chunk (++next_write_seq) and only then decides to refuse. */
    ASSERT_EQ_INT(cloak_stream_write(&u, buf, 3), 3);
    ASSERT_EQ_INT(wu.frame_count, 2);
    {
        cloak_frame_t f = peek(&wu, &o, scratch, 1);
        ASSERT_EQ_INT(f.seq, 1);
        ASSERT_EQ_INT(f.payload_len, 3);
        ASSERT_MEM_EQ(f.payload, buf, 3);
    }

    /* And the boundary datagram survives the round trip as ONE datagram,
     * which is the reason the limit is what it is. */
    cloak_stream_t rx;
    init_stream(&rx, 51, &o, CLOAK_SESSION_ORDERING_UNORDERED, &wu);
    ASSERT_EQ_INT(feed(&wu, &o, &rx, 0), 0);
    {
        uint8_t *out = (uint8_t *)malloc(limit);
        ASSERT_EQ_INT(cloak_stream_read(&rx, out, limit), (long)limit);
        ASSERT_MEM_EQ(out, buf, limit);
        free(out);
    }
    cloak_stream_destroy(&rx);
    cloak_stream_destroy(&u);
    wire_free(&wu);

    /* --- ORDERED, the same two sizes and the same fixture: 16133 SPLITS.
     * Without this half the case would pass against an implementation
     * that refused in both modes -- i.e. against a port that had made the
     * datagram limit a property of the frame size rather than of the
     * MODE, which is the whole thing under test. */
    wire_t wo;
    wire_init(&wo);
    cloak_stream_t ord;
    init_stream(&ord, 51, &o, CLOAK_SESSION_ORDERING_ORDERED, &wo);
    ASSERT_EQ_INT(ord.max_payload_per_frame, limit);

    ASSERT_EQ_INT(cloak_stream_write(&ord, buf, limit), (long)limit);
    ASSERT_EQ_INT(wo.frame_count, 1);

    ASSERT_EQ_INT(cloak_stream_write(&ord, buf, limit + 1), (long)(limit + 1));
    ASSERT_EQ_INT(wo.frame_count, 3); /* 1 + 2: split into 16132 + 1 */
    {
        cloak_frame_t f1 = peek(&wo, &o, scratch, 1);
        ASSERT_EQ_INT(f1.seq, 1);
        ASSERT_EQ_INT(f1.payload_len, limit);
        cloak_frame_t f2 = peek(&wo, &o, scratch, 2);
        ASSERT_EQ_INT(f2.seq, 2);
        ASSERT_EQ_INT(f2.payload_len, 1);
    }
    cloak_stream_destroy(&ord);
    wire_free(&wo);

    /* --- THE SAME BRACKET AT A LIMIT OF 4, and this third section is not
     * decoration: everything above runs at MAX_ON_WIRE 16401, so an
     * implementation that refused writes longer than a HARDCODED 16132 --
     * rather than longer than this stream's own max_payload_per_frame --
     * passes every assertion above. This project has already shipped one
     * hardcoded constant that passed an entire suite. max_on_wire 273
     * gives max_payload_per_frame 273 - 14 - 255 = 4, the same
     * configuration test_full_queue_drops_newest_and_counts uses, and the
     * refusal has to move with it. (It also separates
     * max_payload_per_frame from write_buf_cap, which is 273 here: a
     * guard written against the buffer size would let 5 through and split
     * it.) */
    const size_t small_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 4;
    const size_t small_recv_cap = small_on_wire - CLOAK_FRAME_HEADER_LEN;

    wire_t ws;
    wire_init(&ws);
    cloak_stream_t su;
    ASSERT_EQ_INT(cloak_stream_init(&su, 52, &o, small_on_wire, small_recv_cap, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_UNORDERED, wire_sink, &ws),
                  0);
    ASSERT_EQ_INT(su.max_payload_per_frame, 4);
    ASSERT_EQ_INT(cloak_stream_write(&su, buf, 4), 4);
    ASSERT_EQ_INT(ws.frame_count, 1);
    ASSERT_EQ_INT(cloak_stream_write(&su, buf, 5), CLOAK_STREAM_ERR_SHORT_BUFFER);
    ASSERT_EQ_INT(ws.frame_count, 1);
    cloak_stream_destroy(&su);
    wire_free(&ws);

    wire_t wso;
    wire_init(&wso);
    cloak_stream_t so;
    ASSERT_EQ_INT(cloak_stream_init(&so, 52, &o, small_on_wire, small_recv_cap, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &wso),
                  0);
    ASSERT_EQ_INT(cloak_stream_write(&so, buf, 5), 5);
    ASSERT_EQ_INT(wso.frame_count, 2); /* 4 + 1 */
    cloak_stream_destroy(&so);
    wire_free(&wso);

    free(scratch);
    free(buf);
}

/* ------------------------------------------------------------------ 7 --
 * A ZERO-LENGTH WRITE SENDS NOTHING, IN BOTH MODES -- the plan's D7, and
 * the one of this module's four datagram-size divergences that was
 * settled AGAINST diverging.
 *
 * The plan said to carry a zero-length datagram unless doing so is
 * wire-visible in a way that distinguishes this port from Go. It is, and
 * the measurement is in three parts, all against unmodified upstream
 * v2.12.0 (commit c3d5470, the revision the dev image's go-ck-client and
 * go-ck-server are built from):
 *
 *   1. THE SHIPPED BINARIES SWALLOW IT, END TO END. go-ck-client -u and
 *      go-ck-server, a real session over loopback, a UDP echo upstream: a
 *      zero-length UDP datagram sent to the client's local port produces
 *      NOTHING -- the upstream echo never sees it, no reply comes back,
 *      neither binary logs anything, and the session is unharmed (4-byte
 *      datagrams sent immediately before and after round-trip normally,
 *      which is what makes this a measurement rather than a broken
 *      tunnel). So no Go deployment ever puts a zero-length frame on the
 *      wire.
 *   2. AND IT IS THE ENCODER THAT STOPS IT, not just Stream.Write's loop:
 *      obfuscate returns `errors.New("payload cannot be empty")` for a
 *      zero-length payload (internal/multiplex/obfs.go:65-67), measured
 *      by calling it. This port's cloak_frame_obfuscate returns -1 on the
 *      same condition (libcloak-mux/src/frame.c), so "carry it" was never
 *      reachable from stream.c anyway.
 *   3. SO THE RECORD WOULD BE A LENGTH GO NEVER PRODUCES. Hand-building
 *      the frame Go refuses to build gives a 30-byte record (14 header +
 *      0 payload + 0 pad + 16 tag); the shortest frame Go can emit past
 *      the first five of a stream -- where padding is zero -- is 31. Fed
 *      to a real Go receive path (Session.recvDataFromRemote, both modes;
 *      the binaries cannot be induced to emit one and the session key
 *      makes forging one from outside impossible, so this half was
 *      measured by executing upstream's own package rather than its
 *      binaries) it is ACCEPTED without complaint -- no error, session
 *      stays open, nothing after it is poisoned, and it surfaces to the
 *      application as a Read returning (0, nil). What rules it out is
 *      therefore NOT the peer's reaction: it is that 30 bytes is a length
 *      no Go Cloak on earth emits, in the one place this project pays
 *      attention to length distributions (see the chi-square in
 *      test_frame.c).
 *
 * So this port does what Go does, and the loss is what Go loses: an
 * application datagram of length zero. Go's own RouteUDP reads a
 * zero-length UDP packet off the local socket and calls Stream.Write with
 * it (internal/client/piper.go:83), which swallows it silently. Same
 * here.
 *
 * ASSERTED IN BOTH MODES because nothing about it is mode-specific and a
 * guard written as `in_len == 0 || in_len > max` in the unordered branch
 * alone would be invisible otherwise. */
static void test_zero_length_write_sends_nothing(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);

    const cloak_session_ordering_t modes[2] = {CLOAK_SESSION_ORDERING_UNORDERED,
                                               CLOAK_SESSION_ORDERING_ORDERED};
    for (int i = 0; i < 2; i++) {
        wire_t w;
        wire_init(&w);
        cloak_stream_t s;
        init_stream(&s, 61, &o, modes[i], &w);

        /* A valid pointer with zero length, which is what a relay pumping
         * a zero-length datagram off a socket actually has in hand. */
        const uint8_t byte = 0x5A;
        ASSERT_EQ_INT(cloak_stream_write(&s, &byte, 0), 0); /* accepted, not an error */
        ASSERT_EQ_INT(w.frame_count, 0);                    /* and nothing on the wire */

        /* No sequence number was burned either: the next real write is
         * seq 0. A zero-length frame that was built and then dropped
         * would show up here. */
        ASSERT_EQ_INT(cloak_stream_write(&s, &byte, 1), 1);
        ASSERT_EQ_INT(w.frame_count, 1);
        uint8_t scratch[MAX_ON_WIRE];
        cloak_frame_t f = peek(&w, &o, scratch, 0);
        ASSERT_EQ_INT(f.seq, 0);
        ASSERT_EQ_INT(f.payload_len, 1);

        cloak_stream_destroy(&s);
        wire_free(&w);
    }
}

/* --------------------------------------------------------------- extra --
 * N12 (task 3 review): a datagram that EXACTLY fills the remaining free
 * space of a NON-EMPTY queue must be accepted.
 *
 * test_payload_larger_than_the_queue_is_rejected already pins exact fit
 * into an EMPTY queue, and that is the easy half: the admission test is
 * `len + 4 > cap - used`, and with used == 0 an off-by-one there is also
 * an off-by-one against the whole capacity, which that case sees. With
 * used > 0 it is a different arithmetic path through the same expression,
 * and a one-line mutant that rejects only this case survived all 70 tests
 * -- it was killed only by the reviewer's property test. If it were ever
 * real it would be permanent single-datagram loss at steady state, i.e.
 * the queue silently refusing the one datagram that fits perfectly, over
 * and over, for the life of the stream.
 *
 * The capacity is tiny and the arithmetic is written out so the "exactly
 * fills it" claim is checkable by reading, not by trusting a helper. */
static void test_exact_fit_into_a_non_empty_queue_is_accepted(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    /* max_payload_per_frame = 40; the queue's floor makes 40 + 255 = 295
     * the smallest legal recv_capacity. */
    const size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 40;
    const size_t recv_cap = max_on_wire - CLOAK_FRAME_HEADER_LEN; /* 295 */

    cloak_stream_t rx;
    ASSERT_EQ_INT(cloak_stream_init(&rx, 55, &o, max_on_wire, recv_cap, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_UNORDERED, wire_sink, &w),
                  0);

    uint8_t buf[64];
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i + 1);

    cloak_frame_t f;
    f.stream_id = 55;
    f.seq = 0;
    f.closing = CLOAK_FRAME_CLOSING_NOTHING;
    f.payload = buf;

    /* Three 30-byte datagrams cost 3 * (4 + 30) = 102 bytes of the 295,
     * leaving 193 free -- so a datagram of exactly 193 - 4 = 189 bytes
     * fills the queue to the last byte. 189 is over max_payload_per_frame,
     * which only means no sender in this tree could produce it; the queue
     * has no opinion about frame sizes and neither does this case. */
    for (int i = 0; i < 3; i++) {
        f.payload_len = 30;
        ASSERT_EQ_INT(cloak_stream_feed_frame(&rx, &f), 0);
    }
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx), 90);

    uint8_t *big = (uint8_t *)malloc(190);
    memset(big, 0x7e, 190);
    f.payload = big;
    f.payload_len = 189; /* 189 + 4 == 193 == exactly the free space */
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx, &f), 0);
    ASSERT_EQ_INT(rx.recv_dropped_datagrams, 0); /* accepted, not dropped */
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx), 90 + 189);

    /* One more byte than fits is a DROP, not a rejection -- the other
     * side of the same boundary, and the pair is what makes the
     * off-by-one visible in either direction. */
    f.payload_len = 1;
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx, &f), 0);
    ASSERT_EQ_INT(rx.recv_dropped_datagrams, 1);

    /* And every byte of it comes back whole, in order. */
    uint8_t out[256];
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ_INT(cloak_stream_read(&rx, out, sizeof(out)), 30);
        ASSERT_MEM_EQ(out, buf, 30);
    }
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, sizeof(out)), 189);
    ASSERT_MEM_EQ(out, big, 189);
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, sizeof(out)), 0);

    free(big);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

/* --------------------------------------------------------------- extra --
 * THE ORDERED TWINS OF TWO CELLS THIS FILE ALREADY PINS FOR UNORDERED.
 *
 * Task 3's report tabulated, for ordered mode, "payload larger than the
 * receive queue -> -1" and "any frame after a close -> -1". Both were
 * true and neither had a test: the reviewer's N3 and N4 made each return
 * 0 instead and all 70 tests passed (70 was the suite size when that
 * mutation was run; it is larger now and the mutation has not been
 * re-run). They are pre-existing gaps rather
 * than anything this module introduced -- but this module added a mode
 * branch to the front of cloak_stream_feed_frame, and "a new branch that
 * quietly makes the OLD path lenient" is exactly the defect no new
 * unordered test can see. The unordered halves are asserted in
 * test_payload_larger_than_the_queue_is_rejected and
 * test_closing_frame_closes_immediately_unordered; these are the halves
 * that were missing.
 *
 * Both retire the stream at the session layer (session.c's
 * `rc == 1 || rc == -1`), which is deliberate and, for the duplicate
 * cell, a divergence from Go. THAT DECISION HAS SINCE BEEN MADE and
 * this sentence used to say it was still owed: cloak/stream.h's ORDERED
 * paragraph now records it as a deliberate improvement over Go, and
 * names the Go defect it improves on -- the PENDING duplicate
 * (internal/multiplex/streamBuffer.go:83-90), which wedges Go's stream
 * permanently and grows its heap without bound. An ALREADY-DELIVERED
 * seq is an error in Go too (streamBuffer.go:79-81), so the divergence
 * is narrower than "Go has no error path here". */
static void test_ordered_mode_still_rejects_oversize_and_post_close_frames(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    /* (a) A payload larger than the whole ordered receive queue. */
    cloak_stream_t rx_big;
    init_stream(&rx_big, 61, &o, CLOAK_SESSION_ORDERING_ORDERED, &w);

    uint8_t *buf = (uint8_t *)malloc(RECV_CAP + 1);
    memset(buf, 0x3c, RECV_CAP + 1);

    cloak_frame_t f;
    f.stream_id = 61;
    f.seq = 0;
    f.closing = CLOAK_FRAME_CLOSING_NOTHING;
    f.payload = buf;
    f.payload_len = RECV_CAP + 1;
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx_big, &f), -1);
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx_big), 0);

    /* The ordered queue holds the whole capacity, unlike the datagram
     * queue, which spends 4 bytes of it on the length prefix -- a 4-byte
     * band where the two modes genuinely differ. Asserted so the
     * difference is recorded rather than discovered. */
    f.payload_len = RECV_CAP;
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx_big, &f), 0);
    ASSERT_EQ_INT(cloak_stream_recv_available(&rx_big), RECV_CAP);

    free(buf);
    cloak_stream_destroy(&rx_big);

    /* (b) A frame arriving after a closing frame has drained into order. */
    cloak_stream_t tx;
    init_stream(&tx, 62, &o, CLOAK_SESSION_ORDERING_ORDERED, &w);
    ASSERT_EQ_INT(cloak_stream_send_closing(&tx, CLOAK_FRAME_CLOSING_STREAM), 0); /* seq 0 */
    ASSERT_EQ_INT(w.frame_count, 1);

    cloak_stream_t rx_closed;
    init_stream(&rx_closed, 62, &o, CLOAK_SESSION_ORDERING_ORDERED, &w);
    ASSERT_EQ_INT(feed(&w, &o, &rx_closed, 0), 1); /* drained in order: close */

    uint8_t small[4] = {1, 2, 3, 4};
    f.stream_id = 62;
    f.seq = 1;
    f.closing = CLOAK_FRAME_CLOSING_NOTHING;
    f.payload = small;
    f.payload_len = sizeof(small);
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx_closed, &f), -1);

    uint8_t out[8];
    ASSERT_EQ_INT(cloak_stream_read(&rx_closed, out, sizeof(out)), -1); /* still EOF */

    cloak_stream_destroy(&rx_closed);
    cloak_stream_destroy(&tx);
    wire_free(&w);
}

TEST_MAIN_BEGIN()
    test_out_of_order_is_arrival_order_unordered_sorted_ordered();
    test_duplicate_accepted_twice_unordered_rejected_ordered();
    test_short_read_buffer_does_not_consume_the_datagram();
    test_closing_frame_closes_immediately_unordered();
    test_message_boundaries_survive();
    test_oversize_write_refused_unordered_split_ordered();
    test_zero_length_write_sends_nothing();
    test_full_queue_drops_newest_and_counts();
    test_payload_larger_than_the_queue_is_rejected();
    test_exact_fit_into_a_non_empty_queue_is_accepted();
    test_ordered_mode_still_rejects_oversize_and_post_close_frames();
TEST_MAIN_END()
