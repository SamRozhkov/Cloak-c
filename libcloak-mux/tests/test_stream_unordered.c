#define _POSIX_C_SOURCE 200809L

/* THE UNORDERED (DATAGRAM) RECEIVE PATH -- module 9 task 3.
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
     * which short-circuits to (0, nil) before consulting the pipe. See
     * cloak/stream.h. */
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
    ASSERT_EQ_INT(cloak_stream_write(&tx, payload, sizeof(payload)), (long)sizeof(payload));
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
    for (;;) {
        long n = cloak_stream_read(&rx, out, sizeof(out));
        if (n == 0) break;
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
     * minus the queue's own 4-byte length prefix. */
    const size_t largest = RECV_CAP - CLOAK_MSGQUEUE_LEN_PREFIX;

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

TEST_MAIN_BEGIN()
    test_out_of_order_is_arrival_order_unordered_sorted_ordered();
    test_duplicate_accepted_twice_unordered_rejected_ordered();
    test_short_read_buffer_does_not_consume_the_datagram();
    test_closing_frame_closes_immediately_unordered();
    test_message_boundaries_survive();
    test_full_queue_drops_newest_and_counts();
    test_payload_larger_than_the_queue_is_rejected();
TEST_MAIN_END()
