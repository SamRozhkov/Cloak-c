#include "cloak/stream.h"
#include "cloak/common.h"
#include "cloak/frame.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>

/* --- A simple "wire" collecting sink: appends each obfuscated frame as a
 * length-prefixed record to a growable buffer, for later feeding to a
 * receiver-side stream via cloak_frame_deobfuscate. --- */
typedef struct {
    uint8_t *frames_data;    /* concatenated raw ciphertext bytes, one after another */
    size_t frames_data_len;
    size_t frames_data_cap;
    size_t *frame_lens;      /* length of each frame in frames_data, in order */
    size_t frame_count;
    size_t frame_lens_cap;
    int fail_after_n;        /* if >= 0, sink starts failing after this many successful calls */
} wire_t;

static void wire_init(wire_t *w) {
    memset(w, 0, sizeof(*w));
    w->fail_after_n = -1;
}

static void wire_free(wire_t *w) {
    free(w->frames_data);
    free(w->frame_lens);
}

static int wire_sink(void *userdata, const uint8_t *bytes, size_t len) {
    wire_t *w = (wire_t *)userdata;
    if (w->fail_after_n >= 0 && (size_t)w->fail_after_n <= w->frame_count) {
        return -1;
    }
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

static void make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, CLOAK_AEAD_KEY_LEN);
}

#define MAX_ON_WIRE 2048
#define RECV_CAP 65536
#define MAX_PENDING 64

/* Deobfuscates every frame in w (in the order they were written) and feeds
 * each into dst via cloak_stream_feed_frame, in a caller-specified
 * delivery order (indices into w's frame list) -- lets tests simulate
 * out-of-order arrival. Returns the last cloak_stream_feed_frame return
 * value (so callers can detect a closing frame, i.e. return value 1). */
static int deliver_frames(const wire_t *w, const cloak_obfuscator_t *o, cloak_stream_t *dst,
                           const size_t *order, size_t order_len) {
    size_t *offsets = (size_t *)malloc(w->frame_count * sizeof(size_t));
    size_t off = 0;
    for (size_t i = 0; i < w->frame_count; i++) {
        offsets[i] = off;
        off += w->frame_lens[i];
    }
    int last_rc = 0;
    for (size_t k = 0; k < order_len; k++) {
        size_t idx = order[k];
        uint8_t *copy = (uint8_t *)malloc(w->frame_lens[idx]);
        memcpy(copy, w->frames_data + offsets[idx], w->frame_lens[idx]);
        cloak_frame_t frame;
        int rc = cloak_frame_deobfuscate(o, &frame, copy, w->frame_lens[idx]);
        ASSERT_EQ_INT(rc, 0);
        last_rc = cloak_stream_feed_frame(dst, &frame);
        free(copy);
    }
    free(offsets);
    return last_rc;
}

static void test_round_trip_in_order(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    cloak_stream_t tx;
    ASSERT_EQ_INT(cloak_stream_init(&tx, 7, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w), 0);

    const char *msg = "the quick brown fox jumps over the lazy dog";
    long n = cloak_stream_write(&tx, (const uint8_t *)msg, strlen(msg));
    ASSERT_EQ_INT(n, (long)strlen(msg));
    ASSERT_EQ_INT(w.frame_count, 1);

    cloak_stream_t rx;
    ASSERT_EQ_INT(cloak_stream_init(&rx, 7, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w), 0);

    size_t order[1] = {0};
    deliver_frames(&w, &o, &rx, order, 1);

    uint8_t out[256];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)strlen(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_multi_frame_chunking_and_reassembly(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    /* Force small frames so a sizeable payload spans many of them. */
    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 10;
    cloak_stream_t tx;
    ASSERT_EQ_INT(cloak_stream_init(&tx, 3, &o, max_on_wire, RECV_CAP, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w), 0);

    uint8_t msg[537];
    for (size_t i = 0; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)(i * 7 + 3);
    }
    long n = cloak_stream_write(&tx, msg, sizeof(msg));
    ASSERT_EQ_INT(n, (long)sizeof(msg));
    ASSERT_EQ_INT(w.frame_count, (sizeof(msg) + 10 - 1) / 10);

    cloak_stream_t rx;
    ASSERT_EQ_INT(cloak_stream_init(&rx, 3, &o, max_on_wire, RECV_CAP, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w), 0);
    size_t *order = (size_t *)malloc(w.frame_count * sizeof(size_t));
    for (size_t i = 0; i < w.frame_count; i++) order[i] = i;
    deliver_frames(&w, &o, &rx, order, w.frame_count);
    free(order);

    uint8_t out[600];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)sizeof(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_out_of_order_delivery(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 5;
    cloak_stream_t tx;
    cloak_stream_init(&tx, 9, &o, max_on_wire, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);

    const char *msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* 26 bytes -> multiple 5-byte frames */
    cloak_stream_write(&tx, (const uint8_t *)msg, strlen(msg));
    ASSERT_EQ_INT(w.frame_count, 6);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 9, &o, max_on_wire, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);

    /* Reverse delivery order: worst case for the reorder heap. */
    size_t order[6] = {5, 4, 3, 2, 1, 0};
    deliver_frames(&w, &o, &rx, order, 6);

    uint8_t out[64];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)strlen(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_shuffled_delivery_many_frames(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 3;
    cloak_stream_t tx;
    cloak_stream_init(&tx, 1, &o, max_on_wire, 1 << 20, 200,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);

    uint8_t msg[300];
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)(i * 13 + 1);
    cloak_stream_write(&tx, msg, sizeof(msg));
    ASSERT_EQ_INT(w.frame_count, 100);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 1, &o, max_on_wire, 1 << 20, 200,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);

    size_t *order = (size_t *)malloc(w.frame_count * sizeof(size_t));
    for (size_t i = 0; i < w.frame_count; i++) order[i] = i;
    /* deterministic shuffle */
    unsigned int seed = 42;
    for (size_t i = w.frame_count - 1; i > 0; i--) {
        seed = seed * 1103515245u + 12345u;
        size_t j = (seed >> 8) % (i + 1);
        size_t tmp = order[i]; order[i] = order[j]; order[j] = tmp;
    }
    deliver_frames(&w, &o, &rx, order, w.frame_count);
    free(order);

    uint8_t out[400];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)sizeof(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_closing_frame_signals_eof(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    cloak_stream_t tx;
    cloak_stream_init(&tx, 4, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);
    const char *msg = "final message";
    cloak_stream_write(&tx, (const uint8_t *)msg, strlen(msg));
    ASSERT_EQ_INT(cloak_stream_send_closing(&tx, CLOAK_FRAME_CLOSING_STREAM), 0);
    ASSERT_EQ_INT(cloak_stream_write(&tx, (const uint8_t *)"x", 1), -1);
    ASSERT_EQ_INT(w.frame_count, 2);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 4, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);
    size_t order[2] = {0, 1};
    int last_rc = deliver_frames(&w, &o, &rx, order, 2);
    ASSERT_EQ_INT(last_rc, 1);

    uint8_t out[64];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)strlen(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);
    long eof = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(eof, -1);
    long eof2 = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(eof2, -1);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_closing_frame_out_of_order_stops_drain(void) {
    /* Matches Go's documented subtlety: a closing frame short-circuits the
     * drain loop even if further already-in-order frames are sitting ready
     * in the heap behind it -- those never get delivered. */
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 4;
    cloak_stream_t tx;
    cloak_stream_init(&tx, 2, &o, max_on_wire, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);
    cloak_stream_write(&tx, (const uint8_t *)"AAAA", 4); /* seq 0 */
    cloak_stream_send_closing(&tx, CLOAK_FRAME_CLOSING_STREAM); /* seq 1 */
    ASSERT_EQ_INT(w.frame_count, 2);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 2, &o, max_on_wire, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);

    /* Deliver seq 1 (closing) first (buffered, out of order), THEN seq 0. */
    size_t order[2] = {1, 0};
    int last_rc = deliver_frames(&w, &o, &rx, order, 2);
    ASSERT_EQ_INT(last_rc, 1);

    uint8_t out[16];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, 4);
    ASSERT_MEM_EQ(out, "AAAA", 4);
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, sizeof(out)), -1);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_duplicate_seq_rejected(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    cloak_stream_t tx;
    cloak_stream_init(&tx, 5, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);
    cloak_stream_write(&tx, (const uint8_t *)"hello", 5);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 5, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);
    uint8_t out[16];

    uint8_t *copy1 = (uint8_t *)malloc(w.frame_lens[0]);
    memcpy(copy1, w.frames_data, w.frame_lens[0]);
    cloak_frame_t f1;
    cloak_frame_deobfuscate(&o, &f1, copy1, w.frame_lens[0]);
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx, &f1), 0);
    free(copy1);

    uint8_t *copy2 = (uint8_t *)malloc(w.frame_lens[0]);
    memcpy(copy2, w.frames_data, w.frame_lens[0]);
    cloak_frame_t f2;
    cloak_frame_deobfuscate(&o, &f2, copy2, w.frame_lens[0]);
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx, &f2), -1);
    free(copy2);

    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, 5);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_duplicate_pending_frame_rejected_not_wedged(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 2;
    cloak_stream_t tx;
    cloak_stream_init(&tx, 11, &o, max_on_wire, 1 << 20, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);
    uint8_t msg[16];
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)('A' + i);
    cloak_stream_write(&tx, msg, sizeof(msg)); /* 8 frames of 2 bytes, seq 0..7 */
    ASSERT_EQ_INT(w.frame_count, 8);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 11, &o, max_on_wire, 1 << 20, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);

    size_t *offsets = (size_t *)malloc(w.frame_count * sizeof(size_t));
    size_t off = 0;
    for (size_t i = 0; i < w.frame_count; i++) { offsets[i] = off; off += w.frame_lens[i]; }

    /* Feed seq 5 twice while frames 0-4 are still missing (an open gap) --
     * the first copy should be accepted (buffered out of order), the
     * second copy of the SAME still-pending seq must be rejected, not
     * silently accepted as a second heap entry. */
    uint8_t *copy_a = (uint8_t *)malloc(w.frame_lens[5]);
    memcpy(copy_a, w.frames_data + offsets[5], w.frame_lens[5]);
    cloak_frame_t frame_a;
    cloak_frame_deobfuscate(&o, &frame_a, copy_a, w.frame_lens[5]);
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx, &frame_a), 0);
    free(copy_a);

    uint8_t *copy_b = (uint8_t *)malloc(w.frame_lens[5]);
    memcpy(copy_b, w.frames_data + offsets[5], w.frame_lens[5]);
    cloak_frame_t frame_b;
    cloak_frame_deobfuscate(&o, &frame_b, copy_b, w.frame_lens[5]);
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx, &frame_b), -1);
    free(copy_b);

    /* Now fill the gap (seq 0..4) and deliver the rest (6,7) -- everything
     * must still drain correctly, with no permanent freeze. */
    size_t order[] = {0, 1, 2, 3, 4, 6, 7};
    deliver_frames(&w, &o, &rx, order, 7);
    free(offsets);

    uint8_t out[32];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)sizeof(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_backpressure_and_resume(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    /* 4-byte frames. recv_capacity must now (post final-review Fix 1 Part A)
     * be at least max_on_wire_size - CLOAK_FRAME_HEADER_LEN, so with
     * CLOAK_FRAME_MAX_EXTRA_LEN's fixed padding budget folded into
     * max_on_wire_size, the smallest legal recv_capacity here is 259 --
     * pick 260 (still small relative to the total message) so most, but
     * not all, of the message fits at once. */
    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 4;
    size_t recv_cap = 260; /* == 65 four-byte frames' worth */
    cloak_stream_t tx;
    cloak_stream_init(&tx, 6, &o, max_on_wire, 1 << 20, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);

    /* 400 bytes -> 100 frames of 4 bytes; recv_cap only holds the first 65
     * frames' payload (260 bytes), so the remaining 35 must back up on the
     * heap and only drain as cloak_stream_read frees space. */
    uint8_t msg[400];
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)('0' + (i % 10));
    cloak_stream_write(&tx, msg, sizeof(msg));
    ASSERT_EQ_INT(w.frame_count, 100);

    cloak_stream_t rx;
    ASSERT_EQ_INT(cloak_stream_init(&rx, 6, &o, max_on_wire, recv_cap, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w), 0);

    size_t order[100];
    for (size_t i = 0; i < 100; i++) order[i] = i;
    /* Deliver all 100 in order; backpressure should stall draining partway
     * through since the queue can only hold recv_cap of the 400 payload
     * bytes. */
    deliver_frames(&w, &o, &rx, order, 100);
    ASSERT_TRUE(cloak_stream_recv_available(&rx) <= recv_cap);
    ASSERT_TRUE(cloak_stream_recv_available(&rx) > 0);

    uint8_t out[400];
    long total = 0;
    /* Drain in small chunks, exactly like a real consumer, and confirm
     * try_drain resumes delivering the backpressured frames as space frees. */
    for (int iter = 0; iter < 300 && total < (long)sizeof(msg); iter++) {
        long got = cloak_stream_read(&rx, out + total, 3);
        if (got > 0) {
            total += got;
        }
    }
    ASSERT_EQ_INT(total, (long)sizeof(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)total);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_max_pending_frames_cap(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 2;
    cloak_stream_t tx;
    cloak_stream_init(&tx, 8, &o, max_on_wire, 1 << 20, 1000,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);
    uint8_t msg[20];
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)i;
    cloak_stream_write(&tx, msg, sizeof(msg)); /* 10 frames of 2 bytes */
    ASSERT_EQ_INT(w.frame_count, 10);

    cloak_stream_t rx;
    /* max_pending_frames = 3: never deliver seq 0, so frames 1..9 (9 of
     * them) all pile up out-of-order; the cap should reject once exceeded. */
    ASSERT_EQ_INT(cloak_stream_init(&rx, 8, &o, max_on_wire, 1 << 20, 3,
                                    CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w), 0);

    int saw_rejection = 0;
    size_t *offsets = (size_t *)malloc(w.frame_count * sizeof(size_t));
    size_t off = 0;
    for (size_t i = 0; i < w.frame_count; i++) { offsets[i] = off; off += w.frame_lens[i]; }
    for (size_t idx = 1; idx < w.frame_count; idx++) {
        uint8_t *copy = (uint8_t *)malloc(w.frame_lens[idx]);
        memcpy(copy, w.frames_data + offsets[idx], w.frame_lens[idx]);
        cloak_frame_t frame;
        cloak_frame_deobfuscate(&o, &frame, copy, w.frame_lens[idx]);
        int rc = cloak_stream_feed_frame(&rx, &frame);
        free(copy);
        if (rc == -1) {
            saw_rejection = 1;
            break;
        }
    }
    free(offsets);
    ASSERT_TRUE(saw_rejection);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_sink_failure_propagates(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);
    w.fail_after_n = 0; /* sink fails immediately */

    cloak_stream_t tx;
    cloak_stream_init(&tx, 10, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);
    long n = cloak_stream_write(&tx, (const uint8_t *)"data", 4);
    ASSERT_EQ_INT(n, -1);

    cloak_stream_destroy(&tx);
    wire_free(&w);
}

static void test_undersized_recv_capacity_rejected(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);
    cloak_stream_t s;
    /* recv_capacity smaller than what this max_on_wire_size could ever
     * deliver in one frame must be rejected at init, not accepted and
     * silently wedged later. */
    ASSERT_EQ_INT(cloak_stream_init(&s, 1, &o, MAX_ON_WIRE, 4, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w), -1);
    wire_free(&w);
}

static void test_write_failure_closes_write_side(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);
    w.fail_after_n = 0; /* sink fails on the very first frame */

    cloak_stream_t tx;
    cloak_stream_init(&tx, 12, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);
    ASSERT_EQ_INT(cloak_stream_write(&tx, (const uint8_t *)"x", 1), -1);
    /* A retry must also fail -- the stream must be closed, not silently
     * skip the sequence number that never actually reached the sink. */
    ASSERT_EQ_INT(cloak_stream_write(&tx, (const uint8_t *)"y", 1), -1);

    cloak_stream_destroy(&tx);
    wire_free(&w);
}

static void test_read_with_zero_capacity_is_not_spurious_eof(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    cloak_stream_t tx;
    cloak_stream_init(&tx, 13, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);
    const char *msg = "still here";
    cloak_stream_write(&tx, (const uint8_t *)msg, strlen(msg));
    cloak_stream_send_closing(&tx, CLOAK_FRAME_CLOSING_STREAM);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 13, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                      CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w);
    size_t order[2] = {0, 1};
    deliver_frames(&w, &o, &rx, order, 2);

    uint8_t out[1];
    /* out_cap == 0, with real buffered data and a closing frame already
     * seen -- must NOT report EOF (there's still data to deliver). */
    long got_zero = cloak_stream_read(&rx, out, 0);
    ASSERT_EQ_INT(got_zero, 0);

    uint8_t real_out[64];
    long got = cloak_stream_read(&rx, real_out, sizeof(real_out));
    ASSERT_EQ_INT(got, (long)strlen(msg));
    ASSERT_MEM_EQ(real_out, msg, (size_t)got);
    ASSERT_EQ_INT(cloak_stream_read(&rx, real_out, sizeof(real_out)), -1);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

/* ---- the ordering mode at the stream layer -----------------------------
 *
 * cloak_session_config_t carries the trap that matters (see
 * cloak/ordering.h and test_session.c's own ordering block): a struct
 * field has a zero value on every memset, a parameter does not. What this
 * case pins is that the stream layer does not quietly accept the zero
 * value ANYWAY -- if it did, cloak_session_init would be the single point
 * holding the invariant up, and a future caller that reached
 * cloak_stream_init directly (session.c is not the only conceivable one)
 * would get a stream whose mode is neither of the two real ones.
 *
 * Every assertion names CLOAK_SESSION_ERR_INVALID_ORDERING rather than
 * -1: the pre-existing rejections in this function all return -1, so a
 * non-zero assertion here would be satisfied by an implementation that
 * ignored ordering entirely and happened to object to something else. */
static void test_stream_init_rejects_invalid_ordering(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    const int bad[3] = {(int)CLOAK_SESSION_ORDERING_INVALID, 3, 255};
    for (int i = 0; i < 3; i++) {
        cloak_stream_t s;
        ASSERT_EQ_INT(cloak_stream_init(&s, 1, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                                        (cloak_session_ordering_t)bad[i], wire_sink, &w),
                      CLOAK_SESSION_ERR_INVALID_ORDERING);
    }

    /* Both real modes construct, and the mode the caller asked for is the
     * mode the stream ends up with -- a constructor that validated the
     * argument and then stored a constant would pass every rejection
     * above and hand session.c a stream that disagrees with its session. */
    const cloak_session_ordering_t good[2] = {CLOAK_SESSION_ORDERING_ORDERED,
                                              CLOAK_SESSION_ORDERING_UNORDERED};
    for (int i = 0; i < 2; i++) {
        cloak_stream_t s;
        ASSERT_EQ_INT(cloak_stream_init(&s, 1, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING, good[i],
                                        wire_sink, &w),
                      0);
        ASSERT_EQ_INT(s.ordering, good[i]);
        cloak_stream_destroy(&s);
    }

    wire_free(&w);
}


/* ---- window updates: they go out, and at the rate they are meant to --- */

/* WITHOUT THIS CASE THE WHOLE MECHANISM IS UNPINNED, and that was not a
 * guess: suppressing every window update left all 85 test binaries green.
 * A mechanism nothing would miss is a mechanism that will be deleted or
 * broken by someone who has no way to find out.
 *
 * Three properties, and the rate is the one that matters most. An update
 * per read would be a frame on the wire for every application-sized read
 * -- on a bulk transfer, one per few kilobytes -- and that storm would
 * cost more than the flow control it serves. Half the window bounds it at
 * two per window.
 */
static void test_window_updates_are_emitted_at_half_the_window(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t wtx, wrx;
    wire_init(&wtx);
    wire_init(&wrx);

    cloak_stream_t tx;
    ASSERT_EQ_INT(cloak_stream_init(&tx, 11, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &wtx), 0);
    cloak_stream_t rx;
    ASSERT_EQ_INT(cloak_stream_init(&rx, 11, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &wrx), 0);

    /* A quarter of the window, read out in full: under the half-window
     * mark, so nothing should go out yet. */
    const size_t quarter = RECV_CAP / 4;
    uint8_t *payload = (uint8_t *)malloc(quarter);
    ASSERT_TRUE(payload != NULL);
    memset(payload, 0x27, quarter);

    ASSERT_EQ_INT((long)quarter, cloak_stream_write(&tx, payload, quarter));
    size_t nframes = wtx.frame_count;
    size_t *order = (size_t *)malloc(nframes * sizeof(size_t));
    ASSERT_TRUE(order != NULL);
    for (size_t i = 0; i < nframes; i++) {
        order[i] = i;
    }
    deliver_frames(&wtx, &o, &rx, order, nframes);

    uint8_t *out = (uint8_t *)malloc(RECV_CAP);
    ASSERT_TRUE(out != NULL);
    size_t drained = 0;
    for (;;) {
        long got = cloak_stream_read(&rx, out, RECV_CAP);
        if (got <= 0) {
            break;
        }
        drained += (size_t)got;
    }
    ASSERT_EQ_INT((int)quarter, (int)drained);
    ASSERT_EQ_INT(0, (int)cloak_stream_window_updates_sent(&rx));
    ASSERT_EQ_INT(0, (int)wrx.frame_count);

    /* Another quarter takes the total past half the window: exactly one
     * update, not one per read. */
    ASSERT_EQ_INT((long)quarter, cloak_stream_write(&tx, payload, quarter));
    free(order);
    size_t nframes2 = wtx.frame_count;
    order = (size_t *)malloc(nframes2 * sizeof(size_t));
    ASSERT_TRUE(order != NULL);
    for (size_t i = 0; i < nframes2; i++) {
        order[i] = i;
    }
    /* deliver_frames replays from the start of the wire, so the receiver
     * sees the first quarter again -- already-consumed sequence numbers,
     * which it drops. Only the new frames land. */
    deliver_frames(&wtx, &o, &rx, order, nframes2);

    for (;;) {
        long got = cloak_stream_read(&rx, out, RECV_CAP);
        if (got <= 0) {
            break;
        }
        drained += (size_t)got;
    }
    ASSERT_EQ_INT((int)(quarter * 2), (int)drained);
    ASSERT_EQ_INT(1, (int)cloak_stream_window_updates_sent(&rx));

    /* And what went out really is a window update, with the right length
     * and the delta the consumer actually freed. */
    ASSERT_EQ_INT(1, (int)wrx.frame_count);
    cloak_frame_t upd;
    ASSERT_EQ_INT(0, cloak_frame_deobfuscate(&o, &upd, wrx.frames_data, wrx.frame_lens[0]));
    ASSERT_EQ_INT(upd.closing, CLOAK_FRAME_TYPE_WINDOW_UPDATE);
    ASSERT_EQ_INT(upd.stream_id, 11);
    ASSERT_EQ_INT((int)upd.payload_len, CLOAK_FRAME_WINDOW_UPDATE_LEN);
    uint32_t delta = (uint32_t)upd.payload[0] | ((uint32_t)upd.payload[1] << 8) |
                     ((uint32_t)upd.payload[2] << 16) | ((uint32_t)upd.payload[3] << 24);
    ASSERT_EQ_INT((int)delta, (int)(quarter * 2));

    /* A receiver must ignore one rather than treat it as data or as a
     * close: feeding it back into a stream changes nothing. */
    ASSERT_EQ_INT(0, cloak_stream_feed_frame(&tx, &upd));
    ASSERT_EQ_INT(0, (int)cloak_stream_recv_available(&tx));

    free(payload);
    free(order);
    free(out);
    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&wtx);
    wire_free(&wrx);
}


/* ---- credit: spent by writing, granted by a peer's update ------------- */

/* PINS THE ACCOUNTING BEFORE ANYTHING DEPENDS ON IT. Credit is not
 * enforced yet -- the clamp lands with the relay change that makes a short
 * write safe -- so the only way to know the arithmetic is right is to read
 * it directly. Getting it wrong here would surface much later as a stream
 * that stalls with no visible cause, which is the failure this whole
 * mechanism exists to remove rather than to add.
 *
 * The saturating case is not decoration: a delta that wrapped would take
 * credit from near-SIZE_MAX back to a small number and stall the stream,
 * which is exactly the shape of bug a "+=" would introduce and no
 * ordinary transfer would ever reach. */
static void test_credit_is_spent_by_writes_and_granted_by_updates(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    cloak_stream_t tx;
    ASSERT_EQ_INT(cloak_stream_init(&tx, 13, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING,
                                    CLOAK_SESSION_ORDERING_ORDERED, wire_sink, &w), 0);

    /* Starts at the window both ends know from the session config. */
    ASSERT_EQ_INT((int)RECV_CAP, (int)cloak_stream_send_credit(&tx));

    const size_t chunk = 1000;
    uint8_t buf[1000];
    memset(buf, 0x3d, sizeof(buf));
    ASSERT_EQ_INT((long)chunk, cloak_stream_write(&tx, buf, chunk));
    ASSERT_EQ_INT((int)(RECV_CAP - chunk), (int)cloak_stream_send_credit(&tx));

    ASSERT_EQ_INT((long)chunk, cloak_stream_write(&tx, buf, chunk));
    ASSERT_EQ_INT((int)(RECV_CAP - 2 * chunk), (int)cloak_stream_send_credit(&tx));

    /* A peer's update gives it back. */
    uint8_t upd_payload[CLOAK_FRAME_WINDOW_UPDATE_LEN] = {0xE8, 0x03, 0x00, 0x00}; /* 1000 */
    cloak_frame_t upd;
    upd.stream_id = 13;
    upd.seq = 0;
    upd.closing = CLOAK_FRAME_TYPE_WINDOW_UPDATE;
    upd.payload = upd_payload;
    upd.payload_len = sizeof(upd_payload);
    ASSERT_EQ_INT(0, cloak_stream_feed_frame(&tx, &upd));
    ASSERT_EQ_INT((int)(RECV_CAP - chunk), (int)cloak_stream_send_credit(&tx));

    /* An update carrying nothing usable grants nothing and does not
     * disturb the stream. */
    cloak_frame_t bad = upd;
    bad.payload_len = 1;
    ASSERT_EQ_INT(0, cloak_stream_feed_frame(&tx, &bad));
    ASSERT_EQ_INT((int)(RECV_CAP - chunk), (int)cloak_stream_send_credit(&tx));

    /* THE SATURATING GUARD IS NOT TESTED HERE, AND SAYING SO IS THE
     * POINT. Reaching it needs the credit to approach SIZE_MAX, which on
     * a 64-bit size_t means about four billion maximal updates -- not a
     * test, an afternoon. A first version of this case fed 64 of them and
     * asserted the credit had not gone backwards; it passed against a
     * deliberately wrapping `+=` too, because 274 GiB is nowhere near the
     * top of the range. An assertion that cannot fail is worse than none,
     * so it is gone and the gap is recorded instead. The guard stays in
     * the code: it costs one comparison and the alternative is a stall
     * nobody could diagnose.

     */

    /* Data still flows on this stream afterwards: the update path has not
     * touched the sequence space. */
    size_t frames_before = w.frame_count;
    ASSERT_EQ_INT((long)chunk, cloak_stream_write(&tx, buf, chunk));
    ASSERT_TRUE(w.frame_count > frames_before);

    cloak_stream_destroy(&tx);
    wire_free(&w);
}

TEST_MAIN_BEGIN()
    test_round_trip_in_order();
    test_window_updates_are_emitted_at_half_the_window();
    test_credit_is_spent_by_writes_and_granted_by_updates();
    test_multi_frame_chunking_and_reassembly();
    test_out_of_order_delivery();
    test_shuffled_delivery_many_frames();
    test_closing_frame_signals_eof();
    test_closing_frame_out_of_order_stops_drain();
    test_duplicate_seq_rejected();
    test_duplicate_pending_frame_rejected_not_wedged();
    test_backpressure_and_resume();
    test_max_pending_frames_cap();
    test_sink_failure_propagates();
    test_undersized_recv_capacity_rejected();
    test_write_failure_closes_write_side();
    test_read_with_zero_capacity_is_not_spurious_eof();
    test_stream_init_rejects_invalid_ordering();
TEST_MAIN_END()
