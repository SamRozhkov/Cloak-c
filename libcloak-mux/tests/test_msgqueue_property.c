#define _POSIX_C_SOURCE 200809L

/* A MODEL-CHECKED RANDOM WALK OVER cloak_msgqueue_t.
 *
 * ORIGIN AND CREDIT. This test was designed by the task 3 reviewer, not
 * by the author of msgqueue.c, and it earned its place before it was
 * written down: on the implementation exactly as shipped it found two
 * defects that the entire 70-test suite missed. One was a datagram that
 * exactly fills the free space of a NON-EMPTY queue (a one-line mutant
 * rejecting only that case survived every other test; the ordinary
 * boundary case only ever exercised exact fit into an EMPTY queue, which
 * is a different path through the same expression). The other was a
 * zero-length datagram being swallowed. The reviewer's own copy was
 * temporary and was removed when the review finished, so this is a
 * rewrite to the specification the review states, not a copy of their
 * file -- the shape, the capacities, the operation count and the four
 * read-buffer choices are all theirs.
 *
 * WHY A RANDOM WALK AND NOT MORE EXAMPLES. Every property below could be
 * asserted by hand, and several are, in test_stream_unordered.c. What no
 * hand-written case gives you is the CROSS PRODUCT: the ring's wrap
 * offset, the number of queued datagrams, the free space remaining and
 * the size of the next write are four independent quantities, and the
 * interesting bugs live where an unusual combination of all four meets
 * an off-by-one. Fifteen capacities chosen to straddle the 4-byte length
 * prefix (5, 6, 7, 8, 9 are prefix+1 through prefix+5) and to sit either
 * side of round numbers (259, 260, 261) put the wrap point at every
 * alignment relative to a record boundary.
 *
 * THE MODEL IS THE ASSERTION. A deque of byte strings plus the queue's
 * own stated admission rule, re-derived here from msgqueue.h rather than
 * read out of msgqueue.c, so the test can disagree with the
 * implementation. After EVERY operation it checks count, payload_bytes
 * and peek_len, and every successful read is compared byte for byte.
 *
 * DETERMINISTIC. A fixed seed and a hand-rolled xorshift, so a failure
 * reproduces exactly rather than "sometimes". Nothing here forks, sleeps,
 * touches the reactor or reads the clock. */

#include "cloak/msgqueue.h"

#include "test_framework.h"

#include <stdlib.h>
#include <string.h>

/* The queue's admission rule, restated from msgqueue.h. Deliberately NOT
 * calling anything in msgqueue.c: a model that asked the implementation
 * what it would do could not disagree with it. */
#define PREFIX 4

static uint64_t rng_state;

static void rng_seed(uint64_t s) { rng_state = s ? s : 0x9e3779b97f4a7c15ull; }

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static size_t rng_below(size_t n) { return n == 0 ? 0 : (size_t)(rng_next() % n); }

/* The model: up to MODEL_MAX queued datagrams, each of up to MODEL_MSG
 * bytes. Both bounds exceed anything the largest capacity below can hold
 * (1024 / (PREFIX + 1) = 204 datagrams; 1024 - PREFIX = 1020 bytes). */
#define MODEL_MAX 256
#define MODEL_MSG 1100

struct model {
    size_t cap;
    uint8_t msg[MODEL_MAX][MODEL_MSG];
    size_t len[MODEL_MAX];
    size_t head;  /* index of the oldest */
    size_t count;
    size_t used;  /* bytes the queue should be holding, prefixes included */
    size_t payload_bytes;
};

static void model_init(struct model *m, size_t cap) {
    memset(m, 0, sizeof(*m));
    m->cap = cap;
}

/* What the queue must answer for a write of `len` bytes, per msgqueue.h. */
static int model_write_verdict(const struct model *m, size_t len) {
    if (len > m->cap - PREFIX) {
        return CLOAK_MSGQUEUE_ERR_TOO_LARGE;
    }
    if (len + PREFIX > m->cap - m->used) {
        return CLOAK_MSGQUEUE_ERR_FULL;
    }
    return 0;
}

static void model_push(struct model *m, const uint8_t *msg, size_t len) {
    size_t slot = (m->head + m->count) % MODEL_MAX;
    ASSERT_TRUE(m->count < MODEL_MAX);
    memcpy(m->msg[slot], msg, len);
    m->len[slot] = len;
    m->count++;
    m->used += PREFIX + len;
    m->payload_bytes += len;
}

static void model_pop(struct model *m) {
    ASSERT_TRUE(m->count > 0);
    m->used -= PREFIX + m->len[m->head];
    m->payload_bytes -= m->len[m->head];
    m->head = (m->head + 1) % MODEL_MAX;
    m->count--;
}

/* Every invariant that can be read off the queue without consuming
 * anything, checked after EVERY operation rather than at the end -- a
 * check only at the end cannot say which operation broke it. */
static void check_state(const cloak_msgqueue_t *q, const struct model *m, size_t cap, long op) {
    if (cloak_msgqueue_count(q) != m->count) {
        fprintf(stderr, "cap %zu op %ld: count %zu != model %zu\n", cap, op,
                cloak_msgqueue_count(q), m->count);
        ASSERT_EQ_INT(cloak_msgqueue_count(q), m->count);
        return;
    }
    if (cloak_msgqueue_payload_bytes(q) != m->payload_bytes) {
        fprintf(stderr, "cap %zu op %ld: payload_bytes %zu != model %zu\n", cap, op,
                cloak_msgqueue_payload_bytes(q), m->payload_bytes);
        ASSERT_EQ_INT(cloak_msgqueue_payload_bytes(q), m->payload_bytes);
        return;
    }
    size_t peeked = 0;
    int have = cloak_msgqueue_peek_len(q, &peeked);
    if (have != (m->count > 0)) {
        fprintf(stderr, "cap %zu op %ld: peek_len presence %d != %d\n", cap, op, have,
                (int)(m->count > 0));
        ASSERT_EQ_INT(have, m->count > 0);
        return;
    }
    if (have && peeked != m->len[m->head]) {
        fprintf(stderr, "cap %zu op %ld: peek_len %zu != model %zu\n", cap, op, peeked,
                m->len[m->head]);
        ASSERT_EQ_INT(peeked, m->len[m->head]);
    }
}

static void walk_one_capacity(size_t cap, long ops) {
    cloak_msgqueue_t q;
    ASSERT_EQ_INT(cloak_msgqueue_init(&q, cap), 0);

    struct model m;
    model_init(&m, cap);

    uint8_t *scratch = (uint8_t *)malloc(MODEL_MSG);
    uint8_t *out = (uint8_t *)malloc(MODEL_MSG + 64);
    ASSERT_TRUE(scratch != NULL && out != NULL);
    if (scratch == NULL || out == NULL) {
        free(scratch);
        free(out);
        cloak_msgqueue_destroy(&q);
        return;
    }

    uint32_t stamp = 0;
    for (long op = 0; op < ops; op++) {
        /* Writes twice as often as reads, so the queue spends real time
         * at and near full rather than hovering empty -- FULL and
         * exact-fit are the states this test exists to reach. */
        if (rng_below(3) != 0) {
            /* 0 .. cap + 8, so zero-length, exact-fit, FULL and
             * TOO_LARGE are all reachable at every wrap offset.
             *
             * A NOTE FOR MODULE 9 TASK 4, which owns the zero-length
             * policy and has not reported yet. Including 0 in this range
             * is the reviewer's design and is what killed a mutant that
             * swallowed zero-length datagrams -- but it therefore PINS
             * the queue's current behaviour, which is to carry them,
             * matching Go's datagramBufferedPipe.go:89-91. That is not a
             * decision taken here. If task 4's measurement of a real Go
             * server says the sender should swallow a zero-length write
             * and the receive side should follow, model_write_verdict and
             * cloak_msgqueue_write change together and this comment goes
             * with them. Unreachable from a frame today either way:
             * cloak_frame_obfuscate refuses an empty payload. */
            size_t len = rng_below(cap + 9);
            if (len > MODEL_MSG) {
                len = MODEL_MSG;
            }
            stamp++;
            for (size_t i = 0; i < len; i++) {
                scratch[i] = (uint8_t)((stamp * 31u + i) & 0xffu);
            }
            int want = model_write_verdict(&m, len);
            int got = cloak_msgqueue_write(&q, scratch, len);
            if (got != want) {
                fprintf(stderr, "cap %zu op %ld: write(%zu) -> %d, model says %d"
                                " (used %zu, count %zu)\n",
                        cap, op, len, got, want, m.used, m.count);
                ASSERT_EQ_INT(got, want);
                break;
            }
            if (want == 0) {
                model_push(&m, scratch, len);
            }
        } else {
            size_t head_len = m.count > 0 ? m.len[m.head] : 0;
            /* The four read-buffer choices: one byte short, exact, zero,
             * and generous. "One short" is what makes the no-consume
             * guarantee load-bearing; "zero" is the degenerate case of
             * the same thing. */
            size_t out_cap;
            switch (rng_below(4)) {
            case 0: out_cap = head_len > 0 ? head_len - 1 : 0; break;
            case 1: out_cap = head_len; break;
            case 2: out_cap = 0; break;
            default: out_cap = MODEL_MSG + 64; break;
            }
            memset(out, 0xcd, MODEL_MSG + 64);
            long got = cloak_msgqueue_read(&q, out, out_cap);
            if (m.count == 0) {
                if (got != CLOAK_MSGQUEUE_EMPTY) {
                    fprintf(stderr, "cap %zu op %ld: read on empty -> %ld\n", cap, op, got);
                    ASSERT_EQ_INT(got, CLOAK_MSGQUEUE_EMPTY);
                    break;
                }
            } else if (out_cap < head_len) {
                if (got != CLOAK_MSGQUEUE_SHORT_BUFFER) {
                    fprintf(stderr, "cap %zu op %ld: short read(%zu of %zu) -> %ld\n", cap, op,
                            out_cap, head_len, got);
                    ASSERT_EQ_INT(got, CLOAK_MSGQUEUE_SHORT_BUFFER);
                    break;
                }
                /* And it consumed NOTHING -- checked by check_state
                 * below, which still expects the same count, the same
                 * payload_bytes and the same head length. */
            } else {
                if (got != (long)head_len) {
                    fprintf(stderr, "cap %zu op %ld: read(%zu) -> %ld, want %zu\n", cap, op,
                            out_cap, got, head_len);
                    ASSERT_EQ_INT(got, (long)head_len);
                    break;
                }
                if (head_len > 0 && memcmp(out, m.msg[m.head], head_len) != 0) {
                    fprintf(stderr, "cap %zu op %ld: content mismatch on %zu bytes\n", cap, op,
                            head_len);
                    ASSERT_MEM_EQ(out, m.msg[m.head], head_len);
                    break;
                }
                model_pop(&m);
            }
        }
        check_state(&q, &m, cap, op);
    }

    free(scratch);
    free(out);
    cloak_msgqueue_destroy(&q);
}

/* 15 capacities x 20 000 operations = 300 000 operations. Measured in
 * this tree: 0.05 s in Debug, ~1 s under ASan+UBSan -- cheap enough for
 * the fast tier, which is where it is. */
static void test_random_walk_matches_the_model(void) {
    static const size_t caps[15] = {5, 6, 7, 8, 9, 13, 16, 17, 33, 64, 100, 259, 260, 261, 1024};
    rng_seed(0x5eed1234u);
    for (size_t i = 0; i < 15; i++) {
        walk_one_capacity(caps[i], 20000);
    }
}

/* The walk never closes the queue, because a closed queue stops accepting
 * and the walk would spend its remaining operations draining. The close
 * contract gets its own deterministic case: already-queued datagrams
 * outlive the close, further writes are refused with the named code, and
 * EOF arrives only once the last one is drained. */
static void test_close_keeps_queued_datagrams_and_then_reports_eof(void) {
    cloak_msgqueue_t q;
    ASSERT_EQ_INT(cloak_msgqueue_init(&q, 64), 0);

    const uint8_t a[3] = {1, 2, 3};
    const uint8_t b[5] = {4, 5, 6, 7, 8};
    ASSERT_EQ_INT(cloak_msgqueue_write(&q, a, sizeof(a)), 0);
    ASSERT_EQ_INT(cloak_msgqueue_write(&q, b, sizeof(b)), 0);
    ASSERT_EQ_INT(cloak_msgqueue_is_eof(&q), 0);

    cloak_msgqueue_close(&q);
    ASSERT_EQ_INT(cloak_msgqueue_is_eof(&q), 0); /* closed but not drained */
    ASSERT_EQ_INT(cloak_msgqueue_write(&q, a, sizeof(a)), CLOAK_MSGQUEUE_ERR_CLOSED);
    ASSERT_EQ_INT(cloak_msgqueue_count(&q), 2);

    uint8_t out[16];
    ASSERT_EQ_INT(cloak_msgqueue_read(&q, out, sizeof(out)), (long)sizeof(a));
    ASSERT_MEM_EQ(out, a, sizeof(a));
    ASSERT_EQ_INT(cloak_msgqueue_is_eof(&q), 0);
    ASSERT_EQ_INT(cloak_msgqueue_read(&q, out, sizeof(out)), (long)sizeof(b));
    ASSERT_MEM_EQ(out, b, sizeof(b));
    ASSERT_EQ_INT(cloak_msgqueue_is_eof(&q), 1);
    ASSERT_EQ_INT(cloak_msgqueue_read(&q, out, sizeof(out)), CLOAK_MSGQUEUE_EMPTY);

    /* Idempotent, as the header says. */
    cloak_msgqueue_close(&q);
    ASSERT_EQ_INT(cloak_msgqueue_is_eof(&q), 1);

    cloak_msgqueue_destroy(&q);
}

/* A capacity that cannot hold even a 1-byte datagram plus its prefix is
 * refused at construction rather than becoming a queue that silently
 * accepts nothing forever. PREFIX itself is the boundary. */
static void test_init_refuses_a_capacity_that_can_never_accept(void) {
    cloak_msgqueue_t q;
    for (size_t cap = 0; cap <= PREFIX; cap++) {
        ASSERT_EQ_INT(cloak_msgqueue_init(&q, cap), -1);
    }
    ASSERT_EQ_INT(cloak_msgqueue_init(&q, PREFIX + 1), 0);
    const uint8_t one = 0x42;
    ASSERT_EQ_INT(cloak_msgqueue_write(&q, &one, 1), 0);
    ASSERT_EQ_INT(cloak_msgqueue_write(&q, &one, 1), CLOAK_MSGQUEUE_ERR_FULL);
    cloak_msgqueue_destroy(&q);
}

TEST_MAIN_BEGIN()
    test_random_walk_matches_the_model();
    test_close_keeps_queued_datagrams_and_then_reports_eof();
    test_init_refuses_a_capacity_that_can_never_accept();
TEST_MAIN_END()
