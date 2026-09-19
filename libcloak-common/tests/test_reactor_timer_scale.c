/* The cost of cancelling a timer, as a function of how many timers exist.
 *
 * WHY THIS FILE EXISTS. Module 10b task 4 lifted the server's session cap
 * 256 -> 1024 and replaced the registry's linear scan with a keyed hash,
 * and in doing so measured the scan it could not reach from its own file
 * list: cloak_reactor_cancel_timer walked the whole timer heap looking for
 * an id, at 2 / 78 / 298 / 1164 ns for 1 / 64 / 256 / 1024 timers -- O(n)
 * on the nose, and four times worse after the cap moved. Timer count
 * scales with session count: every session holds an inactivity timer and,
 * while it is tearing down, a deferred-teardown timer, and every
 * dispatcher connection holds a handshake deadline until it completes. So
 * the cap lift moved the defect rather than removing it.
 *
 * A TEST THAT ONLY ASSERTED "cancel still cancels" WOULD PASS AGAINST THE
 * SCAN. That is the trap task 4 named for the registry and this file is
 * the same trap one level out, so the assertions here are on COST, in
 * units that do not depend on the machine.
 *
 * STEPS, NOT NANOSECONDS, ARE WHAT IS ASSERTED. cloak_reactor_cancel_probe_steps
 * counts elements of the timer structure examined or moved, which is
 * deterministic; the wall clock is printed beside it and never asserted
 * on, because this suite runs under ASan at -j4 where a microbenchmark's
 * absolute numbers are somebody else's scheduler. Same discipline as
 * libcloak-server/tests/test_registry_scale.c. */

#include "cloak/reactor.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The four occupancies task 4 measured, so this file's table and its
 * table are comparable line for line. 1024 is CLOAK_REGISTRY_MAX_SESSIONS
 * -- one inactivity timer per session at the cap, before counting the
 * teardown timers and the dispatcher's handshake deadlines. */
static const size_t OCCUPANCIES[4] = {1, 64, 256, 1024};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static uint64_t now_ms_t(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* A deterministic 64-bit LCG. The deadlines below must be SPREAD, not
 * uniform: a heap built from n identical deadlines never sifts, so its
 * array is insertion order and every measurement taken on it describes a
 * structure the server never has. Deterministic so a failure is
 * reproducible -- nothing here is cryptographic. */
static uint64_t lcg_state = 0x243f6a8885a308d3ull;
static void lcg_seed(uint64_t s) { lcg_state = s | 1u; }
static uint64_t lcg_next(void) {
    lcg_state = lcg_state * 6364136223846793005ull + 1442695040888963407ull;
    return lcg_state >> 17;
}

static void never_fires(cloak_reactor_t *r, void *userdata) {
    (void)r;
    int *flag = (int *)userdata;
    if (flag != NULL) {
        *flag = 1;
    }
}

/* --------------------------------------------------------------------- *
 * Case 1 -- the cost bracket.
 * --------------------------------------------------------------------- */

struct bracket_row {
    size_t n;
    double drain_steps;   /* steps per cancel, cancelling every live timer */
    double drain_ns;
    double miss_steps;    /* steps per cancel of a handle that is not there */
    double miss_ns;
};

/* Fills r with n timers whose deadlines are spread far enough into the
 * future that none of them can fire during the measurement, and writes
 * their ids into ids[]. */
static void fill(cloak_reactor_t *r, cloak_timer_id_t *ids, size_t n, int *fired_flag) {
    for (size_t i = 0; i < n; i++) {
        uint64_t delay = 600000 + (lcg_next() % 600000); /* 10-20 minutes out */
        ids[i] = cloak_reactor_add_timer(r, delay, never_fires, fired_flag);
        ASSERT_TRUE(ids[i] != CLOAK_TIMER_INVALID);
    }
}

static struct bracket_row measure(size_t n) {
    struct bracket_row row;
    memset(&row, 0, sizeof(row));
    row.n = n;

    cloak_timer_id_t *ids = (cloak_timer_id_t *)calloc(n, sizeof(*ids));
    ASSERT_TRUE(ids != NULL);
    int fired = 0;

    /* -- the MISS arm: a handle that is not in the structure. This is the
     * arm that reproduces the original measurement, because it forces the
     * linear scan to run to the end every time, which is what the
     * ~1.15 ns-per-element constant in task 4's report describes. It is
     * also a real path: every cancel site in the tree guards on
     * CLOAK_TIMER_INVALID, but libcloak-mux/src/session.c's inactivity
     * re-arm and cloak_session_destroy's teardown cancel both pass ids
     * that have very often already fired. */
    {
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        lcg_seed(0xc10a4c0ffeeull + n);
        fill(r, ids, n, &fired);

        /* A handle no add_timer in this reactor ever returned. Chosen
         * above every live id so the scan cannot short-circuit. */
        cloak_timer_id_t absent = (cloak_timer_id_t)~0ull;
        size_t reps = 2000000u / n;
        if (reps < 64) {
            reps = 64;
        }
        uint64_t steps0 = cloak_reactor_cancel_probe_steps(r);
        uint64_t t0 = now_ns();
        for (size_t i = 0; i < reps; i++) {
            cloak_reactor_cancel_timer(r, absent);
        }
        uint64_t t1 = now_ns();
        row.miss_steps = (double)(cloak_reactor_cancel_probe_steps(r) - steps0) / (double)reps;
        row.miss_ns = (double)(t1 - t0) / (double)reps;
        ASSERT_EQ_INT((long long)cloak_reactor_pending_timers(r), (long long)n);
        cloak_reactor_destroy(r);
    }

    /* -- the DRAIN arm: cancel every live timer once, which is what a mass
     * teardown of every session on the server does. */
    {
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        lcg_seed(0xc10a4c0ffeeull + n);
        fill(r, ids, n, &fired);

        uint64_t steps0 = cloak_reactor_cancel_probe_steps(r);
        uint64_t t0 = now_ns();
        for (size_t i = 0; i < n; i++) {
            cloak_reactor_cancel_timer(r, ids[i]);
        }
        uint64_t t1 = now_ns();
        row.drain_steps = (double)(cloak_reactor_cancel_probe_steps(r) - steps0) / (double)n;
        row.drain_ns = (double)(t1 - t0) / (double)n;
        cloak_reactor_destroy(r);
    }

    ASSERT_TRUE(!fired);
    free(ids);
    return row;
}

/* THE BRACKET, and the two tables it sits between.
 *
 * MEASURED against the linear scan this commit removed (gcc 12.2, Debug):
 *
 *      n | drain steps  drain ns | miss steps   miss ns
 *      1 |      1.000       42.0 |      1.000       2.9
 *     64 |     32.500       81.4 |     64.000     154.4
 *    256 |    128.500      299.6 |    256.000     588.5
 *   1024 |    512.500     1221.2 |   1024.000    2318.6
 *
 * -- which is task 4's reported 2 / 78 / 298 / 1164 ns at 1 / 64 / 256 /
 * 1024, reproduced. (The drain column is the arm that matches it: the
 * scan stops at the id it finds, so cancelling every live id averages n/2
 * elements. The miss column is exactly n and is twice as expensive.)
 *
 * MEASURED against what replaced it, same build, same machine:
 *
 *      n | drain steps  drain ns | miss steps   miss ns
 *      1 |      1.000       42.0 |      1.000       2.4
 *     64 |      2.922       56.6 |      1.000       2.5
 *    256 |      2.902       54.9 |      1.000       2.4
 *   1024 |      3.051       56.0 |      1.000       2.4
 *
 * Ratio across the 1024-fold range: 3.051 and 1.000, against 512.5 and
 * 1024.0. 8.0 is that measured 3.051 plus headroom -- it is not a number
 * anybody picked to make the test pass, and there is no structure that
 * walks its contents that can reach it.
 *
 * The step counts are near-deterministic rather than exactly so: the
 * deadlines come from a fixed LCG, and the only variance is the clock
 * ticking during a fill, which can flip the order of two deadlines that
 * happened to land within a millisecond of each other. That moves a mean
 * taken over n cancels by well under 0.01.
 *
 * The `drain ns` figure at n=1 is one cancel bracketed by two
 * clock_gettime calls and is therefore mostly clock_gettime; the miss
 * column is the amortised one, and it is the column to read for absolute
 * cost. Neither is asserted on -- this suite runs under ASan at -j4. */
#define CANCEL_STEP_BRACKET 8.0

/* And an absolute ceiling at the cap, so that a structure whose ratio
 * happens to be flat because it is uniformly expensive cannot pass.
 * Measured 3.051. */
#define CANCEL_STEP_CEILING_AT_CAP 12.0

static void test_cancel_cost_bracket(void) {
    struct bracket_row rows[4];
    for (size_t i = 0; i < 4; i++) {
        rows[i] = measure(OCCUPANCIES[i]);
    }

    printf("\n  cloak_reactor_cancel_timer, by occupancy\n");
    printf("  %6s | %12s %10s | %12s %10s\n", "n", "drain steps", "drain ns", "miss steps", "miss ns");
    for (size_t i = 0; i < 4; i++) {
        printf("  %6zu | %12.3f %10.1f | %12.3f %10.1f\n", rows[i].n, rows[i].drain_steps,
               rows[i].drain_ns, rows[i].miss_steps, rows[i].miss_ns);
    }

    double drain_min = rows[0].drain_steps, drain_max = rows[0].drain_steps;
    double miss_min = rows[0].miss_steps, miss_max = rows[0].miss_steps;
    for (size_t i = 1; i < 4; i++) {
        if (rows[i].drain_steps < drain_min) drain_min = rows[i].drain_steps;
        if (rows[i].drain_steps > drain_max) drain_max = rows[i].drain_steps;
        if (rows[i].miss_steps < miss_min) miss_min = rows[i].miss_steps;
        if (rows[i].miss_steps > miss_max) miss_max = rows[i].miss_steps;
    }
    printf("  ratio across a 1024-fold range: drain %.3f, miss %.3f\n\n",
           drain_max / drain_min, miss_max / miss_min);

    ASSERT_TRUE(drain_min > 0.0);
    ASSERT_TRUE(miss_min > 0.0);
    ASSERT_TRUE(drain_max <= CANCEL_STEP_BRACKET * drain_min);
    ASSERT_TRUE(miss_max <= CANCEL_STEP_BRACKET * miss_min);
    ASSERT_TRUE(rows[3].drain_steps <= CANCEL_STEP_CEILING_AT_CAP);
    ASSERT_TRUE(rows[3].miss_steps <= CANCEL_STEP_CEILING_AT_CAP);
}

/* --------------------------------------------------------------------- *
 * Case 2 -- cancelling does not merely mark: the structure shrinks.
 *
 * The scan this replaces left a cancelled entry in the heap until it
 * reached the root, so a session that re-armed its inactivity timer once
 * per frame grew the heap once per frame and never gave the memory back
 * until the deadline passed. That is invisible to every correctness
 * assertion and it is half of why the scan was slow.
 * --------------------------------------------------------------------- */
static void test_cancel_releases_the_slot(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    int fired = 0;

    cloak_timer_id_t keep = cloak_reactor_add_timer(r, 600000, never_fires, &fired);
    ASSERT_TRUE(keep != CLOAK_TIMER_INVALID);
    ASSERT_EQ_INT((long long)cloak_reactor_pending_timers(r), 1);

    /* One live timer, re-armed 5000 times, exactly as session.c does per
     * frame. Occupancy must come back to 2 every time, not climb. */
    cloak_timer_id_t t = CLOAK_TIMER_INVALID;
    for (int i = 0; i < 5000; i++) {
        cloak_reactor_cancel_timer(r, t);
        t = cloak_reactor_add_timer(r, 600000, never_fires, &fired);
        ASSERT_TRUE(t != CLOAK_TIMER_INVALID);
        if (cloak_reactor_pending_timers(r) != 2) {
            ASSERT_EQ_INT((long long)cloak_reactor_pending_timers(r), 2);
            break;
        }
    }
    ASSERT_EQ_INT((long long)cloak_reactor_pending_timers(r), 2);
    ASSERT_TRUE(!fired);
    cloak_reactor_destroy(r);
}

/* --------------------------------------------------------------------- *
 * Case 3 -- a handle whose timer has already gone must never reach a
 * different timer.
 *
 * This is the assertion that an id->slot map has to earn and a linear
 * scan over unique ids got for free. If the map recycles a slot without
 * making the old handle distinguishable from the new one, cancelling an
 * id that has already fired silently kills whichever timer inherited its
 * slot -- on the server that is one session's teardown cancelling
 * another session's inactivity deadline.
 * --------------------------------------------------------------------- */
struct fire_log {
    int a_fired;
    int c_fired;
};

static void on_a(cloak_reactor_t *r, void *userdata) {
    (void)r;
    ((struct fire_log *)userdata)->a_fired = 1;
}
static void on_c(cloak_reactor_t *r, void *userdata) {
    (void)r;
    ((struct fire_log *)userdata)->c_fired = 1;
}

static void test_stale_handle_is_inert(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    struct fire_log log;
    memset(&log, 0, sizeof(log));

    cloak_timer_id_t a = cloak_reactor_add_timer(r, 0, on_a, &log);
    ASSERT_TRUE(a != CLOAK_TIMER_INVALID);

    uint64_t budget_end = now_ms_t() + 2000;
    while (!log.a_fired && now_ms_t() < budget_end) {
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_TRUE(log.a_fired);
    ASSERT_EQ_INT((long long)cloak_reactor_pending_timers(r), 0);

    /* C is created after A is gone, so it is the timer most likely to have
     * inherited A's storage. */
    cloak_timer_id_t c = cloak_reactor_add_timer(r, 20, on_c, &log);
    ASSERT_TRUE(c != CLOAK_TIMER_INVALID);
    ASSERT_TRUE(c != a);

    cloak_reactor_cancel_timer(r, a); /* stale: must be a no-op */
    ASSERT_EQ_INT((long long)cloak_reactor_pending_timers(r), 1);

    budget_end = now_ms_t() + 2000;
    while (!log.c_fired && now_ms_t() < budget_end) {
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_TRUE(log.c_fired);

    /* And cancelling the same id twice, and cancelling a handle that was
     * never issued, are both no-ops rather than corruption. */
    cloak_reactor_cancel_timer(r, a);
    cloak_reactor_cancel_timer(r, c);
    cloak_reactor_cancel_timer(r, c);
    cloak_reactor_cancel_timer(r, (cloak_timer_id_t)~0ull);
    cloak_reactor_cancel_timer(r, CLOAK_TIMER_INVALID);
    ASSERT_EQ_INT((long long)cloak_reactor_pending_timers(r), 0);

    cloak_reactor_destroy(r);
}

/* --------------------------------------------------------------------- *
 * Case 4 -- removing an arbitrary element must leave a heap behind.
 *
 * A scan that only sets a flag cannot break the heap invariant; a removal
 * that moves the last element into the hole and sifts it CAN, and the way
 * it shows up is a timer firing late or out of order rather than a crash.
 * 4000 timers, half of them cancelled at random, and the survivors must
 * come out in non-decreasing deadline order.
 * --------------------------------------------------------------------- */
struct order_log {
    size_t seen_len;
    size_t cap;
    int out_of_order;
    uint64_t last;
    int cancelled_fired;
};

struct order_timer {
    struct order_log *log;
    unsigned bucket;    /* the delay passed to add_timer, in ms */
    uint64_t deadline;  /* now_ms() read just BEFORE add_timer, plus bucket */
    int cancelled;
};

static void on_ordered(cloak_reactor_t *r, void *userdata) {
    (void)r;
    struct order_timer *ot = (struct order_timer *)userdata;
    struct order_log *log = ot->log;
    if (ot->cancelled) {
        log->cancelled_fired = 1;
    }
    /* ORDER IS CHECKED AGAINST THE ABSOLUTE DEADLINE, NOT THE DELAY, AND
     * WITH A ONE-MILLISECOND TOLERANCE -- both of which were forced by a
     * measurement, not chosen. Checking `bucket` (the delay) instead
     * fails against the ORIGINAL, correct heap roughly every run: filling
     * 4000 timers takes long enough for now_ms() to tick, so a 5 ms timer
     * added late really does have a later absolute deadline than a 6 ms
     * timer added early, and the heap is right to fire them in that
     * order. `deadline` is read from the same clock one call before
     * add_timer reads it, so it is either exact or one low; two timers
     * with equal true deadlines fire in unspecified order, which is the
     * one millisecond of slack. */
    if (log->seen_len > 0 && ot->deadline + 1 < log->last) {
        log->out_of_order = 1;
    }
    if (ot->deadline > log->last) {
        log->last = ot->deadline;
    }
    log->seen_len++;
}

#define ORDER_N 4000u
#define ORDER_BUCKETS 40u /* 0..39 ms; the whole case costs ~40 ms of wall clock */

static void test_removal_preserves_heap_order(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct order_timer *timers = (struct order_timer *)calloc(ORDER_N, sizeof(*timers));
    cloak_timer_id_t *ids = (cloak_timer_id_t *)calloc(ORDER_N, sizeof(*ids));
    ASSERT_TRUE(timers != NULL && ids != NULL);

    struct order_log log;
    memset(&log, 0, sizeof(log));
    log.cap = ORDER_N;

    lcg_seed(0x5eed1234ull);
    size_t expected = 0;
    for (size_t i = 0; i < ORDER_N; i++) {
        timers[i].log = &log;
        timers[i].bucket = (unsigned)(lcg_next() % ORDER_BUCKETS);
        timers[i].deadline = now_ms_t() + timers[i].bucket;
        ids[i] = cloak_reactor_add_timer(r, timers[i].bucket, on_ordered, &timers[i]);
        ASSERT_TRUE(ids[i] != CLOAK_TIMER_INVALID);
    }
    /* Cancel a random half, interleaved with the fills above only in the
     * sense that the heap is already full -- every cancel here removes an
     * element from an arbitrary position, which is the operation under
     * test. */
    for (size_t i = 0; i < ORDER_N; i++) {
        if ((lcg_next() & 1u) != 0) {
            timers[i].cancelled = 1;
            cloak_reactor_cancel_timer(r, ids[i]);
        } else {
            expected++;
        }
    }

    uint64_t budget_end = now_ms_t() + 5000;
    while (log.seen_len < expected && now_ms_t() < budget_end) {
        cloak_reactor_run_once(r, 5);
    }

    ASSERT_EQ_INT((long long)log.seen_len, (long long)expected);
    ASSERT_TRUE(!log.out_of_order);
    ASSERT_TRUE(!log.cancelled_fired);
    ASSERT_EQ_INT((long long)cloak_reactor_pending_timers(r), 0);

    cloak_reactor_destroy(r);
    free(timers);
    free(ids);
}

/* --------------------------------------------------------------------- *
 * Case 5 -- cancelling from inside a timer callback.
 *
 * libcloak-mux/src/session.c cancels the inactivity timer from inside the
 * teardown callback, and libcloak-server/src/registry.c's sweep callback
 * runs while the heap is mid-pop. A removal-based cancel touches the array
 * the caller is standing on, so this is the reentrancy the flag-setting
 * version never had to survive.
 * --------------------------------------------------------------------- */
struct reentrant_ctx {
    cloak_reactor_t *r;
    cloak_timer_id_t self;
    cloak_timer_id_t victim;
    int self_fired;
    int victim_fired;
    int extra_fired;
};

static void on_victim(cloak_reactor_t *r, void *userdata) {
    (void)r;
    ((struct reentrant_ctx *)userdata)->victim_fired = 1;
}
static void on_extra(cloak_reactor_t *r, void *userdata) {
    (void)r;
    ((struct reentrant_ctx *)userdata)->extra_fired = 1;
}
static void on_reentrant(cloak_reactor_t *r, void *userdata) {
    struct reentrant_ctx *ctx = (struct reentrant_ctx *)userdata;
    ctx->self_fired = 1;
    /* Cancel our own (already-fired) handle: documented no-op. */
    cloak_reactor_cancel_timer(r, ctx->self);
    /* Cancel another pending timer from inside the callback. */
    cloak_reactor_cancel_timer(r, ctx->victim);
    /* And add one, which may reallocate the array under us. */
    for (int i = 0; i < 64; i++) {
        ASSERT_TRUE(cloak_reactor_add_timer(r, 5, on_extra, ctx) != CLOAK_TIMER_INVALID);
    }
}

static void test_cancel_from_inside_callback(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    struct reentrant_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.r = r;

    ctx.victim = cloak_reactor_add_timer(r, 10, on_victim, &ctx);
    ASSERT_TRUE(ctx.victim != CLOAK_TIMER_INVALID);
    ctx.self = cloak_reactor_add_timer(r, 0, on_reentrant, &ctx);
    ASSERT_TRUE(ctx.self != CLOAK_TIMER_INVALID);

    uint64_t budget_end = now_ms_t() + 3000;
    while (cloak_reactor_pending_timers(r) > 0 && now_ms_t() < budget_end) {
        cloak_reactor_run_once(r, 5);
    }

    ASSERT_TRUE(ctx.self_fired);
    ASSERT_TRUE(!ctx.victim_fired);
    ASSERT_TRUE(ctx.extra_fired);
    ASSERT_EQ_INT((long long)cloak_reactor_pending_timers(r), 0);

    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_cancel_cost_bracket();
    test_cancel_releases_the_slot();
    test_stale_handle_is_inert();
    test_removal_preserves_heap_order();
    test_cancel_from_inside_callback();
TEST_MAIN_END()
