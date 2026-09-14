#define _POSIX_C_SOURCE 200809L
#include "cloak/valve.h"

#include <stddef.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* The clock                                                           */
/* ------------------------------------------------------------------ */

/* CLOCK_MONOTONIC, in milliseconds -- deliberately the same clock and
 * the same unit cloak_reactor_add_timer's deadlines use. Every pause a
 * bucket causes is resumed by one of those timers, and a resume computed
 * on one time base but scheduled on another can be made arbitrarily
 * early or late by an NTP step. See cloak_valve_clock_fn. */
static uint64_t valve_default_now_ms(void *userdata) {
    (void)userdata;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static uint64_t valve_now_ms(const cloak_valve_t *v) {
    if (v->clock_fn != NULL) {
        return v->clock_fn(v->clock_userdata);
    }
    return valve_default_now_ms(NULL);
}

/* ------------------------------------------------------------------ */
/* The token bucket                                                    */
/* ------------------------------------------------------------------ */

/* Milli-bytes per byte. Tokens are held at this resolution so that one
 * millisecond of accrual at `rate` bytes/sec is exactly `rate`
 * milli-bytes -- an integer, with nothing to round away. See
 * cloak_valve_bucket_t. */
#define VALVE_MILLI 1000

/* Past this much idle time a bucket is simply full, whatever it held
 * before, so the multiplication below never sees a large elapsed value.
 *
 * TWO seconds and not one, and the difference is load-bearing: tokens
 * can be as low as -capacity (one second of debt), so it takes two
 * seconds of accrual -- not one -- to be certain the linear result would
 * have reached or passed capacity. Short-circuiting at one second would
 * hand a bucket in debt a full bucket it had not earned. */
#define VALVE_FULL_AFTER_MS 2000

/* Refills b for the time elapsed since its last refill.
 *
 * A clock that has not advanced, or has gone backwards (a clock swapped
 * under a live valve, a test that rewinds), re-stamps and credits
 * nothing: time cannot be un-spent, and crediting a negative elapsed
 * would silently destroy tokens the bucket had legitimately earned. */
static void bucket_refill(cloak_valve_bucket_t *b, uint64_t now) {
    if (now <= b->last_refill) {
        b->last_refill = now;
        return;
    }
    uint64_t elapsed = now - b->last_refill;
    b->last_refill = now;
    if (elapsed >= VALVE_FULL_AFTER_MS) {
        b->tokens = b->capacity;
        return;
    }
    /* No overflow: rate <= CLOAK_VALVE_MAX_RATE and elapsed < 2000, so
     * this product is below 2 * capacity, and tokens is in
     * [-capacity, capacity] -- the sum stays under 3 * capacity, which
     * for the clamped maximum rate is ~3.3e15, three orders of magnitude
     * inside int64_t. */
    b->tokens += b->rate * (int64_t)elapsed;
    if (b->tokens > b->capacity) {
        b->tokens = b->capacity;
    }
}

/* Whole bytes available right now. Never negative: C division truncates
 * toward zero, so a bucket in debt yields 0 rather than a negative
 * count, and the caller's "<= 0 means pause" test is exact either way. */
static int64_t bucket_available(cloak_valve_bucket_t *b, uint64_t now) {
    bucket_refill(b, now);
    int64_t avail = b->tokens / VALVE_MILLI;
    return avail < 0 ? 0 : avail;
}

static int64_t bucket_take(cloak_valve_bucket_t *b, uint64_t now, int64_t want) {
    int64_t avail = bucket_available(b, now);
    return avail < want ? avail : want;
}

/* Charges n bytes against the bucket. Tokens may go negative -- see
 * cloak_valve_bucket_t's DEBT paragraph -- but never below one second's
 * worth, which is what bounds the longest pause this module can produce
 * to about two seconds no matter what is charged against it. */
static void bucket_spend(cloak_valve_bucket_t *b, int64_t n) {
    if (n <= 0) {
        return;
    }
    /* n is a completed transfer's byte count (a single read or a single
     * frame), so this clamp is unreachable from any call site in this
     * tree; it is here so that the multiplication cannot be the thing
     * that goes wrong if one ever changes. */
    if (n > INT64_MAX / VALVE_MILLI) {
        n = INT64_MAX / VALVE_MILLI;
    }
    int64_t cost = n * VALVE_MILLI;
    if (b->tokens < -b->capacity + cost) {
        b->tokens = -b->capacity;
        return;
    }
    b->tokens -= cost;
}

/* Milliseconds a caller must wait before this bucket has a whole byte.
 * NEVER 0. Callers distinguish "not rate-limited at all" from "wait this
 * long" by the 0, and only the rate == 0 short circuits above may
 * produce it -- see cloak_valve_rx_resume_delay_ms in cloak/valve.h.
 *
 * THE FLOOR IS THE CONTRACT, not a rounding detail, and an earlier
 * version of this function did not have it. It returned 0 whenever the
 * bucket already held a byte, and the comment above it asserted that
 * could not happen because the function "is only called when it does
 * not". That reasoning was wrong: this call and the take that preceded
 * it read the clock INDEPENDENTLY (see valve_now_ms), so a bucket a
 * fraction of a byte short at the take can hold a whole one a few
 * microseconds later. Every consumer read the 0 back as "the valve is
 * not the binding constraint" and armed nothing, which left a relay
 * paused with a full bucket and no timer -- a permanent stall, hit about
 * once in two hundred ASan runs of libcloak-mux/tests/test_valve_rate.c.
 *
 * Fixed HERE, at the producer, rather than by flooring at each call
 * site: the consumers were doing that and it made the header's promise
 * true only for the callers who already knew it was false. A fourth
 * pause site written against that header -- an RX relay, the planned UDP
 * path -- would have armed the raw value and stalled the same way, with
 * nothing to warn it. */
static uint64_t bucket_delay_ms(cloak_valve_bucket_t *b, uint64_t now) {
    bucket_refill(b, now);
    int64_t need = VALVE_MILLI - b->tokens;
    if (need <= 0) {
        /* The byte arrived between the caller's take and this call. One
         * millisecond, not zero: the caller is about to pause on a
         * refusal it has already decided to act on, and the worst this
         * costs is a wake-up a millisecond from now that finds the byte
         * and resumes immediately. */
        return 1;
    }
    /* Ceiling division: a delay that rounded DOWN would wake to a bucket
     * that still has nothing, which is a spin rather than a resume. */
    int64_t ms = (need + b->rate - 1) / b->rate;
    return ms < 1 ? 1u : (uint64_t)ms;
}

/* ------------------------------------------------------------------ */
/* Counters                                                            */
/* ------------------------------------------------------------------ */

void cloak_valve_add_rx(cloak_valve_t *v, int64_t n) {
    if (v == NULL) {
        return; /* unmetered session -- see cloak/valve.h */
    }
    v->rx += n;
    if (v->rx_bucket.rate != 0) {
        /* The meter is the bucket's drain: bytes are charged at the one
         * moment they are known to have crossed the socket, so a grant
         * the caller could not use costs nothing. See cloak_valve_add_rx's
         * doc comment in cloak/valve.h. */
        bucket_spend(&v->rx_bucket, n);
    }
}

void cloak_valve_add_tx(cloak_valve_t *v, int64_t n) {
    if (v == NULL) {
        return;
    }
    v->tx += n;
    if (v->tx_bucket.rate != 0) {
        bucket_spend(&v->tx_bucket, n);
    }
}

int64_t cloak_valve_rx(const cloak_valve_t *v) {
    return v == NULL ? 0 : v->rx;
}

int64_t cloak_valve_tx(const cloak_valve_t *v) {
    return v == NULL ? 0 : v->tx;
}

void cloak_valve_nullify(cloak_valve_t *v, int64_t *out_rx, int64_t *out_tx) {
    int64_t rx = 0, tx = 0;
    if (v != NULL) {
        /* Read and reset with nothing in between -- see this function's
         * doc comment: any byte counted between a separate read and a
         * separate reset would be zeroed away unbilled. */
        rx = v->rx;
        tx = v->tx;
        v->rx = 0;
        v->tx = 0;
    }
    if (out_rx != NULL) {
        *out_rx = rx;
    }
    if (out_tx != NULL) {
        *out_tx = tx;
    }
    /* The buckets are deliberately NOT reset here. A drain is an
     * ACCOUNTING boundary (how much has this user moved since the last
     * upload) and has nothing to do with pacing; refilling the buckets
     * every drain interval would hand out a free burst on every tick. */
}

/* ------------------------------------------------------------------ */
/* Rate limiting                                                       */
/* ------------------------------------------------------------------ */

void cloak_valve_set_clock(cloak_valve_t *v, cloak_valve_clock_fn fn, void *userdata) {
    if (v == NULL) {
        return;
    }
    v->clock_fn = fn;
    v->clock_userdata = userdata;
    /* Re-stamp against the NEW clock, so no time is considered to have
     * elapsed across the swap -- the old clock's reading is meaningless
     * on the new one's scale, and the difference between the two could
     * otherwise credit or destroy an arbitrary number of tokens. It is
     * also what makes this callable either side of cloak_valve_set_rates. */
    uint64_t now = valve_now_ms(v);
    v->rx_bucket.last_refill = now;
    v->tx_bucket.last_refill = now;
}

static void bucket_set_rate(cloak_valve_bucket_t *b, int64_t rate, uint64_t now) {
    if (rate < 0) {
        rate = 0; /* malformed input means unlimited, never "blocked" */
    }
    if (rate > CLOAK_VALVE_MAX_RATE) {
        rate = CLOAK_VALVE_MAX_RATE;
    }
    b->rate = rate;
    b->capacity = rate * VALVE_MILLI; /* one second's worth -- Go's NewBucketWithRate(rate, rate) */
    b->tokens = b->capacity;          /* Go's bucket starts full; so does this one */
    b->last_refill = now;
}

void cloak_valve_set_rates(cloak_valve_t *v, int64_t rx_rate, int64_t tx_rate) {
    if (v == NULL) {
        return;
    }
    /* rx is client -> server, tx is server -> client. The caller has
     * already done the up/down -> rx/tx conversion, and there is exactly
     * one caller allowed to do it -- see cloak/valve.h. */
    uint64_t now = valve_now_ms(v);
    bucket_set_rate(&v->rx_bucket, rx_rate, now);
    bucket_set_rate(&v->tx_bucket, tx_rate, now);
}

/* The rate == 0 short circuits below come FIRST, before any clock read:
 * an unlimited direction must cost exactly what a NULL valve costs, and
 * "no arithmetic" includes not asking what time it is. */

int64_t cloak_valve_take_rx(cloak_valve_t *v, int64_t want) {
    if (v == NULL || v->rx_bucket.rate == 0 || want <= 0) {
        return want;
    }
    return bucket_take(&v->rx_bucket, valve_now_ms(v), want);
}

int64_t cloak_valve_take_tx(cloak_valve_t *v, int64_t want) {
    if (v == NULL || v->tx_bucket.rate == 0 || want <= 0) {
        return want;
    }
    return bucket_take(&v->tx_bucket, valve_now_ms(v), want);
}

uint64_t cloak_valve_rx_resume_delay_ms(cloak_valve_t *v) {
    if (v == NULL || v->rx_bucket.rate == 0) {
        return 0;
    }
    return bucket_delay_ms(&v->rx_bucket, valve_now_ms(v));
}

uint64_t cloak_valve_tx_resume_delay_ms(cloak_valve_t *v) {
    if (v == NULL || v->tx_bucket.rate == 0) {
        return 0;
    }
    return bucket_delay_ms(&v->tx_bucket, valve_now_ms(v));
}
