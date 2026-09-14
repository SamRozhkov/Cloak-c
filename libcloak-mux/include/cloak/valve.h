#ifndef CLOAK_VALVE_H
#define CLOAK_VALVE_H

#include <stdint.h>

/* Meters one USER's traffic across every session that user holds.
 *
 * Go's internal/multiplex/qos.go. The object is shared BY REFERENCE
 * between sessions, which is exactly why it lives here as its own type
 * rather than as a field of cloak_session_t: one user may hold many
 * concurrent sessions, and their bytes all have to land in one place for
 * the panel to bill them against one credit balance.
 *
 * DIRECTION -- the single thing in this file that is dangerous to get
 * wrong, because getting it wrong is silent:
 *
 *   rx is client -> server. tx is server -> client. Both are from the
 *   SERVER's perspective, and this file never uses the words "up" or
 *   "down" for that reason -- Go's qos.go carries the same warning
 *   ("DO NOT use terms up or down as this is used in usermanager for
 *   bandwidth limiting"), and this port inherits it.
 *
 *   cloak/usermanager.h's up_credit/up_rate/up_usage (and their down_
 *   counterparts) are from the USER's perspective instead. A user's
 *   UPLOAD is the server's RX; a user's DOWNLOAD is the server's TX.
 *
 *   THIS MODULE DOES NOT CONVERT BETWEEN THE TWO VOCABULARIES. It only
 *   counts and limits rx and tx. The conversion happens in exactly TWO
 *   places, both of them in libcloak-server/src/userpanel.c and nowhere
 *   else:
 *
 *     1. the panel's periodic drain, where a cloak_valve_nullify result
 *        is turned into a cloak_user_status_t (rx -> up_usage,
 *        tx -> down_usage);
 *     2. cloak_userpanel_get_user, where the authenticated user's
 *        up_rate/down_rate are installed with cloak_valve_set_rates
 *        (up_rate -> rx rate, down_rate -> tx rate).
 *
 *   Those two are the same conversion in the same direction, made at the
 *   only two moments a user's per-direction numbers cross this boundary
 *   -- one reading out, one writing in. Anyone adding a THIRD has
 *   introduced the defect this comment exists to prevent: the wrong
 *   direction metered against the wrong limit, with no error raised
 *   anywhere, and every test that drives traffic symmetrically passing
 *   either way.
 *
 * WIRE BYTES, NOT PAYLOAD BYTES. The counters accumulate the bytes that
 * actually cross the socket: a stream's payload plus the frame header,
 * the AEAD tag, the obfuscator's random padding, and the connection's
 * own length prefix. A user therefore pays for the framing overhead they
 * cause, and their metered usage is legitimately larger than the number
 * of bytes their application transferred -- which is the same quantity
 * Go counts (switchboard.go counts conn.Write's and conn.Read's byte
 * counts, not stream payloads), and it is the first thing an operator
 * asks about, so it is stated here rather than left to be rediscovered.
 *
 * LIFETIME AND OWNERSHIP. A valve is owned by the panel (the per-user
 * bookkeeping layer), never by a session. A session holds a borrowed
 * pointer for as long as it lives and must NEVER free it; the panel must
 * outlive every session it handed the valve to. There is deliberately no
 * cloak_valve_create/destroy pair: the struct is a plain value the owner
 * embeds or allocates however it likes, zero-initialised (a zeroed
 * cloak_valve_t is a valid, empty valve -- no constructor call needed).
 *
 * A NULL cloak_valve_t * MEANS "NOT METERED AND NOT LIMITED". Every
 * function here tolerates NULL: adds are dropped, reads report 0, and a
 * take is granted in full. That is this port's replacement for Go's
 * UnlimitedValve, at no allocation and with a branch the compiler
 * predicts perfectly. It is what lets a bypass user -- and any session
 * whose config never set a valve -- run through the exact same code path
 * with no metering, no throttling and no special case.
 *
 * A RATE OF 0 MEANS "UNLIMITED" and takes the same path as a NULL valve:
 * no clock read, no arithmetic, no pause, no timer. A valve may
 * therefore be metered but unthrottled in one direction, throttled in
 * the other, or neither -- the three combinations the user database's
 * up_rate/down_rate columns actually produce.
 *
 * THREADING. Plain non-atomic arithmetic, unlike Go's atomics: this port
 * runs every session on one single-threaded reactor (see cloak/reactor.h),
 * so the goroutine races qos.go's sync/atomic guards against do not
 * exist here. Sharing one valve between sessions on DIFFERENT threads
 * would be a data race; do not.
 *
 * EXTENSIBILITY. Nothing may depend on this struct's size or field
 * order. */

/* Monotonic milliseconds since an arbitrary fixed origin.
 *
 * WHY A CLOCK OF THIS MODULE'S OWN, rather than cloak_now_fn (the
 * server's usermanager/userpanel injection point): three reasons, all
 * binding.
 *
 *  - cloak_now_fn lives in libcloak-server/include/cloak/usermanager.h,
 *    and libcloak-mux does not and must not depend on libcloak-server.
 *
 *  - cloak_now_fn returns WHOLE SECONDS (it defaults to time(NULL)),
 *    which cannot express either a token-bucket refill or a resume delay
 *    -- both of which are ordinarily a handful of milliseconds.
 *
 *  - cloak_now_fn is WALL CLOCK. Every pause this file's arithmetic
 *    causes is resumed by a cloak_reactor_add_timer, whose deadline is
 *    CLOCK_MONOTONIC. Mixing the two time bases would mean an NTP step
 *    could desynchronise the pause from its own resume -- the exact
 *    stall this module is built to be incapable of.
 *
 * So: same INJECTION CONVENTION as cloak_now_fn (a function pointer plus
 * an opaque userdata, NULL meaning "use the real one"), different unit
 * and different base -- the reactor's unit and the reactor's base.
 *
 * NULL is the default a zeroed cloak_valve_t already has, and means
 * CLOCK_MONOTONIC in milliseconds. */
typedef uint64_t (*cloak_valve_clock_fn)(void *userdata);

/* Largest rate this module will hold, in bytes/sec. Anything larger is
 * clamped to it on the way in -- 2^40 B/s is ~1.1 TB/s, far past any
 * link this will ever run on, and the clamp is what keeps every product
 * in the refill arithmetic provably inside int64_t rather than resting
 * on an assumption about what an operator types into a database. */
#define CLOAK_VALVE_MAX_RATE ((int64_t)1 << 40)

/* One direction's token bucket. Go's ratelimit.Bucket, minus the part
 * that cannot exist here: Bucket.Wait BLOCKS A GOROUTINE, and this
 * reactor is single-threaded with nothing to block. So this bucket is
 * something the data path CONSULTS -- it asks how many bytes it may move
 * right now, moves at most that many, and when the answer is zero it
 * pauses its own read interest and arms a timer for when the next whole
 * byte is due. Nothing here ever sleeps.
 *
 * UNITS. tokens are held in MILLI-BYTES (1/1000 of a byte) and time in
 * milliseconds, so one millisecond of accrual is exactly `rate`
 * milli-bytes: an exact integer, with no truncated remainder to lose.
 * Holding whole bytes instead would round every sub-millisecond refill
 * down to zero and a slow rate (say 100 B/s, refilled every 5 ms) would
 * deliver nothing at all, forever.
 *
 * CAPACITY == ONE SECOND of the rate, matching Go's
 * ratelimit.NewBucketWithRate(float64(rate), rate) -- same burst
 * allowance as the original, so a link idle for a while may then send a
 * second's worth at once. The bucket starts FULL, as Go's does.
 *
 * DEBT. tokens may go negative, because the deduction point
 * (cloak_valve_add_rx/_tx) also bills traffic no one asked permission
 * for -- a stream's closing frame, the per-frame framing overhead that
 * a granted payload turns into. Debt is floored at one second's worth,
 * which bounds the longest pause this module can ever produce to about
 * two seconds (one second to climb out of debt, and the byte it then
 * needs). The floor does forgive bytes beyond that, which is why it is a
 * floor and not the normal case: on the relay path it is unreachable,
 * since every producer takes before it moves and the only unasked-for
 * charge is per-frame overhead, orders of magnitude below one second of
 * any rate an operator would configure. */
typedef struct {
    int64_t rate;         /* bytes/sec; 0 == unlimited, and nothing below is touched */
    int64_t capacity;     /* milli-bytes; rate * 1000, i.e. one second's worth */
    int64_t tokens;       /* milli-bytes; [-capacity, capacity] */
    uint64_t last_refill; /* ms, on the clock below */
} cloak_valve_bucket_t;

typedef struct {
    int64_t rx; /* client -> server, wire bytes */
    int64_t tx; /* server -> client, wire bytes */

    cloak_valve_bucket_t rx_bucket;
    cloak_valve_bucket_t tx_bucket;

    cloak_valve_clock_fn clock_fn; /* NULL == CLOCK_MONOTONIC */
    void *clock_userdata;
} cloak_valve_t;

/* Add n wire bytes to the corresponding counter AND spend n bytes' worth
 * of that direction's tokens. v == NULL is a no-op (an unmetered
 * session), and so is a direction whose rate is 0 as far as the bucket
 * is concerned -- the counter still moves. n is expected to be a byte
 * count from a completed transfer and therefore >= 0; these functions do
 * not validate it, because there is no call site that can produce a
 * negative one and a check here would only hide a caller bug from the
 * sanitizers.
 *
 * THE METER IS THE BUCKET'S DRAIN, and that is deliberate. The obvious
 * alternative -- have cloak_valve_take_* consume what it grants -- burns
 * tokens the caller turned out not to be able to use: a relay granted
 * 4096 bytes that reads 200 and then EAGAINs would have paid for 4096,
 * so a trickle of small packets would be throttled far below its
 * configured rate by the grants it did not use. Charging at the moment
 * bytes are known to have crossed the socket costs nothing extra (this
 * call already existed, at exactly that moment) and makes the quantity
 * LIMITED identical to the quantity BILLED -- both are wire bytes. The
 * obligation it creates is one line long, and every caller of
 * cloak_valve_take_* in this tree honours it: whatever you actually
 * moved, add_ it. */
void cloak_valve_add_rx(cloak_valve_t *v, int64_t n);
void cloak_valve_add_tx(cloak_valve_t *v, int64_t n);

/* Bytes accumulated since the last cloak_valve_nullify. NULL reports 0. */
int64_t cloak_valve_rx(const cloak_valve_t *v);
int64_t cloak_valve_tx(const cloak_valve_t *v);

/* Reads both counters and zeroes them in one step -- Go's Nullify. The
 * caller receives exactly the bytes moved since the previous drain.
 *
 * This is one call rather than a read followed by a reset precisely so
 * that nothing can be counted between the two: bytes that arrive after
 * the read but before the reset would otherwise be zeroed away and the
 * user would have moved them for free. Either output pointer may be NULL
 * to discard that direction -- the counter is still reset.
 *
 * v == NULL writes 0 to both outputs. */
void cloak_valve_nullify(cloak_valve_t *v, int64_t *out_rx, int64_t *out_tx);

/* ------------------------------------------------------------------ */
/* Rate limiting                                                       */
/* ------------------------------------------------------------------ */

/* Installs the clock both buckets read, and re-stamps their last-refill
 * marks against it so no time is considered to have elapsed across the
 * swap. NULL fn restores CLOCK_MONOTONIC.
 *
 * Because it re-stamps, this may be called before OR after
 * cloak_valve_set_rates -- there is no ordering requirement to get
 * wrong, which is the only reason it re-stamps rather than just storing
 * the pointer. v == NULL is a no-op. */
void cloak_valve_set_clock(cloak_valve_t *v, cloak_valve_clock_fn fn, void *userdata);

/* Sets both directions' rates in bytes/sec and refills both buckets to
 * full, as of now.
 *
 * rx_rate is client -> server, tx_rate is server -> client -- the
 * SERVER's vocabulary, NOT the user's up/down. See this file's DIRECTION
 * paragraph: the single place a user's up_rate/down_rate becomes an
 * rx/tx rate is cloak_userpanel_get_user, and a second such site is a
 * defect.
 *
 * 0 means unlimited, and is the value a zeroed valve already holds.
 * Negative is malformed input (the schema documents 0 for unthrottled)
 * and is treated as unlimited rather than as a total block -- the same
 * choice cloak_usermanager_upload_status makes for a malformed usage,
 * and the one that cannot lock a user out of a server because of a bad
 * row. Anything above CLOAK_VALVE_MAX_RATE is clamped to it.
 *
 * v == NULL is a no-op. */
void cloak_valve_set_rates(cloak_valve_t *v, int64_t rx_rate, int64_t tx_rate);

/* "I would like to move up to `want` bytes in this direction right now.
 * How many may I?" Returns 0..want.
 *
 * ADVISORY, NOT CONSUMING: two calls with nothing moved in between
 * return the same answer. What consumes tokens is cloak_valve_add_rx/
 * _tx, at the moment the bytes are known to have crossed the socket --
 * see those functions for why the split is this way round. A caller that
 * takes and then moves fewer bytes than it was granted owes nothing for
 * the difference, and a caller that never moves any owes nothing at all.
 *
 * v == NULL, a rate of 0, or want <= 0 return `want` unchanged with no
 * clock read and no arithmetic whatsoever.
 *
 * A RETURN OF 0 IS AN OBLIGATION, not merely information. The caller
 * must stop reading in that direction AND arm a timer for
 * cloak_valve_*_resume_delay_ms from now before it returns, because
 * nothing else in the system will ever wake it: unlike the pause
 * cloak_stream_relay_t takes when the session's outbound pool is full
 * (which the pool's own drain callback resumes), a pause taken because a
 * bucket is empty has no event behind it at all. Only time passes. A
 * paused direction with no timer is a hung session that looks exactly
 * like a working one. */
int64_t cloak_valve_take_rx(cloak_valve_t *v, int64_t want);
int64_t cloak_valve_take_tx(cloak_valve_t *v, int64_t want);

/* How long to wait before at least one whole byte is available in that
 * direction -- what to pass to cloak_reactor_add_timer after a take
 * returned 0.
 *
 * A RETURN OF 0 MEANS "THIS DIRECTION IS NOT RATE-LIMITED", and nothing
 * else: a NULL valve, or a rate of 0. For a rate-limited direction the
 * answer is ALWAYS >= 1 -- including when the bucket already holds a
 * byte, which is reported as 1 rather than 0. So a caller may both arm
 * the result verbatim, with no risk of a zero-delay timer that spins,
 * and test it against 0 to ask "is this direction limited at all".
 *
 * THE >= 1 FLOOR EXISTS BECAUSE ITS ABSENCE WAS A PERMANENT STALL, and
 * the shape of it is worth a paragraph because any future pause site
 * will meet it. This function and cloak_valve_take_rx/_tx read the clock
 * INDEPENDENTLY. A bucket a fraction of a byte short when the take
 * refused can hold a whole byte a few microseconds later, so an earlier
 * version of this function answered 0 -- truthfully, for the instant it
 * was asked. Every caller read that 0 back as "the valve is not the
 * binding constraint" and armed no timer at all, leaving a relay paused
 * with a full bucket, an empty queue and no event anywhere in the system
 * that could wake it. At 200 kB/s the window is about five microseconds
 * wide and it was reached roughly once in two hundred ASan runs.
 *
 * DO NOT re-derive "the bucket must still be empty, we were just
 * refused" and re-introduce the 0. It is not true, it cannot be made
 * true, and the cost of the floor is one wake-up a millisecond early.
 *
 * Bounded above by the bucket's own debt floor at 1000 + ceil(1000/rate)
 * ms -- i.e. never more than two seconds, and about one second for any
 * rate worth configuring. See cloak_valve_bucket_t. */
uint64_t cloak_valve_rx_resume_delay_ms(cloak_valve_t *v);
uint64_t cloak_valve_tx_resume_delay_ms(cloak_valve_t *v);

#endif
