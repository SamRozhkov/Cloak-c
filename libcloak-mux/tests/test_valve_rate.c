#define _POSIX_C_SOURCE 200809L
#include "cloak/valve.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "cloak/common.h"
#include "cloak/conn.h"
#include "cloak/session.h"
#include "cloak/stream_relay.h"
#include "cloak/switchboard.h"
#include "test_framework.h"

/* ------------------------------------------------------------------ */
/* Injected time                                                       */
/* ------------------------------------------------------------------ */

/* The valve's clock is injectable (cloak_valve_clock_fn), so every
 * statement this file makes about the token ARITHMETIC is exact and
 * costs no wall-clock time at all.
 *
 * The reactor's timer heap is NOT injectable -- cloak_reactor_add_timer
 * deadlines are CLOCK_MONOTONIC and there is no seam to replace them
 * with. So the three tests that drive a real conn/relay through real
 * pause-and-resume cycles necessarily run against real time. They are
 * written so that a broken implementation FAILS rather than hangs: every
 * wait is a bounded loop with an explicit iteration cap, never a
 * "pump until it happens". */
static uint64_t fake_ms;
static int fake_clock_calls;

static uint64_t fake_clock(void *userdata) {
    (void)userdata;
    fake_clock_calls++;
    return fake_ms;
}

static uint64_t real_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ------------------------------------------------------------------ */
/* 1. Token arithmetic                                                 */
/* ------------------------------------------------------------------ */

static void test_token_arithmetic(void) {
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    fake_ms = 1000000; /* not 0: a bucket keying off "last_refill == 0" as
                        * "uninitialised" would be indistinguishable from a
                        * correct one if the clock started at 0 */
    cloak_valve_set_clock(&v, fake_clock, NULL);
    /* Deliberately unequal, and not multiples of one another: every
     * assertion below would move if rx and tx were transposed inside the
     * valve. */
    cloak_valve_set_rates(&v, 1000, 4000);

    /* The bucket starts FULL, and capacity is exactly one second of the
     * rate -- so a caller asking for far more than a second's worth is
     * given exactly one second's worth. Literal 1000/4000, not
     * "capacity", so a changed capacity formula fails here. */
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 100000), 1000);
    ASSERT_EQ_INT(cloak_valve_take_tx(&v, 100000), 4000);

    /* take is ADVISORY: nothing was moved, so nothing was spent. */
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 100000), 1000);

    /* A request SMALLER than the available tokens is granted in full. */
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 250), 250);

    /* Spending is what consumes, and a request LARGER than what is left
     * is partially granted. */
    cloak_valve_add_rx(&v, 900);
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 500), 100);
    /* ...and the other direction is untouched by rx spending. */
    ASSERT_EQ_INT(cloak_valve_take_tx(&v, 100000), 4000);

    /* REFILL over elapsed time: 50 ms at 1000 B/s is 50 bytes, on top of
     * the 100 still there. */
    fake_ms += 50;
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 500), 150);
    /* ...and tx refilled at ITS rate over the same 50 ms, but was
     * already full, so the cap holds it at 4000. */
    ASSERT_EQ_INT(cloak_valve_take_tx(&v, 100000), 4000);

    /* THE CAP. Ten seconds of idling does not accumulate ten seconds of
     * tokens. */
    fake_ms += 10000;
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 100000), 1000);

    /* Time going BACKWARDS (a clock swap, a test that rewinds) must not
     * manufacture or destroy tokens. The rewind is deliberately NOT
     * undone: the bucket re-stamps itself to the rewound reading, so
     * what follows runs from a bucket whose last refill is exactly
     * `now`, which is what makes the delay literals below exact. */
    fake_ms -= 5;
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 100000), 1000);

    /* DEBT AND ITS FLOOR. Spending 5000 against a 1000-byte bucket puts
     * it 4000 bytes under; the floor clamps that to one second's worth,
     * i.e. -1000 bytes. The resume delay is then the time to climb back
     * to one whole byte: (1000 + 1) bytes at 1000 B/s = 1001 ms.
     *
     * Without the floor the same spend would read -4000 bytes and the
     * delay would be 4001 ms, so this literal is what pins the floor. */
    cloak_valve_add_rx(&v, 5000);
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 500), 0);
    ASSERT_EQ_INT((long long)cloak_valve_rx_resume_delay_ms(&v), 1001);
    /* Half the climb: still nothing, and the delay has shrunk by exactly
     * the time that passed. */
    fake_ms += 500;
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 500), 0);
    ASSERT_EQ_INT((long long)cloak_valve_rx_resume_delay_ms(&v), 501);
    /* One millisecond short of the whole byte, then over it. */
    fake_ms += 500;
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 500), 0);
    ASSERT_EQ_INT((long long)cloak_valve_rx_resume_delay_ms(&v), 1);
    fake_ms += 1;
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 500), 1);
    /* THE CONTRACT, and it is the opposite of what this line used to
     * assert. A rate-limited direction NEVER reports 0, not even with a
     * byte in hand: 0 is reserved for "this direction is not limited at
     * all". The old 0 here was the header's false promise, and a caller
     * arming on it armed nothing -- see cloak/valve.h and the stall it
     * describes. Removing the floor in bucket_delay_ms turns this 1 back
     * into a 0 and fails here, at the producer, without needing the
     * relay. */
    ASSERT_EQ_INT((long long)cloak_valve_rx_resume_delay_ms(&v), 1);
    /* ...while a direction with no rate at all still reports 0, so the
     * two meanings stay distinguishable. v's tx rate is 4000, so this
     * uses a separate unlimited direction rather than v's own. */
    cloak_valve_t unlimited_dir;
    memset(&unlimited_dir, 0, sizeof(unlimited_dir));
    cloak_valve_set_clock(&unlimited_dir, fake_clock, NULL);
    cloak_valve_set_rates(&unlimited_dir, 0, 5000);
    ASSERT_EQ_INT((long long)cloak_valve_rx_resume_delay_ms(&unlimited_dir), 0);
    ASSERT_EQ_INT((long long)cloak_valve_tx_resume_delay_ms(&unlimited_dir), 1);

    /* SUB-MILLIBYTE PRECISION. A rate of 100 B/s gains a tenth of a byte
     * per millisecond. Stepping 5 ms at a time, the whole bytes available
     * must be 0, 1, 1, 2, 2 -- an implementation that recomputed whole
     * bytes per refill call (rate * elapsed_ms / 1000, truncated, the
     * remainder discarded) reports 0 every single time and never moves a
     * byte at this rate for as long as it runs. */
    cloak_valve_t slow;
    memset(&slow, 0, sizeof(slow));
    cloak_valve_set_clock(&slow, fake_clock, NULL);
    cloak_valve_set_rates(&slow, 100, 0);
    cloak_valve_add_rx(&slow, 100); /* drain the initial full second */
    ASSERT_EQ_INT(cloak_valve_take_rx(&slow, 1000), 0);
    static const int64_t expected_steps[5] = {0, 1, 1, 2, 2};
    for (int i = 0; i < 5; i++) {
        fake_ms += 5;
        ASSERT_EQ_INT(cloak_valve_take_rx(&slow, 1000), expected_steps[i]);
    }

    /* THE RESUME DELAY ROUNDS UP. At 700 B/s, a bucket driven to its
     * debt floor needs 1000 + 700000 milli-bytes, which is 1001.43 ms of
     * accrual. Rounding down would schedule the wake-up at 1001 ms, at
     * which point the bucket is still a fraction of a byte short and the
     * caller has to pause all over again -- a wasted wake-up on every
     * single resume whose delay is not a whole number of milliseconds,
     * which for an arbitrary operator-chosen rate is almost all of them.
     * Ceiling gives 1002, flooring gives 1001, and the two assertions
     * after it show which one is right. */
    cloak_valve_t odd;
    memset(&odd, 0, sizeof(odd));
    cloak_valve_set_clock(&odd, fake_clock, NULL);
    cloak_valve_set_rates(&odd, 700, 0);
    cloak_valve_add_rx(&odd, 1000000); /* well past the debt floor */
    ASSERT_EQ_INT((long long)cloak_valve_rx_resume_delay_ms(&odd), 1002);
    fake_ms += 1001;
    ASSERT_EQ_INT(cloak_valve_take_rx(&odd, 4096), 0); /* one millisecond short */
    fake_ms += 1;
    ASSERT_EQ_INT(cloak_valve_take_rx(&odd, 4096), 1);

    /* A rate above the clamp behaves like the clamp, not like an
     * overflowed negative. */
    cloak_valve_t huge;
    memset(&huge, 0, sizeof(huge));
    cloak_valve_set_clock(&huge, fake_clock, NULL);
    cloak_valve_set_rates(&huge, INT64_MAX, INT64_MAX);
    ASSERT_EQ_INT(cloak_valve_take_rx(&huge, 1 << 20), 1 << 20);
    /* 1, not 0: clamped is still LIMITED, however large the rate. */
    ASSERT_EQ_INT((long long)cloak_valve_rx_resume_delay_ms(&huge), 1);

    /* A NEGATIVE rate is malformed input and means unlimited, not
     * "blocked forever". */
    cloak_valve_t bad;
    memset(&bad, 0, sizeof(bad));
    cloak_valve_set_clock(&bad, fake_clock, NULL);
    cloak_valve_set_rates(&bad, -1, -5000);
    ASSERT_EQ_INT(cloak_valve_take_rx(&bad, 1 << 20), 1 << 20);
    ASSERT_EQ_INT(cloak_valve_take_tx(&bad, 1 << 20), 1 << 20);
}

/* ------------------------------------------------------------------ */
/* 2. rate == 0 is unlimited and costs nothing                         */
/* ------------------------------------------------------------------ */

static void test_zero_rate_is_unlimited(void) {
    /* A NULL valve, cloak/valve.h's unmetered default. */
    ASSERT_EQ_INT(cloak_valve_take_rx(NULL, 999), 999);
    ASSERT_EQ_INT(cloak_valve_take_tx(NULL, 999), 999);
    ASSERT_EQ_INT((long long)cloak_valve_rx_resume_delay_ms(NULL), 0);
    ASSERT_EQ_INT((long long)cloak_valve_tx_resume_delay_ms(NULL), 0);
    cloak_valve_set_rates(NULL, 10, 10); /* must not crash */
    cloak_valve_set_clock(NULL, fake_clock, NULL);

    /* A zeroed valve: rate 0 in both directions without anyone calling
     * set_rates at all. */
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    cloak_valve_set_clock(&v, fake_clock, NULL);

    /* The operative meaning of "the same code path as a NULL valve, no
     * timer, no pause, no arithmetic": the clock is never consulted. A
     * bucket that refilled first and only then noticed rate == 0 reads
     * it, and fails here. Nothing else in this file can catch that. */
    fake_clock_calls = 0;
    for (int i = 0; i < 32; i++) {
        ASSERT_EQ_INT(cloak_valve_take_rx(&v, 1 << 20), 1 << 20);
        ASSERT_EQ_INT(cloak_valve_take_tx(&v, 1 << 20), 1 << 20);
        cloak_valve_add_rx(&v, 4096);
        cloak_valve_add_tx(&v, 4096);
        ASSERT_EQ_INT((long long)cloak_valve_rx_resume_delay_ms(&v), 0);
        ASSERT_EQ_INT((long long)cloak_valve_tx_resume_delay_ms(&v), 0);
    }
    ASSERT_EQ_INT(fake_clock_calls, 0);

    /* Metering is unaffected by being unthrottled: 32 * 4096. */
    ASSERT_EQ_INT(cloak_valve_rx(&v), 131072);
    ASSERT_EQ_INT(cloak_valve_tx(&v), 131072);

    /* And an EXPLICIT set_rates(0, 0) is the same thing -- not merely
     * the zeroed struct getting lucky. */
    cloak_valve_set_rates(&v, 0, 0);
    fake_clock_calls = 0;
    ASSERT_EQ_INT(cloak_valve_take_rx(&v, 1 << 20), 1 << 20);
    ASSERT_EQ_INT(cloak_valve_take_tx(&v, 1 << 20), 1 << 20);
    ASSERT_EQ_INT(fake_clock_calls, 0);

    /* One direction unlimited while the other is throttled: the
     * unlimited half still consults no clock and still grants in full,
     * even once the throttled half is empty. */
    cloak_valve_t mixed;
    memset(&mixed, 0, sizeof(mixed));
    cloak_valve_set_clock(&mixed, fake_clock, NULL);
    cloak_valve_set_rates(&mixed, 500, 0);
    cloak_valve_add_rx(&mixed, 500); /* empty the rx bucket */
    ASSERT_EQ_INT(cloak_valve_take_rx(&mixed, 4096), 0);
    ASSERT_TRUE(cloak_valve_rx_resume_delay_ms(&mixed) > 0);
    ASSERT_EQ_INT(cloak_valve_take_tx(&mixed, 1 << 20), 1 << 20);
    ASSERT_EQ_INT((long long)cloak_valve_tx_resume_delay_ms(&mixed), 0);
}

/* ------------------------------------------------------------------ */
/* 3a. Exactly one second's worth of bytes in one simulated second     */
/* ------------------------------------------------------------------ */

/* The data path's own loop, in miniature and on injected time: a
 * producer that always wants more than it can have, asking and moving
 * until it is refused, once per simulated millisecond.
 *
 * This is an EXACT assertion, not a tolerance: over exactly 1000
 * simulated milliseconds a bucket at R bytes/sec must hand out exactly R
 * bytes, because every millisecond credits exactly R milli-bytes and
 * every grant is spent to the milli-byte. Anything that rounds, drops a
 * remainder, or double-credits moves this number. */
static void test_exact_rate_over_a_simulated_second(void) {
    static const int64_t RATE = 12345;
    static const int64_t CHUNK = 4096;

    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    fake_ms = 500000;
    cloak_valve_set_clock(&v, fake_clock, NULL);
    cloak_valve_set_rates(&v, RATE, 0);

    /* Drain the initial full bucket first, so what follows measures the
     * RATE and not the one-second burst allowance sitting on top of it.
     * The burst is itself exactly one second's worth. */
    int64_t burst = 0;
    int guard = 0;
    for (;;) {
        int64_t granted = cloak_valve_take_rx(&v, CHUNK);
        if (granted == 0) {
            break;
        }
        cloak_valve_add_rx(&v, granted);
        burst += granted;
        if (++guard > 64) {
            ASSERT_TRUE(0 && "burst drain did not terminate");
            return;
        }
    }
    ASSERT_EQ_INT(burst, RATE);

    int64_t moved = 0;
    for (int ms = 0; ms < 1000; ms++) {
        fake_ms += 1;
        guard = 0;
        for (;;) {
            int64_t granted = cloak_valve_take_rx(&v, CHUNK);
            if (granted == 0) {
                break;
            }
            cloak_valve_add_rx(&v, granted);
            moved += granted;
            if (++guard > 64) {
                ASSERT_TRUE(0 && "per-millisecond grant loop did not terminate");
                return;
            }
        }
    }
    ASSERT_EQ_INT(moved, RATE);

    /* Every byte granted was also billed, to the byte: burst + moved. */
    ASSERT_EQ_INT(cloak_valve_rx(&v), RATE * 2);
}

/* ------------------------------------------------------------------ */
/* A metered cloak_conn_t over a socketpair -- the RX (client->server)  */
/* read path                                                           */
/* ------------------------------------------------------------------ */

/* A stream of all-zero bytes is a valid stream of zero-length frames on
 * this wire format: a big-endian u16 length prefix of 0x0000 followed by
 * nothing. So the test can shovel raw zeros at the connection and every
 * one of them is accepted, counted and dispatched -- no obfuscator, no
 * session, no framing to build. Two wire bytes per envelope, which is
 * what lets test 6 below cross-check the meter against an independently
 * counted quantity. */
struct rx_probe {
    cloak_conn_t conn;
    int64_t envelopes;
    int closed;
};

static void rx_on_envelope(cloak_conn_t *c, const uint8_t *bytes, size_t len, void *userdata) {
    (void)c;
    (void)bytes;
    struct rx_probe *p = userdata;
    ASSERT_EQ_INT((long long)len, 0);
    p->envelopes++;
}

static void rx_on_closed(cloak_conn_t *c, void *userdata) {
    (void)c;
    struct rx_probe *p = userdata;
    p->closed++;
}

/* Writes zeros into `fd` until the kernel refuses more. Returns how many
 * it managed. */
static int64_t stuff_peer(int fd) {
    uint8_t zeros[8192];
    memset(zeros, 0, sizeof(zeros));
    int64_t total = 0;
    for (;;) {
        ssize_t n = write(fd, zeros, sizeof(zeros));
        if (n > 0) {
            total += n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    return total;
}

/* Sets up a reactor, a conn on one end of a socketpair and the test's own
 * non-blocking end on the other. Returns 0 on success. */
static int rx_probe_start(struct rx_probe *p, cloak_reactor_t *r, cloak_valve_t *v, int *out_peer) {
    memset(p, 0, sizeof(*p));
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return -1;
    }
    if (fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) {
        return -1;
    }
    if (cloak_conn_init(&p->conn, fds[0], r, 2048, 65536, rx_on_envelope, p, rx_on_closed, p) != 0) {
        return -1;
    }
    cloak_conn_set_valve(&p->conn, v);
    *out_peer = fds[1];
    return 0;
}

static void rx_probe_stop(struct rx_probe *p, int peer) {
    int fd = p->conn.fd;
    cloak_conn_destroy(&p->conn);
    close(fd);
    close(peer);
}

/* ------------------------------------------------------------------ */
/* 3b. A real connection limited to a real rate, and the unlimited      */
/*     control run that proves the limiter is what did it               */
/* ------------------------------------------------------------------ */

/* Runs a metered connection flat out for WINDOW_MS of real time with its
 * peer socket kept full, and returns the wire bytes it took in. rate == 0
 * is the unlimited control. */
static int64_t measure_rx_bytes(int64_t rate, uint64_t window_ms, uint64_t *out_elapsed_ms) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return -1;
    }
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    cloak_valve_set_rates(&v, rate, 0);

    struct rx_probe p;
    int peer = -1;
    ASSERT_EQ_INT(rx_probe_start(&p, r, &v, &peer), 0);

    /* Burn off the one-second burst allowance the bucket starts with, so
     * the window below measures the sustained rate. 40 turns at a few
     * kilobytes each is far more than a full bucket for the rates used
     * here, and the assertion after the window does not depend on this
     * being exact -- only on the burst being gone. */
    for (int i = 0; i < 40; i++) {
        stuff_peer(peer);
        cloak_reactor_run_once(r, 0);
    }

    int64_t base = cloak_valve_rx(&v);
    uint64_t t0 = real_mono_ms();
    uint64_t now = t0;
    while (now - t0 < window_ms) {
        stuff_peer(peer);
        cloak_reactor_run_once(r, 0); /* 0: never block, so the control run
                                       * is not throttled by the poll and
                                       * the two runs are comparable */
        now = real_mono_ms();
    }
    int64_t moved = cloak_valve_rx(&v) - base;
    *out_elapsed_ms = now - t0;

    ASSERT_EQ_INT(p.closed, 0);
    rx_probe_stop(&p, peer);
    cloak_reactor_destroy(r);
    return moved;
}

static void test_real_connection_holds_its_rate(void) {
    static const int64_t RATE = 200000; /* bytes/sec */
    static const uint64_t WINDOW_MS = 250;

    uint64_t elapsed = 0;
    int64_t moved = measure_rx_bytes(RATE, WINDOW_MS, &elapsed);
    int64_t expected = RATE * (int64_t)elapsed / 1000;

    /* TOLERANCE: +/- 25% of the expected byte count.
     *
     * Why 25% and not less: each refusal arms a reactor timer whose
     * resolution is one millisecond and whose wake-up competes with
     * every other runnable process on the machine, so a resume can land
     * late by a scheduling quantum. At 200 kB/s a millisecond is 200
     * bytes and the window holds ~250 of them, so a handful of late
     * wake-ups is a low single-digit percentage; 25% buys a large
     * multiple of that for a loaded CI box without ever approaching the
     * number the control run produces.
     *
     * Why not more: the assertion below requires the UNLIMITED run over
     * the same window to land above this band, which is what makes the
     * band evidence of the limiter rather than of the socket. */
    int64_t lo = expected - expected / 4;
    int64_t hi = expected + expected / 4;
    if (moved < lo || moved > hi) {
        fprintf(stderr, "rate window: %lld bytes in %llu ms, expected %lld [%lld, %lld]\n",
                (long long)moved, (unsigned long long)elapsed, (long long)expected,
                (long long)lo, (long long)hi);
    }
    ASSERT_TRUE(moved >= lo);
    ASSERT_TRUE(moved <= hi);

    /* THE CONTROL. The same harness, the same window, rate 0. If this
     * did not land far above `hi`, the band above would be satisfied by
     * a build with no limiter in it at all and would be worth nothing. */
    uint64_t unlimited_elapsed = 0;
    int64_t unlimited = measure_rx_bytes(0, WINDOW_MS, &unlimited_elapsed);
    int64_t unlimited_hi = RATE * (int64_t)unlimited_elapsed / 1000;
    unlimited_hi += unlimited_hi / 4;
    if (unlimited <= unlimited_hi) {
        fprintf(stderr, "control: %lld bytes in %llu ms, needed > %lld\n", (long long)unlimited,
                (unsigned long long)unlimited_elapsed, (long long)unlimited_hi);
    }
    ASSERT_TRUE(unlimited > unlimited_hi);
    /* Stated as a ratio too, so the margin is on the record rather than
     * merely implied: an unmetered unix socketpair moves orders of
     * magnitude more than 200 kB/s. */
    ASSERT_TRUE(unlimited > moved * 4);
}

/* ------------------------------------------------------------------ */
/* 4. THE STALL TEST: a paused direction resumes with only time passing */
/* ------------------------------------------------------------------ */

/* This is the test the whole task exists to satisfy. A direction that
 * hits zero tokens has nothing left in the system that could ever wake
 * it -- no peer write, no drained queue, no readiness edge -- so the
 * pause MUST have armed a timer before it returned.
 *
 * Structured to FAIL, not hang, if it did not: the peer socket is
 * stuffed once and then never touched again, and the wait is a bounded
 * loop. With the timer arming removed the loop runs out and the
 * assertion below reports a failure. */
static void test_paused_direction_resumes_on_time_alone(void) {
    /* Chosen against the socketpair buffer this runs on (~192 KiB): one
     * full bucket has to be a small fraction of what the peer can hold,
     * or "it stopped reading" would be ambiguous between running out of
     * tokens and running out of data. */
    static const int64_t RATE = 40000;
    static const uint64_t QUIET_MS = 300;

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    cloak_valve_set_rates(&v, RATE, 0);

    struct rx_probe p;
    int peer = -1;
    ASSERT_EQ_INT(rx_probe_start(&p, r, &v, &peer), 0);

    /* Stuff the peer ONCE. Everything after this point is time passing
     * and nothing else. */
    int64_t available = stuff_peer(peer);
    ASSERT_TRUE(available > 4 * RATE); /* far more than one bucket, so the
                                        * read below genuinely runs out of
                                        * TOKENS and not out of DATA */

    /* Drain the bucket. Non-blocking turns, so almost no real time
     * passes and almost nothing refills. */
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(r, 0);
    }

    int64_t at_pause = cloak_valve_rx(&v);
    /* The precondition, and it is three separate claims, each of which
     * can fail on its own:
     *   - it read at least the bucket it started with (the limiter did
     *     not simply block everything);
     *   - it read little more than that bucket (the limiter DID stop it,
     *     rather than the read draining the whole socket);
     *   - bytes are still waiting, so what follows is about tokens and
     *     not about an empty peer. */
    ASSERT_TRUE(at_pause >= RATE);
    ASSERT_TRUE(at_pause <= RATE * 3 / 2);
    ASSERT_TRUE(at_pause < available);

    /* Bounded by the WALL CLOCK, not by an iteration count:
     * cloak_reactor_run_once returns as soon as anything fires, so a
     * loop bounded only by turns can be over in a millisecond and would
     * make the byte-count assertion below meaningless. The iteration cap
     * is a backstop against a spin, nothing more.
     *
     * Nothing writes to `peer` and nothing touches the connection in
     * here. The only thing that can move another byte is a timer the
     * pause armed for itself. */
    uint64_t quiet_start = real_mono_ms();
    int turns = 0;
    while (real_mono_ms() - quiet_start < QUIET_MS && turns < 1000000) {
        cloak_reactor_run_once(r, 5);
        turns++;
    }
    int64_t after = cloak_valve_rx(&v);
    int64_t resumed = after - at_pause;
    /* 300 ms at 40000 B/s is 12000 bytes. The floor is a third of that,
     * so scheduling noise cannot fail it -- but a single byte, which is
     * all "it moved at all" would require, cannot pass it either. */
    if (resumed < RATE / 10) {
        fprintf(stderr, "STALL: %lld read before the quiet period, %lld resumed in %llu ms\n",
                (long long)at_pause, (long long)resumed,
                (unsigned long long)(real_mono_ms() - quiet_start));
    }
    ASSERT_TRUE(resumed >= RATE / 10);
    /* ...and it did not run away either: the pacing still held during
     * the quiet period. 300 ms at 40000 B/s, with a quarter's headroom. */
    ASSERT_TRUE(resumed <= RATE * (int64_t)QUIET_MS / 1000 * 5 / 4 + RATE / 10);

    ASSERT_EQ_INT(p.closed, 0);

    /* 6. BYTES MOVED UNDER A LIMIT ARE STILL COUNTED BY THE METERING
     * HALF -- cross-checked against a quantity this file counted for
     * itself, never against the implementation's own expression. Every
     * envelope on this wire is exactly two bytes (a 0x0000 length prefix
     * and no payload), so the meter must equal twice the number of
     * envelopes dispatched, give or take the single odd byte that can be
     * sitting half-read in the accumulator. */
    int64_t metered = cloak_valve_rx(&v);
    ASSERT_TRUE(metered >= p.envelopes * 2);
    ASSERT_TRUE(metered <= p.envelopes * 2 + 1);

    rx_probe_stop(&p, peer);
    cloak_reactor_destroy(r);
}

/* ------------------------------------------------------------------ */
/* 5. Limiting one direction does not throttle the other               */
/* ------------------------------------------------------------------ */

/* The arithmetic half of the claim is in test 1 and test 2 (a mixed
 * valve grants tx in full while rx is refusing). This is the WIRING
 * half: a connection whose RX is paused by an empty bucket must still be
 * able to write, which is a property of the interest mask the pause
 * rewrites and is not visible from the valve at all. */
static void test_rx_pause_does_not_block_tx(void) {
    static const int64_t RATE = 20000;

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    cloak_valve_set_rates(&v, RATE, 0); /* rx throttled, tx unlimited */

    struct rx_probe p;
    int peer = -1;
    ASSERT_EQ_INT(rx_probe_start(&p, r, &v, &peer), 0);

    int64_t available = stuff_peer(peer);
    ASSERT_TRUE(available > 4 * RATE);
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(r, 0);
    }
    /* Genuinely throttled before the write is attempted: it read about
     * one bucket and stopped, with plenty still waiting. */
    ASSERT_TRUE(cloak_valve_rx(&v) >= RATE);
    ASSERT_TRUE(cloak_valve_rx(&v) <= RATE * 3 / 2);

    static const uint8_t payload[7] = {1, 2, 3, 4, 5, 6, 7};
    ASSERT_EQ_INT(cloak_conn_send(&p.conn, payload, sizeof(payload)), 0);
    ASSERT_EQ_INT(p.closed, 0);

    /* It really reached the peer, framed, while rx was refusing. */
    uint8_t got[16];
    memset(got, 0, sizeof(got));
    ssize_t n = -1;
    for (int i = 0; i < 50 && n < 0; i++) {
        cloak_reactor_run_once(r, 1);
        n = read(peer, got, sizeof(got));
    }
    ASSERT_EQ_INT((long long)n, (long long)(sizeof(payload) + CLOAK_CONN_LEN_PREFIX_LEN));
    ASSERT_EQ_INT(got[0], 0);
    ASSERT_EQ_INT(got[1], (int)sizeof(payload));
    ASSERT_MEM_EQ(got + CLOAK_CONN_LEN_PREFIX_LEN, payload, sizeof(payload));

    /* rx is still throttled afterwards -- the write did not quietly
     * unpause the read half. */
    ASSERT_TRUE(cloak_valve_rx(&v) < available);

    rx_probe_stop(&p, peer);
    cloak_reactor_destroy(r);
}

/* ------------------------------------------------------------------ */
/* The TX (server->client) half: a rate-limited cloak_stream_relay_t    */
/* ------------------------------------------------------------------ */

/* Two sessions on one reactor over a socketpair, the same shape as
 * test_stream_relay.c's harness. `b` is the metered side: its relay
 * pulls from an upstream socket the test floods and pushes into the
 * stream, which is the server->client (tx) direction of the valve. */
#define EP_MAX_RELAYS 2

struct endpoint {
    cloak_session_t sesh;
    cloak_stream_t *accepted[EP_MAX_RELAYS];
    int accepted_n;
    /* The dispatcher owns the session callbacks and fans them out to the
     * relays it has spliced; with more than one relay on a session, every
     * relay must be notified, because neither callback says which stream
     * it concerns in a way this harness could route on. Notifying a relay
     * that has nothing to do is a no-op. */
    cloak_stream_relay_t *srs[EP_MAX_RELAYS];
    int new_stream_calls;
};

static void ep_on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct endpoint *ep = userdata;
    ep->new_stream_calls++;
    if (ep->accepted_n < EP_MAX_RELAYS) {
        ep->accepted[ep->accepted_n++] = stream;
    }
}

static void ep_on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    (void)stream;
    struct endpoint *ep = userdata;
    for (int i = 0; i < EP_MAX_RELAYS; i++) {
        if (ep->srs[i] != NULL) {
            cloak_stream_relay_notify_stream_data(ep->srs[i]);
        }
    }
}

static void ep_on_writable(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    struct endpoint *ep = userdata;
    for (int i = 0; i < EP_MAX_RELAYS; i++) {
        if (ep->srs[i] != NULL) {
            cloak_stream_relay_notify_writable(ep->srs[i]);
        }
    }
}

static void ep_on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    (void)userdata;
}

static void ep_fill_config(cloak_session_config_t *cfg, struct endpoint *ep,
                           const cloak_obfuscator_t *obfs, cloak_valve_t *valve) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->obfuscator = *obfs;
    cfg->max_on_wire_size = 16401;
    cfg->stream_recv_capacity = 262144;
    cfg->stream_max_pending_frames = 256;
    cfg->conn_send_queue_cap = 262144;
    cfg->inactivity_timeout_ms = 60000;
    cfg->on_new_stream = ep_on_new_stream;
    cfg->on_new_stream_userdata = ep;
    cfg->on_stream_data = ep_on_stream_data;
    cfg->on_stream_data_userdata = ep;
    cfg->on_writable = ep_on_writable;
    cfg->on_writable_userdata = ep;
    cfg->on_broken = ep_on_broken;
    cfg->on_broken_userdata = ep;
    cfg->valve = valve;
}

static void ep_make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

static void relay_on_done(cloak_stream_relay_t *sr, void *userdata) {
    (void)sr;
    int *calls = userdata;
    (*calls)++;
}

/* 3c/4b. The TX direction, end to end: an upstream socket flooded with
 * bytes, a relay that must pace itself while forwarding them, and the
 * same two questions asked of it -- does the limit bind, and does a
 * paced pause resume with nothing but time. */
static void test_relay_tx_is_paced_and_resumes(void) {
    static const int64_t RATE = 200000;
    static const uint64_t WINDOW_MS = 250;
    static const uint64_t QUIET_MS = 300;

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_obfuscator_t obfs;
    ep_make_obfuscator(&obfs);

    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    cloak_valve_set_rates(&v, 0, RATE); /* rx unlimited, tx throttled */

    struct endpoint a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    cloak_session_config_t cfg_a, cfg_b;
    ep_fill_config(&cfg_a, &a, &obfs, NULL);
    ep_fill_config(&cfg_b, &b, &obfs, &v);

    int fds[2];
    ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    ASSERT_EQ_INT(cloak_session_init(&a.sesh, 1, r, &cfg_a), 0);
    ASSERT_EQ_INT(cloak_session_init(&b.sesh, 1, r, &cfg_b), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(&a.sesh, fds[0]), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(&b.sesh, fds[1]), 0);

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }
    ASSERT_EQ_INT((int)cloak_stream_write(s, (const uint8_t *)"go", 2), 2);
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(b.new_stream_calls, 1);
    ASSERT_TRUE(b.accepted[0] != NULL);
    if (b.accepted[0] == NULL) {
        return;
    }

    /* The relay's upstream: `inner` goes to the relay, `outer` is the
     * test playing the upstream server that has a lot to say. */
    int up[2];
    ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, up), 0);
    ASSERT_EQ_INT(fcntl(up[1], F_SETFL, O_NONBLOCK), 0);

    int done_calls = 0;
    cloak_stream_relay_t sr;
    ASSERT_EQ_INT(cloak_stream_relay_start(&sr, r, &b.sesh, b.accepted[0], up[0], 65536, relay_on_done,
                                           &done_calls),
                  0);
    b.srs[0] = &sr;

    /* Drain the burst allowance, keeping the upstream full. `s` -- the
     * stream `a` opened -- is where the relayed bytes surface, and it
     * must be read or its receive buffer fills and the measurement
     * becomes a test of that buffer instead. */
    uint8_t sink[16384];
    for (int i = 0; i < 40; i++) {
        stuff_peer(up[1]);
        cloak_reactor_run_once(r, 0);
        while (cloak_stream_read(s, sink, sizeof(sink)) > 0) {
        }
    }

    int64_t base = cloak_valve_tx(&v);
    uint64_t t0 = real_mono_ms();
    uint64_t now = t0;
    while (now - t0 < WINDOW_MS) {
        stuff_peer(up[1]);
        cloak_reactor_run_once(r, 0);
        while (cloak_stream_read(s, sink, sizeof(sink)) > 0) {
        }
        now = real_mono_ms();
    }
    uint64_t elapsed = now - t0;
    int64_t moved = cloak_valve_tx(&v) - base;
    int64_t expected = RATE * (int64_t)elapsed / 1000;

    /* Same +/-25% band as test 3b, for the same reasons, plus one more
     * that only applies here: the relay's budget is in stream PAYLOAD
     * bytes while the valve counts WIRE bytes, so each frame's header,
     * tag, padding and length prefix are billed on top of what was
     * granted. The pacing therefore settles slightly BELOW the nominal
     * rate in payload terms and exactly AT it in wire terms, which is
     * the quantity asserted here and the quantity the user is billed
     * for. */
    int64_t lo = expected - expected / 4;
    int64_t hi = expected + expected / 4;
    if (moved < lo || moved > hi) {
        fprintf(stderr, "relay tx window: %lld bytes in %llu ms, expected %lld [%lld, %lld]\n",
                (long long)moved, (unsigned long long)elapsed, (long long)expected, (long long)lo,
                (long long)hi);
    }
    ASSERT_TRUE(moved >= lo);
    ASSERT_TRUE(moved <= hi);
    ASSERT_EQ_INT(done_calls, 0); /* the relay is alive, not finished early */

    /* THE RELAY'S OWN STALL TEST. Stop feeding the upstream entirely --
     * it still holds well over a hundred kilobytes the relay has not
     * taken -- and keep draining `s` so the session's pool never becomes
     * the reason it stops. The relay is mid-pause on an empty tx bucket;
     * only a timer it armed for itself can move another byte. Bounded by
     * the wall clock, so a missing timer fails here rather than
     * hanging. */
    int64_t at_pause = cloak_valve_tx(&v);
    uint64_t quiet_start = real_mono_ms();
    int turns = 0;
    while (real_mono_ms() - quiet_start < QUIET_MS && turns < 1000000) {
        cloak_reactor_run_once(r, 5);
        while (cloak_stream_read(s, sink, sizeof(sink)) > 0) {
        }
        turns++;
    }
    int64_t resumed = cloak_valve_tx(&v) - at_pause;
    if (resumed < RATE / 10) {
        fprintf(stderr, "RELAY STALL: %lld resumed in %llu ms over %d turns\n", (long long)resumed,
                (unsigned long long)(real_mono_ms() - quiet_start), turns);
    }
    ASSERT_TRUE(resumed >= RATE / 10);

    cloak_stream_relay_stop(&sr);
    b.srs[0] = NULL;
    cloak_session_release_stream(&b.sesh, b.accepted[0]);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    close(up[1]);
    cloak_reactor_destroy(r);
}

/* ------------------------------------------------------------------ */
/* The two OTHER ways a relay can be left paused with no timer          */
/* ------------------------------------------------------------------ */

/* Neither of the two tests below is reachable with a single relay on an
 * otherwise idle session, which is why the end-to-end test above does
 * not cover them: both were found by deleting the arming and watching
 * the suite stay green.
 *
 * A one-sided harness is enough for both and is far easier to steer than
 * a session pair: `sesh` sends into a socketpair whose other end the
 * TEST holds and reads by hand, so the test decides exactly when the
 * outbound pool is congested and when it drains. Nothing parses what
 * comes out; these tests are about when the relay is allowed to read,
 * not about what it produces. */
struct tx_probe {
    cloak_session_t sesh;
    /* HEAP-ALLOCATED AND FREED BY tx_probe_stop, on purpose. The real
     * owner, cloak_proxy_stream_t, embeds the relay BY VALUE and frees
     * the whole struct immediately after cloak_stream_relay_stop
     * (proxy_stream_teardown). A relay living in a test's stack frame
     * until the reactor is destroyed can never show that a timer
     * outliving its relay is a use-after-free; one that is freed while
     * the reactor keeps running can. */
    cloak_stream_relay_t *sr;
    /* Held so tx_probe_stop can RELEASE it. The relay closes the stream
     * when it stops but never releases it -- cloak/stream_relay.h is
     * explicit that freeing the stream stays the caller's job -- and a
     * closed stream is no longer active, so cloak_session_destroy's own
     * sweep will not collect it either. */
    cloak_stream_t *stream;
    int peer;     /* the test's end of the session's connection */
    int up_outer; /* the test's end of the relay's upstream socket */
    int64_t drained;
    int broken;
    int done_calls;
};

static void tx_probe_on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    (void)stream;
    struct tx_probe *p = userdata;
    if (p->sr != NULL) {
        cloak_stream_relay_notify_stream_data(p->sr);
    }
}

static void tx_probe_on_writable(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    struct tx_probe *p = userdata;
    if (p->sr != NULL) {
        cloak_stream_relay_notify_writable(p->sr);
    }
}

static void tx_probe_on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    struct tx_probe *p = userdata;
    p->broken++;
}

static void tx_probe_on_done(cloak_stream_relay_t *sr, void *userdata) {
    (void)sr;
    struct tx_probe *p = userdata;
    p->done_calls++;
}

/* Reads and discards everything waiting, returning how much. */
static int64_t drain_peer(struct tx_probe *p) {
    uint8_t sink[16384];
    int64_t total = 0;
    for (;;) {
        ssize_t n = read(p->peer, sink, sizeof(sink));
        if (n > 0) {
            total += n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    p->drained += total;
    return total;
}

/* Takes every token the tx bucket currently has and bills `extra_debt`
 * bytes on top -- exactly what ANOTHER consumer on the same valve does
 * when it moves bytes, since a valve meters and paces one USER across
 * every stream and every session they hold.
 *
 * THE DEBT DEPTH IS LOAD-BEARING, and getting it wrong is why an earlier
 * version of the re-arm test pinned nothing. A relay pausing on an empty
 * bucket arms its timer for the time to ONE byte -- a millisecond or
 * two. If the debt is only a millisecond deep, the bucket has refilled
 * by the time that timer runs and the fire finds tokens, so the re-arm
 * branch is never entered at all and deleting it changes nothing. The
 * debt has to outlast the delay the relay computed BEFORE it was
 * applied; tens of milliseconds does that with room to spare.
 *
 * Skipped entirely when the bucket is already in debt, so repeated calls
 * hold it at roughly -extra_debt instead of driving it to the floor --
 * where climbing back out would take a full second and outlast any
 * sensible measurement window. */
static void starve_tx_bucket(cloak_valve_t *v, int64_t extra_debt) {
    int64_t avail = cloak_valve_take_tx(v, (int64_t)1 << 30);
    if (avail > 0) {
        cloak_valve_add_tx(v, avail + extra_debt);
    }
}

static int tx_probe_start(struct tx_probe *p, cloak_reactor_t *r, cloak_valve_t *v,
                          size_t conn_send_queue_cap) {
    memset(p, 0, sizeof(*p));
    p->peer = -1;
    p->up_outer = -1;

    cloak_obfuscator_t obfs;
    ep_make_obfuscator(&obfs);

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = obfs;
    cfg.max_on_wire_size = 16401;
    cfg.stream_recv_capacity = 65536;
    cfg.stream_max_pending_frames = 64;
    cfg.conn_send_queue_cap = conn_send_queue_cap;
    cfg.inactivity_timeout_ms = 60000;
    cfg.on_stream_data = tx_probe_on_stream_data;
    cfg.on_stream_data_userdata = p;
    cfg.on_writable = tx_probe_on_writable;
    cfg.on_writable_userdata = p;
    cfg.on_broken = tx_probe_on_broken;
    cfg.on_broken_userdata = p;
    cfg.valve = v;

    int conn_fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, conn_fds) != 0) {
        return -1;
    }
    if (fcntl(conn_fds[1], F_SETFL, O_NONBLOCK) != 0) {
        return -1;
    }
    if (cloak_session_init(&p->sesh, 1, r, &cfg) != 0) {
        return -1;
    }
    if (cloak_session_add_conn(&p->sesh, conn_fds[0]) != 0) {
        return -1;
    }
    p->peer = conn_fds[1];

    cloak_stream_t *s = cloak_session_open_stream(&p->sesh, NULL);
    if (s == NULL) {
        return -1;
    }
    p->stream = s;

    int up[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, up) != 0) {
        return -1;
    }
    if (fcntl(up[1], F_SETFL, O_NONBLOCK) != 0) {
        return -1;
    }
    cloak_stream_relay_t *sr = malloc(sizeof(*sr));
    if (sr == NULL) {
        return -1;
    }
    if (cloak_stream_relay_start(sr, r, &p->sesh, s, up[0], 65536, tx_probe_on_done, p) != 0) {
        free(sr);
        return -1;
    }
    p->sr = sr;
    p->up_outer = up[1];
    return 0;
}

static void tx_probe_stop(struct tx_probe *p) {
    if (p->sr != NULL) {
        cloak_stream_relay_stop(p->sr);
        free(p->sr);
        p->sr = NULL;
    }
    if (p->stream != NULL) {
        cloak_session_release_stream(&p->sesh, p->stream);
        p->stream = NULL;
    }
    cloak_session_destroy(&p->sesh);
    if (p->peer >= 0) {
        close(p->peer);
    }
    if (p->up_outer >= 0) {
        close(p->up_outer);
    }
}

/* A relay whose own resume timer fires into a STILL-EMPTY bucket must
 * arm a successor. Without that, the fire that finds nothing is the last
 * event the relay will ever see.
 *
 * REACHABLE, and not rarely. cloak_valve_bucket_t's delay is the time to
 * ONE byte, and any other consumer on the same valve can take it first:
 * a second stream's relay, a second session of the same user, or
 * cloak_switchboard_send billing a control frame's framing overhead. Two
 * concurrent downloads, one finishes, the pool goes quiet, and the
 * survivor sits paused with no timer, holding a live stream and an open
 * fd, forever.
 *
 * WHY THE TEST IS SHAPED LIKE THIS, because an earlier version of it was
 * green for the wrong reason and pinned nothing:
 *
 *  - The competing consumer is the TEST ITSELF (starve_tx_bucket), not a
 *    second relay. Two relays racing for one bucket reach the same state
 *    but not reliably: timers fire in deadline order, so the relay that
 *    armed first keeps winning and the other can legitimately starve for
 *    a whole measurement window. Spending the tokens by hand is the same
 *    situation made deterministic.
 *
 *  - NOTHING READS THE SESSION'S SOCKET inside either loop below, and
 *    that omission is the entire point. Draining it frees kernel buffer
 *    space, which drains the connection's send queue, which fires
 *    on_drained -> on_writable -> cloak_stream_relay_notify_writable --
 *    whose success path un-pauses the relay all by itself. An earlier
 *    version of this test drained every turn and therefore measured the
 *    PRIMARY arming site, not the re-arm: deleting the re-arm left it
 *    green. The single read at the end is after all the measuring is
 *    done and cannot rescue anything retroactively.
 *
 * With nothing written to the upstream, nothing read from the socket and
 * nothing queued to drain, the only event left in the entire system is a
 * timer the relay armed for itself. */
static void test_relay_rearms_when_the_bucket_is_emptied_under_it(void) {
    static const int64_t RATE = 200000;
    static const uint64_t STARVE_MS = 80;
    static const uint64_t QUIET_MS = 300;
    /* 4000 bytes is 20 ms at this rate: an order of magnitude longer
     * than the 1-2 ms delay a relay pausing on an empty bucket arms, so
     * a timer armed at any moment during the loop below fires while the
     * bucket is still in debt. See starve_tx_bucket. */
    static const int64_t DEBT_BYTES = 4000;

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    cloak_valve_set_rates(&v, 0, RATE);

    struct tx_probe p;
    ASSERT_EQ_INT(tx_probe_start(&p, r, &v, 262144), 0);

    /* Get it running and paced, and leave the connection's send queue
     * empty so that no drain notification is owed to anyone once the
     * measurement starts. */
    for (int i = 0; i < 40; i++) {
        stuff_peer(p.up_outer);
        cloak_reactor_run_once(r, 0);
        drain_peer(&p);
    }
    ASSERT_TRUE(p.drained > 0); /* it really was relaying */
    int64_t before = p.drained;

    /* STARVE. Non-blocking turns, so the bucket is re-emptied thousands
     * of times per millisecond and is held at roughly -DEBT_BYTES
     * continuously: a resume timer firing at any point in here finds
     * nothing and must arm a successor. With the re-arm deleted, the
     * first such fire is the last. */
    uint64_t t0 = real_mono_ms();
    int turns = 0;
    while (real_mono_ms() - t0 < STARVE_MS && turns < 100000000) {
        starve_tx_bucket(&v, DEBT_BYTES);
        cloak_reactor_run_once(r, 0);
        turns++;
    }

    /* RELEASE. The bucket is left alone from here. It climbs out of
     * DEBT_BYTES in 20 ms and then refills at the configured rate.
     * Nothing else changes: no upstream write, no socket read, no queued
     * bytes to drain, so a relay that lost its timer during the loop
     * above has nothing left that could ever wake it. */
    t0 = real_mono_ms();
    turns = 0;
    while (real_mono_ms() - t0 < QUIET_MS && turns < 1000000) {
        cloak_reactor_run_once(r, 5);
        turns++;
    }

    /* Only now is the socket read, and what comes out is everything the
     * relay managed to forward across both loops. */
    drain_peer(&p);
    int64_t resumed = p.drained - before;
    if (resumed < RATE / 10) {
        fprintf(stderr, "RE-ARM STALL: %lld relayed across %llu ms of starvation and %llu ms free\n",
                (long long)resumed, (unsigned long long)STARVE_MS, (unsigned long long)QUIET_MS);
    }
    /* The starvation window relays essentially nothing; the release
     * window spends 20 ms climbing out of debt and then relays at the
     * configured rate for the remaining ~280 ms, which is ~56000 bytes,
     * and the socket buffer holds well over that. A tenth of the rate is
     * a floor no scheduling noise can miss and no single stray byte can
     * satisfy. */
    ASSERT_TRUE(resumed >= RATE / 10);
    ASSERT_EQ_INT(p.broken, 0);
    ASSERT_EQ_INT(p.done_calls, 0);

    tx_probe_stop(&p);
    cloak_reactor_destroy(r);
}

/* THE TIMER MUST NOT OUTLIVE THE RELAY. cloak_stream_relay_stop can be
 * called on a relay that is rate-paused with a resume timer pending --
 * the panel terminating a user out of credit does exactly that, via
 * close_all_for_uid -> on_session_closing -> cloak_proxy_session_aborted
 * -> proxy_stream_teardown -- and that owner frees the relay's storage
 * the instant stop returns, because cloak_proxy_stream_t embeds the
 * relay by value. A surviving timer then fires stream_relay_on_rate_timer
 * on freed memory.
 *
 * The relay here is heap-allocated and freed at the same moment its real
 * owner would free it, and the reactor is then run PAST the pending
 * deadline before anything is destroyed. Both halves are required: a
 * relay left on the stack has nothing to corrupt, and destroying the
 * reactor first discards pending timers unfired -- which is exactly why
 * every other test in this file missed this. Under ASan this fails
 * loudly if the cancel in stream_relay_teardown is removed. */
static void test_stopping_a_rate_paused_relay_cancels_its_timer(void) {
    static const int64_t RATE = 200000;
    static const uint64_t AFTER_FREE_MS = 150;

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    cloak_valve_set_rates(&v, 0, RATE);

    struct tx_probe p;
    ASSERT_EQ_INT(tx_probe_start(&p, r, &v, 262144), 0);

    for (int i = 0; i < 40; i++) {
        stuff_peer(p.up_outer);
        cloak_reactor_run_once(r, 0);
        drain_peer(&p);
    }
    ASSERT_TRUE(p.drained > 0);

    /* Drive it into a pause whose resume is tens of milliseconds away.
     *
     * The debt is added in small steps and the loop stops when the VALVE
     * SAYS the delay is where it wants it, rather than by adding a fixed
     * amount a fixed number of times. Both fixed-count versions of this
     * were wrong: adding unconditionally five times accumulated ~100 ms
     * of debt against a 150 ms window and failed about one ASan run in
     * fifty, and routing it through starve_tx_bucket's "skip when
     * already in debt" guard added no debt at all, because the relay has
     * already paced the bucket to zero by the end of the warm-up. A loop
     * that measures what it produced cannot be wrong in either
     * direction.
     *
     * The reactor is turned each step so the relay's own timer fires,
     * finds the growing debt and re-arms at the larger delay -- which is
     * what leaves a pending timer whose deadline is the value asserted
     * below. */
    int steps = 0;
    while (cloak_valve_tx_resume_delay_ms(&v) < 20 && steps < 1000) {
        cloak_valve_add_tx(&v, RATE / 200); /* 5 ms of debt per step */
        cloak_reactor_run_once(r, 0);
        steps++;
    }
    ASSERT_TRUE(steps < 1000);
    uint64_t pending_delay = cloak_valve_tx_resume_delay_ms(&v);
    ASSERT_EQ_INT(cloak_valve_take_tx(&v, 16384), 0); /* really rate-paused */
    /* Far enough away that the timer is certainly still pending when the
     * relay is freed... */
    ASSERT_TRUE(pending_delay >= 20);
    /* ...and comfortably inside the window that runs after the free, or
     * this test would abandon a timer and then stop watching before it
     * could fire -- passing while exercising nothing. */
    ASSERT_TRUE(pending_delay < AFTER_FREE_MS / 2);

    /* Exactly what proxy_stream_teardown does, in exactly that order. */
    cloak_stream_relay_stop(p.sr);
    free(p.sr);
    p.sr = NULL;

    /* Run well past the deadline the freed relay had armed. */
    uint64_t t0 = real_mono_ms();
    int turns = 0;
    while (real_mono_ms() - t0 < AFTER_FREE_MS && turns < 1000000) {
        cloak_reactor_run_once(r, 5);
        turns++;
    }
    ASSERT_EQ_INT(p.broken, 0);

    tx_probe_stop(&p); /* p.sr is already NULL; this releases the rest */
    cloak_reactor_destroy(r);
}

/* A FAILED SEND BILLS NOTHING. cloak_switchboard_send counts tx only on
 * the success path (`rc == 0`), mirroring Go's switchboard.send, which
 * returns from its error branches before ever reaching AddTx.
 *
 * Not a cosmetic accounting point now that the same counter drains the
 * token bucket: billing a frame the kernel never took would charge the
 * user for bytes that did not cross the socket AND push their bucket
 * into debt, throttling them for traffic they never received. The guard
 * was previously verified by reading; this measures it.
 *
 * A switchboard is driven directly here rather than through a session:
 * the failure needed is one connection's own send-queue cap being
 * exceeded, which is a property of cloak_conn_send and is reached by
 * filling a socket whose peer never reads. */
static void sbp_on_envelope(cloak_switchboard_t *sb, const uint8_t *b, size_t n, void *ud) {
    (void)sb;
    (void)b;
    (void)n;
    (void)ud;
}

static void sbp_on_broken(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    int *broken = userdata;
    (*broken)++;
}

static void test_a_failed_send_is_not_billed(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    int broken = 0;
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, 2048, 4096, sbp_on_envelope, NULL, sbp_on_broken,
                                         &broken),
                  0);
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    cloak_switchboard_set_valve(&sb, &v);

    int fds[2];
    ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds[0]), 0);
    /* fds[1] is never read from: the kernel buffer fills, then the
     * connection's own 4096-byte send queue, and the send after that
     * fails. */

    uint8_t frame[2048];
    memset(frame, 0x5a, sizeof(frame));

    int64_t billed_before_the_failure = -1;
    int failed = 0;
    int sends = 0;
    for (int i = 0; i < 100000 && !failed; i++) {
        billed_before_the_failure = cloak_valve_tx(&v);
        if (cloak_switchboard_send(&sb, frame, sizeof(frame)) != 0) {
            failed = 1;
        }
        sends++;
    }
    ASSERT_TRUE(failed);            /* the send really did fail */
    ASSERT_EQ_INT(broken, 1);       /* and reported itself as a pool failure */
    ASSERT_TRUE(sends > 1);         /* after a run of successful ones... */
    ASSERT_TRUE(billed_before_the_failure > 0); /* ...which WERE billed */

    /* The literal claim: the counter is exactly where it was before the
     * failing call. Billing unconditionally adds 2 + 2048 here. */
    ASSERT_EQ_INT(cloak_valve_tx(&v), billed_before_the_failure);

    cloak_switchboard_destroy(&sb);
    close(fds[1]);
    cloak_reactor_destroy(r);
}

/* THE TWO CLOCK READS THAT DISAGREE. This is a regression test for a
 * real stall, and it is here because the flakiness of another test in
 * this file WAS the bug.
 *
 * stream_relay_fd_read_budget asks the valve two questions in a row:
 * "may I move bytes" (cloak_valve_take_tx) and, if not, "how long until
 * I may" (cloak_valve_tx_resume_delay_ms). Each reads the clock for
 * itself. A bucket a fraction of a byte short at the first question can
 * hold a whole byte at the second, and the second then answers 0 --
 * which means "nothing to wait for", not "the valve is fine". A caller
 * reading that 0 as "this pause is not rate-bound" arms nothing, and the
 * relay is left paused with a full bucket, an empty pool, and no event
 * anywhere in the system that could ever wake it.
 *
 * In real time that window is about five microseconds wide at 200 kB/s
 * and it was hit roughly once in two hundred ASan runs -- found only
 * because the relay pacing test started failing with `paused=1
 * rate_timer=0 min_free=262144 take=16384`, which is that state exactly.
 *
 * A CLOCK THAT ALTERNATES A ONE-MILLISECOND SKEW makes it certain rather
 * than rare: consecutive reads land on T and T+1, so the take refuses on
 * a bucket the delay then finds a whole millisecond richer. Every
 * refusal on an even-parity read reproduces it, and with the floor
 * removed a single one is enough to wedge the relay for good.
 *
 * The skew rides on REAL time rather than replacing it, deliberately. A
 * clock that simply advanced a millisecond per read also reproduces the
 * race, but it runs the valve's time far faster than the reactor's, so
 * the bucket starves in real terms and the relay's own computed delays
 * grow past a second -- a correct implementation then looks stalled too,
 * and the test asserts nothing. Skew reproduces the disagreement while
 * leaving the pacing to within a millisecond of correct. */
static unsigned skew_calls;

static uint64_t skew_clock(void *userdata) {
    (void)userdata;
    return real_mono_ms() + (skew_calls++ & 1u);
}

static void test_a_refusal_that_refills_between_the_two_reads_still_arms(void) {
    static const int64_t RATE = 200000;
    static const uint64_t WINDOW_MS = 150;

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    skew_calls = 0;
    cloak_valve_set_clock(&v, skew_clock, NULL);
    cloak_valve_set_rates(&v, 0, RATE);

    struct tx_probe p;
    ASSERT_EQ_INT(tx_probe_start(&p, r, &v, 262144), 0);

    for (int i = 0; i < 40; i++) {
        stuff_peer(p.up_outer);
        cloak_reactor_run_once(r, 0);
        drain_peer(&p);
    }
    ASSERT_TRUE(p.drained > 0); /* it relayed before any refusal */

    /* Nothing is written to the upstream and nothing is read from the
     * session's socket from here, so no readiness edge and no drain
     * notification exists. At this rate the pool never backs up either,
     * so there is no on_drained to fire even in principle. Every byte
     * counted below is one a resume timer went and fetched. */
    int64_t base = cloak_valve_tx(&v);
    uint64_t t0 = real_mono_ms();
    int turns = 0;
    while (real_mono_ms() - t0 < WINDOW_MS && turns < 1000000) {
        cloak_reactor_run_once(r, 5);
        turns++;
    }
    int64_t moved = cloak_valve_tx(&v) - base;
    if (moved <= 5000) {
        fprintf(stderr, "ZERO-DELAY STALL: %lld bytes in %llu ms over %d turns\n", (long long)moved,
                (unsigned long long)WINDOW_MS, turns);
    }
    ASSERT_TRUE(moved > 5000);
    ASSERT_EQ_INT(p.broken, 0);
    ASSERT_EQ_INT(p.done_calls, 0);

    tx_probe_stop(&p);
    cloak_reactor_destroy(r);
}

/* A relay paused because the outbound POOL was full is resumed by the
 * pool draining -- but if the user's bucket has gone empty by the time
 * that notification arrives, that notification is the LAST one the pool
 * will ever send (it is empty now; nothing more will drain). The pause
 * has to be re-attributed to the bucket right there, and armed.
 *
 * Constructed rather than waited for: the pool is filled by refusing to
 * read the session's socket, the bucket is emptied by hand at the moment
 * the pool is still full, and only then is the socket read. */
static void test_relay_pool_pause_becomes_a_rate_pause(void) {
    /* Capacity (one second at this rate) has to exceed the pool's total
     * depth -- this connection's 32 KiB send queue plus whatever the
     * socketpair itself buffers -- or the relay would run out of TOKENS
     * before it ran out of POOL and the pause under test would never be
     * pool-bound in the first place. */
    static const int64_t RATE = 2000000;
    static const size_t CONN_SEND_QUEUE_CAP = 32768;
    static const uint64_t QUIET_MS = 300;

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));
    cloak_valve_set_rates(&v, 0, RATE);

    struct tx_probe p;
    ASSERT_EQ_INT(tx_probe_start(&p, r, &v, CONN_SEND_QUEUE_CAP), 0);

    /* Fill the pool: feed the upstream, run the relay, and NEVER read
     * the session's socket. */
    for (int i = 0; i < 200; i++) {
        stuff_peer(p.up_outer);
        cloak_reactor_run_once(r, 0);
    }
    /* Pool-bound, not rate-bound: the send queue cannot take another
     * whole frame, while the bucket still has plenty. If this were the
     * other way round the test would be exercising the ordinary
     * rate-pause path and would pass with the code under test deleted. */
    ASSERT_TRUE(cloak_session_send_min_conn_free(&p.sesh) < 16403);
    ASSERT_TRUE(cloak_valve_take_tx(&v, 16384) == 16384);
    ASSERT_EQ_INT(p.broken, 0);

    /* Now empty the bucket, while the pause is still pool-bound. */
    starve_tx_bucket(&v, 4000); /* 2 ms at this test's rate -- see starve_tx_bucket */
    ASSERT_EQ_INT(cloak_valve_take_tx(&v, 16384), 0);

    /* Release the pool. This delivers the one and only drain
     * notification the relay is going to get. */
    int64_t freed = drain_peer(&p);
    ASSERT_TRUE(freed > 0);
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(r, 1);
        drain_peer(&p);
    }
    int64_t at_handover = p.drained;

    /* From here the pool is empty, so nothing will ever drain again and
     * no further notification exists. Nothing is written to the upstream
     * either. If the handover above did not arm a timer, this relay is
     * finished for good. */
    uint64_t t0 = real_mono_ms();
    int turns = 0;
    while (real_mono_ms() - t0 < QUIET_MS && turns < 1000000) {
        cloak_reactor_run_once(r, 5);
        drain_peer(&p);
        turns++;
    }
    int64_t resumed = p.drained - at_handover;
    if (resumed <= 0) {
        fprintf(stderr, "HANDOVER STALL: nothing relayed in %llu ms after the pool drained\n",
                (unsigned long long)QUIET_MS);
    }
    ASSERT_TRUE(resumed > 0);
    ASSERT_EQ_INT(p.broken, 0);
    ASSERT_EQ_INT(p.done_calls, 0);

    tx_probe_stop(&p);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_token_arithmetic();
    test_zero_rate_is_unlimited();
    test_exact_rate_over_a_simulated_second();
    test_real_connection_holds_its_rate();
    test_paused_direction_resumes_on_time_alone();
    test_rx_pause_does_not_block_tx();
    test_relay_tx_is_paced_and_resumes();
    test_relay_rearms_when_the_bucket_is_emptied_under_it();
    test_stopping_a_rate_paused_relay_cancels_its_timer();
    test_relay_pool_pause_becomes_a_rate_pause();
    test_a_refusal_that_refills_between_the_two_reads_still_arms();
    test_a_failed_send_is_not_billed();
TEST_MAIN_END()
