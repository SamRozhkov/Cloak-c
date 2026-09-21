#include "cloak/signals.h"

#include "cloak/base64.h"
#include "cloak/crypto.h"
#include "cloak/keygen.h"
#include "cloak/reactor.h"
#include "test_framework.h"

#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

static uint64_t test_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Pumps r via run_once for exactly ms milliseconds of wall-clock time and
 * asserts it actually reached that duration, instead of blocking on
 * cloak_reactor_run until some callback happens to call cloak_reactor_stop.
 * A test that waits on cloak_reactor_run for an event that a contract
 * violation would never produce hangs for the full ctest TIMEOUT instead
 * of failing -- a fast, named assertion failure is strictly better than a
 * 60-second timeout with nothing to read. Matches this branch's other
 * tasks' pump_for_ms helper (e.g. libcloak-client/tests/test_client_stack.c). */
static void pump_for_ms(cloak_reactor_t *r, uint64_t ms) {
    uint64_t start = test_now_ms();
    uint64_t elapsed = 0;
    uint64_t cap = ms * 1000u + 5000000u;
    for (uint64_t i = 0; i < cap; i++) {
        cloak_reactor_run_once(r, 1);
        elapsed = test_now_ms() - start;
        if (elapsed >= ms) {
            break;
        }
    }
    ASSERT_TRUE(elapsed >= ms);
}

/* Case 1: a signal delivered while the reactor runs invokes the callback
 * exactly once, and the reactor returns. */

struct single_sig_ctx {
    int count;
    cloak_reactor_t *r;
};

static void on_single_sig(int signo, void *userdata) {
    (void)signo;
    struct single_sig_ctx *ctx = userdata;
    ctx->count++;
    cloak_reactor_stop(ctx->r);
}

static void raise_sigint_from_reactor(cloak_reactor_t *r, void *userdata) {
    (void)r;
    (void)userdata;
    /* Raising from a timer callback -- itself only ever invoked from
     * inside cloak_reactor_run -- proves the signal genuinely arrives
     * "while the reactor runs", not before it starts. */
    raise(SIGINT);
}

static void test_signal_while_running_invokes_callback_once(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct single_sig_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.r = r;

    cloak_signalfd_t *sfd = cloak_signalfd_create(r, on_single_sig, &ctx);
    ASSERT_TRUE(sfd != NULL);

    ASSERT_TRUE(cloak_reactor_add_timer(r, 20, raise_sigint_from_reactor, NULL) != CLOAK_TIMER_INVALID);

    uint64_t start = test_now_ms();
    cloak_reactor_run(r);
    uint64_t elapsed = test_now_ms() - start;

    ASSERT_EQ_INT(ctx.count, 1);
    ASSERT_TRUE(elapsed < 5000); /* generous: catches a broken wiring that blocks forever */

    cloak_signalfd_destroy(sfd);
    cloak_reactor_destroy(r);
}

/* Case 2: the previous signal mask is restored on destroy -- verified by
 * reading the mask back with sigprocmask, not by inspecting the API's
 * return values. */

static void noop_sig_cb(int signo, void *userdata) {
    (void)signo;
    (void)userdata;
}

static void test_destroy_restores_previous_signal_mask(void) {
    /* Force a known, unblocked baseline before reading "before" -- this
     * test must not trust whatever mask happens to be left over from an
     * earlier test case (in particular, a broken restore in an earlier
     * case must not leave SIGINT/SIGTERM blocked in a way that makes
     * THIS test's own before/after comparison vacuously pass). */
    sigset_t target;
    sigemptyset(&target);
    sigaddset(&target, SIGINT);
    sigaddset(&target, SIGTERM);
    ASSERT_EQ_INT(sigprocmask(SIG_UNBLOCK, &target, NULL), 0);

    sigset_t before;
    /* set == NULL: sigprocmask only reports the current mask into
     * oldset and changes nothing (POSIX) -- this is a pure read. */
    ASSERT_EQ_INT(sigprocmask(SIG_BLOCK, NULL, &before), 0);
    ASSERT_EQ_INT(sigismember(&before, SIGINT), 0);
    ASSERT_EQ_INT(sigismember(&before, SIGTERM), 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    cloak_signalfd_t *sfd = cloak_signalfd_create(r, noop_sig_cb, NULL);
    ASSERT_TRUE(sfd != NULL);

    sigset_t during;
    ASSERT_EQ_INT(sigprocmask(SIG_BLOCK, NULL, &during), 0);
    ASSERT_EQ_INT(sigismember(&during, SIGINT), 1);
    ASSERT_EQ_INT(sigismember(&during, SIGTERM), 1);

    cloak_signalfd_destroy(sfd);
    cloak_reactor_destroy(r);

    sigset_t after;
    ASSERT_EQ_INT(sigprocmask(SIG_BLOCK, NULL, &after), 0);
    ASSERT_EQ_INT(sigismember(&after, SIGINT), sigismember(&before, SIGINT));
    ASSERT_EQ_INT(sigismember(&after, SIGTERM), sigismember(&before, SIGTERM));
}

/* Case 3: this module's documented contract (see cloak/signals.h's
 * "SECOND-SIGNAL CONTRACT") is that it does not latch and does not
 * deduplicate -- every signal instance the KERNEL HANDS THE FD produces
 * its own callback invocation.
 *
 * THE SECOND RAISE IS ANCHORED TO THE FIRST DELIVERY, NOT TO A CLOCK,
 * and that is the whole design of this case. An earlier revision armed
 * two timers 40 ms apart and claimed in its comment that "the reactor
 * drains and dispatches the first long before the second is even
 * raised". That is not a property of this system; it is a bet on the
 * scheduler, and it loses. Measured in this project's dev image at
 * `docker run --cpus=1` with seven busy-loop spinners in the container,
 * `ctest -R '^test_signals$' -j1`: 3 failures in 12 runs of the shipped
 * build, 6 in 12 with a diagnostic build. Every single failure printed
 * the same shape -- both timer callbacks running in the SAME reactor
 * turn, about 100 ms after the timers were armed, with no callback
 * dispatched between them:
 *
 *     [diag] raise #1 at t=104 ms, drains so far=0
 *     [diag] raise #2 at t=104 ms, drains so far=0
 *     [diag] callback #1 at t=104 ms, raises so far=2
 *
 * The process was simply descheduled past both deadlines. The two
 * SIGINTs were then raised back to back with SIGINT blocked and nothing
 * reading the fd in between, and the kernel -- which does not queue
 * ordinary signals -- merged them into ONE pending signal before
 * signalfd ever saw a second. signals.h names that limitation
 * explicitly and disclaims it, so the old assertion was enforcing a
 * property this module documents itself as NOT having. Nothing in
 * signals.c is at fault: it read the fd to EAGAIN and invoked the
 * callback once per siginfo, which is all it promises.
 * test_two_same_turn_signals_coalesce_in_the_kernel below pins that
 * boundary from the other side, so this comment's account of the merge
 * is asserted somewhere and not merely asserted here.
 *
 * So the second SIGINT is raised from inside the FIRST DELIVERY, which
 * is by construction after that first siginfo has been read out of the
 * fd -- exactly the condition signals.h states the contract under ("if
 * the reactor has drained the first SIGINT before a second one
 * arrives"). No wall-clock gap has to hold for that to be true, so no
 * amount of starvation can make it false.
 *
 * AND IT IS STILL THE SAME SIGNAL, WHICH IS LOAD-BEARING rather than
 * incidental. Keeping the two 40 ms timers and making the SECOND one
 * raise SIGTERM also removes the flake -- two distinct ordinary signals
 * can be pending at once, so nothing merges -- and it is the obvious
 * alternative fix. It is also a strictly weaker test, and both halves of
 * that were measured on the commit that wrote this comment: the SIGTERM
 * variant went 0 failures in 12 at the lever above, AND, with
 * cloak_signalfd mutated to latch per signal number -- precisely what
 * "does not deduplicate" forbids -- the SIGTERM variant PASSED while
 * this version failed deterministically at 1 != 2, unstarved. A test
 * that is green over a signalfd which swallows every repeat of a signal
 * is not testing the second-signal contract. */

struct double_sig_ctx {
    int count;
    cloak_reactor_t *r;
};

static void on_double_sig(int signo, void *userdata) {
    (void)signo;
    struct double_sig_ctx *ctx = userdata;
    ctx->count++;
    if (ctx->count == 1) {
        /* THE ANCHOR. This runs from inside on_signal_readable's drain
         * loop, after the siginfo being delivered right now has already
         * been read out of the fd -- so this repeat cannot be merged
         * into it, whatever the scheduler does next. It is left pending
         * by the block cloak_signalfd_create installed and the very next
         * read in that same drain loop picks it up. */
        raise(SIGINT);
    } else {
        cloak_reactor_stop(ctx->r);
    }
}

static void raise_sigint_again(cloak_reactor_t *r, void *userdata) {
    (void)r;
    (void)userdata;
    raise(SIGINT);
}

static void test_two_signals_deliver_two_callbacks(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct double_sig_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.r = r;

    cloak_signalfd_t *sfd = cloak_signalfd_create(r, on_double_sig, &ctx);
    ASSERT_TRUE(sfd != NULL);

    /* One timer, not two: the second raise is on_double_sig's job. The
     * timer exists only so the first signal is raised from inside the
     * reactor rather than before it starts. */
    ASSERT_TRUE(cloak_reactor_add_timer(r, 20, raise_sigint_again, NULL) != CLOAK_TIMER_INVALID);

    /* Bounded pump, not cloak_reactor_run: a contract that collapsed to
     * "first signal only" would never make on_double_sig call
     * cloak_reactor_stop at all, so cloak_reactor_run would block
     * forever waiting for it instead of failing. pump_for_ms instead
     * runs for a fixed window and always returns, so a broken contract
     * fails ASSERT_EQ_INT below immediately, naming exactly the property
     * that broke, rather than timing out the whole test binary. The
     * window is NOT what makes the second callback happen -- both
     * deliveries occur in one drain loop, in one reactor turn, however
     * late that turn arrives. */
    pump_for_ms(r, 300);

    ASSERT_EQ_INT(ctx.count, 2);

    cloak_signalfd_destroy(sfd);
    cloak_reactor_destroy(r);
}

/* Case 3b: the same contract's BOUNDARY, pinned from the other side and
 * measured here rather than taken from the man page. Two SIGINTs raised
 * back to back -- SIGINT blocked by cloak_signalfd_create, nothing
 * reading the fd in between -- are ONE pending signal by the time the
 * reactor looks, because ordinary signals are not queued. That is a
 * kernel property this module inherits and cannot undo; it is what case
 * 3's 40 ms-apart predecessor was relying on the scheduler to avoid; and
 * asserting it here is what stops that shape coming back unnoticed.
 *
 * This is deliberately a repeat of the SAME signal in the SAME reactor
 * turn, which is the one case that coalesces. If this case ever reads 2,
 * the kernel's behaviour has changed under us and case 3's comment needs
 * rewriting, not silently widening. */

static void on_counting_sig(int signo, void *userdata) {
    (void)signo;
    int *count = userdata;
    (*count)++;
}

static void raise_sigint_twice(cloak_reactor_t *r, void *userdata) {
    (void)r;
    (void)userdata;
    raise(SIGINT);
    raise(SIGINT);
}

static void test_two_same_turn_signals_coalesce_in_the_kernel(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    int count = 0;
    cloak_signalfd_t *sfd = cloak_signalfd_create(r, on_counting_sig, &count);
    ASSERT_TRUE(sfd != NULL);

    ASSERT_TRUE(cloak_reactor_add_timer(r, 20, raise_sigint_twice, NULL) != CLOAK_TIMER_INVALID);

    /* No stop callback here on purpose: the window has to stay open past
     * the delivery so that a second callback, if the fd had a second
     * siginfo to give, would be counted. The drain loop would dispatch
     * both in the same turn, so any window that reaches the timer is
     * long enough; 200 ms is that with room to spare. */
    pump_for_ms(r, 200);

    ASSERT_EQ_INT(count, 1);

    cloak_signalfd_destroy(sfd);
    cloak_reactor_destroy(r);
}

/* Case 4: generated UIDs are 16 bytes and decode back to what was
 * generated; two calls differ. */

static void test_generated_uid_is_16_bytes_and_calls_differ(void) {
    char uid_b64_a[64];
    char uid_b64_b[64];

    ASSERT_EQ_INT(cloak_keygen_uid(uid_b64_a, sizeof(uid_b64_a)), 0);
    ASSERT_EQ_INT(cloak_keygen_uid(uid_b64_b, sizeof(uid_b64_b)), 0);

    uint8_t decoded_a[64];
    uint8_t decoded_b[64];
    size_t len_a = 0;
    size_t len_b = 0;

    ASSERT_EQ_INT(cloak_base64_decode(uid_b64_a, decoded_a, sizeof(decoded_a), &len_a), 0);
    ASSERT_EQ_INT(cloak_base64_decode(uid_b64_b, decoded_b, sizeof(decoded_b), &len_b), 0);

    ASSERT_EQ_INT((long long)len_a, CLOAK_KEYGEN_UID_LEN);
    ASSERT_EQ_INT((long long)len_b, CLOAK_KEYGEN_UID_LEN);
    ASSERT_MEM_NE(decoded_a, decoded_b, CLOAK_KEYGEN_UID_LEN);
    ASSERT_TRUE(strcmp(uid_b64_a, uid_b64_b) != 0);
}

/* Case 5: a generated key pair genuinely round-trips -- the public key
 * derived from the reported private key equals the reported public key.
 * X25519 public-key derivation is scalar multiplication of the private
 * scalar by the curve's fixed base point (u-coordinate 9, RFC 7748), so
 * feeding the base point to cloak_x25519_shared_secret as the "peer
 * public key" recomputes the public key from priv alone -- this fails
 * against any implementation that doesn't actually derive pub from priv
 * (e.g. one that returns unrelated random bytes for pub), unlike merely
 * checking that the two base64 strings are non-empty and differ. */

static void test_keypair_round_trips_through_derivation(void) {
    char pub_b64[64];
    char priv_b64[64];

    ASSERT_EQ_INT(cloak_keygen_keypair(pub_b64, sizeof(pub_b64), priv_b64, sizeof(priv_b64)), 0);

    uint8_t pub[CLOAK_X25519_KEY_LEN];
    uint8_t priv[CLOAK_X25519_KEY_LEN];
    size_t pub_len = 0;
    size_t priv_len = 0;

    ASSERT_EQ_INT(cloak_base64_decode(pub_b64, pub, sizeof(pub), &pub_len), 0);
    ASSERT_EQ_INT(cloak_base64_decode(priv_b64, priv, sizeof(priv), &priv_len), 0);
    ASSERT_EQ_INT((long long)pub_len, CLOAK_X25519_KEY_LEN);
    ASSERT_EQ_INT((long long)priv_len, CLOAK_X25519_KEY_LEN);

    uint8_t basepoint[CLOAK_X25519_KEY_LEN];
    memset(basepoint, 0, sizeof(basepoint));
    basepoint[0] = 9;

    uint8_t derived_pub[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(cloak_x25519_shared_secret(priv, basepoint, derived_pub), 0);

    ASSERT_MEM_EQ(derived_pub, pub, CLOAK_X25519_KEY_LEN);
}

TEST_MAIN_BEGIN()
    test_signal_while_running_invokes_callback_once();
    test_destroy_restores_previous_signal_mask();
    test_two_signals_deliver_two_callbacks();
    test_two_same_turn_signals_coalesce_in_the_kernel();
    test_generated_uid_is_16_bytes_and_calls_differ();
    test_keypair_round_trips_through_derivation();
TEST_MAIN_END()
