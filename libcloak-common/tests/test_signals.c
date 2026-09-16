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

/* Case 3: this module's documented contract (see cloak/signals.h) is that
 * every signal instance the kernel actually delivers produces its own
 * callback invocation -- nothing is latched or deduplicated. Two signals,
 * raised far enough apart that the first is fully drained before the
 * second exists, must therefore produce two callbacks. */

struct double_sig_ctx {
    int count;
    cloak_reactor_t *r;
};

static void on_double_sig(int signo, void *userdata) {
    (void)signo;
    struct double_sig_ctx *ctx = userdata;
    ctx->count++;
    if (ctx->count >= 2) {
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

    /* 40ms apart: the reactor drains and dispatches the first long before
     * the second is even raised, so the kernel never has a chance to
     * merge them into a single pending signal. */
    ASSERT_TRUE(cloak_reactor_add_timer(r, 20, raise_sigint_again, NULL) != CLOAK_TIMER_INVALID);
    ASSERT_TRUE(cloak_reactor_add_timer(r, 60, raise_sigint_again, NULL) != CLOAK_TIMER_INVALID);

    /* Bounded pump, not cloak_reactor_run: a contract that collapsed to
     * "first signal only" would never make on_double_sig call
     * cloak_reactor_stop a second time, so cloak_reactor_run would block
     * forever waiting for it instead of failing. pump_for_ms instead runs
     * for a fixed window comfortably past the 60ms second raise and
     * always returns, so a broken contract fails ASSERT_EQ_INT below
     * immediately, naming exactly the property that broke, rather than
     * timing out the whole test binary. */
    pump_for_ms(r, 300);

    ASSERT_EQ_INT(ctx.count, 2);

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
    test_generated_uid_is_16_bytes_and_calls_differ();
    test_keypair_round_trips_through_derivation();
TEST_MAIN_END()
