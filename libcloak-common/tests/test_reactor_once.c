/* Covers cloak_reactor_run_once directly: test_reactor.c only ever
 * exercises it indirectly through cloak_reactor_run (by design -- it must
 * remain untouched, to prove the run_once extraction preserved run()'s
 * semantics), which left run_once's own return value, and
 * effective_timeout_ms's branches for combining a timer deadline with a
 * caller-supplied timeout, without a test of their own. */
#include "cloak/reactor.h"
#include "test_framework.h"

#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint64_t test_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static void test_run_once_returns_immediately_with_nothing_ready(void) {
    /* No fd, no timer: compute_timeout_ms reports "no live timers" (-1),
     * so effective_timeout_ms's first branch picks the caller's 0
     * unchanged -- epoll_wait must not block. */
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    uint64_t start = test_now_ms();
    int dispatched = cloak_reactor_run_once(r, 0);
    uint64_t elapsed = test_now_ms() - start;

    ASSERT_EQ_INT(0, dispatched);
    ASSERT_TRUE(elapsed < 500); /* generous: this must not block at all */

    cloak_reactor_destroy(r);
}

struct read_ctx {
    int fired;
    long n;
    char buf[64];
};

static void on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    struct read_ctx *ctx = userdata;
    ctx->fired++;
    ctx->n = (long)read(fd, ctx->buf, sizeof(ctx->buf));
}

static void test_run_once_dispatches_and_counts_a_ready_fd(void) {
    int fds[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        close(fds[0]);
        close(fds[1]);
        return;
    }

    struct read_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ASSERT_EQ_INT(0, cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_READABLE, on_readable, &ctx));

    const char msg[] = "hi";
    ASSERT_TRUE(write(fds[1], msg, sizeof(msg)) == (long)sizeof(msg));

    /* A generous timeout: the fd is already readable, so this should
     * return almost immediately, but must not hang the suite if it
     * doesn't. */
    int dispatched = cloak_reactor_run_once(r, 1000);

    ASSERT_EQ_INT(1, dispatched);
    ASSERT_EQ_INT(1, ctx.fired);
    ASSERT_EQ_INT((long long)sizeof(msg), (long long)ctx.n);

    /* Nothing else is ready: a second turn must report no dispatches. */
    ASSERT_EQ_INT(0, cloak_reactor_run_once(r, 0));

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

struct timer_ctx {
    int fired;
};

static void on_timer_fire(cloak_reactor_t *r, void *userdata) {
    (void)r;
    struct timer_ctx *ctx = userdata;
    ctx->fired++;
}

static void test_run_once_timer_due_sooner_than_timeout_still_fires(void) {
    /* effective_timeout_ms's "both finite, timer is smaller" branch: a
     * 1000ms caller timeout must not stop a 20ms timer from firing --
     * and, since run_once's timeout is the SMALLER of the two, this
     * returns roughly at 20ms, not 1000ms. */
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct timer_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ASSERT_TRUE(cloak_reactor_add_timer(r, 20, on_timer_fire, &ctx) != CLOAK_TIMER_INVALID);

    uint64_t start = test_now_ms();
    int dispatched = cloak_reactor_run_once(r, 1000);
    uint64_t elapsed = test_now_ms() - start;

    /* Timers do not count toward run_once's fd-dispatch return value. */
    ASSERT_EQ_INT(0, dispatched);
    ASSERT_EQ_INT(1, ctx.fired);
    ASSERT_TRUE(elapsed < 1000); /* proves the timer's deadline won, not the caller's */

    cloak_reactor_destroy(r);
}

static void test_run_once_indefinite_wait_yields_to_earlier_timer(void) {
    /* effective_timeout_ms's "caller wants to block forever, a timer
     * exists" branch: timeout_ms == -1 must not turn into an infinite
     * block when a timer is pending -- the timer's deadline must win. */
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct timer_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ASSERT_TRUE(cloak_reactor_add_timer(r, 20, on_timer_fire, &ctx) != CLOAK_TIMER_INVALID);

    uint64_t start = test_now_ms();
    int dispatched = cloak_reactor_run_once(r, -1);
    uint64_t elapsed = test_now_ms() - start;

    ASSERT_EQ_INT(0, dispatched);
    ASSERT_EQ_INT(1, ctx.fired);
    ASSERT_TRUE(elapsed < 2000); /* would hang forever pre-fix-style regression */

    cloak_reactor_destroy(r);
}

static void test_run_once_timeout_smaller_than_timer_returns_first(void) {
    /* effective_timeout_ms's "both finite, caller is smaller" branch: a
     * short caller timeout must return before a much later timer fires,
     * not get stretched out to the timer's deadline. */
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct timer_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ASSERT_TRUE(cloak_reactor_add_timer(r, 2000, on_timer_fire, &ctx) != CLOAK_TIMER_INVALID);

    uint64_t start = test_now_ms();
    int dispatched = cloak_reactor_run_once(r, 20);
    uint64_t elapsed = test_now_ms() - start;

    ASSERT_EQ_INT(0, dispatched);
    ASSERT_EQ_INT(0, ctx.fired); /* the 2000ms timer must not have fired yet */
    ASSERT_TRUE(elapsed < 1000); /* proves the caller's 20ms won, not the timer's 2000ms */

    /* cloak_reactor_destroy frees the still-pending 2000ms timer without
     * firing it -- nothing further to clean up here. */
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_run_once_returns_immediately_with_nothing_ready();
    test_run_once_dispatches_and_counts_a_ready_fd();
    test_run_once_timer_due_sooner_than_timeout_still_fires();
    test_run_once_indefinite_wait_yields_to_earlier_timer();
    test_run_once_timeout_smaller_than_timer_returns_first();
TEST_MAIN_END()
