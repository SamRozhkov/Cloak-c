#include "cloak/reactor.h"
#include "test_framework.h"

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct read_ctx {
    int fired;
    uint32_t fired_events;
    char buf[64];
    long n;
};

static void on_readable_read_and_stop(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    struct read_ctx *ctx = (struct read_ctx *)userdata;
    ctx->fired = 1;
    ctx->fired_events = events;
    ctx->n = (long)read(fd, ctx->buf, sizeof(ctx->buf));
    cloak_reactor_stop(r);
}

static void test_add_and_dispatch_readable(void) {
    int fds[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct read_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_READABLE, on_readable_read_and_stop, &ctx), 0);

    const char msg[] = "hello reactor";
    ASSERT_TRUE(write(fds[1], msg, sizeof(msg)) == (long)sizeof(msg));

    cloak_reactor_run(r);

    ASSERT_TRUE(ctx.fired);
    ASSERT_TRUE((ctx.fired_events & CLOAK_REACTOR_READABLE) != 0);
    ASSERT_EQ_INT(ctx.n, sizeof(msg));
    ASSERT_MEM_EQ(ctx.buf, msg, sizeof(msg));

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

struct write_ctx {
    int fired;
    uint32_t fired_events;
};

static void on_writable_stop(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)fd;
    struct write_ctx *ctx = (struct write_ctx *)userdata;
    ctx->fired = 1;
    ctx->fired_events = events;
    cloak_reactor_stop(r);
}

static void test_dispatch_writable(void) {
    int fds[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct write_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_WRITABLE, on_writable_stop, &ctx), 0);

    /* A fresh socket's send buffer is empty, so it's immediately writable --
     * no write needed to trigger this. */
    cloak_reactor_run(r);

    ASSERT_TRUE(ctx.fired);
    ASSERT_TRUE((ctx.fired_events & CLOAK_REACTOR_WRITABLE) != 0);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_add_fd_rejects_duplicate(void) {
    int fds[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct write_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_WRITABLE, on_writable_stop, &ctx), 0);
    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_WRITABLE, on_writable_stop, &ctx), -1);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_mod_fd_changes_interest(void) {
    int fds[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct write_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Register for readable only -- a fresh socket has nothing to read, so
     * if mod_fd didn't actually take effect at the kernel level, run()
     * would block forever (this test would hang) instead of dispatching
     * writable. */
    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_READABLE, on_writable_stop, &ctx), 0);
    ASSERT_EQ_INT(cloak_reactor_mod_fd(r, fds[0], CLOAK_REACTOR_WRITABLE), 0);

    cloak_reactor_run(r);

    ASSERT_TRUE(ctx.fired);
    ASSERT_TRUE((ctx.fired_events & CLOAK_REACTOR_WRITABLE) != 0);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

struct remove_ctx {
    int fire_count;
    int fds[2];
};

static void on_either_removes_other(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)events;
    struct remove_ctx *ctx = (struct remove_ctx *)userdata;
    ctx->fire_count++;
    int other = (fd == ctx->fds[0]) ? ctx->fds[1] : ctx->fds[0];
    cloak_reactor_remove_fd(r, other);
    cloak_reactor_stop(r);
}

static void test_remove_fd_stops_dispatch_in_same_batch(void) {
    int fds_a[2];
    int fds_b[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds_a) == 0);
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds_b) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct remove_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fds[0] = fds_a[0];
    ctx.fds[1] = fds_b[0];

    /* Both fds are writable-armed and both are immediately writable (fresh
     * sockets), so both are ready in the very first epoll_wait batch.
     * Whichever callback runs first removes the other one. If the reactor
     * dispatched from a stale copy of the ready-list without re-checking
     * whether the fd is still registered, fire_count would be 2 instead
     * of 1 -- this doesn't depend on which of the two fires first, so it's
     * deterministic regardless of epoll's (unspecified) ready-list order. */
    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds_a[0], CLOAK_REACTOR_WRITABLE, on_either_removes_other, &ctx), 0);
    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds_b[0], CLOAK_REACTOR_WRITABLE, on_either_removes_other, &ctx), 0);

    cloak_reactor_run(r);

    ASSERT_EQ_INT(ctx.fire_count, 1);

    cloak_reactor_destroy(r);
    close(fds_a[0]);
    close(fds_a[1]);
    close(fds_b[0]);
    close(fds_b[1]);
}

struct remove_no_stop_ctx {
    int fire_count;
    int fds[2];
};

static void on_either_removes_other_no_stop(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)events;
    struct remove_no_stop_ctx *ctx = (struct remove_no_stop_ctx *)userdata;
    ctx->fire_count++;
    int other = (fd == ctx->fds[0]) ? ctx->fds[1] : ctx->fds[0];
    cloak_reactor_remove_fd(r, other);
    /* Deliberately do NOT call cloak_reactor_stop() here, unlike
     * test_remove_fd_stops_dispatch_in_same_batch. Letting the for-loop
     * actually continue past this point is what exercises the
     * tombstone/deferred-free guard against the OTHER fd's stale entry
     * later in the SAME already-fetched events[] array -- a test that
     * stops immediately never reaches that code path. */
}

static void on_order_stop_timeout(cloak_reactor_t *r, void *userdata) {
    (void)userdata;
    cloak_reactor_stop(r);
}

static void test_remove_fd_without_stop_does_not_dispatch_survivor(void) {
    int fds_a[2];
    int fds_b[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds_a) == 0);
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds_b) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct remove_no_stop_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fds[0] = fds_a[0];
    ctx.fds[1] = fds_b[0];

    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds_a[0], CLOAK_REACTOR_WRITABLE, on_either_removes_other_no_stop, &ctx), 0);
    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds_b[0], CLOAK_REACTOR_WRITABLE, on_either_removes_other_no_stop, &ctx), 0);

    /* Nothing calls stop() directly in this test, so bound the loop with a
     * short timer (the reactor already supports timers from Task 2). */
    ASSERT_TRUE(cloak_reactor_add_timer(r, 30, on_order_stop_timeout, NULL) != CLOAK_TIMER_INVALID);

    cloak_reactor_run(r);

    ASSERT_EQ_INT(ctx.fire_count, 1);

    cloak_reactor_destroy(r);
    close(fds_a[0]);
    close(fds_a[1]);
    close(fds_b[0]);
    close(fds_b[1]);
}

static uint64_t test_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

struct timer_fire_ctx {
    int fired;
};

static void on_timer_fire_and_stop(cloak_reactor_t *r, void *userdata) {
    struct timer_fire_ctx *ctx = (struct timer_fire_ctx *)userdata;
    ctx->fired = 1;
    cloak_reactor_stop(r);
}

static void test_timer_fires_after_delay(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct timer_fire_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    uint64_t start = test_now_ms();
    cloak_timer_id_t id = cloak_reactor_add_timer(r, 20, on_timer_fire_and_stop, &ctx);
    ASSERT_TRUE(id != CLOAK_TIMER_INVALID);

    cloak_reactor_run(r);
    uint64_t elapsed = test_now_ms() - start;

    ASSERT_TRUE(ctx.fired);
    ASSERT_TRUE(elapsed >= 15); /* small slack below the 20ms target */
    ASSERT_TRUE(elapsed < 2000); /* generous upper bound: catches a broken timeout computation that blocks forever */

    cloak_reactor_destroy(r);
}

struct cancel_ctx {
    int should_not_fire_flag;
    int stopper_flag;
};

static void on_should_not_fire(cloak_reactor_t *r, void *userdata) {
    (void)r;
    struct cancel_ctx *ctx = (struct cancel_ctx *)userdata;
    ctx->should_not_fire_flag = 1;
}

static void on_stopper(cloak_reactor_t *r, void *userdata) {
    struct cancel_ctx *ctx = (struct cancel_ctx *)userdata;
    ctx->stopper_flag = 1;
    cloak_reactor_stop(r);
}

static void test_cancel_timer_prevents_firing(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct cancel_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    cloak_timer_id_t id = cloak_reactor_add_timer(r, 10, on_should_not_fire, &ctx);
    ASSERT_TRUE(id != CLOAK_TIMER_INVALID);
    cloak_reactor_cancel_timer(r, id);

    ASSERT_TRUE(cloak_reactor_add_timer(r, 20, on_stopper, &ctx) != CLOAK_TIMER_INVALID);

    cloak_reactor_run(r);

    ASSERT_TRUE(ctx.stopper_flag);
    ASSERT_TRUE(!ctx.should_not_fire_flag);

    cloak_reactor_destroy(r);
}

struct order_ctx {
    int log[3];
    int log_len;
};

static void on_order_20ms(cloak_reactor_t *r, void *userdata) {
    (void)r;
    struct order_ctx *ctx = (struct order_ctx *)userdata;
    ctx->log[ctx->log_len++] = 20;
}
static void on_order_60ms(cloak_reactor_t *r, void *userdata) {
    (void)r;
    struct order_ctx *ctx = (struct order_ctx *)userdata;
    ctx->log[ctx->log_len++] = 60;
}
static void on_order_120ms(cloak_reactor_t *r, void *userdata) {
    struct order_ctx *ctx = (struct order_ctx *)userdata;
    ctx->log[ctx->log_len++] = 120;
    cloak_reactor_stop(r);
}

static void test_multiple_timers_fire_in_order(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct order_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Added out of chronological order on purpose, to prove the heap
     * orders by deadline, not insertion order. */
    ASSERT_TRUE(cloak_reactor_add_timer(r, 120, on_order_120ms, &ctx) != CLOAK_TIMER_INVALID);
    ASSERT_TRUE(cloak_reactor_add_timer(r, 20, on_order_20ms, &ctx) != CLOAK_TIMER_INVALID);
    ASSERT_TRUE(cloak_reactor_add_timer(r, 60, on_order_60ms, &ctx) != CLOAK_TIMER_INVALID);

    cloak_reactor_run(r);

    ASSERT_EQ_INT(ctx.log_len, 3);
    ASSERT_EQ_INT(ctx.log[0], 20);
    ASSERT_EQ_INT(ctx.log[1], 60);
    ASSERT_EQ_INT(ctx.log[2], 120);

    cloak_reactor_destroy(r);
}

static void test_add_timer_returns_correct_id_after_sift_up(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct cancel_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* A long-delay timer first, so it starts at the heap root... */
    cloak_timer_id_t id_a = cloak_reactor_add_timer(r, 100000, on_should_not_fire, &ctx);
    /* ...then a short-delay timer, whose insertion must sift up PAST timer A. */
    cloak_timer_id_t id_b = cloak_reactor_add_timer(r, 1, on_should_not_fire, &ctx);

    ASSERT_TRUE(id_a != CLOAK_TIMER_INVALID);
    ASSERT_TRUE(id_b != CLOAK_TIMER_INVALID);
    ASSERT_TRUE(id_a != id_b);
    ASSERT_EQ_INT(id_a, 1);
    ASSERT_EQ_INT(id_b, 2);

    /* Cancelling B by its returned id must not silently cancel A instead. */
    cloak_reactor_cancel_timer(r, id_b);

    cloak_reactor_destroy(r);
}

struct timer_stop_ctx {
    int fire_count;
};

static void on_timer_stop_and_count(cloak_reactor_t *r, void *userdata) {
    struct timer_stop_ctx *ctx = (struct timer_stop_ctx *)userdata;
    ctx->fire_count++;
    cloak_reactor_stop(r);
}

static void test_process_expired_timers_stops_dispatch_in_same_batch(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct timer_stop_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Both timers share the same short delay, so both are already expired
     * by the time process_expired_timers runs. Whichever fires first calls
     * cloak_reactor_stop(); if the timer-dispatch loop didn't honor
     * r->stopped mid-batch, the second (already-expired) timer would also
     * fire before run() returns, making fire_count 2 instead of 1 -- this
     * doesn't depend on which of the two fires first, so it's deterministic
     * regardless of heap tie-break order. */
    ASSERT_TRUE(cloak_reactor_add_timer(r, 5, on_timer_stop_and_count, &ctx) != CLOAK_TIMER_INVALID);
    ASSERT_TRUE(cloak_reactor_add_timer(r, 5, on_timer_stop_and_count, &ctx) != CLOAK_TIMER_INVALID);

    cloak_reactor_run(r);

    ASSERT_EQ_INT(ctx.fire_count, 1);

    cloak_reactor_destroy(r);
}

struct restart_ctx {
    int first_fired;
    int second_fired;
};

static void on_restart_first(cloak_reactor_t *r, void *userdata) {
    struct restart_ctx *ctx = (struct restart_ctx *)userdata;
    ctx->first_fired = 1;
    cloak_reactor_stop(r);
}

static void on_restart_second(cloak_reactor_t *r, void *userdata) {
    struct restart_ctx *ctx = (struct restart_ctx *)userdata;
    ctx->second_fired = 1;
    cloak_reactor_stop(r);
}

static void test_run_can_be_called_again_after_stop(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct restart_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    ASSERT_TRUE(cloak_reactor_add_timer(r, 10, on_restart_first, &ctx) != CLOAK_TIMER_INVALID);
    cloak_reactor_run(r);
    ASSERT_TRUE(ctx.first_fired);

    /* If stopped were stuck at 1 from the first run(), this second call
     * would return immediately without ever dispatching the new timer. */
    ASSERT_TRUE(cloak_reactor_add_timer(r, 10, on_restart_second, &ctx) != CLOAK_TIMER_INVALID);
    cloak_reactor_run(r);
    ASSERT_TRUE(ctx.second_fired);

    cloak_reactor_destroy(r);
}

static void test_add_fd_forces_nonblocking(void) {
    int fds[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_READABLE, on_writable_stop, NULL), 0);

    int flags = fcntl(fds[0], F_GETFL, 0);
    ASSERT_TRUE(flags >= 0);
    ASSERT_TRUE((flags & O_NONBLOCK) != 0);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_add_fd_rejects_invalid_arguments(void) {
    int fds[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    ASSERT_EQ_INT(cloak_reactor_add_fd(r, -1, CLOAK_REACTOR_READABLE, on_writable_stop, NULL), -1);
    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_READABLE, NULL, NULL), -1);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

TEST_MAIN_BEGIN()
    test_add_and_dispatch_readable();
    test_dispatch_writable();
    test_add_fd_rejects_duplicate();
    test_mod_fd_changes_interest();
    test_remove_fd_stops_dispatch_in_same_batch();
    test_remove_fd_without_stop_does_not_dispatch_survivor();
    test_timer_fires_after_delay();
    test_cancel_timer_prevents_firing();
    test_multiple_timers_fire_in_order();
    test_add_timer_returns_correct_id_after_sift_up();
    test_process_expired_timers_stops_dispatch_in_same_batch();
    test_run_can_be_called_again_after_stop();
    test_add_fd_forces_nonblocking();
    test_add_fd_rejects_invalid_arguments();
TEST_MAIN_END()
