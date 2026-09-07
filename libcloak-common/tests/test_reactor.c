#include "cloak/reactor.h"
#include "test_framework.h"

#include <string.h>
#include <sys/socket.h>
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

TEST_MAIN_BEGIN()
    test_add_and_dispatch_readable();
    test_dispatch_writable();
    test_add_fd_rejects_duplicate();
    test_mod_fd_changes_interest();
    test_remove_fd_stops_dispatch_in_same_batch();
TEST_MAIN_END()
