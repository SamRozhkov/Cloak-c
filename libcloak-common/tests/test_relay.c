#define _POSIX_C_SOURCE 200809L
#include "cloak/net.h"
#include "test_framework.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct done_capture {
    cloak_reactor_t *reactor;
    int calls;
};

static void on_done(cloak_relay_t *rl, void *userdata) {
    (void)rl;
    struct done_capture *cap = userdata;
    cap->calls++;
    cloak_reactor_stop(cap->reactor);
}

/* Builds two socketpairs and relays between their inner ends, so a test
 * can write on outer_a and read what arrives on outer_b. */
struct harness {
    int outer_a;
    int outer_b;
    int inner_a;
    int inner_b;
};

static int harness_init(struct harness *h) {
    int pa[2];
    int pb[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pa) != 0) {
        return -1;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pb) != 0) {
        close(pa[0]);
        close(pa[1]);
        return -1;
    }
    h->outer_a = pa[0];
    h->inner_a = pa[1];
    h->outer_b = pb[0];
    h->inner_b = pb[1];
    return 0;
}

static void test_forwards_both_directions(void) {
    struct harness h;
    int h_ok = harness_init(&h);
    ASSERT_EQ_INT(0, h_ok);
    if (h_ok != 0) {
        return;
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;

    cloak_relay_t rl;
    ASSERT_EQ_INT(0, cloak_relay_start(&rl, r, h.inner_a, h.inner_b, NULL, 0, 4096,
                                       on_done, &cap));

    ASSERT_TRUE(write(h.outer_a, "ping", 4) == 4);
    ASSERT_TRUE(write(h.outer_b, "pong!!", 6) == 6);

    /* Close both outer ends so the relay sees EOF and finishes, ending the
     * reactor loop through on_done. */
    shutdown(h.outer_a, SHUT_WR);

    cloak_reactor_run(r);
    ASSERT_EQ_INT(1, cap.calls);

    char buf[16];
    memset(buf, 0, sizeof(buf));
    ssize_t n = read(h.outer_b, buf, sizeof(buf));
    ASSERT_TRUE(n >= 4);
    ASSERT_MEM_EQ(buf, "ping", 4);

    memset(buf, 0, sizeof(buf));
    n = read(h.outer_a, buf, sizeof(buf));
    ASSERT_TRUE(n >= 6);
    ASSERT_MEM_EQ(buf, "pong!!", 6);

    close(h.outer_a);
    close(h.outer_b);
    cloak_reactor_destroy(r);
}

static void test_preload_is_delivered_first(void) {
    /* goWeb's shape: the first packet was already read off fd_a before the
     * relay existed, and must reach fd_b ahead of anything else. */
    struct harness h;
    int h_ok = harness_init(&h);
    ASSERT_EQ_INT(0, h_ok);
    if (h_ok != 0) {
        return;
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;

    const uint8_t preload[] = "GET / HTTP/1.1\r\n";
    cloak_relay_t rl;
    ASSERT_EQ_INT(0, cloak_relay_start(&rl, r, h.inner_a, h.inner_b, preload,
                                       sizeof(preload) - 1, 4096, on_done, &cap));

    ASSERT_TRUE(write(h.outer_a, "rest", 4) == 4);
    shutdown(h.outer_a, SHUT_WR);

    cloak_reactor_run(r);
    ASSERT_EQ_INT(1, cap.calls);

    char buf[64];
    memset(buf, 0, sizeof(buf));
    ssize_t n = read(h.outer_b, buf, sizeof(buf));
    ASSERT_TRUE(n == (ssize_t)(sizeof(preload) - 1 + 4));
    ASSERT_MEM_EQ(buf, "GET / HTTP/1.1\r\nrest", sizeof(preload) - 1 + 4);

    close(h.outer_a);
    close(h.outer_b);
    cloak_reactor_destroy(r);
}

static void test_large_transfer_survives_backpressure(void) {
    /* The payload is far larger than the relay's buffer and larger than
     * the socket buffers, so this only completes if the relay correctly
     * deregisters and re-arms read interest as its queues fill and drain. */
    struct harness h;
    int h_ok = harness_init(&h);
    ASSERT_EQ_INT(0, h_ok);
    if (h_ok != 0) {
        return;
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;

    cloak_relay_t rl;
    ASSERT_EQ_INT(0, cloak_relay_start(&rl, r, h.inner_a, h.inner_b, NULL, 0, 4096,
                                       on_done, &cap));

    const size_t total = 512 * 1024;
    uint8_t *sent = malloc(total);
    ASSERT_TRUE(sent != NULL);
    if (sent == NULL) {
        return;
    }
    for (size_t i = 0; i < total; i++) {
        sent[i] = (uint8_t)(i * 31 + (i >> 8));
    }

    /* Feed and drain from the same loop: a blocking write of the whole
     * payload would deadlock against a relay that is not running yet. */
    size_t written = 0;
    size_t received = 0;
    uint8_t *got = malloc(total);
    ASSERT_TRUE(got != NULL);
    if (got == NULL) {
        free(sent);
        return;
    }

    int flags_a = fcntl(h.outer_a, F_GETFL, 0);
    fcntl(h.outer_a, F_SETFL, flags_a | O_NONBLOCK);
    int flags_b = fcntl(h.outer_b, F_GETFL, 0);
    fcntl(h.outer_b, F_SETFL, flags_b | O_NONBLOCK);

    /* Pump: alternate between pushing into the relay, letting the reactor
     * turn once, and draining the far end. */
    for (int spin = 0; spin < 100000 && received < total; spin++) {
        if (written < total) {
            ssize_t n = write(h.outer_a, sent + written, total - written);
            if (n > 0) {
                written += (size_t)n;
                if (written == total) {
                    shutdown(h.outer_a, SHUT_WR);
                }
            }
        }
        cloak_reactor_run_once(r, 10);
        for (;;) {
            ssize_t n = read(h.outer_b, got + received, total - received);
            if (n <= 0) {
                break;
            }
            received += (size_t)n;
            if (received == total) {
                break;
            }
        }
    }

    ASSERT_EQ_INT((long long)total, (long long)received);
    ASSERT_MEM_EQ(sent, got, total);

    free(sent);
    free(got);
    close(h.outer_a);
    close(h.outer_b);
    cloak_relay_stop(&rl);
    cloak_reactor_destroy(r);
}

static void test_stop_is_idempotent_and_suppresses_done(void) {
    struct harness h;
    int h_ok = harness_init(&h);
    ASSERT_EQ_INT(0, h_ok);
    if (h_ok != 0) {
        return;
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;

    cloak_relay_t rl;
    ASSERT_EQ_INT(0, cloak_relay_start(&rl, r, h.inner_a, h.inner_b, NULL, 0, 4096,
                                       on_done, &cap));
    cloak_relay_stop(&rl);
    cloak_relay_stop(&rl);
    ASSERT_EQ_INT(0, cap.calls);

    close(h.outer_a);
    close(h.outer_b);
    cloak_reactor_destroy(r);
}

static void test_start_rejects_oversized_preload(void) {
    struct harness h;
    int h_ok = harness_init(&h);
    ASSERT_EQ_INT(0, h_ok);
    if (h_ok != 0) {
        return;
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    uint8_t big[512];
    memset(big, 'x', sizeof(big));
    cloak_relay_t rl;
    ASSERT_EQ_INT(-1, cloak_relay_start(&rl, r, h.inner_a, h.inner_b, big, sizeof(big),
                                        256, on_done, NULL));

    close(h.inner_a);
    close(h.inner_b);
    close(h.outer_a);
    close(h.outer_b);
    cloak_reactor_destroy(r);
}

static void test_stop_after_failed_start_is_safe(void) {
    /* The struct must be deliberately dirtied first: a freshly-declared or
     * previously-zeroed cloak_relay_t would pass this test whether or not
     * cloak_relay_start actually re-initializes it on every failure path,
     * which is exactly the class of test that would have missed this bug. */
    struct harness h;
    int h_ok = harness_init(&h);
    ASSERT_EQ_INT(0, h_ok);
    if (h_ok != 0) {
        return;
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    uint8_t big[512];
    memset(big, 'x', sizeof(big));

    cloak_relay_t dirty;
    memset(&dirty, 0xAA, sizeof(dirty));

    /* preload_len > buf_cap is rejected after the rl == NULL check, so by
     * the time this returns, rl must already have been reset to the state
     * cloak_relay_stop expects -- not only on a path that reaches the end
     * of the function successfully. */
    ASSERT_EQ_INT(-1, cloak_relay_start(&dirty, r, h.inner_a, h.inner_b, big,
                                        sizeof(big), 256, on_done, NULL));
    /* The direct assertions are the real regression signal: before the fix,
     * this validation ran before the memset/sentinel-init, so dirty.fd[]
     * would still hold 0xAAAAAAAA here, not -1 -- these two asserts fail
     * against that ordering even though 0xAAAAAAAA happens to also be
     * negative as a signed int, which is why calling cloak_relay_stop on it
     * would not itself have been guaranteed to crash in this particular
     * byte pattern (relay_close_fds's `fd >= 0` guard short-circuits on any
     * negative value, coincidentally including this garbage). A genuinely
     * zeroed struct (fd == 0, not negative) is the pattern that crashes;
     * these assertions catch the underlying ordering bug regardless of
     * which garbage pattern is used to prove it. */
    ASSERT_EQ_INT(-1, dirty.fd[0]);
    ASSERT_EQ_INT(-1, dirty.fd[1]);

    /* Must not crash either way. */
    cloak_relay_stop(&dirty);

    close(h.inner_a);
    close(h.inner_b);
    close(h.outer_a);
    close(h.outer_b);
    cloak_reactor_destroy(r);
}

static void test_zero_mask_backpressure_does_not_spin(void) {
    /* Regression test for the critical busy-spin finding: desired_interest
     * legitimately returns 0 when q[i] (the source's queue) is full and
     * q[1-i] (the destination's) is empty -- ordinary backpressure. Before
     * the fix, sync_interest re-issued epoll_ctl(MOD) with that same 0
     * mask on every single dispatch regardless, and on an edge-triggered
     * fd a MOD re-probes current readiness and redelivers a fresh edge if
     * it still holds. The kernel reports EPOLLERR/EPOLLHUP on every probe
     * REGARDLESS of the registered mask, so once the source is RST or
     * closed, that 0-mask MOD loop rediscovers the same HUP forever:
     * pump_read can't even tell (room == 0 makes it return before ever
     * calling read()), so the relay never tears down and the reactor
     * spins at 100% CPU on a single connection, forever. */
    struct harness h;
    int h_ok = harness_init(&h);
    ASSERT_EQ_INT(0, h_ok);
    if (h_ok != 0) {
        return;
    }

    /* Simulate "the destination stops reading": fill inner_b's kernel
     * send buffer completely before the relay ever touches it, so nothing
     * the relay writes to it can ever be accepted. */
    int flags = fcntl(h.inner_b, F_GETFL, 0);
    ASSERT_TRUE(flags >= 0);
    ASSERT_EQ_INT(0, fcntl(h.inner_b, F_SETFL, flags | O_NONBLOCK));
    uint8_t filler[4096];
    memset(filler, 'z', sizeof(filler));
    int inner_b_full = 0;
    for (int i = 0; i < 4096; i++) {
        ssize_t n = write(h.inner_b, filler, sizeof(filler));
        if (n < 0) {
            ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
            inner_b_full = 1;
            break;
        }
    }
    ASSERT_TRUE(inner_b_full);
    if (!inner_b_full) {
        close(h.inner_a);
        close(h.inner_b);
        close(h.outer_a);
        close(h.outer_b);
        return;
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        close(h.inner_a);
        close(h.inner_b);
        close(h.outer_a);
        close(h.outer_b);
        return;
    }

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;

    cloak_relay_t rl;
    const size_t buf_cap = 64;
    ASSERT_EQ_INT(0, cloak_relay_start(&rl, r, h.inner_a, h.inner_b, NULL, 0, buf_cap,
                                       on_done, &cap));

    /* More than buf_cap bytes, so a single read edge fills q[0] to
     * capacity (desired_interest(rl, 0)'s READABLE bit drops) while q[1]
     * stays empty (its WRITABLE bit was never set) -- exactly the 0-mask
     * state the finding describes for fd[0]. pump_write cannot drain any
     * of it because inner_b's kernel buffer is already full. */
    uint8_t payload[256];
    memset(payload, 'p', sizeof(payload));
    ASSERT_TRUE(write(h.outer_a, payload, sizeof(payload)) == (ssize_t)sizeof(payload));

    /* Let the relay read the payload, fill q[0], discover it can't drain
     * to fd[1], and (with the fix) register fd[0] with a 0 mask. */
    ASSERT_TRUE(cloak_reactor_run_once(r, 0) >= 0);

    /* Sever the source. inner_a's peer now sees a fully-closed socket, so
     * epoll reports HUP on it on the next wait -- regardless of fd[0]'s
     * now-empty registered mask. */
    close(h.outer_a);

    int dispatched[4];
    for (int i = 0; i < 4; i++) {
        dispatched[i] = cloak_reactor_run_once(r, 0);
        ASSERT_TRUE(dispatched[i] >= 0);
    }

    /* The first post-close turn is expected to discover the HUP once --
     * that much is unavoidable and correct either way. Every turn after
     * that must dispatch nothing: with the fix, fd[0]'s 0 mask is never
     * re-issued once it stops changing, so there is no reprobe left to
     * redeliver the HUP. Before the fix, every one of these would come
     * back positive instead, forever -- reverting the sync_interest change
     * and re-running this test reproduces exactly that spin. */
    ASSERT_TRUE(dispatched[0] > 0);
    ASSERT_EQ_INT(0, dispatched[1]);
    ASSERT_EQ_INT(0, dispatched[2]);
    ASSERT_EQ_INT(0, dispatched[3]);

    /* The relay never discovered the error (pump_read never got far
     * enough to call read() while the queue was full), so it is still
     * "running" from its own point of view -- tear it down explicitly
     * instead of leaking fds. */
    cloak_relay_stop(&rl);
    close(h.outer_b);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_forwards_both_directions();
    test_preload_is_delivered_first();
    test_large_transfer_survives_backpressure();
    test_stop_is_idempotent_and_suppresses_done();
    test_start_rejects_oversized_preload();
    test_stop_after_failed_start_is_safe();
    test_zero_mask_backpressure_does_not_spin();
TEST_MAIN_END()
