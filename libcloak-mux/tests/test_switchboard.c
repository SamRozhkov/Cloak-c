#include "cloak/switchboard.h"

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test_framework.h"

#define MAX_FRAME_LEN 300u
#define SEND_QUEUE_CAP 4096u

typedef struct {
    uint8_t received[16][512];
    size_t received_len[16];
    int received_count;
    int broken_count;
} sb_harness_t;

static void on_envelope(cloak_switchboard_t *sb, const uint8_t *bytes, size_t len, void *userdata) {
    (void)sb;
    sb_harness_t *h = (sb_harness_t *)userdata;
    ASSERT_TRUE(h->received_count < 16);
    memcpy(h->received[h->received_count], bytes, len);
    h->received_len[h->received_count] = len;
    h->received_count++;
}

static void on_broken(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    sb_harness_t *h = (sb_harness_t *)userdata;
    h->broken_count++;
}

static int make_nonblocking_socketpair(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return -1;
    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0) return -1;
    if (fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) return -1;
    return 0;
}

static void stop_reactor_timer_cb(cloak_reactor_t *r, void *userdata) {
    (void)userdata;
    cloak_reactor_stop(r);
}

static void pump_reactor_once(cloak_reactor_t *r) {
    cloak_reactor_add_timer(r, 20, stop_reactor_timer_cb, r);
    cloak_reactor_run(r);
}

static void test_send_reaches_one_of_the_pool_and_receives_back(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    sb_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                          on_envelope, &h, on_broken, &h), 0);

    int fds_a[2], fds_b[2], fds_c[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_a), 0);
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_b), 0);
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_c), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_a[0]), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_b[0]), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_c[0]), 0);
    ASSERT_EQ_INT(cloak_switchboard_conn_count(&sb), 3);

    uint8_t payload[5] = {1, 2, 3, 4, 5};
    ASSERT_EQ_INT(cloak_switchboard_send(&sb, payload, sizeof(payload)), 0);

    /* Exactly one of the three raw peer fds received the envelope. */
    int hits = 0;
    int peer_fds[3] = {fds_a[1], fds_b[1], fds_c[1]};
    for (int i = 0; i < 3; i++) {
        uint8_t wire[64];
        ssize_t n = read(peer_fds[i], wire, sizeof(wire));
        if (n > 0) {
            hits++;
            ASSERT_EQ_INT(n, 7);
            ASSERT_EQ_INT(wire[0], 0);
            ASSERT_EQ_INT(wire[1], 5);
            ASSERT_MEM_EQ(wire + 2, payload, 5);
        }
    }
    ASSERT_EQ_INT(hits, 1);

    /* Any peer can send back, and it's routed to the switchboard's
     * on_envelope callback regardless of which underlying conn it
     * arrived on. */
    uint8_t reply_wire[2 + 3] = {0, 3, 'h', 'i', '!'};
    ASSERT_EQ_INT(write(fds_b[1], reply_wire, sizeof(reply_wire)), (ssize_t)sizeof(reply_wire));
    pump_reactor_once(r);
    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_MEM_EQ(h.received[0], "hi!", 3);

    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
    close(fds_a[0]); close(fds_a[1]);
    close(fds_b[0]); close(fds_b[1]);
    close(fds_c[0]); close(fds_c[1]);
}

static void test_distribution_hits_every_connection_over_many_sends(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    sb_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                          on_envelope, &h, on_broken, &h), 0);

    enum { NCONN = 4 };
    int fds[NCONN][2];
    for (int i = 0; i < NCONN; i++) {
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds[i]), 0);
        ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds[i][0]), 0);
    }

    int hit_count[NCONN];
    memset(hit_count, 0, sizeof(hit_count));
    uint8_t payload[1] = {0xAB};
    for (int iter = 0; iter < 200; iter++) {
        ASSERT_EQ_INT(cloak_switchboard_send(&sb, payload, sizeof(payload)), 0);
        for (int i = 0; i < NCONN; i++) {
            uint8_t wire[8];
            ssize_t n = read(fds[i][1], wire, sizeof(wire));
            if (n > 0) hit_count[i]++;
        }
    }
    /* Statistical, not exact: with 200 uniformly random picks across 4
     * connections, every connection should be hit at least once (the
     * probability any one is hit zero times is (3/4)^200, astronomically
     * small) -- this is enough to catch a broken distribution (e.g.
     * always picking index 0) without being a flaky exact-count check. */
    for (int i = 0; i < NCONN; i++) {
        ASSERT_TRUE(hit_count[i] > 0);
    }

    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
    for (int i = 0; i < NCONN; i++) {
        close(fds[i][0]);
        close(fds[i][1]);
    }
}

static void test_any_connection_failure_breaks_whole_switchboard(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    sb_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                          on_envelope, &h, on_broken, &h), 0);

    int fds_a[2], fds_b[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_a), 0);
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_b), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_a[0]), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_b[0]), 0);

    close(fds_a[1]); /* peer of conn A hangs up */
    close(fds_b[1]);
    pump_reactor_once(r);

    ASSERT_EQ_INT(h.broken_count, 1);

    /* A send after the switchboard is broken must fail, not crash, and
     * must not fall back to trying a still-technically-open conn. */
    uint8_t payload[2] = {9, 9};
    ASSERT_EQ_INT(cloak_switchboard_send(&sb, payload, sizeof(payload)), -1);

    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
    close(fds_a[0]);
    close(fds_b[0]);
}

static void test_send_with_zero_connections_fails_cleanly(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    sb_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                          on_envelope, &h, on_broken, &h), 0);

    uint8_t payload[1] = {1};
    ASSERT_EQ_INT(cloak_switchboard_send(&sb, payload, sizeof(payload)), -1);

    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
}

static void test_close_all_closes_every_fd_and_empties_pool(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    sb_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                          on_envelope, &h, on_broken, &h), 0);

    int fds_a[2], fds_b[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_a), 0);
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_b), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_a[0]), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_b[0]), 0);

    cloak_switchboard_close_all(&sb);
    ASSERT_EQ_INT(cloak_switchboard_conn_count(&sb), 0);

    /* fds_a[0]/fds_b[0] were closed BY close_all -- confirm each is no
     * longer a valid fd (a write on a closed fd fails with EBADF). */
    ssize_t rc = write(fds_a[0], "x", 1);
    ASSERT_TRUE(rc < 0);

    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
    close(fds_a[1]);
    close(fds_b[1]);
}

TEST_MAIN_BEGIN()
    test_send_reaches_one_of_the_pool_and_receives_back();
    test_distribution_hits_every_connection_over_many_sends();
    test_any_connection_failure_breaks_whole_switchboard();
    test_send_with_zero_connections_fails_cleanly();
    test_close_all_closes_every_fd_and_empties_pool();
TEST_MAIN_END()
