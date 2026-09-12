#define _POSIX_C_SOURCE 200809L
#include "cloak/conn.h"
#include "cloak/switchboard.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* A socketpair whose receiving end is never read, so the sender's kernel
 * buffer fills and conn's own send_q starts accumulating -- the state
 * this task is about. */
struct pair {
    int local;
    int peer;
};

static int pair_init(struct pair *p) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return -1;
    }
    p->local = fds[0];
    p->peer = fds[1];
    return 0;
}

static void on_envelope_ignore(cloak_conn_t *c, const uint8_t *bytes, size_t len, void *ud) {
    (void)c;
    (void)bytes;
    (void)len;
    (void)ud;
}

static void on_closed_ignore(cloak_conn_t *c, void *ud) {
    (void)c;
    (void)ud;
}

struct drain_capture {
    int calls;
};

static void on_drained(cloak_conn_t *c, void *userdata) {
    (void)c;
    struct drain_capture *cap = userdata;
    cap->calls++;
}

static void test_conn_reports_queue_depth(void) {
    struct pair p;
    ASSERT_EQ_INT(0, pair_init(&p));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_conn_t c;
    ASSERT_EQ_INT(0, cloak_conn_init(&c, p.local, r, 4096, 65536,
                                     on_envelope_ignore, NULL, on_closed_ignore, NULL));

    ASSERT_EQ_INT(65536, (int)cloak_conn_send_capacity(&c));
    ASSERT_EQ_INT(0, (int)cloak_conn_send_queued(&c));

    /* Push until the kernel stops accepting and send_q starts holding
     * bytes. A 4 KiB frame at a time keeps this well under the cap. */
    uint8_t frame[4096];
    memset(frame, 'x', sizeof(frame));
    int sends = 0;
    while (cloak_conn_send_queued(&c) == 0 && sends < 64) {
        ASSERT_EQ_INT(0, cloak_conn_send(&c, frame, sizeof(frame)));
        sends++;
    }
    ASSERT_TRUE(cloak_conn_send_queued(&c) > 0);
    ASSERT_TRUE(cloak_conn_send_queued(&c) <= cloak_conn_send_capacity(&c));

    cloak_conn_destroy(&c);
    close(p.peer);
    cloak_reactor_destroy(r);
}

static void test_conn_fires_drained_on_the_transition(void) {
    struct pair p;
    ASSERT_EQ_INT(0, pair_init(&p));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_conn_t c;
    ASSERT_EQ_INT(0, cloak_conn_init(&c, p.local, r, 4096, 65536,
                                     on_envelope_ignore, NULL, on_closed_ignore, NULL));

    struct drain_capture cap;
    memset(&cap, 0, sizeof(cap));
    cloak_conn_set_drained_cb(&c, on_drained, &cap);

    uint8_t frame[4096];
    memset(frame, 'y', sizeof(frame));

    /* A send that the kernel swallows whole never queues anything, so it
     * must not fire the callback -- the callback marks a transition from
     * queued to empty, not "a write happened". */
    ASSERT_EQ_INT(0, cloak_conn_send(&c, frame, sizeof(frame)));
    ASSERT_EQ_INT(0, cap.calls);

    /* Fill until bytes are genuinely queued. */
    int sends = 0;
    while (cloak_conn_send_queued(&c) == 0 && sends < 64) {
        ASSERT_EQ_INT(0, cloak_conn_send(&c, frame, sizeof(frame)));
        sends++;
    }
    ASSERT_TRUE(cloak_conn_send_queued(&c) > 0);
    ASSERT_EQ_INT(0, cap.calls);

    /* Drain the peer so the kernel accepts the backlog, then turn the
     * reactor until the queue empties. */
    uint8_t sink[8192];
    for (int spin = 0; spin < 10000 && cloak_conn_send_queued(&c) > 0; spin++) {
        ssize_t n = read(p.peer, sink, sizeof(sink));
        (void)n;
        cloak_reactor_run_once(r, 10);
    }

    ASSERT_EQ_INT(0, (int)cloak_conn_send_queued(&c));
    ASSERT_EQ_INT(1, cap.calls);

    cloak_conn_destroy(&c);
    close(p.peer);
    cloak_reactor_destroy(r);
}

struct sb_drain_capture {
    int calls;
};

static void on_sb_envelope(cloak_switchboard_t *sb, const uint8_t *bytes, size_t len, void *ud) {
    (void)sb;
    (void)bytes;
    (void)len;
    (void)ud;
}

static void on_sb_broken(cloak_switchboard_t *sb, void *ud) {
    (void)sb;
    (void)ud;
}

static void on_sb_drained(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    struct sb_drain_capture *cap = userdata;
    cap->calls++;
}

static void test_switchboard_aggregates_and_forwards(void) {
    struct pair p1;
    struct pair p2;
    ASSERT_EQ_INT(0, pair_init(&p1));
    ASSERT_EQ_INT(0, pair_init(&p2));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_switchboard_t sb;
    ASSERT_EQ_INT(0, cloak_switchboard_init(&sb, r, 4096, 65536,
                                            on_sb_envelope, NULL, on_sb_broken, NULL));

    struct sb_drain_capture cap;
    memset(&cap, 0, sizeof(cap));
    cloak_switchboard_set_drained_cb(&sb, on_sb_drained, &cap);

    ASSERT_EQ_INT(0, cloak_switchboard_add_conn(&sb, p1.local));
    ASSERT_EQ_INT(0, cloak_switchboard_add_conn(&sb, p2.local));

    /* Capacity is the sum over the pool; nothing is queued yet. */
    ASSERT_EQ_INT(2 * 65536, (int)cloak_switchboard_send_capacity(&sb));
    ASSERT_EQ_INT(0, (int)cloak_switchboard_send_queued(&sb));

    uint8_t frame[4096];
    memset(frame, 'z', sizeof(frame));
    int sends = 0;
    while (cloak_switchboard_send_queued(&sb) == 0 && sends < 128) {
        ASSERT_EQ_INT(0, cloak_switchboard_send(&sb, frame, sizeof(frame)));
        sends++;
    }
    ASSERT_TRUE(cloak_switchboard_send_queued(&sb) > 0);

    uint8_t sink[8192];
    for (int spin = 0; spin < 20000 && cloak_switchboard_send_queued(&sb) > 0; spin++) {
        (void)read(p1.peer, sink, sizeof(sink));
        (void)read(p2.peer, sink, sizeof(sink));
        cloak_reactor_run_once(r, 10);
    }

    ASSERT_EQ_INT(0, (int)cloak_switchboard_send_queued(&sb));
    ASSERT_TRUE(cap.calls >= 1);

    cloak_switchboard_destroy(&sb);
    close(p1.peer);
    close(p2.peer);
    cloak_reactor_destroy(r);
}

static void test_accessors_tolerate_empty_pool(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(0, cloak_switchboard_init(&sb, r, 4096, 65536,
                                            on_sb_envelope, NULL, on_sb_broken, NULL));
    ASSERT_EQ_INT(0, (int)cloak_switchboard_send_queued(&sb));
    ASSERT_EQ_INT(0, (int)cloak_switchboard_send_capacity(&sb));
    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_conn_reports_queue_depth();
    test_conn_fires_drained_on_the_transition();
    test_switchboard_aggregates_and_forwards();
    test_accessors_tolerate_empty_pool();
TEST_MAIN_END()
