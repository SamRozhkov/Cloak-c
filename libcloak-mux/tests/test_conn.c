#include "cloak/conn.h"

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/reactor.h"
#include "test_framework.h"

#define MAX_FRAME_LEN 300u
#define SEND_QUEUE_CAP 4096u

typedef struct {
    uint8_t received[16][512];
    size_t received_len[16];
    int received_count;
    int closed_count;
} conn_harness_t;

static void on_envelope(cloak_conn_t *c, const uint8_t *bytes, size_t len, void *userdata) {
    (void)c;
    conn_harness_t *h = (conn_harness_t *)userdata;
    ASSERT_TRUE(h->received_count < 16);
    memcpy(h->received[h->received_count], bytes, len);
    h->received_len[h->received_count] = len;
    h->received_count++;
}

static void on_closed(cloak_conn_t *c, void *userdata) {
    (void)c;
    conn_harness_t *h = (conn_harness_t *)userdata;
    h->closed_count++;
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

/* Runs the reactor's dispatch loop just long enough to process whatever
 * is currently ready, without blocking indefinitely -- schedules a short
 * timer that stops the reactor, so cloak_reactor_run returns promptly
 * once the current batch of ready fds has been dispatched. */
static void pump_reactor_once(cloak_reactor_t *r) {
    cloak_reactor_add_timer(r, 20, stop_reactor_timer_cb, r);
    cloak_reactor_run(r);
}

static void test_single_envelope_round_trip(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    uint8_t payload[10];
    for (int i = 0; i < 10; i++) payload[i] = (uint8_t)('A' + i);
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), 0);

    /* Read what conn_send just wrote directly off the raw peer fd,
     * confirming the on-wire envelope is exactly [00 0A][payload]. */
    uint8_t wire[64];
    ssize_t n = read(fds[1], wire, sizeof(wire));
    ASSERT_EQ_INT(n, 12);
    ASSERT_EQ_INT(wire[0], 0);
    ASSERT_EQ_INT(wire[1], 10);
    ASSERT_MEM_EQ(wire + 2, payload, 10);

    /* Now the reverse direction: peer writes a raw envelope, conn must
     * parse and dispatch it. */
    uint8_t reply_wire[2 + 5] = {0, 5, 'h', 'e', 'l', 'l', 'o'};
    ASSERT_EQ_INT(write(fds[1], reply_wire, sizeof(reply_wire)), (ssize_t)sizeof(reply_wire));
    pump_reactor_once(r);

    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.received_len[0], 5);
    ASSERT_MEM_EQ(h.received[0], "hello", 5);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_multiple_envelopes_in_one_read(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    uint8_t wire[] = {
        0, 3, 'f', 'o', 'o',
        0, 3, 'b', 'a', 'r',
        0, 4, 'q', 'u', 'u', 'x',
    };
    ASSERT_EQ_INT(write(fds[1], wire, sizeof(wire)), (ssize_t)sizeof(wire));
    pump_reactor_once(r);

    ASSERT_EQ_INT(h.received_count, 3);
    ASSERT_MEM_EQ(h.received[0], "foo", 3);
    ASSERT_MEM_EQ(h.received[1], "bar", 3);
    ASSERT_MEM_EQ(h.received[2], "quux", 4);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_envelope_split_across_many_small_writes(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    uint8_t payload[200];
    for (int i = 0; i < 200; i++) payload[i] = (uint8_t)(i & 0xff);
    uint8_t wire[2 + 200];
    wire[0] = 0;
    wire[1] = 200;
    memcpy(wire + 2, payload, 200);

    size_t off = 0;
    while (off < sizeof(wire)) {
        size_t chunk = 3;
        if (chunk > sizeof(wire) - off) chunk = sizeof(wire) - off;
        ASSERT_EQ_INT(write(fds[1], wire + off, chunk), (ssize_t)chunk);
        off += chunk;
        pump_reactor_once(r);
    }

    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.received_len[0], 200);
    ASSERT_MEM_EQ(h.received[0], payload, 200);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_send_drains_across_epollout_when_kernel_buffer_is_small(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    /* Force a tiny kernel socket buffer on the sending side so a large
     * payload cannot be written in one non-blocking write() call,
     * exercising the EPOLLOUT-driven drain path. */
    int small_buf = 256;
    ASSERT_EQ_INT(setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &small_buf, sizeof(small_buf)), 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    uint8_t big_payload[290];
    for (int i = 0; i < 290; i++) big_payload[i] = (uint8_t)(i & 0xff);
    ASSERT_EQ_INT(cloak_conn_send(&c, big_payload, sizeof(big_payload)), 0);

    /* Drain the peer's read side in a loop, pumping the reactor between
     * reads so cloak_conn_t's EPOLLOUT-driven drain keeps making
     * progress as kernel buffer space frees up. */
    uint8_t assembled[2 + 290];
    size_t assembled_len = 0;
    for (int iter = 0; iter < 50 && assembled_len < sizeof(assembled); iter++) {
        pump_reactor_once(r);
        uint8_t tmp[128];
        ssize_t n;
        while ((n = read(fds[1], tmp, sizeof(tmp))) > 0) {
            ASSERT_TRUE(assembled_len + (size_t)n <= sizeof(assembled));
            memcpy(assembled + assembled_len, tmp, (size_t)n);
            assembled_len += (size_t)n;
        }
    }

    ASSERT_EQ_INT(assembled_len, sizeof(assembled));
    ASSERT_EQ_INT(assembled[0], 1); /* 290 >> 8 */
    ASSERT_EQ_INT(assembled[1], (uint8_t)290);
    ASSERT_MEM_EQ(assembled + 2, big_payload, 290);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_peer_eof_reports_closed(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    close(fds[1]); /* peer hangs up */
    pump_reactor_once(r);

    ASSERT_EQ_INT(h.closed_count, 1);

    /* A send after the conn is marked broken must fail, not crash. */
    uint8_t payload[3] = {1, 2, 3};
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), -1);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
}

static void test_oversized_frame_len_is_rejected_not_wedged(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    /* Declares a frame_len far larger than MAX_FRAME_LEN -- a protocol
     * violation that must mark the connection broken (not silently wait
     * forever for bytes that were never going to arrive validly). */
    uint8_t wire[2] = {0xff, 0xff};
    ASSERT_EQ_INT(write(fds[1], wire, sizeof(wire)), 2);
    pump_reactor_once(r);

    ASSERT_EQ_INT(h.closed_count, 1);
    ASSERT_EQ_INT(h.received_count, 0);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_destroy_after_failed_init_is_safe(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    cloak_conn_t c;
    /* max_frame_len == 0 is rejected. */
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, 0, SEND_QUEUE_CAP, on_envelope, NULL, on_closed, NULL), -1);
    cloak_conn_destroy(&c);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

TEST_MAIN_BEGIN()
    test_single_envelope_round_trip();
    test_multiple_envelopes_in_one_read();
    test_envelope_split_across_many_small_writes();
    test_send_drains_across_epollout_when_kernel_buffer_is_small();
    test_peer_eof_reports_closed();
    test_oversized_frame_len_is_rejected_not_wedged();
    test_destroy_after_failed_init_is_safe();
TEST_MAIN_END()
