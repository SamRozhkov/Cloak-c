#include "cloak/switchboard.h"
#include "cloak/valve.h"

#include <fcntl.h>
#include <stdlib.h>
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
            ASSERT_EQ_INT(n, 10);
            ASSERT_EQ_INT(wire[0], 0x17); /* TLS application-data record */
            ASSERT_EQ_INT(wire[1], 0x03);
            ASSERT_EQ_INT(wire[2], 0x03);
            ASSERT_EQ_INT(wire[3], 0);
            ASSERT_EQ_INT(wire[4], 5);
            ASSERT_MEM_EQ(wire + 5, payload, 5);
        }
    }
    ASSERT_EQ_INT(hits, 1);

    /* Any peer can send back, and it's routed to the switchboard's
     * on_envelope callback regardless of which underlying conn it
     * arrived on. */
    uint8_t reply_wire[5 + 3] = {0x17, 0x03, 0x03, 0, 3, 'h', 'i', '!'};
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

/* ------------------------------------------------------------------ */
/* The TX meter bills the envelope this connection actually emitted    */
/* ------------------------------------------------------------------ */

/* THE DEFECT THIS PINS. cloak_switchboard_send billed
 * CLOAK_CONN_RECORD_HEADER_LEN + frame_len unconditionally -- five bytes
 * of TLS record header regardless of what the connection put on the
 * wire. A WS_SERVER connection emits two bytes below 126 and four at or
 * above it, so an interactive ~30-byte frame was over-charged by about
 * 8.6% (88 MiB per charged GiB) and a 16401-byte bulk frame in the
 * CLIENT direction under-charged by about 0.018% (3 bytes of mask key in
 * 16409 -- 196 kB per GiB). Over-charging a metered user is a real
 * defect, not a rounding difference, and a valve's counter is what bills
 * their credit.
 *
 * THESE CASES LIVE HERE, next to cloak_switchboard_send and
 * cloak_conn_envelope_len, and not in the server suite where the CDN
 * transport that made the defect live is tested: a regression in the
 * envelope arithmetic has to be visible to someone editing libcloak-mux
 * and running only libcloak-mux's tests.
 *
 * THE BRACKET IS MEASURED IN BOTH MODES AND ACROSS THE 125/126
 * BOUNDARY, where the WebSocket extended-length form appears -- a fix
 * that hardcoded "2" instead of consulting the framing would pass at 30
 * bytes and fail at 200, and a fix that kept the TLS constant fails
 * everywhere on the CDN side.
 *
 * A socketpair, not a loopback socket: this measures what the SENDER
 * billed, and no reactor turn is needed for cloak_conn_send to have
 * enqueued (and, at these sizes, written) the bytes. */
typedef struct {
    int seen;
} sb_sink_t;

static void sb_on_envelope(cloak_switchboard_t *sb, const uint8_t *bytes, size_t len,
                           void *userdata) {
    (void)sb;
    (void)bytes;
    (void)len;
    sb_sink_t *s = userdata;
    s->seen++;
}

static void sb_on_broken(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    (void)userdata;
}

/* Sends one frame of frame_len bytes through a switchboard holding a
 * single connection in `framing`, and returns what the valve was
 * charged. */
static int64_t billed_for(cloak_reactor_t *r, cloak_conn_framing_t framing, size_t frame_len) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        ASSERT_TRUE(0);
        return -1;
    }

    sb_sink_t sink = {0};
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(0, cloak_switchboard_init(&sb, r, 16401, 262144, sb_on_envelope, &sink,
                                            sb_on_broken, NULL));
    ASSERT_EQ_INT(0, cloak_switchboard_add_conn_framed(&sb, sv[0], framing));

    cloak_valve_t valve;
    memset(&valve, 0, sizeof(valve));
    cloak_switchboard_set_valve(&sb, &valve);

    uint8_t *frame = malloc(frame_len);
    ASSERT_TRUE(frame != NULL);
    if (frame == NULL) {
        cloak_switchboard_destroy(&sb);
        close(sv[1]);
        return -1;
    }
    memset(frame, 0x5a, frame_len);
    ASSERT_EQ_INT(0, cloak_switchboard_send(&sb, frame, frame_len));
    free(frame);

    int64_t billed = cloak_valve_tx(&valve);

    /* The valve must not outlive the pool that points at it. */
    cloak_switchboard_set_valve(&sb, NULL);
    cloak_switchboard_destroy(&sb);
    close(sv[1]);
    return billed;
}

static void test_tx_meter_bills_the_real_envelope(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    /* The TLS path is unchanged and is asserted so, because a fix that
     * broke it would be a silent under-count on every existing
     * deployment. 5 + n, at every size. */
    ASSERT_EQ_INT(35, (int)billed_for(r, CLOAK_CONN_FRAMING_TLS_RECORD, 30));
    ASSERT_EQ_INT(130, (int)billed_for(r, CLOAK_CONN_FRAMING_TLS_RECORD, 125));
    ASSERT_EQ_INT(131, (int)billed_for(r, CLOAK_CONN_FRAMING_TLS_RECORD, 126));
    ASSERT_EQ_INT(205, (int)billed_for(r, CLOAK_CONN_FRAMING_TLS_RECORD, 200));
    ASSERT_EQ_INT(16406, (int)billed_for(r, CLOAK_CONN_FRAMING_TLS_RECORD, 16401));

    /* The CDN server direction: two header bytes below 126, four at or
     * above it, and never a mask key -- RFC 6455 section 5.1 forbids a
     * server masking. */
    ASSERT_EQ_INT(32, (int)billed_for(r, CLOAK_CONN_FRAMING_WS_SERVER, 30));
    ASSERT_EQ_INT(127, (int)billed_for(r, CLOAK_CONN_FRAMING_WS_SERVER, 125));
    ASSERT_EQ_INT(130, (int)billed_for(r, CLOAK_CONN_FRAMING_WS_SERVER, 126));
    ASSERT_EQ_INT(204, (int)billed_for(r, CLOAK_CONN_FRAMING_WS_SERVER, 200));
    ASSERT_EQ_INT(16405, (int)billed_for(r, CLOAK_CONN_FRAMING_WS_SERVER, 16401));

    /* The CDN client direction, which this port also builds (the ck-client
     * side of the same transport): four more bytes of mask key, which is
     * why its envelope is the LARGEST of the three and not the smallest. */
    ASSERT_EQ_INT(36, (int)billed_for(r, CLOAK_CONN_FRAMING_WS_CLIENT, 30));
    ASSERT_EQ_INT(131, (int)billed_for(r, CLOAK_CONN_FRAMING_WS_CLIENT, 125));
    ASSERT_EQ_INT(134, (int)billed_for(r, CLOAK_CONN_FRAMING_WS_CLIENT, 126));
    ASSERT_EQ_INT(208, (int)billed_for(r, CLOAK_CONN_FRAMING_WS_CLIENT, 200));
    ASSERT_EQ_INT(16409, (int)billed_for(r, CLOAK_CONN_FRAMING_WS_CLIENT, 16401));

    cloak_reactor_destroy(r);
}

/* The over-charge the fix removes, stated as the arithmetic an operator
 * would do, so that a future change which quietly reintroduces the flat
 * +5 fails with a number rather than with a diff. */
static void test_tx_meter_overcharge_is_gone(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    /* The switchboard's own comment uses a ~30-byte interactive frame.
     * The flat +5 billed 35 for what a WS_SERVER conn puts 32 bytes of
     * on the wire: 3 bytes in 32, i.e. 9.4% of the true figure and 8.6%
     * of the charged one. */
    int64_t ws30 = billed_for(r, CLOAK_CONN_FRAMING_WS_SERVER, 30);
    ASSERT_EQ_INT(32, (int)ws30);
    ASSERT_TRUE(ws30 != 35);

    /* And the bulk end, where the old figure was too SMALL: a 16401-byte
     * frame costs 16405 on the wire, not 16406. */
    int64_t ws_bulk = billed_for(r, CLOAK_CONN_FRAMING_WS_SERVER, 16401);
    ASSERT_EQ_INT(16405, (int)ws_bulk);
    ASSERT_TRUE(ws_bulk != 16406);

    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_send_reaches_one_of_the_pool_and_receives_back();
    test_distribution_hits_every_connection_over_many_sends();
    test_any_connection_failure_breaks_whole_switchboard();
    test_send_with_zero_connections_fails_cleanly();
    test_close_all_closes_every_fd_and_empties_pool();
    test_tx_meter_bills_the_real_envelope();
    test_tx_meter_overcharge_is_gone();
TEST_MAIN_END()
