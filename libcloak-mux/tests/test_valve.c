#include "cloak/valve.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/common.h"
#include "cloak/conn.h"
#include "cloak/frame.h"
#include "cloak/session.h"
#include "test_framework.h"

#define MAX_ON_WIRE 2048u
#define STREAM_RECV_CAP 65536u
#define STREAM_MAX_PENDING 64u
#define CONN_SEND_QUEUE_CAP 65536u

/* ------------------------------------------------------------------ */
/* 1. add / read / nullify arithmetic                                  */
/* ------------------------------------------------------------------ */

static void test_arithmetic(void) {
    cloak_valve_t v;
    memset(&v, 0, sizeof(v));

    ASSERT_EQ_INT(cloak_valve_rx(&v), 0);
    ASSERT_EQ_INT(cloak_valve_tx(&v), 0);

    cloak_valve_add_rx(&v, 10);
    cloak_valve_add_rx(&v, 5);
    cloak_valve_add_tx(&v, 7);
    /* Distinct totals in the two directions: equal ones would pass with
     * rx and tx transposed inside the valve itself. */
    ASSERT_EQ_INT(cloak_valve_rx(&v), 15);
    ASSERT_EQ_INT(cloak_valve_tx(&v), 7);

    /* nullify reports the accumulated values AND zeroes them. Seeded with
     * values that are neither 0 nor the expected result, so a nullify
     * that never wrote the outputs fails here. */
    int64_t got_rx = -1, got_tx = -1;
    cloak_valve_nullify(&v, &got_rx, &got_tx);
    ASSERT_EQ_INT(got_rx, 15);
    ASSERT_EQ_INT(got_tx, 7);
    ASSERT_EQ_INT(cloak_valve_rx(&v), 0);
    ASSERT_EQ_INT(cloak_valve_tx(&v), 0);

    /* Accumulation resumes from zero after a drain, and a second drain of
     * an untouched valve reports zero rather than repeating the first. */
    cloak_valve_add_rx(&v, 3);
    got_rx = -1;
    got_tx = -1;
    cloak_valve_nullify(&v, &got_rx, &got_tx);
    ASSERT_EQ_INT(got_rx, 3);
    ASSERT_EQ_INT(got_tx, 0);
    got_rx = -1;
    got_tx = -1;
    cloak_valve_nullify(&v, &got_rx, &got_tx);
    ASSERT_EQ_INT(got_rx, 0);
    ASSERT_EQ_INT(got_tx, 0);

    /* Either output may be discarded. */
    cloak_valve_add_rx(&v, 11);
    cloak_valve_add_tx(&v, 13);
    got_tx = -1;
    cloak_valve_nullify(&v, NULL, &got_tx);
    ASSERT_EQ_INT(got_tx, 13);
    ASSERT_EQ_INT(cloak_valve_rx(&v), 0); /* discarded, but still reset */
}

/* ------------------------------------------------------------------ */
/* 2. every entry point tolerates a NULL (unmetered) valve             */
/* ------------------------------------------------------------------ */

static void test_null_valve_is_a_noop(void) {
    cloak_valve_add_rx(NULL, 100);
    cloak_valve_add_tx(NULL, 100);
    ASSERT_EQ_INT(cloak_valve_rx(NULL), 0);
    ASSERT_EQ_INT(cloak_valve_tx(NULL), 0);

    int64_t got_rx = 123, got_tx = 456;
    cloak_valve_nullify(NULL, &got_rx, &got_tx);
    ASSERT_EQ_INT(got_rx, 0);
    ASSERT_EQ_INT(got_tx, 0);
    cloak_valve_nullify(NULL, NULL, NULL); /* must not crash */
}

/* ------------------------------------------------------------------ */
/* live-session harness (same shape as test_session.c's)               */
/* ------------------------------------------------------------------ */

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

static void pump(cloak_reactor_t *r1, cloak_reactor_t *r2, int rounds) {
    for (int i = 0; i < rounds; i++) {
        cloak_reactor_add_timer(r1, 5, stop_reactor_timer_cb, r1);
        cloak_reactor_run(r1);
        cloak_reactor_add_timer(r2, 5, stop_reactor_timer_cb, r2);
        cloak_reactor_run(r2);
    }
}

typedef struct {
    cloak_stream_t *last_new_stream;
    int new_stream_count;
} valve_harness_t;

static void on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    valve_harness_t *h = (valve_harness_t *)userdata;
    h->last_new_stream = stream;
    h->new_stream_count++;
}

static void make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

/* One client<->server session pair over a single socketpair, each side
 * metered by its own (possibly NULL) valve. */
static void init_pair(cloak_session_t *client, valve_harness_t *client_h, cloak_reactor_t *client_r,
                       cloak_valve_t *client_valve,
                       cloak_session_t *server, valve_harness_t *server_h, cloak_reactor_t *server_r,
                       cloak_valve_t *server_valve,
                       const cloak_obfuscator_t *shared_obfuscator) {
    memset(client_h, 0, sizeof(*client_h));
    memset(server_h, 0, sizeof(*server_h));

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = *shared_obfuscator;
    cfg.max_on_wire_size = MAX_ON_WIRE;
    cfg.stream_recv_capacity = STREAM_RECV_CAP;
    cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    cfg.inactivity_timeout_ms = 60000;
    cfg.on_new_stream = on_new_stream;

    cloak_session_config_t client_cfg = cfg;
    client_cfg.on_new_stream_userdata = client_h;
    client_cfg.valve = client_valve;
    ASSERT_EQ_INT(cloak_session_init(client, 1, client_r, &client_cfg), 0);

    cloak_session_config_t server_cfg = cfg;
    server_cfg.on_new_stream_userdata = server_h;
    server_cfg.valve = server_valve;
    ASSERT_EQ_INT(cloak_session_init(server, 2, server_r, &server_cfg), 0);

    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(client, fds[0]), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(server, fds[1]), 0);
}

/* ------------------------------------------------------------------ */
/* 3. real traffic, ONE direction only -- the direction test           */
/* ------------------------------------------------------------------ */

static void test_direction_of_real_traffic(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);

    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_valve_t client_valve, server_valve;
    memset(&client_valve, 0, sizeof(client_valve));
    memset(&server_valve, 0, sizeof(server_valve));

    cloak_session_t client, server;
    valve_harness_t client_h, server_h;
    init_pair(&client, &client_h, client_r, &client_valve,
              &server, &server_h, server_r, &server_valve, &obfuscator);

    cloak_stream_t *client_stream = cloak_session_open_stream(&client, NULL);
    ASSERT_TRUE(client_stream != NULL);

    /* Deliberately asymmetric: the client sends, the server NEVER writes
     * a byte back (no stream is opened on the server side, and nothing is
     * closed before the assertions below), so a correct implementation
     * leaves the server's tx and the client's rx at exactly 0. Swap the
     * two call sites and every one of the four assertions flips. */
    static const size_t PAYLOAD_LEN = 300;
    uint8_t payload[300];
    memset(payload, 0xA5, sizeof(payload));
    ASSERT_EQ_INT(cloak_stream_write(client_stream, payload, PAYLOAD_LEN), (long)PAYLOAD_LEN);

    pump(client_r, server_r, 5);

    /* The traffic really did flow -- otherwise "both counters are 0 in
     * the directions we expect 0" would pass on a dead connection. */
    ASSERT_EQ_INT(server_h.new_stream_count, 1);
    cloak_stream_t *server_stream = server_h.last_new_stream;
    ASSERT_TRUE(server_stream != NULL);
    uint8_t out[512];
    long got = cloak_stream_read(server_stream, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)PAYLOAD_LEN);

    int64_t c_tx = cloak_valve_tx(&client_valve);
    int64_t c_rx = cloak_valve_rx(&client_valve);
    int64_t s_rx = cloak_valve_rx(&server_valve);
    int64_t s_tx = cloak_valve_tx(&server_valve);

    /* DIRECTION. rx is client->server, tx is server->client, both from
     * the counting process's own point of view. */
    ASSERT_TRUE(c_tx > 0);      /* the client wrote */
    ASSERT_EQ_INT(c_rx, 0);     /* and read nothing */
    ASSERT_TRUE(s_rx > 0);      /* the server read */
    ASSERT_EQ_INT(s_tx, 0);     /* and wrote nothing */

    /* One side's tx is the other side's rx, to the byte: both count the
     * same on-wire envelopes. */
    ASSERT_EQ_INT(s_rx, c_tx);

    /* WIRE bytes, not payload bytes: the frame header, the AEAD tag, the
     * obfuscator's random padding and the conn's own length prefix are all
     * billed to the user who caused them. An implementation counting the
     * stream payload would report exactly PAYLOAD_LEN. The count is not a
     * single number because cloak_frame_obfuscate pads the first
     * CLOAK_FRAME_PAD_FIRST_N_FRAMES frames by a random amount, so this
     * brackets it: header + tag + prefix at minimum, header + the maximum
     * extra + prefix at most. */
    int64_t tag_len = (int64_t)cloak_aead_overhead(CLOAK_AEAD_AES_256_GCM);
    ASSERT_TRUE(c_tx >= (int64_t)(PAYLOAD_LEN + CLOAK_FRAME_HEADER_LEN + CLOAK_CONN_RECORD_HEADER_LEN) + tag_len);
    ASSERT_TRUE(c_tx <= (int64_t)(PAYLOAD_LEN + CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN +
                                   CLOAK_CONN_RECORD_HEADER_LEN));

    cloak_session_release_stream(&client, client_stream);
    cloak_session_release_stream(&server, server_stream);
    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

/* ------------------------------------------------------------------ */
/* 4. two sessions sharing one valve accumulate into it together       */
/* ------------------------------------------------------------------ */

static void test_shared_valve_accumulates(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);

    cloak_obfuscator_t obfuscator_a, obfuscator_b;
    make_obfuscator(&obfuscator_a);
    make_obfuscator(&obfuscator_b);

    /* One user, two sessions -- the whole reason the valve is a separate
     * object rather than a field of cloak_session_t. */
    cloak_valve_t shared;
    memset(&shared, 0, sizeof(shared));
    /* The two servers are metered separately, so the shared total can be
     * checked against an independently-counted ground truth rather than
     * against a number this test computed the same way the code does. */
    cloak_valve_t server_a_valve, server_b_valve;
    memset(&server_a_valve, 0, sizeof(server_a_valve));
    memset(&server_b_valve, 0, sizeof(server_b_valve));

    cloak_session_t client_a, server_a, client_b, server_b;
    valve_harness_t ch_a, sh_a, ch_b, sh_b;
    init_pair(&client_a, &ch_a, client_r, &shared, &server_a, &sh_a, server_r, &server_a_valve, &obfuscator_a);
    init_pair(&client_b, &ch_b, client_r, &shared, &server_b, &sh_b, server_r, &server_b_valve, &obfuscator_b);

    cloak_stream_t *stream_a = cloak_session_open_stream(&client_a, NULL);
    cloak_stream_t *stream_b = cloak_session_open_stream(&client_b, NULL);
    ASSERT_TRUE(stream_a != NULL && stream_b != NULL);

    /* Different lengths: equal ones would let "counted session A twice"
     * produce the right total. */
    uint8_t buf[600];
    memset(buf, 0x5A, sizeof(buf));
    ASSERT_EQ_INT(cloak_stream_write(stream_a, buf, 100), 100);
    ASSERT_EQ_INT(cloak_stream_write(stream_b, buf, 600), 600);

    pump(client_r, server_r, 6);

    int64_t a_rx = cloak_valve_rx(&server_a_valve);
    int64_t b_rx = cloak_valve_rx(&server_b_valve);
    ASSERT_TRUE(a_rx > 0 && b_rx > 0);
    ASSERT_TRUE(a_rx != b_rx); /* the two sessions really did move different amounts */
    ASSERT_EQ_INT(cloak_valve_tx(&shared), a_rx + b_rx);

    cloak_session_release_stream(&client_a, stream_a);
    cloak_session_release_stream(&client_b, stream_b);
    if (sh_a.last_new_stream != NULL) cloak_session_release_stream(&server_a, sh_a.last_new_stream);
    if (sh_b.last_new_stream != NULL) cloak_session_release_stream(&server_b, sh_b.last_new_stream);
    cloak_session_destroy(&client_a);
    cloak_session_destroy(&client_b);
    cloak_session_destroy(&server_a);
    cloak_session_destroy(&server_b);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

/* ------------------------------------------------------------------ */
/* 5. a session with no valve still passes traffic                     */
/* ------------------------------------------------------------------ */

static void test_unmetered_session_still_works(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);

    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_t client, server;
    valve_harness_t client_h, server_h;
    init_pair(&client, &client_h, client_r, NULL, &server, &server_h, server_r, NULL, &obfuscator);

    cloak_stream_t *client_stream = cloak_session_open_stream(&client, NULL);
    ASSERT_TRUE(client_stream != NULL);
    const char *msg = "unmetered traffic still flows";
    ASSERT_EQ_INT(cloak_stream_write(client_stream, (const uint8_t *)msg, strlen(msg)), (long)strlen(msg));

    pump(client_r, server_r, 5);

    ASSERT_EQ_INT(server_h.new_stream_count, 1);
    cloak_stream_t *server_stream = server_h.last_new_stream;
    ASSERT_TRUE(server_stream != NULL);
    uint8_t out[128];
    long got = cloak_stream_read(server_stream, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)strlen(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    /* And the reverse direction too, so the unmetered send path is
     * exercised from both ends. */
    ASSERT_EQ_INT(cloak_stream_write(server_stream, (const uint8_t *)"ack", 3), 3);
    pump(client_r, server_r, 5);
    got = cloak_stream_read(client_stream, out, sizeof(out));
    ASSERT_EQ_INT(got, 3);
    ASSERT_MEM_EQ(out, "ack", 3);

    cloak_session_release_stream(&client, client_stream);
    cloak_session_release_stream(&server, server_stream);
    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

TEST_MAIN_BEGIN()
    test_arithmetic();
    test_null_valve_is_a_noop();
    test_direction_of_real_traffic();
    test_shared_valve_accumulates();
    test_unmetered_session_still_works();
TEST_MAIN_END()
