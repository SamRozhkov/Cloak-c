#include "cloak/session.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/common.h"
#include "test_framework.h"

#define MAX_ON_WIRE 2048u
#define STREAM_RECV_CAP 65536u
#define STREAM_MAX_PENDING 64u
#define CONN_SEND_QUEUE_CAP 65536u

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

/* Runs both reactors' dispatch loops in short alternating bursts until
 * either done_flag becomes true or max_rounds is exhausted -- the
 * standard pattern this integration test uses instead of sleep-polling:
 * each round schedules a short stop-timer on BOTH reactors so each
 * cloak_reactor_run call returns promptly, giving control back to check
 * done_flag. */
static void pump_until(cloak_reactor_t *r1, cloak_reactor_t *r2, const int *done_flag, int max_rounds) {
    for (int i = 0; i < max_rounds && !*done_flag; i++) {
        cloak_reactor_add_timer(r1, 5, stop_reactor_timer_cb, r1);
        cloak_reactor_run(r1);
        cloak_reactor_add_timer(r2, 5, stop_reactor_timer_cb, r2);
        cloak_reactor_run(r2);
    }
}

typedef struct {
    cloak_stream_t *last_new_stream;
    int new_stream_count;
    int broken_count;
} sesh_harness_t;

static void on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    sesh_harness_t *h = (sesh_harness_t *)userdata;
    h->last_new_stream = stream;
    h->new_stream_count++;
}

static void on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    sesh_harness_t *h = (sesh_harness_t *)userdata;
    h->broken_count++;
}

static void make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

static void init_session_pair(cloak_session_t *client, sesh_harness_t *client_h, cloak_reactor_t *client_r,
                               cloak_session_t *server, sesh_harness_t *server_h, cloak_reactor_t *server_r,
                               const cloak_obfuscator_t *shared_obfuscator, int nconns) {
    memset(client_h, 0, sizeof(*client_h));
    memset(server_h, 0, sizeof(*server_h));

    cloak_session_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.obfuscator = *shared_obfuscator;
    client_cfg.max_on_wire_size = MAX_ON_WIRE;
    client_cfg.stream_recv_capacity = STREAM_RECV_CAP;
    client_cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    client_cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    client_cfg.inactivity_timeout_ms = 60000;
    client_cfg.on_new_stream = on_new_stream;
    client_cfg.on_new_stream_userdata = client_h;
    client_cfg.on_broken = on_broken;
    client_cfg.on_broken_userdata = client_h;
    ASSERT_EQ_INT(cloak_session_init(client, 1, client_r, &client_cfg), 0);

    cloak_session_config_t server_cfg = client_cfg;
    server_cfg.on_new_stream_userdata = server_h;
    server_cfg.on_broken_userdata = server_h;
    ASSERT_EQ_INT(cloak_session_init(server, 2, server_r, &server_cfg), 0);

    for (int i = 0; i < nconns; i++) {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        ASSERT_EQ_INT(cloak_session_add_conn(client, fds[0]), 0);
        ASSERT_EQ_INT(cloak_session_add_conn(server, fds[1]), 0);
    }
}

static void test_single_stream_single_conn_round_trip(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);

    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_t client, server;
    sesh_harness_t client_h, server_h;
    init_session_pair(&client, &client_h, client_r, &server, &server_h, server_r, &obfuscator, 1);

    uint32_t stream_id;
    cloak_stream_t *client_stream = cloak_session_open_stream(&client, &stream_id);
    ASSERT_TRUE(client_stream != NULL);

    const char *msg = "hello from the client";
    ASSERT_EQ_INT(cloak_stream_write(client_stream, (const uint8_t *)msg, strlen(msg)), (long)strlen(msg));

    int always_false = 0;
    pump_until(client_r, server_r, &always_false, 5);

    ASSERT_EQ_INT(server_h.new_stream_count, 1);
    cloak_stream_t *server_stream = server_h.last_new_stream;
    ASSERT_TRUE(server_stream != NULL);

    uint8_t out[128];
    long got = cloak_stream_read(server_stream, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)strlen(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    /* Neither stream was ever closed above -- release both explicitly
     * (see cloak_session_release_stream's contract: it performs an
     * implicit active close first when needed) before tearing the
     * sessions down, so this test doesn't leak either allocation. */
    cloak_session_release_stream(&client, client_stream);
    cloak_session_release_stream(&server, server_stream);

    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

typedef struct {
    cloak_stream_t *streams[16];
    int count;
} multi_new_stream_capture_t;

static void on_new_stream_capture_all(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    multi_new_stream_capture_t *cap = (multi_new_stream_capture_t *)userdata;
    ASSERT_TRUE(cap->count < 16);
    cap->streams[cap->count++] = stream;
}

static void test_multiple_streams_multiple_conns_byte_exact(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);

    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.obfuscator = obfuscator;
    client_cfg.max_on_wire_size = MAX_ON_WIRE;
    client_cfg.stream_recv_capacity = STREAM_RECV_CAP;
    client_cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    client_cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    client_cfg.inactivity_timeout_ms = 60000;

    cloak_session_t client, server;
    ASSERT_EQ_INT(cloak_session_init(&client, 1, client_r, &client_cfg), 0);

    multi_new_stream_capture_t cap;
    memset(&cap, 0, sizeof(cap));
    cloak_session_config_t server_cfg = client_cfg;
    server_cfg.on_new_stream = on_new_stream_capture_all;
    server_cfg.on_new_stream_userdata = &cap;
    ASSERT_EQ_INT(cloak_session_init(&server, 2, server_r, &server_cfg), 0);

    enum { NCONN = 4, NSTREAMS = 6 };
    for (int i = 0; i < NCONN; i++) {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        ASSERT_EQ_INT(cloak_session_add_conn(&client, fds[0]), 0);
        ASSERT_EQ_INT(cloak_session_add_conn(&server, fds[1]), 0);
    }

    cloak_stream_t *client_streams[NSTREAMS];
    char messages[NSTREAMS][64];
    size_t message_lens[NSTREAMS];
    for (int i = 0; i < NSTREAMS; i++) {
        uint32_t id;
        client_streams[i] = cloak_session_open_stream(&client, &id);
        ASSERT_TRUE(client_streams[i] != NULL);
        int len = snprintf(messages[i], sizeof(messages[i]), "stream-%d-payload-abcdef", i);
        message_lens[i] = (size_t)len;
        ASSERT_EQ_INT(cloak_stream_write(client_streams[i], (const uint8_t *)messages[i], (size_t)len),
                      (long)len);
    }

    int always_false = 0;
    pump_until(client_r, server_r, &always_false, 10);

    ASSERT_EQ_INT(cap.count, NSTREAMS);
    for (int i = 0; i < NSTREAMS; i++) {
        uint8_t out[128];
        long got = cloak_stream_read(cap.streams[i], out, sizeof(out));
        ASSERT_TRUE(got > 0);
        int matched = 0;
        for (int j = 0; j < NSTREAMS; j++) {
            if ((size_t)got == message_lens[j] && memcmp(out, messages[j], (size_t)got) == 0) {
                matched = 1;
                break;
            }
        }
        ASSERT_TRUE(matched);
        cloak_session_release_stream(&server, cap.streams[i]);
    }
    for (int i = 0; i < NSTREAMS; i++) {
        cloak_session_release_stream(&client, client_streams[i]);
    }

    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

static void test_active_stream_close_propagates_to_peer(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);
    cloak_session_t client, server;
    sesh_harness_t client_h, server_h;
    init_session_pair(&client, &client_h, client_r, &server, &server_h, server_r, &obfuscator, 1);

    uint32_t id;
    cloak_stream_t *client_stream = cloak_session_open_stream(&client, &id);
    ASSERT_TRUE(client_stream != NULL);
    ASSERT_EQ_INT(cloak_stream_write(client_stream, (const uint8_t *)"x", 1), 1);

    int always_false = 0;
    pump_until(client_r, server_r, &always_false, 5);
    ASSERT_EQ_INT(server_h.new_stream_count, 1);
    cloak_stream_t *server_stream = server_h.last_new_stream;

    /* Regression test for a real heap-use-after-free caught during this
     * plan's own design verification: the client closes its stream
     * (sends a closing frame) immediately after writing one byte, with
     * NO gap for the test to read anything in between. On the server
     * side, both the data frame and the closing frame can land in the
     * same non-blocking read() and get dispatched back-to-back inside
     * session_on_envelope -- so by the time pump_until returns control
     * here, cloak_stream_feed_frame has already reported the closing
     * frame (return value 1) to session_on_envelope, which retires (but,
     * per this module's design, does NOT free) server_stream. If
     * session.c ever again frees a stream's memory at the moment it's
     * retired (rather than only in cloak_session_release_stream), the
     * cloak_stream_read call below reads freed memory -- this exact
     * scenario is what an earlier draft of this plan's session.c got
     * wrong, caught by this test under ASan (heap-use-after-free in
     * cloak_bytequeue_read, freed by session_close_stream_internal). */
    ASSERT_EQ_INT(cloak_session_close_stream(&client, client_stream), 0);
    pump_until(client_r, server_r, &always_false, 5);

    /* The server side's stream must still be safely readable here,
     * reporting end-of-stream only once its buffered byte and the close
     * are both delivered -- not a moment before, and definitely not via
     * a dangling pointer. */
    uint8_t out[8];
    long got = cloak_stream_read(server_stream, out, sizeof(out));
    ASSERT_EQ_INT(got, 1);
    ASSERT_MEM_EQ(out, "x", 1);
    ASSERT_EQ_INT(cloak_stream_read(server_stream, out, sizeof(out)), -1);

    cloak_session_release_stream(&client, client_stream);
    cloak_session_release_stream(&server, server_stream);

    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

static void test_active_session_close_notifies_peer(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);
    cloak_session_t client, server;
    sesh_harness_t client_h, server_h;
    init_session_pair(&client, &client_h, client_r, &server, &server_h, server_r, &obfuscator, 1);

    ASSERT_EQ_INT(cloak_session_close(&client), 0);

    int always_false = 0;
    pump_until(client_r, server_r, &always_false, 5);

    ASSERT_EQ_INT(server_h.broken_count, 1);
    ASSERT_EQ_INT(cloak_session_is_closed(&server), 1);

    /* cloak_session_close (called above on client) already destroyed
     * every stream client owned (there were none opened here), and
     * server's whole-session teardown will do the same for server's (also
     * none) -- nothing to release in this test. */
    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

static void test_inactivity_timeout_closes_session(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = obfuscator;
    cfg.max_on_wire_size = MAX_ON_WIRE;
    cfg.stream_recv_capacity = STREAM_RECV_CAP;
    cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    cfg.inactivity_timeout_ms = 30; /* short, real timeout -- no streams are ever opened */

    sesh_harness_t h;
    memset(&h, 0, sizeof(h));
    cfg.on_broken = on_broken;
    cfg.on_broken_userdata = &h;

    cloak_session_t sesh;
    ASSERT_EQ_INT(cloak_session_init(&sesh, 1, client_r, &cfg), 0);

    ASSERT_EQ_INT(cloak_session_is_closed(&sesh), 0);

    /* Pump ONLY this session's own reactor (no peer needed -- this
     * exercises the timer firing, not the network path) until on_broken
     * actually fires or a generous round budget is exhausted. Waits on
     * h.broken_count, not cloak_session_is_closed: is_closed() flips
     * synchronously inside session_check_timeout (before the deferred
     * teardown that fires on_broken even gets scheduled), so a loop that
     * stopped as soon as is_closed() became true could exit one round
     * too early, on the rare occasion this test's own stop_reactor_timer_cb
     * (used to bound each cloak_reactor_run call) is itself due in the
     * very same batch as the freshly-scheduled 0ms deferred-teardown
     * timer and happens to run first, setting the reactor's own stopped
     * flag before that timer gets a chance to fire. Found as a real,
     * reproducible ~5% flake during this plan's own design verification
     * after the deferred-teardown redesign (see this plan's Global
     * Constraints) separated is_closed() from on_broken() in time where
     * they used to be simultaneous. */
    for (int i = 0; i < 50 && h.broken_count == 0; i++) {
        cloak_reactor_add_timer(client_r, 10, stop_reactor_timer_cb, client_r);
        cloak_reactor_run(client_r);
    }

    ASSERT_EQ_INT(cloak_session_is_closed(&sesh), 1);
    ASSERT_EQ_INT(h.broken_count, 1);

    cloak_session_destroy(&sesh);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

static cloak_session_t *g_on_new_stream_closes_target = NULL;

static void on_new_stream_closes_whole_session(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)stream;
    (void)userdata;
    /* A legitimate consumer policy: reject an unexpected new stream by
     * tearing down the whole session on the spot, synchronously, from
     * within this very callback. cloak_session_close's doc comment
     * promises this is safe. */
    ASSERT_EQ_INT(cloak_session_close(sesh), 0);
    g_on_new_stream_closes_target = sesh;
}

/* Regression test for a real heap-use-after-free caught during this
 * plan's own design verification (found by an adversarial probe beyond
 * this file's own originally-written tests, then folded in here): if
 * session_on_envelope invoked on_new_stream BEFORE feeding the revealing
 * frame to the brand new stream, and on_new_stream synchronously called
 * cloak_session_close (a documented-safe, realistic thing to do), that
 * close's synchronous stream-teardown sweep would free the stream that
 * session_on_envelope was still about to call cloak_stream_feed_frame
 * on. This test exercises exactly that sequence under ASan. */
static void test_on_new_stream_closing_session_is_safe(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.obfuscator = obfuscator;
    client_cfg.max_on_wire_size = MAX_ON_WIRE;
    client_cfg.stream_recv_capacity = STREAM_RECV_CAP;
    client_cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    client_cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    client_cfg.inactivity_timeout_ms = 60000;

    cloak_session_t client, server;
    ASSERT_EQ_INT(cloak_session_init(&client, 1, client_r, &client_cfg), 0);

    cloak_session_config_t server_cfg = client_cfg;
    server_cfg.on_new_stream = on_new_stream_closes_whole_session;
    ASSERT_EQ_INT(cloak_session_init(&server, 2, server_r, &server_cfg), 0);

    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(&client, fds[0]), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(&server, fds[1]), 0);

    uint32_t id;
    cloak_stream_t *client_stream = cloak_session_open_stream(&client, &id);
    ASSERT_TRUE(client_stream != NULL);
    ASSERT_EQ_INT(cloak_stream_write(client_stream, (const uint8_t *)"hi", 2), 2);

    g_on_new_stream_closes_target = NULL;
    int always_false = 0;
    pump_until(client_r, server_r, &always_false, 5);

    /* If session_on_envelope's ordering is correct, this whole sequence
     * (new stream created, fed, retired, THEN on_new_stream closes the
     * session) completes without any use-after-free, and the server
     * session ends up closed. */
    ASSERT_TRUE(g_on_new_stream_closes_target == &server);
    ASSERT_EQ_INT(cloak_session_is_closed(&server), 1);

    /* server's active close (triggered from within on_new_stream above)
     * sends a session-closing frame to client -- which client processes
     * within this same pump_until call, passively closing ITS session
     * too (matching Go: an active Close() on one side always notifies
     * the remote, which tears itself down symmetrically) and, as part of
     * that, freeing every stream it owned via
     * session_destroy_stream_iter_cb, including client_stream. Do NOT
     * call cloak_session_release_stream on client_stream here -- its
     * memory is already gone by this point, and doing so would itself be
     * a use-after-free (caught by this plan's own verification process
     * against an earlier draft of this exact test). Assert the symmetric
     * teardown happened instead. */
    ASSERT_EQ_INT(cloak_session_is_closed(&client), 1);

    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

/* Regression test for findings 3/4 in this plan's Global Constraints
 * (the fifth/sixth instances of this project's recurring UAF class):
 * closing a stream whose underlying connection has already died must
 * not free that same stream out from under cloak_session_close_stream's
 * own call chain. Completely ordinary trigger -- a peer disconnecting is
 * the single most common event a proxy server has to handle -- not an
 * artificial configuration (no tiny queue caps, no forced small buffers). */
static void test_close_stream_after_peer_disconnect_is_safe(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = obfuscator;
    cfg.max_on_wire_size = MAX_ON_WIRE;
    cfg.stream_recv_capacity = STREAM_RECV_CAP;
    cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    cfg.inactivity_timeout_ms = 60000;

    cloak_session_t sesh;
    ASSERT_EQ_INT(cloak_session_init(&sesh, 1, r, &cfg), 0);

    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(&sesh, fds[0]), 0);

    uint32_t id;
    cloak_stream_t *stream = cloak_session_open_stream(&sesh, &id);
    ASSERT_TRUE(stream != NULL);

    close(fds[1]); /* peer disconnects */

    /* Actively closing this stream now triggers, inside
     * cloak_stream_send_closing's own sink call, a write failure that
     * cascades all the way up into a full session teardown -- reentrant
     * to this very call. Must not crash. */
    (void)cloak_session_close_stream(&sesh, stream);
    ASSERT_EQ_INT(cloak_session_is_closed(&sesh), 1);

    /* cloak_session_close_stream only retires stream -- it does not free
     * it (see cloak_session_release_stream's own contract). Release it
     * explicitly so this test doesn't leak (cloak_session_destroy's own
     * deferred/synchronous sweep only reaches still-ACTIVE streams;
     * stream is already retired by this point, so it would otherwise
     * never be freed by anything). */
    cloak_session_release_stream(&sesh, stream);

    cloak_session_destroy(&sesh);
    cloak_reactor_destroy(r);
}

/* Sibling regression test: the same reentrant-teardown hazard, but
 * triggered from cloak_stream_write's own sink call instead of an
 * explicit close -- the specific path that reordering
 * cloak_session_close_stream/cloak_session_release_stream alone would
 * NOT have closed (see this plan's Global Constraints, finding 4) and
 * which is why the fix defers the whole stream-freeing sweep instead. */
static void test_stream_write_after_peer_disconnect_is_safe(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = obfuscator;
    cfg.max_on_wire_size = MAX_ON_WIRE;
    cfg.stream_recv_capacity = STREAM_RECV_CAP;
    cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    cfg.inactivity_timeout_ms = 60000;

    cloak_session_t sesh;
    ASSERT_EQ_INT(cloak_session_init(&sesh, 1, r, &cfg), 0);

    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(&sesh, fds[0]), 0);

    uint32_t id;
    cloak_stream_t *stream = cloak_session_open_stream(&sesh, &id);
    ASSERT_TRUE(stream != NULL);

    close(fds[1]); /* peer disconnects */

    /* This write's own sink call fails (peer gone), cascading into a
     * full session teardown reentrant to this very call -- must not
     * crash, and cloak_stream_write itself must survive touching
     * `stream` again (s->write_closed = 1) after its sink call returns. */
    long got = cloak_stream_write(stream, (const uint8_t *)"x", 1);
    ASSERT_EQ_INT(got, -1);
    ASSERT_EQ_INT(cloak_session_is_closed(&sesh), 1);

    cloak_session_destroy(&sesh);
    cloak_reactor_destroy(r);
}

static cloak_session_t *g_heap_alloc_destroy_target = NULL;

static void on_broken_destroys_and_frees_heap_session(cloak_session_t *sesh, void *userdata) {
    (void)userdata;
    /* Exactly the documented-safe pattern: destroy AND free the
     * session's own heap storage from within on_broken. Regression test
     * for the seventh instance of this module's recurring UAF class
     * (see this plan's Global Constraints, finding 7): the deferred
     * teardown must survive this without ever touching `sesh` again
     * once this callback returns -- including the second, sweep-only
     * timer that was scheduled just before this callback was invoked. */
    cloak_session_destroy(sesh);
    free(sesh);
    g_heap_alloc_destroy_target = NULL; /* sentinel: reached this line without crashing */
}

static void test_on_broken_destroying_and_freeing_heap_session_is_safe(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = obfuscator;
    cfg.max_on_wire_size = MAX_ON_WIRE;
    cfg.stream_recv_capacity = STREAM_RECV_CAP;
    cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    cfg.inactivity_timeout_ms = 30; /* short, real timeout -- fires on its own, no streams ever opened */
    cfg.on_broken = on_broken_destroys_and_frees_heap_session;

    cloak_session_t *sesh = (cloak_session_t *)malloc(sizeof(cloak_session_t));
    ASSERT_TRUE(sesh != NULL);
    ASSERT_EQ_INT(cloak_session_init(sesh, 1, r, &cfg), 0);
    g_heap_alloc_destroy_target = sesh;

    for (int i = 0; i < 50 && g_heap_alloc_destroy_target != NULL; i++) {
        cloak_reactor_add_timer(r, 10, stop_reactor_timer_cb, r);
        cloak_reactor_run(r);
    }
    ASSERT_TRUE(g_heap_alloc_destroy_target == NULL); /* on_broken ran, destroyed+freed sesh, no crash */

    /* Pump a few more rounds to make sure nothing was left dangling --
     * in particular, the sweep timer session_deferred_teardown_cb
     * schedules just before calling on_broken must have been cancelled
     * by cloak_session_destroy above, or it would fire here against
     * already-freed memory. */
    for (int i = 0; i < 5; i++) {
        cloak_reactor_add_timer(r, 10, stop_reactor_timer_cb, r);
        cloak_reactor_run(r);
    }

    cloak_reactor_destroy(r);
}

static void test_destroy_after_failed_init_is_safe(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = obfuscator;
    cfg.max_on_wire_size = 0; /* invalid -- too small to fit a header */
    cfg.stream_recv_capacity = STREAM_RECV_CAP;
    cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    cfg.inactivity_timeout_ms = 1000;

    cloak_session_t sesh;
    ASSERT_EQ_INT(cloak_session_init(&sesh, 1, r, &cfg), -1);
    cloak_session_destroy(&sesh);

    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_single_stream_single_conn_round_trip();
    test_multiple_streams_multiple_conns_byte_exact();
    test_active_stream_close_propagates_to_peer();
    test_active_session_close_notifies_peer();
    test_inactivity_timeout_closes_session();
    test_on_new_stream_closing_session_is_safe();
    test_close_stream_after_peer_disconnect_is_safe();
    test_stream_write_after_peer_disconnect_is_safe();
    test_on_broken_destroying_and_freeing_heap_session_is_safe();
    test_destroy_after_failed_init_is_safe();
TEST_MAIN_END()
