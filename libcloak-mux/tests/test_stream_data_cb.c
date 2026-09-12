#define _POSIX_C_SOURCE 200809L
#include "cloak/session.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/common.h"
#include "cloak/conn.h"
#include "test_framework.h"

/* Two sessions wired to each other over a socketpair, so one can open a
 * stream and write to it and the other observes the callbacks. */
struct endpoint {
    cloak_session_t sesh;
    cloak_stream_t *accepted;
    int new_stream_calls;
    int data_calls;
    int last_data_len;
};

static void on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct endpoint *ep = userdata;
    ep->new_stream_calls++;
    ep->accepted = stream;
}

static void on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct endpoint *ep = userdata;
    ep->data_calls++;
    uint8_t buf[4096];
    long n = cloak_stream_read(stream, buf, sizeof(buf));
    ep->last_data_len = n > 0 ? (int)n : 0;
}

static void on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    (void)userdata;
}

/* A second, non-draining endpoint used by the retirement-path tests below:
 * unlike `struct endpoint`'s on_stream_data (which drains inline), these
 * callbacks only record that they fired and which stream, so the test body
 * itself can drive cloak_stream_read afterward and observe exactly what a
 * consumer would see at the moment of notification. */
struct endpoint_nd {
    cloak_session_t sesh;
    cloak_stream_t *accepted;
    int new_stream_calls;
    int data_calls;
};

static void on_new_stream_nd(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct endpoint_nd *ep = userdata;
    ep->new_stream_calls++;
    ep->accepted = stream;
}

static void on_stream_data_nd(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    (void)stream;
    struct endpoint_nd *ep = userdata;
    ep->data_calls++;
}

static void fill_config_nd(cloak_session_config_t *cfg, struct endpoint_nd *ep,
                            const cloak_obfuscator_t *obfs) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->obfuscator = *obfs;
    cfg->max_on_wire_size = 16401;
    cfg->stream_recv_capacity = 65536;
    cfg->stream_max_pending_frames = 64;
    cfg->conn_send_queue_cap = 262144;
    cfg->inactivity_timeout_ms = 60000;
    cfg->on_new_stream = on_new_stream_nd;
    cfg->on_new_stream_userdata = ep;
    cfg->on_stream_data = on_stream_data_nd;
    cfg->on_stream_data_userdata = ep;
    cfg->on_broken = on_broken;
    cfg->on_broken_userdata = ep;
}

/* cloak_obfuscator_t has no constructor of its own -- test_session.c fills
 * it directly (method + a random key), so this follows suit rather than
 * inventing a cloak_obfuscator_init that doesn't exist. */
static void make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

static void fill_config(cloak_session_config_t *cfg, struct endpoint *ep,
                        const cloak_obfuscator_t *obfs) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->obfuscator = *obfs;
    cfg->max_on_wire_size = 16401;
    cfg->stream_recv_capacity = 65536;
    cfg->stream_max_pending_frames = 64;
    cfg->conn_send_queue_cap = 262144;
    cfg->inactivity_timeout_ms = 60000;
    cfg->on_new_stream = on_new_stream;
    cfg->on_new_stream_userdata = ep;
    cfg->on_stream_data = on_stream_data;
    cfg->on_stream_data_userdata = ep;
    cfg->on_broken = on_broken;
    cfg->on_broken_userdata = ep;
}

static void test_data_callback_fires_for_subsequent_frames_only(void) {
    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    struct endpoint a;
    struct endpoint b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    cloak_session_config_t cfg_a;
    cloak_session_config_t cfg_b;
    fill_config(&cfg_a, &a, &obfs);
    fill_config(&cfg_b, &b, &obfs);

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 1, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 1, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    /* First write creates the stream on b: on_new_stream fires, and the
     * data callback deliberately does not. */
    ASSERT_EQ_INT(5, (int)cloak_stream_write(s, (const uint8_t *)"hello", 5));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);
    ASSERT_EQ_INT(0, b.data_calls);

    /* Drain what the first frame delivered, so the next assertion is
     * about the second frame's bytes and not leftovers. */
    uint8_t buf[64];
    ASSERT_EQ_INT(5, (int)cloak_stream_read(b.accepted, buf, sizeof(buf)));
    ASSERT_MEM_EQ(buf, "hello", 5);

    /* Second write lands on a stream b already knows: now the data
     * callback is the only notification, and it can read the bytes. */
    ASSERT_EQ_INT(6, (int)cloak_stream_write(s, (const uint8_t *)"world!", 6));
    for (int i = 0; i < 50 && b.data_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);
    ASSERT_EQ_INT(1, b.data_calls);
    ASSERT_EQ_INT(6, b.last_data_len);

    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

static void test_absent_callback_is_not_required(void) {
    /* A config that leaves on_stream_data NULL must still route frames --
     * the notification is optional, like every other session callback. */
    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    struct endpoint a;
    struct endpoint b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    cloak_session_config_t cfg_a;
    cloak_session_config_t cfg_b;
    fill_config(&cfg_a, &a, &obfs);
    fill_config(&cfg_b, &b, &obfs);
    cfg_b.on_stream_data = NULL;
    cfg_b.on_stream_data_userdata = NULL;

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 2, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 2, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }
    ASSERT_EQ_INT(3, (int)cloak_stream_write(s, (const uint8_t *)"abc", 3));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);

    ASSERT_EQ_INT(3, (int)cloak_stream_write(s, (const uint8_t *)"def", 3));
    for (int i = 0; i < 50; i++) {
        cloak_reactor_run_once(r, 10);
    }
    /* No callback, but the bytes still arrived and are readable. */
    uint8_t buf[64];
    long total = 0;
    long n;
    while ((n = cloak_stream_read(b.accepted, buf, sizeof(buf))) > 0) {
        total += n;
    }
    ASSERT_EQ_INT(6, (int)total);
    ASSERT_EQ_INT(0, b.data_calls);

    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

static void test_data_callback_fires_on_stream_close(void) {
    /* rc == 1 path: a closing frame routed to an already-known stream
     * must still fire on_stream_data (not just the ordinary-data case),
     * and the stream it hands over must be safe to drain first and only
     * report end-of-stream once that's done -- "drain then EOF", not
     * just "EOF". */
    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    struct endpoint_nd a;
    struct endpoint_nd b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    cloak_session_config_t cfg_a;
    cloak_session_config_t cfg_b;
    fill_config_nd(&cfg_a, &a, &obfs);
    fill_config_nd(&cfg_b, &b, &obfs);

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 3, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 3, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    /* First frame creates the stream on b and leaves "hello" unread --
     * this is the data that must precede the close in the assertion
     * below, so this test exercises "drain then EOF" and not just "EOF". */
    ASSERT_EQ_INT(5, (int)cloak_stream_write(s, (const uint8_t *)"hello", 5));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);
    ASSERT_EQ_INT(0, b.data_calls);

    /* Actively close the stream from a's side: this sends a closing-stream
     * frame that routes to the ACTIVE branch on b (the stream is already
     * known there), feeds it (rc == 1), retires it, and only then must
     * fire on_stream_data. */
    ASSERT_EQ_INT(0, cloak_session_close_stream(&a.sesh, s));
    for (int i = 0; i < 50 && b.data_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);
    ASSERT_EQ_INT(1, b.data_calls);

    /* The stream handed to on_stream_data is retired but still safe to
     * read: drain "hello" (buffered before the close) first, and only
     * then observe end-of-stream. */
    uint8_t buf[64];
    ASSERT_EQ_INT(5, (int)cloak_stream_read(b.accepted, buf, sizeof(buf)));
    ASSERT_MEM_EQ(buf, "hello", 5);
    ASSERT_EQ_INT(-1, (int)cloak_stream_read(b.accepted, buf, sizeof(buf)));

    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

static void test_data_callback_fires_on_protocol_violation(void) {
    /* rc == -1 path: a frame that is itself a protocol violation (here, a
     * duplicate/already-delivered sequence number -- cloak_stream_feed_frame's
     * own documented trigger) must still fire on_stream_data when it
     * routes to an already-known stream, and the stream it hands over
     * must still be safe to read whatever arrived before the violation.
     *
     * There is no way to provoke this through the public session/stream
     * write API -- cloak_stream_write always assigns the next sequential
     * seq itself, so a legitimate sender can never emit a duplicate. This
     * forges one directly on the wire instead: a hand-obfuscated frame
     * (built with cloak_frame_obfuscate, the same shared obfuscator both
     * sessions use) reusing stream_id/seq 0 -- the seq the real first
     * frame already consumed -- length-prefixed exactly as cloak_conn_send
     * would (CLOAK_CONN_LEN_PREFIX_LEN, big-endian), and written straight
     * onto the raw socket fd. This is still "driving it from outside", not
     * reaching into cloak_stream_t/cloak_session_t internals: everything
     * used here (cloak_frame_t, cloak_frame_obfuscate,
     * CLOAK_CONN_LEN_PREFIX_LEN) is public API, and it's exactly what an
     * on-path attacker replaying a captured frame would produce. */
    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    struct endpoint_nd a;
    struct endpoint_nd b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    cloak_session_config_t cfg_a;
    cloak_session_config_t cfg_b;
    fill_config_nd(&cfg_a, &a, &obfs);
    fill_config_nd(&cfg_b, &b, &obfs);

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 4, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 4, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    uint32_t stream_id = 0;
    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, &stream_id);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    /* First frame (seq 0) creates the stream on b and advances its
     * next_recv_seq past 0, so a later frame claiming seq 0 again is a
     * duplicate. */
    ASSERT_EQ_INT(5, (int)cloak_stream_write(s, (const uint8_t *)"hello", 5));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);
    ASSERT_EQ_INT(0, b.data_calls);

    /* Forge a duplicate-seq frame for the same stream and inject it
     * directly onto the wire, bypassing both sessions' own framing. */
    const uint8_t dup_payload[] = "dup";
    cloak_frame_t dup;
    dup.stream_id = stream_id;
    dup.seq = 0; /* already consumed above -- a protocol violation */
    dup.closing = CLOAK_FRAME_CLOSING_NOTHING;
    dup.payload = dup_payload;
    dup.payload_len = sizeof(dup_payload) - 1;

    uint8_t wire[CLOAK_CONN_LEN_PREFIX_LEN + CLOAK_FRAME_HEADER_LEN + 64 + CLOAK_FRAME_MAX_EXTRA_LEN];
    long written = cloak_frame_obfuscate(&obfs, &dup, wire + CLOAK_CONN_LEN_PREFIX_LEN,
                                          sizeof(wire) - CLOAK_CONN_LEN_PREFIX_LEN, 0);
    ASSERT_TRUE(written > 0);
    if (written <= 0) {
        return;
    }
    wire[0] = (uint8_t)(((size_t)written >> 8) & 0xffu);
    wire[1] = (uint8_t)((size_t)written & 0xffu);
    size_t envelope_len = (size_t)CLOAK_CONN_LEN_PREFIX_LEN + (size_t)written;
    ASSERT_EQ_INT((int)envelope_len, (int)write(fds[0], wire, envelope_len));

    for (int i = 0; i < 50 && b.data_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);
    ASSERT_EQ_INT(1, b.data_calls);

    /* Retired but still safe to read: "hello" (buffered before the
     * violation) is still there; the duplicate's own payload never was
     * (rejected before touching the receive queue), and since no closing
     * frame was ever involved, the stream reads as merely empty
     * afterward, not end-of-stream. */
    uint8_t buf[64];
    ASSERT_EQ_INT(5, (int)cloak_stream_read(b.accepted, buf, sizeof(buf)));
    ASSERT_MEM_EQ(buf, "hello", 5);
    ASSERT_EQ_INT(0, (int)cloak_stream_read(b.accepted, buf, sizeof(buf)));

    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_data_callback_fires_for_subsequent_frames_only();
    test_absent_callback_is_not_required();
    test_data_callback_fires_on_stream_close();
    test_data_callback_fires_on_protocol_violation();
TEST_MAIN_END()
