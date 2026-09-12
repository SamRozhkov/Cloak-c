#define _POSIX_C_SOURCE 200809L
#include "cloak/session.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/common.h"
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

TEST_MAIN_BEGIN()
    test_data_callback_fires_for_subsequent_frames_only();
    test_absent_callback_is_not_required();
TEST_MAIN_END()
