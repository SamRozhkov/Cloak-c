#define _POSIX_C_SOURCE 200809L
#include "cloak/session.h"
#include "cloak/stream_relay.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/common.h"
#include "test_framework.h"

/* Two sessions wired to each other over a socketpair -- the same shape as
 * test_stream_data_cb.c's harness -- so one can open/close a stream
 * directly and the other observes it through the session callbacks a real
 * dispatcher would wire to a cloak_stream_relay_t. `sr`, when non-NULL, is
 * the relay currently spliced to `accepted`; the two forwarding callbacks
 * below just relay the notification into it, exactly as the dispatcher
 * documented in cloak/stream_relay.h is expected to. */
struct endpoint {
    cloak_session_t sesh;
    cloak_stream_t *accepted;
    cloak_stream_relay_t *sr;
    int new_stream_calls;
};

static void on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct endpoint *ep = userdata;
    ep->new_stream_calls++;
    ep->accepted = stream;
}

static void on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    (void)stream;
    struct endpoint *ep = userdata;
    if (ep->sr != NULL) {
        cloak_stream_relay_notify_stream_data(ep->sr);
    }
}

static void on_writable(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    struct endpoint *ep = userdata;
    if (ep->sr != NULL) {
        cloak_stream_relay_notify_writable(ep->sr);
    }
}

static void on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    (void)userdata;
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
    cfg->on_writable = on_writable;
    cfg->on_writable_userdata = ep;
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

/* The relay's own fd, socketpair-style: `inner` is handed to the relay
 * (which takes ownership and will close it); `outer` is the test's own
 * end, playing the role of the application on the other side of the
 * splice (a proxy client or an upstream server). Non-blocking so a test
 * can poll it while interleaving cloak_reactor_run_once calls, the same
 * reason test_relay.c's own large-transfer test makes its outer fds
 * non-blocking. */
struct sockpair {
    int inner;
    int outer;
};

static int sockpair_init(struct sockpair *sp) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return -1;
    }
    sp->inner = fds[0];
    sp->outer = fds[1];
    int flags = fcntl(sp->outer, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    if (fcntl(sp->outer, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -1;
    }
    return 0;
}

struct done_capture {
    int calls;
};

static void on_relay_done(cloak_stream_relay_t *sr, void *userdata) {
    (void)sr;
    struct done_capture *cap = userdata;
    cap->calls++;
}

static void test_forwards_both_directions(void) {
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

    /* Written before the relay exists, mirroring the dispatcher's real
     * order: on_new_stream fires first, and only then does the dispatcher
     * wire up a relay -- cloak_stream_relay_start's own initial pump must
     * deliver this. */
    ASSERT_EQ_INT(5, (int)cloak_stream_write(s, (const uint8_t *)"hello", 5));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);

    struct sockpair sp;
    ASSERT_EQ_INT(0, sockpair_init(&sp));

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));

    cloak_stream_relay_t sr;
    ASSERT_EQ_INT(0, cloak_stream_relay_start(&sr, r, &b.sesh, b.accepted, sp.inner, 4096,
                                              on_relay_done, &cap));
    b.sr = &sr;

    char buf[64];
    memset(buf, 0, sizeof(buf));
    ssize_t n = -2;
    for (int i = 0; i < 50 && n <= 0; i++) {
        n = read(sp.outer, buf, sizeof(buf));
        if (n > 0) {
            break;
        }
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_TRUE(n == 5);
    ASSERT_MEM_EQ(buf, "hello", 5);

    /* stream -> fd again, this time through the ordinary
     * notify_stream_data path rather than start's own initial pump. */
    ASSERT_EQ_INT(6, (int)cloak_stream_write(s, (const uint8_t *)"world!", 6));
    memset(buf, 0, sizeof(buf));
    n = -2;
    for (int i = 0; i < 50 && n <= 0; i++) {
        n = read(sp.outer, buf, sizeof(buf));
        if (n > 0) {
            break;
        }
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_TRUE(n == 6);
    ASSERT_MEM_EQ(buf, "world!", 6);

    /* fd -> stream */
    ASSERT_TRUE(write(sp.outer, "reply", 5) == 5);
    memset(buf, 0, sizeof(buf));
    long sn = 0;
    for (int i = 0; i < 50 && sn <= 0; i++) {
        cloak_reactor_run_once(r, 10);
        sn = cloak_stream_read(s, (uint8_t *)buf, sizeof(buf));
    }
    ASSERT_TRUE(sn == 5);
    ASSERT_MEM_EQ(buf, "reply", 5);

    cloak_stream_relay_stop(&sr);
    close(sp.outer);
    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

static void test_large_transfer_survives_backpressure(void) {
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
    /* Far below the 512 KiB payload below, so the socket-to-stream
     * direction genuinely has to backpressure through
     * cloak_session_send_queued/_capacity many times over the course of
     * the transfer -- not just through the relay's own small buf_cap --
     * or b's session pool breaks. Kept comfortably above the relay's own
     * internal per-read chunk size (16 KiB, STREAM_RELAY_CHUNK in
     * stream_relay.c): cloak_session_send_queued is only re-checked
     * between whole fd reads, so a single already-permitted read/write
     * can add up to about one chunk's worth of framed bytes to the queue
     * in one step: with a cap too close to that chunk size, a burst that
     * starts just under the watermark could land past the queue's hard
     * cap in that single step and break the session outright -- the
     * documented "surfaces one layer down" failure mode -- rather than
     * exercising the graceful pause/resume this test means to cover. This
     * is exactly what a first attempt at this test (conn_send_queue_cap
     * == STREAM_RELAY_CHUNK == 16384) hit: b's pool broke and the relay
     * tore itself down mid-transfer, which is a real, if narrow, sizing
     * constraint worth documenting for real callers too -- see
     * cloak/stream_relay.h's own note above CLOAK_STREAM_RELAY_HIGH_WATER_NUM. */
    cfg_b.conn_send_queue_cap = 65536;

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 2, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 2, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    /* A tiny priming write, just so b learns about the stream. */
    ASSERT_EQ_INT(1, (int)cloak_stream_write(s, (const uint8_t *)"x", 1));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);

    struct sockpair sp;
    ASSERT_EQ_INT(0, sockpair_init(&sp));

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));

    cloak_stream_relay_t sr;
    ASSERT_EQ_INT(0, cloak_stream_relay_start(&sr, r, &b.sesh, b.accepted, sp.inner, 4096,
                                              on_relay_done, &cap));
    b.sr = &sr;

    /* Drain the priming byte so it doesn't pollute the transfer
     * comparison below. */
    char priming[4];
    ssize_t pn = -1;
    for (int i = 0; i < 50 && pn <= 0; i++) {
        pn = read(sp.outer, priming, sizeof(priming));
        if (pn > 0) {
            break;
        }
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_TRUE(pn == 1);

    const size_t total = 512 * 1024;
    uint8_t *sent = malloc(total);
    ASSERT_TRUE(sent != NULL);
    if (sent == NULL) {
        return;
    }
    for (size_t i = 0; i < total; i++) {
        sent[i] = (uint8_t)(i * 31 + (i >> 8));
    }
    uint8_t *got = malloc(total);
    ASSERT_TRUE(got != NULL);
    if (got == NULL) {
        free(sent);
        return;
    }

    size_t written = 0;
    size_t received = 0;

    /* Feed sp.outer (the socket side of the splice) and drain a's own
     * stream (the far end of the multiplexed side), interleaving with
     * reactor turns -- the same pump-loop shape as
     * test_relay.c's own large-transfer test. */
    for (int spin = 0; spin < 200000 && received < total; spin++) {
        if (written < total) {
            ssize_t n = write(sp.outer, sent + written, total - written);
            if (n > 0) {
                written += (size_t)n;
            }
        }
        cloak_reactor_run_once(r, 10);
        for (;;) {
            long n = cloak_stream_read(s, got + received, total - received);
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

    /* The whole point of the backpressure machinery: this only holds if
     * the relay paused reading sp.inner whenever b's session queue got
     * too full, instead of blindly calling cloak_stream_write until the
     * connection pool broke and took the session down with it. A
     * byte-for-byte match alone would not catch a backpressure
     * regression -- it would just fail differently (a broken session,
     * not corrupted bytes) -- which is exactly why this assertion exists
     * on top of the memcmp above. */
    ASSERT_TRUE(!cloak_session_is_closed(&a.sesh));
    ASSERT_TRUE(!cloak_session_is_closed(&b.sesh));

    free(sent);
    free(got);
    cloak_stream_relay_stop(&sr);
    close(sp.outer);
    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

static void test_closing_fd_fires_done_once_and_ends_far_stream(void) {
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

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 3, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 3, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    ASSERT_EQ_INT(2, (int)cloak_stream_write(s, (const uint8_t *)"hi", 2));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);

    struct sockpair sp;
    ASSERT_EQ_INT(0, sockpair_init(&sp));

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));

    cloak_stream_relay_t sr;
    ASSERT_EQ_INT(0, cloak_stream_relay_start(&sr, r, &b.sesh, b.accepted, sp.inner, 4096,
                                              on_relay_done, &cap));
    b.sr = &sr;

    /* Close the outer/application end -- the relay's own fd sees EOF. */
    close(sp.outer);

    for (int i = 0; i < 50 && cap.calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, cap.calls);

    /* Keep pumping: on_done must never fire a second time on top. */
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_EQ_INT(1, cap.calls);

    /* The far end (a's own copy of the stream) must observe end of
     * stream: the relay closed it (via cloak_session_close_stream) as
     * part of tearing down. */
    uint8_t buf[16];
    long n = 0;
    for (int i = 0; i < 50 && n != -1; i++) {
        n = cloak_stream_read(s, buf, sizeof(buf));
        if (n != -1) {
            cloak_reactor_run_once(r, 10);
        }
    }
    ASSERT_EQ_INT(-1, (int)n);

    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

static void test_stream_eof_closes_fd_and_fires_done_once(void) {
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

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 4, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 4, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    ASSERT_EQ_INT(2, (int)cloak_stream_write(s, (const uint8_t *)"hi", 2));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);

    struct sockpair sp;
    ASSERT_EQ_INT(0, sockpair_init(&sp));

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));

    cloak_stream_relay_t sr;
    ASSERT_EQ_INT(0, cloak_stream_relay_start(&sr, r, &b.sesh, b.accepted, sp.inner, 4096,
                                              on_relay_done, &cap));
    b.sr = &sr;

    /* Drain the priming "hi" first, so the EOF check below isn't
     * confused by leftover forwarded bytes still sitting ahead of it. */
    char primed[8];
    ssize_t pn = -1;
    for (int i = 0; i < 50 && pn <= 0; i++) {
        pn = read(sp.outer, primed, sizeof(primed));
        if (pn > 0) {
            break;
        }
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(2, (int)pn);

    /* The far end actively closes its own copy of the stream. */
    ASSERT_EQ_INT(0, cloak_session_close_stream(&a.sesh, s));

    for (int i = 0; i < 50 && cap.calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, cap.calls);

    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_EQ_INT(1, cap.calls);

    /* The relay's own socket must show a clean EOF to its peer. */
    char buf[16];
    ssize_t n = read(sp.outer, buf, sizeof(buf));
    ASSERT_EQ_INT(0, (int)n);

    close(sp.outer);
    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

static void test_stop_is_idempotent_and_suppresses_done(void) {
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

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 5, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 5, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    ASSERT_EQ_INT(1, (int)cloak_stream_write(s, (const uint8_t *)"x", 1));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);

    struct sockpair sp;
    ASSERT_EQ_INT(0, sockpair_init(&sp));

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));

    cloak_stream_relay_t sr;
    ASSERT_EQ_INT(0, cloak_stream_relay_start(&sr, r, &b.sesh, b.accepted, sp.inner, 4096,
                                              on_relay_done, &cap));
    b.sr = &sr;

    cloak_stream_relay_stop(&sr);
    cloak_stream_relay_stop(&sr);
    ASSERT_EQ_INT(0, cap.calls);
    b.sr = NULL; /* the relay is gone -- nothing else may touch it */

    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_EQ_INT(0, cap.calls);

    /* Also safe on a relay left by a failed start. */
    cloak_stream_relay_t sr2;
    ASSERT_EQ_INT(-1, cloak_stream_relay_start(&sr2, r, &b.sesh, b.accepted, -1, 4096,
                                               on_relay_done, &cap));
    cloak_stream_relay_stop(&sr2);
    cloak_stream_relay_stop(&sr2);
    ASSERT_EQ_INT(0, cap.calls);

    close(sp.outer);
    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

static void test_failed_start_leaves_struct_safe(void) {
    /* Deliberately dirtied first: a freshly-declared or previously-zeroed
     * cloak_stream_relay_t would pass this test whether or not
     * cloak_stream_relay_start actually re-initializes it on every
     * failure path -- exactly the class of test
     * cloak_relay_t's own test_stop_after_failed_start_is_safe (in
     * libcloak-common) exists to guard against. */
    cloak_stream_relay_t dirty;
    memset(&dirty, 0xAA, sizeof(dirty));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    struct endpoint a;
    memset(&a, 0, sizeof(a));
    cloak_session_config_t cfg_a;
    fill_config(&cfg_a, &a, &obfs);
    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 6, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    int sock_fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds));

    /* buf_cap == 0 is rejected. */
    ASSERT_EQ_INT(-1, cloak_stream_relay_start(&dirty, r, &a.sesh, s, sock_fds[0], 0,
                                               on_relay_done, NULL));
    /* The direct assertion is the real regression signal: a struct that
     * an earlier successful call had already zeroed would pass this
     * whether or not the reset-on-every-failure-path bug is present. */
    ASSERT_EQ_INT(-1, dirty.fd);

    /* Must not crash, and on a failed start the caller keeps fd. */
    cloak_stream_relay_stop(&dirty);
    char c = 'z';
    ASSERT_TRUE(write(sock_fds[0], &c, 1) == 1); /* still open -- ours to close */

    close(sock_fds[0]);
    close(sock_fds[1]);
    close(fds[1]);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_reactor_destroy(r);
}

/* Not one of the six cases the brief names in prose, but a genuine gap: it
 * is the only test in this file that actually exercises the deferred-
 * teardown fix cloak_stream_relay_start's own doc comment describes for a
 * relay that turns out to already be finished at start time. Without it,
 * nothing here would fail if that deferral were accidentally reverted to
 * firing on_done synchronously (violating "never before start returns")
 * or to never firing it at all (the original wrinkle the task brief
 * flagged and asked to be resolved, not merely documented). */
static void test_immediate_finish_defers_on_done(void) {
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

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 7, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 7, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    /* Close it before ever writing anything: cloak_session_close_stream
     * sends exactly one frame (the closing frame -- see session.c), and
     * since nothing was ever written first, that single frame is itself
     * the frame that reveals this stream to b. b's copy therefore arrives
     * already ended (cloak_stream_read on it returns -1 immediately) --
     * exactly the wrinkle cloak_stream_relay_start's own initial pump
     * must detect and handle. */
    ASSERT_EQ_INT(0, cloak_session_close_stream(&a.sesh, s));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);

    struct sockpair sp;
    ASSERT_EQ_INT(0, sockpair_init(&sp));

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));

    cloak_stream_relay_t sr;
    int rc = cloak_stream_relay_start(&sr, r, &b.sesh, b.accepted, sp.inner, 4096,
                                      on_relay_done, &cap);
    ASSERT_EQ_INT(0, rc);
    /* The header's promise: on_done never fires before start returns,
     * even for a relay that is already finished internally by the time
     * it does. */
    ASSERT_EQ_INT(0, cap.calls);

    for (int i = 0; i < 50 && cap.calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, cap.calls);

    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_EQ_INT(1, cap.calls);

    close(sp.outer);
    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

/* Companion to the test above: stopping a relay whose start already
 * discovered it was finished must cancel the pending deferred-finish
 * timer, not merely rely on stream_relay_teardown's own done-guard to
 * make a later fire harmless. sr is heap-allocated and freed right after
 * stop specifically so that a missing cancellation shows up as an ASan
 * heap-use-after-free when the reactor is run afterward, rather than
 * silently passing because a stack slot happened to be reused without
 * anything reading stale data through it. */
static void test_stop_before_immediate_finish_fires_cancels_timer(void) {
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

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 8, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 8, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    ASSERT_EQ_INT(0, cloak_session_close_stream(&a.sesh, s));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);

    struct sockpair sp;
    ASSERT_EQ_INT(0, sockpair_init(&sp));

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));

    cloak_stream_relay_t *sr = malloc(sizeof(*sr));
    ASSERT_TRUE(sr != NULL);
    if (sr == NULL) {
        return;
    }

    ASSERT_EQ_INT(0, cloak_stream_relay_start(sr, r, &b.sesh, b.accepted, sp.inner, 4096,
                                              on_relay_done, &cap));
    ASSERT_EQ_INT(0, cap.calls);

    cloak_stream_relay_stop(sr);
    free(sr);

    /* If cloak_stream_relay_stop failed to cancel the pending finish
     * timer, this is where it would fire: userdata is the pointer just
     * freed above. */
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_EQ_INT(0, cap.calls);

    close(sp.outer);
    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_forwards_both_directions();
    test_large_transfer_survives_backpressure();
    test_closing_fd_fires_done_once_and_ends_far_stream();
    test_stream_eof_closes_fd_and_fires_done_once();
    test_stop_is_idempotent_and_suppresses_done();
    test_failed_start_leaves_struct_safe();
    test_immediate_finish_defers_on_done();
    test_stop_before_immediate_finish_fires_cancels_timer();
TEST_MAIN_END()
