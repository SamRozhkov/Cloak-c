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
     * or b's session pool breaks. stream_relay.c now bounds every single
     * fd read by exactly the room the session's aggregate pool currently
     * has (see stream_relay_fd_read_budget), so unlike an earlier version
     * of this file, this value no longer needs any safety margin above
     * the relay's own internal chunk size to avoid a single burst
     * overrunning the hard cap in one step -- any value works correctness-
     * wise; this one is just small enough, relative to the 512 KiB total,
     * to force many real pause/resume cycles over the course of the
     * transfer. */
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

/* Regression test for a defect the code review found in
 * pump_stream_to_fd's two independent, sequential phases: bytes the far
 * end already sent, but that didn't fit in buf_cap on the first pass,
 * can be stranded forever in the stream's own reassembly buffer if the
 * destination fd only becomes writable again in a LATER call, once the
 * far end has nothing further to send (so no further on_stream_data
 * notification will ever prompt another look).
 *
 * Reproduced by: writing far more than buf_cap in one shot BEFORE the
 * relay exists (so start's own initial pump hits the bug directly);
 * pre-saturating the relay's own fd so that same initial pump's attempt
 * to drain what little it could fit gets EAGAIN and makes zero progress
 * (mirroring test_relay.c's own test_zero_mask_backpressure_does_not_spin
 * technique); then relieving the stall in one step big enough that a
 * single later send() can drain the entire (small) queue in one shot --
 * exactly "a CLOAK_REACTOR_WRITABLE event" from the review's trace. The
 * far end (this test) never writes anything else afterward. */
static void test_pump_does_not_strand_bytes_when_fd_unstalls(void) {
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

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 9, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 9, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    /* One write, far exceeding the relay's own buf_cap below, and the
     * only one the far end (this test) ever makes. */
    const size_t total = 3000;
    uint8_t *sent = malloc(total);
    ASSERT_TRUE(sent != NULL);
    if (sent == NULL) {
        return;
    }
    for (size_t i = 0; i < total; i++) {
        sent[i] = (uint8_t)(i * 17 + 3);
    }
    ASSERT_EQ_INT((int)total, (int)cloak_stream_write(s, sent, total));

    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);

    struct sockpair sp;
    ASSERT_EQ_INT(0, sockpair_init(&sp));

    /* Saturate sp.inner's own kernel send buffer BEFORE the relay ever
     * touches it, so the relay's very first send() attempt on it is
     * guaranteed to hit EAGAIN regardless of anything else. */
    int flags = fcntl(sp.inner, F_GETFL, 0);
    ASSERT_TRUE(flags >= 0);
    ASSERT_EQ_INT(0, fcntl(sp.inner, F_SETFL, flags | O_NONBLOCK));
    uint8_t filler[4096];
    memset(filler, 'z', sizeof(filler));
    int inner_full = 0;
    size_t filler_total = 0;
    for (int i = 0; i < 4096; i++) {
        ssize_t n = write(sp.inner, filler, sizeof(filler));
        if (n < 0) {
            ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
            inner_full = 1;
            break;
        }
        filler_total += (size_t)n;
    }
    ASSERT_TRUE(inner_full);
    ASSERT_TRUE(filler_total > 0);

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));

    /* buf_cap far smaller than `total`: the stream already holds all
     * 3000 bytes (delivered before this relay existed, exactly like
     * on_new_stream firing with the first frame already fed), so start's
     * own initial pump fills to_fd to capacity and leaves the rest
     * sitting unread in the stream, then fails to send even one byte of
     * it -- the fd is fully stalled above. */
    cloak_stream_relay_t sr;
    ASSERT_EQ_INT(0, cloak_stream_relay_start(&sr, r, &b.sesh, b.accepted, sp.inner, 256,
                                              on_relay_done, &cap));
    b.sr = &sr;

    /* Relieve the stall by draining EXACTLY the filler bytes this test
     * itself queued above -- not "some generous chunk" of it. Nothing
     * else can possibly be sitting in this pipe yet (the relay's own
     * send() has not succeeded even once so far: the fd was already
     * fully stalled before start() ever ran), so this drains the pipe
     * back to genuinely empty without risking scooping up any real
     * relayed payload bytes along with leftover filler -- which a
     * partial drain of an unknown-sized backlog would risk doing, since
     * the two would sit back-to-back in FIFO order in the same pipe. */
    uint8_t drain_buf[4096];
    size_t drained_total = 0;
    while (drained_total < filler_total) {
        size_t want = filler_total - drained_total;
        if (want > sizeof(drain_buf)) {
            want = sizeof(drain_buf);
        }
        ssize_t n = read(sp.outer, drain_buf, want);
        ASSERT_TRUE(n > 0);
        if (n <= 0) {
            break;
        }
        drained_total += (size_t)n;
    }
    ASSERT_EQ_INT((int)filler_total, (int)drained_total);
    cloak_reactor_run_once(r, 10);

    /* Behave like an ordinary client from here: keep reading whatever
     * trickles out, running the reactor in between, for a generous
     * number of turns, with the far end silent throughout. */
    uint8_t *got = malloc(total);
    ASSERT_TRUE(got != NULL);
    size_t received = 0;
    for (int i = 0; i < 200 && received < total; i++) {
        cloak_reactor_run_once(r, 10);
        for (;;) {
            ssize_t n = read(sp.outer, got + received, total - received);
            if (n <= 0) {
                break;
            }
            received += (size_t)n;
        }
    }

    ASSERT_EQ_INT((int)total, (int)received);
    if (received == total) {
        ASSERT_MEM_EQ(sent, got, total);
    }

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

/* Regression test for finding 1 (final whole-branch review): the header
 * now documents, as prominently as the ownership note, that every relay
 * bound to a session MUST be stopped before or during that session's
 * on_broken -- because immediately after on_broken returns, every
 * still-active stream (including this relay's own sr->stream) is
 * destroyed and freed, and the relay has no third notification through
 * which it could ever learn that on its own. This pins the CORRECT
 * pattern (stop from on_broken) and proves it actually prevents the
 * use-after-free the finding described, rather than merely documenting
 * that it should. */
struct broken_capture {
    int calls;
    cloak_stream_relay_t *sr; /* the relay a correct dispatcher stops */
};

static void on_broken_stops_relay(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    struct broken_capture *bc = userdata;
    bc->calls++;
    if (bc->sr != NULL) {
        cloak_stream_relay_stop(bc->sr);
    }
}

static void test_stopping_relay_from_on_broken_avoids_use_after_free(void) {
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

    struct broken_capture bc;
    memset(&bc, 0, sizeof(bc));
    cfg_b.on_broken = on_broken_stops_relay;
    cfg_b.on_broken_userdata = &bc;

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 10, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 10, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

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
    bc.sr = &sr;

    /* Some data actually flows through the relay first -- genuinely
     * "mid-transfer", not at the instant the relay was created. */
    ASSERT_EQ_INT(6, (int)cloak_stream_write(s, (const uint8_t *)"world!", 6));
    char buf[64];
    ssize_t n = -2;
    for (int i = 0; i < 50 && n <= 0; i++) {
        n = read(sp.outer, buf, sizeof(buf));
        if (n > 0) {
            break;
        }
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_TRUE(n > 0);

    /* Kill the session mid-transfer: an active close on `a` sends a
     * closing-session frame that reaches `b` and fires b's on_broken
     * exactly once, with a relay still live and spliced to b.accepted.
     * cloak_session_broken_cb's own doc comment lists "any underlying
     * connection failing" and "a received closing-session frame" side by
     * side as equally valid triggers sharing an identical contract, so
     * this exercises the exact same teardown-ordering hazard a real
     * connection failure would, without this test needing to reach
     * around either session's own fd bookkeeping by closing a raw fd out
     * from under it. */
    ASSERT_EQ_INT(0, cloak_session_close(&a.sesh));

    for (int i = 0; i < 50 && bc.calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, bc.calls);
    b.sr = NULL; /* the relay is gone -- nothing else may touch it */

    /* cloak_stream_relay_stop, called from on_broken above, never fires
     * on_done by its own documented contract -- this must stay 0, not 1,
     * for the correct teardown pattern this test exercises. */
    ASSERT_EQ_INT(0, cap.calls);

    /* The actual regression signal: b's own deferred sweep (already
     * scheduled before on_broken even ran -- see
     * session_deferred_teardown_cb) destroys and frees b.accepted
     * immediately after on_broken returns. The relay's own fd (sp.inner)
     * is completely independent of the mux connection that just died, so
     * without the mandated stop() above it would still be registered
     * with the reactor; pushing more bytes and running the reactor from
     * here is exactly the pump_fd_to_stream -> cloak_stream_write-on-
     * freed-memory sequence the finding describes. With stop() already
     * having closed and deregistered sr's fd, this is a silent no-op --
     * and, under ASan, exactly where an unfixed dispatcher pattern would
     * instead abort on a heap-use-after-free. send() with MSG_NOSIGNAL,
     * not write(): sp.inner is already closed, so the kernel would
     * otherwise raise SIGPIPE against this test process, and there is no
     * SIGPIPE handler anywhere in this tree. */
    for (int i = 0; i < 5; i++) {
        char junk[8];
        memset(junk, 'z', sizeof(junk));
        (void)send(sp.outer, junk, sizeof(junk), MSG_NOSIGNAL);
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, bc.calls);
    ASSERT_EQ_INT(0, cap.calls);

    close(sp.outer);
    /* Neither stream is released here: cloak_session_close(&a.sesh)
     * above already destroyed every stream `a` owned (matching
     * test_session.c's own test_active_session_close_notifies_peer), and
     * b's automatic post-on_broken sweep already destroyed b.accepted --
     * releasing either now would be a double free. */
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

/* Regression test for finding 4 (final whole-branch review):
 * cloak_stream_relay_start must reject outright, rather than silently
 * hang forever later, when the session's pool could never hold even one
 * worst-case frame -- conn_send_queue_cap smaller than max_on_wire_size
 * (plus the connection layer's own length-prefix overhead), both
 * individually valid to cloak_conn_init/cloak_session_init. Uses the
 * fresh-0xAA-struct pattern test_failed_start_leaves_struct_safe already
 * established in this file, for the same reason: a struct an earlier
 * successful call had already zeroed would pass the direct field
 * assertion below whether or not this exact failure path resets it. */
static void test_start_rejects_when_no_connection_can_ever_fit_one_frame(void) {
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
    /* max_on_wire_size 16401 (this file's own default) plus
     * CLOAK_CONN_LEN_PREFIX_LEN means one worst-case frame costs 16403
     * on-wire bytes -- comfortably more than this 8192-byte cap, so no
     * connection in this one-connection pool could ever hold a single
     * full frame, no matter how empty it is. */
    cfg_a.conn_send_queue_cap = 8192;
    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 11, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    int sock_fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds));

    ASSERT_EQ_INT(-1, cloak_stream_relay_start(&dirty, r, &a.sesh, s, sock_fds[0], 4096,
                                               on_relay_done, NULL));
    ASSERT_EQ_INT(-1, dirty.fd);

    /* Must not crash, and on a failed start the caller keeps fd. */
    cloak_stream_relay_stop(&dirty);
    char c = 'z';
    ASSERT_TRUE(write(sock_fds[0], &c, 1) == 1);

    close(sock_fds[0]);
    close(sock_fds[1]);
    close(fds[1]);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_reactor_destroy(r);
}

/* Regression test for finding 3 (final whole-branch review): the
 * realistic failure cloak_switchboard_send's random-connection pick
 * creates is not an unlucky run, it is one congested connection in a
 * pool of N. connA below is a real, healthy connection whose peer (a's
 * own session) this test actively drains every turn; connDead's peer is
 * deliberately never read anywhere in this test, modeling one stuck
 * connection sitting behind an otherwise-healthy pool. Before this
 * plan's fix, stream_relay's read budget was derived from the pool's
 * AGGREGATE free space, which stays large throughout (dominated by
 * connA's continuously-drained room) right up until the random pick
 * lands on connDead often enough to exceed ITS OWN send_q cap --
 * fatal to the whole pool via conn_mark_broken, taking b.sesh (and, once
 * the dead connection's closure propagates, a.sesh too) down with it.
 * After the fix, the budget is derived from the MINIMUM free space over
 * the pool, which shrinks as connDead fills and throttles further reads
 * before connDead's own cap is ever exceeded -- so the session survives
 * (the transfer itself stalls once connDead saturates, since nothing
 * ever reads its peer to let it drain, but that is not what this test
 * asserts). */
static void test_session_survives_one_congested_connection_among_many(void) {
    int fds_ab[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds_ab));
    int dead_pair[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, dead_pair));

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
    /* Small enough that connDead's own send_q -- on top of whatever the
     * kernel itself buffers for that socket -- fills well within the
     * transfer size below. */
    cfg_b.conn_send_queue_cap = 65536;

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 12, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 12, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds_ab[1]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds_ab[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, dead_pair[0]));
    /* dead_pair[1] is deliberately never read anywhere in this test --
     * it plays the role of a stalled peer on one connection in the pool. */

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

    /* Drain the priming byte. */
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

    /* Push up to several MB through the relay's own outer fd: enough
     * that, if roughly half of the resulting frames route to connDead
     * (as cloak_switchboard_send's uniform-random pick would over this
     * many frames), connDead's cumulative share vastly exceeds its own
     * 65536-byte cap plus any kernel socket buffering -- comfortably
     * beyond statistical noise, so this is not a flaky assertion. This
     * test's own success does not depend on ever finishing the transfer:
     * once connDead saturates, the fix is expected to throttle the
     * relay's own reads to a permanent stall (nothing ever drains
     * connDead), not to keep writing past it -- so the loop below detects
     * that stall (neither side making any further progress for
     * STALL_LIMIT consecutive rounds) and stops spinning instead of
     * burning the full iteration budget waiting on a reactor that has
     * nothing left to do, which is exactly what happens once the fix
     * takes hold and would otherwise make this test needlessly slow. */
    uint8_t chunk[4096];
    memset(chunk, 'q', sizeof(chunk));
    const size_t target_total = 4 * 1024 * 1024;
    const int STALL_LIMIT = 30;
    size_t total_written = 0;
    int stall_spins = 0;
    for (int spin = 0; spin < 2000 && stall_spins < STALL_LIMIT; spin++) {
        int made_progress = 0;
        /* Drain as much as the kernel currently accepts in one go, rather
         * than paying a reactor turn per 4 KiB chunk. */
        for (int w = 0; w < 64 && total_written < target_total; w++) {
            ssize_t n = write(sp.outer, chunk, sizeof(chunk));
            if (n <= 0) {
                break;
            }
            total_written += (size_t)n;
            made_progress = 1;
        }
        cloak_reactor_run_once(r, 5);
        /* Keep a's own stream reassembly buffer from blocking connA's
         * continued draining -- not required for this test's own
         * assertions, just keeps the healthy side of the pool moving. */
        uint8_t sink[4096];
        for (;;) {
            long rn = cloak_stream_read(s, sink, sizeof(sink));
            if (rn <= 0) {
                break;
            }
            made_progress = 1;
        }
        if (cloak_session_is_closed(&a.sesh) || cloak_session_is_closed(&b.sesh)) {
            break; /* stop early on the very regression this test exists to catch */
        }
        if (total_written >= target_total) {
            break;
        }
        stall_spins = made_progress ? 0 : stall_spins + 1;
    }

    ASSERT_TRUE(!cloak_session_is_closed(&a.sesh));
    ASSERT_TRUE(!cloak_session_is_closed(&b.sesh));

    cloak_stream_relay_stop(&sr);
    close(sp.outer);
    if (!cloak_session_is_closed(&b.sesh)) {
        cloak_session_release_stream(&b.sesh, b.accepted);
    }
    if (!cloak_session_is_closed(&a.sesh)) {
        cloak_session_release_stream(&a.sesh, s);
    }
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    close(dead_pair[1]);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_forwards_both_directions();
    test_large_transfer_survives_backpressure();
    test_pump_does_not_strand_bytes_when_fd_unstalls();
    test_closing_fd_fires_done_once_and_ends_far_stream();
    test_stream_eof_closes_fd_and_fires_done_once();
    test_stop_is_idempotent_and_suppresses_done();
    test_failed_start_leaves_struct_safe();
    test_immediate_finish_defers_on_done();
    test_stop_before_immediate_finish_fires_cancels_timer();
    test_stopping_relay_from_on_broken_avoids_use_after_free();
    test_start_rejects_when_no_connection_can_ever_fit_one_frame();
    test_session_survives_one_congested_connection_among_many();
TEST_MAIN_END()
