#define _POSIX_C_SOURCE 200809L
#include "cloak/proxy.h"
#include "cloak/base64.h"
#include "cloak/clienthello.h"
#include "cloak/crypto.h"
#include "cloak/dispatcher.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "test_framework.h"
#include "client_harness.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* TEARDOWN coverage for cloak_proxy_t: what happens when a session DIES,
 * which is the half of this module that is either right or is a
 * use-after-free. test_proxy_stream.c covers the same machinery while
 * sessions live.
 *
 * MOST OF THIS FILE ONLY MEANS ANYTHING UNDER ASan. A relay left running
 * past its session's on_broken still has its fd registered with the
 * reactor, and the next byte that arrives on it runs cloak_stream_write
 * on freed memory -- on an uninstrumented build that reads whatever the
 * allocator left behind and very often "passes". Every test here is
 * written to fail loudly under -fsanitize=address (heap-use-after-free)
 * or LeakSanitizer (an abandoned context), and the counter assertions
 * (cloak_proxy_stream_count / cloak_proxy_session_count reaching 0) are
 * what gives the plain Debug build something to check at all. Run this
 * file under BOTH suites; a green Debug run on its own proves much less
 * than it looks like it does.
 *
 * EVERY wait is a bounded pump_until and EVERY peer socket is
 * non-blocking, the same discipline test_proxy_stream.c states and for
 * the same reason (three tests on this project have hung or flaked in
 * CI). */

/* ---- fake upstream: accepts, records, echoes ---------------------------- */

#define UP_MAX_CONNS 8
#define UP_BUF_CAP ((size_t)(1u << 16))

typedef struct {
    int fd;
    uint8_t *in;
    size_t in_len;
    uint8_t *out;
    size_t out_len;
    size_t out_head;
    int eof;
} up_conn_t;

struct upstream;
typedef struct {
    struct upstream *up;
    int idx;
} up_slot_t;

typedef struct upstream {
    cloak_reactor_t *reactor;
    int accept_count;
    up_conn_t conns[UP_MAX_CONNS];
    up_slot_t slots[UP_MAX_CONNS];
} upstream_t;

static void up_flush(up_conn_t *c) {
    while (c->out_head < c->out_len) {
        ssize_t n = send(c->fd, c->out + c->out_head, c->out_len - c->out_head, MSG_NOSIGNAL);
        if (n > 0) {
            c->out_head += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (c->out_head == c->out_len) {
        c->out_head = 0;
        c->out_len = 0;
    }
}

static void up_sync(upstream_t *up, up_conn_t *c) {
    uint32_t ev = CLOAK_REACTOR_READABLE;
    if (c->out_head < c->out_len) {
        ev |= CLOAK_REACTOR_WRITABLE;
    }
    (void)cloak_reactor_mod_fd(up->reactor, c->fd, ev);
}

static void up_on_readable_writable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    up_slot_t *slot = userdata;
    upstream_t *up = slot->up;
    up_conn_t *c = &up->conns[slot->idx];

    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        up_flush(c);
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        for (;;) {
            if (c->in_len >= UP_BUF_CAP) {
                break;
            }
            size_t room = UP_BUF_CAP - c->in_len;
            if (UP_BUF_CAP - c->out_len < room) {
                room = UP_BUF_CAP - c->out_len;
            }
            if (room == 0) {
                break;
            }
            ssize_t n = read(c->fd, c->in + c->in_len, room);
            if (n > 0) {
                memcpy(c->out + c->out_len, c->in + c->in_len, (size_t)n);
                c->out_len += (size_t)n;
                c->in_len += (size_t)n;
                up_flush(c);
                continue;
            }
            if (n == 0) {
                c->eof = 1;
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            break;
        }
    }
    up_sync(up, c);
}

static void up_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    upstream_t *up = userdata;
    if (up->accept_count >= UP_MAX_CONNS) {
        close(fd);
        return;
    }
    int idx = up->accept_count++;
    up_conn_t *c = &up->conns[idx];
    c->fd = fd;
    c->in = malloc(UP_BUF_CAP);
    c->out = malloc(UP_BUF_CAP);
    if (c->in == NULL || c->out == NULL) {
        free(c->in);
        free(c->out);
        c->in = NULL;
        c->out = NULL;
        close(fd);
        c->fd = -1;
        return;
    }
    up->slots[idx].up = up;
    up->slots[idx].idx = idx;
    (void)cloak_reactor_add_fd(up->reactor, fd, CLOAK_REACTOR_READABLE, up_on_readable_writable,
                               &up->slots[idx]);
}

/* Pushes bytes at the proxy from the upstream side, unprompted. This is
 * how the live-relay teardown test reproduces the ACTUAL bug obligation 1
 * exists for rather than only its symptom: a relay left running past its
 * session's teardown still has this socket's peer registered with the
 * reactor, so the next byte to arrive on it runs cloak_stream_write
 * against a freed cloak_stream_t. Without a byte arriving, that mistake
 * shows up merely as a leak at exit. */
static void up_send(upstream_t *up, int idx, const void *data, size_t len) {
    up_conn_t *c = &up->conns[idx];
    if (c->fd < 0 || c->out_len + len > UP_BUF_CAP) {
        return;
    }
    memcpy(c->out + c->out_len, data, len);
    c->out_len += len;
    up_flush(c);
    up_sync(up, c);
}

static void up_close_conn(upstream_t *up, int idx) {
    up_conn_t *c = &up->conns[idx];
    if (c->fd >= 0) {
        cloak_reactor_remove_fd(up->reactor, c->fd);
        close(c->fd);
        c->fd = -1;
    }
}

static void up_destroy(upstream_t *up) {
    for (int i = 0; i < UP_MAX_CONNS; i++) {
        up_close_conn(up, i);
        free(up->conns[i].in);
        free(up->conns[i].out);
        up->conns[i].in = NULL;
        up->conns[i].out = NULL;
    }
}

/* ---- the black hole: an upstream whose connect(2) never completes -------
 *
 * The DIALING teardown case needs a stream whose cloak_dial_t is still in
 * flight when its session breaks, and that needs a TCP address whose
 * connect neither completes nor fails for the duration of a test.
 *
 * "Bind a listener and never accept it" is NOT that address, and this is
 * the one piece of this file worth reading carefully: on Linux a SYN to a
 * listening socket with room in its accept queue completes the handshake
 * in the kernel, with no accept(2) anywhere -- connect() returns success
 * and the dial callback fires. What DOES keep a connect pending is a
 * listening socket whose accept queue is FULL: tcp_conn_request drops the
 * SYN outright (LISTENOVERFLOWS), the client retransmits, and connect
 * stays in progress until it times out minutes later. listen(fd, 0) makes
 * that queue hold exactly one connection, so one filler connect saturates
 * it; BH_FILLERS is 4 purely so this does not depend on a kernel that
 * rounds a zero backlog up a little.
 *
 * The tests that use this assert the DIALING state itself (dialing == 1
 * on a live stream context) before they do anything else, so if a future
 * kernel ever changed that behaviour this file fails loudly rather than
 * quietly stopping covering the case it exists for. */

#define BH_FILLERS 4

/* ---- fixture ------------------------------------------------------------- */

struct fixture {
    cloak_reactor_t *reactor;

    cover_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;

    upstream_t up;
    cloak_listener_t up_listener;
    int have_up_listener;
    int up_port;

    int bh_listen_fd;
    int bh_port;
    int bh_filler[BH_FILLERS];

    cloak_server_config_t cfg;
    cloak_server_t srv;
    int srv_ready;

    cloak_proxy_t proxy;
    int proxy_ready;

    cloak_server_registry_t registry;
    int registry_ready;

    cloak_dispatcher_t d;
    int d_ready;
    cloak_listener_t front;
    int have_front;

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    /* TWO bypass UIDs, because one is not enough to test the thing every
     * abort path in this module depends on: proxy_find_session matches on
     * (uid, session_id), and with a single UID in the config no test can
     * ever hold two contexts whose session_ids collide. Clients choose
     * their own session ids and they are small, so that collision is
     * routine in production. See test_same_session_id_different_uid. */
    uint8_t uid_ok[CLOAK_UID_LEN];
    uint8_t uid_ok2[CLOAK_UID_LEN];

    /* What the chained cloak_registry_broken_cb saw, recorded at the
     * moment it ran -- i.e. AFTER cloak_proxy_registry_broken's own
     * cleanup, which is the whole point of the ordering. */
    int chain_calls;
    uint32_t chain_last_session_id;
    size_t chain_streams;
    size_t chain_sessions;

    /* Proof that the abandoned-handshake tests are not vacuous: a
     * session_aborted assertion means nothing unless prepare_session
     * really did run and really did return 0 for that handshake. */
    int prepare_calls;
    int prepare_ok;
    int aborted_calls;
};

/* The chain (cloak_proxy_config_t::chain): it must observe the proxy's own
 * cleanup as ALREADY DONE. */
static void chain_on_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                            const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                            void *userdata) {
    (void)reg;
    (void)sesh;
    (void)uid;
    struct fixture *fx = userdata;
    fx->chain_calls++;
    fx->chain_last_session_id = session_id;
    fx->chain_streams = cloak_proxy_stream_count(&fx->proxy);
    fx->chain_sessions = cloak_proxy_session_count(&fx->proxy);
}

/* Thin counting wrappers around the two real entry points, so that every
 * assertion below about "the context was reclaimed" can be paired with
 * one about "the callback that reclaims it actually fired, for a
 * handshake that had actually been prepared". */
static int fx_prepare_session(cloak_dispatcher_t *d, const cloak_server_clientinfo_t *info,
                              cloak_session_config_t *config, void *userdata) {
    struct fixture *fx = userdata;
    fx->prepare_calls++;
    int rc = cloak_proxy_prepare_session(d, info, config, &fx->proxy);
    if (rc == 0) {
        fx->prepare_ok++;
    }
    return rc;
}

static void fx_session_aborted(cloak_dispatcher_t *d, const uint8_t uid[CLOAK_UID_LEN],
                               uint32_t session_id, void *userdata) {
    struct fixture *fx = userdata;
    fx->aborted_calls++;
    cloak_proxy_session_aborted(d, uid, session_id, &fx->proxy);
}

static int blackhole_open(struct fixture *fx) {
    fx->bh_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fx->bh_listen_fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fx->bh_listen_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        return -1;
    }
    if (listen(fx->bh_listen_fd, 0) != 0) {
        return -1;
    }
    socklen_t len = sizeof(sa);
    if (getsockname(fx->bh_listen_fd, (struct sockaddr *)&sa, &len) != 0) {
        return -1;
    }
    fx->bh_port = ntohs(sa.sin_port);

    for (int i = 0; i < BH_FILLERS; i++) {
        int f = socket(AF_INET, SOCK_STREAM, 0);
        if (f < 0) {
            return -1;
        }
        fx->bh_filler[i] = f;
        int flags = fcntl(f, F_GETFL, 0);
        (void)fcntl(f, F_SETFL, flags | O_NONBLOCK);
        /* EINPROGRESS is the expected answer for every filler after the
         * first; nothing here ever waits on them. */
        (void)connect(f, (struct sockaddr *)&sa, sizeof(sa));
    }
    return 0;
}

/* conn_send_queue_cap sizes the SERVER session's outbound pool: the
 * roomy default for every test but the RETRY ones, which need it exactly
 * one byte below a single worst-case frame's on-wire cost (see
 * test_retry_state_is_torn_down). retry_delay_ms/max_retries go straight
 * into cloak_proxy_config_t.
 *
 * The ProxyBook always carries two entries: "ss" -> the echoing upstream,
 * "bh" -> the black hole above. Which one a session uses is chosen per
 * handshake by its proxy method, which is what lets one fixture hold a
 * relaying session and a permanently-dialing one at the same time. */
static int fixture_init_opts(struct fixture *fx, size_t conn_send_queue_cap,
                             uint64_t dial_timeout_ms, uint64_t retry_delay_ms,
                             unsigned max_retries) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    for (int i = 0; i < UP_MAX_CONNS; i++) {
        fx->up.conns[i].fd = -1;
    }
    fx->bh_listen_fd = -1;
    for (int i = 0; i < BH_FILLERS; i++) {
        fx->bh_filler[i] = -1;
    }

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

    fx->cover.reactor = fx->reactor;
    fx->cover.fd = -1;
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->cover_listener, fx->reactor, "127.0.0.1:0",
                                         cover_on_accept, &fx->cover, err, sizeof(err)));
    fx->have_cover_listener = 1;
    int cover_port = cloak_listener_port(&fx->cover_listener);
    ASSERT_TRUE(cover_port > 0);

    fx->up.reactor = fx->reactor;
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->up_listener, fx->reactor, "127.0.0.1:0", up_on_accept,
                                         &fx->up, err, sizeof(err)));
    fx->have_up_listener = 1;
    fx->up_port = cloak_listener_port(&fx->up_listener);
    ASSERT_TRUE(fx->up_port > 0);

    ASSERT_EQ_INT(0, blackhole_open(fx));
    ASSERT_TRUE(fx->bh_port > 0);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, fx->server_pub));

    for (size_t i = 0; i < CLOAK_UID_LEN; i++) {
        fx->uid_ok[i] = (uint8_t)(0x10 + i);
        fx->uid_ok2[i] = (uint8_t)(0xA0 + i);
    }

    char priv_b64[64];
    char uidok_b64[32];
    char uidok2_b64[32];
    ASSERT_EQ_INT(
        0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64, sizeof(priv_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(fx->uid_ok, CLOAK_UID_LEN, uidok_b64, sizeof(uidok_b64)));
    ASSERT_EQ_INT(
        0, cloak_base64_encode(fx->uid_ok2, CLOAK_UID_LEN, uidok2_b64, sizeof(uidok2_b64)));

    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:%d\"],"
             "\"bh\":[\"tcp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\",\"%s\"]}",
             fx->up_port, fx->bh_port, cover_port, priv_b64, uidok_b64, uidok2_b64);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    cloak_proxy_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.reactor = fx->reactor;
    pcfg.srv = &fx->srv;
    pcfg.dial_timeout_ms = dial_timeout_ms;
    pcfg.retry_delay_ms = retry_delay_ms;
    pcfg.max_retries = max_retries;
    pcfg.chain = chain_on_broken;
    pcfg.chain_userdata = fx;
    ASSERT_EQ_INT(0, cloak_proxy_init(&fx->proxy, &pcfg));
    fx->proxy_ready = 1;

    /* THE WIRING THIS WHOLE FILE IS ABOUT: the proxy IS the registry's
     * broken callback. An owner that forgets this has a use-after-free,
     * which is precisely why the module is wired this way round rather
     * than exporting something the owner must remember to call. */
    ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor,
                                                cloak_proxy_registry_broken, &fx->proxy));
    fx->registry_ready = 1;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.registry = &fx->registry;

    dcfg.session_config_template.max_on_wire_size = 16401;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = conn_send_queue_cap;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;

    dcfg.prepare_session = fx_prepare_session;
    dcfg.prepare_session_userdata = fx;
    dcfg.session_aborted = fx_session_aborted;
    dcfg.session_aborted_userdata = fx;

    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, "127.0.0.1:0",
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;

    int sndbuf = 8192;
    (void)setsockopt(fx->front.fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    return 0;
}

static int fixture_init(struct fixture *fx) {
    return fixture_init_opts(fx, 262144, 0, 0, 0);
}

/* THE DIAL TIMEOUT IS WHY THE DIALING TESTS BELOW ARE TESTS AT ALL, and
 * it was put here by mutation: with the proxy's default 10-second dial
 * timeout, deleting cloak_dial_cancel from the teardown walk did not fail
 * a single assertion in this file. Nothing ever fired into the freed
 * context, because a dial against the black hole neither completes nor
 * times out inside a test's lifetime -- the leaked reactor registration
 * and the leaked timer just sat there and the process exited.
 *
 * A short timeout (DIAL_TIMEOUT_MS) plus a post-teardown pump longer than
 * it (pump_for_ms(POST_TEARDOWN_MS)) is what turns "the cancel did not
 * happen" into an observable heap-use-after-free: the dial's own timeout
 * timer fires at a moment when its userdata is a freed
 * cloak_proxy_stream_t. DIAL_TIMEOUT_MS must stay comfortably longer than
 * the few milliseconds a test needs to reach the DIALING state and break
 * its session, or the dial would time out on its own before the state
 * under test was ever set up -- which would fail loudly (the stream-count
 * precondition), not silently. POST_TEARDOWN_MS must stay longer than
 * both DIAL_TIMEOUT_MS and the retry ladder's 50ms delay, since it has to
 * outlast whichever timer the teardown was supposed to cancel. */
#define DIAL_TIMEOUT_MS ((uint64_t)200)
#define POST_TEARDOWN_MS 400L

static int fixture_init_dialing(struct fixture *fx) {
    return fixture_init_opts(fx, 262144, DIAL_TIMEOUT_MS, 0, 0);
}

/* Destroy order is test_proxy_stream.c's, for the reasons stated there --
 * in particular THE PROXY BEFORE THE REGISTRY. Note that in this file
 * most tests have already driven the proxy's teardown through the broken
 * path by the time this runs, so cloak_proxy_destroy here is usually the
 * idempotent no-op case; the destroy-path tests are the ones that make it
 * do work. */
static void fixture_destroy(struct fixture *fx) {
    if (fx->have_front) {
        cloak_listener_close(&fx->front);
    }
    if (fx->d_ready) {
        cloak_dispatcher_destroy(&fx->d);
    }
    if (fx->proxy_ready) {
        cloak_proxy_destroy(&fx->proxy);
    }
    if (fx->registry_ready) {
        cloak_server_registry_destroy(&fx->registry);
    }
    if (fx->srv_ready) {
        cloak_server_destroy(&fx->srv);
    }
    if (fx->have_up_listener) {
        cloak_listener_close(&fx->up_listener);
    }
    up_destroy(&fx->up);
    for (int i = 0; i < BH_FILLERS; i++) {
        if (fx->bh_filler[i] >= 0) {
            close(fx->bh_filler[i]);
            fx->bh_filler[i] = -1;
        }
    }
    if (fx->bh_listen_fd >= 0) {
        close(fx->bh_listen_fd);
        fx->bh_listen_fd = -1;
    }
    if (fx->have_cover_listener) {
        cloak_listener_close(&fx->cover_listener);
    }
    if (fx->cover.fd >= 0) {
        close(fx->cover.fd);
    }
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
    }
}

static int front_port(struct fixture *fx) {
    return cloak_listener_port(&fx->front);
}

static int open_client_as(struct fixture *fx, client_session_t *cs,
                          const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                          const char *proxy_method) {
    cloak_session_config_t ccfg;
    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.ordering = CLOAK_SESSION_ORDERING_ORDERED;
    ccfg.max_on_wire_size = 16401;
    ccfg.stream_recv_capacity = 65536;
    ccfg.stream_max_pending_frames = 64;
    ccfg.conn_send_queue_cap = 262144;
    ccfg.inactivity_timeout_ms = 60000;
    return client_session_open(cs, fx->reactor, front_port(fx), fx->server_pub, uid, proxy_method,
                               session_id, 0, &ccfg);
}

static int open_client_via(struct fixture *fx, client_session_t *cs, uint32_t session_id,
                           const char *proxy_method) {
    return open_client_as(fx, cs, fx->uid_ok, session_id, proxy_method);
}

static int open_client(struct fixture *fx, client_session_t *cs, uint32_t session_id) {
    return open_client_via(fx, cs, session_id, "ss");
}

/* ---- predicates (every one of them bounded by pump_until) --------------- */

struct up_wait {
    upstream_t *up;
    int idx;
    size_t want;
};

static int up_has_len(void *ctx) {
    struct up_wait *w = ctx;
    return w->up->conns[w->idx].in_len >= w->want;
}

static int up_accepted(void *ctx) {
    struct up_wait *w = ctx;
    return w->up->accept_count >= w->idx;
}

static int up_saw_eof(void *ctx) {
    struct up_wait *w = ctx;
    return w->up->conns[w->idx].eof;
}

struct fx_wait {
    struct fixture *fx;
    size_t want;
};

/* KEEPS THE REACTOR TURNING FOR AT LEAST ms MILLISECONDS OF WALL CLOCK,
 * which an iteration-counted pump_until does NOT do and which every
 * post-teardown window in this file depends on.
 *
 * cloak_reactor_run_once returns as soon as any fd is ready, so its
 * timeout is a ceiling, not a floor -- and a socket sitting at EOF (an
 * upstream whose peer the teardown under test just closed) is ready on
 * every single turn. An iteration-counted pump therefore burns its whole
 * budget in well under a millisecond in exactly the tests that most need
 * real time to pass, and never reaches a 50ms retry timer.
 *
 * FOUND BY MUTATION, which is the only reason this exists: with
 * iteration-counted pumps, deleting the retry-timer cancel from the
 * teardown walk did not fail a single assertion in this file, because
 * the timer that would have fired into freed memory was still 50ms away
 * when the test finished. Still doubly bounded (deadline AND iteration
 * cap), so it cannot hang. */
struct until_ms {
    struct timespec start;
    long ms;
};

static int elapsed_at_least(void *ctx) {
    struct until_ms *w = ctx;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long d = (long)(now.tv_sec - w->start.tv_sec) * 1000L +
             (long)((now.tv_nsec - w->start.tv_nsec) / 1000000L);
    return d >= w->ms;
}

/* The iteration cap is DERIVED FROM ms, and generously, so that the wall
 * clock is always the bound that binds. A fixed cap does not work and
 * quietly lost this file real coverage once already: run_once returns in
 * well under a microsecond when an fd is always ready, so a flat 100000
 * iterations was exhausted after 84ms of a 400ms request in four of the
 * five call sites -- and the discarded return value hid it. 20000
 * iterations per millisecond allows for a reactor spinning at 20M turns
 * a second before the cap could bind again; if it ever does, the assert
 * below fails the test rather than silently shortening the window a
 * mutation is supposed to be caught in. */
#define PUMP_ITERS_PER_MS 20000

static void pump_for_ms(cloak_reactor_t *r, long ms) {
    struct until_ms w;
    clock_gettime(CLOCK_MONOTONIC, &w.start);
    w.ms = ms;
    int reached = pump_until(r, elapsed_at_least, &w, (int)(ms * PUMP_ITERS_PER_MS), 2);
    /* NOT decoration: every caller's comment claims to have pumped past
     * some timer's deadline, and this is what makes that claim true
     * rather than merely intended. */
    ASSERT_TRUE(reached);
}

/* Every teardown wait in this file is on the CALLBACK having run, never
 * on a count having reached 0: the counts are what the callback is
 * asserted to have got right, so waiting on them would make the
 * assertions that follow tautological. */
static int chain_calls_at_least(void *ctx) {
    struct fx_wait *w = ctx;
    return (size_t)w->fx->chain_calls >= w->want;
}

static int aborted_calls_at_least(void *ctx) {
    struct fx_wait *w = ctx;
    return (size_t)w->fx->aborted_calls >= w->want;
}

/* Reaching into cloak_proxy_stream_t is deliberate and is what makes the
 * DIALING and RETRY cases assertions rather than hopes: both states are
 * invisible from the outside (no byte moves in either), so a test that
 * merely broke a session at some arbitrary moment could sit in neither
 * state and still pass. test_proxy_stream.c's retry test already reads
 * these same fields. */
static int some_stream_dialing(void *ctx) {
    struct fixture *fx = ctx;
    for (cloak_proxy_session_t *ps = fx->proxy.sessions; ps != NULL; ps = ps->next) {
        for (cloak_proxy_stream_t *pst = ps->streams; pst != NULL; pst = pst->next) {
            if (pst->dialing) {
                return 1;
            }
        }
    }
    return 0;
}

static int some_stream_retrying(void *ctx) {
    struct fixture *fx = ctx;
    for (cloak_proxy_session_t *ps = fx->proxy.sessions; ps != NULL; ps = ps->next) {
        for (cloak_proxy_stream_t *pst = ps->streams; pst != NULL; pst = pst->next) {
            if (pst->retry_timer != CLOAK_TIMER_INVALID && pst->fd_pending >= 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* Waits for the broken callback while latching, on every turn, whether
 * the session's stream was still DIALING -- updated only while a stream
 * context exists, so the final value is the state the teardown walk
 * actually saw rather than the state some earlier assertion saw. */
struct dial_watch {
    struct fixture *fx;
    int last_dialing;
};

static int chain_after_dialing(void *ctx) {
    struct dial_watch *w = ctx;
    if (cloak_proxy_stream_count(&w->fx->proxy) > 0) {
        w->last_dialing = some_stream_dialing(w->fx);
    }
    return w->fx->chain_calls >= 1;
}

static int some_stream_relaying(void *ctx) {
    struct fixture *fx = ctx;
    for (cloak_proxy_session_t *ps = fx->proxy.sessions; ps != NULL; ps = ps->next) {
        for (cloak_proxy_stream_t *pst = ps->streams; pst != NULL; pst = pst->next) {
            if (pst->relaying) {
                return 1;
            }
        }
    }
    return 0;
}

/* ---- tests ---------------------------------------------------------------- */

/* 1. THE CASE OBLIGATION 1 EXISTS FOR. One stream mid-transfer, relaying,
 * when the connection carrying its session dies. Immediately after the
 * registry's broken callback returns, the session destroys and frees
 * every still-active stream -- so a relay still running at that moment
 * holds a freed cloak_stream_t and a live reactor registration, and the
 * next byte from its upstream is a heap-use-after-free.
 *
 * ON A PLAIN DEBUG BUILD THE COUNTER ASSERTIONS BELOW ARE ALL THIS TEST
 * CAN SEE. The use-after-free itself shows up under ASan, which is where
 * this file's real verdict comes from. */
static void test_broken_session_with_live_relay(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 2001));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(4, (int)cloak_stream_write(st, (const uint8_t *)"ping", 4));

    struct up_wait uw = {&fx.up, 0, 4};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_TRUE(some_stream_relaying(&fx));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    /* Kills the only connection this session has: the server sees EOF,
     * the pool empties, the session breaks. */
    client_session_close(&cs);

    struct fx_wait w = {&fx, 1};
    ASSERT_TRUE(pump_until(fx.reactor, chain_calls_at_least, &w, 600, 5));
    ASSERT_EQ_INT(1, fx.chain_calls);
    ASSERT_EQ_INT(2001, (int)fx.chain_last_session_id);
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));

    /* THE PART THAT MAKES THIS A REGRESSION TEST, and it is not the
     * counters above: the upstream sends a byte AFTER the teardown. A
     * relay that was not stopped still has this socket registered, so
     * this byte reaches cloak_stream_write on a cloak_stream_t the
     * session freed the instant the broken callback returned. With the
     * relay stopped, this lands on a closed socket and nothing happens at
     * all. (Verified by mutation: without this send, deleting
     * cloak_stream_relay_stop showed up only as a leak at exit.) */
    up_send(&fx.up, 0, "boom", 4);
    pump_for_ms(fx.reactor, POST_TEARDOWN_MS);
    ASSERT_EQ_INT(1, fx.chain_calls);

    fixture_destroy(&fx);
}

/* 2. The same, with the stream still DIALING. cloak_dial_t holds its own
 * reactor registration and its own timeout timer, and its callback would
 * fire into a freed cloak_proxy_stream_t -- cloak_dial_cancel is the only
 * thing that prevents it, and only the broken path can still call it. */
static void test_broken_session_with_pending_dial(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_dialing(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client_via(&fx, &cs, 2002, "bh"));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_stream_write(st, (const uint8_t *)"x", 1));

    /* The precondition, asserted rather than assumed: this stream really
     * is stuck mid-connect. */
    ASSERT_TRUE(pump_until(fx.reactor, some_stream_dialing, &fx, 400, 5));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    client_session_close(&cs);

    /* THE STATE AT TEARDOWN IS WHAT THIS TEST IS ABOUT, and asserting it
     * before the break is not the same claim: the break lands several
     * reactor turns after client_session_close, and if the black hole
     * ever stopped black-holing, the dial would complete during those
     * turns, the teardown would take the relay branch instead, and this
     * test would go green having covered nothing it exists to cover. So
     * the dialing flag is re-sampled on every turn for as long as a
     * stream context exists; last_dialing is therefore its value on the
     * last turn before the teardown freed it. */
    struct dial_watch dw = {&fx, 0};
    ASSERT_TRUE(pump_until(fx.reactor, chain_after_dialing, &dw, 600, 5));
    ASSERT_EQ_INT(1, dw.last_dialing);
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));

    /* THE PART THAT MAKES THIS A REGRESSION TEST. A cancel that did not
     * happen leaves the dial's fd registration AND its timeout timer live
     * against a freed cloak_proxy_stream_t; this fixture's dial timeout
     * is DIAL_TIMEOUT_MS, and this pump deliberately outlasts it, so the
     * timer fires inside the test rather than never. See
     * fixture_init_dialing. */
    pump_for_ms(fx.reactor, POST_TEARDOWN_MS);
    ASSERT_EQ_INT(1, fx.chain_calls);

    fixture_destroy(&fx);
}

/* 3. The same, with the stream in RETRY: a connected upstream descriptor
 * parked in fd_pending and a retry timer armed against a context that is
 * about to be freed.
 *
 * The rejection is a GENUINE one, provoked by sizing exactly as
 * test_proxy_stream.c's retry test provokes it: at max_on_wire_size 16401
 * one worst-case frame costs 16406 bytes on the wire, so a pool of 16402
 * can never satisfy cloak_stream_relay_start's start-time check and every
 * start attempt is rejected with -2. max_retries is left at the default
 * (400 * 50ms, twenty seconds), far longer than this test runs, so the
 * stream is still ON the ladder when the session breaks -- which is the
 * state under test. */
static void test_retry_state_is_torn_down(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, 16402, 0, 0, 0));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 2003));

    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_stream_write(st, (const uint8_t *)"x", 1));

    ASSERT_TRUE(pump_until(fx.reactor, some_stream_retrying, &fx, 600, 5));
    ASSERT_EQ_INT(1, fx.up.accept_count);
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    client_session_close(&cs);

    struct fx_wait w = {&fx, 1};
    ASSERT_TRUE(pump_until(fx.reactor, chain_calls_at_least, &w, 600, 5));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));

    /* fd_pending was the proxy's own descriptor: nothing else would have
     * closed it, so the upstream seeing EOF is the externally visible
     * proof that the teardown did. */
    struct up_wait uw = {&fx.up, 0, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_saw_eof, &uw, 200, 5));
    ASSERT_EQ_INT(1, fx.up.conns[0].eof);

    /* An uncancelled retry timer fires 50ms later into freed memory. */
    pump_for_ms(fx.reactor, POST_TEARDOWN_MS);
    ASSERT_EQ_INT(1, fx.chain_calls);

    fixture_destroy(&fx);
}

/* 4. Several sessions, several streams each, all broken in the same
 * reactor turn: the teardown walk has to cope with its own list shrinking
 * under it, in both dimensions at once. */
#define MANY_SESSIONS 3
#define MANY_STREAMS 2

static void test_many_sessions_broken_together(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs[MANY_SESSIONS];
    cloak_stream_t *st[MANY_SESSIONS][MANY_STREAMS];
    memset(st, 0, sizeof(st));

    int opened = 0;
    for (int i = 0; i < MANY_SESSIONS; i++) {
        ASSERT_EQ_INT(0, open_client(&fx, &cs[i], (uint32_t)(2100 + i)));
        opened++;
        for (int j = 0; j < MANY_STREAMS; j++) {
            st[i][j] = cloak_session_open_stream(&cs[i].sesh, NULL);
            ASSERT_TRUE(st[i][j] != NULL);
            if (st[i][j] == NULL) {
                continue;
            }
            ASSERT_EQ_INT(2, (int)cloak_stream_write(st[i][j], (const uint8_t *)"hi", 2));
            /* One at a time, so every dial has completed and every relay
             * is live before the next stream is opened -- the state this
             * test wants at teardown is "all relaying", not "some
             * still dialing". */
            struct up_wait uw = {&fx.up, i * MANY_STREAMS + j + 1, 0};
            ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &uw, 400, 5));
        }
    }

    ASSERT_EQ_INT(MANY_SESSIONS, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(MANY_SESSIONS * MANY_STREAMS, (int)cloak_proxy_stream_count(&fx.proxy));

    /* Every client session is destroyed before the reactor is pumped
     * again, so all three servers-side sessions break off the same turn. */
    for (int i = 0; i < opened; i++) {
        client_session_close(&cs[i]);
    }

    struct fx_wait w = {&fx, MANY_SESSIONS};
    ASSERT_TRUE(pump_until(fx.reactor, chain_calls_at_least, &w, 800, 5));
    ASSERT_EQ_INT(MANY_SESSIONS, fx.chain_calls);
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    /* The last chain call is the last session: by then everything is
     * gone, which is what "the proxy's cleanup runs first" means. */
    ASSERT_EQ_INT(0, (int)fx.chain_streams);
    ASSERT_EQ_INT(0, (int)fx.chain_sessions);

    fixture_destroy(&fx);
}

/* 5a. cloak_proxy_destroy -- the owner's own shutdown rather than a
 * failure path -- with live relays AND a pending dial at once, and with
 * every session still in the registry. This is the ordering
 * cloak/stream_relay.h requires of every caller: stop the relays, THEN
 * destroy the registry that owns the sessions they are bound to. */
static void test_destroy_with_relays_and_pending_dial(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_dialing(&fx));

    client_session_t cs_relay;
    ASSERT_EQ_INT(0, open_client(&fx, &cs_relay, 2201));
    cloak_stream_t *s1 = cloak_session_open_stream(&cs_relay.sesh, NULL);
    cloak_stream_t *s2 = cloak_session_open_stream(&cs_relay.sesh, NULL);
    ASSERT_TRUE(s1 != NULL && s2 != NULL);
    if (s1 == NULL || s2 == NULL) {
        client_session_close(&cs_relay);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(2, (int)cloak_stream_write(s1, (const uint8_t *)"s1", 2));
    struct up_wait uw1 = {&fx.up, 1, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &uw1, 400, 5));
    ASSERT_EQ_INT(2, (int)cloak_stream_write(s2, (const uint8_t *)"s2", 2));
    struct up_wait uw2 = {&fx.up, 2, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &uw2, 400, 5));

    client_session_t cs_dial;
    ASSERT_EQ_INT(0, open_client_via(&fx, &cs_dial, 2202, "bh"));
    cloak_stream_t *s3 = cloak_session_open_stream(&cs_dial.sesh, NULL);
    ASSERT_TRUE(s3 != NULL);
    if (s3 != NULL) {
        ASSERT_EQ_INT(1, (int)cloak_stream_write(s3, (const uint8_t *)"x", 1));
    }
    ASSERT_TRUE(pump_until(fx.reactor, some_stream_dialing, &fx, 400, 5));

    ASSERT_EQ_INT(2, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(3, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_TRUE(some_stream_relaying(&fx));

    cloak_proxy_destroy(&fx.proxy);
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    /* Its own shutdown, not a failure notification: no chain fires. */
    ASSERT_EQ_INT(0, fx.chain_calls);

    /* Nothing left registered may fire afterwards -- pumped past
     * DIAL_TIMEOUT_MS so that an uncancelled dial's timer would fire here
     * rather than merely being leaked at exit. */
    pump_for_ms(fx.reactor, POST_TEARDOWN_MS);
    ASSERT_EQ_INT(0, fx.chain_calls);

    /* The proxy's teardown closed these streams from the far end, so the
     * CLIENT's copies are retired rather than active and
     * cloak_session_destroy will not reclaim them (cloak/session.h's
     * on_broken doc spells this out); releasing them is the test's own
     * housekeeping, not part of what is under test. */
    cloak_session_release_stream(&cs_relay.sesh, s1);
    cloak_session_release_stream(&cs_relay.sesh, s2);
    if (s3 != NULL) {
        cloak_session_release_stream(&cs_dial.sesh, s3);
    }
    client_session_close(&cs_relay);
    client_session_close(&cs_dial);
    fixture_destroy(&fx);
}

/* 5b. The rest of the same case: cloak_proxy_destroy with an ARMED RETRY
 * TIMER and a descriptor parked in fd_pending.
 *
 * It is a separate fixture from 5a and cannot be folded into it: the pool
 * size that makes a start rejection certain (one byte below a worst-case
 * frame) is the same setting that forbids any relay in that fixture from
 * ever starting, and conn_send_queue_cap comes from the dispatcher's one
 * session_config_template, shared by every session it creates. So one
 * fixture can hold relays-and-a-dial, or a retry-and-a-dial, but not all
 * three; between 5a and 5b every state cloak_proxy_destroy has to handle
 * is covered. */
static void test_destroy_with_armed_retry_timer(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init_opts(&fx, 16402, DIAL_TIMEOUT_MS, 0, 0));

    client_session_t cs_retry;
    ASSERT_EQ_INT(0, open_client(&fx, &cs_retry, 2211));
    cloak_stream_t *s1 = cloak_session_open_stream(&cs_retry.sesh, NULL);
    ASSERT_TRUE(s1 != NULL);
    if (s1 == NULL) {
        client_session_close(&cs_retry);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_stream_write(s1, (const uint8_t *)"x", 1));
    ASSERT_TRUE(pump_until(fx.reactor, some_stream_retrying, &fx, 600, 5));

    client_session_t cs_dial;
    ASSERT_EQ_INT(0, open_client_via(&fx, &cs_dial, 2212, "bh"));
    cloak_stream_t *s2 = cloak_session_open_stream(&cs_dial.sesh, NULL);
    ASSERT_TRUE(s2 != NULL);
    if (s2 != NULL) {
        ASSERT_EQ_INT(1, (int)cloak_stream_write(s2, (const uint8_t *)"x", 1));
    }
    ASSERT_TRUE(pump_until(fx.reactor, some_stream_dialing, &fx, 400, 5));

    ASSERT_EQ_INT(2, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));

    cloak_proxy_destroy(&fx.proxy);
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, fx.chain_calls);

    /* The parked descriptor was closed, not leaked. */
    ASSERT_EQ_INT(1, fx.up.accept_count);
    struct up_wait uw = {&fx.up, 0, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_saw_eof, &uw, 200, 5));
    ASSERT_EQ_INT(1, fx.up.conns[0].eof);

    /* Past DIAL_TIMEOUT_MS and past retry_delay_ms, so an uncancelled
     * dial or retry timer would fire into freed memory right here. */
    pump_for_ms(fx.reactor, POST_TEARDOWN_MS);
    ASSERT_EQ_INT(0, fx.chain_calls);

    /* Retired by the teardown above, so the test releases them itself --
     * see the same note in test_destroy_with_relays_and_pending_dial. */
    cloak_session_release_stream(&cs_retry.sesh, s1);
    if (s2 != NULL) {
        cloak_session_release_stream(&cs_dial.sesh, s2);
    }
    client_session_close(&cs_retry);
    client_session_close(&cs_dial);
    fixture_destroy(&fx);
}

/* 6. The chain runs, and runs AFTER the proxy's own cleanup. A chained
 * callback is permitted to call cloak_server_registry_destroy, which
 * destroys every session still in the table -- so if it could observe
 * this proxy's streams as still live, a relay would outlive its session
 * by exactly one callback. */
static void test_chain_observes_cleanup_already_done(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 2301));
    cloak_stream_t *s1 = cloak_session_open_stream(&cs.sesh, NULL);
    cloak_stream_t *s2 = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(s1 != NULL && s2 != NULL);
    if (s1 == NULL || s2 == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(2, (int)cloak_stream_write(s1, (const uint8_t *)"s1", 2));
    struct up_wait uw1 = {&fx.up, 1, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &uw1, 400, 5));
    ASSERT_EQ_INT(2, (int)cloak_stream_write(s2, (const uint8_t *)"s2", 2));
    struct up_wait uw2 = {&fx.up, 2, 0};
    ASSERT_TRUE(pump_until(fx.reactor, up_accepted, &uw2, 400, 5));
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));

    client_session_close(&cs);

    struct fx_wait w = {&fx, 1};
    ASSERT_TRUE(pump_until(fx.reactor, chain_calls_at_least, &w, 600, 5));
    ASSERT_EQ_INT(1, fx.chain_calls);
    ASSERT_EQ_INT(2301, (int)fx.chain_last_session_id);
    ASSERT_EQ_INT(0, (int)fx.chain_streams);
    ASSERT_EQ_INT(0, (int)fx.chain_sessions);

    fixture_destroy(&fx);
}

/* 7. A session this proxy has no context for -- created directly in the
 * registry, never through cloak_proxy_prepare_session -- must reach the
 * chain without the proxy touching anything of its own.
 *
 * A socketpair stands in for the session's connection so that closing one
 * end breaks it on demand; a session with no context is exactly what a
 * prepare_session that returned -1 would leave behind if one could exist
 * (it cannot: that path redirects and creates no session at all), and
 * equally what any OTHER owner of the same registry would create. */
static void test_foreign_session_reaches_chain_untouched(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    /* One real proxied session, so "touched nothing" is a claim with
     * something to touch. */
    client_session_t cs;
    ASSERT_EQ_INT(0, open_client(&fx, &cs, 2401));
    cloak_stream_t *st = cloak_session_open_stream(&cs.sesh, NULL);
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, (int)cloak_stream_write(st, (const uint8_t *)"x", 1));
    struct up_wait uw = {&fx.up, 0, 1};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uw, 400, 5));
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));

    int sv[2] = {-1, -1};
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));

    uint8_t other_uid[CLOAK_UID_LEN];
    memset(other_uid, 0x5A, sizeof(other_uid));

    cloak_session_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.obfuscator.method = CLOAK_AEAD_AES_256_GCM;
    scfg.ordering = CLOAK_SESSION_ORDERING_ORDERED;
    scfg.max_on_wire_size = 16401;
    scfg.stream_recv_capacity = 65536;
    scfg.stream_max_pending_frames = 64;
    scfg.conn_send_queue_cap = 262144;
    scfg.inactivity_timeout_ms = 60000;

    int created = 0;
    cloak_session_t *foreign =
        cloak_server_registry_get_or_create(&fx.registry, other_uid, 4242, &scfg, &created);
    ASSERT_TRUE(foreign != NULL);
    ASSERT_EQ_INT(1, created);
    if (foreign == NULL) {
        close(sv[0]);
        close(sv[1]);
        cloak_session_release_stream(&cs.sesh, st);
        client_session_close(&cs);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(0, cloak_session_add_conn(foreign, sv[0]));
    close(sv[1]); /* the peer is gone: this session breaks */

    struct fx_wait w = {&fx, 1};
    ASSERT_TRUE(pump_until(fx.reactor, chain_calls_at_least, &w, 600, 5));
    ASSERT_EQ_INT(1, fx.chain_calls);
    ASSERT_EQ_INT(4242, (int)fx.chain_last_session_id);
    /* Untouched: the proxied session and its stream are exactly as they
     * were, both at the moment the chain ran and now. */
    ASSERT_EQ_INT(1, (int)fx.chain_sessions);
    ASSERT_EQ_INT(1, (int)fx.chain_streams);
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));
    ASSERT_EQ_INT(0, cs.broken);

    cloak_session_release_stream(&cs.sesh, st);
    client_session_close(&cs);
    fixture_destroy(&fx);
}

/* 8. SITE A of the orphaned-context leak: cloak_server_registry_get_or_
 * create returns NULL (the registry is at CLOAK_REGISTRY_MAX_SESSIONS)
 * immediately after cloak_proxy_prepare_session has already allocated and
 * linked a context for that handshake. No session is ever created, so the
 * registry's broken callback can never fire for it -- without the
 * dispatcher's session_aborted callback that context is leaked, ~64 bytes
 * per handshake, remotely reachable and unbounded.
 *
 * THE COUNTER IS THE DETECTOR, and deliberately so: LeakSanitizer does
 * NOT catch this one, because the fixture's own cloak_proxy_destroy
 * reclaims the orphaned context at the end of the test, exactly as a
 * server shutting down would. The leak is real only for a server that
 * keeps running -- one context per abandoned handshake, for as long as
 * the registry stays full -- which is precisely why it has to be
 * asserted as "the count went back to 0 while the proxy was still
 * alive". Confirmed by mutation: deleting the site-A firing fails the
 * aborted_calls and session_count assertions here and produces no
 * sanitizer output at all.
 *
 * The prepare_ok assertion is what keeps the rest honest: without it, a
 * change that stopped prepare_session running at all would pass this
 * test.
 *
 * The cap is reached with sessions created directly in the registry
 * rather than with 256 handshakes, which is both faster and unambiguous
 * about what is being tested. */
static void test_registry_full_reclaims_prepared_context(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    cloak_session_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.obfuscator.method = CLOAK_AEAD_AES_256_GCM;
    scfg.ordering = CLOAK_SESSION_ORDERING_ORDERED;
    scfg.max_on_wire_size = 16401;
    scfg.stream_recv_capacity = 65536;
    scfg.stream_max_pending_frames = 64;
    scfg.conn_send_queue_cap = 262144;
    scfg.inactivity_timeout_ms = 60000;

    uint8_t filler_uid[CLOAK_UID_LEN];
    memset(filler_uid, 0x77, sizeof(filler_uid));
    for (int i = 0; i < CLOAK_REGISTRY_MAX_SESSIONS; i++) {
        int created = 0;
        cloak_session_t *s = cloak_server_registry_get_or_create(&fx.registry, filler_uid,
                                                                 (uint32_t)(30000 + i), &scfg,
                                                                 &created);
        ASSERT_TRUE(s != NULL);
        if (s == NULL) {
            fixture_destroy(&fx);
            return;
        }
    }
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, (int)cloak_server_registry_count(&fx.registry));

    /* A handshake that is valid in every respect the dispatcher checks:
     * it gets as far as prepare_session and no further. */
    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len =
        build_client_record(fx.server_pub, fx.uid_ok, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM, now,
                            2501, 0, record, sizeof(record), shared_secret);
    ASSERT_TRUE(record_len > 0);

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    if (client < 0) {
        fixture_destroy(&fx);
        return;
    }
    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    struct fx_wait w = {&fx, 1};
    ASSERT_TRUE(pump_until(fx.reactor, aborted_calls_at_least, &w, 400, 5));

    ASSERT_EQ_INT(1, fx.prepare_calls);
    ASSERT_EQ_INT(1, fx.prepare_ok); /* a context really was allocated */
    ASSERT_EQ_INT(1, fx.aborted_calls);
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));
    /* Nothing was created, so nothing was removed either. */
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, (int)cloak_server_registry_count(&fx.registry));

    /* And the connection itself took the ordinary redirect. */
    struct len_wait lw = {&fx.cover, record_len};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &lw, 300, 5));
    ASSERT_EQ_INT((int)record_len, (int)fx.cover.len);

    close(client);
    fixture_destroy(&fx);
}

/* 9. SITE C of the same leak: this connection created a session, then its
 * reply write failed, so conn_teardown unwinds the session it created --
 * through cloak_server_registry_close, which deliberately does NOT fire
 * on_broken. Same orphaned context, reached by a completely different
 * route.
 *
 * The reply write is forced to fail with test_write_shim.c's LD_PRELOAD
 * interposition, the same mechanism (and the same one-shot peer-port
 * protocol) test_dispatcher_auth.c uses for this connection state: the
 * reply is far smaller than any socket buffer's floor, so genuine
 * backpressure cannot produce a failed write for it.
 *
 * SITE B (a cloak_server_auth_compose_reply failure after step 8 created
 * the session) has NO test here and that is a deliberate, reported gap:
 * every one of that function's failure returns is an internal invariant
 * -- a cert length drawn from its own fixed table, an output buffer sized
 * by the same header that defines the reply, and an AEAD seal of a
 * 32-byte key -- so no input this test could choose can provoke it. The
 * firing at that site is one line, positioned identically to site C's and
 * gated on the same `created` flag. */
static void test_reply_write_failure_reclaims_prepared_context(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len =
        build_client_record(fx.server_pub, fx.uid_ok, "ss", (uint8_t)CLOAK_AEAD_AES_256_GCM, now,
                            2601, 0, record, sizeof(record), shared_secret);
    ASSERT_TRUE(record_len > 0);

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    if (client < 0) {
        fixture_destroy(&fx);
        return;
    }
    int cport = client_local_port(client);
    ASSERT_TRUE(cport > 0);

    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", cport);
    setenv("CLOAK_TEST_FORCE_PEER_PORT", portbuf, 1);
    setenv("CLOAK_TEST_FORCE_MODE", "error", 1);

    ASSERT_TRUE(write(client, record, record_len) == (ssize_t)record_len);

    struct fx_wait w = {&fx, 1};
    ASSERT_TRUE(pump_until(fx.reactor, aborted_calls_at_least, &w, 400, 5));

    unsetenv("CLOAK_TEST_FORCE_PEER_PORT");
    unsetenv("CLOAK_TEST_FORCE_MODE");

    ASSERT_EQ_INT(1, fx.prepare_calls);
    ASSERT_EQ_INT(1, fx.prepare_ok);
    ASSERT_EQ_INT(1, fx.aborted_calls);
    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    /* The session this connection created was closed with it. */
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&fx.registry));
    /* A closed session fires no on_broken -- which is exactly why
     * session_aborted has to exist. */
    ASSERT_EQ_INT(0, fx.chain_calls);

    close(client);
    fixture_destroy(&fx);
}

/* A client-side accumulating reader, polled from inside a bounded
 * pump_until predicate -- the same discipline test_proxy_stream.c uses
 * and for the same reason: a poll cannot miss an edge, so a wait built on
 * it is bounded by construction where one built on a callback is not. */
struct sb_reader {
    cloak_stream_t *stream;
    uint8_t buf[32];
    size_t len;
};

static int sb_has_nine(void *ctx) {
    struct sb_reader *r = ctx;
    while (r->len < sizeof(r->buf)) {
        long n = cloak_stream_read(r->stream, r->buf + r->len, sizeof(r->buf) - r->len);
        if (n <= 0) {
            break;
        }
        r->len += (size_t)n;
    }
    return r->len >= 9;
}

/* The context this proxy holds for exactly (uid, session_id), or NULL --
 * the test-side equivalent of proxy_find_session, written out here so the
 * test can name WHICH context survived rather than only how many did.
 * Deliberately not calling into the module's own lookup: a test that
 * asked the code under test which context it thinks it has would pass
 * under the very mutation it exists to catch. */
static cloak_proxy_session_t *ctx_for(struct fixture *fx, const uint8_t uid[CLOAK_UID_LEN],
                                      uint32_t session_id) {
    for (cloak_proxy_session_t *ps = fx->proxy.sessions; ps != NULL; ps = ps->next) {
        if (ps->session_id == session_id && memcmp(ps->uid, uid, CLOAK_UID_LEN) == 0) {
            return ps;
        }
    }
    return NULL;
}

/* 11. TWO SESSIONS WITH THE SAME session_id UNDER DIFFERENT UIDs, one of
 * them broken. This is the discriminator every abort path in this module
 * rests on and it had no test at all: proxy_find_session matches on
 * (uid, session_id), and both cloak_proxy_registry_broken and
 * cloak_proxy_session_aborted funnel through it. A regression to
 * id-only matching frees the WRONG user's context -- after which that
 * user's relays hold raw pointers into a live session with no owner, and
 * their next upstream byte is a use-after-free.
 *
 * The collision is routine, not exotic: clients pick their own session
 * ids and pick small ones, so two users landing on the same id is
 * ordinary. A is opened first (so it sits at the TAIL of the proxy's
 * session list) and A is the one broken, so an id-only scan -- which
 * returns the first match from the head -- would tear down B.
 *
 * WHAT MAKES THIS A TEST rather than an arrangement: the counters alone
 * would NOT catch id-only matching (one context and one stream die either
 * way, so both counts read 1 regardless). The assertions that bite are
 * the two identity ones -- A's context is gone and B's is still there,
 * still holding its one relaying stream -- and B still carrying bytes
 * both ways afterwards. Verified by mutation; see this file's header on
 * why the post-teardown byte matters. */
static void test_same_session_id_different_uid(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    const uint32_t shared_id = 2701;

    client_session_t cs_a;
    ASSERT_EQ_INT(0, open_client_as(&fx, &cs_a, fx.uid_ok, shared_id, "ss"));
    cloak_stream_t *sa = cloak_session_open_stream(&cs_a.sesh, NULL);
    ASSERT_TRUE(sa != NULL);
    if (sa == NULL) {
        client_session_close(&cs_a);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(2, (int)cloak_stream_write(sa, (const uint8_t *)"aa", 2));
    struct up_wait uwa = {&fx.up, 0, 2};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uwa, 600, 5));

    client_session_t cs_b;
    ASSERT_EQ_INT(0, open_client_as(&fx, &cs_b, fx.uid_ok2, shared_id, "ss"));
    cloak_stream_t *sb = cloak_session_open_stream(&cs_b.sesh, NULL);
    ASSERT_TRUE(sb != NULL);
    if (sb == NULL) {
        cloak_session_release_stream(&cs_a.sesh, sa);
        client_session_close(&cs_a);
        client_session_close(&cs_b);
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(2, (int)cloak_stream_write(sb, (const uint8_t *)"bb", 2));
    struct up_wait uwb = {&fx.up, 1, 2};
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uwb, 600, 5));

    /* Two genuinely distinct contexts, same id, both live and relaying. */
    ASSERT_EQ_INT(2, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(2, (int)cloak_proxy_stream_count(&fx.proxy));
    cloak_proxy_session_t *ctx_a = ctx_for(&fx, fx.uid_ok, shared_id);
    cloak_proxy_session_t *ctx_b = ctx_for(&fx, fx.uid_ok2, shared_id);
    ASSERT_TRUE(ctx_a != NULL);
    ASSERT_TRUE(ctx_b != NULL);
    ASSERT_TRUE(ctx_a != ctx_b);

    /* Break A, and only A. */
    client_session_close(&cs_a);

    struct fx_wait w = {&fx, 1};
    ASSERT_TRUE(pump_until(fx.reactor, chain_calls_at_least, &w, 600, 5));
    ASSERT_EQ_INT(1, fx.chain_calls);
    ASSERT_EQ_INT((int)shared_id, (int)fx.chain_last_session_id);

    /* THE ASSERTIONS THAT DISTINGUISH THE TWO MATCH RULES. */
    ASSERT_TRUE(ctx_for(&fx, fx.uid_ok, shared_id) == NULL);
    cloak_proxy_session_t *still_b = ctx_for(&fx, fx.uid_ok2, shared_id);
    ASSERT_TRUE(still_b == ctx_b);
    ASSERT_EQ_INT(1, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(1, (int)cloak_proxy_stream_count(&fx.proxy));
    if (still_b != NULL) {
        ASSERT_EQ_INT(1, (int)still_b->stream_count);
        ASSERT_TRUE(still_b->streams != NULL);
        if (still_b->streams != NULL) {
            ASSERT_EQ_INT(1, still_b->streams->relaying);
        }
    }
    ASSERT_EQ_INT(0, cs_b.broken);

    /* A's upstream socket sat at EOF from the moment A's teardown closed
     * the proxy's end, and it is STILL REGISTERED with the reactor: this
     * file's fake upstream re-arms interest (cloak_reactor_mod_fd) on
     * every event, so an EOF'd connection is ready on every single turn
     * and cloak_reactor_run_once returns instantly forever. Every
     * iteration-counted pump below would then burn its whole budget in no
     * wall-clock time at all -- which is not hypothetical here: with this
     * line absent, the four post-teardown bytes below never arrived
     * within 600 iterations and the assertion failed. Closing it is what
     * makes the waits that follow bounded by time rather than by spin. */
    up_close_conn(&fx.up, 0);

    /* And B is not merely present, it still works: a byte each way,
     * across the relay whose session A's teardown could have killed. The
     * upstream-to-client direction is the one that reproduces the actual
     * use-after-free rather than its symptom (see this file's header). */
    ASSERT_EQ_INT(3, (int)cloak_stream_write(sb, (const uint8_t *)"bbb", 3));
    uwb.want = 5;
    ASSERT_TRUE(pump_until(fx.reactor, up_has_len, &uwb, 600, 5));
    ASSERT_MEM_EQ(fx.up.conns[1].in, "bbbbb", 5);

    up_send(&fx.up, 1, "down", 4);
    /* 9 = the echoes of "bb" and "bbb" (5) plus "down" (4). Nothing has
     * read this stream yet, so all of it is still queued. */
    struct sb_reader rr = {sb, {0}, 0};
    ASSERT_TRUE(pump_until(fx.reactor, sb_has_nine, &rr, 600, 5));
    ASSERT_EQ_INT(9, (int)rr.len);
    ASSERT_MEM_EQ(rr.buf, "bbbbbdown", 9);

    pump_for_ms(fx.reactor, POST_TEARDOWN_MS);
    ASSERT_EQ_INT(1, fx.chain_calls);

    /* sa is NOT released here: client_session_close(&cs_a) above destroyed
     * A's client session while sa was still active, and cloak_session_
     * destroy frees every active stream itself (cloak/session.h). B's is
     * the opposite case -- its session is alive, so its stream is the
     * test's to release. */
    cloak_session_release_stream(&cs_b.sesh, sb);
    client_session_close(&cs_b);
    fixture_destroy(&fx);
}

/* 10. Argument discipline for the two new entry points, matching what
 * this project asserts for every other public function: neither may
 * dereference a NULL, and neither may do anything at all for a key it
 * has no context for. */
static void test_new_entry_points_tolerate_junk(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx));

    uint8_t uid[CLOAK_UID_LEN];
    memset(uid, 0x33, sizeof(uid));

    /* No proxy: there is not even a chain reachable from here, so
     * nothing at all happens. */
    cloak_proxy_registry_broken(&fx.registry, NULL, uid, 1, NULL);
    cloak_proxy_session_aborted(&fx.d, uid, 1, NULL);
    ASSERT_EQ_INT(0, fx.chain_calls);

    /* No uid: no context can be looked up, but the chain is the owner's
     * and is forwarded to regardless -- this module never swallows a
     * broken notification. */
    cloak_proxy_registry_broken(&fx.registry, NULL, NULL, 1, &fx.proxy);
    ASSERT_EQ_INT(1, fx.chain_calls);
    cloak_proxy_session_aborted(&fx.d, NULL, 1, &fx.proxy);
    ASSERT_EQ_INT(1, fx.chain_calls); /* the aborted path has no chain */

    /* A key this proxy has never seen: not an error either, and the
     * chain still runs for the broken path. */
    cloak_proxy_registry_broken(&fx.registry, NULL, uid, 99, &fx.proxy);
    ASSERT_EQ_INT(2, fx.chain_calls);
    ASSERT_EQ_INT(99, (int)fx.chain_last_session_id);
    cloak_proxy_session_aborted(&fx.d, uid, 99, &fx.proxy);
    ASSERT_EQ_INT(2, fx.chain_calls);

    ASSERT_EQ_INT(0, (int)cloak_proxy_session_count(&fx.proxy));
    ASSERT_EQ_INT(0, (int)cloak_proxy_stream_count(&fx.proxy));

    fixture_destroy(&fx);
}

TEST_MAIN_BEGIN()
test_broken_session_with_live_relay();
test_broken_session_with_pending_dial();
test_retry_state_is_torn_down();
test_many_sessions_broken_together();
test_destroy_with_relays_and_pending_dial();
test_destroy_with_armed_retry_timer();
test_chain_observes_cleanup_already_done();
test_foreign_session_reaches_chain_untouched();
test_registry_full_reclaims_prepared_context();
test_reply_write_failure_reclaims_prepared_context();
test_same_session_id_different_uid();
test_new_entry_points_tolerate_junk();
TEST_MAIN_END()
