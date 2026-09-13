#define _POSIX_C_SOURCE 200809L
#include "cloak/dispatcher.h"
#include "cloak/firstpacket.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/server.h"
#include "test_framework.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Base64 of 32 bytes of key material -- the server config parser does not
 * validate the private key cryptographically, so any 32-byte value is
 * fine. Same literal test_server_state.c uses. */
#define PRIV_B64 "cHJpdmF0ZS1rZXktbWF0ZXJpYWwtZXhhY3RseS0zMiE="

/* ---- bounded reactor pumping ------------------------------------------
 *
 * Every wait in this file is expressed as "poll the reactor for up to
 * N turns of at most MS each", never as an unbounded loop -- three tests
 * on this project have hung or flaked in CI, all found only by
 * repetition, so every loop here has an explicit iteration cap. */

typedef int (*pump_done_fn)(void *ctx);

static int pump_until(cloak_reactor_t *r, pump_done_fn done, void *ctx, int max_iters,
                      int per_iter_ms) {
    for (int i = 0; i < max_iters; i++) {
        if (done(ctx)) {
            return 1;
        }
        cloak_reactor_run_once(r, per_iter_ms);
    }
    return done(ctx);
}

/* ---- fake cover site ----------------------------------------------------
 *
 * A plain listener (not going through the dispatcher) that accepts one
 * connection and records every byte it reads, exactly the way a real web
 * server would. */

typedef struct {
    cloak_reactor_t *reactor;
    int fd;
    int accept_count;
    uint8_t buf[8192];
    size_t len;
    int eof;
} cover_site_t;

static void cover_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    cover_site_t *cov = userdata;
    for (;;) {
        if (cov->len >= sizeof(cov->buf)) {
            break;
        }
        ssize_t n = read(fd, cov->buf + cov->len, sizeof(cov->buf) - cov->len);
        if (n > 0) {
            cov->len += (size_t)n;
            continue;
        }
        if (n == 0) {
            cov->eof = 1;
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        /* EAGAIN or a real error: either way, nothing more to read now */
        break;
    }
}

static void cover_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    cover_site_t *cov = userdata;
    cov->fd = fd;
    cov->accept_count++;
    cloak_reactor_add_fd(cov->reactor, fd, CLOAK_REACTOR_READABLE, cover_on_readable, cov);
}

struct len_wait {
    cover_site_t *cov;
    size_t want;
};

static int cover_has_len(void *ctx) {
    struct len_wait *w = ctx;
    return w->cov->len >= w->want;
}

/* ---- client helper ------------------------------------------------------
 *
 * A plain blocking socket, like test_listener.c's connect_and_send: the
 * dispatcher's own fd is non-blocking, but nothing requires the peer to
 * be. A receive timeout bounds every read against a dispatcher that never
 * closes the way it should. */

static int client_connect(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* Opens a listener on loopback, records its port, and closes it again --
 * connecting to that port afterward gets a prompt ECONNREFUSED. Same
 * technique libcloak-common/tests/test_dial.c uses. */
static int reserve_closed_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        close(fd);
        return -1;
    }
    int port = ntohs(sa.sin_port);
    close(fd);
    return port;
}

/* ---- fixture: reactor + cover site + server + dispatcher + front listener */

struct fixture {
    cloak_reactor_t *reactor;
    cover_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;
    cloak_server_config_t cfg;
    cloak_server_t srv;
    int srv_ready;
    cloak_dispatcher_t d;
    int d_ready;
    cloak_listener_t front;
    int have_front;
};

/* redir_port < 0 means "start our own fake cover site and redirect
 * there"; redir_port >= 0 means "use this port verbatim" (e.g. a
 * deliberately closed one). */
static int fixture_init(struct fixture *fx, int redir_port, uint64_t handshake_timeout_ms) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

    int port_to_use = redir_port;
    if (redir_port < 0) {
        fx->cover.reactor = fx->reactor;
        fx->cover.fd = -1;
        err[0] = '\0';
        ASSERT_EQ_INT(0, cloak_listener_open(&fx->cover_listener, fx->reactor, "127.0.0.1:0",
                                             cover_on_accept, &fx->cover, err, sizeof(err)));
        fx->have_cover_listener = 1;
        port_to_use = cloak_listener_port(&fx->cover_listener);
        ASSERT_TRUE(port_to_use > 0);
    }

    char json[512];
    snprintf(json, sizeof(json),
             "{\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\"}",
             port_to_use, PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.handshake_timeout_ms = handshake_timeout_ms;
    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, "127.0.0.1:0",
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;

    return 0;
}

static void fixture_destroy(struct fixture *fx) {
    if (fx->have_front) {
        cloak_listener_close(&fx->front);
    }
    if (fx->d_ready) {
        cloak_dispatcher_destroy(&fx->d);
    }
    if (fx->srv_ready) {
        cloak_server_destroy(&fx->srv);
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

/* 1. Junk first byte: the whole line must reach the cover site, byte for
 * byte -- the entire redirect contract in one assertion. */
static void test_junk_first_byte_is_forwarded(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, -1, 0));

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    const char *msg = "HELLO\n";
    ASSERT_TRUE(write(client, msg, strlen(msg)) == (ssize_t)strlen(msg));

    struct len_wait w = {&fx.cover, strlen(msg)};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &w, 200, 20));

    ASSERT_EQ_INT((int)strlen(msg), (int)fx.cover.len);
    ASSERT_MEM_EQ(fx.cover.buf, msg, strlen(msg));

    if (client >= 0) {
        close(client);
    }
    fixture_destroy(&fx);
}

/* 2. A well-formed TLS record that is not Cloak: the cover site must see
 * the whole record, including the 5-byte header cloak_firstpacket_t
 * buffers rather than passing straight through. */
static void test_tls_record_is_forwarded_whole(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, -1, 0));

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);

    uint8_t record[5 + 64];
    record[0] = 0x16;
    record[1] = 0x03;
    record[2] = 0x03;
    record[3] = 0;
    record[4] = 64;
    for (size_t i = 0; i < 64; i++) {
        record[5 + i] = (uint8_t)(i * 7 + 3);
    }
    ASSERT_TRUE(write(client, record, sizeof(record)) == (ssize_t)sizeof(record));

    struct len_wait w = {&fx.cover, sizeof(record)};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &w, 200, 20));

    ASSERT_EQ_INT((int)sizeof(record), (int)fx.cover.len);
    ASSERT_MEM_EQ(fx.cover.buf, record, sizeof(record));

    if (client >= 0) {
        close(client);
    }
    fixture_destroy(&fx);
}

/* 3. A complete HTTP GET: the cover site must receive the entire request,
 * including its terminating blank line. */
static void test_http_get_is_forwarded_whole(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, -1, 0));

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);

    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    size_t req_len = strlen(req);
    ASSERT_TRUE(write(client, req, req_len) == (ssize_t)req_len);

    struct len_wait w = {&fx.cover, req_len};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &w, 200, 20));

    ASSERT_EQ_INT((int)req_len, (int)fx.cover.len);
    ASSERT_MEM_EQ(fx.cover.buf, req, req_len);

    if (client >= 0) {
        close(client);
    }
    fixture_destroy(&fx);
}

/* 4. Bidirectionality: once redirected, the cover site's own reply must
 * reach the client -- the relay is a splice, not a one-way forward. */
static void test_relay_is_bidirectional(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, -1, 0));

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    const char *msg = "HELLO\n";
    ASSERT_TRUE(write(client, msg, strlen(msg)) == (ssize_t)strlen(msg));

    struct len_wait w = {&fx.cover, strlen(msg)};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &w, 200, 20));
    ASSERT_EQ_INT(1, fx.cover.accept_count);

    const char *resp = "HTTP/1.1 200 OK\r\n\r\nhi";
    ASSERT_TRUE(fx.cover.fd >= 0);
    ASSERT_TRUE(write(fx.cover.fd, resp, strlen(resp)) == (ssize_t)strlen(resp));

    /* Pump the reactor so it notices cov.fd is readable, relays the
     * response to the client fd, and read it back with a bounded loop. */
    char buf[128];
    memset(buf, 0, sizeof(buf));
    size_t got = 0;
    for (int i = 0; i < 50 && got < strlen(resp); i++) {
        cloak_reactor_run_once(fx.reactor, 10);
        ssize_t n = recv(client, buf + got, sizeof(buf) - got, MSG_DONTWAIT);
        if (n > 0) {
            got += (size_t)n;
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
    }
    ASSERT_EQ_INT((int)strlen(resp), (int)got);
    ASSERT_MEM_EQ(buf, resp, strlen(resp));

    if (client >= 0) {
        close(client);
    }
    fixture_destroy(&fx);
}

/* 5. The handshake deadline: a client that sends one byte and then goes
 * silent must be dropped once handshake_timeout_ms elapses, without ever
 * reaching the cover site. */
static void test_deadline_drops_connection(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, -1, 150));

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    uint8_t one = 0x16;
    ASSERT_TRUE(write(client, &one, 1) == 1);

    /* Bounded: 150ms deadline, polled in 20ms steps for up to 4 seconds. */
    int done = 0;
    for (int i = 0; i < 200 && !done; i++) {
        cloak_reactor_run_once(fx.reactor, 20);
        if (cloak_dispatcher_conn_count(&fx.d) == 0) {
            done = 1;
        }
    }
    ASSERT_TRUE(done);
    ASSERT_EQ_INT(0, (int)cloak_dispatcher_conn_count(&fx.d));

    char c;
    ssize_t n = recv(client, &c, 1, 0);
    ASSERT_EQ_INT(0, (int)n); /* EOF: the server closed on us */
    ASSERT_EQ_INT(0, fx.cover.accept_count);
    ASSERT_EQ_INT(0, (int)fx.cover.len);

    if (client >= 0) {
        close(client);
    }
    fixture_destroy(&fx);
}

/* 6. Peer closes mid-packet: no redirect happens (nobody to redirect to)
 * and nothing crashes. */
static void test_peer_close_mid_packet_drops_without_redirect(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, -1, 0));

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    uint8_t one = 0x16;
    ASSERT_TRUE(write(client, &one, 1) == 1);
    close(client);
    client = -1;

    int done = 0;
    for (int i = 0; i < 200 && !done; i++) {
        cloak_reactor_run_once(fx.reactor, 10);
        if (cloak_dispatcher_conn_count(&fx.d) == 0) {
            done = 1;
        }
    }
    ASSERT_TRUE(done);
    ASSERT_EQ_INT(0, (int)cloak_dispatcher_conn_count(&fx.d));
    ASSERT_EQ_INT(0, fx.cover.accept_count);
    ASSERT_EQ_INT(0, (int)fx.cover.len);

    fixture_destroy(&fx);
}

/* 7. Redirect dial failure: RedirAddr points at a closed port, so the
 * client connection must be closed (not hung) and the dispatcher's
 * connection count must return to zero. */
static void test_dial_failure_closes_client(void) {
    int closed_port = reserve_closed_port();
    ASSERT_TRUE(closed_port > 0);

    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, closed_port, 0));

    int client = client_connect(front_port(&fx));
    ASSERT_TRUE(client >= 0);
    const char *msg = "HELLO\n";
    ASSERT_TRUE(write(client, msg, strlen(msg)) == (ssize_t)strlen(msg));

    int done = 0;
    for (int i = 0; i < 300 && !done; i++) {
        cloak_reactor_run_once(fx.reactor, 20);
        if (cloak_dispatcher_conn_count(&fx.d) == 0) {
            done = 1;
        }
    }
    ASSERT_TRUE(done);
    ASSERT_EQ_INT(0, (int)cloak_dispatcher_conn_count(&fx.d));

    /* "HELLO\n" only ever gave up 1 byte to cloak_firstpacket_t (the
     * junk-byte error fires on the very first byte); the other 5 are
     * still sitting unread in the kernel's receive buffer for this fd
     * when the dispatcher closes it, so the client can legitimately see
     * either a clean EOF or ECONNRESET (closing a socket with unread
     * data queued sends RST, not FIN, on Linux) -- either is "closed",
     * not "hanging". The SO_RCVTIMEO set in client_connect is what turns
     * an actual hang into a distinguishable EAGAIN/EWOULDBLOCK instead of
     * this test blocking forever. */
    char c;
    ssize_t n = recv(client, &c, 1, 0);
    ASSERT_TRUE(n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK));

    if (client >= 0) {
        close(client);
    }
    fixture_destroy(&fx);
}

/* 8. cloak_dispatcher_destroy with connections in flight -- one mid-read
 * (still awaiting its first packet) and one mid-relay (already
 * redirected) -- must leave nothing leaked or double-freed. Real
 * assurance here comes from running this test under ASan/UBSan. */
static void test_destroy_tears_down_inflight_connections(void) {
    struct fixture fx;
    ASSERT_EQ_INT(0, fixture_init(&fx, -1, 15000));

    /* Connection A: never sends anything, so it stays in the reading
     * state (fd registered, deadline armed, nothing else). */
    int client_a = client_connect(front_port(&fx));
    ASSERT_TRUE(client_a >= 0);

    /* Connection B: junk byte, pumped until it is fully redirected and
     * relaying. */
    int client_b = client_connect(front_port(&fx));
    ASSERT_TRUE(client_b >= 0);
    const char *msg = "HELLO\n";
    ASSERT_TRUE(write(client_b, msg, strlen(msg)) == (ssize_t)strlen(msg));

    struct len_wait w = {&fx.cover, strlen(msg)};
    ASSERT_TRUE(pump_until(fx.reactor, cover_has_len, &w, 200, 20));
    ASSERT_EQ_INT(1, fx.cover.accept_count);

    /* One extra turn so B's relay is fully wired up (both fds
     * registered) before destroy runs. */
    cloak_reactor_run_once(fx.reactor, 10);

    ASSERT_EQ_INT(2, (int)cloak_dispatcher_conn_count(&fx.d));

    /* The destroy under test. Must not crash, leak, or double-free
     * either connection -- ASan/UBSan is what actually proves this. */
    cloak_dispatcher_destroy(&fx.d);
    fx.d_ready = 0; /* already torn down; fixture_destroy must not repeat it */

    ASSERT_EQ_INT(0, (int)cloak_dispatcher_conn_count(&fx.d));

    close(client_a);
    close(client_b);
    fixture_destroy(&fx);
}

/* 9. cloak_dispatcher_init rejects a relay_buf_cap too small to ever hold
 * a preload -- a config typo that would otherwise silently turn every
 * redirect into a close (cloak_relay_start failing on preload_len >
 * buf_cap, which this module correctly treats as close-not-redirect). */
static void test_init_rejects_undersized_relay_buf_cap(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    char json[512];
    snprintf(json, sizeof(json),
             "{\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:1\","
             "\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    cloak_server_config_t cfg;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));

    cloak_server_t srv;
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&srv, &cfg, 16, err, sizeof(err)));

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = r;
    dcfg.srv = &srv;
    /* Below CLOAK_FIRSTPACKET_MAX: cloak_relay_start would reject any
     * preload longer than this on every single redirect. */
    dcfg.relay_buf_cap = CLOAK_FIRSTPACKET_MAX / 2;

    /* Dirtied first, the pattern this project's net.h/relay.h tests use:
     * a freshly zeroed struct would pass this test whether or not
     * cloak_dispatcher_init actually re-initializes it on a rejection
     * path, not only on the one that reaches the end successfully. */
    cloak_dispatcher_t dirty;
    memset(&dirty, 0xAA, sizeof(dirty));
    ASSERT_EQ_INT(-1, cloak_dispatcher_init(&dirty, &dcfg));

    /* init-before-validate: even on this rejection, d comes back zeroed,
     * not left holding the 0xAA fill. */
    ASSERT_TRUE(dirty.conns == NULL);
    ASSERT_EQ_INT(0, (int)dirty.conn_count);

    /* destroy must still be safe on a struct left this way. */
    cloak_dispatcher_destroy(&dirty);
    ASSERT_EQ_INT(0, (int)cloak_dispatcher_conn_count(&dirty));

    cloak_server_destroy(&srv);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_junk_first_byte_is_forwarded();
    test_tls_record_is_forwarded_whole();
    test_http_get_is_forwarded_whole();
    test_relay_is_bidirectional();
    test_deadline_drops_connection();
    test_peer_close_mid_packet_drops_without_redirect();
    test_dial_failure_closes_client();
    test_destroy_tears_down_inflight_connections();
    test_init_rejects_undersized_relay_buf_cap();
TEST_MAIN_END()
