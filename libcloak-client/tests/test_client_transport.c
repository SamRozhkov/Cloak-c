#define _POSIX_C_SOURCE 200809L

/* Tests for the client's direct-TLS handshake state machine.
 *
 * TWO KINDS OF SERVER ARE USED HERE, on purpose:
 *
 *  - The REAL one (a cloak_dispatcher_t over a cloak_server_t and a
 *    cloak_server_registry_t, wired exactly as libcloak-server's own
 *    dispatcher tests wire it) for the cases that must prove the two
 *    halves genuinely agree: that a handshake completes, and that the
 *    key the client recovers is byte-for-byte the key the server put
 *    into the session. Nothing hand-computed, nothing mocked.
 *
 *  - A SCRIPTED one (fake_server_t below) for every case that needs
 *    control over *when* bytes arrive: one byte per reactor turn, a
 *    close halfway through the reply, silence after a valid ServerHello,
 *    a record header claiming an illegal length. Its accepted socket is
 *    deliberately NOT registered with the reactor -- the test moves
 *    every byte by hand, in both directions, so "delivered one byte per
 *    reactor turn" means exactly that rather than "delivered in
 *    whatever chunks the kernel felt like".
 *
 * Both run on the SAME reactor as the client under test, the way every
 * other reactor test in this project drives both ends of a connection. */

#include "cloak/base64.h"
#include "cloak/client_transport.h"
#include "cloak/clienthello_parse.h"
#include "cloak/common.h"
#include "cloak/crypto.h"
#include "cloak/dispatcher.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "cloak/session.h"
#include "test_framework.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---- shared helpers ----------------------------------------------------- */

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* small_buffers shrinks this socket's send buffer to the kernel minimum.
 * Combined with a shrunken receive buffer on the listener (see
 * test_partial_client_hello_write), that is what makes a short write of
 * the ~1.8KB ClientHello REACHABLE at all: Linux only reports an
 * edge-triggered EPOLLOUT once roughly half the send buffer is free, so
 * with a default-sized buffer every write of something this small
 * completes in one call no matter how the peer behaves, and a
 * partial-write test against such a socket would be testing nothing. */
static int connect_nonblocking_ex(int port, int small_buffers) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (small_buffers) {
        int one = 1; /* clamped up to the kernel minimum, ~4608 bytes */
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &one, sizeof(one));
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

static int connect_nonblocking(int port) {
    return connect_nonblocking_ex(port, 0);
}

typedef struct {
    int calls;
    cloak_client_handshake_status_t status;
    cloak_client_handshake_error_t error;
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    int have_key;
} hs_result_t;

static void hs_done(cloak_client_handshake_t *h, cloak_client_handshake_status_t status,
                    void *userdata) {
    hs_result_t *res = userdata;
    res->calls++;
    res->status = status;
    res->error = cloak_client_handshake_error(h);
    const uint8_t *k = cloak_client_handshake_session_key(h);
    if (k != NULL) {
        memcpy(res->key, k, CLOAK_AEAD_KEY_LEN);
        res->have_key = 1;
    }
}

static void fill_uid(uint8_t uid[CLOAK_UID_LEN], uint8_t seed) {
    for (size_t i = 0; i < CLOAK_UID_LEN; i++) {
        uid[i] = (uint8_t)(seed + i);
    }
}

static void base_config(cloak_client_handshake_config_t *cfg, cloak_reactor_t *r, int fd,
                        const uint8_t server_pub[CLOAK_X25519_KEY_LEN],
                        const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                        hs_result_t *res) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->reactor = r;
    cfg->fd = fd;
    cfg->browser = CLOAK_CLIENT_BROWSER_CHROME;
    cfg->server_name = "www.example.com";
    memcpy(cfg->server_pub, server_pub, CLOAK_X25519_KEY_LEN);
    memcpy(cfg->uid, uid, CLOAK_UID_LEN);
    cfg->proxy_method = "ss";
    cfg->encryption_method = (uint8_t)CLOAK_AEAD_AES_256_GCM;
    cfg->session_id = session_id;
    cfg->unordered = 0;
    cfg->now_unix = (int64_t)time(NULL);
    cfg->timeout_ms = 5000;
    cfg->on_done = hs_done;
    cfg->on_done_userdata = res;
}

/* ---- the scripted server ------------------------------------------------ */

typedef struct {
    cloak_reactor_t *reactor;
    cloak_listener_t listener;
    int have_listener;
    int fd; /* accepted; intentionally NOT registered with the reactor */

    uint8_t priv[CLOAK_X25519_KEY_LEN];
    uint8_t pub[CLOAK_X25519_KEY_LEN];

    size_t junk_left; /* bytes to discard before the ClientHello starts */
    uint8_t in[4096];
    size_t in_len;
    int hello_parsed;
    char sni[256];

    uint8_t reply[CLOAK_SERVER_AUTH_REPLY_MAX_BYTES];
    size_t reply_len;
    size_t reply_sent;
    uint8_t session_key[CLOAK_AEAD_KEY_LEN];
} fake_server_t;

static void fake_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    fake_server_t *fs = userdata;
    if (fs->fd >= 0) {
        close(fd);
        return;
    }
    fs->fd = fd;
}

static int fake_server_start(fake_server_t *fs, cloak_reactor_t *r) {
    memset(fs, 0, sizeof(*fs));
    fs->reactor = r;
    fs->fd = -1;
    if (cloak_x25519_generate_keypair(fs->priv, fs->pub) != 0) {
        return -1;
    }
    char err[256] = {0};
    if (cloak_listener_open(&fs->listener, r, "127.0.0.1:0", fake_on_accept, fs, err,
                            sizeof(err)) != 0) {
        return -1;
    }
    fs->have_listener = 1;
    return 0;
}

static void fake_server_stop(fake_server_t *fs) {
    if (fs->have_listener) {
        cloak_listener_close(&fs->listener);
        fs->have_listener = 0;
    }
    if (fs->fd >= 0) {
        close(fs->fd);
        fs->fd = -1;
    }
}

static int fake_server_port(fake_server_t *fs) {
    return cloak_listener_port(&fs->listener);
}

/* Decrypts the accumulated ClientHello with the scripted server's own
 * private key and composes the very reply a real server would -- via
 * cloak_server_auth_decrypt and cloak_server_auth_compose_reply
 * themselves, so the bytes this test delivers byte-by-byte are genuine
 * server bytes, not a fixture that could drift from the server. */
static void fake_server_try_parse(fake_server_t *fs) {
    if (fs->hello_parsed || fs->in_len < 5) {
        return;
    }
    size_t total = 5 + (((size_t)fs->in[3] << 8) | (size_t)fs->in[4]);
    if (fs->in_len < total) {
        return;
    }
    cloak_clienthello_parsed_t ch;
    memset(&ch, 0, sizeof(ch));
    ASSERT_EQ_INT(0, cloak_clienthello_parse(fs->in, total, &ch));
    if (ch.sni != NULL && ch.sni_len < sizeof(fs->sni)) {
        memcpy(fs->sni, ch.sni, ch.sni_len);
        fs->sni[ch.sni_len] = '\0';
    }

    cloak_server_clientinfo_t info;
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_server_auth_decrypt(ch.random, ch.session_id, ch.session_id_len,
                                               ch.x25519_key_share, fs->priv, (int64_t)time(NULL),
                                               &info, shared));

    cloak_random_bytes(fs->session_key, sizeof(fs->session_key));
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    uint8_t pad4[4];
    cloak_random_bytes(nonce, sizeof(nonce));
    cloak_random_bytes(pad4, sizeof(pad4));
    size_t cert_len = cloak_server_auth_cert_lens[0];
    uint8_t cert[128];
    ASSERT_TRUE(cert_len <= sizeof(cert));
    cloak_random_bytes(cert, cert_len);

    long n = cloak_server_auth_compose_reply(shared, fs->session_key, nonce, ch.session_id, pad4,
                                             cert, cert_len, fs->reply, sizeof(fs->reply));
    ASSERT_TRUE(n > 0);
    if (n <= 0) {
        return;
    }
    fs->reply_len = (size_t)n;
    fs->hello_parsed = 1;
}

/* Reads at most max bytes from the client. Nothing is read unless a test
 * asks for it, which is what lets a test hold the client's send buffer
 * full and so force a partial write. */
static size_t fake_server_pull(fake_server_t *fs, size_t max) {
    if (fs->fd < 0) {
        return 0;
    }
    uint8_t buf[2048];
    size_t got = 0;
    while (got < max) {
        size_t want = max - got;
        if (want > sizeof(buf)) {
            want = sizeof(buf);
        }
        ssize_t n = recv(fs->fd, buf, want, 0);
        if (n <= 0) {
            break;
        }
        got += (size_t)n;
        size_t off = 0;
        if (fs->junk_left > 0) {
            size_t d = fs->junk_left < (size_t)n ? fs->junk_left : (size_t)n;
            fs->junk_left -= d;
            off = d;
        }
        size_t copy = (size_t)n - off;
        if (copy > sizeof(fs->in) - fs->in_len) {
            copy = sizeof(fs->in) - fs->in_len;
        }
        memcpy(fs->in + fs->in_len, buf + off, copy);
        fs->in_len += copy;
    }
    fake_server_try_parse(fs);
    return got;
}

/* Writes at most max further bytes of the composed reply. */
static size_t fake_server_push(fake_server_t *fs, size_t max) {
    if (fs->fd < 0 || fs->reply_sent >= fs->reply_len) {
        return 0;
    }
    size_t remaining = fs->reply_len - fs->reply_sent;
    if (max > remaining) {
        max = remaining;
    }
    ssize_t n = send(fs->fd, fs->reply + fs->reply_sent, max, MSG_NOSIGNAL);
    if (n <= 0) {
        return 0;
    }
    fs->reply_sent += (size_t)n;
    return (size_t)n;
}

static void fake_server_push_raw(fake_server_t *fs, const uint8_t *data, size_t len) {
    if (fs->fd < 0) {
        return;
    }
    ssize_t n = send(fs->fd, data, len, MSG_NOSIGNAL);
    ASSERT_EQ_INT((int)len, (int)n);
}

/* Pumps until the scripted server has accepted the client's connection. */
static void pump_until_accepted(cloak_reactor_t *r, fake_server_t *fs) {
    for (int i = 0; i < 200 && fs->fd < 0; i++) {
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_TRUE(fs->fd >= 0);
}

/* ---- the real server fixture -------------------------------------------- */

typedef struct {
    int calls;
    int last_created;
    cloak_session_t *last_sesh;
} attached_record_t;

static void attached_cb(cloak_dispatcher_t *d, cloak_session_t *sesh,
                        const cloak_server_clientinfo_t *info, int created, void *userdata) {
    (void)d;
    (void)info;
    attached_record_t *rec = userdata;
    rec->calls++;
    rec->last_created = created;
    rec->last_sesh = sesh;
}

static int prepare_cb(cloak_dispatcher_t *d, const cloak_server_clientinfo_t *info,
                      cloak_session_config_t *config, void *userdata) {
    (void)d;
    (void)info;
    (void)config;
    (void)userdata;
    return 0;
}

static void registry_on_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                               const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    (void)reg;
    (void)sesh;
    (void)uid;
    (void)session_id;
    (void)userdata;
}

/* The cover site the dispatcher redirects unrecognised traffic to. It
 * must exist (RedirAddr is mandatory) but nothing here should ever reach
 * it; accept_count is asserted to stay 0. */
typedef struct {
    cloak_listener_t listener;
    int have_listener;
    int accept_count;
    int fds[8];
    int fd_count;
} cover_t;

static void cover_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    cover_t *cov = userdata;
    cov->accept_count++;
    if (cov->fd_count < (int)(sizeof(cov->fds) / sizeof(cov->fds[0]))) {
        cov->fds[cov->fd_count++] = fd;
    } else {
        close(fd);
    }
}

struct real_server {
    cloak_reactor_t *reactor;
    cover_t cover;
    cloak_server_config_t cfg;
    cloak_server_t srv;
    int srv_ready;
    cloak_server_registry_t registry;
    int registry_ready;
    attached_record_t attached;
    cloak_dispatcher_t d;
    int d_ready;
    cloak_listener_t front;
    int have_front;
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid[CLOAK_UID_LEN];
};

static int real_server_init(struct real_server *rs, cloak_reactor_t *r) {
    memset(rs, 0, sizeof(*rs));
    rs->reactor = r;
    char err[256] = {0};

    if (cloak_listener_open(&rs->cover.listener, r, "127.0.0.1:0", cover_accept, &rs->cover, err,
                            sizeof(err)) != 0) {
        return -1;
    }
    rs->cover.have_listener = 1;
    int cover_port = cloak_listener_port(&rs->cover.listener);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, rs->server_pub));
    fill_uid(rs->uid, 0x21);

    char priv_b64[64];
    char uid_b64[32];
    ASSERT_EQ_INT(0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64,
                                         sizeof(priv_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(rs->uid, CLOAK_UID_LEN, uid_b64, sizeof(uid_b64)));

    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"AdminUID\":\"%s\",\"BypassUID\":[\"%s\"]}",
             cover_port, priv_b64, uid_b64, uid_b64);
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &rs->cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, cloak_server_init(&rs->srv, &rs->cfg, 16, err, sizeof(err)));
    rs->srv_ready = 1;

    ASSERT_EQ_INT(0, cloak_server_registry_init(&rs->registry, r, registry_on_broken, NULL));
    rs->registry_ready = 1;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = r;
    dcfg.srv = &rs->srv;
    dcfg.registry = &rs->registry;
    dcfg.session_config_template.max_on_wire_size = 16401;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = 262144;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;
    dcfg.prepare_session = prepare_cb;
    dcfg.attached = attached_cb;
    dcfg.attached_userdata = &rs->attached;
    ASSERT_EQ_INT(0, cloak_dispatcher_init(&rs->d, &dcfg));
    rs->d_ready = 1;

    ASSERT_EQ_INT(0, cloak_listener_open(&rs->front, r, "127.0.0.1:0", cloak_dispatcher_accept,
                                         &rs->d, err, sizeof(err)));
    rs->have_front = 1;
    return 0;
}

static void real_server_destroy(struct real_server *rs) {
    if (rs->have_front) {
        cloak_listener_close(&rs->front);
    }
    if (rs->d_ready) {
        cloak_dispatcher_destroy(&rs->d);
    }
    if (rs->registry_ready) {
        cloak_server_registry_destroy(&rs->registry);
    }
    if (rs->srv_ready) {
        cloak_server_destroy(&rs->srv);
    }
    if (rs->cover.have_listener) {
        cloak_listener_close(&rs->cover.listener);
    }
    for (int i = 0; i < rs->cover.fd_count; i++) {
        close(rs->cover.fds[i]);
    }
}

static void pump_until_done(cloak_reactor_t *r, hs_result_t *res, int max_iters) {
    for (int i = 0; i < max_iters && res->calls == 0; i++) {
        cloak_reactor_run_once(r, 5);
    }
}

/* ---- case 1: against the real server, the keys agree -------------------- */

/* The one assertion in this file that catches a wrong key split: the
 * client's recovered key compared byte for byte against the key the
 * SERVER installed in the session it created. A client that read the
 * right bytes from the wrong offsets, or opened the AEAD with the wrong
 * nonce, would still report DONE for some inputs but could never produce
 * this exact 32-byte value -- and a session built on a wrong key fails
 * every subsequent frame silently, which is precisely the failure this
 * assertion exists to make loud. */
static void test_real_server_key_agreement(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    struct real_server rs;
    ASSERT_EQ_INT(0, real_server_init(&rs, r));

    hs_result_t res;
    memset(&res, 0, sizeof(res));
    int fd = connect_nonblocking(cloak_listener_port(&rs.front));
    ASSERT_TRUE(fd >= 0);

    cloak_client_handshake_config_t cfg;
    base_config(&cfg, r, fd, rs.server_pub, rs.uid, 4242, &res);

    cloak_client_handshake_t h;
    ASSERT_EQ_INT(0, cloak_client_handshake_init(&h, &cfg));
    ASSERT_EQ_INT(0, cloak_client_handshake_start(&h));
    /* The callback must never fire before start returns. */
    ASSERT_EQ_INT(0, res.calls);

    pump_until_done(r, &res, 400);

    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_DONE, res.status);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_ERR_NONE, res.error);
    ASSERT_EQ_INT(1, rs.attached.calls);
    ASSERT_EQ_INT(1, rs.attached.last_created);
    ASSERT_TRUE(rs.attached.last_sesh != NULL);
    ASSERT_EQ_INT(0, rs.cover.accept_count);

    /* THE key agreement assertion. */
    ASSERT_TRUE(res.have_key);
    if (rs.attached.last_sesh != NULL) {
        ASSERT_MEM_EQ(res.key, rs.attached.last_sesh->obfuscator.session_key, CLOAK_AEAD_KEY_LEN);
        /* A both-sides-zero comparison would pass the line above without
         * either side having agreed on anything. */
        uint8_t zero[CLOAK_AEAD_KEY_LEN];
        memset(zero, 0, sizeof(zero));
        ASSERT_MEM_NE(res.key, zero, CLOAK_AEAD_KEY_LEN);
    }

    /* Exactly the three records, nothing more: 127 + 6 + (5 + cert_len). */
    ASSERT_TRUE(h.reply_bytes >= 165);
    ASSERT_TRUE(h.reply_bytes <= 206);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_REPLY_RECORDS, (int)h.record_index);

    cloak_client_handshake_destroy(&h);
    close(fd);
    real_server_destroy(&rs);
    cloak_reactor_destroy(r);
}

/* ---- case 2: one byte per reactor turn, and never one byte more --------- */

/* Two properties in one run, because they are two halves of the same
 * requirement:
 *
 *  (a) RESUMABILITY. The reply is handed over one byte per reactor turn.
 *      Splits land inside the ServerHello's 5-byte record header, inside
 *      its body, inside the ChangeCipherSpec header, and inside the fake
 *      Certificate header -- every boundary there is. The handshake is
 *      asserted to still be PENDING after every byte but the last, so a
 *      "completed early" bug cannot hide either.
 *
 *  (b) NO OVER-READ. The final push carries the reply's last byte AND
 *      four bytes that belong to the session that follows. Those four
 *      must still be sitting in the socket when the handshake reports
 *      DONE: an implementation that read greedily into a buffer would
 *      swallow them, and the session's first frame would be lost. */
static void test_byte_at_a_time_and_no_over_read(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    fake_server_t fs;
    ASSERT_EQ_INT(0, fake_server_start(&fs, r));

    hs_result_t res;
    memset(&res, 0, sizeof(res));
    int fd = connect_nonblocking(fake_server_port(&fs));
    ASSERT_TRUE(fd >= 0);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0x33);
    cloak_client_handshake_config_t cfg;
    base_config(&cfg, r, fd, fs.pub, uid, 77, &res);

    cloak_client_handshake_t h;
    ASSERT_EQ_INT(0, cloak_client_handshake_init(&h, &cfg));
    ASSERT_EQ_INT(0, cloak_client_handshake_start(&h));

    pump_until_accepted(r, &fs);
    for (int i = 0; i < 100 && !fs.hello_parsed; i++) {
        cloak_reactor_run_once(r, 5);
        fake_server_pull(&fs, 4096);
    }
    ASSERT_TRUE(fs.hello_parsed);
    ASSERT_TRUE(fs.reply_len > 138);

    /* Every byte but the last, one per reactor turn. */
    int header_split_seen = 0;
    for (size_t i = 0; i + 1 < fs.reply_len; i++) {
        ASSERT_EQ_INT(1, (int)fake_server_push(&fs, 1));
        cloak_reactor_run_once(r, 5);
        cloak_reactor_run_once(r, 0);
        ASSERT_EQ_INT(0, res.calls);
        /* A split strictly inside a 5-byte record header: the machine is
         * parked in READ_RECORD_HEADER with 1..4 bytes of it in hand.
         * If this never happened the "including splits inside a record
         * header" half of the requirement would be untested. */
        if (h.state == CLOAK_CLIENT_HS_STATE_READ_RECORD_HEADER && h.header_len > 0 &&
            h.header_len < 5) {
            header_split_seen = 1;
        }
    }
    ASSERT_TRUE(header_split_seen);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_PENDING, cloak_client_handshake_status(&h));

    /* The last reply byte plus four bytes of the next layer, together. */
    uint8_t trailer[5];
    trailer[0] = fs.reply[fs.reply_len - 1];
    trailer[1] = 0xde;
    trailer[2] = 0xad;
    trailer[3] = 0xbe;
    trailer[4] = 0xef;
    fake_server_push_raw(&fs, trailer, sizeof(trailer));
    fs.reply_sent = fs.reply_len;

    pump_until_done(r, &res, 200);
    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_DONE, res.status);
    ASSERT_MEM_EQ(res.key, fs.session_key, CLOAK_AEAD_KEY_LEN);
    ASSERT_EQ_INT((int)fs.reply_len, (int)h.reply_bytes);

    /* The four bytes that were NOT part of the reply must still be here. */
    uint8_t leftover[8];
    ssize_t n = recv(fd, leftover, sizeof(leftover), 0);
    ASSERT_EQ_INT(4, (int)n);
    if (n == 4) {
        ASSERT_MEM_EQ(leftover, trailer + 1, 4);
    }

    cloak_client_handshake_destroy(&h);
    close(fd);
    fake_server_stop(&fs);
    cloak_reactor_destroy(r);
}

/* ---- case 3: a partial ClientHello write ------------------------------- */

/* Forcing a GENUINE short write, which takes some doing on Linux: an
 * edge-triggered EPOLLOUT is only reported once about half the send
 * buffer is free, so against a default-sized buffer a ~1.8KB ClientHello
 * is always accepted in a single send() and a "partial write" test would
 * be green without ever exercising the resumption it claims to cover.
 * Three things together make the short write reachable and repeatable:
 * the client's send buffer is shrunk to the kernel minimum, the
 * listener's receive buffer likewise, and the socket is stuffed full of
 * junk (which the scripted server is told to discard) before the
 * handshake starts. The server then drains a kilobyte per reactor turn,
 * so each writable edge exposes less room than the ClientHello needs.
 *
 * The test asserts it actually OBSERVED a short write -- 0 < hello_sent
 * < hello_len at some point -- so a machine or kernel on which the whole
 * hello did fit in one call fails here rather than passing vacuously. */
static void test_partial_client_hello_write(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    fake_server_t fs;
    ASSERT_EQ_INT(0, fake_server_start(&fs, r));
    /* Set on the LISTENING socket, before the connection exists, so the
     * accepted socket inherits it and the receive window is negotiated
     * small at SYN time. */
    int one = 1;
    setsockopt(fs.listener.fd, SOL_SOCKET, SO_RCVBUF, &one, sizeof(one));

    hs_result_t res;
    memset(&res, 0, sizeof(res));
    int fd = connect_nonblocking_ex(fake_server_port(&fs), 1);
    ASSERT_TRUE(fd >= 0);

    /* TCP_NOTSENT_LOWAT IS WHAT MAKES THE SHORT WRITE A CONSTRUCTION
     * RATHER THAN A BET ON THE KERNEL'S BUFFER ARITHMETIC.
     *
     * A small SO_SNDBUF (connect_nonblocking_ex's `small_buffers`, above)
     * is not enough on its own, and the failure was not hypothetical:
     * on Linux 6.17.0-1022-azure this case failed 10 times out of 10
     * with stuffed=3776, hello_len=1725..1821, write_calls=1, while the
     * same code on 6.12.76-linuxkit produced stuffed=3776,
     * hello_len=1757, write_calls=2. Identical buffer, opposite verdict.
     *
     * The reason is that Linux only reports EPOLLOUT once about half the
     * send buffer is free -- roughly 2304 bytes against the 4608-byte
     * floor -- and no ClientHello this client can build is that long.
     * Measured, not assumed: stretching the server name to 242
     * characters, the longest this config accepts, moved hello_len only
     * from 1757 to 1952. So on a kernel that applies the rule strictly,
     * the whole hello always fits in the first write and the resume path
     * is simply unreachable this way.
     *
     * TCP_NOTSENT_LOWAT caps the UNSENT bytes the kernel will queue, so
     * sendmsg returns a short count and the next writable edge comes
     * when that queue drains below the cap. That is the same resume the
     * case is about, and it does not depend on the buffer arithmetic
     * that differs between kernels. */
    int lowat = 128;
    setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, sizeof(lowat));

    pump_until_accepted(r, &fs);

    /* Stuff the connection until the kernel refuses more. The 1KB chunk
     * size is load-bearing: stuffing in small chunks leaves the send
     * queue full of small buffers whose per-skb overhead inflates the
     * kernel's accounting, and freeing any of it then leaves room for
     * the whole ClientHello in one call -- measured, not assumed. */
    uint8_t junk[1024];
    memset(junk, 0x5a, sizeof(junk));
    size_t stuffed = 0;
    for (int i = 0; i < 4096; i++) {
        ssize_t n = send(fd, junk, sizeof(junk), MSG_NOSIGNAL);
        if (n <= 0) {
            break;
        }
        stuffed += (size_t)n;
    }
    ASSERT_TRUE(stuffed > 0);
    fs.junk_left = stuffed;

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0x44);
    cloak_client_handshake_config_t cfg;
    base_config(&cfg, r, fd, fs.pub, uid, 88, &res);
    cfg.timeout_ms = 20000; /* this test is slow by construction */

    cloak_client_handshake_t h;
    ASSERT_EQ_INT(0, cloak_client_handshake_init(&h, &cfg));
    ASSERT_TRUE(h.hello_len > 1024); /* the premise: bigger than one drained chunk */
    ASSERT_EQ_INT(0, cloak_client_handshake_start(&h));

    /* Nothing can go out yet: the socket is full, so no writable edge. */
    cloak_reactor_run_once(r, 5);
    cloak_reactor_run_once(r, 5);
    ASSERT_EQ_INT(0, (int)h.hello_sent);
    ASSERT_EQ_INT(CLOAK_CLIENT_HS_STATE_WRITE_HELLO, (int)h.state);

    int saw_partial = 0;
    int write_calls = 0;
    size_t last_sent = 0;
    for (int i = 0; i < 2000 && !fs.hello_parsed; i++) {
        fake_server_pull(&fs, 64);
        cloak_reactor_run_once(r, 5);
        if (h.hello_sent != last_sent) {
            write_calls++;
            last_sent = h.hello_sent;
        }
        if (h.hello_sent > 0 && h.hello_sent < h.hello_len) {
            saw_partial = 1;
        }
    }
    ASSERT_TRUE(saw_partial);
    /* More than one write call means the ClientHello genuinely resumed
     * across writable edges rather than being handed over in one go. */
    ASSERT_TRUE(write_calls >= 2);
    if (!saw_partial || write_calls < 2) {
        /* Diagnostic, not decoration: if a future kernel's send-buffer
         * accounting stops producing a short write here, this line says
         * so directly instead of leaving a bare assertion failure whose
         * cause is invisible. */
        fprintf(stderr, "  stuffed=%zu hello_len=%zu write_calls=%d\n", stuffed, h.hello_len,
                write_calls);
    }
    ASSERT_TRUE(fs.hello_parsed);
    ASSERT_EQ_INT((int)h.hello_len, (int)h.hello_sent);

    for (int i = 0; i < 400 && res.calls == 0; i++) {
        fake_server_push(&fs, 4096);
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_DONE, res.status);
    ASSERT_MEM_EQ(res.key, fs.session_key, CLOAK_AEAD_KEY_LEN);

    cloak_client_handshake_destroy(&h);
    close(fd);
    fake_server_stop(&fs);
    cloak_reactor_destroy(r);
}

/* ---- case 4: a server that closes mid-reply, and record-length bounds --- */

static void test_close_mid_reply(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    fake_server_t fs;
    ASSERT_EQ_INT(0, fake_server_start(&fs, r));

    hs_result_t res;
    memset(&res, 0, sizeof(res));
    int fd = connect_nonblocking(fake_server_port(&fs));
    ASSERT_TRUE(fd >= 0);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0x55);
    cloak_client_handshake_config_t cfg;
    base_config(&cfg, r, fd, fs.pub, uid, 99, &res);

    cloak_client_handshake_t h;
    ASSERT_EQ_INT(0, cloak_client_handshake_init(&h, &cfg));
    ASSERT_EQ_INT(0, cloak_client_handshake_start(&h));

    pump_until_accepted(r, &fs);
    for (int i = 0; i < 100 && !fs.hello_parsed; i++) {
        cloak_reactor_run_once(r, 5);
        fake_server_pull(&fs, 4096);
    }
    ASSERT_TRUE(fs.hello_parsed);

    /* Half a ServerHello, then a clean close. */
    fake_server_push(&fs, 60);
    cloak_reactor_run_once(r, 5);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_PENDING, cloak_client_handshake_status(&h));
    close(fs.fd);
    fs.fd = -1;

    pump_until_done(r, &res, 200);
    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_FAILED, res.status);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_ERR_EOF, res.error);
    ASSERT_EQ_INT(0, res.have_key);
    ASSERT_TRUE(cloak_client_handshake_session_key(&h) == NULL);

    /* Destroy after a failure must be safe, and idempotent. */
    cloak_client_handshake_destroy(&h);
    cloak_client_handshake_destroy(&h);
    close(fd);
    fake_server_stop(&fs);
    cloak_reactor_destroy(r);
}

/* The record-body bound, pinned AT its boundary rather than somewhere
 * far outside it: a declared body of exactly
 * CLOAK_CLIENT_HANDSHAKE_MAX_RECORD_BODY is accepted (the machine moves
 * on to READ_RECORD_BODY and waits), one byte more is rejected. Widening
 * or narrowing the real bound by a single byte breaks one of the two. */
static void run_declared_length_case(uint8_t content_type, size_t declared, int expect_reject) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    fake_server_t fs;
    ASSERT_EQ_INT(0, fake_server_start(&fs, r));

    hs_result_t res;
    memset(&res, 0, sizeof(res));
    int fd = connect_nonblocking(fake_server_port(&fs));
    ASSERT_TRUE(fd >= 0);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0x66);
    cloak_client_handshake_config_t cfg;
    base_config(&cfg, r, fd, fs.pub, uid, 111, &res);

    cloak_client_handshake_t h;
    ASSERT_EQ_INT(0, cloak_client_handshake_init(&h, &cfg));
    ASSERT_EQ_INT(0, cloak_client_handshake_start(&h));

    pump_until_accepted(r, &fs);
    for (int i = 0; i < 100 && !fs.hello_parsed; i++) {
        cloak_reactor_run_once(r, 5);
        fake_server_pull(&fs, 4096);
    }
    ASSERT_TRUE(fs.hello_parsed);

    uint8_t header[5] = {content_type, 0x03, 0x03, (uint8_t)(declared >> 8),
                         (uint8_t)(declared & 0xff)};
    fake_server_push_raw(&fs, header, sizeof(header));
    for (int i = 0; i < 40 && res.calls == 0; i++) {
        cloak_reactor_run_once(r, 5);
    }

    if (expect_reject) {
        ASSERT_EQ_INT(1, res.calls);
        ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_FAILED, res.status);
        ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_ERR_PROTOCOL, res.error);
    } else {
        ASSERT_EQ_INT(0, res.calls);
        ASSERT_EQ_INT(CLOAK_CLIENT_HS_STATE_READ_RECORD_BODY, (int)h.state);
        ASSERT_EQ_INT((int)declared, (int)h.body_total);
    }

    cloak_client_handshake_destroy(&h);
    close(fd);
    fake_server_stop(&fs);
    cloak_reactor_destroy(r);
}

static void test_record_length_bound(void) {
    run_declared_length_case(0x16, CLOAK_CLIENT_HANDSHAKE_MAX_RECORD_BODY, 0);
    run_declared_length_case(0x16, CLOAK_CLIENT_HANDSHAKE_MAX_RECORD_BODY + 1, 1);
    /* A ServerHello too short to carry both halves of the sealed session
     * key is rejected at its header, before any of it is read. */
    run_declared_length_case(0x16, CLOAK_CLIENT_HANDSHAKE_SERVERHELLO_PREFIX - 1, 1);
    /* The first record must be a HANDSHAKE record. A perfectly sized
     * application-data record in the ServerHello's place is rejected --
     * without this case the content-type check is uncovered, because
     * every other fixture in this file pushes 0x16. */
    run_declared_length_case(0x17, 122, 1);
    run_declared_length_case(0x14, 122, 1);
}

/* ---- case 5: the deadline, measured ------------------------------------- */

/* `deadline_ms` is asserted to have ELAPSED on the wall clock, not merely
 * to have produced an error: a pump that gave up early, or an error
 * raised for some other reason, would otherwise be indistinguishable
 * from the deadline firing. The upper bound matters just as much -- it
 * is what would fail if the deadline stopped being armed and the test
 * were instead finishing because its own loop ran out. */
static void run_deadline_case(int send_server_hello) {
    const uint64_t deadline_ms = 400;
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    fake_server_t fs;
    ASSERT_EQ_INT(0, fake_server_start(&fs, r));

    hs_result_t res;
    memset(&res, 0, sizeof(res));
    int fd = connect_nonblocking(fake_server_port(&fs));
    ASSERT_TRUE(fd >= 0);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0x77);
    cloak_client_handshake_config_t cfg;
    base_config(&cfg, r, fd, fs.pub, uid, 123, &res);
    cfg.timeout_ms = deadline_ms;

    cloak_client_handshake_t h;
    ASSERT_EQ_INT(0, cloak_client_handshake_init(&h, &cfg));
    uint64_t t0 = now_ms();
    ASSERT_EQ_INT(0, cloak_client_handshake_start(&h));

    pump_until_accepted(r, &fs);
    for (int i = 0; i < 100 && !fs.hello_parsed; i++) {
        cloak_reactor_run_once(r, 5);
        fake_server_pull(&fs, 4096);
    }
    ASSERT_TRUE(fs.hello_parsed);

    if (send_server_hello) {
        /* A complete, VALID ServerHello record (127 bytes) -- and then
         * nothing, ever. */
        fake_server_push(&fs, 127);
        for (int i = 0; i < 20; i++) {
            cloak_reactor_run_once(r, 1);
        }
        ASSERT_EQ_INT(1, (int)h.record_index);
        ASSERT_EQ_INT(CLOAK_CLIENT_HS_STATE_READ_RECORD_HEADER, (int)h.state);
        /* The key was already recovered: the connection is being held
         * open purely by the server's silence, which is the exact
         * situation the deadline exists for. */
        ASSERT_MEM_EQ(h.session_key, fs.session_key, CLOAK_AEAD_KEY_LEN);
    }

    /* Bounded at ~5x the deadline, so running out of iterations and the
     * deadline firing cannot be confused. */
    for (int i = 0; i < 400 && res.calls == 0; i++) {
        cloak_reactor_run_once(r, 5);
    }
    uint64_t elapsed = now_ms() - t0;

    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_FAILED, res.status);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_ERR_TIMEOUT, res.error);
    /* THE measurement: the deadline was genuinely reached. */
    ASSERT_TRUE(elapsed >= deadline_ms);
    ASSERT_TRUE(elapsed < deadline_ms * 3);
    if (elapsed < deadline_ms || elapsed >= deadline_ms * 3) {
        fprintf(stderr, "  deadline %llu ms, elapsed %llu ms\n", (unsigned long long)deadline_ms,
                (unsigned long long)elapsed);
    }

    cloak_client_handshake_destroy(&h);
    close(fd);
    fake_server_stop(&fs);
    cloak_reactor_destroy(r);
}

static void test_deadline(void) {
    /* Silence from the very first byte: the deadline is armed at start,
     * not at the first byte read. */
    run_deadline_case(0);
    /* A valid ServerHello, then silence. */
    run_deadline_case(1);
}

/* A zero timeout_ms selects the documented default rather than "no
 * deadline" -- the one place that constant is observable. */
static void test_default_deadline_is_applied(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    fake_server_t fs;
    ASSERT_EQ_INT(0, fake_server_start(&fs, r));
    int fd = connect_nonblocking(fake_server_port(&fs));
    ASSERT_TRUE(fd >= 0);

    hs_result_t res;
    memset(&res, 0, sizeof(res));
    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0x88);
    cloak_client_handshake_config_t cfg;
    base_config(&cfg, r, fd, fs.pub, uid, 1, &res);
    cfg.timeout_ms = 0;

    cloak_client_handshake_t h;
    ASSERT_EQ_INT(0, cloak_client_handshake_init(&h, &cfg));
    ASSERT_EQ_INT((int)CLOAK_CLIENT_HANDSHAKE_DEFAULT_TIMEOUT_MS, (int)h.timeout_ms);

    cloak_client_handshake_destroy(&h);
    close(fd);
    fake_server_stop(&fs);
    cloak_reactor_destroy(r);
}

/* ---- case 6: "random" server names -------------------------------------- */

/* Go Cloak's topLevelDomains, transcribed by hand from
 * internal/client/TLS.go:33 and deliberately NOT derived from the
 * library's own array. Checking a generated TLD against
 * cloak_client_top_level_domains only ever proves the generator uses its
 * own list; the property that actually matters is that the list IS Go's,
 * because a Cloak client drawing from a different set than every other
 * Cloak client is distinguishable from them. This literal is the only
 * thing in the tree that pins that. */
static const char *const go_top_level_domains[13] = {
    "com", "net", "org", "it", "fr", "me", "ru", "cn", "es", "tr", "top", "xyz", "info",
};

static void test_tld_list_matches_go(void) {
    ASSERT_EQ_INT(13, CLOAK_CLIENT_TLD_COUNT);
    for (size_t i = 0; i < CLOAK_CLIENT_TLD_COUNT && i < 13; i++) {
        ASSERT_TRUE(strcmp(cloak_client_top_level_domains[i], go_top_level_domains[i]) == 0);
        if (strcmp(cloak_client_top_level_domains[i], go_top_level_domains[i]) != 0) {
            fprintf(stderr, "  TLD %zu: have \"%s\", Go has \"%s\"\n", i,
                    cloak_client_top_level_domains[i], go_top_level_domains[i]);
        }
    }
}

static int tld_is_listed(const char *tld) {
    for (size_t i = 0; i < CLOAK_CLIENT_TLD_COUNT; i++) {
        if (strcmp(tld, cloak_client_top_level_domains[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static void check_plausible_hostname(const char *name) {
    const char *dot = strchr(name, '.');
    ASSERT_TRUE(dot != NULL);
    if (dot == NULL) {
        return;
    }
    size_t label_len = (size_t)(dot - name);
    ASSERT_TRUE(label_len >= 3 && label_len <= 12);
    for (size_t i = 0; i < label_len; i++) {
        ASSERT_TRUE(name[i] >= 'a' && name[i] <= 'z');
    }
    ASSERT_TRUE(tld_is_listed(dot + 1));
}

static void test_random_server_name(void) {
    /* Every draw is plausible, every label length in 3..12 occurs, every
     * listed TLD occurs, and the LETTERS VARY WITHIN a label -- so a
     * generator stuck on one length, one TLD, or one letter per name
     * fails here rather than passing on a lucky sample. The per-character
     * check is not decoration: drawing a single letter and repeating it
     * ("aaaaaa.com", "zzz.net") satisfies "every character is in a..z"
     * while collapsing the label space from 26^n to 26, which across many
     * connections is exactly the aggregate distinguisher
     * randomServerName exists to avoid. */
    int len_seen[13];
    int tld_seen[CLOAK_CLIENT_TLD_COUNT];
    int letter_seen[26];
    memset(len_seen, 0, sizeof(len_seen));
    memset(tld_seen, 0, sizeof(tld_seen));
    memset(letter_seen, 0, sizeof(letter_seen));

    char first[CLOAK_CLIENT_RANDOM_SERVER_NAME_MAX];
    ASSERT_EQ_INT(0, cloak_client_random_server_name(first, sizeof(first)));
    check_plausible_hostname(first);

    int distinct = 0;
    int mixed_label_seen = 0;
    for (int i = 0; i < 2000; i++) {
        char name[CLOAK_CLIENT_RANDOM_SERVER_NAME_MAX];
        ASSERT_EQ_INT(0, cloak_client_random_server_name(name, sizeof(name)));
        check_plausible_hostname(name);
        if (strcmp(name, first) != 0) {
            distinct = 1;
        }
        const char *dot = strchr(name, '.');
        if (dot == NULL) {
            continue;
        }
        size_t label_len = (size_t)(dot - name);
        len_seen[label_len] = 1;
        for (size_t c = 0; c < label_len; c++) {
            int idx = name[c] - 'a';
            if (idx >= 0 && idx < 26) {
                letter_seen[idx] = 1;
            }
            if (name[c] != name[0]) {
                mixed_label_seen = 1;
            }
        }
        for (size_t t = 0; t < CLOAK_CLIENT_TLD_COUNT; t++) {
            if (strcmp(dot + 1, cloak_client_top_level_domains[t]) == 0) {
                tld_seen[t] = 1;
            }
        }
    }
    ASSERT_TRUE(distinct);
    for (int l = 3; l <= 12; l++) {
        ASSERT_TRUE(len_seen[l]);
    }
    for (size_t t = 0; t < CLOAK_CLIENT_TLD_COUNT; t++) {
        ASSERT_TRUE(tld_seen[t]);
    }
    /* At least one label mixed two different letters, and the alphabet is
     * covered: over 2000 draws averaging 7.5 letters each, a genuine
     * uniform draw misses a given letter with probability ~(25/26)^15000,
     * so requiring all 26 is not flaky. */
    ASSERT_TRUE(mixed_label_seen);
    int letters_used = 0;
    for (int c = 0; c < 26; c++) {
        letters_used += letter_seen[c];
    }
    ASSERT_EQ_INT(26, letters_used);

    /* Too small a buffer is refused rather than truncated. */
    char tiny[CLOAK_CLIENT_RANDOM_SERVER_NAME_MAX - 1];
    ASSERT_EQ_INT(-1, cloak_client_random_server_name(tiny, sizeof(tiny)));
}

/* "random" is matched case-insensitively (Go's strings.EqualFold), and
 * the generated name is the one that actually reaches the wire -- read
 * back out of the SNI extension of the ClientHello the server parsed,
 * not merely out of the client's own struct. */
static void test_random_server_name_reaches_the_wire(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    fake_server_t fs;
    ASSERT_EQ_INT(0, fake_server_start(&fs, r));
    int fd = connect_nonblocking(fake_server_port(&fs));
    ASSERT_TRUE(fd >= 0);

    hs_result_t res;
    memset(&res, 0, sizeof(res));
    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0x99);
    cloak_client_handshake_config_t cfg;
    base_config(&cfg, r, fd, fs.pub, uid, 5, &res);
    cfg.server_name = "RaNdOm";

    cloak_client_handshake_t h;
    ASSERT_EQ_INT(0, cloak_client_handshake_init(&h, &cfg));
    const char *generated = cloak_client_handshake_server_name(&h);
    ASSERT_TRUE(generated != NULL);
    if (generated != NULL) {
        ASSERT_TRUE(strcmp(generated, "RaNdOm") != 0);
        check_plausible_hostname(generated);
    }
    ASSERT_EQ_INT(0, cloak_client_handshake_start(&h));

    pump_until_accepted(r, &fs);
    for (int i = 0; i < 100 && !fs.hello_parsed; i++) {
        cloak_reactor_run_once(r, 5);
        fake_server_pull(&fs, 4096);
    }
    ASSERT_TRUE(fs.hello_parsed);
    if (generated != NULL) {
        ASSERT_TRUE(strcmp(fs.sni, generated) == 0);
    }

    /* A literal name passes straight through, unchanged. */
    cloak_client_handshake_destroy(&h);
    close(fd);
    fake_server_stop(&fs);

    fake_server_t fs2;
    ASSERT_EQ_INT(0, fake_server_start(&fs2, r));
    int fd2 = connect_nonblocking(fake_server_port(&fs2));
    ASSERT_TRUE(fd2 >= 0);
    hs_result_t res2;
    memset(&res2, 0, sizeof(res2));
    cloak_client_handshake_config_t cfg2;
    base_config(&cfg2, r, fd2, fs2.pub, uid, 6, &res2);
    cfg2.server_name = "cdn.example.org";
    cloak_client_handshake_t h2;
    ASSERT_EQ_INT(0, cloak_client_handshake_init(&h2, &cfg2));
    ASSERT_EQ_INT(0, cloak_client_handshake_start(&h2));
    pump_until_accepted(r, &fs2);
    for (int i = 0; i < 100 && !fs2.hello_parsed; i++) {
        cloak_reactor_run_once(r, 5);
        fake_server_pull(&fs2, 4096);
    }
    ASSERT_TRUE(fs2.hello_parsed);
    ASSERT_TRUE(strcmp(fs2.sni, "cdn.example.org") == 0);

    cloak_client_handshake_destroy(&h2);
    close(fd2);
    fake_server_stop(&fs2);
    cloak_reactor_destroy(r);
}

/* ---- case 7: all three browser templates authenticate ------------------- */

static void test_all_browsers_authenticate(void) {
    const cloak_client_browser_t browsers[3] = {CLOAK_CLIENT_BROWSER_CHROME,
                                                CLOAK_CLIENT_BROWSER_FIREFOX,
                                                CLOAK_CLIENT_BROWSER_SAFARI};
    for (int b = 0; b < 3; b++) {
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        struct real_server rs;
        ASSERT_EQ_INT(0, real_server_init(&rs, r));

        hs_result_t res;
        memset(&res, 0, sizeof(res));
        int fd = connect_nonblocking(cloak_listener_port(&rs.front));
        ASSERT_TRUE(fd >= 0);

        cloak_client_handshake_config_t cfg;
        base_config(&cfg, r, fd, rs.server_pub, rs.uid, (uint32_t)(9000 + b), &res);
        cfg.browser = browsers[b];

        cloak_client_handshake_t h;
        ASSERT_EQ_INT(0, cloak_client_handshake_init(&h, &cfg));
        ASSERT_EQ_INT(0, cloak_client_handshake_start(&h));
        pump_until_done(r, &res, 400);

        ASSERT_EQ_INT(1, res.calls);
        ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_DONE, res.status);
        ASSERT_EQ_INT(1, rs.attached.calls);
        ASSERT_EQ_INT(0, rs.cover.accept_count);
        if (rs.attached.last_sesh != NULL) {
            ASSERT_MEM_EQ(res.key, rs.attached.last_sesh->obfuscator.session_key,
                          CLOAK_AEAD_KEY_LEN);
        }

        cloak_client_handshake_destroy(&h);
        close(fd);
        real_server_destroy(&rs);
        cloak_reactor_destroy(r);
    }
}

/* Case 7's other half, and the one that stops it being one template run
 * three times. test_all_browsers_authenticate proves each browser value
 * produces a ClientHello the real server accepts -- but a template_for()
 * that returned the Chrome template for all three would satisfy that
 * completely, and the whole point of having three templates is that they
 * are three different DPI fingerprints.
 *
 * The comparison is made on the cipher_suites block, which is the largest
 * run of bytes in a ClientHello that is fixed by the template and
 * untouched by everything cloak_clienthello_build randomises or shifts:
 * it sits before the extensions (so the SNI-length and ECH-length shifts
 * cannot move it) and after the session_id (so Cloak's own spliced
 * fields cannot overwrite it). In the framed record it starts at offset
 * 5 + 71 = 76; in the template's own byte array, at 71.
 *
 * Two assertions, and both are needed: the block must EQUAL the template
 * the browser names (which is what pins the mapping), and the three
 * blocks must be pairwise DIFFERENT (without which the equality could
 * hold for three identical templates and prove nothing). */
#define CS_BLOCK_OFF_IN_TEMPLATE 71
#define CS_BLOCK_OFF_IN_RECORD (5 + CS_BLOCK_OFF_IN_TEMPLATE)

static size_t cs_block_len(const uint8_t *at) {
    return 2 + (((size_t)at[0] << 8) | (size_t)at[1]);
}

static int cs_is_grease(uint16_t v) {
    return (v & 0x0f0fu) == 0x0a0au && (uint8_t)(v >> 8) == (uint8_t)(v & 0xffu);
}

/* Copies a cipher_suites block, replacing every entry that the TEMPLATE
 * holds a GREASE codepoint in with a single canonical value, and
 * asserting the WIRE held a GREASE codepoint in the same slot.
 *
 * This is here because cloak_clienthello_build now re-draws GREASE per
 * connection, the way real Chrome, real Safari and Go's uTLS do
 * (internal/client/TLS.go:66-80), so the GREASE slot of a captured hello
 * cannot equal the template's frozen capture byte and must not be
 * required to. This test runs a real handshake over a real socket, so
 * there is no seed to pin -- unlike test_clienthello.c, which uses
 * cloak_clienthello_build_with_grease_seed and keeps its literals exact.
 *
 * Nothing is weakened by this: the slot still has to be a legal GREASE
 * value (which a zeroed or truncated block is not), and every OTHER byte
 * of the block is still compared exactly. What is dropped is only the
 * requirement that the value be one specific frozen constant -- which
 * was the defect. */
static void cs_normalize_grease(uint8_t *dst, const uint8_t *wire, const uint8_t *tmpl,
                                size_t len) {
    memcpy(dst, wire, len);
    for (size_t i = 2; i + 1 < len; i += 2) {
        uint16_t t = (uint16_t)(((uint16_t)tmpl[i] << 8) | tmpl[i + 1]);
        if (!cs_is_grease(t)) {
            continue;
        }
        uint16_t w = (uint16_t)(((uint16_t)wire[i] << 8) | wire[i + 1]);
        ASSERT_TRUE(cs_is_grease(w));
        dst[i] = 0x0a;
        dst[i + 1] = 0x0a;
    }
}

static void test_browser_templates_are_distinct(void) {
    const cloak_client_browser_t browsers[3] = {CLOAK_CLIENT_BROWSER_CHROME,
                                                CLOAK_CLIENT_BROWSER_FIREFOX,
                                                CLOAK_CLIENT_BROWSER_SAFARI};
    const cloak_clienthello_template_t *templates[3] = {
        &cloak_clienthello_chrome, &cloak_clienthello_firefox, &cloak_clienthello_safari};

    uint8_t captured[3][512];
    size_t captured_len[3] = {0, 0, 0};

    for (int b = 0; b < 3; b++) {
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        fake_server_t fs;
        ASSERT_EQ_INT(0, fake_server_start(&fs, r));
        int fd = connect_nonblocking(fake_server_port(&fs));
        ASSERT_TRUE(fd >= 0);

        hs_result_t res;
        memset(&res, 0, sizeof(res));
        uint8_t uid[CLOAK_UID_LEN];
        fill_uid(uid, (uint8_t)(0xc0 + b));
        cloak_client_handshake_config_t cfg;
        base_config(&cfg, r, fd, fs.pub, uid, (uint32_t)(300 + b), &res);
        cfg.browser = browsers[b];

        cloak_client_handshake_t h;
        ASSERT_EQ_INT(0, cloak_client_handshake_init(&h, &cfg));
        ASSERT_EQ_INT(0, cloak_client_handshake_start(&h));
        pump_until_accepted(r, &fs);
        for (int i = 0; i < 200 && !fs.hello_parsed; i++) {
            cloak_reactor_run_once(r, 5);
            fake_server_pull(&fs, 4096);
        }
        ASSERT_TRUE(fs.hello_parsed);

        const uint8_t *tmpl_cs = templates[b]->bytes + CS_BLOCK_OFF_IN_TEMPLATE;
        size_t len = cs_block_len(tmpl_cs);
        ASSERT_TRUE(len <= sizeof(captured[0]));
        ASSERT_TRUE(fs.in_len > CS_BLOCK_OFF_IN_RECORD + len);
        if (len <= sizeof(captured[0]) && fs.in_len > CS_BLOCK_OFF_IN_RECORD + len) {
            /* What went on the wire IS this browser's template, modulo
             * the per-connection GREASE draw. */
            uint8_t norm_wire[512];
            uint8_t norm_tmpl[512];
            cs_normalize_grease(norm_wire, fs.in + CS_BLOCK_OFF_IN_RECORD, tmpl_cs, len);
            cs_normalize_grease(norm_tmpl, tmpl_cs, tmpl_cs, len);
            ASSERT_MEM_EQ(norm_wire, norm_tmpl, len);
            memcpy(captured[b], norm_wire, len);
            captured_len[b] = len;
        }

        cloak_client_handshake_destroy(&h);
        close(fd);
        fake_server_stop(&fs);
        cloak_reactor_destroy(r);
    }

    /* Pairwise different, so the equalities above are not three copies of
     * the same assertion. */
    for (int i = 0; i < 3; i++) {
        for (int j = i + 1; j < 3; j++) {
            ASSERT_TRUE(captured_len[i] > 0 && captured_len[j] > 0);
            int same = captured_len[i] == captured_len[j] &&
                       memcmp(captured[i], captured[j], captured_len[i]) == 0;
            ASSERT_TRUE(!same);
            if (same) {
                fprintf(stderr, "  browsers %d and %d produced identical cipher suites\n", i, j);
            }
        }
    }
}

/* ---- construction contract ---------------------------------------------- */

/* Every rejected construction leaves h safe to destroy, and none of them
 * fires on_done. */
static void test_init_rejects_and_stays_safe(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    uint8_t uid[CLOAK_UID_LEN];
    uint8_t pub[CLOAK_X25519_KEY_LEN];
    uint8_t priv[CLOAK_X25519_KEY_LEN];
    fill_uid(uid, 0x11);
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(priv, pub));

    hs_result_t res;
    cloak_client_handshake_config_t cfg;
    cloak_client_handshake_t h;

    /* A handshake destroyed while never initialized at all. */
    memset(&h, 0, sizeof(h));
    cloak_client_handshake_destroy(&h);

    struct {
        const char *what;
        int null_reactor;
        int bad_fd;
        const char *server_name;
        const char *proxy_method;
        int null_cb;
        int bad_browser;
    } cases[] = {
        {"null reactor", 1, 0, "a.com", "ss", 0, 0},
        {"bad fd", 0, 1, "a.com", "ss", 0, 0},
        {"null server name", 0, 0, NULL, "ss", 0, 0},
        {"empty server name", 0, 0, "", "ss", 0, 0},
        {"null proxy method", 0, 0, "a.com", NULL, 0, 0},
        {"over-long proxy method", 0, 0, "a.com", "thirteenchars", 0, 0},
        {"null callback", 0, 0, "a.com", "ss", 1, 0},
        {"unknown browser", 0, 0, "a.com", "ss", 0, 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(&res, 0, sizeof(res));
        base_config(&cfg, r, 3, pub, uid, 1, &res);
        if (cases[i].null_reactor) {
            cfg.reactor = NULL;
        }
        if (cases[i].bad_fd) {
            cfg.fd = -1;
        }
        cfg.server_name = cases[i].server_name;
        cfg.proxy_method = cases[i].proxy_method;
        if (cases[i].null_cb) {
            cfg.on_done = NULL;
        }
        if (cases[i].bad_browser) {
            cfg.browser = (cloak_client_browser_t)77;
        }
        ASSERT_EQ_INT(-1, cloak_client_handshake_init(&h, &cfg));
        ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_FAILED, cloak_client_handshake_status(&h));
        ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_ERR_CONFIG, cloak_client_handshake_error(&h));
        ASSERT_EQ_INT(-1, cloak_client_handshake_start(&h));
        ASSERT_EQ_INT(0, res.calls);
        cloak_client_handshake_destroy(&h);
        ASSERT_EQ_INT(0, res.calls);
    }

    /* A server name longer than DNS allows is refused, not truncated. */
    char long_name[CLOAK_CLIENT_SERVER_NAME_MAX + 8];
    memset(long_name, 'a', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';
    memset(&res, 0, sizeof(res));
    base_config(&cfg, r, 3, pub, uid, 1, &res);
    cfg.server_name = long_name;
    ASSERT_EQ_INT(-1, cloak_client_handshake_init(&h, &cfg));
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_ERR_CONFIG, cloak_client_handshake_error(&h));
    cloak_client_handshake_destroy(&h);

    /* NULL tolerance on every accessor. */
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_FAILED, cloak_client_handshake_status(NULL));
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_ERR_CONFIG, cloak_client_handshake_error(NULL));
    ASSERT_TRUE(cloak_client_handshake_session_key(NULL) == NULL);
    ASSERT_TRUE(cloak_client_handshake_server_name(NULL) == NULL);
    ASSERT_EQ_INT(-1, cloak_client_handshake_init(NULL, &cfg));
    ASSERT_EQ_INT(-1, cloak_client_handshake_start(NULL));
    cloak_client_handshake_destroy(NULL);

    cloak_reactor_destroy(r);
}

/* A server that answers with a well-formed reply sealed under the WRONG
 * secret is rejected as ERR_AUTH, not accepted with a garbage key. */
static void test_wrong_key_reply_is_rejected(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    fake_server_t fs;
    ASSERT_EQ_INT(0, fake_server_start(&fs, r));

    hs_result_t res;
    memset(&res, 0, sizeof(res));
    int fd = connect_nonblocking(fake_server_port(&fs));
    ASSERT_TRUE(fd >= 0);

    uint8_t uid[CLOAK_UID_LEN];
    fill_uid(uid, 0xaa);
    cloak_client_handshake_config_t cfg;
    base_config(&cfg, r, fd, fs.pub, uid, 12, &res);

    cloak_client_handshake_t h;
    ASSERT_EQ_INT(0, cloak_client_handshake_init(&h, &cfg));
    ASSERT_EQ_INT(0, cloak_client_handshake_start(&h));

    pump_until_accepted(r, &fs);
    for (int i = 0; i < 100 && !fs.hello_parsed; i++) {
        cloak_reactor_run_once(r, 5);
        fake_server_pull(&fs, 4096);
    }
    ASSERT_TRUE(fs.hello_parsed);

    /* Corrupt one byte of the sealed ciphertext inside the ServerHello's
     * random field. */
    fs.reply[23] ^= 0xff;
    for (int i = 0; i < 400 && res.calls == 0; i++) {
        fake_server_push(&fs, 4096);
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_EQ_INT(1, res.calls);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_FAILED, res.status);
    ASSERT_EQ_INT(CLOAK_CLIENT_HANDSHAKE_ERR_AUTH, res.error);

    cloak_client_handshake_destroy(&h);
    close(fd);
    fake_server_stop(&fs);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
test_real_server_key_agreement();
test_byte_at_a_time_and_no_over_read();
test_partial_client_hello_write();
test_close_mid_reply();
test_record_length_bound();
test_deadline();
test_default_deadline_is_applied();
test_tld_list_matches_go();
test_random_server_name();
test_random_server_name_reaches_the_wire();
test_all_browsers_authenticate();
test_browser_templates_are_distinct();
test_init_rejects_and_stays_safe();
test_wrong_key_reply_is_rejected();
TEST_MAIN_END()
