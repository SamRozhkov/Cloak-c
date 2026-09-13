#ifndef CLOAK_TEST_CLIENT_HARNESS_H
#define CLOAK_TEST_CLIENT_HARNESS_H

/* Shared client-side test harness for the dispatcher test suite.
 *
 * test_dispatcher_auth.c and test_dispatcher_limits.c each used to carry
 * their own verbatim copy of everything below -- building a real Cloak
 * ClientHello, pumping a reactor against a fake cover site, and reading a
 * dispatcher's reply -- matching this project's convention (see git log)
 * of duplicating small test-only helpers across dispatcher test files
 * instead of sharing them. That stopped scaling once a THIRD family of
 * tests (the server-proxy plan) needed the same helpers plus a
 * client-side cloak_session_t built on top of them, so this header is the
 * single place all of that now lives. test_dispatcher_redirect.c keeps its
 * own separate (older) copy of the handshake-agnostic pieces it needs
 * (pump_until, cover_site_t, client_connect) -- it predates this header
 * and was out of scope for the extraction that created it.
 *
 * This header assumes -- like test_framework.h already does for every
 * dispatcher test file -- that it is included by exactly ONE translation
 * unit per test binary, so every symbol below is file-scope (static).
 * Some of these helpers may end up unused in a given includer (not every
 * test file needs every helper), so each one is marked `static inline`
 * rather than plain `static`: a `static inline` function that is never
 * used does not trigger -Wunused-function, where a plain `static` one
 * would (verified against this project's actual -Wall -Wextra build, not
 * merely assumed). */

#include "cloak/base64.h"
#include "cloak/clienthello.h"
#include "cloak/config.h"
#include "cloak/crypto.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/server_auth.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "test_framework.h"

#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ---- bounded reactor pumping (same discipline test_dispatcher_redirect.c
 * uses: every wait here is "poll for up to N turns of at most MS each",
 * never unbounded -- three tests on this project have hung or flaked in
 * CI, all found only by repetition). ---------------------------------- */

typedef int (*pump_done_fn)(void *ctx);

static inline int pump_until(cloak_reactor_t *r, pump_done_fn done, void *ctx, int max_iters,
                             int per_iter_ms) {
    for (int i = 0; i < max_iters; i++) {
        if (done(ctx)) {
            return 1;
        }
        cloak_reactor_run_once(r, per_iter_ms);
    }
    return done(ctx);
}

/* ---- fake cover site -----------------------------------------------------
 *
 * Note this struct's buf/len are shared across every connection the fake
 * cover site accepts: fine for a test that expects exactly one connection
 * to reach it, and fine too for a test that only ever checks
 * accept_count (never buf content) across many connections -- but not a
 * general-purpose per-connection buffer. */

typedef struct {
    cloak_reactor_t *reactor;
    int fd;
    int accept_count;
    uint8_t buf[8192];
    size_t len;
    int eof;
} cover_site_t;

static inline void cover_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
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
        break;
    }
}

static inline void cover_on_accept(cloak_listener_t *l, int fd, void *userdata) {
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

static inline int cover_has_len(void *ctx) {
    struct len_wait *w = ctx;
    return w->cov->len >= w->want;
}

/* ---- client helper --------------------------------------------------------
 *
 * A plain blocking socket. A receive timeout bounds every read against a
 * dispatcher that never closes the way it should. */

static inline int client_connect(int port) {
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

/* The client's own local (ephemeral) port -- which is exactly the PEER
 * port the dispatcher's accepted socket for this same connection will
 * report via getpeername(), and therefore what test_write_shim.c's
 * CLOAK_TEST_FORCE_PEER_PORT must be set to in order to target this
 * specific connection's reply write. Returns -1 on failure. */
static inline int client_local_port(int fd) {
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        return -1;
    }
    return ntohs(sa.sin_port);
}

/* ---- building a real Cloak ClientHello ------------------------------------
 *
 * This builds a REAL Cloak handshake from primitives already merged
 * elsewhere in this project -- cloak_x25519_generate_keypair/
 * cloak_x25519_shared_secret, cloak_aead_seal, and cloak_clienthello_build
 * -- rather than a mock, so a passing test using it means the dispatcher's
 * authentication path genuinely agrees with the rest of this codebase
 * about wire format, not merely with itself.
 *
 * cloak_clienthello_build's own header (cloak/clienthello.h) documents
 * that it "Builds a ClientHello handshake message (no TLS record layer)":
 * it returns ONLY the handshake_type(1)+length(3)+body bytes, never the
 * 5-byte TLS record header. cloak_clienthello_parse (and therefore
 * cloak_firstpacket_t, which is what actually frames a connection's first
 * packet) expects that 5-byte record header to already be present -- see
 * libcloak-server/tests/test_clienthello_parse.c's own GOOD_HEX vector,
 * which starts with the record header {0x16, 0x03, 0x01, len_hi, len_lo}
 * before the handshake message begins. build_client_record therefore
 * prepends that header itself; the dispatcher's own first-packet framing
 * is what requires it. */

/* The 48-byte decrypted-payload layout server_auth.h documents byte for
 * byte: [0:16) UID, [16:28) NUL-padded proxy method, [28] encryption
 * method, [29:37) big-endian Unix timestamp, [37:41) big-endian session
 * id, [41] flags, [42:48) reserved. */
static inline void build_auth_payload(uint8_t out[48], const uint8_t uid[CLOAK_UID_LEN],
                                      const char *proxy_method, uint8_t encryption_method,
                                      int64_t timestamp, uint32_t session_id, int unordered) {
    memset(out, 0, 48);
    memcpy(out, uid, CLOAK_UID_LEN);

    size_t pmlen = strlen(proxy_method);
    if (pmlen > CLOAK_SERVER_AUTH_PROXY_METHOD_LEN) {
        pmlen = CLOAK_SERVER_AUTH_PROXY_METHOD_LEN;
    }
    memcpy(out + 16, proxy_method, pmlen);

    out[28] = encryption_method;

    uint64_t ts = (uint64_t)timestamp;
    for (int i = 0; i < 8; i++) {
        out[29 + i] = (uint8_t)(ts >> (8 * (7 - i)));
    }
    for (int i = 0; i < 4; i++) {
        out[37 + i] = (uint8_t)(session_id >> (8 * (3 - i)));
    }
    out[41] = unordered ? CLOAK_SERVER_AUTH_UNORDERED_FLAG : 0;
    /* [42:48) reserved -- already zero from the memset above. */
}

/* Builds one complete, framed ClientHello record (5-byte TLS record
 * header + the handshake message cloak_clienthello_build returns) for a
 * fresh ephemeral keypair, encrypting the auth payload exactly the way a
 * real Cloak client does: cloak_aead_seal with AES-256-GCM, key = the
 * ECDH shared secret against server_pub, nonce = the first 12 bytes of
 * the ephemeral public key (this is also, byte-for-byte, the same
 * "random" field cloak_server_auth_decrypt uses as ITS nonce -- see
 * server_auth.c, which passes the ClientHello's random field straight
 * through to cloak_aead_open as the nonce).
 *
 * Returns the total record length and writes the derived shared secret to
 * out_shared_secret, needed later to decrypt this connection's own reply. */
static inline size_t build_client_record(const uint8_t server_pub[CLOAK_X25519_KEY_LEN],
                                         const uint8_t uid[CLOAK_UID_LEN], const char *proxy_method,
                                         uint8_t encryption_method, int64_t timestamp,
                                         uint32_t session_id, int unordered, uint8_t *out_record,
                                         size_t out_cap, uint8_t out_shared_secret[CLOAK_AEAD_KEY_LEN]) {
    uint8_t eph_priv[CLOAK_X25519_KEY_LEN];
    uint8_t eph_pub[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(eph_priv, eph_pub));

    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_shared_secret(eph_priv, server_pub, shared));
    memcpy(out_shared_secret, shared, CLOAK_AEAD_KEY_LEN);

    uint8_t payload[48];
    build_auth_payload(payload, uid, proxy_method, encryption_method, timestamp, session_id,
                       unordered);

    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    memcpy(nonce, eph_pub, CLOAK_AEAD_NONCE_LEN);

    uint8_t ct[64];
    size_t ct_len = 0;
    ASSERT_EQ_INT(0, cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, shared, nonce, NULL, 0, payload,
                                     sizeof(payload), ct, &ct_len));
    ASSERT_EQ_INT((int)ct_len, 64);

    uint8_t handshake[CLOAK_CLIENTHELLO_MAX_BYTES];
    long hs_len = cloak_clienthello_build(&cloak_clienthello_chrome, eph_pub, ct, ct + 32,
                                          "www.example.com", handshake, sizeof(handshake));
    ASSERT_TRUE(hs_len > 0);
    if (hs_len <= 0) {
        return 0;
    }

    size_t total = 5 + (size_t)hs_len;
    ASSERT_TRUE(out_cap >= total);

    out_record[0] = 0x16;
    out_record[1] = 0x03;
    out_record[2] = 0x01;
    out_record[3] = (uint8_t)(((size_t)hs_len >> 8) & 0xff);
    out_record[4] = (uint8_t)((size_t)hs_len & 0xff);
    memcpy(out_record + 5, handshake, (size_t)hs_len);
    return total;
}

/* Reads a dispatcher reply off fd, pumping r as needed. The ServerHello
 * portion of any reply is always exactly 127 bytes (5-byte record header
 * + a 122-byte handshake message: cloak/server_auth.h's own
 * CLOAK_SERVER_AUTH_REPLY_MAX_BYTES comment derives the same fixed 127),
 * followed by a fixed 6-byte ChangeCipherSpec record, followed by a fake
 * Certificate record whose own 2-byte length field (at byte offset
 * [136:138) -- 127 + 6 + 3 bytes into that record's own header) tells us
 * exactly how many more bytes to expect. Once we can see that field, the
 * total reply length is fully determined and this stops pumping. */
static inline int read_reply(cloak_reactor_t *r, int fd, uint8_t *buf, size_t cap, size_t *out_len) {
    size_t got = 0;
    for (int i = 0; i < 300; i++) {
        cloak_reactor_run_once(r, 10);
        if (got < cap) {
            ssize_t n = recv(fd, buf + got, cap - got, MSG_DONTWAIT);
            if (n > 0) {
                got += (size_t)n;
            } else if (n == 0) {
                break;
            }
        }
        if (got >= 138) {
            size_t cert_len = ((size_t)buf[136] << 8) | (size_t)buf[137];
            size_t target = 138 + cert_len;
            if (got >= target) {
                got = target;
                break;
            }
        }
    }
    *out_len = got;
    return got > 0 ? 0 : -1;
}

/* Undoes cloak_server_auth_compose_reply's split of the 48-byte sealed
 * session key across the ServerHello's random field (bytes [11:23) =
 * reply_nonce, [23:43) = ciphertext[0:20)) and its key_share extension
 * ([89:117) = ciphertext[20:48), the offsets server_auth.c's own
 * cloak_server_auth_compose_reply writes to, then AEAD-opens it with the
 * caller's own shared secret -- exactly what a real Cloak client does to
 * recover its session key. */
static inline int extract_session_key_from_reply(const uint8_t shared_secret[CLOAK_AEAD_KEY_LEN],
                                                  const uint8_t *reply, size_t reply_len,
                                                  uint8_t out_session_key[CLOAK_AEAD_KEY_LEN]) {
    if (reply_len < 127) {
        return -1;
    }
    uint8_t reply_nonce[CLOAK_AEAD_NONCE_LEN];
    memcpy(reply_nonce, reply + 11, CLOAK_AEAD_NONCE_LEN);

    uint8_t ct[48];
    memcpy(ct, reply + 23, 20);
    memcpy(ct + 20, reply + 89, 28);

    uint8_t out[CLOAK_AEAD_KEY_LEN];
    size_t out_len = 0;
    if (cloak_aead_open(CLOAK_AEAD_AES_256_GCM, shared_secret, reply_nonce, NULL, 0, ct,
                        sizeof(ct), out, &out_len) != 0) {
        return -1;
    }
    if (out_len != CLOAK_AEAD_KEY_LEN) {
        return -1;
    }
    memcpy(out_session_key, out, CLOAK_AEAD_KEY_LEN);
    return 0;
}

/* ---- a fully established client-side cloak_session_t ---------------------
 *
 * A fully established CLIENT side of a Cloak session, for tests that need
 * to pass real traffic rather than only complete a handshake. Wraps what
 * every such test would otherwise repeat: connect, send a ClientHello
 * built by build_client_record, read the reply, recover the session key
 * from it, build a matching obfuscator, and bring up a client-side
 * cloak_session_t over the same socket.
 *
 * The client session runs on the SAME reactor as the server under test --
 * one pump_until loop drives both ends, exactly as the existing tests
 * already drive their fake cover site. */
typedef struct {
    cloak_session_t sesh;
    int sesh_ready;
    int fd;                 /* owned by sesh once client_session_open returns 0 */
    uint8_t session_key[CLOAK_AEAD_KEY_LEN];
    int broken;             /* set by the harness's own on_broken */
} client_session_t;

static inline void client_session_on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    client_session_t *cs = userdata;
    cs->broken = 1;
}

/* port: the dispatcher's front listener port. server_pub / uid /
 * proxy_method / session_id / unordered are passed straight through to
 * build_client_record. cfg supplies the mux parameters; its obfuscator,
 * on_broken and on_broken_userdata are overwritten by this call.
 *
 * Pumps r internally (bounded) to complete the handshake. Returns 0 on
 * success with cs fully live, -1 otherwise with cs safe to pass to
 * client_session_close. */
static inline int client_session_open(client_session_t *cs, cloak_reactor_t *r, int port,
                                      const uint8_t server_pub[CLOAK_X25519_KEY_LEN],
                                      const uint8_t uid[CLOAK_UID_LEN],
                                      const char *proxy_method, uint32_t session_id,
                                      int unordered, cloak_session_config_t *cfg) {
    memset(cs, 0, sizeof(*cs));
    cs->fd = -1;

    int64_t now = (int64_t)time(NULL);
    uint8_t record[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    size_t record_len = build_client_record(server_pub, uid, proxy_method,
                                            (uint8_t)CLOAK_AEAD_AES_256_GCM, now, session_id,
                                            unordered, record, sizeof(record), shared_secret);
    if (record_len == 0) {
        return -1;
    }

    int fd = client_connect(port);
    if (fd < 0) {
        return -1;
    }
    if (write(fd, record, record_len) != (ssize_t)record_len) {
        close(fd);
        return -1;
    }

    uint8_t reply[512];
    size_t reply_len = 0;
    if (read_reply(r, fd, reply, sizeof(reply), &reply_len) != 0) {
        close(fd);
        return -1;
    }

    uint8_t session_key[CLOAK_AEAD_KEY_LEN];
    if (extract_session_key_from_reply(shared_secret, reply, reply_len, session_key) != 0) {
        close(fd);
        return -1;
    }
    memcpy(cs->session_key, session_key, CLOAK_AEAD_KEY_LEN);

    cfg->obfuscator.method = CLOAK_AEAD_AES_256_GCM;
    memcpy(cfg->obfuscator.session_key, cs->session_key, CLOAK_AEAD_KEY_LEN);
    cfg->on_broken = client_session_on_broken;
    cfg->on_broken_userdata = cs;

    if (cloak_session_init(&cs->sesh, session_id, r, cfg) != 0) {
        close(fd);
        return -1;
    }
    cs->sesh_ready = 1;

    if (cloak_session_add_conn(&cs->sesh, fd) != 0) {
        /* cloak_session_add_conn's own contract: the caller still owns fd
         * on failure. */
        close(fd);
        cloak_session_destroy(&cs->sesh);
        cs->sesh_ready = 0;
        return -1;
    }
    cs->fd = fd;
    return 0;
}

static inline void client_session_close(client_session_t *cs) {
    if (cs->sesh_ready) {
        cloak_session_destroy(&cs->sesh);
        cs->sesh_ready = 0;
    }
    /* fd is owned by sesh from the moment client_session_open returns 0
     * (see client_session_t's own field comment); every failure path in
     * client_session_open already closed it itself before returning, so
     * there is nothing left to close here in that case. */
    cs->fd = -1;
}

#endif
