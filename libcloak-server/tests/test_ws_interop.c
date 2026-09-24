#define _POSIX_C_SOURCE 200809L

/* THE CDN SERVER, MEASURED AGAINST IMPLEMENTATIONS NOBODY HERE WROTE.
 *
 * Tasks 1-4 built a WebSocket frame codec, a framing mode, an upgrade
 * parser and the dispatcher branch that joins them, and every test of all
 * of it has this project's code on both ends. That is the exact shape of
 * this port's most expensive defect: a data path that carried a two-byte
 * length prefix where Go writes a five-byte TLS record header, so the
 * disguise applied for one round trip and then dropped -- and it survived
 * five modules because both ends agreed. A round-trip test cannot see a
 * self-consistent error.
 *
 * So every case here puts the finished server in front of either an
 * outside implementation or an input nothing in this tree would ever
 * produce:
 *
 *   1. A REAL GO CLIENT, through a real ck-server, byte for byte. The
 *      client is gorilla/websocket plus cbeuw/Cloak's own authentication
 *      payload, frame obfuscator and Salsa20, copied verbatim (see
 *      ws_interop_oracle/cloak_upstream.go for what came from which file
 *      and which four edits the toolchain forced). The upstream behind
 *      the server XORs rather than echoes, so a session on the wrong key
 *      -- which establishes cleanly and then silently drops every frame
 *      -- cannot pass, and the payload crosses many frames in both
 *      directions, so a prefix comparison cannot pass either.
 *   2. GORILLA AS A DECODER ORACLE, in both directions, with the
 *      negative controls that make the positive result mean something:
 *      an unmasked client frame and a masked server frame must each draw
 *      gorilla's "bad MASK". The gorilla SERVER leg also re-computes
 *      Sec-WebSocket-Accept over a key this file chose, which is the only
 *      check of that computation in this tree that is not our own
 *      opinion.
 *   3. A HAND-WRITTEN FRAGMENTING PROXY between the two, splitting every
 *      message into 2-3 continuation frames with a ping interleaved.
 *      Neither end of a C-to-C test produces this and neither does a Go
 *      peer: it has to be synthesised deliberately, and it is the only
 *      defence this suite has against the CDN-rewriting class of bug,
 *      every one of which passes everything else and fails in production
 *      behind an intermediary nobody here controls.
 *   4. PONG ON PING, from a gorilla client with SetPongHandler. A CDN
 *      pings idle connections and hangs up when no pong comes back.
 *   5. THE NO-OVER-READ GUARANTEE, asserted structurally with
 *      ioctl(FIONREAD) on the server's own descriptor: a byte read past
 *      the upgrade request is a byte the session never sees, and it
 *      desynchronises frame one.
 *   6. PARTIAL-READ RESUMPTION AT EVERY SPLIT POINT, which has no oracle
 *      at all, so it is asserted exhaustively instead.
 *
 * EVERY WAIT IS BOUNDED BY THE CLOCK, never by an iteration count, and
 * every port is ephemeral -- including the ck-server's, which is bound
 * with port 0 and read back out of its own startup log rather than
 * guessed in advance.
 *
 * WHAT THE BRIEF ASKED FOR AND THIS FILE DOES NOT DO: case 6's brief says
 * to "assert the same session key each time". It cannot be the same. The
 * server draws a fresh random session key per session (as Go does), and
 * the only way to hold the client's half of the handshake constant across
 * attempts would be to replay one `Hidden` value, which the replay cache
 * refuses by design. What is invariant across split points is asserted
 * instead, and it is strictly more than the brief asked for: a
 * byte-identical 101, a byte-identical frame header, a reply that decrypts
 * under THAT attempt's own shared secret, and 32 bytes out -- plus the
 * negative form, that no two attempts produced the same key, which a
 * server that had hardcoded one would fail. */

#include "cloak/base64.h"
#include "cloak/common.h"
#include "cloak/conn.h"
#include "cloak/crypto.h"
#include "cloak/dispatcher.h"
#include "cloak/frame.h"
#include "cloak/net.h"
#include "cloak/proxy.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "cloak/session.h"
#include "cloak/switchboard.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
#include "cloak/valve.h"
#include "cloak/ws_handshake.h"
#include "test_framework.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Clocks                                                              */
/* ------------------------------------------------------------------ */

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static uint64_t now_ms(void) { return now_us() / 1000u; }

/* Generous on purpose: this file forks real processes and runs under
 * ctest -j4 with ASan, and a bound that expires because the machine was
 * busy is a false failure, which is strictly worse than a slow pass.
 * Nothing here measures anything against these numbers -- they are
 * backstops, and the ctest TIMEOUT behind them is a backstop to those. */
#define BOOT_MS 15000
#define CHILD_MS 10000
#define PUMP_MS 10000

typedef int (*pump_done_fn)(void *ctx);

/* Pumps the reactor until done(ctx), bounded by REAL TIME. The iteration
 * ceiling is a backstop against a clock that does not advance and is
 * sized so it cannot bind first. */
static int pump_until(cloak_reactor_t *r, pump_done_fn done, void *ctx, int budget_ms,
                      int per_iter_ms) {
    uint64_t start = now_us();
    uint64_t budget_us = (uint64_t)(budget_ms > 0 ? budget_ms : 0) * 1000u;
    for (uint64_t i = 0; i < 50000000u; i++) {
        if (done(ctx)) {
            return 1;
        }
        if (now_us() - start >= budget_us) {
            break;
        }
        cloak_reactor_run_once(r, per_iter_ms);
    }
    return done(ctx);
}

/* A bounded substring search over a byte range. Not memmem(): that is a
 * GNU extension, and this file declares _POSIX_C_SOURCE and nothing
 * wider, so calling it would be an implicit declaration -- a warning, in
 * a tree that builds with -Wall -Wextra and zero of them. */
static const char *mem_find(const void *hay, size_t hay_len, const char *needle,
                            size_t needle_len) {
    const char *h = hay;
    if (needle_len == 0 || hay_len < needle_len) {
        return NULL;
    }
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(h + i, needle, needle_len) == 0) {
            return h + i;
        }
    }
    return NULL;
}

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) {
        (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
}

/* ------------------------------------------------------------------ */
/* Plain sockets (no reactor)                                          */
/* ------------------------------------------------------------------ */

static int listen_on(int *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0; /* EPHEMERAL, always */
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    socklen_t al = sizeof(a);
    if (getsockname(fd, (struct sockaddr *)&a, &al) != 0) {
        close(fd);
        return -1;
    }
    *out_port = (int)ntohs(a.sin_port);
    return fd;
}

static int connect_to(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Accepts one connection, bounded by the clock. */
static int accept_within(int listen_fd, int budget_ms) {
    uint64_t deadline = now_ms() + (uint64_t)budget_ms;
    for (;;) {
        uint64_t now = now_ms();
        if (now >= deadline) {
            return -1;
        }
        struct pollfd p = {listen_fd, POLLIN, 0};
        int rc = poll(&p, 1, (int)(deadline - now));
        if (rc > 0) {
            int fd = accept(listen_fd, NULL, NULL);
            if (fd >= 0) {
                return fd;
            }
        } else if (rc < 0 && errno != EINTR) {
            return -1;
        }
    }
}

/* Reads until `until` appears, bounded by the clock. Returns bytes read,
 * or -1. */
static ssize_t read_until(int fd, char *buf, size_t cap, const char *until, int budget_ms) {
    size_t len = 0;
    size_t ulen = strlen(until);
    uint64_t deadline = now_ms() + (uint64_t)budget_ms;
    while (len + 1 < cap) {
        buf[len] = '\0';
        if (len >= ulen && mem_find(buf, len, until, ulen) != NULL) {
            return (ssize_t)len;
        }
        uint64_t now = now_ms();
        if (now >= deadline) {
            return -1;
        }
        struct pollfd p = {fd, POLLIN, 0};
        int rc = poll(&p, 1, (int)(deadline - now));
        if (rc <= 0) {
            continue;
        }
        ssize_t n = recv(fd, buf + len, cap - len - 1, 0);
        if (n <= 0) {
            return -1;
        }
        len += (size_t)n;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Child processes                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    pid_t pid;
    int fd; /* read end of the child's merged stdout+stderr */
    char out[65536];
    size_t out_len;
    int reaped;
    int status;
} child_t;

static void child_init(child_t *c) {
    memset(c, 0, sizeof(*c));
    c->pid = -1;
    c->fd = -1;
}

static int child_spawn(child_t *c, const char *path, char *const argv[]) {
    int pfd[2];
    child_init(c);
    if (pipe(pfd) != 0) {
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        (void)dup2(pfd[1], STDOUT_FILENO);
        (void)dup2(pfd[1], STDERR_FILENO);
        close(pfd[0]);
        close(pfd[1]);
        execv(path, argv);
        _exit(127);
    }
    close(pfd[1]);
    c->pid = pid;
    c->fd = pfd[0];
    set_nonblock(c->fd);
    return 0;
}

static void child_drain(child_t *c) {
    for (;;) {
        if (c->fd < 0 || c->out_len + 1 >= sizeof(c->out)) {
            return;
        }
        ssize_t n = read(c->fd, c->out + c->out_len, sizeof(c->out) - c->out_len - 1);
        if (n <= 0) {
            return;
        }
        c->out_len += (size_t)n;
        c->out[c->out_len] = '\0';
    }
}

static int child_wait_for(child_t *c, const char *needle, int budget_ms) {
    uint64_t deadline = now_ms() + (uint64_t)budget_ms;
    for (;;) {
        child_drain(c);
        if (strstr(c->out, needle) != NULL) {
            return 0;
        }
        uint64_t now = now_ms();
        if (now >= deadline) {
            return -1;
        }
        struct pollfd p = {c->fd, POLLIN, 0};
        (void)poll(&p, 1, (int)(deadline - now < 50 ? deadline - now : 50));
    }
}

/* Waits for exit, bounded by the clock. Returns the exit code, or -1. */
static int child_reap(child_t *c, int budget_ms) {
    uint64_t deadline = now_ms() + (uint64_t)budget_ms;
    if (c->reaped) {
        /* Already collected -- by feed_gorilla's pump, which waits for the
         * child precisely so the writes and the wait share one loop.
         * waitpid() on an already-reaped pid returns ECHILD, which a
         * caller reading the return value would report as "the child
         * failed"; this is the difference between a passing case and a
         * confusing one. */
        return WIFEXITED(c->status) ? WEXITSTATUS(c->status) : -1;
    }
    for (;;) {
        child_drain(c);
        int status = 0;
        pid_t rc = waitpid(c->pid, &status, WNOHANG);
        if (rc == c->pid) {
            child_drain(c);
            c->reaped = 1;
            c->status = status;
            if (c->fd >= 0) {
                close(c->fd);
                c->fd = -1;
            }
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }
        uint64_t now = now_ms();
        if (now >= deadline) {
            return -1;
        }
        struct pollfd p = {c->fd, POLLIN, 0};
        (void)poll(&p, 1, (int)(deadline - now < 20 ? deadline - now : 20));
    }
}

static void child_stop(child_t *c) {
    if (c->pid > 0 && !c->reaped) {
        kill(c->pid, SIGTERM);
        if (child_reap(c, 3000) < 0) {
            kill(c->pid, SIGKILL);
            (void)child_reap(c, 3000);
        }
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

/* ------------------------------------------------------------------ */
/* Key and UID fixtures                                                 */
/* ------------------------------------------------------------------ */

/* One throwaway X25519 private key, with the public key DERIVED from it
 * at runtime rather than written beside it as a second literal: a
 * hardcoded pair that silently stopped matching would make every case
 * here fail with "the tunnel carried nothing", the least diagnosable
 * failure this file can produce. */
#define PRIV_B64 "SN6EG6BhjnLLpGCMqrLzZuSNmEWXOJgEnqN0uaPihgs="
#define UID_B64 "MTIzNDU2Nzg5MGFiY2RlZg==" /* "1234567890abcdef" */

static void derive_pub_b64(char *out, size_t cap) {
    uint8_t priv[CLOAK_X25519_KEY_LEN];
    size_t priv_len = 0;
    ASSERT_EQ_INT(0, cloak_base64_decode(PRIV_B64, priv, sizeof(priv), &priv_len));
    ASSERT_EQ_INT(CLOAK_X25519_KEY_LEN, (long long)priv_len);
    uint8_t base[CLOAK_X25519_KEY_LEN];
    memset(base, 0, sizeof(base));
    base[0] = 9;
    uint8_t pub[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_shared_secret(priv, base, pub));
    ASSERT_EQ_INT(0, cloak_base64_encode(pub, sizeof(pub), out, cap));
}

/* ------------------------------------------------------------------ */
/* The upstream behind the server                                       */
/* ------------------------------------------------------------------ */

/* IT XORs, IT DOES NOT ECHO. An echoing upstream would let a server pass
 * that never relayed anything and simply looped the client's own bytes
 * back at it, and a session built on the wrong key establishes cleanly
 * and then drops every frame -- so "it connected" proves nothing about
 * the data path. Only transformed bytes coming back do.
 *
 * It also re-derives the payload the client claims to have sent and
 * checks it byte by byte, so the claim "the tunnel carried exactly these
 * bytes" is made at BOTH ends of it. */
#define UP_PEND_CAP (1u << 20)

typedef struct {
    int listen_fd;
    int port;
    int conn_fd;
    uint8_t xor_mask;
    uint64_t rng;
    size_t seen;
    size_t mismatches;
    uint8_t *pend;
    size_t pend_len;
    size_t pend_off;
} upstream_t;

/* xorshift64, mirroring makePayload() in ws_interop_oracle/client.go
 * exactly: seed|1, three shifts, and the byte is bits 24..31. Written out
 * on both sides rather than shared, so the two cannot agree by accident. */
static uint8_t up_next_byte(upstream_t *u) {
    u->rng ^= u->rng << 13;
    u->rng ^= u->rng >> 7;
    u->rng ^= u->rng << 17;
    return (uint8_t)(u->rng >> 24);
}

static int up_open(upstream_t *u) {
    memset(u, 0, sizeof(*u));
    u->conn_fd = -1;
    u->listen_fd = listen_on(&u->port);
    if (u->listen_fd < 0) {
        return -1;
    }
    set_nonblock(u->listen_fd);
    u->pend = malloc(UP_PEND_CAP);
    return u->pend == NULL ? -1 : 0;
}

static void up_reset(upstream_t *u, uint8_t xor_mask, uint64_t seed) {
    if (u->conn_fd >= 0) {
        close(u->conn_fd);
        u->conn_fd = -1;
    }
    u->xor_mask = xor_mask;
    u->rng = seed | 1u;
    u->seen = 0;
    u->mismatches = 0;
    u->pend_len = 0;
    u->pend_off = 0;
}

static void up_close(upstream_t *u) {
    if (u->conn_fd >= 0) {
        close(u->conn_fd);
        u->conn_fd = -1;
    }
    if (u->listen_fd >= 0) {
        close(u->listen_fd);
        u->listen_fd = -1;
    }
    free(u->pend);
    u->pend = NULL;
}

/* One non-blocking step of the upstream: accept, read-and-transform,
 * write back what is pending. */
static void up_step(upstream_t *u, int timeout_ms) {
    struct pollfd p[2];
    int n = 0;
    int li = -1;
    int ci = -1;
    if (u->conn_fd < 0 && u->listen_fd >= 0) {
        li = n;
        p[n].fd = u->listen_fd;
        p[n].events = POLLIN;
        p[n].revents = 0;
        n++;
    }
    if (u->conn_fd >= 0) {
        ci = n;
        p[n].fd = u->conn_fd;
        p[n].events = POLLIN;
        if (u->pend_off < u->pend_len) {
            p[n].events |= POLLOUT;
        }
        p[n].revents = 0;
        n++;
    }
    if (n == 0) {
        return;
    }
    int rc = poll(p, (nfds_t)n, timeout_ms);
    if (rc <= 0) {
        return;
    }
    if (li >= 0 && (p[li].revents & POLLIN) != 0) {
        int fd = accept(u->listen_fd, NULL, NULL);
        if (fd >= 0) {
            set_nonblock(fd);
            u->conn_fd = fd;
        }
        return;
    }
    if (ci < 0) {
        return;
    }
    if ((p[ci].revents & POLLIN) != 0) {
        uint8_t buf[16384];
        ssize_t got = recv(u->conn_fd, buf, sizeof(buf), 0);
        if (got > 0) {
            for (ssize_t i = 0; i < got; i++) {
                if (buf[i] != up_next_byte(u)) {
                    u->mismatches++;
                }
                if (u->pend_len < UP_PEND_CAP) {
                    u->pend[u->pend_len++] = (uint8_t)(buf[i] ^ u->xor_mask);
                }
            }
            u->seen += (size_t)got;
        } else if (got == 0) {
            close(u->conn_fd);
            u->conn_fd = -1;
            return;
        }
    }
    if ((p[ci].revents & POLLOUT) != 0 && u->pend_off < u->pend_len) {
        ssize_t w = send(u->conn_fd, u->pend + u->pend_off, u->pend_len - u->pend_off, MSG_NOSIGNAL);
        if (w > 0) {
            u->pend_off += (size_t)w;
        }
    }
}

/* Runs a child to completion while servicing the upstream. */
static int run_child_serving_upstream(child_t *c, upstream_t *u, int budget_ms) {
    uint64_t deadline = now_ms() + (uint64_t)budget_ms;
    for (;;) {
        child_drain(c);
        int status = 0;
        pid_t rc = waitpid(c->pid, &status, WNOHANG);
        if (rc == c->pid) {
            child_drain(c);
            c->reaped = 1;
            c->status = status;
            if (c->fd >= 0) {
                close(c->fd);
                c->fd = -1;
            }
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }
        if (now_ms() >= deadline) {
            return -1;
        }
        up_step(u, 5);
    }
}

/* ------------------------------------------------------------------ */
/* The ck-server, started once and shared                               */
/* ------------------------------------------------------------------ */

/* Suite runtime is a real constraint (the ASan leg is minutes, not
 * seconds), and three of the six cases want the same server, so it is
 * started once and reused. Nothing carries state between them: the
 * upstream is reset per case, and each case opens a fresh session. */
typedef struct {
    child_t proc;
    int port;
    char pub_b64[64];
    upstream_t up;
} server_t;

static server_t g_srv;

static int server_start(server_t *s) {
    memset(s, 0, sizeof(*s));
    child_init(&s->proc);
    if (up_open(&s->up) != 0) {
        return -1;
    }
    derive_pub_b64(s->pub_b64, sizeof(s->pub_b64));

    /* BindAddr port 0: the kernel picks, and the port is read back out of
     * the server's own "listening on ... (port N)" line rather than
     * guessed by binding-and-closing first. Two fixed-port defects were
     * introduced and removed on the previous branch alone.
     *
     * BypassUID rather than a user row: nothing here is about metering,
     * and a bypassed user needs no database at all.
     * RedirAddr is loopback port 1, which nothing listens on -- no case
     * here is redirected, and a cover site that cannot be dialled makes
     * that visible rather than silently plausible. */
    char cfg[1024];
    snprintf(cfg, sizeof(cfg),
             "{\"ProxyBook\":{\"shadowsocks\":[\"tcp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\"127.0.0.1:0\"],"
             "\"BypassUID\":[\"%s\"],"
             "\"RedirAddr\":\"127.0.0.1:1\","
             "\"PrivateKey\":\"%s\","
             "\"KeepAlive\":0,\"FlowControl\":false}",
             s->up.port, UID_B64, PRIV_B64);

    char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};
    if (child_spawn(&s->proc, CK_SERVER_PATH, argv) != 0) {
        return -1;
    }
    if (child_wait_for(&s->proc, "ck-server ready", BOOT_MS) != 0) {
        return -1;
    }
    const char *at = strstr(s->proc.out, "(port ");
    if (at == NULL || sscanf(at, "(port %d)", &s->port) != 1 || s->port <= 0) {
        return -1;
    }
    return 0;
}

static void server_stop(server_t *s) {
    child_stop(&s->proc);
    up_close(&s->up);
}

/* ------------------------------------------------------------------ */
/* Case 1 and case 3: a real Go client, with and without the proxy      */
/* ------------------------------------------------------------------ */

#define EXCHANGE_BYTES 40000
#define EXCHANGE_CHUNK 4096
#define EXCHANGE_XOR 90 /* 0x5a */
#define EXCHANGE_SEED 0x9e3779b97f4a7c15ULL

/* Pulls an integer out of "name=NNN" in the child's output. Returns -1 if
 * the key is absent, which every caller asserts against: a case that
 * accepted a missing counter would pass against a client that printed
 * nothing at all. */
static long child_field(const child_t *c, const char *key) {
    const char *at = strstr(c->out, key);
    if (at == NULL) {
        return -1;
    }
    return strtol(at + strlen(key), NULL, 10);
}

static void go_exchange(int fragment) {
    up_reset(&g_srv.up, (uint8_t)EXCHANGE_XOR, EXCHANGE_SEED);

    char addr[64];
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", g_srv.port);
    char bytes[32];
    snprintf(bytes, sizeof(bytes), "%d", EXCHANGE_BYTES);
    char chunk[32];
    snprintf(chunk, sizeof(chunk), "%d", EXCHANGE_CHUNK);
    char xorv[32];
    snprintf(xorv, sizeof(xorv), "%d", EXCHANGE_XOR);
    char seed[32];
    snprintf(seed, sizeof(seed), "%llu", (unsigned long long)EXCHANGE_SEED);

    char *argv[24];
    size_t n = 0;
    argv[n++] = (char *)"ws_interop_oracle";
    argv[n++] = (char *)"client";
    argv[n++] = (char *)"-addr";
    argv[n++] = addr;
    argv[n++] = (char *)"-uid";
    argv[n++] = (char *)UID_B64;
    argv[n++] = (char *)"-pub";
    argv[n++] = g_srv.pub_b64;
    argv[n++] = (char *)"-bytes";
    argv[n++] = bytes;
    argv[n++] = (char *)"-chunk";
    argv[n++] = chunk;
    argv[n++] = (char *)"-xor";
    argv[n++] = xorv;
    argv[n++] = (char *)"-seed";
    argv[n++] = seed;
    if (fragment) {
        argv[n++] = (char *)"-fragment";
    }
    argv[n] = NULL;

    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, ORACLE_PATH, argv));
    int rc = run_child_serving_upstream(&c, &g_srv.up, CHILD_MS);
    if (rc != 0) {
        fprintf(stderr, "go client (fragment=%d) said:\n%s\n", fragment, c.out);
    }
    ASSERT_EQ_INT(0, rc);

    /* The client's own verdict, and then the same claim measured from the
     * other end of the tunnel. */
    ASSERT_TRUE(strstr(c.out, "HANDSHAKE ok") != NULL);
    ASSERT_TRUE(strstr(c.out, "EXCHANGE ok bytes=40000") != NULL);
    ASSERT_EQ_INT(EXCHANGE_BYTES, (long long)g_srv.up.seen);
    ASSERT_EQ_INT(0, (long long)g_srv.up.mismatches);

    /* MORE THAN ONE FRAME IN EACH DIRECTION, asserted here and not only
     * inside the child: a payload that fitted in one frame would make
     * this case a test of a 40000-byte memcpy. */
    ASSERT_TRUE(child_field(&c, "sent_frames=") >= 2);
    ASSERT_TRUE(child_field(&c, "recv_frames=") >= 2);

    if (fragment) {
        /* The proxy really did re-frame, and really did interleave a
         * ping. Without this the case would pass against a proxy that
         * quietly forwarded bytes unchanged -- which is precisely the
         * shape of test that this whole file exists to avoid. */
        long frames_out = child_field(&c, "frames_out=");
        long pings = child_field(&c, "pings=");
        long sent = child_field(&c, "sent_frames=");
        ASSERT_TRUE(sent > 0);
        ASSERT_TRUE(frames_out >= 2 * sent);
        ASSERT_TRUE(pings >= sent);
    }
    child_stop(&c);
}

static void test_a_real_go_client_completes_a_session(void) { go_exchange(0); }

static void test_a_fragmenting_proxy_does_not_break_the_session(void) { go_exchange(1); }

/* ------------------------------------------------------------------ */
/* Case 4: pong on ping                                                 */
/* ------------------------------------------------------------------ */

static void test_the_server_pongs_a_gorilla_ping(void) {
    up_reset(&g_srv.up, (uint8_t)EXCHANGE_XOR, EXCHANGE_SEED);

    char addr[64];
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", g_srv.port);
    char *const argv[] = {(char *)"ws_interop_oracle",
                          (char *)"client",
                          (char *)"-addr",
                          addr,
                          (char *)"-uid",
                          (char *)UID_B64,
                          (char *)"-pub",
                          g_srv.pub_b64,
                          (char *)"-ping",
                          NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, ORACLE_PATH, argv));
    int rc = run_child_serving_upstream(&c, &g_srv.up, CHILD_MS);
    if (rc != 0) {
        fprintf(stderr, "go ping client said:\n%s\n", c.out);
    }
    ASSERT_EQ_INT(0, rc);
    ASSERT_TRUE(strstr(c.out, "PONG ok") != NULL);
    /* The payload length is the client's own assertion; what this end can
     * add is that the pong carried the full 24 bytes rather than an empty
     * frame the handler would also have accepted as "a pong". */
    ASSERT_EQ_INT(24, child_field(&c, "bytes="));

    /* And nothing was proxied: a ping must not open a stream. If it did,
     * the upstream would have been dialled. */
    ASSERT_EQ_INT(0, (long long)g_srv.up.seen);
    ASSERT_EQ_INT(-1, g_srv.up.conn_fd);
    child_stop(&c);
}

/* ------------------------------------------------------------------ */
/* Case 2: gorilla as a decoder, both directions                        */
/* ------------------------------------------------------------------ */

/* The sizes span RFC 6455 section 5.2's two length forms: 125 is the last
 * 7-bit length and 126 is the first that needs the 16-bit extension, and
 * 16000 is a frame no single buffered read on the far side can satisfy. */
static const int ORACLE_SIZES[] = {1, 125, 126, 16000};
#define ORACLE_SIZES_N ((int)(sizeof(ORACLE_SIZES) / sizeof(ORACLE_SIZES[0])))
#define ORACLE_SIZES_STR "1,125,126,16000"

/* Mirrors oraclePayload() in ws_interop_oracle/decode.go. Index-dependent
 * in both the offset and the message number, so a reassembly that
 * dropped, duplicated or reordered a fragment fails on content and not
 * merely on length. */
static void oracle_payload(int msg, int n, uint8_t *out) {
    for (int i = 0; i < n; i++) {
        out[i] = (uint8_t)(i * 5 + 1 + msg * 97);
    }
}

typedef struct {
    child_t *c;
} child_ctx_t;

static int child_exited(void *ctx) {
    child_ctx_t *cc = ctx;
    child_drain(cc->c);
    int status = 0;
    pid_t rc = waitpid(cc->c->pid, &status, WNOHANG);
    if (rc == cc->c->pid) {
        child_drain(cc->c);
        cc->c->reaped = 1;
        cc->c->status = status;
        return 1;
    }
    return 0;
}

/* Puts the C connection layer -- the production writer, in the requested
 * framing mode -- onto a live socket a gorilla peer is reading, sends one
 * message per size, and pumps until the child has said what it thinks.
 *
 * The switchboard is what a session uses, so these are the bytes a real
 * session emits and not a test's imitation of them. */
static void sb_on_envelope(cloak_switchboard_t *sb, const uint8_t *bytes, size_t len,
                           void *userdata) {
    (void)sb;
    (void)bytes;
    (void)len;
    (void)userdata;
}

static void sb_on_broken(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    (void)userdata;
}

static void feed_gorilla(int fd, cloak_conn_framing_t framing, child_t *c, int nmsgs) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(0,
                  cloak_switchboard_init(&sb, r, 16401, 262144, sb_on_envelope, NULL, sb_on_broken, NULL));
    ASSERT_EQ_INT(0, cloak_switchboard_add_conn_framed(&sb, fd, framing));

    uint8_t *buf = malloc(16000);
    ASSERT_TRUE(buf != NULL);
    if (buf != NULL) {
        for (int i = 0; i < nmsgs && i < ORACLE_SIZES_N; i++) {
            oracle_payload(i, ORACLE_SIZES[i], buf);
            ASSERT_EQ_INT(0, cloak_switchboard_send(&sb, buf, (size_t)ORACLE_SIZES[i]));
            /* Drains whatever the kernel would not take at once; a
             * 16000-byte frame does not always fit in one write. */
            cloak_reactor_run_once(r, 0);
        }
        free(buf);
    }

    child_ctx_t cc = {c};
    ASSERT_TRUE(pump_until(r, child_exited, &cc, CHILD_MS, 5));

    /* The switchboard owns fd from here (cloak_switchboard_close_all
     * closes it), so it must not be closed again by the caller. */
    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
}

/* A 96-byte `Hidden` value that is well formed and means nothing. The
 * gorilla legs never authenticate -- they are decoders, not clients --
 * but cloak_ws_handshake_parse refuses a request without one, and it is
 * cloak_ws_handshake_parse that must produce the accept for the leg where
 * this file plays the server. */
static void make_dummy_hidden(char *out, size_t cap) {
    uint8_t hidden[CLOAK_WS_HS_HIDDEN_LEN];
    cloak_random_bytes(hidden, sizeof(hidden));
    ASSERT_EQ_INT(0, cloak_base64_encode(hidden, sizeof(hidden), out, cap));
}

/* gorilla on the CLIENT side of the upgrade: it validates the 101 this
 * file composes with the production composer, and then its advanceFrame
 * is the judge of every frame the C conn layer produced. */
static void gorilla_client_decodes(cloak_conn_framing_t framing, const char *expect) {
    int port = 0;
    int ln = listen_on(&port);
    ASSERT_TRUE(ln >= 0);
    if (ln < 0) {
        return;
    }

    char hidden[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
    make_dummy_hidden(hidden, sizeof(hidden));
    char addr[64];
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
    /* The negative control only needs one frame to be refused, and
     * pushing more after gorilla has hung up would only race. */
    const char *sizes = (strcmp(expect, "ok") == 0) ? ORACLE_SIZES_STR : "1";
    int nmsgs = (strcmp(expect, "ok") == 0) ? ORACLE_SIZES_N : 1;

    char *const argv[] = {(char *)"ws_interop_oracle",
                          (char *)"decode",
                          (char *)"-addr",
                          addr,
                          (char *)"-expect",
                          (char *)expect,
                          (char *)"-sizes",
                          (char *)sizes,
                          (char *)"-hidden",
                          hidden,
                          NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, ORACLE_PATH, argv));

    int fd = accept_within(ln, BOOT_MS);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        child_stop(&c);
        close(ln);
        return;
    }

    char req[8192];
    ssize_t req_len = read_until(fd, req, sizeof(req), "\r\n\r\n", BOOT_MS);
    ASSERT_TRUE(req_len > 0);

    /* THE PRODUCTION PARSER, over a request a real gorilla client
     * composed. A parser that only ever saw requests this tree built
     * would be agreeing with itself. */
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, cloak_ws_handshake_parse((const uint8_t *)req, (size_t)req_len, &hs));

    uint8_t resp[CLOAK_WS_HS_101_LEN];
    ssize_t rn = cloak_ws_handshake_compose_101(resp, sizeof(resp), hs.accept);
    ASSERT_EQ_INT(CLOAK_WS_HS_101_LEN, (long long)rn);
    ASSERT_EQ_INT((long long)rn, (long long)send(fd, resp, (size_t)rn, MSG_NOSIGNAL));

    feed_gorilla(fd, framing, &c, nmsgs);

    int rc = child_reap(&c, CHILD_MS);
    if (rc != 0) {
        fprintf(stderr, "gorilla client decoder (%s) said:\n%s\n", expect, c.out);
    }
    ASSERT_EQ_INT(0, rc);
    ASSERT_TRUE(strstr(c.out, "UPGRADE ok") != NULL);
    if (strcmp(expect, "ok") == 0) {
        ASSERT_TRUE(strstr(c.out, "MSG 3 len=16000 ok") != NULL);
        ASSERT_TRUE(strstr(c.out, "DECODE ok side=client") != NULL);
    } else {
        ASSERT_TRUE(strstr(c.out, "bad MASK") != NULL);
    }
    child_stop(&c);
    close(ln);
}

/* gorilla on the SERVER side, for the mirror-image control -- and for the
 * accept, which a real Upgrader computes here over a key this file chose. */
static void gorilla_server_decodes(cloak_conn_framing_t framing, const char *expect) {
    const char *sizes = (strcmp(expect, "ok") == 0) ? ORACLE_SIZES_STR : "1";
    int nmsgs = (strcmp(expect, "ok") == 0) ? ORACLE_SIZES_N : 1;
    char *const argv[] = {(char *)"ws_interop_oracle", (char *)"serve", (char *)"-expect",
                          (char *)expect,             (char *)"-sizes", (char *)sizes,
                          NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, ORACLE_PATH, argv));
    ASSERT_EQ_INT(0, child_wait_for(&c, "PORT ", BOOT_MS));
    int port = (int)child_field(&c, "PORT ");
    ASSERT_TRUE(port > 0);
    if (port <= 0) {
        child_stop(&c);
        return;
    }

    int fd = connect_to(port);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        child_stop(&c);
        return;
    }

    char hidden[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
    make_dummy_hidden(hidden, sizeof(hidden));
    char req[4096];
    int req_len = snprintf(req, sizeof(req),
                           "GET /ws/path HTTP/1.1\r\n"
                           "Host: 127.0.0.1:%d\r\n"
                           "Connection: Upgrade\r\n"
                           "Hidden: %s\r\n"
                           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                           "Sec-WebSocket-Version: 13\r\n"
                           "Upgrade: websocket\r\n"
                           "\r\n",
                           port, hidden);
    ASSERT_TRUE(req_len > 0 && req_len < (int)sizeof(req));
    ASSERT_EQ_INT(req_len, (long long)send(fd, req, (size_t)req_len, MSG_NOSIGNAL));

    char resp[2048];
    ssize_t resp_len = read_until(fd, resp, sizeof(resp), "\r\n\r\n", BOOT_MS);
    ASSERT_TRUE(resp_len > 0);
    ASSERT_TRUE(strstr(resp, "HTTP/1.1 101 Switching Protocols") == resp);

    /* THE ACCEPT, CHECKED AGAINST AN IMPLEMENTATION THAT IS NOT OURS.
     * gorilla's Upgrader computed the value in `resp`; the production
     * parser computed hs.accept from the same request. RFC 6455 section
     * 1.3's own vector is the key above, so this line also pins the
     * published answer -- but the point of doing it here is that a real
     * WebSocket server independently agrees. */
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, cloak_ws_handshake_parse((const uint8_t *)req, (size_t)req_len, &hs));
    ASSERT_EQ_INT(0, strcmp(hs.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    char want[128];
    snprintf(want, sizeof(want), "Sec-WebSocket-Accept: %s\r\n", hs.accept);
    if (strstr(resp, want) == NULL) {
        fprintf(stderr, "gorilla answered:\n%s\nwe computed: %s\n", resp, hs.accept);
    }
    ASSERT_TRUE(strstr(resp, want) != NULL);

    feed_gorilla(fd, framing, &c, nmsgs);

    int rc = child_reap(&c, CHILD_MS);
    if (rc != 0) {
        fprintf(stderr, "gorilla server decoder (%s) said:\n%s\n", expect, c.out);
    }
    ASSERT_EQ_INT(0, rc);
    if (strcmp(expect, "ok") == 0) {
        ASSERT_TRUE(strstr(c.out, "MSG 3 len=16000 ok") != NULL);
        ASSERT_TRUE(strstr(c.out, "DECODE ok side=server") != NULL);
    } else {
        ASSERT_TRUE(strstr(c.out, "bad MASK") != NULL);
    }
    child_stop(&c);
}

static void test_gorilla_decodes_our_frames(void) {
    /* THE POSITIVE RESULTS. A server's frames are never masked and a
     * client's always are, so each is fed to the gorilla peer that is
     * entitled to receive it. */
    gorilla_client_decodes(CLOAK_CONN_FRAMING_WS_SERVER, "ok");
    gorilla_server_decodes(CLOAK_CONN_FRAMING_WS_CLIENT, "ok");

    /* THE NEGATIVE CONTROLS, and they are not optional. Both feed the
     * SAME frames to the WRONG side, which is the one thing RFC 6455
     * section 5.1 makes non-negotiable, and gorilla must refuse each. If
     * these two did not fail, the two above would not be evidence that
     * gorilla was reading anything at all. */
    gorilla_client_decodes(CLOAK_CONN_FRAMING_WS_CLIENT, "badmask");
    gorilla_server_decodes(CLOAK_CONN_FRAMING_WS_SERVER, "badmask");
}

/* ------------------------------------------------------------------ */
/* A frame the Go original actually emitted                             */
/* ------------------------------------------------------------------ */

/* A STATIC CROSS-IMPLEMENTATION VECTOR, so the interoperability of the
 * mux frame format is pinned even where no Go toolchain runs.
 *
 * These 47 bytes were produced by cbeuw/Cloak's own
 * (*Obfuscator).obfuscate -- the copy in ws_interop_oracle, which is that
 * file verbatim -- with session key k[i] = i*3, stream 1, seq 10 (>= 5,
 * so no random padding and the output is deterministic), closing 0 and
 * the payload below, under aes-gcm.
 *
 * It exists because of what case 1 found. cloak_frame_obfuscate used to
 * pass header bytes 12-13 to AES-GCM as associated data; Go passes none,
 * AES-GCM's tag covers the AAD, and so NOT ONE frame could cross between
 * the two implementations -- for five modules, invisibly, because every
 * test of it had our code on both ends. libcloak-mux/tests/test_frame.c's
 * closing-byte case says the rest. This vector is the part of that fix
 * that does not need a Go process to defend itself. */
static const char GO_FRAME_HEX[] =
    "3b102b8f4e30767cf2e1118368ebfd8ffc46f418f57e2f4b5bf7e3c84f77627a"
    "bcb7f3747ac8bb3ca00df34f9fe01a";
static const char GO_FRAME_PAYLOAD[] = "hello-cloak-frame";

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static void test_a_go_produced_frame_deobfuscates_byte_for_byte(void) {
    size_t hex_len = strlen(GO_FRAME_HEX);
    ASSERT_EQ_INT(0, (long long)(hex_len % 2));
    size_t n = hex_len / 2;
    uint8_t buf[128];
    ASSERT_TRUE(n <= sizeof(buf));
    if (n > sizeof(buf)) {
        return;
    }
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(GO_FRAME_HEX[2 * i]);
        int lo = hex_nibble(GO_FRAME_HEX[2 * i + 1]);
        ASSERT_TRUE(hi >= 0 && lo >= 0);
        buf[i] = (uint8_t)(hi * 16 + lo);
    }

    cloak_obfuscator_t o;
    o.method = CLOAK_AEAD_AES_256_GCM;
    for (int i = 0; i < CLOAK_AEAD_KEY_LEN; i++) {
        o.session_key[i] = (uint8_t)(i * 3);
    }

    cloak_frame_t f;
    memset(&f, 0, sizeof(f));
    int rc = cloak_frame_deobfuscate(&o, &f, buf, n);
    ASSERT_EQ_INT(0, rc);
    /* THE GUARD IS NOT DEFENSIVE TIDINESS; IT IS WHAT KEEPS THE REST OF
     * THIS FILE RUNNING UNDER THE ONE DEFECT IT EXISTS TO CATCH.
     *
     * cloak_frame_deobfuscate's contract leaves *out untouched on failure,
     * so f.payload is still the NULL this function memset it to, and
     * ASSERT_MEM_EQ below is a memcmp(NULL, ...). That is a SEGFAULT, and
     * a segfault ends the process: cases 5 and 6 are called after this one
     * in TEST_MAIN and would never run at all. Measured, with the AAD
     * regression (mutation M9/M15) applied: ctest reported SEGFAULT and
     * the last assertion printed was the payload_len one below -- a third
     * of this file silently stopped executing in exactly the scenario it
     * was written for.
     *
     * A crash that swallows later assertions is the same shape as a
     * timeout that swallows them, which this project has ruled against
     * twice. With the guard, the same regression reports six named
     * assertions across three cases and still runs the other two. */
    if (rc != 0) {
        return;
    }
    ASSERT_EQ_INT(1, (long long)f.stream_id);
    ASSERT_EQ_INT(10, (long long)f.seq);
    ASSERT_EQ_INT(CLOAK_FRAME_CLOSING_NOTHING, f.closing);
    ASSERT_EQ_INT((long long)strlen(GO_FRAME_PAYLOAD), (long long)f.payload_len);
    ASSERT_TRUE(f.payload != NULL);
    if (f.payload != NULL && f.payload_len == strlen(GO_FRAME_PAYLOAD)) {
        ASSERT_MEM_EQ(f.payload, GO_FRAME_PAYLOAD, strlen(GO_FRAME_PAYLOAD));
    }
}

/* ------------------------------------------------------------------ */
/* The in-process fixture, for the two cases with no outside oracle     */
/* ------------------------------------------------------------------ */

struct fixture {
    cloak_reactor_t *reactor;

    char db_path[512];
    cloak_usermanager_t *mgr;

    cloak_server_config_t cfg;
    cloak_server_t srv;
    int srv_ready;

    cloak_server_registry_t registry;
    int registry_ready;

    cloak_userpanel_t *panel;

    cloak_proxy_t proxy;
    int proxy_ready;

    cloak_dispatcher_t d;
    int d_ready;

    cloak_listener_t front;
    int have_front;

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid[CLOAK_UID_LEN];

    /* THE POINT OF THE WHOLE FIXTURE: the server's own end of the socket,
     * captured on the way past so ioctl(FIONREAD) can be asked what the
     * kernel still holds for it. A listener whose callback IS
     * cloak_dispatcher_accept never reveals this. */
    int last_server_fd;
};

static void fx_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    struct fixture *fx = userdata;
    fx->last_server_fd = fd;
    cloak_dispatcher_accept(l, fd, &fx->d);
}

static void fx_session_closing(const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                               void *userdata) {
    cloak_proxy_session_aborted(NULL, uid, session_id, userdata);
}

static int64_t db_now(void *userdata) {
    (void)userdata;
    return (int64_t)time(NULL);
}

static void tmp_path(char *buf, size_t cap, const char *tag) {
    snprintf(buf, cap, "/tmp/cloak_%s_%d_%ld.db", tag, (int)getpid(), (long)time(NULL));
}

static void db_unlink(const char *path) {
    char extra[600];
    unlink(path);
    snprintf(extra, sizeof(extra), "%s-wal", path);
    unlink(extra);
    snprintf(extra, sizeof(extra), "%s-shm", path);
    unlink(extra);
    snprintf(extra, sizeof(extra), "%s-journal", path);
    unlink(extra);
}

static int fixture_init(struct fixture *fx) {
    memset(fx, 0, sizeof(*fx));
    fx->last_server_fd = -1;
    char err[256] = {0};

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(fx->server_priv, fx->server_pub));
    memset(fx->uid, 0x33, sizeof(fx->uid));
    char uid_b64[64];
    ASSERT_EQ_INT(0, cloak_base64_encode(fx->uid, sizeof(fx->uid), uid_b64, sizeof(uid_b64)));
    char priv_b64[64];
    ASSERT_EQ_INT(0, cloak_base64_encode(fx->server_priv, CLOAK_X25519_KEY_LEN, priv_b64,
                                         sizeof(priv_b64)));

    /* Nothing here proxies or redirects: both addresses are loopback port
     * 1, which nothing listens on, so a case that accidentally started
     * relaying would fail rather than quietly succeed somewhere else. */
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"shadowsocks\":[\"tcp\",\"127.0.0.1:1\"]},"
             "\"BindAddr\":[\"127.0.0.1:0\"],\"RedirAddr\":\"127.0.0.1:1\","
             "\"BypassUID\":[\"%s\"],\"PrivateKey\":\"%s\"}",
             uid_b64, priv_b64);
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    tmp_path(fx->db_path, sizeof(fx->db_path), "wsinterop");
    db_unlink(fx->db_path);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_usermanager_open(&fx->mgr, fx->db_path, db_now, NULL, err, sizeof(err)));
    ASSERT_TRUE(fx->mgr != NULL);
    if (fx->mgr == NULL) {
        return -1;
    }

    ASSERT_EQ_INT(0, cloak_server_registry_init(&fx->registry, fx->reactor,
                                                cloak_proxy_registry_broken, &fx->proxy));
    fx->registry_ready = 1;

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = fx->mgr;
    pcfg.registry = &fx->registry;
    pcfg.reactor = fx->reactor;
    pcfg.upload_interval_ms = 3600000;
    pcfg.now_fn = db_now;
    pcfg.on_session_closing = fx_session_closing;
    pcfg.on_session_closing_userdata = &fx->proxy;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&fx->panel, &pcfg));
    ASSERT_TRUE(fx->panel != NULL);
    if (fx->panel == NULL) {
        return -1;
    }

    cloak_proxy_config_t pxcfg;
    memset(&pxcfg, 0, sizeof(pxcfg));
    pxcfg.reactor = fx->reactor;
    pxcfg.srv = &fx->srv;
    pxcfg.chain = cloak_userpanel_registry_broken;
    pxcfg.chain_userdata = fx->panel;
    ASSERT_EQ_INT(0, cloak_proxy_init(&fx->proxy, &pxcfg));
    fx->proxy_ready = 1;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.registry = &fx->registry;
    dcfg.panel = fx->panel;
    dcfg.session_config_template.max_on_wire_size = 16401;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = 262144;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;
    dcfg.prepare_session = cloak_proxy_prepare_session;
    dcfg.prepare_session_userdata = &fx->proxy;
    dcfg.session_aborted = cloak_proxy_session_aborted;
    dcfg.session_aborted_userdata = &fx->proxy;
    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, fx->cfg.bind_addr[0], fx_on_accept,
                                         fx, err, sizeof(err)));
    fx->have_front = 1;
    return 0;
}

static void fixture_destroy(struct fixture *fx) {
    if (fx->have_front) {
        cloak_listener_close(&fx->front);
        fx->have_front = 0;
    }
    if (fx->d_ready) {
        cloak_dispatcher_destroy(&fx->d);
        fx->d_ready = 0;
    }
    if (fx->proxy_ready) {
        cloak_proxy_destroy(&fx->proxy);
        fx->proxy_ready = 0;
    }
    if (fx->panel != NULL) {
        cloak_userpanel_close(fx->panel);
        fx->panel = NULL;
    }
    if (fx->registry_ready) {
        cloak_server_registry_destroy(&fx->registry);
        fx->registry_ready = 0;
    }
    if (fx->mgr != NULL) {
        cloak_usermanager_close(fx->mgr);
        fx->mgr = NULL;
    }
    if (fx->srv_ready) {
        cloak_server_destroy(&fx->srv);
        fx->srv_ready = 0;
    }
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
        fx->reactor = NULL;
    }
    db_unlink(fx->db_path);
}

static int front_port(struct fixture *fx) { return cloak_listener_port(&fx->front); }

/* ------------------------------------------------------------------ */
/* Building a real CDN upgrade request                                  */
/* ------------------------------------------------------------------ */

/* The 48-byte decrypted-payload layout cloak/server_auth.h documents byte
 * for byte. */
static void build_auth_payload(uint8_t out[48], const uint8_t uid[CLOAK_UID_LEN],
                               const char *proxy_method, uint8_t encryption_method,
                               int64_t timestamp, uint32_t session_id) {
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
}

static void make_hidden(const uint8_t server_pub[CLOAK_X25519_KEY_LEN],
                        const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                        char out_b64[CLOAK_WS_HS_HIDDEN_B64_LEN + 1],
                        uint8_t out_shared[CLOAK_AEAD_KEY_LEN]) {
    uint8_t eph_priv[CLOAK_X25519_KEY_LEN];
    uint8_t eph_pub[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(eph_priv, eph_pub));
    ASSERT_EQ_INT(0, cloak_x25519_shared_secret(eph_priv, server_pub, out_shared));

    uint8_t payload[48];
    build_auth_payload(payload, uid, "shadowsocks", (uint8_t)CLOAK_AEAD_AES_256_GCM,
                       (int64_t)time(NULL), session_id);

    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    memcpy(nonce, eph_pub, CLOAK_AEAD_NONCE_LEN);

    uint8_t hidden[CLOAK_WS_HS_HIDDEN_LEN];
    memcpy(hidden, eph_pub, 32);
    size_t ct_len = 0;
    ASSERT_EQ_INT(0, cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, out_shared, nonce, NULL, 0, payload,
                                     sizeof(payload), hidden + 32, &ct_len));
    ASSERT_EQ_INT(64, (long long)ct_len);
    ASSERT_EQ_INT(0, cloak_base64_encode(hidden, sizeof(hidden), out_b64,
                                         CLOAK_WS_HS_HIDDEN_B64_LEN + 1));
}

/* KEY_GO is the Sec-WebSocket-Key a real gorilla client emitted, and
 * ACCEPT_GO is what a real gorilla Upgrader answered with. Captured
 * literals, never recomputed here. */
#define KEY_GO "Q6fJUvdRNbjAgU3LVM25sg=="
#define ACCEPT_GO "fmxopr2FgzOlKg8nTOunDaBh4TU="

static size_t build_ws_request(char *buf, size_t cap, const char *hidden) {
    int n = snprintf(buf, cap,
                     "GET /ws/path HTTP/1.1\r\n"
                     "Host: cdn.example.com:443\r\n"
                     "User-Agent: Go-http-client/1.1\r\n"
                     "Connection: Upgrade\r\n"
                     "Hidden: %s\r\n"
                     "Sec-WebSocket-Key: " KEY_GO "\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "Upgrade: websocket\r\n"
                     "\r\n",
                     hidden);
    ASSERT_TRUE(n > 0 && (size_t)n < cap);
    return (size_t)(n > 0 ? n : 0);
}

/* The whole CDN reply: a fixed-length 101 plus a two-byte unmasked binary
 * frame header plus 60 bytes of payload. */
#define WS_REPLY_TOTAL (CLOAK_WS_HS_101_LEN + 2 + 60)

typedef struct {
    int fd;
    uint8_t buf[512];
    size_t len;
    size_t want;
} reader_t;

static int reader_has(void *ctx) {
    reader_t *rd = ctx;
    if (rd->len >= rd->want) {
        return 1;
    }
    ssize_t n = recv(rd->fd, rd->buf + rd->len, sizeof(rd->buf) - rd->len, MSG_DONTWAIT);
    if (n > 0) {
        rd->len += (size_t)n;
    }
    return rd->len >= rd->want;
}

static int ws_reply_session_key(const uint8_t *reply, const uint8_t shared[CLOAK_AEAD_KEY_LEN],
                                uint8_t out_key[CLOAK_AEAD_KEY_LEN]) {
    const uint8_t *payload = reply + CLOAK_WS_HS_101_LEN + 2;
    uint8_t out[CLOAK_AEAD_KEY_LEN];
    size_t out_len = 0;
    if (cloak_aead_open(CLOAK_AEAD_AES_256_GCM, shared, payload, NULL, 0, payload + 12, 48, out,
                        &out_len) != 0) {
        return -1;
    }
    if (out_len != CLOAK_AEAD_KEY_LEN) {
        return -1;
    }
    memcpy(out_key, out, CLOAK_AEAD_KEY_LEN);
    return 0;
}

/* Waits (bounded by the clock) until the kernel holds nothing more for
 * the server's end of the socket -- i.e. until the server has actually
 * consumed everything written so far. This is what makes a split point a
 * split point rather than a single write that happened to be issued in
 * two calls. */
typedef struct {
    int fd;
} fionread_ctx_t;

static int fionread_of(int fd) {
    int n = 0;
    if (ioctl(fd, FIONREAD, &n) != 0) {
        return -1;
    }
    return n;
}

static int fionread_is_zero(void *ctx) {
    fionread_ctx_t *c = ctx;
    return fionread_of(c->fd) == 0;
}

typedef struct {
    struct fixture *fx;
} accepted_ctx_t;

static int server_fd_captured(void *ctx) {
    accepted_ctx_t *a = ctx;
    return a->fx->last_server_fd >= 0;
}

/* ------------------------------------------------------------------ */
/* Case 5: not one byte past the request                                */
/* ------------------------------------------------------------------ */

/* cloak_firstpacket_t's whole reason to exist is that it never consumes a
 * byte past the first packet: after the handshake the descriptor is handed
 * to a cloak_conn_t that reads from wherever the kernel left off, so a
 * byte read past the request is a byte the session never sees, and the
 * session desynchronises on frame one. Every previous test of this could
 * only observe the CONSEQUENCE (a session that works), which a
 * sufficiently lucky over-read does not always break. This one observes
 * the kernel's own count. */
#define TRAILER_LEN 7

static void test_the_handshake_reads_no_byte_past_the_request(void) {
    struct fixture fx;
    if (fixture_init(&fx) != 0) {
        fixture_destroy(&fx);
        return;
    }

    char hidden[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    make_hidden(fx.server_pub, fx.uid, 1, hidden, shared);

    char req[4096];
    size_t req_len = build_ws_request(req, sizeof(req), hidden);

    /* ONE write carrying the request AND seven bytes that belong to the
     * session after it. This is the shape a real client produces when it
     * pipelines, and it is the only shape in which an over-read is
     * observable at all: bytes written later cannot be over-read. */
    uint8_t wire[4200];
    ASSERT_TRUE(req_len + TRAILER_LEN <= sizeof(wire));
    memcpy(wire, req, req_len);
    memset(wire + req_len, 0xAB, TRAILER_LEN);

    int fd = connect_to(front_port(&fx));
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT((long long)(req_len + TRAILER_LEN),
                  (long long)write(fd, wire, req_len + TRAILER_LEN));

    reader_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.fd = fd;
    rd.want = WS_REPLY_TOTAL;
    ASSERT_TRUE(pump_until(fx.reactor, reader_has, &rd, PUMP_MS, 1));
    ASSERT_EQ_INT(WS_REPLY_TOTAL, (long long)rd.len);

    /* Measured the instant the reply is complete, which is the same
     * reactor turn the hand-off happened in: the conn that now owns this
     * descriptor has not had an event dispatched to it yet. Seven, not
     * six, and not zero. */
    ASSERT_TRUE(fx.last_server_fd >= 0);
    ASSERT_EQ_INT(TRAILER_LEN, fionread_of(fx.last_server_fd));

    /* And the reply itself is the flat CDN shape, so this case cannot
     * pass against a server that answered something else entirely. */
    ASSERT_EQ_INT(0x82, rd.buf[CLOAK_WS_HS_101_LEN]);
    ASSERT_EQ_INT(0x3C, rd.buf[CLOAK_WS_HS_101_LEN + 1]);
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    ASSERT_EQ_INT(0, ws_reply_session_key(rd.buf, shared, key));

    close(fd);
    /* Let the teardown the close provokes run before the fixture goes. */
    uint64_t t0 = now_ms();
    while (now_ms() - t0 < 50) {
        cloak_reactor_run_once(fx.reactor, 5);
    }
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* Case 6: every split point                                            */
/* ------------------------------------------------------------------ */

static void test_the_handshake_resumes_at_every_split_point(void) {
    struct fixture fx;
    if (fixture_init(&fx) != 0) {
        fixture_destroy(&fx);
        return;
    }

    /* The reference run, unsplit, whose 101 every split must reproduce
     * byte for byte. */
    uint8_t ref_101[CLOAK_WS_HS_101_LEN];
    int have_ref = 0;

    /* Every session key seen, so "no two attempts agree" can be asserted:
     * a server that had hardcoded a key -- the exact defect an
     * independent reviewer found live on the previous branch -- passes
     * every other assertion in this function. */
    size_t keys_cap = 0;
    uint8_t(*keys)[CLOAK_AEAD_KEY_LEN] = NULL;
    size_t keys_len = 0;

    char probe_hidden[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
    uint8_t probe_shared[CLOAK_AEAD_KEY_LEN];
    make_hidden(fx.server_pub, fx.uid, 1, probe_hidden, probe_shared);
    char probe[4096];
    size_t req_len = build_ws_request(probe, sizeof(probe), probe_hidden);
    ASSERT_TRUE(req_len > 300);

    keys_cap = req_len + 1;
    keys = malloc(keys_cap * CLOAK_AEAD_KEY_LEN);
    ASSERT_TRUE(keys != NULL);
    if (keys == NULL) {
        fixture_destroy(&fx);
        return;
    }

    int failures_at_start = cloak_test_failures;
    for (size_t split = 1; split <= req_len; split++) {
        char hidden[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
        uint8_t shared[CLOAK_AEAD_KEY_LEN];
        /* A FRESH EPHEMERAL KEY EVERY TIME, because the replay cache
         * refuses a repeated one -- which is also why the brief's "assert
         * the same session key each time" is not achievable here. */
        make_hidden(fx.server_pub, fx.uid, (uint32_t)split, hidden, shared);
        char req[4096];
        size_t len = build_ws_request(req, sizeof(req), hidden);
        ASSERT_EQ_INT((long long)req_len, (long long)len);

        fx.last_server_fd = -1;
        int fd = connect_to(front_port(&fx));
        ASSERT_TRUE(fd >= 0);
        if (fd < 0) {
            break;
        }

        accepted_ctx_t ac = {&fx};
        if (!pump_until(fx.reactor, server_fd_captured, &ac, PUMP_MS, 1)) {
            ASSERT_TRUE(0);
            close(fd);
            break;
        }

        ASSERT_EQ_INT((long long)split, (long long)write(fd, req, split));
        /* The split is only real if the server has consumed the prefix
         * and gone back to waiting. Asking the kernel is exact; a sleep
         * would be a guess. */
        fionread_ctx_t fc = {fx.last_server_fd};
        if (!pump_until(fx.reactor, fionread_is_zero, &fc, PUMP_MS, 1)) {
            ASSERT_TRUE(0);
            close(fd);
            break;
        }
        if (split < req_len) {
            ASSERT_EQ_INT((long long)(req_len - split),
                          (long long)write(fd, req + split, req_len - split));
        }

        reader_t rd;
        memset(&rd, 0, sizeof(rd));
        rd.fd = fd;
        rd.want = WS_REPLY_TOTAL;
        if (!pump_until(fx.reactor, reader_has, &rd, PUMP_MS, 1)) {
            fprintf(stderr, "split %zu of %zu: only %zu reply bytes\n", split, req_len, rd.len);
            ASSERT_TRUE(0);
            close(fd);
            break;
        }

        /* The 101 is byte-identical across every split: the accept is a
         * pure function of a header value that never changes here, so any
         * difference is the parser having read a different request. */
        if (!have_ref) {
            memcpy(ref_101, rd.buf, CLOAK_WS_HS_101_LEN);
            have_ref = 1;
            ASSERT_TRUE(mem_find(ref_101, CLOAK_WS_HS_101_LEN, ACCEPT_GO, strlen(ACCEPT_GO)) != NULL);
        }
        ASSERT_MEM_EQ(rd.buf, ref_101, CLOAK_WS_HS_101_LEN);
        ASSERT_EQ_INT(0x82, rd.buf[CLOAK_WS_HS_101_LEN]);
        ASSERT_EQ_INT(0x3C, rd.buf[CLOAK_WS_HS_101_LEN + 1]);

        /* And the reply decrypts under THIS attempt's shared secret,
         * which is the whole of what the handshake had to get right from
         * a stream broken at this offset. */
        if (ws_reply_session_key(rd.buf, shared, keys[keys_len]) != 0) {
            fprintf(stderr, "split %zu of %zu: reply did not decrypt\n", split, req_len);
            ASSERT_TRUE(0);
            close(fd);
            break;
        }
        keys_len++;

        close(fd);
        uint64_t t0 = now_ms();
        while (now_ms() - t0 < 2) {
            cloak_reactor_run_once(fx.reactor, 0);
        }

        /* One loud failure is a diagnosis; three hundred is a wall of
         * text with the first one scrolled off. */
        if (cloak_test_failures != failures_at_start) {
            fprintf(stderr, "first failure was at split %zu of %zu\n", split, req_len);
            break;
        }
    }

    ASSERT_EQ_INT((long long)req_len, (long long)keys_len);
    for (size_t i = 0; i + 1 < keys_len; i++) {
        ASSERT_MEM_NE(keys[i], keys[i + 1], CLOAK_AEAD_KEY_LEN);
    }
    free(keys);

    uint64_t t0 = now_ms();
    while (now_ms() - t0 < 50) {
        cloak_reactor_run_once(fx.reactor, 5);
    }
    fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */

TEST_MAIN_BEGIN()
ASSERT_EQ_INT(0, server_start(&g_srv));
test_a_real_go_client_completes_a_session();
test_a_fragmenting_proxy_does_not_break_the_session();
test_the_server_pongs_a_gorilla_ping();
server_stop(&g_srv);
test_gorilla_decodes_our_frames();
test_a_go_produced_frame_deobfuscates_byte_for_byte();
test_the_handshake_reads_no_byte_past_the_request();
test_the_handshake_resumes_at_every_split_point();
TEST_MAIN_END()
