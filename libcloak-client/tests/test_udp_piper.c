#define _POSIX_C_SOURCE 200809L

/* THE CLIENT'S UDP LOCAL LISTENER: one datagram socket, many peers.
 *
 * The far end here is a second real cloak_session_t wired to the piper's
 * over a socketpair -- the harness test_stream_relay.c and
 * test_stream_data_cb.c use -- rather than the whole merged server, and
 * that is deliberate rather than thrift: every case in this file turns on
 * what happens to ONE peer's datagram queue while ANOTHER peer's is
 * healthy, and only a far end the test drives datagram by datagram can
 * produce that. A real server would decide for itself when to reply.
 *
 * ---- WHY TWO ADDRESS FAMILIES, AND WHICH CASES USE WHICH --------------
 *
 * D5 -- the declared divergence this whole module is built around -- is
 * only reachable when sendto(2) REFUSES a datagram, and an AF_INET UDP
 * socket on loopback does not refuse. Measured in this project's image
 * before any of this was written: SO_SNDBUF 4096 on the sender, SO_RCVBUF
 * 1024 on the receiver, 20000 sends of 1024 bytes, ZERO failures --
 * loopback frees the skb the moment the receiver accepts or drops it, so
 * the loss happens silently at the receiver and the sender never learns.
 * An AF_UNIX SOCK_DGRAM socket does refuse, deterministically: with
 * SO_RCVBUF 4096 on the receiver, the 11th send of 1024 bytes returned
 * EAGAIN, and the first send after the receiver drained one datagram
 * succeeded. Case 2A below re-measures both halves of that, so this
 * comment is an assertion rather than a claim.
 *
 * So: the cases about ROUTING and SIZES use a real AF_INET UDP socket,
 * because that is the production path and a file that never opened one
 * would prove nothing about it; the cases about BACKPRESSURE use AF_UNIX
 * SOCK_DGRAM, because it is the only datagram socket available here whose
 * backpressure a test can produce. cloak_udp_piper_adopt exists for
 * exactly this and says so.
 *
 * ---- WHAT EACH CASE IS FOR --------------------------------------------
 *
 *  1. Two peers on one socket get two DISTINCT streams and traffic does
 *     not cross between them. The far end replies with the bytes it
 *     received XORed with 0xFF, so a reply that arrives transformed
 *     cannot have come from anywhere but the far end, and each peer
 *     asserts it got back ITS OWN payload -- which a crossed route fails
 *     even though both peers "work".
 *  2A. The measurement above, so the rest of the file's mechanism is
 *     pinned rather than assumed.
 *  2B. A slow peer does not stall a fast one: one peer's receive queue is
 *     filled until the piper's sendto is refused, and the other peer
 *     still receives every datagram, in order, while that lasts.
 *  3. THE DROP POLICY, asserted as a policy and not as a survival: the
 *     exact SET of datagrams that reached the slow peer is compared
 *     element by element against the set the newest-drops rule predicts,
 *     and the counter is asserted to move by exactly one per excess
 *     datagram. Dropping the OLDEST passes "the peer still works" and
 *     fails this; dropping nothing (an unbounded queue) fails the
 *     counter.
 *  4. The per-peer deadline: retired after it, NOT retired while the peer
 *     is speaking, and NOT retired while only the far end is speaking --
 *     the third being the half a refresh on the inbound path alone would
 *     silently lose. Descriptors counted from /proc/self/fd, because
 *     LeakSanitizer does not track them.
 *  5. Sizes (D7): 16132 carried whole in BOTH directions, 8193 carried
 *     whole (Go truncates at 8192 and tears the stream down on the way
 *     back), 16133 refused as a whole datagram with the peer left alive,
 *     zero-length swallowed.
 *  6. Churn: 1000 short-lived peers leave no descriptors, no peers and
 *     no refusals.
 *  7. The write-side hazard this task was dispatched to resolve:
 *     cloak_stream_relay_t's read budget against an UNORDERED stream's
 *     16132-byte write limit. Not this module's object, but this module's
 *     dispatch -- see the case.
 *
 * EVERY WAIT IS BOUNDED BY THE CLOCK, never by an iteration count, and
 * every wait whose comment names a duration asserts it reached that
 * duration. The two helpers are copied from test_client_piper.c, whose
 * comments record why: a loop of "2000 turns of 1 ms" bounded by turns
 * alone completed in 4.2 ms on this project once one permanently-ready
 * descriptor was registered. */

#include "cloak/client_stack.h"
#include "cloak/common.h"
#include "cloak/config.h"
#include "cloak/crypto.h"
#include "cloak/conn.h"
#include "cloak/frame.h"
#include "cloak/net.h"
#include "cloak/ordering.h"
#include "cloak/reactor.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "cloak/stream_relay.h"
#include "cloak/udp_piper.h"
#include "test_framework.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* ---- bounded reactor pumping ------------------------------------------- */

#define PUMP_MAX_TURNS 2000
#define PUMP_TURN_MS 1

typedef int (*pump_done_fn)(void *ctx);

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Pumps until done(ctx), bounded by REAL TIME: max_iters * per_iter_ms
 * milliseconds. Returns 1 if done became true. The iteration ceiling is a
 * backstop against a clock that does not advance and is sized so it
 * cannot bind first -- see test_client_piper.c's copy for the measurement
 * that made this a wall-clock bound in seven files at once. */
static int pump_until(cloak_reactor_t *r, pump_done_fn done, void *ctx, int max_iters,
                      int per_iter_ms) {
    uint64_t budget_ms = (uint64_t)(max_iters > 0 ? max_iters : 0) *
                         (uint64_t)(per_iter_ms > 0 ? per_iter_ms : 0);
    uint64_t start = monotonic_ms();
    uint64_t ceiling = budget_ms * 1000u + 5000000u;
    for (uint64_t i = 0; i < ceiling; i++) {
        if (done(ctx)) {
            return 1;
        }
        if (monotonic_ms() - start >= budget_ms) {
            break;
        }
        cloak_reactor_run_once(r, per_iter_ms);
    }
    return done(ctx);
}

/* Pumps for at least `ms` of REAL time, and ASSERTS it really did: a
 * deadline is a wall-clock quantity, and a loop that exited early would
 * turn every assertion after it into nothing. */
static void pump_for_ms(cloak_reactor_t *r, uint64_t ms) {
    uint64_t start = monotonic_ms();
    uint64_t ceiling = ms * 1000u + 5000000u;
    uint64_t i = 0;
    while (monotonic_ms() - start < ms && i < ceiling) {
        cloak_reactor_run_once(r, 1);
        i++;
    }
    ASSERT_TRUE(monotonic_ms() - start >= ms);
}

/* Pumps until the reactor has had nothing to dispatch for three
 * consecutive turns, bounded by the clock at `ms`.
 *
 * IT IS NOT A WAIT FOR A CONDITION and is never used as one. It is used
 * where the event being waited for is ALREADY PENDING -- a frame has just
 * been written into a socketpair both ends of which this process owns --
 * and the question is only "let the reactor carry it". A fixed number of
 * turns would be a guess; this is the same guess with evidence, and every
 * case that uses it asserts the consequence afterwards. */
static void pump_quiesce(cloak_reactor_t *r, uint64_t ms) {
    uint64_t start = monotonic_ms();
    uint64_t ceiling = ms * 1000u + 5000000u;
    int idle = 0;
    for (uint64_t i = 0; i < ceiling && monotonic_ms() - start < ms; i++) {
        if (cloak_reactor_run_once(r, 1) > 0) {
            idle = 0;
            continue;
        }
        if (++idle >= 3) {
            return;
        }
    }
}

/* Open descriptors, counted from /proc/self/fd. LeakSanitizer tracks
 * memory, not descriptors: a piper that freed every byte it allocated and
 * quietly dropped a socket is indistinguishable, to ASan and to every
 * counter in this file, from a correct one. Returns -1 where /proc is
 * absent, and every call site asserts that did not happen -- a -1 == -1
 * comparison is how this check silently stopped working on an earlier
 * branch of this project. */
static int count_open_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) {
        return -1;
    }
    int n = 0;
    while (readdir(d) != NULL) {
        n++;
    }
    closedir(d);
    return n;
}

/* ---- the far end -------------------------------------------------------- */

#define FAR_MAX_STREAMS 1100
#define FAR_MAX_DGRAMS 64
#define FAR_BUF 20000

struct far_stream {
    cloak_stream_t *s;
    int closed;
    int count;
    /* The FIRST byte of the first datagram this stream ever carried. The
     * peers in case 1 make theirs distinct, so this is what maps a stream
     * back to the peer that must own it -- without it, "two streams
     * exist" is compatible with both peers sharing one. */
    uint8_t tag;
    size_t last_len;
    uint64_t last_sum;
    /* Per datagram, in arrival order: its first byte (which identifies
     * the sender in every case here) and its LENGTH. The lengths are what
     * make boundary preservation assertable -- a reader that concatenated
     * two datagrams, or split one, agrees with a test that only counts
     * bytes. */
    int seqs[FAR_MAX_DGRAMS];
    int lens[FAR_MAX_DGRAMS];
};

struct far_end {
    cloak_session_t sesh;
    struct far_stream st[FAR_MAX_STREAMS];
    int nstreams;
    int echo;            /* reply with every byte XORed with 0xFF */
    int new_stream_calls;
    int overflow;        /* a stream or datagram past this harness's arrays */
};

static uint64_t sum_bytes(const uint8_t *p, size_t n) {
    uint64_t s = 0;
    for (size_t i = 0; i < n; i++) {
        s += p[i];
    }
    return s;
}

static struct far_stream *far_find(struct far_end *fe, const cloak_stream_t *s) {
    for (int i = 0; i < fe->nstreams; i++) {
        if (fe->st[i].s == s) {
            return &fe->st[i];
        }
    }
    return NULL;
}

/* Drains every datagram currently readable on one far-end stream,
 * recording the boundaries exactly as they arrive. Boundary preservation
 * is half of what this file tests, so nothing here concatenates. */
static void far_drain(struct far_end *fe, struct far_stream *fs) {
    static uint8_t buf[FAR_BUF];
    for (;;) {
        long n = cloak_stream_read(fs->s, buf, sizeof(buf));
        if (n == 0) {
            return;
        }
        if (n < 0) {
            /* -1 is end of stream. CLOAK_STREAM_ERR_SHORT_BUFFER would be
             * a harness bug (FAR_BUF is larger than any datagram this
             * file sends), and is reported as one rather than folded into
             * EOF -- which is the exact conflation Go's own client makes
             * and this port exists not to repeat. */
            ASSERT_EQ_INT(-1, (int)n);
            fs->closed = 1;
            return;
        }
        if (fs->count < FAR_MAX_DGRAMS) {
            fs->seqs[fs->count] = n > 0 ? buf[0] : 0;
            fs->lens[fs->count] = (int)n;
        } else {
            fe->overflow = 1;
        }
        fs->count++;
        fs->last_len = (size_t)n;
        fs->last_sum = sum_bytes(buf, (size_t)n);
        if (fs->tag == 0) {
            fs->tag = buf[0];
        }
        if (fe->echo) {
            for (long i = 0; i < n; i++) {
                buf[i] = (uint8_t)(buf[i] ^ 0xFFu);
            }
            ASSERT_EQ_INT(n, (int)cloak_stream_write(fs->s, buf, (size_t)n));
        }
    }
}

static void far_on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct far_end *fe = userdata;
    fe->new_stream_calls++;
    if (fe->nstreams >= FAR_MAX_STREAMS) {
        fe->overflow = 1;
        return;
    }
    struct far_stream *fs = &fe->st[fe->nstreams++];
    memset(fs, 0, sizeof(*fs));
    fs->s = stream;
    /* on_stream_data is deliberately NOT fired for the frame that created
     * the stream (cloak/session.h), so a harness that only drained there
     * would lose every peer's first datagram. */
    far_drain(fe, fs);
}

static void far_on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct far_end *fe = userdata;
    struct far_stream *fs = far_find(fe, stream);
    if (fs != NULL) {
        far_drain(fe, fs);
    }
}

static void far_on_writable(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    (void)userdata;
}

static void far_on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    (void)userdata;
}

static void make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

static void fill_far_config(cloak_session_config_t *cfg, struct far_end *fe,
                            const cloak_obfuscator_t *obfs, size_t wire, size_t recv_cap) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->obfuscator = *obfs;
    cfg->ordering = CLOAK_SESSION_ORDERING_UNORDERED;
    cfg->max_on_wire_size = wire;
    cfg->stream_recv_capacity = recv_cap;
    cfg->stream_max_pending_frames = 64;
    cfg->conn_send_queue_cap = 262144;
    cfg->inactivity_timeout_ms = 60000;
    cfg->on_new_stream = far_on_new_stream;
    cfg->on_new_stream_userdata = fe;
    cfg->on_stream_data = far_on_stream_data;
    cfg->on_stream_data_userdata = fe;
    cfg->on_writable = far_on_writable;
    cfg->on_writable_userdata = fe;
    cfg->on_broken = far_on_broken;
    cfg->on_broken_userdata = fe;
}

/* ---- the fixture -------------------------------------------------------- */

struct fixture {
    cloak_reactor_t *r;
    struct far_end far;
    cloak_session_t near_sesh;
    cloak_udp_piper_t pp;
    int conn_fds[2];
    int far_attached;
    /* A SECOND connection on the NEAR session whose far end is never
     * read, so it backs up while the first stays clear. That is the only
     * shape in which the MINIMUM free space over the pool and the
     * AGGREGATE free space differ, which is the whole of case 10. */
    int conn2_fds[2];
    int have_conn2;
    int ready;
};

/* wire/recv_cap are per case: the size cases need the shipping 16401, the
 * churn case wants a small one so that 1000 peers do not each hold a
 * 16 KiB datagram buffer, and the drop case wants a small datagram queue
 * so that "full" is reached in a handful of datagrams rather than
 * hundreds. */
static int fixture_init_ex(struct fixture *fx, const cloak_udp_piper_config_t *pcfg_in,
                           size_t wire, size_t recv_cap, size_t conn_cap, int attach_far,
                           int congested_conn) {
    memset(fx, 0, sizeof(*fx));
    fx->conn_fds[0] = -1;
    fx->conn_fds[1] = -1;
    fx->conn2_fds[0] = -1;
    fx->conn2_fds[1] = -1;

    fx->r = cloak_reactor_create();
    if (fx->r == NULL) {
        return -1;
    }
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return -1;
    }

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    cloak_udp_piper_config_t pcfg = *pcfg_in;
    pcfg.reactor = fx->r;
    if (cloak_udp_piper_init(&fx->pp, &pcfg) != 0) {
        return -1;
    }

    /* The piper owns ALL FOUR of the near session's callbacks, so this
     * config carries none of its own -- passing a far_end here would be
     * an object nothing ever calls back into. */
    cloak_session_config_t near_cfg;
    fill_far_config(&near_cfg, NULL, &obfs, wire, recv_cap);
    cloak_udp_piper_install(&fx->pp, &near_cfg);

    cloak_session_config_t far_cfg;
    fill_far_config(&far_cfg, &fx->far, &obfs, wire, recv_cap);
    if (conn_cap > 0) {
        near_cfg.conn_send_queue_cap = conn_cap;
        far_cfg.conn_send_queue_cap = conn_cap;
    }

    if (cloak_session_init(&fx->near_sesh, 1, fx->r, &near_cfg) != 0) {
        return -1;
    }
    if (cloak_session_init(&fx->far.sesh, 1, fx->r, &far_cfg) != 0) {
        return -1;
    }
    if (cloak_session_add_conn(&fx->near_sesh, fds[0]) != 0) {
        return -1;
    }
    fx->conn_fds[0] = fds[0];
    /* attach_far == 0 leaves the far end's socket UNREAD, which is the
     * only way to make the near session's outbound pool fill on loopback:
     * the socketpair's own buffer fills first, then the connection's send
     * queue, and the piper must stop reading the local socket before that
     * queue overruns its cap -- an overrun breaks the connection and with
     * it the whole session. fixture_attach_far completes the wiring
     * later, which is how the RESUME half is reached. */
    fx->conn_fds[1] = fds[1];
    if (attach_far) {
        if (cloak_session_add_conn(&fx->far.sesh, fds[1]) != 0) {
            return -1;
        }
        fx->far_attached = 1;
    }

    if (congested_conn) {
        /* Added to the NEAR session only, with both ends' socket buffers
         * shrunk to the kernel minimum so it backs up after a datagram or
         * two rather than after the 200 KiB a default socketpair holds.
         * Nothing ever reads its far end -- that is the point. */
        int f2[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, f2) != 0) {
            return -1;
        }
        int small = 4096;
        (void)setsockopt(f2[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
        (void)setsockopt(f2[1], SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
        if (cloak_session_add_conn(&fx->near_sesh, f2[0]) != 0) {
            close(f2[0]);
            close(f2[1]);
            return -1;
        }
        fx->conn2_fds[0] = f2[0]; /* the session's now */
        fx->conn2_fds[1] = f2[1]; /* ours, and never read */
        fx->have_conn2 = 1;
    }

    cloak_udp_piper_set_session(&fx->pp, &fx->near_sesh);
    fx->ready = 1;
    return 0;
}

static int fixture_init(struct fixture *fx, const cloak_udp_piper_config_t *pcfg_in, size_t wire,
                        size_t recv_cap) {
    return fixture_init_ex(fx, pcfg_in, wire, recv_cap, 0, 1, 0);
}

static int fixture_attach_far(struct fixture *fx) {
    if (fx->far_attached) {
        return 0;
    }
    if (cloak_session_add_conn(&fx->far.sesh, fx->conn_fds[1]) != 0) {
        return -1;
    }
    fx->far_attached = 1;
    return 0;
}

static void fixture_destroy(struct fixture *fx) {
    if (!fx->ready) {
        if (fx->r != NULL) {
            cloak_reactor_destroy(fx->r);
        }
        return;
    }
    /* THE PIPER FIRST, BEFORE EITHER SESSION: it is what releases the
     * streams, and a stream can only be released to a live session. */
    cloak_udp_piper_destroy(&fx->pp);
    for (int i = 0; i < fx->far.nstreams; i++) {
        cloak_session_release_stream(&fx->far.sesh, fx->far.st[i].s);
    }
    cloak_session_destroy(&fx->near_sesh);
    cloak_session_destroy(&fx->far.sesh);
    if (!fx->far_attached && fx->conn_fds[1] >= 0) {
        close(fx->conn_fds[1]); /* never handed to a session, so ours */
    }
    if (fx->have_conn2 && fx->conn2_fds[1] >= 0) {
        close(fx->conn2_fds[1]); /* the deliberately unread far end */
    }
    cloak_reactor_destroy(fx->r);
}

/* ---- local peers -------------------------------------------------------- */

/* One "application" speaking to the piper's socket.
 *
 * AF_UNIX peers need a bound address of their own: an unbound AF_UNIX
 * datagram socket has no address, so recvfrom on the piper's side would
 * report a zero-length source and the piper would have nothing to reply
 * to. AF_INET peers are autobound by the kernel on first send. */
struct peer {
    int fd;
    struct sockaddr_storage me;
    socklen_t me_len;
    struct sockaddr_storage piper;
    socklen_t piper_len;
};

/* Abstract-namespace names, randomised rather than derived from the pid:
 * inside a container every process sees pid 1, which this project has
 * already measured to be useless as a uniquifier (task 1's fix round,
 * where a pid-stamped temporary file collided 5 times in 6 concurrent
 * runs). Abstract names also need no unlink, so a crashed run leaves
 * nothing behind. */
static void unix_addr(struct sockaddr_un *sa, socklen_t *len, const char *name) {
    memset(sa, 0, sizeof(*sa));
    sa->sun_family = AF_UNIX;
    sa->sun_path[0] = '\0';
    size_t n = strlen(name);
    if (n > sizeof(sa->sun_path) - 2) {
        n = sizeof(sa->sun_path) - 2;
    }
    memcpy(sa->sun_path + 1, name, n);
    *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

static void unique_name(char *out, size_t cap, const char *what) {
    uint8_t rnd[8];
    cloak_random_bytes(rnd, sizeof(rnd));
    snprintf(out, cap, "cloak-udp-%s-%02x%02x%02x%02x%02x%02x%02x%02x", what, rnd[0], rnd[1],
             rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7]);
}

static int make_unix_dgram(struct sockaddr_storage *out, socklen_t *out_len, const char *what,
                           int rcvbuf) {
    char name[80];
    unique_name(name, sizeof(name), what);
    struct sockaddr_un sa;
    socklen_t len;
    unix_addr(&sa, &len, name);
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }
    if (rcvbuf > 0 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) != 0) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&sa, len) != 0) {
        close(fd);
        return -1;
    }
    memcpy(out, &sa, sizeof(sa));
    *out_len = len;
    return fd;
}

/* The piper's OWN context for one local peer -- i.e. the near end of that
 * peer's stream. D5's drop counter lives there and NOT on the far end's
 * stream, which is a different cloak_stream_t on a different session: the
 * drop happens when a frame ARRIVES and the queue behind it is full. The
 * first version of these cases read the far end's counter and saw zero
 * while the piper's total said 23, which is the difference between
 * asserting on the queue that drops and asserting on the queue that
 * sends. The piper's struct is public, so this needs no seam. */
static cloak_udp_piper_peer_t *near_peer(cloak_udp_piper_t *pp, const struct sockaddr_storage *addr,
                                         socklen_t len) {
    for (cloak_udp_piper_peer_t *p = pp->peers; p != NULL; p = p->next) {
        if (p->addr_len == len && memcmp(&p->addr, addr, (size_t)len) == 0) {
            return p;
        }
    }
    return NULL;
}

struct peers_ctx {
    cloak_udp_piper_t *pp;
    size_t want;
};

static int peer_count_is(void *ctx) {
    struct peers_ctx *c = ctx;
    return cloak_udp_piper_peer_count(c->pp) == c->want;
}

static int peer_send(struct peer *p, const uint8_t *buf, size_t len) {
    ssize_t n = sendto(p->fd, buf, len, 0, (const struct sockaddr *)&p->piper, p->piper_len);
    return n == (ssize_t)len ? 0 : -1;
}

/* Reads one datagram if one is waiting. Returns its length, -1 if none. */
static long peer_recv(struct peer *p, uint8_t *buf, size_t cap) {
    ssize_t n = recvfrom(p->fd, buf, cap, 0, NULL, NULL);
    return n < 0 ? -1 : (long)n;
}

static void fill_pattern(uint8_t *buf, size_t len, uint8_t tag) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(tag + i);
    }
    if (len > 0) {
        buf[0] = tag;
    }
}

/* ============ 1. two peers, two streams, no crossing ==================== */

struct pair_ctx {
    struct far_end *far;
    int want;
};

static int far_streams_at_least(void *ctx) {
    struct pair_ctx *c = ctx;
    return c->far->nstreams >= c->want;
}

/* "Both of these far-end streams have carried at least one more datagram
 * than they had." The piper refreshes a peer's deadline when it READS that
 * peer's datagram off the local socket, and the far end's count is the
 * only externally visible consequence of that read -- so waiting on it is
 * how a case can KNOW the refresh happened rather than assume it. */
struct arrived_ctx {
    struct far_stream *a;
    int a_want;
    struct far_stream *b;
    int b_want;
};

static int both_streams_arrived(void *ctx) {
    struct arrived_ctx *c = ctx;
    return c->a->count >= c->a_want && c->b->count >= c->b_want;
}

static void test_two_peers_two_streams_no_crossing(void) {
    /* static, not automatic: struct far_end carries a per-stream record
     * for up to FAR_MAX_STREAMS streams, which case 6 needs 1000 of. */
    static struct fixture fx;
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.peer_timeout_ms = 60000;
    ASSERT_EQ_INT(0, fixture_init(&fx, &pcfg, 16401, 65536));
    if (!fx.ready) {
        fixture_destroy(&fx);
        return;
    }
    fx.far.echo = 1;

    /* THE PRODUCTION PATH: a real AF_INET UDP socket, bound to an
     * ephemeral port. */
    char err[200] = {0};
    ASSERT_EQ_INT(0, cloak_udp_piper_open(&fx.pp, "127.0.0.1:0", err, sizeof(err)));
    int port = cloak_udp_piper_port(&fx.pp);
    ASSERT_TRUE(port > 0);

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    to.sin_port = htons((uint16_t)port);

    struct peer a;
    struct peer b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    a.fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    b.fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_TRUE(a.fd >= 0 && b.fd >= 0);
    memcpy(&a.piper, &to, sizeof(to));
    a.piper_len = sizeof(to);
    b.piper = a.piper;
    b.piper_len = a.piper_len;

    uint8_t pa[64];
    uint8_t pb[64];
    fill_pattern(pa, sizeof(pa), 0xA1);
    fill_pattern(pb, sizeof(pb), 0xB2);
    ASSERT_EQ_INT(0, peer_send(&a, pa, sizeof(pa)));
    ASSERT_EQ_INT(0, peer_send(&b, pb, sizeof(pb)));

    struct pair_ctx pc = {&fx.far, 2};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_streams_at_least, &pc, PUMP_MAX_TURNS, PUMP_TURN_MS));

    /* TWO peers, TWO streams, and the stream ids differ -- a piper that
     * reused one stream for both source addresses would show one. */
    ASSERT_EQ_INT(2, (int)cloak_udp_piper_peer_count(&fx.pp));
    ASSERT_EQ_INT(2, (int)cloak_udp_piper_peers_created(&fx.pp));
    ASSERT_EQ_INT(2, fx.far.nstreams);
    /* Guarded so that an implementation which produced ONE stream fails
     * the assertion above and REPORTS it, rather than dereferencing a
     * NULL st[1].s: a crash costs a mutation battery every result after
     * this point, and this project has already recorded two tests that
     * segfault instead of asserting under mutation. */
    if (fx.far.nstreams == 2) {
        ASSERT_TRUE(fx.far.st[0].s->id != fx.far.st[1].s->id);
    }
    /* Each stream carried exactly one peer's payload, identified by the
     * tag byte the two peers do not share. */
    ASSERT_TRUE((fx.far.st[0].tag == 0xA1 && fx.far.st[1].tag == 0xB2) ||
                (fx.far.st[0].tag == 0xB2 && fx.far.st[1].tag == 0xA1));
    ASSERT_EQ_INT(1, fx.far.st[0].count);
    ASSERT_EQ_INT(1, fx.far.st[1].count);

    /* THE REPLIES. The far end XORs, which nothing on the client side can
     * do, so a payload that comes back transformed proves it crossed --
     * and each peer asserting it got back ITS OWN payload is what a
     * crossed route fails. */
    uint8_t got[128];
    long ga = -1;
    long gb = -1;
    uint64_t start = monotonic_ms();
    while (monotonic_ms() - start < 2000 && (ga < 0 || gb < 0)) {
        cloak_reactor_run_once(fx.r, 1);
        if (ga < 0) {
            ga = peer_recv(&a, got, sizeof(got));
            if (ga > 0) {
                ASSERT_EQ_INT(64, (int)ga);
                for (long i = 0; i < ga; i++) {
                    ASSERT_EQ_INT(pa[i] ^ 0xFF, got[i]);
                }
            }
        }
        if (gb < 0) {
            gb = peer_recv(&b, got, sizeof(got));
            if (gb > 0) {
                ASSERT_EQ_INT(64, (int)gb);
                for (long i = 0; i < gb; i++) {
                    ASSERT_EQ_INT(pb[i] ^ 0xFF, got[i]);
                }
            }
        }
    }
    ASSERT_EQ_INT(64, (int)ga);
    ASSERT_EQ_INT(64, (int)gb);

    /* Nothing was dropped, refused, oversized or stalled on a healthy
     * pair -- the counters this file leans on elsewhere must read zero
     * when nothing went wrong, or they prove nothing when they do not. */
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_dropped_datagrams(&fx.pp));
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_refused_peers(&fx.pp));
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_oversize_datagrams(&fx.pp));
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_send_stalls(&fx.pp));
    ASSERT_EQ_INT(0, fx.far.overflow);

    close(a.fd);
    close(b.fd);
    fixture_destroy(&fx);
}

/* ============ 2A. the mechanism the backpressure cases rest on ========== */

/* Re-measures, in the running test, the two facts quoted in this file's
 * header and in cloak/udp_piper.h: an AF_INET UDP send on loopback never
 * reports backpressure, and an AF_UNIX SOCK_DGRAM send does and recovers.
 * If either stops holding -- a kernel change, a different sandbox -- the
 * cases that follow would quietly stop testing what they claim, and this
 * is what says so out loud instead. */
static void test_datagram_backpressure_mechanism(void) {
    struct sockaddr_storage recv_addr;
    socklen_t recv_len;
    int recv_fd = make_unix_dgram(&recv_addr, &recv_len, "mech-r", 4096);
    struct sockaddr_storage send_addr;
    socklen_t send_len;
    int send_fd = make_unix_dgram(&send_addr, &send_len, "mech-s", 0);
    ASSERT_TRUE(recv_fd >= 0 && send_fd >= 0);
    if (recv_fd < 0 || send_fd < 0) {
        return;
    }

    uint8_t buf[1024];
    memset(buf, 'x', sizeof(buf));
    int sent = 0;
    int refused_at = -1;
    for (int i = 0; i < 1000; i++) {
        ssize_t n = sendto(send_fd, buf, sizeof(buf), 0, (struct sockaddr *)&recv_addr, recv_len);
        if (n < 0) {
            ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS);
            refused_at = i;
            break;
        }
        sent++;
    }
    /* Bounded, not exact: the kernel's per-socket accounting is not a
     * promise. What matters is that it refuses at all, and soon. */
    ASSERT_TRUE(refused_at > 0);
    ASSERT_TRUE(refused_at < 200);

    /* ...and that draining the RECEIVER is what clears it, which is the
     * property the piper's retry timer depends on. */
    uint8_t in[2048];
    ASSERT_TRUE(recvfrom(recv_fd, in, sizeof(in), 0, NULL, NULL) == 1024);
    ASSERT_TRUE(sendto(send_fd, buf, sizeof(buf), 0, (struct sockaddr *)&recv_addr, recv_len) ==
                1024);

    /* The other half: AF_INET on loopback does NOT refuse, which is why
     * these cases cannot be written against a UDP socket. */
    int u = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    int v = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_TRUE(u >= 0 && v >= 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ_INT(0, bind(v, (struct sockaddr *)&a, sizeof(a)));
    socklen_t al = sizeof(a);
    ASSERT_EQ_INT(0, getsockname(v, (struct sockaddr *)&a, &al));
    int small = 1024;
    setsockopt(v, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
    int snd = 4096;
    setsockopt(u, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    int fails = 0;
    for (int i = 0; i < 5000; i++) {
        if (sendto(u, buf, sizeof(buf), 0, (struct sockaddr *)&a, sizeof(a)) < 0) {
            fails++;
        }
    }
    ASSERT_EQ_INT(0, fails);

    close(u);
    close(v);
    close(recv_fd);
    close(send_fd);
}

/* ---- the stalled-peer fixture, shared by cases 2B and 3 ---------------- */

/* A piper on an AF_UNIX socket, one peer whose receive queue is tiny and
 * which never reads (the SLOW peer), and one peer which reads everything
 * (the FAST peer). Both have a stream by the time this returns. */
struct stalled {
    struct fixture fx;
    int piper_fd;
    struct sockaddr_storage piper_addr;
    socklen_t piper_len;
    struct peer slow;
    struct peer fast;
    struct far_stream *slow_stream;
    struct far_stream *fast_stream;
};

#define SLOW_TAG 0x51
#define FAST_TAG 0xF5

static int stalled_init(struct stalled *sc, size_t wire, size_t recv_cap, uint64_t peer_timeout) {
    memset(sc, 0, sizeof(*sc));
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.peer_timeout_ms = peer_timeout;
    pcfg.send_retry_delay_ms = 2;
    if (fixture_init(&sc->fx, &pcfg, wire, recv_cap) != 0) {
        return -1;
    }

    sc->piper_fd = make_unix_dgram(&sc->piper_addr, &sc->piper_len, "piper", 0);
    if (sc->piper_fd < 0) {
        return -1;
    }
    if (cloak_udp_piper_adopt(&sc->fx.pp, sc->piper_fd) != 0) {
        return -1;
    }

    /* SO_RCVBUF 2048 on the slow peer: the kernel doubles it and applies
     * its own floor, so this is "as small as this system allows", not a
     * number with meaning. Two 700-byte datagrams are enough to refuse
     * the third, which case 2A has already measured the shape of. */
    sc->slow.fd = make_unix_dgram(&sc->slow.me, &sc->slow.me_len, "slow", 2048);
    sc->fast.fd = make_unix_dgram(&sc->fast.me, &sc->fast.me_len, "fast", 0);
    if (sc->slow.fd < 0 || sc->fast.fd < 0) {
        return -1;
    }
    sc->slow.piper = sc->piper_addr;
    sc->slow.piper_len = sc->piper_len;
    sc->fast.piper = sc->piper_addr;
    sc->fast.piper_len = sc->piper_len;

    uint8_t hello[16];
    fill_pattern(hello, sizeof(hello), SLOW_TAG);
    if (peer_send(&sc->slow, hello, sizeof(hello)) != 0) {
        return -1;
    }
    fill_pattern(hello, sizeof(hello), FAST_TAG);
    if (peer_send(&sc->fast, hello, sizeof(hello)) != 0) {
        return -1;
    }

    struct pair_ctx pc = {&sc->fx.far, 2};
    if (!pump_until(sc->fx.r, far_streams_at_least, &pc, PUMP_MAX_TURNS, PUMP_TURN_MS)) {
        return -1;
    }
    for (int i = 0; i < sc->fx.far.nstreams; i++) {
        if (sc->fx.far.st[i].tag == SLOW_TAG) {
            sc->slow_stream = &sc->fx.far.st[i];
        }
        if (sc->fx.far.st[i].tag == FAST_TAG) {
            sc->fast_stream = &sc->fx.far.st[i];
        }
    }
    return (sc->slow_stream != NULL && sc->fast_stream != NULL) ? 0 : -1;
}

static void stalled_destroy(struct stalled *sc) {
    if (sc->slow.fd >= 0) {
        close(sc->slow.fd);
    }
    if (sc->fast.fd >= 0) {
        close(sc->fast.fd);
    }
    fixture_destroy(&sc->fx);
}

/* One datagram of `len` bytes carrying `seq` in its first byte, written
 * from the far end into one peer's stream and pumped until the near
 * session has actually fed it. */
static void far_send(struct stalled *sc, struct far_stream *fs, uint8_t seq, size_t len) {
    uint8_t buf[2048];
    ASSERT_TRUE(len <= sizeof(buf));
    fill_pattern(buf, len, seq);
    ASSERT_EQ_INT((int)len, (int)cloak_stream_write(fs->s, buf, len));
    /* The frame is already in the socketpair by now; this only lets the
     * reactor carry it the rest of the way, and returns as soon as it
     * has. Case 3 classifies each datagram by the drop counter
     * immediately afterwards, so a turn that did not suffice would show
     * up there as a mis-classified datagram and fail the element-wise
     * comparison at the end -- which is what makes this safe to use
     * rather than merely convenient. */
    pump_quiesce(sc->fx.r, 500);
}

/* ============ 2B. a slow peer does not stall a fast one ================== */

static void test_slow_peer_does_not_stall_fast_peer(void) {
    static struct stalled sc;
    ASSERT_EQ_INT(0, stalled_init(&sc, 1024, 4096, 60000));
    if (sc.slow_stream == NULL) {
        stalled_destroy(&sc);
        return;
    }

    /* Fill the slow peer until the piper's sendto is actually refused.
     * The datagram queue behind it then fills too, which is case 3's
     * subject; here the only question is what that does to the OTHER
     * peer. */
    for (int i = 0; i < 40; i++) {
        far_send(&sc, sc.slow_stream, (uint8_t)i, 700);
    }
    ASSERT_TRUE(cloak_udp_piper_send_stalls(&sc.fx.pp) > 0);
    ASSERT_TRUE(cloak_udp_piper_dropped_datagrams(&sc.fx.pp) > 0);

    /* NOW THE FAST PEER, with the slow one still wedged. Twenty
     * datagrams, distinct and ordered. */
    for (int i = 0; i < 20; i++) {
        far_send(&sc, sc.fast_stream, (uint8_t)(0x80 + i), 64);
    }

    uint8_t got[2048];
    int received = 0;
    uint64_t start = monotonic_ms();
    while (monotonic_ms() - start < 2000 && received < 20) {
        long n = peer_recv(&sc.fast, got, sizeof(got));
        if (n > 0) {
            /* In order, and the right peer's payloads: 0x80 + i, never
             * one of the slow peer's 0..39. */
            ASSERT_EQ_INT(0x80 + received, got[0]);
            ASSERT_EQ_INT(64, (int)n);
            received++;
            continue;
        }
        cloak_reactor_run_once(sc.fx.r, 1);
    }
    ASSERT_EQ_INT(20, received);

    /* The fast peer's stream lost nothing: every drop counted belongs to
     * the slow peer. A piper that shared one queue, or that paused the
     * socket for everybody when one destination refused, fails the count
     * above; one that dropped the fast peer's datagrams too fails this. */
    cloak_udp_piper_peer_t *np_slow = near_peer(&sc.fx.pp, &sc.slow.me, sc.slow.me_len);
    cloak_udp_piper_peer_t *np_fast = near_peer(&sc.fx.pp, &sc.fast.me, sc.fast.me_len);
    ASSERT_TRUE(np_slow != NULL && np_fast != NULL);
    if (np_slow != NULL && np_fast != NULL) {
        ASSERT_EQ_INT(0, (int)np_fast->stream->recv_dropped_datagrams);
        ASSERT_TRUE(np_slow->stream->recv_dropped_datagrams > 0);
    }
    ASSERT_EQ_INT(2, (int)cloak_udp_piper_peer_count(&sc.fx.pp));

    stalled_destroy(&sc);
}

/* ============ 3. the drop policy, asserted as a policy =================== */

static void test_full_queue_drops_the_newest_and_counts(void) {
    static struct stalled sc;
    /* wire 1024 -> 755 bytes of payload per frame; a 4096-byte datagram
     * queue holds a handful of 700-byte datagrams, so "full" arrives in
     * single digits and the expected set below stays readable. */
    ASSERT_EQ_INT(0, stalled_init(&sc, 1024, 4096, 60000));
    if (sc.slow_stream == NULL) {
        stalled_destroy(&sc);
        return;
    }

    /* Datagram i carries i in its first byte. After each one, the
     * piper-level drop counter says whether THAT datagram was the one
     * dropped -- which is the whole assertion: the drop is attributed to
     * the newest arrival, one per excess datagram, not to a batch and not
     * to something already accepted. */
    int expected[64];
    int n_expected = 0;
    uint64_t dropped_before = 0;
    int first_drop_at = -1;
    for (int i = 0; i < 40; i++) {
        far_send(&sc, sc.slow_stream, (uint8_t)i, 700);
        uint64_t now = cloak_udp_piper_dropped_datagrams(&sc.fx.pp);
        if (now == dropped_before) {
            ASSERT_TRUE(n_expected < (int)(sizeof(expected) / sizeof(expected[0])));
            expected[n_expected++] = i;
        } else {
            /* EXACTLY ONE per excess datagram. A queue that dropped a
             * batch, or that counted per frame rather than per dropped
             * datagram, fails here rather than at the totals. */
            ASSERT_EQ_INT(1, (int)(now - dropped_before));
            if (first_drop_at < 0) {
                first_drop_at = i;
            }
        }
        dropped_before = now;
    }

    /* The state this case exists to reach was actually reached. */
    ASSERT_TRUE(first_drop_at > 0);
    ASSERT_TRUE(dropped_before > 0);
    ASSERT_TRUE(cloak_udp_piper_send_stalls(&sc.fx.pp) > 0);
    /* The piper's total is the stream's own counter, read through the
     * accessor -- so an accessor that returned a constant, or that
     * forgot live peers, is caught. */
    cloak_udp_piper_peer_t *np = near_peer(&sc.fx.pp, &sc.slow.me, sc.slow.me_len);
    ASSERT_TRUE(np != NULL);
    if (np != NULL) {
        ASSERT_EQ_INT((int)np->stream->recv_dropped_datagrams, (int)dropped_before);
    }
    ASSERT_EQ_INT(40, n_expected + (int)dropped_before);

    /* NOW DRAIN THE SLOW PEER and let everything still queued come out.
     * What arrives must be EXACTLY the datagrams that were not dropped,
     * in order.
     *
     * THIS IS THE ASSERTION THE CASE IS FOR. "The peer still works"
     * passes against a queue that drops the OLDEST (the surviving set is
     * then the newest datagrams, a different set of the same size),
     * against one that drops at random, and against one that never
     * dropped at all. Comparing the SET element by element fails all
     * three. */
    uint8_t got[2048];
    int received = 0;
    uint64_t start = monotonic_ms();
    while (monotonic_ms() - start < 3000 && received < n_expected) {
        long n = peer_recv(&sc.slow, got, sizeof(got));
        if (n > 0) {
            ASSERT_EQ_INT(700, (int)n);
            ASSERT_TRUE(received < n_expected);
            if (received < n_expected) {
                ASSERT_EQ_INT(expected[received], got[0]);
            }
            received++;
            continue;
        }
        cloak_reactor_run_once(sc.fx.r, 1);
    }
    ASSERT_EQ_INT(n_expected, received);

    /* And nothing more: a datagram that was counted as dropped must not
     * turn up late. Give the reactor real time to produce one if it is
     * going to. */
    pump_for_ms(sc.fx.r, 50);
    ASSERT_EQ_INT(-1, (int)peer_recv(&sc.slow, got, sizeof(got)));
    /* The peer is still alive and its stream was never retired over the
     * drops -- backpressure is not an error. */
    ASSERT_EQ_INT(2, (int)cloak_udp_piper_peer_count(&sc.fx.pp));
    ASSERT_EQ_INT(0, sc.slow_stream->closed);
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_peers_expired(&sc.fx.pp));

    /* AND THE TOTAL SURVIVES THE PEER. The counter this reads lives on
     * the cloak_stream_t and dies with it, so a piper that summed only
     * LIVE peers would report zero the moment the peer that was dropping
     * went away -- which is exactly when an operator goes looking. */
    uint64_t total = cloak_udp_piper_dropped_datagrams(&sc.fx.pp);
    ASSERT_TRUE(total > 0);
    cloak_udp_piper_destroy(&sc.fx.pp); /* retires every peer */
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_peer_count(&sc.fx.pp));
    ASSERT_EQ_INT((int)total, (int)cloak_udp_piper_dropped_datagrams(&sc.fx.pp));

    stalled_destroy(&sc);
}

/* ============ 3b. a wedged peer is still retired ======================== */

/* BOTH PEERS SPEAK ONCE, and this returns the instant sampled BEFORE they
 * did -- i.e. a time no later than either peer's own last_activity_ms.
 *
 * WHY A CASE WOULD WANT THIS. peer_timeout_ms is measured from a peer's
 * LAST ACTIVITY, so a case that configures a short deadline is also
 * putting its own setup on that clock: every reactor turn the setup takes
 * is spent out of the peer's remaining life. This moves the origin of both
 * deadlines to a point the case chooses, which is the difference between
 * "the deadline fires 150 ms after something the case did not control" and
 * "150 ms after this line".
 *
 * The peer->piper direction is the one to use: it is the direction that
 * still works when a peer's RECEIVE queue is wedged, so this refreshes a
 * wedged peer without unwedging it. Returns 0 if a peer has already gone,
 * which every caller asserts against rather than ignores. */
static uint64_t keepalive_both(struct stalled *sc) {
    int slow_before = sc->slow_stream->count;
    int fast_before = sc->fast_stream->count;
    uint8_t ka[16];
    fill_pattern(ka, sizeof(ka), 0x6B);
    uint64_t before = monotonic_ms();
    if (peer_send(&sc->slow, ka, sizeof(ka)) != 0 || peer_send(&sc->fast, ka, sizeof(ka)) != 0) {
        return 0;
    }
    struct arrived_ctx fed = {sc->slow_stream, slow_before + 1, sc->fast_stream, fast_before + 1};
    if (!pump_until(sc->fx.r, both_streams_arrived, &fed, PUMP_MAX_TURNS, PUMP_TURN_MS)) {
        return 0;
    }
    return before == 0 ? 1 : before;
}

/* A peer that can neither receive (its queue is full and sendto refuses)
 * nor send (it has gone quiet) must still hit its deadline.
 *
 * THIS IS WHAT MAKES THE DEADLINE A BOUND RATHER THAN A DECORATION. The
 * retry timer behind a refused sendto has no ceiling of its own -- see
 * cloak/udp_piper.h, which says so and names this deadline as the reason
 * it does not need one. If a REFUSED send counted as activity, the timer
 * would refresh the deadline every few milliseconds and the one bound on
 * a wedged peer's life would never fire: a slot, a stream and a buffer
 * held forever by a local application that stopped reading. */
static void test_wedged_peer_is_still_retired_by_the_deadline(void) {
    /* One number, used twice: as the piper's deadline and as the lower
     * bound asserted at the end. Two literals could drift apart and the
     * bound would silently stop being the deadline. */
    static const uint64_t deadline_ms = 150;

    static struct stalled sc;
    ASSERT_EQ_INT(0, stalled_init(&sc, 1024, 4096, deadline_ms));
    if (sc.slow_stream == NULL) {
        stalled_destroy(&sc);
        return;
    }

    /* THE KEEPALIVE IN THIS LOOP IS LOAD-BEARING, AND IT IS NOT A WIDENED
     * TOLERANCE -- it MOVES THE ORIGIN of the two deadlines.
     *
     * MEASURED, on an idle container, without it: each far_send costs
     * ~6 ms of reactor turns, so the twenty below span ~120 ms -- and the
     * FAST peer, which this case never feeds and which is therefore never
     * touched again after its hello inside stalled_init, arrives at the
     * peer-count assertion 120 ms idle against this 150 ms deadline. That
     * is 30 ms of margin for setup that a loaded machine spends: the same
     * window, instrumented under a --cpus=2 container with four CPU
     * spinners, measured 174-181 ms, the fast peer was retired before the
     * loop ended, and peer_count read 1 -- the reported flake, reproduced
     * 7 times in 20 runs. Refreshing both peers each turn takes the setup
     * off the deadline's clock entirely, so what the deadline measures
     * below is only the silence this case is about. It does NOT unwedge
     * the slow peer: this is the peer->piper direction, and every sendto
     * TOWARDS the slow peer goes on being refused throughout. */
    uint64_t touched = 0;
    for (int i = 0; i < 20; i++) {
        far_send(&sc, sc.slow_stream, (uint8_t)i, 700);
        touched = keepalive_both(&sc);
        ASSERT_TRUE(touched != 0); /* a peer that vanished mid-setup is a failure, not a skip */
        if (touched == 0) {
            stalled_destroy(&sc);
            return;
        }
    }
    ASSERT_TRUE(cloak_udp_piper_send_stalls(&sc.fx.pp) > 0);
    ASSERT_EQ_INT(2, (int)cloak_udp_piper_peer_count(&sc.fx.pp));

    /* Nobody speaks from here on, and `touched` is when they last did.
     * Bounded by the clock at ~20x the deadline so a failure is an
     * assertion, not a ctest timeout. */
    struct peers_ctx gone = {&sc.fx.pp, 0};
    ASSERT_EQ_INT(1, pump_until(sc.fx.r, peer_count_is, &gone, 3000, 1));
    ASSERT_EQ_INT(2, (int)cloak_udp_piper_peers_expired(&sc.fx.pp));
    /* AND NOT ONE MILLISECOND EARLY. The piper and this file read the same
     * CLOCK_MONOTONIC through the same truncation, and `touched` was
     * sampled BEFORE the datagrams that refreshed the peers, so this is an
     * exact bound and not a tolerance -- which is what lets the assertion
     * exist at all, the deadline being the thing under test.
     *
     * MUTATION-CHECKED, not assumed: peer_on_deadline changed to retire at
     * a THIRD of peer_timeout_ms (and to re-arm against that third) leaves
     * every assertion above this one passing -- the peers are still both
     * there, both still expire, and the pump still reaches zero -- and
     * fails HERE, at 50 ms where 150 was configured. Without this line the
     * case cannot tell a deadline from an early retirement. */
    ASSERT_TRUE(monotonic_ms() - touched >= deadline_ms);

    stalled_destroy(&sc);
}

/* ============ 4. the per-peer deadline =================================== */

static void test_silent_peer_is_retired_after_the_deadline(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before > 0); /* /proc is present; a -1 == -1 compare proves nothing */

    static struct fixture fx;
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.peer_timeout_ms = 150;
    ASSERT_EQ_INT(0, fixture_init(&fx, &pcfg, 16401, 65536));
    if (!fx.ready) {
        fixture_destroy(&fx);
        return;
    }

    struct sockaddr_storage piper_addr;
    socklen_t piper_len;
    int piper_fd = make_unix_dgram(&piper_addr, &piper_len, "dl-piper", 0);
    ASSERT_TRUE(piper_fd >= 0);
    ASSERT_EQ_INT(0, cloak_udp_piper_adopt(&fx.pp, piper_fd));

    struct peer p;
    memset(&p, 0, sizeof(p));
    p.fd = make_unix_dgram(&p.me, &p.me_len, "dl-peer", 0);
    ASSERT_TRUE(p.fd >= 0);
    p.piper = piper_addr;
    p.piper_len = piper_len;

    int fds_idle = count_open_fds();

    uint8_t msg[32];
    fill_pattern(msg, sizeof(msg), 0x11);
    ASSERT_EQ_INT(0, peer_send(&p, msg, sizeof(msg)));

    struct far_stream *fs = &fx.far.st[0];
    struct pair_ctx pc = {&fx.far, 1};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_streams_at_least, &pc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));
    /* A peer costs NO descriptor of its own -- one socket serves them all
     * -- so this is the baseline the retirement must return to, and it is
     * also the observation that a per-peer socket would break. */
    ASSERT_EQ_INT(fds_idle, count_open_fds());

    /* 4a: SPEAKING KEEPS IT ALIVE. Four refreshes at 60 ms each spans
     * 240 ms, well past the 150 ms deadline, so a piper that armed the
     * deadline once and never refreshed it retires the peer here. */
    uint64_t t0 = monotonic_ms();
    for (int i = 0; i < 4; i++) {
        pump_for_ms(fx.r, 60);
        ASSERT_EQ_INT(0, peer_send(&p, msg, sizeof(msg)));
        cloak_reactor_run_once(fx.r, 1);
    }
    ASSERT_TRUE(monotonic_ms() - t0 >= 240);
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_peers_expired(&fx.pp));

    /* 4b: BEING SPOKEN TO ALSO KEEPS IT ALIVE. Go refreshes the deadline
     * in the reader goroutine too, and a refresh on the inbound path
     * alone would kill a peer that is only receiving -- a download, a DNS
     * answer, a media stream -- in the middle of it. This is the half a
     * test written from the sending side would miss. */
    t0 = monotonic_ms();
    for (int i = 0; i < 4; i++) {
        pump_for_ms(fx.r, 60);
        uint8_t reply[48];
        fill_pattern(reply, sizeof(reply), (uint8_t)(0x30 + i));
        ASSERT_EQ_INT(48, (int)cloak_stream_write(fs->s, reply, sizeof(reply)));
        cloak_reactor_run_once(fx.r, 1);
        cloak_reactor_run_once(fx.r, 1);
        uint8_t got[128];
        ASSERT_EQ_INT(48, (int)peer_recv(&p, got, sizeof(got)));
    }
    ASSERT_TRUE(monotonic_ms() - t0 >= 240);
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_peers_expired(&fx.pp));

    /* 4c: SILENCE RETIRES IT, AND WITHIN A BRACKET.
     *
     * THE UPPER BOUND IS HALF THE ASSERTION AND IT WAS MISSING. 4a and 4b
     * pin the lower side well -- 240 ms of activity against a 150 ms
     * deadline, in both directions -- but "it eventually expired" is
     * satisfied by a deadline ten or a hundred times too long, and a
     * review measured exactly that: multiplying every deadline by ten
     * passed this entire file. At the shipping StreamTimeout of 300 s
     * that is a peer slot, a stream and a buffer held for fifty minutes
     * instead of five, under an unauthenticated local source address's
     * control -- which is the resource this timer exists to bound.
     *
     * t_last is taken BEFORE the last datagram is sent, so the peer's own
     * last_activity_ms is necessarily >= it and the measured span is
     * never shorter than the true one: the lower bound cannot fire
     * spuriously. MEASURED at 151-156 ms on this machine in Debug and
     * under ASan, against a 150 ms deadline; the ceiling is set at 600,
     * four times the deadline, which leaves ~4x headroom for a loaded
     * machine and still fails the 1500 ms a 10x deadline produces. */
    uint8_t last_reply[48];
    fill_pattern(last_reply, sizeof(last_reply), 0x3F);
    uint64_t t_last = monotonic_ms();
    ASSERT_EQ_INT(48, (int)cloak_stream_write(fs->s, last_reply, sizeof(last_reply)));
    {
        uint8_t got[128];
        long n = -1;
        uint64_t start = monotonic_ms();
        while (monotonic_ms() - start < 2000 && n < 0) {
            cloak_reactor_run_once(fx.r, 1);
            n = peer_recv(&p, got, sizeof(got));
        }
        ASSERT_EQ_INT(48, (int)n);
    }

    struct peers_ctx ctx = {&fx.pp, 0};
    ASSERT_EQ_INT(1, pump_until(fx.r, peer_count_is, &ctx, 3000, 1));
    uint64_t expiry_ms = monotonic_ms() - t_last;
    ASSERT_COUNT_IN_RANGE("peer expiry, ms after the last datagram (deadline 150)", expiry_ms, 150,
                          600);
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_peer_count(&fx.pp));
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peers_expired(&fx.pp));

    /* THE FAR END LEARNS. A retirement that forgot the peer locally but
     * left the stream open on the session would pass every count above
     * and leak a stream on the server for the life of the session. */
    pump_quiesce(fx.r, 200);
    ASSERT_EQ_INT(1, fs->closed);

    /* AND THE DESCRIPTORS COME BACK. LeakSanitizer does not track
     * these. */
    ASSERT_EQ_INT(fds_idle, count_open_fds());

    close(p.fd);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ============ 5. sizes (D7) ============================================== */

struct count_ctx {
    struct far_stream *fs;
    int want;
};

static int far_count_at_least(void *ctx) {
    struct count_ctx *c = ctx;
    return c->fs->count >= c->want;
}

static void test_sizes_are_carried_whole(void) {
    static struct fixture fx;
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.peer_timeout_ms = 60000;
    ASSERT_EQ_INT(0, fixture_init(&fx, &pcfg, 16401, 65536));
    if (!fx.ready) {
        fixture_destroy(&fx);
        return;
    }

    char err[200] = {0};
    ASSERT_EQ_INT(0, cloak_udp_piper_open(&fx.pp, "127.0.0.1:0", err, sizeof(err)));
    int port = cloak_udp_piper_port(&fx.pp);
    ASSERT_TRUE(port > 0);

    struct peer p;
    memset(&p, 0, sizeof(p));
    p.fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_TRUE(p.fd >= 0);
    int rcv = 262144;
    setsockopt(p.fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    to.sin_port = htons((uint16_t)port);
    memcpy(&p.piper, &to, sizeof(to));
    p.piper_len = sizeof(to);

    /* THE BOUNDARY IS DERIVED, NOT TYPED. cloak/stream.h derives
     * max_payload_per_frame as max_on_wire_size - CLOAK_FRAME_HEADER_LEN
     * - CLOAK_FRAME_MAX_EXTRA_LEN; a hardcoded 16132 in this file would
     * agree with a hardcoded 16132 in the implementation no matter what
     * either did to the other. The literal is asserted once, here, so the
     * derivation and the number are both pinned -- the second bracket
     * task 4 had to add after asking what would still pass. */
    size_t limit = (size_t)16401 - CLOAK_FRAME_HEADER_LEN - CLOAK_FRAME_MAX_EXTRA_LEN;
    ASSERT_EQ_INT(16132, (int)limit);

    static uint8_t big[20000];

    /* 5a: 8193 bytes -- Go silently truncates this to 8192 on the way in
     * (piper.go's `data := make([]byte, 8192)`), so this is a datagram
     * the reference implementation corrupts. */
    fill_pattern(big, 8193, 0x21);
    ASSERT_EQ_INT(0, peer_send(&p, big, 8193));
    struct pair_ctx pc = {&fx.far, 1};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_streams_at_least, &pc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    struct far_stream *fs = &fx.far.st[0];
    struct count_ctx cc = {fs, 1};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_count_at_least, &cc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT(8193, (int)fs->last_len);
    ASSERT_EQ_INT(8193, fs->lens[0]);
    ASSERT_EQ_INT((int)sum_bytes(big, 8193), (int)fs->last_sum);

    /* 5b: exactly the limit, whole and in one datagram. */
    fill_pattern(big, limit, 0x22);
    ASSERT_EQ_INT(0, peer_send(&p, big, limit));
    cc.want = 2;
    ASSERT_EQ_INT(1, pump_until(fx.r, far_count_at_least, &cc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT((int)limit, (int)fs->last_len);
    ASSERT_EQ_INT((int)limit, fs->lens[1]);
    ASSERT_EQ_INT((int)sum_bytes(big, limit), (int)fs->last_sum);
    ASSERT_EQ_INT(2, fs->count); /* ONE datagram, not two halves */

    /* 5c: one byte over. REFUSED WHOLE -- not split, not truncated -- and
     * the peer survives it. Go's answer here is to send the first 8192
     * bytes and carry on, which is a corrupted datagram the application
     * cannot detect. */
    fill_pattern(big, limit + 1, 0x23);
    ASSERT_EQ_INT(0, peer_send(&p, big, limit + 1));
    pump_for_ms(fx.r, 30);
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_oversize_datagrams(&fx.pp));
    ASSERT_EQ_INT(2, fs->count); /* nothing at all crossed */
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));
    ASSERT_EQ_INT(0, fs->closed);

    /* 5d: a zero-length datagram is SWALLOWED, matching Go, and does not
     * end the read loop -- recvfrom returning 0 on a datagram socket is a
     * real empty datagram, not EOF, and a reader that treats it as EOF
     * stops serving every peer. The datagram after it proves the loop
     * survived. */
    ASSERT_EQ_INT(0, peer_send(&p, big, 0));
    /* THE NEXT DATAGRAM IS SENT BEFORE THE REACTOR RUNS, deliberately, so
     * both are sitting in the socket when the read loop starts and the
     * empty one is read FIRST. A loop that stopped on it -- which is what
     * "0 means EOF" looks like on a stream socket -- would leave this one
     * behind. (Even then the socket's interest is re-armed at the end of
     * the turn and an edge-triggered re-arm re-reports data still
     * buffered, so such a bug costs a turn rather than the datagram;
     * measured, and recorded in the report as the reason the mutation
     * that breaks out of the loop here survives.) */
    fill_pattern(big, 64, 0x24);
    ASSERT_EQ_INT(0, peer_send(&p, big, 64));
    cc.want = 3;
    ASSERT_EQ_INT(1, pump_until(fx.r, far_count_at_least, &cc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_empty_datagrams(&fx.pp));
    /* THREE, not four: the empty one was swallowed, not carried. */
    ASSERT_EQ_INT(3, fs->count);
    ASSERT_EQ_INT(64, (int)fs->last_len);
    ASSERT_EQ_INT(64, fs->lens[2]);

    /* 5e: THE OTHER DIRECTION, which is Go's bug 6: a reply of 8193..16132
     * bytes overflows its 8192-byte reader buffer, and its `if err != nil
     * { break }` treats io.ErrShortBuffer exactly like EOF -- so the
     * reply is lost AND the peer's tunnel is torn down. Here it arrives
     * whole. */
    fill_pattern(big, limit, 0x25);
    ASSERT_EQ_INT((int)limit, (int)cloak_stream_write(fs->s, big, limit));
    static uint8_t got[20000];
    long n = -1;
    uint64_t start = monotonic_ms();
    while (monotonic_ms() - start < 2000 && n < 0) {
        cloak_reactor_run_once(fx.r, 1);
        n = peer_recv(&p, got, sizeof(got));
    }
    ASSERT_EQ_INT((int)limit, (int)n);
    if (n == (long)limit) {
        ASSERT_MEM_EQ(got, big, limit);
    }
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));

    close(p.fd);
    fixture_destroy(&fx);
}

/* ============ 5B. the limit is the SESSION's, not a constant ============= */

/* THE SECOND BRACKET, and it exists because of what the first one cannot
 * see. Case 5 runs at the shipping max_on_wire_size of 16401, where one
 * frame's payload is 16132 -- so a hardcoded 16132 in the implementation
 * agrees with every assertion there, and so does a hardcoded 16384, and
 * so does anything else at least that large. This case runs the same
 * boundary at max_on_wire_size 1024, where the limit is 755, and a
 * constant of any kind fails it: too large a read cap lets the datagram
 * through to cloak_stream_write, which refuses it (splitting is not
 * allowed in this mode) and takes the peer's stream down with it, which
 * is the opposite of what a refusal is supposed to cost. */
static void test_the_size_limit_follows_the_session(void) {
    static struct fixture fx;
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.peer_timeout_ms = 60000;
    ASSERT_EQ_INT(0, fixture_init(&fx, &pcfg, 1024, 4096));
    if (!fx.ready) {
        fixture_destroy(&fx);
        return;
    }
    struct sockaddr_storage piper_addr;
    socklen_t piper_len;
    int piper_fd = make_unix_dgram(&piper_addr, &piper_len, "lim-p", 0);
    ASSERT_TRUE(piper_fd >= 0);
    ASSERT_EQ_INT(0, cloak_udp_piper_adopt(&fx.pp, piper_fd));

    struct peer p;
    memset(&p, 0, sizeof(p));
    p.fd = make_unix_dgram(&p.me, &p.me_len, "lim-c", 0);
    ASSERT_TRUE(p.fd >= 0);
    p.piper = piper_addr;
    p.piper_len = piper_len;

    size_t limit = (size_t)1024 - CLOAK_FRAME_HEADER_LEN - CLOAK_FRAME_MAX_EXTRA_LEN;
    ASSERT_EQ_INT(755, (int)limit);

    uint8_t buf[1024];
    fill_pattern(buf, limit, 0x71);
    ASSERT_EQ_INT(0, peer_send(&p, buf, limit));
    struct pair_ctx pc = {&fx.far, 1};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_streams_at_least, &pc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    struct far_stream *fs = &fx.far.st[0];
    struct count_ctx cc = {fs, 1};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_count_at_least, &cc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT((int)limit, fs->lens[0]);

    fill_pattern(buf, limit + 1, 0x72);
    ASSERT_EQ_INT(0, peer_send(&p, buf, limit + 1));
    pump_for_ms(fx.r, 30);
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_oversize_datagrams(&fx.pp));
    ASSERT_EQ_INT(1, fs->count);
    /* THE PEER SURVIVED IT. A read cap larger than this session's limit
     * would have handed the datagram to cloak_stream_write, whose refusal
     * this module reads as a broken stream -- so the peer would be gone
     * and this is the assertion that says so. */
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));
    ASSERT_EQ_INT(0, fs->closed);

    close(p.fd);
    fixture_destroy(&fx);
}

/* ============ 6. churn ==================================================== */

#define CHURN_PEERS 1000

struct created_ctx {
    cloak_udp_piper_t *pp;
    size_t want;
};

static int peers_created_at_least(void *ctx) {
    struct created_ctx *c = ctx;
    return cloak_udp_piper_peers_created(c->pp) >= c->want;
}

/* ONE WAVE: CHURN_PEERS peers, each a fresh abstract-namespace socket that
 * sends one datagram and is closed immediately. Returns once the piper has
 * READ all of them.
 *
 * IT WAITS ON peers_created, NOT ON peer_count, AND THAT IS THE WHOLE
 * DIFFERENCE. peers_created only ever rises, so waiting on it is waiting
 * for something that will arrive: the tail of datagrams the per-iteration
 * turn did not get to. peer_count, once this loop stops feeding it, can
 * only FALL -- every peer here is silent from the instant its socket
 * closes, so its deadline is the only thing still acting on it.
 *
 * MEASURED, with the `pump_until(peer_count_is CHURN_PEERS, 3000, 1)` this
 * replaced: under a --cpus=1 container with four CPU spinners the loop
 * below took 607 ms where it takes 49 ms idle, 338 peers had ALREADY
 * expired by the time it ended, and the wait then spent its full 3000 ms
 * watching the other 662 expire too -- turning a 338-peer shortfall into
 * `peer_count` 0 and reporting `1000 != 0` for every count after it. A
 * wait on a receding condition does not merely fail to help: it destroys
 * the evidence of what actually happened. Rate under that load: 14 of 20
 * runs. */
static void churn_wave(struct fixture *fx, const struct sockaddr_storage *piper_addr,
                       socklen_t piper_len) {
    uint8_t msg[32];
    fill_pattern(msg, sizeof(msg), 0x66);
    for (int i = 0; i < CHURN_PEERS; i++) {
        struct peer p;
        memset(&p, 0, sizeof(p));
        p.fd = make_unix_dgram(&p.me, &p.me_len, "cp", 0);
        ASSERT_TRUE(p.fd >= 0);
        if (p.fd < 0) {
            return;
        }
        p.piper = *piper_addr;
        p.piper_len = piper_len;
        ASSERT_EQ_INT(0, peer_send(&p, msg, sizeof(msg)));
        /* One turn each: the datagram must be consumed before the socket
         * is closed and its address reused by nobody. */
        cloak_reactor_run_once(fx->r, 0);
        close(p.fd);
    }
    struct created_ctx made = {&fx->pp, CHURN_PEERS};
    ASSERT_EQ_INT(1, pump_until(fx->r, peers_created_at_least, &made, 3000, 1));
}

/* 6a. THE CAP HOLDS: a thousand peers coexist, and the next one is
 * refused.
 *
 * THE DEADLINE HERE IS DELIBERATELY ONE THAT CANNOT FIRE, and that is the
 * point of splitting this case from 6b rather than a convenience. Every
 * assertion below needs all thousand peers alive AT THE SAME INSTANT, so
 * with a short peer_timeout_ms the case would be racing its own setup: the
 * creation loop's duration would be spent out of the earliest peers'
 * lives, and on a machine ~12x slower than this one (measured:
 * --cpus=1 plus four CPU spinners) a third of them are gone before the
 * loop ends. Moving the ORIGIN is not available here -- these peers' own
 * sockets are closed by design, so nothing can refresh them -- so the
 * deadline is removed from this half instead, and 6b keeps it for the half
 * that is about it. Neither number was widened: 6b still uses 400 ms. */
static void test_peer_map_holds_its_cap_under_churn(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before > 0);

    static struct fixture fx;
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    /* Longer than any plausible run of this case, so no peer can expire
     * while the thousand are being created OR while they are counted. */
    pcfg.peer_timeout_ms = 60000;
    /* EXACTLY the number about to be created, so the next peer after them
     * must be refused. A cap set comfortably above the load would leave
     * "max_peers is enforced at all" untested, which is the shape of hole
     * this project keeps finding: the bound that is not the bound that
     * binds. */
    pcfg.max_peers = CHURN_PEERS;
    /* wire 1024 -> a 755-byte per-peer datagram buffer instead of 16 KiB,
     * so 1000 live peers cost under a megabyte. */
    ASSERT_EQ_INT(0, fixture_init(&fx, &pcfg, 1024, 4096));
    if (!fx.ready) {
        fixture_destroy(&fx);
        return;
    }

    struct sockaddr_storage piper_addr;
    socklen_t piper_len;
    int piper_fd = make_unix_dgram(&piper_addr, &piper_len, "churn", 0);
    ASSERT_TRUE(piper_fd >= 0);
    ASSERT_EQ_INT(0, cloak_udp_piper_adopt(&fx.pp, piper_fd));
    int fds_idle = count_open_fds();

    churn_wave(&fx, &piper_addr, piper_len);

    /* EVERY ONE OF THEM WAS REAL: created, not refused, and not silently
     * merged into one peer because the addresses compared equal. */
    ASSERT_EQ_INT(CHURN_PEERS, (int)cloak_udp_piper_peers_created(&fx.pp));
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_refused_peers(&fx.pp));
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_dropped_datagrams(&fx.pp));
    ASSERT_EQ_INT(CHURN_PEERS, (int)cloak_udp_piper_peer_count(&fx.pp));
    /* And none of them died on the way: with a deadline that cannot fire,
     * a non-zero count here would be a retirement this case did not ask
     * for, not a slow machine. */
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_peers_expired(&fx.pp));
    /* The piper's own count reaching 1000 does not mean the thousandth
     * frame has crossed the socketpair yet -- it was written, not
     * delivered. Measured: without this the far end was at 999. */
    pump_quiesce(fx.r, 1000);
    ASSERT_EQ_INT(CHURN_PEERS, fx.far.new_stream_calls);
    ASSERT_EQ_INT(0, fx.far.overflow);

    /* THE CAP IS REAL. Three more peers arrive with the map full: each is
     * refused, counted, and changes nothing about the 1000 already
     * held. */
    uint8_t msg[32];
    fill_pattern(msg, sizeof(msg), 0x66);
    for (int i = 0; i < 3; i++) {
        struct peer over;
        memset(&over, 0, sizeof(over));
        over.fd = make_unix_dgram(&over.me, &over.me_len, "cx", 0);
        ASSERT_TRUE(over.fd >= 0);
        over.piper = piper_addr;
        over.piper_len = piper_len;
        ASSERT_EQ_INT(0, peer_send(&over, msg, sizeof(msg)));
        pump_quiesce(fx.r, 200);
        close(over.fd);
    }
    ASSERT_EQ_INT(3, (int)cloak_udp_piper_refused_peers(&fx.pp));
    ASSERT_EQ_INT(CHURN_PEERS, (int)cloak_udp_piper_peer_count(&fx.pp));
    ASSERT_EQ_INT(CHURN_PEERS, (int)cloak_udp_piper_peers_created(&fx.pp));
    /* 1000 peers, still one descriptor. */
    ASSERT_EQ_INT(fds_idle, count_open_fds());

    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* 6b. AND THEY ALL GO AWAY AGAIN: a thousand deadlines, a thousand
 * retirements, and the descriptor count back where it started.
 *
 * NOTHING HERE NEEDS THE THOUSAND ALIVE AT ONCE, which is exactly why the
 * short deadline belongs in this half and not in 6a. On a slow machine
 * some of these peers expire while the rest are still being created --
 * that costs this case nothing, because what it asserts is a TOTAL
 * (peers_created == peers_expired == CHURN_PEERS), and a total does not
 * care when each term arrived. */
static void test_churned_peers_all_expire(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before > 0);

    static struct fixture fx;
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    /* Short enough that the sweep below is bounded by the clock rather
     * than by patience. */
    pcfg.peer_timeout_ms = 400;
    pcfg.max_peers = CHURN_PEERS;
    ASSERT_EQ_INT(0, fixture_init(&fx, &pcfg, 1024, 4096));
    if (!fx.ready) {
        fixture_destroy(&fx);
        return;
    }

    struct sockaddr_storage piper_addr;
    socklen_t piper_len;
    int piper_fd = make_unix_dgram(&piper_addr, &piper_len, "sweep", 0);
    ASSERT_TRUE(piper_fd >= 0);
    ASSERT_EQ_INT(0, cloak_udp_piper_adopt(&fx.pp, piper_fd));
    int fds_idle = count_open_fds();

    churn_wave(&fx, &piper_addr, piper_len);
    ASSERT_EQ_INT(CHURN_PEERS, (int)cloak_udp_piper_peers_created(&fx.pp));
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_refused_peers(&fx.pp));

    /* Now let them all expire. Bounded by the clock at ~10x the deadline,
     * and peer_count only falls from here, so this waits on a condition
     * that is arriving rather than receding. */
    struct peers_ctx down = {&fx.pp, 0};
    ASSERT_EQ_INT(1, pump_until(fx.r, peer_count_is, &down, 4000, 1));
    /* THE DEADLINE RETIRED EVERY ONE OF THEM. peers_expired counts only
     * the deadline -- peer_retire's other callers pass 0 -- so a sweep
     * that lost a peer to a broken stream or a closed session instead
     * lands here as a shortfall rather than passing as "they all went
     * away somehow". */
    ASSERT_EQ_INT(CHURN_PEERS, (int)cloak_udp_piper_peers_expired(&fx.pp));
    ASSERT_EQ_INT(CHURN_PEERS, (int)cloak_udp_piper_peers_created(&fx.pp));
    ASSERT_EQ_INT(fds_idle, count_open_fds());

    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ============ 9. the SESSION-WIDE pause, and its resume ================== */

/* The one backpressure this module applies to the SOCKET rather than to a
 * peer: when the session's outbound pool cannot hold one more worst-case
 * frame, reading the local socket has to stop for everybody, because
 * cloak_stream_write cannot fail on a full queue and an overrun surfaces
 * one layer down as a BROKEN CONNECTION -- which takes the pool, the
 * session and every peer with it.
 *
 * "The bytes eventually crossed" would pass against a piper that never
 * checked, so this asserts both halves: the pause happened (its counter
 * moved) and the session is still alive afterwards (it is not, if the
 * check is removed -- the connection breaks and every peer is retired).
 * Then it attaches the far end's socket, which drains the pool, and the
 * resume is asserted by a datagram sent AFTER the pause arriving at the
 * far end. */
static void test_pool_backpressure_pauses_the_socket_and_resumes(void) {
    static struct fixture fx;
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.peer_timeout_ms = 60000;
    /* conn_send_queue_cap 65536 and a 16401 wire: four worst-case frames
     * fit, so the pause arrives after the socketpair's own buffer has
     * filled and a handful more datagrams have queued -- tens of
     * datagrams, not thousands. */
    ASSERT_EQ_INT(0, fixture_init_ex(&fx, &pcfg, 16401, 65536, 65536, 0, 0));
    if (!fx.ready) {
        fixture_destroy(&fx);
        return;
    }
    char err[200] = {0};
    ASSERT_EQ_INT(0, cloak_udp_piper_open(&fx.pp, "127.0.0.1:0", err, sizeof(err)));
    int port = cloak_udp_piper_port(&fx.pp);
    ASSERT_TRUE(port > 0);

    struct peer p;
    memset(&p, 0, sizeof(p));
    p.fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_TRUE(p.fd >= 0);
    int rcv = 262144;
    setsockopt(p.fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    to.sin_port = htons((uint16_t)port);
    memcpy(&p.piper, &to, sizeof(to));
    p.piper_len = sizeof(to);

    static uint8_t big[16132];
    fill_pattern(big, sizeof(big), 0x90);
    /* One at a time with a turn each, so the piper actually reads them
     * rather than the kernel dropping them at a full receive buffer. */
    for (int i = 0; i < 60 && cloak_udp_piper_pool_pauses(&fx.pp) == 0; i++) {
        if (peer_send(&p, big, sizeof(big)) != 0) {
            break; /* our own socket refused -- pump and try again below */
        }
        pump_quiesce(fx.r, 100);
    }
    ASSERT_TRUE(cloak_udp_piper_pool_pauses(&fx.pp) > 0);
    /* THE SESSION SURVIVED THE PRESSURE. Without the check the connection
     * layer's own cap fires, the connection is marked broken, on_broken
     * runs and the peer is gone -- so this single assertion is what
     * separates "backpressure" from "overrun". */
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));

    /* THE RESUME. Attaching the far end drains the socketpair, which
     * drains the pool, which fires on_writable, which is the only thing
     * that can ever re-arm the socket -- a paused read has no readiness
     * edge left of its own. */
    ASSERT_EQ_INT(0, fixture_attach_far(&fx));
    struct pair_ctx pc = {&fx.far, 1};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_streams_at_least, &pc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    struct far_stream *fs = &fx.far.st[0];
    int before = 0;
    {
        struct count_ctx cc0 = {fs, 1};
        ASSERT_EQ_INT(1, pump_until(fx.r, far_count_at_least, &cc0, PUMP_MAX_TURNS, PUMP_TURN_MS));
        pump_quiesce(fx.r, 500);
        before = fs->count;
    }
    /* A datagram sent AFTER the pause: it can only arrive if the socket
     * is being read again. */
    uint8_t tail[128];
    fill_pattern(tail, sizeof(tail), 0x91);
    ASSERT_EQ_INT(0, peer_send(&p, tail, sizeof(tail)));
    struct count_ctx cc = {fs, before + 1};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_count_at_least, &cc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT(128, fs->lens[fs->count - 1 < FAR_MAX_DGRAMS ? fs->count - 1 : 0]);
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));

    close(p.fd);
    fixture_destroy(&fx);
}

/* ============ 10. the pool bound is the MINIMUM, not the aggregate ======= */

/* TWO CONNECTIONS, ONE OF THEM CONGESTED -- the only shape in which the
 * two candidate quantities differ, and the reason the module budgets off
 * cloak_session_send_min_conn_free rather than the aggregate free space.
 *
 * WHY THE AGGREGATE IS NOT MERELY LESS PRECISE. cloak_switchboard_send
 * hands each whole frame to ONE connection chosen uniformly at random,
 * not spread across the pool. With one congested connection among two,
 * the aggregate stays roomy (dominated by the clear one) right up until a
 * random pick lands on the congested one and its own per-connection cap
 * fires -- and that fires conn_mark_broken, which breaks the switchboard,
 * the session, and every peer on it. The cost of the wrong quantity is
 * therefore not a dropped datagram: it is the whole tunnel.
 *
 * THE CONDITION IS REACHABLE BY DEFAULT, which is why this is worth a
 * case rather than a comment. An omitted NumConn makes config_client.c
 * set singleplex, and singleplex is refused with UDP -- so every working
 * UDP configuration sets NumConn explicitly, and more than one connection
 * is the ordinary value.
 *
 * A review measured the gap: substituting the aggregate escaped all 72
 * tests in the tree. This case is what fails instead. */
static void test_pool_bound_is_the_minimum_connection_not_the_aggregate(void) {
    static struct fixture fx;
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.peer_timeout_ms = 60000;
    /* Both connections attached to the near session; the FIRST one's far
     * end is read normally (so the aggregate stays large), the second's
     * is never read (so the minimum collapses). */
    ASSERT_EQ_INT(0, fixture_init_ex(&fx, &pcfg, 16401, 65536, 65536, 1, 1));
    if (!fx.ready) {
        fixture_destroy(&fx);
        return;
    }
    ASSERT_EQ_INT(1, fx.have_conn2);

    char err[200] = {0};
    ASSERT_EQ_INT(0, cloak_udp_piper_open(&fx.pp, "127.0.0.1:0", err, sizeof(err)));
    int port = cloak_udp_piper_port(&fx.pp);
    ASSERT_TRUE(port > 0);

    struct peer p;
    memset(&p, 0, sizeof(p));
    p.fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_TRUE(p.fd >= 0);
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    to.sin_port = htons((uint16_t)port);
    memcpy(&p.piper, &to, sizeof(to));
    p.piper_len = sizeof(to);

    static uint8_t big[16132];
    fill_pattern(big, sizeof(big), 0xA0);
    for (int i = 0; i < 60 && cloak_udp_piper_pool_pauses(&fx.pp) == 0; i++) {
        if (peer_send(&p, big, sizeof(big)) != 0) {
            pump_quiesce(fx.r, 100);
            continue;
        }
        pump_quiesce(fx.r, 100);
    }

    /* THE PAUSE HAPPENED -- the minimum saw the congested connection
     * filling even while the aggregate stayed roomy. */
    ASSERT_TRUE(cloak_udp_piper_pool_pauses(&fx.pp) > 0);
    /* AND NOTHING BROKE. This is the assertion the aggregate bound fails:
     * it keeps writing until a random pick lands on the congested
     * connection with its queue over cap, which marks it broken, breaks
     * the session, and takes every peer with it. */
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));
    ASSERT_EQ_INT(0, cloak_session_is_closed(&fx.near_sesh));
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_peers_expired(&fx.pp));

    close(p.fd);
    fixture_destroy(&fx);
}

/* ============ 11. IPv6 peers are peers ================================== */

/* Case 1 with AF_INET6, because peer identity is family-aware code and
 * only the AF_INET half of it was exercised: making every IPv6 sender
 * compare equal escaped the whole suite.
 *
 * WHAT THIS CANNOT ASSERT, stated rather than implied: sin6_flowinfo's
 * deliberate EXCLUSION from a peer's identity. The kernel leaves
 * sin6_flowinfo zero in the address recvfrom reports unless the socket
 * asked for IPV6_RECVTCLASS/flowinfo, so a sender cannot vary it through
 * this interface and the exclusion is unobservable here -- measured, not
 * assumed (a probe in this image reported flowinfo 0 and scope 0 on a
 * ::1 datagram). What IS asserted is the rest: family, address, port. */
static void test_ipv6_peers_are_distinct_peers(void) {
    static struct fixture fx;
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.peer_timeout_ms = 60000;
    ASSERT_EQ_INT(0, fixture_init(&fx, &pcfg, 16401, 65536));
    if (!fx.ready) {
        fixture_destroy(&fx);
        return;
    }
    fx.far.echo = 1;

    char err[200] = {0};
    /* If this image had no IPv6 loopback the open would fail and the
     * assertion would name it, rather than the case quietly skipping --
     * a skip is how a family stops being covered without anyone noticing. */
    ASSERT_EQ_INT(0, cloak_udp_piper_open(&fx.pp, "[::1]:0", err, sizeof(err)));
    int port = cloak_udp_piper_port(&fx.pp);
    ASSERT_TRUE(port > 0);

    struct sockaddr_in6 to;
    memset(&to, 0, sizeof(to));
    to.sin6_family = AF_INET6;
    to.sin6_addr = in6addr_loopback;
    to.sin6_port = htons((uint16_t)port);

    struct peer a;
    struct peer b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    a.fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    b.fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_TRUE(a.fd >= 0 && b.fd >= 0);
    memcpy(&a.piper, &to, sizeof(to));
    a.piper_len = sizeof(to);
    b.piper = a.piper;
    b.piper_len = a.piper_len;

    uint8_t pa[64];
    uint8_t pb[64];
    fill_pattern(pa, sizeof(pa), 0x61);
    fill_pattern(pb, sizeof(pb), 0x62);
    ASSERT_EQ_INT(0, peer_send(&a, pa, sizeof(pa)));
    ASSERT_EQ_INT(0, peer_send(&b, pb, sizeof(pb)));

    struct pair_ctx pc = {&fx.far, 2};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_streams_at_least, &pc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT(2, (int)cloak_udp_piper_peer_count(&fx.pp));
    ASSERT_EQ_INT(2, fx.far.nstreams);
    /* Guarded so that an implementation which produced ONE stream fails
     * the assertion above and REPORTS it, rather than dereferencing a
     * NULL st[1].s: a crash costs a mutation battery every result after
     * this point, and this project has already recorded two tests that
     * segfault instead of asserting under mutation. */
    if (fx.far.nstreams == 2) {
        ASSERT_TRUE(fx.far.st[0].s->id != fx.far.st[1].s->id);
    }

    /* The same per-peer reply check case 1 makes: two v6 sockets on ::1
     * differ ONLY in their kernel-assigned port, so a reply arriving at
     * the wrong one is exactly what an identity that ignores the port
     * produces. */
    uint8_t got[128];
    long ga = -1;
    long gb = -1;
    uint64_t start = monotonic_ms();
    while (monotonic_ms() - start < 2000 && (ga < 0 || gb < 0)) {
        cloak_reactor_run_once(fx.r, 1);
        if (ga < 0) {
            ga = peer_recv(&a, got, sizeof(got));
            if (ga > 0) {
                ASSERT_EQ_INT(64, (int)ga);
                for (long i = 0; i < ga; i++) {
                    ASSERT_EQ_INT(pa[i] ^ 0xFF, got[i]);
                }
            }
        }
        if (gb < 0) {
            gb = peer_recv(&b, got, sizeof(got));
            if (gb > 0) {
                ASSERT_EQ_INT(64, (int)gb);
                for (long i = 0; i < gb; i++) {
                    ASSERT_EQ_INT(pb[i] ^ 0xFF, got[i]);
                }
            }
        }
    }
    ASSERT_EQ_INT(64, (int)ga);
    ASSERT_EQ_INT(64, (int)gb);
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_dropped_datagrams(&fx.pp));

    close(a.fd);
    close(b.fd);
    fixture_destroy(&fx);
}

/* ============ 12. a hard sendto error discards ONE datagram ============== */

/* THE POLICY, WHICH WAS DECIDED IN CODE AND ASSERTED NOWHERE: a sendto
 * that fails with something other than EAGAIN cannot be retried for THAT
 * datagram, so the datagram is discarded and the peer is KEPT -- bounded
 * by its deadline like any other. A review's mutation that retired the
 * peer instead escaped the whole suite, which means either behaviour
 * would have shipped.
 *
 * KEEPING IT IS THE RIGHT CALL because the error belongs to a datagram,
 * not to the flow: an AF_UNIX peer that closed and re-bound, an ICMP
 * report on a connected socket, a datagram larger than the send buffer.
 * A peer that has gone for good is retired by the deadline anyway, which
 * is the same bound every other wedged peer gets -- so keeping it costs a
 * slot for at most one timeout and never leaks one.
 *
 * ECONNREFUSED from an AF_UNIX datagram send to a name whose socket is
 * gone is the reproducible instance: measured in this image at errno 111. */
static void test_hard_send_error_discards_the_datagram_and_keeps_the_peer(void) {
    static struct fixture fx;
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.peer_timeout_ms = 200;
    ASSERT_EQ_INT(0, fixture_init(&fx, &pcfg, 16401, 65536));
    if (!fx.ready) {
        fixture_destroy(&fx);
        return;
    }
    struct sockaddr_storage piper_addr;
    socklen_t piper_len;
    int piper_fd = make_unix_dgram(&piper_addr, &piper_len, "hard-p", 0);
    ASSERT_TRUE(piper_fd >= 0);
    ASSERT_EQ_INT(0, cloak_udp_piper_adopt(&fx.pp, piper_fd));

    struct peer p;
    memset(&p, 0, sizeof(p));
    p.fd = make_unix_dgram(&p.me, &p.me_len, "hard-c", 0);
    ASSERT_TRUE(p.fd >= 0);
    p.piper = piper_addr;
    p.piper_len = piper_len;

    uint8_t msg[32];
    fill_pattern(msg, sizeof(msg), 0xC1);
    ASSERT_EQ_INT(0, peer_send(&p, msg, sizeof(msg)));
    struct pair_ctx pc = {&fx.far, 1};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_streams_at_least, &pc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));

    /* The peer's socket goes away, so its abstract name no longer exists
     * and every sendto to it fails with ECONNREFUSED -- permanently, for
     * this address. */
    close(p.fd);
    p.fd = -1;

    struct far_stream *fs = &fx.far.st[0];
    uint8_t reply[64];
    fill_pattern(reply, sizeof(reply), 0xC2);
    ASSERT_EQ_INT(64, (int)cloak_stream_write(fs->s, reply, sizeof(reply)));
    pump_quiesce(fx.r, 300);

    /* DISCARDED, NOT RETRIED: this is not backpressure, so no stall was
     * counted and no retry timer is running. */
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_send_stalls(&fx.pp));
    /* AND THE PEER IS STILL HERE. */
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_peers_expired(&fx.pp));
    ASSERT_EQ_INT(0, fs->closed);

    /* ...and is bounded by the ordinary deadline rather than kept
     * forever, which is what makes "keep the peer" safe. */
    struct peers_ctx gone = {&fx.pp, 0};
    ASSERT_EQ_INT(1, pump_until(fx.r, peer_count_is, &gone, 3000, 1));
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peers_expired(&fx.pp));

    fixture_destroy(&fx);
}

/* ============ 7. the write-side hazard in cloak_stream_relay_t =========== */

/* NOT THIS MODULE'S OBJECT, BUT THIS TASK'S DISPATCH, and it lives here
 * rather than in libcloak-mux/tests/test_stream_relay.c only because a
 * sibling's fix to the READ side of that same file is in flight and two
 * agents editing one test file is how a fix round loses an assertion.
 *
 * THE HAZARD: STREAM_RELAY_CHUNK is 16384 and an unordered stream refuses
 * any write over max_payload_per_frame, which is 16132 at the shipping
 * 16401. cloak_stream_relay_t treats every negative from
 * cloak_stream_write as fatal, so before this task a TCP local connection
 * spliced onto an UNORDERED session would be KILLED by its own first
 * large read -- silently, and only once a peer sent more than 16132 bytes
 * in one go. Nothing reached it before module 9 because no session was
 * ever unordered.
 *
 * Resolved by clamping the relay's read budget to one frame's payload in
 * unordered mode, which leaves the ordered path byte-for-byte unchanged.
 * This case is what pins it: it fails with the relay torn down and zero
 * bytes delivered if the clamp is removed. */
struct relay_done_ctx {
    int calls;
};

static void on_relay_done(cloak_stream_relay_t *sr, void *userdata) {
    (void)sr;
    struct relay_done_ctx *c = userdata;
    c->calls++;
}

static void test_relay_read_budget_respects_the_unordered_write_limit(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    int conn[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, conn));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    static struct far_end near;
    static struct far_end far;
    memset(&near, 0, sizeof(near));
    memset(&far, 0, sizeof(far));
    cloak_session_config_t near_cfg;
    cloak_session_config_t far_cfg;
    fill_far_config(&near_cfg, &near, &obfs, 16401, 65536);
    fill_far_config(&far_cfg, &far, &obfs, 16401, 65536);
    ASSERT_EQ_INT(0, cloak_session_init(&near.sesh, 1, r, &near_cfg));
    ASSERT_EQ_INT(0, cloak_session_init(&far.sesh, 1, r, &far_cfg));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&near.sesh, conn[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&far.sesh, conn[1]));

    cloak_stream_t *s = cloak_session_open_stream(&near.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    int sp[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
    int flags = fcntl(sp[1], F_GETFL, 0);
    ASSERT_EQ_INT(0, fcntl(sp[1], F_SETFL, flags | O_NONBLOCK));

    struct relay_done_ctx done;
    memset(&done, 0, sizeof(done));
    cloak_stream_relay_t sr;
    ASSERT_EQ_INT(0, cloak_stream_relay_start(&sr, r, &near.sesh, s, sp[0], 16384, on_relay_done,
                                              &done));

    /* 16384 bytes in one go: more than 16132, which is exactly the read
     * the unclamped budget would have taken and the write that would have
     * been refused. */
    static uint8_t out[16384];
    for (size_t i = 0; i < sizeof(out); i++) {
        out[i] = (uint8_t)(i * 7u + 3u);
    }
    /* ONE write(2) into an empty socketpair, asserted complete: a
     * partial write would let the relay read the remainder on a later
     * turn and the datagram boundaries below would then say nothing about
     * the budget. AF_UNIX stream socketpairs hold ~200 KiB, so 16 KiB
     * goes in one call or the assertion names it. */
    ssize_t w = write(sp[1], out, sizeof(out));
    ASSERT_EQ_INT((int)sizeof(out), (int)w);

    struct pair_ctx pc = {&far, 1};
    ASSERT_EQ_INT(1, pump_until(r, far_streams_at_least, &pc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    struct far_stream *fs = &far.st[0];

    /* Everything arrives, as TWO datagrams -- 16132 and 252 -- because an
     * unordered stream cannot split a write and the relay must therefore
     * stop asking for more than one frame's worth at a time. */
    struct count_ctx cc = {fs, 2};
    ASSERT_EQ_INT(1, pump_until(r, far_count_at_least, &cc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT(2, fs->count);
    ASSERT_EQ_INT(16132, fs->lens[0]);
    ASSERT_EQ_INT(252, fs->lens[1]);
    ASSERT_EQ_INT(0, fs->closed);
    /* The relay is alive: the refusal never happened. */
    ASSERT_EQ_INT(0, done.calls);

    cloak_stream_relay_stop(&sr);
    close(sp[1]);
    cloak_session_release_stream(&far.sesh, fs->s);
    cloak_session_release_stream(&near.sesh, s);
    cloak_session_destroy(&near.sesh);
    cloak_session_destroy(&far.sesh);
    cloak_reactor_destroy(r);
}

/* ============ 8. the wiring: `udp` selects THIS listener ================ */

/* cloak_client_stack_open is the supported way a binary assembles a
 * client, and before this task it gave a `udp` client an UNORDERED
 * session behind a TCP local listener -- which is not a UDP tunnel at
 * all, and which is also the one configuration that could reach the
 * cloak_stream_relay_t hazard case 7 pins.
 *
 * THE ASSERTION IS AN INVERSION, not a presence check. Binding the local
 * port as UDP must FAIL (the stack holds it) and the stack's own socket
 * must NOT be a stream socket (it does not hold the port as TCP). A
 * wiring that still opened a TCP listener passes neither half; a test
 * that only checked cloak_client_stack_local_port > 0 passes both
 * wirings. The UDP half is genuinely a question about OUR OWN socket: if
 * anyone else held this exact port as UDP, our own open() could not have
 * claimed it, so there is no third party to race against, and the probe
 * socket deliberately does NOT set SO_REUSEADDR (Linux lets two UDP
 * sockets share an address only when both ask to). The TCP half is NOT
 * checked by attempting a TCP bind at the same port number -- ephemeral
 * port ranges are shared ACROSS protocol families by the kernel, so any
 * concurrent process (another test in this same ctest run) can be
 * holding that number as TCP for reasons that have nothing to do with
 * us, and such a probe can fail even when our listener is correctly a
 * datagram socket. Instead it asks the stack's own descriptor what it
 * is, via cloak_client_stack_local_is_datagram (getsockopt(SO_TYPE)
 * underneath), which is decided by our fd alone and cannot be perturbed
 * by any other process holding any port number. */
static void test_stack_udp_mode_binds_a_datagram_socket(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_client_config_t c;
    memset(&c, 0, sizeof(c));
    snprintf(c.server_name, sizeof(c.server_name), "www.example.com");
    snprintf(c.proxy_method, sizeof(c.proxy_method), "ss");
    c.encryption_method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(c.uid, CLOAK_UID_LEN);
    cloak_random_bytes(c.server_pub_key, CLOAK_X25519_KEY_LEN);
    c.num_conn = 1;
    snprintf(c.local_host, sizeof(c.local_host), "127.0.0.1");
    snprintf(c.local_port, sizeof(c.local_port), "0");
    snprintf(c.remote_host, sizeof(c.remote_host), "127.0.0.1");
    /* Port 1: nothing is listening, so round 1 fails on the ladder. This
     * case is about what was BOUND locally, which open has already done
     * by the time it returns. */
    snprintf(c.remote_port, sizeof(c.remote_port), "1");
    c.browser = CLOAK_BROWSER_CHROME;
    c.transport = CLOAK_TRANSPORT_DIRECT;
    c.stream_timeout_sec = 300;
    c.keep_alive_sec = -1;
    c.udp = 1;

    cloak_client_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.reactor = r;
    sc.config = &c;
    sc.max_rounds = 1;

    char err[256] = {0};
    cloak_client_stack_t *st = NULL;
    ASSERT_EQ_INT(0, cloak_client_stack_open(&st, &sc, err, sizeof(err)));
    ASSERT_TRUE(st != NULL);
    if (st == NULL) {
        cloak_reactor_destroy(r);
        return;
    }
    int port = cloak_client_stack_local_port(st);
    ASSERT_TRUE(port > 0);

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);

    int u = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_TRUE(u >= 0);
    ASSERT_TRUE(bind(u, (struct sockaddr *)&a, sizeof(a)) != 0); /* the stack holds it, as UDP */
    close(u);

    /* NOT a TCP bind probe at this port number: see this test's opening
     * comment for why that would be racing every other process on the
     * machine instead of testing our own socket. Ask the stack's own fd
     * directly. */
    ASSERT_EQ_INT(1, cloak_client_stack_local_is_datagram(st));

    /* No peer has spoken, so both local counters are zero -- and in this
     * mode they are the same number, because a UDP peer opens its stream
     * with its first datagram and has no D6 window to sit in. */
    ASSERT_EQ_INT(0, (int)cloak_client_stack_local_conns(st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_local_streams(st));

    cloak_client_stack_close(st);

    /* AND THE COMBINATION THAT IS NOT IMPLEMENTED IS REFUSED BY NAME,
     * rather than silently sharing one session where the user asked for
     * one per flow. */
    cloak_client_config_t sp = c;
    sp.singleplex = 1;
    sc.config = &sp;
    st = NULL;
    err[0] = '\0';
    ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_CONFIG,
                  cloak_client_stack_open(&st, &sc, err, sizeof(err)));
    ASSERT_TRUE(st == NULL);
    ASSERT_TRUE(strstr(err, "singleplex") != NULL);

    cloak_reactor_destroy(r);
}

struct dgram_wait {
    const cloak_udp_piper_t *pp;
    int want;
};

static int piper_read_at_least(void *ctx) {
    struct dgram_wait *w = ctx;
    return (int)cloak_udp_piper_datagrams_read(w->pp) >= w->want;
}

/* ============ 13. THE PER-TURN READ BUDGET ============================== */

/* THE HAZARD THIS CLOSES, and why it only becomes one now. Until the
 * refusal in cmd/ck-client/main.c was lifted, nothing in a shipped binary
 * could reach piper_pump_read at all. It is now the client's whole local
 * endpoint, shared by every peer, and its read loop had exactly two
 * exits: EAGAIN, and the pool check.
 *
 * NEITHER BOUNDS A TURN.
 *
 *  - The pool check only fires when the session's outbound queue is
 *    backing up. On loopback, and on any healthy link, every frame this
 *    loop produces is handed to a connection that accepts it immediately,
 *    so min_conn_free never falls and the loop runs until the socket is
 *    dry -- however much a peer put there.
 *  - Worse, the datagrams that are DROPPED rather than sent -- oversized,
 *    empty, or from a source the peer map refuses -- cost the pool
 *    nothing at all, so a flood of them is unbounded no matter how
 *    congested the session is.
 *
 * One busy peer can therefore hold the reactor turn, and everything else
 * this process owns -- the other peers' send timers, the peer deadlines,
 * the connection pool's own readiness -- waits behind it. Task 5's
 * implementer asked for this budget before task 7 put the module in front
 * of real traffic, which is this commit.
 *
 * THE NUMBER IS A LITERAL HERE, derived by hand from the 32 in
 * udp_piper.c rather than spelled as that symbol: a bound written in
 * terms of the constant it is testing moves with a mutation to it instead
 * of catching it (this file's ladder cases make the same argument). 40 is
 * sent, so the remainder is 8 -- enough that "all of them arrived" cannot
 * be confused with "the budget happens to be 40".
 *
 * WHAT EACH ASSERTION KILLS:
 *   - no budget at all: the first turn reads all 40, so `32` fails.
 *   - a budget that does not re-arm the socket (a `read_paused = 1` on
 *     the way out, say): the remaining 8 never arrive, because a paused
 *     read has no readiness edge left of its own and only on_writable
 *     resumes it -- and the pool never backed up, so on_writable never
 *     fires. The second wait fails.
 *   - a budget applied only to datagrams that were actually SENT: this
 *     case's datagrams all are, so it would survive here -- which is why
 *     the counter is incremented at the recvfrom and not at the write,
 *     and why that placement is stated in udp_piper.c rather than left to
 *     be inferred. */
static void test_the_read_loop_yields_after_its_budget(void) {
    static struct fixture fx;
    cloak_udp_piper_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.peer_timeout_ms = 60000;
    /* The default conn_send_queue_cap (262144) against a 16401 wire: the
     * pool can hold fifteen worst-case frames and these datagrams are
     * eight bytes each, so the pool check cannot be what stops the loop.
     * Asserted below rather than assumed. */
    ASSERT_EQ_INT(0, fixture_init_ex(&fx, &pcfg, 16401, 65536, 0, 1, 0));
    if (!fx.ready) {
        fixture_destroy(&fx);
        return;
    }
    char err[200] = {0};
    ASSERT_EQ_INT(0, cloak_udp_piper_open(&fx.pp, "127.0.0.1:0", err, sizeof(err)));
    int port = cloak_udp_piper_port(&fx.pp);
    ASSERT_TRUE(port > 0);

    struct peer p;
    memset(&p, 0, sizeof(p));
    p.fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_TRUE(p.fd >= 0);
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    to.sin_port = htons((uint16_t)port);
    memcpy(&p.piper, &to, sizeof(to));
    p.piper_len = sizeof(to);

    /* Forty small datagrams, queued in the piper's socket BEFORE the
     * reactor is touched: eight bytes each is around 30 KiB of kernel
     * accounting against a default 208 KiB receive buffer, so none is
     * dropped -- which the final count asserts rather than assumes. */
    uint8_t d[8];
    for (int i = 0; i < 40; i++) {
        fill_pattern(d, sizeof(d), (uint8_t)(0x50 + i));
        ASSERT_EQ_INT(0, peer_send(&p, d, sizeof(d)));
    }

    /* ONE TURN. cloak_reactor_run_once dispatches each ready descriptor
     * once, so this is exactly one entry into piper_pump_read. */
    ASSERT_TRUE(cloak_reactor_run_once(fx.r, 100) > 0);
    ASSERT_EQ_INT(32, (int)cloak_udp_piper_datagrams_read(&fx.pp));
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_read_yields(&fx.pp));
    /* The loop stopped on the BUDGET and not on the pool, which is the
     * difference between this case and case 9. */
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_pool_pauses(&fx.pp));

    /* AND THE REST ARRIVE, with nothing further sent by the peer: the
     * yield re-arms the socket, so the readiness this turn did not
     * consume is redelivered. */
    struct dgram_wait dw = {&fx.pp, 40};
    ASSERT_EQ_INT(1, pump_until(fx.r, piper_read_at_least, &dw, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT(40, (int)cloak_udp_piper_datagrams_read(&fx.pp));
    /* Exactly one yield: 40 = 32 + 8, and the second pass had eight left. */
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_read_yields(&fx.pp));
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));

    /* All forty reached the far end, in order and whole -- so the budget
     * costs datagrams nothing, which is the other half of the claim. */
    struct pair_ctx pc = {&fx.far, 1};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_streams_at_least, &pc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    struct count_ctx cc = {&fx.far.st[0], 40};
    ASSERT_EQ_INT(1, pump_until(fx.r, far_count_at_least, &cc, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT(40, fx.far.st[0].count);
    for (int i = 0; i < 40; i++) {
        ASSERT_EQ_INT(0x50 + i, fx.far.st[0].seqs[i]);
        ASSERT_EQ_INT(8, fx.far.st[0].lens[i]);
    }

    /* ---- AND THE PLACEMENT, which is the half the first phase cannot
     * see. Every datagram above was FORWARDED, so a budget spent just
     * before cloak_stream_write instead of at the recvfrom would have
     * behaved identically -- and that is not a hypothetical: an
     * independent reviewer made exactly that edit and all 73 tests
     * passed. udp_piper.c and cloak/udp_piper.h both argue that counting
     * at the recvfrom, ahead of every `continue`, "is the whole of the
     * budget's usefulness"; until this phase existed, nothing tested the
     * claim.
     *
     * FORTY ZERO-LENGTH DATAGRAMS, which the module swallows (Go does
     * too) without ever reaching a write and without costing the outbound
     * pool a single byte. That is the flood the argument is about: with
     * the budget spent at the write it is bounded by NOTHING, and one
     * peer drains the whole socket in one reactor turn however much it
     * put there.
     *
     * Zero-length rather than oversized because it needs no buffer: forty
     * empty datagrams cannot be lost to a full receive queue, so the
     * exact counts below are counts and not a lower bound. */
    for (int i = 0; i < 40; i++) {
        ASSERT_EQ_INT(0, peer_send(&p, d, 0));
    }
    uint64_t read_before = cloak_udp_piper_datagrams_read(&fx.pp);
    uint64_t yields_before = cloak_udp_piper_read_yields(&fx.pp);
    ASSERT_EQ_INT(40, (int)read_before);
    ASSERT_TRUE(cloak_reactor_run_once(fx.r, 100) > 0);
    /* EXACTLY 32 MORE in that one turn, and one more yield. With the
     * increments moved to the write site both numbers stand still --
     * read_before + 0 and yields_before + 0 -- because not one of these
     * datagrams reaches a write, and all forty are consumed in the single
     * turn instead of thirty-two. */
    ASSERT_EQ_INT((int)read_before + 32, (int)cloak_udp_piper_datagrams_read(&fx.pp));
    ASSERT_EQ_INT((int)yields_before + 1, (int)cloak_udp_piper_read_yields(&fx.pp));
    ASSERT_EQ_INT(32, (int)cloak_udp_piper_empty_datagrams(&fx.pp));
    /* Still the budget and still not the pool: an empty datagram queues
     * nothing, so this number cannot have moved. */
    ASSERT_EQ_INT(0, (int)cloak_udp_piper_pool_pauses(&fx.pp));

    /* The remaining eight arrive on later turns, so a yield on a stream
     * of dropped datagrams re-arms exactly as one on a stream of
     * forwarded datagrams does. */
    struct dgram_wait dw2 = {&fx.pp, (int)read_before + 40};
    ASSERT_EQ_INT(1, pump_until(fx.r, piper_read_at_least, &dw2, PUMP_MAX_TURNS, PUMP_TURN_MS));
    ASSERT_EQ_INT(40, (int)cloak_udp_piper_empty_datagrams(&fx.pp));
    /* And the peer is untouched by any of it: an empty datagram from a
     * KNOWN sender refreshes its deadline and nothing more. */
    ASSERT_EQ_INT(1, (int)cloak_udp_piper_peer_count(&fx.pp));
    ASSERT_EQ_INT(40, fx.far.st[0].count);

    close(p.fd);
    fixture_destroy(&fx);
}

TEST_MAIN_BEGIN()
test_two_peers_two_streams_no_crossing();
test_datagram_backpressure_mechanism();
test_slow_peer_does_not_stall_fast_peer();
test_full_queue_drops_the_newest_and_counts();
test_wedged_peer_is_still_retired_by_the_deadline();
test_silent_peer_is_retired_after_the_deadline();
test_sizes_are_carried_whole();
test_the_size_limit_follows_the_session();
test_peer_map_holds_its_cap_under_churn();
test_churned_peers_all_expire();
test_pool_backpressure_pauses_the_socket_and_resumes();
test_pool_bound_is_the_minimum_connection_not_the_aggregate();
test_ipv6_peers_are_distinct_peers();
test_hard_send_error_discards_the_datagram_and_keeps_the_peer();
test_relay_read_budget_respects_the_unordered_write_limit();
test_stack_udp_mode_binds_a_datagram_socket();
test_the_read_loop_yields_after_its_budget();
TEST_MAIN_END()
