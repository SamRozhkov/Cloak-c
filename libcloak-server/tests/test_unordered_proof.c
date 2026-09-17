#define _POSIX_C_SOURCE 200809L

/* UNORDERED (DATAGRAM) MODE, PROVED -- INCLUDING THE PARTS NO ORACLE CAN SEE.
 *
 * WHY THIS FILE EXISTS, AND WHY IT IS FIVE CASES AND NOT TWO.
 *
 * Module 8 discovered, on its first contact with real Go, that this port
 * could not exchange a single data frame with the implementation it is a
 * port of: two header bytes went into the AEAD as associated data where
 * Go passes nil. Every round-trip test in the tree passed, because both
 * ends of every one of them were our own code and two copies of one
 * mistake always agree. Module 9 built unordered mode -- the whole reason
 * `-u` exists -- and until this file NOTHING asserted that a datagram
 * crosses a Cloak tunnel at all, in either role, against anybody's
 * implementation but ours.
 *
 * So case 1 is the oracle. But an oracle is blind to three things that
 * this module could get catastrophically wrong while every interop test
 * stayed green, and cases 2-5 are those three things:
 *
 *   1. THE MODE ITSELF DOES NOTHING OBSERVABLE OVER LOOPBACK. Module 9's
 *      task 7 review measured this directly: an ORDERED client session
 *      under an UNORDERED server session carried its datagram byte for
 *      byte, with attach_count, created_count, local_conns, local_streams
 *      and the whole fd census matching. Over loopback with NumConn 4,
 *      frames essentially never arrive out of order, so the two modes are
 *      observationally identical and a round-trip test cannot tell them
 *      apart. Case 2 SYNTHESISES the reordering, which is the only way
 *      anything in this module proves the mode does something.
 *
 *   2. `Seq` IS STILL GENERATED, STILL MONOTONIC, AND STILL HALF THE AEAD
 *      NONCE -- the unordered RECEIVER simply ignores it. Pinning seq = 0
 *      as an "obvious simplification" for a mode that does no reassembly
 *      is silent GCM NONCE REUSE (cloak_frame_obfuscate's nonce is
 *      buf[0:12] == stream_id || seq), and every single round-trip test
 *      in this tree, and both halves of case 1, pass under it. Case 3 is
 *      the assertion that does not.
 *
 *   3. DISTRIBUTIONS. Module 8 found FOUR distribution biases no interop
 *      test could see, one of which made sixteen of 240 padding lengths
 *      twice as likely -- on the wire, in the padding whose stated purpose
 *      in Go's own comment is defeating a size side channel. Case 4 pins
 *      the pad/no-pad boundary and the padding-length distribution IN
 *      UNORDERED MODE, and measures the switchboard's connection pick,
 *      which module 9's plan flagged for measurement and never measured.
 *
 * Case 5 closes an item task 3 explicitly deferred here: it asserted the
 * duplicate/late-frame policy at cloak_stream_feed_frame's RETURN VALUE,
 * and named "a frame-replaying middle-box harness" as what would drive it
 * through a live session instead. This is that harness.
 *
 * WHAT CASE 1 MUST COMPARE, AND THE TRAP IT WOULD OTHERWISE WALK INTO.
 * Measured twice in this module: GO REORDERS RATHER THAN DROPS. Task 1's
 * review forced the unordered flag on and found ALL THREE byte counts
 * identical, with only the content comparison failing. Task 7's review
 * reproduced it inside our own code. A size-only assertion is GREEN on
 * exactly the corruption these cases exist to catch, so every probe here
 * compares CONTENT, and the upstream XORs rather than echoes so that a
 * tunnel which carried nothing and looped the application's own bytes
 * back cannot satisfy it either.
 *
 * THE SIZE POLICY (the plan's D7), where fidelity and correctness part
 * company on purpose, and which case 1 turns into exact numbers:
 *
 *   > 16132 outbound    refused, nothing on the wire. Same as Go.
 *   8193..16132         CARRIED. Go loses it AND tears the peer's stream
 *                       down (bug 6) -- reproduced here at the real
 *                       binaries by the amplifying-upstream probe.
 *   > 8192 read locally  READ WHOLE. Go truncates to 8192 (bug 7) --
 *                       measured here as an exact received length.
 *   zero-length         SWALLOWED, matching Go: its frame encoder refuses
 *                       an empty payload outright and so does ours.
 *
 * EVERY WAIT IN THIS FILE IS BOUNDED BY CLOCK_MONOTONIC, never by an
 * iteration count, and the Go binaries are checked for BEFORE any case
 * runs so a missing oracle is a named failure in milliseconds.
 *
 * THE SUBPROCESS PLUMBING BELOW (child_spawn/child_drain/child_reap,
 * free_port/listen_on/dial, write_temp_unique, derive_keys) IS COPIED
 * FROM test_go_interop.c RATHER THAN SHARED. That file's rules are that
 * it passes UNMODIFIED, and hoisting its statics into a header is a
 * modification. Everything above the copied layer differs anyway: this
 * file's relay CAPTURES and its "application" and "upstream" are datagram
 * sockets, not stream ones. Where a comment there recorded a measurement
 * (mkstemp's uniqueness, the logrus signature) the measurement is cited
 * here rather than re-derived. */

#include "cloak/base64.h"
#include "cloak/clienthello_parse.h"
#include "cloak/common.h"
#include "cloak/crypto.h"
#include "cloak/frame.h"
#include "cloak/ordering.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "cloak/switchboard.h"
#include "test_framework.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef CK_SERVER_PATH
#error "CK_SERVER_PATH must be defined by the build"
#endif
#ifndef CK_CLIENT_PATH
#error "CK_CLIENT_PATH must be defined by the build"
#endif
#ifndef GO_CK_SERVER_PATH
#error "GO_CK_SERVER_PATH must be defined by the build"
#endif
#ifndef GO_CK_CLIENT_PATH
#error "GO_CK_CLIENT_PATH must be defined by the build"
#endif

/* ------------------------------------------------------------------ */
/* Sizes that are protocol, not taste                                  */
/* ------------------------------------------------------------------ */

/* Go's MsgOnWireSizeLimit and this port's
 * CLOAK_CLIENT_STACK_DEFAULT_MAX_ON_WIRE_SIZE / its server twin, so
 * max_payload_per_frame is Go's maxStreamUnitWrite exactly. */
#define MAX_ON_WIRE 16401u
#define MAX_DGRAM   (MAX_ON_WIRE - CLOAK_FRAME_HEADER_LEN - CLOAK_FRAME_MAX_EXTRA_LEN) /* 16132 */

/* internal/client/piper.go: RouteUDP's `data := make([]byte, 8192)` and
 * its reader goroutine's `buf := make([]byte, 8192)`. Both bugs 6 and 7
 * are this one number. READ FROM GO'S SOURCE, and then MEASURED by case
 * 1's role A, whose expected received lengths are min(sent, this). */
#define GO_UDP_BUF 8192u

/* ------------------------------------------------------------------ */
/* Budgets. Every one is set from the worst FAILING run.                */
/* ------------------------------------------------------------------ */

#define OUT_CAP 65536
#define BOOT_MS 15000
#define EXIT_MS 5000

/* One probe's round trip. MEASURED in Debug: the nine-probe ladder,
 * including the 16132-byte probe, takes 92 ms in the Go-client role and
 * 790 ms in ours -- and 700 ms of the latter is the deliberate quiet
 * window for the refused 16133-byte datagram, so a healthy probe is a
 * handful of milliseconds. A BROKEN one -- the shape of the defect this
 * file exists to catch -- never completes, and there are twelve probes
 * per role, so this bound times the probe count is what has to fit in the
 * ctest TIMEOUT. 2000 is a ~400x margin over the healthy figure and caps
 * a wholly dead role's probes at 24 s. A 15 s budget, which is what
 * test_go_interop.c uses for its ONE transfer, would have put the nine
 * ladder probes alone past any sane timeout. */
#define PROBE_MS 2000

/* How long a datagram that MUST NOT arrive is waited for. Three of these
 * per role (the refused oversize, the zero-length, the amplified reply),
 * so it is deliberately the smallest window that is still an order of
 * magnitude above the measured healthy round trip. */
#define QUIET_MS 700

/* ------------------------------------------------------------------ */
/* Clock                                                               */
/* ------------------------------------------------------------------ */

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ------------------------------------------------------------------ */
/* Subprocess plumbing (copied -- see the file header)                  */
/* ------------------------------------------------------------------ */

typedef struct {
    pid_t pid;
    int fd;
    char out[OUT_CAP];
    size_t out_len;
} child_t;

static void close_inherited_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) {
        return;
    }
    int keep = dirfd(d);
    int doomed[256];
    size_t n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < sizeof(doomed) / sizeof(doomed[0])) {
        int fd = atoi(e->d_name);
        if (fd > STDERR_FILENO && fd != keep) {
            doomed[n++] = fd;
        }
    }
    closedir(d);
    for (size_t i = 0; i < n; i++) {
        close(doomed[i]);
    }
}

static int child_spawn(child_t *c, const char *path, char *const argv[]) {
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close_inherited_fds();
        execv(path, argv);
        _exit(127);
    }
    close(pipefd[1]);
    c->pid = pid;
    c->fd = pipefd[0];
    return 0;
}

static int child_drain(child_t *c, int wait_ms) {
    if (c->fd < 0) {
        return 1;
    }
    struct pollfd p;
    p.fd = c->fd;
    p.events = POLLIN;
    int rc = poll(&p, 1, wait_ms);
    if (rc <= 0) {
        return 0;
    }
    if (c->out_len + 1 >= sizeof(c->out)) {
        return 0;
    }
    ssize_t got = read(c->fd, c->out + c->out_len, sizeof(c->out) - c->out_len - 1);
    if (got > 0) {
        c->out_len += (size_t)got;
        c->out[c->out_len] = '\0';
        return 0;
    }
    if (got == 0) {
        return 1;
    }
    return (errno == EAGAIN || errno == EINTR) ? 0 : 1;
}

static int child_reap(child_t *c, int timeout_ms) {
    if (c->pid <= 0) {
        return -1;
    }
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        int status = 0;
        pid_t r = waitpid(c->pid, &status, WNOHANG);
        if (r == c->pid) {
            while (child_drain(c, 10) == 0 && now_ms() < deadline) {
                /* flush the tail */
            }
            if (c->fd >= 0) {
                close(c->fd);
            }
            c->fd = -1;
            c->pid = 0;
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        }
        if (now_ms() >= deadline) {
            kill(c->pid, SIGKILL);
            waitpid(c->pid, &status, 0);
            if (c->fd >= 0) {
                close(c->fd);
            }
            c->fd = -1;
            c->pid = 0;
            return -1;
        }
        child_drain(c, 20);
    }
}

static void child_stop(child_t *c) {
    if (c->pid <= 0) {
        if (c->fd >= 0) {
            close(c->fd);
            c->fd = -1;
        }
        return;
    }
    kill(c->pid, SIGTERM);
    (void)child_reap(c, EXIT_MS);
}

/* ------------------------------------------------------------------ */
/* Sockets                                                             */
/* ------------------------------------------------------------------ */

static int free_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(a);
    if (getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
        close(fd);
        return -1;
    }
    int port = ntohs(a.sin_port);
    close(fd);
    return port;
}

static int listen_on(int *port_out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(a);
    if (getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(a.sin_port);
    return fd;
}

static int dial(int port) {
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

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* A bound, non-blocking UDP socket on loopback.
 *
 * THE RECEIVE BUFFER IS RAISED DELIBERATELY. The largest probe here is
 * 16132 bytes and the bug-6 probe puts an 8193-byte reply in flight while
 * an earlier one may still be queued; a default rmem on a loaded host is
 * ample, but a datagram lost to a full socket buffer would be reported as
 * "the tunnel dropped it", which is the single most misleading failure
 * this file can produce. Best effort: a kernel that refuses the option is
 * left alone, since nothing here depends on the larger value. */
static int udp_socket(int *port_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    int buf = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(a);
    if (getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
        close(fd);
        return -1;
    }
    if (port_out != NULL) {
        *port_out = ntohs(a.sin_port);
    }
    set_nonblock(fd);
    return fd;
}

/* ------------------------------------------------------------------ */
/* Payloads                                                             */
/* ------------------------------------------------------------------ */

static void fill_payload(uint8_t *buf, size_t len, uint32_t seed) {
    uint32_t x = seed;
    for (size_t i = 0; i < len; i++) {
        x = x * 1103515245u + 12345u;
        buf[i] = (uint8_t)(x >> 16);
    }
}

/* ================================================================== */
/* PART ONE: THE GO ORACLE, IN UDP MODE                                */
/* ================================================================== */

#define MAX_PAIRS 8
#define QCAP 65536
#define HELLO_CAP 8192
/* Per relayed connection, per direction, in the CLIENT -> SERVER
 * direction only. Case 1's role B puts ~58 KiB of application payload
 * through one stream; 192 KiB leaves room for the frame overheads and the
 * handshake and is still only 1.5 MiB of static storage across MAX_PAIRS.
 * A capture that fills simply stops growing -- case 3 reports how many
 * records it parsed, so a truncated capture is visible rather than silent. */
#define CAP_C2S (192u * 1024u)
/* Only the ServerHello is ever needed from the other direction. Its record
 * is 127 bytes; 256 covers it with room for the relay's read boundaries
 * to fall anywhere. */
#define CAP_S2C 256u

typedef struct {
    uint8_t buf[QCAP];
    size_t len;
    size_t off;
} q_t;

static size_t q_pending(const q_t *q) { return q->len - q->off; }

static int q_flush(q_t *q, int fd) {
    while (q->off < q->len) {
        ssize_t w = write(fd, q->buf + q->off, q->len - q->off);
        if (w > 0) {
            q->off += (size_t)w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            return 0;
        }
        return -1;
    }
    q->len = 0;
    q->off = 0;
    return 0;
}

typedef struct {
    int cfd;
    int sfd;
    q_t c2s;
    q_t s2c;
    uint64_t s2c_total;
    /* Everything the client sent, up to CAP_C2S: the ClientHello record
     * and then every data record. Case 3 deobfuscates it. */
    uint8_t cap_c2s[CAP_C2S];
    size_t cap_c2s_len;
    int cap_c2s_full;
    uint8_t cap_s2c[CAP_S2C];
    size_t cap_s2c_len;
} relay_pair_t;

typedef struct {
    int listen_fd;
    int port;
    int server_port;
    relay_pair_t pairs[MAX_PAIRS];
    size_t npairs;
    size_t accepted;
} relay_t;

typedef struct {
    relay_t relay;

    /* The fake UDP upstream behind the Cloak server. It XORs rather than
     * echoes, for the reason test_go_interop.c records: an echoing
     * upstream lets every length assertion pass against a tunnel that
     * carried nothing and looped the application's own bytes back, and a
     * session built on the wrong key establishes cleanly and then drops
     * every frame, so "it connected" proves nothing about the data path. */
    int up_fd;
    int up_port;
    uint8_t xor_mask;
    size_t up_datagrams;
    size_t up_last_len;
    /* When non-zero, the NEXT datagram is answered with this many bytes of
     * 0xC7 instead of the XOR echo. This is the ONLY way to reach Go's bug
     * 6 from the application side: bug 7 truncates everything the app
     * sends to 8192 first, so a reply larger than 8192 has to be
     * manufactured behind the server. */
    size_t amplify_next;

    /* The application's own datagram socket, connected to the Cloak
     * client's local UDP port. */
    int app_fd;
    uint8_t rx[MAX_DGRAM + 4096];
    size_t rx_len;
    int rx_have;
    size_t rx_count;
} uharness_t;

static void uh_init(uharness_t *h) {
    memset(h, 0, sizeof(*h));
    h->relay.listen_fd = -1;
    for (size_t i = 0; i < MAX_PAIRS; i++) {
        h->relay.pairs[i].cfd = -1;
        h->relay.pairs[i].sfd = -1;
    }
    h->up_fd = -1;
    h->app_fd = -1;
    h->xor_mask = 0x5a;
}

static void uh_close(uharness_t *h) {
    for (size_t i = 0; i < h->relay.npairs; i++) {
        if (h->relay.pairs[i].cfd >= 0) {
            close(h->relay.pairs[i].cfd);
            h->relay.pairs[i].cfd = -1;
        }
        if (h->relay.pairs[i].sfd >= 0) {
            close(h->relay.pairs[i].sfd);
            h->relay.pairs[i].sfd = -1;
        }
    }
    h->relay.npairs = 0;
    if (h->relay.listen_fd >= 0) {
        close(h->relay.listen_fd);
        h->relay.listen_fd = -1;
    }
    if (h->up_fd >= 0) {
        close(h->up_fd);
        h->up_fd = -1;
    }
    if (h->app_fd >= 0) {
        close(h->app_fd);
        h->app_fd = -1;
    }
}

static void pair_drop(relay_t *r, size_t i) {
    if (r->pairs[i].cfd >= 0) {
        close(r->pairs[i].cfd);
        r->pairs[i].cfd = -1;
    }
    if (r->pairs[i].sfd >= 0) {
        close(r->pairs[i].sfd);
        r->pairs[i].sfd = -1;
    }
}

static void cap_append(uint8_t *dst, size_t *len, size_t cap, int *full, const uint8_t *src,
                       size_t n) {
    size_t room = cap - *len;
    size_t take = n < room ? n : room;
    memcpy(dst + *len, src, take);
    *len += take;
    if (take < n && full != NULL) {
        *full = 1;
    }
}

/* One turn of the whole harness: the MITM relay, the UDP upstream, and the
 * application's receive side. Nothing blocks for longer than timeout_ms. */
static void uh_pump(uharness_t *h, int timeout_ms) {
    struct pollfd pf[1 + 2 * MAX_PAIRS + 2];
    int idx[1 + 2 * MAX_PAIRS + 2];
    enum { T_LISTEN, T_CFD, T_SFD, T_UP, T_APP };
    int tag[1 + 2 * MAX_PAIRS + 2];
    nfds_t n = 0;
    relay_t *r = &h->relay;

    if (r->listen_fd >= 0 && r->npairs < MAX_PAIRS) {
        pf[n].fd = r->listen_fd;
        pf[n].events = POLLIN;
        tag[n] = T_LISTEN;
        idx[n] = 0;
        n++;
    }
    for (size_t i = 0; i < r->npairs; i++) {
        relay_pair_t *p = &r->pairs[i];
        if (p->cfd >= 0) {
            short ev = 0;
            if (q_pending(&p->c2s) == 0) {
                ev |= POLLIN;
            }
            if (q_pending(&p->s2c) > 0) {
                ev |= POLLOUT;
            }
            if (ev != 0) {
                pf[n].fd = p->cfd;
                pf[n].events = ev;
                tag[n] = T_CFD;
                idx[n] = (int)i;
                n++;
            }
        }
        if (p->sfd >= 0) {
            short ev = 0;
            if (q_pending(&p->s2c) == 0) {
                ev |= POLLIN;
            }
            if (q_pending(&p->c2s) > 0) {
                ev |= POLLOUT;
            }
            if (ev != 0) {
                pf[n].fd = p->sfd;
                pf[n].events = ev;
                tag[n] = T_SFD;
                idx[n] = (int)i;
                n++;
            }
        }
    }
    if (h->up_fd >= 0) {
        pf[n].fd = h->up_fd;
        pf[n].events = POLLIN;
        tag[n] = T_UP;
        idx[n] = 0;
        n++;
    }
    if (h->app_fd >= 0) {
        pf[n].fd = h->app_fd;
        pf[n].events = POLLIN;
        tag[n] = T_APP;
        idx[n] = 0;
        n++;
    }

    if (n == 0) {
        struct pollfd dummy;
        memset(&dummy, 0, sizeof(dummy));
        dummy.fd = -1;
        poll(&dummy, 1, timeout_ms);
        return;
    }
    if (poll(pf, n, timeout_ms) <= 0) {
        return;
    }

    for (nfds_t k = 0; k < n; k++) {
        if (pf[k].revents == 0) {
            continue;
        }
        switch (tag[k]) {
        case T_LISTEN: {
            int c = accept(r->listen_fd, NULL, NULL);
            if (c < 0) {
                break;
            }
            int s = dial(r->server_port);
            if (s < 0) {
                close(c);
                break;
            }
            set_nonblock(c);
            set_nonblock(s);
            relay_pair_t *p = &r->pairs[r->npairs];
            memset(p, 0, sizeof(*p));
            p->cfd = c;
            p->sfd = s;
            r->npairs++;
            r->accepted++;
            break;
        }
        case T_CFD: {
            relay_pair_t *p = &r->pairs[idx[k]];
            if ((pf[k].revents & POLLOUT) != 0) {
                if (q_flush(&p->s2c, p->cfd) != 0) {
                    pair_drop(r, (size_t)idx[k]);
                    break;
                }
            }
            if (p->cfd >= 0 && (pf[k].revents & (POLLIN | POLLHUP | POLLERR)) != 0 &&
                q_pending(&p->c2s) == 0) {
                ssize_t got = read(p->cfd, p->c2s.buf, QCAP);
                if (got > 0) {
                    p->c2s.len = (size_t)got;
                    p->c2s.off = 0;
                    cap_append(p->cap_c2s, &p->cap_c2s_len, CAP_C2S, &p->cap_c2s_full,
                               p->c2s.buf, (size_t)got);
                    if (q_flush(&p->c2s, p->sfd) != 0) {
                        pair_drop(r, (size_t)idx[k]);
                    }
                } else if (got == 0 ||
                           (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                    pair_drop(r, (size_t)idx[k]);
                }
            }
            break;
        }
        case T_SFD: {
            relay_pair_t *p = &r->pairs[idx[k]];
            if ((pf[k].revents & POLLOUT) != 0) {
                if (q_flush(&p->c2s, p->sfd) != 0) {
                    pair_drop(r, (size_t)idx[k]);
                    break;
                }
            }
            if (p->sfd >= 0 && (pf[k].revents & (POLLIN | POLLHUP | POLLERR)) != 0 &&
                q_pending(&p->s2c) == 0) {
                ssize_t got = read(p->sfd, p->s2c.buf, QCAP);
                if (got > 0) {
                    p->s2c.len = (size_t)got;
                    p->s2c.off = 0;
                    cap_append(p->cap_s2c, &p->cap_s2c_len, CAP_S2C, NULL, p->s2c.buf,
                               (size_t)got);
                    p->s2c_total += (uint64_t)got;
                    if (q_flush(&p->s2c, p->cfd) != 0) {
                        pair_drop(r, (size_t)idx[k]);
                    }
                } else if (got == 0 ||
                           (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                    pair_drop(r, (size_t)idx[k]);
                }
            }
            break;
        }
        case T_UP: {
            static uint8_t in[MAX_DGRAM + 8192];
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t got = recvfrom(h->up_fd, in, sizeof(in), 0, (struct sockaddr *)&from, &flen);
            if (got < 0) {
                break;
            }
            h->up_datagrams++;
            h->up_last_len = (size_t)got;
            if (h->amplify_next > 0) {
                static uint8_t amp[MAX_DGRAM];
                size_t len = h->amplify_next;
                if (len > sizeof(amp)) {
                    len = sizeof(amp);
                }
                memset(amp, 0xC7, len);
                h->amplify_next = 0;
                sendto(h->up_fd, amp, len, 0, (struct sockaddr *)&from, flen);
                break;
            }
            for (ssize_t i = 0; i < got; i++) {
                in[i] ^= h->xor_mask;
            }
            sendto(h->up_fd, in, (size_t)got, 0, (struct sockaddr *)&from, flen);
            break;
        }
        case T_APP: {
            /* ONE datagram per turn, and it is never coalesced with the
             * next: a byte-stream read here would turn two replies into
             * one and hide precisely the boundary loss this file is for. */
            ssize_t got = recv(h->app_fd, h->rx, sizeof(h->rx), 0);
            if (got >= 0) {
                h->rx_len = (size_t)got;
                h->rx_have = 1;
                h->rx_count++;
            }
            break;
        }
        default:
            break;
        }
    }

    /* Compact the pair table. */
    size_t w = 0;
    for (size_t i = 0; i < r->npairs; i++) {
        if (r->pairs[i].cfd < 0 && r->pairs[i].sfd < 0) {
            continue;
        }
        if (w != i) {
            r->pairs[w] = r->pairs[i];
        }
        w++;
    }
    r->npairs = w;
}

static int uh_wait_marker(uharness_t *h, child_t *c, const char *marker, int timeout_ms) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        if (strstr(c->out, marker) != NULL) {
            return 0;
        }
        if (now_ms() >= deadline) {
            return -1;
        }
        uh_pump(h, 10);
        if (child_drain(c, 0) == 1) {
            return strstr(c->out, marker) != NULL ? 0 : -1;
        }
    }
}

/* Sends one datagram and waits for ONE reply, bounded by the clock.
 * Returns the reply length, or -1 if none arrived inside timeout_ms. */
static long uh_probe(uharness_t *h, const uint8_t *out, size_t out_len, int timeout_ms) {
    h->rx_have = 0;
    h->rx_len = 0;
    ssize_t w = send(h->app_fd, out, out_len, 0);
    if (w < 0 || (size_t)w != out_len) {
        return -2;
    }
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    while (now_ms() < deadline) {
        uh_pump(h, 5);
        if (h->rx_have) {
            return (long)h->rx_len;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Key and config fixtures (copied -- see the file header)              */
/* ------------------------------------------------------------------ */

#define PRIV_B64 "SN6EG6BhjnLLpGCMqrLzZuSNmEWXOJgEnqN0uaPihgs="
#define UID_B64  "MTIzNDU2Nzg5MGFiY2RlZg=="

static void derive_keys(uint8_t priv[CLOAK_X25519_KEY_LEN], char *pub_b64, size_t cap) {
    size_t priv_len = 0;
    ASSERT_EQ_INT(0, cloak_base64_decode(PRIV_B64, priv, CLOAK_X25519_KEY_LEN, &priv_len));
    ASSERT_EQ_INT(CLOAK_X25519_KEY_LEN, (long long)priv_len);
    uint8_t base[CLOAK_X25519_KEY_LEN];
    memset(base, 0, sizeof(base));
    base[0] = 9;
    uint8_t pub[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_shared_secret(priv, base, pub));
    ASSERT_EQ_INT(0, cloak_base64_encode(pub, sizeof(pub), pub_b64, cap));
}

/* mkstemp, not a fixed name and not getpid(): test_go_interop.c measured
 * both alternatives failing (5 of 5 with fixed names, 5 of 6 with the pid,
 * because container PIDs are namespaced and two `docker run`s get the same
 * small number). The filesystem is the only namespace two runs share. */
static int write_temp_unique(char *path_out, size_t cap, const char *name, const char *content) {
    if (snprintf(path_out, cap, "unordered_proof_%s_XXXXXX", name) >= (int)cap) {
        return -1;
    }
    int fd = mkstemp(path_out);
    if (fd < 0) {
        return -1;
    }
    size_t len = strlen(content);
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, content + off, len - off);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) {
            continue;
        }
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/* ONE server configuration text for BOTH servers and ONE client text for
 * BOTH clients: if the two implementations needed different configuration
 * to do the same thing, that would itself be the divergence, and writing
 * the fixture twice would hide it.
 *
 * "udp" in the ProxyBook is the whole point -- Go's state.go:100 resolves
 * it to a net.UDPAddr and ours (config_server.c:67) to SOCK_DGRAM, and it
 * is what puts a datagram relay rather than a byte-stream relay behind
 * each server. */
static void write_server_config(char *path_out, size_t cap, const char *name, int bind_port,
                                int upstream_port) {
    char cfg[1024];
    snprintf(cfg, sizeof(cfg),
             "{"
             "\"ProxyBook\":{\"shadowsocks\":[\"udp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\"127.0.0.1:%d\"],"
             "\"BypassUID\":[\"%s\"],"
             "\"RedirAddr\":\"127.0.0.1:1\","
             "\"PrivateKey\":\"%s\","
             "\"KeepAlive\":0"
             "}",
             upstream_port, bind_port, UID_B64, PRIV_B64);
    ASSERT_EQ_INT(0, write_temp_unique(path_out, cap, name, cfg));
}

/* "UDP":true, not the -u flag, because it is the ONE spelling both
 * binaries accept from a file: Go's state.go:86 lists UDP among its
 * unquoted raw keys and ck-client.go:125 only overrides it when -u was
 * actually given, and module 9 task 7 taught ours the same key. */
static void write_client_config(char *path_out, size_t cap, const char *name, const char *pub_b64,
                                int remote_port, int local_port, int num_conn) {
    char cfg[1024];
    snprintf(cfg, sizeof(cfg),
             "{"
             "\"Transport\":\"direct\","
             "\"ServerName\":\"www.bing.com\","
             "\"ProxyMethod\":\"shadowsocks\","
             "\"EncryptionMethod\":\"aes-gcm\","
             "\"UID\":\"%s\","
             "\"PublicKey\":\"%s\","
             "\"NumConn\":%d,"
             "\"UDP\":true,"
             "\"BrowserSig\":\"chrome\","
             "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"%d\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"%d\""
             "}",
             UID_B64, pub_b64, num_conn, remote_port, local_port);
    ASSERT_EQ_INT(0, write_temp_unique(path_out, cap, name, cfg));
}

/* logrus writing to a PIPE emits logfmt (`level=info msg=`), never the
 * `INFO[...]` TextFormatter form, which is TTY-only -- measured by
 * test_go_interop.c, whose first draft guessed the other one and failed on
 * every scenario. cloak_log_write produces nothing resembling it, so this
 * is a decisive implementation signature: without it, a scenario whose two
 * paths were accidentally the same binary could satisfy its marker wait
 * and then "interoperate" with itself. */
static void assert_implementation(const char *who, const child_t *c, int is_go) {
    int looks_go = strstr(c->out, "level=info msg=") != NULL;
    if (looks_go != is_go) {
        fprintf(stderr,
                "FAIL %s:%d: %s was expected to be %s, but its output %s logrus's "
                "\"level=info msg=\" signature. It said:\n%s\n",
                __FILE__, __LINE__, who, is_go ? "Go's binary" : "ours",
                looks_go ? "carries" : "lacks", c->out);
        cloak_test_failures++;
    }
}

/* ------------------------------------------------------------------ */
/* The size ladder                                                      */
/* ------------------------------------------------------------------ */

/* The exact sizes the brief names, and each one is a boundary rather than
 * a sample: 1 and 2 are the shortest legal datagrams; 1500 is an ordinary
 * one; 8191/8192/8193 bracket Go's local read buffer (bugs 6 and 7);
 * 16131/16132 bracket max_payload_per_frame from below; 16133 is the first
 * datagram that cannot be carried at all. */
static const size_t LADDER[] = {1, 2, 1500, 8191, 8192, 8193, 16131, 16132, 16133};
#define LADDER_N (sizeof(LADDER) / sizeof(LADDER[0]))

typedef struct {
    const char *name;
    const char *server_path;
    const char *server_ready;
    int server_is_go;
    const char *client_path;
    const char *client_ready;
    int client_is_go;
    /* The largest datagram this role's client will take from the local
     * socket: GO_UDP_BUF for Go's (piper.go's `make([]byte, 8192)`),
     * MAX_DGRAM for ours. */
    size_t client_read_cap;
    /* AND WHAT IT DOES WITH A BIGGER ONE, which is the whole of bug 7 and
     * is NOT the same question as the cap. Go TRUNCATES: ReadFrom fills
     * its 8192 bytes, the rest of the datagram is discarded by the kernel,
     * no error is reported anywhere, and the fragment is forwarded as
     * though it were the message -- which a UDP application cannot
     * distinguish from a genuinely short one. This port REFUSES: the
     * datagram is still whole at the socket when the size is checked, so
     * it is dropped as a unit and nothing goes on the wire, which is what
     * the network itself would have done with a datagram too large for a
     * hop. Two different policies; one `expect` formula cannot express
     * both, and an earlier draft of this file that tried failed here. */
    int client_truncates;
    /* Whether this role's client can RECEIVE a datagram larger than
     * GO_UDP_BUF. Go's cannot -- its reader goroutine takes
     * io.ErrShortBuffer and tears the stream down (bug 6). */
    int client_can_receive_large;
    int num_conn;
} uscenario_t;

/* Filled by the C-client role; consumed by cases 3 and 4. */
static uint8_t cap_hello[HELLO_CAP];
static size_t cap_hello_len;
static uint8_t cap_frames[2][CAP_C2S];
static size_t cap_frames_len[2];
static uint8_t cap_reply[2][CAP_S2C];
static size_t cap_reply_len[2];
static size_t cap_pairs;

static void run_ladder(const uscenario_t *sc, int capture) {
    printf("-- %s\n", sc->name);

    uharness_t h;
    uh_init(&h);

    uint8_t priv[CLOAK_X25519_KEY_LEN];
    char pub_b64[64];
    derive_keys(priv, pub_b64, sizeof(pub_b64));

    h.up_fd = udp_socket(&h.up_port);
    ASSERT_TRUE(h.up_fd >= 0);

    int server_port = free_port();
    ASSERT_TRUE(server_port > 0);

    h.relay.listen_fd = listen_on(&h.relay.port);
    ASSERT_TRUE(h.relay.listen_fd >= 0);
    set_nonblock(h.relay.listen_fd);
    h.relay.server_port = server_port;

    int local_port = free_port();
    ASSERT_TRUE(local_port > 0);

    char scfg[160];
    char ccfg[160];
    char sname[96];
    char cname[96];
    snprintf(sname, sizeof(sname), "%s_server", sc->name);
    snprintf(cname, sizeof(cname), "%s_client", sc->name);
    write_server_config(scfg, sizeof(scfg), sname, server_port, h.up_port);
    write_client_config(ccfg, sizeof(ccfg), cname, pub_b64, h.relay.port, local_port,
                        sc->num_conn);

    child_t server;
    child_t client;
    memset(&server, 0, sizeof(server));
    memset(&client, 0, sizeof(client));
    server.fd = -1;
    client.fd = -1;

    char *const sargv[] = {(char *)"ck-server", (char *)"-c", scfg, NULL};
    ASSERT_EQ_INT(0, child_spawn(&server, sc->server_path, sargv));
    if (uh_wait_marker(&h, &server, sc->server_ready, BOOT_MS) != 0) {
        fprintf(stderr, "FAIL %s:%d: %s: server never said \"%s\"; it said:\n%s\n", __FILE__,
                __LINE__, sc->name, sc->server_ready, server.out);
        cloak_test_failures++;
        child_stop(&server);
        uh_close(&h);
        unlink(scfg);
        unlink(ccfg);
        return;
    }

    char *const cargv[] = {(char *)"ck-client", (char *)"-c", ccfg, NULL};
    ASSERT_EQ_INT(0, child_spawn(&client, sc->client_path, cargv));
    if (uh_wait_marker(&h, &client, sc->client_ready, BOOT_MS) != 0) {
        fprintf(stderr, "FAIL %s:%d: %s: client never said \"%s\"; it said:\n%s\n", __FILE__,
                __LINE__, sc->name, sc->client_ready, client.out);
        cloak_test_failures++;
        child_stop(&client);
        child_stop(&server);
        uh_close(&h);
        unlink(scfg);
        unlink(ccfg);
        return;
    }

    assert_implementation("the server", &server, sc->server_is_go);
    assert_implementation("the client", &client, sc->client_is_go);

    /* THE LOCAL ENDPOINT MUST BE A UDP ONE, AND BOTH CLIENTS SAY SO.
     * Go's ck-client.go:170-175 sets `network` from authInfo.Unordered and
     * ours does the same (module 9 task 7). Without this a client that
     * ignored "UDP":true would open a TCP listener, every probe below
     * would fail with "no reply", and the diagnosis would name the tunnel
     * rather than the mode. */
    char want[64];
    snprintf(want, sizeof(want), "UDP 127.0.0.1:%d", local_port);
    if (strstr(client.out, want) == NULL) {
        fprintf(stderr,
                "FAIL %s:%d: %s: the client never announced a UDP listener on port %d -- it "
                "either ignored \"UDP\":true or read a configuration that is not this run's "
                "(%s). It said:\n%s\n",
                __FILE__, __LINE__, sc->name, local_port, ccfg, client.out);
        cloak_test_failures++;
    }

    h.app_fd = udp_socket(NULL);
    ASSERT_TRUE(h.app_fd >= 0);
    struct sockaddr_in la;
    memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    la.sin_port = htons((uint16_t)local_port);
    ASSERT_EQ_INT(0, connect(h.app_fd, (struct sockaddr *)&la, sizeof(la)));

    /* THE WARM-UP, AND WHY IT IS RETRIED RATHER THAN ASSERTED.
     * NEITHER client has a session before the first datagram: Go's
     * RouteUDP calls newSeshFunc() from inside its read loop, and ours may
     * still be completing its first round. A UDP application retries; so
     * does this one, bounded by the clock. The ladder below is asserted
     * EXACTLY, and none of it starts until this has come back. */
    static uint8_t warm[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    long warm_got = -1;
    uint64_t warm_deadline = now_ms() + BOOT_MS;
    int warm_tries = 0;
    while (now_ms() < warm_deadline) {
        warm_tries++;
        warm_got = uh_probe(&h, warm, sizeof(warm), 400);
        if (warm_got > 0) {
            break;
        }
    }
    if (warm_got != (long)sizeof(warm)) {
        fprintf(stderr,
                "FAIL %s:%d: %s: no datagram ever completed the round trip (%d attempts, "
                "%zu reached the upstream). Client said:\n%s\nServer said:\n%s\n",
                __FILE__, __LINE__, sc->name, warm_tries, h.up_datagrams, client.out,
                server.out);
        cloak_test_failures++;
        child_stop(&client);
        child_stop(&server);
        uh_close(&h);
        unlink(scfg);
        unlink(ccfg);
        return;
    }

    /* ---- the ladder ---- */
    static uint8_t out[MAX_DGRAM + 8];
    static uint8_t want_buf[MAX_DGRAM + 8];
    uint64_t t0 = now_ms();
    for (size_t i = 0; i < LADDER_N; i++) {
        size_t len = LADDER[i];
        fill_payload(out, len, (uint32_t)(0x9e3779b9u + len));

        /* What the far end can possibly have seen, and therefore the
         * EXACT length that must come back. Not "at most": exact. */
        size_t expect;
        if (len <= sc->client_read_cap) {
            expect = len;
        } else if (sc->client_truncates) {
            expect = sc->client_read_cap;
        } else {
            expect = 0; /* refused at the socket -- nothing on the wire */
        }
        int carried = expect > 0 && (sc->client_can_receive_large || expect <= GO_UDP_BUF);

        if (!carried) {
            long got = uh_probe(&h, out, len, QUIET_MS);
            if (got >= 0) {
                fprintf(stderr,
                        "FAIL %s:%d: %s: a %zu-byte datagram must not cross, but %ld bytes "
                        "came back\n",
                        __FILE__, __LINE__, sc->name, len, got);
                cloak_test_failures++;
            }
            printf("   %6zu -> refused, nothing back\n", len);
            continue;
        }

        long got = uh_probe(&h, out, len, PROBE_MS);
        if (got < 0) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: a %zu-byte datagram produced no reply in %d ms "
                    "(expected exactly %zu bytes back). Client said:\n%s\n",
                    __FILE__, __LINE__, sc->name, len, PROBE_MS, expect, client.out);
            cloak_test_failures++;
            continue;
        }
        /* THE EXACT LENGTH. A ">= 1" or "something came back" assertion
         * here would pass against a port that split a 16132-byte datagram
         * into two frames and let the far end deliver the first, which is
         * one of the two defects this ladder exists to catch. */
        ASSERT_EQ_INT((long long)expect, got);
        /* AND THE CONTENT, because Go REORDERS RATHER THAN DROPS: task 1's
         * review measured all three byte counts identical under a forced
         * flag, with only this comparison failing. */
        for (size_t b = 0; b < expect; b++) {
            want_buf[b] = (uint8_t)(out[b] ^ h.xor_mask);
        }
        if ((size_t)got == expect) {
            ASSERT_MEM_EQ(want_buf, h.rx, expect);
            ASSERT_MEM_NE(out, h.rx, expect);
        }
        printf("   %6zu -> %ld back%s\n", len, got,
               expect == len ? "" : "  (TRUNCATED by the client's local read buffer)");
    }
    uint64_t ladder_ms = now_ms() - t0;

    /* ---- the zero-length datagram ---- */
    static uint8_t nothing[1];
    long zero_got = uh_probe(&h, nothing, 0, QUIET_MS);
    if (zero_got >= 0) {
        fprintf(stderr,
                "FAIL %s:%d: %s: a zero-length datagram must be swallowed, but %ld bytes came "
                "back\n",
                __FILE__, __LINE__, sc->name, zero_got);
        cloak_test_failures++;
    }

    /* ---- and the session still works afterwards ----
     * Without this, "swallowed" and "wedged the stream" are the same
     * observation. Same for the refused oversize datagram above. */
    fill_payload(out, 64, 0x5151u);
    long after = uh_probe(&h, out, 64, PROBE_MS);
    ASSERT_EQ_INT(64, after);
    if (after == 64) {
        for (size_t b = 0; b < 64; b++) {
            want_buf[b] = (uint8_t)(out[b] ^ h.xor_mask);
        }
        ASSERT_MEM_EQ(want_buf, h.rx, 64);
    }

    /* ---- BUG 6, reproduced at the real binaries ----
     * Only reachable with an amplifying upstream: bug 7 truncates anything
     * the APP sends to 8192 first, so a reply larger than Go's 8192-byte
     * receive buffer has to be manufactured behind the server. Our client
     * must deliver it; Go's must lose it AND tear the stream down, after
     * which a later datagram still crosses on a NEW stream (piper.go
     * deletes the map entry before closing). */
    h.amplify_next = GO_UDP_BUF + 1;
    long amp = uh_probe(&h, out, 8, sc->client_can_receive_large ? PROBE_MS : QUIET_MS);
    if (sc->client_can_receive_large) {
        ASSERT_EQ_INT((long long)(GO_UDP_BUF + 1), amp);
        if (amp == (long)(GO_UDP_BUF + 1)) {
            int all_c7 = 1;
            for (size_t b = 0; b < GO_UDP_BUF + 1; b++) {
                if (h.rx[b] != 0xC7) {
                    all_c7 = 0;
                }
            }
            ASSERT_TRUE(all_c7);
        }
        printf("   amplified %u-byte reply -> %ld back (this port carries it)\n",
               GO_UDP_BUF + 1, amp);
    } else {
        if (amp >= 0) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: Go's client is expected to LOSE an %u-byte reply "
                    "(io.ErrShortBuffer against its 8192-byte buffer), but %ld bytes arrived\n",
                    __FILE__, __LINE__, sc->name, GO_UDP_BUF + 1, amp);
            cloak_test_failures++;
        }
        fill_payload(out, 32, 0x7777u);
        long again = uh_probe(&h, out, 32, PROBE_MS);
        ASSERT_EQ_INT(32, again);
        printf("   amplified %u-byte reply -> lost (bug 6), next datagram -> %ld back\n",
               GO_UDP_BUF + 1, again);
    }

    printf("   %zu datagrams reached the upstream, %zu relayed connection(s), ladder in "
           "%llu ms\n",
           h.up_datagrams, h.relay.accepted, (unsigned long long)ladder_ms);

    if (capture) {
        cap_pairs = h.relay.npairs < 2 ? h.relay.npairs : 2;
        for (size_t i = 0; i < cap_pairs; i++) {
            cap_frames_len[i] = h.relay.pairs[i].cap_c2s_len;
            memcpy(cap_frames[i], h.relay.pairs[i].cap_c2s, cap_frames_len[i]);
            cap_reply_len[i] = h.relay.pairs[i].cap_s2c_len;
            memcpy(cap_reply[i], h.relay.pairs[i].cap_s2c, cap_reply_len[i]);
            if (h.relay.pairs[i].cap_c2s_full) {
                fprintf(stderr,
                        "FAIL %s:%d: %s: connection %zu's capture buffer filled (%u bytes); "
                        "case 3 would analyse a truncated connection\n",
                        __FILE__, __LINE__, sc->name, i, CAP_C2S);
                cloak_test_failures++;
            }
        }
        cap_hello_len = 0;
        if (cap_pairs > 0) {
            size_t n = cap_frames_len[0] < HELLO_CAP ? cap_frames_len[0] : HELLO_CAP;
            memcpy(cap_hello, cap_frames[0], n);
            cap_hello_len = n;
        }
    }

    child_stop(&client);
    child_stop(&server);
    uh_close(&h);
    unlink(scfg);
    unlink(ccfg);
}

/* ---- CASE 1 ---- */

static void test_ladder_go_client_to_c_server(void) {
    uscenario_t sc = {
        .name = "case1a_go_client_udp_to_c_server",
        .server_path = CK_SERVER_PATH,
        .server_ready = "ck-server ready",
        .server_is_go = 0,
        .client_path = GO_CK_CLIENT_PATH,
        .client_ready = "Listening on",
        .client_is_go = 1,
        /* internal/client/piper.go:25 -- `data := make([]byte, 8192)`. */
        .client_read_cap = GO_UDP_BUF,
        .client_truncates = 1,
        /* internal/client/piper.go:57 -- the reader goroutine's own 8192. */
        .client_can_receive_large = 0,
        .num_conn = 2,
    };
    run_ladder(&sc, 0);
}

static void test_ladder_c_client_to_go_server(void) {
    uscenario_t sc = {
        .name = "case1b_c_client_udp_to_go_server",
        .server_path = GO_CK_SERVER_PATH,
        .server_ready = "Listening on",
        .server_is_go = 1,
        .client_path = CK_CLIENT_PATH,
        .client_ready = "session up",
        .client_is_go = 0,
        /* We read the whole datagram and refuse only what cannot be
         * carried in one frame. */
        .client_read_cap = MAX_DGRAM,
        .client_truncates = 0,
        .client_can_receive_large = 1,
        .num_conn = 2,
    };
    run_ladder(&sc, 1);
}

/* ================================================================== */
/* CASE 3: NO ORACLE, WHITE BOX -- seq on a captured connection        */
/* ================================================================== */

/* Recovers the session key from a captured connection WITHOUT ASKING
 * EITHER IMPLEMENTATION ANYTHING.
 *
 *   - the ClientHello's `random` field is the client's ephemeral X25519
 *     public key, and this test holds the server PRIVATE key it wrote
 *     into the configuration, so it can compute the same shared secret
 *     both ends derived;
 *   - the ServerHello carries the session key sealed under that secret,
 *     split across the record exactly as client_transport.c's
 *     recover_session_key documents: nonce at reply[11:23), ciphertext
 *     halves at reply[23:43) and reply[89:117). Go reads the same offsets
 *     (internal/client/TLS.go, buf[6:38] ++ buf[84:116], five bytes
 *     further along because its record header is already stripped).
 *
 * With that key our own cloak_frame_deobfuscate reads every frame on the
 * wire, which is the only way to see a property the far end ignores. */
static int recover_session_key(const uint8_t *hello, size_t hello_len, const uint8_t *reply,
                               size_t reply_len, const uint8_t priv[CLOAK_X25519_KEY_LEN],
                               uint8_t out_key[CLOAK_AEAD_KEY_LEN]) {
    if (hello_len < 5) {
        return -1;
    }
    size_t record_len = ((size_t)hello[3] << 8) | (size_t)hello[4];
    if (5 + record_len > hello_len) {
        return -2;
    }
    cloak_clienthello_parsed_t p;
    if (cloak_clienthello_parse(hello, 5 + record_len, &p) != 0) {
        return -3;
    }
    uint8_t secret[CLOAK_X25519_KEY_LEN];
    if (cloak_x25519_shared_secret(priv, p.random, secret) != 0) {
        return -4;
    }
    if (reply_len < 117) {
        return -5;
    }
    uint8_t ct[48];
    memcpy(ct, reply + 23, 20);
    memcpy(ct + 20, reply + 89, 28);
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    size_t key_len = 0;
    if (cloak_aead_open(CLOAK_AEAD_AES_256_GCM, secret, reply + 11, NULL, 0, ct, sizeof(ct), key,
                        &key_len) != 0) {
        return -6;
    }
    if (key_len != CLOAK_AEAD_KEY_LEN) {
        return -7;
    }
    memcpy(out_key, key, CLOAK_AEAD_KEY_LEN);
    return 0;
}

#define MAX_CAP_FRAMES 128

typedef struct {
    uint32_t stream_id;
    uint64_t seq;
    uint8_t closing;
    size_t payload_len;
    size_t extra_len;
    size_t conn;
} seen_frame_t;

static seen_frame_t seen[MAX_CAP_FRAMES];
static size_t seen_n;

/* Walks one captured client->server byte stream, skipping the ClientHello
 * record, and deobfuscates every 0x17 application-data record after it.
 * Every Cloak frame is exactly one TLS-shaped record (conn.c:806-827
 * writes 0x17 0x03 0x03 <be16 len> then the frame), so the record
 * boundaries ARE the frame boundaries. */
static size_t parse_conn(uint8_t *buf, size_t len, const cloak_obfuscator_t *o, size_t conn_idx,
                         int *bad_out) {
    size_t off = 0;
    size_t frames = 0;
    int first = 1;
    while (off + 5 <= len) {
        size_t body = ((size_t)buf[off + 3] << 8) | (size_t)buf[off + 4];
        if (off + 5 + body > len) {
            break; /* a partially captured trailing record */
        }
        uint8_t type = buf[off];
        uint8_t *frame_bytes = buf + off + 5;
        off += 5 + body;
        if (first) {
            first = 0;
            if (type == 0x16) {
                continue; /* the ClientHello */
            }
        }
        cloak_frame_t f;
        /* extra_len is read BEFORE deobfuscation destroys the ciphertext:
         * it is byte 13 of the Salsa20-encrypted header, so it has to come
         * out of the decrypted header instead -- hence the recomputation
         * from the record length and the payload length below. */
        if (cloak_frame_deobfuscate(o, &f, frame_bytes, body) != 0) {
            (*bad_out)++;
            continue;
        }
        if (seen_n < MAX_CAP_FRAMES) {
            seen[seen_n].stream_id = f.stream_id;
            seen[seen_n].seq = f.seq;
            seen[seen_n].closing = f.closing;
            seen[seen_n].payload_len = f.payload_len;
            /* body = 14 header + payload + extra, so extra = body - 14 -
             * payload. That is byte 13 of the header, recovered without
             * trusting the copy deobfuscation left behind. */
            seen[seen_n].extra_len = body - CLOAK_FRAME_HEADER_LEN - f.payload_len;
            seen[seen_n].conn = conn_idx;
            seen_n++;
        }
        frames++;
    }
    return frames;
}

/* THE PROPERTY NO ORACLE CAN SEE, NUMBER ONE.
 *
 * The unordered RECEIVER ignores seq entirely -- feed_frame_unordered
 * (stream.c:330) does not look at frame->seq at all, and neither does
 * Go's datagramBufferedPipe. So a sender that stopped generating
 * sequence numbers, or reset them per datagram, or emitted a constant,
 * would interoperate PERFECTLY: case 1 passes, every round-trip test in
 * the tree passes, and Go's own client and server accept every frame.
 *
 * What it would actually be is AEAD NONCE REUSE. cloak_frame_obfuscate
 * builds the AES-GCM nonce from buf[0:12] -- stream_id (4) || seq (8) --
 * before the header is encrypted. One session key, one stream id, and a
 * repeated seq is the same (key, nonce) pair used twice, which for GCM
 * leaks the XOR of the two plaintexts and, worse, the authentication
 * subkey. There is no oracle for this anywhere: it is a property of the
 * bytes, so it is asserted on the bytes.
 *
 * Asserted two ways, because each catches something the other does not:
 *   (a) WITHIN one connection, seq is strictly increasing. Frames are
 *       written to a connection in generation order, so this is the
 *       monotonicity property directly.
 *   (b) ACROSS both connections, the seqs of one stream are DISTINCT and
 *       form 0..n-1 with no gaps. This is what catches a constant seq
 *       (every value 0), a per-connection counter (each connection
 *       restarting at 0 -- invisible to (a)), and a generator that skips.
 * A test with only (a) passes against a per-connection counter; a test
 * with only (b) passes against a generator that emits 0..n-1 shuffled. */
static void test_seq_is_still_generated_and_monotonic(void) {
    printf("-- case3: seq is generated, monotonic and unique (NO ORACLE: the unordered "
           "receiver ignores it; a constant seq is silent GCM nonce reuse)\n");

    if (cap_pairs == 0 || cap_hello_len == 0) {
        fprintf(stderr, "FAIL %s:%d: case 1b captured no connection to analyse\n", __FILE__,
                __LINE__);
        cloak_test_failures++;
        return;
    }

    uint8_t priv[CLOAK_X25519_KEY_LEN];
    char pub_b64[64];
    derive_keys(priv, pub_b64, sizeof(pub_b64));

    cloak_obfuscator_t o;
    o.method = CLOAK_AEAD_AES_256_GCM;
    int rc = recover_session_key(cap_hello, cap_hello_len, cap_reply[0], cap_reply_len[0], priv,
                                 o.session_key);
    ASSERT_EQ_INT(0, rc);
    if (rc != 0) {
        return;
    }

    /* EVERY CONNECTION OF ONE SESSION CARRIES ONE SESSION KEY. Not
     * decoration: if the two connections had different keys the frames on
     * connection 1 would simply fail to authenticate below, and "seq was
     * fine on the frames we could read" is not the assertion this case
     * makes. Our connector enforces this with keys_agree(); here it is
     * measured off a real Go server's two ServerHellos. */
    for (size_t i = 1; i < cap_pairs; i++) {
        uint8_t k2[CLOAK_AEAD_KEY_LEN];
        int rc2 = recover_session_key(cap_frames[i], cap_frames_len[i], cap_reply[i],
                                      cap_reply_len[i], priv, k2);
        ASSERT_EQ_INT(0, rc2);
        if (rc2 == 0) {
            ASSERT_MEM_EQ(o.session_key, k2, CLOAK_AEAD_KEY_LEN);
        }
    }

    seen_n = 0;
    int bad = 0;
    size_t total = 0;
    for (size_t i = 0; i < cap_pairs; i++) {
        total += parse_conn(cap_frames[i], cap_frames_len[i], &o, i, &bad);
    }
    /* A frame our own deobfuscator cannot read is either a capture bug or
     * a wire-format divergence, and either one makes every assertion below
     * vacuous. */
    ASSERT_EQ_INT(0, bad);
    /* The ladder puts at least the warm-up, seven carried sizes, the
     * post-zero probe and the two amplification probes on the wire. Ten is
     * a floor, not a count: it exists so that an empty capture cannot pass
     * the loops below by having nothing to iterate over. */
    ASSERT_TRUE(total >= 10);

    /* (a) strictly increasing within each connection, per stream. */
    int mono_ok = 1;
    for (size_t c = 0; c < cap_pairs; c++) {
        uint64_t last = 0;
        int have = 0;
        for (size_t i = 0; i < seen_n; i++) {
            if (seen[i].conn != c) {
                continue;
            }
            if (have && seen[i].seq <= last) {
                fprintf(stderr,
                        "FAIL %s:%d: connection %zu carried seq %llu after seq %llu -- "
                        "sequence numbers must be strictly increasing in generation order\n",
                        __FILE__, __LINE__, c, (unsigned long long)seen[i].seq,
                        (unsigned long long)last);
                cloak_test_failures++;
                mono_ok = 0;
            }
            last = seen[i].seq;
            have = 1;
        }
    }

    /* (b) distinct and contiguous from 0 across the whole session. */
    size_t stream_frames = 0;
    uint32_t sid = seen_n > 0 ? seen[0].stream_id : 0;
    static unsigned char hit[MAX_CAP_FRAMES + 8];
    memset(hit, 0, sizeof(hit));
    int dup = 0;
    uint64_t max_seq = 0;
    for (size_t i = 0; i < seen_n; i++) {
        if (seen[i].stream_id != sid) {
            continue;
        }
        stream_frames++;
        if (seen[i].seq < sizeof(hit)) {
            if (hit[seen[i].seq]) {
                dup++;
            }
            hit[seen[i].seq] = 1;
        }
        if (seen[i].seq > max_seq) {
            max_seq = seen[i].seq;
        }
    }
    if (dup != 0) {
        fprintf(stderr,
                "FAIL %s:%d: %d frame(s) of stream %u REPEATED a sequence number. With one "
                "session key that is an AES-GCM (key, nonce) pair used twice -- see this "
                "case's own comment\n",
                __FILE__, __LINE__, dup, sid);
        cloak_test_failures++;
    }
    int gaps = 0;
    for (uint64_t s = 0; s <= max_seq; s++) {
        if (s < sizeof(hit) && !hit[s]) {
            gaps++;
        }
    }
    ASSERT_EQ_INT(0, gaps);
    ASSERT_EQ_INT((long long)(max_seq + 1), (long long)stream_frames);

    printf("   %zu frames on %zu connection(s), stream %u seq 0..%llu, distinct=%s, "
           "monotonic-per-connection=%s\n",
           total, cap_pairs, sid, (unsigned long long)max_seq, dup == 0 ? "yes" : "NO",
           mono_ok ? "yes" : "NO");

    /* THE PAD BOUNDARY, ON A REAL WIRE. Only the guaranteed direction is
     * asserted here: a frame at seq >= 5 must carry NO padding at all
     * (extra_len is exactly the AEAD tag). The other direction is not a
     * theorem -- a padded frame may legitimately draw pad_len 0, once in
     * 240 -- so it is pinned statistically in case 4 instead. */
    size_t padded_early = 0;
    for (size_t i = 0; i < seen_n; i++) {
        if (seen[i].seq >= CLOAK_FRAME_PAD_FIRST_N_FRAMES) {
            if (seen[i].extra_len != 16) {
                fprintf(stderr,
                        "FAIL %s:%d: frame seq %llu carried extra_len %zu; past frame %d a "
                        "frame must carry the 16-byte tag and nothing else\n",
                        __FILE__, __LINE__, (unsigned long long)seen[i].seq, seen[i].extra_len,
                        CLOAK_FRAME_PAD_FIRST_N_FRAMES);
                cloak_test_failures++;
            }
        } else if (seen[i].extra_len > 16) {
            padded_early++;
        }
    }
    printf("   %zu of the first-%d-frame slots carried padding on the wire\n", padded_early,
           CLOAK_FRAME_PAD_FIRST_N_FRAMES);
}

/* ================================================================== */
/* PART TWO: THE IN-PROCESS REPLAYING/REORDERING MIDDLE BOX            */
/* ================================================================== */

/* Two REAL cloak_session_t objects, each on its own reactor, joined by N
 * connections that this test sits in the middle of. Every frame therefore
 * travels through cloak_conn_send, a real socket, this middle box, another
 * real socket and cloak_session_on_envelope -- which is the difference
 * between these cases and task 3's, which asserted the same policies at
 * cloak_stream_feed_frame's return value and named this harness as what
 * would close the gap.
 *
 * WHY A MIDDLE BOX AND NOT A DIRECT socketpair. Reordering and replay are
 * not things either endpoint can be asked to do; they are things the
 * network does. Over loopback with NumConn 4 they never happen on their
 * own -- module 9's scouting could not force a single out-of-order arrival
 * -- so the only honest way to test the mode is to synthesise them. */

#define MB_CONNS 2
#define MB_ACC 262144
#define MB_RECS 64

typedef struct {
    uint8_t bytes[MAX_ON_WIRE + 64];
    size_t len;
    size_t conn;
} mb_rec_t;

typedef enum {
    MB_PASS = 0,     /* forward every record as it arrives */
    MB_REVERSE2,     /* hold the first two data records, release them reversed */
    MB_DUPLICATE1    /* forward every record, and send the FIRST one a second time */
} mb_policy_t;

typedef struct {
    /* [i][0] talks to the client session, [i][1] to the server session. */
    int mid[MB_CONNS][2];
    uint8_t acc[MB_CONNS][MB_ACC];
    size_t acc_len[MB_CONNS];
    mb_rec_t held[MB_RECS];
    size_t held_n;
    mb_policy_t policy;
    int armed;          /* the policy has not fired yet */
    /* MB_REVERSE2 only. The second-released record (the EARLIER of the two
     * frames) waits here until the test says the peer has already taken
     * delivery of the later one.
     *
     * THIS EXISTS BECAUSE THE FIRST DESIGN WAS WRONG, AND THE TEST CAUGHT
     * IT. Writing B's record and then A's record back to back does NOT
     * make them ARRIVE in that order when they are on two different
     * sockets: the receiving reactor drains both in one turn and
     * dispatches them in fd order, so A (on the lower-numbered
     * connection) was routed first and the case failed under ASan while
     * passing in Debug. Released-reversed is not arrived-reversed. The
     * gap below is what makes the reversal real, and it is closed on an
     * EVENT (the peer session has seen the first frame) rather than on a
     * sleep. */
    mb_rec_t deferred;
    int have_deferred;
    int release_deferred;
    size_t released;
    size_t rec_conn[4]; /* which connection the first few records came from */
    size_t rec_seen;
} mb_t;

static int mb_write_all(int fd, const uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, b + off, n - off);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            struct pollfd p;
            p.fd = fd;
            p.events = POLLOUT;
            poll(&p, 1, 50);
            continue;
        }
        return -1;
    }
    return 0;
}

static void mb_emit(mb_t *m, const mb_rec_t *r) {
    mb_write_all(m->mid[r->conn][1], r->bytes, r->len);
    m->released++;
}

/* Drains whole records out of connection c's accumulator and applies the
 * policy. Returns the number of records consumed. */
static void mb_step(mb_t *m, size_t c) {
    size_t off = 0;
    while (off + 5 <= m->acc_len[c]) {
        size_t body = ((size_t)m->acc[c][off + 3] << 8) | (size_t)m->acc[c][off + 4];
        size_t total = 5 + body;
        if (off + total > m->acc_len[c]) {
            break;
        }
        mb_rec_t r;
        if (total > sizeof(r.bytes)) {
            /* Structurally impossible at MAX_ON_WIRE, and a silent
             * truncation here would be indistinguishable from the tunnel
             * losing a frame. */
            fprintf(stderr, "FAIL %s:%d: middle box saw a %zu-byte record\n", __FILE__, __LINE__,
                    total);
            cloak_test_failures++;
            off += total;
            continue;
        }
        memcpy(r.bytes, m->acc[c] + off, total);
        r.len = total;
        r.conn = c;
        off += total;

        if (m->rec_seen < sizeof(m->rec_conn) / sizeof(m->rec_conn[0])) {
            m->rec_conn[m->rec_seen] = c;
        }
        m->rec_seen++;

        switch (m->policy) {
        case MB_REVERSE2:
            if (m->armed) {
                m->held[m->held_n++] = r;
                if (m->held_n == 2) {
                    /* RELEASED REVERSED. Each record still goes out on the
                     * connection it arrived on, so nothing about the
                     * transport is faked -- only the ORDER in which the
                     * peer's two sockets deliver, which is exactly what
                     * two connections with different queue depths produce
                     * on a real network. The EARLIER frame is deferred
                     * until the peer has taken the later one; see
                     * have_deferred. */
                    mb_emit(m, &m->held[1]);
                    m->deferred = m->held[0];
                    m->have_deferred = 1;
                    m->held_n = 0;
                    m->armed = 0;
                }
                break;
            }
            mb_emit(m, &r);
            break;
        case MB_DUPLICATE1:
            mb_emit(m, &r);
            if (m->armed) {
                /* THE REPLAY. The same bytes, a second time, on the same
                 * connection -- which is what an on-path attacker or a
                 * retransmitting middle box produces, and which neither
                 * endpoint can distinguish from a genuine frame without
                 * looking at seq. */
                mb_emit(m, &r);
                m->armed = 0;
            }
            break;
        case MB_PASS:
        default:
            mb_emit(m, &r);
            break;
        }
    }
    if (off > 0) {
        memmove(m->acc[c], m->acc[c] + off, m->acc_len[c] - off);
        m->acc_len[c] -= off;
    }
}

static void mb_pump(mb_t *m) {
    if (m->have_deferred && m->release_deferred) {
        mb_emit(m, &m->deferred);
        m->have_deferred = 0;
    }
    for (size_t c = 0; c < MB_CONNS; c++) {
        for (;;) {
            if (m->acc_len[c] >= MB_ACC) {
                break;
            }
            ssize_t got = read(m->mid[c][0], m->acc[c] + m->acc_len[c], MB_ACC - m->acc_len[c]);
            if (got > 0) {
                m->acc_len[c] += (size_t)got;
                continue;
            }
            break;
        }
        mb_step(m, c);

        /* The reply direction is a plain splice: nothing in these two
         * cases needs the server's answers disturbed, and disturbing them
         * would make a failure ambiguous about which direction broke. */
        uint8_t back[65536];
        for (;;) {
            ssize_t got = read(m->mid[c][1], back, sizeof(back));
            if (got > 0) {
                mb_write_all(m->mid[c][0], back, (size_t)got);
                continue;
            }
            break;
        }
    }
}

typedef struct {
    cloak_stream_t *last_new_stream;
    int new_stream_count;
    int broken_count;
    int data_count;
} mb_sesh_t;

static void mb_on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    mb_sesh_t *h = (mb_sesh_t *)userdata;
    h->last_new_stream = stream;
    h->new_stream_count++;
}

static void mb_on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    mb_sesh_t *h = (mb_sesh_t *)userdata;
    h->broken_count++;
}

static void mb_on_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    (void)stream;
    mb_sesh_t *h = (mb_sesh_t *)userdata;
    h->data_count++;
}

typedef struct {
    cloak_reactor_t *cr;
    cloak_reactor_t *sr;
    cloak_session_t client;
    cloak_session_t server;
    mb_sesh_t ch;
    mb_sesh_t sh;
    mb_t mb;
    int client_fds[MB_CONNS];
    int server_fds[MB_CONNS];
} mb_env_t;

static int nonblocking_pair(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return -1;
    }
    set_nonblock(fds[0]);
    set_nonblock(fds[1]);
    return 0;
}

static void mb_env_init(mb_env_t *e, cloak_session_ordering_t ordering, mb_policy_t policy) {
    memset(e, 0, sizeof(*e));
    e->mb.policy = policy;
    e->mb.armed = 1;

    e->cr = cloak_reactor_create();
    e->sr = cloak_reactor_create();
    ASSERT_TRUE(e->cr != NULL && e->sr != NULL);

    cloak_obfuscator_t o;
    o.method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o.session_key, sizeof(o.session_key));

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.ordering = ordering;
    cfg.obfuscator = o;
    cfg.max_on_wire_size = MAX_ON_WIRE;
    cfg.stream_recv_capacity = 262144;
    cfg.stream_max_pending_frames = 64;
    cfg.conn_send_queue_cap = 262144;
    cfg.inactivity_timeout_ms = 60000;
    cfg.on_new_stream = mb_on_new_stream;
    cfg.on_new_stream_userdata = &e->ch;
    cfg.on_broken = mb_on_broken;
    cfg.on_broken_userdata = &e->ch;
    cfg.on_stream_data = mb_on_data;
    cfg.on_stream_data_userdata = &e->ch;
    ASSERT_EQ_INT(0, cloak_session_init(&e->client, 1, e->cr, &cfg));

    cfg.on_new_stream_userdata = &e->sh;
    cfg.on_broken_userdata = &e->sh;
    cfg.on_stream_data_userdata = &e->sh;
    ASSERT_EQ_INT(0, cloak_session_init(&e->server, 2, e->sr, &cfg));

    for (size_t i = 0; i < MB_CONNS; i++) {
        int a[2];
        int b[2];
        ASSERT_EQ_INT(0, nonblocking_pair(a));
        ASSERT_EQ_INT(0, nonblocking_pair(b));
        e->client_fds[i] = a[0];
        e->mb.mid[i][0] = a[1];
        e->mb.mid[i][1] = b[0];
        e->server_fds[i] = b[1];
        ASSERT_EQ_INT(0, cloak_session_add_conn(&e->client, a[0]));
        ASSERT_EQ_INT(0, cloak_session_add_conn(&e->server, b[1]));
    }
}

static void mb_env_close(mb_env_t *e) {
    cloak_session_destroy(&e->client);
    cloak_session_destroy(&e->server);
    for (size_t i = 0; i < MB_CONNS; i++) {
        close(e->mb.mid[i][0]);
        close(e->mb.mid[i][1]);
    }
    cloak_reactor_destroy(e->cr);
    cloak_reactor_destroy(e->sr);
}

/* BOUNDED BY THE CLOCK, NEVER BY A ROUND COUNT. The existing session tests
 * use pump_until(r1, r2, flag, max_rounds); a round count is a wall-clock
 * bound only on a machine that is not loaded, which is the machine no CI
 * run happens on. */
static void mb_turn(mb_env_t *e) {
    cloak_reactor_run_once(e->cr, 0);
    mb_pump(&e->mb);
    cloak_reactor_run_once(e->sr, 0);
    mb_pump(&e->mb);
}

static void mb_run(mb_env_t *e, int ms) {
    uint64_t deadline = now_ms() + (uint64_t)ms;
    while (now_ms() < deadline) {
        mb_turn(e);
    }
}

/* Turns until the peer session has seen its first frame, or ms expires. */
static void mb_run_until_new_stream(mb_env_t *e, int ms);
/* Turns until the middle box has SEEN n records, or ms expires. */
static void mb_run_until_seen(mb_env_t *e, size_t n, int ms);

/* Turns until `want` records have left the middle box, then a few settle
 * turns so the receiving session has dispatched them, or until ms expires.
 * The early exit is what makes case 2's retry loop affordable; the
 * deadline is still the bound. */
static void mb_run_until(mb_env_t *e, size_t want, int ms) {
    uint64_t deadline = now_ms() + (uint64_t)ms;
    while (now_ms() < deadline) {
        mb_turn(e);
        if (e->mb.released >= want) {
            for (int i = 0; i < 4; i++) {
                mb_turn(e);
            }
            return;
        }
    }
}

static void mb_run_until_seen(mb_env_t *e, size_t n, int ms) {
    uint64_t deadline = now_ms() + (uint64_t)ms;
    while (now_ms() < deadline) {
        mb_turn(e);
        if (e->mb.rec_seen >= n) {
            return;
        }
    }
}

static void mb_run_until_new_stream(mb_env_t *e, int ms) {
    uint64_t deadline = now_ms() + (uint64_t)ms;
    while (now_ms() < deadline) {
        mb_turn(e);
        if (e->sh.new_stream_count >= 1) {
            for (int i = 0; i < 4; i++) {
                mb_turn(e);
            }
            return;
        }
    }
}

/* ---- CASE 2: DELIBERATE REORDERING ---- */

/* THE ONLY TEST IN THIS MODULE THAT PROVES THE MODE DOES ANYTHING.
 *
 * Over loopback with NumConn 4, frames essentially never arrive out of
 * order; module 9's scouting report could not force a single instance,
 * and task 7's review measured the consequence directly -- an ORDERED
 * client session under an UNORDERED server session carried its datagram
 * byte for byte with every counter in the harness matching. So the two
 * modes are observationally identical until something reorders, and the
 * middle box above is that something.
 *
 * Both modes are run through the SAME fixture. A test that only ever saw
 * one of them would pass against an implementation that ignored the
 * ordering field entirely. */
static void run_reordering(cloak_session_ordering_t ordering, const char *label) {
    /* THE TWO FRAMES MUST COME FROM TWO DIFFERENT CONNECTIONS, and that is
     * a DRAW, not a choice: cloak_switchboard_send picks uniformly at
     * random per frame (and in unordered mode it does so for every
     * datagram of every stream, because Go stops pinning a stream to one
     * connection there). So this retries until it has the two-connection
     * arrangement the mode exists for. P(one attempt fails) = 1/2 and the
     * loop is bounded by the clock at 5 s against a measured ~15 ms per
     * attempt, so exhausting it is a ~2^-300 event and is reported as a
     * failure rather than skipped. */
    uint64_t deadline = now_ms() + 5000;
    for (;;) {
        mb_env_t e;
        mb_env_init(&e, ordering, MB_REVERSE2);

        cloak_stream_t *cs = cloak_session_open_stream(&e.client, NULL);
        ASSERT_TRUE(cs != NULL);
        if (cs == NULL) {
            mb_env_close(&e);
            return;
        }

        uint8_t a[64];
        uint8_t b[64];
        memset(a, 0xA1, sizeof(a));
        memset(b, 0xB2, sizeof(b));
        /* ONE FRAME AT A TIME INTO THE MIDDLE BOX, AND THAT IS NOT
         * fussiness -- it was a defect. Writing both and then draining
         * means the box scans its two connections in INDEX order, so when
         * the switchboard happened to put A on the higher-numbered
         * connection the box saw B first and "reversed" them back into
         * generation order: no reordering at all, and the case failed
         * about half the time. Holding until the box has SEEN the first
         * frame is what makes held[0] == A and held[1] == B by
         * construction rather than by luck. */
        ASSERT_EQ_INT(64, cloak_stream_write(cs, a, sizeof(a)));
        mb_run_until_seen(&e, 1, 1000);
        ASSERT_EQ_INT(64, cloak_stream_write(cs, b, sizeof(b)));
        mb_run_until_seen(&e, 2, 1000);

        /* THE LATER FRAME FIRST, AND ONLY THEN THE EARLIER ONE. The box
         * released B the moment it had both; the test waits until the peer
         * session has actually taken delivery (one frame for an unknown id
         * creates a stream there in BOTH modes, whatever its seq) and only
         * then lets A through. Writing the two records back to back does
         * NOT reverse the delivery: the receiving reactor drains both
         * sockets in one turn and dispatches them in fd order, which is
         * how the first version of this case passed in Debug and failed
         * under ASan. */
        mb_run_until(&e, 1, 1000);
        mb_run_until_new_stream(&e, 1000);
        e.mb.release_deferred = 1;
        mb_run_until(&e, 2, 1000);

        int two_conns = e.mb.rec_seen >= 2 && e.mb.rec_conn[0] != e.mb.rec_conn[1];
        if (!two_conns && now_ms() < deadline) {
            cloak_session_release_stream(&e.client, cs);
            if (e.sh.last_new_stream != NULL) {
                cloak_session_release_stream(&e.server, e.sh.last_new_stream);
            }
            mb_env_close(&e);
            continue;
        }
        if (!two_conns) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: after 5 s the switchboard never put the two frames on "
                    "different connections (last: %zu and %zu)\n",
                    __FILE__, __LINE__, label, e.mb.rec_conn[0], e.mb.rec_conn[1]);
            cloak_test_failures++;
        }

        ASSERT_EQ_INT(1, e.sh.new_stream_count);
        cloak_stream_t *ss = e.sh.last_new_stream;
        ASSERT_TRUE(ss != NULL);
        ASSERT_EQ_INT(2, (long long)e.mb.released);

        uint8_t got[256];
        if (ss == NULL) {
            cloak_session_release_stream(&e.client, cs);
            mb_env_close(&e);
            return;
        }

        if (ordering == CLOAK_SESSION_ORDERING_UNORDERED) {
            /* ARRIVAL ORDER, NOT SEQUENCE ORDER. The second datagram was
             * released first, so it must be delivered first -- one frame
             * in, one datagram out, no reassembly and no waiting. An
             * implementation that quietly used the ordered receive path
             * would hand back A then B here and pass every other test in
             * this tree, including both halves of case 1. */
            long n1 = cloak_stream_read(ss, got, sizeof(got));
            ASSERT_EQ_INT(64, n1);
            if (n1 == 64) {
                ASSERT_EQ_INT(0xB2, got[0]);
                ASSERT_EQ_INT(0xB2, got[63]);
            }
            long n2 = cloak_stream_read(ss, got, sizeof(got));
            ASSERT_EQ_INT(64, n2);
            if (n2 == 64) {
                ASSERT_EQ_INT(0xA1, got[0]);
                ASSERT_EQ_INT(0xA1, got[63]);
            }
            /* And nothing else: two frames in, two datagrams out. */
            ASSERT_EQ_INT(0, cloak_stream_read(ss, got, sizeof(got)));
        } else {
            /* SORTED. The ordered path holds the out-of-order frame on its
             * seq heap until its predecessor arrives, then delivers a
             * gap-free byte stream: A's 64 bytes then B's, whatever order
             * the wire chose. Reading is byte-oriented here, so one read
             * may return both. */
            size_t total = 0;
            while (total < 128) {
                long n = cloak_stream_read(ss, got + total, sizeof(got) - total);
                if (n <= 0) {
                    break;
                }
                total += (size_t)n;
            }
            ASSERT_EQ_INT(128, (long long)total);
            if (total == 128) {
                int ok = 1;
                for (size_t i = 0; i < 64; i++) {
                    if (got[i] != 0xA1 || got[64 + i] != 0xB2) {
                        ok = 0;
                    }
                }
                if (!ok) {
                    fprintf(stderr,
                            "FAIL %s:%d: the ordered receiver delivered the two frames in "
                            "ARRIVAL order (first byte 0x%02x); it must reassemble them by "
                            "sequence\n",
                            __FILE__, __LINE__, got[0]);
                    cloak_test_failures++;
                }
            }
        }

        printf("   %s: 2 frames from connections %zu and %zu, released REVERSED, delivery %s\n",
               label, e.mb.rec_conn[0], e.mb.rec_conn[1],
               ordering == CLOAK_SESSION_ORDERING_UNORDERED ? "in ARRIVAL order"
                                                            : "SORTED by seq");

        cloak_session_release_stream(&e.client, cs);
        cloak_session_release_stream(&e.server, ss);
        mb_env_close(&e);
        return;
    }
}

static void test_deliberate_reordering(void) {
    printf("-- case2: a middle box releases two frames REVERSED (loopback will not do it)\n");
    run_reordering(CLOAK_SESSION_ORDERING_UNORDERED, "unordered");
    run_reordering(CLOAK_SESSION_ORDERING_ORDERED, "ordered  ");
}

/* ---- CASE 5: DUPLICATE / LATE FRAME REPLAY, END TO END ---- */

/* Task 3 asserted this policy at cloak_stream_feed_frame's RETURN VALUE
 * and wrote, in its own report: "What is NOT proven: that a duplicate
 * frame leaves a stream in a live session un-retired ... Doing that needs
 * a frame-replaying middle-box harness, which the plan assigns to task 8."
 * This is it, and it is deliberately end to end: a real frame, on a real
 * socket, replayed by a third party, reaching cloak_session_on_envelope a
 * second time.
 *
 * THE TWO MODES DIVERGE AND BOTH BEHAVIOURS ARE GO'S:
 *   UNORDERED  no sequence state exists (datagramBufferedPipe consults
 *              none), so the replayed datagram is DELIVERED AGAIN and the
 *              stream keeps working. That is not a bug being tolerated --
 *              it is the documented shape of a datagram pipe.
 *   ORDERED    the seq is below next_recv_seq, which is a protocol
 *              violation, and the stream is RETIRED.
 * Asserting both from one fixture is what makes either meaningful. */
static void run_replay(cloak_session_ordering_t ordering, const char *label) {
    mb_env_t e;
    mb_env_init(&e, ordering, MB_DUPLICATE1);

    cloak_stream_t *cs = cloak_session_open_stream(&e.client, NULL);
    ASSERT_TRUE(cs != NULL);

    uint8_t a[48];
    memset(a, 0xA1, sizeof(a));
    ASSERT_EQ_INT(48, cloak_stream_write(cs, a, sizeof(a)));
    mb_run(&e, 200);

    ASSERT_EQ_INT(1, e.sh.new_stream_count);
    cloak_stream_t *ss = e.sh.last_new_stream;
    ASSERT_TRUE(ss != NULL);
    if (ss == NULL) {
        mb_env_close(&e);
        return;
    }
    /* The replay really happened: three records left the middle box for
     * the two the client wrote. Without this the case could pass because
     * nothing was ever duplicated. */
    ASSERT_EQ_INT(0, e.mb.armed);
    ASSERT_EQ_INT(2, (long long)e.mb.released);

    /* A LATE frame as well as a duplicate one: a second datagram is sent
     * AFTER the replay, so in ordered mode the replayed seq 0 is strictly
     * below next_recv_seq rather than merely equal to a pending entry. */
    uint8_t b[48];
    memset(b, 0xB2, sizeof(b));
    long w2 = cloak_stream_write(cs, b, sizeof(b));
    ASSERT_EQ_INT(48, w2);
    mb_run(&e, 200);

    uint8_t got[256];
    if (ordering == CLOAK_SESSION_ORDERING_UNORDERED) {
        long n1 = cloak_stream_read(ss, got, sizeof(got));
        ASSERT_EQ_INT(48, n1);
        long n2 = cloak_stream_read(ss, got, sizeof(got));
        ASSERT_EQ_INT(48, n2);
        long n3 = cloak_stream_read(ss, got, sizeof(got));
        ASSERT_EQ_INT(48, n3);
        /* THE DUPLICATE WAS DELIVERED AGAIN AND THE SECOND DATAGRAM STILL
         * CROSSED. Three deliveries for two datagrams sent: 0xA1, 0xA1,
         * 0xB2 in arrival order. A "the duplicate was dropped"
         * implementation returns two; a "the duplicate killed the stream"
         * implementation returns one and then -1. */
        if (n3 == 48) {
            ASSERT_EQ_INT(0xB2, got[0]);
        }
        /* And the stream is alive, not retired. */
        ASSERT_EQ_INT(0, cloak_stream_read(ss, got, sizeof(got)));
        printf("   %s: replayed frame DELIVERED TWICE, stream still live, later datagram "
               "crossed\n",
               label);
    } else {
        /* WHAT RETIREMENT LOOKS LIKE FROM OUTSIDE, AND IT IS NOT -1.
         * MEASURED, and it corrected this case's first draft:
         * session_retire_stream (session.c:56) tombstones the strmtab
         * entry and drops the active-stream count -- it does NOT mark the
         * receive queue EOF, so cloak_stream_read on a retired-but-drained
         * stream returns 0, not -1. The observable consequence of the
         * retirement is therefore the one that matters end to end: NO
         * FURTHER FRAME IS ROUTED TO THE STREAM. The second datagram, sent
         * after the replay and perfectly valid, never arrives.
         *
         * So the assertion is a total: exactly the ORIGINAL 48 bytes, and
         * nothing else, ever.
         *   - an implementation that ACCEPTED the duplicate delivers 144
         *     (A, A, B) or 96 (A, B);
         *   - one that merely DROPPED the duplicate without retiring
         *     delivers 96 (A, B);
         *   - the one we have delivers 48.
         * And the stream is not resurrected under a new identity, which
         * is what new_stream_count pins. */
        size_t total = 0;
        for (;;) {
            long n = cloak_stream_read(ss, got + (total % 128), sizeof(got) - 128);
            if (n <= 0) {
                break;
            }
            total += (size_t)n;
            if (total > 1024) {
                break;
            }
        }
        ASSERT_EQ_INT(48, (long long)total);
        ASSERT_EQ_INT(1, e.sh.new_stream_count);
        printf("   %s: replayed frame RETIRED the stream -- %zu byte(s) delivered in total, "
               "the later datagram never routed\n",
               label, total);
    }

    cloak_session_release_stream(&e.client, cs);
    cloak_session_release_stream(&e.server, ss);
    mb_env_close(&e);
}

static void test_duplicate_and_late_frame_replay(void) {
    printf("-- case5: a middle box REPLAYS a frame into a live session (task 3 deferred this "
           "here)\n");
    run_replay(CLOAK_SESSION_ORDERING_UNORDERED, "unordered");
    run_replay(CLOAK_SESSION_ORDERING_ORDERED, "ordered  ");
}

/* ================================================================== */
/* CASE 4: NO ORACLE, DISTRIBUTIONS                                    */
/* ================================================================== */

/* THE PROPERTY NO ORACLE CAN SEE, NUMBER TWO.
 *
 * Module 8 found FOUR distribution biases that no interoperability test
 * could see. One of them drew the frame padding length as `one random byte
 * % 240`: 256 = 240 + 16, so the sixteen smallest pad lengths came out
 * TWICE as often as the other 224 -- measured at 12.547 % against Go's
 * 6.667 % over 200,000 frames. That went straight onto the wire, in the
 * padding whose stated purpose in Go's own comment is "Pad to avoid size
 * side channel leak", and it survived five modules because both ends of
 * every test agreed and the interop oracle only ever checks that frames
 * DECODE, never how long they are.
 *
 * test_frame.c pins the draw at cloak_frame_obfuscate. THIS case pins it
 * where module 9 would hide a fifth: through cloak_stream_write on an
 * UNORDERED stream, which is a separate send path with its own seq
 * handling -- and where the padding decision depends on a sequence number
 * that a "the receiver ignores seq anyway" change would flatten. Under a
 * constant seq every frame is seq 0, every frame is padded, and the
 * boundary assertion below fails; under a per-frame reset the same. */

#define PAD_STREAMS 4800u
#define PAD_PER_STREAM CLOAK_FRAME_PAD_FIRST_N_FRAMES
#define PAD_DRAWS (PAD_STREAMS * PAD_PER_STREAM) /* 24000 */
#define PAD_BINS 240
/* MEASURED, in the dev image, on this exact loop -- 15 runs of the shipped
 * sampler and 5 of the mutated one (mutation M3, which restores the byte
 * modulo this project actually shipped for five modules):
 *   fixed (cloak_random_below)  chi2  209.7 ..  270.7   [0,15] 1507..1663
 *   mutated (`b % 240`)         chi2 1475.6 .. 1655.2   [0,15] 2976..3055
 * The threshold sits in that gap and the mutation was WATCHED TO FAIL:
 * "chi2 = 1550.6, not < 420.0" and "2988 not in [1368, 1832]". Expected
 * chi2 for 239 degrees of freedom is 239 with sigma 21.9, so 420 is about
 * +8 sigma -- deliberately loose, because a flaky distribution test gets
 * deleted and a strict one catches nothing a 2x bias would not also trip. */
#define PAD_CHI2_THRESHOLD 420.0
/* Expected 24000 * 16/240 = 1600, sigma = sqrt(24000 * (1/15)(14/15)) =
 * 38.6; the bracket is +/- 6 sigma. The biased sampler lands near 3000. */
#define PAD_LOW_MIN 1368ul
#define PAD_LOW_MAX 1832ul

typedef struct {
    unsigned long counts[PAD_BINS];
    unsigned long out_of_range;
    unsigned long padded_past_boundary;
    unsigned long frames;
    cloak_obfuscator_t o;
} pad_ctx_t;

static int pad_sink(void *userdata, const uint8_t *bytes, size_t len) {
    pad_ctx_t *p = (pad_ctx_t *)userdata;
    /* The frame as it would go on the wire: 14 header + payload + pad +
     * 16 tag. The payload is a fixed 10 bytes, so the pad length is the
     * only degree of freedom in `len`. Deobfuscating would work too, but
     * the LENGTH is the thing a passive observer sees, and the length is
     * therefore what is measured. */
    long pad = (long)len - (long)(CLOAK_FRAME_HEADER_LEN + 10 + 16);
    p->frames++;
    if (pad < 0 || pad >= PAD_BINS) {
        p->out_of_range++;
        return 0;
    }
    if (p->frames > PAD_PER_STREAM) {
        /* Frames past the boundary, counted separately below. */
    }
    p->counts[pad]++;
    (void)bytes;
    return 0;
}

typedef struct {
    size_t n;
    size_t extra[16];
} boundary_ctx_t;

static int boundary_sink(void *userdata, const uint8_t *bytes, size_t len) {
    boundary_ctx_t *b = (boundary_ctx_t *)userdata;
    (void)bytes;
    if (b->n < sizeof(b->extra) / sizeof(b->extra[0])) {
        b->extra[b->n] = len - (CLOAK_FRAME_HEADER_LEN + 10);
    }
    b->n++;
    return 0;
}

static void test_padding_distribution_unordered(void) {
    printf("-- case4a: the pad/no-pad boundary at frame %d and the padding-length "
           "distribution, UNORDERED (NO ORACLE)\n",
           CLOAK_FRAME_PAD_FIRST_N_FRAMES);

    const uint8_t payload[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    /* ---- the boundary, exactly ---- */
    {
        cloak_obfuscator_t o;
        o.method = CLOAK_AEAD_AES_256_GCM;
        cloak_random_bytes(o.session_key, sizeof(o.session_key));
        boundary_ctx_t b;
        memset(&b, 0, sizeof(b));
        cloak_stream_t s;
        ASSERT_EQ_INT(0, cloak_stream_init(&s, 7, &o, MAX_ON_WIRE, 65536, 64,
                                            CLOAK_SESSION_ORDERING_UNORDERED, boundary_sink, &b));
        for (int i = 0; i < 12; i++) {
            ASSERT_EQ_INT(10, cloak_stream_write(&s, payload, sizeof(payload)));
        }
        cloak_stream_destroy(&s);
        ASSERT_EQ_INT(12, (long long)b.n);
        /* PAST THE BOUNDARY: EXACTLY THE TAG, EVERY TIME. This is the
         * half that is a theorem, and it is the half a "seq = 0"
         * simplification breaks -- with a constant seq every frame here
         * carries padding and every one of these seven assertions fails. */
        for (size_t i = PAD_PER_STREAM; i < b.n; i++) {
            if (b.extra[i] != 16) {
                fprintf(stderr,
                        "FAIL %s:%d: unordered frame %zu carried extra_len %zu; past frame %d "
                        "there must be no padding at all\n",
                        __FILE__, __LINE__, i, b.extra[i], CLOAK_FRAME_PAD_FIRST_N_FRAMES);
                cloak_test_failures++;
            }
        }
        /* BEFORE the boundary padding is a DRAW, so "every one of the
         * first five is padded" is not a theorem (pad_len 0 happens 1 time
         * in 240). What is asserted is that at least one of the first five
         * is padded, which over five independent draws fails with
         * probability 240^-5 ~= 1.3e-12. */
        int any_padded = 0;
        for (size_t i = 0; i < PAD_PER_STREAM && i < b.n; i++) {
            if (b.extra[i] > 16) {
                any_padded = 1;
            }
        }
        ASSERT_TRUE(any_padded);
    }

    /* ---- the distribution ---- */
    static pad_ctx_t p;
    memset(&p, 0, sizeof(p));
    p.o.method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(p.o.session_key, sizeof(p.o.session_key));

    for (unsigned long st = 0; st < PAD_STREAMS; st++) {
        cloak_stream_t s;
        p.frames = 0;
        ASSERT_EQ_INT(0, cloak_stream_init(&s, (uint32_t)(st + 1), &p.o, MAX_ON_WIRE, 65536, 64,
                                            CLOAK_SESSION_ORDERING_UNORDERED, pad_sink, &p));
        for (unsigned i = 0; i < PAD_PER_STREAM; i++) {
            if (cloak_stream_write(&s, payload, sizeof(payload)) != 10) {
                p.out_of_range++;
                break;
            }
        }
        cloak_stream_destroy(&s);
    }
    ASSERT_EQ_INT(0, (long long)p.out_of_range);

    unsigned long total = 0;
    for (int i = 0; i < PAD_BINS; i++) {
        total += p.counts[i];
    }
    ASSERT_EQ_INT((long long)PAD_DRAWS, (long long)total);

    ASSERT_UNIFORM_CHI_SQUARE(p.counts, PAD_BINS, PAD_DRAWS, PAD_CHI2_THRESHOLD);

    /* The defect NAMED rather than merely detected. A chi-square says
     * "not uniform"; this says which sixteen values carried twice their
     * share, which is the actual shipped defect's signature. */
    unsigned long low = 0;
    for (int v = 0; v < 16; v++) {
        low += p.counts[v];
    }
    ASSERT_COUNT_IN_RANGE("unordered first-five-frame pad lengths in [0,15]", low, PAD_LOW_MIN,
                          PAD_LOW_MAX);
    printf("   %lu padded frames over %u unordered streams, chi2 = %.1f, [0,15] = %lu\n", total,
           PAD_STREAMS, cloak_test_chi_square_uniform(p.counts, PAD_BINS, PAD_DRAWS), low);
}

/* The switchboard's connection pick. Module 9's plan flagged this and did
 * NOT measure it: "whether the C switchboard's connection pick is
 * bias-free like Go's Uint32N ... was flagged for measurement and not
 * measured. Measure it in Task 8 case 4."
 *
 * It matters specifically in UNORDERED mode: Go stops pinning a stream to
 * one connection there (Stream.assignedConn is documented as "not used in
 * unordered connection mode"), so EVERY datagram of every stream takes a
 * fresh draw from this generator. A biased pick is a traffic-analysis
 * signal -- connection load ratios that no other implementation produces
 * -- and, like every other distribution, no round-trip test can see it.
 *
 * MEASURED HERE, NOT ASSUMED: cloak_switchboard_send is
 * `xorshift32(&state) % conns_len`. With conns_len a power of two the
 * modulo is exact, so what is actually under test is xorshift32's LOW
 * BITS, which is the half of a linear generator most likely to be weak.
 * A non-power-of-two pool is measured too, where the modulo itself could
 * bias (it does not: the reduction is over 2^32, not over 256, so the
 * worst-case excess is about 1 in 1.4 billion -- which is why the
 * 240-value byte modulo was a 2x defect and this is not). */
/* MEASURED, 15 runs each: 4 connections chi2 0.27 .. 10.31 (3 d.f.,
 * expected 3), 3 connections chi2 0.17 .. 9.87 (2 d.f., expected 2). So
 * the pick IS unbiased, which is the answer the plan asked for and did
 * not have. The thresholds are set well above the observed maxima rather
 * than at a textbook quantile: P(chi2_3 > 30) = 1.4e-6 and
 * P(chi2_2 > 25) = 3.7e-6, which is the flake budget this project's
 * distribution tests are held to, and they still kill the mutations that
 * matter by three orders of magnitude -- an always-pick-connection-0
 * switchboard scores 72000 here (mutation M8, run).
 *
 * WHAT THIS DOES NOT CATCH, and it is worth writing down rather than
 * leaving as an unexamined pass: a ROUND-ROBIN pick is perfectly uniform
 * and sails through both assertions. Mutation M9 replaced the xorshift
 * with `counter++ % conns_len` and NOT ONE of the 75 tests failed, even
 * though round robin is wire-visible -- a passive observer sees the
 * connections used in strict rotation, which no other Cloak
 * implementation produces. A chi-square tests the marginal distribution,
 * not independence, and nothing in this tree tests independence. */
#define PICK_SENDS 24000ul
#define PICK_CHI2_4 30.0
#define PICK_CHI2_3 25.0

static void sb_on_envelope(cloak_switchboard_t *sb, const uint8_t *frame_bytes, size_t frame_len,
                           void *userdata) {
    (void)sb;
    (void)frame_bytes;
    (void)frame_len;
    (void)userdata;
}

static void sb_on_broken(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    int *broken = (int *)userdata;
    (*broken)++;
}

static void measure_pick(size_t nconn, double threshold) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    int broken = 0;
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(0, cloak_switchboard_init(&sb, r, 4096, 65536, sb_on_envelope, NULL,
                                             sb_on_broken, &broken));

    int peer[8];
    for (size_t i = 0; i < nconn; i++) {
        int fds[2];
        ASSERT_EQ_INT(0, nonblocking_pair(fds));
        ASSERT_EQ_INT(0, cloak_switchboard_add_conn(&sb, fds[0]));
        peer[i] = fds[1];
    }

    unsigned long counts[8];
    memset(counts, 0, sizeof(counts));
    uint8_t payload[1] = {0xAB};
    uint8_t sink[4096];
    for (unsigned long i = 0; i < PICK_SENDS; i++) {
        ASSERT_EQ_INT(0, cloak_switchboard_send(&sb, payload, sizeof(payload)));
        for (size_t c = 0; c < nconn; c++) {
            ssize_t n = read(peer[c], sink, sizeof(sink));
            if (n > 0) {
                /* 5 record header + 1 payload per send, so a read that
                 * caught several is several picks. */
                counts[c] += (unsigned long)n / 6u;
            }
        }
    }
    unsigned long total = 0;
    for (size_t c = 0; c < nconn; c++) {
        total += counts[c];
    }
    ASSERT_EQ_INT((long long)PICK_SENDS, (long long)total);
    ASSERT_UNIFORM_CHI_SQUARE(counts, nconn, PICK_SENDS, threshold);
    printf("   %zu connections, %lu picks, chi2 = %.2f\n", nconn, total,
           cloak_test_chi_square_uniform(counts, nconn, PICK_SENDS));

    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
    for (size_t i = 0; i < nconn; i++) {
        close(peer[i]);
    }
}

static void test_connection_pick_is_unbiased(void) {
    printf("-- case4b: the switchboard's connection pick (flagged for measurement by the plan "
           "and never measured)\n");
    measure_pick(4, PICK_CHI2_4);
    measure_pick(3, PICK_CHI2_3);
}

/* ------------------------------------------------------------------ */

static int oracle_binaries_present(void) {
    static const char *const paths[] = {GO_CK_CLIENT_PATH, GO_CK_SERVER_PATH};
    int ok = 1;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (access(paths[i], X_OK) != 0) {
            fprintf(stderr, "FAIL %s: the Go interoperability oracle is not executable: %s (%s)\n",
                    __FILE__, paths[i], strerror(errno));
            ok = 0;
        }
    }
    if (!ok) {
        fprintf(stderr,
                "Dockerfile.dev's `gobuild` stage builds Go Cloak v2.12.0's own ck-client and "
                "ck-server into /usr/local/bin of the cloak-c-dev image, which is what this "
                "test is run in. Rebuild the image (docker build -f Dockerfile.dev -t "
                "cloak-c-dev .), or point -DCLOAK_GO_CK_CLIENT= and -DCLOAK_GO_CK_SERVER= at "
                "binaries you built yourself.\n");
    }
    return ok;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (!oracle_binaries_present()) {
        return 1;
    }

    uint64_t t0 = now_ms();
    test_ladder_go_client_to_c_server();
    test_ladder_c_client_to_go_server();
    uint64_t t1 = now_ms();
    test_deliberate_reordering();
    test_seq_is_still_generated_and_monotonic();
    test_padding_distribution_unordered();
    test_connection_pick_is_unbiased();
    test_duplicate_and_late_frame_replay();
    uint64_t t2 = now_ms();

    printf("-- timing: oracle cases %llu ms, white-box cases %llu ms\n",
           (unsigned long long)(t1 - t0), (unsigned long long)(t2 - t1));

    if (cloak_test_failures > 0) {
        fprintf(stderr, "%d assertion(s) failed\n", cloak_test_failures);
        return 1;
    }
    printf("All tests passed\n");
    return 0;
}
