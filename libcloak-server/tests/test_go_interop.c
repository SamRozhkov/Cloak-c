#define _POSIX_C_SOURCE 200809L

/* THE DIRECT TLS PATH AND THE WHOLE C CLIENT, AGAINST GO'S OWN BINARIES.
 *
 * WHY THIS FILE EXISTS. Eight modules in, every test in this tree had our
 * implementation on BOTH ends of the wire. The one time that changed --
 * module 8's WebSocket oracle, which put gorilla/websocket in front of our
 * server -- it discovered on its first day that this port could not
 * exchange a single data frame with the implementation it is a port of:
 * two header bytes were passed as AES-GCM associated data where Go passes
 * nil, so the handshake succeeded, the session key was correct, and every
 * frame was silently dropped. That defect had survived five modules for
 * exactly one reason -- a round trip between two copies of the same
 * mistake always agrees.
 *
 * The DIRECT (TLS-shaped) path and the C CLIENT had never had that
 * treatment at all. This file gives it to them, by driving Go Cloak's own
 * `ck-client` and `ck-server` binaries (v2.12.0, built into the dev image
 * by Dockerfile.dev's `gobuild` stage) as subprocesses at the far end.
 *
 * WHAT EACH CASE IS FOR, and what would have to break for it to fail:
 *
 *   1. GO ck-client -> C ck-server. A real Go client, a real C server, a
 *      TCP session, 128 KiB compared byte for byte in both directions.
 *      This exercises OUR ClientHello parser (on a uTLS-generated Chrome
 *      hello, which is over 1500 bytes and therefore arrives in several
 *      reads), OUR auth decrypt, OUR ServerHello composer, OUR frame
 *      DEcoder and OUR proxy relay.
 *
 *   2. C ck-client -> GO ck-server. The mirror. This exercises our
 *      ClientHello GENERATOR, our auth payload, our frame ENcoder and our
 *      local TCP listener -- and it is the only test in this tree that
 *      would notice if our sender misbehaved, because Go's receiver is the
 *      only receiver that is not also ours.
 *
 *   3. NEGATIVE CONTROL. Case 1 again, with exactly one byte of the C
 *      server's ServerHello flipped in flight, and nothing else changed.
 *      The Go client must REFUSE -- it must log its handshake failure and
 *      no application byte may cross. A positive-only interoperability
 *      test proves nothing: it cannot distinguish "the two implementations
 *      agree" from "the assertion cannot fail". Module 8's controls (an
 *      unmasked client and a masked server, both of which drew a "bad
 *      MASK" from gorilla) are what made its passes mean anything.
 *
 *   5. THE MIRROR OF THE CONTROL, ADDED AFTER REVIEW. Case 3 proves GO's
 *      client refuses; nothing proved OURS did. A C client that ignored
 *      the ServerHello's AES-GCM tag entirely passed all four of the
 *      original cases, because an honest Go server always produces a
 *      valid tag. So case 5 is case 2 with one bit flipped in a GO
 *      server's ServerHello, and our client must refuse it.
 *
 *   4. BYTE 41 IS 0 IN BOTH DIRECTIONS. The auth payload's flag byte
 *      (bit 0 = unordered) is read off the wire by this test itself -- it
 *      decrypts the ClientHello it relayed, using the server private key
 *      it generated the configuration with -- and asserted 0 for the Go
 *      client's hello and 0 for the C client's hello. Both are the ORDERED
 *      baseline module 9 task 7 has to flip; a task-7 change that sets the
 *      bit unconditionally, or that never sets it, is now visible here.
 *
 * HOW THE BYTES ARE OBSERVED AT ALL. Every case puts a man-in-the-middle
 * TCP relay of this test's own between the Cloak client and the Cloak
 * server. It is the only way to see the ClientHello (case 4) and the only
 * way to corrupt one byte of the ServerHello without editing either
 * implementation (case 3), and running it in the positive cases too means
 * case 3 differs from case 1 in ONE FLIPPED BIT and nothing else.
 *
 * WHAT THIS FILE DOES NOT COVER, stated so nobody reads more into a pass
 * than is there: no distribution of any kind (padding length, SNI choice,
 * connection pick) -- those need the chi-square assertions in
 * test_framework.h and their own test; no real reordering, since frames
 * over loopback essentially never arrive out of order; no CDN/WebSocket
 * leg (that is test_ws_interop's); and nothing about a real network.
 *
 * EVERY WAIT IS BOUNDED BY THE CLOCK, never by an iteration count, and
 * the binaries this file needs are checked for BEFORE any case runs, so a
 * missing oracle is reported in milliseconds as a named missing file
 * rather than as a two-minute ctest timeout. */

#include "cloak/base64.h"
#include "cloak/clienthello_parse.h"
#include "cloak/crypto.h"
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
/* Budgets                                                             */
/* ------------------------------------------------------------------ */

#define OUT_CAP 65536
#define BOOT_MS 15000
#define EXIT_MS 5000
/* One transfer's budget, and EVERY NUMBER ABOVE AND BELOW IS SET FROM THE
 * WORST *FAILING* RUN, NOT THE PASSING ONE -- because the failing run is
 * the one that has to fit inside ctest's TIMEOUT 120 and still print its
 * own named assertion instead of being truncated as "***Timeout".
 *
 * MEASURED, in Debug, during this file's mutation campaign: a healthy
 * transfer is 45-55 ms, and a BROKEN one (the frame-AEAD mutation, which
 * makes Go and C drop each other's frames) stalls until this bound and
 * then reports three named assertions. At the 30000 first written here,
 * the two positive cases alone spent 60 s of a 120 s budget on one
 * mutation; 15000 is still a ~300x margin over the healthy figure and
 * leaves the whole file's worst failing path at roughly
 *   (XFER_MS + 2*EXIT_MS) * 2  +  (HANDSHAKE_FAIL_MS + QUIET_MS + 2*EXIT_MS) * 2
 *   = 50 + 2 * 20 = 90 s,
 * counting BOTH negative controls, which is what TIMEOUT 120 has to
 * cover. That sum assumes every one of the six children also ignores
 * SIGTERM; the realistic worst failing run measured here is about half of
 * it. The case prints what it actually took, so this is a backstop and
 * not the mechanism. */
#define XFER_MS 15000
/* The negative controls' two windows. HANDSHAKE_FAIL_MS is how long a
 * client gets to say it refused; QUIET_MS is how long the application end
 * is then watched for a byte that must never come.
 *
 * CUT FROM 15000 WHEN THE SECOND NEGATIVE CONTROL WAS ADDED, because two
 * of these windows now sit in the same TIMEOUT 120 as two XFER_MS ones.
 * Both clients log their refusal on the FIRST failed handshake -- Go's
 * MakeSession logs before its 3 s sleep, not after, and ours narrates the
 * stack event immediately -- so this window only ever has to cover one
 * round trip on loopback. Measured below in each case's printed line. */
#define HANDSHAKE_FAIL_MS 8000
#define QUIET_MS 2000

/* 128 KiB. Go's client caps one on-wire message at appDataMaxLength =
 * 16401 bytes (internal/client/TLS.go), so a payload this size CANNOT fit
 * in fewer than eight frames in either direction. That number is read off
 * Go's source, not measured here -- this file never decrypts a data frame,
 * so it cannot count them; counting frames is module 9 task 3's white-box
 * job. What IS measured here is that all 131072 bytes arrive, transformed,
 * in both directions. */
#define PAYLOAD_LEN 131072

/* ------------------------------------------------------------------ */
/* Clock                                                               */
/* ------------------------------------------------------------------ */

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ------------------------------------------------------------------ */
/* Subprocess plumbing                                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    pid_t pid;
    int fd; /* the child's stdout and stderr, merged */
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
        /* Everything above stderr belongs to the TEST -- the relay's
         * listener, the upstream's, ctest's own pipes. None of it has any
         * business surviving into a Cloak binary, and a Go child that
         * inherited the relay's listening socket would keep this test's
         * own port alive after the test closed it. */
        close_inherited_fds();
        execv(path, argv);
        _exit(127);
    }
    close(pipefd[1]);
    c->pid = pid;
    c->fd = pipefd[0];
    return 0;
}

/* Pulls whatever is readable right now into c->out. Returns 1 on EOF. */
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
        return 0; /* full: stop reading rather than spinning */
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

/* ------------------------------------------------------------------ */
/* The harness: a MITM relay, a fake upstream, and an application        */
/* ------------------------------------------------------------------ */

#define MAX_PAIRS 8
#define QCAP 65536
#define HELLO_CAP 8192

/* A one-read-deep queue. The flow-control rule below (never read from a
 * socket whose outbound queue still has bytes in it) is what bounds it to
 * one read, so there is no growth path and no allocation anywhere in this
 * harness. */
typedef struct {
    uint8_t buf[QCAP];
    size_t len;
    size_t off;
} q_t;

static size_t q_pending(const q_t *q) { return q->len - q->off; }

/* Writes what the socket will take. Returns -1 only on a fatal error. */
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
    int cfd; /* accepted from the Cloak client */
    int sfd; /* connected to the Cloak server */
    q_t c2s;
    q_t s2c;
    uint64_t c2s_total;
    uint64_t s2c_total;
    uint8_t hello[HELLO_CAP]; /* the first bytes the client sent, verbatim */
    size_t hello_len;
} relay_pair_t;

typedef struct {
    int listen_fd;
    int port;        /* what the Cloak client is pointed at */
    int server_port; /* what this relay forwards to */
    /* Offset, counted in bytes of the SERVER -> CLIENT stream of each
     * connection, at which one bit is flipped. -1 disables. */
    long corrupt_at;
    relay_pair_t pairs[MAX_PAIRS];
    size_t npairs;
    size_t accepted; /* total connections ever accepted, for diagnostics */
    /* Every byte ever forwarded server -> client, across all pairs
     * including ones already closed. The negative controls use it to
     * prove the refusal happened AFTER a reply was delivered rather than
     * because nothing ever arrived -- without it, "the client refused"
     * and "the client never got anything" are the same assertion. */
    uint64_t s2c_total_all;
} relay_t;

typedef struct {
    relay_t relay;

    /* The fake upstream behind the Cloak server: it does not echo, it
     * XORs. An echoing upstream would let a case pass against a tunnel
     * that never carried anything and simply looped the application's own
     * bytes back at it -- and a session built on the WRONG key establishes
     * cleanly and then drops every frame, so "it connected" proves nothing
     * about the data path. Only transformed bytes coming back do. */
    int up_listen;
    int up_port;
    int up_fd;
    q_t up_out;
    size_t up_seen;
    uint8_t xor_mask;

    /* The application at the near end. */
    int app_fd;
    const uint8_t *send_buf;
    size_t send_len;
    size_t sent;
    uint8_t *reply;
    size_t reply_cap;
    size_t got;
} harness_t;

static void harness_init(harness_t *h) {
    memset(h, 0, sizeof(*h));
    h->relay.listen_fd = -1;
    h->relay.corrupt_at = -1;
    for (size_t i = 0; i < MAX_PAIRS; i++) {
        h->relay.pairs[i].cfd = -1;
        h->relay.pairs[i].sfd = -1;
    }
    h->up_listen = -1;
    h->up_fd = -1;
    h->app_fd = -1;
    h->xor_mask = 0x5a;
}

static void harness_close(harness_t *h) {
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
    if (h->up_listen >= 0) {
        close(h->up_listen);
        h->up_listen = -1;
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

/* One turn of the whole harness. Nothing here blocks for longer than
 * timeout_ms, and every descriptor is non-blocking, so a peer that stalls
 * costs this loop nothing. */
static void harness_pump(harness_t *h, int timeout_ms) {
    struct pollfd pf[2 + 2 * MAX_PAIRS + 2];
    int idx[2 + 2 * MAX_PAIRS + 2]; /* what each slot is: see the tags below */
    enum { T_RELAY_LISTEN, T_CFD, T_SFD, T_UP_LISTEN, T_UP, T_APP };
    int tag[2 + 2 * MAX_PAIRS + 2];
    nfds_t n = 0;

    relay_t *r = &h->relay;

    if (r->listen_fd >= 0 && r->npairs < MAX_PAIRS) {
        pf[n].fd = r->listen_fd;
        pf[n].events = POLLIN;
        tag[n] = T_RELAY_LISTEN;
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
    if (h->up_listen >= 0 && h->up_fd < 0) {
        pf[n].fd = h->up_listen;
        pf[n].events = POLLIN;
        tag[n] = T_UP_LISTEN;
        idx[n] = 0;
        n++;
    }
    if (h->up_fd >= 0) {
        short ev = 0;
        if (q_pending(&h->up_out) == 0) {
            ev |= POLLIN;
        } else {
            ev |= POLLOUT;
        }
        pf[n].fd = h->up_fd;
        pf[n].events = ev;
        tag[n] = T_UP;
        idx[n] = 0;
        n++;
    }
    if (h->app_fd >= 0) {
        short ev = 0;
        if (h->sent < h->send_len) {
            ev |= POLLOUT;
        }
        if (h->got < h->reply_cap) {
            ev |= POLLIN;
        }
        if (ev != 0) {
            pf[n].fd = h->app_fd;
            pf[n].events = ev;
            tag[n] = T_APP;
            idx[n] = 0;
            n++;
        }
    }

    if (n == 0) {
        struct pollfd dummy;
        memset(&dummy, 0, sizeof(dummy));
        dummy.fd = -1;
        poll(&dummy, 1, timeout_ms);
        return;
    }
    int rc = poll(pf, n, timeout_ms);
    if (rc <= 0) {
        return;
    }

    for (nfds_t k = 0; k < n; k++) {
        if (pf[k].revents == 0) {
            continue;
        }
        switch (tag[k]) {
        case T_RELAY_LISTEN: {
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
                    /* The first bytes a Cloak client sends are its
                     * ClientHello, and case 4 decrypts them. */
                    size_t room = HELLO_CAP - p->hello_len;
                    size_t take = ((size_t)got < room) ? (size_t)got : room;
                    memcpy(p->hello + p->hello_len, p->c2s.buf, take);
                    p->hello_len += take;
                    p->c2s_total += (uint64_t)got;
                    if (q_flush(&p->c2s, p->sfd) != 0) {
                        pair_drop(r, (size_t)idx[k]);
                    }
                } else if (got == 0 || (errno != EAGAIN && errno != EWOULDBLOCK &&
                                        errno != EINTR)) {
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
                    /* THE ONE FLIPPED BIT (case 3). corrupt_at is an
                     * offset into this connection's server -> client
                     * stream, so it lands on the same byte of the
                     * ServerHello no matter how the server's write was
                     * split across reads. */
                    if (r->corrupt_at >= 0) {
                        uint64_t lo = p->s2c_total;
                        uint64_t hi = lo + (uint64_t)got;
                        uint64_t at = (uint64_t)r->corrupt_at;
                        if (at >= lo && at < hi) {
                            p->s2c.buf[at - lo] ^= 0x01;
                        }
                    }
                    p->s2c.len = (size_t)got;
                    p->s2c.off = 0;
                    p->s2c_total += (uint64_t)got;
                    r->s2c_total_all += (uint64_t)got;
                    if (q_flush(&p->s2c, p->cfd) != 0) {
                        pair_drop(r, (size_t)idx[k]);
                    }
                } else if (got == 0 || (errno != EAGAIN && errno != EWOULDBLOCK &&
                                        errno != EINTR)) {
                    pair_drop(r, (size_t)idx[k]);
                }
            }
            break;
        }
        case T_UP_LISTEN: {
            int c = accept(h->up_listen, NULL, NULL);
            if (c >= 0) {
                set_nonblock(c);
                h->up_fd = c;
            }
            break;
        }
        case T_UP: {
            if ((pf[k].revents & POLLOUT) != 0) {
                if (q_flush(&h->up_out, h->up_fd) != 0) {
                    close(h->up_fd);
                    h->up_fd = -1;
                }
                break;
            }
            ssize_t got = read(h->up_fd, h->up_out.buf, QCAP);
            if (got > 0) {
                for (ssize_t i = 0; i < got; i++) {
                    h->up_out.buf[i] ^= h->xor_mask;
                }
                h->up_out.len = (size_t)got;
                h->up_out.off = 0;
                h->up_seen += (size_t)got;
                if (q_flush(&h->up_out, h->up_fd) != 0) {
                    close(h->up_fd);
                    h->up_fd = -1;
                }
            } else if (got == 0 ||
                       (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                close(h->up_fd);
                h->up_fd = -1;
            }
            break;
        }
        case T_APP: {
            if ((pf[k].revents & POLLOUT) != 0 && h->sent < h->send_len) {
                ssize_t w = write(h->app_fd, h->send_buf + h->sent, h->send_len - h->sent);
                if (w > 0) {
                    h->sent += (size_t)w;
                }
            }
            if ((pf[k].revents & POLLIN) != 0 && h->got < h->reply_cap) {
                ssize_t got = read(h->app_fd, h->reply + h->got, h->reply_cap - h->got);
                if (got > 0) {
                    h->got += (size_t)got;
                }
            }
            break;
        }
        default:
            break;
        }
    }

    /* Compact the pair table: a pair whose sockets are both gone is dead. */
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

/* Waits for `marker` in the child's merged output WHILE PUMPING THE RELAY.
 * This has to pump: the C client builds its session at startup, so its
 * ClientHello is in flight before the marker it is waited on for can be
 * printed, and a wait that did not move those bytes would deadlock. */
static int wait_for_marker(harness_t *h, child_t *c, const char *marker, int timeout_ms) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        if (strstr(c->out, marker) != NULL) {
            return 0;
        }
        if (now_ms() >= deadline) {
            return -1;
        }
        harness_pump(h, 10);
        if (child_drain(c, 0) == 1) {
            return strstr(c->out, marker) != NULL ? 0 : -1;
        }
    }
}

/* Connects to the Cloak client's local port, retrying until it answers.
 * Go's ck-client logs "Listening on ..." BEFORE it calls net.Listen, so
 * the marker is not proof the socket exists yet -- only a successful
 * connect is. Bounded by the clock. */
static int dial_local_retrying(harness_t *h, int port, int timeout_ms) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        int fd = dial(port);
        if (fd >= 0) {
            return fd;
        }
        if (now_ms() >= deadline) {
            return -1;
        }
        harness_pump(h, 20);
    }
}

/* ------------------------------------------------------------------ */
/* Key and config fixtures                                              */
/* ------------------------------------------------------------------ */

/* One throwaway X25519 private key, and the public key DERIVED from it at
 * runtime rather than written beside it as a second literal: a pair that
 * silently stopped matching would make every case fail with "the tunnel
 * carried nothing", the least diagnosable failure this file can produce. */
#define PRIV_B64 "SN6EG6BhjnLLpGCMqrLzZuSNmEWXOJgEnqN0uaPihgs="
#define UID_B64  "MTIzNDU2Nzg5MGFiY2RlZg==" /* "1234567890abcdef" */

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

/* Writes `content` to a FRESHLY CREATED, UNIQUELY NAMED file and returns
 * its path in path_out.
 *
 * THE UNIQUENESS IS LOAD-BEARING AND mkstemp IS THE ONLY THING THAT
 * DELIVERS IT HERE. Measured, and the measurement is the whole reason
 * this function exists: two concurrent `ctest -R test_go_interop` runs
 * against one build directory failed 5 times out of 5 when the config
 * files had fixed names -- one run overwrote the other's configuration,
 * so a ck-client dutifully listened on the OTHER run's local port and the
 * first run's 15-second dial never connected. `ctest` never schedules one
 * test twice in parallel, but two shells against one build directory is a
 * plausible edit-loop accident (task 0 just created an edit loop), and a
 * sibling task reported exactly this symptom in the wild.
 *
 * PUTTING getpid() IN THE NAME DOES NOT FIX IT, and that was measured
 * too: 5 failures out of 6 with the pid in the name, because inside a
 * container PIDs are namespaced -- two identical `docker run`s hand the
 * test the same small pid, so the "unique" names collided exactly as
 * before. mkstemp asks the filesystem, which is the only namespace both
 * runs actually share.
 *
 * No ".json" suffix: mkstemp requires its XXXXXX to be the last six
 * characters, mkstemps is not POSIX, and neither binary cares about the
 * extension (ck-client decides file-versus-ssv on the content, not the
 * name). */
static int write_temp_unique(char *path_out, size_t cap, const char *name,
                             const char *content) {
    if (snprintf(path_out, cap, "go_interop_%s_XXXXXX", name) >= (int)cap) {
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

/* ONE server configuration text for BOTH servers, and one client
 * configuration text for BOTH clients. That is not tidiness: it is the
 * point. If the two implementations needed different configuration to do
 * the same thing, that would itself be a divergence, and writing the
 * fixture twice would hide it.
 *
 * Written to a FILE rather than passed inline, because Go's
 * server.ParseConfig reads a path and, when the read fails, unmarshals the
 * empty buffer it just failed to fill -- so its own flag help's "path to
 * the configuration file or its content" is false for the server. (Our
 * ck-server accepts both; see the binaries plan's D3.) */
static void write_server_config(char *path_out, size_t cap, const char *name, int bind_port,
                                int upstream_port) {
    char cfg[1024];
    snprintf(cfg, sizeof(cfg),
             "{"
             "\"ProxyBook\":{\"shadowsocks\":[\"tcp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\"127.0.0.1:%d\"],"
             "\"BypassUID\":[\"%s\"],"
             "\"RedirAddr\":\"127.0.0.1:1\","
             "\"PrivateKey\":\"%s\","
             "\"KeepAlive\":0"
             "}",
             upstream_port, bind_port, UID_B64, PRIV_B64);
    ASSERT_EQ_INT(0, write_temp_unique(path_out, cap, name, cfg));
}

static void write_client_config(char *path_out, size_t cap, const char *name,
                                const char *pub_b64, int remote_port, int local_port,
                                int num_conn) {
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
             "\"BrowserSig\":\"chrome\","
             "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"%d\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"%d\""
             "}",
             UID_B64, pub_b64, num_conn, remote_port, local_port);
    ASSERT_EQ_INT(0, write_temp_unique(path_out, cap, name, cfg));
}

/* ------------------------------------------------------------------ */
/* Reading the auth payload back off the wire (case 4)                  */
/* ------------------------------------------------------------------ */

/* Decrypts the relayed ClientHello with the SERVER PRIVATE KEY this test
 * generated the configuration with, and returns the 48-byte authentication
 * payload -- the same bytes the server's own auth decrypt sees, obtained
 * without asking either implementation anything.
 *
 * Layout (Go: internal/client/auth.go makeAuthenticationPayload):
 *   [0:16) UID  [16:28) proxy method  [28] encryption method
 *   [29:37) timestamp  [37:41) session id  [41] FLAGS  [42:48) reserved
 * Bit 0 of byte 41 is UNORDERED_FLAG.
 *
 * Returns 0 on success, or a negative code naming which step failed, so a
 * failure says whether the hello did not parse, the key share was absent,
 * or the AEAD refused. */
static int auth_payload_from_hello(const uint8_t *hello, size_t hello_len,
                                   const uint8_t priv[CLOAK_X25519_KEY_LEN],
                                   uint8_t out48[48]) {
    if (hello_len < 5) {
        return -1;
    }
    size_t record_len = ((size_t)hello[3] << 8) | (size_t)hello[4];
    if (5 + record_len > hello_len) {
        return -2; /* the whole record has not been captured yet */
    }
    cloak_clienthello_parsed_t p;
    if (cloak_clienthello_parse(hello, 5 + record_len, &p) != 0) {
        return -3;
    }
    if (p.session_id == NULL || p.session_id_len != 32 || p.x25519_key_share == NULL) {
        return -4;
    }
    uint8_t ct[64];
    memcpy(ct, p.session_id, 32);
    memcpy(ct + 32, p.x25519_key_share, 32);
    uint8_t secret[CLOAK_X25519_KEY_LEN];
    if (cloak_x25519_shared_secret(priv, p.random, secret) != 0) {
        return -5;
    }
    uint8_t plain[64];
    size_t plain_len = 0;
    if (cloak_aead_open(CLOAK_AEAD_AES_256_GCM, secret, p.random, NULL, 0, ct, sizeof(ct),
                        plain, &plain_len) != 0) {
        return -6;
    }
    if (plain_len != 48) {
        return -7;
    }
    memcpy(out48, plain, 48);
    return 0;
}

/* ------------------------------------------------------------------ */
/* The payload                                                          */
/* ------------------------------------------------------------------ */

static void fill_payload(uint8_t *buf, size_t len, uint32_t seed) {
    uint32_t x = seed;
    for (size_t i = 0; i < len; i++) {
        x = x * 1103515245u + 12345u;
        buf[i] = (uint8_t)(x >> 16);
    }
}

/* ------------------------------------------------------------------ */
/* One end-to-end run, parameterised by which side is Go                */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *name;
    const char *server_path;
    const char *server_ready; /* a marker each binary prints once listening */
    int server_is_go;
    const char *client_path;
    const char *client_ready;
    int client_is_go;
    long corrupt_at; /* -1, or an offset into the server -> client stream */
    /* Negative runs only, and the two clients need DIFFERENT evidence
     * because they narrate differently.
     *
     * `client_refusal`, when non-NULL, is a line the client must print
     * once it has rejected the corrupted ServerHello. Go's ck-client logs
     * one per failed handshake, so it is immediate and reliable.
     *
     * `require_reconnect` asks instead that the relay see MORE
     * connections than one healthy session needs. That is the right
     * evidence for OUR client, which narrates only whole rounds: its
     * connector retries a failed handshake several times inside one round
     * before reporting "round failed", so the round-level line arrives
     * after a delay that depends on machine load. MEASURED: with a
     * "round failed" wait and an 8 s window, four concurrent-run trials
     * out of twelve missed it; the reconnect is visible in milliseconds
     * and cannot be produced by a client that accepted the reply, since
     * with NumConn 1 an accepting client opens exactly one connection and
     * stops.
     *
     * `client_forbidden`, when non-NULL, is a line the client must NOT
     * print -- for ours that is "session up", which is precisely what a
     * client with no ServerHello tag check does print. */
    const char *client_refusal;
    int require_reconnect;
    const char *client_forbidden;
    /* NumConn for the client's configuration. 2 everywhere but case 5 --
     * see that case's comment for why 1 is load-bearing there. */
    int num_conn;
} scenario_t;

/* WHICH IMPLEMENTATION IS ACTUALLY AT THAT END. The readiness markers
 * alone cannot answer this: our ck-client logs "listening on TCP
 * 127.0.0.1:%d for %s client" and Go's logs "Listening on TCP
 * 127.0.0.1:%d for %s client", which differ in ONE CAPITAL LETTER -- so a
 * scenario whose paths were both accidentally set to the same binary
 * could still satisfy its marker wait and then "interoperate" with
 * itself, which is the precise failure this whole file exists to end.
 *
 * logrus, writing to a pipe rather than a terminal, emits logfmt:
 * `time="2026-09-17T00:39:23Z" level=info msg="Listening on ..."`.
 * (MEASURED, not assumed -- an earlier draft of this assertion guessed
 * logrus's TextFormatter `INFO[...]` form and failed on all three
 * scenarios, because that form is only used on a TTY.) cloak_log_write
 * (libcloak-common/src/log.c) writes `<stamp> <LEVEL> <message>` and
 * nothing resembling `level=info msg=`. So that substring is a decisive,
 * implementation-level signature, and it is asserted for every child of
 * every scenario. */
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

/* Runs one scenario end to end. On a positive run (corrupt_at < 0) it
 * asserts the full byte-for-byte round trip and returns the client's
 * ClientHello through hello_out/hello_len_out for case 4. On a negative
 * run it asserts that the client refuses and that not one application byte
 * arrives. */
static void run_scenario(const scenario_t *sc, uint8_t *hello_out, size_t *hello_len_out) {
    printf("-- %s\n", sc->name);

    harness_t h;
    harness_init(&h);

    uint8_t priv[CLOAK_X25519_KEY_LEN];
    char pub_b64[64];
    derive_keys(priv, pub_b64, sizeof(pub_b64));

    /* The fake upstream the Cloak server proxies to. */
    h.up_listen = listen_on(&h.up_port);
    ASSERT_TRUE(h.up_listen >= 0);

    int server_port = free_port();
    ASSERT_TRUE(server_port > 0);

    /* The MITM, between the Cloak client and the Cloak server. */
    h.relay.listen_fd = listen_on(&h.relay.port);
    ASSERT_TRUE(h.relay.listen_fd >= 0);
    set_nonblock(h.relay.listen_fd);
    set_nonblock(h.up_listen);
    h.relay.server_port = server_port;
    h.relay.corrupt_at = sc->corrupt_at;

    int local_port = free_port();
    ASSERT_TRUE(local_port > 0);

    char scfg[160];
    char ccfg[160];
    /* Unique names, created atomically -- see write_temp_unique. */
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
    if (wait_for_marker(&h, &server, sc->server_ready, BOOT_MS) != 0) {
        fprintf(stderr, "FAIL %s:%d: %s: server never said \"%s\"; it said:\n%s\n", __FILE__,
                __LINE__, sc->name, sc->server_ready, server.out);
        cloak_test_failures++;
        child_stop(&server);
        harness_close(&h);
        unlink(scfg);
        unlink(ccfg);
        return;
    }

    char *const cargv[] = {(char *)"ck-client", (char *)"-c", ccfg, NULL};
    ASSERT_EQ_INT(0, child_spawn(&client, sc->client_path, cargv));
    if (wait_for_marker(&h, &client, sc->client_ready, BOOT_MS) != 0) {
        fprintf(stderr, "FAIL %s:%d: %s: client never said \"%s\"; it said:\n%s\n", __FILE__,
                __LINE__, sc->name, sc->client_ready, client.out);
        cloak_test_failures++;
        child_stop(&client);
        child_stop(&server);
        harness_close(&h);
        unlink(scfg);
        unlink(ccfg);
        return;
    }

    assert_implementation("the server", &server, sc->server_is_go);
    assert_implementation("the client", &client, sc->client_is_go);

    /* THE CLIENT MUST BE LISTENING ON THE PORT WE CONFIGURED, and this
     * assertion exists because its absence cost a diagnosis. When two
     * concurrent runs shared a config file name, the client read the
     * OTHER run's configuration and listened on the other run's port --
     * and the only symptom was "the client's local port never accepted"
     * after a fifteen-second dial, which names the wrong thing entirely.
     * Both clients log the address they bind, so one strstr turns a
     * mysterious timeout into "it is listening somewhere else".
     *
     * Checked against the CHILD'S OWN OUTPUT rather than against our
     * config text, so it catches a configuration that never reached the
     * child as well as one that reached the wrong child. */
    char want_port[32];
    snprintf(want_port, sizeof(want_port), ":%d", local_port);
    if (strstr(client.out, want_port) == NULL) {
        fprintf(stderr,
                "FAIL %s:%d: %s: the client was configured with local port %d but never said "
                "so -- it is listening somewhere else, which almost always means it read a "
                "configuration that is not the one this run wrote (%s). It said:\n%s\n",
                __FILE__, __LINE__, sc->name, local_port, ccfg, client.out);
        cloak_test_failures++;
    }

    static uint8_t send_buf[PAYLOAD_LEN];
    static uint8_t reply_buf[PAYLOAD_LEN];
    static uint8_t want_buf[PAYLOAD_LEN];
    fill_payload(send_buf, sizeof(send_buf), 0x9e3779b9u);
    memset(reply_buf, 0, sizeof(reply_buf));
    for (size_t i = 0; i < sizeof(want_buf); i++) {
        want_buf[i] = (uint8_t)(send_buf[i] ^ h.xor_mask);
    }

    h.app_fd = dial_local_retrying(&h, local_port, BOOT_MS);
    if (h.app_fd < 0) {
        fprintf(stderr,
                "FAIL %s:%d: %s: the client's local port %d never accepted. It said:\n%s\n",
                __FILE__, __LINE__, sc->name, local_port, client.out);
        cloak_test_failures++;
        child_stop(&client);
        child_stop(&server);
        harness_close(&h);
        unlink(scfg);
        unlink(ccfg);
        return;
    }
    set_nonblock(h.app_fd);
    h.send_buf = send_buf;
    h.send_len = sizeof(send_buf);
    h.reply = reply_buf;
    h.reply_cap = sizeof(reply_buf);

    if (sc->corrupt_at < 0) {
        uint64_t start = now_ms();
        uint64_t deadline = start + XFER_MS;
        while (h.got < h.reply_cap && now_ms() < deadline) {
            harness_pump(&h, 20);
        }
        uint64_t took = now_ms() - start;

        ASSERT_EQ_INT((long long)sizeof(send_buf), (long long)h.sent);
        ASSERT_EQ_INT((long long)sizeof(send_buf), (long long)h.up_seen);
        ASSERT_EQ_INT((long long)sizeof(reply_buf), (long long)h.got);
        ASSERT_MEM_EQ(want_buf, reply_buf, sizeof(want_buf));
        /* The reply must NOT be the request: an upstream that echoed, or a
         * near end that looped the application's own bytes back without
         * ever crossing the tunnel, would satisfy every length assertion
         * above. */
        ASSERT_MEM_NE(send_buf, reply_buf, sizeof(send_buf));
        /* h.sent and h.got, NOT the buffer size: a stalled transfer must
         * print what actually crossed, or the line reads like a success
         * next to the assertions that just failed. */
        printf("   %zu bytes out, %zu back, %zu seen upstream, in %llu ms, "
               "%zu relayed connection(s)\n",
               h.sent, h.got, h.up_seen, (unsigned long long)took, h.relay.accepted);

        if (hello_out != NULL && hello_len_out != NULL) {
            *hello_len_out = 0;
            if (h.relay.npairs > 0) {
                size_t n = h.relay.pairs[0].hello_len;
                memcpy(hello_out, h.relay.pairs[0].hello, n);
                *hello_len_out = n;
            }
        }
    } else {
        /* THE NEGATIVE CONTROL. The client must say it refused, and no
         * application byte may cross. */
        int refused = 0;
        uint64_t deadline = now_ms() + HANDSHAKE_FAIL_MS;
        while (now_ms() < deadline) {
            harness_pump(&h, 10);
            child_drain(&client, 0);
            int said_so = sc->client_refusal == NULL ||
                          strstr(client.out, sc->client_refusal) != NULL;
            int tried_again =
                !sc->require_reconnect || h.relay.accepted > (size_t)sc->num_conn;
            if (said_so && tried_again) {
                refused = 1;
                break;
            }
        }
        if (!refused) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: the client ACCEPTED a ServerHello with one flipped "
                    "bit at server->client offset %ld -- no refusal evidence in %d ms "
                    "(wanted %s%s%zu of %d connection(s) reopened). It said:\n%s\n",
                    __FILE__, __LINE__, sc->name, sc->corrupt_at, HANDSHAKE_FAIL_MS,
                    sc->client_refusal != NULL ? sc->client_refusal : "(no marker)",
                    sc->require_reconnect ? ", and a reconnect; saw " : "; saw ",
                    h.relay.accepted, sc->num_conn, client.out);
            cloak_test_failures++;
        }
        uint64_t quiet = now_ms() + QUIET_MS;
        while (now_ms() < quiet) {
            harness_pump(&h, 10);
        }
        ASSERT_EQ_INT(0, (long long)h.got);
        ASSERT_EQ_INT(0, (long long)h.up_seen);
        if (sc->client_forbidden != NULL && strstr(client.out, sc->client_forbidden) != NULL) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: the client printed \"%s\" even though the ServerHello "
                    "it was given does not authenticate. It said:\n%s\n",
                    __FILE__, __LINE__, sc->name, sc->client_forbidden, client.out);
            cloak_test_failures++;
        }
        /* A REFUSAL IS ONLY MEANINGFUL IF A REPLY WAS DELIVERED. The
         * ServerHello record alone is 127 bytes; requiring more than the
         * corruption offset rules out a "refusal" that is really a
         * connection that never got an answer. */
        if (h.relay.s2c_total_all <= (uint64_t)sc->corrupt_at) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: only %llu byte(s) ever reached the client from the "
                    "server, so its refusal proves nothing about the ServerHello\n",
                    __FILE__, __LINE__, sc->name,
                    (unsigned long long)h.relay.s2c_total_all);
            cloak_test_failures++;
        }
        printf("   refused=%d, %zu application bytes crossed, %llu server bytes delivered, "
               "%zu relayed connection(s)\n",
               refused, h.got, (unsigned long long)h.relay.s2c_total_all, h.relay.accepted);
    }

    child_stop(&client);
    child_stop(&server);
    harness_close(&h);
    unlink(scfg);
    unlink(ccfg);
}

/* ------------------------------------------------------------------ */
/* The cases                                                            */
/* ------------------------------------------------------------------ */

/* Filled in by cases 1 and 2, asserted by case 4. */
static uint8_t go_hello[HELLO_CAP];
static size_t go_hello_len;
static uint8_t c_hello[HELLO_CAP];
static size_t c_hello_len;

static void test_go_client_to_c_server(void) {
    scenario_t sc = {
        .name = "go_client_to_c_server",
        .server_path = CK_SERVER_PATH,
        .server_ready = "ck-server ready",
        .server_is_go = 0,
        .client_path = GO_CK_CLIENT_PATH,
        .client_ready = "Listening on",
        .client_is_go = 1,
        .corrupt_at = -1,
        .num_conn = 2,
    };
    run_scenario(&sc, go_hello, &go_hello_len);
    ASSERT_TRUE(go_hello_len > 0);
}

static void test_c_client_to_go_server(void) {
    scenario_t sc = {
        .name = "c_client_to_go_server",
        .server_path = GO_CK_SERVER_PATH,
        .server_ready = "Listening on",
        .server_is_go = 1,
        .client_path = CK_CLIENT_PATH,
        .client_ready = "session up",
        .client_is_go = 0,
        .corrupt_at = -1,
        .num_conn = 2,
    };
    run_scenario(&sc, c_hello, &c_hello_len);
    ASSERT_TRUE(c_hello_len > 0);
}

/* Offset 11 of the server -> client stream is the FIRST BYTE OF THE
 * AES-GCM NONCE inside the ServerHello:
 *
 *   [0:5)   TLS record header
 *   [5:9)   handshake type (0x02) + 3-byte length
 *   [9:11)  legacy version
 *   [11:43) ServerHello.random == reply_nonce(12) || ciphertext[0:20)
 *
 * Go's client reads exactly those bytes (internal/client/TLS.go:
 * `encrypted := append(buf[6:38], buf[84:116]...)`, buf being the record
 * PAYLOAD, hence +5 here) and AES-GCM-decrypts them to recover the session
 * key. One flipped bit anywhere in that span must make the tag check fail.
 * Nothing else about this case differs from case 1. */
#define SERVERHELLO_NONCE_OFFSET 11

static void test_go_client_refuses_a_corrupted_serverhello(void) {
    scenario_t sc = {
        .name = "negative_control",
        .server_path = CK_SERVER_PATH,
        .server_ready = "ck-server ready",
        .server_is_go = 0,
        .client_path = GO_CK_CLIENT_PATH,
        .client_ready = "Listening on",
        .client_is_go = 1,
        .corrupt_at = SERVERHELLO_NONCE_OFFSET,
        .client_refusal = "Failed to prepare connection to remote",
        .require_reconnect = 0,
        .client_forbidden = NULL,
        .num_conn = 2,
    };
    run_scenario(&sc, NULL, NULL);
}

/* CASE 5: THE MIRROR OF CASE 3, AND THE REASON IT EXISTS.
 *
 * Case 3 proves GO's client refuses a ServerHello this port corrupted.
 * Nothing proved OURS does. That asymmetry was not theoretical: this
 * task's review made a C client that does not enforce the ServerHello's
 * AES-GCM tag at all -- it fell back to using the ciphertext as the
 * session key -- and it passed all four of this file's cases, because an
 * honest Go server always produces a valid tag. The only test in the tree
 * that caught it was test_client_transport.c's
 * test_wrong_key_reply_is_rejected, which corrupts a ServerHello produced
 * by OUR OWN fake server: exactly the "both ends are ours" condition this
 * whole file exists to end.
 *
 * So: case 2 again, with one bit flipped at the same offset 11 of a GO
 * server's reply, and nothing else changed. Our client must refuse.
 *
 * WHAT IS ASSERTED, and its one honest limit: ck-client narrates stack
 * events, so "round failed" is visible from outside the process, but the
 * specific CLOAK_CLIENT_HANDSHAKE_ERR_AUTH code is not -- it never
 * reaches stdout. That code is pinned in-process by
 * test_wrong_key_reply_is_rejected; this case pins that a REAL Go
 * server's corrupted reply reaches the same refusal, that "session up" is
 * never printed, that no application byte crosses, and that the reply
 * really was delivered first. Together the two cover both the code and
 * the interoperation; neither does it alone. */
static void test_c_client_refuses_a_corrupted_serverhello(void) {
    scenario_t sc = {
        .name = "negative_control_c_client",
        .server_path = GO_CK_SERVER_PATH,
        .server_ready = "Listening on",
        .server_is_go = 1,
        .client_path = CK_CLIENT_PATH,
        /* "ck-client ready", not "session up": the whole point is that the
         * session never comes up. The local listener is open before the
         * first handshake either way. */
        .client_ready = "ck-client ready",
        .client_is_go = 0,
        .corrupt_at = SERVERHELLO_NONCE_OFFSET,
        /* No marker: see require_reconnect's comment on scenario_t. */
        .client_refusal = NULL,
        .require_reconnect = 1,
        .client_forbidden = "session up",
        /* ONE CONNECTION, AND THE NUMBER IS LOAD-BEARING.
         *
         * With NumConn 2 this case PASSED against a client that had the
         * AEAD check removed entirely -- measured, by re-applying the
         * review's own mutation. Our connector has a defence Go does not:
         * cloak_client_connector's keys_agree() refuses a round whose N
         * connections did not derive the SAME session key
         * (CLOAK_CLIENT_CONNECTOR_ERR_KEY_MISMATCH). Each connection's
         * garbage key is different garbage, so the round failed on the
         * mismatch and never reached the tag check -- the case asserted a
         * refusal and got one, for the wrong reason.
         *
         * With ONE connection there is nothing to disagree with, so the
         * only thing that can reject this ServerHello is the AES-GCM tag
         * -- which is exactly the property this case exists to pin. The
         * masking is a real (and welcome) divergence from Go, recorded
         * here rather than in a comment nobody reads, and it is why a
         * mirror control written the obvious way would have proved
         * nothing. */
        .num_conn = 1,
    };
    run_scenario(&sc, NULL, NULL);
}

/* Byte 41 of the authentication payload, in both directions, with the
 * ordered value asserted exactly. Module 9 task 7 flips this bit when
 * unordered mode lands; until then a 1 in either hello is a defect, and a
 * task-7 implementation that sets the bit for every session -- or that
 * reads it from the wrong offset -- fails here. */
static void test_byte_41_is_zero_in_both_directions(void) {
    uint8_t priv[CLOAK_X25519_KEY_LEN];
    char pub_b64[64];
    derive_keys(priv, pub_b64, sizeof(pub_b64));

    uint8_t plain[48];
    if (go_hello_len == 0) {
        fprintf(stderr, "FAIL %s:%d: no ClientHello was captured from Go's ck-client\n",
                __FILE__, __LINE__);
        cloak_test_failures++;
    } else {
        int rc = auth_payload_from_hello(go_hello, go_hello_len, priv, plain);
        ASSERT_EQ_INT(0, rc);
        if (rc == 0) {
            printf("-- Go ck-client auth payload: flag byte 41 = 0x%02x, proxy method \"%.12s\"\n",
                   plain[41], (const char *)plain + 16);
            ASSERT_EQ_INT(0, plain[41]);
            /* Not decoration: it proves the 48 bytes decrypted here really
             * are the authentication payload and not 48 bytes of anything
             * else that happened to authenticate. */
            ASSERT_EQ_INT(0, memcmp(plain + 16, "shadowsocks", 11));
        }
    }

    if (c_hello_len == 0) {
        fprintf(stderr, "FAIL %s:%d: no ClientHello was captured from our ck-client\n", __FILE__,
                __LINE__);
        cloak_test_failures++;
    } else {
        int rc = auth_payload_from_hello(c_hello, c_hello_len, priv, plain);
        ASSERT_EQ_INT(0, rc);
        if (rc == 0) {
            printf("-- C  ck-client auth payload: flag byte 41 = 0x%02x, proxy method \"%.12s\"\n",
                   plain[41], (const char *)plain + 16);
            ASSERT_EQ_INT(0, plain[41]);
            ASSERT_EQ_INT(0, memcmp(plain + 16, "shadowsocks", 11));
        }
    }
}

/* ------------------------------------------------------------------ */

/* THE ORACLE'S ABSENCE MUST BE A NAMED FAILURE IN MILLISECONDS, NOT A
 * TIMEOUT. A test that hangs when its oracle is missing costs a minute of
 * every worst-case CI run, reports "***Timeout" instead of the broken
 * property, and makes a genuine future hang indistinguishable from a
 * missing file. So this runs before any case does. */
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
    /* The relay writes to sockets whose peer may already have gone -- a
     * refused handshake closes one under it by design. Without this the
     * negative control would kill the test process instead of asserting. */
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (!oracle_binaries_present()) {
        return 1;
    }

    test_go_client_to_c_server();
    test_c_client_to_go_server();
    test_go_client_refuses_a_corrupted_serverhello();
    test_c_client_refuses_a_corrupted_serverhello();
    test_byte_41_is_zero_in_both_directions();

    if (cloak_test_failures > 0) {
        fprintf(stderr, "%d assertion(s) failed\n", cloak_test_failures);
        return 1;
    }
    printf("All tests passed\n");
    return 0;
}
