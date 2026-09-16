#define _POSIX_C_SOURCE 200809L

/* cloak_client_stack_t: THE WHOLE CLIENT AS ONE OBJECT, AND THE
 * RECONNECT LOOP ABOVE IT.
 *
 * The far end of every case here is the real merged server, assembled by
 * its own sibling helper (cloak/server_stack.h) -- which is itself the
 * point: if the two stacks cannot face each other in twenty lines then
 * neither has done its job. Beyond the server sits a fake upstream; at
 * the near end sits an application socket. Everything between them is
 * library code.
 *
 * THIS FILE #includes ../src/client_stack.c DIRECTLY, exactly as
 * test_client_connector.c includes the connector's. Two of this module's
 * contributions are functions of numbers rather than of a network -- the
 * backoff ladder and the session-id predicate -- and the honest way to
 * pin a ladder is to evaluate it, not to infer its shape from how long
 * something took. Everything else here is driven through the public
 * handle and never names a struct member, which is the evidence that a
 * binary does not need one.
 *
 * FIVE CONSTRUCTIONS CARRY THIS FILE, each keeping a case from passing
 * through a path other than the one it names.
 *
 * 1. THE UPSTREAM DOES NOT ECHO -- it replies with every byte XORed with
 *    0xFF. An echoing upstream would let the round-trip cases pass
 *    against a client that never opened a stream and simply wrote the
 *    local connection's own bytes back at it. XOR cannot be produced
 *    anywhere on the client side, so a transformed reply is proof the
 *    bytes crossed the tunnel. This matters more here than anywhere: the
 *    edge this module exists to enforce (cloak_client_piper_install
 *    before cloak_client_connector_init) produces a client that
 *    CONNECTS PERFECTLY and moves no bytes, so "it came up" is exactly
 *    the assertion that cannot see it.
 *
 * 2. THE SESSION ID IS READ OFF THE SERVER, not off the client. Case 2's
 *    whole claim is that a replacement session uses a DIFFERENT id, and
 *    an accessor that reported a fresh number while the connector dialled
 *    with a stale one would satisfy any client-side assertion. The
 *    server's dispatcher attach callback records cloak_session_t::id for
 *    every session it CREATES, which is the number that was on the wire.
 *
 * 3. THE DEAD PORT IS A PORT THIS PROCESS BOUND AND CLOSED, so a round
 *    against it fails with ECONNREFUSED in microseconds. That is what
 *    makes the backoff the only thing between two rounds, and therefore
 *    the only thing a wall-clock bracket can be measuring.
 *
 * 4. THE BLACK HOLE ACCEPTS AND SAYS NOTHING. A connection to it dials
 *    successfully and then hangs in the handshake until its timeout,
 *    which is the only way to hold a singleplex bring-up open long
 *    enough for the piper's deadline to cancel it -- case 6E, the one
 *    case that observes cancel_session while the stack is still alive
 *    and therefore the only one that catches an emptied cancel_session
 *    without LeakSanitizer.
 *
 * 5. EVERY WAIT IS A BOUNDED pump_until WHOSE RESULT IS ASSERTED, and
 *    every TIMING claim is a MEASURED BRACKET rather than a claimed
 *    margin: a lower bound that fails if the delay is dropped or halved,
 *    and an upper bound that fails if it is doubled. Both numbers are
 *    literals derived from the ladder by hand, never from the constants
 *    under test -- a bracket spelled in terms of the symbol it is
 *    testing moves with the mutation instead of catching it. */

#include "cloak/base64.h"
#include "cloak/client_stack.h"
#include "cloak/log.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/server_stack.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "cloak/switchboard.h"
#include "cloak/valve.h"
#include "cloak/userpanel.h"
#include "test_framework.h"

/* The implementation itself, for the two things that are functions of
 * numbers. See this file's header. */
#include "../src/client_stack.c"

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---- bounded reactor pumping ------------------------------------------- */

/* Sized so a BROKEN run fails an ASSERTION rather than the ctest timeout:
 * at CS_MAX_TURNS turns of CS_TURN_MS each, one wait is at most ~6 s, and
 * the waits in this file total well under TIMEOUT 60. Six seconds rather
 * than the usual two because several cases here deliberately wait out a
 * retry ladder. */
#define CS_MAX_TURNS 6000
#define CS_TURN_MS 1

typedef int (*pump_done_fn)(void *ctx);

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Pumps the reactor until done(ctx) is true, bounded by REAL TIME:
 * max_iters * per_iter_ms milliseconds. Returns 1 if done became true, 0
 * if the budget ran out.
 *
 * THE BOUND IS WALL-CLOCK AND NOT AN ITERATION COUNT, and that
 * distinction is a defect these suites already paid for: one
 * permanently-ready descriptor (an EOF peer left registered) makes every
 * turn return immediately, and a loop of max_iters turns then expires in
 * milliseconds -- measured at 4.2 ms for a caller that believed it had
 * asked for two seconds. The iteration ceiling below is only a backstop
 * against a clock that does not advance, sized far above the spin rate so
 * it cannot bind first. */
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

/* Pumps for at least `ms` of REAL time, and ASSERTS it really did. Used
 * only where a case has to establish that something did NOT happen
 * within a window; a loop that exited early would silently turn the
 * assertion that follows into nothing. */
static void pump_for_ms(cloak_reactor_t *r, uint64_t ms) {
    uint64_t start = monotonic_ms();
    uint64_t elapsed = 0;
    uint64_t cap = ms * 1000u + 5000000u;
    for (uint64_t i = 0; i < cap; i++) {
        cloak_reactor_run_once(r, 1);
        elapsed = monotonic_ms() - start;
        if (elapsed >= ms) {
            break;
        }
    }
    ASSERT_TRUE(elapsed >= ms);
}

/* Open descriptors, counted from /proc/self/fd. LeakSanitizer tracks
 * memory, not file descriptors: a stack that freed every byte it
 * allocated and quietly dropped a socket is indistinguishable, to ASan
 * and to every counter here, from a correct one. Returns -1 where /proc
 * is absent, and every call site asserts that did not happen -- a
 * -1 == -1 comparison is how this check silently stopped working on a
 * previous branch. */
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

/* ---- the fake upstream: records everything, replies with it XORed ------- */

#define UP_MAX_CONNS 8
#define UP_BUF_CAP ((size_t)(1u << 20))

/* NOT an echo. See this file's header. */
#define UP_XOR ((uint8_t)0xFF)

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
        break; /* EAGAIN, or the peer is gone: the writable event resumes us */
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

static void up_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    up_slot_t *slot = userdata;
    upstream_t *up = slot->up;
    up_conn_t *c = &up->conns[slot->idx];

    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        up_flush(c);
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        for (;;) { /* edge-triggered: read until EAGAIN or the buffers fill */
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
                for (ssize_t i = 0; i < n; i++) {
                    c->out[c->out_len + (size_t)i] =
                        (uint8_t)(c->in[c->in_len + (size_t)i] ^ UP_XOR);
                }
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
    (void)cloak_reactor_add_fd(up->reactor, fd, CLOAK_REACTOR_READABLE, up_on_event,
                               &up->slots[idx]);
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

/* ---- a listener that accepts and keeps quiet ---------------------------- */

/* Two roles, one object: the cover site nothing here should ever reach,
 * and (case 6E) the BLACK HOLE a handshake hangs against. */
typedef struct {
    int fds[16];
    int count;
    int accept_count;
} quiet_site_t;

static void quiet_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    quiet_site_t *q = userdata;
    q->accept_count++;
    if (q->count >= (int)(sizeof(q->fds) / sizeof(q->fds[0]))) {
        close(fd);
        return;
    }
    q->fds[q->count++] = fd;
}

static int quiet_accepted(void *ctx) {
    quiet_site_t *q = ctx;
    return q->accept_count >= 1;
}

static void quiet_destroy(quiet_site_t *q) {
    for (int i = 0; i < q->count; i++) {
        close(q->fds[i]);
    }
    q->count = 0;
}

/* ---- the fixture: the whole merged server, via its own stack ------------ */

/* The wire size BOTH ends are built with. Both must agree -- a connection
 * whose peer frames larger than its own max_frame_len is broken by the
 * connection layer, not tolerated. This is also the value
 * CLOAK_SERVER_STACK_DEFAULT_MAX_ON_WIRE_SIZE and
 * CLOAK_CLIENT_STACK_DEFAULT_MAX_ON_WIRE_SIZE both carry, spelled as a
 * literal here so that a mutation to either default is visible as a
 * disagreement rather than following both sides at once. */
#define CS_WIRE ((size_t)16401)

#define CS_MAX_ATTACHED 16

struct fixture {
    cloak_reactor_t *reactor;

    quiet_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover;

    upstream_t up;
    cloak_listener_t up_listener;
    int have_up;
    int up_port;

    cloak_server_config_t scfg;
    cloak_server_stack_t *srv;

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid[CLOAK_UID_LEN];
    int front_port;

    /* THE OUTSIDE ORACLE. Every session the server CREATES, by the id the
     * server itself gave it -- which is the id that was on the wire, and
     * therefore the only trustworthy answer to "did the reconnect use a
     * different one". */
    uint32_t created_ids[CS_MAX_ATTACHED];
    int created_count;
    int attach_count;
};

static void fx_attached(cloak_dispatcher_t *d, cloak_session_t *sesh,
                        const cloak_server_clientinfo_t *info, int created, void *userdata) {
    (void)d;
    (void)info;
    struct fixture *fx = userdata;
    fx->attach_count++;
    if (created && fx->created_count < CS_MAX_ATTACHED) {
        fx->created_ids[fx->created_count++] = sesh->id;
    }
}

static int fixture_init(struct fixture *fx) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    for (int i = 0; i < UP_MAX_CONNS; i++) {
        fx->up.conns[i].fd = -1;
    }

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

    ASSERT_EQ_INT(0, cloak_listener_open(&fx->cover_listener, fx->reactor, "127.0.0.1:0",
                                         quiet_on_accept, &fx->cover, err, sizeof(err)));
    fx->have_cover = 1;
    int cover_port = cloak_listener_port(&fx->cover_listener);
    ASSERT_TRUE(cover_port > 0);

    fx->up.reactor = fx->reactor;
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->up_listener, fx->reactor, "127.0.0.1:0", up_on_accept,
                                         &fx->up, err, sizeof(err)));
    fx->have_up = 1;
    fx->up_port = cloak_listener_port(&fx->up_listener);
    ASSERT_TRUE(fx->up_port > 0);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, fx->server_pub));
    for (size_t i = 0; i < CLOAK_UID_LEN; i++) {
        fx->uid[i] = (uint8_t)(0x40 + i);
    }

    char priv_b64[64];
    char uid_b64[32];
    ASSERT_EQ_INT(
        0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64, sizeof(priv_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(fx->uid, CLOAK_UID_LEN, uid_b64, sizeof(uid_b64)));

    /* No DatabasePath: the void user manager, which serves the BypassUID
     * list and nobody else. Every case here authenticates that one UID,
     * so a database would add a file, a teardown and nothing else. */
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\"127.0.0.1:0\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\"]}",
             fx->up_port, cover_port, priv_b64, uid_b64);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->scfg, err, sizeof(err)));

    /* THE SERVER IS ITS OWN STACK. Nine objects, their cross-pointers,
     * the four-link chain and the teardown order, in five statements --
     * and the reason this file can afford a fixture a tenth the size of
     * test_client_full_e2e.c's. */
    cloak_server_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.reactor = fx->reactor;
    sc.config = &fx->scfg;
    sc.session_config_template.max_on_wire_size = CS_WIRE;
    sc.attached = fx_attached;
    sc.attached_userdata = fx;
    err[0] = '\0';
    int rc = cloak_server_stack_open(&fx->srv, &sc, err, sizeof(err));
    ASSERT_EQ_INT(0, rc);
    if (rc != 0) {
        fprintf(stderr, "server stack: %s: %s\n", cloak_server_stack_strerror(rc), err);
        return -1;
    }
    fx->front_port = cloak_server_stack_listener_port(fx->srv, 0);
    ASSERT_TRUE(fx->front_port > 0);
    return 0;
}

static void fixture_destroy(struct fixture *fx) {
    if (fx->srv != NULL) {
        cloak_server_stack_close(fx->srv);
        fx->srv = NULL;
    }
    if (fx->have_up) {
        cloak_listener_close(&fx->up_listener);
        fx->have_up = 0;
    }
    up_destroy(&fx->up);
    if (fx->have_cover) {
        cloak_listener_close(&fx->cover_listener);
        fx->have_cover = 0;
    }
    quiet_destroy(&fx->cover);
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
        fx->reactor = NULL;
    }
}

/* A TCP port on loopback that nothing is listening on: bound, its number
 * read, and closed again. A round against it fails with ECONNREFUSED in
 * microseconds, which is what makes a backoff the only thing between two
 * rounds. */
static int dead_port(cloak_reactor_t *r) {
    cloak_listener_t l;
    char err[256] = {0};
    if (cloak_listener_open(&l, r, "127.0.0.1:0", quiet_on_accept, NULL, err, sizeof(err)) != 0) {
        return -1;
    }
    int port = cloak_listener_port(&l);
    cloak_listener_close(&l);
    return port;
}

/* ---- the local peer: the "application" the stack serves ----------------- */

#define LP_BUF_CAP ((size_t)(1u << 20))

typedef struct {
    cloak_reactor_t *reactor;
    cloak_dial_t dial;
    int dialing;
    int fd;
    int registered;
    int connected;
    int dial_failed;

    uint8_t *in;
    size_t in_len;
    uint8_t *out;
    size_t out_len;
    size_t out_head;
    int eof; /* the client closed our side */
} local_peer_t;

static void lp_flush(local_peer_t *lp) {
    while (lp->out_head < lp->out_len) {
        ssize_t n = send(lp->fd, lp->out + lp->out_head, lp->out_len - lp->out_head, MSG_NOSIGNAL);
        if (n > 0) {
            lp->out_head += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (lp->out_head == lp->out_len) {
        lp->out_head = 0;
        lp->out_len = 0;
    }
}

static void lp_sync(local_peer_t *lp) {
    uint32_t ev = CLOAK_REACTOR_READABLE;
    if (lp->out_head < lp->out_len) {
        ev |= CLOAK_REACTOR_WRITABLE;
    }
    (void)cloak_reactor_mod_fd(lp->reactor, lp->fd, ev);
}

static void lp_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    local_peer_t *lp = userdata;
    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        lp_flush(lp);
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        for (;;) {
            if (lp->in_len >= LP_BUF_CAP) {
                break;
            }
            ssize_t n = read(lp->fd, lp->in + lp->in_len, LP_BUF_CAP - lp->in_len);
            if (n > 0) {
                lp->in_len += (size_t)n;
                continue;
            }
            if (n == 0) {
                lp->eof = 1;
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            break;
        }
    }
    lp_sync(lp);
}

static void lp_on_dial(cloak_dial_t *d, int fd, void *userdata) {
    (void)d;
    local_peer_t *lp = userdata;
    lp->dialing = 0;
    if (fd < 0) {
        lp->dial_failed = 1;
        return;
    }
    lp->fd = fd;
    if (cloak_reactor_add_fd(lp->reactor, fd, CLOAK_REACTOR_READABLE, lp_on_event, lp) != 0) {
        close(fd);
        lp->fd = -1;
        lp->dial_failed = 1;
        return;
    }
    lp->registered = 1;
    lp->connected = 1;
    lp_flush(lp);
    lp_sync(lp);
}

static int lp_connected(void *ctx) {
    local_peer_t *lp = ctx;
    return lp->connected || lp->dial_failed;
}

static int lp_open(local_peer_t *lp, cloak_reactor_t *r, int port) {
    memset(lp, 0, sizeof(*lp));
    lp->reactor = r;
    lp->fd = -1;
    lp->in = malloc(LP_BUF_CAP);
    lp->out = malloc(LP_BUF_CAP);
    if (lp->in == NULL || lp->out == NULL) {
        free(lp->in);
        free(lp->out);
        lp->in = NULL;
        lp->out = NULL;
        return -1;
    }
    char addr[64];
    char err[256];
    cloak_addr_t a;
    snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
    if (cloak_net_resolve(addr, 0, &a, err, sizeof(err)) != 0) {
        return -1;
    }
    if (cloak_dial_start(&lp->dial, r, &a, 5000, lp_on_dial, lp, err, sizeof(err)) != 0) {
        return -1;
    }
    lp->dialing = 1;
    return 0;
}

static void lp_send(local_peer_t *lp, const uint8_t *buf, size_t len) {
    ASSERT_TRUE(lp->out_len + len <= LP_BUF_CAP);
    memcpy(lp->out + lp->out_len, buf, len);
    lp->out_len += len;
    if (lp->connected) {
        lp_flush(lp);
        lp_sync(lp);
    }
}

static void lp_shutdown(local_peer_t *lp) {
    if (lp->registered) {
        cloak_reactor_remove_fd(lp->reactor, lp->fd);
        lp->registered = 0;
    }
    if (lp->fd >= 0) {
        close(lp->fd);
        lp->fd = -1;
    }
}

static void lp_destroy(local_peer_t *lp) {
    if (lp->dialing) {
        cloak_dial_cancel(&lp->dial);
        lp->dialing = 0;
    }
    lp_shutdown(lp);
    free(lp->in);
    free(lp->out);
    lp->in = NULL;
    lp->out = NULL;
}

struct lp_wait {
    local_peer_t *lp;
    size_t want;
};

static int lp_has_len(void *ctx) {
    struct lp_wait *w = ctx;
    return w->lp->in_len >= w->want;
}

static int lp_at_eof(void *ctx) {
    local_peer_t *lp = ctx;
    return lp->eof != 0;
}

static void xor_fill(uint8_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = (uint8_t)(src[i] ^ UP_XOR);
    }
}

/* ---- the client under test ---------------------------------------------- */

#define CS_MAX_EVENTS 64

typedef struct {
    cloak_client_stack_event_t ev;
    uint32_t session_id;
    int round;
    uint64_t retry_in_ms;
    uint64_t at_ms; /* CLOCK_MONOTONIC, for the backoff bracket */
} cs_event_t;

typedef struct {
    cloak_client_config_t cfg;
    cloak_client_stack_t *st;

    cs_event_t events[CS_MAX_EVENTS];
    int event_count;
    int counts[8];
} client_t;

static void cs_on_event(cloak_client_stack_t *s, cloak_client_stack_event_t ev, uint32_t session_id,
                        int round, uint64_t retry_in_ms, void *userdata) {
    (void)s;
    client_t *cl = userdata;
    if ((int)ev >= 0 && (int)ev < 8) {
        cl->counts[(int)ev]++;
    }
    if (cl->event_count < CS_MAX_EVENTS) {
        cs_event_t *e = &cl->events[cl->event_count++];
        e->ev = ev;
        e->session_id = session_id;
        e->round = round;
        e->retry_in_ms = retry_in_ms;
        e->at_ms = monotonic_ms();
    }
}

/* Fills in the parts of a client config every case shares. `port` is the
 * Cloak server's front door -- or a dead one, which is the whole of what
 * several cases change. */
static void cs_config(client_t *cl, struct fixture *fx, int port, int singleplex, int num_conn) {
    memset(cl, 0, sizeof(*cl));
    cloak_client_config_t *c = &cl->cfg;
    snprintf(c->server_name, sizeof(c->server_name), "www.example.com");
    snprintf(c->proxy_method, sizeof(c->proxy_method), "ss");
    c->encryption_method = CLOAK_AEAD_AES_256_GCM;
    memcpy(c->uid, fx->uid, CLOAK_UID_LEN);
    memcpy(c->server_pub_key, fx->server_pub, CLOAK_X25519_KEY_LEN);
    c->num_conn = num_conn;
    c->singleplex = singleplex;
    snprintf(c->local_host, sizeof(c->local_host), "127.0.0.1");
    snprintf(c->local_port, sizeof(c->local_port), "0");
    snprintf(c->remote_host, sizeof(c->remote_host), "127.0.0.1");
    snprintf(c->remote_port, sizeof(c->remote_port), "%d", port);
    c->browser = CLOAK_BROWSER_CHROME;
    c->transport = CLOAK_TRANSPORT_DIRECT;
    c->stream_timeout_sec = 300;
    c->keep_alive_sec = -1;
}

/* Everything a binary writes, and this IS the measurement the report
 * quotes: a config, a memset, five assignments, one call. */
static int cs_open(client_t *cl, struct fixture *fx, cloak_client_stack_config_t *sc, char *err,
                   size_t err_cap) {
    sc->reactor = fx->reactor;
    sc->config = &cl->cfg;
    sc->session_template.max_on_wire_size = CS_WIRE;
    sc->on_event = cs_on_event;
    sc->on_event_userdata = cl;
    return cloak_client_stack_open(&cl->st, sc, err, err_cap);
}

static void cs_close(client_t *cl) {
    if (cl->st != NULL) {
        cloak_client_stack_close(cl->st);
        cl->st = NULL;
    }
}

struct cs_wait {
    client_t *cl;
    size_t want;
};

static int cs_session_up(void *ctx) {
    client_t *cl = ctx;
    return cloak_client_stack_session_up(cl->st);
}

static int cs_live_is(void *ctx) {
    struct cs_wait *w = ctx;
    return cloak_client_stack_live_sessions(w->cl->st) == w->want;
}

static int cs_down_is(void *ctx) {
    struct cs_wait *w = ctx;
    return cloak_client_stack_sessions_down(w->cl->st) >= w->want;
}

static int cs_rounds_is(void *ctx) {
    struct cs_wait *w = ctx;
    return cloak_client_stack_rounds_started(w->cl->st) >= w->want;
}

static int cs_failed_is(void *ctx) {
    struct cs_wait *w = ctx;
    return cloak_client_stack_sessions_failed(w->cl->st) >= w->want;
}

static int cs_pending_is(void *ctx) {
    struct cs_wait *w = ctx;
    return cloak_client_stack_pending_sessions(w->cl->st) == w->want;
}

struct reg_wait {
    struct fixture *fx;
    size_t want;
};

static int reg_count_is(void *ctx) {
    struct reg_wait *w = ctx;
    return cloak_server_stack_session_count(w->fx->srv) == w->want;
}

/* One local connection's whole round trip: connect, send, receive the
 * XORed reply, assert it byte for byte. THE ONLY THING THAT PROVES A
 * SESSION CARRIES BYTES. */
static void round_trip(struct fixture *fx, client_t *cl, local_peer_t *lp, const uint8_t *payload,
                       size_t len) {
    uint8_t want[512];
    ASSERT_TRUE(len <= sizeof(want));
    size_t before = lp->in_len;
    lp_send(lp, payload, len);
    struct lp_wait w = {lp, before + len};
    ASSERT_TRUE(pump_until(fx->reactor, lp_has_len, &w, CS_MAX_TURNS, CS_TURN_MS));
    (void)cl;
    xor_fill(want, payload, len);
    if (lp->in_len >= before + len) {
        ASSERT_MEM_EQ(lp->in + before, want, len);
    }
}

/* ---- case 3a: the ladder, evaluated rather than inferred ---------------- */

/* THE LADDER IS A FUNCTION OF TWO NUMBERS, so it is tested as one. Every
 * bound below is a LITERAL derived by hand from "500 ms, doubling, capped
 * at 30 s, +/-25%"; spelling them in terms of
 * CLOAK_CLIENT_STACK_MAX_RECONNECT_DELAY_MS or ..._JITTER_PCT would make
 * both sides of every comparison move with a mutation to the constant,
 * which is the shape this project has already paid for twice.
 *
 * THE JITTER IS PINNED ON BOTH SIDES AND FOR ITS WIDTH, and the third of
 * those is the one an earlier version of this file was missing. `d >= lo
 * && d < hi` is a CONTAINMENT test, satisfied by any NARROWER jitter, and
 * `seen_min < nominal` / `seen_max > nominal` pin only the sign of the
 * spread. Measured: with the jitter cut from +/-25% to +/-5% this file
 * stayed green three runs out of three -- which is the scenario the
 * jitter exists for, a thousand clients behind one outage retrying in a
 * 10% band instead of a 50% one, i.e. the dial storm back at five times
 * the density. The two REACH assertions below therefore demand that the
 * observed extremes get within a fifth of the nominal value of the
 * documented window's edges: +/-5% cannot, +/-25% does with room, and a
 * one-sided jitter still fails the upper one outright.
 *
 * The four-fifths and six-fifths are literals derived from "+/-25%" by
 * hand, not from CLOAK_CLIENT_STACK_RECONNECT_JITTER_PCT: a bracket
 * spelled in terms of the constant it is testing moves with the mutation
 * instead of catching it. */
#define LADDER_DRAWS 400

static void ladder_bracket(uint64_t base, int round, uint64_t lo, uint64_t hi, uint64_t nominal) {
    uint64_t seen_min = (uint64_t)-1;
    uint64_t seen_max = 0;
    for (int i = 0; i < LADDER_DRAWS; i++) {
        uint64_t d = stack_backoff_ms(base, round);
        ASSERT_TRUE(d >= lo);
        ASSERT_TRUE(d < hi);
        if (d < seen_min) {
            seen_min = d;
        }
        if (d > seen_max) {
            seen_max = d;
        }
    }
    /* THE SPREAD, not merely the direction. nominal * 4/5 is 0.8x and
     * nominal * 6/5 is 1.2x: a +/-25% window reaches both (its edges are
     * 0.75x and 1.25x, and 400 draws of a 256-bucket uniform miss the
     * outer fifth of either tail with probability below 2^-100), while
     * any window of +/-20% or less reaches neither. */
    ASSERT_TRUE(seen_min < nominal * 4u / 5u);
    ASSERT_TRUE(seen_max > nominal * 6u / 5u);
}

static void test_the_backoff_ladder_is_what_the_header_says(void) {
    /* Round 1 runs immediately -- the whole reason a client that has
     * never failed feels nothing. */
    for (int i = 0; i < 16; i++) {
        ASSERT_EQ_INT(0, (int)stack_backoff_ms(500, 1));
        ASSERT_EQ_INT(0, (int)stack_backoff_ms(500, 0));
        ASSERT_EQ_INT(0, (int)stack_backoff_ms(500, -3));
    }

    /* base 1000: 1000, 2000, 4000, 8000 nominal, each +/-25%. The
     * DOUBLING is what separates these brackets -- a flat ladder lands
     * every round inside [750,1250) and fails round 3's lower bound. */
    ladder_bracket(1000, 2, 750, 1250, 1000);
    ladder_bracket(1000, 3, 1500, 2500, 2000);
    ladder_bracket(1000, 4, 3000, 5000, 4000);
    ladder_bracket(1000, 5, 6000, 10000, 8000);

    /* THE CAP, spelled as literals: nominal 30000 by round 7 (1000 x
     * 2^5 = 32000 is already over it) and never more, however high the
     * round. A missing cap makes round 40 astronomically large; a cap at
     * the connector's 8000 makes it land in [6000,10000). */
    ladder_bracket(1000, 7, 22500, 37500, 30000);
    ladder_bracket(1000, 40, 22500, 37500, 30000);

    /* The default base is 500 ms, asserted as a literal against the
     * constant a caller actually gets. */
    ASSERT_EQ_INT(500, (int)CLOAK_CLIENT_STACK_DEFAULT_RECONNECT_BASE_MS);
    ladder_bracket(CLOAK_CLIENT_STACK_DEFAULT_RECONNECT_BASE_MS, 2, 375, 625, 500);

    /* The event and error name tables, compared EXACTLY. An assertion
     * that merely checked for a non-empty string would be satisfied by
     * "unknown" for every one of them. */
    ASSERT_EQ_INT(0, strcmp("round started",
                            cloak_client_stack_event_name(CLOAK_CLIENT_STACK_EVENT_ROUND_STARTED)));
    ASSERT_EQ_INT(0, strcmp("round failed",
                            cloak_client_stack_event_name(CLOAK_CLIENT_STACK_EVENT_ROUND_FAILED)));
    ASSERT_EQ_INT(0, strcmp("session up",
                            cloak_client_stack_event_name(CLOAK_CLIENT_STACK_EVENT_SESSION_UP)));
    ASSERT_EQ_INT(0, strcmp("session down",
                            cloak_client_stack_event_name(CLOAK_CLIENT_STACK_EVENT_SESSION_DOWN)));
    ASSERT_EQ_INT(
        0, strcmp("gave up", cloak_client_stack_event_name(CLOAK_CLIENT_STACK_EVENT_GAVE_UP)));
    ASSERT_EQ_INT(0, strcmp("unknown", cloak_client_stack_event_name((cloak_client_stack_event_t)99)));

    ASSERT_EQ_INT(0, strcmp("ok", cloak_client_stack_strerror(0)));
    ASSERT_EQ_INT(0, strcmp("argument", cloak_client_stack_strerror(CLOAK_CLIENT_STACK_ERR_ARG)));
    ASSERT_EQ_INT(0,
                  strcmp("client config", cloak_client_stack_strerror(CLOAK_CLIENT_STACK_ERR_CONFIG)));
    ASSERT_EQ_INT(
        0, strcmp("session template", cloak_client_stack_strerror(CLOAK_CLIENT_STACK_ERR_TEMPLATE)));
    ASSERT_EQ_INT(
        0, strcmp("remote address", cloak_client_stack_strerror(CLOAK_CLIENT_STACK_ERR_RESOLVE)));
    ASSERT_EQ_INT(0,
                  strcmp("local piper", cloak_client_stack_strerror(CLOAK_CLIENT_STACK_ERR_PIPER)));
    ASSERT_EQ_INT(0,
                  strcmp("local address", cloak_client_stack_strerror(CLOAK_CLIENT_STACK_ERR_LISTEN)));
    ASSERT_EQ_INT(
        0, strcmp("first bring-up", cloak_client_stack_strerror(CLOAK_CLIENT_STACK_ERR_CONNECTOR)));
    ASSERT_EQ_INT(0, strcmp("unknown", cloak_client_stack_strerror(-99)));
}

/* ---- the session-id predicate ------------------------------------------- */

/* stack_id_in_use is the half of edge E4 that has one right answer for a
 * list a test can build by hand. The draw around it is random and a
 * mutation to it hides in the noise; this does not.
 *
 * It is exercised against a hand-built list rather than a running client
 * BECAUSE a running client has one or two sessions and the interesting
 * cases are "the head", "the middle", "the tail" and "absent". */
static void test_the_session_id_predicate(void) {
    cloak_client_stack_t s;
    memset(&s, 0, sizeof(s));

    ASSERT_EQ_INT(0, stack_id_in_use(&s, 7));

    stack_slot_t a, b, c;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    memset(&c, 0, sizeof(c));
    a.session_id = 11;
    b.session_id = 22;
    c.session_id = 33;
    s.slots = &a;
    a.next = &b;
    b.prev = &a;
    b.next = &c;
    c.prev = &b;

    ASSERT_EQ_INT(1, stack_id_in_use(&s, 11)); /* head */
    ASSERT_EQ_INT(1, stack_id_in_use(&s, 22)); /* middle */
    ASSERT_EQ_INT(1, stack_id_in_use(&s, 33)); /* tail */
    ASSERT_EQ_INT(0, stack_id_in_use(&s, 12));
    ASSERT_EQ_INT(0, stack_id_in_use(&s, 0));

    /* And the draw never returns 0 (a uid plus session id 0 is the
     * server's ADMIN session) nor an id already in the list. 4096 draws
     * over a three-entry list is not a probabilistic argument about
     * collisions -- it is the zero rule that matters here, and 4096 draws
     * of a uniform 32-bit value would hit 0 with probability 2^-20. */
    for (int i = 0; i < 4096; i++) {
        uint32_t id = stack_pick_session_id(&s);
        ASSERT_TRUE(id != 0);
        ASSERT_EQ_INT(0, stack_id_in_use(&s, id));
    }
}

/* ---- the replacement's id is SEEDED, not merely likely to differ ------- */

/* THE CLAIM THE HEADER AND THE COMMIT MESSAGE BOTH MAKE is that a
 * reconnect's session id differs from the id it replaces STRUCTURALLY
 * rather than with probability 1 - 2^-32, because the replacement slot
 * carries the dead id while the new one is drawn. Nothing pinned that:
 * deleting the seeding line leaves case 2's `id1 != id0` passing 4
 * billion times out of 4 billion and one. Measured -- the deletion
 * escaped three runs out of three before this case existed.
 *
 * So the seeding is asserted where it happens. stack_schedule_replacement
 * is the whole of what stack_on_broken does for a shared session, and it
 * needs nothing but a reactor, which is why it is its own function. */
static void test_a_replacement_is_seeded_with_the_dead_id(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_client_stack_t s;
    memset(&s, 0, sizeof(s));
    s.self = &s;
    s.reactor = r;
    s.cfg.reconnect_base_ms = 1000;
    s.cfg.max_rounds = CLOAK_CLIENT_STACK_ROUNDS_UNBOUNDED;

    const uint32_t dead_id = 0xFACEB00Du;
    stack_schedule_replacement(&s, dead_id);

    /* A replacement really was created, it is the SHARED slot, it has not
     * run a round yet, and its ladder is armed. */
    ASSERT_TRUE(s.slots != NULL);
    if (s.slots == NULL) {
        cloak_reactor_destroy(r);
        return;
    }
    ASSERT_EQ_INT(1, s.slots->shared);
    ASSERT_EQ_INT(0, s.slots->round);
    ASSERT_EQ_INT(1, (int)s.pending);
    ASSERT_TRUE(s.slots->retry_timer != CLOAK_TIMER_INVALID);

    /* THE SEED. Without this line the slot's id is 0 and the dead id is
     * back in the pool. */
    ASSERT_EQ_INT((int)dead_id, (int)s.slots->session_id);

    /* AND THEREFORE the draw the next round makes cannot return it --
     * over as many draws as the real thing will ever make in a lifetime
     * of reconnects. This is the property; the line above is only how it
     * is obtained. */
    for (int i = 0; i < 20000; i++) {
        ASSERT_TRUE(stack_pick_session_id(&s) != dead_id);
    }

    stack_slot_destroy(&s, s.slots);
    ASSERT_TRUE(s.slots == NULL);
    ASSERT_EQ_INT(0, (int)s.pending);
    cloak_reactor_destroy(r);
}

/* ---- the SNI is drawn from ServerName together with MockDomainList ----- */

/* alt_names is parsed everywhere in this tree and, until this round, was
 * consumed nowhere: every session of every client presented one fixed
 * SNI, which is more distinguishable than one that varies. The selection
 * is per SESSION, which is Go's own granularity.
 *
 * Asserted here rather than end to end because no server in this project
 * validates SNI, so an integration test could not tell a fixed name from
 * a drawn one -- exactly the shape of test whose green comes from a path
 * other than the one it names. */
static void test_the_sni_is_drawn_from_the_whole_mock_domain_list(void) {
    cloak_client_config_t c;
    memset(&c, 0, sizeof(c));
    snprintf(c.server_name, sizeof(c.server_name), "a.example.com");

    /* NO alt names: always ServerName, and nothing is read past the end
     * of an empty list. */
    for (int i = 0; i < 256; i++) {
        ASSERT_EQ_INT(0, strcmp("a.example.com", stack_pick_server_name(&c)));
    }

    snprintf(c.alt_names[0], sizeof(c.alt_names[0]), "b.example.com");
    snprintf(c.alt_names[1], sizeof(c.alt_names[1]), "c.example.com");
    c.num_alt_names = 2;

    int seen[3] = {0, 0, 0};
    for (int i = 0; i < 600; i++) {
        const char *n = stack_pick_server_name(&c);
        ASSERT_TRUE(n != NULL);
        if (n == NULL) {
            return;
        }
        if (strcmp(n, "a.example.com") == 0) {
            seen[0]++;
        } else if (strcmp(n, "b.example.com") == 0) {
            seen[1]++;
        } else if (strcmp(n, "c.example.com") == 0) {
            seen[2]++;
        } else {
            ASSERT_TRUE(0); /* a name from outside the configured set */
        }
    }
    /* All three reached. A selection that ignored the list, or that drew
     * only from it, leaves one of these at zero; 600 draws over three
     * candidates misses one with probability below (2/3)^600. */
    ASSERT_TRUE(seen[0] > 0);
    ASSERT_TRUE(seen[1] > 0);
    ASSERT_TRUE(seen[2] > 0);
    /* And roughly evenly: a byte reduced modulo 3 gives each candidate
     * between 85 and 86 of 256 buckets, so ~200 +/- noise out of 600.
     * The wide bound is the point -- this catches "always the first
     * alt name", not a distribution claim. */
    for (int i = 0; i < 3; i++) {
        ASSERT_TRUE(seen[i] > 100);
    }
}

/* ---- case 1: the whole stack carries application bytes ------------------ */

static const uint8_t CASE1_PAYLOAD[] = "case 1: an application's bytes, end to end";

static void test_a_stack_carries_application_bytes_end_to_end(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before > 0);

    struct fixture fx;
    if (fixture_init(&fx) != 0) {
        fixture_destroy(&fx);
        return;
    }

    client_t cl;
    cs_config(&cl, &fx, fx.front_port, 0, 2);
    cloak_client_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    char err[256] = {0};
    int rc = cs_open(&cl, &fx, &sc, err, sizeof(err));
    ASSERT_EQ_INT(0, rc);
    if (rc != 0) {
        fprintf(stderr, "client stack: %s: %s\n", cloak_client_stack_strerror(rc), err);
        fixture_destroy(&fx);
        return;
    }

    /* The listener exists before the session does -- an application's
     * port must be stable across the life of the process. */
    ASSERT_TRUE(cloak_client_stack_local_port(cl.st) > 0);

    ASSERT_TRUE(pump_until(fx.reactor, cs_session_up, &cl, CS_MAX_TURNS, CS_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_sessions_up(cl.st));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_rounds_started(cl.st));
    /* Nothing was retried, which is what makes the reconnect counter
     * evidence in case 2 rather than decoration. */
    ASSERT_EQ_INT(0, (int)cloak_client_stack_reconnects(cl.st));

    /* TWO underlying connections joined ONE session, read off the server:
     * two attaches, one creation. */
    ASSERT_EQ_INT(2, fx.attach_count);
    ASSERT_EQ_INT(1, fx.created_count);
    ASSERT_EQ_INT(1, (int)cloak_server_stack_session_count(fx.srv));

    /* THE ACCESSOR IS PINNED AGAINST THE SERVER'S OWN VIEW. This is what
     * makes case 2's "the id changed" mean the id ON THE WIRE changed. */
    ASSERT_EQ_INT((int)fx.created_ids[0], (int)cloak_client_stack_session_id(cl.st));
    ASSERT_TRUE(cloak_client_stack_session_id(cl.st) != 0);

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cloak_client_stack_local_port(cl.st)));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, CS_MAX_TURNS, CS_TURN_MS));
    ASSERT_EQ_INT(1, lp.connected);

    /* D6: accepted, and NO stream until a byte arrives. */
    ASSERT_EQ_INT(1, (int)cloak_client_stack_local_conns(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_local_streams(cl.st));

    round_trip(&fx, &cl, &lp, CASE1_PAYLOAD, sizeof(CASE1_PAYLOAD));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_local_streams(cl.st));
    ASSERT_EQ_INT(1, fx.up.accept_count);

    lp_destroy(&lp);
    cs_close(&cl);
    fixture_destroy(&fx);

    int fds_after = count_open_fds();
    ASSERT_TRUE(fds_after > 0);
    ASSERT_EQ_INT(fds_before, fds_after);
}

/* ---- case 2: a dead session is replaced, under a DIFFERENT id ----------- */

static const uint8_t CASE2_FIRST[] = "case 2: before the session died";
static const uint8_t CASE2_SECOND[] = "case 2: after it was replaced";

/* D4'S WHOLE POINT, AND THE ASSERTION IS THE ID RATHER THAN THE TRAFFIC.
 * A reconnect that reused the session id would carry bytes perfectly
 * well against a server that had already reaped the old session -- and
 * would, against a server that had NOT, attach to a half-dead session
 * the client knows nothing about. Traffic resuming is necessary and not
 * sufficient, so this case asserts both, and the id first. */
static void test_a_dead_session_is_replaced_under_a_different_id(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before > 0);

    struct fixture fx;
    if (fixture_init(&fx) != 0) {
        fixture_destroy(&fx);
        return;
    }

    client_t cl;
    cs_config(&cl, &fx, fx.front_port, 0, 1);
    cloak_client_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    /* 200 ms so the post-break delay below has a bracket wide enough to
     * be read off event timestamps rather than off scheduling noise. */
    sc.reconnect_base_ms = 200;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cs_open(&cl, &fx, &sc, err, sizeof(err)));
    if (cl.st == NULL) {
        fixture_destroy(&fx);
        return;
    }

    ASSERT_TRUE(pump_until(fx.reactor, cs_session_up, &cl, CS_MAX_TURNS, CS_TURN_MS));
    uint32_t id0 = cloak_client_stack_session_id(cl.st);
    ASSERT_TRUE(id0 != 0);
    ASSERT_EQ_INT(1, fx.created_count);
    ASSERT_EQ_INT((int)fx.created_ids[0], (int)id0);

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cloak_client_stack_local_port(cl.st)));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, CS_MAX_TURNS, CS_TURN_MS));
    round_trip(&fx, &cl, &lp, CASE2_FIRST, sizeof(CASE2_FIRST));

    /* KILL IT FROM THE SERVER, by the server's own policy path: the panel
     * terminating the user destroys every session that user holds. This
     * is the same call an out-of-credit user reaches, and it is the one
     * kill available without holding the underlying socket. */
    cloak_userpanel_t *panel = cloak_server_stack_panel(fx.srv);
    ASSERT_TRUE(panel != NULL);
    cloak_userpanel_user_t *user = cloak_userpanel_find(panel, fx.uid);
    ASSERT_TRUE(user != NULL);
    if (user == NULL) {
        lp_destroy(&lp);
        cs_close(&cl);
        fixture_destroy(&fx);
        return;
    }
    cloak_userpanel_terminate(panel, user, "test: case 2");

    struct cs_wait w1 = {&cl, 1};
    ASSERT_TRUE(pump_until(fx.reactor, cs_down_is, &w1, CS_MAX_TURNS, CS_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_sessions_down(cl.st));

    /* The local connection that was spliced onto the dead session is gone
     * -- the piper tore it down in the one window where that was legal --
     * and the application sees EOF. */
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &lp, CS_MAX_TURNS, CS_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_local_conns(cl.st));

    /* THE REPLACEMENT. */
    ASSERT_TRUE(pump_until(fx.reactor, cs_session_up, &cl, CS_MAX_TURNS, CS_TURN_MS));
    uint32_t id1 = cloak_client_stack_session_id(cl.st);

    /* THE ASSERTION THIS CASE EXISTS FOR, stated three ways so that no
     * single mutation satisfies all of them: the client's own id changed,
     * the SERVER created a second session, and the id the SERVER gave it
     * is the new one rather than the old. */
    ASSERT_TRUE(id1 != 0);
    ASSERT_TRUE(id1 != id0);
    ASSERT_EQ_INT(2, fx.created_count);
    ASSERT_EQ_INT((int)id1, (int)fx.created_ids[1]);
    ASSERT_TRUE(fx.created_ids[1] != fx.created_ids[0]);

    /* It was the reconnect loop that did it, and it did it once. */
    ASSERT_EQ_INT(1, (int)cloak_client_stack_reconnects(cl.st));
    ASSERT_EQ_INT(2, (int)cloak_client_stack_rounds_started(cl.st));
    ASSERT_EQ_INT(2, (int)cloak_client_stack_sessions_up(cl.st));
    ASSERT_EQ_INT(1, cl.counts[CLOAK_CLIENT_STACK_EVENT_SESSION_DOWN]);
    ASSERT_EQ_INT(2, cl.counts[CLOAK_CLIENT_STACK_EVENT_SESSION_UP]);

    /* THE POST-BREAK DELAY, WITH A FLOOR. A replacement after a break
     * restarts the ladder at round 1 but still waits one base interval,
     * and that wait is not politeness: a server closing sessions for a
     * PERSISTENT reason -- the terminated user this case just used --
     * would otherwise put the client into a full-handshake hot loop
     * against it. Measured: arming that round with zero delay escaped
     * three runs out of three before this bracket existed, because
     * everything else here only waits for the replacement to arrive.
     *
     * 200 ms base, jittered to [150, 250): the floor is what catches the
     * hot loop, the ceiling catches a ladder that did not restart at
     * round 1 (round 2's delay would be 400). Both literals. */
    {
        uint64_t down_at = 0;
        uint64_t next_round_at = 0;
        for (int i = 0; i < cl.event_count; i++) {
            if (cl.events[i].ev == CLOAK_CLIENT_STACK_EVENT_SESSION_DOWN && down_at == 0) {
                down_at = cl.events[i].at_ms;
            } else if (down_at != 0 && next_round_at == 0 &&
                       cl.events[i].ev == CLOAK_CLIENT_STACK_EVENT_ROUND_STARTED) {
                next_round_at = cl.events[i].at_ms;
                ASSERT_EQ_INT(1, cl.events[i].round); /* the ladder restarted */
            }
        }
        ASSERT_TRUE(down_at != 0);
        ASSERT_TRUE(next_round_at != 0);
        uint64_t gap = next_round_at - down_at;
        fprintf(stderr, "case 2 measured: replacement round started %llums after the break\n",
                (unsigned long long)gap);
        ASSERT_TRUE(gap >= 145);
        ASSERT_TRUE(gap <= 330);
    }

    /* AND EDGE E3: the replacement's template got the piper too. A
     * reconnect wired without it establishes and then carries nothing --
     * which is exactly the failure that "traffic resumed" alone would
     * catch and "the id changed" alone would not. */
    local_peer_t lp2;
    ASSERT_EQ_INT(0, lp_open(&lp2, fx.reactor, cloak_client_stack_local_port(cl.st)));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp2, CS_MAX_TURNS, CS_TURN_MS));
    round_trip(&fx, &cl, &lp2, CASE2_SECOND, sizeof(CASE2_SECOND));

    lp_destroy(&lp2);
    lp_destroy(&lp);
    cs_close(&cl);
    fixture_destroy(&fx);

    int fds_after = count_open_fds();
    ASSERT_TRUE(fds_after > 0);
    ASSERT_EQ_INT(fds_before, fds_after);
}

/* ---- case 3: the backoff is observed between rounds --------------------- */

static int cs_events_at_least(void *ctx) {
    struct cs_wait *w = ctx;
    return (size_t)w->cl->event_count >= w->want;
}

/* A MEASURED BRACKET, NOT A CLAIMED MARGIN. With base = 200 ms the
 * nominal gaps between round starts are 200 and 400 ms, each jittered to
 * [0.75x, 1.25x): [150, 250) and [300, 500). Every round fails on a
 * refused connect to a closed loopback port, which costs microseconds,
 * so the gap IS the backoff plus one reactor turn's granularity.
 *
 * The brackets below are literals with a small allowance above for
 * scheduling, and every one of them fails on a real mutation:
 *   - backoff removed          -> gaps near 0, both lower bounds fail
 *   - the ladder does not double -> gap 2 lands in [150,250), its lower
 *                                 bound of 290 fails
 *   - the ladder doubles twice  -> gap 1 nominal 400, upper bound fails
 *   - the jitter goes one-sided -> not caught here, and it is not this
 *                                 case's job: test_the_backoff_ladder_
 *                                 is_what_the_header_says pins it
 *                                 directly, where 400 draws can. */
static void test_the_backoff_is_observed_between_rounds(void) {
    struct fixture fx;
    if (fixture_init(&fx) != 0) {
        fixture_destroy(&fx);
        return;
    }
    int dead = dead_port(fx.reactor);
    ASSERT_TRUE(dead > 0);

    client_t cl;
    cs_config(&cl, &fx, dead, 0, 1);
    cloak_client_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.reconnect_base_ms = 200;
    sc.max_rounds = 3;
    sc.connector_max_attempts = 1; /* one dial per round: the round's cost is ~0 */
    sc.dial_timeout_ms = 2000;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cs_open(&cl, &fx, &sc, err, sizeof(err)));
    if (cl.st == NULL) {
        fixture_destroy(&fx);
        return;
    }

    struct cs_wait w = {&cl, 1};
    ASSERT_TRUE(pump_until(fx.reactor, cs_failed_is, &w, CS_MAX_TURNS, CS_TURN_MS));

    ASSERT_EQ_INT(3, (int)cloak_client_stack_rounds_started(cl.st));
    ASSERT_EQ_INT(2, (int)cloak_client_stack_reconnects(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_sessions_up(cl.st));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_sessions_failed(cl.st));
    ASSERT_EQ_INT(3, cl.counts[CLOAK_CLIENT_STACK_EVENT_ROUND_STARTED]);
    ASSERT_EQ_INT(3, cl.counts[CLOAK_CLIENT_STACK_EVENT_ROUND_FAILED]);
    ASSERT_EQ_INT(1, cl.counts[CLOAK_CLIENT_STACK_EVENT_GAVE_UP]);
    /* max_rounds spent means the stack stops: nothing is pending and no
     * fourth round appears however long this runs. */
    ASSERT_EQ_INT(0, (int)cloak_client_stack_pending_sessions(cl.st));
    pump_for_ms(fx.reactor, 400);
    ASSERT_EQ_INT(3, (int)cloak_client_stack_rounds_started(cl.st));

    uint64_t start_at[4];
    int starts = 0;
    for (int i = 0; i < cl.event_count; i++) {
        if (cl.events[i].ev == CLOAK_CLIENT_STACK_EVENT_ROUND_STARTED && starts < 4) {
            ASSERT_EQ_INT(starts + 1, cl.events[i].round);
            start_at[starts++] = cl.events[i].at_ms;
        }
    }
    ASSERT_EQ_INT(3, starts);
    if (starts < 3) {
        cs_close(&cl);
        fixture_destroy(&fx);
        return;
    }

    uint64_t gap1 = start_at[1] - start_at[0];
    uint64_t gap2 = start_at[2] - start_at[1];
    uint64_t total = start_at[2] - start_at[0];
    fprintf(stderr, "case 3 measured: gap1=%llums gap2=%llums total=%llums\n",
            (unsigned long long)gap1, (unsigned long long)gap2, (unsigned long long)total);

    ASSERT_TRUE(gap1 >= 145);  /* nominal 200, jitter floor 150 */
    ASSERT_TRUE(gap1 <= 290);  /* jitter ceiling 250, plus scheduling */
    ASSERT_TRUE(gap2 >= 290);  /* nominal 400, jitter floor 300: THE DOUBLING */
    ASSERT_TRUE(gap2 <= 560);  /* jitter ceiling 500, plus scheduling */
    ASSERT_TRUE(total >= 440); /* 150 + 300 */
    ASSERT_TRUE(total <= 820); /* 250 + 500, plus scheduling */

    /* The ROUND_FAILED events carry the delay that was actually armed,
     * and it matches what was observed to within a reactor turn -- which
     * is what makes the event an operator's window onto the loop rather
     * than a number of its own. */
    int failed_seen = 0;
    for (int i = 0; i < cl.event_count; i++) {
        if (cl.events[i].ev != CLOAK_CLIENT_STACK_EVENT_ROUND_FAILED) {
            continue;
        }
        failed_seen++;
        if (failed_seen == 1) {
            ASSERT_TRUE(cl.events[i].retry_in_ms >= 150 && cl.events[i].retry_in_ms < 250);
        } else if (failed_seen == 2) {
            ASSERT_TRUE(cl.events[i].retry_in_ms >= 300 && cl.events[i].retry_in_ms < 500);
        } else {
            ASSERT_EQ_INT(0, (int)cl.events[i].retry_in_ms); /* no fourth round */
        }
    }
    ASSERT_EQ_INT(3, failed_seen);

    cs_close(&cl);
    fixture_destroy(&fx);
}

/* ---- case 4: singleplex -- two connections, two sessions ---------------- */

static const uint8_t CASE4_A[] = "case 4: connection A's own payload";
static const uint8_t CASE4_B[] = "case 4: connection B's, deliberately different";
static const uint8_t CASE4_B2[] = "case 4: B again, after A is gone";

static void test_singleplex_gives_each_connection_its_own_session(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before > 0);

    struct fixture fx;
    if (fixture_init(&fx) != 0) {
        fixture_destroy(&fx);
        return;
    }

    client_t cl;
    cs_config(&cl, &fx, fx.front_port, 1, 1);
    cloak_client_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    char err[256] = {0};
    ASSERT_EQ_INT(0, cs_open(&cl, &fx, &sc, err, sizeof(err)));
    if (cl.st == NULL) {
        fixture_destroy(&fx);
        return;
    }

    /* A SINGLEPLEX CLIENT WITH NO LOCAL CONNECTIONS DIALS NOTHING. That
     * is the mode's whole point and it is asserted before anything else,
     * because every later count is relative to it. */
    pump_for_ms(fx.reactor, 60);
    ASSERT_EQ_INT(0, (int)cloak_client_stack_rounds_started(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_live_sessions(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_session_count(fx.srv));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_session_id(cl.st)); /* no shared session to name */

    int port = cloak_client_stack_local_port(cl.st);

    local_peer_t a;
    ASSERT_EQ_INT(0, lp_open(&a, fx.reactor, port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &a, CS_MAX_TURNS, CS_TURN_MS));
    /* Accepted, and STILL nothing dialled: D6's saving applied to the
     * handshake, which in singleplex is the expensive half. */
    ASSERT_EQ_INT(1, (int)cloak_client_stack_local_conns(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_rounds_started(cl.st));

    round_trip(&fx, &cl, &a, CASE4_A, sizeof(CASE4_A));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_rounds_started(cl.st));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_live_sessions(cl.st));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_session_count(fx.srv));

    local_peer_t b;
    ASSERT_EQ_INT(0, lp_open(&b, fx.reactor, port));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &b, CS_MAX_TURNS, CS_TURN_MS));
    round_trip(&fx, &cl, &b, CASE4_B, sizeof(CASE4_B));

    /* TWO SESSIONS, not one session carrying two streams -- read off the
     * SERVER's registry, which is the only thing that can tell them
     * apart. */
    ASSERT_EQ_INT(2, (int)cloak_client_stack_rounds_started(cl.st));
    ASSERT_EQ_INT(2, (int)cloak_client_stack_live_sessions(cl.st));
    ASSERT_EQ_INT(2, (int)cloak_server_stack_session_count(fx.srv));
    ASSERT_EQ_INT(2, fx.created_count);
    /* EDGE E4: and they are not the same session id, which is what keeps
     * the server from attaching them to each other. */
    ASSERT_TRUE(fx.created_ids[0] != fx.created_ids[1]);
    ASSERT_EQ_INT(2, (int)cloak_client_stack_local_streams(cl.st));

    /* EACH SESSION DIES WITH ITS OWN CONNECTION. A closes; B must be
     * untouched, and must still carry bytes afterwards. */
    lp_shutdown(&a);
    struct cs_wait w1 = {&cl, 1};
    ASSERT_TRUE(pump_until(fx.reactor, cs_live_is, &w1, CS_MAX_TURNS, CS_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_live_sessions(cl.st));
    struct reg_wait rw1 = {&fx, 1};
    ASSERT_TRUE(pump_until(fx.reactor, reg_count_is, &rw1, CS_MAX_TURNS, CS_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_server_stack_session_count(fx.srv));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_sessions_down(cl.st));
    /* AND NO RECONNECT: in singleplex a dead session has no connection to
     * come back for. A stack that reconnected here would spend a
     * handshake per closed local connection, forever. */
    ASSERT_EQ_INT(0, (int)cloak_client_stack_reconnects(cl.st));
    ASSERT_EQ_INT(2, (int)cloak_client_stack_rounds_started(cl.st));

    round_trip(&fx, &cl, &b, CASE4_B2, sizeof(CASE4_B2));

    lp_shutdown(&b);
    struct cs_wait w0 = {&cl, 0};
    ASSERT_TRUE(pump_until(fx.reactor, cs_live_is, &w0, CS_MAX_TURNS, CS_TURN_MS));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_live_sessions(cl.st));
    struct reg_wait rw0 = {&fx, 0};
    ASSERT_TRUE(pump_until(fx.reactor, reg_count_is, &rw0, CS_MAX_TURNS, CS_TURN_MS));
    ASSERT_EQ_INT(2, (int)cloak_client_stack_sessions_down(cl.st));

    /* AND IT STAYS THAT WAY, WHICH IS THE ASSERTION THAT ACTUALLY
     * CARRIES THIS. A replacement round would be armed one base interval
     * (500 ms by default) after a break, so every counter above is read
     * INSIDE that window and a stack that wrongly reconnected in
     * singleplex satisfies all of them. Measured: with the mode check in
     * stack_on_broken removed, this file was green until this wait was
     * added. Nine hundred milliseconds is past 500 + 25% with room. */
    pump_for_ms(fx.reactor, 900);
    ASSERT_EQ_INT(2, (int)cloak_client_stack_rounds_started(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_reconnects(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_live_sessions(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_pending_sessions(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_server_stack_session_count(fx.srv));

    lp_destroy(&b);
    lp_destroy(&a);
    cs_close(&cl);
    fixture_destroy(&fx);

    int fds_after = count_open_fds();
    ASSERT_TRUE(fds_after > 0);
    ASSERT_EQ_INT(fds_before, fds_after);
}

/* ---- case 5: a connection whose session never comes up ------------------ */

static const uint8_t CASE5_BYTE[] = "x";

/* THE STATED CONTRACT, BOTH HALVES OF IT.
 *
 * SINGLEPLEX: the connection is accepted, held with no session requested
 * until its first byte, and then waits out this stack's ladder. When the
 * ladder is spent the piper is told the session will never exist and
 * THAT ONE connection is closed. The bracket below is what makes this a
 * test of the ladder rather than of an immediate refusal.
 *
 * SHARED: there is no per-connection bring-up to wait for, so an accept
 * arriving while no session exists is closed immediately by the piper --
 * the alternative, queueing it, would be a lie about a connection the
 * application believes is live. */
static void test_a_connection_whose_session_never_comes_up(void) {
    int fds_before = count_open_fds();
    ASSERT_TRUE(fds_before > 0);

    struct fixture fx;
    if (fixture_init(&fx) != 0) {
        fixture_destroy(&fx);
        return;
    }
    int dead = dead_port(fx.reactor);
    ASSERT_TRUE(dead > 0);

    /* ---- singleplex ---- */
    client_t cl;
    cs_config(&cl, &fx, dead, 1, 1);
    /* Far larger than the ladder, so that what fires is the STACK's
     * bound and not the piper's deadline. The deadline's own half of the
     * contract is case 6E. */
    cl.cfg.stream_timeout_sec = 30;
    cloak_client_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.reconnect_base_ms = 200;
    sc.max_rounds = 2;
    sc.connector_max_attempts = 1;
    sc.dial_timeout_ms = 2000;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cs_open(&cl, &fx, &sc, err, sizeof(err)));
    if (cl.st == NULL) {
        fixture_destroy(&fx);
        return;
    }

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cloak_client_stack_local_port(cl.st)));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, CS_MAX_TURNS, CS_TURN_MS));

    uint64_t t0 = monotonic_ms();
    lp_send(&lp, CASE5_BYTE, sizeof(CASE5_BYTE));
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &lp, CS_MAX_TURNS, CS_TURN_MS));
    uint64_t elapsed = monotonic_ms() - t0;
    fprintf(stderr, "case 5 measured: singleplex give-up after %llums\n",
            (unsigned long long)elapsed);

    /* THE BRACKET. Two rounds separated by one base interval jittered to
     * [150, 250): the connection must NOT be dropped before the ladder
     * has actually been walked, and must not sit there once it has. */
    ASSERT_TRUE(elapsed >= 145);
    ASSERT_TRUE(elapsed <= 700);

    ASSERT_EQ_INT(1, lp.eof);
    ASSERT_EQ_INT(2, (int)cloak_client_stack_rounds_started(cl.st));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_reconnects(cl.st));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_sessions_failed(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_pending_sessions(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_local_conns(cl.st));
    ASSERT_EQ_INT(1, cl.counts[CLOAK_CLIENT_STACK_EVENT_GAVE_UP]);

    lp_destroy(&lp);
    cs_close(&cl);

    /* ---- shared ---- */
    client_t cl2;
    cs_config(&cl2, &fx, dead, 0, 1);
    cloak_client_stack_config_t sc2;
    memset(&sc2, 0, sizeof(sc2));
    sc2.reconnect_base_ms = 5000; /* the next round is far away: no session, for a while */
    sc2.connector_max_attempts = 1;
    sc2.dial_timeout_ms = 2000;
    err[0] = '\0';
    ASSERT_EQ_INT(0, cs_open(&cl2, &fx, &sc2, err, sizeof(err)));
    if (cl2.st == NULL) {
        fixture_destroy(&fx);
        return;
    }
    struct cs_wait rw = {&cl2, 1};
    ASSERT_TRUE(pump_until(fx.reactor, cs_rounds_is, &rw, CS_MAX_TURNS, CS_TURN_MS));
    ASSERT_EQ_INT(0, cloak_client_stack_session_up(cl2.st));

    local_peer_t lp2;
    ASSERT_EQ_INT(0, lp_open(&lp2, fx.reactor, cloak_client_stack_local_port(cl2.st)));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp2, CS_MAX_TURNS, CS_TURN_MS));
    uint64_t t1 = monotonic_ms();
    ASSERT_TRUE(pump_until(fx.reactor, lp_at_eof, &lp2, CS_MAX_TURNS, CS_TURN_MS));
    uint64_t closed_after = monotonic_ms() - t1;
    fprintf(stderr, "case 5 measured: shared accept closed after %llums\n",
            (unsigned long long)closed_after);
    /* IMMEDIATELY, which here means "inside a reactor turn or two", and
     * emphatically not "when the next round happens" (5000 ms away). */
    ASSERT_TRUE(closed_after <= 250);
    ASSERT_EQ_INT(0, (int)cloak_client_stack_local_conns(cl2.st));
    /* And the stack is still trying: unbounded rounds, so nothing gave
     * up. */
    ASSERT_EQ_INT(0, cl2.counts[CLOAK_CLIENT_STACK_EVENT_GAVE_UP]);
    ASSERT_EQ_INT(1, (int)cloak_client_stack_pending_sessions(cl2.st));

    lp_destroy(&lp2);
    cs_close(&cl2);
    fixture_destroy(&fx);

    int fds_after = count_open_fds();
    ASSERT_TRUE(fds_after > 0);
    ASSERT_EQ_INT(fds_before, fds_after);
}

/* ---- case 6: teardown at every stage ------------------------------------ */

static const uint8_t CASE6_PAYLOAD[] = "case 6: bytes in flight when the stack is closed";

/* SIX TEARDOWN POINTS, each one asserted to BE the point it claims --
 * "pending == 1" and "live == 1" are what separate "torn down
 * mid-handshake" from "torn down after it quietly finished", which is
 * the difference between a teardown test and a test of nothing. */
static void test_teardown_at_every_stage(void) {
    /* 6A: before the first dial has even left the kickoff timer. */
    {
        int fds_before = count_open_fds();
        struct fixture fx;
        if (fixture_init(&fx) != 0) {
            fixture_destroy(&fx);
            return;
        }
        client_t cl;
        cs_config(&cl, &fx, fx.front_port, 0, 2);
        cloak_client_stack_config_t sc;
        memset(&sc, 0, sizeof(sc));
        char err[256] = {0};
        ASSERT_EQ_INT(0, cs_open(&cl, &fx, &sc, err, sizeof(err)));
        ASSERT_EQ_INT(1, (int)cloak_client_stack_pending_sessions(cl.st));
        cs_close(&cl);
        fixture_destroy(&fx);
        ASSERT_EQ_INT(fds_before, count_open_fds());
    }

    /* 6B: mid-handshake -- dials issued, nothing complete. */
    {
        int fds_before = count_open_fds();
        struct fixture fx;
        if (fixture_init(&fx) != 0) {
            fixture_destroy(&fx);
            return;
        }
        client_t cl;
        cs_config(&cl, &fx, fx.front_port, 0, 2);
        cloak_client_stack_config_t sc;
        memset(&sc, 0, sizeof(sc));
        char err[256] = {0};
        ASSERT_EQ_INT(0, cs_open(&cl, &fx, &sc, err, sizeof(err)));
        for (int i = 0; i < 2; i++) {
            cloak_reactor_run_once(fx.reactor, 1);
        }
        ASSERT_EQ_INT(1, (int)cloak_client_stack_pending_sessions(cl.st));
        ASSERT_EQ_INT(0, (int)cloak_client_stack_live_sessions(cl.st));
        cs_close(&cl);
        fixture_destroy(&fx);
        ASSERT_EQ_INT(fds_before, count_open_fds());
    }

    /* 6C: mid-traffic -- a relay running, bytes in flight. */
    {
        int fds_before = count_open_fds();
        struct fixture fx;
        if (fixture_init(&fx) != 0) {
            fixture_destroy(&fx);
            return;
        }
        client_t cl;
        cs_config(&cl, &fx, fx.front_port, 0, 2);
        cloak_client_stack_config_t sc;
        memset(&sc, 0, sizeof(sc));
        char err[256] = {0};
        ASSERT_EQ_INT(0, cs_open(&cl, &fx, &sc, err, sizeof(err)));
        ASSERT_TRUE(pump_until(fx.reactor, cs_session_up, &cl, CS_MAX_TURNS, CS_TURN_MS));
        local_peer_t lp;
        ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cloak_client_stack_local_port(cl.st)));
        ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, CS_MAX_TURNS, CS_TURN_MS));
        round_trip(&fx, &cl, &lp, CASE6_PAYLOAD, sizeof(CASE6_PAYLOAD));
        ASSERT_EQ_INT(1, (int)cloak_client_stack_local_streams(cl.st));
        /* More bytes on their way out, then close without draining them:
         * THE PIPER MUST BE DESTROYED BEFORE THE SESSION or this is a
         * heap-use-after-free under ASan. */
        lp_send(&lp, CASE6_PAYLOAD, sizeof(CASE6_PAYLOAD));
        cloak_reactor_run_once(fx.reactor, 1);
        cs_close(&cl);
        lp_destroy(&lp);
        fixture_destroy(&fx);
        ASSERT_EQ_INT(fds_before, count_open_fds());
    }

    /* 6D: mid-backoff -- a retry timer armed and nothing else. */
    {
        int fds_before = count_open_fds();
        struct fixture fx;
        if (fixture_init(&fx) != 0) {
            fixture_destroy(&fx);
            return;
        }
        int dead = dead_port(fx.reactor);
        client_t cl;
        cs_config(&cl, &fx, dead, 0, 1);
        cloak_client_stack_config_t sc;
        memset(&sc, 0, sizeof(sc));
        sc.reconnect_base_ms = 300;
        sc.connector_max_attempts = 1;
        sc.dial_timeout_ms = 2000;
        char err[256] = {0};
        ASSERT_EQ_INT(0, cs_open(&cl, &fx, &sc, err, sizeof(err)));
        struct cs_wait w = {&cl, 1};
        ASSERT_TRUE(pump_until(fx.reactor, cs_events_at_least, &w, CS_MAX_TURNS, CS_TURN_MS));
        struct cs_wait w2 = {&cl, 2};
        ASSERT_TRUE(pump_until(fx.reactor, cs_events_at_least, &w2, CS_MAX_TURNS, CS_TURN_MS));
        ASSERT_EQ_INT(1, cl.counts[CLOAK_CLIENT_STACK_EVENT_ROUND_FAILED]);
        ASSERT_TRUE(cl.events[1].retry_in_ms >= 225); /* a timer really is armed */
        ASSERT_EQ_INT(1, (int)cloak_client_stack_pending_sessions(cl.st));
        cs_close(&cl);
        /* AND THE REACTOR KEEPS RUNNING PAST WHEN THAT TIMER WOULD HAVE
         * FIRED. Closing alone proves nothing about a cancelled timer: a
         * stale one whose userdata is the freed slot never fires if the
         * reactor is destroyed first, so every teardown case in this file
         * was green with stack_slot_destroy's cancel removed until this
         * wait was added. Now the stale timer runs, and reads a freed
         * slot -- a heap-use-after-free under ASan. */
        pump_for_ms(fx.reactor, 600);
        fixture_destroy(&fx);
        ASSERT_EQ_INT(fds_before, count_open_fds());
    }

    /* 6E: SINGLEPLEX, mid-bring-up, torn down by cloak_client_stack_close
     * -- which reaches stack_cancel_session through the piper. */
    {
        int fds_before = count_open_fds();
        struct fixture fx;
        if (fixture_init(&fx) != 0) {
            fixture_destroy(&fx);
            return;
        }
        quiet_site_t hole;
        memset(&hole, 0, sizeof(hole));
        cloak_listener_t hole_l;
        char err[256] = {0};
        ASSERT_EQ_INT(0, cloak_listener_open(&hole_l, fx.reactor, "127.0.0.1:0", quiet_on_accept,
                                             &hole, err, sizeof(err)));
        int hole_port = cloak_listener_port(&hole_l);

        client_t cl;
        cs_config(&cl, &fx, hole_port, 1, 1);
        cloak_client_stack_config_t sc;
        memset(&sc, 0, sizeof(sc));
        sc.handshake_timeout_ms = 30000; /* the handshake will never finish; hold it open */
        err[0] = '\0';
        ASSERT_EQ_INT(0, cs_open(&cl, &fx, &sc, err, sizeof(err)));
        local_peer_t lp;
        ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cloak_client_stack_local_port(cl.st)));
        ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, CS_MAX_TURNS, CS_TURN_MS));
        lp_send(&lp, CASE5_BYTE, sizeof(CASE5_BYTE));
        /* Waited on the BLACK HOLE'S accept rather than on the stack's own
         * counter: pending goes to 1 the instant the slot is created, so a
         * teardown at that moment would be testing the kickoff timer
         * again (6A's job) rather than a handshake in flight. */
        ASSERT_TRUE(pump_until(fx.reactor, quiet_accepted, &hole, CS_MAX_TURNS, CS_TURN_MS));
        ASSERT_EQ_INT(1, hole.accept_count); /* the dial really is in flight */
        ASSERT_EQ_INT(1, (int)cloak_client_stack_pending_sessions(cl.st));
        cs_close(&cl);
        lp_destroy(&lp);
        cloak_listener_close(&hole_l);
        quiet_destroy(&hole);
        fixture_destroy(&fx);
        ASSERT_EQ_INT(fds_before, count_open_fds());
    }
}

/* ---- case 6F: cancel_session, observed while the stack is ALIVE --------- */

/* THE ONE CASE THAT CATCHES AN EMPTIED cancel_session WITHOUT
 * LeakSanitizer, and the reason it exists: every other teardown path
 * reaches cancel_session from cloak_client_stack_close, where a slot that
 * was never freed is freed a moment later by the close walk anyway --
 * indistinguishable, in Debug, from a correct run. Here the piper's
 * first-byte deadline (the config's StreamTimeout, which in singleplex
 * bounds the SESSION wait too) expires against a black hole that accepts
 * and never replies, and the stack is then asked, while still running,
 * whether it let go.
 *
 * THE BRACKET IS MEASURED ON BOTH SIDES: nothing may be cancelled before
 * the one-second deadline, and it must have happened well before the
 * handshake's own 30-second timeout could account for it -- otherwise
 * this case would pass for the wrong reason. */
static void test_a_cancelled_bring_up_is_released_while_the_stack_runs(void) {
    int fds_before = count_open_fds();
    struct fixture fx;
    if (fixture_init(&fx) != 0) {
        fixture_destroy(&fx);
        return;
    }
    quiet_site_t hole;
    memset(&hole, 0, sizeof(hole));
    cloak_listener_t hole_l;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_listener_open(&hole_l, fx.reactor, "127.0.0.1:0", quiet_on_accept, &hole,
                                         err, sizeof(err)));
    int hole_port = cloak_listener_port(&hole_l);

    client_t cl;
    cs_config(&cl, &fx, hole_port, 1, 1);
    cl.cfg.stream_timeout_sec = 1; /* the piper's deadline, in Go's own units */
    cloak_client_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.handshake_timeout_ms = 30000;
    sc.connector_max_attempts = 1;
    err[0] = '\0';
    ASSERT_EQ_INT(0, cs_open(&cl, &fx, &sc, err, sizeof(err)));
    if (cl.st == NULL) {
        cloak_listener_close(&hole_l);
        quiet_destroy(&hole);
        fixture_destroy(&fx);
        return;
    }

    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cloak_client_stack_local_port(cl.st)));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, CS_MAX_TURNS, CS_TURN_MS));
    uint64_t t0 = monotonic_ms();
    lp_send(&lp, CASE5_BYTE, sizeof(CASE5_BYTE));

    struct cs_wait w1 = {&cl, 1};
    ASSERT_TRUE(pump_until(fx.reactor, cs_pending_is, &w1, CS_MAX_TURNS, CS_TURN_MS));
    ASSERT_EQ_INT(1, (int)cloak_client_stack_rounds_started(cl.st));

    /* NOT YET: the deadline is a second away, and a stack that dropped
     * the bring-up early would be dropping it for a reason that has
     * nothing to do with the contract. */
    pump_for_ms(fx.reactor, 600);
    ASSERT_EQ_INT(1, (int)cloak_client_stack_pending_sessions(cl.st));

    struct cs_wait w0 = {&cl, 0};
    ASSERT_TRUE(pump_until(fx.reactor, cs_pending_is, &w0, CS_MAX_TURNS, CS_TURN_MS));
    uint64_t elapsed = monotonic_ms() - t0;
    fprintf(stderr, "case 6F measured: bring-up released after %llums\n",
            (unsigned long long)elapsed);

    /* THE BRACKET. The deadline is 1000 ms; the handshake timeout that
     * must NOT be what ended this is 30000 ms. */
    ASSERT_TRUE(elapsed >= 900);
    ASSERT_TRUE(elapsed <= 3000);
    ASSERT_EQ_INT(0, (int)cloak_client_stack_pending_sessions(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_local_conns(cl.st));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_live_sessions(cl.st));
    /* The stack is still running and never gave up: the cancel came from
     * the piper, not from the ladder. */
    ASSERT_EQ_INT(0, cl.counts[CLOAK_CLIENT_STACK_EVENT_GAVE_UP]);
    ASSERT_EQ_INT(1, (int)cloak_client_stack_rounds_started(cl.st));

    lp_destroy(&lp);
    cs_close(&cl);
    cloak_listener_close(&hole_l);
    quiet_destroy(&hole);
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- the template fields the stack promises to clear -------------------- */

static int poison_calls;

static void poison_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    (void)userdata;
    poison_calls++;
}
static void poison_new_stream(cloak_session_t *sesh, cloak_stream_t *st, void *userdata) {
    (void)sesh;
    (void)st;
    (void)userdata;
    poison_calls++;
}
static void poison_stream_data(cloak_session_t *sesh, cloak_stream_t *st, void *userdata) {
    (void)sesh;
    (void)st;
    (void)userdata;
    poison_calls++;
}
static void poison_writable(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    (void)userdata;
    poison_calls++;
}

static const uint8_t POISON_PAYLOAD[] = "the template's ignored fields are cleared, not honoured";

/* THE HEADER SAYS obfuscator, valve AND THE FOUR CALLBACKS ARE IGNORED,
 * and fill_template_defaults clears them rather than merely documenting
 * it. Nothing in this suite ever SET any of them, so every one of those
 * clears was an equivalent mutant: the code was right and the test did
 * not know it.
 *
 * WHAT THIS CASE CAN AND CANNOT KILL, said plainly rather than implied:
 *
 *   THE VALVE CLEAR IS THE ONE THAT IS OBSERVABLE, and it is the one that
 *   matters. Nothing downstream overwrites it, so a valve left in the
 *   template is installed into every session this client creates and
 *   metered into -- through a pointer the caller may have popped off its
 *   stack. Removing that clear makes the counter below non-zero.
 *
 *   THE OTHER FIVE ARE EQUIVALENT MUTANTS AND WILL STAY THAT WAY, for a
 *   reason worth recording: cloak_client_piper_install overwrites all
 *   four callbacks on the way to every connector, and the connector
 *   overwrites the obfuscator with the agreed key. So the clears are
 *   belt to install's braces. They are kept because "ignored" should be
 *   TRUE at the point the header says it, not true only because
 *   something later happens to rewrite it -- but a reader should not be
 *   told these assertions pin something they do not. What the four
 *   never-called assertions DO pin is install's own overwrite, which is
 *   a different claim and a real one. */
static void test_the_ignored_template_fields_are_cleared(void) {
    int fds_before = count_open_fds();
    struct fixture fx;
    if (fixture_init(&fx) != 0) {
        fixture_destroy(&fx);
        return;
    }

    poison_calls = 0;
    cloak_valve_t poison_valve;
    memset(&poison_valve, 0, sizeof(poison_valve));

    client_t cl;
    cs_config(&cl, &fx, fx.front_port, 0, 1);
    cloak_client_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.session_template.on_broken = poison_broken;
    sc.session_template.on_broken_userdata = &poison_calls;
    sc.session_template.on_new_stream = poison_new_stream;
    sc.session_template.on_new_stream_userdata = &poison_calls;
    sc.session_template.on_stream_data = poison_stream_data;
    sc.session_template.on_stream_data_userdata = &poison_calls;
    sc.session_template.on_writable = poison_writable;
    sc.session_template.on_writable_userdata = &poison_calls;
    sc.session_template.valve = &poison_valve;
    memset(&sc.session_template.obfuscator, 0xEE, sizeof(sc.session_template.obfuscator));
    char err[256] = {0};
    ASSERT_EQ_INT(0, cs_open(&cl, &fx, &sc, err, sizeof(err)));
    if (cl.st == NULL) {
        fixture_destroy(&fx);
        return;
    }

    ASSERT_TRUE(pump_until(fx.reactor, cs_session_up, &cl, CS_MAX_TURNS, CS_TURN_MS));
    local_peer_t lp;
    ASSERT_EQ_INT(0, lp_open(&lp, fx.reactor, cloak_client_stack_local_port(cl.st)));
    ASSERT_TRUE(pump_until(fx.reactor, lp_connected, &lp, CS_MAX_TURNS, CS_TURN_MS));

    /* THE TUNNEL STILL WORKS, which is what a poisoned obfuscator would
     * have broken outright had the connector not replaced it. */
    round_trip(&fx, &cl, &lp, POISON_PAYLOAD, sizeof(POISON_PAYLOAD));

    /* NOTHING WAS METERED INTO THE CALLER'S VALVE: bytes crossed the
     * session and this counter did not move. */
    ASSERT_EQ_INT(0, (int)cloak_valve_rx(&poison_valve));
    ASSERT_EQ_INT(0, (int)cloak_valve_tx(&poison_valve));

    /* AND NONE OF THE FOUR CALLBACKS WAS EVER THE SESSION'S: the piper
     * owns all four, which is edge E2 -- an owner's on_broken in this
     * position is a use-after-free, not a customisation. */
    ASSERT_EQ_INT(0, poison_calls);

    lp_destroy(&lp);
    cs_close(&cl);
    /* The session breaking on close would have reached a poison
     * on_broken had one survived. */
    ASSERT_EQ_INT(0, poison_calls);
    ASSERT_EQ_INT(0, (int)cloak_valve_rx(&poison_valve));
    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

/* ---- the configuration contracts ---------------------------------------- */

/* Every rejection open can make, each asserted to produce ITS OWN code
 * and ITS OWN name -- and every one of them tried against a stack that is
 * then closed, so that a rejected open is also a leak-free one. */
static void test_the_configuration_contracts(void) {
    int fds_before = count_open_fds();
    struct fixture fx;
    if (fixture_init(&fx) != 0) {
        fixture_destroy(&fx);
        return;
    }

    char err[256];
    cloak_client_stack_t *st = (cloak_client_stack_t *)(void *)&fx; /* deliberately junk */

    /* ARG, and the initialize-before-validate rule: *out is NULL on every
     * failure path, so a caller's cleanup closes NULL rather than the
     * junk above. */
    err[0] = '\0';
    ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_ARG,
                  cloak_client_stack_open(&st, NULL, err, sizeof(err)));
    ASSERT_TRUE(st == NULL);
    ASSERT_TRUE(err[0] != '\0');
    ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_ARG, cloak_client_stack_open(NULL, NULL, err, sizeof(err)));

    client_t cl;
    cs_config(&cl, &fx, fx.front_port, 0, 1);
    cloak_client_stack_config_t base;
    memset(&base, 0, sizeof(base));
    base.reactor = fx.reactor;
    base.config = &cl.cfg;
    base.session_template.max_on_wire_size = CS_WIRE;

    {
        cloak_client_stack_config_t sc = base;
        sc.reactor = NULL;
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_ARG,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
        ASSERT_TRUE(st == NULL);
    }
    {
        cloak_client_stack_config_t sc = base;
        sc.config = NULL;
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_ARG,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
    }

    /* CONFIG, one rejection at a time against an otherwise-valid config. */
    {
        cloak_client_stack_config_t sc = base;
        cloak_client_config_t bad = cl.cfg;
        bad.num_conn = 0;
        sc.config = &bad;
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_CONFIG,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
        bad.num_conn = CLOAK_CLIENT_CONNECTOR_MAX_CONN + 1;
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_CONFIG,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
        /* The boundary from BOTH sides: the largest accepted value must
         * be accepted. 64 as a literal, not as the constant, so a
         * mutation to the constant is visible. */
        ASSERT_EQ_INT(64, CLOAK_CLIENT_CONNECTOR_MAX_CONN);
    }
    {
        /* Singleplex with more than one connection: the parser cannot
         * produce it, a hand-built config can, and it would silently cost
         * an N-connection handshake per local connection. */
        cloak_client_stack_config_t sc = base;
        cloak_client_config_t bad = cl.cfg;
        bad.singleplex = 1;
        bad.num_conn = 2;
        sc.config = &bad;
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_CONFIG,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
    }
    {
        cloak_client_stack_config_t sc = base;
        cloak_client_config_t bad = cl.cfg;
        bad.remote_host[0] = '\0';
        sc.config = &bad;
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_CONFIG,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
    }
    {
        cloak_client_stack_config_t sc = base;
        cloak_client_config_t bad = cl.cfg;
        bad.local_port[0] = '\0';
        sc.config = &bad;
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_CONFIG,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
    }
    {
        cloak_client_stack_config_t sc = base;
        cloak_client_config_t bad = cl.cfg;
        bad.proxy_method[0] = '\0';
        sc.config = &bad;
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_CONFIG,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
    }
    {
        /* CDN: refused HERE, once, rather than by the connector on every
         * bring-up forever. */
        cloak_client_stack_config_t sc = base;
        cloak_client_config_t bad = cl.cfg;
        bad.transport = CLOAK_TRANSPORT_CDN;
        sc.config = &bad;
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_CONFIG,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
    }
    {
        cloak_client_stack_config_t sc = base;
        cloak_client_config_t bad = cl.cfg;
        bad.stream_timeout_sec = -1;
        sc.config = &bad;
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_CONFIG,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
    }

    /* TEMPLATE, rejected by cloak_session_init itself. */
    {
        cloak_client_stack_config_t sc = base;
        sc.session_template.max_on_wire_size = 3; /* below any frame header */
        err[0] = '\0';
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_TEMPLATE,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
        ASSERT_TRUE(st == NULL);
    }

    /* RESOLVE. */
    {
        cloak_client_stack_config_t sc = base;
        cloak_client_config_t bad = cl.cfg;
        snprintf(bad.remote_host, sizeof(bad.remote_host), "no-such-host.invalid");
        sc.config = &bad;
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_RESOLVE,
                      cloak_client_stack_open(&st, &sc, err, sizeof(err)));
    }

    /* LISTEN: a local address that cannot be bound. 192.0.2.1 is
     * TEST-NET-1 (RFC 5737) and is not assigned to any interface here, so
     * bind fails with EADDRNOTAVAIL.
     *
     * NOT a privileged port: this suite runs as root inside its container,
     * where binding port 1 SUCCEEDS -- which it duly did, leaving a live
     * stack and two descriptors behind and failing the fd bracket at the
     * end of this function. That is the fd bracket doing its job, and it
     * is why the check is worth having. */
    {
        cloak_client_stack_config_t sc = base;
        cloak_client_config_t bad = cl.cfg;
        snprintf(bad.local_host, sizeof(bad.local_host), "192.0.2.1");
        sc.config = &bad;
        int rc = cloak_client_stack_open(&st, &sc, err, sizeof(err));
        ASSERT_EQ_INT(CLOAK_CLIENT_STACK_ERR_LISTEN, rc);
        ASSERT_TRUE(st == NULL);
        if (rc == 0) {
            cloak_client_stack_close(st);
            st = NULL;
        }
    }

    /* THE CONFIG IS COPIED: the caller's may die the moment open
     * returns, and every bring-up after that still authenticates. */
    {
        cloak_client_config_t *heap = malloc(sizeof(*heap));
        ASSERT_TRUE(heap != NULL);
        if (heap == NULL) {
            fixture_destroy(&fx);
            return;
        }
        *heap = cl.cfg;
        cloak_client_stack_config_t sc = base;
        sc.config = heap;
        sc.on_event = cs_on_event;
        sc.on_event_userdata = &cl;
        cloak_client_stack_t *live = NULL;
        err[0] = '\0';
        ASSERT_EQ_INT(0, cloak_client_stack_open(&live, &sc, err, sizeof(err)));
        memset(heap, 0xAB, sizeof(*heap));
        free(heap);
        cl.st = live;
        ASSERT_TRUE(pump_until(fx.reactor, cs_session_up, &cl, CS_MAX_TURNS, CS_TURN_MS));
        ASSERT_EQ_INT(1, (int)cloak_client_stack_sessions_up(cl.st));
        cs_close(&cl);
    }

    /* Accessors on NULL and on a closed handle answer rather than crash. */
    ASSERT_EQ_INT(-1, cloak_client_stack_local_port(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_session_id(NULL));
    ASSERT_EQ_INT(0, cloak_client_stack_session_up(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_live_sessions(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_pending_sessions(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_rounds_started(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_reconnects(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_sessions_up(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_sessions_failed(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_sessions_down(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_local_conns(NULL));
    ASSERT_EQ_INT(0, (int)cloak_client_stack_local_streams(NULL));
    cloak_client_stack_close(NULL); /* idempotent on NULL */

    fixture_destroy(&fx);
    ASSERT_EQ_INT(fds_before, count_open_fds());
}

TEST_MAIN_BEGIN()
cloak_log_set_level(CLOAK_LOG_ERROR);
test_the_backoff_ladder_is_what_the_header_says();
test_the_session_id_predicate();
test_a_replacement_is_seeded_with_the_dead_id();
test_the_sni_is_drawn_from_the_whole_mock_domain_list();
test_a_stack_carries_application_bytes_end_to_end();
test_a_dead_session_is_replaced_under_a_different_id();
test_the_backoff_is_observed_between_rounds();
test_singleplex_gives_each_connection_its_own_session();
test_a_connection_whose_session_never_comes_up();
test_teardown_at_every_stage();
test_a_cancelled_bring_up_is_released_while_the_stack_runs();
test_the_ignored_template_fields_are_cleared();
test_the_configuration_contracts();
TEST_MAIN_END()
