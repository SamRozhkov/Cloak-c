#define _POSIX_C_SOURCE 200809L
#include "cloak/net.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* Scratch size for one read()/write() syscall. Independent of the queue
 * capacity: the loop below keeps going until EAGAIN either way. */
#define RELAY_CHUNK 16384

static void relay_teardown(cloak_relay_t *rl, int fire_done);

/* What each side needs to be watched for, given the current queue state:
 * readable while its own queue has room and it has not hit EOF, writable
 * while the opposite queue has bytes waiting for it. */
static uint32_t desired_interest(const cloak_relay_t *rl, int i) {
    uint32_t ev = 0;
    /* read_eof[i] is defensive: with the current all-or-nothing teardown
     * (any EOF ends the whole relay in the same turn that discovers it,
     * before sync_interest runs again), fd[i] never survives long enough
     * for this to actually suppress a re-arm in practice. Keep it anyway
     * -- it is what makes this function's contract correct on its own
     * terms, and is exactly what a future half-close would need -- but it
     * is not advertising that half-close is supported today; it isn't. */
    if (!rl->read_eof[i] && cloak_bytequeue_free_space(&rl->q[i]) > 0) {
        ev |= CLOAK_REACTOR_READABLE;
    }
    if (cloak_bytequeue_len(&rl->q[1 - i]) > 0) {
        ev |= CLOAK_REACTOR_WRITABLE;
    }
    return ev;
}

static void sync_interest(cloak_relay_t *rl) {
    for (int i = 0; i < 2; i++) {
        if (rl->fd[i] < 0) {
            continue;
        }
        uint32_t want = desired_interest(rl, i);
        if (want == 0 && rl->interest[i] == 0) {
            /* Both the mask we'd register and the mask already registered
             * are empty -- legitimate backpressure: q[i] is full and
             * q[1-i] is empty, so fd[i] needs neither read nor write
             * interest right now. Unlike the nonzero case below, there is
             * nothing here worth reprobing for: the only things a
             * zero-mask epoll_ctl(MOD) can surface are EPOLLERR/EPOLLHUP,
             * which the kernel reports regardless of the registered mask
             * -- and this code cannot act on either one while the queue
             * is full (pump_read returns before ever calling read(), so
             * the error is never actually discovered). Re-issuing the MOD
             * anyway would just make the kernel re-arm and re-deliver
             * that ERR/HUP on every following dispatch, forever, spinning
             * the reactor at 100% CPU on a connection whose peer has
             * simply gone away. See cloak_relay_t::interest's doc comment
             * in net.h for why this needs remembered state to detect. */
            continue;
        }
        /* Always re-issue MOD, even when the bitmask is unchanged from
         * before this dispatch: on an edge-triggered fd, EPOLL_CTL_MOD
         * makes the kernel re-probe the fd's current readiness and, if it
         * still holds, deliver a fresh edge on the next epoll_wait --
         * independent of whether the requested event mask actually
         * changed. That reprobe is exactly what a full-then-drained queue
         * needs: pump_read can stop early because OUR queue filled (not
         * because the socket was read down to EAGAIN), and if pump_write
         * drains that same queue again later in this very dispatch, the
         * bitmask computed here nets out identical to what it was before
         * the read -- even though bytes are still sitting unread in the
         * kernel socket buffer. Skipping the MOD call whenever the mask
         * happens to match would silently drop that reprobe and stall the
         * fd forever, since no *new* data is coming to generate a fresh
         * wakeup on its own. This unconditional re-issue is exactly what
         * the want==0/interest==0 case above opts out of -- a zero mask
         * has no readable/writable edge to reprobe for in the first
         * place, only ERR/HUP, which is the one case this reprobe must
         * NOT keep re-arming. */
        (void)cloak_reactor_mod_fd(rl->reactor, rl->fd[i], want);
        rl->interest[i] = want;
    }
}

/* Reads from fd[i] into q[i] until the queue is full or the socket is
 * drained. Returns 0 to continue, -1 if the relay should tear down. */
static int pump_read(cloak_relay_t *rl, int i) {
    uint8_t buf[RELAY_CHUNK];
    for (;;) {
        size_t room = cloak_bytequeue_free_space(&rl->q[i]);
        if (room == 0) {
            return 0; /* backpressure: stop reading until the peer drains */
        }
        size_t want = room < sizeof(buf) ? room : sizeof(buf);
        ssize_t n = read(rl->fd[i], buf, want);
        if (n > 0) {
            cloak_bytequeue_write(&rl->q[i], buf, (size_t)n);
            continue;
        }
        if (n == 0) {
            rl->read_eof[i] = 1;
            return -1; /* Go's Copy tears both directions down on EOF */
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
}

/* Writes q[1 - i] out through fd[i] until the queue empties or the socket
 * blocks. Returns 0 to continue, -1 if the relay should tear down. */
static int pump_write(cloak_relay_t *rl, int i) {
    uint8_t buf[RELAY_CHUNK];
    for (;;) {
        size_t have = cloak_bytequeue_peek(&rl->q[1 - i], buf, sizeof(buf));
        if (have == 0) {
            return 0;
        }
        ssize_t n = write(rl->fd[i], buf, have);
        if (n > 0) {
            cloak_bytequeue_read(&rl->q[1 - i], buf, (size_t)n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        return -1;
    }
}

static void relay_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    cloak_relay_t *rl = userdata;
    if (rl->done) {
        return;
    }

    int i = (fd == rl->fd[0]) ? 0 : 1;

    /* Always attempt the write side first: draining frees queue space,
     * which may let the read side below make progress in the same turn. */
    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        if (pump_write(rl, i) != 0) {
            relay_teardown(rl, 1);
            return;
        }
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        if (pump_read(rl, i) != 0) {
            /* One side ended. Before tearing down, make a best-effort pass
             * over everything still in flight: drain whatever the OTHER
             * side has already sent (it may have been readable in this very
             * turn and not dispatched yet), then flush both queues. Without
             * the read, a short reply that crossed paths with the EOF is
             * silently dropped. */
            (void)pump_read(rl, 1 - i);
            (void)pump_write(rl, 1 - i);
            (void)pump_write(rl, i);
            relay_teardown(rl, 1);
            return;
        }
        /* the bytes just read may be immediately writable on the peer */
        if (pump_write(rl, 1 - i) != 0) {
            relay_teardown(rl, 1);
            return;
        }
    }

    sync_interest(rl);
}

static void relay_close_fds(cloak_relay_t *rl) {
    for (int i = 0; i < 2; i++) {
        if (rl->fd[i] >= 0) {
            cloak_reactor_remove_fd(rl->reactor, rl->fd[i]);
            close(rl->fd[i]);
            rl->fd[i] = -1;
        }
    }
}

static void relay_teardown(cloak_relay_t *rl, int fire_done) {
    if (rl->done) {
        return;
    }
    rl->done = 1;
    relay_close_fds(rl);
    cloak_bytequeue_destroy(&rl->q[0]);
    cloak_bytequeue_destroy(&rl->q[1]);
    if (fire_done && rl->on_done != NULL) {
        rl->on_done(rl, rl->on_done_userdata);
    }
}

int cloak_relay_start(cloak_relay_t *rl, cloak_reactor_t *r, int fd_a, int fd_b,
                      const uint8_t *preload, size_t preload_len, size_t buf_cap,
                      cloak_relay_done_cb on_done, void *userdata) {
    if (rl == NULL) {
        return -1;
    }

    /* Every validation below this point can fail and return -1, and the
     * header promises cloak_relay_stop is then safe to call on rl -- so rl
     * must already be in the state relay_teardown expects (fd[] sentinels
     * set to -1, everything else zeroed) before any of those checks run,
     * not only once they've all passed. */
    memset(rl, 0, sizeof(*rl));
    rl->fd[0] = -1;
    rl->fd[1] = -1;

    if (r == NULL || fd_a < 0 || fd_b < 0 || buf_cap == 0) {
        return -1;
    }
    if (preload_len > buf_cap) {
        return -1;
    }
    if (preload_len > 0 && preload == NULL) {
        return -1;
    }

    rl->reactor = r;
    rl->on_done = on_done;
    rl->on_done_userdata = userdata;

    if (cloak_bytequeue_init(&rl->q[0], buf_cap) != 0) {
        return -1;
    }
    if (cloak_bytequeue_init(&rl->q[1], buf_cap) != 0) {
        cloak_bytequeue_destroy(&rl->q[0]);
        return -1;
    }
    if (preload_len > 0) {
        cloak_bytequeue_write(&rl->q[0], preload, preload_len);
    }

    /* Register both before touching either fd's state, so a failure on the
     * second leaves nothing half-registered. */
    if (cloak_reactor_add_fd(r, fd_a, CLOAK_REACTOR_READABLE, relay_on_event, rl) != 0) {
        cloak_bytequeue_destroy(&rl->q[0]);
        cloak_bytequeue_destroy(&rl->q[1]);
        return -1;
    }
    if (cloak_reactor_add_fd(r, fd_b, CLOAK_REACTOR_READABLE, relay_on_event, rl) != 0) {
        cloak_reactor_remove_fd(r, fd_a);
        cloak_bytequeue_destroy(&rl->q[0]);
        cloak_bytequeue_destroy(&rl->q[1]);
        return -1;
    }

    rl->fd[0] = fd_a;
    rl->fd[1] = fd_b;
    /* Matches the CLOAK_REACTOR_READABLE both cloak_reactor_add_fd calls
     * above actually registered, so sync_interest's want==0/interest==0
     * check compares against the real current registration from its very
     * first call -- not against the memset-to-0 default, which would be
     * wrong whenever the first computed want is also 0 (e.g. a preload
     * that exactly fills q[0], leaving fd_a nothing to read and nothing
     * queued to write). */
    rl->interest[0] = CLOAK_REACTOR_READABLE;
    rl->interest[1] = CLOAK_REACTOR_READABLE;

    /* A freshly registered socket may already be writable with the preload
     * waiting, and an edge for that may never arrive on its own -- so ask
     * for it explicitly. */
    sync_interest(rl);
    return 0;
}

void cloak_relay_stop(cloak_relay_t *rl) {
    if (rl == NULL) {
        return;
    }
    relay_teardown(rl, 0);
}
