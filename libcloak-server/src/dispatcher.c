#define _POSIX_C_SOURCE 200809L
#include "cloak/dispatcher.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- connection lifecycle helpers -------------------------------------- */

static void conn_unlink(cloak_dispatch_conn_t *c) {
    cloak_dispatcher_t *d = c->d;
    if (c->prev != NULL) {
        c->prev->next = c->next;
    } else {
        d->conns = c->next;
    }
    if (c->next != NULL) {
        c->next->prev = c->prev;
    }
    d->conn_count--;
}

/* Cancels whatever this connection still has live (its deadline, an
 * in-progress dial, an in-progress relay) and closes whatever fd(s) it
 * still owns. Used both by the ordinary per-connection teardown paths
 * (conn_drop) and by cloak_dispatcher_destroy, which calls this on every
 * entry in its list before freeing it. Does NOT unlink c from the list or
 * free it -- callers that need that do it themselves, since
 * cloak_dispatcher_destroy walks (and discards) the whole list at once
 * rather than unlinking one node at a time. */
static void conn_teardown(cloak_dispatch_conn_t *c) {
    cloak_reactor_t *r = c->d->cfg.reactor;

    if (c->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(r, c->deadline);
        c->deadline = CLOAK_TIMER_INVALID;
    }

    if (c->relaying) {
        /* The relay owns both fds by now; stopping it closes both and
         * fires no completion callback (this is a teardown, not the
         * relay finishing on its own). c->fd must not be touched again. */
        cloak_relay_stop(&c->relay);
        c->relaying = 0;
        c->fd = -1;
    } else {
        if (c->dialing) {
            /* Guarantees the dial callback will NOT fire; c->fd (the
             * client fd, deregistered from the reactor before the dial
             * started -- see conn_start_redirect) is still ours and is
             * closed below. */
            cloak_dial_cancel(&c->dial);
            c->dialing = 0;
        }
        if (c->fd >= 0) {
            /* A no-op (returns -1) if fd is not currently registered,
             * e.g. because we are mid-dial and already removed it --
             * safe either way, see cloak_reactor_remove_fd's own doc
             * comment. */
            cloak_reactor_remove_fd(r, c->fd);
            close(c->fd);
            c->fd = -1;
        }
    }
}

/* Tears c down, unlinks it, and frees it. The one function every
 * "something ended, and it is not a successful hand-off" path funnels
 * through. */
static void conn_drop(cloak_dispatch_conn_t *c) {
    conn_teardown(c);
    conn_unlink(c);
    free(c);
}

/* ---- authentication stub ------------------------------------------------
 *
 * Always fails. Task 2 replaces this with real ClientHello parsing,
 * decryption, replay checking and session lookup
 * (cloak_clienthello_parse + cloak_server_check_replay +
 * cloak_server_auth_decrypt + cloak_server_registry_get_or_create); a
 * successful authentication there hands the connection to
 * cloak_session_add_conn instead of falling through to redirect. Until
 * then, every connection that completes its first packet -- Cloak or
 * not -- is treated as unauthenticated, which is exactly Go's behaviour
 * for any connection this server cannot yet recognise. */
static int dispatcher_authenticate(cloak_dispatch_conn_t *c) {
    (void)c;
    return -1;
}

/* ---- redirect path ------------------------------------------------------ */

static void on_relay_done(cloak_relay_t *rl, void *userdata) {
    (void)rl;
    cloak_dispatch_conn_t *c = userdata;
    /* The relay already closed both fds; it does not touch c->fd, which
     * this connection stopped owning the moment it handed both
     * descriptors to cloak_relay_start (see on_dial_done). */
    c->relaying = 0;
    conn_unlink(c);
    free(c);
}

static void on_dial_done(cloak_dial_t *dial, int fd, void *userdata) {
    (void)dial;
    cloak_dispatch_conn_t *c = userdata;
    c->dialing = 0;

    if (fd < 0) {
        /* Nothing to forward to: close, matching the property this whole
         * module protects everywhere else it can (redirect) except here,
         * where redirecting is exactly what just failed. */
        conn_drop(c);
        return;
    }

    int client_fd = c->fd;
    /* Ownership of the client fd passes to the relay now, unconditionally
     * -- set the sentinel before the call that might fail, so that if it
     * does fail, the explicit close() below is the only thing that will
     * ever touch this fd again. */
    c->fd = -1;

    if (cloak_relay_start(&c->relay, c->d->cfg.reactor, client_fd, fd,
                          cloak_firstpacket_data(&c->fp), cloak_firstpacket_len(&c->fp),
                          c->d->cfg.relay_buf_cap, on_relay_done, c) != 0) {
        /* cloak_relay_start's own contract: on failure neither descriptor
         * is closed and neither is left registered with the reactor --
         * we still own both and must close them ourselves rather than
         * leave the client hanging. */
        close(client_fd);
        close(fd);
        conn_unlink(c);
        free(c);
        return;
    }
    c->relaying = 1;
}

static void conn_start_redirect(cloak_dispatch_conn_t *c) {
    cloak_dispatcher_t *d = c->d;

    /* Cancel the deadline first: from this point on the connection is no
     * longer "reading its first packet", regardless of what happens
     * next, and nothing past here should be raced by that timer firing. */
    if (c->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->cfg.reactor, c->deadline);
        c->deadline = CLOAK_TIMER_INVALID;
    }

    cloak_addr_t addr;
    if (cloak_server_redir_addr(d->cfg.srv, c->local_port, &addr) != 0) {
        /* Only reachable if srv or addr were NULL, neither of which is
         * possible here (cloak_dispatcher_init requires a non-NULL srv,
         * and addr is a local). Handled anyway: there is nowhere to
         * forward to, so close rather than hang. */
        conn_drop(c);
        return;
    }

    /* Deregister the client fd; the relay (on dial success) re-registers
     * it itself. Bytes already sitting in the kernel's receive buffer for
     * it are not lost -- EPOLL_CTL_ADD on an already-ready fd still
     * enqueues a fresh event even under edge-triggered mode. */
    cloak_reactor_remove_fd(d->cfg.reactor, c->fd);

    if (cloak_dial_start(&c->dial, d->cfg.reactor, &addr, d->cfg.redirect_dial_timeout_ms,
                         on_dial_done, c, NULL, 0) != 0) {
        /* Could not even start the dial: nothing to forward to. */
        conn_drop(c);
        return;
    }
    c->dialing = 1;
}

/* ---- reading the first packet -------------------------------------------- */

static void conn_on_firstpacket_error(cloak_dispatch_conn_t *c) {
    /* cloak/firstpacket.h's own contract: every error it can report is a
     * redirectable one. cloak_firstpacket_redirect_on_error would agree
     * for every case this parser actually produces, but the contract
     * itself -- not a per-case check of it -- is what this branch relies
     * on, matching the task's own instruction to send every ERROR
     * straight to redirect. */
    conn_start_redirect(c);
}

static void conn_on_firstpacket_done(cloak_dispatch_conn_t *c) {
    if (dispatcher_authenticate(c) != 0) {
        conn_start_redirect(c);
        return;
    }
    /* Task 2: a successful authentication hands c->fd to
     * cloak_session_add_conn here instead. */
}

static void conn_drop_peer_gone(cloak_dispatch_conn_t *c) {
    /* read() returned 0 or a real error: the peer is already gone, so
     * there is nobody to redirect to -- this is the one first-packet
     * outcome that is not itself a CLOAK_FIRSTPACKET_ERROR and still does
     * not redirect. */
    conn_drop(c);
}

static void on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    cloak_dispatch_conn_t *c = userdata;

    /* Edge-triggered: this loop must keep reading until want() reaches 0
     * or read() returns EAGAIN, or data that arrived within this same
     * edge is never reported again. */
    for (;;) {
        size_t want = cloak_firstpacket_want(&c->fp);
        if (want == 0) {
            /* Should not happen while still registered readable -- every
             * path that reaches DONE/ERROR returns immediately below --
             * but stop rather than loop forever if it ever does. */
            return;
        }

        uint8_t buf[CLOAK_FIRSTPACKET_MAX];
        ssize_t n = read(fd, buf, want);
        if (n > 0) {
            cloak_firstpacket_status_t st = cloak_firstpacket_feed(&c->fp, buf, (size_t)n);
            if (st == CLOAK_FIRSTPACKET_DONE) {
                conn_on_firstpacket_done(c);
                return;
            }
            if (st == CLOAK_FIRSTPACKET_ERROR) {
                conn_on_firstpacket_error(c);
                return;
            }
            continue; /* NEED_MORE: want() may have changed, loop again */
        }
        if (n == 0) {
            conn_drop_peer_gone(c);
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return; /* wait for the next readiness edge */
        }
        /* Any other read() error: the peer is effectively gone too. */
        conn_drop_peer_gone(c);
        return;
    }
}

static void on_deadline(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_dispatch_conn_t *c = userdata;
    /* The timer already fired (this callback is that firing); mark it
     * consumed before conn_drop's own cancel-timer call, which would
     * otherwise be cancelling a timer that no longer exists. */
    c->deadline = CLOAK_TIMER_INVALID;
    conn_drop(c);
}

/* ---- public API ---------------------------------------------------------- */

int cloak_dispatcher_init(cloak_dispatcher_t *d, const cloak_dispatcher_config_t *cfg) {
    if (d == NULL) {
        return -1;
    }
    /* Initialize before validating anything else, so that ANY failure
     * return below still leaves d in a state cloak_dispatcher_destroy can
     * safely be called against -- four earlier constructors on this
     * project got this ordering backwards and it was a crash every time. */
    memset(d, 0, sizeof(*d));

    if (cfg == NULL || cfg->reactor == NULL || cfg->srv == NULL) {
        return -1;
    }
    /* A non-zero relay_buf_cap smaller than CLOAK_FIRSTPACKET_MAX would
     * make cloak_relay_start fail (preload_len > buf_cap) on every single
     * redirect -- silently turning "every failure redirects" into "every
     * connection closes" from nothing worse than a config typo. Reject it
     * here, loudly, rather than let it surface later as connections that
     * merely fail to redirect. */
    if (cfg->relay_buf_cap != 0 && cfg->relay_buf_cap < CLOAK_FIRSTPACKET_MAX) {
        return -1;
    }

    d->cfg = *cfg;
    if (d->cfg.handshake_timeout_ms == 0) {
        d->cfg.handshake_timeout_ms = CLOAK_DISPATCHER_DEFAULT_HANDSHAKE_TIMEOUT_MS;
    }
    if (d->cfg.redirect_dial_timeout_ms == 0) {
        d->cfg.redirect_dial_timeout_ms = CLOAK_DISPATCHER_DEFAULT_REDIRECT_DIAL_TIMEOUT_MS;
    }
    if (d->cfg.relay_buf_cap == 0) {
        d->cfg.relay_buf_cap = CLOAK_DISPATCHER_DEFAULT_RELAY_BUF_CAP;
    }

    d->conns = NULL;
    d->conn_count = 0;
    return 0;
}

void cloak_dispatcher_destroy(cloak_dispatcher_t *d) {
    if (d == NULL) {
        return;
    }
    cloak_dispatch_conn_t *c = d->conns;
    while (c != NULL) {
        cloak_dispatch_conn_t *next = c->next;
        conn_teardown(c);
        free(c);
        c = next;
    }
    d->conns = NULL;
    d->conn_count = 0;
}

void cloak_dispatcher_accept(cloak_listener_t *l, int fd, void *userdata) {
    cloak_dispatcher_t *d = userdata;
    if (d == NULL) {
        close(fd);
        return;
    }

    cloak_dispatch_conn_t *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        close(fd);
        return;
    }

    c->d = d;
    c->fd = fd;
    /* Exactly the local_port cloak_server_redir_addr wants, straight from
     * the listener this connection arrived on -- no getsockname needed
     * (see docs/superpowers/plans/2026-09-13-libcloak-server-state-plan.md,
     * "What a paper walk of that loop already established"). */
    c->local_port = (uint16_t)cloak_listener_port(l);
    cloak_firstpacket_init(&c->fp);
    c->deadline = CLOAK_TIMER_INVALID;
    c->dialing = 0;
    c->relaying = 0;
    c->prev = NULL;
    c->next = NULL;

    /* Link in before arming anything, so any failure path below can use
     * conn_drop (which unlinks) uniformly rather than needing a separate
     * "not linked yet" teardown. */
    c->next = d->conns;
    if (d->conns != NULL) {
        d->conns->prev = c;
    }
    d->conns = c;
    d->conn_count++;

    c->deadline =
        cloak_reactor_add_timer(d->cfg.reactor, d->cfg.handshake_timeout_ms, on_deadline, c);
    if (c->deadline == CLOAK_TIMER_INVALID) {
        /* Cannot honor the handshake deadline (allocation failure growing
         * the reactor's timer heap) -- refusing to read from this fd
         * without any deadline at all would risk pinning it forever, the
         * exact failure mode the deadline exists to prevent, so drop the
         * connection instead. */
        conn_drop(c);
        return;
    }

    if (cloak_reactor_add_fd(d->cfg.reactor, fd, CLOAK_REACTOR_READABLE, on_readable, c) != 0) {
        conn_drop(c);
        return;
    }
}

size_t cloak_dispatcher_conn_count(const cloak_dispatcher_t *d) {
    return d == NULL ? 0 : d->conn_count;
}
