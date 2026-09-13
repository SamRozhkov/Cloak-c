#define _POSIX_C_SOURCE 200809L
#include "cloak/dispatcher.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cloak/clienthello_parse.h"
#include "cloak/common.h"
#include "cloak/crypto.h"

/* Forward-declared: armed both at accept (the first-packet read deadline)
 * and again in conn_on_firstpacket_done (the reply-write/hand-off
 * deadline), but its own natural home -- alongside on_readable, the other
 * reactor callback registered against a connection's fd -- is well after
 * both of those call sites. See its own doc comment, below. */
static void on_deadline(cloak_reactor_t *r, void *userdata);

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

    /* If dispatcher_authenticate got as far as creating a brand-new
     * session for this connection (auth_created) but the connection
     * itself never completed hand-off to it -- a step-10 write failure,
     * a step-11 cloak_session_add_conn failure, or the whole dispatcher
     * tearing down while this connection was mid-reply-write -- that
     * session would otherwise sit in the registry forever with zero
     * connections and nobody left who could ever add one. Every one of
     * those paths funnels through conn_drop (hence here) rather than
     * through conn_handoff's success branch, which never calls this
     * function at all (see on_relay_done's sibling pattern) -- so this
     * check never fires for a connection that actually made it onto its
     * session. auth_created is 0 for an additional connection to an
     * ALREADY-existing session, so this never tears one of those down
     * over one bad late-stage failure -- exactly the discrimination
     * cloak/registry.h's own "created == 1" guidance on
     * cloak_server_registry_close requires. Guarded so this runs at most
     * once even if conn_teardown is ever called twice on the same c. */
    if (c->auth_created) {
        cloak_server_registry_close(c->d->cfg.registry, c->auth_uid, c->auth_session_id);
        c->auth_created = 0;
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
        /* Covers the writing_reply case too: a connection mid-reply-write
         * has no dial or relay live, just an fd registered
         * CLOAK_REACTOR_WRITABLE, which this removes and closes exactly
         * like any other still-owned fd. */
        c->writing_reply = 0;
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

/* ---- authentication ------------------------------------------------------
 *
 * The maximum length cloak_server_auth_cert_lens can ever contain (see
 * cloak/server_auth.h's own CLOAK_SERVER_AUTH_REPLY_MAX_BYTES comment,
 * which derives the same number: 68). A stack buffer this size can hold
 * any cert length that constant offers, chosen uniformly per connection
 * below. */
#define DISPATCHER_MAX_FAKE_CERT_LEN 68

/* Steps 1-9 of the task-2 brief's authenticated path, in order, with the
 * reason each is where it is:
 *
 *  1. Only CLOAK_FIRSTPACKET_TRANSPORT_TLS proceeds --
 *     CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET has no consumer until the CDN
 *     module exists (cloak/firstpacket.h says so).
 *  2. cloak_clienthello_parse over the already-framed record.
 *  3. cloak_server_check_replay against the RAW, not-yet-authenticated
 *     ch.random -- BEFORE any decryption, so a replayed handshake is
 *     rejected without the server doing any asymmetric work (both
 *     cloak/server.h and cloak/server_auth.h state this ordering; Go does
 *     the same).
 *  4. cloak_server_auth_decrypt. Everything in info is attacker-chosen
 *     until step 6 authorises info.uid.
 *  5. cloak_aead_method_is_valid on info.encryption_method BEFORE it is
 *     used for anything -- cloak/crypto.h requires this of any
 *     wire-sourced method byte; skipping it is how a wire byte becomes an
 *     out-of-range array index later (cloak_aead_overhead,
 *     cloak_session_config_t's obfuscator).
 *  6. cloak_server_is_bypass is the whole authorisation policy until a
 *     user manager exists. No logging on failure -- a prober learns
 *     nothing from a silent redirect.
 *  7. cloak_server_lookup_proxy(info.proxy_method) must resolve; this
 *     task only checks existence; the address itself is a later task's
 *     concern.
 *  8. cloak_server_registry_find FIRST. If found, this is an additional
 *     connection to a session that already exists: THE LIVE-KEY RULE --
 *     compose the reply with sesh->obfuscator.session_key, never a fresh
 *     one (cloak/registry.h's own get_or_create doc comment explains why
 *     composing with fresh material here silently breaks every frame on
 *     this connection with no error at the handshake). If not found,
 *     generate a fresh key, build the session config from
 *     cfg.session_config_template plus the decrypted encryption method,
 *     run the owner's prepare_session callback (if any), and
 *     cloak_server_registry_get_or_create.
 *  9. cloak_server_auth_compose_reply with a fresh nonce, a fresh pad4,
 *     and a cert length chosen uniformly from cloak_server_auth_cert_lens
 *     (a DPI-plausibility measure -- a fixed length would itself be a
 *     fingerprint).
 *
 * On success, fills c->reply/reply_len and c->auth_* (consumed by
 * conn_continue_reply_write and conn_handoff, steps 10-11) and returns 0.
 * On any failure this function returns -1 having left the connection
 * exactly as it found it (redirectable) EXCEPT for one thing: if step 8
 * created a brand-new session and a LATER step in this same function
 * (only step 9 can fail after that point) then fails, that session is
 * torn down here, via cloak_server_registry_close, before returning --
 * matching cloak/registry.h's "created == 1 is the only correct
 * discriminator" guidance. A failure at or before step 8's create never
 * has a session to unwind. */
static int dispatcher_authenticate(cloak_dispatch_conn_t *c) {
    cloak_dispatcher_t *d = c->d;
    cloak_server_t *srv = d->cfg.srv;

    /* 1. Transport. */
    if (c->fp.transport != CLOAK_FIRSTPACKET_TRANSPORT_TLS) {
        return -1;
    }

    /* 2. Parse. */
    cloak_clienthello_parsed_t ch;
    if (cloak_clienthello_parse(cloak_firstpacket_data(&c->fp), cloak_firstpacket_len(&c->fp),
                                &ch) != 0) {
        return -1;
    }

    int64_t now = (int64_t)time(NULL);

    /* 3. Replay, against the raw random, before decrypting. */
    if (cloak_server_check_replay(srv, ch.random, now)) {
        return -1;
    }

    /* 4. Decrypt. */
    cloak_server_clientinfo_t info;
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    if (cloak_server_auth_decrypt(ch.random, ch.session_id, ch.session_id_len,
                                  ch.x25519_key_share, srv->cfg->private_key, now, &info,
                                  shared_secret) != 0) {
        return -1;
    }

    /* 5. Validate the wire-sourced method byte before it is used for
     * anything at all. */
    if (!cloak_aead_method_is_valid((cloak_aead_method_t)info.encryption_method)) {
        return -1;
    }

    /* 6. Authorise the UID. */
    if (!cloak_server_is_bypass(srv, info.uid)) {
        return -1;
    }

    /* 7. Proxy method must be known; the resolved address itself is a
     * later task's concern. */
    if (cloak_server_lookup_proxy(srv, info.proxy_method) == NULL) {
        return -1;
    }

    /* 8. Find, then (only if not found) create. */
    int created = 0;
    uint8_t session_key[CLOAK_AEAD_KEY_LEN];
    cloak_session_t *sesh = cloak_server_registry_find(d->cfg.registry, info.uid, info.session_id);
    if (sesh != NULL) {
        /* THE LIVE-KEY RULE: an existing session's config (obfuscator
         * included) was fixed at whatever creation first used -- read
         * ITS key back out rather than generating a fresh one. See
         * cloak/registry.h's own get_or_create doc comment. */
        memcpy(session_key, sesh->obfuscator.session_key, CLOAK_AEAD_KEY_LEN);
    } else {
        cloak_random_bytes(session_key, sizeof(session_key));

        cloak_session_config_t session_cfg = d->cfg.session_config_template;
        session_cfg.obfuscator.method = (cloak_aead_method_t)info.encryption_method;
        memcpy(session_cfg.obfuscator.session_key, session_key, CLOAK_AEAD_KEY_LEN);

        if (d->cfg.prepare_session != NULL &&
            d->cfg.prepare_session(d, &info, &session_cfg, d->cfg.prepare_session_userdata) != 0) {
            /* Nothing was created yet -- nothing to unwind. */
            return -1;
        }

        sesh = cloak_server_registry_get_or_create(d->cfg.registry, info.uid, info.session_id,
                                                    &session_cfg, &created);
        if (sesh == NULL) {
            /* Resource limit or cloak_session_init/allocation failure --
             * cloak/registry.h documents *out_created as untouched here,
             * and indeed nothing was created either way. */
            return -1;
        }
    }

    /* 9. Compose the reply: fresh nonce, fresh pad4, a uniformly chosen
     * cert length. */
    uint8_t reply_nonce[CLOAK_AEAD_NONCE_LEN];
    uint8_t pad4[4];
    cloak_random_bytes(reply_nonce, sizeof(reply_nonce));
    cloak_random_bytes(pad4, sizeof(pad4));

    uint8_t cert_pick;
    cloak_random_bytes(&cert_pick, 1);
    size_t cert_len = cloak_server_auth_cert_lens[cert_pick % CLOAK_SERVER_AUTH_CERT_LEN_COUNT];
    uint8_t fake_cert[DISPATCHER_MAX_FAKE_CERT_LEN];
    cloak_random_bytes(fake_cert, cert_len);

    long n = cloak_server_auth_compose_reply(shared_secret, session_key, reply_nonce, ch.session_id,
                                             pad4, fake_cert, cert_len, c->reply, sizeof(c->reply));
    if (n <= 0) {
        /* Unwind: this is the one failure in this function that can
         * happen AFTER step 8 created a session. created == 1 is the
         * only correct discriminator -- see this function's own
         * top-of-task comment and cloak/registry.h. */
        if (created) {
            cloak_server_registry_close(d->cfg.registry, info.uid, info.session_id);
        }
        return -1;
    }

    c->reply_len = (size_t)n;
    c->reply_sent = 0;
    c->auth_sesh = sesh;
    c->auth_created = created;
    c->auth_info = info;
    memcpy(c->auth_uid, info.uid, CLOAK_UID_LEN);
    c->auth_session_id = info.session_id;
    return 0;
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

/* ---- post-authentication: reply write and hand-off ---------------------- */

/* Step 11. Only ever called once c->reply has been written in full.
 * c->fd is still ours; this is the one place that either hands it, still
 * open, to cloak_session_add_conn, or closes it itself. */
static void conn_handoff(cloak_dispatch_conn_t *c) {
    cloak_dispatcher_t *d = c->d;
    int fd = c->fd;
    cloak_session_t *sesh = c->auth_sesh;
    int created = c->auth_created;
    cloak_server_clientinfo_t info = c->auth_info;

    /* c->fd was registered CLOAK_REACTOR_WRITABLE (or never re-registered
     * at all, if step 10's write completed synchronously on the first
     * attempt) for the reply write; either way it must come off the
     * reactor before cloak_session_add_conn wraps it in a cloak_conn_t of
     * its own, exactly like the redirect path's own dial hand-off. */
    cloak_reactor_remove_fd(d->cfg.reactor, fd);

    if (cloak_session_add_conn(sesh, fd) != 0) {
        /* The dispatcher still owns fd on failure (cloak_session_add_conn's
         * own contract). The client has already received a ServerHello by
         * this point -- the reply this connection just finished writing
         * -- so the cover story is blown regardless of what happens now;
         * close rather than redirect, the same reasoning
         * conn_reply_write_failed documents for a step-10 write error.
         * conn_drop's call into conn_teardown is what unwinds a
         * brand-new session here, if this connection was the one that
         * created it (auth_created is still set on c at this point). */
        close(fd);
        c->fd = -1;
        conn_drop(c);
        return;
    }

    c->fd = -1;
    /* The one exit from the reply-write/hand-off state that does NOT go
     * through conn_teardown (see on_relay_done's sibling pattern) --
     * conn_teardown is what cancels the deadline armed for this state on
     * every other exit, so this success path must do it explicitly
     * itself, exactly once, here. */
    if (c->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->cfg.reactor, c->deadline);
        c->deadline = CLOAK_TIMER_INVALID;
    }
    if (d->cfg.attached != NULL) {
        d->cfg.attached(d, sesh, &info, created, d->cfg.attached_userdata);
    }
    conn_unlink(c);
    free(c);
}

/* Step 10's failure path. A write error here is the ONE place in this
 * whole module that closes instead of redirecting: by the time this can
 * fire, the client has already received a ServerHello (composed in
 * dispatcher_authenticate, step 9), so the cover story is already blown
 * -- forwarding to the cover site now would be visibly incoherent (a real
 * web server never follows a ServerHello with a second, unrelated
 * handshake attempt). Do NOT "fix" this into a redirect. conn_drop's call
 * into conn_teardown is what unwinds a brand-new session here, if this
 * connection was the one that created it. */
static void conn_reply_write_failed(cloak_dispatch_conn_t *c) {
    conn_drop(c);
}

/* Step 10. Writes c->reply[c->reply_sent, c->reply_len) to c->fd,
 * non-blocking: what the socket takes is taken, and on a short write or
 * EAGAIN this registers c->fd for writable and returns, to be called
 * again from on_readable (see its own comment) once the reactor says the
 * fd is writable. Only once the last byte is out does the connection
 * proceed to hand-off (step 11) -- this is the one non-blocking
 * write-then-handover primitive the project did not already have. */
static void conn_continue_reply_write(cloak_dispatch_conn_t *c) {
    while (c->reply_sent < c->reply_len) {
        size_t remaining = c->reply_len - c->reply_sent;
        ssize_t n = write(c->fd, c->reply + c->reply_sent, remaining);
        if (n > 0) {
            c->reply_sent += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!c->writing_reply) {
                c->writing_reply = 1;
                /* Switches this fd's registration from whatever it was
                 * (READABLE, during first-packet reading) to WRITABLE;
                 * on_readable (registered once, at accept) is what
                 * dispatches the resulting event back into this
                 * function -- see its own comment for why the same
                 * callback handles both phases. */
                if (cloak_reactor_mod_fd(c->d->cfg.reactor, c->fd, CLOAK_REACTOR_WRITABLE) != 0) {
                    /* An unlikely failure (this fd is definitely still
                     * registered, from either cloak_dispatcher_accept's
                     * original add_fd or an earlier mod_fd call), but
                     * leaving writing_reply == 1 against a mask that
                     * never actually changed to WRITABLE would silently
                     * stall this connection with no further event ever
                     * arriving for it. Handled the same way every other
                     * failure in this state is: close, not redirect --
                     * see conn_reply_write_failed's own comment. */
                    conn_reply_write_failed(c);
                }
            }
            return;
        }
        /* A real write error: the peer is gone or the socket is broken. */
        conn_reply_write_failed(c);
        return;
    }

    /* Fully drained. */
    c->writing_reply = 0;
    conn_handoff(c);
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
    /* Past this point the connection is no longer "reading its first
     * packet" regardless of what happens next -- authentication success,
     * authentication failure (redirect), or a step-10 write failure
     * (close) -- so the deadline is cancelled here, once, on every path
     * out of this state. conn_start_redirect's own cancellation below is
     * then a documented no-op (CLOAK_TIMER_INVALID guard). */
    if (c->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(c->d->cfg.reactor, c->deadline);
        c->deadline = CLOAK_TIMER_INVALID;
    }

    if (dispatcher_authenticate(c) != 0) {
        conn_start_redirect(c);
        return;
    }

    /* Entering the reply-write/hand-off state: arm a deadline covering
     * it. This module's own stated philosophy (see the redirect-dial
     * timeout's comment, and the first-packet deadline this one just
     * replaces) is that no state here is unbounded -- a step-10 write
     * that never drains because the client never reads is exactly the
     * same failure shape as a first-packet read that never completes,
     * and deserves the same treatment rather than being allowed to pin
     * this connection's heap state (including, potentially, a
     * freshly-created session sitting in the registry) forever.
     * handshake_timeout_ms is reused rather than given its own knob:
     * this phase is a single bounded write of at most
     * CLOAK_SERVER_AUTH_REPLY_MAX_BYTES followed by one
     * cloak_session_add_conn call, no less bounded than the first-packet
     * read it follows, so the same timeout is an equally reasonable
     * bound and it is not worth a second configuration surface for it.
     * Cancelled on every exit from this state: conn_handoff's success
     * path cancels it explicitly (see its own comment, since success is
     * the one exit that does not go through conn_teardown), and every
     * other exit (redirect is not reachable from here; a step-10 write
     * failure or a step-11 hand-off failure both route through
     * conn_drop) cancels it via conn_teardown's own unconditional check
     * at its top. */
    c->deadline =
        cloak_reactor_add_timer(c->d->cfg.reactor, c->d->cfg.handshake_timeout_ms, on_deadline, c);
    if (c->deadline == CLOAK_TIMER_INVALID) {
        /* Cannot honor a deadline for this state either -- the same
         * allocation failure growing the reactor's timer heap that
         * cloak_dispatcher_accept's own arm-failure handling documents,
         * with the same conclusion: refusing to enter an unbounded state
         * is not an option, so this connection is dropped rather than
         * left to write its reply with nothing to bound it. Routed
         * through conn_reply_write_failed (close, not redirect) rather
         * than conn_start_redirect for the same reason every other
         * failure in this state is: matches this function's own
         * top-of-state comment above. */
        conn_reply_write_failed(c);
        return;
    }

    conn_continue_reply_write(c);
}

static void conn_drop_peer_gone(cloak_dispatch_conn_t *c) {
    /* read() returned 0 or a real error: the peer is already gone, so
     * there is nobody to redirect to -- this is the one first-packet
     * outcome that is not itself a CLOAK_FIRSTPACKET_ERROR and still does
     * not redirect. */
    conn_drop(c);
}

/* The single callback registered (once, at accept) for a connection's own
 * fd, for the whole time this module owns that fd. It serves two,
 * mutually exclusive, phases of that fd's life: reading the first packet
 * (registered CLOAK_REACTOR_READABLE) and, after a successful
 * authentication, draining the non-blocking reply write (registered
 * CLOAK_REACTOR_WRITABLE via cloak_reactor_mod_fd in
 * conn_continue_reply_write) -- cloak_reactor_mod_fd changes the event
 * mask of an existing registration, not its callback, so this same
 * function is what the reactor calls for both; c->writing_reply is what
 * tells it which phase it is in. */
static void on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    cloak_dispatch_conn_t *c = userdata;

    if (c->writing_reply) {
        conn_continue_reply_write(c);
        return;
    }

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

/* Fires for BOTH deadlines this module ever arms against c->deadline: the
 * first-packet read deadline (armed in cloak_dispatcher_accept) and the
 * reply-write/hand-off deadline (armed in conn_on_firstpacket_done) --
 * never both at once, since the second is armed only after the first has
 * already been cancelled. Either way, conn_drop is the right response: a
 * client that never finishes sending its first packet and a client that
 * never drains this connection's write buffer fail the same way, by
 * pinning this connection's state forever, and both are handled by
 * simply dropping the connection. */
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
    if (d->cfg.max_pending_conns == 0) {
        d->cfg.max_pending_conns = CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS;
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

    /* THE CAP, checked before any allocation happens for this fd -- see
     * CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS's and this function's own
     * doc comments in cloak/dispatcher.h for the full reasoning. Short
     * version: this is a C server allocating ~3KB of heap per
     * unauthenticated connection, Go has no equivalent cap because it has
     * no equivalent allocation, and CLOSING (not redirecting) is the
     * correct response at the cap -- redirecting would spend a second fd
     * and, on a successful dial, a live relay's buffers, which is exactly
     * backwards when the reason we are here is that resources are already
     * exhausted. Every other close-instead-of-redirect path in this
     * module fires because there is nowhere to redirect TO; this is the
     * only one that closes despite somewhere to redirect existing, so a
     * future reader should not "fix" this into a redirect. */
    if (d->conn_count >= d->cfg.max_pending_conns) {
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
