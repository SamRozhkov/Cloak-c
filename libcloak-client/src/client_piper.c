#define _POSIX_C_SOURCE 200809L
#include "cloak/client_piper.h"

#include "cloak/frame.h"
#include "cloak/log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- intrusive list bookkeeping ----------------------------------------- */

static void piper_conn_link(cloak_client_piper_t *pp, cloak_client_piper_conn_t *ctx) {
    ctx->prev = NULL;
    ctx->next = pp->conns;
    if (pp->conns != NULL) {
        pp->conns->prev = ctx;
    }
    pp->conns = ctx;
    pp->conn_count++;
}

static void piper_conn_unlink(cloak_client_piper_t *pp, cloak_client_piper_conn_t *ctx) {
    if (ctx->prev != NULL) {
        ctx->prev->next = ctx->next;
    } else {
        pp->conns = ctx->next;
    }
    if (ctx->next != NULL) {
        ctx->next->prev = ctx->prev;
    }
    ctx->prev = NULL;
    ctx->next = NULL;
    pp->conn_count--;
}

/* ---- teardown ------------------------------------------------------------
 *
 * THE ONE COPY. Three paths have to perform exactly this walk -- a
 * relay's ordinary completion, cloak_client_piper_destroy (the owner's
 * shutdown) and piper_on_broken (the session died under us) -- and they
 * differ only in what they do afterwards. cloak_proxy_t has one walk for
 * the same reason and it is the right reason: two copies of the most
 * lifetime-sensitive code in a module drifting apart is the worst outcome
 * available. */

/* Releases every resource one context holds, releases its stream back to
 * its session, unlinks the context and FREES IT -- and, in singleplex,
 * closes the session that existed only for this context. ctx must not be
 * touched after this returns. */
static void piper_conn_teardown(cloak_client_piper_conn_t *ctx) {
    cloak_client_piper_t *pp = ctx->pp;

    if (ctx->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(pp->cfg.reactor, ctx->deadline);
        ctx->deadline = CLOAK_TIMER_INVALID;
    }
    if (ctx->retry_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(pp->cfg.reactor, ctx->retry_timer);
        ctx->retry_timer = CLOAK_TIMER_INVALID;
    }
    if (ctx->awaiting_session) {
        /* SINGLEPLEX: A BRING-UP IS STILL IN FLIGHT FOR A CONTEXT THAT IS
         * ABOUT TO BE FREED, and this is the only thing standing between
         * that and a use-after-free of the worst kind -- the owner
         * completing seconds later, through
         * cloak_client_piper_conn_session_ready, against a pointer this
         * line is about to free. It is reachable by three entirely
         * ordinary routes: the deadline expiring, the local peer closing,
         * and cloak_client_piper_destroy.
         *
         * Cleared BEFORE the callback so that an owner which (against the
         * contract) answered from inside it would find nothing to answer
         * rather than re-entering this walk. */
        ctx->awaiting_session = 0;
        if (pp->cfg.cancel_session != NULL) {
            pp->cfg.cancel_session(ctx, pp->cfg.session_userdata);
        }
    }
    if (ctx->relaying) {
        /* THE ORDER OF THESE TWO STEPS -- stop the relay HERE, release
         * the stream BELOW -- is the whole of this module's teardown
         * correctness, and it is stated at this site and not only in the
         * header because this is where it is easy to get backwards.
         *
         * cloak_stream_relay_stop closes the stream (so the peer actually
         * learns the stream ended) and the relay's own fd; it
         * deliberately does NOT fire on_done and deliberately does NOT
         * release the stream -- cloak/stream_relay.h is explicit that
         * releasing is ours. Releasing FIRST would free the
         * cloak_stream_t while the relay still holds it as a raw pointer
         * it cannot validate, and the stop below would then write a close
         * through freed memory. */
        ctx->relaying = 0;
        cloak_stream_relay_stop(&ctx->relay);
    }
    if (ctx->fd_registered) {
        /* Only ever set while WE hold the descriptor: the relay owns its
         * own registration and ctx->fd is -1 for the whole of that. */
        cloak_reactor_remove_fd(pp->cfg.reactor, ctx->fd);
        ctx->fd_registered = 0;
    }
    if (ctx->fd >= 0) {
        /* D6's window, or the retry window: no relay has taken this
         * descriptor, so nothing else is going to close it. */
        close(ctx->fd);
        ctx->fd = -1;
    }
    if (ctx->stream != NULL) {
        if (ctx->sesh != NULL) {
            /* cloak_session_release_stream performs the active close
             * itself when the stream has not already been closed (by the
             * relay's own teardown, or by the peer), so there is no
             * separate cloak_session_close_stream call to make here.
             *
             * THE GUARD IS CURRENTLY UNREACHABLE, AND THAT IS STATED
             * RATHER THAN DRESSED UP. An earlier version of this comment
             * claimed ctx->sesh is NULL once piper_on_broken has run and
             * that singleplex exercises this branch. BOTH ARE FALSE: the
             * broken walk tears a matching context down instead of
             * NULLing it, never touches a surviving context's session,
             * and the only assignment of NULL is two statements below
             * this one -- so a context that has a stream always has the
             * session it opened it on. Replacing the condition with
             * `if (1)` leaves both suites green, and
             * cloak_session_release_stream does not null-check its
             * session argument, so the branch genuinely never runs with
             * NULL.
             *
             * IT IS KEPT ANYWAY, on the same ground the session guards in
             * the two notify loops are kept: what makes it dead is an
             * ORDERING -- "nothing forgets a live context's session" --
             * and the plausible near-term change is a broken walk that
             * cleared surviving contexts' sesh instead of leaving it, or
             * a detach that did. Under either, this line is the
             * difference between a leak and a fault in a function that
             * cannot defend itself. It is one branch; the ordering it
             * backstops is the module's most fragile property. */
            cloak_session_release_stream(ctx->sesh, ctx->stream);
        }
        ctx->stream = NULL;
        /* THE ONLY PLACE stream_count EVER FALLS, paired with the only
         * place it rises (piper_open_stream). */
        pp->stream_count--;
    }

    /* SINGLEPLEX'S OWN LINE, and Go's: RouteTCP's singleplex branch calls
     * sesh.Close() when the stream it opened could not be used or has
     * ended. CLOSE, NOT DESTROY -- this module has never owned a session's
     * storage in either mode (cloak_client_piper_set_session says so for
     * the shared one, and cloak_client_piper_conn_session_ready says the
     * same for this one), and destroying here would additionally be
     * illegal on most of the stacks that reach this function. Closing is
     * legal from all of them (cloak/session.h), defers its teardown to the
     * reactor, and fires on_broken -- which is this module's own walk,
     * followed by cfg.chain, which is where the owner reaps.
     *
     * Read AFTER the stream release and applied AFTER the free, so that
     * nothing this call sets in motion can reach a half-dismantled
     * context. A session already closing answers -1 and is unharmed,
     * which is exactly what happens when this runs from inside
     * piper_on_broken. */
    cloak_session_t *own = ctx->own_sesh ? ctx->sesh : NULL;
    ctx->sesh = NULL;
    ctx->own_sesh = 0;

    piper_conn_unlink(pp, ctx);
    free(ctx);

    if (own != NULL) {
        (void)cloak_session_close(own);
    }
}

/* ---- relay start, with the retry the interface forces on us ------------- */

static void piper_on_relay_done(cloak_stream_relay_t *sr, void *userdata);
static void piper_on_retry_timer(cloak_reactor_t *r, void *userdata);

/* Attempts to splice ctx->stream with the local descriptor in ctx->fd,
 * retrying on a timer if -- and only if -- the relay rejects the start
 * for its one transient reason. Every exit either hands the descriptor to
 * the relay, arms a retry, or tears the context down; ctx may be freed by
 * the time this returns. */
static void piper_try_start_relay(cloak_client_piper_conn_t *ctx) {
    cloak_client_piper_t *pp = ctx->pp;

    if (ctx->sesh == NULL || ctx->stream == NULL || ctx->fd < 0) {
        piper_conn_teardown(ctx);
        return;
    }

    int rc = cloak_stream_relay_start(&ctx->relay, pp->cfg.reactor, ctx->sesh, ctx->stream, ctx->fd,
                                      pp->cfg.relay_buf_cap, piper_on_relay_done, ctx);
    if (rc == 0) {
        /* Ownership of fd is the relay's from here; see this module's
         * header for the fd == -1 rule this implements. */
        ctx->fd = -1;
        ctx->relaying = 1;

        /* D6'S FIRST BYTES, AND THIS IS THE ONLY PLACE THEY ARE WRITTEN.
         *
         * WHY AFTER THE START AND NOT BEFORE IT, which is the opposite of
         * Go's order and is the one ordering question in this file worth
         * spending a reader's attention on:
         *
         *  - cloak_stream_write cannot fail on a full queue
         *    (cloak/session.h); an overrun surfaces one layer down as a
         *    broken connection that takes the whole pool and every other
         *    stream with it. The ONLY proof of room this module ever has
         *    is cloak_stream_relay_start's own -2 check, which it has
         *    just passed -- room for one worst-case frame. Writing first
         *    would be writing with no such proof, and writing on the -2
         *    path would be writing into a pool that has just said it has
         *    no room at all.
         *  - It is safe with respect to ordering, which is the thing that
         *    made Go write first: cloak_stream_relay_start's initial pump
         *    is stream-to-fd only. It never reads the fd -- the first fd
         *    read happens in its reactor callback, on a later turn -- so
         *    no byte the relay pulls from the local socket can overtake
         *    these.
         *
         * The read that produced them was capped at one frame's payload
         * (piper_first_read_cap), so this is exactly one frame and the
         * room just proven is exactly enough. first_len is cleared BEFORE
         * the write because cloak_stream_write can re-enter this module
         * through on_writable (cloak/session.h says that callback can
         * fire synchronously from inside a write). */
        if (ctx->first_len > 0) {
            size_t len = ctx->first_len;
            ctx->first_len = 0;
            if (cloak_stream_write(ctx->stream, ctx->first, len) < 0) {
                /* cloak/stream.h: a mid-write failure leaves the stream
                 * unusable and the caller must tear it down. */
                piper_conn_teardown(ctx);
            }
        }
        return;
    }

    /* Either way below, fd is still ours: cloak_stream_relay_start leaves
     * the descriptor with the caller on EVERY failure. */
    if (rc != -2) {
        /* PERMANENT (-1): bad arguments, allocation failure, or a reactor
         * registration failure. Nothing about this session will change to
         * make the identical call succeed later, so retrying would hold
         * the local socket and this context open for the whole budget and
         * fail anyway. Close this one local connection; the session and
         * its other streams are untouched. */
        piper_conn_teardown(ctx);
        return;
    }

    /* TRANSIENT (-2): the session's pool cannot hold one worst-case frame
     * right now. On the client this is the COMMON case, not a corner --
     * a browser opening a tab during an upload produces exactly it -- so
     * it is waited out. See the header for what the finite ceiling is
     * actually protecting against, which is not congestion. */
    if (ctx->retries >= pp->cfg.max_retries) {
        piper_conn_teardown(ctx);
        return;
    }
    ctx->retries++;
    pp->retried_starts++;
    ctx->retry_timer = cloak_reactor_add_timer(pp->cfg.reactor, pp->cfg.retry_delay_ms,
                                               piper_on_retry_timer, ctx);
    if (ctx->retry_timer == CLOAK_TIMER_INVALID) {
        /* An ENOMEM-class failure growing the reactor's timer heap: there
         * is no way left to ever make progress on this connection, so
         * waiting for one would just pin the descriptor forever. */
        piper_conn_teardown(ctx);
    }
}

static void piper_on_retry_timer(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_client_piper_conn_t *ctx = userdata;
    ctx->retry_timer = CLOAK_TIMER_INVALID;
    piper_try_start_relay(ctx);
}

/* The ordinary end of a local connection's life: the local peer closed,
 * the stream ended, or either side errored. The relay has already closed
 * both the descriptor and the stream; releasing the stream is ours, and
 * is done in the teardown walk and nowhere else.
 *
 * FREEING ctx FROM INSIDE on_done IS SAFE, and cloak/stream_relay.h does
 * not say so -- which is exactly why this comment exists. In
 * libcloak-mux/src/stream_relay.c the on_done call is the final statement
 * of stream_relay_teardown, and every call site that passes fire_done = 1
 * returns immediately afterwards without touching sr again. Since
 * cloak_client_piper_conn_t embeds its relay BY VALUE, that is the only
 * thing that makes the normal completion path work at all: there is no
 * later turn on which this context could otherwise be reclaimed. */
static void piper_on_relay_done(cloak_stream_relay_t *sr, void *userdata) {
    (void)sr;
    cloak_client_piper_conn_t *ctx = userdata;
    ctx->relaying = 0;
    piper_conn_teardown(ctx);
}

/* ---- D6: the first-byte window ------------------------------------------ */

/* The most bytes to take from the local socket before the stream exists.
 *
 * CLAMPED TO ONE FRAME'S PAYLOAD, and that is load-bearing rather than
 * tidy: these bytes are written with cloak_stream_write, which cannot
 * fail on a full queue, and the only room this module can prove it has at
 * that moment is the single worst-case frame cloak_stream_relay_start
 * checked for. A larger read would chunk into several frames whose summed
 * on-wire cost could exceed that proof in one step -- the same class of
 * overrun cloak_stream_relay_t's own per-read budget exists to prevent.
 *
 * The clamp uses the same two constants cloak_stream_init derives
 * max_payload_per_frame from, because there is no stream to ask yet: the
 * whole point of D6 is that none has been opened.
 *
 * IT READS THE CONTEXT'S SESSION, NOT THE PIPER'S, and that is what makes
 * singleplex possible at all rather than merely tidy: in that mode there
 * is no piper-wide session to ask, and the reason the first read is
 * deferred until a session exists (see piper_on_local_readable's peek) is
 * precisely that this clamp has nothing to compute from before then. */
static size_t piper_first_read_cap(const cloak_client_piper_conn_t *ctx) {
    size_t overhead = (size_t)CLOAK_FRAME_HEADER_LEN + (size_t)CLOAK_FRAME_MAX_EXTRA_LEN;
    size_t wire = ctx->sesh->max_on_wire_size;
    /* A session whose wire size cannot hold a header could not have been
     * created (cloak_stream_init rejects it), so this floor is a
     * guarantee that the cap is never 0, not a supported configuration:
     * a cap of 0 would make read(2) indistinguishable from EOF. */
    size_t one_frame = wire > overhead ? wire - overhead : 1;
    size_t cap = CLOAK_CLIENT_PIPER_FIRST_BYTES;
    if (one_frame < cap) {
        cap = one_frame;
    }
    return cap;
}

/* Leaves D6's window: the deadline is spent, the reactor registration is
 * handed back, a stream is opened and the splice is attempted. */
static void piper_open_stream(cloak_client_piper_conn_t *ctx) {
    cloak_client_piper_t *pp = ctx->pp;

    if (ctx->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(pp->cfg.reactor, ctx->deadline);
        ctx->deadline = CLOAK_TIMER_INVALID;
    }
    if (ctx->fd_registered) {
        /* Deregistered HERE rather than by cloak_stream_relay_start,
         * which would fail outright on an fd that is already registered
         * (cloak/reactor.h). The relay re-adds it, and the add is what
         * re-reports any bytes still sitting in the socket: an
         * EPOLL_CTL_ADD reports an fd that is already readable, which is
         * what lets this function take just one read and leave the rest
         * to the relay. */
        cloak_reactor_remove_fd(pp->cfg.reactor, ctx->fd);
        ctx->fd_registered = 0;
    }

    ctx->stream = cloak_session_open_stream(ctx->sesh, NULL);
    if (ctx->stream == NULL) {
        /* The session closed under us, or an allocation failed. One local
         * connection dies; nothing else is touched. */
        piper_conn_teardown(ctx);
        return;
    }
    pp->stream_count++;
    ctx->retries = 0;
    piper_try_start_relay(ctx);
}

/* D6's deadline. A local connection that has connected and said nothing
 * is closed WITHOUT ever having cost a stream -- on this side or on the
 * server's. */
static void piper_on_deadline(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_client_piper_conn_t *ctx = userdata;
    ctx->deadline = CLOAK_TIMER_INVALID;
    piper_conn_teardown(ctx);
}

/* SINGLEPLEX: leaves the first-byte window WITHOUT reading anything, and
 * asks the owner for a session of this connection's own.
 *
 * THE DEADLINE IS DELIBERATELY LEFT ARMED. It was armed at accept and is
 * cancelled in piper_open_stream -- i.e. when a stream actually opens, not
 * when the first byte arrives -- so in this mode it bounds the session
 * bring-up as well as the first-byte wait. That is the whole of the time
 * half of the resource answer: an owner whose handshake hangs, or whose
 * connector is grinding through its retry ladder, cannot pin this
 * descriptor past first_byte_timeout_ms. Reusing the one timer rather
 * than arming a second is not thrift: two timers would be two states to
 * keep consistent across every teardown path in this file, which is the
 * one place this module has already been burned.
 *
 * The descriptor is deregistered first, exactly as piper_open_stream
 * deregisters it, and for the same reason: the eventual EPOLL_CTL_ADD is
 * what re-reports the bytes still sitting in the socket. */
static void piper_begin_session(cloak_client_piper_conn_t *ctx) {
    cloak_client_piper_t *pp = ctx->pp;

    if (ctx->fd_registered) {
        cloak_reactor_remove_fd(pp->cfg.reactor, ctx->fd);
        ctx->fd_registered = 0;
    }
    ctx->awaiting_session = 1;
    pp->sessions_started++;

    /* pp->answering is what makes the failure path below safe against an
     * owner that answered from inside the call -- see that field's own
     * comment. Saved and restored rather than simply cleared, so a future
     * nested call site cannot silently lose an outer one. */
    cloak_client_piper_conn_t *prev = pp->answering;
    pp->answering = ctx;
    int rc = pp->cfg.new_session(ctx, pp->cfg.session_userdata);
    int answered = (pp->answering != ctx);
    pp->answering = prev;

    if (rc != 0) {
        if (answered) {
            /* The owner both answered AND reported a failed start, so ctx
             * has already been dealt with -- and, if the answer was
             * _failed, FREED. Nothing below may touch it. */
            return;
        }
        /* NOTHING WAS STARTED, so nothing may be cancelled: clearing the
         * flag before the teardown is what stops this from firing
         * cancel_session for a bring-up the owner just told us it never
         * began. */
        ctx->awaiting_session = 0;
        piper_conn_teardown(ctx);
    }
}

/* The first readable edge on a local connection. ONE read, matching Go's
 * io.ReadAtLeast(localConn, data, 1): one byte is enough to know this
 * connection is real, and draining to EAGAIN would buy nothing -- the
 * relay is about to take the descriptor and read the rest.
 *
 * IN SINGLEPLEX THIS FUNCTION RUNS TWICE for one connection: once with no
 * session, where it only PEEKS, and once after the owner has handed a
 * session over (cloak_client_piper_conn_session_ready re-registers the
 * descriptor, and an EPOLL_CTL_ADD on an fd that is already readable
 * reports it immediately), where it takes the ordinary capped read. The
 * two passes are told apart by ctx->sesh, as everything else in this
 * module is. */
static void piper_on_local_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    cloak_client_piper_conn_t *ctx = userdata;
    cloak_client_piper_t *pp = ctx->pp;

    if (ctx->sesh == NULL) {
        if (!pp->cfg.singleplex) {
            /* The shared session died between the accept and the first
             * byte. */
            piper_conn_teardown(ctx);
            return;
        }

        /* SINGLEPLEX'S FIRST PASS: PEEK, DO NOT CONSUME.
         *
         * WHY A PEEK RATHER THAN THE READ Go DOES HERE, and this is the
         * one deliberate divergence in this file. Go reads the first
         * bytes into a 10 KiB buffer and only then opens its stream, which
         * works because its session already exists by that point. Here it
         * does not, and that has two consequences that both point the
         * same way:
         *
         *  - THE READ CANNOT BE SIZED YET. piper_first_read_cap clamps to
         *    one frame's payload, derived from the session's
         *    max_on_wire_size, and there is no session to ask. Reading
         *    with the unclamped 10 KiB constant instead would reintroduce
         *    exactly the overrun that clamp exists to prevent, on a
         *    session configured with a small wire size.
         *  - IT WOULD PIN DATA FOR THE WHOLE HANDSHAKE. Copying bytes out
         *    now means holding them for however long the bring-up takes --
         *    seconds, legitimately, once the connector's retry ladder is
         *    involved -- per waiting connection.
         *
         * MSG_PEEK answers the only question that actually has to be
         * answered before spending a handshake ("did this connection say
         * anything, or is it a scanner that connected and closed?")
         * without consuming a byte. What it does NOT read stays in the
         * kernel's receive buffer, which is a fixed size the OS bounds
         * and which backpressures the local application through TCP's own
         * window. See cloak_client_piper_buffered_bytes. */
        uint8_t probe;
        ssize_t got;
        for (;;) {
            got = recv(fd, &probe, 1, MSG_PEEK);
            if (got < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
        if (got < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* cloak/reactor.h folds EPOLLHUP/EPOLLERR into READABLE,
                 * so a spurious edge is expected and is not a reason to
                 * give up on a connection that may still speak. */
                return;
            }
            piper_conn_teardown(ctx);
            return;
        }
        if (got == 0) {
            /* Connected and closed without saying anything. In this mode
             * that saves a whole dial and handshake, not just a stream --
             * which is why the session is requested here and not at
             * accept time. */
            piper_conn_teardown(ctx);
            return;
        }
        piper_begin_session(ctx);
        return;
    }

    ssize_t n;
    for (;;) {
        n = read(fd, ctx->first, piper_first_read_cap(ctx));
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* cloak/reactor.h: EPOLLHUP/EPOLLERR are folded into
             * READABLE, so a spurious edge is expected and is not a
             * reason to give up on a connection that may still speak. */
            return;
        }
        piper_conn_teardown(ctx);
        return;
    }
    if (n == 0) {
        /* Connected and closed without saying anything -- the same
         * non-event D6's deadline covers, arriving sooner. */
        piper_conn_teardown(ctx);
        return;
    }

    ctx->first_len = (size_t)n;
    piper_open_stream(ctx);
}

/* ---- session callbacks --------------------------------------------------- */

/* THE SERVER OPENED A STREAM TOWARD US, which in this transport is a
 * protocol violation: every stream is client-initiated, and the server's
 * whole data path (cloak/proxy.h) only ever accepts. Refuse it. See
 * cloak_client_piper_rejected_streams for the full argument, including
 * why silently ignoring the stream is NOT the harmless option (it leaks
 * the stream for the life of the process and keeps the session's
 * inactivity timeout from ever retiring it, both under a remote peer's
 * control) and why tearing the whole session down is worse than absorbing
 * it. */
static void piper_on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    cloak_client_piper_t *pp = userdata;
    if (pp == NULL || sesh == NULL || stream == NULL) {
        return;
    }
    pp->rejected_streams++;
    if (!pp->logged_rejected_stream) {
        pp->logged_rejected_stream = 1;
        CLOAK_LOGW("client piper: the server opened a stream toward this client -- refusing. "
                   "Every stream in this protocol is client-initiated, so this is a server bug "
                   "or a server that is not the one we think it is; further occurrences are "
                   "counted but not logged");
    }
    /* Legal from within on_new_stream (cloak/session.h), and it performs
     * the active close itself, so the far end learns immediately rather
     * than waiting out a timeout. */
    cloak_session_release_stream(sesh, stream);

    /* THE CEILING. Refusing is cheap but not free: each refusal costs a
     * PERMANENT cloak_strmtab_t tombstone for the life of this session
     * (cloak/strmtab.h) and one outbound closing frame, so an unbounded
     * refusal path is a one-to-one amplification with no end. Past the
     * ceiling the session is closed -- see
     * CLOAK_CLIENT_PIPER_MAX_REJECTED_STREAMS for why that does not
     * contradict refusing the FIRST one rather than tearing everything
     * down, the short form being that the server could close this session
     * itself at any time regardless.
     *
     * cloak_session_close is explicitly safe from within on_new_stream
     * (cloak/session.h); cloak_session_destroy is not, and is not called.
     * The close defers its teardown to the reactor, which fires on_broken,
     * which is this module's own walk -- so every local connection is torn
     * down through exactly one path, as always. */
    if (pp->rejected_streams == CLOAK_CLIENT_PIPER_MAX_REJECTED_STREAMS) {
        CLOAK_LOGW("client piper: %zu streams opened toward this client and refused -- closing "
                   "the session. A server doing this is hostile or broken, and it could close "
                   "this session itself at any time anyway",
                   pp->rejected_streams);
        (void)cloak_session_close(sesh);
    }
}

static void piper_on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    cloak_client_piper_t *pp = userdata;
    if (pp == NULL || stream == NULL) {
        return;
    }

    /* A LINEAR SCAN IS THE RIGHT STRUCTURE HERE, and the next reader will
     * wonder whether it should be a hash table: one client's live local
     * connection count is small (a browser's worth), Go indexes this no
     * better, and replacing it would add a second structure to keep in
     * step with the list during teardown -- the exact place this module
     * is most fragile -- to save a handful of pointer comparisons.
     *
     * next is saved before the notify because
     * cloak_stream_relay_notify_stream_data CAN tear the relay down and
     * fire on_done, which frees ctx. The early return below means this
     * particular loop would survive without it; it is written this way
     * anyway so the pattern is identical in both notify loops and cannot
     * rot if the early return ever goes. */
    cloak_client_piper_conn_t *ctx = pp->conns;
    while (ctx != NULL) {
        cloak_client_piper_conn_t *next = ctx->next;
        /* THE SESSION IS PART OF THE KEY, and the honest status of that
         * is stated rather than overclaimed: in singleplex this list
         * holds contexts belonging to SEVERAL sessions at once, so the
         * pair is the actual identity of a stream, but the stream pointer
         * ALONE is already unambiguous given this module's own
         * invariants -- a live context's stream belongs to a live
         * session, and piper_on_broken NULLs it before its session can
         * free it, so no two entries in this list can ever hold the same
         * address. The pair is kept because it is free and because that
         * invariant is the one an ABA bug would break silently, but a
         * mutation dropping it is NOT caught by this branch's tests and
         * the report says so. */
        if (ctx->sesh == sesh && ctx->stream == stream) {
            /* A connection still waiting out a retry has no relay yet and
             * needs no notification: its data waits in its own receive
             * buffer and the relay's initial pump collects it. */
            if (ctx->relaying) {
                cloak_stream_relay_notify_stream_data(&ctx->relay);
            }
            return; /* ctx may already be freed */
        }
        ctx = next;
    }
}

static void piper_on_writable(cloak_session_t *sesh, void *userdata) {
    cloak_client_piper_t *pp = userdata;
    if (pp == NULL) {
        return;
    }

    /* Every relay bound to this session is told the pool drained, and
     * each independently re-checks its own budget. Nothing divides the
     * newly freed space between them, so the connection whose relay is
     * notified first can consume all of it -- unfairness rather than
     * starvation, and the same trade cloak_proxy_on_writable documents
     * at length on the server side.
     *
     * next is saved before each notify because
     * cloak_stream_relay_notify_writable CAN fire on_done: its rate-timer
     * re-arm has a failure path that tears the relay down, which frees
     * ctx.
     *
     * SAVING next IS NOT A COMPLETE DEFENCE, and the residue is stated
     * rather than fixed. That same on_done path runs this module's
     * teardown, which can reach cloak_stream_write and so re-enter this
     * function; a nested pass could free the context this pass is holding
     * in `next`. It is reachable only through an allocation failure
     * arming the relay's rate timer, and cloak_proxy_on_writable has the
     * identical shape -- so this is precedent-equivalent, not a
     * regression, and a fix belongs in both at once (a generation counter
     * on the list, or an explicit "walking" guard) rather than in one. */
    cloak_client_piper_conn_t *ctx = pp->conns;
    while (ctx != NULL) {
        cloak_client_piper_conn_t *next = ctx->next;
        /* Only the relays bound to the session that actually drained: in
         * singleplex the others are on different pools entirely, so
         * notifying them is wasted work and a misleading signal. It is
         * not a CORRECTNESS guard -- cloak_stream_relay_notify_writable
         * re-checks its own session's budget and does nothing if there is
         * no room -- so, like the pair above, a mutation dropping it is
         * not caught by this branch's tests. */
        if (ctx->sesh == sesh && ctx->relaying) {
            cloak_stream_relay_notify_writable(&ctx->relay);
        }
        ctx = next;
    }
}

/* THE ONLY WINDOW IN WHICH A RELAY BOUND TO THIS SESSION CAN STILL BE
 * STOPPED, and the reason this module insists on owning on_broken.
 * cloak_session_broken_cb's contract (cloak/session.h) is that
 * immediately after this returns, every still-active stream the session
 * owns is destroyed and freed. A cloak_stream_relay_t holds its stream
 * and its session as raw pointers it can never validate -- so a relay
 * left running past this point still has its fd registered with the
 * reactor, and the next byte that arrives on it runs cloak_stream_write
 * on freed memory.
 *
 * The walk therefore runs BEFORE anything else, including before the
 * chain: cloak/session.h permits a callback in this position to call
 * cloak_session_destroy, and by the time the chain can do that every
 * relay must already be stopped. And the pointers to this session are
 * cleared only AFTER the walk, because piper_conn_teardown legitimately
 * needs a live session to release its streams to -- this is the one
 * window where that is still possible.
 *
 * IT IS PER SESSION, NOT PER PIPER, and that is the structural change
 * singleplex forces. One piper's context list can hold contexts belonging
 * to many different sessions at once; a walk that tore down all of them
 * because ONE session died would kill every unrelated local connection
 * the client had, which is precisely the failure mode singleplex exists
 * to prevent. So the walk is keyed on ctx->sesh, and contexts whose
 * session is a different one -- or which have no session yet, because
 * theirs is still handshaking -- are left entirely alone. In shared mode
 * every live context matches, so this is the old walk unchanged. */
static void piper_on_broken(cloak_session_t *sesh, void *userdata) {
    cloak_client_piper_t *pp = userdata;
    if (pp == NULL) {
        return;
    }

    cloak_client_piper_conn_t *ctx = pp->conns;
    while (ctx != NULL) {
        /* next is saved before the teardown for the ordinary reason: the
         * teardown frees ctx. It can only unlink ctx itself -- no context
         * tears down another -- so `next` stays valid. */
        cloak_client_piper_conn_t *next = ctx->next;
        if (ctx->sesh == sesh) {
            piper_conn_teardown(ctx);
        }
        ctx = next;
    }

    /* THIS IS THE INSTANT pp->sesh STOPS BEING VALID, and clearing it
     * here is what makes the rule this module's header states true of the
     * code rather than only of the comment. Guarded because in singleplex
     * pp->sesh is NULL throughout and the session that just died belonged
     * to one context, which the walk above has already forgotten; every
     * later accept in that mode asks for a session of its own rather than
     * being refused. */
    if (pp->sesh == sesh) {
        pp->sesh = NULL;
    }

    if (pp->cfg.chain != NULL) {
        pp->cfg.chain(sesh, pp->cfg.chain_userdata);
    }
}

/* ---- public entry points -------------------------------------------------- */

int cloak_client_piper_init(cloak_client_piper_t *pp, const cloak_client_piper_config_t *cfg) {
    if (pp == NULL) {
        return -1;
    }
    /* Fully initialize BEFORE validating anything else, so that every
     * failure return leaves pp safe to pass to
     * cloak_client_piper_destroy -- the same ordering cloak_proxy_init
     * and cloak_client_connector_init document, and for the same reason. */
    memset(pp, 0, sizeof(*pp));

    if (cfg == NULL || cfg->reactor == NULL) {
        return -1;
    }
    if (cfg->singleplex && cfg->new_session == NULL) {
        /* REJECTED HERE, NOT AT THE FIRST ACCEPT. A singleplex piper with
         * no way to obtain a session can do exactly one thing with every
         * connection it is handed -- close it -- and an operator whose
         * client silently drops every connection has nothing to go on.
         * The same argument cloak_client_connector_init makes for
         * refusing an out-of-range num_conn rather than clamping it. */
        return -1;
    }

    pp->cfg = *cfg;
    if (pp->cfg.relay_buf_cap == 0) {
        pp->cfg.relay_buf_cap = CLOAK_CLIENT_PIPER_DEFAULT_RELAY_BUF_CAP;
    }
    if (pp->cfg.first_byte_timeout_ms == 0) {
        pp->cfg.first_byte_timeout_ms = CLOAK_CLIENT_PIPER_DEFAULT_FIRST_BYTE_TIMEOUT_MS;
    }
    if (pp->cfg.retry_delay_ms == 0) {
        pp->cfg.retry_delay_ms = CLOAK_CLIENT_PIPER_DEFAULT_RETRY_DELAY_MS;
    }
    if (pp->cfg.max_retries == 0) {
        pp->cfg.max_retries = CLOAK_CLIENT_PIPER_DEFAULT_MAX_RETRIES;
    }
    if (pp->cfg.max_local_conns == 0) {
        pp->cfg.max_local_conns = CLOAK_CLIENT_PIPER_DEFAULT_MAX_LOCAL_CONNS;
    }
    return 0;
}

void cloak_client_piper_install(cloak_client_piper_t *pp, cloak_session_config_t *config) {
    if (pp == NULL || config == NULL) {
        return;
    }
    config->on_new_stream = piper_on_new_stream;
    config->on_new_stream_userdata = pp;
    config->on_stream_data = piper_on_stream_data;
    config->on_stream_data_userdata = pp;
    config->on_writable = piper_on_writable;
    config->on_writable_userdata = pp;
    /* ALL FOUR, on_broken included: unlike cloak_proxy_t -- which must
     * leave on_broken alone because cloak_server_registry_get_or_create
     * overwrites it -- nothing else on the client wants this hook, and an
     * owner that took it would leave relays running past their session's
     * death. cloak_client_piper_config_t::chain is where an owner's own
     * bookkeeping goes. */
    config->on_broken = piper_on_broken;
    config->on_broken_userdata = pp;
}

void cloak_client_piper_set_session(cloak_client_piper_t *pp, cloak_session_t *sesh) {
    if (pp == NULL) {
        return;
    }
    pp->sesh = sesh;
}

void cloak_client_piper_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    cloak_client_piper_t *pp = userdata;
    if (fd < 0) {
        return;
    }
    if (pp == NULL) {
        /* Not this module's callback at all, but the descriptor is still
         * ours by cloak_listener_accept_cb's contract and dropping it
         * would leak it. */
        close(fd);
        return;
    }

    if (!pp->cfg.singleplex && pp->sesh == NULL) {
        /* No shared session to open a stream on -- either one has never
         * been set or it has broken. Closing immediately is the honest
         * answer: an application that gets a connection and then silence
         * cannot tell a dead tunnel from a slow one.
         *
         * A SINGLEPLEX PIPER NEVER TAKES THIS BRANCH, and must not: it has
         * no shared session by construction, and the session this
         * connection will use does not exist yet and will not until the
         * connection has said something. */
        close(fd);
        return;
    }

    if (pp->conn_count >= pp->cfg.max_local_conns) {
        pp->refused_conns++;
        if (!pp->logged_refused_conn) {
            pp->logged_refused_conn = 1;
            CLOAK_LOGW("client piper: refusing local connections -- %zu already open, which is "
                       "the configured maximum; further refusals are counted but not logged",
                       pp->cfg.max_local_conns);
        }
        close(fd);
        return;
    }

    cloak_client_piper_conn_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        close(fd);
        return;
    }
    ctx->pp = pp;
    ctx->fd = fd;
    ctx->deadline = CLOAK_TIMER_INVALID;
    ctx->retry_timer = CLOAK_TIMER_INVALID;
    /* THE SESSION IS BOUND TO THE CONTEXT HERE, ONCE, and everything
     * afterwards reads it from the context. In singleplex there is none
     * to bind yet: NULL is this context's whole state until its own
     * bring-up answers. */
    ctx->sesh = pp->cfg.singleplex ? NULL : pp->sesh;
    piper_conn_link(pp, ctx);

    /* D6: NOTHING IS OPENED ON THE SESSION HERE. The connection is
     * registered for reading and put on a deadline, and only the first
     * byte to actually arrive buys it a stream. See this module's header
     * for what that saves and what the deadline is bounding. */
    if (cloak_reactor_add_fd(pp->cfg.reactor, fd, CLOAK_REACTOR_READABLE, piper_on_local_readable,
                             ctx) != 0) {
        piper_conn_teardown(ctx);
        return;
    }
    ctx->fd_registered = 1;

    ctx->deadline = cloak_reactor_add_timer(pp->cfg.reactor, pp->cfg.first_byte_timeout_ms,
                                            piper_on_deadline, ctx);
    if (ctx->deadline == CLOAK_TIMER_INVALID) {
        /* Without the deadline this connection could wait forever, which
         * is precisely the resource pin D6 exists to bound. Refuse it
         * rather than admit an unbounded one. */
        piper_conn_teardown(ctx);
    }
}

/* SINGLEPLEX: the owner's answer to config::new_session.
 *
 * WHY THIS RE-REGISTERS THE DESCRIPTOR INSTEAD OF READING IT. The first
 * pass through piper_on_local_readable only peeked, so the connection's
 * bytes are still in the kernel. Handing the fd back to the reactor makes
 * the ordinary path run again -- and an EPOLL_CTL_ADD on a descriptor that
 * is already readable reports it at once (cloak/reactor.h), which is the
 * same property piper_open_stream relies on -- so the capped read, the
 * stream open and the relay start are ONE code path shared by both modes
 * rather than two that can drift. */
void cloak_client_piper_conn_session_ready(cloak_client_piper_conn_t *ctx, cloak_session_t *sesh) {
    if (ctx == NULL) {
        return;
    }
    if (sesh == NULL) {
        cloak_client_piper_conn_session_failed(ctx);
        return;
    }
    if (!ctx->awaiting_session) {
        /* Answered twice, or answered after cancel_session said not to.
         * Both are contract violations; ignoring is the only safe reply,
         * since the alternative interpretation of a stale ctx is a
         * use-after-free this function could not detect anyway. */
        return;
    }
    cloak_client_piper_t *pp = ctx->pp;
    ctx->awaiting_session = 0;
    if (pp->answering == ctx) {
        pp->answering = NULL; /* answered from inside new_session */
    }
    /* own_sesh is set BEFORE the registration can fail, deliberately: from
     * this instant the session is this context's responsibility, so even
     * the failure path below must close it rather than leak it. */
    ctx->sesh = sesh;
    ctx->own_sesh = 1;

    if (ctx->fd < 0 ||
        cloak_reactor_add_fd(pp->cfg.reactor, ctx->fd, CLOAK_REACTOR_READABLE,
                             piper_on_local_readable, ctx) != 0) {
        piper_conn_teardown(ctx);
        return;
    }
    ctx->fd_registered = 1;
}

void cloak_client_piper_conn_session_failed(cloak_client_piper_conn_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (!ctx->awaiting_session) {
        return;
    }
    cloak_client_piper_t *pp = ctx->pp;
    if (pp->answering == ctx) {
        /* Answered from inside new_session. Recorded BEFORE the free, so
         * piper_begin_session's failure path knows not to touch ctx
         * again -- which is the whole of the defence described on
         * cloak_client_piper_t::answering. */
        pp->answering = NULL;
    }
    /* Cleared first so the teardown does not then fire cancel_session for
     * a bring-up the owner has just finished telling us about. */
    ctx->awaiting_session = 0;
    piper_conn_teardown(ctx);
}

void cloak_client_piper_destroy(cloak_client_piper_t *pp) {
    if (pp == NULL) {
        return;
    }
    /* Idempotent and safe on a zeroed struct for the same reason: a
     * zeroed (or already-drained) piper has no contexts, so this loop
     * does not run and nothing below it touches the borrowed reactor. */
    while (pp->conns != NULL) {
        piper_conn_teardown(pp->conns);
    }
}

size_t cloak_client_piper_conn_count(const cloak_client_piper_t *pp) {
    return pp == NULL ? 0 : pp->conn_count;
}

size_t cloak_client_piper_stream_count(const cloak_client_piper_t *pp) {
    return pp == NULL ? 0 : pp->stream_count;
}

size_t cloak_client_piper_refused_conns(const cloak_client_piper_t *pp) {
    return pp == NULL ? 0 : pp->refused_conns;
}

size_t cloak_client_piper_rejected_streams(const cloak_client_piper_t *pp) {
    return pp == NULL ? 0 : pp->rejected_streams;
}

size_t cloak_client_piper_retried_starts(const cloak_client_piper_t *pp) {
    return pp == NULL ? 0 : pp->retried_starts;
}

size_t cloak_client_piper_sessions_started(const cloak_client_piper_t *pp) {
    return pp == NULL ? 0 : pp->sessions_started;
}

/* O(live connections), like piper_on_stream_data's scan and for the same
 * reason: the count is a browser's worth, and a running total would be a
 * second thing to keep in step with first_len across every teardown path
 * -- which is the exact place this module is most fragile. */
size_t cloak_client_piper_buffered_bytes(const cloak_client_piper_t *pp) {
    if (pp == NULL) {
        return 0;
    }
    size_t total = 0;
    for (const cloak_client_piper_conn_t *ctx = pp->conns; ctx != NULL; ctx = ctx->next) {
        total += ctx->first_len;
    }
    return total;
}
