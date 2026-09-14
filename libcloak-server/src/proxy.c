#define _POSIX_C_SOURCE 200809L
#include "cloak/proxy.h"

#include "cloak/log.h"

#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- the stream caps: derivation, and the state behind the log --------- */

/* Half the process's RLIMIT_NOFILE soft limit, clamped into
 * [FLOOR, CEILING]. cloak/proxy.h carries the reasoning; this is only the
 * arithmetic. getrlimit failing yields the FLOOR rather than failing init
 * -- a caller that cannot learn its own descriptor limit should assume a
 * small one. An unlimited soft limit yields the CEILING. */
static size_t proxy_derive_max_streams_total(void) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        return CLOAK_PROXY_MAX_STREAMS_TOTAL_FLOOR;
    }
    if (rl.rlim_cur == RLIM_INFINITY) {
        return CLOAK_PROXY_MAX_STREAMS_TOTAL_CEILING;
    }
    /* Compared in rlim_t, never narrowed first: the ceiling check is what
     * makes the cast below safe on any platform whose rlim_t is wider
     * than size_t. */
    rlim_t half = rl.rlim_cur / 2;
    if (half >= (rlim_t)CLOAK_PROXY_MAX_STREAMS_TOTAL_CEILING) {
        return CLOAK_PROXY_MAX_STREAMS_TOTAL_CEILING;
    }
    if (half <= (rlim_t)CLOAK_PROXY_MAX_STREAMS_TOTAL_FLOOR) {
        return CLOAK_PROXY_MAX_STREAMS_TOTAL_FLOOR;
    }
    return (size_t)half;
}

/* The count at or below which a cap is considered RECOVERED, an eighth of
 * the cap below the cap itself.
 *
 * THE HYSTERESIS IS THE WHOLE MECHANISM and not a refinement. Without it
 * the capped flag flips every time a client closes one stream and opens
 * two, so a "transition only" log would still emit at the attacker's
 * rate -- which is the exact failure mode logging per refusal has. With
 * it, a line pair costs the attacker an eighth of the cap's worth of
 * stream lifecycles. The eighth is clamped to at least 1 so that a cap of
 * 1 or 2 (which only a test or a deliberately crippled config produces)
 * still has somewhere to recover to. */
static size_t proxy_cap_low_water(size_t cap) {
    size_t h = cap / 8;
    if (h == 0) {
        h = 1;
    }
    return h >= cap ? 0 : cap - h;
}

/* ---- intrusive list bookkeeping ----------------------------------------- */

static void proxy_session_link(cloak_proxy_t *p, cloak_proxy_session_t *ps) {
    ps->prev = NULL;
    ps->next = p->sessions;
    if (p->sessions != NULL) {
        p->sessions->prev = ps;
    }
    p->sessions = ps;
    p->session_count++;
}

static void proxy_session_unlink(cloak_proxy_t *p, cloak_proxy_session_t *ps) {
    if (ps->prev != NULL) {
        ps->prev->next = ps->next;
    } else {
        p->sessions = ps->next;
    }
    if (ps->next != NULL) {
        ps->next->prev = ps->prev;
    }
    ps->prev = NULL;
    ps->next = NULL;
    p->session_count--;
}

static void proxy_stream_link(cloak_proxy_session_t *ps, cloak_proxy_stream_t *pst) {
    pst->prev = NULL;
    pst->next = ps->streams;
    if (ps->streams != NULL) {
        ps->streams->prev = pst;
    }
    ps->streams = pst;
    ps->stream_count++;
    ps->p->stream_count++;
}

static void proxy_stream_unlink(cloak_proxy_session_t *ps, cloak_proxy_stream_t *pst) {
    if (pst->prev != NULL) {
        pst->prev->next = pst->next;
    } else {
        ps->streams = pst->next;
    }
    if (pst->next != NULL) {
        pst->next->prev = pst->prev;
    }
    pst->prev = NULL;
    pst->next = NULL;
    ps->stream_count--;
    ps->p->stream_count--;

    /* THE ONLY PLACE EITHER COUNT EVER FALLS, which is why the recovery
     * side of the log lives here rather than at the five call sites that
     * free a stream context -- the same reason the decrement itself does.
     * A recovery line emitted from a session that is being torn down
     * would be a lie, and proxy_session_teardown clears ps->capped before
     * its walk so that one cannot happen. */
    if (ps->capped && ps->stream_count <= proxy_cap_low_water(ps->p->cfg.max_streams_per_session)) {
        ps->capped = 0;
        CLOAK_LOGI("proxy: session %u no longer at its stream cap (%zu of %zu in use)",
                   ps->session_id, ps->stream_count, ps->p->cfg.max_streams_per_session);
    }
    if (ps->p->total_capped &&
        ps->p->stream_count <= proxy_cap_low_water(ps->p->cfg.max_streams_total)) {
        ps->p->total_capped = 0;
        CLOAK_LOGI("proxy: no longer at the total stream cap (%zu of %zu in use)",
                   ps->p->stream_count, ps->p->cfg.max_streams_total);
    }
}

/* ---- teardown ------------------------------------------------------------
 *
 * THE ONE COPY. Three public entry points have to perform exactly this
 * walk -- cloak_proxy_destroy (the owner's shutdown),
 * cloak_proxy_registry_broken (the session died under us) and
 * cloak_proxy_session_aborted (the session never came to exist) -- and
 * they differ only in what they do afterwards. Two copies of the most
 * lifetime-sensitive code in this module drifting apart is the worst
 * outcome available here, so there is deliberately one. */

/* Releases every resource one stream context holds, releases the stream
 * itself back to its session, unlinks the context and FREES IT. pst must
 * not be touched after this returns. */
static void proxy_stream_teardown(cloak_proxy_stream_t *pst) {
    cloak_proxy_session_t *ps = pst->ps;
    cloak_proxy_t *p = ps->p;

    if (pst->retry_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(p->cfg.reactor, pst->retry_timer);
        pst->retry_timer = CLOAK_TIMER_INVALID;
    }
    if (pst->dialing) {
        /* Only ever reached from OUTSIDE the dial callback: that callback
         * clears this flag before it can lead here, because cloak/net.h
         * forbids cancelling a dial from within its own completion. */
        pst->dialing = 0;
        cloak_dial_cancel(&pst->dial);
    }
    if (pst->relaying) {
        /* THE ORDER OF THESE TWO STEPS -- stop the relay HERE, release
         * the stream BELOW -- is the whole of this module's teardown
         * correctness, and it is stated at this site and not only in the
         * header because this is where it is easy to get backwards.
         *
         * cloak_stream_relay_stop closes the stream (so the peer
         * actually learns the stream ended) and the relay's own fd; it
         * deliberately does NOT fire on_done, and deliberately does NOT
         * release the stream -- cloak/stream_relay.h is explicit that
         * releasing is ours. Releasing FIRST would free the
         * cloak_stream_t while the relay still holds it as a raw pointer
         * it cannot validate, and the stop below would then write a
         * close through freed memory. */
        pst->relaying = 0;
        cloak_stream_relay_stop(&pst->relay);
    }
    if (pst->fd_pending >= 0) {
        /* The retry window: no relay has taken this descriptor yet, so
         * nothing else is going to close it. */
        close(pst->fd_pending);
        pst->fd_pending = -1;
    }
    if (ps->sesh != NULL && pst->stream != NULL) {
        /* cloak_session_release_stream performs the active close itself
         * when the stream has not already been closed (by the relay's own
         * teardown, or by the peer), so there is no separate
         * cloak_session_close_stream call to make here. */
        cloak_session_release_stream(ps->sesh, pst->stream);
    }
    pst->stream = NULL;

    proxy_stream_unlink(ps, pst);
    free(pst);
}

/* Tears down every stream context this session holds, then unlinks and
 * frees the session context. ps must not be touched after this returns. */
static void proxy_session_teardown(cloak_proxy_session_t *ps) {
    /* Silently, and BEFORE the walk: this session is going away, so its
     * cap state is moot and a "no longer at its stream cap" line about a
     * context being destroyed would mislead whoever read it. The
     * proxy-wide flag is deliberately NOT cleared here -- descriptors
     * really are coming back, so that recovery is genuine. */
    ps->capped = 0;

    while (ps->streams != NULL) {
        proxy_stream_teardown(ps->streams);
    }

    /* THIS IS THE INSTANT ps->sesh STOPS BEING VALID, and clearing it
     * here is what makes the rule cloak/proxy.h states about that field
     * ("must never be dereferenced once the session has broken") true of
     * the code rather than only of the comment. It has to happen HERE:
     * after the walk above, because proxy_stream_teardown legitimately
     * needs a live session to call cloak_session_release_stream on (this
     * function's most important caller, cloak_proxy_registry_broken,
     * runs in the one window where that is still possible), and before
     * anything else can run, because on the broken path the session is
     * gone the moment the callback that led here returns. The free below
     * makes the store dead in this particular ordering; it is written
     * anyway so that the invariant survives any future path that keeps a
     * context alive past its session. */
    ps->sesh = NULL;

    proxy_session_unlink(ps->p, ps);
    free(ps);
}

/* The session context for (uid, session_id), or NULL if this proxy has
 * none.
 *
 * A LINEAR SCAN IS THE RIGHT STRUCTURE HERE, for the same reason the
 * per-stream scan in proxy_on_stream_data gives: this list holds one
 * entry per live session, it is walked once per session teardown (not
 * per frame), and a second structure to keep in step with it during
 * teardown -- the exact place this module is most fragile -- would buy
 * nothing.
 *
 * KEYED ON (uid, session_id), NOT ON THE cloak_session_t POINTER. That
 * pair is recorded by cloak_proxy_prepare_session, which is the only
 * place a context is ever created, so it is valid for the whole of a
 * context's life -- including the window before ps->sesh is ever set,
 * which is exactly the window cloak_proxy_session_aborted has to search
 * in. A scan on ps->sesh would find nothing at any of its three sites,
 * and would also miss a session that was created but whose context never
 * learned its pointer (which is every session that has not yet carried a
 * stream: proxy_on_new_stream is what records it). */
static cloak_proxy_session_t *proxy_find_session(cloak_proxy_t *p,
                                                 const uint8_t uid[CLOAK_UID_LEN],
                                                 uint32_t session_id) {
    for (cloak_proxy_session_t *ps = p->sessions; ps != NULL; ps = ps->next) {
        if (ps->session_id == session_id && memcmp(ps->uid, uid, CLOAK_UID_LEN) == 0) {
            return ps;
        }
    }
    return NULL;
}

/* ---- relay start, with the retry the interface forces on us ------------- */

static void proxy_on_relay_done(cloak_stream_relay_t *sr, void *userdata);
static void proxy_on_retry_timer(cloak_reactor_t *r, void *userdata);

/* Attempts to splice pst->stream with the descriptor currently held in
 * pst->fd_pending, retrying on a timer if -- and only if -- the relay
 * rejects the start for its one transient reason. Every exit either hands
 * the descriptor to the relay or tears the stream context down; pst may
 * be freed by the time this returns. */
static void proxy_try_start_relay(cloak_proxy_stream_t *pst) {
    cloak_proxy_session_t *ps = pst->ps;
    cloak_proxy_t *p = ps->p;

    if (ps->sesh == NULL || pst->stream == NULL || pst->fd_pending < 0) {
        proxy_stream_teardown(pst);
        return;
    }

    int rc = cloak_stream_relay_start(&pst->relay, p->cfg.reactor, ps->sesh, pst->stream,
                                      pst->fd_pending, p->cfg.relay_buf_cap, proxy_on_relay_done,
                                      pst);
    if (rc == 0) {
        /* Ownership of fd is the relay's from here; see this module's
         * header for the fd_pending == -1 rule this implements. */
        pst->fd_pending = -1;
        pst->relaying = 1;
        return;
    }

    /* Either way below, fd_pending is still ours: cloak_stream_relay_start
     * leaves the descriptor with the caller on EVERY failure. */
    if (rc != -2) {
        /* PERMANENT (-1): bad arguments, allocation failure, or a reactor
         * registration failure. Nothing about this session will change to
         * make the identical call succeed later, so retrying would hold a
         * connected upstream socket and this context open for the whole
         * budget and fail anyway. Close this one stream now; the session
         * and its other streams are untouched. */
        proxy_stream_teardown(pst);
        return;
    }

    /* TRANSIENT (-2): the session's pool cannot hold one worst-case frame
     * right now. This is ordinary congestion -- a relay already running
     * on this session holds min_conn_free below exactly this threshold
     * for as long as its peer is slow to drain -- so it is waited out,
     * not treated as a failure. See cloak_proxy_config_t::max_retries for
     * what the finite ceiling is actually protecting against. */
    if (pst->retries >= p->cfg.max_retries) {
        proxy_stream_teardown(pst);
        return;
    }
    pst->retries++;
    pst->retry_timer =
        cloak_reactor_add_timer(p->cfg.reactor, p->cfg.retry_delay_ms, proxy_on_retry_timer, pst);
    if (pst->retry_timer == CLOAK_TIMER_INVALID) {
        /* An ENOMEM-class failure growing the reactor's timer heap: there
         * is no way left to ever make progress on this stream, so waiting
         * for one would just pin the descriptor forever. */
        proxy_stream_teardown(pst);
    }
}

static void proxy_on_retry_timer(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_proxy_stream_t *pst = userdata;
    pst->retry_timer = CLOAK_TIMER_INVALID;
    proxy_try_start_relay(pst);
}

/* The ordinary end of a stream's life: the stream ended, the upstream
 * ended, or either side errored. The relay has already closed both the
 * descriptor and the stream; releasing the stream is ours, and is done
 * here and in the teardown walk above, nowhere else.
 *
 * FREEING pst FROM INSIDE on_done IS SAFE, and cloak/stream_relay.h does
 * not say so -- which is exactly why this comment exists. In
 * libcloak-mux/src/stream_relay.c, the on_done call is the final
 * statement of stream_relay_teardown, and every call site that passes
 * fire_done = 1 returns immediately afterwards without touching sr again.
 * Since cloak_proxy_stream_t embeds its relay BY VALUE, that is the only
 * thing that makes the normal completion path work at all: there is no
 * later turn on which this context could otherwise be reclaimed. */
static void proxy_on_relay_done(cloak_stream_relay_t *sr, void *userdata) {
    (void)sr;
    cloak_proxy_stream_t *pst = userdata;
    pst->relaying = 0;
    proxy_stream_teardown(pst);
}

static void proxy_on_dial_done(cloak_dial_t *d, int fd, void *userdata) {
    (void)d;
    cloak_proxy_stream_t *pst = userdata;

    /* FIRST, before anything that could reach proxy_stream_teardown:
     * cloak/net.h forbids calling cloak_dial_cancel from within the dial
     * callback -- the callback IS the completion, there is nothing left
     * to cancel -- and the teardown walk cancels whenever this flag is
     * set. */
    pst->dialing = 0;

    if (fd < 0) {
        /* The connect failed or timed out; the dial has already closed
         * its own socket. One stream dies, the session does not. */
        proxy_stream_teardown(pst);
        return;
    }

    pst->fd_pending = fd;
    pst->retries = 0;
    proxy_try_start_relay(pst);
}

/* ---- session callbacks --------------------------------------------------- */

static void proxy_on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    cloak_proxy_session_t *ps = userdata;
    if (ps == NULL || sesh == NULL || stream == NULL) {
        return;
    }
    if (ps->sesh == NULL) {
        /* THE ONLY PLACE ps->sesh IS EVER SET. Taking the session from
         * the callback that is handing over one of its streams needs no
         * ordering assumption and no second callback: this fires strictly
         * before anything in this module could want the pointer, because
         * everything that wants it wants it for a stream. */
        ps->sesh = sesh;
    }
    cloak_proxy_t *p = ps->p;

    /* THE CAPS, and they are checked HERE -- before a context is
     * allocated, before a descriptor is asked for, before anything is
     * registered with the reactor -- because a cap enforced any later
     * would already have spent the resource it exists to protect.
     *
     * Both are counted off the two counters that track THE CONTEXTS THAT
     * EXIST, so a stream refused right here never counted against them
     * and a stream that ends gives its share back the instant its context
     * is freed. The give-back is not conditional on which path ended it:
     * proxy_stream_teardown is the only function that frees a
     * cloak_proxy_stream_t, and it unlinks -- decrementing both counters
     * -- immediately before the free, so every caller of it (the relay's
     * done callback, dial failure, a permanent or exhausted relay start,
     * the broken/aborted/destroy walk) decrements by construction rather
     * than by remembering to.
     *
     * Releasing the stream is this module's whole response: it is legal
     * from within on_new_stream (cloak/session.h), it performs the active
     * close itself so the client learns immediately rather than waiting
     * out a timeout, and it touches nothing else on the session. The
     * client's extra streams degrade; the server's ability to dial its
     * own cover-site redirect -- which is what an exhausted descriptor
     * table would actually cost -- does not. See
     * cloak_proxy_config_t::max_streams_total. */
    if (p->stream_count >= p->cfg.max_streams_total) {
        /* Checked before the per-session cap because it is the server-wide
         * condition: an operator seeing only "session N is capped" when
         * the whole proxy is full would be told the less useful of the two
         * facts. One line per episode, never one per refusal -- see
         * cloak_proxy_t::total_capped. */
        if (!p->total_capped) {
            p->total_capped = 1;
            CLOAK_LOGW("proxy: refusing new streams -- total cap of %zu reached; descriptors "
                       "beyond it are reserved so the dispatcher can still dial its cover-site "
                       "redirects",
                       p->cfg.max_streams_total);
        }
        cloak_session_release_stream(sesh, stream);
        return;
    }
    if (ps->stream_count >= p->cfg.max_streams_per_session) {
        if (!ps->capped) {
            ps->capped = 1;
            CLOAK_LOGW("proxy: refusing new streams for session %u -- per-session cap of %zu "
                       "reached; other sessions are unaffected",
                       ps->session_id, p->cfg.max_streams_per_session);
        }
        cloak_session_release_stream(sesh, stream);
        return;
    }

    cloak_proxy_stream_t *pst = calloc(1, sizeof(*pst));
    if (pst == NULL) {
        /* cloak/session.h:26-32 explicitly permits releasing the stream
         * from within this callback; release performs the active close
         * itself, so the peer still learns. */
        cloak_session_release_stream(sesh, stream);
        return;
    }
    pst->ps = ps;
    pst->stream = stream;
    pst->fd_pending = -1;
    pst->retry_timer = CLOAK_TIMER_INVALID;
    proxy_stream_link(ps, pst);

    /* Deliberately NOT reading the stream here. Bytes that arrived with
     * the frame that revealed this stream are already sitting in its
     * receive buffer, and cloak_stream_relay_start's own initial pump is
     * what drains them -- consuming them here would strand them. */
    char err[128];
    err[0] = '\0';
    if (cloak_dial_start(&pst->dial, p->cfg.reactor, ps->upstream, p->cfg.dial_timeout_ms,
                         proxy_on_dial_done, pst, err, sizeof(err)) != 0) {
        /* cloak_dial_start closes its own socket on every failure path
         * and never fires the callback, so this owns nothing. */
        proxy_stream_teardown(pst);
        return;
    }
    pst->dialing = 1;
}

static void proxy_on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    cloak_proxy_session_t *ps = userdata;
    if (ps == NULL || stream == NULL) {
        return;
    }

    /* A LINEAR SCAN IS THE RIGHT STRUCTURE HERE, and the next reader will
     * wonder whether it should be a hash table: a single session's live
     * stream count is small (a browser's worth of concurrent connections,
     * not a server's), and Go Cloak indexes this no better. Replacing it
     * would add a second structure to keep in step with the list during
     * teardown -- the exact place this module is most fragile -- to save
     * a handful of pointer comparisons.
     *
     * next is saved before the notify because
     * cloak_stream_relay_notify_stream_data CAN tear the relay down and
     * fire on_done (stream_relay.c's notify path), which frees pst. The
     * early return below means this particular loop would survive without
     * it; it is written this way anyway so that the pattern is identical
     * in both notify loops and cannot rot if the early return ever goes. */
    cloak_proxy_stream_t *pst = ps->streams;
    while (pst != NULL) {
        cloak_proxy_stream_t *next = pst->next;
        if (pst->stream == stream) {
            /* A stream still dialing or waiting on a retry has no relay
             * yet and needs no notification: its data waits in its own
             * receive buffer and the relay's initial pump collects it. */
            if (pst->relaying) {
                cloak_stream_relay_notify_stream_data(&pst->relay);
            }
            return; /* pst may already be freed */
        }
        pst = next;
    }
}

static void proxy_on_writable(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    cloak_proxy_session_t *ps = userdata;
    if (ps == NULL) {
        return;
    }

    /* THE SESSION'S STREAMS DO NOT COORDINATE, and this is the one place
     * in the code where that is visible. The session's outbound pool
     * drained by some amount; every relay bound to it is told, and each
     * independently re-checks its own budget (cloak_session_send_min_conn_
     * free) and re-arms read interest if it can. Nothing divides the
     * newly freed space between them, so a stream whose relay happens to
     * be notified first can consume all of it and the ones after it find
     * none -- repeatedly, since this list's order is stable. For bulk
     * transfers that is unfairness, not starvation (the greedy stream's
     * own reads stop at its budget and the next drain notifies everyone
     * again), but it IS unfairness. A fix would be a per-session
     * round-robin cursor into this list, advanced one position per
     * on_writable, so the stream that gets first refusal rotates; it is
     * not done here because nothing in this module yet measures whether
     * the unfairness is observable.
     *
     * next is saved before each notify for the same reason as in
     * proxy_on_stream_data. cloak_stream_relay_notify_writable does not
     * itself tear a relay down today -- it only re-arms interest -- but
     * that asymmetry with notify_stream_data is exactly the kind that
     * changes under a later edit to stream_relay.c, and saving next costs
     * nothing. */
    cloak_proxy_stream_t *pst = ps->streams;
    while (pst != NULL) {
        cloak_proxy_stream_t *next = pst->next;
        if (pst->relaying) {
            cloak_stream_relay_notify_writable(&pst->relay);
        }
        pst = next;
    }
}

/* ---- public entry points -------------------------------------------------- */

int cloak_proxy_init(cloak_proxy_t *p, const cloak_proxy_config_t *cfg) {
    if (p == NULL) {
        return -1;
    }
    /* Fully initialize BEFORE validating anything else, so that every
     * failure return leaves p safe to pass to cloak_proxy_destroy -- the
     * same ordering cloak_dispatcher_init documents and for the same
     * reason. */
    memset(p, 0, sizeof(*p));

    if (cfg == NULL || cfg->reactor == NULL || cfg->srv == NULL) {
        return -1;
    }

    p->cfg = *cfg;
    if (p->cfg.relay_buf_cap == 0) {
        p->cfg.relay_buf_cap = CLOAK_PROXY_DEFAULT_RELAY_BUF_CAP;
    }
    if (p->cfg.dial_timeout_ms == 0) {
        p->cfg.dial_timeout_ms = CLOAK_PROXY_DEFAULT_DIAL_TIMEOUT_MS;
    }
    if (p->cfg.retry_delay_ms == 0) {
        p->cfg.retry_delay_ms = CLOAK_PROXY_DEFAULT_RETRY_DELAY_MS;
    }
    if (p->cfg.max_retries == 0) {
        p->cfg.max_retries = CLOAK_PROXY_DEFAULT_MAX_RETRIES;
    }
    if (p->cfg.max_streams_per_session == 0) {
        p->cfg.max_streams_per_session = CLOAK_PROXY_DEFAULT_MAX_STREAMS_PER_SESSION;
    }
    if (p->cfg.max_streams_total == 0) {
        /* DERIVED, not a constant: see the two CLOAK_PROXY_MAX_STREAMS_
         * TOTAL_* constants for why a fixed number is inert on exactly the
         * hosts that need this cap. An explicit non-zero value is honoured
         * verbatim and never reaches here. */
        p->cfg.max_streams_total = proxy_derive_max_streams_total();
    }
    return 0;
}

void cloak_proxy_destroy(cloak_proxy_t *p) {
    if (p == NULL) {
        return;
    }
    /* Idempotent and safe on a zeroed struct for the same reason: a
     * zeroed (or already-drained) proxy has no sessions, so this loop
     * does not run and nothing below it touches the borrowed reactor. */
    while (p->sessions != NULL) {
        proxy_session_teardown(p->sessions);
    }
}

int cloak_proxy_prepare_session(cloak_dispatcher_t *d, const cloak_server_clientinfo_t *info,
                                 cloak_session_config_t *config, void *userdata) {
    (void)d;
    cloak_proxy_t *p = userdata;
    if (p == NULL || info == NULL || config == NULL) {
        return -1;
    }

    /* Obligation 5. See this function's doc comment in cloak/proxy.h for
     * why a create-path check is the COMPLETE check, and why a redirect
     * (rather than a stream that would quietly mangle the client's
     * datagrams) is the right answer. */
    if (info->unordered) {
        return -1;
    }

    const cloak_addr_t *upstream = cloak_server_lookup_proxy(p->cfg.srv, info->proxy_method);
    if (upstream == NULL) {
        /* TWO WAYS TO GET HERE, and neither may dereference NULL.
         *
         * 1. AN ADMIN SESSION ROUTED TO THE PROXY. dispatcher.c's step 7
         *    deliberately does NOT check the proxy method of an admin
         *    session (its step 6a explains why: a real `ck-client -a`
         *    sends whatever method its config names), so an owner with no
         *    cloak_adminapi_t -- every caller written before that module
         *    existed -- hands such a connection here with a method this
         *    server may well not offer. Refusing it is the right answer
         *    and the pre-existing one: the -1 redirects the connection to
         *    the cover site exactly as the dispatcher's own check did
         *    before.
         * 2. A caller bug: this proxy and that dispatcher were handed
         *    different cloak_server_t instances.
         *
         * Either way, degrade to a redirect. */
        return -1;
    }
    if (upstream->socktype != SOCK_STREAM) {
        /* A ProxyBook entry declared "udp". cloak_stream_relay_t splices
         * a stream with a stream socket and has no way to preserve
         * datagram boundaries; datagram upstreams are out of scope for
         * this module, so nothing here half-works silently. */
        return -1;
    }

    cloak_proxy_session_t *ps = calloc(1, sizeof(*ps));
    if (ps == NULL) {
        return -1;
    }
    ps->p = p;
    ps->sesh = NULL; /* proxy_on_new_stream records it with the first stream */
    ps->upstream = upstream;
    /* The only handle this context can be found by until -- and, on
     * every path that abandons the handshake, ever. See
     * proxy_find_session. */
    memcpy(ps->uid, info->uid, CLOAK_UID_LEN);
    ps->session_id = info->session_id;
    proxy_session_link(p, ps);

    config->on_new_stream = proxy_on_new_stream;
    config->on_new_stream_userdata = ps;
    config->on_stream_data = proxy_on_stream_data;
    config->on_stream_data_userdata = ps;
    config->on_writable = proxy_on_writable;
    config->on_writable_userdata = ps;
    /* on_broken and on_broken_userdata are deliberately untouched --
     * cloak_server_registry_get_or_create overwrites both regardless. */
    return 0;
}

void cloak_proxy_registry_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                 const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                 void *userdata) {
    cloak_proxy_t *p = userdata;
    if (p == NULL) {
        /* Not this module's callback at all; there is not even a chain to
         * reach from here. */
        return;
    }

    /* OBLIGATION 1, and the only window in which it can be met: sesh is
     * still fully usable right now, and every stream still active when
     * this returns is destroyed and freed by the session itself. So the
     * whole walk -- stop the relay, THEN release the stream, for every
     * stream on this session -- happens before anything else, including
     * before the chain. proxy_session_teardown is that walk; see
     * proxy_stream_teardown for why the two steps are in that order and
     * nowhere else in this module for a second copy of it. */
    if (uid != NULL) {
        cloak_proxy_session_t *ps = proxy_find_session(p, uid, session_id);
        if (ps != NULL) {
            proxy_session_teardown(ps);
        }
        /* No context is not an error: this session was created by
         * something other than cloak_proxy_prepare_session, or that
         * callback returned -1 and nothing was ever prepared. Fall
         * through to the chain. */
    }

    /* AFTER the cleanup, never before. cloak/registry.h permits a
     * callback in this position to call cloak_server_registry_destroy --
     * including on the registry that is mid-teardown -- which destroys
     * every session still in the table. If any relay of ours were still
     * running at that point it would outlive its session by exactly one
     * callback. */
    if (p->cfg.chain != NULL) {
        p->cfg.chain(reg, sesh, uid, session_id, p->cfg.chain_userdata);
    }
}

void cloak_proxy_session_aborted(cloak_dispatcher_t *d, const uint8_t uid[CLOAK_UID_LEN],
                                 uint32_t session_id, void *userdata) {
    (void)d;
    cloak_proxy_t *p = userdata;
    if (p == NULL || uid == NULL) {
        return;
    }

    /* The handshake that prepared this context never produced a session
     * that will ever break, so this is the only notification that will
     * ever arrive for it and the context leaks without it. At all three
     * of the dispatcher's sites ps->sesh is NULL and ps holds no streams,
     * so the shared walk degenerates to an unlink and a free -- it is
     * still the shared walk, deliberately: a second, "simpler" copy of
     * the teardown here is exactly how the two would drift apart if a
     * later change ever made one of those sites reachable with a stream
     * in flight. */
    cloak_proxy_session_t *ps = proxy_find_session(p, uid, session_id);
    if (ps != NULL) {
        proxy_session_teardown(ps);
    }
}

size_t cloak_proxy_session_count(const cloak_proxy_t *p) {
    return p == NULL ? 0 : p->session_count;
}

size_t cloak_proxy_stream_count(const cloak_proxy_t *p) {
    return p == NULL ? 0 : p->stream_count;
}

size_t cloak_proxy_max_streams_total(const cloak_proxy_t *p) {
    return p == NULL ? 0 : p->cfg.max_streams_total;
}
