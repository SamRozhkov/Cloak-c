#define _POSIX_C_SOURCE 200809L
#include "cloak/proxy.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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
}

/* ---- teardown ------------------------------------------------------------
 *
 * THE ONE COPY. A later task adds a registry-broken entry point that has
 * to perform exactly this walk before the session's storage goes away,
 * differing only in what it does afterwards. Two copies of the most
 * lifetime-sensitive code in this module drifting apart is the worst
 * outcome available here, so there is deliberately one: both
 * cloak_proxy_destroy and that future entry point call these. */

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
        /* Closes the stream and the relay's fd; deliberately does NOT
         * fire on_done, and deliberately does NOT release the stream --
         * cloak/stream_relay.h is explicit that releasing is ours. */
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
    while (ps->streams != NULL) {
        proxy_stream_teardown(ps->streams);
    }
    proxy_session_unlink(ps->p, ps);
    free(ps);
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
        /* cloak_proxy_attached normally gets here first, but taking the
         * session from the callback that is handing us one of its streams
         * costs nothing and removes the ordering assumption entirely. */
        ps->sesh = sesh;
    }
    cloak_proxy_t *p = ps->p;

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
        /* A caller bug, not an attacker: the dispatcher already rejected
         * unknown proxy methods before reaching here, so this means this
         * proxy and that dispatcher were handed different cloak_server_t
         * instances. Degrade to a redirect rather than dereference NULL. */
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
    ps->sesh = NULL; /* cloak_proxy_attached joins the two */
    ps->upstream = upstream;
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

void cloak_proxy_attached(cloak_dispatcher_t *d, cloak_session_t *sesh,
                          const cloak_server_clientinfo_t *info, int created, void *userdata) {
    (void)d;
    (void)info;
    cloak_proxy_t *p = userdata;
    if (p == NULL || sesh == NULL || !created) {
        /* created == 0 means this connection merely joined a session that
         * already exists -- its context already has its session, and
         * there is nothing to prepare or record. */
        return;
    }

    /* Recover the context cloak_proxy_prepare_session allocated for THIS
     * session. cloak/registry.h guarantees on_new_stream and its userdata
     * are passed through to cloak_session_init untouched, so the session
     * itself is the record of which context it was built from -- exact,
     * where scanning p->sessions for "the one without a session yet"
     * would be ambiguous whenever two creations are in flight at once (a
     * reply write that hit EAGAIN defers hand-off across reactor turns).
     * The callback identity is checked too, so a session someone else
     * configured can never be mistaken for one of ours. */
    if (sesh->on_new_stream != proxy_on_new_stream) {
        return;
    }
    cloak_proxy_session_t *ps = sesh->on_new_stream_userdata;
    if (ps == NULL || ps->p != p) {
        return;
    }
    if (ps->sesh == NULL) {
        ps->sesh = sesh;
    }
}

size_t cloak_proxy_session_count(const cloak_proxy_t *p) {
    return p == NULL ? 0 : p->session_count;
}

size_t cloak_proxy_stream_count(const cloak_proxy_t *p) {
    return p == NULL ? 0 : p->stream_count;
}
