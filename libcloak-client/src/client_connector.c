#define _POSIX_C_SOURCE 200809L

#include "cloak/client_connector.h"

#include "cloak/common.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* cloak_client_connector_t -- N handshakes into one session.
 *
 * THE SHAPE, and the one invariant everything else rests on. Every
 * resource this object can hold is held by exactly one named field of one
 * cloak_client_connector_conn_t, and each has exactly one release site:
 *
 *   conn->retry_timer   cancelled in conn_release
 *   conn->dial          cancelled in conn_release (cloak_dial_cancel
 *                       closes the dial's own socket; we never see it)
 *   conn->hs            destroyed in conn_release (it never owns an fd,
 *                       by cloak/client_transport.h's contract)
 *   conn->fd            closed in conn_release, and set to -1 the instant
 *                       anything else takes ownership of it
 *   c->kickoff_timer    cancelled in connector_release
 *   c->conns            freed in cloak_client_connector_destroy
 *   c->session          destroyed ONLY while c->session_owned is 1
 *
 * conn_release is idempotent, connector_release calls it for every
 * connection, and every failure path plus destroy goes through
 * connector_release. That is what makes "torn down at any point closes
 * every fd exactly once" a property of the structure rather than a claim
 * about a set of code paths -- which matters, because the points at which
 * a teardown can land are the cross product of N connections' states.
 *
 * THE CALLBACK DISCIPLINE is the same one client_transport.c uses and for
 * the same reason: `fail`/`succeed` only record the outcome and release
 * resources, and `finish` -- which actually invokes on_done -- is the LAST
 * statement of every function the reactor can call into this file. A
 * caller is therefore free to destroy or free the connector from inside
 * on_done, because nothing here touches it afterwards. */

/* ---- small helpers ------------------------------------------------------ */

static int64_t connector_now(const cloak_client_connector_t *c) {
    if (c->now_fn != NULL) {
        return c->now_fn(c->now_userdata);
    }
    return (int64_t)time(NULL);
}

/* D2's backoff: base * 2^(attempt-1), capped, then jittered by +/-25%
 * AROUND that value -- symmetric, so the mean is the nominal interval and
 * the schedule the header documents is the schedule that happens. See
 * cloak/client_connector.h for why the jitter exists at all (a
 * thundering-herd argument, and only that) and why it is not one-sided.
 *
 * The jitter draws a single byte and scales, rather than reducing a wide
 * random value modulo the interval: the quantity being randomised is a
 * delay in milliseconds whose exact distribution matters not at all (only
 * that N connections stop retrying in lockstep), so 1/256 granularity is
 * ample and the byte-wide draw stays consistent with how the rest of this
 * tree spends randomness on non-observable quantities. */
static uint64_t backoff_ms(const cloak_client_connector_t *c, int attempt) {
    uint64_t delay = c->retry_base_ms;
    for (int i = 1; i < attempt && delay < CLOAK_CLIENT_CONNECTOR_MAX_RETRY_DELAY_MS; i++) {
        delay *= 2;
    }
    if (delay > CLOAK_CLIENT_CONNECTOR_MAX_RETRY_DELAY_MS) {
        delay = CLOAK_CLIENT_CONNECTOR_MAX_RETRY_DELAY_MS;
    }
    uint8_t r = 0;
    cloak_random_bytes(&r, 1);
    /* [delay - delay/4, delay + delay/4), centred on delay. */
    uint64_t span = delay / 4u;
    return delay - span + (2u * span) * (uint64_t)r / 256u;
}

/* Releases everything one connection holds. Idempotent, and the ONLY
 * place any of it is released -- see this file's header. */
static void conn_release(cloak_client_connector_conn_t *conn) {
    cloak_client_connector_t *c = conn->owner;
    if (conn->retry_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(c->reactor, conn->retry_timer);
        conn->retry_timer = CLOAK_TIMER_INVALID;
    }
    if (conn->dial_active) {
        /* cloak_dial_cancel closes the socket it was connecting and
         * guarantees the callback will not fire. The fd never reached
         * conn->fd, so there is nothing here to double-close. */
        cloak_dial_cancel(&conn->dial);
        conn->dial_active = 0;
    }
    if (conn->hs_active) {
        /* Deregisters the fd and cancels the deadline; never closes the
         * fd, which is why conn->fd below is still ours to close. */
        cloak_client_handshake_destroy(&conn->hs);
        conn->hs_active = 0;
    }
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

static void connector_release(cloak_client_connector_t *c) {
    if (c->kickoff_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(c->reactor, c->kickoff_timer);
        c->kickoff_timer = CLOAK_TIMER_INVALID;
    }
    if (c->conns != NULL) {
        for (int i = 0; i < c->num_conn; i++) {
            conn_release(&c->conns[i]);
        }
    }
}

/* Records a terminal failure and releases everything. Deliberately does
 * NOT fire on_done -- see this file's header. */
static void fail(cloak_client_connector_t *c, cloak_client_connector_error_t err) {
    if (c->status != CLOAK_CLIENT_CONNECTOR_PENDING) {
        return;
    }
    c->status = CLOAK_CLIENT_CONNECTOR_FAILED;
    c->error = err;
    connector_release(c);
    if (c->session_owned) {
        /* A session that got as far as cloak_session_init but that the
         * caller has never been shown. Destroying it closes every
         * connection already attached to it; the ones that never made it
         * in were closed by connector_release just above. */
        cloak_session_destroy(c->session);
        c->session_owned = 0;
    }
}

/* MUST be the last statement of any function the reactor can call into
 * this file: c may be destroyed or freed by on_done. */
static void finish(cloak_client_connector_t *c) {
    if (c->status == CLOAK_CLIENT_CONNECTOR_PENDING || c->notified) {
        return;
    }
    c->notified = 1;
    if (c->on_done != NULL) {
        cloak_session_t *sesh = c->status == CLOAK_CLIENT_CONNECTOR_DONE ? c->session : NULL;
        c->on_done(c, c->status, sesh, c->on_done_userdata);
    }
}

/* ---- assembling the session -------------------------------------------- */

/* D4: every connection must have recovered the same session key. See
 * cloak/client_connector.h's cloak_client_connector_init comment for why
 * this exists at all when the reference implementation simply takes the
 * last one. */
static int keys_agree(const cloak_client_connector_t *c) {
    for (int i = 1; i < c->num_conn; i++) {
        if (memcmp(c->conns[i].key, c->conns[0].key, CLOAK_AEAD_KEY_LEN) != 0) {
            return 0;
        }
    }
    return 1;
}

/* All N connections have handshaken. Check the keys, build the session,
 * and hand every socket to it. Does not fire on_done; the caller does. */
static void assemble(cloak_client_connector_t *c) {
    if (!keys_agree(c)) {
        fail(c, CLOAK_CLIENT_CONNECTOR_ERR_KEY_MISMATCH);
        return;
    }

    cloak_session_config_t scfg = c->session_template;
    scfg.obfuscator.method = (cloak_aead_method_t)c->encryption_method;
    memcpy(scfg.obfuscator.session_key, c->conns[0].key, CLOAK_AEAD_KEY_LEN);

    if (cloak_session_init(c->session, c->session_id, c->reactor, &scfg) != 0) {
        fail(c, CLOAK_CLIENT_CONNECTOR_ERR_SESSION);
        return;
    }
    c->session_owned = 1;

    for (int i = 0; i < c->num_conn; i++) {
        if (cloak_session_add_conn(c->session, c->conns[i].fd) != 0) {
            /* cloak_session_add_conn's contract: on failure the caller
             * still owns fd. Leaving it in conn->fd is exactly right --
             * fail() -> connector_release() -> conn_release() closes it,
             * along with every connection that never got this far, and
             * cloak_session_destroy closes the ones already attached. */
            fail(c, CLOAK_CLIENT_CONNECTOR_ERR_SESSION);
            return;
        }
        c->conns[i].fd = -1; /* the session owns it now */
    }

    c->status = CLOAK_CLIENT_CONNECTOR_DONE;
    c->error = CLOAK_CLIENT_CONNECTOR_ERR_NONE;
    /* Ownership of the session passes to the caller at the moment it is
     * reported; from here this object must never touch it again, not even
     * from destroy. */
    c->session_owned = 0;
    connector_release(c);
}

/* ---- one connection's attempt loop ------------------------------------- */

static void start_attempt(cloak_client_connector_conn_t *conn);
static void on_retry(cloak_reactor_t *r, void *userdata);

/* D2: back off and try again, or give up and fail the whole session.
 * err is what to report if this was the last attempt.
 *
 * ONE CONNECTION EXHAUSTING ITS ATTEMPTS FAILS THE WHOLE SESSION, which
 * is the right reading of Go: there, every goroutine must reach
 * wg.Done(), so a connection that never succeeds means MakeSession never
 * returns. A session brought up with fewer connections than configured
 * would be a silent downgrade of the very property NumConn exists to
 * provide. */
static void retry_or_fail(cloak_client_connector_conn_t *conn,
                          cloak_client_connector_error_t err) {
    cloak_client_connector_t *c = conn->owner;
    if (conn->attempts >= c->max_attempts) {
        fail(c, err);
        return;
    }
    conn->retry_timer =
        cloak_reactor_add_timer(c->reactor, backoff_ms(c, conn->attempts), on_retry, conn);
    if (conn->retry_timer == CLOAK_TIMER_INVALID) {
        fail(c, CLOAK_CLIENT_CONNECTOR_ERR_INTERNAL);
    }
}

static void on_retry(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_client_connector_conn_t *conn = userdata;
    cloak_client_connector_t *c = conn->owner;
    conn->retry_timer = CLOAK_TIMER_INVALID; /* it has fired; never cancel it again */
    if (c->status == CLOAK_CLIENT_CONNECTOR_PENDING) {
        start_attempt(conn);
    }
    finish(c); /* last statement: c may be freed by on_done */
}

static void on_handshake_done(cloak_client_handshake_t *h,
                              cloak_client_handshake_status_t status, void *userdata) {
    cloak_client_connector_conn_t *conn = userdata;
    cloak_client_connector_t *c = conn->owner;
    conn->hs_active = 0;

    if (c->status != CLOAK_CLIENT_CONNECTOR_PENDING) {
        /* The connector already failed or was torn down under us in this
         * same dispatch. conn->fd is still ours; release it. */
        conn_release(conn);
        return;
    }

    if (status == CLOAK_CLIENT_HANDSHAKE_DONE) {
        const uint8_t *key = cloak_client_handshake_session_key(h);
        if (key == NULL) {
            /* Cannot happen per the handshake's contract; treated as a
             * handshake failure rather than trusted, because the
             * alternative is memcpy from NULL. */
            c->last_handshake_error = CLOAK_CLIENT_HANDSHAKE_ERR_PROTOCOL;
            close(conn->fd);
            conn->fd = -1;
            retry_or_fail(conn, CLOAK_CLIENT_CONNECTOR_ERR_HANDSHAKE);
            finish(c);
            return;
        }
        memcpy(conn->key, key, CLOAK_AEAD_KEY_LEN);
        conn->have_key = 1;
        conn->done = 1;
        c->completed++;
        /* conn->fd stays ours until assemble hands it to the session. */
        if (c->completed == c->num_conn) {
            assemble(c);
        }
        finish(c); /* last statement: c may be freed by on_done */
        return;
    }

    c->last_handshake_error = cloak_client_handshake_error(h);
    close(conn->fd);
    conn->fd = -1;

    /* D3: the Chrome-to-Firefox fallback. Per connection and sticky for
     * its remaining attempts, exactly as Go mutates its goroutine's own
     * copy of transportConfig. The reason is in the header, on
     * cloak_client_connector_conn_t::browser, and it is load-bearing:
     * this port's Chrome ClientHello is 1720 bytes and some networks drop
     * a first packet over 1500. Do not remove this as superstition. */
    /* The transport conjunct CANNOT currently be false: cloak_client_connector_init
     * rejects every non-direct transport, so a CDN connector never exists
     * to reach this line. It is kept, and annotated rather than deleted,
     * for the same reason cloak/client_transport.h keeps its third reply
     * bound -- it guards the CONFIGURATION SPACE, not the wire, and it is
     * the half of Go's condition that stops being vacuous the day a
     * WebSocket transport lands (a CDN's first packet is an HTTP upgrade,
     * not a ClientHello, so falling back on it would be meaningless).
     * Structurally dead today; not superstition, and not removable
     * without also removing the note in init that pairs with it. */
    if (c->transport == CLOAK_TRANSPORT_DIRECT && conn->browser == CLOAK_CLIENT_BROWSER_CHROME) {
        conn->browser = CLOAK_CLIENT_BROWSER_FIREFOX;
    }

    retry_or_fail(conn, CLOAK_CLIENT_CONNECTOR_ERR_HANDSHAKE);
    finish(c); /* last statement: c may be freed by on_done */
}

static void on_dial_done(cloak_dial_t *d, int fd, void *userdata) {
    (void)d;
    cloak_client_connector_conn_t *conn = userdata;
    cloak_client_connector_t *c = conn->owner;
    conn->dial_active = 0;

    if (c->status != CLOAK_CLIENT_CONNECTOR_PENDING) {
        /* Another connection failed the whole session in this same
         * dispatch batch. Ownership of fd passed to this callback, so it
         * is ours to close. */
        if (fd >= 0) {
            close(fd);
        }
        return;
    }

    if (fd < 0) {
        retry_or_fail(conn, CLOAK_CLIENT_CONNECTOR_ERR_DIAL);
        finish(c); /* last statement: c may be freed by on_done */
        return;
    }

    conn->fd = fd;

    cloak_client_handshake_config_t hcfg;
    memset(&hcfg, 0, sizeof(hcfg));
    hcfg.reactor = c->reactor;
    hcfg.fd = fd;
    hcfg.browser = conn->browser;
    hcfg.server_name = c->server_name;
    memcpy(hcfg.server_pub, c->server_pub, CLOAK_X25519_KEY_LEN);
    memcpy(hcfg.uid, c->uid, CLOAK_UID_LEN);
    hcfg.proxy_method = c->proxy_method;
    hcfg.encryption_method = c->encryption_method;
    hcfg.session_id = c->session_id;
    hcfg.unordered = c->unordered;
    /* Stamped now, not when the connector was constructed: the server
     * checks this against its own clock, and a backoff of several seconds
     * would have made a captured value stale. */
    hcfg.now_unix = connector_now(c);
    hcfg.timeout_ms = c->handshake_timeout_ms;
    hcfg.on_done = on_handshake_done;
    hcfg.on_done_userdata = conn;

    if (cloak_client_handshake_init(&conn->hs, &hcfg) != 0) {
        /* CONFIG or BUILD: our own arguments, or an OpenSSL-level
         * failure. Neither is transient, so this is NOT retried -- five
         * attempts at a ClientHello that cannot be built is five times
         * the delay before the caller learns what is actually wrong. */
        c->last_handshake_error = cloak_client_handshake_error(&conn->hs);
        close(conn->fd);
        conn->fd = -1;
        fail(c, CLOAK_CLIENT_CONNECTOR_ERR_HANDSHAKE);
        finish(c); /* last statement: c may be freed by on_done */
        return;
    }
    if (cloak_client_handshake_start(&conn->hs) != 0) {
        /* A reactor registration failure, which CAN be transient (the fd
         * table, or a collision with a descriptor this reactor has not
         * yet reaped), so this one does retry. on_done will not fire for
         * this handshake -- start says so -- and it owns nothing. */
        c->last_handshake_error = cloak_client_handshake_error(&conn->hs);
        cloak_client_handshake_destroy(&conn->hs);
        close(conn->fd);
        conn->fd = -1;
        retry_or_fail(conn, CLOAK_CLIENT_CONNECTOR_ERR_HANDSHAKE);
        finish(c); /* last statement: c may be freed by on_done */
        return;
    }
    conn->hs_active = 1;
    finish(c); /* last statement: a no-op while PENDING, kept for uniformity */
}

static void start_attempt(cloak_client_connector_conn_t *conn) {
    cloak_client_connector_t *c = conn->owner;
    char err[256];

    conn->attempts++;
    c->total_attempts++;

    if (cloak_dial_start(&conn->dial, c->reactor, &c->remote, c->dial_timeout_ms, on_dial_done,
                         conn, err, sizeof(err)) != 0) {
        /* A synchronous connect() error (ENETUNREACH, EACCES,
         * EADDRNOTAVAIL) or a socket()/registration failure. No callback
         * will come and the socket is already closed by cloak_dial_start
         * itself, so the retry path is entered directly. */
        retry_or_fail(conn, CLOAK_CLIENT_CONNECTOR_ERR_DIAL);
        return;
    }
    conn->dial_active = 1;
}

/* Every connection's first attempt, deferred by one reactor turn. This is
 * what makes on_done's "never from inside start" guarantee structural:
 * every path to a completion, success or failure, begins here or in a
 * later reactor callback. */
static void on_kickoff(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_client_connector_t *c = userdata;
    c->kickoff_timer = CLOAK_TIMER_INVALID; /* it has fired */
    for (int i = 0; i < c->num_conn && c->status == CLOAK_CLIENT_CONNECTOR_PENDING; i++) {
        start_attempt(&c->conns[i]);
    }
    finish(c); /* last statement: c may be freed by on_done */
}

/* ---- construction ------------------------------------------------------- */

int cloak_client_connector_init(cloak_client_connector_t *c,
                                const cloak_client_connector_config_t *cfg) {
    if (c == NULL) {
        return -1;
    }
    /* Fully initialized BEFORE anything is validated, so every rejected
     * call still leaves c safe for cloak_client_connector_destroy. Note
     * that a zeroed struct is NOT already safe here: fd 0 is a real
     * descriptor, so the sentinels below matter, and destroy additionally
     * guards on reactor == NULL for the case where init bailed before
     * setting them. */
    memset(c, 0, sizeof(*c));
    c->kickoff_timer = CLOAK_TIMER_INVALID;
    c->status = CLOAK_CLIENT_CONNECTOR_FAILED;
    c->error = CLOAK_CLIENT_CONNECTOR_ERR_CONFIG;
    c->notified = 1; /* a never-started connector must never fire on_done */

    if (cfg == NULL || cfg->reactor == NULL || cfg->session == NULL || cfg->on_done == NULL ||
        cfg->server_name == NULL || cfg->proxy_method == NULL) {
        return -1;
    }
    if (cfg->num_conn < 1 || cfg->num_conn > CLOAK_CLIENT_CONNECTOR_MAX_CONN) {
        return -1;
    }
    if (cfg->remote.len == 0) {
        return -1;
    }
    /* Only direct TLS exists in this port. A CDN/WebSocket configuration
     * is refused rather than silently carried over a transport the
     * operator did not ask for -- which on a censored network is the
     * difference between "did not connect" and "connected visibly". */
    if (cfg->transport != CLOAK_TRANSPORT_DIRECT) {
        return -1;
    }
    /* NOTE, paired with on_handshake_done's D3 guard: this rejection is
     * what makes that guard's transport conjunct structurally unreachable.
     * If this ever admits another transport, that conjunct becomes live. */
    /* Checked here rather than left to cloak_client_handshake_init, which
     * would report it once per attempt as a non-retryable handshake
     * failure. An over-long SNI is a configuration error and says so. */
    size_t sn_len = strlen(cfg->server_name);
    if (sn_len == 0 || sn_len > CLOAK_CLIENT_SERVER_NAME_MAX) {
        return -1;
    }
    if (strlen(cfg->proxy_method) > CLOAK_PROXY_METHOD_LEN) {
        return -1;
    }
    if (cfg->max_attempts < 0) {
        return -1;
    }

    c->reactor = cfg->reactor;
    c->remote = cfg->remote;
    c->num_conn = cfg->num_conn;
    c->session = cfg->session;

    memcpy(c->server_name, cfg->server_name, sn_len + 1);
    memcpy(c->proxy_method, cfg->proxy_method, strlen(cfg->proxy_method) + 1);
    memcpy(c->server_pub, cfg->server_pub, CLOAK_X25519_KEY_LEN);
    memcpy(c->uid, cfg->uid, CLOAK_UID_LEN);
    c->encryption_method = cfg->encryption_method;
    c->session_id = cfg->session_id;
    c->unordered = cfg->unordered;
    c->browser = cfg->browser;
    c->transport = cfg->transport;

    c->dial_timeout_ms = cfg->dial_timeout_ms != 0
                             ? cfg->dial_timeout_ms
                             : (uint64_t)CLOAK_CLIENT_CONNECTOR_DEFAULT_DIAL_TIMEOUT_MS;
    c->handshake_timeout_ms = cfg->handshake_timeout_ms;
    c->max_attempts =
        cfg->max_attempts != 0 ? cfg->max_attempts : CLOAK_CLIENT_CONNECTOR_DEFAULT_MAX_ATTEMPTS;
    c->retry_base_ms = cfg->retry_base_ms != 0
                           ? cfg->retry_base_ms
                           : (uint64_t)CLOAK_CLIENT_CONNECTOR_DEFAULT_RETRY_BASE_MS;

    c->now_fn = cfg->now_fn;
    c->now_userdata = cfg->now_userdata;
    c->session_template = cfg->session_template;
    c->on_done = cfg->on_done;
    c->on_done_userdata = cfg->on_done_userdata;

    c->conns = calloc((size_t)c->num_conn, sizeof(*c->conns));
    if (c->conns == NULL) {
        c->error = CLOAK_CLIENT_CONNECTOR_ERR_INTERNAL;
        /* c->reactor is set, so destroy will run connector_release -- which
         * is harmless with conns == NULL and no timer armed. */
        return -1;
    }
    for (int i = 0; i < c->num_conn; i++) {
        c->conns[i].owner = c;
        c->conns[i].index = i;
        c->conns[i].fd = -1;
        c->conns[i].retry_timer = CLOAK_TIMER_INVALID;
        /* Every connection starts on the configured fingerprint; D3's
         * fallback is per connection, so one connection falling back does
         * not drag the others with it. */
        c->conns[i].browser = c->browser;
    }

    c->status = CLOAK_CLIENT_CONNECTOR_PENDING;
    c->error = CLOAK_CLIENT_CONNECTOR_ERR_NONE;
    c->notified = 0;
    return 0;
}

int cloak_client_connector_start(cloak_client_connector_t *c) {
    if (c == NULL || c->status != CLOAK_CLIENT_CONNECTOR_PENDING || c->conns == NULL ||
        c->started) {
        return -1;
    }
    c->kickoff_timer = cloak_reactor_add_timer(c->reactor, 0, on_kickoff, c);
    if (c->kickoff_timer == CLOAK_TIMER_INVALID) {
        c->status = CLOAK_CLIENT_CONNECTOR_FAILED;
        c->error = CLOAK_CLIENT_CONNECTOR_ERR_INTERNAL;
        c->notified = 1; /* start failed: on_done must never fire */
        return -1;
    }
    c->started = 1;
    return 0;
}

void cloak_client_connector_destroy(cloak_client_connector_t *c) {
    if (c == NULL || c->reactor == NULL) {
        /* A zeroed c, or one left by an init that bailed before it had a
         * reactor, holds nothing: no timer, no dial, no handshake, no fd
         * and no array. */
        return;
    }
    connector_release(c);
    if (c->session_owned) {
        cloak_session_destroy(c->session);
        c->session_owned = 0;
    }
    free(c->conns);
    c->conns = NULL;
    c->num_conn = 0;
    c->notified = 1;
    if (c->status == CLOAK_CLIENT_CONNECTOR_PENDING) {
        c->status = CLOAK_CLIENT_CONNECTOR_FAILED;
    }
}

/* ---- accessors ---------------------------------------------------------- */

cloak_client_connector_status_t cloak_client_connector_status(const cloak_client_connector_t *c) {
    return c == NULL ? CLOAK_CLIENT_CONNECTOR_FAILED : c->status;
}

cloak_client_connector_error_t cloak_client_connector_error(const cloak_client_connector_t *c) {
    return c == NULL ? CLOAK_CLIENT_CONNECTOR_ERR_CONFIG : c->error;
}

cloak_client_handshake_error_t
cloak_client_connector_handshake_error(const cloak_client_connector_t *c) {
    return c == NULL ? CLOAK_CLIENT_HANDSHAKE_ERR_NONE : c->last_handshake_error;
}

cloak_session_t *cloak_client_connector_session(const cloak_client_connector_t *c) {
    if (c == NULL || c->status != CLOAK_CLIENT_CONNECTOR_DONE) {
        return NULL;
    }
    return c->session;
}

const uint8_t *cloak_client_connector_session_key(const cloak_client_connector_t *c) {
    if (c == NULL || c->status != CLOAK_CLIENT_CONNECTOR_DONE || c->conns == NULL) {
        return NULL;
    }
    return c->conns[0].key;
}

int cloak_client_connector_attempts(const cloak_client_connector_t *c) {
    return c == NULL ? 0 : c->total_attempts;
}
