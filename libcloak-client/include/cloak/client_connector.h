#ifndef CLOAK_CLIENT_CONNECTOR_H
#define CLOAK_CLIENT_CONNECTOR_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/client_transport.h"
#include "cloak/config.h"
#include "cloak/crypto.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/session.h"

/* Brings up ONE Cloak session across N underlying connections: N dials, N
 * handshakes, one key, one cloak_session_t with every connection attached
 * to it. Go's reference is internal/client/connector.go's MakeSession (83
 * lines).
 *
 * WHY N STATE MACHINES AND NOT N THREADS. Go spawns a goroutine per
 * connection and sync.WaitGroup.Wait()s for all of them; each goroutine
 * blocks in Dial and again in Handshake. This port has one
 * cloak_reactor_t and no threads, so the N connections are N
 * cloak_client_handshake_t objects driven concurrently by that one
 * reactor, and "all N finished" is a counter rather than a WaitGroup.
 * That is the same shape libcloak-server's dispatcher already uses for
 * many in-flight connections; it needs no new machinery.
 *
 * NO GLOBAL OR STATIC STATE, DELIBERATELY. Everything an invocation needs
 * lives in the cloak_client_connector_t the caller supplies and in the
 * per-connection array it allocates in init. That is not incidental
 * tidiness: singleplex mode (Go's NumConn <= 0) brings up one session per
 * accepted local connection, so this object becomes a hot path, created
 * repeatedly and concurrently with overlapping lifetimes. A shared
 * scratch buffer or a file-static counter here would be a latent aliasing
 * bug visible ONLY in the mode a user turns on for isolation.
 *
 * THE SESSION'S STORAGE IS THE CALLER'S. cloak_session_t is a public
 * struct that every other user of libcloak-mux holds inline, and this
 * object follows that: the caller points config::session at storage it
 * owns, and on success that storage holds a live session whose lifetime
 * is entirely the caller's from the moment on_done fires. This connector
 * never destroys a session it has successfully handed over -- it destroys
 * one only when assembly itself fails partway through, which is the one
 * moment the caller has never seen it. */

/* Largest NumConn this connector will accept. Go imposes no bound at all
 * (its loop is `for i := 0; i < connConfig.NumConn; i++` over a value the
 * config parser passes through unchecked, and this port's parser does the
 * same). A bound exists here because each connection costs a
 * cloak_client_handshake_t -- a couple of kilobytes, dominated by its
 * ClientHello buffer -- and because a NumConn of, say, 100000 is a typo,
 * not a deployment. 64 is far above any real configuration (Go Cloak's
 * own example configs use 4). Exceeding it is rejected as
 * CLOAK_CLIENT_CONNECTOR_ERR_CONFIG rather than silently clamped: an
 * operator who asked for 200 connections and got 64 would have no way to
 * find out. */
#define CLOAK_CLIENT_CONNECTOR_MAX_CONN 64

/* ---- D2: the retry bound and the backoff -------------------------------
 *
 * Go retries FOREVER. internal/client/connector.go's `makeconn:` label is
 * jumped back to on every dial failure and every handshake failure, after
 * a flat time.Sleep(3 * time.Second), with a `// TODO increase the
 * interval if failed multiple times` admitting the interval is wrong. A
 * goroutine that never gives up is a defensible choice for a daemon whose
 * only job is to keep one tunnel alive; it is not a defensible choice for
 * a LIBRARY, because a caller that can never be told "this did not work"
 * cannot exit non-zero, cannot log a final diagnosis, and cannot fail
 * over to a different server. So this object bounds the attempts, backs
 * off between them, and reports a typed failure.
 *
 * WHERE AN UNBOUNDED RETRY LOOP BELONGS: in ck-client, the binary this
 * library is for, wrapped around whole cloak_client_connector_t
 * invocations where an operator can see it, interrupt it, and have it
 * pick a different server between rounds. Not buried here, where its only
 * observable effect is that nothing ever happens.
 *
 * AND THAT OUTER LOOP MUST USE A FRESH SESSION ID AND BACK OFF BETWEEN
 * ROUNDS. One connection exhausting its attempts fails the whole
 * invocation immediately, abandoning the N-1 sockets that DID
 * authenticate -- and the server holds the session those sockets joined
 * until its own inactivity timeout expires. Retrying under the same
 * session id would then attach to a half-dead server-side session;
 * retrying without a delay, on a flaky network, multiplies server-side
 * sessions per client. Go never meets this because it never gives up:
 * its goroutine keeps retrying that one connection forever, so the
 * session id it was built with stays the right one. A caller that bounds
 * the attempts inherits the obligation.
 *
 * THE BOUND: 5 attempts per connection. The failures this retry loop
 * exists to survive are transient at the scale of seconds -- a DHCP
 * renewal or Wi-Fi roam between association and route (typically under
 * 2s), a server restarting behind the same address, a momentary
 * ENETUNREACH while a default route is replaced, a listen backlog
 * briefly full. Each of those clears well inside the ~7.5s of backoff
 * that 5 attempts spans. The failures that do NOT clear -- a wrong public
 * key, a revoked UID, a blocked address, a DPI box that drops our first
 * packet -- do not become survivable at attempt 50 either, so spending
 * more attempts on them only delays the diagnosis the caller needs. The
 * one shaped like it might is D3's oversized-ClientHello drop, which is
 * why the fingerprint fallback takes effect on attempt 2 rather than
 * after the bound.
 *
 * THE BACKOFF: exponential from 500ms, doubling, capped at 8000ms, with
 * each interval jittered uniformly by +/-25% AROUND that value. Nominal
 * delays are therefore 500, 1000, 2000 and 4000 ms -- about 7.5s of
 * backoff across the 5 attempts, plus or minus a quarter. Flat 3s (Go's)
 * is simultaneously too slow for the common case (a server that restarted
 * in 200ms is not reachable again for 3s) and, repeated forever without
 * growth, too aggressive against one that is genuinely down.
 *
 * The jitter is a divergence from Go, and its justification is narrower
 * than it might look. It is NOT a traffic-shape argument: N simultaneous
 * SYNs to one host is a weak signal to begin with, and both Go and this
 * port already open all N connections in lockstep on attempt 1 with no
 * jitter at all -- a louder synchronised burst than any retry round.
 * It is a thundering-herd argument and only that: the N connections of
 * one session fail at nearly the same instant, because they share a
 * route, a server and a middlebox, so an unjittered backoff has all N
 * retrying together at exactly the moment the far end is least able to
 * absorb it. Decorrelating them costs nothing.
 *
 * It is symmetric rather than one-sided ON PURPOSE. Jittering only
 * DOWNWARD (an earlier version of this code) decorrelates just as well
 * but shifts the mean to 0.75x, making every retry strictly more
 * aggressive than the schedule documented here and the real span ~5.6s
 * rather than ~7.5s. A +/-25% window decorrelates equally and preserves
 * the mean, so the numbers above are the numbers that happen.
 *
 * Both are overridable per invocation (config::max_attempts,
 * config::retry_base_ms), because a test needs them small and a caller
 * with its own outer loop may want max_attempts == 1. */
#define CLOAK_CLIENT_CONNECTOR_DEFAULT_MAX_ATTEMPTS 5
#define CLOAK_CLIENT_CONNECTOR_DEFAULT_RETRY_BASE_MS 500u
#define CLOAK_CLIENT_CONNECTOR_MAX_RETRY_DELAY_MS 8000u

/* Bounds one dial attempt when config::dial_timeout_ms is 0. A connect()
 * to a black-holed address otherwise sits in SYN retransmission for
 * ~130s on Linux, which would make the attempt bound above meaningless:
 * five attempts of that is eleven minutes. Go bounds the dial via its
 * dialer's own timeout, configured elsewhere. */
#define CLOAK_CLIENT_CONNECTOR_DEFAULT_DIAL_TIMEOUT_MS 10000u

typedef struct cloak_client_connector cloak_client_connector_t;

typedef enum {
    CLOAK_CLIENT_CONNECTOR_PENDING = 0,
    CLOAK_CLIENT_CONNECTOR_DONE = 1,
    CLOAK_CLIENT_CONNECTOR_FAILED = -1,
} cloak_client_connector_status_t;

/* Typed, for the same reason cloak_client_handshake_error_t is typed: a
 * caller deciding whether to try a different server has to tell "the
 * network or that server refused us" from "our own configuration cannot
 * work anywhere". */
typedef enum {
    CLOAK_CLIENT_CONNECTOR_ERR_NONE = 0,
    /* Bad arguments to init: NULL reactor/session/callback, num_conn out
     * of range, an over-long server name or proxy method, a transport
     * mode this build cannot speak. */
    CLOAK_CLIENT_CONNECTOR_ERR_CONFIG = 1,
    /* One connection used up all its attempts without ever reaching a
     * server: every dial failed or timed out. */
    CLOAK_CLIENT_CONNECTOR_ERR_DIAL = 2,
    /* One connection used up all its attempts with the dial succeeding
     * and the handshake failing -- i.e. something answered but was not a
     * Cloak server that would have us. cloak_client_connector_handshake_error
     * carries that handshake's own typed reason, which is the part worth
     * logging. Also reported for a handshake that could not even be
     * built (a CONFIG or BUILD failure), which is NOT retried: an
     * OpenSSL-level failure will not fix itself on attempt 2. */
    CLOAK_CLIENT_CONNECTOR_ERR_HANDSHAKE = 3,
    /* D4: the N connections did not agree on the session key. See
     * cloak_client_connector_init's own comment. */
    CLOAK_CLIENT_CONNECTOR_ERR_KEY_MISMATCH = 4,
    /* Every connection handshook and agreed, but cloak_session_init or
     * cloak_session_add_conn refused -- a bad session template, or an
     * allocation failure. */
    CLOAK_CLIENT_CONNECTOR_ERR_SESSION = 5,
    /* A reactor timer could not be armed, or the per-connection array
     * could not be allocated. */
    CLOAK_CLIENT_CONNECTOR_ERR_INTERNAL = 6,
} cloak_client_connector_error_t;

/* Fired EXACTLY ONCE per successful cloak_client_connector_start, and
 * never from inside that call -- start arms a zero-delay reactor timer
 * and returns, so the very first dial begins on a later reactor turn and
 * every path to this callback runs from reactor dispatch. That is the
 * same deferral cloak_dial_t and cloak_stream_relay_t already guarantee,
 * and it is what lets a caller finish initializing its own state after
 * start without racing its own completion.
 *
 * On CLOAK_CLIENT_CONNECTOR_DONE, session is the caller's storage, now
 * holding a live cloak_session_t with all N connections attached, and
 * OWNERSHIP OF IT IS THE CALLER'S from this moment: it must eventually
 * call cloak_session_destroy. cloak_client_connector_destroy will not.
 *
 * On CLOAK_CLIENT_CONNECTOR_FAILED, session is NULL, every socket this
 * connector ever opened is closed, and the reason is available from
 * cloak_client_connector_error.
 *
 * By the time this fires the connector holds no reactor registration, no
 * timer and no file descriptor, so it is legal to call
 * cloak_client_connector_destroy on c, or to free c's storage outright,
 * from inside this callback -- nothing in this object touches c after
 * on_done returns. */
typedef void (*cloak_client_connector_cb)(cloak_client_connector_t *c,
                                          cloak_client_connector_status_t status,
                                          cloak_session_t *session, void *userdata);

/* The wall clock the authentication payload is timestamped against. NULL
 * selects time(NULL). Taken as a function rather than a value because
 * every attempt must be stamped afresh -- the server checks the timestamp
 * against its own clock, so a value captured before a 4-second backoff
 * would be 4 seconds stale by the time it goes on the wire. Go gets this
 * for free by calling time.Now() inside makeAuthenticationPayload on
 * every pass through its retry label. */
typedef int64_t (*cloak_client_connector_now_fn)(void *userdata);

typedef struct {
    cloak_reactor_t *reactor;

    /* The server, ALREADY RESOLVED. cloak_net_resolve blocks (cloak/net.h
     * says so in capitals), so it belongs in startup code, not in an
     * object that may be constructed once per local connection under
     * singleplex. */
    cloak_addr_t remote;

    /* How many underlying connections this session gets. 1 to
     * CLOAK_CLIENT_CONNECTOR_MAX_CONN. Go's NumConn.
     *
     * WHAT MORE THAN ONE BUYS, because the obvious reading is wrong and
     * an operator choosing this number deserves the right one: NumConn >
     * 1 buys THROUGHPUT and traffic spreading -- one stream's frames are
     * distributed over the pool, so no single TCP connection's congestion
     * window bounds the session, and an observer sees several ordinary
     * flows instead of one long one. It does NOT buy REDUNDANCY. A single
     * connection failing is fatal to the WHOLE session, in this port and
     * in Go alike (internal/multiplex/switchboard.go closes the session
     * when any connection errors), so N connections means N chances to
     * lose the session rather than N-1 spares. This was confirmed against
     * the reference rather than assumed. */
    int num_conn;

    /* Storage for the session, owned by the caller, untouched unless and
     * until every connection succeeds. Must stay live and at a fixed
     * address from init until the session itself is destroyed. NULL is
     * rejected. */
    cloak_session_t *session;

    /* Everything below is per-handshake; see cloak/client_transport.h for
     * each field's contract. server_name and proxy_method are COPIED, so
     * they need not outlive this call. */
    cloak_client_browser_t browser;
    cloak_transport_mode_t transport;
    const char *server_name; /* "random" regenerates per attempt, as in Go */
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid[CLOAK_UID_LEN];
    const char *proxy_method;
    uint8_t encryption_method;
    uint32_t session_id;
    int unordered;

    /* 0 selects CLOAK_CLIENT_CONNECTOR_DEFAULT_DIAL_TIMEOUT_MS; 0 for the
     * handshake selects cloak_client_handshake_t's own default. */
    uint64_t dial_timeout_ms;
    uint64_t handshake_timeout_ms;

    /* 0 selects the D2 defaults above. */
    int max_attempts;
    uint64_t retry_base_ms;

    cloak_client_connector_now_fn now_fn;
    void *now_userdata;

    /* The session to build on success. The obfuscator field is IGNORED
     * and overwritten with the agreed key and encryption_method; every
     * other field (queue caps, timeouts, stream callbacks) is used as
     * given. */
    cloak_session_config_t session_template;

    cloak_client_connector_cb on_done;
    void *on_done_userdata;
} cloak_client_connector_config_t;

/* One underlying connection's whole life: a dial, then a handshake, then
 * a connected fd and a session key -- plus the retry bookkeeping D2 and
 * D3 need.
 *
 * Public, like cloak_client_handshake_t's own struct and for the same
 * reason: a teardown test has to be able to assert that it is tearing
 * down at the point it claims to be (dials in flight, handshakes in
 * flight, some connections already complete) rather than asserting on a
 * state it merely hopes it reached. Nothing outside client_connector.c
 * may WRITE to any field. */
typedef struct {
    cloak_client_connector_t *owner;
    int index;

    cloak_dial_t dial;
    int dial_active; /* a dial is in flight: its callback has not yet run */

    cloak_client_handshake_t hs;
    int hs_active; /* a handshake is in flight: its callback has not yet run */

    /* The connected socket, owned HERE from the moment the dial hands it
     * over until cloak_session_add_conn takes it (the handshake never
     * closes an fd, by its own contract). -1 whenever this connection
     * holds no socket, which is what makes "close it if it is >= 0"
     * a correct and idempotent teardown. */
    int fd;

    uint8_t key[CLOAK_AEAD_KEY_LEN];
    int have_key;

    int attempts; /* attempts STARTED, including the one in flight */

    /* D3: THE CHROME-TO-FIREFOX FALLBACK, per connection and sticky for
     * that connection's remaining attempts -- exactly as in Go, where the
     * goroutine mutates its own copy of transportConfig.
     *
     * WHY THIS EXISTS, because a reader who does not know will delete it
     * as superstition: Cloak v2.11.0 updated uTLS, which pushed the
     * Chrome fingerprint's first packet above 1500 bytes
     * (cbeuw/Cloak#306). Some networks drop it. Firefox's ClientHello is
     * smaller and gets through. THIS PORT HAS THE SAME HAZARD, not an
     * inherited one: cloak_clienthello_chrome builds a 1720-byte
     * ClientHello. So a handshake failure under Chrome is retried under
     * Firefox, and a connection that has fallen back never goes back. */
    cloak_client_browser_t browser;

    cloak_timer_id_t retry_timer;
    int done; /* handshook successfully; key and fd are both held */
} cloak_client_connector_conn_t;

/* c must stay live, at a fixed address, from a successful
 * cloak_client_connector_start until on_done fires (or until
 * cloak_client_connector_destroy, if torn down first): the reactor holds
 * pointers into it -- and into the per-connection array it owns -- for
 * that whole span. The same rule cloak_listener_t, cloak_dial_t,
 * cloak_relay_t and cloak_client_handshake_t all state for themselves. */
struct cloak_client_connector {
    cloak_reactor_t *reactor;
    cloak_addr_t remote;

    int num_conn;
    /* num_conn entries, allocated by init and freed by destroy. Heap
     * rather than a CLOAK_CLIENT_CONNECTOR_MAX_CONN-sized inline array
     * because singleplex constructs one connector per local connection
     * with num_conn == 1, and a 64-slot inline array would make that
     * ~160KB of stack or heap per local connection to hold one
     * handshake's worth of state. */
    cloak_client_connector_conn_t *conns;

    char server_name[CLOAK_MAX_HOST_LEN];
    char proxy_method[CLOAK_PROXY_METHOD_LEN + 1];
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid[CLOAK_UID_LEN];
    uint8_t encryption_method;
    uint32_t session_id;
    int unordered;
    cloak_client_browser_t browser;
    cloak_transport_mode_t transport;

    uint64_t dial_timeout_ms;
    uint64_t handshake_timeout_ms;
    int max_attempts;
    uint64_t retry_base_ms;

    cloak_client_connector_now_fn now_fn;
    void *now_userdata;

    cloak_session_config_t session_template;
    cloak_session_t *session;
    /* 1 only while a session exists that the CALLER has never been shown:
     * from a successful cloak_session_init until either assembly fails
     * (this object destroys it) or on_done reports DONE (ownership
     * passes, and this object must never touch it again). */
    int session_owned;

    int started;
    cloak_timer_id_t kickoff_timer;

    int completed;      /* connections holding a verified key and an fd */
    int total_attempts; /* summed over every connection, for diagnostics
                         * and for a test that must prove a retry HAPPENED
                         * rather than infer it from eventual success */

    cloak_client_connector_status_t status;
    cloak_client_connector_error_t error;
    cloak_client_handshake_error_t last_handshake_error;

    /* 1 once on_done has fired, so it fires exactly once no matter how
     * many terminal conditions are reached in one dispatch. */
    int notified;

    cloak_client_connector_cb on_done;
    void *on_done_userdata;
};

/* Prepares c: validates the configuration, copies it, and allocates the
 * per-connection array. No socket is opened, no reactor registration is
 * made and no timer is armed -- all of that starts at
 * cloak_client_connector_start.
 *
 * c is FULLY INITIALIZED (zeroed, then every fd set to -1 and every timer
 * id to CLOAK_TIMER_INVALID) BEFORE any argument is validated, so a
 * rejected call still leaves c safe to pass to
 * cloak_client_connector_destroy -- the same constructor discipline
 * cloak_client_handshake_init and cloak_listener_open follow.
 *
 * D4 -- WHAT THIS DOES THAT GO DOES NOT, and why. Go stores each
 * connection's recovered session key into a sync/atomic.Value and, after
 * the WaitGroup, reads back whichever store happened to land last
 * (connector.go's `_sessionKey.Store(sk)` then `_sessionKey.Load()`). It
 * never compares them. They SHOULD be identical -- the server composes
 * every additional connection's reply with the LIVE session's key, a rule
 * this project enforces and has tests for -- but "should" is an
 * assumption, and this connector checks it instead: all N keys are
 * compared, and any disagreement fails the whole session with
 * CLOAK_CLIENT_CONNECTOR_ERR_KEY_MISMATCH.
 *
 * Silently taking the last key is not a safe default for software whose
 * users are targets. A disagreement has exactly two causes, and neither
 * is benign: a bug on one side of a protocol carrying traffic someone is
 * trying to read, or an adversary who has split this session's
 * connections across two endpoints and is holding a valid key for some of
 * them. Go's version turns the first into a session that mysteriously
 * carries no bytes on some connections, and the second into a working
 * session the attacker partly controls. Refusing costs at most a session
 * that Go would have brought up -- loudly, with a typed error, at
 * startup.
 *
 * Returns 0 on success, -1 on failure with the reason in
 * cloak_client_connector_error(c) (CONFIG or INTERNAL). on_done does NOT
 * fire for an init failure: the caller learns it from the return value,
 * exactly as with cloak_client_handshake_init. */
int cloak_client_connector_init(cloak_client_connector_t *c,
                                const cloak_client_connector_config_t *cfg);

/* Begins the N connections. Arms a zero-delay reactor timer and returns
 * immediately; the first dial is issued from that timer, which is what
 * makes on_done's "never from inside start" guarantee structural rather
 * than a property of the dial layer that a future change could lose.
 *
 * Returns 0 if the attempt started, -1 if c was not successfully
 * initialized, start was already called, or the timer could not be armed
 * -- in which case on_done will NOT fire and the caller owns the
 * failure. */
int cloak_client_connector_start(cloak_client_connector_t *c);

/* Tears everything down WITHOUT firing on_done, from ANY point in the
 * sequence: dials in flight, handshakes in flight, some connections
 * already complete, or any mixture. Every in-flight dial is cancelled
 * (cloak_dial_cancel closes its own socket), every in-flight handshake is
 * destroyed (it never owned an fd), every retry timer and the kickoff
 * timer are cancelled, every socket this object still holds is closed
 * exactly once, and the per-connection array is freed.
 *
 * The session is destroyed here ONLY if assembly had begun and the caller
 * has never been shown it. After a DONE completion the session is the
 * caller's and this call does not touch it.
 *
 * Idempotent, and safe on a c left zeroed or left however a failed
 * init/start left it -- the same guarantee cloak_listener_close,
 * cloak_dial_cancel and cloak_client_handshake_destroy give. Safe to call
 * from within on_done; must not be called from within any OTHER callback
 * of this connector's own making (there are none a caller can reach). */
void cloak_client_connector_destroy(cloak_client_connector_t *c);

/* PENDING until on_done fires, then DONE or FAILED. Returns FAILED for a
 * NULL c. */
cloak_client_connector_status_t cloak_client_connector_status(const cloak_client_connector_t *c);

/* Why it failed. Meaningless unless the status is FAILED. Returns
 * CLOAK_CLIENT_CONNECTOR_ERR_CONFIG for a NULL c. */
cloak_client_connector_error_t cloak_client_connector_error(const cloak_client_connector_t *c);

/* The typed reason the most recent failed handshake gave. Worth logging
 * alongside CLOAK_CLIENT_CONNECTOR_ERR_HANDSHAKE: it separates "the
 * server closed on us" (ERR_EOF, what a Cloak server does to a client it
 * declines) from "nothing answered in time" (ERR_TIMEOUT) from "whatever
 * answered is not the server we were configured for" (ERR_AUTH). */
cloak_client_handshake_error_t
cloak_client_connector_handshake_error(const cloak_client_connector_t *c);

/* The live session, or NULL unless the status is DONE. Same pointer the
 * caller supplied as config::session, and the caller's to destroy. */
cloak_session_t *cloak_client_connector_session(const cloak_client_connector_t *c);

/* The agreed session key, or NULL unless the status is DONE. All N
 * connections were verified to have recovered exactly these bytes. */
const uint8_t *cloak_client_connector_session_key(const cloak_client_connector_t *c);

/* Attempts STARTED so far, summed over every connection. num_conn on a
 * run where nothing had to be retried; strictly more when D2's retry loop
 * did any work. Exposed because "the retry happened" is otherwise
 * unobservable: a test that only checks the session eventually came up
 * would pass just as well against an implementation with no retry at all,
 * which is one of the coverage shapes this project has already paid
 * for. */
int cloak_client_connector_attempts(const cloak_client_connector_t *c);

#endif
