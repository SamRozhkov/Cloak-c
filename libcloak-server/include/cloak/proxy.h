#ifndef CLOAK_PROXY_H
#define CLOAK_PROXY_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/dispatcher.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "cloak/session.h"
#include "cloak/stream_relay.h"

/* The server's data path: everything that happens AFTER the dispatcher's
 * front door has authenticated a connection and joined it to a
 * cloak_session_t. For every stream that session accepts, this dials the
 * upstream named by the client's authenticated proxy method and splices
 * the two together with a cloak_stream_relay_t. This is the C equivalent
 * of the goroutine Go Cloak's dispatchConnection spawns per accepted
 * stream (internal/server/dispatcher.go's proxy-book dial + Copy loop).
 *
 * WIRING: one cloak_proxy_t serves a whole server. It supplies the
 * dispatcher's two session callbacks --
 *
 *     dcfg.prepare_session          = cloak_proxy_prepare_session;
 *     dcfg.prepare_session_userdata = &proxy;
 *     dcfg.attached                 = cloak_proxy_attached;
 *     dcfg.attached_userdata        = &proxy;
 *
 * -- and, through the first of those, installs three of the session's own
 * four callbacks (on_new_stream, on_stream_data, on_writable) into every
 * session it prepares. The fourth, on_broken, belongs to the registry and
 * is NOT this module's to set; see cloak_proxy_prepare_session.
 *
 * LIFETIME: the proxy holds a heap-allocated context for every session it
 * ever prepared, and each of those holds a heap-allocated context for
 * every stream that session currently has in flight. Both are reactor and
 * session callback userdata, so neither ever moves, and THE PROXY MUST
 * OUTLIVE EVERY SESSION IT EVER PREPARED A CONTEXT FOR -- the session's
 * own on_new_stream/on_stream_data/on_writable point into it. Concretely,
 * for a caller that owns both: destroy the proxy BEFORE the registry that
 * owns the sessions. cloak/stream_relay.h states the underlying rule --
 * every relay bound to a session must be stopped before that session is
 * destroyed -- and cloak_proxy_destroy is what performs those stops.
 *
 * OWNERSHIP OF SOCKETS, stated once: cloak_proxy_t NEVER owns a socket
 * for longer than one narrow window. A dialed descriptor belongs to
 * cloak_dial_t until the dial callback fires; to cloak_proxy_stream_t's
 * own fd_pending from that instant until a cloak_stream_relay_start
 * succeeds; and to the relay from then on (which closes it on completion
 * or on cloak_stream_relay_stop). fd_pending is the ONE field that says
 * which of the three currently holds it: it is -1 whenever the proxy does
 * not itself hold a descriptor, exactly as cloak_dispatch_conn_t::fd is
 * -1 whenever that connection does not (cloak/dispatcher.h).
 *
 * A STREAM IS RELEASED IN EXACTLY TWO PLACES, and nowhere else:
 * cloak_stream_relay_t's done callback (the ordinary end of a stream's
 * life -- either side finished) and the shared teardown walk that
 * cloak_proxy_destroy drives (and that the registry-broken path added in
 * a later task drives too). cloak/session.h requires exactly one
 * cloak_session_release_stream per stream this module is handed, or the
 * stream's memory leaks for the life of the process. */
typedef struct cloak_proxy cloak_proxy_t;

typedef struct cloak_proxy_session cloak_proxy_session_t;

/* Per-direction buffer capacity handed to cloak_stream_relay_start, which
 * uses it for the stream-to-fd queue (the other direction needs none --
 * cloak_stream_write always accepts what it is given). The dispatcher's
 * own CLOAK_DISPATCHER_DEFAULT_RELAY_BUF_CAP is the same value for the
 * same reason, and matching it deliberately: one upstream connection
 * should not cost more buffer than one redirected one.
 *
 * Much smaller and every frame the stream delivers has to cross the queue
 * in several reactor turns instead of one -- correct, but it turns one
 * wakeup per frame into several, on the hottest path this server has.
 * Much larger and the cost is paid per CONCURRENT STREAM, not per
 * session: a client is free to open many, so this multiplies by exactly
 * the quantity an attacker chooses. 16 KiB is also one whole
 * max_on_wire_size frame with room to spare, which is the smallest value
 * that keeps the common case to a single turn. */
#define CLOAK_PROXY_DEFAULT_RELAY_BUF_CAP ((size_t)16384)

/* How long a single upstream connect attempt may take. The direct
 * analogue is CLOAK_DISPATCHER_DEFAULT_REDIRECT_DIAL_TIMEOUT_MS, and this
 * matches it: both dial a third party on the client's behalf, and neither
 * has a Go constant to port (Go relies on its own dialer's default).
 *
 * Much smaller and an upstream on a genuinely slow path (a remote
 * ShadowSocks endpoint, a loaded SOCKS server) is abandoned while it was
 * still going to answer, which the client sees as an unexplained stream
 * failure. Much larger and an upstream that accepts TCP but never
 * completes the handshake -- or a ProxyBook entry pointed at a black hole
 * -- pins a cloak_proxy_stream_t, a cloak_stream_t and a half-open socket
 * per stream for that long, again multiplied by however many streams the
 * client opens. */
#define CLOAK_PROXY_DEFAULT_DIAL_TIMEOUT_MS ((uint64_t)10000)

/* How long to wait before re-attempting a cloak_stream_relay_start that
 * was rejected (see cloak_proxy_config_t::max_retries for why the retry
 * exists at all). The condition being waited out is the session's
 * outbound pool draining, which happens when the kernel accepts more
 * bytes on a connection to the client -- so the natural timescale is one
 * client round trip, tens of milliseconds.
 *
 * Much smaller and this is a busy-wait: it burns the whole retry budget
 * inside a window far shorter than any real drain could complete in, so
 * the retry stops being a retry. Much larger and a connected upstream
 * socket sits idle, with the client waiting on it, for a condition that
 * had probably already cleared. */
#define CLOAK_PROXY_DEFAULT_RETRY_DELAY_MS ((uint64_t)50)

/* How many times a rejected cloak_stream_relay_start is re-attempted
 * before that one stream is given up on. With the delay above this is a
 * ceiling of about one second per stream.
 *
 * Much smaller and a genuinely transient congestion spike -- the case
 * this retry exists for -- kills a stream that would have worked a
 * moment later. Much larger and the PERMANENT failures this cannot tell
 * apart from the transient one (see max_retries' own comment below) hold
 * a connected socket and a heap context for proportionally longer, once
 * per stream, for a stream count the client chooses. */
#define CLOAK_PROXY_DEFAULT_MAX_RETRIES ((unsigned)20)

/* One accepted stream, being connected to or spliced with its upstream.
 * Heap-allocated and never moved: its address is the userdata for its own
 * dial, its own relay and its own retry timer.
 *
 * dialing, relaying and a live retry_timer are mutually exclusive -- they
 * mark which piece of machinery, if any, currently holds a registration
 * with the reactor, so the teardown walk knows which of
 * cloak_dial_cancel / cloak_stream_relay_stop / cancel-the-timer to
 * apply rather than trying all three against whichever one happens to
 * hold zeroed state. This mirrors cloak_dispatch_conn_t's own
 * dialing/relaying/writing_reply flags exactly. */
typedef struct cloak_proxy_stream {
    cloak_proxy_session_t *ps;
    cloak_stream_t *stream; /* owned by the session; released by us */

    cloak_dial_t dial; /* live only while dialing != 0 */
    int dialing;

    cloak_stream_relay_t relay; /* live only while relaying != 0 */
    int relaying;

    /* A transient cloak_stream_relay_start rejection, held over a timer.
     * fd_pending is the connected upstream descriptor across that window,
     * and -1 whenever this object does not hold one -- see this file's
     * top-of-file ownership paragraph. */
    cloak_timer_id_t retry_timer;
    int fd_pending;
    unsigned retries;

    struct cloak_proxy_stream *prev, *next;
} cloak_proxy_stream_t;

/* One authenticated session's proxy state. Allocated by
 * cloak_proxy_prepare_session -- i.e. BEFORE the cloak_session_t it
 * describes exists, since it has to go into that session's config -- and
 * freed by cloak_proxy_destroy (and, from a later task, by the registry's
 * broken callback, which is what lets it be freed while the server keeps
 * running).
 *
 * sesh is NULL until cloak_proxy_attached joins the two, and must never
 * be dereferenced once the session has broken. upstream is resolved once,
 * at prepare time, and points into the cloak_server_t's own ProxyBook
 * table -- which is why cloak_proxy_config_t::srv must outlive the
 * proxy. */
struct cloak_proxy_session {
    cloak_proxy_t *p;
    cloak_session_t *sesh;
    const cloak_addr_t *upstream;
    cloak_proxy_stream_t *streams;
    size_t stream_count;
    struct cloak_proxy_session *prev, *next;
};

/* reactor and srv are borrowed, not owned: both must outlive the proxy,
 * which in turn must outlive every session it prepared (see
 * cloak_proxy_t's own doc comment). srv supplies the resolved ProxyBook
 * and is read-only here -- but is typed non-const to match
 * cloak_dispatcher_config_t::srv, which every caller already holds a
 * mutable cloak_server_t for.
 *
 * Each sizing field defaults (0 means "use the default") to the
 * CLOAK_PROXY_DEFAULT_* constant above; a config that leaves them all
 * zeroed gets exactly those. */
typedef struct {
    cloak_reactor_t *reactor;
    cloak_server_t *srv;

    size_t relay_buf_cap;     /* 0 -> CLOAK_PROXY_DEFAULT_RELAY_BUF_CAP */
    uint64_t dial_timeout_ms; /* 0 -> CLOAK_PROXY_DEFAULT_DIAL_TIMEOUT_MS */

    /* THE RETRY POLICY, AND WHY IT EXISTS AT ALL. cloak_stream_relay_start
     * returns -1 for two categorically different reasons and gives the
     * caller no way to tell them apart: a permanent failure (bad
     * arguments, allocation, reactor registration) and a transient one
     * ("the session's outbound pool could not hold even a single
     * worst-case frame right now" -- see that function's own doc
     * comment, which documents both under one return value). Treating
     * every -1 as permanent would drop streams during ordinary
     * congestion; treating every -1 as transient costs a bounded number
     * of retries on a failure that was never going to clear. This takes
     * the second, conservative branch: retry up to max_retries, spaced
     * retry_delay_ms apart, holding the connected descriptor in
     * cloak_proxy_stream_t::fd_pending meanwhile, then give up on THAT
     * ONE STREAM (never the session).
     *
     * IF cloak/stream_relay.h EVER DISTINGUISHES THE TWO -- a distinct
     * return value, or an out-parameter -- this whole mechanism (both
     * fields, retry_timer, fd_pending and retries) should collapse to
     * "retry the transient case, fail the permanent one immediately".
     * That is the change this comment exists to point at. */
    uint64_t retry_delay_ms; /* 0 -> CLOAK_PROXY_DEFAULT_RETRY_DELAY_MS */
    unsigned max_retries;    /* 0 -> CLOAK_PROXY_DEFAULT_MAX_RETRIES */
} cloak_proxy_config_t;

struct cloak_proxy {
    cloak_proxy_config_t cfg; /* copied by value, defaults already filled in */

    /* Every session this proxy has prepared a context for and not yet
     * torn down. NULL when empty. */
    cloak_proxy_session_t *sessions;
    size_t session_count;

    /* The sum of every session context's own stream_count, kept in step
     * with it so cloak_proxy_stream_count stays O(1) rather than walking
     * the session list on every call. */
    size_t stream_count;
};

/* Zeroes p and validates the rest -- IN THAT ORDER, so that any failure
 * return still leaves p safe to pass to cloak_proxy_destroy. Five earlier
 * constructors on this project got that ordering backwards and it was a
 * crash every time a caller's own cleanup ran against an uninitialized
 * struct.
 *
 * Copies *cfg by value, substituting CLOAK_PROXY_DEFAULT_* for any of the
 * four sizing fields left at 0. cfg->reactor and cfg->srv remain borrowed
 * pointers.
 *
 * Returns 0 on success, -1 if p is NULL, or cfg, cfg->reactor or
 * cfg->srv is NULL. */
int cloak_proxy_init(cloak_proxy_t *p, const cloak_proxy_config_t *cfg);

/* Tears down everything the proxy still holds: for every stream context,
 * cancels an in-flight dial or retry timer, stops a live relay, closes a
 * descriptor still held in fd_pending, and releases the stream back to
 * its session; then frees every stream context and every session context.
 *
 * THIS IS THE CALLER'S OWN SHUTDOWN, not a failure path, so nothing is
 * reported anywhere. It also does NOT close or destroy any session: the
 * sessions belong to the registry, and the ONLY reason this must run
 * before the registry is destroyed is cloak/stream_relay.h's requirement
 * that a relay be stopped before the session it is bound to goes away.
 *
 * Idempotent, and safe on a zeroed struct. */
void cloak_proxy_destroy(cloak_proxy_t *p);

/* A cloak_dispatch_prepare_session_cb (userdata: the cloak_proxy_t).
 * Install it as cloak_dispatcher_config_t::prepare_session.
 *
 * It allocates this session's context, resolves its upstream once, and
 * installs on_new_stream/on_stream_data/on_writable into *config with
 * that context as all three userdata values.
 *
 * It MUST NOT, and does not, touch config->on_broken or
 * config->on_broken_userdata: cloak_server_registry_get_or_create
 * overwrites both unconditionally and discards whatever is there
 * (cloak/registry.h explains why the registry needs that hook for
 * itself). It also must not call cloak_dispatcher_destroy or anything
 * else that could free the in-flight connection -- see
 * cloak_dispatch_prepare_session_cb's own CALLING CONTEXT paragraph in
 * cloak/dispatcher.h: this fires from deep inside that same connection's
 * dispatch chain, with the connection live on the stack above.
 *
 * Returns -1 -- which redirects the connection to the cover site exactly
 * as if authentication itself had failed, leaving nothing in the registry
 * -- in four cases:
 *
 *  1. THE CLIENT ASKED FOR AN UNORDERED (DATAGRAM-ORIENTED) SESSION.
 *     This server has no UDP data path, and a client that got an ordered
 *     stream anyway would have its datagrams silently reassembled into a
 *     byte stream -- corruption it could not diagnose. A redirect is the
 *     kinder answer AND the safer one: the client learns nothing about
 *     this server and falls back, exactly as it would against any cover
 *     site. Checking only here, on the CREATE path, is the complete
 *     check and not an oversight: Go treats Unordered as a session-level
 *     property fixed when the session is created, so an additional
 *     connection joining an already-ordered session never reaches this
 *     callback at all and its own flag is meaningless.
 *
 *  2. THE PROXY METHOD HAS NO ProxyBook ENTRY. The dispatcher already
 *     rejected unknown proxy methods before calling this, so a NULL from
 *     cloak_server_lookup_proxy here is a PROGRAMMING ERROR (a caller
 *     that wired this proxy to a different cloak_server_t than the
 *     dispatcher's), not an attacker's doing. It still returns -1 rather
 *     than dereferencing NULL: a caller bug should degrade to a redirect,
 *     not a crash.
 *
 *  3. THE ProxyBook ENTRY IS A DATAGRAM UPSTREAM. An entry declared
 *     "udp" resolves to SOCK_DGRAM (cloak_server_init), and
 *     cloak_stream_relay_t splices a stream with a STREAM socket -- it
 *     has no framing with which to preserve datagram boundaries.
 *     Datagram upstreams are out of scope for this module entirely, so
 *     redirecting is the honest response; nothing here silently
 *     half-works.
 *
 *  4. Allocation failure.
 *
 * Returns 0 otherwise. */
int cloak_proxy_prepare_session(cloak_dispatcher_t *d, const cloak_server_clientinfo_t *info,
                                 cloak_session_config_t *config, void *userdata);

/* A cloak_dispatch_attached_cb (userdata: the cloak_proxy_t). Install it
 * as cloak_dispatcher_config_t::attached.
 *
 * Joins the session context cloak_proxy_prepare_session already built to
 * the cloak_session_t that was created from it -- the context necessarily
 * exists first, since it had to go into that session's config, so this is
 * the one place the two can meet. On the created == 0 path there is
 * nothing to do: the context already has its session.
 *
 * Like cloak_proxy_prepare_session, this MUST NOT call
 * cloak_dispatcher_destroy or otherwise free the connection it describes
 * -- cloak_dispatch_attached_cb's own doc comment notes it fires BEFORE
 * that connection is unlinked and freed, so destroying the dispatcher
 * here makes conn_handoff's own later free a double free. */
void cloak_proxy_attached(cloak_dispatcher_t *d, cloak_session_t *sesh,
                          const cloak_server_clientinfo_t *info, int created, void *userdata);

/* Session contexts currently held, and the total number of stream
 * contexts across all of them. Diagnostics and tests; both are O(1).
 * p == NULL returns 0. */
size_t cloak_proxy_session_count(const cloak_proxy_t *p);
size_t cloak_proxy_stream_count(const cloak_proxy_t *p);

#endif
