#ifndef CLOAK_PROXY_H
#define CLOAK_PROXY_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/dgram_relay.h"
#include "cloak/dispatcher.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "cloak/session.h"
#include "cloak/stream_relay.h"

/* The server's data path: everything that happens AFTER the dispatcher's
 * front door has authenticated a connection and joined it to a
 * cloak_session_t. For every stream that session accepts, this dials the
 * upstream named by the client's authenticated proxy method and splices
 * the two together -- with a cloak_stream_relay_t for a STREAM upstream
 * and a cloak_dgram_relay_t for a DATAGRAM one, chosen by the ProxyBook
 * entry's own resolved socket type and by nothing else. This is the C
 * equivalent of the goroutine Go Cloak's dispatchConnection spawns per
 * accepted stream (internal/server/dispatcher.go's proxy-book dial +
 * Copy loop), which likewise dials whatever the book names.
 *
 * WIRING: one cloak_proxy_t serves a whole server. It supplies two of the
 * dispatcher's session callbacks --
 *
 *     dcfg.prepare_session          = cloak_proxy_prepare_session;
 *     dcfg.prepare_session_userdata = &proxy;
 *     dcfg.session_aborted          = cloak_proxy_session_aborted;
 *     dcfg.session_aborted_userdata = &proxy;
 *
 * -- and, through the first of those, installs three of the session's own
 * four callbacks (on_new_stream, on_stream_data, on_writable) into every
 * session it prepares. The fourth, on_broken, belongs to the registry and
 * is NOT this module's to set; see cloak_proxy_prepare_session.
 *
 * It is ALSO the registry's own broken callback, which is not optional
 * either:
 *
 *     cloak_server_registry_init(&reg, reactor, cloak_proxy_registry_broken,
 *                                &proxy);
 *
 * NOTHING IS WIRED INTO dcfg.attached, and that is deliberate: this
 * module used to install a callback there whose only effect was to record
 * the cloak_session_t on the context prepare_session had already built,
 * and proxy_on_new_stream records it anyway from the callback that hands
 * over the session's first stream -- which is the earliest moment the
 * pointer is of any use, since a context with no streams never
 * dereferences it. Deleting the callback rather than keeping an inert one
 * that looks load-bearing is the whole change; dcfg.attached remains free
 * for an owner's own bookkeeping.
 *
 * The last two wirings above are what make this module correct when
 * sessions DIE rather than only while they live: cloak_proxy_registry_
 * broken stops every relay in the one window in which that is still
 * possible, and cloak_proxy_session_aborted reclaims the contexts of
 * handshakes that never produced a session at all. Read both of their doc
 * comments before wiring this module in; an owner that installs only
 * prepare_session has a use-after-free and a leak, not a working
 * server.
 *
 *
 * A BINARY SHOULD NOT DO ANY OF THIS BY HAND. cloak/server_stack.h
 * assembles this module together with the other eight, owns the whole
 * broken-session chain and the teardown order, and validates what it
 * can -- it is the supported wiring for an executable. Hand-wiring
 * remains legal and is what every test in this module does, because a
 * test that builds a partial graph is exactly what a test is for.
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
 * own fd_pending from that instant until whichever relay-start succeeds;
 * and to that relay from then on (which closes it on completion or on
 * its own stop). Both relays make the same promise about a FAILED start
 * -- the descriptor stays the caller's -- which is what lets one retry
 * ladder drive either. fd_pending is the ONE field that says
 * which of the three currently holds it: it is -1 whenever the proxy does
 * not itself hold a descriptor, exactly as cloak_dispatch_conn_t::fd is
 * -1 whenever that connection does not (cloak/dispatcher.h).
 *
 * A STREAM IS RELEASED IN EXACTLY TWO PLACES, and nowhere else: the
 * relay's done callback (the ordinary end of a stream's life -- either
 * side finished; one such callback per relay kind, doing the same one
 * thing) and the shared teardown walk that
 * cloak_proxy_destroy, cloak_proxy_registry_broken and
 * cloak_proxy_session_aborted all drive -- ONE walk, driven by three
 * entry points, deliberately: two copies of the most lifetime-sensitive
 * code in this module drifting apart is the worst outcome available
 * here. cloak/session.h requires exactly one
 * cloak_session_release_stream per stream this module is handed, or the
 * stream's memory leaks for the life of the process. */
typedef struct cloak_proxy cloak_proxy_t;

typedef struct cloak_proxy_session cloak_proxy_session_t;

/* Per-direction buffer capacity handed to cloak_stream_relay_start, which
 * uses it for the stream-to-fd queue (the other direction needs none --
 * cloak_stream_write always accepts what it is given).
 *
 * NOT USED BY A DATAGRAM UPSTREAM, and deliberately not passed to one:
 * cloak_dgram_relay_start takes no capacity at all, because its one
 * buffer must be exactly the stream's max_payload_per_frame and any
 * other value would either waste memory or wedge the stream. See that
 * function's own doc comment. The dispatcher's
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
 * was rejected with -2 (see cloak_proxy_config_t::max_retries for the
 * policy). The condition being waited out is the session's outbound pool
 * draining, which happens when the kernel accepts more bytes on a
 * connection to the client -- so the natural timescale is one client
 * round trip, tens of milliseconds.
 *
 * Much smaller and this is a busy-wait: it burns the whole retry budget
 * inside a window far shorter than any real drain could complete in, so
 * the retry stops being a retry. Much larger and a connected upstream
 * socket sits idle, with the client waiting on it, for a condition that
 * had probably already cleared. */
#define CLOAK_PROXY_DEFAULT_RETRY_DELAY_MS ((uint64_t)50)

/* How many times a -2 (transient) rejection is re-attempted before that
 * one stream is given up on. With the delay above this is a ceiling of
 * about twenty seconds per stream.
 *
 * WHAT THIS CEILING IS PROTECTING AGAINST, which is not what it looks
 * like: it is NOT a bound on congestion. Congestion ends the ladder by
 * ITSELF, the moment the pool drains, after however few or many retries
 * that took. The ceiling exists because -2 is also produced by a
 * condition that is transient in SHAPE but permanent in FACT, and that
 * the relay cannot distinguish from congestion at that call site: a pool
 * whose conn_send_queue_cap is simply smaller than one worst-case
 * frame's on-wire cost for this stream can NEVER satisfy the check, no
 * matter how long anyone waits. That is an operator misconfiguration
 * (two individually valid mux parameters that do not fit together --
 * cloak/stream_relay.h's start-time rejection exists to catch exactly
 * it), and without a ceiling every stream such a server accepted would
 * park a connected upstream descriptor and a heap context on a timer
 * forever.
 *
 * So: long enough to outlast any congestion episode during which the
 * stream would still have been worth starting, and short enough that a
 * misconfigured server reclaims each descriptor instead of accumulating
 * one per stream. Twenty seconds sits above this project's own dial and
 * handshake timeouts (10s, 15s) and below the session inactivity
 * timeouts its callers configure. Much smaller and an ordinary bulk
 * transfer on the same session can kill a second stream that was merely
 * waiting its turn -- which is precisely what an earlier one-second
 * ceiling would have done, chosen when this ladder still had to absorb
 * permanent failures too. Much larger and the misconfiguration case
 * above is barely bounded at all.
 *
 * IT MUST STAY BELOW THE SESSION'S OWN inactivity_timeout_ms, so that a
 * stream which can never start is reclaimed on the stream path rather
 * than left for the session's. A caller configuring an inactivity
 * timeout shorter than retry_delay_ms * max_retries must lower
 * max_retries to match; nothing here can check that, because the session
 * config belongs to the dispatcher, not to this module. */
#define CLOAK_PROXY_DEFAULT_MAX_RETRIES ((unsigned)400)

/* The most streams ONE authenticated session may hold contexts for at
 * once. Over it the stream is released straight back to its session --
 * no context, no dial, no descriptor -- and the session's other streams
 * are untouched.
 *
 * THE AXIS THIS CAPS IS NOT THE ONE THE DISPATCHER CAPS. Its
 * max_pending_conns bounds CONNECTIONS, and a connection is expensive to
 * obtain: an attacker has to complete a handshake for each. A STREAM is
 * bought with one frame carrying an unseen stream_id, on a connection
 * that already exists -- cloak_session_t creates a cloak_stream_t for any
 * such id -- and each one costs this module an upstream descriptor, a
 * reactor watcher, a dial timer and a receive buffer. An upstream that
 * accepts nothing holds each of those for the whole of dial_timeout_ms;
 * worse, because cloak_stream_relay_start's -2 rejection is a
 * SESSION-WIDE condition (cloak_session_send_min_conn_free), a client
 * that slow-drains one bulk stream makes every later stream on the same
 * session park a CONNECTED upstream descriptor for the full retry ladder.
 *
 * 256 is several times a browser's worth of concurrent connections, which
 * is the load the one honest client behind a session actually generates
 * (see proxy_on_stream_data on why a linear scan suffices at this scale).
 * Much smaller and an ordinary client's own parallelism is what trips it,
 * which the client sees as unexplained stream failures. Much larger and
 * one UID's share stops being a share at all: the total cap below is
 * then the only thing standing between a single authenticated client and
 * the whole descriptor budget. */
#define CLOAK_PROXY_DEFAULT_MAX_STREAMS_PER_SESSION ((size_t)256)

/* The bounds on the most streams the WHOLE proxy may hold contexts for at
 * once, summed over every session. Unlike every other default in this
 * file, the value itself is DERIVED AT cloak_proxy_init FROM THE
 * PROCESS'S OWN DESCRIPTOR LIMIT rather than fixed here, and these two
 * constants are the range that derivation is clamped into.
 *
 * THE DERIVATION: half of getrlimit(RLIMIT_NOFILE)'s SOFT limit, clamped
 * to [FLOOR, CEILING]. An unlimited soft limit yields the ceiling; a
 * getrlimit that fails yields the FLOOR, because a caller that cannot
 * learn its own limit should assume a small one rather than a generous
 * one. cloak_proxy_max_streams_total reports what a given proxy ended up
 * with.
 *
 * WHY IT IS DERIVED AND NOT A NUMBER. A fixed cap only bounds the servers
 * that did not need bounding. This module's per-session cap times the
 * registry's session cap is far more than any descriptor limit, so the
 * total cap is the one that protects the process -- and a fixed 4096 is
 * inert on a host left at the common 1024-descriptor default, where the
 * process hits EMFILE long before the cap does. That is precisely the
 * state this cap exists to prevent, on precisely the hosts most likely to
 * be in it.
 *
 * WHAT THE RESERVED HALF IS FOR, which is the whole point and is not
 * capacity: the DISPATCHER's own cover story needs descriptors.
 * conn_start_redirect dials the cover site, and under EMFILE/ENFILE that
 * socket() fails and conn_drop runs instead (libcloak-server/src/
 * dispatcher.c) -- so a prober gets an abrupt close where it should have
 * got the redirect. The listener's own accept(2) fails the same way.
 * Reserving half the descriptor budget for those, and never letting this
 * module's upstream sockets past the other half, is what keeps a resource
 * shortage from becoming a distinguisher. Losing one client's next stream
 * is cheap; losing the cover story is the failure this project exists to
 * avoid.
 *
 * THE FLOOR exists so a container with a miserly limit gets a proxy that
 * still works rather than one that refuses everything -- it is allowed to
 * exceed half the soft limit, and on such a host the descriptor limit
 * itself, not this cap, is what binds. THE CEILING exists so a host with
 * a million descriptors does not hand this module an effectively
 * unbounded cap: past a few thousand concurrent streams the bound that
 * matters is memory and reactor turn cost, neither of which scales with
 * RLIMIT_NOFILE.
 *
 * An explicitly configured non-zero cloak_proxy_config_t::max_streams_
 * total is honoured verbatim and skips all of this: a caller that knows
 * its deployment knows better than a heuristic. */
#define CLOAK_PROXY_MAX_STREAMS_TOTAL_FLOOR ((size_t)64)
#define CLOAK_PROXY_MAX_STREAMS_TOTAL_CEILING ((size_t)4096)

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

    /* THE RELAY, IN WHICHEVER OF THE TWO KINDS THIS UPSTREAM NEEDS.
     * Exactly one of the two is live, and only while relaying != 0;
     * relay_is_dgram says which, and is meaningless while relaying == 0.
     *
     * WHY BOTH ARE EMBEDDED BY VALUE rather than one being a pointer, or
     * the pair a union: every reactor-driven object in this tree must
     * stay at a fixed address until its terminal event, and a
     * cloak_proxy_stream_t is already heap-allocated and never moved, so
     * embedding satisfies that for free. A union would save a few dozen
     * bytes per stream and would make every teardown path one mistaken
     * discriminator away from running the wrong destructor over live
     * state -- on the most lifetime-sensitive code in this module. The
     * cost of not unioning is bounded by max_streams_total.
     *
     * WHICH ONE IS CHOSEN BY THE UPSTREAM'S SOCKET TYPE ALONE, never by
     * the session's ordering mode -- see cloak_proxy_prepare_session's
     * own doc comment for why those are two different questions. */
    cloak_stream_relay_t relay;
    cloak_dgram_relay_t dgram;
    int relaying;
    int relay_is_dgram;

    /* A transient relay-start rejection, held over a timer.
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
 * freed by cloak_proxy_destroy, by cloak_proxy_registry_broken (which is
 * what lets it be freed while the server keeps running) or by
 * cloak_proxy_session_aborted (the handshake that was preparing it never
 * produced a session at all).
 *
 * sesh is NULL until this session's FIRST STREAM arrives -- proxy_on_new_
 * stream records it from the callback that hands the stream over, which
 * is both the earliest moment the pointer can be of any use and the only
 * moment it is needed, since a context holding no streams never
 * dereferences it. It must never be dereferenced once the session has
 * broken either: cloak_proxy_registry_broken clears it to NULL the
 * instant the last stream has been released, so that rule is enforced by
 * the code and not merely stated here.
 * upstream is resolved once, at prepare time, and points into the
 * cloak_server_t's own ProxyBook table -- which is why
 * cloak_proxy_config_t::srv must outlive the proxy.
 *
 * (uid, session_id) IS THE ONLY HANDLE THIS MODULE CAN LOOK A CONTEXT UP
 * BY, and that is why it is recorded here rather than derived when
 * needed. It is set by cloak_proxy_prepare_session -- the one and only
 * place a context is ever created -- so it is valid for the whole of a
 * context's life, including the entire window before sesh exists. Both
 * paths that have to find a context from the outside (the registry's
 * broken callback and the dispatcher's session-aborted callback) are
 * handed exactly that pair and nothing else; at all three abort sites
 * sesh is still NULL, so a scan keyed on the session pointer would find
 * nothing there. At most one live context exists per key: a context is
 * only ever created when cloak_server_registry_find reported no session
 * for that key, and every path that retires a session tears its context
 * down before that key can be reused. */
struct cloak_proxy_session {
    cloak_proxy_t *p;
    cloak_session_t *sesh;
    const cloak_addr_t *upstream;
    uint8_t uid[CLOAK_UID_LEN];
    uint32_t session_id;
    cloak_proxy_stream_t *streams;
    size_t stream_count;

    /* 1 while this session is inside the capped EPISODE that began when
     * it last refused a stream at max_streams_per_session. NOT the same
     * predicate as "is refusing right now": the episode ends at the
     * low-water mark, an eighth of the cap below the cap, so this stays
     * set across counts at which a new stream would in fact be admitted.
     * That asymmetry is deliberate and is the hysteresis itself; it
     * affects ONLY the log, never admission, which is always the plain
     * stream_count >= cap test. See cloak_proxy_t::total_capped. */
    int capped;

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

    /* THE RETRY POLICY. cloak_stream_relay_start distinguishes its two
     * failure kinds by return value -- and cloak_dgram_relay_start makes
     * the identical distinction with the identical two values, which is
     * what lets one ladder drive either upstream kind -- and this module
     * branches on that distinction rather than guessing:
     *
     *   -1 PERMANENT (bad arguments, allocation, reactor registration).
     *      Failed immediately. Retrying cannot help, and would hold a
     *      connected upstream descriptor and this stream's context open
     *      for the whole budget before failing anyway. ONE CAUSE FOLDED
     *      IN HERE IS ARGUABLY TRANSIENT -- an epoll watch-table
     *      exhaustion -- and is deliberately not retried anyway;
     *      cloak/stream_relay.h names it and gives the reason.
     *
     *   -2 TRANSIENT ("the pool cannot hold one worst-case frame right
     *      now"). Retried up to max_retries, spaced retry_delay_ms
     *      apart, with the connected descriptor held in
     *      cloak_proxy_stream_t::fd_pending meanwhile. This is NOT a
     *      rare corner: a relay already running on the session
     *      deliberately holds the pool below exactly that threshold for
     *      as long as its own peer is slow to drain, so a second stream
     *      opened during a bulk transfer takes this path routinely, and
     *      for as long as the congestion lasts.
     *
     * Exhausting the budget gives up on THAT ONE STREAM, never on the
     * session. See CLOAK_PROXY_DEFAULT_MAX_RETRIES for what that finite
     * budget is actually protecting against, which is not congestion. */
    uint64_t retry_delay_ms; /* 0 -> CLOAK_PROXY_DEFAULT_RETRY_DELAY_MS */
    unsigned max_retries;    /* 0 -> CLOAK_PROXY_DEFAULT_MAX_RETRIES */

    /* THE TWO STREAM CAPS, checked together before anything is allocated
     * or dialed for a newly accepted stream. Over EITHER, the stream is
     * handed straight back with cloak_session_release_stream (legal from
     * on_new_stream -- cloak/session.h) and nothing else happens: no
     * context, no dial, no descriptor, and no effect on the session or on
     * any stream already running.
     *
     * THE TRADE-OFF, stated once because it is the whole reason these
     * exist: degrade the greedy client's extra streams rather than the
     * cover story, since a server that has run out of descriptors closes
     * probers instead of redirecting them to the cover site and is
     * therefore distinguishable. See the two CLOAK_PROXY_DEFAULT_MAX_
     * STREAMS_* constants for what each bounds and why.
     *
     * Both count THE CONTEXTS THAT EXIST -- cloak_proxy_session_t::
     * stream_count and cloak_proxy_t::stream_count respectively -- so a
     * stream refused at the cap never counted against it, and a stream
     * that ends frees its share the instant its context is freed. */
    size_t max_streams_per_session; /* 0 -> ..._DEFAULT_MAX_STREAMS_PER_SESSION */
    size_t max_streams_total;       /* 0 -> derived; see the two _TOTAL_ constants */

    /* OPTIONAL, and the reason cloak_proxy_registry_broken can afford to
     * BE the registry's one on_broken callback rather than something the
     * owner has to remember to call: an owner with bookkeeping of its own
     * installs it here and gets it invoked with its own userdata AFTER
     * this module's cleanup for that session has completed. NULL (the
     * default) simply means there is nothing to chain.
     *
     * THE ORDERING IS NOT NEGOTIABLE, and it is this way round because a
     * chained callback is explicitly permitted (cloak/registry.h) to call
     * cloak_server_registry_destroy -- including for the registry that is
     * mid-teardown -- which destroys every session still in the table.
     * By the time the chain can do that, every relay this proxy held must
     * already be stopped. See cloak_proxy_registry_broken. */
    cloak_registry_broken_cb chain;
    void *chain_userdata;
} cloak_proxy_config_t;

struct cloak_proxy {
    cloak_proxy_config_t cfg; /* copied by value, defaults already filled in */

    /* Every session this proxy has prepared a context for and not yet
     * torn down. NULL when empty. */
    cloak_proxy_session_t *sessions;
    size_t session_count;

    /* The sum of every session context's own stream_count, kept in step
     * with it so cloak_proxy_stream_count stays O(1) rather than walking
     * the session list on every call.
     *
     * IT IS ALSO WHAT ENFORCES cfg.max_streams_total, which is why the
     * single place it is decremented matters: exactly one function frees
     * a cloak_proxy_stream_t, and it unlinks (and so decrements) on the
     * way. A decrement missed on any path would not merely skew a
     * statistic -- it would ratchet this counter upward until the cap
     * became a permanent, server-wide refusal to accept any stream at
     * all, which is a worse failure than the exhaustion it prevents. */
    size_t stream_count;

    /* 1 while the proxy is inside the capped episode that began when it
     * last refused a stream at max_streams_total; see
     * cloak_proxy_session_t::capped for why that is not the same
     * predicate as "is refusing right now".
     *
     * IT EXISTS SO THE OPERATOR LOG IS BOUNDED BY THE STATE, NOT BY THE
     * ATTACKER. An operator otherwise has no way to tell this cap from a
     * failing upstream, because to the CLIENT a refusal is
     * indistinguishable from one IN FORM -- same close, same frame, same
     * byte count -- which is what the refusal path is careful to preserve.
     * IT IS NOT INDISTINGUISHABLE IN LATENCY, and that limitation is
     * inherent rather than an oversight: a refusal is emitted in the same
     * reactor turn that parsed the opening frame, where any real upstream
     * failure costs at least a dial round trip and at most
     * dial_timeout_ms. A prober holding one valid UID can therefore time
     * stream-open-to-close and read off whether this server is at its
     * cap -- a coarse load oracle, available only to an authenticated
     * client, and the unavoidable price of refusing BEFORE the dial, which
     * is the entire point (a refusal that first dialled would spend the
     * descriptor the cap exists to protect). It is stated here rather than
     * fixed.
     *
     * Either way it leaves the person running the server blind, which is
     * what this flag addresses. One line when a cap starts refusing and
     * one when it stops is enough to diagnose; a line per refusal would be
     * an amplifier, since refusals are exactly what an attacker generates
     * in bulk.
     *
     * The flag alone would still flip at the attacker's rate (close one
     * stream, open two), so recovery is HYSTERETIC: the capped state is
     * only left once the count has fallen an eighth of the cap below it.
     * That makes the log rate bounded by cap/8 stream lifecycles per line
     * pair rather than by one. */
    int total_capped;
};

/* Zeroes p and validates the rest -- IN THAT ORDER, so that any failure
 * return still leaves p safe to pass to cloak_proxy_destroy. Five earlier
 * constructors on this project got that ordering backwards and it was a
 * crash every time a caller's own cleanup ran against an uninitialized
 * struct.
 *
 * Copies *cfg by value, substituting CLOAK_PROXY_DEFAULT_* for any of the
 * five fixed sizing fields left at 0, and DERIVING the sixth -- a
 * max_streams_total of 0 becomes half the process's RLIMIT_NOFILE soft
 * limit, clamped into [CLOAK_PROXY_MAX_STREAMS_TOTAL_FLOOR, ..._CEILING].
 * A getrlimit failure is not an init failure: it yields the floor. See
 * those constants for the whole derivation and why it is one.
 * cfg->reactor and cfg->srv remain borrowed pointers.
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
 * -- in two cases:
 *
 *  1. THE PROXY METHOD HAS NO ProxyBook ENTRY. The dispatcher already
 *     rejected unknown proxy methods before calling this, so a NULL from
 *     cloak_server_lookup_proxy here is a PROGRAMMING ERROR (a caller
 *     that wired this proxy to a different cloak_server_t than the
 *     dispatcher's), not an attacker's doing. It still returns -1 rather
 *     than dereferencing NULL: a caller bug should degrade to a redirect,
 *     not a crash.
 *
 *  2. Allocation failure.
 *
 * Returns 0 otherwise.
 *
 * TWO CASES WERE REMOVED IN MODULE 9, and what they were is worth more
 * than a diff, because both were correct when written and neither is now:
 *
 *  GONE: "THE CLIENT ASKED FOR AN UNORDERED (DATAGRAM-ORIENTED)
 *  SESSION." This used to be the first thing the function did. The
 *  argument was that a server with no UDP data path should redirect such
 *  a client rather than hand it an ordered stream that would silently
 *  reassemble its datagrams -- corruption the client could not diagnose
 *  -- and it was right for as long as the premise held. Module 9 removed
 *  the premise: the dispatcher now builds the session in the mode the
 *  flag asks for, and cloak_dgram_relay_t carries datagrams end to end.
 *
 *  AND ITS OLD JUSTIFICATION IS NOW FALSE IN A WAY THAT MATTERED. It
 *  claimed a check on the CREATE path was the COMPLETE check, because Go
 *  treats Unordered as a session-level property fixed at creation
 *  (internal/multiplex/session.go:48-63 reads it once, in makeStream,
 *  from the session) and an additional connection joining an existing
 *  session never reaches this callback (internal/server/activeuser.go:46-47
 *  returns early with the existing session). The first half is true and still is; the conclusion was
 *  only true while every unordered client was refused outright. Once
 *  they are not, a second connection whose flag DISAGREES with the live
 *  session would be spliced onto it silently -- its frames interpreted
 *  under the session's mode rather than its own. That hole is closed
 *  where it lives, in dispatcher.c's step 8, which now REFUSES the
 *  joining connection (see cloak_dispatcher_t::ordering_mismatch_
 *  refusals): a deliberate divergence from Go, which splices. It is
 *  named here, in the comment that used to assert the check was
 *  complete, so that the correction is found by whoever finds the claim.
 *
 *  GONE: "THE ProxyBook ENTRY IS A DATAGRAM UPSTREAM." An entry declared
 *  "udp" resolves to SOCK_DGRAM (cloak_server_init), and
 *  cloak_stream_relay_t has no framing with which to preserve datagram
 *  boundaries -- so refusing was the honest answer while it was the only
 *  relay. There are now two, and the socket type is what chooses between
 *  them, at relay-start time rather than here (proxy_try_start_relay).
 *  Deliberately not re-checked in this function: a second check could
 *  only duplicate that one and would then be free to disagree with it.
 *
 * THE TWO QUESTIONS ARE INDEPENDENT, which is the part that is easy to
 * get wrong now that both are answered. The session's ordering mode says
 * how the client's application framed what it sent; the upstream's
 * socket type says what the far end can receive. All four combinations
 * are legal and all four are what Go does -- Go chooses nothing, it
 * dials whatever the ProxyBook names
 * (internal/server/dispatcher.go:289-290, `ProxyDialer.Dial(
 * proxyAddr.Network(), proxyAddr.String())`) and runs one copy loop
 * over it (common.Copy, internal/common/copy.go). An
 * unordered session against a "tcp" upstream loses its boundaries at the
 * TCP socket, in this port exactly as in Go, because there is nowhere
 * else they could survive. */
int cloak_proxy_prepare_session(cloak_dispatcher_t *d, const cloak_server_clientinfo_t *info,
                                 cloak_session_config_t *config, void *userdata);

/* A cloak_registry_broken_cb (userdata: the cloak_proxy_t). Pass it, with
 * the proxy as its userdata, to cloak_server_registry_init:
 *
 *     cloak_server_registry_init(&reg, reactor, cloak_proxy_registry_broken,
 *                                &proxy);
 *
 * THIS IS OBLIGATION 1 AND IT IS THE REASON THIS MODULE IS EITHER CORRECT
 * OR NOT. cloak_session_broken_cb's contract (cloak/session.h) is that
 * immediately after on_broken returns, every still-active stream the
 * session owns is destroyed and freed. A cloak_stream_relay_t holds its
 * stream and its session as raw pointers it can never validate and has no
 * third notification through which it could learn either died -- so a
 * relay left running past that point still has its fd registered with the
 * reactor, and the next byte that arrives on it runs cloak_stream_write
 * on freed memory. THE REGISTRY'S BROKEN CALLBACK IS THE ONLY WINDOW in
 * which those relays can still be stopped: it fires while sesh is still
 * fully usable, and cloak_server_registry_close/destroy deliberately do
 * not fire it at all.
 *
 * WHY THIS IS THE CALLBACK ITSELF rather than a cloak_proxy_on_session_
 * broken() the owner calls from its own: cloak_server_registry_init takes
 * exactly one on_broken for the whole registry, so this module cannot
 * install a second one beside the owner's. Exporting a function for the
 * owner to remember to call would make every user of this module
 * responsible for the one mistake cloak/registry.h names as the single
 * most likely a caller wiring up all four session callbacks can make.
 * Being the callback makes the cleanup the default and the owner's own
 * bookkeeping the addition -- see cloak_proxy_config_t::chain.
 *
 * For the session context matching (uid, session_id) -- looked up by that
 * pair, not by sesh, because it is the one handle valid at every site
 * that needs it -- this tears down every stream context, releases every
 * stream back to sesh, clears the now-dead sesh pointer and frees the
 * session context; then invokes cfg.chain, if any, with cfg.chain_
 * userdata. A session this proxy has no context for (one created by
 * something else, or one whose cloak_proxy_prepare_session returned -1 so
 * that no context was ever made) is not an error: it skips straight to
 * the chain. So does a NULL uid (which the registry never passes): there
 * is no key to look a context up by, but the chain is the owner's own and
 * is forwarded to regardless -- this function never swallows a broken
 * notification. A NULL userdata is the one case where nothing happens at
 * all, since the chain itself lives on the proxy.
 *
 * CALLING CONTEXT is exactly cloak_registry_broken_cb's own, which is in
 * turn exactly cloak_session_broken_cb's: outside any cloak_session_t/
 * cloak_conn_t/cloak_switchboard_t callback's call stack. Everything this
 * does inside that window -- cloak_stream_relay_stop,
 * cloak_dial_cancel, cancelling a timer, cloak_session_release_stream --
 * is permitted there; cloak_session_destroy is not called, and must not
 * be, from here. */
void cloak_proxy_registry_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                 const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                 void *userdata);

/* A cloak_dispatch_session_aborted_cb (userdata: the cloak_proxy_t).
 * Install it as cloak_dispatcher_config_t::session_aborted:
 *
 *     dcfg.session_aborted          = cloak_proxy_session_aborted;
 *     dcfg.session_aborted_userdata = &proxy;
 *
 * WIRING IT IS NOT OPTIONAL FOR A CALLER THAT USES cloak_proxy_prepare_
 * session. That callback allocates and links a session context before the
 * cloak_session_t exists; if the session then never comes to exist (the
 * registry was at its cap, an allocation failed, or the handshake unwound
 * after creating one), the registry's broken callback never fires for it
 * -- cloak_server_registry_close deliberately does not fire on_broken --
 * and nothing else would ever free that context. That is a small, remotely
 * reachable, unbounded leak: one context per abandoned handshake.
 *
 * THE SAME OBLIGATION FALLS ON AN OWNER THAT CALLS
 * cloak_server_registry_close ITSELF. That function is public and fires
 * neither on_broken (cloak/registry.h: it is the owner's own action) nor
 * this callback, which only the dispatcher's own unwinds raise -- so an
 * owner that closes a session by hand must call this function for that
 * same (uid, session_id) FIRST, while the session is still alive, exactly
 * as dispatcher.c's sites B and C do. Closing without it leaves the
 * context orphaned until cloak_proxy_destroy, and leaves any relay bound
 * to that session running past its destruction. Nothing in this codebase
 * does that today; this sentence exists so the next owner learns it here
 * rather than from a leak.
 *
 * Tears down and frees the context for (uid, session_id) if this proxy
 * has one, and does nothing at all if it does not (the dispatcher fires
 * this for a session it created, which is not necessarily one this proxy
 * prepared). At every site the dispatcher fires it from, that context's
 * sesh is still NULL and it holds no streams, so this is ordinarily just
 * an unlink and a free -- it goes through the same teardown walk as every
 * other path anyway, because a second copy of that walk is the one thing
 * this module cannot afford.
 *
 * CALLING CONTEXT: see cloak_dispatch_session_aborted_cb in
 * cloak/dispatcher.h, which is stricter than either of this module's
 * other dispatcher callbacks -- one of its three sites runs during
 * connection teardown, including from inside cloak_dispatcher_destroy.
 * Nothing this function does touches the dispatcher or the registry, so
 * it is safe at all three. */
void cloak_proxy_session_aborted(cloak_dispatcher_t *d, const uint8_t uid[CLOAK_UID_LEN],
                                 uint32_t session_id, void *userdata);

/* Session contexts currently held, and the total number of stream
 * contexts across all of them. Diagnostics and tests; both are O(1).
 * p == NULL returns 0. */
size_t cloak_proxy_session_count(const cloak_proxy_t *p);
size_t cloak_proxy_stream_count(const cloak_proxy_t *p);

/* The total-stream cap this proxy is actually enforcing: whatever
 * cloak_proxy_config_t::max_streams_total was set to, or the value
 * cloak_proxy_init derived from RLIMIT_NOFILE when it was left at 0. It
 * exists because that derived number is otherwise unobservable -- a
 * caller cannot check what it got, and a test cannot assert that the
 * derivation left the process any headroom at all. Never 0 for an
 * initialized proxy; p == NULL returns 0. */
size_t cloak_proxy_max_streams_total(const cloak_proxy_t *p);

#endif
