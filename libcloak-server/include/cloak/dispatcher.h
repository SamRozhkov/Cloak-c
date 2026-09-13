#ifndef CLOAK_DISPATCHER_H
#define CLOAK_DISPATCHER_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/firstpacket.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "cloak/session.h"

/* The server's front door: turns an accepted connection into either a
 * redirect to the cover site or an authenticated session. This is the C
 * equivalent of Go Cloak's dispatchConnection (internal/server/
 * dispatcher.go).
 *
 * WIRING: the caller passes cloak_dispatcher_accept as the on_accept
 * callback to cloak_listener_open, with a live cloak_dispatcher_t as its
 * userdata -- one dispatcher can serve every listener the server opens,
 * since cloak_dispatcher_accept reads each connection's own local_port
 * from the cloak_listener_t handed to it. OWNERSHIP OF THE ACCEPTED FD
 * PASSES AT THAT CALL, exactly as cloak_listener_accept_cb's own doc
 * comment requires: cloak_dispatcher_accept either takes the fd into a
 * newly heap-allocated connection or, on an allocation/registration
 * failure, closes it itself. The listener never sees it again.
 *
 * THE PROPERTY THIS MODULE EXISTS TO PROTECT: every failure redirects to
 * RedirAddr rather than closing the connection, wherever there is
 * anything left to redirect. Closing tells a prober that something other
 * than a web server is listening, which is exactly what Cloak exists to
 * prevent -- so an unrecognised protocol, an oversized or malformed first
 * packet, and a failed authentication all take the same path: forward
 * whatever the client already sent to the cover site and splice the two
 * sockets together.
 *
 * That is the common case, not the whole contract: this module closes
 * instead of redirecting in five distinct classes of situation, and a
 * reader who needs the exact list should not have to derive it from the
 * source. In order of how often each is actually reached:
 *
 *  (a) NOTHING TO REDIRECT TO. The peer is already gone (conn_drop_peer_
 *      gone -- read() returned 0 or an error before a first packet was
 *      even framed), the redirect dial itself failed or could not even be
 *      started (on_dial_done's fd < 0 case, conn_start_redirect's
 *      cloak_dial_start failure), or the dial succeeded but the relay
 *      itself could not be started (on_dial_done's cloak_relay_start
 *      failure). In every one of these there is no live peer connection
 *      left to hand bytes to, regardless of what this module does.
 *
 *  (b) THE COVER STORY IS ALREADY SPENT. Once dispatcher_authenticate has
 *      succeeded, the client has (or is about to have) a genuine
 *      ServerHello in hand -- forwarding it to the cover site after that
 *      would be visibly incoherent (a real web server never follows a
 *      ServerHello with a second, unrelated handshake attempt), so every
 *      failure from that point on closes rather than redirects: a step-10
 *      reply-write error (conn_reply_write_failed), a step-11
 *      cloak_session_add_conn failure, and the session having already
 *      been torn down out from under this connection by the time it
 *      reaches hand-off (conn_handoff's re-resolve-by-(uid,session_id)
 *      coming back NULL -- see conn_handoff's own comment in
 *      dispatcher.c and this module's C1 finding for why a stored session
 *      pointer cannot be trusted here instead).
 *
 *  (c) RESOURCES ARE ALREADY EXHAUSTED. cloak_dispatcher_accept's own cap
 *      (deliberately closes despite somewhere to redirect existing -- see
 *      CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS's own comment for why),
 *      and every allocation/timer/registration failure at accept
 *      (calloc, the handshake-deadline timer, cloak_reactor_add_fd) or in
 *      the reply-write state (the reply-write deadline timer,
 *      cloak_reactor_mod_fd switching to WRITABLE) -- all ENOMEM-class
 *      failures where refusing to proceed is the only sound option
 *      regardless of which state the connection is in.
 *
 *  (d) THE FIRST-PACKET DEADLINE. on_deadline firing for the read-side
 *      deadline armed in cloak_dispatcher_accept matches Go's own
 *      behaviour, not just this port's own judgement: Go's
 *      readFirstPacket returning a read error sets redirOnErr = false,
 *      so dispatchConnection calls conn.Close() rather than redirecting
 *      -- this module's on_deadline->conn_drop is the same call, ported.
 *
 *  (e) CALLER BUGS WITH NO CONNECTION YET. cloak_dispatcher_accept's own
 *      userdata == NULL check: there is no cloak_dispatch_conn_t to
 *      redirect through at that point, only the bare fd the listener
 *      handed over, so closing it is the only possible response to a
 *      caller that wired this callback up wrong.
 *
 * A KNOWN GAP IN THAT CLOSE, worth stating explicitly since this header
 * calls out fingerprint-surface details everywhere else it can: the
 * dial-failure close can make the kernel send a TCP RST instead of a
 * clean FIN. cloak_firstpacket_want() bounds every read to exactly what
 * the parser still needs to reach a verdict, so a client that sent more
 * than that (e.g. a full request following one junk byte) leaves the
 * excess sitting unread in the socket's receive buffer; closing an fd
 * with unread inbound data queued is what makes Linux emit RST rather
 * than FIN, regardless of anything this module does deliberately. This
 * is judged acceptable rather than fixed: it is only reachable when
 * RedirAddr is already unreachable (an operator-visible outage, not
 * ordinary traffic), and an ordinary web server that closes early with
 * data still queued -- e.g. hitting a request-size or timeout limit --
 * produces the identical RST, so it is not a signal that distinguishes
 * this server from a real one. The mitigation NOT taken is a
 * non-blocking drain of the client fd immediately before this close:
 * cheap, but it has its own edge case (a client that keeps trickling
 * bytes for the duration of the drain window can extend it indefinitely,
 * turning a bounded close into an unbounded one) and was not worth
 * taking on for a signal that already fails to distinguish this server
 * from a real one.
 *
 * AUTHENTICATION: a connection whose first packet is a TLS record parses
 * as a real Cloak ClientHello, passes the replay check, decrypts, carries
 * a valid encryption method, an authorised UID, and a known proxy method
 * attaches to a cloak_session_t (new or existing) instead of falling
 * through to redirect -- see dispatcher.c's dispatcher_authenticate for
 * the ordered list of checks and docs/superpowers/plans/
 * 2026-09-13-libcloak-server-dispatcher-plan.md's task-2 brief for why
 * each one is where it is. Every other connection -- wrong transport,
 * unparseable, replayed, undecryptable, unauthorised, or an unknown proxy
 * method -- is treated exactly like any other non-Cloak connection and
 * redirected, matching Go Cloak's own behaviour. The exception is class
 * (b) above: once authentication succeeds the client has (or is about
 * to have) a ServerHello, so the cover story is blown regardless, and
 * every failure from that point on (step-10 reply-write, step-11
 * cloak_session_add_conn, or the session having already been torn down
 * from underneath this connection) closes rather than redirects -- see
 * conn_reply_write_failed's and conn_handoff's own comments in
 * dispatcher.c.
 *
 * TEARDOWN: cloak_dispatcher_destroy walks every connection still
 * in-flight (reading its first packet, mid-dial, mid-relay, or mid-reply-
 * write) and tears each one down -- cancelling its deadline, cancelling
 * or stopping whatever redirect machinery is live, closing a brand-new
 * session this connection created but never finished attaching to
 * PROVIDED no other connection has since attached to it in the meantime
 * (see conn_teardown's own comment in dispatcher.c, and this module's I1
 * finding for why "created this session" alone is not sufficient), and
 * closing whatever fd(s) the connection still owns. This is the caller's
 * own shutdown, not a failure path, so nothing here is reported back to
 * whoever initiated it.
 *
 * OWNERSHIP, stated once: a connection owns its client fd from the moment
 * cloak_dispatcher_accept takes it until the moment that ownership passes
 * elsewhere -- to cloak_relay_start (which then owns both fds until it
 * closes them) or to cloak_session_add_conn. The connection
 * sets its own fd field to -1 at exactly the instant ownership leaves, so
 * that every subsequent teardown path (an error on another field,
 * cloak_dispatcher_destroy) sees -1 and knows there is nothing left for
 * it to close. Every early exit before that handoff closes the fd itself. */
typedef struct cloak_dispatcher cloak_dispatcher_t;

/* Go's readFirstPacket (internal/server/dispatcher.go) hard-codes a
 * 15-second read deadline before it reads anything at all. This is that
 * same constant: the deadline cloak_dispatcher_accept arms the moment it
 * starts feeding a client's bytes into a cloak_firstpacket_t. Without it,
 * a client that sends one deciding byte (e.g. a single 0x16) and then
 * nothing else leaves cloak_firstpacket_want() permanently non-zero,
 * pinning both the fd and the ~3KB cloak_firstpacket_t for as long as the
 * connection stays open -- i.e. forever. See cloak/firstpacket.h's own
 * top-of-file comment, which states this exact obligation as something
 * only the dispatcher (not cloak_firstpacket_t itself) can enforce. */
#define CLOAK_DISPATCHER_DEFAULT_HANDSHAKE_TIMEOUT_MS 15000u

/* This implementation's own choice, with no direct Go equivalent to port:
 * Go's goWeb dial carries no explicit deadline of its own. Without one
 * here, a cover site that accepts TCP connections but never completes
 * them (or a RedirAddr pointed at a black hole) would pin a connection's
 * heap state on cloak_dial_t forever, the same failure mode the
 * handshake deadline above prevents on the read side. */
#define CLOAK_DISPATCHER_DEFAULT_REDIRECT_DIAL_TIMEOUT_MS 10000u

/* Default per-direction buffer capacity handed to cloak_relay_start. Must
 * be large enough to hold the preload (at most CLOAK_FIRSTPACKET_MAX
 * bytes) plus room to make forward progress under ordinary backpressure. */
#define CLOAK_DISPATCHER_DEFAULT_RELAY_BUF_CAP ((size_t)16384)

/* A DELIBERATE DIVERGENCE FROM GO: Go's dispatchConnection has no cap on
 * how many connections it will handle concurrently and relies on its
 * runtime instead -- goroutines are cheap, and there is no per-connection
 * heap allocation of this module's shape for a cap to protect. This is a
 * C server: cloak_dispatcher_accept heap-allocates one
 * cloak_dispatch_conn_t (~3KB, dominated by cloak_firstpacket_t's own
 * buffer) for every accepted fd, before that connection has proven it is
 * anything but an attacker -- unauthenticated, unvalidated, wholly
 * attacker-controlled input, exactly the property this whole module's
 * top-of-file comment opens with. Without a cap, an attacker who simply
 * opens connections and sends nothing grows that allocation without
 * bound, long before any per-connection deadline would reclaim it.
 *
 * max_pending_conns bounds d->pending_count, NOT d->conn_count -- a
 * connection counts against it from accept until it either enters the
 * relaying state or is handed off to a session, and stops counting the
 * moment either happens, even though it stays on d->conns (for teardown)
 * for as long as it lives after that. This distinction is load-bearing,
 * not cosmetic: a relaying connection's lifetime is controlled by
 * whoever it is relaying to, not by this module, so counting it against
 * this cap would let an attacker who simply opens max_pending_conns
 * connections, lets each one redirect, and then holds every one of them
 * open (trivial: control the peer on the other end of the relay) starve
 * every legitimate client of a slot -- permanently, since nothing here
 * would ever reclaim it. That is a remotely triggerable denial of
 * service strictly worse than the memory-exhaustion failure this cap
 * exists to prevent: unbounded-but-degrading traded for a hard, cheap,
 * permanent one. Once a connection IS relaying, the two descriptors and
 * the relay's own buffers it holds are bounded the same way a real web
 * server's own connections are: by the process's descriptor limit, not
 * by this cap -- and that analogy is exactly right, because at that
 * point this server genuinely IS proxying to a web server, and capping
 * the cover story itself would be self-defeating (refusing to redirect
 * is precisely the behaviour that would distinguish this server from a
 * real one to anyone watching). See cloak_dispatcher_accept's own
 * comment for where pending_count is incremented and decremented.
 *
 * A KNOWN, UNAVOIDABLE RESIDUAL: this cap is necessarily indiscriminate.
 * Before a connection's first packet is even read, the dispatcher cannot
 * know whether it will turn out to be a redirect (using a pending slot
 * only briefly), a brand-new authenticated session, or an additional
 * connection to a session that ALREADY exists (attaching in effectively
 * no time once its ClientHello arrives) -- so a cap sized correctly for
 * legitimate load can still, in principle, turn away a legitimate client
 * that arrives while the cap is saturated by other pending connections,
 * regardless of what any of them eventually turn out to be. There is no
 * way to distinguish "legitimate" from "attacker-controlled" pending
 * connections before authentication succeeds, which is the whole reason
 * this cap -- an indiscriminate one -- exists at all; this is a
 * structural trade-off, not an oversight. */
#define CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS ((size_t)512)

/* Invoked exactly once per authenticated connection, ONLY when that
 * connection's (uid, session_id) is about to create a brand-new session
 * (cloak_server_registry_find found nothing) -- never for an additional
 * connection to a session that already exists, since there is nothing
 * left for this callback to prepare in that case. This is the owner's one
 * chance to install its own on_new_stream/on_stream_data/on_writable
 * (plus their userdata) into *config before cloak_server_registry_get_or_
 * create runs; info is the fully authorised cloak_server_clientinfo_t
 * (uid already checked against cloak_server_is_bypass, proxy_method
 * already checked against cloak_server_lookup_proxy) this session is
 * being created for.
 *
 * The owner MUST NOT set config->on_broken or config->on_broken_userdata
 * -- cloak_server_registry_get_or_create overwrites both unconditionally
 * regardless of what is here, and cloak/registry.h's own doc comment
 * explains why: the registry needs its own hook to do the bookkeeping
 * that makes cloak_server_registry_close and the sweep timer work at all.
 * Anything written to either field here is simply discarded.
 *
 * Returning -1 abandons the handshake: the connection is redirected to
 * RedirAddr exactly as if authentication itself had failed, and
 * cloak_server_registry_get_or_create is never called -- so nothing is
 * left in the registry. Returning 0 proceeds to create the session with
 * *config as (possibly) modified by this callback.
 *
 * CALLING CONTEXT: this fires synchronously from inside
 * dispatcher_authenticate, itself called from conn_on_firstpacket_done,
 * itself called from this connection's own on_readable -- i.e. from deep
 * inside this SAME connection's dispatch call chain, with c (the
 * connection this callback's own info/config describe) still live on the
 * stack above this call, about to be touched again once this callback
 * returns regardless of whether it returns 0 or -1. Calling
 * cloak_dispatcher_destroy(d) from here frees that same connection out
 * from under its own still-running call chain -- a use-after-free, not
 * merely against the rules, on both this callback's return paths. Do not
 * call it, or anything else that could free or hand off this connection,
 * from within this callback; ordinary read-only accessors
 * (cloak_server_registry_find, cloak_server_registry_count,
 * cloak_dispatcher_conn_count/pending_count) are fine. */
typedef int (*cloak_dispatch_prepare_session_cb)(cloak_dispatcher_t *d,
                                                  const cloak_server_clientinfo_t *info,
                                                  cloak_session_config_t *config,
                                                  void *userdata);

/* Fired once per authenticated connection, after cloak_session_add_conn
 * has already succeeded -- i.e. this connection is now genuinely part of
 * sesh's pool. created is 1 if this connection is what just created sesh
 * (cloak_dispatch_prepare_session_cb, if non-NULL, already ran for it) or
 * 0 if sesh already existed and this connection merely attached to it.
 * info is the same authorised cloak_server_clientinfo_t
 * cloak_dispatch_prepare_session_cb would have seen (had it run) --
 * notably, on the created == 0 path, info still describes THIS
 * connection's own authentication, not whatever created sesh originally,
 * so a caller wanting session-identifying data should prefer sesh's own
 * (uid, session_id) it already tracks rather than re-deriving it from
 * info on this path.
 *
 * CALLING CONTEXT: this fires from inside conn_handoff, BEFORE the
 * connection it describes is unlinked from d's own list and freed --
 * conn_handoff's own remaining work (cancelling its deadline, unlinking
 * it, freeing it) still runs after this callback returns. Two
 * consequences: calling cloak_dispatcher_destroy(d) from here walks and
 * frees that same still-linked, not-yet-freed connection as part of
 * destroying d, so conn_handoff's own unlink-and-free of it afterward is
 * a double free -- do not call it from here. And cloak_dispatcher_
 * conn_count(d)/cloak_dispatcher_pending_count(d), if read from within
 * this callback, still include this connection (its own unlink/decrement
 * has not happened yet) -- a caller that wants the post-hand-off count
 * should read it after this callback returns, not from inside it. */
typedef void (*cloak_dispatch_attached_cb)(cloak_dispatcher_t *d, cloak_session_t *sesh,
                                            const cloak_server_clientinfo_t *info, int created,
                                            void *userdata);

/* Everything cloak_dispatcher_init needs. reactor, srv and registry are
 * all borrowed, not copied or owned: every one of them must outlive every
 * connection the dispatcher ever accepts, i.e. for the dispatcher's own
 * whole lifetime.
 *
 * srv is deliberately NOT const (unlike a plain read-only accessor):
 * cloak_server_check_replay mutates srv's replay cache, and the
 * dispatcher must call it on every authentication attempt (see
 * dispatcher.c's dispatcher_authenticate) -- so the caller's own
 * cloak_server_t must itself be non-const/mutable, exactly like every
 * existing caller in this codebase already constructs it as.
 *
 * registry may be NULL: authentication can then never succeed (every
 * cloak_server_registry_find/get_or_create call this module makes
 * tolerates a NULL registry by reporting "not found"/"cannot create",
 * exactly like every other NULL-tolerant accessor cloak/registry.h
 * documents), so every otherwise-successful handshake redirects instead
 * -- useful for a caller (or a test) that only wants the redirect path
 * exercised and has no registry to offer yet.
 *
 * session_config_template is copied by value into every NEWLY created
 * session's config (cloak_server_registry_find found nothing): the
 * dispatcher overwrites exactly two fields of the copy before passing it
 * to cloak_server_registry_get_or_create --
 * obfuscator.method (the client's authenticated, wire-validated
 * encryption method) and obfuscator.session_key (a fresh
 * cloak_random_bytes key) -- so whatever this template's own obfuscator
 * field holds is irrelevant and always replaced. on_broken/
 * on_broken_userdata are similarly irrelevant here for the same reason
 * cloak_dispatch_prepare_session_cb's own doc comment gives: get_or_create
 * overwrites both unconditionally. This template is NEVER consulted on
 * the existing-session path (cloak_server_registry_find succeeded) --
 * see cloak/registry.h's own warning that the existing-session path
 * discards *config entirely, obfuscator included, which is why the live
 * session's own key must be read back out of it rather than recomputed
 * from this template; dispatcher.c's dispatcher_authenticate does exactly
 * that.
 *
 * prepare_session/prepare_session_userdata and attached/attached_userdata
 * may each be NULL independently (no-op / nothing to fire).
 *
 * The four *_ms/_cap/_conns fields each default (0 means "use the
 * default") to the CLOAK_DISPATCHER_DEFAULT_* constant above; a config
 * that leaves them zeroed gets exactly Go's 15-second first-packet
 * deadline and this port's own 512-connection cap. Tests that need to
 * exercise the deadline without an actual 15-second wait set
 * handshake_timeout_ms explicitly instead, and tests that need to
 * exercise the cap without opening 512 connections set max_pending_conns
 * explicitly the same way. */
typedef struct {
    cloak_reactor_t *reactor;
    cloak_server_t *srv;
    cloak_server_registry_t *registry;

    cloak_session_config_t session_config_template;
    cloak_dispatch_prepare_session_cb prepare_session;
    void *prepare_session_userdata;
    cloak_dispatch_attached_cb attached;
    void *attached_userdata;

    uint64_t handshake_timeout_ms;
    uint64_t redirect_dial_timeout_ms;
    size_t relay_buf_cap;

    /* See CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS's own comment for
     * why this exists at all, and for why it bounds PENDING connections
     * only (mid first-packet, mid-dial, mid-reply-write) rather than
     * every connection this dispatcher is tracking -- a relaying
     * connection does not count against it. Checked in
     * cloak_dispatcher_accept against cloak_dispatcher_pending_count
     * (the same counter that accessor reports, distinct from
     * cloak_dispatcher_conn_count) BEFORE any allocation happens for the
     * new fd. */
    size_t max_pending_conns;
} cloak_dispatcher_config_t;

typedef struct cloak_dispatch_conn cloak_dispatch_conn_t;

/* One in-flight, not-yet-authenticated connection. Heap-allocated at
 * accept, freed when it is handed off, redirected, or dropped. Its
 * address is the reactor's callback userdata (for its own fd, its
 * deadline timer, its cloak_dial_t and its cloak_relay_t all at once, at
 * different points in its life), so it must never move.
 *
 * fd is -1 once ownership of it has left this connection (handed to
 * cloak_relay_start, or already closed on a path that drops the
 * connection) -- see cloak_dispatcher_t's own doc comment for the
 * ownership rule this implements.
 *
 * dialing, relaying and writing_reply are never more than one set at a
 * time: they mark which piece of post-first-packet machinery (if any)
 * currently has a live registration with the reactor, so teardown code
 * knows which of cloak_dial_cancel/cloak_relay_stop/"just remove_fd and
 * close" it must apply, rather than trying all of them defensively
 * against whichever one happens to hold stale zeroed state.
 *
 * auth_created, auth_uid, auth_session_id and auth_info are populated by
 * a SUCCESSFUL dispatcher_authenticate (dispatcher.c) and are what
 * carries a connection's authentication result across the non-blocking
 * reply write (writing_reply) to the eventual hand-off -- they are
 * meaningless (and untouched) before that point. auth_created is THE
 * unwind discriminator conn_teardown uses: see its own comment in
 * dispatcher.c and cloak/registry.h's own "created == 1" guidance on
 * cloak_server_registry_close for why closing unconditionally instead
 * would be wrong -- and why even auth_created == 1 alone is not quite
 * enough; conn_teardown's own comment has the rest.
 *
 * Deliberately NOT stored here: a cloak_session_t* captured at
 * authentication time. auth_uid/auth_session_id are what conn_handoff and
 * conn_teardown both use to re-resolve the session via
 * cloak_server_registry_find immediately before touching it, rather than
 * dereferencing a raw pointer that spans the writing_reply gap -- a gap
 * the registry can free that exact memory within, via either another
 * connection's session breaking (a zero-delay sweep timer) or this
 * session's own inactivity timeout. A stored pointer field here would
 * invite exactly the use-after-free re-resolving avoids; see
 * conn_handoff's own comment in dispatcher.c for the full sequence.
 *
 * pending is 1 from cloak_dispatcher_accept until this connection either
 * starts relaying or is handed off to a session, and 0 for the rest of
 * its life after that -- see CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS's
 * own comment for why the cap must stop counting a connection at exactly
 * that point. It governs d->pending_count the same way this struct being
 * linked into d->conns at all governs d->conn_count: cleared (with the
 * matching decrement) in conn_unlink for every path that removes this
 * connection while still pending, and cleared separately, in
 * on_dial_done, for the one path (entering the relaying state) that does
 * NOT remove it from d->conns at that moment. */
struct cloak_dispatch_conn {
    cloak_dispatcher_t *d;
    int fd;
    uint16_t local_port;
    cloak_firstpacket_t fp;
    cloak_timer_id_t deadline;
    int pending;

    /* Redirect state. Only one of dialing/relaying/writing_reply is live
     * at a time. */
    cloak_dial_t dial;
    int dialing;
    cloak_relay_t relay;
    int relaying;

    /* Authenticated-reply-write state (dispatcher.c's step 10). reply_len
     * is the total number of bytes cloak_server_auth_compose_reply wrote;
     * reply_sent is how many of those this connection has successfully
     * written to fd so far. writing_reply is 1 exactly while fd is
     * registered CLOAK_REACTOR_WRITABLE for this purpose. */
    int writing_reply;
    uint8_t reply[CLOAK_SERVER_AUTH_REPLY_MAX_BYTES];
    size_t reply_len;
    size_t reply_sent;

    /* Authentication result, valid only once dispatcher_authenticate has
     * returned success for this connection -- see this struct's own
     * top-of-task comment above. */
    int auth_created;
    uint8_t auth_uid[CLOAK_UID_LEN];
    uint32_t auth_session_id;
    cloak_server_clientinfo_t auth_info;

    struct cloak_dispatch_conn *prev, *next; /* dispatcher's intrusive list */
};

struct cloak_dispatcher {
    cloak_dispatcher_config_t cfg;

    /* Every connection currently reading its first packet, dialing the
     * cover site, being relayed to it, or (once authenticated) draining
     * its non-blocking reply write before hand-off. NULL when empty. A
     * connection unlinks itself (and frees itself) the moment it is
     * finished -- handed off, redirected to completion, or dropped -- so
     * this list is exactly "still in flight", never a history. */
    cloak_dispatch_conn_t *conns;
    size_t conn_count;

    /* Everything conn_count counts EXCEPT a connection that has started
     * relaying -- see CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS's own
     * comment for why relaying connections must not count against
     * max_pending_conns, and cloak_dispatch_conn_t's own "pending" field
     * comment for exactly where this is kept in step with conn_count.
     * Always <= conn_count. This is what cloak_dispatcher_accept checks
     * against the cap, NOT conn_count. */
    size_t pending_count;
};

/* Zeroes d and validates the rest -- in that order, so that ANY failure
 * return (including cfg, cfg->reactor or cfg->srv being NULL) still
 * leaves d in a state cloak_dispatcher_destroy can safely be called
 * against. Four earlier constructors on this project got this ordering
 * backwards, and it was a crash every time a caller's own cleanup code
 * ran destroy against an uninitialized struct.
 *
 * Copies *cfg by value (d does not borrow the cfg struct itself), filling
 * in CLOAK_DISPATCHER_DEFAULT_* for any of handshake_timeout_ms,
 * redirect_dial_timeout_ms, relay_buf_cap or max_pending_conns left at 0.
 * cfg->reactor and cfg->srv are themselves still borrowed pointers -- see
 * cloak_dispatcher_config_t's own doc comment.
 *
 * A non-zero relay_buf_cap smaller than CLOAK_FIRSTPACKET_MAX is REJECTED
 * here rather than accepted and left to fail later: cloak_relay_start
 * requires preload_len <= buf_cap, so such a value would make every
 * single redirect's cloak_relay_start call fail -- which this module
 * correctly treats as close-not-redirect, but that silently defeats the
 * "every failure redirects" property this whole module exists for, from
 * nothing worse than a config typo. Rejecting it loudly here, where a
 * caller is checking a return value, is the only place that failure mode
 * can be caught before it is indistinguishable from working.
 *
 * Returns 0 on success, -1 if d is NULL, cfg, cfg->reactor or cfg->srv is
 * NULL, or cfg->relay_buf_cap is non-zero and smaller than
 * CLOAK_FIRSTPACKET_MAX. */
int cloak_dispatcher_init(cloak_dispatcher_t *d, const cloak_dispatcher_config_t *cfg);

/* Tears down every connection still in flight: cancels each one's
 * deadline timer, cancels an in-progress dial or stops an in-progress
 * relay (whichever, if either, is live), closes a brand-new session this
 * connection created (auth_created) but never finished attaching to --
 * PROVIDED no other connection has since attached to it in the meantime,
 * see conn_teardown's own comment in dispatcher.c for why "created this
 * session" alone does not gate this -- and closes whatever fd(s) that
 * connection still owns, including one still registered
 * CLOAK_REACTOR_WRITABLE for a not-yet-drained post-authentication reply
 * write (writing_reply). Neither cloak_dial_cancel nor cloak_relay_stop
 * fires its normal completion callback for a connection torn down this
 * way -- this is the caller's own shutdown, not a failure to report.
 *
 * Idempotent, and safe on a dispatcher left zeroed by a failed
 * cloak_dispatcher_init. Does not touch cfg.reactor or cfg.srv themselves
 * -- the caller owns both and must not destroy either before this
 * returns, since this call still uses cfg.reactor to cancel timers and
 * unregister fds.
 *
 * NULL d is a no-op. */
void cloak_dispatcher_destroy(cloak_dispatcher_t *d);

/* The cloak_listener_accept_cb to hand to cloak_listener_open, with a
 * live cloak_dispatcher_t as userdata. See this file's own top-of-file
 * comment for the full wiring and ownership contract; in short, ownership
 * of fd passes here, unconditionally -- every path through this function
 * either keeps it (linking a new connection into d) or closes it.
 *
 * THE CAP: if cloak_dispatcher_pending_count(d) -- NOT
 * cloak_dispatcher_conn_count(d); see cloak_dispatcher_t's own
 * pending_count comment for why they differ -- is already at
 * cfg.max_pending_conns, fd is closed immediately and nothing is
 * allocated -- see CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS's own
 * comment for why a C dispatcher needs this where Go's does not, and for
 * why a relaying connection must not count against it (counting it would
 * itself be a remotely triggerable, permanent denial of service). This is
 * the one place in this module where closing, not redirecting, is
 * correct: every other close-instead-of-redirect path in this file is a
 * case with nowhere to redirect TO (the peer is already gone, or the
 * dial itself failed); this one has somewhere to redirect to but
 * deliberately declines, because redirecting here costs a second fd (the
 * dial) and, if that dial succeeds, a live relay holding buffers for
 * both sides -- exactly the resources this cap exists to conserve
 * because they are already exhausted. Spending them to keep up the cover
 * story at the exact moment resources ran out would defeat the cap
 * entirely, so this is not the bug it looks like next to every other
 * rule in this file.
 *
 * pending_count is incremented here, unconditionally, for every
 * connection that gets past the cap check (see c->pending's own comment
 * in cloak/dispatcher.h for exactly where it is later decremented). This
 * check is necessarily indiscriminate -- see
 * CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS's own "KNOWN, UNAVOIDABLE
 * RESIDUAL" paragraph -- and can turn away a legitimate client purely
 * because the cap happens to be saturated by other pending connections at
 * that instant, since nothing is knowable about a connection's
 * legitimacy before its first packet is even read. */
void cloak_dispatcher_accept(cloak_listener_t *l, int fd, void *userdata);

/* The number of connections currently in flight (reading their first
 * packet, dialing, being relayed, or draining a post-authentication reply
 * write). NULL d returns 0. This is NOT what the cap is checked against
 * -- see cloak_dispatcher_pending_count for that. */
size_t cloak_dispatcher_conn_count(const cloak_dispatcher_t *d);

/* The number of connections currently counting against max_pending_conns
 * -- every connection cloak_dispatcher_conn_count would also count,
 * EXCEPT one that has already started relaying (see
 * CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS's own comment for why that
 * exclusion exists). Always <= cloak_dispatcher_conn_count(d). NULL d
 * returns 0. */
size_t cloak_dispatcher_pending_count(const cloak_dispatcher_t *d);

#endif
