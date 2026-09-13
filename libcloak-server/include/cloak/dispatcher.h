#ifndef CLOAK_DISPATCHER_H
#define CLOAK_DISPATCHER_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/firstpacket.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/server.h"

/* The server's front door: turns an accepted connection into either a
 * redirect to the cover site or (from a later task) an authenticated
 * session. This is the C equivalent of Go Cloak's dispatchConnection
 * (internal/server/dispatcher.go).
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
 * RedirAddr rather than closing the connection. Closing tells a prober
 * that something other than a web server is listening, which is exactly
 * what Cloak exists to prevent -- so an unrecognised protocol, an
 * oversized or malformed first packet, and (until a later task replaces
 * the stub) a failed authentication all take the same path: forward
 * whatever the client already sent to the cover site and splice the two
 * sockets together. The only cases that close instead are the ones where
 * there is nothing to redirect: the peer already went away (there is no
 * one to forward to), or the redirect dial itself failed (there is
 * nowhere to forward to).
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
 * AUTHENTICATION IS STUBBED IN THIS TASK: every connection that completes
 * its first packet is treated as unauthenticated and redirected. This
 * makes the server behave exactly like Go Cloak does for any non-Cloak
 * connection today, which is why it is a real milestone rather than
 * scaffolding -- Task 2 replaces the stub with real ClientHello parsing,
 * decryption, replay checking and session lookup, at which point a
 * successful authentication starts handing connections to a
 * cloak_session_t instead of always falling through here.
 *
 * TEARDOWN: cloak_dispatcher_destroy walks every connection still
 * in-flight (reading its first packet, mid-dial, or mid-relay) and tears
 * each one down -- cancelling its deadline, cancelling or stopping
 * whatever redirect machinery is live, and closing whatever fd(s) the
 * connection still owns. This is the caller's own shutdown, not a failure
 * path, so nothing here is reported back to whoever initiated it.
 *
 * OWNERSHIP, stated once: a connection owns its client fd from the moment
 * cloak_dispatcher_accept takes it until the moment that ownership passes
 * elsewhere -- to cloak_relay_start (which then owns both fds until it
 * closes them) or, in Task 2, to cloak_session_add_conn. The connection
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

/* Everything cloak_dispatcher_init needs. reactor and srv are borrowed,
 * not copied or owned: both must outlive every connection the dispatcher
 * ever accepts, i.e. for the dispatcher's own whole lifetime.
 *
 * The three *_ms/_cap fields each default (0 means "use the default")
 * to the CLOAK_DISPATCHER_DEFAULT_* constant above; a config that leaves
 * them zeroed gets exactly Go's 15-second first-packet deadline. Tests
 * that need to exercise the deadline without an actual 15-second wait
 * set handshake_timeout_ms explicitly instead. */
typedef struct {
    cloak_reactor_t *reactor;
    const cloak_server_t *srv;

    uint64_t handshake_timeout_ms;
    uint64_t redirect_dial_timeout_ms;
    size_t relay_buf_cap;
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
 * dialing and relaying are never both set: they mark which of dial/relay
 * (if either) currently has a live registration with the reactor, so
 * teardown code knows which of cloak_dial_cancel/cloak_relay_stop (if
 * either) it must call, rather than calling both defensively against
 * whichever one happens to hold stale zeroed state. */
struct cloak_dispatch_conn {
    cloak_dispatcher_t *d;
    int fd;
    uint16_t local_port;
    cloak_firstpacket_t fp;
    cloak_timer_id_t deadline;

    /* Redirect state. Only one of these is live at a time. */
    cloak_dial_t dial;
    int dialing;
    cloak_relay_t relay;
    int relaying;

    struct cloak_dispatch_conn *prev, *next; /* dispatcher's intrusive list */
};

struct cloak_dispatcher {
    cloak_dispatcher_config_t cfg;

    /* Every connection currently reading its first packet, dialing the
     * cover site, or being relayed to it. NULL when empty. A connection
     * unlinks itself (and frees itself) the moment it is finished --
     * handed off, redirected to completion, or dropped -- so this list is
     * exactly "still in flight", never a history. */
    cloak_dispatch_conn_t *conns;
    size_t conn_count;
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
 * redirect_dial_timeout_ms or relay_buf_cap left at 0. cfg->reactor and
 * cfg->srv are themselves still borrowed pointers -- see
 * cloak_dispatcher_config_t's own doc comment.
 *
 * Returns 0 on success, -1 if d is NULL, or cfg, cfg->reactor or cfg->srv
 * is NULL. */
int cloak_dispatcher_init(cloak_dispatcher_t *d, const cloak_dispatcher_config_t *cfg);

/* Tears down every connection still in flight: cancels each one's
 * deadline timer, cancels an in-progress dial or stops an in-progress
 * relay (whichever, if either, is live), and closes whatever fd(s) that
 * connection still owns. Neither cloak_dial_cancel nor cloak_relay_stop
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
 * either keeps it (linking a new connection into d) or closes it. */
void cloak_dispatcher_accept(cloak_listener_t *l, int fd, void *userdata);

/* The number of connections currently in flight (reading their first
 * packet, dialing, or being relayed). NULL d returns 0. */
size_t cloak_dispatcher_conn_count(const cloak_dispatcher_t *d);

#endif
