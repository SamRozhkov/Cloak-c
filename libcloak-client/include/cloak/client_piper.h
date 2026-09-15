#ifndef CLOAK_CLIENT_PIPER_H
#define CLOAK_CLIENT_PIPER_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/session.h"
#include "cloak/stream_relay.h"

/* The client's data path: the local listener an application actually
 * points at. Every connection accepted on it becomes ONE stream on the
 * Cloak session cloak_client_connector_t brought up, spliced together by
 * a cloak_stream_relay_t. This is the C equivalent of the goroutine Go
 * Cloak's RouteTCP spawns per accepted local connection
 * (internal/client/piper.go).
 *
 * IT IS THE EXACT MIRROR OF cloak_proxy_t (cloak/proxy.h), and is written
 * that way on purpose. The server splices a stream it was HANDED with a
 * socket it DIALS; this splices a stream it OPENS with a socket it was
 * handed by an accept. Everything else -- one heap context per stream, an
 * intrusive list, a per-context deadline, the save-`next`-before-calling-
 * out iteration in both notify loops, and a single teardown walk driven
 * by several entry points -- is the same shape, deliberately. Those rules
 * were established over two review rounds and a use-after-free on the
 * server side; read cloak/proxy.h before changing any of them here.
 *
 * WIRING, and all four parts are obligatory:
 *
 *     cloak_client_piper_init(&piper, &pcfg);
 *     cloak_client_piper_install(&piper, &ccfg.session_template);
 *     ... cloak_client_connector_start(...) ... on DONE:
 *     cloak_client_piper_set_session(&piper, session);
 *     cloak_listener_open(&l, r, addr, cloak_client_piper_on_accept, &piper, ...);
 *
 * cloak_client_piper_install supplies ALL FOUR of the session's
 * callbacks, which is the one structural difference from the server: on
 * the server the registry owns on_broken and cloak_proxy_t may not touch
 * it, whereas on the client nothing else wants it, so this module takes
 * it and offers cloak_client_piper_config_t::chain to an owner that has
 * bookkeeping of its own. That matters because on_broken is THE ONLY
 * WINDOW in which a relay bound to a dying session can still be stopped
 * (cloak/stream_relay.h); an owner that installed its own on_broken over
 * this one would have a use-after-free, not a working client.
 *
 * LIFETIME: the piper holds a heap-allocated context per accepted local
 * connection. Each is reactor and relay callback userdata, so none ever
 * moves, and THE PIPER MUST BE DESTROYED BEFORE THE SESSION IT WAS GIVEN
 * -- cloak_client_piper_destroy is what stops the relays that
 * cloak/stream_relay.h requires be stopped first.
 *
 * ---- THE TWO MODES, AND HOW TO TELL THEM APART ------------------------
 *
 * ONE FIELD ANSWERS IT EVERYWHERE: cloak_client_piper_conn_t::sesh, the
 * session THAT ONE local connection is spliced onto. Every dereference in
 * this module goes through it and through nothing else, so the two modes
 * differ only in where it came from and in who ends it:
 *
 *   SHARED (config::singleplex == 0, Go's NumConn >= 1). The owner brings
 *   up one session, hands it over with cloak_client_piper_set_session,
 *   and every accepted connection copies it into its own ctx->sesh at
 *   accept time. cloak_client_piper_t::sesh is that session; ctx->sesh
 *   equals it for every live context; ctx->own_sesh is 0 and this module
 *   never closes anything.
 *
 *   SINGLEPLEX (config::singleplex == 1, Go's NumConn <= 0).
 *   cloak_client_piper_t::sesh is ALWAYS NULL -- there is no shared
 *   session and cloak_client_piper_set_session is never called. Each
 *   context starts with ctx->sesh == NULL, asks the owner for a session
 *   of its own through config::new_session, receives it through
 *   cloak_client_piper_conn_session_ready, and sets ctx->own_sesh == 1.
 *   When that context's life ends, this module calls cloak_session_close
 *   on that session -- Go's `sesh.Close()` in RouteTCP's singleplex
 *   branch -- and the owner reaps it from config::chain.
 *
 * So: pp->sesh non-NULL means shared; ctx->own_sesh means singleplex; and
 * ctx->sesh == NULL on a live context means a singleplex connection whose
 * session has not arrived yet. There is no third combination, and no
 * function in this file consults config::singleplex to decide what to do
 * with a session it already has.
 *
 * THE SESSION IS NOT ASSUMED TO OUTLIVE ANY CONTEXT, and that is not
 * defensive coding: singleplex gives each local connection its OWN
 * session, which dies when that connection's stream ends -- so the mode
 * that creates and destroys sessions most often is exactly the mode in
 * which a context can outlive its session by a callback, and the mode in
 * which the session genuinely dies first. Three things enforce it rather
 * than merely hope for it: a context's ctx->sesh is NULL whenever there
 * is no session it may touch; piper_on_broken tears down every context
 * bound to the dying session FIRST, while that session is still usable,
 * and only then forgets it; and an accept that has no session and no way
 * to get one is closed rather than queued.
 *
 * OWNERSHIP OF SOCKETS, stated once: a cloak_client_piper_conn_t NEVER
 * owns its local descriptor for longer than one window. It belongs to the
 * accept callback's caller until this module takes it; to
 * cloak_client_piper_conn_t::fd from that instant until a
 * cloak_stream_relay_start succeeds; and to the relay from then on (which
 * closes it on completion or on cloak_stream_relay_stop). fd is the ONE
 * field that says which of the three holds it: it is -1 whenever this
 * module does not itself hold a descriptor, exactly as
 * cloak_proxy_stream_t::fd_pending is.
 *
 * A STREAM IS RELEASED IN EXACTLY TWO PLACES, and nowhere else:
 * cloak_stream_relay_t's done callback (the ordinary end of a stream's
 * life) and the shared teardown walk that cloak_client_piper_destroy and
 * piper_on_broken both drive -- ONE walk, deliberately, for the same
 * reason cloak_proxy_t has one. cloak/session.h requires exactly one
 * cloak_session_release_stream per stream, or its memory leaks for the
 * life of the process. */
typedef struct cloak_client_piper cloak_client_piper_t;

/* ---- D6: read the first bytes BEFORE opening a stream -------------------
 *
 * Go's RouteTCP does io.ReadAtLeast(localConn, data, 1) under the stream
 * timeout and only then calls sesh.OpenStream(). This port does the same,
 * and the reason is worth stating because the obvious implementation --
 * open a stream the moment accept returns -- looks simpler and is wrong.
 *
 * A local connection that opens and sends NOTHING is a normal event, not
 * an attack: a port scanner, a health check, a browser's speculative
 * socket, an application's connection pool pre-warming. Opening a stream
 * for one of those costs a stream id on this session, a stream context
 * here, a cloak_proxy_stream_t and a DIALED UPSTREAM SOCKET on the
 * server, and the server's per-session stream cap -- all for a connection
 * that will never carry a byte. Waiting for the first byte costs one
 * context and one descriptor on this side and nothing at all on the
 * server's.
 *
 * THE DEADLINE ON THAT READ IS WHAT STOPS IT PINNING RESOURCES. Without
 * one, "waiting for the first byte" is unbounded and the cheap local
 * context becomes the leak instead. See CLOAK_CLIENT_PIPER_DEFAULT_FIRST_
 * BYTE_TIMEOUT_MS and cloak_client_piper_config_t::max_local_conns, which
 * bound that wait in time and in count respectively. */

/* The most bytes read from the local connection before its stream is
 * opened -- Go's `data := make([]byte, 10240)`, kept verbatim. It is a
 * buffer size, not a threshold: ONE byte is enough to proceed, and this
 * only bounds how much is taken in the same breath.
 *
 * IT IS ADDITIONALLY CLAMPED, per connection, TO ONE FRAME'S PAYLOAD
 * (session->max_on_wire_size - CLOAK_FRAME_HEADER_LEN -
 * CLOAK_FRAME_MAX_EXTRA_LEN), and that clamp is load-bearing rather than
 * tidiness. These bytes are written with cloak_stream_write, which
 * cannot fail on a full queue (cloak/session.h) -- an overrun surfaces
 * one layer down as a broken connection that takes the whole pool and
 * every other stream with it. The only room this module can PROVE it has
 * at that moment is the one worst-case frame cloak_stream_relay_start
 * just checked for, so the first write is sized to be exactly one
 * frame. */
#define CLOAK_CLIENT_PIPER_FIRST_BYTES ((size_t)10240)

/* How long a local connection may sit accepted without sending its first
 * byte. Go's own: ck-client's StreamTimeout, which defaults to 300
 * seconds (internal/client/state.go) and is applied as exactly this
 * deadline in RouteTCP.
 *
 * Much smaller and a protocol whose server speaks first -- SMTP, FTP,
 * IMAP, SSH through a SOCKS proxy that has already connected -- is killed
 * while behaving correctly; the local application would see connections
 * dropped for no reason it could diagnose. Much larger, or absent, and
 * every connection that never speaks pins a context, a 10 KiB buffer and
 * a descriptor for that long, which is what D6's whole saving is spent
 * on. 300 s matches the reference and keeps this port's timeout
 * behaviour identical to Go's for the same config. */
#define CLOAK_CLIENT_PIPER_DEFAULT_FIRST_BYTE_TIMEOUT_MS ((uint64_t)300000)

/* Per-direction buffer capacity handed to cloak_stream_relay_start, for
 * the stream-to-fd queue (the other direction needs none --
 * cloak_stream_write always accepts what it is given). The same value as
 * CLOAK_PROXY_DEFAULT_RELAY_BUF_CAP, matched deliberately: the two ends
 * of one tunnel should not disagree about what a reasonable per-stream
 * buffer is, and 16 KiB is one whole max_on_wire_size frame with room to
 * spare, which is the smallest value that keeps the common case to a
 * single reactor turn. Much larger and the cost is paid per CONCURRENT
 * LOCAL CONNECTION. */
#define CLOAK_CLIENT_PIPER_DEFAULT_RELAY_BUF_CAP ((size_t)16384)

/* How long to wait before re-attempting a cloak_stream_relay_start that
 * was rejected with -2, and how many times. Both match
 * CLOAK_PROXY_DEFAULT_RETRY_DELAY_MS / _MAX_RETRIES, and the reasoning
 * there applies unchanged: -2 means "the session's pool cannot hold one
 * worst-case frame RIGHT NOW", which is ordinary congestion -- a relay
 * already running on this session holds min_conn_free below exactly that
 * threshold for as long as its own peer is slow to drain.
 *
 * ON THIS SIDE THE CONGESTED CASE IS THE COMMON ONE, not a corner: a
 * browser opening a tab while an upload is in flight produces exactly it.
 * Giving up would drop a local connection the application had every
 * reason to expect to work; cloak/stream_relay.h says in as many words
 * that a caller should wait and try again.
 *
 * The finite ceiling is not a bound on congestion -- congestion ends the
 * ladder by itself the moment the pool drains. It exists because -2 is
 * also produced by a condition that is transient in SHAPE and permanent
 * in FACT: a conn_send_queue_cap smaller than one worst-case frame's
 * on-wire cost can NEVER satisfy the check. That is an operator
 * misconfiguration, and without a ceiling every local connection such a
 * client accepted would park a descriptor, a stream and a context on a
 * timer forever. */
#define CLOAK_CLIENT_PIPER_DEFAULT_RETRY_DELAY_MS ((uint64_t)50)
#define CLOAK_CLIENT_PIPER_DEFAULT_MAX_RETRIES ((unsigned)400)

/* The most local connections this piper will hold contexts for at once.
 * Over it, the newly accepted descriptor is closed immediately and
 * nothing else happens -- no context, no stream, no effect on any
 * connection already running.
 *
 * WHY A CLIENT NEEDS A CAP AT ALL, given that Go has none and the peers
 * here are local processes rather than an adversary: because D6's wait
 * is what creates the exposure. Between accept and the first byte this
 * module holds a descriptor and a CLOAK_CLIENT_PIPER_FIRST_BYTES buffer
 * per connection for up to first_byte_timeout_ms, which defaults to five
 * minutes. Anything that can reach the local listener -- every process on
 * the host, and every host on the LAN if the listener is not bound to
 * loopback -- can therefore pin ~10 KiB and one descriptor per connection
 * for five minutes at the cost of one connect(2). Running the process out
 * of descriptors that way does not merely drop the offender's
 * connections: it breaks the tunnel for the legitimate application too,
 * and it breaks the connector's ability to re-dial.
 *
 * 256 is several times a browser's worth of concurrent connections,
 * which is the load one honest local application actually generates.
 * Much smaller and an ordinary client's own parallelism is what trips it.
 * Much larger and it stops bounding anything the descriptor limit had not
 * already bounded. */
#define CLOAK_CLIENT_PIPER_DEFAULT_MAX_LOCAL_CONNS ((size_t)256)

/* How many streams the SERVER may open toward this client, and have
 * refused, before the session is closed outright. See
 * cloak_client_piper_rejected_streams for why refusing rather than
 * accepting, and this constant for why refusing cannot go on forever.
 *
 * REFUSING IS NOT FREE, and the cost is what forces a ceiling.
 * cloak_strmtab_t remembers a closed stream id as a TOMBSTONE for the
 * whole life of the session and never reuses another key's slot
 * (cloak/strmtab.h says so, and gives the correctness reason), and every
 * refusal also emits one closing-stream frame. So a server opening N
 * distinct stream ids costs this client N permanent table entries and N
 * outbound frames -- a one-to-one amplification that is small per event
 * and unbounded in total.
 *
 * WHY CLOSING THE SESSION IS THE RIGHT CEILING, and why this does not
 * contradict the argument against closing it on the FIRST refusal. That
 * argument stands: one injected frame must not be able to drop every live
 * local connection. But a server that has opened 16 streams toward a
 * client that refused every one of them is hostile or broken, not
 * confused -- and the decisive point is that THE SERVER CAN CLOSE THIS
 * SESSION UNILATERALLY AT ANY TIME ANYWAY. Declining to continue
 * therefore costs the user nothing the other end could not already take,
 * while leaving the bounded-but-unbounded-in-total amplification above
 * with no ceiling would.
 *
 * 16 rather than 1: no correct server opens even one, so any ceiling is
 * generous, and leaving room for a handful means a server with a real bug
 * gets a diagnosable log line and a working tunnel rather than an
 * immediate disconnect. Much larger and the amplification it bounds stops
 * being bounded in any useful sense. */
#define CLOAK_CLIENT_PIPER_MAX_REJECTED_STREAMS ((size_t)16)

/* One accepted local connection, from the moment it is accepted until its
 * relay finishes. Heap-allocated and never moved: its address is the
 * userdata for its own reactor registration, its own timers and its own
 * relay.
 *
 * THE STATE MACHINE, in the order a connection passes through it:
 *
 *   1. WAITING FOR THE FIRST BYTE. fd >= 0 and fd_registered == 1, a
 *      deadline timer is armed, stream is NULL. This is D6's window.
 *   1b. WAITING FOR ITS OWN SESSION. SINGLEPLEX ONLY. fd >= 0,
 *      fd_registered == 0, awaiting_session == 1, sesh is NULL, stream is
 *      NULL, and THE SAME DEADLINE IS STILL ARMED -- it is not cancelled
 *      until a stream actually opens, which is what bounds how long an
 *      owner's handshake may pin this connection. Not one byte has been
 *      taken out of the socket yet: see cloak_client_piper_buffered_bytes
 *      for why, and for what that buys.
 *   2. RETRYING A START. fd >= 0, fd_registered == 0, stream is open,
 *      retry_timer is armed. Only reachable from a -2 rejection.
 *   3. RELAYING. fd == -1 (the relay owns it), relaying == 1.
 *
 * fd_registered, awaiting_session, retry_timer and relaying are mutually
 * exclusive in exactly the way cloak_proxy_stream_t's
 * dialing/relaying/retry_timer are, and for the same reason: the teardown
 * walk uses them to decide which piece of machinery currently holds a
 * registration (or, for awaiting_session, which outside party has to be
 * told to stop), rather than applying all of them to whichever one
 * happens to hold zeroed state. */
typedef struct cloak_client_piper_conn {
    cloak_client_piper_t *pp;

    /* The local socket. -1 whenever this object does not hold one -- see
     * this file's ownership paragraph. */
    int fd;
    int fd_registered; /* fd is registered with the reactor by US, for the
                        * first-byte read (never while relaying: the relay
                        * owns the registration then) */

    cloak_timer_id_t deadline; /* D6's first-byte deadline -- and, in
                                * singleplex, the bound on the session
                                * wait too: cancelled when a stream opens,
                                * not when the first byte arrives */

    /* THE SESSION THIS ONE CONNECTION IS SPLICED ONTO, and the only
     * session pointer any code path in this module dereferences. NULL
     * means "there is no session this context may touch", which is a
     * reachable state in both modes: before a singleplex context's own
     * session has been handed over, and after either mode's session has
     * broken. */
    cloak_session_t *sesh;
    /* 1 if this context brought sesh up FOR ITSELF (singleplex) and is
     * therefore the thing that ends it. 0 for a shared session, which
     * this module never closes. */
    int own_sesh;
    /* 1 while config::new_session has been called for this context and
     * neither cloak_client_piper_conn_session_ready nor _failed has
     * answered. The teardown walk uses it to fire config::cancel_session,
     * which is what stops the owner from completing a bring-up against a
     * context that no longer exists. */
    int awaiting_session;

    cloak_stream_t *stream; /* owned by the session; released by us */

    cloak_stream_relay_t relay; /* live only while relaying != 0 */
    int relaying;

    cloak_timer_id_t retry_timer; /* live only during a -2 retry window */
    unsigned retries;

    /* The bytes read before the stream was opened, and not yet written
     * into it. Non-zero only between the successful first read and the
     * successful relay start -- which is also the whole of the retry
     * window, so a retry does not re-read and does not double-write. */
    size_t first_len;
    uint8_t first[CLOAK_CLIENT_PIPER_FIRST_BYTES];

    struct cloak_client_piper_conn *prev, *next;
} cloak_client_piper_conn_t;

/* ---- the singleplex seam -------------------------------------------------
 *
 * THIS MODULE NEVER BRINGS A SESSION UP AND NEVER DESTROYS ONE, in either
 * mode, and that is the same division of labour cloak_client_piper_set_
 * session already states for the shared case: a session costs a
 * cloak_client_connector_t, N dials, N handshakes and storage the CALLER
 * owns, and none of that belongs behind a local listener's accept
 * callback. What singleplex adds is only that the request now happens per
 * connection, so it needs a seam instead of a setter. */

/* Asked for ONE session, for ONE local connection, and only once that
 * connection has actually sent a byte.
 *
 * ctx is an OPAQUE KEY. Store it, pass it back to
 * cloak_client_piper_conn_session_ready or
 * cloak_client_piper_conn_session_failed exactly once, and never
 * dereference it or call any other function with it -- it is a context
 * this module owns and may free.
 *
 * Return 0 if a bring-up has STARTED and will be answered later; -1 if it
 * could not even be started, which closes that one local connection and
 * nothing else. The answer must NOT be delivered synchronously from
 * inside this call; cloak_client_connector_t guarantees that structurally
 * (its on_done never fires from inside start), and any other producer
 * must defer to a reactor turn the same way.
 *
 * If the local connection dies before the answer arrives -- its deadline
 * expires, the local peer closes, the piper is destroyed -- cancel_session
 * is called for the same ctx and the answer must then never be
 * delivered. */
typedef int (*cloak_client_piper_new_session_fn)(cloak_client_piper_conn_t *ctx, void *userdata);

/* "Forget ctx: the connection it was for is gone." Fired exactly once,
 * for a ctx that new_session returned 0 for and that has not yet been
 * answered. After it returns, ctx must never be passed to
 * cloak_client_piper_conn_session_ready or _failed.
 *
 * The owner should cancel or abandon whatever it started -- for a
 * cloak_client_connector_t, cloak_client_connector_destroy, which tears
 * down dials and handshakes in flight WITHOUT firing on_done, which is
 * precisely the shape this needs. It must not call back into the piper. */
typedef void (*cloak_client_piper_cancel_session_fn)(cloak_client_piper_conn_t *ctx,
                                                     void *userdata);

/* reactor is borrowed, not owned, and must outlive the piper.
 *
 * Each sizing field defaults (0 means "use the default") to the
 * CLOAK_CLIENT_PIPER_DEFAULT_* constant above; a config that leaves them
 * all zeroed gets exactly those. */
typedef struct {
    cloak_reactor_t *reactor;

    size_t relay_buf_cap;             /* 0 -> ..._DEFAULT_RELAY_BUF_CAP */
    uint64_t first_byte_timeout_ms;   /* 0 -> ..._DEFAULT_FIRST_BYTE_TIMEOUT_MS */
    uint64_t retry_delay_ms;          /* 0 -> ..._DEFAULT_RETRY_DELAY_MS */
    unsigned max_retries;             /* 0 -> ..._DEFAULT_MAX_RETRIES */
    size_t max_local_conns;           /* 0 -> ..._DEFAULT_MAX_LOCAL_CONNS */

    /* OPTIONAL, and the reason this module can afford to BE the session's
     * on_broken rather than something the owner has to remember to call:
     * an owner with bookkeeping of its own installs it here and gets it
     * invoked with its own userdata AFTER this module's cleanup has
     * completed.
     *
     * THE ORDERING IS NOT NEGOTIABLE. cloak/session.h permits a callback
     * in this position to call cloak_session_destroy -- including on the
     * session that is mid-teardown -- and by the time the chain can do
     * that, every relay this piper held must already be stopped. */
    cloak_session_broken_cb chain;
    void *chain_userdata;

    /* GO'S `singleplex` (NumConn <= 0). 0 shares one session across every
     * local connection; 1 gives each local connection its own.
     *
     * WHAT A USER IS BUYING, since the cost is real: in shared mode every
     * local connection is a stream on one session, so an observer sees
     * one long-lived TLS-shaped flow and the per-connection cost is a
     * stream id. In singleplex each local connection is its own session
     * with its own dial and its own handshake, so a compromised or
     * observed session reveals one local connection rather than all of
     * them -- at the price of a full handshake, and its latency, per
     * connection. That price is why the handshake is not spent until the
     * connection has actually sent a byte.
     *
     * new_session is REQUIRED when this is 1 and IGNORED when it is 0;
     * cloak_client_piper_init rejects the first mismatch rather than
     * discovering it at the first accept, where the only answer available
     * would be to drop a connection the application believes is live.
     * cancel_session is optional but an owner that allocates anything to
     * start a bring-up needs it. */
    int singleplex;
    cloak_client_piper_new_session_fn new_session;
    cloak_client_piper_cancel_session_fn cancel_session;
    void *session_userdata; /* passed to both */
} cloak_client_piper_config_t;

struct cloak_client_piper {
    cloak_client_piper_config_t cfg; /* copied by value, defaults filled in */

    /* THE SHARED session every local connection is spliced onto, or NULL.
     * IT IS NEVER DEREFERENCED: it is copied into a context's own
     * ctx->sesh at accept time and every actual use goes through that.
     *
     * NULL IS A REAL AND REACHABLE STATE, not an initialization artifact:
     * before cloak_client_piper_set_session (the session does not exist
     * yet -- this module's callbacks have to be installed into the
     * session TEMPLATE, which is consumed by cloak_session_init, so there
     * is necessarily a window in which the piper is wired up and the
     * session is not), after the shared session has broken (it is about
     * to be destroyed by its owner and must never be touched again), and
     * FOR THE WHOLE LIFE OF A SINGLEPLEX PIPER, which has no shared
     * session at all. */
    cloak_session_t *sesh;

    cloak_client_piper_conn_t *conns;
    size_t conn_count;

    /* Contexts that currently hold a cloak_stream_t. Strictly less than
     * conn_count whenever any connection is still inside D6's first-byte
     * window, and THAT DIFFERENCE IS THE ONLY OBSERVABLE D6 HAS: a piper
     * that opened its stream at accept time keeps these two equal. */
    size_t stream_count;

    /* Local connections refused at max_local_conns, and streams the
     * SERVER opened toward us and had refused (see
     * cloak_client_piper_rejected_streams). Diagnostics only; neither
     * ever falls. */
    size_t refused_conns;
    size_t rejected_streams;
    size_t retried_starts;
    size_t sessions_started;

    /* 1 once the corresponding line has been logged, so that neither a
     * misbehaving server nor a local process opening connections in bulk
     * can make this module write one line per event -- which is exactly
     * the shape of log an attacker generates on purpose. ONE LINE PER
     * PIPER, not one per episode: cloak_proxy_t's hysteretic version
     * exists because its caps are crossed in normal operation by an
     * honest client's own parallelism, whereas both of these conditions
     * mean something is wrong and stays wrong. The counts above stay
     * exact either way, and are what a test or an operator should read. */
    int logged_rejected_stream;
    int logged_refused_conn;
};

/* Zeroes pp and validates the rest -- IN THAT ORDER, so that any failure
 * return still leaves pp safe to pass to cloak_client_piper_destroy. Five
 * earlier constructors on this project got that ordering backwards and it
 * was a crash every time a caller's own cleanup ran against an
 * uninitialized struct.
 *
 * Copies *cfg by value, substituting CLOAK_CLIENT_PIPER_DEFAULT_* for any
 * sizing field left at 0. cfg->reactor remains a borrowed pointer. No
 * socket is opened, no reactor registration is made and no timer is armed.
 *
 * Returns 0 on success, -1 if pp is NULL, if cfg or cfg->reactor is
 * NULL, or if cfg->singleplex is set without a cfg->new_session -- that
 * last one rejected HERE rather than at the first accept, because the
 * only answer available there would be to drop a connection the
 * application already believes is live. */
int cloak_client_piper_init(cloak_client_piper_t *pp, const cloak_client_piper_config_t *cfg);

/* Installs this module's four session callbacks into *config with pp as
 * all four userdata values. Call it on the session TEMPLATE before the
 * session is created -- for a session brought up by
 * cloak_client_connector_t, that is cloak_client_connector_config_t::
 * session_template, which is passed through to cloak_session_init
 * verbatim.
 *
 * ALL FOUR, and none of them is optional:
 *   on_new_stream   -- refuses it; see cloak_client_piper_rejected_streams.
 *   on_stream_data  -- routes the frame to the right relay.
 *   on_writable     -- tells every relay the pool drained.
 *   on_broken       -- stops every relay in the one window where that is
 *                      still possible, then calls cfg.chain.
 *
 * An owner that overwrites on_broken afterwards has a use-after-free (a
 * relay left running past its session's death writes through freed
 * memory on the next byte that arrives); that is what cfg.chain is for.
 * A no-op on a NULL pp or config. */
void cloak_client_piper_install(cloak_client_piper_t *pp, cloak_session_config_t *config);

/* SHARED MODE ONLY. Points the piper at the live session that local
 * connections will be spliced onto, and must be called before the
 * listener can accept anything useful: an accept arriving with no shared
 * session and no way to get one is closed immediately, because there is
 * nothing to open a stream on and queueing it would be a lie about a
 * connection the application believes is live. A singleplex piper never
 * calls this -- it has no shared session, and each accept asks
 * config::new_session for one of its own instead.
 *
 * sesh is BORROWED. This module never destroys it and never closes it;
 * it only opens, releases and reads streams on it. Passing NULL detaches
 * -- which is what piper_on_broken does internally -- and does NOT tear
 * down the contexts that are still running, because the two orderings
 * differ: a detach for an ALREADY-DEAD session must be preceded by the
 * teardown walk (a stream can only be released while its session lives),
 * whereas a caller swapping in a new session wants the old contexts gone
 * first too. Call cloak_client_piper_destroy for that; this function is
 * deliberately not a teardown in disguise. */
void cloak_client_piper_set_session(cloak_client_piper_t *pp, cloak_session_t *sesh);

/* A cloak_listener_accept_cb (userdata: the cloak_client_piper_t). Pass
 * it, with the piper, to cloak_listener_open:
 *
 *     cloak_listener_open(&l, r, cfg.local_addr, cloak_client_piper_on_accept,
 *                         &piper, err, sizeof(err));
 *
 * Takes ownership of fd exactly as cloak_listener_accept_cb requires: it
 * is closed by this module, by the relay that eventually takes it, or
 * immediately if there is no session or the piper is at
 * max_local_conns. It is never dropped.
 *
 * Nothing is opened on the session here: this arms the first-byte
 * deadline and registers fd for reading, and D6's stream is opened only
 * once a byte has actually arrived. IN SINGLEPLEX, NO SESSION IS EVEN
 * REQUESTED HERE either -- config::new_session is called only once a byte
 * has arrived, which is D6's saving applied to the far more expensive of
 * the two things a connection can cost in that mode. */
void cloak_client_piper_on_accept(cloak_listener_t *l, int fd, void *userdata);

/* SINGLEPLEX ONLY: the two answers to config::new_session, exactly one of
 * which must be called exactly once for each ctx that new_session
 * returned 0 for -- unless config::cancel_session has since fired for
 * that ctx, after which neither may ever be called.
 *
 * _ready hands over a live session. It is BORROWED, exactly as
 * cloak_client_piper_set_session's is: this module opens, releases and
 * reads streams on it and eventually calls cloak_session_close on it, but
 * never cloak_session_destroy -- the storage and the destroy remain the
 * owner's, and the owner is told the session has ended through
 * config::chain. Passing a NULL session is treated as _failed.
 *
 * _failed says the session will never exist. That one local connection is
 * closed; nothing else is affected.
 *
 * Both are no-ops on a NULL ctx, and both may free ctx before returning
 * -- it must not be used again afterwards for any purpose. Neither may be
 * called from inside config::new_session itself (see
 * cloak_client_piper_new_session_fn). */
void cloak_client_piper_conn_session_ready(cloak_client_piper_conn_t *ctx, cloak_session_t *sesh);
void cloak_client_piper_conn_session_failed(cloak_client_piper_conn_t *ctx);

/* Tears down everything the piper still holds: for every context, cancels
 * its deadline and any retry timer, stops a live relay, deregisters and
 * closes a descriptor still held here, and releases its stream back to
 * the session; then frees every context.
 *
 * MUST RUN BEFORE cloak_session_destroy ON THE SESSION IT WAS GIVEN.
 * cloak/stream_relay.h states the underlying rule -- every relay bound to
 * a session must be stopped before that session goes away -- and this is
 * what performs those stops. It does NOT destroy or close the session:
 * that is the caller's, exactly as the session is the caller's from the
 * moment cloak_client_connector_t hands it over.
 *
 * Idempotent, and safe on a zeroed struct. Safe to call after
 * piper_on_broken has already run (there is nothing left to walk, and
 * pp->sesh is NULL so nothing is touched). */
void cloak_client_piper_destroy(cloak_client_piper_t *pp);

/* Contexts currently held, and how many of them hold a stream.
 * Diagnostics and tests; both are O(1). pp == NULL returns 0.
 *
 * THE SECOND IS D6'S OWN ASSERTION. A local connection that has connected
 * and said nothing counts in the first and not in the second; an
 * implementation that opened its stream at accept time makes them equal. */
size_t cloak_client_piper_conn_count(const cloak_client_piper_t *pp);
size_t cloak_client_piper_stream_count(const cloak_client_piper_t *pp);

/* Local connections closed on arrival because the piper was already at
 * max_local_conns. Never falls. */
size_t cloak_client_piper_refused_conns(const cloak_client_piper_t *pp);

/* Streams THE SERVER OPENED TOWARD THIS CLIENT, and this module refused.
 *
 * THE DECISION, and the argument for it, because "just ignore it" and
 * "accept it" are both available and both wrong:
 *
 * In this transport every stream is client-initiated. The client's only
 * source of streams is its local listener, and the server's whole data
 * path (cloak/proxy.h) opens none -- it only ever accepts. So a frame
 * carrying a stream id this client never issued is a PROTOCOL VIOLATION,
 * with exactly two causes: a bug on the server side, or a server that is
 * not the one we think it is trying to make this host originate
 * connections the user never asked for. Neither deserves a stream.
 *
 * REFUSING means cloak_session_release_stream, which performs the active
 * close itself, so the far end learns immediately instead of waiting out
 * a timeout; the session and every stream already running on it are
 * untouched. SILENTLY ACCEPTING -- returning without doing anything --
 * is not the harmless option it looks like: cloak/session.h requires
 * exactly one release per stream this module is handed, so an ignored
 * stream holds its memory FOR THE LIFE OF THE SESSION -- not of the
 * process: it stays ACTIVE, so session_free_all_active_streams reclaims
 * it at teardown -- and, being active, keeps the session's inactivity
 * timeout from ever retiring an otherwise idle session. A remote peer
 * would control both.
 * ACTUALLY ACCEPTING is worse still and there is nowhere to put it: this
 * module has no local peer to splice such a stream to, and inventing one
 * would mean the client dialling somewhere on a remote party's
 * instruction, which is a reverse proxy, not a censorship-circumvention
 * client.
 *
 * TEARING THE WHOLE SESSION DOWN was the other candidate and is rejected
 * deliberately: it hands anything that can inject one frame a way to kill
 * every live local connection at once, which turns a violation this
 * module can absorb into a denial of service it cannot.
 *
 * BOUNDED: once this count reaches CLOAK_CLIENT_PIPER_MAX_REJECTED_
 * STREAMS the session is closed (cloak_session_close), which fires
 * on_broken and so tears every local connection down through this
 * module's ordinary walk. See that constant for why a ceiling is
 * necessary and why closing is the right one.
 *
 * One log line per piper, not per stream -- the count stays exact either
 * way, and is what a test or an operator should read. pp == NULL returns
 * 0. */
size_t cloak_client_piper_rejected_streams(const cloak_client_piper_t *pp);

/* Relay starts this piper has re-attempted after a transient (-2)
 * rejection, summed over every local connection it has ever accepted.
 * 0 on a run where no start was ever congested; strictly more when the
 * retry ladder did any work.
 *
 * EXPOSED BECAUSE "THE RETRY HAPPENED" IS OTHERWISE UNOBSERVABLE: a test
 * that only checks the local connection eventually carried its bytes
 * would pass just as well against an implementation that treated -2 as
 * permanent, against a server that never congested anything -- one of the
 * coverage shapes this project has already paid for (cloak_client_
 * connector_attempts exists for exactly the same reason). Never falls.
 * pp == NULL returns 0. */
size_t cloak_client_piper_retried_starts(const cloak_client_piper_t *pp);

/* Times config::new_session has been called, i.e. sessions this piper has
 * ASKED FOR. Always 0 in shared mode; one per local connection that sent
 * a byte in singleplex. Never falls. pp == NULL returns 0.
 *
 * EXPOSED BECAUSE THE MODE FLAG IS OTHERWISE ONLY OBSERVABLE FROM THE FAR
 * END. Everything else about a working singleplex client looks exactly
 * like a working shared one from the local side -- same bytes, same
 * round trips, same stream counts -- so a test that did not read the
 * server's session registry could not tell them apart at all, and one
 * that reads only this could not tell "asked" from "got". Both halves are
 * needed and both are cheap. */
size_t cloak_client_piper_sessions_started(const cloak_client_piper_t *pp);

/* Local bytes this piper is holding that have not yet reached a stream,
 * summed over every context. pp == NULL returns 0.
 *
 * THE DECISION IT MAKES ASSERTABLE, which is why it is public at all. A
 * singleplex local connection has to do SOMETHING while its own session
 * handshakes, and the connector's retry ladder means that can legitimately
 * take seconds. Buffering its first bytes is the obvious answer and is
 * NOT the one taken here: this module takes nothing out of the socket
 * until a session exists to take it for. It establishes that the
 * connection is real with a one-byte MSG_PEEK -- enough to tell a browser
 * from a port scanner without consuming anything -- then DEREGISTERS the
 * descriptor and asks for a session. The unread bytes stay in the
 * kernel's own receive buffer, which is a fixed size the OS already
 * bounds and which backpressures the local application through TCP's own
 * window rather than through anything this module would have to grow.
 *
 * SO THE BOUND ON THE WAIT IS EXACT AND IT IS ZERO: a connection waiting
 * out a handshake, however slow, holds one context, one descriptor and no
 * copied bytes, and this function returns 0 for it.
 *
 * WHAT IT CAN BE NON-ZERO FOR, so that a caller reading it does not
 * mistake the two: the window between the capped first read and the relay
 * start that consumes it. That window is normally within one dispatch,
 * but it spans the whole of a -2 RETRY LADDER, so on a congested session
 * this legitimately reads up to one frame's payload per retrying
 * connection -- bounded by CLOAK_CLIENT_PIPER_FIRST_BYTES times
 * max_local_conns, and by max_retries in time. That is the same bound D6
 * already carries; the point of this accessor is that the session wait
 * adds nothing to it.
 *
 * The wait is bounded in TIME by the same first-byte deadline (which is
 * not cancelled until a stream actually opens) and in COUNT by
 * max_local_conns, exactly as D6's own wait is. */
size_t cloak_client_piper_buffered_bytes(const cloak_client_piper_t *pp);

#endif
