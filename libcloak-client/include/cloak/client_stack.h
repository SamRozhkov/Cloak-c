#ifndef CLOAK_CLIENT_STACK_H
#define CLOAK_CLIENT_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/client_connector.h"
#include "cloak/client_piper.h"
#include "cloak/config.h"
#include "cloak/net.h"
#include "cloak/reactor.h"

/* THE WHOLE CLIENT AS ONE OBJECT: a resolved remote, a local listener, a
 * cloak_client_piper_t, one cloak_client_connector_t and one
 * cloak_session_t per SESSION, the session-maker seam the piper calls in
 * singleplex, the broken-session chain, the teardown order -- and THE
 * RECONNECT LOOP, which cloak/client_connector.h deliberately left to
 * its caller.
 *
 * WHY THIS EXISTS. Before this file a client was assembled by hand: 76
 * measured code lines of object graph and about 325 for a realistic
 * main.c, carrying NINE forced-but-unenforced ordering edges -- two of
 * them not the reverse of construction, and one that FAILS SILENTLY.
 * That last one is the shape that matters: call
 * cloak_client_piper_install AFTER cloak_client_connector_init and the
 * session template the connector already copied has no callbacks in it,
 * so the client dials, authenticates, establishes a session, opens the
 * local listener, accepts connections -- and moves no bytes, forever,
 * with no error emitted anywhere. A startup error is the only feedback
 * an operator can act on.
 *
 * THE STACK IS AN OPAQUE HANDLE, AND THAT IS THE ENFORCEMENT. Its
 * sibling cloak/server_stack.h learned this the hard way: its first
 * revision was a public struct holding public sub-objects, and claimed
 * its edges were structural because the CONFIG had no field for any of
 * them. That claim was defeated by writing one member --
 * `st.registry.on_broken = ...` compiled cleanly. The client's graph is
 * worse in exactly that respect, because cloak_client_piper_t and
 * cloak_client_connector_t are BOTH public structs with writable wiring
 * fields (`pp->cfg.chain`, `pp->sesh`, `c->session_template.on_broken`),
 * so a by-value stack would put every one of them back within reach.
 * The definition therefore lives in client_stack.c and a caller holds a
 * pointer it cannot dereference. The accessors below hand back only
 * counters and scalars.
 *
 * ONE STACK PER PROCESS, BUT THE GRAPH INSIDE IT IS DYNAMIC. This is the
 * one place the client is genuinely harder than the server. The server's
 * graph is static: built once, torn down once. SINGLEPLEX (Go's NumConn
 * <= 0) brings up ONE SESSION PER ACCEPTED LOCAL CONNECTION, so a
 * connector, a session and a bring-up's worth of state are created and
 * destroyed on a hot path with overlapping lifetimes. Two consequences
 * that are requirements, not observations:
 *
 *   - NOTHING IN THIS MODULE IS FILE-SCOPE MUTABLE, and there is no
 *     shared scratch buffer and no single reusable connector. Each
 *     bring-up owns a separately heap-allocated block holding its own
 *     connector and its own cloak_session_t storage, at a fixed address
 *     for that bring-up's whole life. cloak/client_connector.h was
 *     written with no global state precisely so this would be possible;
 *     re-introducing any here would be an aliasing bug visible ONLY in
 *     the mode a user turns on for isolation.
 *   - EVERY SESSION GETS ITS OWN RANDOM SESSION ID, checked against the
 *     ids this stack currently holds. Two live sessions sharing an id
 *     are ATTACHED TO EACH OTHER on the server, whose registry is keyed
 *     by (uid, session id) -- which in singleplex would silently undo
 *     the isolation the mode exists to provide.
 *
 * ---- THE RECONNECT LOOP -------------------------------------------------
 *
 * cloak/client_connector.h bounds its own retries (5 attempts per
 * connection, ~7.5 s of backoff) and reports a typed failure instead of
 * retrying forever, which is a deliberate divergence from Go's
 * `makeconn:` label. It then names the obligation that divergence
 * creates, and this is where that obligation is discharged:
 *
 *   A RETRY ABOVE THE CONNECTOR MUST USE A FRESH SESSION ID AND BACK
 *   OFF. When one connection exhausts its attempts the WHOLE invocation
 *   fails at once, abandoning the N-1 sockets that DID authenticate --
 *   and the server has already created that session and holds it until
 *   its own inactivity timeout (60 s by default). Retrying under the
 *   same id attaches to a half-dead server-side session; retrying with
 *   no delay, on a flaky network, multiplies server-side sessions per
 *   client. Go never meets this because it never gives up.
 *
 * THE BACKOFF: exponential from CLOAK_CLIENT_STACK_DEFAULT_RECONNECT_
 * BASE_MS (500 ms), doubling per round, capped at
 * CLOAK_CLIENT_STACK_MAX_RECONNECT_DELAY_MS (30 s), jittered uniformly
 * by +/-25% AROUND the nominal value. Round 1 runs immediately; the
 * nominal delays before rounds 2..n are 500, 1000, 2000, 4000, 8000,
 * 16000, 30000, 30000... The shape, the +/-25% and the symmetry are
 * deliberately the same as the connector's D2 ladder -- one schedule a
 * reader can hold in their head rather than two -- and the symmetry is
 * load-bearing for the same reason it is there: jittering only downward
 * shifts the mean to 0.75x and makes every retry strictly more
 * aggressive than the schedule documented here.
 *
 * THE CAP IS 30 s, NOT THE CONNECTOR'S 8 s, and the difference is the
 * point. The connector's ladder separates ATTEMPTS ON ONE SOCKET, where
 * the failure being waited out is a route flap measured in seconds.
 * This ladder separates WHOLE ROUNDS, and a round already costs the
 * connector's own ~7.5 s plus N dials and N handshakes -- so the only
 * regime in which this delay dominates is the one where the far end is
 * genuinely down, and there the question is how often a client that
 * cannot connect knocks on a server that cannot answer. 30 s means at
 * most two rounds a minute, and notices a server that came back inside
 * half a minute. An 8 s cap would mean roughly seven.
 *
 * THE BOUND: cloak_client_stack_config_t::max_rounds, and its DEFAULT IS
 * UNBOUNDED. That is the opposite of the connector's choice and for the
 * reason the connector gives: an unbounded retry is indefensible in a
 * LIBRARY, whose caller can then never be told "this did not work", and
 * is exactly right in the thing a BINARY wires itself out of, where an
 * operator can see it, interrupt it, and pick a different server. What
 * makes it defensible HERE rather than merely inherited from Go is that
 * it is not silent: every round start, every round failure, every
 * session up and down fires cloak_client_stack_event_cb with the round
 * number and the delay to the next one, so a ck-client logs a line per
 * round and an operator watching the log sees a client that is trying
 * rather than a client that is hung. A caller that wants to fail over
 * rather than wait sets max_rounds and gets CLOAK_CLIENT_STACK_EVENT_
 * GAVE_UP.
 *
 * WHAT IS BOUNDED, since "unbounded rounds" is only half a sentence:
 * the LADDER is bounded (30 s), each ROUND is bounded by the connector
 * (5 attempts, its own backoff, its own dial and handshake timeouts),
 * and every local connection's wait is bounded -- see the next
 * paragraph, which is the question a user actually feels.
 *
 * WHAT HAPPENS TO A LOCAL CONNECTION WHOSE SESSION NEVER COMES UP. The
 * two modes answer differently because the piper's own contract does:
 *
 *   SHARED (num_conn >= 1). The local listener is opened at
 *   cloak_client_stack_open and stays open for the life of the stack --
 *   it has to, because an application is configured to point at a port
 *   and a listener that came and went with the session would not have a
 *   stable one. While no shared session exists (before the first
 *   bring-up finishes, and between a break and its replacement)
 *   cloak_client_piper_on_accept CLOSES EACH ACCEPTED CONNECTION
 *   IMMEDIATELY -- its documented behaviour, because there is nothing to
 *   open a stream on and queueing it would be a lie about a connection
 *   the application believes is live. The application sees a connection
 *   that is accepted and then immediately closed, within one reactor
 *   turn, and can retry. cloak_client_stack_session_up reports which
 *   state the stack is in.
 *
 *   SINGLEPLEX. The connection is accepted and held with NO session
 *   requested until it sends its first byte (the piper's D6 saving,
 *   applied to the far more expensive of the two costs in this mode).
 *   The first byte starts a bring-up, and that bring-up retries on this
 *   stack's ladder like any other. THE WAIT IS BOUNDED TWICE OVER: by
 *   max_rounds if one is set, and unconditionally by the piper's
 *   first-byte deadline, which in singleplex is NOT cancelled when the
 *   byte arrives but when a stream actually opens. That deadline is the
 *   config's StreamTimeout (300 s by default), and this module wires it
 *   there rather than offering a second knob, so the two bounds cannot
 *   disagree. Whichever fires first closes that ONE local connection and
 *   affects nothing else: max_rounds through
 *   cloak_client_piper_conn_session_failed, the deadline through
 *   cloak_client_piper_cancel_session_fn, which this module answers by
 *   destroying the in-flight connector WITHOUT firing its on_done.
 *
 * ---- THE EDGES ----------------------------------------------------------
 *
 * Nine forced ordering edges, all of them now structural -- a caller
 * holding a cloak_client_stack_t * has no way to reach any of them:
 *
 *   E1 cloak_client_piper_install runs on the connector's session
 *      template BEFORE cloak_client_connector_init copies it. THIS IS
 *      THE ONE THAT FAILS SILENTLY (see this file's opening) and the
 *      reason a "the tunnel carries bytes" test, not a "it connected"
 *      test, is what pins it.
 *   E2 the session's on_broken IS the piper's, never an owner's -- it is
 *      the only window in which a relay bound to a dying session can
 *      still be stopped (cloak/stream_relay.h). An owner's own
 *      bookkeeping goes in cloak_client_stack_config_t::on_event, which
 *      runs after the piper's cleanup and cannot displace it.
 *   E3 the piper is installed into EVERY session's template, including
 *      every reconnect's -- a replacement session wired without it is
 *      the same silent failure as E1, arriving minutes later.
 *   E4 each bring-up gets a FRESH random session id, distinct from every
 *      id this stack currently holds. See the singleplex paragraph.
 *   E5 the remote address is resolved ONCE, at open, and every bring-up
 *      reuses that cloak_addr_t. cloak_net_resolve BLOCKS (cloak/net.h
 *      says so in capitals) and singleplex would otherwise put a
 *      synchronous DNS lookup on the accept path.
 *   E6 in singleplex, exactly one of cloak_client_piper_conn_session_
 *      ready / _failed answers each ctx new_session returned 0 for, and
 *      NEITHER is called after cancel_session has fired for it.
 *   E7 cancel_session destroys the in-flight connector, which tears down
 *      dials and handshakes WITHOUT firing on_done -- the only shape
 *      that cannot answer a ctx the piper has already freed.
 *   E8 a session is destroyed only from the broken chain or from
 *      teardown, never from both. The piper only ever CLOSES a
 *      singleplex session; reaping it is this module's.
 *   E9 the teardown order. See cloak_client_stack_close.
 *
 * HAND-WIRING REMAINS LEGAL. cloak/client_connector.h and
 * cloak/client_piper.h still document their contracts for an owner, and
 * every test in this module that builds a partial graph still wires it
 * by hand -- that is those tests' value. This is the supported path for
 * BINARIES.
 *
 * THREADING: none, like everything else in this project. One stack, one
 * reactor, one thread. */

typedef struct cloak_client_stack cloak_client_stack_t;

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

/* Every failure return NAMES THE EDGE that failed, both as a code a
 * caller can switch on and as a sentence in the caller's err buffer.
 * "Returned -1" is not enough when six construction steps can fail and
 * an operator reading a log line has to know which. */
#define CLOAK_CLIENT_STACK_ERR_ARG       (-1) /* a NULL this call requires */
#define CLOAK_CLIENT_STACK_ERR_CONFIG    (-2) /* the cloak_client_config_t itself */
#define CLOAK_CLIENT_STACK_ERR_TEMPLATE  (-3) /* session_config_template */
#define CLOAK_CLIENT_STACK_ERR_RESOLVE   (-4) /* RemoteHost:RemotePort */
#define CLOAK_CLIENT_STACK_ERR_PIPER     (-5) /* cloak_client_piper_init */
#define CLOAK_CLIENT_STACK_ERR_LISTEN    (-6) /* LocalHost:LocalPort */
#define CLOAK_CLIENT_STACK_ERR_CONNECTOR (-7) /* the first bring-up could not be started */

/* A short, stable, English name for a code above ("remote address",
 * "local address", ...). Never NULL: an unrecognised code returns
 * "unknown". THESE STRINGS ARE PART OF THE CONTRACT and are compared
 * exactly by this module's tests -- an assertion that merely checked for
 * a non-empty string would be satisfied by "unknown" for every code,
 * which is a test written against the symbol it tests rather than
 * against the behaviour. */
const char *cloak_client_stack_strerror(int code);

/* ------------------------------------------------------------------ */
/* Defaults                                                            */
/* ------------------------------------------------------------------ */

/* The mux parameters every existing configuration in this tree uses.
 * They are defaults here (a zeroed session_config_template gets exactly
 * these) rather than something a binary has to know, for the reason
 * cloak/server_stack.h gives for its own: a template left zeroed would
 * otherwise be accepted here and rejected by cloak_session_init on the
 * first bring-up, where the connector reports it as
 * CLOAK_CLIENT_CONNECTOR_ERR_SESSION long after startup.
 *
 * THEY MATCH cloak/server_stack.h'S EXACTLY, and 16401 in particular:
 * both ends of one tunnel must agree about max_on_wire_size, because a
 * connection whose peer frames larger than its own max_frame_len is
 * broken by the connection layer rather than tolerated. */
#define CLOAK_CLIENT_STACK_DEFAULT_MAX_ON_WIRE_SIZE      ((size_t)16401)
#define CLOAK_CLIENT_STACK_DEFAULT_STREAM_RECV_CAPACITY  ((size_t)65536)
#define CLOAK_CLIENT_STACK_DEFAULT_STREAM_MAX_PENDING    ((size_t)64)
#define CLOAK_CLIENT_STACK_DEFAULT_CONN_SEND_QUEUE_CAP   ((size_t)262144)
#define CLOAK_CLIENT_STACK_DEFAULT_INACTIVITY_TIMEOUT_MS ((uint64_t)60000)

/* The reconnect ladder. See this file's RECONNECT LOOP section for the
 * argument behind every one of these three numbers. */
#define CLOAK_CLIENT_STACK_DEFAULT_RECONNECT_BASE_MS ((uint64_t)500)
#define CLOAK_CLIENT_STACK_MAX_RECONNECT_DELAY_MS    ((uint64_t)30000)
/* Percent, each way, around the nominal delay. */
#define CLOAK_CLIENT_STACK_RECONNECT_JITTER_PCT      ((unsigned)25)

/* max_rounds == 0. Named rather than written as a bare 0 at call sites,
 * because "zero rounds" and "no limit on rounds" are opposite readings
 * of the same literal. */
#define CLOAK_CLIENT_STACK_ROUNDS_UNBOUNDED 0

/* ------------------------------------------------------------------ */
/* Events                                                              */
/* ------------------------------------------------------------------ */

/* WHAT MAKES AN UNBOUNDED RETRY DEFENSIBLE: it is narrated. Every one of
 * these fires from reactor dispatch, never from inside
 * cloak_client_stack_open.
 *
 * A HANDLER MAY READ THE ACCESSORS BELOW AND NOTHING ELSE -- this is a
 * notification, not a seam. In particular it must NOT call
 * cloak_client_stack_close; see that function for why that is a
 * use-after-free rather than merely unsupported, and for the two-line
 * shape that does work. */
typedef enum {
    /* A bring-up is starting. round is 1-based; session_id is the fresh
     * id this round will use. */
    CLOAK_CLIENT_STACK_EVENT_ROUND_STARTED = 1,
    /* That round failed. retry_in_ms is the jittered delay before the
     * next round, or 0 when there will not be one. */
    CLOAK_CLIENT_STACK_EVENT_ROUND_FAILED = 2,
    /* A session is live. In singleplex this is one local connection's
     * own session. */
    CLOAK_CLIENT_STACK_EVENT_SESSION_UP = 3,
    /* A LIVE session broke -- the far end went away, a user was
     * terminated, an underlying connection died. In shared mode a
     * replacement round follows; in singleplex the local connection that
     * owned it is already gone and none does. */
    CLOAK_CLIENT_STACK_EVENT_SESSION_DOWN = 4,
    /* max_rounds is spent. In shared mode the stack will not try again
     * until a caller closes and reopens it; in singleplex that one local
     * connection is closed and the rest of the client is unaffected. */
    CLOAK_CLIENT_STACK_EVENT_GAVE_UP = 5,
} cloak_client_stack_event_t;

/* A short, stable, English name for an event ("round started", ...).
 * Never NULL; an unrecognised value returns "unknown". Part of the
 * contract, and compared exactly by this module's tests, for the same
 * reason cloak_client_stack_strerror's strings are. */
const char *cloak_client_stack_event_name(cloak_client_stack_event_t ev);

typedef void (*cloak_client_stack_event_cb)(cloak_client_stack_t *s,
                                            cloak_client_stack_event_t ev, uint32_t session_id,
                                            int round, uint64_t retry_in_ms, void *userdata);

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    /* Required. BORROWED, and NOT ENFORCEABLE: the reactor must outlive
     * the stack. The listener, the piper, every connector and every
     * session registers descriptors and timers with it, and C offers no
     * way to check a pointer's liveness. Close the stack, then the
     * reactor. */
    cloak_reactor_t *reactor;

    /* Required, and READ ONLY FOR THE DURATION OF cloak_client_stack_open
     * -- the stack takes its own COPY. cloak_client_config_t is a pure
     * POD (fixed arrays, no pointers), so one memcpy removes an entire
     * class of caller error: a binary that parses into a local and
     * returns would otherwise leave every bring-up reading a dangling
     * uid, server key and proxy method on a hot path.
     *
     * WHICH FIELDS ARE CONSUMED, stated exhaustively because a field
     * that is silently ignored is worse than one that is rejected:
     *   server_name TOGETHER WITH alt_names (Go's MockDomainList): one
     *   SNI is drawn uniformly from the whole set PER SESSION, which is
     *   Go's own granularity -- cloak_client_connector_t copies
     *   server_name at init, this module calls init once per round, and
     *   a round produces exactly one session. The literal "random" is
     *   passed through unchanged and the transport regenerates it per
     *   attempt, exactly as in Go.
     *   server_pub_key, uid, proxy_method, encryption_method, browser,
     *   transport, num_conn, singleplex, udp (-> the session's unordered
     *   flag AND, since module 9, WHICH LOCAL LISTENER IS BUILT: 1 gives
     *   a cloak_udp_piper_t -- one datagram socket, one unordered stream
     *   per source address -- instead of a TCP cloak_listener_t and a
     *   cloak_client_piper_t. The two are alternatives, never both, and
     *   the choice is made once here. udp WITH singleplex is REFUSED as
     *   ERR_CONFIG: Go supports the combination and this build does not,
     *   and quietly sharing one session where the user asked for one per
     *   flow would give none of the isolation the mode exists for),
     *   remote_host/remote_port (resolved once, here),
     *   local_host/local_port (the listener), stream_timeout_sec (-> the
     *   piper's first-byte deadline, which is Go's own use of
     *   StreamTimeout in RouteTCP).
     *
     * WHICH ARE NOT, and why -- this is a gap, recorded rather than
     * hidden:
     *   keep_alive_sec. Nothing in this port sets SO_KEEPALIVE yet.
     *   cdn_origin_host / cdn_ws_url_path. transport ==
     *   CLOAK_TRANSPORT_CDN is REJECTED at open (the connector rejects
     *   it too), so these can never be reached rather than being
     *   quietly dropped. */
    const cloak_client_config_t *config;

    /* The mux parameters every session this client creates is built
     * with. A zeroed field gets the matching CLOAK_CLIENT_STACK_DEFAULT_*
     * above; a NON-zero field is used verbatim and is VALIDATED at open
     * (see that function's TEMPLATE paragraph).
     *
     * obfuscator, ordering, valve and the four callbacks are ignored here
     * and are CLEARED rather than merely documented as ignored: the
     * connector overwrites the obfuscator with the agreed key, it
     * likewise sets the session's ordering mode from `udp` above (the
     * same bit it puts in the auth record, so the session and its own
     * handshake cannot disagree), the valve is a server-side concept, and
     * all four callbacks belong to the piper (edge E2 -- an on_broken of
     * a caller's own is a use-after-free, not a customisation). */
    cloak_session_config_t session_template;

    /* 0 selects the connector's own defaults. dial_timeout_ms bounds one
     * dial; handshake_timeout_ms bounds one handshake; max_attempts and
     * retry_base_ms are the connector's D2 ladder, INSIDE one round of
     * this module's. */
    uint64_t dial_timeout_ms;
    uint64_t handshake_timeout_ms;
    int connector_max_attempts;
    uint64_t connector_retry_base_ms;

    /* The reconnect ladder. 0 -> CLOAK_CLIENT_STACK_DEFAULT_RECONNECT_
     * BASE_MS; max_rounds 0 (CLOAK_CLIENT_STACK_ROUNDS_UNBOUNDED) means
     * never stop trying. Both are overridable because a test needs them
     * small and a caller that fails over to another server needs a
     * finite bound. */
    uint64_t reconnect_base_ms;
    int max_rounds;

    /* ADMIN MODE -- Go's `ck-client -a`. 1 makes every session this stack
     * brings up carry SESSION ID 0 instead of the fresh random id edge E4
     * otherwise requires.
     *
     * WHY THIS HAS TO BE A KNOB AND CANNOT BE THE CALLER'S BUSINESS. The
     * server calls a session admin only when the uid is its AdminUID AND
     * the session id is 0 (cloak/dispatcher.h, and src/dispatcher.c's
     * `info.is_admin = cloak_server_is_admin(...) && info.session_id ==
     * 0`). Both halves are needed, and the uid half is the only one a
     * caller of this module could supply -- the id is drawn inside
     * stack_pick_session_id, which deliberately EXCLUDES 0 for exactly
     * this reason. Without this field an admin uid reaches the server on
     * a non-zero id and is dispatched to the ordinary proxy, so `ck-client
     * -a` could not reach the admin API at all. That is not a divergence
     * a binary can work around; the stack is the supported wiring for one.
     *
     * REQUIRES num_conn == 1 AND singleplex == 0, and cloak_client_stack_
     * open rejects anything else as ERR_CONFIG rather than accepting it.
     * Go's own -a sets NumConn to 1 for the same reason the check exists:
     * every session under this flag carries the SAME id, so two live ones
     * would be keyed identically on the server's registry and attached to
     * each other -- which is what singleplex, one session per local
     * connection, would produce on the second connection. With one shared
     * session there is only ever one.
     *
     * The reconnect ladder is unaffected: a replacement session after a
     * break also carries id 0, which is correct here and is the one place
     * where "a reconnect's id differs structurally from the id it
     * replaces" does not apply -- there is only ever one such session and
     * the server has already dropped the dead one. */
    int admin_session;

    /* Piper sizing; 0 selects the piper's own CLOAK_CLIENT_PIPER_DEFAULT_*.
     * The first-byte deadline is NOT here: it comes from the config's
     * StreamTimeout, so the bound on a singleplex connection's session
     * wait cannot disagree with the bound on its first byte. */
    size_t relay_buf_cap;
    uint64_t piper_retry_delay_ms;
    unsigned piper_max_retries;
    size_t max_local_conns;

    /* The clock the authentication payload is timestamped against. NULL
     * selects time(NULL). Injectable for the reason
     * cloak/client_connector.h gives: every attempt must be stamped
     * afresh, and a test must be able to say what "now" is. */
    cloak_client_connector_now_fn now_fn;
    void *now_userdata;

    /* Optional. See the EVENTS section: this is where an owner's own
     * bookkeeping goes, and it is deliberately NOT a chain slot on the
     * session -- that one belongs to the piper and giving it away is a
     * use-after-free (edge E2). */
    cloak_client_stack_event_cb on_event;
    void *on_event_userdata;
} cloak_client_stack_config_t;

/* ------------------------------------------------------------------ */
/* Lifetime                                                            */
/* ------------------------------------------------------------------ */

/* Builds the whole graph, in the one order that works, and writes the
 * handle to *out.
 *
 * *out is set to NULL FIRST and is written only on success, so a caller
 * whose cleanup path runs cloak_client_stack_close(*out) closes NULL
 * rather than an uninitialized pointer -- the same
 * initialize-before-validate ordering every other constructor in this
 * project uses.
 *
 * CONSTRUCTION ORDER, and why each step is where it is:
 *
 *   1. the config is copied and the session template defaulted.
 *   2. the session template is PROBED, by cloak_session_init itself.
 *   3. RemoteHost:RemotePort is RESOLVED. This step BLOCKS on DNS, which
 *      is permitted here and only here (cloak/net.h) -- edge E5.
 *   4. cloak_client_piper_t, in the mode the config asked for, with this
 *      module's new_session/cancel_session seam and with the piper
 *      owning on_broken.
 *   5. the LOCAL LISTENER, before any session exists. It has to be: an
 *      application is configured to point at a fixed port, and in
 *      singleplex there is no session to bring up until a local
 *      connection has asked for one. In shared mode a connection
 *      arriving in the window before the first session is up is closed
 *      immediately by the piper -- see this file's "WHAT HAPPENS TO A
 *      LOCAL CONNECTION" section.
 *   6. SHARED MODE ONLY: round 1 of the shared session's bring-up is
 *      started. It completes on a later reactor turn; open does not
 *      block on it, and cloak_client_stack_session_up reports when it
 *      has. SINGLEPLEX does nothing here at all -- a client with no
 *      local connections holds no session, dials nothing and is
 *      invisible, which is the mode's whole point.
 *
 * WHAT IS VALIDATED, one typed error per edge, each naming itself in err:
 *
 *   ARG        out, cfg, cfg->reactor or cfg->config is NULL.
 *   CONFIG     num_conn outside 1..CLOAK_CLIENT_CONNECTOR_MAX_CONN;
 *              singleplex with num_conn != 1 (Go's singleplex IS one
 *              connection per session, and the parser can only produce
 *              the pair together -- this catches a hand-built config);
 *              an empty RemoteHost/RemotePort/LocalPort; a proxy_method
 *              longer than the wire's 12-byte field; transport ==
 *              CLOAK_TRANSPORT_CDN, which this build cannot speak and
 *              which is refused HERE rather than at the first dial;
 *              a negative StreamTimeout.
 *   TEMPLATE   the session template is rejected -- BY cloak_session_init
 *              ITSELF, which this function calls once on a throwaway
 *              session and destroys again. Re-deriving the mux layer's
 *              bounds here would be a second copy of them that could
 *              disagree with the first; asking the only authority is
 *              exact and stays exact. Without it the rejection first
 *              happens inside the first bring-up, as a connector error
 *              that says SESSION and nothing more.
 *   RESOLVE    cloak_net_resolve said no; its own message is forwarded.
 *   PIPER      cloak_client_piper_init refused.
 *   LISTEN     the local address could not be opened; err carries the
 *              address and the listener's own message.
 *   CONNECTOR  shared mode only: round 1 could not even be STARTED
 *              (cloak_client_connector_init or _start refused, which at
 *              this point means an allocation or a reactor timer, not a
 *              network condition). A network condition is NOT this: it
 *              is a round that fails later, on the ladder.
 *
 *              THAT CLAIM WAS FALSE ONCE AND IS TRUE NOW, which is worth
 *              recording because it is the shape of thing headers get
 *              wrong. cloak_client_connector_init also refuses a
 *              server_name over CLOAK_CLIENT_SERVER_NAME_MAX, and the
 *              parser used to accept two characters more than that -- so
 *              a CONFIGURATION error arrived here, as a runtime one, with
 *              a message naming no field. The parser now bounds
 *              ServerName and AlternativeNames at the same
 *              CLOAK_MAX_DNS_NAME_LEN the connector uses (the connector's
 *              constant is now DEFINED from it), so every config check
 *              this arm could fail is strictly weaker than one the parser
 *              already made, and allocation is genuinely all that is
 *              left.
 *
 * ON ANY FAILURE everything built so far is torn down before this
 * returns, in the same order cloak_client_stack_close uses -- a rejected
 * open leaks nothing and holds no descriptor -- and *out is left NULL.
 *
 * err, when non-NULL, always receives a NUL-terminated sentence naming
 * the edge, truncated to err_cap. */
int cloak_client_stack_open(cloak_client_stack_t **out, const cloak_client_stack_config_t *cfg,
                            char *err, size_t err_cap);

/* Tears the whole graph down, in the one order that works, and frees the
 * handle. Safe on NULL. After this, s is freed.
 *
 * TEARDOWN ORDER -- edge E9, and it is NOT the reverse of construction:
 *
 *   1. the local listener, so nothing new arrives mid-teardown.
 *   2. THE PIPER, BEFORE ANY SESSION. cloak_client_piper_destroy is what
 *      stops every cloak_stream_relay_t, and cloak/stream_relay.h
 *      requires that to happen before the session a relay is bound to is
 *      destroyed. THIS ONE IS REAL AND IS PINNED: reversed, it is a
 *      heap-use-after-free under ASan with traffic in flight.
 *      This step also fires cancel_session for every singleplex bring-up
 *      still in flight, which is what stops an in-flight connector from
 *      later answering a piper context that no longer exists (E7) -- so
 *      it does part of step 3's work for it, and must run first.
 *   3. every session slot still held, in list order: its retry timer is
 *      cancelled, its connector destroyed (which cancels dials and
 *      handshakes WITHOUT firing on_done), and its cloak_session_t
 *      destroyed if this stack still owns one.
 *   4. the handle.
 *
 * DOES NOT touch the reactor -- borrowed, and it must still be alive
 * when this is called.
 *
 * MUST NOT BE CALLED FROM INSIDE cloak_client_stack_event_cb, and this
 * is worth stating because that is exactly where a ck-client wants it
 * ("GAVE_UP, so exit"). An event fires from the middle of this module's
 * own work -- a connector callback, a broken chain -- and those frames
 * read s again after the callback returns, so freeing it there is a
 * use-after-free one frame up rather than merely unsupported. The shape
 * that works in a reactor program is the ordinary one: set a flag in the
 * handler, return, let cloak_reactor_run_once finish its turn, and close
 * from the main loop.
 *
 * NOT ENFORCEABLE: the calling context. This reaches
 * cloak_session_destroy and therefore inherits its restriction -- NOT
 * from within on_new_stream, and NOT from within any cloak_conn_t /
 * cloak_switchboard_t callback. From ordinary code, from a reactor
 * timer, from a signalfd handler or from this module's own event
 * callback it is safe. */
void cloak_client_stack_close(cloak_client_stack_t *s);

/* ------------------------------------------------------------------ */
/* Accessors                                                           */
/* ------------------------------------------------------------------ */

/* THESE ARE DELIBERATELY NARROW. Handing back a cloak_client_piper_t *
 * or a cloak_client_connector_t * would put every wiring field this
 * module exists to own back within a caller's reach, which is the
 * mistake the public-struct revision of cloak/server_stack.h made. What
 * is returned here is a counter or a scalar, and nothing else. */

/* The port the local listener is actually bound to, which is what a
 * LocalPort of "0" makes worth asking. In UDP mode this is the datagram
 * socket's port -- the same question, a different socket. -1 for a NULL
 * stack. */
int cloak_client_stack_local_port(const cloak_client_stack_t *s);

/* Whether the local listener holds its port as a datagram socket, asked
 * of the socket itself (SO_TYPE) rather than inferred from a bind at
 * that port number succeeding or failing -- a port number can be held by
 * any concurrent process in another protocol family, so it proves
 * nothing about THIS socket. Returns 1 in UDP mode with a datagram
 * socket, 0 in UDP mode if the socket is somehow not one (or once this
 * stack is not in UDP mode -- its listener is a stream socket by
 * construction), or -1 for a NULL stack or a UDP-mode stack with no
 * socket yet. */
int cloak_client_stack_local_is_datagram(const cloak_client_stack_t *s);

/* SHARED MODE: the id of the session currently live, or 0 when none is.
 * SINGLEPLEX: always 0 -- there is no single session to name.
 *
 * THIS IS WHAT A RECONNECT TEST READS, and it is worth saying what makes
 * it trustworthy: it is the id that was handed to the connector, so an
 * implementation that reported a fresh id while dialling with a stale
 * one would be caught by asserting the SERVER holds a session under this
 * number, which is what this module's own test does. */
uint32_t cloak_client_stack_session_id(const cloak_client_stack_t *s);

/* SHARED MODE: 1 while a session is live and attached to the piper, 0
 * while the stack is between sessions (including before the first one).
 * SINGLEPLEX: 1 while at least one local connection's session is live.
 * 0 for a NULL stack. */
int cloak_client_stack_session_up(const cloak_client_stack_t *s);

/* Sessions currently live, in either mode. In singleplex this is the
 * number of local connections that have their own tunnel. */
size_t cloak_client_stack_live_sessions(const cloak_client_stack_t *s);

/* Bring-ups started but not yet answered: a connector is dialling or
 * handshaking, or its slot is waiting out a backoff. THIS IS WHAT PINS
 * cancel_session: a piper destroyed with a bring-up in flight must leave
 * this at zero. */
size_t cloak_client_stack_pending_sessions(const cloak_client_stack_t *s);

/* Lifetime totals. Never fall.
 *
 *   rounds_started    every bring-up ROUND, first attempts and retries
 *                     alike -- the connector's own attempts are NOT
 *                     counted here, they are inside one round.
 *   reconnects        rounds started BY THE RECONNECT LOOP rather than by
 *                     open or by an accept -- i.e. every round that
 *                     followed a failed round or a broken session. This
 *                     is the loop's own work, and a client that never had
 *                     to retry reports 0, which is what makes it evidence
 *                     rather than decoration.
 *   sessions_up       rounds that produced a live session.
 *   sessions_failed   bring-ups abandoned: max_rounds spent, or the
 *                     piper cancelled the request.
 *   sessions_down     live sessions that later broke. */
size_t cloak_client_stack_rounds_started(const cloak_client_stack_t *s);
size_t cloak_client_stack_reconnects(const cloak_client_stack_t *s);
size_t cloak_client_stack_sessions_up(const cloak_client_stack_t *s);
size_t cloak_client_stack_sessions_failed(const cloak_client_stack_t *s);
size_t cloak_client_stack_sessions_down(const cloak_client_stack_t *s);

/* The piper's own counters, forwarded rather than exposing the piper:
 * local connections currently held, and how many of them hold a stream.
 * The difference is the piper's D6 window. */
size_t cloak_client_stack_local_conns(const cloak_client_stack_t *s);
size_t cloak_client_stack_local_streams(const cloak_client_stack_t *s);

#endif
