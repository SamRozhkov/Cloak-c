#ifndef CLOAK_SERVER_STACK_H
#define CLOAK_SERVER_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/config.h"
#include "cloak/dispatcher.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/session.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"

/* THE WHOLE SERVER AS ONE OBJECT: nine pieces, their cross-pointers, the
 * four-link broken-session chain, the three trampolines and the teardown
 * order, assembled in the one arrangement that is correct.
 *
 * WHY THIS EXISTS, because it decides how much it should enforce. Before
 * this file a server was assembled by hand -- about 129 lines of it,
 * spread over nine constructors, three `chain` assignments plus the
 * registry's own callback, three owner-written trampolines, and a
 * destruction order that is NOT the reverse of the construction order.
 * That wiring carries nine forced ordering edges and, until now, exactly
 * ONE of them was enforced anywhere (cloak_userpanel_open refuses to
 * start without on_session_closing). The other eight were documented, in
 * three separate headers, and the documentation was written three times
 * because it kept not being enough.
 *
 * THE FAILURE THOSE EDGES PREVENT IS NOT A CRASH AT STARTUP. It is a
 * server that boots, serves traffic, and then produces a use-after-free
 * on the next upstream byte after a user is terminated -- because
 * somebody installed the panel's broken callback as the registry's head,
 * which is what every caller wrote before the admin API module existed.
 * A startup error is the only feedback anyone can act on; the alternative
 * arrives in production, under load, long after the mistake.
 *
 * THE STACK IS AN OPAQUE HANDLE, AND THAT IS THE ENFORCEMENT. An earlier
 * revision of this file made cloak_server_stack_t a public struct holding
 * the nine objects by value, and claimed the nine edges were structural
 * because the CONFIG has no field for any of them. That claim was half
 * true and was caught in review: cloak_server_registry_t, cloak_proxy_t,
 * cloak_adminapi_t and cloak_dispatcher_t are all public structs with
 * writable wiring fields, so `st.registry.on_broken =
 * cloak_userpanel_registry_broken` -- the exact mis-wire this file exists
 * to prevent -- compiled cleanly, as did cloak_proxy_destroy(&st.proxy)
 * out of order. "Unreachable through the config, reachable by writing a
 * member the header invites you to read" is a documentation rule wearing
 * a structural claim's clothes, and documentation is precisely what has
 * already failed three times here. The definition now lives in
 * server_stack.c and a caller holds a pointer it cannot dereference. Six
 * of the nine edges became genuinely unreachable at that moment; the
 * accessors below hand back only opaque types and counters.
 *
 * WHAT THIS CHANGES FOR A BINARY: a ck-server needs a config, a reactor
 * and two calls.
 *
 * THE NINE EDGES, and where each one now lives:
 *
 *   E1 the registry's head IS cloak_proxy_registry_broken (+ the proxy),
 *      never the panel's or the admin API's -- a relay must be stopped
 *      while its session is still alive (cloak/stream_relay.h).
 *   E2 cloak_proxy_config_t::chain IS cloak_adminapi_registry_broken.
 *   E3 cloak_adminapi_config_t::chain IS cloak_userpanel_registry_broken.
 *   E4 cloak_userpanel_config_t::chain is the OWNER's, and only the
 *      owner's (cloak_server_stack_config_t::on_session_broken).
 *   E5 on_session_closing calls BOTH cloak_proxy_session_aborted AND
 *      cloak_adminapi_session_aborted -- a termination closes sessions
 *      without firing on_broken, so this is the only notification either
 *      module gets (cloak/userpanel.h's obligation 3).
 *   E6 the dispatcher's session_aborted calls BOTH of the same two.
 *   E7 the dispatcher's prepare_session branches on info->is_admin
 *      between cloak_adminapi_prepare_session and
 *      cloak_proxy_prepare_session, and on nothing else.
 *   E8 the dispatcher's panel IS the panel that owns the valves every
 *      session it authorises meters into.
 *   E9 the teardown order. See cloak_server_stack_close.
 *
 * WHAT ORDER THE CHAIN ACTUALLY REQUIRES, stated precisely because the
 * three module headers imply a total order and only part of it is real.
 * The registry's adapter invokes the head BEFORE any bookkeeping of its
 * own and defers the session's free to a zero-delay timer, so the session
 * is fully live through all four links. The proxy's link and the admin
 * API's link touch only their own module's per-session contexts and
 * neither reads the other's, so SWAPPING THOSE TWO IS UNOBSERVABLE --
 * verified by mutation under ASan, not assumed. What IS load-bearing is
 * that the PANEL'S LINK RUNS LAST of the three, because it alone can
 * reach cloak_userpanel_terminate, which destroys sessions through
 * cloak_server_registry_close_all_for_uid: anything still holding a
 * pointer into one of those sessions must have let go first. The order
 * below keeps proxy-then-adminapi because that is the order the three
 * module headers describe, not because it is forced.
 *
 * WHAT IT STILL CANNOT ENFORCE is stated at each such edge below rather
 * than in a preamble, because a preamble is the part a reader skips:
 * search this file for "NOT ENFORCEABLE".
 *
 * HAND-WIRING REMAINS LEGAL. cloak/proxy.h, cloak/adminapi.h and
 * cloak/userpanel.h still document the chain as an owner's
 * responsibility, and every test in this module that builds a partial
 * graph still does it by hand -- that is those tests' value. This is the
 * supported path for BINARIES, not a replacement for the modules' own
 * contracts.
 *
 * ONE STACK PER PROCESS. The graph is static: it is built once at
 * startup and torn down once at shutdown, and nothing about it changes
 * while the server runs. (The client's equivalent is not like this --
 * singleplex creates one connector per accepted local connection -- and
 * nothing here is generalised for that.)
 *
 * THREADING: none, like everything else in this project. One stack, one
 * reactor, one thread. */

typedef struct cloak_server_stack cloak_server_stack_t;

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

/* Every failure return NAMES THE EDGE that failed, both as a code a
 * caller can switch on and as a sentence in the caller's err buffer.
 * "Returned -1" was not enough: nine construction steps can fail and an
 * operator reading a log line needs to know which. */
#define CLOAK_SERVER_STACK_ERR_ARG          (-1)  /* a NULL this call requires */
#define CLOAK_SERVER_STACK_ERR_CONFIG       (-2)  /* the cloak_server_config_t itself */
#define CLOAK_SERVER_STACK_ERR_TEMPLATE     (-3)  /* session_config_template */
#define CLOAK_SERVER_STACK_ERR_RETRY_LADDER (-4)  /* proxy retries vs inactivity timeout */
#define CLOAK_SERVER_STACK_ERR_SERVER       (-5)  /* cloak_server_init */
#define CLOAK_SERVER_STACK_ERR_DATABASE     (-6)  /* cloak_usermanager_open */
#define CLOAK_SERVER_STACK_ERR_REGISTRY     (-7)  /* cloak_server_registry_init */
#define CLOAK_SERVER_STACK_ERR_PANEL        (-8)  /* cloak_userpanel_open */
#define CLOAK_SERVER_STACK_ERR_ADMINAPI     (-9)  /* cloak_adminapi_init */
#define CLOAK_SERVER_STACK_ERR_PROXY        (-10) /* cloak_proxy_init */
#define CLOAK_SERVER_STACK_ERR_DISPATCHER   (-11) /* cloak_dispatcher_init */
#define CLOAK_SERVER_STACK_ERR_LISTEN       (-12) /* cloak_listener_open */

/* A short, stable, English name for a code above ("bind address",
 * "session template", ...). Never NULL: an unrecognised code returns
 * "unknown". Intended for a log line that already carries the err
 * buffer's sentence. THESE STRINGS ARE PART OF THE CONTRACT and are
 * compared exactly by this module's tests -- an assertion that merely
 * checked for a non-empty string would be satisfied by "unknown" for
 * every code, which is a test written against the symbol it tests
 * rather than against the behaviour. */
const char *cloak_server_stack_strerror(int code);

/* ------------------------------------------------------------------ */
/* Defaults                                                            */
/* ------------------------------------------------------------------ */

/* The mux parameters every existing configuration in this tree uses.
 * They are defaults here (a zeroed session_config_template gets exactly
 * these) rather than something a binary has to know, because a template
 * left zeroed is otherwise accepted by this stack and then rejected by
 * cloak_session_init on the FIRST client connection -- where the
 * dispatcher turns the rejection into a redirect to the cover site.
 * Every client would be silently and correctly redirected, forever, with
 * no error anywhere. That is precisely the failure shape this module
 * exists to remove.
 *
 * 16401 is this project's max_on_wire_size everywhere and sits
 * comfortably inside CLOAK_CONN_MAX_FRAME_LEN (cloak/conn.h explains why
 * that ceiling is a wire-format constant and not a policy). */
#define CLOAK_SERVER_STACK_DEFAULT_MAX_ON_WIRE_SIZE       ((size_t)16401)
#define CLOAK_SERVER_STACK_DEFAULT_STREAM_RECV_CAPACITY   ((size_t)65536)
#define CLOAK_SERVER_STACK_DEFAULT_STREAM_MAX_PENDING     ((size_t)64)
#define CLOAK_SERVER_STACK_DEFAULT_CONN_SEND_QUEUE_CAP    ((size_t)262144)
#define CLOAK_SERVER_STACK_DEFAULT_INACTIVITY_TIMEOUT_MS  ((uint64_t)60000)

/* Slots in the replay cache. Go's server keeps its replay window in a
 * map it never bounds; this port bounds it, so the number has to come
 * from somewhere. One slot per session the registry will ever hold at
 * once, times four for the connections a multi-connection client opens
 * per session -- i.e. the number of distinct handshakes a fully loaded
 * server sees inside one replay window, with headroom. */
#define CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY  ((size_t)1024)

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    /* Required. BORROWED, and NOT ENFORCEABLE: the reactor must outlive
     * the stack. Every one of the nine objects below registers
     * descriptors and timers with it, and C offers no way to check a
     * pointer's liveness. Close the stack, then the reactor. */
    cloak_reactor_t *reactor;

    /* Required, and READ ONLY FOR THE DURATION OF cloak_server_stack_open
     * -- the stack takes its own COPY. cloak_server_config_t is a pure
     * POD (fixed arrays, no pointers), so one memcpy removes an entire
     * class of caller error: a binary that parses its config into a local
     * and returns, or reuses the struct for a reload, would otherwise
     * leave cloak_server_t holding a dangling pointer that
     * authentication reads on every handshake
     * (cloak_server_lookup_proxy and cloak_server_is_admin both read it).
     * An earlier revision of this header listed that as unenforceable; it
     * was one memcpy. */
    const cloak_server_config_t *config;

    /* 0 -> CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY. Reported
     * back by cloak_server_stack_replay_cache_capacity. */
    size_t replay_cache_capacity;

    /* The mux parameters every session this server creates is built
     * with. A zeroed field gets the matching CLOAK_SERVER_STACK_DEFAULT_*
     * above; a NON-zero field is used verbatim and is VALIDATED at
     * cloak_server_stack_open (see that function's TEMPLATE paragraph).
     *
     * ordering, valve, on_broken and the three stream callbacks are
     * ignored here, and are CLEARED rather than merely documented as
     * ignored: the ordering mode is the CLIENT's per-session declaration
     * and the dispatcher sets it from the auth record it just decrypted
     * (one server serves both modes at once, so there is no server-wide
     * answer to put here), the panel supplies the valve per user, the
     * registry overwrites on_broken (cloak/registry.h), and
     * prepare_session installs the other three. */
    cloak_session_config_t session_config_template;

    /* The clock, shared by the user manager and the panel. NULL ->
     * time(NULL). Injectable for the reason cloak/usermanager.h gives:
     * expiry and credit behaviour must be testable without writing
     * timestamps relative to the wall clock and hoping. */
    cloak_now_fn now_fn;
    void *now_userdata;

    /* 0 -> the panel's own default. */
    uint64_t upload_interval_ms;

    /* 0 -> the admin API's own default. */
    uint64_t adminapi_request_timeout_ms;

    /* 0 -> the proxy's own CLOAK_PROXY_DEFAULT_*. These are here, rather
     * than left at the proxy's defaults unconditionally, because ONE
     * cross-module invariant can only be checked where both halves are
     * visible -- and this struct is the first place in the project where
     * they are. See cloak_server_stack_open's RETRY LADDER paragraph.
     * Note that the check runs on the EFFECTIVE values, so a caller that
     * leaves these at 0 (which is what a binary accepting the proxy's
     * defaults writes) is checked against the proxy's real 50 ms x 400
     * ladder, not against zero. */
    uint64_t proxy_retry_delay_ms;
    unsigned proxy_max_retries;
    uint64_t proxy_dial_timeout_ms;
    size_t proxy_max_streams_per_session;
    size_t proxy_max_streams_total;

    /* 0 -> the dispatcher's own defaults. */
    uint64_t handshake_timeout_ms;
    uint64_t redirect_dial_timeout_ms;
    size_t max_pending_conns;

    /* THE OWNER'S LINK OF THE BROKEN-SESSION CHAIN -- the fifth and last,
     * after registry -> proxy -> adminapi -> panel. Optional; NULL means
     * the chain simply ends at the panel.
     *
     * This is the ONLY chain slot a caller has, and that is the point:
     * the other three carry the module callbacks that make teardown
     * correct, and a caller with bookkeeping of its own used to have to
     * displace one of them to get notified.
     *
     * Read cloak_userpanel_config_t::chain before writing one. Two of the
     * arguments are not what the earlier links saw: uid points at a copy
     * valid only for this call, and sesh is NULL when the panel's own
     * termination destroyed the session. Key off uid and session_id.
     *
     * NOT ENFORCEABLE: cloak/registry.h forbids this callback from
     * freeing the registry's own storage -- and therefore from freeing
     * the stack that contains it. Calling cloak_server_stack_close from
     * here is safe; nothing here can check that a caller did not instead
     * free the handle out from under the registry adapter, which reads
     * its own struct again after this returns. */
    cloak_registry_broken_cb on_session_broken;
    void *on_session_broken_userdata;

    /* The dispatcher's attach notification, which this module leaves
     * entirely to the owner -- cloak/proxy.h explains why nothing else
     * wants it. Optional. */
    cloak_dispatch_attached_cb attached;
    void *attached_userdata;
} cloak_server_stack_config_t;

/* ------------------------------------------------------------------ */
/* Lifetime                                                            */
/* ------------------------------------------------------------------ */

/* Builds the whole graph, in the one order that works, and writes the
 * handle to *out.
 *
 * *out is set to NULL FIRST and is written only on success, so a caller
 * whose cleanup path runs cloak_server_stack_close(*out) closes NULL
 * rather than an uninitialized pointer -- the same
 * initialize-before-validate ordering every other constructor in this
 * project uses, for the same reason.
 *
 * CONSTRUCTION ORDER, and why each step is where it is:
 *
 *   1. cloak_server_t       -- resolved ProxyBook and RedirAddr, bypass
 *                              set, replay cache, pointed at the stack's
 *                              OWN COPY of the config. This step BLOCKS
 *                              on DNS, which is permitted here and only
 *                              here (cloak/server.h).
 *   2. cloak_usermanager_t  -- borrowed by the panel and the admin API.
 *                              Also blocks; also startup-only.
 *   3. cloak_server_registry_t with cloak_proxy_registry_broken and the
 *                              PROXY'S ADDRESS, which is legal before the
 *                              proxy exists because the registry stores
 *                              that pointer and never dereferences it
 *                              until a session breaks.
 *   4. cloak_userpanel_t    -- needs the registry; carries the owner's
 *                              chain link and this module's
 *                              on_session_closing trampoline.
 *   5. cloak_adminapi_t     -- its chain is the panel's callback, so the
 *                              panel must exist.
 *   6. cloak_proxy_t        -- its chain is the admin API's callback.
 *   7. cloak_dispatcher_t   -- needs the server state, the registry, the
 *                              panel, and both trampolines.
 *   8. one cloak_listener_t per BindAddr -- last, so nothing can arrive
 *                              before everything that serves it exists.
 *
 * WHAT IS VALIDATED, one typed error per edge, each naming itself in err:
 *
 *   ARG        out, cfg, cfg->reactor or cfg->config is NULL.
 *   CONFIG     the config names no BindAddr at all (a server that binds
 *              nothing is not a degraded server, it is a silent one), or
 *              more than CLOAK_MAX_BIND_ADDR of them.
 *   TEMPLATE   the session template is rejected -- BY cloak_session_init
 *              ITSELF, which this function calls once on a throwaway
 *              session and destroys again. Re-deriving the mux layer's
 *              bounds here would be a second copy of them that could
 *              disagree with the first; asking the only authority is
 *              exact and stays exact. Without this check the rejection
 *              first happens on the first client's connection, where the
 *              dispatcher turns it into a cover-site redirect: every
 *              client silently redirected forever, and no error anywhere.
 *   RETRY      THE RETRY LADDER. cloak/proxy.h states this invariant and
 *   LADDER     then says "nothing here can check that, because the
 *              session config belongs to the dispatcher, not to this
 *              module". This struct owns both, so this is the first place
 *              in the project where it CAN be checked, and it is:
 *              retry_delay_ms * max_retries must be strictly less than
 *              the template's inactivity_timeout_ms, so a stream that can
 *              never start is reclaimed on the stream path rather than
 *              left to the session's. THE EFFECTIVE VALUES ARE USED, so
 *              the common case -- a binary that writes neither field and
 *              gets the proxy's 50 ms x 400 -- is the case that is
 *              checked.
 *   SERVER     cloak_server_init said no (an unresolvable RedirAddr or
 *              ProxyBook entry, a hand-built config over
 *              CLOAK_MAX_PROXY_BOOK / CLOAK_MAX_BYPASS_UID); its own
 *              message is forwarded.
 *   DATABASE   cloak_usermanager_open said no; its own message is
 *              forwarded. An EMPTY DatabasePath is not this: that is the
 *              void manager, and it succeeds.
 *   REGISTRY / PANEL / ADMINAPI / PROXY / DISPATCHER
 *              the matching constructor refused. At this point every
 *              argument has been checked, so these are allocation-class
 *              failures.
 *   LISTEN     a BindAddr could not be opened; err carries the address
 *              and the listener's own message.
 *
 * ON ANY FAILURE everything built so far is torn down before this
 * returns, in the same order cloak_server_stack_close uses -- a rejected
 * open leaks nothing and holds no descriptor -- and *out is left NULL.
 *
 * err, when non-NULL, always receives a NUL-terminated sentence naming
 * the edge, truncated to err_cap. */
int cloak_server_stack_open(cloak_server_stack_t **out, const cloak_server_stack_config_t *cfg,
                            char *err, size_t err_cap);

/* Tears the whole graph down, in the one order that works, and frees the
 * handle. Safe on NULL. After this, s is freed.
 *
 * TEARDOWN ORDER:
 *
 *   1. the listeners, so nothing new arrives mid-teardown;
 *   2. the dispatcher, which unwinds connections still mid-handshake --
 *      those can still call into the registry;
 *   3. THE PROXY, BEFORE THE REGISTRY. cloak_proxy_destroy stops every
 *      live cloak_stream_relay_t, and cloak/stream_relay.h requires that
 *      to happen before the session a relay is bound to is destroyed.
 *      THIS ONE IS REAL AND IS PINNED: reversed, it is a
 *      heap-use-after-free under ASan with traffic in flight.
 *   4. THE ADMIN API, BEFORE THE REGISTRY, for the same shape of reason:
 *      releasing a stream requires a live session, and its per-stream
 *      deadline timers are armed against streams the registry is about
 *      to free.
 *   5. the registry, which destroys every session left.
 *   6. the panel, AFTER the registry. It frees every active user's
 *      cloak_valve_t without closing anybody's sessions, and every live
 *      session holds a borrowed pointer to one (cloak/valve.h).
 *      HONESTLY: THIS ONE IS NOT OBSERVABLE TODAY, and saying so is
 *      better than billing it as load-bearing. Swapping 5 and 6 survives
 *      ASan with traffic in flight, because a valve is read only on the
 *      switchboard's data path and no reactor turn intervenes between
 *      two consecutive statements of this function. The order is kept
 *      because the rule is real at the level of the objects -- any
 *      future teardown step between them that yields to the reactor, or
 *      any panel close that grew a flush, makes it observable at once --
 *      and because cloak/userpanel.h states it as a requirement.
 *   7. the user manager, after the panel that reads it;
 *   8. the server state the proxy and the dispatcher borrowed, and then
 *      the handle itself.
 *
 * DOES NOT touch the reactor -- borrowed, and it must still be alive
 * when this is called. It no longer has any opinion about the caller's
 * cloak_server_config_t, which it copied at open.
 *
 * DOES NOT upload whatever metering the panel still has queued: that is
 * cloak_userpanel_close's documented trade (an operator loses at most one
 * upload interval). A binary that wants the last interval billed calls
 * cloak_server_stack_upload_now BEFORE this.
 *
 * NOT ENFORCEABLE: the calling context. This reaches cloak_session_destroy
 * (through the registry) and therefore inherits its restriction -- NOT
 * from within on_new_stream, and NOT from within any cloak_conn_t /
 * cloak_switchboard_t callback. From ordinary code, from a reactor timer,
 * from a signalfd handler or from a cloak_registry_broken_cb it is
 * safe. */
void cloak_server_stack_close(cloak_server_stack_t *s);

/* One upload cycle, run by hand: drains every active user's valve,
 * settles the queue into the database in one transaction, and terminates
 * whoever the database says has run out. Exactly what the periodic timer
 * runs. A graceful shutdown calls this before cloak_server_stack_close so
 * the last interval is billed. Returns cloak_userpanel_upload_now's own
 * result; s == NULL returns -1. */
int cloak_server_stack_upload_now(cloak_server_stack_t *s);

/* ------------------------------------------------------------------ */
/* Accessors                                                           */
/* ------------------------------------------------------------------ */

/* THESE ARE DELIBERATELY NARROW. Handing back a cloak_proxy_t * or a
 * cloak_server_registry_t * would put every wiring field this module
 * exists to own back within a caller's reach, which is the mistake the
 * public-struct revision of this header made. What is returned here is
 * either a COUNTER or an OPAQUE type whose own wiring lives behind its
 * own module's typedef. */

/* How many listeners are open: the config's num_bind_addr after a
 * successful open. s == NULL returns 0. */
size_t cloak_server_stack_listener_count(const cloak_server_stack_t *s);

/* The port listener i is actually bound to, which is what a BindAddr of
 * ":0" makes worth asking. -1 for a NULL stack or an out-of-range i. */
int cloak_server_stack_listener_port(const cloak_server_stack_t *s, size_t i);

/* Live sessions in the registry, in total and for one UID. */
size_t cloak_server_stack_session_count(const cloak_server_stack_t *s);
size_t cloak_server_stack_session_count_for_uid(const cloak_server_stack_t *s,
                                                const uint8_t uid[CLOAK_UID_LEN]);

/* Per-session and per-stream contexts the proxy and the admin API
 * currently hold. Diagnostics, and what a test asserts the chain and the
 * trampolines against. */
size_t cloak_server_stack_proxy_session_count(const cloak_server_stack_t *s);
size_t cloak_server_stack_proxy_stream_count(const cloak_server_stack_t *s);
size_t cloak_server_stack_admin_session_count(const cloak_server_stack_t *s);
size_t cloak_server_stack_admin_stream_count(const cloak_server_stack_t *s);

/* The replay cache this stack actually allocated -- the configured value
 * when one was given, and the default otherwise. */
size_t cloak_server_stack_replay_cache_capacity(const cloak_server_stack_t *s);

/* The panel and the user manager. BORROWED, still owned by the stack,
 * and returned rather than wrapped because BOTH ARE OPAQUE TYPES: there
 * is no wiring field behind either typedef for a caller to reach, so
 * handing them out costs nothing structurally, while wrapping every one
 * of cloak/userpanel.h's and cloak/usermanager.h's operations would be a
 * second API that could drift from the first.
 *
 * A binary wants the panel for its own reporting and the manager for a
 * user-administration subcommand. NOT ENFORCEABLE, and the one residual
 * of handing these out: do not close either yourself -- the stack does,
 * in the order above. */
cloak_userpanel_t *cloak_server_stack_panel(cloak_server_stack_t *s);
cloak_usermanager_t *cloak_server_stack_manager(cloak_server_stack_t *s);

#endif
