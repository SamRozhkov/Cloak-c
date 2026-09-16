#ifndef CLOAK_SERVER_STACK_H
#define CLOAK_SERVER_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/adminapi.h"
#include "cloak/config.h"
#include "cloak/dispatcher.h"
#include "cloak/net.h"
#include "cloak/proxy.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/server.h"
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
 * WHAT THIS CHANGES FOR A BINARY: the nine ordering edges below are no
 * longer edges a caller can reach at all. There is no field in
 * cloak_server_stack_config_t for the registry's on_broken, for any of
 * the three `chain` slots, for on_session_closing, for prepare_session or
 * for session_aborted -- those are this module's, always, and a binary
 * that wanted to get one wrong would have to edit this file. A ck-server
 * now needs a config, a reactor and two calls.
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
 *   E9 the teardown order, which inverts construction TWICE: the proxy
 *      and the admin API are destroyed BEFORE the registry (they hold
 *      stream pointers into live sessions), and the panel is closed
 *      AFTER it (it owns the valves those sessions meter into). See
 *      cloak_server_stack_destroy.
 *
 * WHAT IT STILL CANNOT ENFORCE is stated at each such edge below rather
 * than in a preamble, because a preamble is the part a reader skips:
 * search this file for "NOT ENFORCEABLE".
 *
 * HAND-WIRING REMAINS LEGAL. cloak/proxy.h, cloak/adminapi.h and
 * cloak/userpanel.h still document the chain as an owner's
 * responsibility, and every test in this module that builds a partial
 * graph still does it by hand -- that is those tests' value. This is the
 * supported path for BINARIES, not a replacement for the modules'
 * own contracts.
 *
 * ONE STACK PER PROCESS. The graph is static: it is built once at
 * startup and torn down once at shutdown, and nothing about it changes
 * while the server runs. (The client's equivalent is not like this --
 * singleplex creates one connector per accepted local connection -- and
 * nothing here is generalised for that.)
 *
 * THREADING: none, like everything else in this project. One stack, one
 * reactor, one thread. */

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
 * buffer's sentence. */
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
     * pointer's liveness. Destroy the stack, then the reactor. */
    cloak_reactor_t *reactor;

    /* Required. BORROWED, and NOT ENFORCEABLE for the same reason: the
     * cloak_server_t holds this pointer for its whole life
     * (cloak/server.h), so the config must outlive the stack. A binary
     * that parses its config into a local and returns is the realistic
     * way to get this wrong; keep it alongside the stack. */
    const cloak_server_config_t *config;

    /* 0 -> CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY. */
    size_t replay_cache_capacity;

    /* The mux parameters every session this server creates is built
     * with. A zeroed field gets the matching CLOAK_SERVER_STACK_DEFAULT_*
     * above; a NON-zero field is used verbatim and is VALIDATED at
     * cloak_server_stack_init (see that function's TEMPLATE paragraph).
     *
     * valve, on_broken and the three stream callbacks are ignored here:
     * the panel supplies the valve per user, the registry overwrites
     * on_broken (cloak/registry.h), and prepare_session installs the
     * other three. */
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
     * they are. See cloak_server_stack_init's RETRY LADDER paragraph. */
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
     * the stack that contains it. Calling cloak_server_stack_destroy from
     * here is safe; free()ing the cloak_server_stack_t is not, because
     * the registry adapter reads its own struct again after this returns.
     * Nothing here can check that. */
    cloak_registry_broken_cb on_session_broken;
    void *on_session_broken_userdata;

    /* The dispatcher's attach notification, which this module leaves
     * entirely to the owner -- cloak/proxy.h explains why nothing else
     * wants it. Optional. */
    cloak_dispatch_attached_cb attached;
    void *attached_userdata;
} cloak_server_stack_config_t;

/* ------------------------------------------------------------------ */
/* The stack                                                           */
/* ------------------------------------------------------------------ */

/* PUBLIC so that a binary can hold one by value and so that a test can
 * assert against the pieces, exactly as cloak_proxy_t and
 * cloak_adminapi_t are public. Read the fields freely; do not construct
 * or destroy any of them yourself, which is the whole point of the file.
 *
 * Every *_ready flag exists so cloak_server_stack_destroy can run on a
 * partially built stack -- which is what a failure halfway through
 * cloak_server_stack_init leaves behind, and what the caller's own
 * cleanup path will hand it. */
typedef struct {
    cloak_server_stack_config_t cfg; /* copied by value, defaults filled in */

    cloak_reactor_t *reactor; /* borrowed; cfg.reactor, hoisted */

    cloak_server_t srv;
    int srv_ready;

    /* NULL until built. A VOID manager (no rows, every route 500) when
     * the config named no DatabasePath -- which cloak/usermanager.h and
     * cloak/adminapi.h both call a legitimate deployment rather than a
     * degraded one: the server then serves its bypass and admin UIDs and
     * nobody else. */
    cloak_usermanager_t *mgr;

    cloak_server_registry_t registry;
    int registry_ready;

    cloak_userpanel_t *panel;

    cloak_adminapi_t api;
    int api_ready;

    cloak_proxy_t proxy;
    int proxy_ready;

    cloak_dispatcher_t dispatcher;
    int dispatcher_ready;

    /* One per configured BindAddr, in config order. */
    cloak_listener_t listeners[CLOAK_MAX_BIND_ADDR];
    size_t listener_count;
} cloak_server_stack_t;

/* Builds the whole graph, in the one order that works, and returns 0.
 *
 * CONSTRUCTION ORDER, and why each step is where it is:
 *
 *   1. cloak_server_t       -- resolved ProxyBook and RedirAddr, bypass
 *                              set, replay cache. Borrowed by the proxy
 *                              and the dispatcher, so it is first. This
 *                              step BLOCKS on DNS, which is permitted
 *                              here and only here (cloak/server.h).
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
 *   ARG        s, cfg, cfg->reactor or cfg->config is NULL.
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
 *              left to the session's.
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
 *              and the listener's own message. Every listener already
 *              opened is closed again before this returns.
 *
 * ON ANY FAILURE everything built so far is torn down before this
 * returns, in the same order cloak_server_stack_destroy uses -- so a
 * rejected init leaks nothing and holds no descriptor, and the partially
 * built graph is never handed back to a caller who would then have to
 * know which half of it exists. s is zeroed BEFORE anything is
 * validated, so even the ARG returns leave a struct
 * cloak_server_stack_destroy is safe on, and calling it afterwards is
 * then a documented no-op -- a caller's unconditional cleanup path is
 * correct either way.
 *
 * err, when non-NULL, always receives a NUL-terminated sentence naming
 * the edge, truncated to err_cap. */
int cloak_server_stack_init(cloak_server_stack_t *s, const cloak_server_stack_config_t *cfg,
                            char *err, size_t err_cap);

/* Tears the whole graph down, in the one order that works.
 *
 * TEARDOWN ORDER, which INVERTS CONSTRUCTION TWICE -- and those two
 * inversions are the thing a hand-wired binary gets silently wrong:
 *
 *   1. the listeners, so nothing new arrives mid-teardown;
 *   2. the dispatcher, which unwinds connections still mid-handshake --
 *      those can still call into the registry;
 *   3. THE PROXY, BEFORE THE REGISTRY. cloak_proxy_destroy stops every
 *      live cloak_stream_relay_t, and cloak/stream_relay.h requires that
 *      to happen before the session a relay is bound to is destroyed.
 *      Reversed, the relay holds a freed cloak_stream_t and the next
 *      upstream byte is a use-after-free.
 *   4. THE ADMIN API, BEFORE THE REGISTRY, for the same shape of reason:
 *      releasing a stream requires a live session, and its per-stream
 *      deadline timers are armed against streams the registry is about
 *      to free.
 *   5. the registry, which destroys every session left.
 *   6. THE PANEL, AFTER THE REGISTRY. It frees every active user's
 *      cloak_valve_t without closing anybody's sessions, and every live
 *      session holds a borrowed pointer to one (cloak/valve.h). A
 *      session outliving the panel meters into freed memory on its next
 *      byte. This is the second inversion: the panel was built before
 *      the registry and must be closed after it.
 *   7. the user manager, after the panel that reads it;
 *   8. the server state the proxy and the dispatcher borrowed.
 *
 * DOES NOT touch the reactor or the cloak_server_config_t -- both are
 * borrowed, and both must still be alive when this is called.
 *
 * DOES NOT upload whatever metering the panel still has queued: that is
 * cloak_userpanel_close's documented trade (an operator loses at most one
 * upload interval). A binary that wants the last interval billed calls
 * cloak_userpanel_upload_now(s->panel) BEFORE this.
 *
 * Idempotent, and safe on a zeroed struct, so a caller's cleanup path can
 * call it unconditionally.
 *
 * NOT ENFORCEABLE: the calling context. This reaches cloak_session_destroy
 * (through the registry) and therefore inherits its restriction -- NOT
 * from within on_new_stream, and NOT from within any cloak_conn_t /
 * cloak_switchboard_t callback. From ordinary code, from a reactor timer,
 * from a signalfd handler or from a cloak_registry_broken_cb it is safe.
 * s == NULL is a no-op. */
void cloak_server_stack_destroy(cloak_server_stack_t *s);

/* The port listener i is actually bound to, which is what a BindAddr of
 * ":0" makes worth asking. Returns -1 for a NULL stack or an i at or past
 * cloak_server_stack_listener_count. */
int cloak_server_stack_listener_port(const cloak_server_stack_t *s, size_t i);

/* How many listeners are open -- the config's num_bind_addr after a
 * successful init, and however many had been opened before the failing
 * one after a failed one (which is zero, since the failure path closes
 * them). s == NULL returns 0. */
size_t cloak_server_stack_listener_count(const cloak_server_stack_t *s);

#endif
