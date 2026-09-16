#ifndef CLOAK_ADMINAPI_H
#define CLOAK_ADMINAPI_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/config.h"
#include "cloak/http.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/session.h"
#include "cloak/usermanager.h"

/* The admin REST API, served over a Cloak session instead of over a
 * listening socket: Go's internal/server/usermanager/api_router.go plus
 * the http.Server that adminhttp.go wraps around it.
 *
 * A client that authenticates with the server's ADMIN UID does not get a
 * proxy; it gets this. Every stream that session accepts is one HTTP
 * connection carrying exactly one request, parsed by cloak_http_parser_t
 * (cloak/http.h), routed here, answered, and closed.
 *
 * WIRING. One cloak_adminapi_t serves a whole server, exactly as one
 * cloak_proxy_t does. The owner's own cloak_dispatch_prepare_session_cb
 * decides which of the two a session belongs to and calls the matching
 * prepare function; this module deliberately does NOT install itself as
 * the dispatcher's prepare_session, because that hook is single and the
 * decision ("is this the admin UID with session id 0?") belongs to the
 * owner, not here.
 *
 *     // in the owner's prepare_session callback:
 *     if (is_admin_session(info))
 *         return cloak_adminapi_prepare_session(&api, info->uid,
 *                                               info->session_id, config);
 *     return cloak_proxy_prepare_session(d, info, config, &proxy);
 *
 *     // and, at startup, the ONE broken-session chain:
 *     cloak_server_registry_init(&reg, reactor, cloak_proxy_registry_broken,
 *                                &proxy);
 *     proxy_cfg.chain          = cloak_adminapi_registry_broken;
 *     proxy_cfg.chain_userdata = &api;
 *     api_cfg.chain            = cloak_userpanel_registry_broken;
 *     api_cfg.chain_userdata   = panel;
 *     // panel_cfg.chain is then free for the OWNER's own bookkeeping.
 *
 * THE CHAIN, AND WHY IT IS A CHAIN. cloak_server_registry_init takes
 * exactly ONE cloak_registry_broken_cb for the whole registry. Three
 * modules need that one notification -- the proxy (its relays hold raw
 * session and stream pointers), this module (its per-stream contexts hold
 * a cloak_stream_t * and an armed deadline timer) and the panel (its
 * bookkeeping) -- so each link names the next and the registry sees one
 * callback:
 *
 *     registry -> proxy -> adminapi -> panel -> (owner)
 *
 * THE ORDER IS ARGUED, NOT ARBITRARY. The proxy runs FIRST because
 * cloak_stream_relay_t must be stopped while the session is still alive
 * (cloak/stream_relay.h) and the broken callback is the only window in
 * which that is possible. This module runs NEXT because it also holds
 * stream pointers and a timer, and cloak_session_broken_cb's contract
 * (cloak/session.h) is that every still-active stream is destroyed and
 * freed the instant on_broken returns -- an adminapi never told leaks its
 * contexts and fires a deadline timer on a freed stream. The panel runs
 * LAST because its work is bookkeeping and because cloak_userpanel_
 * terminate can itself close sessions, which nothing earlier in the chain
 * may still be holding pointers into.
 *
 * AN OWNER-ASSEMBLED TRAMPOLINE THAT CALLS TWO CALLBACKS IS NOT THE SAME
 * THING and was rejected: it is silently omittable, and the failure it
 * produces is a use-after-free that shows up on a session teardown under
 * load rather than at startup. Each link naming the next makes the
 * cleanup the default and the owner's own hook the addition.
 *
 *
 * A BINARY SHOULD NOT DO ANY OF THIS BY HAND. cloak/server_stack.h
 * assembles this module together with the other eight, owns the whole
 * broken-session chain and the teardown order, and validates what it
 * can -- it is the supported wiring for an executable. Hand-wiring
 * remains legal and is what every test in this module does, because a
 * test that builds a partial graph is exactly what a test is for.
 *
 * LIFETIME: one heap context per session prepared, one per stream in
 * flight, both reactor/session callback userdata and therefore never
 * moved. THE ADMINAPI MUST OUTLIVE EVERY SESSION IT EVER PREPARED A
 * CONTEXT FOR -- the session's own on_new_stream/on_stream_data/
 * on_writable point into it. Destroy it BEFORE the registry that owns the
 * sessions, exactly as cloak_proxy_t requires.
 *
 * THE THREAT MODEL, restated because it governs every line of the
 * implementation. This module's input is attacker-controlled AND
 * AUTHENTICATED AS THE OPERATOR: reaching it costs an attacker the admin
 * UID, a 16-byte secret in a config file, and on the far side is the
 * process holding every user's credentials. Everywhere else in
 * libcloak-server a parsing bug costs a fingerprint; here it costs the
 * machine. Nothing is trusted because it authenticated, every cap is
 * enforced before the allocation it bounds, and every refusal returns
 * without performing the operation it refused.
 *
 * WHERE BYTE-FIDELITY WITH GO STOPS, and it is one place. This API is a
 * faithful port of api_router.go's wire format -- the field names, their
 * order, the status codes and the header set are Go's, and a real
 * `ck-client -a` parses what this emits. The asymmetry is in the NUMBERS,
 * and it is cloak/user_json.h's deliberate one: the encoder emits any
 * int64 exactly, because a row already holding one must be reportable,
 * while the decoder refuses any magnitude above 2^53 - 1, because cJSON
 * stores every parsed number as a double and cannot recover more than
 * that without silently truncating it. The visible consequence AT THIS
 * LAYER is that a read-modify-write round trip is not closed for every
 * document this API can produce: GET a user whose credit exceeds about 9
 * petabytes and POST the same document back, and the POST is a 400. No
 * value this API can WRITE can reach that range -- the decoder is the
 * only way in -- so such a row can only have been created by an operator
 * with a direct SQLite tool, and the credit saturation in cloak/
 * usermanager.h is the only other thing that produces one. It is
 * therefore not reachable through this interface; it is written down
 * because "byte-for-byte what Go emits" invites the assumption that
 * anything this API prints, it will also accept.
 *
 * WHAT THIS MODULE DOES NOT BOUND, stated because the memory arithmetic
 * above invites the opposite reading. SESSION contexts are uncapped here:
 * one is created per cloak_adminapi_prepare_session and the only limits
 * on how many can exist are the registry's own session cap and the admin
 * user's sessions_cap, neither of which belongs to this file. There is
 * also NO REQUEST RATE LIMIT of any kind -- nothing stops a client from
 * issuing back-to-back GET /admin/users and driving continuous full-table
 * scans through a synchronous SQLite connection on the reactor thread,
 * which stalls every other session on the server for the duration of each
 * scan (cloak/usermanager.h's own opening section explains why that stall
 * is real). Both are judged acceptable BECAUSE the only party who can do
 * either already holds the admin UID and can simply delete every user
 * instead; they are not judged impossible. An operator who shares that
 * UID more widely than one administrator should read this paragraph as
 * the reason not to.
 *
 * THREADING: none, like everything else in this project. */

typedef struct cloak_adminapi cloak_adminapi_t;
typedef struct cloak_adminapi_session cloak_adminapi_session_t;

/* ------------------------------------------------------------------ */
/* Caps and deadlines                                                  */
/* ------------------------------------------------------------------ */

/* HOW LONG ONE STREAM MAY LIVE, measured from the moment the session
 * hands it over to the moment its response has been fully written -- the
 * WHOLE exchange, not merely the request read.
 *
 * WHY A DEADLINE AT ALL: cloak/http.h states the obligation this meets.
 * A parser has no notion of time and cannot end its own wait, so a client
 * that sends "Content-Length: 65536" and then nothing pins that parser,
 * its 64 KiB body allocation, a cloak_stream_t and a context for as long
 * as the session lives. It is the same failure the dispatcher's handshake
 * deadline prevents one layer down, and it is reached the same way: by
 * starting something and stopping.
 *
 * WHY IT COVERS THE WRITE TOO, which the dispatcher's does not have to: a
 * response is composed into a buffer and drained through on_writable, so
 * a client that issues a large GET and then simply stops reading pins
 * that buffer exactly as a half-sent request pins a parser. One deadline
 * over the whole exchange bounds both with one timer and one rule, and
 * cannot be forgotten on the half nobody was thinking about.
 *
 * WHY 15 SECONDS, against CLOAK_DISPATCHER_DEFAULT_HANDSHAKE_TIMEOUT_MS.
 * That constant is 15000 because Go's readFirstPacket hard-codes a
 * 15-second read deadline; there is NO Go constant to port here (Go's
 * adminhttp.go sets no ReadTimeout or WriteTimeout on its http.Server at
 * all, so upstream bounds this with nothing), so the value is this port's
 * own choice and it deliberately matches the one deadline this project
 * already has for "a client went quiet in the middle of a message". An
 * operator learns one number, not two, and the two are the same shape of
 * protection at two layers.
 *
 * Much smaller and a legitimate exchange dies: every byte here crosses
 * the tunnel, and the response drain is paused whenever the session's
 * outbound pool is busy carrying somebody else's traffic, so a
 * one-or-two-second deadline would kill a large listing on a congested
 * server for no reason. Much larger and the pinned state above -- 64 KiB
 * of body plus a response buffer of up to the listing cap -- is held for
 * that long, multiplied by max_streams_per_session, on an attacker's
 * say-so. */
#define CLOAK_ADMINAPI_DEFAULT_REQUEST_TIMEOUT_MS ((uint64_t)15000)

/* The most users GET /admin/users will list in one response.
 *
 * WHY A CAP EXISTS: cloak_usermanager_list has no cursor (cloak/
 * usermanager.h), so a listing is count-then-allocate-all -- there is no
 * shape of this handler that streams. Go has no cap and would json.Marshal
 * a database of any size into one []byte; this is a C server on a single
 * reactor thread, and one operator request must not be able to ask it for
 * an unbounded allocation.
 *
 * WHAT IT COSTS AT THE CAP: 1024 users is at most 1024 *
 * CLOAK_USER_JSON_MAX bytes of response buffer (256 KiB) plus 1024
 * cloak_user_info_t (under 64 KiB), held for at most the request deadline
 * above, multiplied by at most max_streams_per_session.
 *
 * WHAT HAPPENS PAST IT: the request is REFUSED with 500 and a body naming
 * both the true user count and the cap. It is NOT truncated, and that is
 * the whole point -- an operator handed 1024 rows of a 5000-row database
 * with no signal would delete or re-provision users on the strength of a
 * list that silently lied. A refusal is recoverable (raise the cap, or
 * query the database directly); a silent truncation is not detectable at
 * all. 500 is the honest status: the server cannot fulfil a well-formed
 * request because of a limit of its own. */
#define CLOAK_ADMINAPI_DEFAULT_MAX_LIST_USERS ((size_t)1024)

/* The most streams ONE admin session may hold contexts for at once. Over
 * it the stream is handed straight back with cloak_session_release_stream
 * -- no context, no parser, no timer -- and the session's other streams
 * are untouched, exactly as cloak_proxy_t refuses at its own caps.
 *
 * A stream is bought with one frame carrying an unseen stream_id, and
 * each one costs this module a cloak_http_parser_t (which may grow a
 * 64 KiB body), a response buffer (up to the listing cap above) and a
 * reactor timer. 16 is several times what the real admin client does --
 * `ck-client -a` issues one request at a time -- and bounds one admin
 * session's worst case at a few megabytes rather than at whatever the
 * client chooses. Much smaller and a client pipelining a handful of
 * requests sees unexplained stream failures; much larger and the bound
 * stops bounding. */
#define CLOAK_ADMINAPI_DEFAULT_MAX_STREAMS_PER_SESSION ((size_t)16)

/* ------------------------------------------------------------------ */
/* The per-stream and per-session contexts                             */
/* ------------------------------------------------------------------ */

/* One accepted stream: one HTTP request in, one response out, then the
 * stream is closed. Heap-allocated and never moved -- its address is its
 * own deadline timer's userdata.
 *
 * ONE STREAM IS ONE REQUEST, AND THE PARSER IS NEVER REUSED. Both
 * CLOAK_HTTP_DONE and CLOAK_HTTP_ERROR are sticky (cloak/http.h), and
 * cloak_http_parser_destroy re-initializes rather than poisons -- so
 * "destroy and keep feeding" would quietly start a SECOND request from
 * whatever bytes came next, which is exactly the request smuggling the
 * parser's terminal-state stickiness exists to prevent. This module
 * therefore destroys a parser only as part of freeing its stream context,
 * and answers a finished request by closing the stream. */
typedef struct cloak_adminapi_stream {
    cloak_adminapi_session_t *as;
    cloak_stream_t *stream; /* owned by the session; released by us */

    cloak_http_parser_t parser;

    /* The composed response, and how much of it the session has taken.
     * resp is NULL until a response exists, which is also the flag that
     * says this stream has stopped reading: nothing after the request is
     * ever fed to the parser.
     *
     * WHY A BUFFER AND NOT A DIRECT WRITE: cloak_stream_write never fails
     * on a full queue by design (cloak/session.h), so a handler that
     * wrote a whole user listing in one call would not get an error -- it
     * would overrun a connection's own send-queue cap, which breaks the
     * pool and therefore EVERY stream on that session. The response is
     * composed once and drained in whole frames that are guaranteed to
     * fit, pausing when they do not, which is the same pause/resume shape
     * cloak_stream_relay_t uses for exactly the same reason. */
    char *resp;
    size_t resp_len;
    size_t resp_sent;

    /* Set for the duration of the write pump. cloak_session_writable_cb
     * is explicitly permitted to fire SYNCHRONOUSLY from inside a
     * cloak_stream_write this module itself just made, so the pump can be
     * re-entered from within itself; the flag makes the nested call a
     * no-op and lets the outer loop, which re-reads resp_sent and the
     * budget on every turn, finish the work.
     *
     * NOT REACHED BY ANY TEST IN THIS PROJECT, and that is stated here
     * rather than left to be assumed from the fact that this file argues
     * for it. Both this flag and cloak_adminapi_session_t::in_writable
     * were instrumented across the whole suite and neither branch was
     * taken once. The window is genuinely narrow: cloak_conn_t fires
     * on_drained inline only when a PREVIOUS write had already hit EAGAIN
     * and the very send this pump just made is what clears the remainder
     * (libcloak-mux/src/conn.c, conn_try_drain_send -- it deliberately
     * does not fire for a send the kernel swallows whole), and this pump
     * only writes when the queue is already nearly empty. Forcing that
     * pairing would need control over which send(2) returns EAGAIN, and
     * this project's LD_PRELOAD test shim interposes write(2), which
     * conn.c does not use for draining.
     *
     * The guards stay because they are correct and cost one branch, and
     * because the contract that makes them necessary is cloak/session.h's
     * and can change without this file. Removing them leaves all tests
     * passing -- which is exactly why this paragraph exists instead of a
     * claim of coverage. */
    int pumping;

    cloak_timer_id_t deadline;

    struct cloak_adminapi_stream *prev, *next;
} cloak_adminapi_stream_t;

/* One admin session's state. Allocated by cloak_adminapi_prepare_session
 * -- i.e. BEFORE the cloak_session_t it describes exists, since it has to
 * go into that session's config -- and freed by cloak_adminapi_destroy,
 * by cloak_adminapi_registry_broken or by cloak_adminapi_session_aborted.
 *
 * sesh is NULL until this session's FIRST STREAM arrives, for the same
 * reason cloak_proxy_session_t::sesh is: the callback that hands over a
 * stream is both the earliest moment the pointer can be useful and the
 * only moment it is needed. (uid, session_id) is the only handle a
 * context can be looked up by at every site that needs one, including the
 * abort sites where sesh is still NULL. */
struct cloak_adminapi_session {
    cloak_adminapi_t *a;
    cloak_session_t *sesh;
    uint8_t uid[CLOAK_UID_LEN];
    uint32_t session_id;

    cloak_adminapi_stream_t *streams;
    size_t stream_count;

    /* Set for the duration of on_writable. That callback walks this
     * session's stream list and may tear entries out of it; a nested
     * on_writable (which cloak_stream_write is permitted to raise from
     * inside the walk) would walk the same list underneath the outer one.
     * Refusing the nested walk loses nothing: the outer loop re-reads the
     * budget for every stream it has not yet reached.
     *
     * LIKE cloak_adminapi_stream_t::pumping, THIS BRANCH IS NOT REACHED
     * BY ANY TEST IN THIS PROJECT -- see that field's own note for the
     * measurement and for why the nesting cannot currently be forced. */
    int in_writable;

    struct cloak_adminapi_session *prev, *next;
};

/* reactor and manager are borrowed, not owned: both must outlive the
 * adminapi, which in turn must outlive every session it prepared.
 *
 * Each sizing field defaults (0 means "use the default") to the
 * CLOAK_ADMINAPI_DEFAULT_* constant above. */
typedef struct {
    cloak_reactor_t *reactor;

    /* Required. May be a VOID manager (cloak_usermanager_open with a NULL
     * path), in which case every route answers 500 -- which is the honest
     * answer: the server genuinely has no user database to administer,
     * and pretending an empty one exists would let an operator "create" a
     * user that silently went nowhere. */
    cloak_usermanager_t *manager;

    uint64_t request_timeout_ms;    /* 0 -> ..._DEFAULT_REQUEST_TIMEOUT_MS */
    size_t max_list_users;          /* 0 -> ..._DEFAULT_MAX_LIST_USERS */
    size_t max_streams_per_session; /* 0 -> ..._DEFAULT_MAX_STREAMS_PER_SESSION */

    /* The NEXT LINK of the broken-session chain, invoked with
     * chain_userdata AFTER this module's cleanup for that session has
     * completed. The panel's cloak_userpanel_registry_broken belongs here;
     * NULL simply means there is nothing further to notify.
     *
     * THE ORDERING IS NOT NEGOTIABLE. A chained callback is explicitly
     * permitted (cloak/registry.h) to destroy the registry -- including
     * the one that is mid-teardown -- and cloak_userpanel_registry_broken
     * can reach cloak_userpanel_terminate, which closes sessions. Every
     * stream this module holds must already be released by then. */
    cloak_registry_broken_cb chain;
    void *chain_userdata;
} cloak_adminapi_config_t;

struct cloak_adminapi {
    cloak_adminapi_config_t cfg; /* copied by value, defaults filled in */

    cloak_adminapi_session_t *sessions;
    size_t session_count;
    size_t stream_count; /* the sum of every session context's own */
};

/* ------------------------------------------------------------------ */
/* Lifetime                                                            */
/* ------------------------------------------------------------------ */

/* Zeroes a and validates the rest -- IN THAT ORDER, so that any failure
 * return still leaves a safe to pass to cloak_adminapi_destroy.
 *
 * Copies *cfg by value, substituting the CLOAK_ADMINAPI_DEFAULT_*
 * constants for any sizing field left at 0. cfg->reactor and
 * cfg->manager remain borrowed pointers.
 *
 * Returns 0 on success, -1 if a is NULL, or cfg, cfg->reactor or
 * cfg->manager is NULL. */
int cloak_adminapi_init(cloak_adminapi_t *a, const cloak_adminapi_config_t *cfg);

/* Tears down everything still held: for every stream context, cancels its
 * deadline, destroys its parser, frees its response buffer and releases
 * the stream back to its session; then frees every stream and session
 * context.
 *
 * Does NOT close or destroy any session -- those belong to the registry.
 * The reason this must run BEFORE the registry is destroyed is that
 * releasing a stream requires a live session.
 *
 * Idempotent, and safe on a zeroed struct. */
void cloak_adminapi_destroy(cloak_adminapi_t *a);

/* ------------------------------------------------------------------ */
/* The session callbacks                                               */
/* ------------------------------------------------------------------ */

/* Allocates this session's context and installs on_new_stream,
 * on_stream_data and on_writable into *config with that context as all
 * three userdata values.
 *
 * It MUST NOT, and does not, touch config->on_broken or
 * config->on_broken_userdata: cloak_server_registry_get_or_create
 * overwrites both unconditionally (cloak/registry.h).
 *
 * This is NOT itself a cloak_dispatch_prepare_session_cb. The dispatcher
 * has exactly one such hook and the owner needs it to choose between this
 * module and cloak_proxy_t; see the WIRING block at the top of this file.
 *
 * Returns 0, or -1 if a, uid or config is NULL, or on allocation failure.
 * A -1 from the owner's prepare_session redirects the connection to the
 * cover site, which is the right answer here too: an admin client that
 * cannot be served learns nothing about this server. */
int cloak_adminapi_prepare_session(cloak_adminapi_t *a, const uint8_t uid[CLOAK_UID_LEN],
                                   uint32_t session_id, cloak_session_config_t *config);

/* A cloak_registry_broken_cb (userdata: the cloak_adminapi_t), designed
 * to sit in the MIDDLE of the chain described at the top of this file:
 * install it as cloak_proxy_config_t::chain, and put the panel's own in
 * cloak_adminapi_config_t::chain.
 *
 * For the session context matching (uid, session_id) this tears down
 * every stream context -- cancelling each deadline and releasing each
 * stream while sesh is still usable, which is the ONLY window in which
 * that is possible -- clears the now-dead sesh pointer and frees the
 * session context; THEN invokes cfg.chain.
 *
 * A session this module has no context for is not an error: it skips
 * straight to the chain, as does a NULL uid (there is no key to look up,
 * but the chain is somebody else's and is never swallowed). A NULL
 * userdata is the one case where nothing happens at all, since the chain
 * itself lives on the adminapi.
 *
 * CALLING CONTEXT is cloak_registry_broken_cb's own, which is
 * cloak_session_broken_cb's: outside any cloak_session_t/cloak_conn_t/
 * cloak_switchboard_t callback's call stack. Everything done here --
 * cancelling a timer, cloak_session_release_stream -- is permitted
 * there. */
void cloak_adminapi_registry_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                    const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                    void *userdata);

/* Tears down and frees the context for (uid, session_id) if this module
 * has one, and does nothing at all if it does not.
 *
 * WIRING IT IS NOT OPTIONAL FOR AN OWNER THAT USES cloak_adminapi_prepare_
 * session, and it is the exact analogue of cloak_proxy_session_aborted:
 * prepare_session allocates a context before the cloak_session_t exists,
 * and if that session never comes to exist -- the registry was at its
 * cap, an allocation failed, the handshake unwound -- the registry's
 * broken callback never fires for it and nothing else would ever free it.
 * That is a small, remotely reachable, unbounded leak: one context per
 * abandoned admin handshake.
 *
 * The same obligation falls on an owner that calls
 * cloak_server_registry_close (or cloak_userpanel_terminate, through its
 * on_session_closing hook) by hand: neither fires on_broken, so this must
 * be called for that (uid, session_id) FIRST, while the session is still
 * alive. Closing without it leaves the context orphaned and leaves a
 * deadline timer armed against a stream the session is about to free.
 *
 * Deliberately a plain function rather than a
 * cloak_dispatch_session_aborted_cb: that dispatcher hook is single and
 * cloak_proxy_session_aborted already occupies it, so an owner running
 * both modules calls both from its own. Unlike the broken chain, this one
 * cannot be a chain -- cloak_proxy_config_t has no field for it -- and
 * the failure it guards is a leak rather than a use-after-free, which is
 * why it is documented here rather than made structural. */
void cloak_adminapi_session_aborted(cloak_adminapi_t *a, const uint8_t uid[CLOAK_UID_LEN],
                                    uint32_t session_id);

/* Session contexts currently held, and the total number of stream
 * contexts across all of them. Diagnostics and tests; both are O(1).
 * a == NULL returns 0. */
size_t cloak_adminapi_session_count(const cloak_adminapi_t *a);
size_t cloak_adminapi_stream_count(const cloak_adminapi_t *a);

#endif
