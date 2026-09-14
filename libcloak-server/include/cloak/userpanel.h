#ifndef CLOAK_USERPANEL_H
#define CLOAK_USERPANEL_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/config.h"
#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/usermanager.h"
#include "cloak/valve.h"

/* The layer between the user database and the sessions: Go's
 * internal/server/userpanel.go plus activeuser.go.
 *
 * cloak_usermanager_t (cloak/usermanager.h) knows how much credit each
 * user has left. cloak_valve_t (cloak/valve.h) counts the wire bytes one
 * user moves. Neither knows about the other. THIS module is what joins
 * them: it decides who is currently active, owns one valve per active
 * user, drains those valves onto a queue on a timer, settles the queue
 * into the database in ONE transaction, and terminates whoever the
 * database says has run out.
 *
 * WIRING (all four of these, or the module does not work):
 *
 *   cloak_userpanel_config_t pcfg = {0};
 *   pcfg.manager  = manager;    // may be a VOID manager; see below
 *   pcfg.registry = &reg;       // the ONLY session store -- see D6 below
 *   pcfg.reactor  = reactor;
 *   cloak_userpanel_open(&panel, &pcfg);
 *
 *   // 1. the dispatcher authorises through the panel, and installs the
 *   //    user's valve into the session config it hands the registry:
 *   //        scfg.valve = cloak_userpanel_user_valve(user);
 *   // 2. the panel learns a session died through the PROXY'S CHAIN:
 *   proxy_cfg.chain          = cloak_userpanel_registry_broken;
 *   proxy_cfg.chain_userdata = panel;
 *   // 3. an owner that also runs a cloak_proxy_t must stop that proxy's
 *   //    relays before the panel closes a session out from under them:
 *   pcfg.on_session_closing         = <trampoline to cloak_proxy_session_aborted>;
 *   pcfg.on_session_closing_userdata = <...>;
 *
 * WHY THE CHAIN AND NOT THE REGISTRY'S OWN CALLBACK: cloak_server_
 * registry_init takes exactly ONE cloak_registry_broken_cb for the whole
 * registry, and cloak_proxy_registry_broken already owns it -- it has to,
 * because a relay left running past its session's on_broken is a
 * use-after-free (cloak/stream_relay.h). cloak_proxy_config_t::chain
 * exists for exactly this second consumer, and the ordering is not a free
 * choice: THE PROXY RUNS FIRST, because its relays must be stopped while
 * the session is still alive, and this module's bookkeeping has no such
 * constraint.
 *
 * D6 -- THE REGISTRY IS THE ONLY SESSION STORE. Go's ActiveUser.sessions
 * map is deliberately NOT ported. A cloak_userpanel_user_t owns a valve, a
 * bypass flag and the rates it authenticated with; it does not own, count
 * or reference a single session. Everything session-shaped goes through
 * cloak_server_registry_count_for_uid / _close_all_for_uid, which are
 * linear scans over at most CLOAK_REGISTRY_MAX_SESSIONS entries. A second
 * per-user session table would have to be kept in step with the registry
 * through every teardown path this project spent a whole branch getting
 * right, and the two would disagree exactly when it mattered -- during a
 * teardown, which is when termination and billing both happen.
 *
 * THREADING: none, like everything else here. One panel, one reactor, one
 * thread. */

typedef struct cloak_userpanel cloak_userpanel_t;

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

/* These continue cloak/usermanager.h's negative code space rather than
 * starting a new one, deliberately: cloak_userpanel_get_user returns the
 * manager's own codes verbatim when authentication fails, so a caller
 * switches over ONE set of values and cannot mistake a panel code for a
 * manager code (or vice versa) at a call site that handles both. */
#define CLOAK_USERPANEL_ERR_FULL  (-11) /* the active-user table is at its cap */
#define CLOAK_USERPANEL_ERR_ALLOC (-12) /* out of memory, or the reactor refused a timer */

/* ------------------------------------------------------------------ */
/* Caps                                                                */
/* ------------------------------------------------------------------ */

/* THE ACTIVE-USER CAP, and why it is this number. A user becomes active
 * because a session is being opened for them and stops being active when
 * their last session goes (cloak_userpanel_notify_session_closed), so the
 * number of users that can usefully be active at once is bounded by the
 * number of sessions the registry will hold. Deriving it from
 * CLOAK_REGISTRY_MAX_SESSIONS rather than picking a second independent
 * number means the two can never drift into a state where the registry
 * happily creates a session for a user this table has no room to bill. */
#define CLOAK_USERPANEL_MAX_ACTIVE_USERS CLOAK_REGISTRY_MAX_SESSIONS

/* THE QUEUE CAP. The queue outlives the active user (see the queue's own
 * section below), so between two uploads it can hold entries for users
 * who are no longer active as well as every user who is -- hence twice
 * the active cap rather than equal to it. Exceeding it needs more than
 * CLOAK_USERPANEL_MAX_QUEUED_USERS DISTINCT users to have moved bytes
 * within a single upload interval. */
#define CLOAK_USERPANEL_MAX_QUEUED_USERS (2 * CLOAK_USERPANEL_MAX_ACTIVE_USERS)

/* Go's defaultUploadInterval, 1 minute. */
#define CLOAK_USERPANEL_DEFAULT_UPLOAD_INTERVAL_MS 60000u

/* ------------------------------------------------------------------ */
/* The active user                                                     */
/* ------------------------------------------------------------------ */

/* One active user. Allocated by the panel, NEVER MOVED for as long as it
 * is active, and freed by cloak_userpanel_terminate -- the address of the
 * embedded valve is handed to every one of that user's sessions
 * (cloak_session_config_t::valve) and a session has no way to learn it
 * became dangling, so an active-user table that reallocated its entries
 * would be a use-after-free the first time it grew. The table is
 * therefore a fixed-size array of pointers, for the same reason
 * cloak/registry.h's is.
 *
 * LIFETIME, stated as a rule rather than left to be inferred: a
 * cloak_userpanel_user_t * is valid until that user is terminated, and
 * cloak_userpanel_terminate destroys EVERY session belonging to that user
 * before it frees the entry -- so no session can outlive the valve it was
 * given. Do not cache this pointer across a reactor turn without also
 * re-checking cloak_userpanel_find. */
typedef struct {
    uint8_t uid[CLOAK_UID_LEN];

    /* What cloak_usermanager_authenticate returned when this user became
     * active: bytes/sec, 0 meaning unthrottled. Stored, not acted on --
     * Task 6 (token buckets) is what consumes them. A bypass user has
     * both at 0, because no manager was consulted. */
    int64_t up_rate, down_rate;

    /* A bypass user is not metered and is never uploaded, matching Go
     * (GetBypassUser hands out UNLIMITED_VALVE and updateUsageQueue skips
     * bypass users). Here that is expressed as
     * cloak_userpanel_user_valve returning NULL, which cloak/valve.h
     * already defines as the no-cost unmetered default. */
    int bypass;

    /* The user's metered traffic since the last drain. Read through
     * cloak_userpanel_user_valve, never directly, so the bypass case
     * cannot be got wrong at a call site. */
    cloak_valve_t valve;

    /* Set for the duration of cloak_userpanel_terminate -- see that
     * function's RE-ENTRANCY paragraph. An entry with this set is
     * invisible to cloak_userpanel_find (and therefore to
     * cloak_userpanel_notify_session_closed), exactly as if it had
     * already been removed. */
    int terminating;
} cloak_userpanel_user_t;

/* Returns the valve to install in a session config for this user, or NULL
 * for a bypass user (cloak/valve.h: NULL means "not metered"). u == NULL
 * returns NULL. */
cloak_valve_t *cloak_userpanel_user_valve(cloak_userpanel_user_t *u);

/* ------------------------------------------------------------------ */
/* Lifetime                                                            */
/* ------------------------------------------------------------------ */

/* Fired by cloak_userpanel_terminate once per session it is about to
 * close, WHILE THAT SESSION IS STILL ALIVE, and before anything about it
 * is torn down.
 *
 * THIS IS NOT AN EVENT, IT IS AN OBLIGATION. Terminating a user closes
 * its sessions through cloak_server_registry_close_all_for_uid, which --
 * exactly like cloak_server_registry_close, whose contract it shares --
 * does NOT fire the registry's own on_broken. That callback is the only
 * window in which a cloak_stream_relay_t bound to the session may still
 * be stopped (cloak/stream_relay.h, cloak/registry.h), so an owner that
 * also runs a cloak_proxy_t MUST use this hook to call
 * cloak_proxy_session_aborted for (uid, session_id) here. Not doing so
 * leaves relays running against a destroyed session, which is a
 * use-after-free the next byte the upstream sends.
 *
 * An owner with no relays (the panel's own tests, a server whose data
 * path is something else) may leave it NULL.
 *
 * WHAT IS SAFE FROM HERE: cloak_userpanel_notify_session_closed and
 * cloak_userpanel_find are safe and are no-ops for the user being
 * terminated (it is already marked terminating and therefore invisible).
 * cloak_userpanel_terminate on that same user is safe and is a no-op.
 * Do NOT call cloak_userpanel_close from here -- it would free the panel
 * whose terminate is still on the stack above you. */
typedef void (*cloak_userpanel_session_closing_cb)(const uint8_t uid[CLOAK_UID_LEN],
                                                   uint32_t session_id, void *userdata);

typedef struct {
    /* Required. Borrowed; must outlive the panel. May be a VOID manager
     * (cloak_usermanager_open with a NULL path), in which case
     * cloak_userpanel_get_user always fails with CLOAK_USER_ERR_VOID and
     * the server serves its bypass UIDs and nobody else -- which is a
     * legitimate deployment, not a degraded one. */
    cloak_usermanager_t *manager;

    /* Required. Borrowed. The panel's only source of truth about
     * sessions; see D6 at the top of this file. */
    cloak_server_registry_t *registry;

    /* Required. Borrowed. Carries the periodic upload timer. */
    cloak_reactor_t *reactor;

    /* 0 -> CLOAK_USERPANEL_DEFAULT_UPLOAD_INTERVAL_MS. */
    uint64_t upload_interval_ms;

    /* The clock used for cloak_user_status_t::timestamp. NULL ->
     * time(NULL). Injectable for the same reason the manager's is. */
    cloak_now_fn now_fn;
    void *now_userdata;

    /* Optional, but see cloak_userpanel_session_closing_cb -- "optional"
     * there means "only if you have no relays". */
    cloak_userpanel_session_closing_cb on_session_closing;
    void *on_session_closing_userdata;
} cloak_userpanel_config_t;

/* Allocates the panel, copies *cfg by value (substituting the default
 * upload interval for 0), and arms the first upload timer.
 *
 * *out is set to NULL first and is written only on success, so a caller
 * whose own cleanup runs cloak_userpanel_close(*out) on the failure path
 * closes NULL rather than an uninitialized pointer -- the same
 * initialize-before-validate ordering every other constructor in this
 * project now uses, for the same reason.
 *
 * Returns 0, CLOAK_USER_ERR_ARG (out, cfg, or any of the three required
 * pointers NULL), or CLOAK_USERPANEL_ERR_ALLOC (allocation, or the
 * reactor refused the timer). */
int cloak_userpanel_open(cloak_userpanel_t **out, const cloak_userpanel_config_t *cfg);

/* Cancels the upload timer and frees every active user and the queue.
 *
 * DOES NOT upload what is still queued, and does not close anybody's
 * sessions: this is the owner's own shutdown, and by the time it runs the
 * registry it was pointed at may already be gone. Whatever usage was
 * still queued is lost, which is the same trade cloak/usermanager.h's WAL
 * paragraph already makes for a crash -- an operator loses at most one
 * upload interval of metering. A caller that wants that last interval
 * billed calls cloak_userpanel_upload_now first, while the manager is
 * still open.
 *
 * ORDERING, AND IT IS NOT INTERCHANGEABLE: destroy the proxy, then the
 * registry, and only THEN close the panel. Every live session holds a
 * BORROWED pointer to an active user's valve, and cloak/valve.h states
 * the rule this imposes -- the panel must outlive every session it handed
 * a valve to. This function frees every active user (and therefore every
 * valve) without closing anybody's sessions, so a session still alive
 * afterwards meters into freed memory on its next byte. Close the panel
 * before the manager too: it does not touch the manager here, but the
 * reverse order invites a later change that uploads from here to find a
 * closed manager.
 *
 * Safe on NULL. After this, p is freed. */
void cloak_userpanel_close(cloak_userpanel_t *p);

/* ------------------------------------------------------------------ */
/* Users                                                               */
/* ------------------------------------------------------------------ */

/* Go's GetUser: returns the already-active user for uid, or authenticates
 * it through the manager and makes it active. The rates the manager
 * returns are stored on the entry (for Task 6) and the entry gets a fresh,
 * zeroed valve.
 *
 * Returns 0 and writes *out on success. On failure *out is set to NULL
 * and NOTHING is created -- an unknown, expired or out-of-credit user
 * leaves the active table exactly as it was -- and the return is the
 * manager's own code verbatim (CLOAK_USER_ERR_NOT_FOUND,
 * _NO_UP_CREDIT, _NO_DOWN_CREDIT, _EXPIRED, _VOID, _DB) or
 * CLOAK_USERPANEL_ERR_FULL / _ALLOC.
 *
 * AT THE CAP THIS REFUSES THE NEWEST USER rather than evicting an older
 * one, and that is a security decision, not an arbitrary tie-break.
 * Refusing to track a user is refusing to bill them: an eviction policy
 * would let whoever can open sessions fastest evict an established user's
 * entry, discarding the traffic accumulated in its valve (free service
 * for whoever caused the eviction) AND orphaning a valve that that user's
 * live sessions still point at (a use-after-free, not merely a billing
 * hole). Refusing the newest denies service to one marginal connection,
 * and the user denied is never billed for traffic they never got to send.
 * See CLOAK_USERPANEL_MAX_ACTIVE_USERS for why the cap is where it is. */
int cloak_userpanel_get_user(cloak_userpanel_t *p, const uint8_t uid[CLOAK_UID_LEN],
                             cloak_userpanel_user_t **out);

/* Go's GetBypassUser: the same, except that the manager is NEVER
 * consulted and the user is created unconditionally. A bypass UID comes
 * from the config file, not the database, so it may well have no row at
 * all -- and a bypass user is not metered, which here means
 * cloak_userpanel_user_valve returns NULL for it and the upload path
 * skips it entirely.
 *
 * Returns 0, or CLOAK_USERPANEL_ERR_FULL / _ALLOC / CLOAK_USER_ERR_ARG.
 * Never returns an authorisation error, because it never asks.
 *
 * If uid is already active as a NON-bypass user, that existing user is
 * returned unchanged (it is already metered; silently un-metering it
 * mid-flight would hand out free traffic). Go behaves the same way, by
 * returning whatever is in the map. */
int cloak_userpanel_get_bypass_user(cloak_userpanel_t *p, const uint8_t uid[CLOAK_UID_LEN],
                                    cloak_userpanel_user_t **out);

/* The active user for uid, or NULL if there is none. Never creates
 * anything and never consults the manager.
 *
 * A user currently inside cloak_userpanel_terminate is NOT returned: from
 * the outside it has already stopped being active, and handing back an
 * entry whose valve is about to be freed is the failure this rule exists
 * to prevent. */
cloak_userpanel_user_t *cloak_userpanel_find(cloak_userpanel_t *p,
                                             const uint8_t uid[CLOAK_UID_LEN]);

/* How many users are active. Recomputed by scanning the table, for the
 * same reason cloak_server_registry_count is: the table is small and
 * there is then exactly one thing that can disagree with reality. */
size_t cloak_userpanel_active_count(const cloak_userpanel_t *p);

/* Go's TerminateActiveUser. In order: drains this user's valve onto the
 * usage queue (so the bytes it moved are still billed), closes EVERY
 * session it holds through cloak_server_registry_close_all_for_uid, then
 * removes the entry from the active table and FREES IT.
 *
 * user IS INVALID WHEN THIS RETURNS. So is the valve any session was
 * given -- which is safe only because every such session was destroyed by
 * the close above, and is the reason that close is not optional, not
 * deferred, and reaches even a session that is ITSELF mid-teardown (see
 * cloak_server_registry_close_all_for_uid: a session whose on_broken has
 * already fired still has its connections registered with the reactor for
 * one more turn, and one more turn is all a use-after-free needs).
 *
 * A bypass user is not drained (there is nothing to drain: its valve is
 * NULL) but is otherwise terminated identically.
 *
 * RE-ENTRANCY. This function GUARDS against re-entry rather than being
 * re-entrant, and the guard is the entry's `terminating` flag, set before
 * anything else happens and never cleared (the entry is freed instead).
 * Re-entry is not hypothetical: on_session_closing is owner code invoked
 * from the middle of this function, and the realistic owner (a proxy
 * unwinding a session) can end up calling back into
 * cloak_userpanel_notify_session_closed. Without the guard, the second
 * terminate would drain a valve that is about to be freed, close an
 * already-empty session set, and free the entry a second time -- a double
 * free, which is precisely the bug shape this project has already shipped
 * twice. With it, every re-entrant terminate or notify for this user is a
 * no-op and the outermost call finishes the work.
 *
 * The alternative (making terminate genuinely re-entrant, e.g. by
 * removing the entry from the table first and letting each nested call
 * handle its own share) was rejected because it makes the SAFE ordering
 * depend on the registry continuing to tear sessions down synchronously.
 * The guard keeps the invariant local to this module, which is the one
 * property the two earlier bugs of this shape did not have.
 *
 * CALLING CONTEXT: safe from ordinary code, from a reactor timer, and
 * from inside cloak_registry_broken_cb (this is exactly where
 * cloak_userpanel_notify_session_closed calls it from). It calls
 * cloak_session_destroy indirectly, so it inherits that function's
 * restriction: NOT from within on_new_stream, and NOT from within any
 * cloak_conn_t/cloak_switchboard_t callback.
 *
 * p == NULL or user == NULL is a no-op. reason is logged and may be
 * NULL. */
void cloak_userpanel_terminate(cloak_userpanel_t *p, cloak_userpanel_user_t *user,
                               const char *reason);

/* Go does this from ActiveUser.CloseSession; here the sessions live in
 * the registry, so the panel has to be TOLD. When the last session of an
 * active user goes away, that user stops being active (and its remaining
 * usage is drained onto the queue on the way out, so nothing is lost).
 *
 * THE CALLER IS cloak_userpanel_registry_broken, installed as
 * cloak_proxy_config_t::chain -- see the WIRING block at the top of this
 * file. THIS IS THE ONE CALL THAT IS EASY TO FORGET AND IMPOSSIBLE TO
 * NOTICE: a panel that is never told simply never deactivates anybody,
 * the active table grows until it hits its cap, and the first visible
 * symptom is legitimate users being refused with
 * CLOAK_USERPANEL_ERR_FULL long after the connections responsible are
 * gone. Nothing else fails, and no log line says why.
 *
 * A no-op if uid is not active, if it still has sessions, or if it is
 * already being terminated. Safe (and intended) to call from inside a
 * cloak_registry_broken_cb: the registry marks the breaking entry dead
 * BEFORE invoking that callback, so the session that is going away is
 * already excluded from cloak_server_registry_count_for_uid by the time
 * this runs -- which is what makes "no sessions left" observable at
 * exactly the right moment rather than one turn late.
 *
 * p == NULL or uid == NULL is a no-op. */
void cloak_userpanel_notify_session_closed(cloak_userpanel_t *p,
                                           const uint8_t uid[CLOAK_UID_LEN]);

/* A cloak_registry_broken_cb (userdata: the cloak_userpanel_t). Install
 * it as cloak_proxy_config_t::chain, NOT as the registry's own on_broken
 * -- that one belongs to the proxy and must run first; see the WIRING
 * block at the top of this file.
 *
 * It is exactly cloak_userpanel_notify_session_closed for the uid, and
 * ignores reg, sesh and session_id: which session broke does not matter,
 * only whether any are left. A NULL uid (which the proxy forwards to its
 * chain when it has no key) is a no-op. */
void cloak_userpanel_registry_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                     const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                     void *userdata);

/* ------------------------------------------------------------------ */
/* The usage queue and the periodic upload                             */
/* ------------------------------------------------------------------ */

/* One upload cycle, which is what the timer runs and what a caller may
 * run by hand (tests, and a graceful shutdown that wants the last
 * interval billed). In order:
 *
 *  1. DRAIN. Every active, non-bypass user's valve is nullified and the
 *     bytes are ADDED to that user's queue entry. This is the ONE place
 *     in this codebase where the server's rx/tx vocabulary becomes the
 *     user's up/down vocabulary: a user's UPLOAD is the server's RX, a
 *     user's DOWNLOAD is the server's TX (cloak/valve.h states the rule
 *     and forbids a second conversion site). Getting it backwards meters
 *     the wrong direction against the wrong limit, silently.
 *
 *  2. COMMIT. The whole queue goes to cloak_usermanager_upload_status as
 *     one batch, i.e. one transaction and one commit. Each entry reports
 *     active = "is this uid still in the active table", num_session =
 *     cloak_server_registry_count_for_uid, and the configured clock's
 *     timestamp.
 *
 *  3. TERMINATE. Every user the manager named is terminated, with the
 *     manager's own reason string.
 *
 * THE QUEUE OUTLIVES THE ACTIVE USER, and that is why it is a separate
 * structure rather than a field on cloak_userpanel_user_t. A user who
 * disconnects between two uploads has its usage drained onto the queue by
 * cloak_userpanel_terminate and is then gone from the active table; the
 * next upload still bills it, reporting active = 0. Go keeps
 * usageUpdateQueue separate from activeUsers for exactly this reason and
 * its commitUpdate reports Active: false for such a user; this is a port
 * of that, not a coincidence.
 *
 * A FAILED UPLOAD IS RETRIED, NOT DISCARDED, and this is a deliberate
 * divergence from Go (which empties its queue BEFORE calling
 * UploadStatus, so a failure loses that interval's billing outright). The
 * manager's busy_timeout is 0, so a second writer -- an operator's
 * sqlite3 CLI, the admin API -- makes upload_status fail fast with
 * "database is locked". That is the right trade for the reactor (it never
 * stalls and never costs an authorisation outage), but it makes a failed
 * upload a routine, transient event rather than a disaster. The queue is
 * therefore cleared ONLY after upload_status returns 0; on any failure
 * every entry stays exactly as it was and the next tick re-sends the
 * whole accumulated amount. Because upload_status is all-or-nothing (one
 * transaction), re-sending the full amount is correct and not a double
 * charge. CLOAK_USER_ERR_WEDGED is retried too -- it is documented as
 * self-healing on the next drain.
 *
 * AT THE QUEUE CAP, a user with no entry yet is NOT drained at all: the
 * bytes stay in its valve and are drained at a later tick when there is
 * room. Nothing is lost on this path. The one path where usage can be
 * lost is cloak_userpanel_terminate finding the queue full -- the valve
 * is about to be freed, so there is nowhere to leave the bytes; it is
 * logged at WARN. That needs more than CLOAK_USERPANEL_MAX_QUEUED_USERS
 * distinct users to have moved bytes within one interval.
 *
 * Returns 0 when there was nothing to send or the batch was accepted, and
 * the manager's negative code when it was not. p == NULL returns
 * CLOAK_USER_ERR_ARG. */
int cloak_userpanel_upload_now(cloak_userpanel_t *p);

#endif
