#ifndef CLOAK_REGISTRY_H
#define CLOAK_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/config.h"
#include "cloak/reactor.h"
#include "cloak/session.h"

/* Sessions keyed by the (UID, session id) pair -- the whole of Go's
 * userPanel -> ActiveUser -> sessions map[uint32]*mux.Session, flattened,
 * until there is a user manager to key the outer level on UID alone.
 *
 * The reason this is its own module rather than a map living inside the
 * dispatcher is entirely about lifetime, and it is worth reading in full
 * before calling anything below.
 *
 * cloak_session_broken_cb's own contract (cloak/session.h) is that
 * immediately after on_broken returns, every still-active stream this
 * session owns is destroyed and freed, and every underlying connection is
 * closed. cloak_stream_relay_t (cloak/stream_relay.h) holds its stream and
 * session as raw pointers it can never validate on its own, and states as
 * a MUST that every relay bound to a session be stopped before or during
 * that session's on_broken -- a relay left running past that point still
 * has its fd registered with the reactor, and the next byte that arrives
 * on it touches freed memory. THE OWNER'S on_broken (the callback passed
 * to cloak_server_registry_init) IS THE LAST MOMENT AT WHICH ANY RELAY
 * BOUND TO THIS SESSION MAY BE STOPPED. This registry's own internal
 * on_broken adapter therefore calls the owner's callback FIRST, before
 * doing any bookkeeping of its own or freeing anything -- so the owner
 * always gets that window, every time, regardless of what the registry
 * does afterward. Failing to stop every such relay from within that
 * callback is a use-after-free, not a hypothetical one: see
 * cloak/stream_relay.h's own doc comment for the mechanism.
 *
 * Freeing the session itself is deferred one further step, to a
 * zero-delay reactor timer, rather than done inline from inside the
 * adapter -- for the same reason cloak_session_t defers its own teardown
 * off of on_broken's call stack. This project has produced seven
 * use-after-free bugs to date; every one of them was something freed
 * while its own callback was still on the stack.
 *
 * Entries never move. Each is heap-allocated, holds its cloak_session_t
 * BY VALUE, and its address is what the session's own callbacks carry as
 * userdata for as long as that session lives. Storing entries by value in
 * a growable array would be a use-after-free the moment such an array
 * reallocs out from under a live session's callback userdata -- so this
 * table is a fixed-size array of pointers instead.
 *
 * The table is capped at CLOAK_REGISTRY_MAX_SESSIONS. A get_or_create
 * that would exceed the cap returns NULL -- this is a RESOURCE LIMIT, not
 * an error in the caller's arguments, so an attacker who keeps opening
 * sessions cannot exhaust memory through this path. */
typedef struct cloak_server_registry cloak_server_registry_t;

/* CLOAK_REGISTRY_MAX_SESSIONS is ample for this stage: there is no user
 * manager yet to spread sessions across, so this is the entire server's
 * session budget, not a per-user one. */
#define CLOAK_REGISTRY_MAX_SESSIONS 256

/* Fired exactly once per session, the moment that session becomes broken
 * for any reason cloak_session_broken_cb itself fires for. sesh is still
 * fully usable for the duration of this callback -- in particular, it is
 * still safe (and is in fact the entire reason this callback exists) to
 * call cloak_session_release_stream on any stream still held, and to stop
 * every cloak_stream_relay_t bound to sesh, from within this call. Do NOT
 * call cloak_server_registry_close on (uid, session_id) from within this
 * callback expecting a second teardown to happen -- it is documented as a
 * no-op here precisely because the registry is already mid-teardown for
 * this entry by the time this fires. sesh is freed on a LATER reactor
 * turn, never before this callback returns and never synchronously from
 * within it. */
typedef void (*cloak_registry_broken_cb)(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                          const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                          void *userdata);

struct cloak_registry_entry;

struct cloak_server_registry {
    cloak_reactor_t *reactor;
    cloak_registry_broken_cb on_broken;
    void *on_broken_userdata;

    /* NULL slots are free. cloak_server_registry_count recomputes its
     * answer by scanning this array rather than maintaining a running
     * total -- CLOAK_REGISTRY_MAX_SESSIONS is small enough that this
     * costs nothing and there is then exactly one place that can ever
     * disagree with reality. */
    struct cloak_registry_entry *entries[CLOAK_REGISTRY_MAX_SESSIONS];

    /* Non-CLOAK_TIMER_INVALID while a zero-delay sweep of dead entries is
     * pending -- at most one at a time, matching every other deferred
     * teardown in this project (cloak_session_t's own teardown_timer,
     * cloak_dial_t's immediate_timer). */
    cloak_timer_id_t sweep_timer;
};

/* Zeroes reg and validates the rest -- in that order, so that ANY failure
 * return (including r or on_broken being NULL) still leaves reg in a
 * state cloak_server_registry_destroy can safely be called against. This
 * ordering has been the source of a real crash on this branch more than
 * once: validate-then-init leaves an uninitialized struct on the
 * rejected-argument path, which is exactly the struct a caller's own
 * cleanup code goes on to pass to destroy.
 *
 * Returns 0 on success, -1 if reg, r or on_broken is NULL. */
int cloak_server_registry_init(cloak_server_registry_t *reg, cloak_reactor_t *r,
                                cloak_registry_broken_cb on_broken, void *userdata);

/* Runs any pending sweep of dead entries, cancels the sweep timer, and
 * then destroys and frees every still-live session in the table -- in
 * that order, so nothing is destroyed twice and nothing is leaked. Safe
 * to call on a registry left zeroed by a rejected
 * cloak_server_registry_init, and idempotent otherwise (a second call
 * sees an empty table and does nothing). Does not fire on_broken for any
 * session torn down this way -- this is the owner's own shutdown, not a
 * failure notification, matching cloak_session_destroy's own reasoning. */
void cloak_server_registry_destroy(cloak_server_registry_t *reg);

/* Looks up (uid, session_id). If found, returns the existing session and
 * sets *out_created (if non-NULL) to 0. Otherwise creates a new one from
 * *config and sets *out_created to 1.
 *
 * config is used verbatim for every field EXCEPT on_broken and
 * on_broken_userdata, which this call overwrites with the registry's own
 * internal adapter -- config->on_broken is therefore never invoked. This
 * is deliberate, not an oversight: the registry needs its own hook into
 * every session's on_broken to run the bookkeeping documented at the top
 * of this file (marking the entry dead, removing it from the table,
 * deferring the free), and a caller-supplied on_broken would either be
 * silently skipped by that hook or have to be chained by the registry
 * itself -- neither of which any caller here currently needs, so this
 * takes the plainer contract instead: pass cloak_registry_broken_cb to
 * cloak_server_registry_init for that purpose. Every other field --
 * obfuscator, max_on_wire_size, stream_recv_capacity,
 * stream_max_pending_frames, conn_send_queue_cap, inactivity_timeout_ms,
 * on_new_stream(_userdata), on_stream_data(_userdata) and
 * on_writable(_userdata) -- is the caller's and is passed through to
 * cloak_session_init untouched.
 *
 * Returns NULL, without creating anything, if the table is already at
 * CLOAK_REGISTRY_MAX_SESSIONS and a new session would be required -- this
 * is a RESOURCE LIMIT, not a rejection of uid/session_id/config, and is
 * indistinguishable at this call from a cloak_session_init or allocation
 * failure (both also return NULL); callers that need to tell the two
 * apart have nothing here to do so with, by design -- either way there is
 * no session and the connection this call was serving should be
 * rejected. */
cloak_session_t *cloak_server_registry_get_or_create(cloak_server_registry_t *reg,
                                                      const uint8_t uid[CLOAK_UID_LEN],
                                                      uint32_t session_id,
                                                      const cloak_session_config_t *config,
                                                      int *out_created);

/* Returns the session for (uid, session_id), or NULL if there is none
 * (never created, or already torn down). Never creates anything. */
cloak_session_t *cloak_server_registry_find(cloak_server_registry_t *reg,
                                            const uint8_t uid[CLOAK_UID_LEN],
                                            uint32_t session_id);

/* Actively tears down and removes the session for (uid, session_id), via
 * cloak_session_destroy -- immediately, not deferred, and without firing
 * on_broken (this is the owner's own action, not a failure notification;
 * matches cloak_session_destroy's own reasoning for not firing it). A
 * no-op if there is no session for (uid, session_id), including the case
 * where one existed but is already mid-teardown (dead but not yet swept)
 * because it is breaking or was already closed this way -- calling this
 * from within this registry's own cloak_registry_broken_cb callback for
 * the SAME session is exactly that case, and is therefore safe and a
 * no-op rather than a double teardown. */
void cloak_server_registry_close(cloak_server_registry_t *reg, const uint8_t uid[CLOAK_UID_LEN],
                                 uint32_t session_id);

/* The number of live sessions currently in the table (dead entries
 * awaiting their sweep do not count). */
size_t cloak_server_registry_count(const cloak_server_registry_t *reg);

#endif
