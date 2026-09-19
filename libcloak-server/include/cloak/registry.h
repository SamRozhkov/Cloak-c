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
 * table is a fixed-size, open-chained hash OF POINTERS to them instead;
 * see CLOAK_REGISTRY_KEY_BUCKETS below for the structure and for what it
 * replaced.
 *
 * The table is capped at CLOAK_REGISTRY_MAX_SESSIONS. A get_or_create
 * that would exceed the cap returns NULL -- this is a RESOURCE LIMIT, not
 * an error in the caller's arguments, so an attacker who keeps opening
 * sessions cannot exhaust memory through this path. */
typedef struct cloak_server_registry cloak_server_registry_t;

/* THE SESSION CAP, and where the number comes from.
 *
 * WHAT IT WAS, AND WHY IT WAS WRONG. This was 256, defended by a comment
 * reading "ample for this stage: there is no user manager yet to spread
 * sessions across, so this is the entire server's session budget, not a
 * per-user one". There has been a user manager since module 4
 * (libcloak-server/src/usermanager.c, SQLite-backed), so the premise
 * expired three modules before the number was revisited -- and the
 * second half of that sentence is the defect stated in the header's own
 * words: 256 was the WHOLE SERVER'S budget, not one user's. One Cloak
 * session per client instance (cloak/session.h) means it was a ceiling
 * of 256 simultaneous clients, server-wide, and a deployment with 300
 * users met a hard refusal delivered as a cover-site redirect -- i.e. at
 * the least visible moment this protocol has.
 *
 * WHY THERE IS A CAP AT ALL: A DELIBERATE DIVERGENCE FROM GO. Go has no
 * equivalent. /Users/sam/Cloak/internal/server/activeuser.go:21 is
 * `sessions map[uint32]*mux.Session`, an unbounded map, one per
 * ActiveUser, hanging off userpanel.go:22's equally unbounded
 * `activeUsers map[[16]byte]*ActiveUser`. Go can afford that: its map
 * grows, its runtime collects, and the worst case is pressure. This port
 * allocates one never-moved entry per session and frees it only on
 * teardown, so an unbounded table's failure mode is the OOM killer
 * taking the process down for every user at once. A refusal for one
 * client is a strictly smaller failure than that. The cap therefore
 * stays and the number is CHOSEN, which means it has to be justified.
 *
 * THE ARITHMETIC, with every input named.
 *
 *   Connections per session   K = 4
 *     (the NumConn a multi-connection client opens -- the same 4
 *      cloak/server_stack.h's replay-cache sizing uses, and what
 *      upstream's example config ships.)
 *
 *   Send-queue bytes per connection
 *     Q = CLOAK_SERVER_STACK_DEFAULT_CONN_SEND_QUEUE_CAP = 262144
 *
 *   Worst-case buffered bytes per session = K * Q = 1 MiB. Send queues
 *     only: per-stream receive buffers sit on top of this and scale with
 *     STREAMS, not sessions, so they are not what a session cap can
 *     bound and are deliberately left out of the term.
 *
 *   Backlog budget   B = 1 GiB at full occupancy. THIS IS THE ONE INPUT
 *     NOT READ OFF ANOTHER CONSTANT IN THIS TREE. It is a deployment
 *     assumption -- a server with a couple of gigabytes to its name --
 *     and it is written down so it can be argued with rather than
 *     inferred from the answer.
 *
 *   Cap = B / (K * Q) = 1 GiB / 1 MiB = 1024 sessions.
 *
 * WHAT IT IS SIZED FOR: 1024 simultaneously connected client instances,
 * server-wide. Four times the old ceiling, and the first version of this
 * number with a term in it for the resource the cap exists to protect.
 *
 * TWO CONSEQUENCES A DEPLOYMENT HAS TO KNOW ABOUT.
 *
 *  - DESCRIPTORS. 1024 * 4 = 4096 client-side descriptors at full
 *    occupancy, plus one upstream socket per proxied stream. A server at
 *    this cap needs RLIMIT_NOFILE well above the common 1024 default.
 *    The old cap already needed 1024 for its connections alone, so this
 *    is a bigger number rather than a new kind of requirement. NOT
 *    MEASURED: nothing in this tree opens 4096 descriptors at once.
 *
 *  - THE REPLAY CACHE MOVES WITH THIS NUMBER, and that coupling is not
 *    optional. cloak/server_stack.h sizes
 *    CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY from
 *    CLOAK_REGISTRY_MAX_SESSIONS * 4 connections turning over every
 *    120 s; quadrupling this quadruples that sized handshake rate, so
 *    the capacity went from 2^19 to 2^21 in the same commit.
 *    libcloak-server/tests/test_replay_cache_keyed.c derives the same
 *    inequality from the same two symbols and fails if they drift apart.
 *
 * RAISING IT FURTHER means raising B and raising the replay capacity by
 * the same factor. What it no longer means is making every lookup on the
 * handshake path proportionally slower -- see CLOAK_REGISTRY_KEY_BUCKETS
 * below, which is the other half of this commit and the reason it is one
 * commit rather than a constant bump. */
#define CLOAK_REGISTRY_MAX_SESSIONS 1024

/* THE LOOKUP STRUCTURE, and why raising the cap required replacing it.
 *
 * Until this commit the table was `entries[CLOAK_REGISTRY_MAX_SESSIONS]`
 * and EVERY operation on it was a linear scan of the whole array, at full
 * price whether the server held one session or all of them. Two of those
 * scans are on the per-connection handshake path:
 * cloak_server_registry_get_or_create's existence check, and
 * cloak_server_registry_count_for_uid, which
 * libcloak-server/src/dispatcher.c calls once per new session to apply
 * the per-user cap. Raising the session cap alone would have multiplied
 * both by four, per connection -- the scan would have become the defect.
 *
 * The table is now an OPEN-CHAINED HASH. Entries are still individually
 * heap-allocated and never moved (the reason is unchanged; it is in the
 * top-of-file comment above). What changed is how they are found: three
 * chains run through every entry, all of them maintained in exactly one
 * pair of functions in registry.c, registry_entry_link and
 * registry_entry_unlink.
 *
 *   - BY (uid, session_id): cloak_server_registry_find,
 *     cloak_server_registry_close, and get_or_create's existence check.
 *     O(1) expected, independent of how many sessions the server holds.
 *   - BY uid ALONE: cloak_server_registry_count_for_uid and
 *     cloak_server_registry_close_all_for_uid, which now cost one step
 *     per session THAT UID holds instead of one per slot in the table.
 *   - THE DEAD CHAIN: entries whose session has broken and whose
 *     deferred sweep has not yet run, so the sweep costs one step per
 *     dead entry rather than a scan of everything.
 *
 * THE OBJECTION THIS ANSWERS, because this header used to make it.
 * cloak_server_registry_count_for_uid carried "an index keyed on UID
 * would be a second structure that could disagree with the table --
 * which is the failure this module is least able to afford, since the
 * table is the only record of what is still alive." That was right about
 * an index added BESIDE the array. There is no array any more: the
 * chains ARE the table, an entry is linked in one place and unlinked in
 * one place, and there is nothing left for them to disagree with.
 * libcloak-server/tests/test_registry_scale.c case 5 cross-checks the
 * uid chains against the key chains at full occupancy regardless.
 *
 * BUCKET COUNTS, AND THE SHAPE THEY BUY. Powers of two, so the reduction
 * is a mask, and both are sized FROM THE CAP -- which is what makes the
 * cost of a lookup a constant of this table rather than a function of how
 * many sessions the server happens to be holding.
 *
 *   2048 key buckets against a 1024-entry cap is a load factor of 0.5.
 *   A successful lookup walks 1 + (n-1)/2m steps, i.e. 1.000 at one
 *   session and 1.25 at the cap. MEASURED at 1.000 / 1.015 / 1.058 /
 *   1.229 for n = 1 / 64 / 256 / 1024 by test_registry_scale.c case 2,
 *   which asserts the ratio across that whole range stays under 3.
 *
 *   1024 uid buckets, one per possible session, because
 *   cloak_server_registry_count_for_uid does not stop at its first hit --
 *   it walks its whole bucket -- so its cost is 1 + (n-1)/m rather than
 *   1 + (n-1)/2m. MEASURED at 4.988 steps at the cap when this array was
 *   256 entries long, and 2.0 at 1024, against the 1024 the scan it
 *   replaced cost unconditionally. That measurement is why this number is
 *   1024 and not 256: it is the one place in this table where halving the
 *   memory doubled the work on the handshake path.
 *
 * Together they cost (2048 + 1024) * sizeof(void *) = 24 KiB per
 * registry, of which there is one per server.
 *
 * THE HASH IS KEYED, for exactly the reason cloak/replay_cache.h gives
 * for its own: half of this key -- the session id -- is chosen by the
 * client and arrives off the wire. SipHash-2-4 under 16 bytes drawn from
 * cloak_random_bytes per registry at cloak_server_registry_init means an
 * attacker who cannot read that key cannot compute the colliding session
 * ids that would collapse one bucket back into the linear scan this
 * commit removed. That is not a hypothetical failure shape in this tree:
 * replay_cache.h records the same bug found, unkeyed, by measurement. */
#define CLOAK_REGISTRY_KEY_BUCKETS 2048
#define CLOAK_REGISTRY_UID_BUCKETS 1024

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
 * within it.
 *
 * What is and is not permitted from within this callback (mirroring
 * cloak/session.h's own on_broken doc, since reg's adapter runs in exactly
 * the calling context cloak_session_broken_cb documents itself as
 * guaranteed to run in, i.e. outside of any cloak_session_t/cloak_conn_t/
 * cloak_switchboard_t callback's call stack): calling
 * cloak_server_registry_destroy(reg) from here is safe, including for reg
 * itself -- this is the same context cloak_session_destroy's own doc
 * permits calling it in from a plain on_broken. Doing so destroys sesh
 * (among everything else still in the table) synchronously, before this
 * function returns, which is safe for the same reason calling
 * cloak_session_destroy on sesh itself would be. It also means the
 * deferred sweep this adapter is about to arm on return from your
 * callback never gets armed (cloak_server_registry_destroy sets an
 * internal destroyed flag this adapter checks first) -- reg's own
 * contract of cancelling/completing every sweep before returning is
 * upheld, not bypassed.
 *
 * MUST NOT, even with the above in mind: freeing reg's OWN backing
 * storage (e.g. `free(reg)` for a heap-allocated registry, or otherwise
 * deallocating or reusing the memory reg itself occupies) from within
 * this callback. cloak_server_registry_destroy only frees what reg OWNS
 * (its entries and their sessions); it never touches reg's own storage,
 * which remains the caller's to manage. The adapter that invoked this
 * callback (registry_on_session_broken) still runs code that reads reg
 * AFTER this callback returns -- specifically the sweep-arming check this
 * paragraph just described as safe -- so if reg's own memory is freed
 * before that point, that check is a read of freed memory regardless of
 * what cloak_server_registry_destroy did or didn't do first. In short:
 * destroying the registry from here is safe; destroying reg is not.
 *
 * What is NOT safe (in addition to the above): calling
 * cloak_server_registry_close or cloak_server_registry_destroy on this
 * registry from any OTHER callback context (e.g. from inside
 * on_stream_data) -- see cloak_server_registry_close's own doc comment. */
typedef void (*cloak_registry_broken_cb)(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                          const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                          void *userdata);

struct cloak_registry_entry;

struct cloak_server_registry {
    cloak_reactor_t *reactor;
    cloak_registry_broken_cb on_broken;
    void *on_broken_userdata;

    /* Chain heads only; everything behind them is an individually
     * heap-allocated struct cloak_registry_entry that never moves. See
     * CLOAK_REGISTRY_KEY_BUCKETS above for the whole structure. */
    struct cloak_registry_entry *key_buckets[CLOAK_REGISTRY_KEY_BUCKETS];
    struct cloak_registry_entry *uid_buckets[CLOAK_REGISTRY_UID_BUCKETS];

    /* Entries marked dead -- their session's on_broken has fired and the
     * deferred sweep has not yet reached them. A dead entry stays in BOTH
     * hash chains above: it is invisible to find and to count, but NOT to
     * cloak_server_registry_close_all_for_uid, which must still reach it
     * (see that function's doc comment for why that divergence exists). */
    struct cloak_registry_entry *dead_head;

    /* n_entries counts EVERY entry, live or dead, and is what the cap is
     * applied to -- a dead entry still owns its session, its connections
     * and its memory until the sweep runs, so it still spends budget.
     * n_dead is the length of the dead chain, and
     * cloak_server_registry_count is their difference.
     *
     * MAINTAINED RATHER THAN RECOMPUTED, which reverses what this header
     * used to say: that count "recomputes its answer by scanning this
     * array rather than maintaining a running total --
     * CLOAK_REGISTRY_MAX_SESSIONS is small enough that this costs
     * nothing and there is then exactly one place that can ever disagree
     * with reality". The first half stopped being true when the cap
     * moved: a scan is now 1024 slots and the cap check runs once per
     * handshake. The second half is preserved by construction rather
     * than given up -- these two fields are written in exactly three
     * functions, all in registry.c and all within ten lines of each
     * other: registry_entry_link, registry_entry_unlink and
     * registry_mark_dead. */
    size_t n_entries;
    size_t n_dead;

    /* SipHash-2-4's 128-bit key, drawn per registry from
     * cloak_random_bytes by cloak_server_registry_init. See the keying
     * paragraph at CLOAK_REGISTRY_KEY_BUCKETS. */
    uint8_t hash_key[16];

    /* DIAGNOSTIC COUNTERS, and the only reason they exist:
     * libcloak-server/tests/test_registry_scale.c case 2 divides one by
     * the other to measure what a lookup COSTS at one session and at the
     * full cap, and asserts the ratio. That measurement is the point of
     * this commit -- a test asserting only that lookups still return the
     * right session would pass just as happily against the linear scan
     * this replaced. Incremented by registry_find_live and by
     * cloak_server_registry_count_for_uid, the two lookups the dispatcher
     * performs per handshake. Never read by shipping code. */
    uint64_t lookup_probe_steps;
    uint64_t lookup_calls;

    /* Non-CLOAK_TIMER_INVALID while a zero-delay sweep of dead entries is
     * pending -- at most one at a time, matching every other deferred
     * teardown in this project (cloak_session_t's own teardown_timer,
     * cloak_dial_t's immediate_timer). */
    cloak_timer_id_t sweep_timer;

    /* Set by cloak_server_registry_destroy before it does anything else,
     * and checked by the sweep-arming logic before it arms a new timer.
     * This exists for exactly one reentrant sequence: a session breaks,
     * its on_broken fires, the owner calls cloak_server_registry_destroy
     * on THIS registry from inside that callback (see
     * cloak_registry_broken_cb's own doc comment -- this is permitted),
     * and destroy runs to completion -- including freeing every entry --
     * before control returns to the adapter that is still about to arm
     * the deferred sweep for the entry it just finished processing.
     * Without this flag that arm call would succeed, leaving a timer
     * pending against a registry the caller has just been told is fully
     * torn down (and may go on to free reg's own storage), so that timer
     * firing later would read and write freed memory. With it, arming
     * after destroy is a documented no-op instead. */
    int destroyed;
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
 * failure notification, matching cloak_session_destroy's own reasoning.
 *
 * Because on_broken does NOT fire here, this is NOT a second chance to
 * stop relays the way a session's own on_broken is: the caller MUST stop
 * every cloak_stream_relay_t bound to every session still in this
 * registry itself, before calling this -- see cloak_registry_broken_cb's
 * own doc comment and cloak/stream_relay.h for why a relay left running
 * past its session's teardown is a use-after-free.
 *
 * Marks reg destroyed (see the destroyed field's own comment) as the very
 * first thing this function does, before running the pending sweep or
 * freeing anything -- this is what makes it safe to call reentrantly from
 * inside this registry's own cloak_registry_broken_cb, including for reg
 * itself, per that callback's doc comment.
 *
 * NULL arguments: reg == NULL is a no-op. */
void cloak_server_registry_destroy(cloak_server_registry_t *reg);

/* Looks up (uid, session_id). If found, returns the existing session and
 * sets *out_created (if non-NULL) to 0. Otherwise creates a new one from
 * *config and sets *out_created to 1.
 *
 * *out_created is left UNTOUCHED on every NULL return (table full,
 * cloak_session_init failure, or allocation failure) -- there is no
 * session either way on that path, so there is nothing to report, and a
 * caller that reads *out_created after a NULL return without having
 * initialized it itself is reading uninitialized memory.
 *
 * THE EXISTING-SESSION PATH DISCARDS THE WHOLE OF *config, obfuscator
 * included -- this is the highest-probability mistake a caller of this
 * function can make. A dispatcher that generates a fresh per-connection
 * key and obfuscator, builds *config around it, and then finds this call
 * landing on an existing session (*out_created == 0) must NOT compose its
 * reply (or anything else keyed on that fresh material) using what it just
 * built: the session actually in use is still running on whatever
 * obfuscator it was FIRST created with. Read the live key back out of the
 * returned cloak_session_t itself -- sesh->obfuscator (cloak_session_t is
 * a fully public struct; see cloak/session.h) -- and compose the reply
 * with that. Composing with the freshly generated key instead produces a
 * session whose every frame fails AEAD, silently, with no error at the
 * handshake -- Go gets this right by construction (it looks up the
 * existing session and reuses its own key), so this is a real behavioural
 * gap this port must close by hand at the call site, not something the
 * plain "config is used verbatim" phrasing below makes obvious enough.
 *
 * Similarly, on_new_stream_userdata and on_stream_data_userdata (and
 * on_writable_userdata) pass through from *config into the session
 * UNTOUCHED only on the *out_created == 1 path -- on the existing-session
 * path they are whatever the FIRST creator supplied and are not updated.
 * A dispatcher that needs a per-session context reachable from those
 * callbacks must therefore not allocate one and hand it to every
 * get_or_create call unconditionally (that leaks the allocation on every
 * existing-session call): call cloak_server_registry_find first, and only
 * allocate a fresh context and call get_or_create when find returns NULL.
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
 * rejected.
 *
 * NULL arguments: reg == NULL, uid == NULL, or config == NULL returns
 * NULL, *out_created left untouched exactly as on every other NULL
 * return documented above. */
cloak_session_t *cloak_server_registry_get_or_create(cloak_server_registry_t *reg,
                                                      const uint8_t uid[CLOAK_UID_LEN],
                                                      uint32_t session_id,
                                                      const cloak_session_config_t *config,
                                                      int *out_created);

/* Returns the session for (uid, session_id), or NULL if there is none
 * (never created, or already torn down). Never creates anything.
 *
 * NULL arguments: reg == NULL or uid == NULL returns NULL, the same as a
 * genuine not-found. */
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
 * no-op rather than a double teardown.
 *
 * Because on_broken does NOT fire here, this function is NOT itself a
 * safe place to stop a relay from -- by the time this call reaches
 * cloak_session_destroy the session's on_broken window (the last moment a
 * bound cloak_stream_relay_t may be stopped, per
 * cloak_registry_broken_cb's own doc comment above) has already passed
 * without firing. The caller MUST stop every cloak_stream_relay_t bound
 * to this (uid, session_id) itself, BEFORE calling this -- this is the
 * function the dispatcher is expected to call most often (e.g. Go calls
 * its equivalent from the proxy-dial-failure path while relays are still
 * live), so this is not a corner case to defer thinking about.
 *
 * This is a synchronous cloak_session_destroy and therefore carries that
 * function's own calling-context restriction (cloak/session.h): it must
 * NOT be called from within on_new_stream, or from within any
 * cloak_conn_t/cloak_switchboard_t callback. Concretely, the natural-
 * looking call site "the relay for this stream just finished, tear the
 * session down" is exactly such a callback: cloak_stream_relay_done_cb
 * reached via cloak_stream_relay_notify_stream_data is invoked from a
 * session's on_stream_data, which itself fires from underneath the
 * switchboard's envelope callback on the conn read path -- calling this
 * function from there is a use-after-free, not merely against the rules.
 * Defer the call to ordinary application code (e.g. on_writable, a timer,
 * or the next reactor turn) or to this session's own on_broken instead.
 *
 * Composability note: calling this on a session where *out_created was 1
 * on the get_or_create call that produced it (i.e. this call's own doer
 * just created the session) is how a dispatcher unwinds a failure that
 * happens after creating a session but before it should be allowed to
 * live -- e.g. a reply-write failure right after handshake. *out_created
 * is the ONLY thing that should gate this: calling it unconditionally
 * after such a failure, without checking *out_created, risks tearing down
 * a live, multi-connection, pre-existing session over one bad handshake
 * on what was actually just an additional connection to it.
 *
 * NULL arguments: reg == NULL or uid == NULL is a no-op. */
void cloak_server_registry_close(cloak_server_registry_t *reg, const uint8_t uid[CLOAK_UID_LEN],
                                 uint32_t session_id);

/* The number of live sessions currently in the table (dead entries
 * awaiting their sweep do not count).
 *
 * NULL arguments: reg == NULL returns 0. */
size_t cloak_server_registry_count(const cloak_server_registry_t *reg);

/* The number of live sessions this UID currently holds (dead entries
 * awaiting their sweep do not count, exactly as in
 * cloak_server_registry_count -- which is what makes this usable from
 * inside a cloak_registry_broken_cb to ask "were there any OTHER sessions
 * besides the one that just broke?", since the breaking entry is marked
 * dead before that callback runs).
 *
 * ONE STEP PER SESSION THIS UID HOLDS, not one per slot in the table:
 * this walks the uid chain described at CLOAK_REGISTRY_KEY_BUCKETS, which
 * also answers the objection this comment used to raise against a
 * uid-keyed index (there is no separate table left for it to disagree
 * with). It matters because libcloak-server/src/dispatcher.c calls this
 * once per new session, on the handshake path, to apply the per-user cap
 * -- it was a full scan of the table there until this commit.
 *
 * NULL arguments: reg == NULL or uid == NULL returns 0. */
size_t cloak_server_registry_count_for_uid(const cloak_server_registry_t *reg,
                                           const uint8_t uid[CLOAK_UID_LEN]);

/* Fired by cloak_server_registry_close_all_for_uid once per session it is
 * about to close, while that session is STILL ALIVE and before anything
 * about it is torn down. This is the only window that function offers,
 * and it exists because that function -- like cloak_server_registry_close,
 * whose contract it shares -- does not fire on_broken: see
 * cloak_server_registry_close_all_for_uid itself.
 *
 * The entry has ALREADY been removed from the table when this fires, so a
 * cloak_server_registry_close or a nested
 * cloak_server_registry_close_all_for_uid for this same session from here
 * is a no-op rather than a double teardown, and
 * cloak_server_registry_count_for_uid no longer counts it. sesh is valid
 * for the duration of this call and is destroyed the moment it
 * returns. */
typedef void (*cloak_registry_closing_cb)(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                          const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                          void *userdata);

/* Closes every session belonging to uid, each exactly as
 * cloak_server_registry_close would: via cloak_session_destroy,
 * immediately, not deferred, and WITHOUT firing on_broken. Returns how
 * many sessions it closed.
 *
 * "EVERY" INCLUDES AN ENTRY THAT IS ALREADY DEAD -- one whose on_broken
 * has fired and whose deferred sweep has not yet run -- AND THAT IS THE
 * ONE PLACE THIS DIVERGES FROM cloak_server_registry_close, which skips
 * such an entry as a no-op. The divergence is deliberate and is the whole
 * reason to close by UID: the caller closing by UID is, by construction,
 * about to invalidate something every session of that UID holds a
 * borrowed pointer to -- for cloak_userpanel_t it is the user's
 * cloak_valve_t, which the panel frees the instant this returns. A dead
 * entry is NOT harmless in that window: its cloak_session_t is still
 * fully constructed and its remaining connections are still registered
 * with the reactor until the sweep runs a turn later, so a byte arriving
 * on one of them meters into freed memory. Skipping dead entries here
 * would therefore reintroduce, one reactor turn later, precisely the
 * use-after-free class this registry was restructured to prevent.
 * Destroying a dead entry (including the one whose on_broken is on the
 * stack right now) is safe for exactly the reason
 * cloak_server_registry_destroy -- which also destroys dead entries, from
 * that same context -- is safe; the entry is unlinked first, so the
 * pending sweep simply finds nothing where it was.
 *
 * Every other word of cloak_server_registry_close's own doc comment
 * applies, and the two that matter most are repeated because getting them
 * wrong is a use-after-free rather than a bug:
 *
 *  - Because on_broken does NOT fire, this is NOT a safe place to stop a
 *    relay from -- by the time cloak_session_destroy runs, the session's
 *    on_broken window (the last moment a bound cloak_stream_relay_t may
 *    be stopped; see cloak_registry_broken_cb above and
 *    cloak/stream_relay.h) has passed without firing. The caller MUST
 *    stop every relay bound to every session of this uid itself. THAT IS
 *    WHAT on_closing IS FOR: it fires per session, with that session's
 *    id, while the session is still alive, which is exactly the window a
 *    caller needs and cannot otherwise get -- a caller that closes by uid
 *    has no other way to learn which session ids it is about to destroy.
 *    on_closing may be NULL only when the caller genuinely has nothing
 *    bound to these sessions.
 *
 *  - This is a synchronous cloak_session_destroy and carries that
 *    function's calling-context restriction (cloak/session.h): NOT from
 *    within on_new_stream, and NOT from within any cloak_conn_t/
 *    cloak_switchboard_t callback. From within a cloak_registry_broken_cb
 *    it IS safe -- that is the same context in which
 *    cloak_server_registry_destroy (which destroys every session in the
 *    table) is already documented as permitted.
 *
 * ONE STEP PER SESSION THIS UID HOLDS, over the uid chain described at
 * CLOAK_REGISTRY_KEY_BUCKETS. Each iteration RE-READS the chain from its
 * head rather than carrying a saved `next` pointer across the callback,
 * and unlinks the entry BEFORE invoking on_closing -- so an on_closing
 * that reenters this module and closes or frees other entries of this
 * same uid cannot leave this loop holding a pointer to something it
 * freed, and cannot see, close or free the same entry twice. Re-reading
 * the head is not a second scan: every session of one uid hashes to one
 * bucket by construction, so the head of that bucket is a matching entry
 * except for the handful of foreign uids that collided into it.
 *
 * NULL arguments: reg == NULL or uid == NULL returns 0. */
size_t cloak_server_registry_close_all_for_uid(cloak_server_registry_t *reg,
                                               const uint8_t uid[CLOAK_UID_LEN],
                                               cloak_registry_closing_cb on_closing,
                                               void *userdata);

#endif
