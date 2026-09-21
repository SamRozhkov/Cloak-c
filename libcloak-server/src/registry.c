#include "cloak/registry.h"

#include <stdlib.h>
#include <string.h>

#include "cloak/common.h" /* cloak_random_bytes, for this registry's hash key */

#include "hash_internal.h"

/* One heap-allocated, never-moved entry per (uid, session_id). Its
 * address is handed to cloak_session_init as the userdata behind
 * registry_on_session_broken for as long as the session lives -- see
 * cloak/registry.h's own top-of-file comment for why this table is a
 * hash of pointers to these rather than an array of the entries
 * themselves. */
struct cloak_registry_entry {
    cloak_session_t sesh;
    uint8_t uid[CLOAK_UID_LEN];
    uint32_t session_id;
    cloak_server_registry_t *reg;

    /* Set the instant this session's on_broken fires, before the owner's
     * own callback is invoked -- see registry_on_session_broken. Once
     * set, this entry is invisible to cloak_server_registry_find and
     * cloak_server_registry_close (both skip dead entries), and no
     * longer counted by cloak_server_registry_count; it still holds its
     * place in both hash chains, still spends one of the cap's
     * CLOAK_REGISTRY_MAX_SESSIONS entries, and its cloak_session_t is
     * still live (not yet destroyed) until the deferred sweep reaches
     * it. Marking dead also links it onto reg->dead_head, which is how
     * that sweep finds it in one step. */
    int dead;

    /* THE THREE CHAINS, described in full at CLOAK_REGISTRY_KEY_BUCKETS
     * in cloak/registry.h. Each is an intrusive doubly-linked list in the
     * hlist shape: `next` forwards, `pprev` pointing AT the pointer that
     * points at this entry (a bucket head, or the previous entry's next
     * field), which is what makes an unlink O(1) without a head special
     * case and without knowing which bucket the entry sits in.
     *
     * key_*  -- the (uid, session_id) bucket. Every entry, live or dead.
     * uid_*  -- the uid bucket. Every entry, live or dead.
     * dead_* -- reg->dead_head. Dead entries only; pprev is NULL for a
     *           live one, which is what registry_entry_unlink tests. */
    struct cloak_registry_entry *key_next, **key_pprev;
    struct cloak_registry_entry *uid_next, **uid_pprev;
    struct cloak_registry_entry *dead_next, **dead_pprev;
};

/* ------------------------------------------------------------------ */
/* The keyed bucket functions                                          */
/* ------------------------------------------------------------------ */

static size_t registry_key_bucket(const cloak_server_registry_t *reg,
                                   const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id) {
    uint8_t buf[CLOAK_UID_LEN + 4];
    memcpy(buf, uid, CLOAK_UID_LEN);
    /* Explicit little-endian, not a memcpy of the uint32_t: the bucket a
     * session lands in must not depend on the host's byte order, or a
     * test that pins a distribution passes on one machine and not
     * another. */
    buf[CLOAK_UID_LEN + 0] = (uint8_t)(session_id & 0xFFu);
    buf[CLOAK_UID_LEN + 1] = (uint8_t)((session_id >> 8) & 0xFFu);
    buf[CLOAK_UID_LEN + 2] = (uint8_t)((session_id >> 16) & 0xFFu);
    buf[CLOAK_UID_LEN + 3] = (uint8_t)((session_id >> 24) & 0xFFu);
    return (size_t)(cloak_siphash24(reg->hash_key, buf, sizeof(buf)) &
                    (uint64_t)(CLOAK_REGISTRY_KEY_BUCKETS - 1));
}

static size_t registry_uid_bucket(const cloak_server_registry_t *reg,
                                   const uint8_t uid[CLOAK_UID_LEN]) {
    return (size_t)(cloak_siphash24(reg->hash_key, uid, CLOAK_UID_LEN) &
                    (uint64_t)(CLOAK_REGISTRY_UID_BUCKETS - 1));
}

/* ------------------------------------------------------------------ */
/* The three chains                                                    */
/* ------------------------------------------------------------------ */

/* Six near-identical five-line functions rather than one macro or one
 * offsetof-driven helper: a chain bug here is a use-after-free or a lost
 * session, the three chains have different membership rules, and code
 * that can be read without expanding anything is worth more than the
 * duplication costs. */

static void key_chain_add(cloak_server_registry_t *reg, struct cloak_registry_entry *e) {
    struct cloak_registry_entry **head =
        &reg->key_buckets[registry_key_bucket(reg, e->uid, e->session_id)];
    e->key_next = *head;
    if (*head != NULL) {
        (*head)->key_pprev = &e->key_next;
    }
    *head = e;
    e->key_pprev = head;
}

static void key_chain_del(struct cloak_registry_entry *e) {
    if (e->key_pprev == NULL) {
        return;
    }
    if (e->key_next != NULL) {
        e->key_next->key_pprev = e->key_pprev;
    }
    *e->key_pprev = e->key_next;
    e->key_next = NULL;
    e->key_pprev = NULL;
}

static void uid_chain_add(cloak_server_registry_t *reg, struct cloak_registry_entry *e) {
    struct cloak_registry_entry **head = &reg->uid_buckets[registry_uid_bucket(reg, e->uid)];
    e->uid_next = *head;
    if (*head != NULL) {
        (*head)->uid_pprev = &e->uid_next;
    }
    *head = e;
    e->uid_pprev = head;
}

static void uid_chain_del(struct cloak_registry_entry *e) {
    if (e->uid_pprev == NULL) {
        return;
    }
    if (e->uid_next != NULL) {
        e->uid_next->uid_pprev = e->uid_pprev;
    }
    *e->uid_pprev = e->uid_next;
    e->uid_next = NULL;
    e->uid_pprev = NULL;
}

static void dead_chain_add(cloak_server_registry_t *reg, struct cloak_registry_entry *e) {
    struct cloak_registry_entry **head = &reg->dead_head;
    e->dead_next = *head;
    if (*head != NULL) {
        (*head)->dead_pprev = &e->dead_next;
    }
    *head = e;
    e->dead_pprev = head;
}

static void dead_chain_del(struct cloak_registry_entry *e) {
    if (e->dead_pprev == NULL) {
        return;
    }
    if (e->dead_next != NULL) {
        e->dead_next->dead_pprev = e->dead_pprev;
    }
    *e->dead_pprev = e->dead_next;
    e->dead_next = NULL;
    e->dead_pprev = NULL;
}

/* THE ONLY THREE FUNCTIONS THAT WRITE reg->n_entries OR reg->n_dead, and
 * the only three that change an entry's chain membership. cloak/registry.h
 * cites exactly this when it says the maintained counters keep the
 * "exactly one place that can disagree with reality" property the old
 * recomputing count had. */

static void registry_entry_link(cloak_server_registry_t *reg, struct cloak_registry_entry *e) {
    key_chain_add(reg, e);
    uid_chain_add(reg, e);
    reg->n_entries++;
}

static void registry_entry_unlink(cloak_server_registry_t *reg, struct cloak_registry_entry *e) {
    key_chain_del(e);
    uid_chain_del(e);
    if (e->dead) {
        dead_chain_del(e);
        reg->n_dead--;
    }
    reg->n_entries--;
}

static void registry_mark_dead(cloak_server_registry_t *reg, struct cloak_registry_entry *e) {
    e->dead = 1;
    dead_chain_add(reg, e);
    reg->n_dead++;
}

/* Destroys and frees one entry unconditionally -- used by the sweep, by
 * cloak_server_registry_close, and by cloak_server_registry_destroy. The
 * caller is responsible for having already called registry_entry_unlink
 * on it first -- every caller here does, on the line above. */
static void registry_free_entry(struct cloak_registry_entry *entry) {
    cloak_session_destroy(&entry->sesh);
    free(entry);
}

/* Finds the live (not dead) entry for (uid, session_id), or NULL. Shared
 * by get_or_create (existence check), find, and close.
 *
 * One walk of one key bucket. A dead entry with the same key is skipped
 * rather than removed from the chain, because a dead entry is still
 * reachable BY UID until its sweep runs (see
 * cloak_server_registry_close_all_for_uid) -- so both the dead entry and
 * the live one a later get_or_create created for the same key can sit in
 * the same bucket, and the live one is the answer.
 *
 * The two counters are the measurement test_registry_scale.c case 2
 * reads; see their declaration in cloak/registry.h. */
static struct cloak_registry_entry *registry_find_live(cloak_server_registry_t *reg,
                                                        const uint8_t uid[CLOAK_UID_LEN],
                                                        uint32_t session_id) {
    reg->lookup_calls++;
    for (struct cloak_registry_entry *entry = reg->key_buckets[registry_key_bucket(reg, uid, session_id)];
         entry != NULL; entry = entry->key_next) {
        reg->lookup_probe_steps++;
        if (!entry->dead && entry->session_id == session_id &&
            memcmp(entry->uid, uid, CLOAK_UID_LEN) == 0) {
            return entry;
        }
    }
    return NULL;
}

/* Destroys and frees every entry still marked dead -- the work a pending
 * sweep timer performs, factored out so cloak_server_registry_destroy can
 * run it synchronously for anything still pending instead of duplicating
 * the loop. */
static void registry_sweep_dead_entries(cloak_server_registry_t *reg) {
    /* Pops the dead chain's head each turn rather than walking it with a
     * saved `next`: registry_free_entry runs cloak_session_destroy, and
     * re-reading the head is what makes this correct without having to
     * prove that nothing anywhere under that call can reach back into
     * this registry and unlink the entry we were about to visit. It is
     * also one step per DEAD entry rather than one per slot in the
     * table, which is what a sweep armed by a single session's teardown
     * needs to be once the cap is 1024. */
    struct cloak_registry_entry *entry;
    while ((entry = reg->dead_head) != NULL) {
        registry_entry_unlink(reg, entry);
        registry_free_entry(entry);
    }
}

static void registry_sweep_timer_cb(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_server_registry_t *reg = userdata;
    reg->sweep_timer = CLOAK_TIMER_INVALID; /* this timer has now fired -- nothing left to cancel */
    registry_sweep_dead_entries(reg);
}

/* Arms the deferred sweep if one is not already pending. Called only
 * right after marking an entry dead, so there is always at least one
 * dead entry for the timer to find when it fires. */
static void registry_arm_sweep(cloak_server_registry_t *reg) {
    if (reg->destroyed) {
        /* reg has already been (or is currently being) torn down by
         * cloak_server_registry_destroy -- reached when that destroy was
         * called reentrantly from within this same registry's
         * cloak_registry_broken_cb, before this function's caller
         * (registry_on_session_broken) got a chance to arm the sweep for
         * the entry it just finished processing. Every entry, including
         * that one, has already been destroyed and freed by that destroy
         * call, so arming a timer here would either fire against a
         * registry the caller may have already freed, or, best case, be
         * pure waste. See the destroyed field's own comment. */
        return;
    }
    if (reg->sweep_timer != CLOAK_TIMER_INVALID) {
        return; /* a sweep is already on its way; it will catch this entry too */
    }
    reg->sweep_timer = cloak_reactor_add_timer(reg->reactor, 0, registry_sweep_timer_cb, reg);
    if (reg->sweep_timer == CLOAK_TIMER_INVALID) {
        /* Only reachable on allocation failure growing the reactor's timer
         * heap. There is no later event that would ever retry arming this
         * timer, so leaving the entry dead-but-unswept here would leak it
         * (and everything it owns) for the rest of the process. Falling
         * back to sweeping synchronously, right here, is safe specifically
         * because this function is only ever called from
         * registry_on_session_broken AFTER it has already invoked the
         * owner's callback -- i.e. from the same safe-to-destroy context
         * cloak_session_broken_cb's own doc comment describes (outside of
         * any cloak_session_t/cloak_conn_t/cloak_stream_t callback's call
         * stack), not from underneath one. */
        registry_sweep_dead_entries(reg);
    }
}

/* The registry's own cloak_session_broken_cb adapter, installed as
 * on_broken/on_broken_userdata on every session this registry creates
 * (see cloak_server_registry_get_or_create). userdata is the owning
 * entry.
 *
 * Order matters here and must never change: mark dead FIRST (so a
 * reentrant cloak_server_registry_close call for this same session,
 * issued from inside the owner's callback below, sees an already-dead
 * entry and does nothing), THEN invoke the owner's callback (this is the
 * owner's last chance to stop every cloak_stream_relay_t bound to sesh --
 * see cloak/registry.h and cloak/stream_relay.h), and only THEN arm the
 * deferred sweep that will actually destroy and free sesh. Freeing
 * anything before the owner's callback returns would take away the
 * window this whole adapter exists to provide. */
static void registry_on_session_broken(cloak_session_t *sesh, void *userdata) {
    struct cloak_registry_entry *entry = userdata;
    cloak_server_registry_t *reg = entry->reg;
    registry_mark_dead(reg, entry);

    if (reg->on_broken != NULL) {
        reg->on_broken(reg, sesh, entry->uid, entry->session_id, reg->on_broken_userdata);
    }

    registry_arm_sweep(reg);
}

int cloak_server_registry_init(cloak_server_registry_t *reg, cloak_reactor_t *r,
                                cloak_registry_broken_cb on_broken, void *userdata) {
    /* Zero and sentinel FIRST, before validating anything else, so every
     * failure return below (including reg itself surviving with nothing
     * else valid) leaves a struct cloak_server_registry_destroy can
     * safely be called against. Only reg == NULL is exempt, since there
     * is nothing to initialize. */
    if (reg != NULL) {
        memset(reg, 0, sizeof(*reg));
        reg->sweep_timer = CLOAK_TIMER_INVALID;
    }

    if (reg == NULL || r == NULL || on_broken == NULL) {
        return -1;
    }

    reg->reactor = r;
    reg->on_broken = on_broken;
    reg->on_broken_userdata = userdata;

    /* Drawn here, per registry, and never anywhere else -- the same
     * discipline cloak_replay_cache_init follows, for the same reason.
     * Drawn AFTER the argument checks so that a rejected init does no
     * work, and before any entry can exist, since the bucket an entry
     * lands in is computed from this key and nothing rehashes. */
    cloak_random_bytes(reg->hash_key, sizeof(reg->hash_key));
    return 0;
}

void cloak_server_registry_destroy(cloak_server_registry_t *reg) {
    if (reg == NULL) {
        return;
    }

    /* Set FIRST, before touching anything else -- see the destroyed
     * field's own comment. This is what makes it safe for
     * registry_arm_sweep to be reached (as a no-op) after this function
     * has already run to completion, in the one sequence that can
     * actually produce that ordering: a session breaks ->
     * registry_on_session_broken marks it dead and invokes the owner's
     * on_broken -> the owner calls cloak_server_registry_destroy(reg)
     * (permitted; see cloak_registry_broken_cb's doc comment) -> this
     * function runs to completion and returns -> control resumes inside
     * registry_on_session_broken, which still calls registry_arm_sweep
     * before returning itself. */
    reg->destroyed = 1;

    /* Run any pending sweep ourselves first, then cancel the timer that
     * would otherwise fire it later against a registry that may no
     * longer exist by then -- in that order, matching this function's
     * own contract. */
    if (reg->sweep_timer != CLOAK_TIMER_INVALID) {
        registry_sweep_dead_entries(reg);
        cloak_reactor_cancel_timer(reg->reactor, reg->sweep_timer);
        reg->sweep_timer = CLOAK_TIMER_INVALID;
    }

    /* Destroy and free every entry still in the table, live or dead. Most
     * of the time everything left here is live (any dead entry was just
     * swept above via the pending timer) -- but NOT always: when this
     * function is invoked reentrantly from within registry_on_session_broken
     * (see above), the entry currently mid-teardown is already marked
     * dead but its sweep was never armed (that happens AFTER the owner's
     * callback returns, and we are still inside it), so it is still
     * sitting in this table, dead, when we reach this loop. Destroying it
     * here anyway is correct and safe: registry_free_entry's
     * cloak_session_destroy on that entry's own sesh, called from within
     * that same sesh's own on_broken, is exactly the reentrant pattern
     * cloak_session_broken_cb's own doc comment documents as safe. */
    for (size_t i = 0; i < CLOAK_REGISTRY_KEY_BUCKETS; i++) {
        struct cloak_registry_entry *entry;
        while ((entry = reg->key_buckets[i]) != NULL) {
            registry_entry_unlink(reg, entry);
            registry_free_entry(entry);
        }
    }
}

cloak_session_t *cloak_server_registry_get_or_create(cloak_server_registry_t *reg,
                                                      const uint8_t uid[CLOAK_UID_LEN],
                                                      uint32_t session_id,
                                                      const cloak_session_config_t *config,
                                                      int *out_created) {
    if (reg == NULL || uid == NULL || config == NULL) {
        return NULL;
    }

    struct cloak_registry_entry *existing = registry_find_live(reg, uid, session_id);
    if (existing != NULL) {
        if (out_created != NULL) {
            *out_created = 0;
        }
        return &existing->sesh;
    }

    /* DEAD ENTRIES COUNT AGAINST THE CAP, exactly as they did when they
     * occupied a slot in the old array: one still owns its session, its
     * connections and its memory until the sweep runs. This check is O(1)
     * -- it has to be, it is on the handshake path -- which is why the
     * counters exist at all; see their declaration in cloak/registry.h. */
    if (reg->n_entries >= CLOAK_REGISTRY_MAX_SESSIONS) {
        return NULL; /* table full -- a resource limit, not an argument error; see cloak/registry.h */
    }

    struct cloak_registry_entry *entry = malloc(sizeof(*entry));
    if (entry == NULL) {
        return NULL;
    }
    memset(entry, 0, sizeof(*entry));
    memcpy(entry->uid, uid, CLOAK_UID_LEN);
    entry->session_id = session_id;
    entry->reg = reg;
    entry->dead = 0;

    /* Every field of the caller's config is used as-is EXCEPT
     * on_broken/on_broken_userdata, which this overwrites with the
     * registry's own adapter -- see cloak/registry.h's doc comment on
     * this function for why. */
    cloak_session_config_t cfg = *config;
    cfg.on_broken = registry_on_session_broken;
    cfg.on_broken_userdata = entry;

    if (cloak_session_init(&entry->sesh, session_id, reg->reactor, &cfg) != 0) {
        free(entry);
        return NULL;
    }

    /* Linked only once the session is fully constructed, so nothing can
     * ever find a half-initialized entry -- the same ordering the old
     * slot assignment had. */
    registry_entry_link(reg, entry);
    if (out_created != NULL) {
        *out_created = 1;
    }
    return &entry->sesh;
}

cloak_session_t *cloak_server_registry_find(cloak_server_registry_t *reg,
                                            const uint8_t uid[CLOAK_UID_LEN],
                                            uint32_t session_id) {
    if (reg == NULL || uid == NULL) {
        return NULL;
    }
    struct cloak_registry_entry *entry = registry_find_live(reg, uid, session_id);
    return entry != NULL ? &entry->sesh : NULL;
}

void cloak_server_registry_close(cloak_server_registry_t *reg, const uint8_t uid[CLOAK_UID_LEN],
                                 uint32_t session_id) {
    if (reg == NULL || uid == NULL) {
        return;
    }

    /* registry_find_live skips dead entries, so this is correctly a
     * no-op (rather than a double teardown) when called for a session
     * that is already mid-teardown -- in particular, when called from
     * within that very session's own on_broken, where
     * registry_on_session_broken has already marked it dead before
     * invoking the owner's callback. */
    struct cloak_registry_entry *entry = registry_find_live(reg, uid, session_id);
    if (entry != NULL) {
        registry_entry_unlink(reg, entry);
        registry_free_entry(entry);
    }
}

size_t cloak_server_registry_count_for_uid(const cloak_server_registry_t *reg,
                                           const uint8_t uid[CLOAK_UID_LEN]) {
    if (reg == NULL || uid == NULL) {
        return 0;
    }
    /* One walk of one uid bucket -- see this function's doc comment. Dead
     * entries are excluded for the same reason cloak_server_registry_count
     * excludes them: they are no longer sessions anyone can use.
     *
     * THE CONST CAST is for the two diagnostic counters and nothing else.
     * This function is on the dispatcher's per-handshake path and is
     * therefore half of what test_registry_scale.c case 2 measures, so it
     * has to count its own steps; no cloak_server_registry_t is ever
     * defined const, and no other field is touched. */
    cloak_server_registry_t *counters = (cloak_server_registry_t *)reg;
    counters->lookup_calls++;

    size_t n = 0;
    for (const struct cloak_registry_entry *entry = reg->uid_buckets[registry_uid_bucket(reg, uid)];
         entry != NULL; entry = entry->uid_next) {
        counters->lookup_probe_steps++;
        if (!entry->dead && memcmp(entry->uid, uid, CLOAK_UID_LEN) == 0) {
            n++;
        }
    }
    return n;
}

size_t cloak_server_registry_close_all_for_uid(cloak_server_registry_t *reg,
                                               const uint8_t uid[CLOAK_UID_LEN],
                                               cloak_registry_closing_cb on_closing,
                                               void *userdata) {
    if (reg == NULL || uid == NULL) {
        return 0;
    }

    const size_t bucket = registry_uid_bucket(reg, uid);
    size_t closed = 0;
    for (;;) {
        /* RE-READ FROM THE HEAD every iteration rather than carrying a
         * saved `next` across on_closing: that callback is documented as
         * being allowed to reenter this module and close other sessions,
         * and a saved pointer is exactly what such a call would leave
         * dangling. Not a rescan -- every session of one uid hashes into
         * this one bucket, so the head is a match except for the foreign
         * uids that collided into it.
         *
         * Dead entries are NOT skipped, unlike in every other lookup in
         * this file -- see this function's doc comment: a dead entry's
         * connections are still registered with the reactor until its
         * sweep runs, and the caller is about to free something they
         * still point at. */
        struct cloak_registry_entry *entry = NULL;
        for (struct cloak_registry_entry *e = reg->uid_buckets[bucket]; e != NULL; e = e->uid_next) {
            if (memcmp(e->uid, uid, CLOAK_UID_LEN) == 0) {
                entry = e;
                break;
            }
        }
        if (entry == NULL) {
            break;
        }

        /* Unlink BEFORE anything else, so that an on_closing which
         * reenters this module (the realistic one -- a proxy tearing its
         * own bookkeeping down -- can end up calling
         * cloak_server_registry_close or this very function again) finds
         * nothing here to close or free a second time. The entry is a
         * never-moved heap allocation whose address we still hold, so
         * unlinking it does not lose it; this is the same ordering
         * registry_on_session_broken uses when it marks an entry dead
         * before invoking the owner's callback. */
        registry_entry_unlink(reg, entry);

        if (on_closing != NULL) {
            /* Still fully alive here -- this is the caller's only window
             * to stop relays bound to it, since no on_broken will fire.
             * See the doc comment. */
            on_closing(reg, &entry->sesh, entry->uid, entry->session_id, userdata);
        }

        registry_free_entry(entry);
        closed++;
    }
    return closed;
}

size_t cloak_server_registry_count(const cloak_server_registry_t *reg) {
    if (reg == NULL) {
        return 0;
    }
    /* Live = every entry minus the dead ones awaiting their sweep. See
     * the two counters' declaration in cloak/registry.h for why this is a
     * subtraction rather than the scan it used to be. */
    return reg->n_entries - reg->n_dead;
}
