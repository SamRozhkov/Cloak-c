#include "cloak/registry.h"

#include <stdlib.h>
#include <string.h>

/* One heap-allocated, never-moved entry per (uid, session_id). Its
 * address is handed to cloak_session_init as the userdata behind
 * registry_on_session_broken for as long as the session lives -- see
 * cloak/registry.h's own top-of-file comment for why this table is an
 * array of pointers to these rather than an array of the entries
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
     * longer counted by cloak_server_registry_count; it still occupies
     * its table slot and its cloak_session_t is still live (not yet
     * destroyed) until the deferred sweep reaches it. */
    int dead;
};

/* Destroys and frees one entry unconditionally -- used by the sweep, by
 * cloak_server_registry_close, and by cloak_server_registry_destroy. The
 * caller is responsible for having already cleared the entry's slot in
 * reg->entries first. */
static void registry_free_entry(struct cloak_registry_entry *entry) {
    cloak_session_destroy(&entry->sesh);
    free(entry);
}

/* Finds the live (not dead) entry for (uid, session_id), or NULL. Shared
 * by get_or_create (existence check), find, and close. */
static struct cloak_registry_entry *registry_find_live(cloak_server_registry_t *reg,
                                                        const uint8_t uid[CLOAK_UID_LEN],
                                                        uint32_t session_id) {
    for (size_t i = 0; i < CLOAK_REGISTRY_MAX_SESSIONS; i++) {
        struct cloak_registry_entry *entry = reg->entries[i];
        if (entry != NULL && !entry->dead && entry->session_id == session_id &&
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
    for (size_t i = 0; i < CLOAK_REGISTRY_MAX_SESSIONS; i++) {
        struct cloak_registry_entry *entry = reg->entries[i];
        if (entry != NULL && entry->dead) {
            reg->entries[i] = NULL;
            registry_free_entry(entry);
        }
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
    entry->dead = 1;

    cloak_server_registry_t *reg = entry->reg;
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
    return 0;
}

void cloak_server_registry_destroy(cloak_server_registry_t *reg) {
    if (reg == NULL) {
        return;
    }

    /* Run any pending sweep ourselves first, then cancel the timer that
     * would otherwise fire it later against a registry that may no
     * longer exist by then -- in that order, matching this function's
     * own contract. */
    if (reg->sweep_timer != CLOAK_TIMER_INVALID) {
        registry_sweep_dead_entries(reg);
        cloak_reactor_cancel_timer(reg->reactor, reg->sweep_timer);
        reg->sweep_timer = CLOAK_TIMER_INVALID;
    }

    /* Everything left is a live session (any dead one was just swept
     * above) -- destroy and free every one of them. */
    for (size_t i = 0; i < CLOAK_REGISTRY_MAX_SESSIONS; i++) {
        struct cloak_registry_entry *entry = reg->entries[i];
        if (entry != NULL) {
            reg->entries[i] = NULL;
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

    size_t slot = CLOAK_REGISTRY_MAX_SESSIONS;
    for (size_t i = 0; i < CLOAK_REGISTRY_MAX_SESSIONS; i++) {
        if (reg->entries[i] == NULL) {
            slot = i;
            break;
        }
    }
    if (slot == CLOAK_REGISTRY_MAX_SESSIONS) {
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

    reg->entries[slot] = entry;
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
    for (size_t i = 0; i < CLOAK_REGISTRY_MAX_SESSIONS; i++) {
        struct cloak_registry_entry *entry = reg->entries[i];
        if (entry != NULL && !entry->dead && entry->session_id == session_id &&
            memcmp(entry->uid, uid, CLOAK_UID_LEN) == 0) {
            reg->entries[i] = NULL;
            registry_free_entry(entry);
            return;
        }
    }
}

size_t cloak_server_registry_count(const cloak_server_registry_t *reg) {
    if (reg == NULL) {
        return 0;
    }
    size_t n = 0;
    for (size_t i = 0; i < CLOAK_REGISTRY_MAX_SESSIONS; i++) {
        const struct cloak_registry_entry *entry = reg->entries[i];
        if (entry != NULL && !entry->dead) {
            n++;
        }
    }
    return n;
}
