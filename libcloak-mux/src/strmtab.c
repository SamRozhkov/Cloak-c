#include "cloak/strmtab.h"

#include <stdlib.h>
#include <string.h>

static uint32_t hash_u32(uint32_t x) {
    /* murmur3 finalizer -- fast, good enough avalanche for a probe-order
     * hash; no adversarial-input concerns here since stream_id space is
     * either locally monotonic (OpenStream) or bounded by the remote
     * peer's own monotonic counter, not attacker-chosen against this
     * specific hash. */
    x ^= x >> 16;
    x *= 0x85ebca6bu;
    x ^= x >> 13;
    x *= 0xc2b2ae35u;
    x ^= x >> 16;
    return x;
}

static size_t next_pow2(size_t n) {
    size_t p = 8;
    while (p < n) p *= 2;
    return p;
}

int cloak_strmtab_init(cloak_strmtab_t *t, size_t initial_cap_hint) {
    memset(t, 0, sizeof(*t));
    if (initial_cap_hint == 0) {
        return -1;
    }
    size_t cap = next_pow2(initial_cap_hint);
    t->slots = (cloak_strmtab_slot_t *)calloc(cap, sizeof(cloak_strmtab_slot_t));
    if (t->slots == NULL) {
        return -1;
    }
    t->cap = cap;
    t->count = 0;
    return 0;
}

void cloak_strmtab_destroy(cloak_strmtab_t *t) {
    free(t->slots);
    memset(t, 0, sizeof(*t));
}

int cloak_strmtab_lookup(const cloak_strmtab_t *t, uint32_t key,
                          cloak_strmtab_state_t *out_state, void **out_value) {
    size_t mask = t->cap - 1;
    size_t i = hash_u32(key) & mask;
    for (size_t probes = 0; probes < t->cap; probes++) {
        const cloak_strmtab_slot_t *s = &t->slots[i];
        if (s->state == CLOAK_STRMTAB_ABSENT) {
            return 0;
        }
        if (s->key == key) {
            if (out_state) *out_state = s->state;
            if (out_value) *out_value = s->value;
            return 1;
        }
        i = (i + 1) & mask;
    }
    return 0;
}

static int strmtab_grow(cloak_strmtab_t *t) {
    size_t old_cap = t->cap;
    cloak_strmtab_slot_t *old_slots = t->slots;
    size_t new_cap = old_cap * 2;
    cloak_strmtab_slot_t *new_slots = (cloak_strmtab_slot_t *)calloc(new_cap, sizeof(cloak_strmtab_slot_t));
    if (new_slots == NULL) {
        return -1;
    }
    t->slots = new_slots;
    t->cap = new_cap;
    t->count = 0;
    size_t mask = new_cap - 1;
    for (size_t i = 0; i < old_cap; i++) {
        if (old_slots[i].state == CLOAK_STRMTAB_ABSENT) {
            continue;
        }
        /* Both ACTIVE and TOMBSTONE entries must survive a grow: a
         * tombstone's entire purpose is to be remembered for the whole
         * session's lifetime (matching Go's sesh.streams[id] = nil,
         * which is never deleted, only ever overwritten by session
         * close) so a late frame for a since-closed stream is recognized
         * as "known dead, drop silently" rather than mistaken for a
         * brand new stream. Dropping tombstones on grow would reopen
         * exactly the bug tombstoning exists to prevent, just gated on
         * when a resize happens to occur. */
        size_t j = hash_u32(old_slots[i].key) & mask;
        while (t->slots[j].state != CLOAK_STRMTAB_ABSENT) {
            j = (j + 1) & mask;
        }
        t->slots[j] = old_slots[i];
        t->count++;
    }
    free(old_slots);
    return 0;
}

/* Deliberately does NOT reuse a *different* key's tombstone slot: a
 * tombstone must remain permanently findable (see strmtab_grow's comment
 * above) for the life of the table, so a new, unrelated key is only ever
 * placed in a genuinely ABSENT slot. The one safe exception is
 * reinserting the SAME key that was tombstoned in this exact slot -- no
 * information is lost, since it's the same key. An earlier version of
 * this function reused the first tombstone seen along the probe chain
 * for ANY new key, which silently destroyed the overwritten key's
 * tombstone -- a late frame for that now-clobbered id would then be
 * misread as ABSENT (a brand new stream) instead of TOMBSTONE (drop
 * silently), exactly the bug tombstoning exists to prevent. Caught by
 * this module's own 5000-key growth test during design verification (a
 * lookup for a previously-tombstoned id started returning "not found"
 * once enough further insertions had cycled through its slot). */
int cloak_strmtab_insert_active(cloak_strmtab_t *t, uint32_t key, void *value) {
    if (t->count * 10 >= t->cap * 7) { /* load factor 0.7 */
        if (strmtab_grow(t) != 0) {
            return -1;
        }
    }
    size_t mask = t->cap - 1;
    size_t i = hash_u32(key) & mask;
    for (size_t probes = 0; probes < t->cap; probes++) {
        cloak_strmtab_slot_t *s = &t->slots[i];
        if (s->state == CLOAK_STRMTAB_ABSENT) {
            s->key = key;
            s->state = CLOAK_STRMTAB_ACTIVE;
            s->value = value;
            t->count++;
            return 0;
        }
        if (s->key == key) {
            if (s->state == CLOAK_STRMTAB_ACTIVE) {
                return -1;
            }
            /* s->state == CLOAK_STRMTAB_TOMBSTONE for this exact key. */
            s->state = CLOAK_STRMTAB_ACTIVE;
            s->value = value;
            return 0; /* slot was already counted as occupied */
        }
        i = (i + 1) & mask;
    }
    return -1; /* table full -- shouldn't happen given load-factor growth */
}

int cloak_strmtab_tombstone(cloak_strmtab_t *t, uint32_t key) {
    size_t mask = t->cap - 1;
    size_t i = hash_u32(key) & mask;
    for (size_t probes = 0; probes < t->cap; probes++) {
        cloak_strmtab_slot_t *s = &t->slots[i];
        if (s->state == CLOAK_STRMTAB_ABSENT) {
            return -1;
        }
        if (s->state == CLOAK_STRMTAB_ACTIVE && s->key == key) {
            s->state = CLOAK_STRMTAB_TOMBSTONE;
            s->value = NULL;
            return 0;
        }
        i = (i + 1) & mask;
    }
    return -1;
}

void cloak_strmtab_for_each_active(const cloak_strmtab_t *t, cloak_strmtab_iter_cb cb, void *userdata) {
    for (size_t i = 0; i < t->cap; i++) {
        if (t->slots[i].state == CLOAK_STRMTAB_ACTIVE) {
            cb(t->slots[i].key, t->slots[i].value, userdata);
        }
    }
}
