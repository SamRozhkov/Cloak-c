#ifndef CLOAK_STRMTAB_H
#define CLOAK_STRMTAB_H

#include <stddef.h>
#include <stdint.h>

/* A uint32_t stream_id -> void* table with three states per key (not the
 * usual two): CLOAK_STRMTAB_ABSENT (never seen), CLOAK_STRMTAB_ACTIVE (a
 * live pointer), or CLOAK_STRMTAB_TOMBSTONE (was active, has since been
 * closed -- remembered forever, not deleted). This mirrors Go Cloak's
 * Session.streams map, where a closed stream's entry is set to nil rather
 * than deleted, specifically so a late-arriving frame for a since-closed
 * stream is recognized as "known dead, drop silently" instead of being
 * mistaken for a brand new stream. Open addressing, linear probing,
 * power-of-two capacity, grows (rehashes) at a 0.7 load factor. Not
 * thread-safe (matches this whole project's single-threaded-reactor
 * design -- see the master spec). */
typedef enum {
    CLOAK_STRMTAB_ABSENT = 0,
    CLOAK_STRMTAB_ACTIVE = 1,
    CLOAK_STRMTAB_TOMBSTONE = 2
} cloak_strmtab_state_t;

typedef struct {
    uint32_t key;
    cloak_strmtab_state_t state;
    void *value; /* only meaningful when state == CLOAK_STRMTAB_ACTIVE */
} cloak_strmtab_slot_t;

typedef struct {
    cloak_strmtab_slot_t *slots;
    size_t cap;   /* always a power of two */
    size_t count; /* ACTIVE + TOMBSTONE entries -- both occupy a probe slot permanently */
} cloak_strmtab_t;

/* Allocates a backing array sized to the next power of two >=
 * initial_cap_hint (minimum 8). Returns 0 on success, -1 on allocation
 * failure or initial_cap_hint == 0. */
int cloak_strmtab_init(cloak_strmtab_t *t, size_t initial_cap_hint);

void cloak_strmtab_destroy(cloak_strmtab_t *t);

/* Returns 1 and sets out_state/out_value if key has an entry (ACTIVE or
 * TOMBSTONE); returns 0 (out_state/out_value untouched) if key was never
 * seen (ABSENT). Either output pointer may be NULL if not needed. */
int cloak_strmtab_lookup(const cloak_strmtab_t *t, uint32_t key,
                          cloak_strmtab_state_t *out_state, void **out_value);

/* Inserts key as ACTIVE with value. Fails (-1) if key is already ACTIVE,
 * or on allocation failure during a triggered grow. Succeeds (0) for a
 * brand new key, or for a key that's currently TOMBSTONE (reactivating it
 * in place -- safe, since it's the same key, no information is lost).
 *
 * Deliberately never reuses a DIFFERENT key's tombstone slot for a new
 * key -- see this file's own strmtab.c comment on cloak_strmtab_insert_active
 * for why that specific optimization is unsafe here. */
int cloak_strmtab_insert_active(cloak_strmtab_t *t, uint32_t key, void *value);

/* Marks key's entry as TOMBSTONE (must currently be ACTIVE). Returns 0 on
 * success, -1 if key is not currently ACTIVE (absent or already a
 * tombstone). Never grows/reallocates -- safe to call from within a
 * cloak_strmtab_for_each_active callback. */
int cloak_strmtab_tombstone(cloak_strmtab_t *t, uint32_t key);

typedef void (*cloak_strmtab_iter_cb)(uint32_t key, void *value, void *userdata);

/* Calls cb once for every currently-ACTIVE entry (TOMBSTONE and ABSENT
 * slots are skipped). It is safe for cb to call cloak_strmtab_tombstone
 * on the key it was just given (tombstoning never grows/reallocates the
 * table), but not to call cloak_strmtab_insert_active (which can grow the
 * table mid-iteration). */
void cloak_strmtab_for_each_active(const cloak_strmtab_t *t, cloak_strmtab_iter_cb cb, void *userdata);

#endif
