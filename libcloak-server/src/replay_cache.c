#include "cloak/replay_cache.h"

#include <stdlib.h>
#include <string.h>

int cloak_replay_cache_init(cloak_replay_cache_t *cache, size_t capacity) {
    cache->slots = NULL;
    cache->capacity = 0;
    if (capacity == 0) {
        return -1;
    }
    cloak_replay_slot_t *slots = (cloak_replay_slot_t *)calloc(capacity, sizeof(cloak_replay_slot_t));
    if (slots == NULL) {
        return -1;
    }
    cache->slots = slots;
    cache->capacity = capacity;
    return 0;
}

void cloak_replay_cache_destroy(cloak_replay_cache_t *cache) {
    free(cache->slots);
    cache->slots = NULL;
    cache->capacity = 0;
}

/* FNV-1a, 64-bit. Not a cryptographic hash -- doesn't need to be: keys are
 * always 32 bytes of real entropy, and this is a fixed-capacity direct-map
 * bucket selector, not a security boundary in itself (see the header's
 * doc comment on the collision tradeoff). */
static uint64_t fnv1a(const uint8_t *data, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

int cloak_replay_cache_check_and_insert(cloak_replay_cache_t *cache, const uint8_t key[32],
                                         int64_t now_unix, int64_t age_limit_seconds) {
    size_t slot_idx = (size_t)(fnv1a(key, 32) % cache->capacity);
    cloak_replay_slot_t *slot = &cache->slots[slot_idx];

    if (slot->inserted_at != 0 && memcmp(slot->key, key, 32) == 0) {
        int64_t age = now_unix - slot->inserted_at;
        if (age >= 0 && age < age_limit_seconds) {
            return 1; /* replay -- do not refresh */
        }
    }

    memcpy(slot->key, key, 32);
    slot->inserted_at = now_unix;
    /* Zero is reserved as "empty"; a real Unix timestamp of exactly 0
     * (1970-01-01T00:00:00Z) is not a value this project's clock will ever
     * legitimately produce, so this ambiguity is intentionally accepted:
     * an insert at now_unix == 0 will be indistinguishable from an empty
     * slot on the next lookup and can be immediately replayed. */
    return 0;
}
