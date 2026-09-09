#ifndef CLOAK_REPLAY_CACHE_H
#define CLOAK_REPLAY_CACHE_H

#include <stddef.h>
#include <stdint.h>

/* A fixed-capacity, direct-mapped cache of recently-seen 32-byte values
 * (client ClientHello.random / auth ephemeral public keys), used to reject
 * replayed authentication attempts. Single-threaded (matches this project's
 * single-threaded epoll reactor design -- no locking).
 *
 * This is a DELIBERATE bounded-memory tradeoff, not a full replay-proof
 * set: it is direct-mapped (one slot per hash bucket, no chaining), so two
 * different keys that hash to the same slot within the same age window
 * will evict one another -- the older entry silently stops being tracked.
 * With 32 bytes of real entropy per key and a reasonably sized table, an
 * accidental collision between two legitimate clients is astronomically
 * unlikely; an attacker deliberately flooding collisions can at most cause
 * some replay-window entries to be forgotten early, which only weakens
 * (never strengthens) an attacker's ability to replay a key they don't
 * already possess a valid, not-yet-expired ciphertext for -- and the
 * timestamp window (CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS) bounds
 * how long a captured ciphertext remains replayable regardless of this
 * cache. This mirrors the "bounded hash set" design the project's spec
 * calls for. */
typedef struct {
    uint8_t key[32];
    int64_t inserted_at; /* 0 = empty slot (never used) */
} cloak_replay_slot_t;

typedef struct {
    cloak_replay_slot_t *slots;
    size_t capacity;
} cloak_replay_cache_t;

/* Allocates a zeroed table of `capacity` slots (capacity must be > 0).
 * Returns 0 on success, -1 on allocation failure. */
int cloak_replay_cache_init(cloak_replay_cache_t *cache, size_t capacity);

/* Frees the table. Safe to call after cloak_replay_cache_init returned 0
 * (normal use) OR -1 (a failed init leaves the cache in a safe, zeroed
 * state). NOT safe to call on a cloak_replay_cache_t that
 * cloak_replay_cache_init was never called on at all -- zero-initialize it
 * yourself first (e.g. cloak_replay_cache_t cache = {0};) if you need
 * that. */
void cloak_replay_cache_destroy(cloak_replay_cache_t *cache);

/* Looks up key's slot (hash(key) % capacity). If that slot currently holds
 * `key` itself AND its age (now_unix - inserted_at) is within
 * [0, age_limit_seconds), this is a replay: returns 1, WITHOUT updating the
 * slot (a replay does not refresh its own timestamp -- an attacker
 * resending the exact same ciphertext repeatedly should not be able to
 * keep extending its own window).
 *
 * Otherwise (slot empty, held a different key, or held the same key but
 * aged out) this is not a replay: stores key at its slot with
 * inserted_at = now_unix (overwriting whatever was there), and returns 0.
 *
 * now_unix going backwards between calls (a clock adjustment) is handled
 * safely: age is computed as now_unix - inserted_at and treated as
 * expired (not a replay) whenever it falls outside [0, age_limit_seconds),
 * which includes negative values from a clock that moved backwards.
 *
 * For use alongside cloak_server_auth_decrypt's timestamp check,
 * age_limit_seconds must exceed twice that check's tolerance window, or a
 * replayed ciphertext can succeed after the cache entry ages out but
 * before the timestamp window closes -- see
 * CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS in
 * cloak/server_auth.h. */
int cloak_replay_cache_check_and_insert(cloak_replay_cache_t *cache, const uint8_t key[32],
                                         int64_t now_unix, int64_t age_limit_seconds);

#endif
