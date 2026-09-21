#ifndef CLOAK_REPLAY_CACHE_H
#define CLOAK_REPLAY_CACHE_H

#include <stddef.h>
#include <stdint.h>

/* A fixed-capacity, direct-mapped cache of recently-seen 32-byte values
 * (client ClientHello.random / auth ephemeral public keys), used to reject
 * replayed authentication attempts. Single-threaded (matches this project's
 * single-threaded epoll reactor design -- no locking).
 *
 * WHAT AN EARLIER REVISION OF THIS COMMENT GOT WRONG, because the
 * argument is the part that has to be right. It said that an attacker
 * flooding collisions "only weakens (never strengthens) an attacker's
 * ability to replay a key they don't already possess a valid,
 * not-yet-expired ciphertext for". THAT CARVE-OUT IS THE ATTACK. An
 * active prober DOES possess a valid, not-yet-expired ciphertext: it
 * watched a real client connect and captured the ClientHello. Replaying
 * that capture and seeing whether the host answers like a proxy or like a
 * web server is how a censor confirms what it is looking at, and it is
 * the single adversary this whole port exists to defeat. Combined with an
 * UNKEYED hash over a fully attacker-chosen 32 bytes and a 1024-slot
 * table, that sentence was excusing a defect: about 1024 offline
 * evaluations of FNV-1a found a second 32-byte string landing in the
 * captured handshake's slot, and ONE packet from an unauthenticated
 * prober then evicted it. See libcloak-server/tests/test_replay_cache_keyed.c,
 * whose case 1 fails against that code.
 *
 * THE THREE THINGS THAT MAKE THE TRADEOFF HONEST NOW, none of which
 * works without the other two:
 *
 * 1. THE SLOT FUNCTION IS KEYED. It is SipHash-2-4 under a 128-bit key
 *    drawn from cloak_random_bytes at cloak_replay_cache_init -- PER
 *    CACHE INSTANCE, not per process and certainly not per build. An
 *    attacker who cannot read that key cannot compute a colliding input
 *    at all, offline or otherwise, so eviction stops being something
 *    that can be AIMED. (Per instance rather than per process because it
 *    costs nothing extra and because it is the only form of the property
 *    a single-process test can observe: two caches in one process must
 *    disagree about where the same key goes. test_replay_cache_keyed.c
 *    case 4 asserts exactly that, and is the case that would catch a
 *    "keyed" hash whose key was a compile-time constant -- a fix shape
 *    this project has shipped twice before under other names.)
 *
 * 2. THE TABLE IS SIZED FOR A REAL HANDSHAKE RATE rather than for the
 *    server's concurrency. cloak/server_stack.h's
 *    CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY carries the
 *    arithmetic and the rate it assumes.
 *
 * 3. A FULL TABLE EVICTS AND NEVER REFUSES. See "WHEN IT IS FULL" below.
 *
 * WHAT REMAINS, stated plainly rather than carved out. This is still a
 * direct-mapped table: one slot per bucket, no chaining, so two keys
 * that land in the same slot inside the same age window still evict one
 * another and the older entry silently stops being tracked. What changed
 * is who can arrange that. Blind flooding is all an attacker has left,
 * and to reach even a 50 % chance of evicting one chosen entry it must
 * land ln(2) * capacity inserts inside the window in which the captured
 * ciphertext is still replayable at all (2 *
 * CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS, because a client clock
 * may run up to the tolerance ahead of the server's). At the shipped
 * capacity that is ~363,000 handshakes in 360 s, about 1,009 per second,
 * sustained -- against ONE packet before. THAT IS A COST RATIO, NOT
 * IMPOSSIBILITY: a state-level adversary can push 1,009 handshakes a
 * second. What it cannot do any more is evict silently and surgically;
 * it has to mount a flood that is a denial of service in its own right
 * and looks like one. test_replay_cache_keyed.c case 2 measures the
 * underlying probability law rather than asserting it.
 *
 * WHEN IT IS FULL: IT EVICTS, AND IT NEVER REFUSES, AND THAT IS THE
 * DELIBERATE CHOICE. Direct-mapped means the table is never "full" in a
 * way an insert can notice -- every key has exactly one home and the
 * insert always succeeds by overwriting. Keeping it that way is a
 * security decision, not an accident of the data structure. A server
 * that began REFUSING handshakes once its replay table filled would hand
 * an active prober a free, reliable distinguisher: send capacity+1
 * handshakes, watch the behaviour change, and you have identified a
 * Cloak server without ever authenticating -- and you can, because this
 * cache is written BEFORE authentication (deliberately; see below). A
 * web server does not do that. Refusal would also convert a bounded,
 * probabilistic gap in replay detection into a deterministic outage for
 * legitimate clients, triggered by the same flood. Eviction's failure
 * mode is strictly smaller: a replayed ciphertext whose entry was
 * evicted still has to pass cloak_server_auth_decrypt's timestamp check,
 * so the exposure from any one eviction is bounded by that window
 * regardless of this cache.
 *
 * A DELIBERATE DIVERGENCE FROM GO, and the right one. Go's server keeps
 * its replay window in an exact, UNBOUNDED map: State.UsedRandom
 * (internal/server/state.go:47, allocated at :139), written by
 * State.registerRandom (internal/server/state.go:228-231) and swept only by
 * State.UsedRandomCleaner (internal/server/state.go:214-225), whose loop body begins
 * `time.Sleep(replayCacheAgeLimit)` -- twelve hours between passes. So a
 * Go server's replay set grows without limit for up to twelve hours at a
 * time, driven by packets that never authenticate, which is a memory
 * lever this port does not want. Go therefore has NO eviction hole and
 * needs no keyed hash; this port has the bounded structure and needs
 * both. BOUNDING THE SET WAS THE RIGHT CALL AND IS KEPT -- what must not
 * be inherited along with it is the failure mode bounding introduces,
 * which is what the keying and the sizing above are for. */
typedef struct {
    uint8_t key[32];
    int64_t inserted_at; /* 0 = empty slot (never used) */
} cloak_replay_slot_t;

typedef struct {
    cloak_replay_slot_t *slots;
    size_t capacity;
    /* SipHash-2-4's 128-bit key, drawn per instance at
     * cloak_replay_cache_init. NOT a configuration knob and not to be
     * set by callers: reading it out and reusing it would reintroduce
     * exactly the predictability it exists to remove. Zero on a cache
     * whose init failed or that has been destroyed. */
    uint8_t hash_key[16];
} cloak_replay_cache_t;

/* Allocates a zeroed table of `capacity` slots (capacity must be > 0) and
 * draws this instance's hash key from cloak_random_bytes. Returns 0 on
 * success, -1 on allocation failure. */
int cloak_replay_cache_init(cloak_replay_cache_t *cache, size_t capacity);

/* Frees the table. Safe to call after cloak_replay_cache_init returned 0
 * (normal use) OR -1 (a failed init leaves the cache in a safe, zeroed
 * state). NOT safe to call on a cloak_replay_cache_t that
 * cloak_replay_cache_init was never called on at all -- zero-initialize it
 * yourself first (e.g. cloak_replay_cache_t cache = {0};) if you need
 * that. */
void cloak_replay_cache_destroy(cloak_replay_cache_t *cache);

/* Looks up key's slot (siphash24(hash_key, key) % capacity). If that slot
 * currently holds `key` itself AND its age (now_unix - inserted_at) is
 * within [0, age_limit_seconds), this is a replay: returns 1, WITHOUT
 * updating the slot (a replay does not refresh its own timestamp -- an
 * attacker resending the exact same ciphertext repeatedly should not be
 * able to keep extending its own window).
 *
 * Otherwise (slot empty, held a different key, or held the same key but
 * aged out) this is not a replay: stores key at its slot with
 * inserted_at = now_unix (overwriting whatever was there), and returns 0.
 * It never refuses -- see "WHEN IT IS FULL" above for why that is a
 * security property and not just the data structure's shape.
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
 * cloak/server_auth.h.
 *
 * CALLED BEFORE AUTHENTICATION, ON PURPOSE. libcloak-server/src/dispatcher.c
 * runs this against the raw, not-yet-decrypted ClientHello random, before
 * any asymmetric work, and Go does the same (internal/server/auth.go:76,
 * before decryptClientInfo at :81). That ordering is what makes the check
 * cheap enough to survive a flood, and it is why the key above has to be
 * secret: everything this function sees on that path is attacker-chosen. */
int cloak_replay_cache_check_and_insert(cloak_replay_cache_t *cache, const uint8_t key[32],
                                         int64_t now_unix, int64_t age_limit_seconds);

#endif
