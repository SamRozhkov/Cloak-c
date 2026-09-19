#include "cloak/replay_cache.h"

#include "cloak/common.h"

#include <stdlib.h>
#include <string.h>

int cloak_replay_cache_init(cloak_replay_cache_t *cache, size_t capacity) {
    memset(cache, 0, sizeof(*cache));
    if (capacity == 0) {
        return -1;
    }
    cloak_replay_slot_t *slots = (cloak_replay_slot_t *)calloc(capacity, sizeof(cloak_replay_slot_t));
    if (slots == NULL) {
        return -1;
    }
    cache->slots = slots;
    cache->capacity = capacity;
    /* Drawn here, per instance, and never anywhere else. cloak_random_bytes
     * aborts rather than returning a weak key if the CSPRNG is
     * unavailable (libcloak-common/src/random.c), so there is no failure
     * path to handle and, more to the point, no path on which this cache
     * comes up with a predictable key. */
    cloak_random_bytes(cache->hash_key, sizeof(cache->hash_key));
    return 0;
}

void cloak_replay_cache_destroy(cloak_replay_cache_t *cache) {
    free(cache->slots);
    cache->slots = NULL;
    cache->capacity = 0;
    memset(cache->hash_key, 0, sizeof(cache->hash_key));
}

/* ------------------------------------------------------------------ */
/* SipHash-2-4                                                         */
/* ------------------------------------------------------------------ */

/* WHY THIS AND NOT THE FNV-1a THAT WAS HERE. FNV-1a is unkeyed, so the
 * slot a 32-byte value lands in was a pure function of bytes the sender
 * chooses -- an attacker could compute a colliding input offline in about
 * `capacity` trials and evict any entry it liked with one packet.
 * cloak/replay_cache.h describes the attack in full and names the test
 * that reproduces it. The replacement has to be a KEYED pseudorandom
 * function, not merely a better-mixing one: "unpredictable to the
 * attacker" is the property, and no unkeyed hash has it against an
 * attacker who can read this source.
 *
 * SipHash-2-4 is the standard answer to exactly this problem (it was
 * designed for hash-flooding resistance in hash tables) and it is small
 * enough to carry here rather than pull in. Written out in full rather
 * than reduced to "some PRF" because getting it wrong is silent: a
 * miswired round still returns a number, still spreads keys, and still
 * passes every functional test in test_replay_cache.c.
 *
 * COST. This runs once per handshake, on the pre-authentication path,
 * which is the path that has to stay cheap under a flood -- so the
 * comparison that matters is against what the handshake does next. Six
 * SipHash rounds over 32 bytes is a few hundred arithmetic operations;
 * cloak_server_auth_decrypt's X25519 is a scalar multiplication. This is
 * not the term that decides whether a flood hurts. NOT MEASURED HERE --
 * that is an argument from orders of magnitude, not a benchmark, and
 * nothing in the suite times it.
 *
 * The input is always exactly 32 bytes (four whole 64-bit words, no
 * partial tail), which is why the compression loop below has no
 * remainder handling: cloak_replay_cache_check_and_insert is the only
 * caller and the key parameter is `const uint8_t key[32]`. */

#define SIP_ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIP_ROUND()                    \
    do {                               \
        v0 += v1;                      \
        v1 = SIP_ROTL(v1, 13);         \
        v1 ^= v0;                      \
        v0 = SIP_ROTL(v0, 32);         \
        v2 += v3;                      \
        v3 = SIP_ROTL(v3, 16);         \
        v3 ^= v2;                      \
        v0 += v3;                      \
        v3 = SIP_ROTL(v3, 21);         \
        v3 ^= v0;                      \
        v2 += v1;                      \
        v1 = SIP_ROTL(v1, 17);         \
        v1 ^= v2;                      \
        v2 = SIP_ROTL(v2, 32);         \
    } while (0)

/* Explicit little-endian load, not a cast to uint64_t*: the latter is
 * both an alignment violation and endian-dependent, and this project is
 * required to be warning- and UB-free under two compilers. */
static uint64_t sip_load_le64(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static uint64_t siphash24_32(const uint8_t k[16], const uint8_t in[32]) {
    uint64_t k0 = sip_load_le64(k);
    uint64_t k1 = sip_load_le64(k + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    for (int i = 0; i < 4; i++) {
        uint64_t m = sip_load_le64(in + (size_t)i * 8);
        v3 ^= m;
        SIP_ROUND();
        SIP_ROUND();
        v0 ^= m;
    }

    /* The final block for a 32-byte message: no leftover bytes, and the
     * length modulo 256 in the top byte. */
    uint64_t b = (uint64_t)32 << 56;
    v3 ^= b;
    SIP_ROUND();
    SIP_ROUND();
    v0 ^= b;

    v2 ^= 0xff;
    SIP_ROUND();
    SIP_ROUND();
    SIP_ROUND();
    SIP_ROUND();

    return v0 ^ v1 ^ v2 ^ v3;
}

int cloak_replay_cache_check_and_insert(cloak_replay_cache_t *cache, const uint8_t key[32],
                                         int64_t now_unix, int64_t age_limit_seconds) {
    if (cache->capacity == 0) {
        return 0; /* uninitialized or destroyed cache: nothing to check against, fail open on
                    the "is this a duplicate" question rather than crash. Calling this function
                    with such a cache is a caller bug -- see cloak_replay_cache_init's contract --
                    but a SIGFPE is a worse failure mode than silently treating everything as
                    novel, especially since insert-side state is unusable anyway if capacity is
                    0 (there's nowhere to store the entry). */
    }

    size_t slot_idx = (size_t)(siphash24_32(cache->hash_key, key) % cache->capacity);
    cloak_replay_slot_t *slot = &cache->slots[slot_idx];

    if (slot->inserted_at != 0 && memcmp(slot->key, key, 32) == 0) {
        /* Unlike server_auth.c's timestamp check, both operands here come
         * from this process's own clock (never directly from
         * attacker-controlled wire bytes), so this subtraction cannot be
         * driven to the extremes that made a bound-comparison rewrite
         * necessary there. */
        int64_t age = now_unix - slot->inserted_at;
        if (age >= 0 && age < age_limit_seconds) {
            return 1; /* replay -- do not refresh */
        }
    }

    /* THE INSERT ALWAYS SUCCEEDS. It overwrites whatever shared the slot,
     * and it never reports "full" -- cloak/replay_cache.h's "WHEN IT IS
     * FULL" paragraph is why: a server that starts refusing handshakes
     * under load is a distinguisher an unauthenticated prober can trip
     * on purpose, and this function is on the pre-authentication path. */
    memcpy(slot->key, key, 32);
    slot->inserted_at = now_unix;
    /* Zero is reserved as "empty"; a real Unix timestamp of exactly 0
     * (1970-01-01T00:00:00Z) is not a value this project's clock will ever
     * legitimately produce, so this ambiguity is intentionally accepted:
     * an insert at now_unix == 0 will be indistinguishable from an empty
     * slot on the next lookup and can be immediately replayed. */
    return 0;
}
