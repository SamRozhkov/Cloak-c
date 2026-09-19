#ifndef CLOAK_SERVER_HASH_INTERNAL_H
#define CLOAK_SERVER_HASH_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

/* SipHash-2-4, keyed, over an arbitrary-length buffer.
 *
 * WHY THIS EXISTS AS A HEADER. Two lookup tables in this directory hash a
 * key an attacker has a hand in choosing -- cloak_server_registry_t's
 * (uid, session_id) chains, where the session id comes straight off the
 * wire, and cloak_userpanel_t's active-user chains -- and both draw their
 * 128-bit key from cloak_random_bytes per instance. A hash table whose
 * bucket function an attacker can evaluate offline is a table whose worst
 * case an attacker can ask for, which for a chained table is the linear
 * scan the chains were introduced to remove. cloak/replay_cache.h records
 * that exact bug being found in this tree, unkeyed, by measurement.
 *
 * DELIBERATELY NOT SHARED WITH libcloak-server/src/replay_cache.c, which
 * carries its own copy specialised to a fixed 32-byte input. Widening and
 * exporting that one would have meant editing the single function in this
 * tree whose every byte is pinned by an adversarial test
 * (test_replay_cache_keyed.c) inside a commit that is already replacing
 * the session table underneath the whole server. The two are checked
 * against each other rather than merged: this implementation was verified
 * to produce byte-identical output to replay_cache.c's siphash24_32 for
 * 32-byte inputs under the same key before it was committed, and
 * test_registry_scale.c case 6 keeps a fixed test vector for it.
 *
 * static inline, header-only: no new translation unit, no link change. */

static inline uint64_t cloak_sip_load_le64(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline uint64_t cloak_sip_rotl(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}

static inline void cloak_sip_round(uint64_t v[4]) {
    v[0] += v[1];
    v[1] = cloak_sip_rotl(v[1], 13);
    v[1] ^= v[0];
    v[0] = cloak_sip_rotl(v[0], 32);
    v[2] += v[3];
    v[3] = cloak_sip_rotl(v[3], 16);
    v[3] ^= v[2];
    v[0] += v[3];
    v[3] = cloak_sip_rotl(v[3], 21);
    v[3] ^= v[0];
    v[2] += v[1];
    v[1] = cloak_sip_rotl(v[1], 17);
    v[1] ^= v[2];
    v[2] = cloak_sip_rotl(v[2], 32);
}

static inline uint64_t cloak_siphash24(const uint8_t k[16], const uint8_t *in, size_t len) {
    const uint64_t k0 = cloak_sip_load_le64(k);
    const uint64_t k1 = cloak_sip_load_le64(k + 8);
    uint64_t v[4];
    v[0] = 0x736f6d6570736575ULL ^ k0;
    v[1] = 0x646f72616e646f6dULL ^ k1;
    v[2] = 0x6c7967656e657261ULL ^ k0;
    v[3] = 0x7465646279746573ULL ^ k1;

    const size_t blocks = len / 8;
    for (size_t i = 0; i < blocks; i++) {
        const uint64_t m = cloak_sip_load_le64(in + i * 8);
        v[3] ^= m;
        cloak_sip_round(v);
        cloak_sip_round(v);
        v[0] ^= m;
    }

    /* The tail, assembled with a loop rather than the reference's
     * fall-through switch: a switch with seven fall-throughs is the one
     * shape in this primitive that -Wimplicit-fallthrough (on under
     * -Wextra for GCC) treats differently from clang, and the loop is
     * exactly as correct. */
    uint64_t b = (uint64_t)len << 56;
    const uint8_t *tail = in + blocks * 8;
    for (size_t i = 0; i < (len & 7u); i++) {
        b |= (uint64_t)tail[i] << (8 * i);
    }
    v[3] ^= b;
    cloak_sip_round(v);
    cloak_sip_round(v);
    v[0] ^= b;

    v[2] ^= 0xff;
    cloak_sip_round(v);
    cloak_sip_round(v);
    cloak_sip_round(v);
    cloak_sip_round(v);
    return v[0] ^ v[1] ^ v[2] ^ v[3];
}

#endif /* CLOAK_SERVER_HASH_INTERNAL_H */
