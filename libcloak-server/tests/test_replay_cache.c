#include "cloak/replay_cache.h"
#include "test_framework.h"

#include <string.h>

static void fill_key(uint8_t key[32], uint32_t seed) {
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(seed >> (8 * (i % 4))) ^ (uint8_t)i;
    }
}

static void test_insert_then_replay_then_ages_out(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 1024), 0);
    uint8_t k1[32];
    fill_key(k1, 1);

    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k1, 1000, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k1, 1001, 180), 1);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k1, 1179, 180), 1);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k1, 1180, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k1, 1181, 180), 1);

    cloak_replay_cache_destroy(&cache);
}

static void test_distinct_keys_dont_interfere(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 1024), 0);
    uint8_t k2[32], k3[32];
    fill_key(k2, 2);
    fill_key(k3, 3);

    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k2, 5000, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k3, 5000, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k2, 5001, 180), 1);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k3, 5001, 180), 1);

    cloak_replay_cache_destroy(&cache);
}

static void test_direct_mapped_collision_evicts(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 1), 0); /* capacity 1 forces every key into the same slot */
    uint8_t k2[32], k3[32];
    fill_key(k2, 2);
    fill_key(k3, 3);

    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k2, 100, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k3, 101, 180), 0); /* k3 evicts k2 */
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k2, 102, 180), 0); /* k2 no longer tracked -- not a replay */
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k3, 103, 180), 0); /* k3 was itself evicted just above */
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k3, 104, 180), 1); /* k3 is now in the slot, unevicted since */

    cloak_replay_cache_destroy(&cache);
}

static void test_backwards_clock_not_a_replay(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 1024), 0);
    uint8_t k4[32];
    fill_key(k4, 4);

    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k4, 10000, 180), 0);
    ASSERT_EQ_INT(cloak_replay_cache_check_and_insert(&cache, k4, 9999, 180), 0); /* clock moved backwards: treated as expired */

    cloak_replay_cache_destroy(&cache);
}

static void test_stress_low_collision_rate(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 65536), 0);

    int replay_hits = 0;
    const int n = 50000;
    for (int i = 0; i < n; i++) {
        uint8_t key[32];
        fill_key(key, (uint32_t)(i * 2654435761u)); /* Knuth multiplicative hash: decent spread */
        int rc1 = cloak_replay_cache_check_and_insert(&cache, key, 1000000 + i, 180);
        int rc2 = cloak_replay_cache_check_and_insert(&cache, key, 1000000 + i, 180);
        ASSERT_EQ_INT(rc1, 0);
        if (rc2 == 1) {
            replay_hits++;
        }
    }
    ASSERT_TRUE(replay_hits > n * 9 / 10);

    cloak_replay_cache_destroy(&cache);
}

static void test_init_rejects_zero_capacity(void) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(cloak_replay_cache_init(&cache, 0), -1);
}

TEST_MAIN_BEGIN()
    test_insert_then_replay_then_ages_out();
    test_distinct_keys_dont_interfere();
    test_direct_mapped_collision_evicts();
    test_backwards_clock_not_a_replay();
    test_stress_low_collision_rate();
    test_init_rejects_zero_capacity();
TEST_MAIN_END()
