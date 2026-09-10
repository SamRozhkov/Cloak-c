#include "cloak/strmtab.h"

#include <stdlib.h>
#include <string.h>

#include "test_framework.h"

static void test_absent_key_reports_absent(void) {
    cloak_strmtab_t t;
    ASSERT_EQ_INT(cloak_strmtab_init(&t, 4), 0);

    cloak_strmtab_state_t state;
    void *value;
    ASSERT_EQ_INT(cloak_strmtab_lookup(&t, 42, &state, &value), 0);

    cloak_strmtab_destroy(&t);
}

static void test_insert_lookup_tombstone_reinsert(void) {
    cloak_strmtab_t t;
    ASSERT_EQ_INT(cloak_strmtab_init(&t, 4), 0);

    int dummy1 = 111;
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 42, &dummy1), 0);

    cloak_strmtab_state_t state;
    void *value;
    ASSERT_EQ_INT(cloak_strmtab_lookup(&t, 42, &state, &value), 1);
    ASSERT_EQ_INT(state, CLOAK_STRMTAB_ACTIVE);
    ASSERT_TRUE(value == &dummy1);

    /* Duplicate insert of a still-active key must fail. */
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 42, &dummy1), -1);

    /* Tombstone it -- lookup must report TOMBSTONE, not ABSENT. This is
     * the distinction Go's nil-but-present map entry exists to capture: a
     * late frame for id 42 must be recognized as "known dead", not
     * mistaken for a brand new stream. */
    ASSERT_EQ_INT(cloak_strmtab_tombstone(&t, 42), 0);
    ASSERT_EQ_INT(cloak_strmtab_lookup(&t, 42, &state, &value), 1);
    ASSERT_EQ_INT(state, CLOAK_STRMTAB_TOMBSTONE);

    /* Tombstoning an already-tombstoned (or never-active) key fails. */
    ASSERT_EQ_INT(cloak_strmtab_tombstone(&t, 42), -1);
    ASSERT_EQ_INT(cloak_strmtab_tombstone(&t, 999), -1);

    /* Reinserting the SAME key over its own tombstone must succeed (no
     * information is lost -- it's the same key). */
    int dummy2 = 222;
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 42, &dummy2), 0);
    ASSERT_EQ_INT(cloak_strmtab_lookup(&t, 42, &state, &value), 1);
    ASSERT_EQ_INT(state, CLOAK_STRMTAB_ACTIVE);
    ASSERT_TRUE(value == &dummy2);

    cloak_strmtab_destroy(&t);
}

typedef struct {
    uint32_t keys[16];
    void *values[16];
    size_t count;
} iter_capture_t;

static void capture_iter_cb(uint32_t key, void *value, void *userdata) {
    iter_capture_t *cap = (iter_capture_t *)userdata;
    ASSERT_TRUE(cap->count < 16);
    cap->keys[cap->count] = key;
    cap->values[cap->count] = value;
    cap->count++;
}

static void test_for_each_active_visits_only_active(void) {
    cloak_strmtab_t t;
    ASSERT_EQ_INT(cloak_strmtab_init(&t, 4), 0);

    int a = 1, b = 2, c = 3;
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 1, &a), 0);
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 2, &b), 0);
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 3, &c), 0);
    ASSERT_EQ_INT(cloak_strmtab_tombstone(&t, 2), 0);

    iter_capture_t cap;
    cap.count = 0;
    cloak_strmtab_for_each_active(&t, capture_iter_cb, &cap);

    ASSERT_EQ_INT(cap.count, 2);
    int saw_1 = 0, saw_3 = 0;
    for (size_t i = 0; i < cap.count; i++) {
        if (cap.keys[i] == 1) { ASSERT_TRUE(cap.values[i] == &a); saw_1 = 1; }
        if (cap.keys[i] == 3) { ASSERT_TRUE(cap.values[i] == &c); saw_3 = 1; }
        ASSERT_TRUE(cap.keys[i] != 2); /* tombstoned -- must not be visited */
    }
    ASSERT_TRUE(saw_1 && saw_3);

    cloak_strmtab_destroy(&t);
}

/* Regression test for a real bug caught during this table's design
 * verification: an earlier version of insert_active reused the FIRST
 * tombstone slot seen along the probe chain for ANY new key, which
 * silently destroyed the overwritten key's tombstone. A late frame for
 * that now-clobbered id would then be misread as ABSENT (a brand new
 * stream) instead of TOMBSTONE (drop silently) -- exactly the bug
 * tombstoning exists to prevent. This test inserts and tombstones 5000
 * sequential ids (a third of them, interspersed), verifying after EVERY
 * single insertion that every previously-tombstoned id is still
 * correctly reported as TOMBSTONE and every still-active id still maps
 * to its correct pointer -- including across every table growth the 5000
 * insertions trigger. */
static void test_5000_key_growth_with_interspersed_tombstones(void) {
    cloak_strmtab_t t;
    ASSERT_EQ_INT(cloak_strmtab_init(&t, 4), 0);

    enum { N = 5000 };
    void **ptrs = (void **)malloc(N * sizeof(void *));
    int *alive = (int *)calloc(N, sizeof(int));
    ASSERT_TRUE(ptrs != NULL && alive != NULL);

    for (int i = 0; i < N; i++) {
        ptrs[i] = malloc(1);
        ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, (uint32_t)i, ptrs[i]), 0);
        alive[i] = 1;
        if (i % 3 == 0) {
            ASSERT_EQ_INT(cloak_strmtab_tombstone(&t, (uint32_t)i), 0);
            alive[i] = 0;
        }
        for (int j = 0; j <= i; j++) {
            cloak_strmtab_state_t state;
            void *value;
            ASSERT_EQ_INT(cloak_strmtab_lookup(&t, (uint32_t)j, &state, &value), 1);
            if (alive[j]) {
                ASSERT_EQ_INT(state, CLOAK_STRMTAB_ACTIVE);
                ASSERT_TRUE(value == ptrs[j]);
            } else {
                ASSERT_EQ_INT(state, CLOAK_STRMTAB_TOMBSTONE);
            }
        }
    }

    cloak_strmtab_state_t state;
    void *value;
    ASSERT_EQ_INT(cloak_strmtab_lookup(&t, (uint32_t)(N + 1000), &state, &value), 0);

    for (int i = 0; i < N; i++) free(ptrs[i]);
    free(ptrs);
    free(alive);
    cloak_strmtab_destroy(&t);
}

static void test_destroy_after_failed_init_is_safe(void) {
    cloak_strmtab_t t;
    /* initial_cap_hint == 0 is rejected (see Step 3) -- destroy on the
     * resulting zeroed struct must not crash. */
    ASSERT_EQ_INT(cloak_strmtab_init(&t, 0), -1);
    cloak_strmtab_destroy(&t);
}

TEST_MAIN_BEGIN()
    test_absent_key_reports_absent();
    test_insert_lookup_tombstone_reinsert();
    test_for_each_active_visits_only_active();
    test_5000_key_growth_with_interspersed_tombstones();
    test_destroy_after_failed_init_is_safe();
TEST_MAIN_END()
