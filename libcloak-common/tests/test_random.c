#include "cloak/common.h"
#include "test_framework.h"
#include <stdint.h>
#include <string.h>

static void test_random_bytes_fills_buffer_differently_each_call(void) {
    uint8_t a[32];
    uint8_t b[32];
    memset(a, 0, sizeof(a));
    memset(b, 0, sizeof(b));

    cloak_random_bytes(a, sizeof(a));
    cloak_random_bytes(b, sizeof(b));

    ASSERT_MEM_NE(a, b, sizeof(a));
}

static void test_random_bytes_zero_length_is_a_no_op(void) {
    uint8_t canary[4] = {1, 2, 3, 4};
    cloak_random_bytes(canary, 0);
    uint8_t expected[4] = {1, 2, 3, 4};
    ASSERT_MEM_EQ(canary, expected, sizeof(canary));
}

TEST_MAIN_BEGIN()
    test_random_bytes_fills_buffer_differently_each_call();
    test_random_bytes_zero_length_is_a_no_op();
TEST_MAIN_END()
