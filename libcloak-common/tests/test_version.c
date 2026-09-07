#include "cloak/common.h"
#include "test_framework.h"

static void test_version_returns_nonempty_string(void) {
    const char *v = cloak_common_version();
    ASSERT_TRUE(v != NULL);
    ASSERT_TRUE(strlen(v) > 0);
}

TEST_MAIN_BEGIN()
    test_version_returns_nonempty_string();
TEST_MAIN_END()
