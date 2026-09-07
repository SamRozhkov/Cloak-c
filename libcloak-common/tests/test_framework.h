#ifndef CLOAK_TEST_FRAMEWORK_H
#define CLOAK_TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>

static int cloak_test_failures = 0;

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: ASSERT_TRUE(%s)\n", __FILE__, __LINE__, #cond); \
            cloak_test_failures++; \
        } \
    } while (0)

#define ASSERT_EQ_INT(a, b) \
    do { \
        long long _a = (long long)(a); \
        long long _b = (long long)(b); \
        if (_a != _b) { \
            fprintf(stderr, "FAIL %s:%d: ASSERT_EQ_INT(%s, %s) -> %lld != %lld\n", \
                    __FILE__, __LINE__, #a, #b, _a, _b); \
            cloak_test_failures++; \
        } \
    } while (0)

#define ASSERT_MEM_EQ(a, b, len) \
    do { \
        if (memcmp((a), (b), (len)) != 0) { \
            fprintf(stderr, "FAIL %s:%d: ASSERT_MEM_EQ(%s, %s, %s)\n", \
                    __FILE__, __LINE__, #a, #b, #len); \
            cloak_test_failures++; \
        } \
    } while (0)

#define ASSERT_MEM_NE(a, b, len) \
    do { \
        if (memcmp((a), (b), (len)) == 0) { \
            fprintf(stderr, "FAIL %s:%d: ASSERT_MEM_NE(%s, %s, %s)\n", \
                    __FILE__, __LINE__, #a, #b, #len); \
            cloak_test_failures++; \
        } \
    } while (0)

#define TEST_MAIN_BEGIN() int main(void) {

#define TEST_MAIN_END() \
    if (cloak_test_failures > 0) { \
        fprintf(stderr, "%d assertion(s) failed\n", cloak_test_failures); \
        return 1; \
    } \
    printf("All tests passed\n"); \
    return 0; \
    }

#endif
