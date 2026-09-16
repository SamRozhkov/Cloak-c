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

/* ---- distribution assertions ---------------------------------------------
 *
 * WHY A STATISTICAL ASSERTION EXISTS IN THIS TREE AT ALL. Two shipped
 * randomness sites reduced a single random byte modulo a range that does
 * not divide 256, so some outcomes were drawn twice as often as others,
 * and one of those outcomes lands directly in an on-wire frame length. No
 * assertion of the form "the values differ" or "every value appears" can
 * see that -- both pass under a 2x bias -- so the shape of the assertion
 * has to be the shape of the defect: a goodness-of-fit test against
 * uniform. See cloak/common.h's cloak_random_below.
 *
 * Pearson's chi-square, sum over bins of (observed - expected)^2/expected
 * with expected = total/bins. Under the uniform null it is distributed as
 * chi-square with (bins - 1) degrees of freedom; the caller supplies a
 * threshold with the false-failure rate it wants, and each call site
 * records the MEASURED separation between a biased and an unbiased
 * implementation rather than a claimed one. No math.h, so no -lm. */
static inline double cloak_test_chi_square_uniform(const unsigned long *counts, size_t bins,
                                                   unsigned long total) {
    double expected = (double)total / (double)bins;
    double chi = 0.0;
    for (size_t i = 0; i < bins; i++) {
        double d = (double)counts[i] - expected;
        chi += (d * d) / expected;
    }
    return chi;
}

#define ASSERT_UNIFORM_CHI_SQUARE(counts, bins, total, threshold) \
    do { \
        double _chi = cloak_test_chi_square_uniform((counts), (bins), (total)); \
        if (!(_chi < (double)(threshold))) { \
            fprintf(stderr, \
                    "FAIL %s:%d: ASSERT_UNIFORM_CHI_SQUARE(%s over %s bins, %s draws)" \
                    " -> chi2 = %.1f, not < %.1f\n", \
                    __FILE__, __LINE__, #counts, #bins, #total, _chi, (double)(threshold)); \
            cloak_test_failures++; \
        } \
    } while (0)

/* An observed count that must land inside [lo, hi]. Used beside the
 * chi-square to name the SPECIFIC defect a chi-square only detects
 * generically -- e.g. "the sixteen smallest pad lengths carry twice their
 * share of the mass". */
#define ASSERT_COUNT_IN_RANGE(what, observed, lo, hi) \
    do { \
        unsigned long _o = (unsigned long)(observed); \
        unsigned long _lo = (unsigned long)(lo); \
        unsigned long _hi = (unsigned long)(hi); \
        if (_o < _lo || _o > _hi) { \
            fprintf(stderr, "FAIL %s:%d: ASSERT_COUNT_IN_RANGE(%s) -> %lu not in [%lu, %lu]\n", \
                    __FILE__, __LINE__, (what), _o, _lo, _hi); \
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
