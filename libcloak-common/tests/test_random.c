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

static void test_random_below_degenerate_bounds(void) {
    for (int i = 0; i < 16; i++) {
        ASSERT_EQ_INT(cloak_random_below(0), 0);
        ASSERT_EQ_INT(cloak_random_below(1), 0);
    }
}

static void test_random_below_stays_in_range(void) {
    for (int i = 0; i < 4096; i++) {
        ASSERT_TRUE(cloak_random_below(240) < 240u);
        ASSERT_TRUE(cloak_random_below(7) < 7u);
        ASSERT_TRUE(cloak_random_below(26) < 26u);
    }
}

/* THE ASSERTION THAT WOULD HAVE CAUGHT THE DEFECT.
 *
 * 240 is the frame-padding bound (CLOAK_FRAME_MAX_EXTRA_LEN - tagLen + 1
 * for AES-GCM), and 240 does not divide 256, so the shipped
 * `one_random_byte % 240` gave the sixteen results in [0,15] twice the
 * probability of the other 224. Every pre-existing assertion about
 * randomness in this tree -- "two draws differ", "every value appears" --
 * passes unchanged under that bias. A goodness-of-fit test does not.
 *
 * MEASURED BRACKET -- in the dev image, against OpenSSL's RAND_bytes,
 * 40 independent runs of each sampler at 200,000 draws:
 *
 *              chi2 min    chi2 mean   chi2 max    draws in [0,15]
 *   rejection     202.6       243.5       292.7    13103 .. 13592
 *   `b % 240`   10260.4     11130.9     11724.5    24513 .. 25297
 *
 * The threshold below, 420.0, sits in the gap between 292.7 and 10260.4
 * with the whole of both clouds on the correct side. In distribution terms
 * it is the 1 - 1.5e-11 point of chi-square with 239 degrees of freedom,
 * so an unbiased sampler fails this about once in 7e10 runs. 200,000
 * draws is far more than the minimum the 2.009x effect needs; it is kept
 * because it is the sample size the defect was first measured at, and it
 * costs 21 ms.
 *
 * AND IT WAS WATCHED TO FAIL, not merely reasoned about: with
 * cloak_random_below temporarily replaced by the one-byte modulo, this
 * exact assertion printed
 *   "chi2 = 10783.2, not < 420.0"
 * and the one below it "24794 not in [12664, 14003]". */
#define PAD_RANGE_DRAWS 200000ul
#define PAD_RANGE_BINS 240
#define CHI2_239DF_THRESHOLD 420.0

static void test_random_below_240_is_uniform(void) {
    static unsigned long counts[PAD_RANGE_BINS];
    memset(counts, 0, sizeof(counts));

    for (unsigned long i = 0; i < PAD_RANGE_DRAWS; i++) {
        uint32_t v = cloak_random_below(PAD_RANGE_BINS);
        ASSERT_TRUE(v < (uint32_t)PAD_RANGE_BINS);
        counts[v]++;
    }

    ASSERT_UNIFORM_CHI_SQUARE(counts, PAD_RANGE_BINS, PAD_RANGE_DRAWS, CHI2_239DF_THRESHOLD);

    /* And the specific shape of the old defect, named, so a failure says
     * what broke rather than only that something did: the low sixteen
     * results carry 16/240 = 6.667 % of the mass, not 12.547 %.
     * Expected 13333.3, sigma = sqrt(N p (1-p)) = 111.5; the bracket below
     * is +/- 6 sigma (a 2e-9 false-failure rate). Measured over the same
     * 40 runs: the rejection sampler produced 13103..13592, comfortably
     * inside it, and the byte-modulo produced 24513..25297 -- a hundred
     * sigma outside, never once overlapping. */
    unsigned long low = 0;
    for (int v = 0; v < 16; v++) {
        low += counts[v];
    }
    ASSERT_COUNT_IN_RANGE("cloak_random_below(240) draws in [0,15]", low, 12664ul, 14003ul);
}

/* The same test at the OTHER bound this project reduces onto: the seven
 * fake-certificate lengths in cloak_server_auth_cert_lens, picked per
 * connection on the direct-TLS reply path (libcloak-server/src/dispatcher.c).
 * 256 = 7*36 + 4, so the shipped `one_random_byte % 7` drew four of the
 * seven lengths 37/256 = 14.453 % of the time and three of them
 * 36/256 = 14.063 % -- a 1.028x ratio, 70x weaker than the padding one and
 * correspondingly more expensive to see.
 *
 * MEASURED BRACKET -- same image, same RNG, 40 runs of each sampler:
 *
 *   draws        rejection (min/mean/max)   `b % 7` (min/mean/max)
 *   2,000,000       1.3 /   5.8 /  15.5      300.0 / 369.9 / 442.3
 *     200,000       1.5 /   7.2 /  16.7       23.6 /  40.7 /  65.2
 *
 * The threshold is 60.0, the 1 - 4.6e-11 point of chi-square with 6
 * degrees of freedom. THE SECOND ROW IS WHY THE SAMPLE SIZE IS 2,000,000
 * AND NOT THE 200,000 USED ABOVE: at 200,000 draws the biased sampler's
 * statistic straddles the threshold -- most runs land under it -- so the
 * test would have PASSED on a biased build, which is the failure mode this
 * whole exercise exists to prevent. Ten times the draws buys a gap of
 * 15.5 against 300.0 with nothing in between, and costs 210 ms.
 *
 * Watched to fail: with the byte-modulo in place this assertion printed
 * "chi2 = 316.7, not < 60.0". */
#define CERT_LEN_DRAWS 2000000ul
#define CERT_LEN_BINS 7
#define CHI2_6DF_THRESHOLD 60.0

static void test_random_below_7_is_uniform(void) {
    static unsigned long counts[CERT_LEN_BINS];
    memset(counts, 0, sizeof(counts));

    for (unsigned long i = 0; i < CERT_LEN_DRAWS; i++) {
        uint32_t v = cloak_random_below(CERT_LEN_BINS);
        ASSERT_TRUE(v < (uint32_t)CERT_LEN_BINS);
        counts[v]++;
    }

    ASSERT_UNIFORM_CHI_SQUARE(counts, CERT_LEN_BINS, CERT_LEN_DRAWS, CHI2_6DF_THRESHOLD);
}

TEST_MAIN_BEGIN()
    test_random_bytes_fills_buffer_differently_each_call();
    test_random_bytes_zero_length_is_a_no_op();
    test_random_below_degenerate_bounds();
    test_random_below_stays_in_range();
    test_random_below_240_is_uniform();
    test_random_below_7_is_uniform();
TEST_MAIN_END()
