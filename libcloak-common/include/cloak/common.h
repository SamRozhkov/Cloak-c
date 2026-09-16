#ifndef CLOAK_COMMON_H
#define CLOAK_COMMON_H

#include <stddef.h>
#include <stdint.h>

const char *cloak_common_version(void);

void cloak_random_bytes(uint8_t *buf, size_t len);

/* A uniform draw from [0, n), and the ONLY correct way to reduce this
 * project's randomness onto a small range.
 *
 * `cloak_random_bytes(&b, 1); b % n` IS NOT THAT DRAW, AND THE DIFFERENCE
 * HAS BEEN ON THE WIRE. 256 is not a multiple of 240, so `b % 240` gives
 * the sixteen smallest results twice the probability of the other 224.
 * MEASURED, 200,000 samples each: the old libcloak-mux/src/frame.c drew a
 * frame pad length in [0,15] 12.547 % of the time where Go's
 * common.RandInt(240) draws it 6.667 % -- a per-value ratio of 2.009. That
 * pad length is added straight into the on-wire frame length of the first
 * five frames of every stream, in both directions, on both transports, so
 * the bias was a passive size-distribution distinguisher between this port
 * and the reference implementation -- in the padding whose stated purpose
 * (Go's own comment: "Pad to avoid size side channel leak") is to defeat a
 * size side channel. Nothing saw it for five modules because every test in
 * the tree has our code on both ends and the interop oracle checks that
 * frames DECODE, never how long they are.
 *
 * This is the C equivalent of Go's common.RandInt
 * (internal/common/crypto.go:86-97), which is crypto/rand.Int over a
 * big.Int bound and is rejection-sampled and unbiased. Same strategy here:
 * draw 32 bits, discard the short tail above the largest multiple of n,
 * reduce. The loop is unbounded in principle and never runs twice in
 * practice for the ranges this project uses -- for n <= 256 the discarded
 * tail is at most 255 values out of 2^32, i.e. below 2^-24 per draw.
 *
 * n == 0 and n == 1 both return 0.
 *
 * Distribution pinned by libcloak-common/tests/test_random.c (a chi-square
 * over 240 and over 7 bins) and, for the on-wire quantity itself, by
 * libcloak-mux/tests/test_frame.c. */
uint32_t cloak_random_below(uint32_t n);

#endif
