#include "cloak/common.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

void cloak_random_bytes(uint8_t *buf, size_t len) {
    if (len == 0) {
        return;
    }
    if (RAND_bytes(buf, (int)len) != 1) {
        fprintf(stderr, "cloak: fatal: RAND_bytes failed, CSPRNG unavailable\n");
        abort();
    }
}

/* Rejection sampling, matching Go's common.RandInt. See cloak/common.h for
 * why the obvious one-byte modulo is wrong and what it cost. */
uint32_t cloak_random_below(uint32_t n) {
    if (n <= 1) {
        return 0;
    }
    /* The largest multiple of n that fits in 32 bits. Values at or above
     * it are the short tail that makes the modulo non-uniform, and they
     * are the values discarded below. */
    uint64_t limit = 0x100000000ULL - (0x100000000ULL % (uint64_t)n);
    for (;;) {
        uint8_t b[4];
        cloak_random_bytes(b, sizeof(b));
        uint32_t v = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
                     ((uint32_t)b[2] << 8) | (uint32_t)b[3];
        if ((uint64_t)v < limit) {
            return v % n;
        }
    }
}
