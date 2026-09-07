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
