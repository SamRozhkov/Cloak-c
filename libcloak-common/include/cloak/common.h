#ifndef CLOAK_COMMON_H
#define CLOAK_COMMON_H

#include <stddef.h>
#include <stdint.h>

const char *cloak_common_version(void);

void cloak_random_bytes(uint8_t *buf, size_t len);

#endif
