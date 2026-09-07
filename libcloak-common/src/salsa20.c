#include "cloak/crypto.h"

#include <string.h>

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* Salsa20/20 core: produces one 64-byte keystream block for the given
 * 256-bit key, 64-bit nonce, and 64-bit little-endian block counter.
 * Follows the standard diagonal state layout and the columnround/rowround
 * construction from the published Salsa20 specification. */
static void salsa20_block(const uint8_t key[CLOAK_SALSA20_KEY_LEN],
                           const uint8_t nonce[CLOAK_SALSA20_NONCE_LEN],
                           uint64_t counter, uint8_t out[64]) {
    static const uint32_t sigma[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};

    uint32_t x[16];
    x[0]  = sigma[0];
    x[1]  = load_le32(key + 0);
    x[2]  = load_le32(key + 4);
    x[3]  = load_le32(key + 8);
    x[4]  = load_le32(key + 12);
    x[5]  = sigma[1];
    x[6]  = load_le32(nonce + 0);
    x[7]  = load_le32(nonce + 4);
    x[8]  = (uint32_t)(counter & 0xffffffffu);
    x[9]  = (uint32_t)(counter >> 32);
    x[10] = sigma[2];
    x[11] = load_le32(key + 16);
    x[12] = load_le32(key + 20);
    x[13] = load_le32(key + 24);
    x[14] = load_le32(key + 28);
    x[15] = sigma[3];

    uint32_t w[16];
    memcpy(w, x, sizeof(w));

#define QR(a, b, c, d) \
    do { \
        w[b] ^= rotl32(w[a] + w[d], 7); \
        w[c] ^= rotl32(w[b] + w[a], 9); \
        w[d] ^= rotl32(w[c] + w[b], 13); \
        w[a] ^= rotl32(w[d] + w[c], 18); \
    } while (0)

    for (int i = 0; i < 10; i++) {
        /* columnround */
        QR(0, 4, 8, 12);
        QR(5, 9, 13, 1);
        QR(10, 14, 2, 6);
        QR(15, 3, 7, 11);
        /* rowround */
        QR(0, 1, 2, 3);
        QR(5, 6, 7, 4);
        QR(10, 11, 8, 9);
        QR(15, 12, 13, 14);
    }
#undef QR

    for (int i = 0; i < 16; i++) {
        store_le32(out + 4 * i, w[i] + x[i]);
    }
}

void cloak_salsa20_xor(uint8_t *dst, const uint8_t *src, size_t len,
                        const uint8_t nonce[CLOAK_SALSA20_NONCE_LEN],
                        const uint8_t key[CLOAK_SALSA20_KEY_LEN]) {
    uint8_t block[64];
    uint64_t counter = 0;
    size_t offset = 0;

    while (offset < len) {
        salsa20_block(key, nonce, counter, block);
        size_t chunk = len - offset;
        if (chunk > 64) {
            chunk = 64;
        }
        for (size_t i = 0; i < chunk; i++) {
            dst[offset + i] = (uint8_t)(src[offset + i] ^ block[i]);
        }
        offset += chunk;
        counter++;
    }
}
