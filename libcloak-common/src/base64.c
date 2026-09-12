#include "cloak/base64.h"

#include <string.h>

static const char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Returns the 6-bit value of a standard-alphabet character, or -1 if c is
 * not in the alphabet. '=' is handled by the caller, not here. */
static int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

size_t cloak_base64_encoded_size(size_t in_len) {
    return ((in_len + 2) / 3) * 4 + 1;
}

int cloak_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    if (out == NULL) {
        return -1;
    }
    if (in == NULL && in_len > 0) {
        return -1;
    }
    if (out_cap < cloak_base64_encoded_size(in_len)) {
        return -1;
    }

    size_t o = 0;
    size_t i = 0;
    while (in_len - i >= 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
                     (uint32_t)in[i + 2];
        out[o++] = b64_alphabet[(v >> 18) & 0x3f];
        out[o++] = b64_alphabet[(v >> 12) & 0x3f];
        out[o++] = b64_alphabet[(v >> 6) & 0x3f];
        out[o++] = b64_alphabet[v & 0x3f];
        i += 3;
    }

    size_t rem = in_len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = b64_alphabet[(v >> 18) & 0x3f];
        out[o++] = b64_alphabet[(v >> 12) & 0x3f];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = b64_alphabet[(v >> 18) & 0x3f];
        out[o++] = b64_alphabet[(v >> 12) & 0x3f];
        out[o++] = b64_alphabet[(v >> 6) & 0x3f];
        out[o++] = '=';
    }

    out[o] = '\0';
    return 0;
}

int cloak_base64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (in == NULL || out_len == NULL) {
        return -1;
    }
    if (out == NULL && out_cap > 0) {
        return -1;
    }

    size_t len = strlen(in);
    if (len % 4 != 0) {
        return -1;
    }

    size_t produced = 0;
    for (size_t i = 0; i < len; i += 4) {
        int vals[4];
        int pad = 0;
        for (int j = 0; j < 4; j++) {
            char c = in[i + j];
            if (c == '=') {
                /* padding is legal only in the last quantum, only in the
                 * last two positions, and "=x" is never legal */
                if (i + 4 != len) {
                    return -1;
                }
                if (j < 2) {
                    return -1;
                }
                if (j == 2 && in[i + 3] != '=') {
                    return -1;
                }
                pad++;
                vals[j] = 0;
            } else {
                if (pad > 0) {
                    return -1;
                }
                int v = b64_value(c);
                if (v < 0) {
                    return -1;
                }
                vals[j] = v;
            }
        }

        uint32_t v = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12) |
                     ((uint32_t)vals[2] << 6) | (uint32_t)vals[3];
        size_t n = 3 - (size_t)pad;
        if (n > out_cap - produced) {
            return -1;
        }
        if (n > 0) {
            out[produced] = (uint8_t)((v >> 16) & 0xff);
        }
        if (n > 1) {
            out[produced + 1] = (uint8_t)((v >> 8) & 0xff);
        }
        if (n > 2) {
            out[produced + 2] = (uint8_t)(v & 0xff);
        }
        produced += n;
    }

    *out_len = produced;
    return 0;
}
