#include "cloak/base64.h"

#include <string.h>

/* The standard and URL-safe alphabets agree on characters 0-61 (A-Z, a-z,
 * 0-9) and differ only at 62 and 63 ('+'/'/' vs '-'/'_'). That 62-character
 * run is shared below, at the source level only: each full alphabet table
 * is still its own separate `static const` array (below), and
 * b64_common62_value() (further down) only ever resolves the shared 62
 * characters -- it does not know about '+', '/', '-' or '_' at all, so it
 * has nothing to leak between the two alphabets. Editing this macro can
 * only ever change both alphabets' shared prefix identically, which is
 * exactly what correctness requires; it cannot make one decoder start
 * accepting the other's special characters. */
#define B64_COMMON62 \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

static const char b64_alphabet[] = B64_COMMON62 "+/";
static const char b64url_alphabet[] = B64_COMMON62 "-_";

/* Returns the 6-bit value of a character shared by both alphabets (i.e.
 * A-Z, a-z, 0-9), or -1 if c is not one of those 62 characters. Does not
 * and must not know about '+', '/', '-' or '_' -- see B64_COMMON62 above. */
static int b64_common62_value(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    return -1;
}

/* Returns the 6-bit value of a standard-alphabet character, or -1 if c is
 * not in the alphabet. '=' is handled by the caller, not here. */
static int b64_value(char c) {
    int v = b64_common62_value(c);
    if (v >= 0) {
        return v;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

/* Returns the 6-bit value of a URL-safe-alphabet character, or -1 if c is
 * not in the alphabet. '=' is handled by the caller, not here. */
static int b64url_value(char c) {
    int v = b64_common62_value(c);
    if (v >= 0) {
        return v;
    }
    if (c == '-') {
        return 62;
    }
    if (c == '_') {
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

int cloak_base64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    if (out == NULL) {
        return -1;
    }
    if (in == NULL && in_len > 0) {
        return -1;
    }
    /* the encoded-size formula is pure arithmetic on in_len -- it has no
     * dependency on which alphabet is used, so sharing it cannot leak
     * anything between the two alphabets */
    if (out_cap < cloak_base64_encoded_size(in_len)) {
        return -1;
    }

    size_t o = 0;
    size_t i = 0;
    while (in_len - i >= 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
                     (uint32_t)in[i + 2];
        out[o++] = b64url_alphabet[(v >> 18) & 0x3f];
        out[o++] = b64url_alphabet[(v >> 12) & 0x3f];
        out[o++] = b64url_alphabet[(v >> 6) & 0x3f];
        out[o++] = b64url_alphabet[v & 0x3f];
        i += 3;
    }

    size_t rem = in_len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = b64url_alphabet[(v >> 18) & 0x3f];
        out[o++] = b64url_alphabet[(v >> 12) & 0x3f];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = b64url_alphabet[(v >> 18) & 0x3f];
        out[o++] = b64url_alphabet[(v >> 12) & 0x3f];
        out[o++] = b64url_alphabet[(v >> 6) & 0x3f];
        out[o++] = '=';
    }

    out[o] = '\0';
    return 0;
}

int cloak_base64url_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (in == NULL || out_len == NULL) {
        return -1;
    }
    if (out == NULL && out_cap > 0) {
        return -1;
    }

    size_t len = strlen(in);
    size_t rem = len % 4;
    if (rem == 1) {
        /* not a valid length under the padded scheme (multiple of 4) or
         * the unpadded one (a final group of 2 or 3 characters) */
        return -1;
    }

    size_t full_len = len - rem;
    size_t produced = 0;

    /* Full 4-character quanta. When rem == 0 the whole input is such
     * quanta and this loop is byte-for-byte the same padding logic as
     * cloak_base64_decode (just against b64url_value instead of
     * b64_value): '=' legal only in the last quantum of the whole input,
     * only in the last one or two positions. When rem != 0 the input ends
     * in an unpadded tail, so no quantum in this loop is allowed to
     * contain '=' either -- that combination belongs to neither scheme. */
    for (size_t i = 0; i < full_len; i += 4) {
        int vals[4];
        int pad = 0;
        for (int j = 0; j < 4; j++) {
            char c = in[i + j];
            if (c == '=') {
                if (rem != 0) {
                    return -1;
                }
                if (i + 4 != full_len) {
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
                int v = b64url_value(c);
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

    if (rem != 0) {
        /* Unpadded final group of 2 or 3 characters (matches Go's
         * base64.RawURLEncoding): every position must be a real data
         * character, '=' is not accepted here at all. rem == 2 yields 1
         * output byte, rem == 3 yields 2. */
        int vals[4] = {0, 0, 0, 0};
        for (size_t j = 0; j < rem; j++) {
            int v = b64url_value(in[full_len + j]);
            if (v < 0) {
                return -1;
            }
            vals[j] = v;
        }

        uint32_t v = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12) |
                     ((uint32_t)vals[2] << 6) | (uint32_t)vals[3];
        size_t n = rem - 1;
        if (n > out_cap - produced) {
            return -1;
        }
        if (n > 0) {
            out[produced] = (uint8_t)((v >> 16) & 0xff);
        }
        if (n > 1) {
            out[produced + 1] = (uint8_t)((v >> 8) & 0xff);
        }
        produced += n;
    }

    *out_len = produced;
    return 0;
}
