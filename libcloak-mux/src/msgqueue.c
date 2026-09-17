#define _POSIX_C_SOURCE 200809L

#include "cloak/msgqueue.h"

#include <stdlib.h>
#include <string.h>

/* Copies n bytes out of the ring starting at absolute offset `off`,
 * wrapping once. Split out rather than inlined three times because the
 * wrap is the only interesting thing in this file and one copy of it is
 * one place to get it wrong. */
static void ring_peek(const cloak_msgqueue_t *q, size_t off, uint8_t *dst, size_t n) {
    size_t first = q->cap - off;
    if (first >= n) {
        memcpy(dst, q->data + off, n);
        return;
    }
    memcpy(dst, q->data + off, first);
    memcpy(dst + first, q->data, n - first);
}

static void ring_put(cloak_msgqueue_t *q, size_t off, const uint8_t *src, size_t n) {
    size_t first = q->cap - off;
    if (first >= n) {
        memcpy(q->data + off, src, n);
        return;
    }
    memcpy(q->data + off, src, first);
    memcpy(q->data, src + first, n - first);
}

int cloak_msgqueue_init(cloak_msgqueue_t *q, size_t cap) {
    if (cap <= CLOAK_MSGQUEUE_LEN_PREFIX) {
        return -1;
    }
    memset(q, 0, sizeof(*q));
    q->data = (uint8_t *)malloc(cap);
    if (q->data == NULL) {
        return -1;
    }
    q->cap = cap;
    return 0;
}

void cloak_msgqueue_destroy(cloak_msgqueue_t *q) {
    free(q->data);
    memset(q, 0, sizeof(*q));
}

int cloak_msgqueue_write(cloak_msgqueue_t *q, const uint8_t *msg, size_t len) {
    if (q->closed) {
        return CLOAK_MSGQUEUE_ERR_CLOSED;
    }
    /* Written as a subtraction rather than `len + PREFIX > cap` because
     * len comes from a frame header and a hostile one can be near
     * SIZE_MAX; the addition would wrap and admit it. cap >
     * CLOAK_MSGQUEUE_LEN_PREFIX is guaranteed by init, so the subtraction
     * cannot wrap. The 0xffffffff test is the prefix's own range, checked
     * separately so the diagnosis is the same TOO_LARGE either way. */
    if (len > q->cap - CLOAK_MSGQUEUE_LEN_PREFIX || len > 0xffffffffu) {
        return CLOAK_MSGQUEUE_ERR_TOO_LARGE;
    }
    if (len + CLOAK_MSGQUEUE_LEN_PREFIX > q->cap - q->len) {
        return CLOAK_MSGQUEUE_ERR_FULL;
    }

    uint8_t prefix[CLOAK_MSGQUEUE_LEN_PREFIX];
    prefix[0] = (uint8_t)(len >> 24);
    prefix[1] = (uint8_t)(len >> 16);
    prefix[2] = (uint8_t)(len >> 8);
    prefix[3] = (uint8_t)len;

    size_t tail = (q->head + q->len) % q->cap;
    ring_put(q, tail, prefix, CLOAK_MSGQUEUE_LEN_PREFIX);
    if (len > 0) {
        ring_put(q, (tail + CLOAK_MSGQUEUE_LEN_PREFIX) % q->cap, msg, len);
    }
    q->len += CLOAK_MSGQUEUE_LEN_PREFIX + len;
    q->payload_bytes += len;
    q->count++;
    return 0;
}

int cloak_msgqueue_peek_len(const cloak_msgqueue_t *q, size_t *out_len) {
    if (q->count == 0) {
        return 0;
    }
    uint8_t prefix[CLOAK_MSGQUEUE_LEN_PREFIX];
    ring_peek(q, q->head, prefix, CLOAK_MSGQUEUE_LEN_PREFIX);
    *out_len = ((size_t)prefix[0] << 24) | ((size_t)prefix[1] << 16) |
               ((size_t)prefix[2] << 8) | (size_t)prefix[3];
    return 1;
}

long cloak_msgqueue_read(cloak_msgqueue_t *q, uint8_t *out, size_t out_cap) {
    size_t data_len;
    if (!cloak_msgqueue_peek_len(q, &data_len)) {
        return CLOAK_MSGQUEUE_EMPTY;
    }
    /* THE EARLY RETURN, and it must stay early. Everything below this
     * line mutates the queue; Go's datagramBufferedPipe.go:58-60 returns
     * here for the same reason, one line before the pop at :62. See the
     * header. */
    if (out_cap < data_len) {
        return CLOAK_MSGQUEUE_SHORT_BUFFER;
    }
    if (data_len > 0) {
        ring_peek(q, (q->head + CLOAK_MSGQUEUE_LEN_PREFIX) % q->cap, out, data_len);
    }
    q->head = (q->head + CLOAK_MSGQUEUE_LEN_PREFIX + data_len) % q->cap;
    q->len -= CLOAK_MSGQUEUE_LEN_PREFIX + data_len;
    q->payload_bytes -= data_len;
    q->count--;
    return (long)data_len;
}

size_t cloak_msgqueue_count(const cloak_msgqueue_t *q) {
    return q->count;
}

size_t cloak_msgqueue_payload_bytes(const cloak_msgqueue_t *q) {
    return q->payload_bytes;
}

void cloak_msgqueue_close(cloak_msgqueue_t *q) {
    q->closed = 1;
}

int cloak_msgqueue_is_eof(const cloak_msgqueue_t *q) {
    return q->closed && q->count == 0;
}
