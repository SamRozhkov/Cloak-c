#include "cloak/bytequeue.h"

#include <stdlib.h>
#include <string.h>

int cloak_bytequeue_init(cloak_bytequeue_t *q, size_t cap) {
    if (cap == 0) {
        return -1;
    }
    q->data = (uint8_t *)malloc(cap);
    if (q->data == NULL) {
        return -1;
    }
    q->cap = cap;
    q->head = 0;
    q->len = 0;
    q->closed = 0;
    return 0;
}

void cloak_bytequeue_destroy(cloak_bytequeue_t *q) {
    free(q->data);
    q->data = NULL;
    q->cap = 0;
    q->head = 0;
    q->len = 0;
    q->closed = 0;
}

size_t cloak_bytequeue_write(cloak_bytequeue_t *q, const uint8_t *data, size_t len) {
    if (len == 0) {
        return 0;
    }
    if (q->closed || len > q->cap - q->len) {
        return 0;
    }
    size_t tail = (q->head + q->len) % q->cap;
    size_t first_chunk = q->cap - tail;
    if (first_chunk >= len) {
        memcpy(q->data + tail, data, len);
    } else {
        memcpy(q->data + tail, data, first_chunk);
        memcpy(q->data, data + first_chunk, len - first_chunk);
    }
    q->len += len;
    return len;
}

size_t cloak_bytequeue_read(cloak_bytequeue_t *q, uint8_t *out, size_t len) {
    size_t n = len < q->len ? len : q->len;
    if (n == 0) {
        return 0;
    }
    size_t first_chunk = q->cap - q->head;
    if (first_chunk >= n) {
        memcpy(out, q->data + q->head, n);
    } else {
        memcpy(out, q->data + q->head, first_chunk);
        memcpy(out + first_chunk, q->data, n - first_chunk);
    }
    q->head = (q->head + n) % q->cap;
    q->len -= n;
    return n;
}

void cloak_bytequeue_close(cloak_bytequeue_t *q) {
    q->closed = 1;
}

size_t cloak_bytequeue_len(const cloak_bytequeue_t *q) {
    return q->len;
}

size_t cloak_bytequeue_free_space(const cloak_bytequeue_t *q) {
    return q->cap - q->len;
}

int cloak_bytequeue_is_eof(const cloak_bytequeue_t *q) {
    return q->closed && q->len == 0;
}
