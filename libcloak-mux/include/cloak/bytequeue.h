#ifndef CLOAK_BYTEQUEUE_H
#define CLOAK_BYTEQUEUE_H

#include <stddef.h>
#include <stdint.h>

/* A fixed-capacity, non-blocking byte ring buffer -- the single-threaded
 * reactor equivalent of Go Cloak's streamBufferedPipe (which instead blocks
 * the calling goroutine via a sync.Cond). There is no blocking here: writes
 * either fully succeed or are fully rejected (0 bytes written) if they
 * would not fit, and reads return whatever is currently available (0 if
 * empty). Callers drive backpressure themselves by checking
 * cloak_bytequeue_free_space / cloak_bytequeue_len. */
typedef struct {
    uint8_t *data;
    size_t cap;
    size_t head; /* index of the oldest unread byte */
    size_t len;  /* bytes currently stored */
    int closed;
} cloak_bytequeue_t;

/* Allocates a cap-byte backing buffer. Returns 0 on success, -1 on
 * allocation failure or cap == 0. */
int cloak_bytequeue_init(cloak_bytequeue_t *q, size_t cap);

void cloak_bytequeue_destroy(cloak_bytequeue_t *q);

/* Writes data atomically: either all len bytes are written (returns len),
 * or none are (returns 0) if fewer than len bytes of free space remain, or
 * the queue is closed. Never partially writes. */
size_t cloak_bytequeue_write(cloak_bytequeue_t *q, const uint8_t *data, size_t len);

/* Reads up to len bytes (may return fewer than len if that's all that's
 * available -- unlike write, read is not all-or-nothing). Returns 0 if
 * currently empty, whether or not the queue is closed -- use
 * cloak_bytequeue_is_eof to tell "no data yet" apart from "closed and
 * drained". */
size_t cloak_bytequeue_read(cloak_bytequeue_t *q, uint8_t *out, size_t len);

/* Copies up to len bytes starting at the current head into out, WITHOUT
 * consuming them -- a subsequent cloak_bytequeue_read (or another peek)
 * returns the same bytes. Returns bytes copied (may be fewer than len if
 * that's all that's currently available). */
size_t cloak_bytequeue_peek(const cloak_bytequeue_t *q, uint8_t *out, size_t len);

/* Marks the queue closed: no further cloak_bytequeue_write calls will
 * succeed (they return 0), but already-buffered bytes remain readable
 * until drained. Idempotent. */
void cloak_bytequeue_close(cloak_bytequeue_t *q);

size_t cloak_bytequeue_len(const cloak_bytequeue_t *q);
size_t cloak_bytequeue_free_space(const cloak_bytequeue_t *q);

/* True once the queue is closed AND fully drained (len == 0) -- the
 * end-of-stream condition a reader should treat as EOF. */
int cloak_bytequeue_is_eof(const cloak_bytequeue_t *q);

#endif
