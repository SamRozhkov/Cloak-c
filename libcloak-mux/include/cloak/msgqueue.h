#ifndef CLOAK_MSGQUEUE_H
#define CLOAK_MSGQUEUE_H

#include <stddef.h>
#include <stdint.h>

/* A FIXED-CAPACITY, NON-BLOCKING QUEUE OF WHOLE DATAGRAMS -- the receive
 * side of Go Cloak's datagramBufferedPipe
 * (/Users/sam/Cloak/internal/multiplex/datagramBufferedPipe.go), as
 * cloak_bytequeue_t is the receive side of its streamBufferedPipe.
 *
 * THE ONE DIFFERENCE FROM cloak_bytequeue_t IS THE ONLY REASON THIS FILE
 * EXISTS: message boundaries survive. A byte queue is free to hand a
 * reader half of one write and all of the next; that is exactly what an
 * ordered byte stream wants and exactly what a datagram tunnel must never
 * do. Go keeps the boundaries in a parallel `pLens []int` alongside a
 * single `bytes.Buffer`; this keeps them inline instead, as a 4-byte
 * big-endian length prefix in front of every datagram in one ring. Inline
 * because a separate length ring raises a question with no good answer --
 * how many entries does it need? -- and the scouting report
 * (docs/superpowers/plans/2026-09-17-module-9-scouting.md, §5) names that
 * question as a trap: "the length ring must be sized so it cannot be the
 * thing that overflows first". A prefix in the same ring cannot be the
 * thing that overflows first, because it is charged against the same
 * capacity as the bytes it describes and is reserved in the same
 * all-or-nothing admission test. The cost is 4 bytes of the caller's
 * capacity per queued datagram, which cloak_stream_init's existing
 * recv_capacity bound already covers with 251 bytes to spare (see
 * cloak_msgqueue_write).
 *
 * WHAT THIS DELIBERATELY DOES NOT DO, because Go's datagramBufferedPipe
 * does not do it either and this port's job here is behavioural identity,
 * not improvement: there is no sequence number anywhere in this file, no
 * reordering, no gap detection and no duplicate suppression. A caller
 * that writes the same datagram twice gets it out twice. That is not an
 * oversight; it is the whole difference between the two receive paths,
 * and cloak/ordering.h explains why one session gets one and one gets the
 * other.
 *
 * NOTHING HERE BLOCKS. Go's pipe blocks a goroutine on a sync.Cond in
 * both directions (Write waits for room, Read waits for a datagram); this
 * port is a single-threaded reactor, so both become immediate returns
 * with a status, and the caller drives backpressure by looking at
 * cloak_msgqueue_payload_bytes / cloak_msgqueue_count. That is the same
 * substitution cloak_bytequeue_t already makes, for the same reason. */

/* The per-datagram inline length prefix, in bytes. 4 rather than 8
 * because no frame payload this port will ever queue approaches 2^32 (a
 * mux frame's payload is bounded by max_on_wire_size, 16401 in every
 * shipping config), and rather than 2 because 65535 is NOT such a bound
 * -- max_on_wire_size is a caller-chosen size_t and a 2-byte prefix would
 * silently truncate a legal one. cloak_msgqueue_write rejects anything
 * that does not fit in the prefix rather than trusting that bound. */
#define CLOAK_MSGQUEUE_LEN_PREFIX ((size_t)4)

typedef struct {
    uint8_t *data;
    size_t cap;           /* allocated bytes; prefixes are charged against this */
    size_t head;          /* index of the oldest stored byte -- always a prefix's first byte */
    size_t len;           /* bytes currently stored, prefixes INCLUDED */
    size_t count;         /* datagrams currently stored */
    size_t payload_bytes; /* bytes currently stored, prefixes EXCLUDED */
    int closed;
} cloak_msgqueue_t;

/* cloak_msgqueue_read's two non-length returns. Both negative, and
 * distinct from each other, because the caller has to tell them apart:
 * EMPTY is "come back later" (or end-of-stream, which the caller resolves
 * with cloak_msgqueue_is_eof), while SHORT_BUFFER is "your buffer is too
 * small for the datagram at the head, and it is STILL THERE". Collapsing
 * the two into one error is precisely the shape of Go's own bug 6 (see
 * cloak_msgqueue_read). */
#define CLOAK_MSGQUEUE_EMPTY        (-1)
#define CLOAK_MSGQUEUE_SHORT_BUFFER (-2)

/* cloak_msgqueue_write's three failure returns, distinct for the same
 * reason: a caller must be able to tell a transient shortage of room from
 * a datagram that can never be queued at this capacity, because those two
 * call for opposite reactions (drop this one and carry on, versus treat
 * the peer as out of spec). See cloak_msgqueue_write. */
#define CLOAK_MSGQUEUE_ERR_FULL      (-1)
#define CLOAK_MSGQUEUE_ERR_TOO_LARGE (-2)
#define CLOAK_MSGQUEUE_ERR_CLOSED    (-3)

/* Allocates a cap-byte backing ring. Returns 0 on success, -1 on
 * allocation failure or on cap <= CLOAK_MSGQUEUE_LEN_PREFIX -- a capacity
 * that cannot hold even a 1-byte datagram plus its prefix is a queue that
 * can never accept anything, which is a configuration error worth
 * refusing at construction rather than discovering as an unexplained
 * total packet loss later. */
int cloak_msgqueue_init(cloak_msgqueue_t *q, size_t cap);

void cloak_msgqueue_destroy(cloak_msgqueue_t *q);

/* Enqueues msg[0,len) as ONE datagram, all or nothing -- a half-written
 * datagram is not a legal state of this queue, so there is no partial
 * write and no short write to handle.
 *
 * Returns 0 on success, or:
 *   CLOAK_MSGQUEUE_ERR_TOO_LARGE  len + CLOAK_MSGQUEUE_LEN_PREFIX exceeds
 *                                 the whole capacity, or len exceeds what
 *                                 the 4-byte prefix can express. This
 *                                 datagram can NEVER be queued, no matter
 *                                 how much the reader drains.
 *   CLOAK_MSGQUEUE_ERR_FULL       it would fit in an empty queue but does
 *                                 not fit right now. Transient: draining
 *                                 makes room.
 *   CLOAK_MSGQUEUE_ERR_CLOSED     cloak_msgqueue_close has been called.
 *
 * len == 0 is accepted and enqueues a zero-length datagram, because Go
 * does (datagramBufferedPipe.go:89-91 appends len(f.Payload) whatever it
 * is). It is not reachable from either end of this port today --
 * cloak_frame_obfuscate refuses an empty payload, so no frame can carry
 * one -- and module 9's task 4 owns the decision about what the SENDER
 * does with a zero-length write. This function simply does not add a
 * second, contradictory policy one layer down.
 *
 * THE CAPACITY ARITHMETIC A CALLER MUST SATISFY, stated here because
 * getting it wrong turns into permanent single-datagram loss rather than
 * a visible failure: to be sure every frame this stream could legally
 * receive can be queued, cap must be at least max_payload_per_frame +
 * CLOAK_MSGQUEUE_LEN_PREFIX. cloak_stream_init already demands
 * recv_capacity >= max_on_wire_size - CLOAK_FRAME_HEADER_LEN, which is
 * max_payload_per_frame + CLOAK_FRAME_MAX_EXTRA_LEN (255) -- 251 bytes
 * more than this queue needs. That bound predates this file and was
 * imposed for the ordered path's identical concern ("too small to ever
 * hold this stream's own largest possible frame payload, which would
 * otherwise let a single oversized frame wedge the stream permanently");
 * it is reused rather than tightened so that the two modes cannot
 * disagree about which configurations are legal. */
int cloak_msgqueue_write(cloak_msgqueue_t *q, const uint8_t *msg, size_t len);

/* Dequeues the oldest datagram into out[0,out_cap), whole. Returns its
 * length (>= 0) on success, CLOAK_MSGQUEUE_EMPTY if no datagram is
 * queued, or CLOAK_MSGQUEUE_SHORT_BUFFER if out_cap is smaller than the
 * datagram at the head.
 *
 * ON SHORT_BUFFER THE DATAGRAM IS NOT CONSUMED, and that sentence is the
 * single most load-bearing line in this header. It is what Go does --
 * datagramBufferedPipe.go:58-60 returns io.ErrShortBuffer BEFORE :62 pops
 * pLens -- and it is not merely fidelity: an implementation that
 * discovered the buffer was too small only after popping would delete a
 * datagram that the reader never saw and never asked to discard.
 *
 * Go's own client then gets the layer ABOVE this wrong, which is why the
 * behaviour is worth naming rather than just implementing: piper.go:60
 * reads into a fixed 8192-byte buffer while the server writes up to
 * maxStreamUnitWrite (16132) per datagram, so a reply of 8193..16132
 * bytes returns io.ErrShortBuffer forever, the reader goroutine breaks on
 * the error, and the peer's stream is torn down with nothing reported to
 * the application. Measured against real ck-client/ck-server v2.12.0 in
 * the scouting report (§6.6, bug 6). Keeping the datagram queued is what
 * makes that a recoverable caller bug (read again with a big enough
 * buffer and the data is still there) instead of data loss, and
 * test_stream_unordered.c's short-buffer case asserts the second read
 * succeeds rather than merely asserting the error code -- a test that
 * only checked the code would pass against an implementation that
 * consumed it. */
long cloak_msgqueue_read(cloak_msgqueue_t *q, uint8_t *out, size_t out_cap);

/* Reports the length of the datagram at the head WITHOUT consuming it.
 * Returns 1 and stores the length in *out_len if one is queued, 0
 * otherwise (*out_len untouched). This is how a caller sizes its read
 * buffer correctly, i.e. how a caller avoids being Go's bug 6. */
int cloak_msgqueue_peek_len(const cloak_msgqueue_t *q, size_t *out_len);

size_t cloak_msgqueue_count(const cloak_msgqueue_t *q);

/* Queued bytes EXCLUDING the inline prefixes -- the number a caller
 * reasoning about how much application data is waiting actually wants.
 * The prefixes are this file's private overhead and deliberately do not
 * appear in it. */
size_t cloak_msgqueue_payload_bytes(const cloak_msgqueue_t *q);

/* Marks the queue closed: further writes fail with
 * CLOAK_MSGQUEUE_ERR_CLOSED, but already-queued datagrams stay readable
 * until drained. Idempotent. Matches Go's recvBuffer contract verbatim
 * (recvBuffer.go:12-16: "Read should NOT return error on a closed
 * streamBuffer with a non-empty buffer... Closure is only relevant when
 * the buffer is empty"). */
void cloak_msgqueue_close(cloak_msgqueue_t *q);

/* True once the queue is closed AND drained -- the end-of-stream
 * condition, and exactly Go's `d.closed && len(d.pLens) == 0`
 * (datagramBufferedPipe.go:38). */
int cloak_msgqueue_is_eof(const cloak_msgqueue_t *q);

#endif
