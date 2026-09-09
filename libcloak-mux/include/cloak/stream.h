#ifndef CLOAK_STREAM_H
#define CLOAK_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/frame.h"
#include "cloak/bytequeue.h"

/* Returns 0 on success (bytes accepted for transmission -- the connection
 * layer may still buffer them internally), or -1 on a hard failure (the
 * underlying connection is broken), mirroring Go Cloak's
 * switchboard.send()'s error contract. Must not block. */
typedef int (*cloak_stream_frame_sink_t)(void *userdata, const uint8_t *bytes, size_t len);

typedef struct {
    uint64_t seq;
    uint8_t closing;
    uint8_t *payload; /* owned copy, malloc'd (NULL iff payload_len == 0) */
    size_t payload_len;
} cloak_pending_frame_t;

/* One multiplexed logical stream's framing state: chunks outbound bytes
 * into frames (obfuscating and handing each to a caller-supplied sink),
 * and reassembles inbound frames (received out of order, since a session
 * spreads one stream's frames across multiple underlying connections) back
 * into an ordered byte stream via a sequence-number min-heap -- the
 * single-threaded, non-blocking equivalent of Go Cloak's
 * Stream+streamBuffer+streamBufferedPipe. Unlike Go, nothing here ever
 * blocks: cloak_stream_read returns 0 immediately if no data is ready yet
 * (never blocks waiting for it), and cloak_stream_feed_frame never blocks
 * on backpressure -- see its own doc comment. */
typedef struct {
    uint32_t id;

    const cloak_obfuscator_t *obfuscator; /* not owned -- must outlive the stream */
    cloak_stream_frame_sink_t sink;
    void *sink_userdata;

    size_t max_payload_per_frame;
    uint8_t *write_buf; /* owned scratch buffer for obfuscate() output */
    size_t write_buf_cap;
    uint64_t next_write_seq;
    int write_closed;

    cloak_bytequeue_t recv_bytes;
    uint64_t next_recv_seq;
    cloak_pending_frame_t *heap; /* owned, binary min-heap by .seq */
    size_t heap_len;
    size_t heap_cap;
    size_t max_pending_frames; /* defensive cap on out-of-order buffering */
    int recv_closing_seen;     /* a closing frame has been drained into order */
} cloak_stream_t;

/* max_on_wire_size is the same quantity as Go's SessionConfig.MsgOnWireSizeLimit
 * (the full framed-and-encrypted size budget per frame, e.g. 1<<14+256);
 * this function derives the actual per-frame payload budget from it the
 * same way Go's Session does (accounting for the frame header and the
 * worst-case padding/AEAD overhead).
 *
 * recv_capacity is the reassembled-byte-queue's fixed capacity (Go's
 * streamBufferedPipe has no real cap in practice -- 1<<31-1 -- because Go
 * relies on blocking a goroutine for backpressure instead; this port uses
 * a real, finite capacity and non-blocking backpressure signaling instead,
 * matching this project's reactor-driven design).
 *
 * max_pending_frames bounds how many out-of-order frames may be buffered
 * awaiting a gap-filling frame, as a defensive measure against unbounded
 * memory growth from adversarial frame reordering (Go's implementation has
 * no such cap).
 *
 * Returns 0 on success, -1 on allocation failure or invalid parameters
 * (max_on_wire_size too small to fit a header, recv_capacity == 0). */
int cloak_stream_init(cloak_stream_t *s, uint32_t id, const cloak_obfuscator_t *obfuscator,
                       size_t max_on_wire_size, size_t recv_capacity, size_t max_pending_frames,
                       cloak_stream_frame_sink_t sink, void *sink_userdata);

void cloak_stream_destroy(cloak_stream_t *s);

/* Chunks in[0,in_len) into one or more frames (each up to
 * max_payload_per_frame bytes), obfuscates and hands each to the sink, in
 * order. On success returns in_len (all bytes were chunked and handed off
 * -- matching Go's Stream.Write, which never partially writes in ordered
 * mode). Returns -1 if the stream's write side is already closed, or if
 * an obfuscate/sink call fails partway through (some frames may already
 * have reached the sink in this case -- the stream should be considered
 * broken and torn down by the caller, exactly as a mid-write failure in
 * Go leaves the stream in an unusable state). */
long cloak_stream_write(cloak_stream_t *s, const uint8_t *in, size_t in_len);

/* Sends a single closing-only frame (CLOAK_FRAME_CLOSING_STREAM or
 * CLOAK_FRAME_CLOSING_SESSION) using the stream's next write sequence
 * number, with a random 1-256 byte padding payload, clamped to
 * max_payload_per_frame (matching Go's anti-fingerprinting closing-frame
 * construction -- a closing frame must not be reliably distinguishable in
 * size from a data frame, and cloak_frame_obfuscate requires a nonzero
 * payload; the clamp guarantees this payload always fits in write_buf
 * alongside cloak_frame_obfuscate's own additional random padding, the
 * same guarantee cloak_stream_init's sizing already provides for ordinary
 * data frames). Marks the stream's write side closed. Returns 0 on
 * success, -1 on failure. */
int cloak_stream_send_closing(cloak_stream_t *s, uint8_t closing_type);

/* Delivers one already-deobfuscated incoming frame for reassembly. The
 * frame's payload is only ever read during this call (deep-copied if it
 * can't be delivered immediately) -- frame->payload need not remain valid
 * after this call returns, matching cloak_frame_deobfuscate's contract
 * that payload points into a caller-owned buffer.
 *
 * This never blocks and never drops a frame silently for lack of space:
 * every accepted frame is deep-copied into an internal reorder buffer
 * (bounded by max_pending_frames) and drained into the readable byte queue
 * as space allows -- so backpressure shows up as slower draining (check
 * cloak_stream_recv_available), not as rejected frames, except for the
 * defensive max_pending_frames cap itself.
 *
 * Returns 0 (accepted, delivered and/or buffered for reassembly), 1 (a
 * closing frame was drained into order -- the caller should tear this
 * stream down after this call), or -1 (protocol violation: frame->seq is
 * a duplicate/already-delivered sequence number, the out-of-order buffer's
 * max_pending_frames cap was exceeded, or an allocation failure). */
int cloak_stream_feed_frame(cloak_stream_t *s, const cloak_frame_t *frame);

/* Copies up to out_cap reassembled bytes into out. Returns bytes copied
 * (0 if none are ready yet -- not an error, just "nothing to read right
 * now"), or -1 once the stream has both seen a closing frame drain into
 * order AND fully delivered every byte before it (end of stream). Calling
 * this after a previous -1 return continues to return -1. */
long cloak_stream_read(cloak_stream_t *s, uint8_t *out, size_t out_cap);

size_t cloak_stream_recv_available(const cloak_stream_t *s);

#endif
