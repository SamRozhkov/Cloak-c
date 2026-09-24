#ifndef CLOAK_STREAM_H
#define CLOAK_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/frame.h"
#include "cloak/bytequeue.h"
#include "cloak/msgqueue.h"
#include "cloak/ordering.h" /* cloak_session_ordering_t, CLOAK_SESSION_ERR_INVALID_ORDERING */

/* Returns 0 on success (bytes accepted for transmission -- the connection
 * layer may still buffer them internally), or -1 on a hard failure (the
 * underlying connection is broken), mirroring Go Cloak's
 * switchboard.send()'s error contract. Must not block.
 *
 * bytes is valid only for the duration of this call -- cloak_stream_write
 * reuses the same internal scratch buffer for every frame it obfuscates,
 * so the sink must fully copy or fully consume bytes before returning;
 * retaining the pointer past this call (e.g. for a later batched write)
 * will read overwritten/corrupted data. */
typedef int (*cloak_stream_frame_sink_t)(void *userdata, const uint8_t *bytes, size_t len);

typedef struct {
    uint64_t seq;
    uint8_t closing;
    uint8_t *payload; /* owned copy, malloc'd (NULL iff payload_len == 0) */
    size_t payload_len;
} cloak_pending_frame_t;

/* One multiplexed logical stream's framing state: chunks outbound bytes
 * into frames (obfuscating and handing each to a caller-supplied sink),
 * and turns inbound frames back into something readable. Unlike Go,
 * nothing here ever blocks: cloak_stream_read returns 0 immediately if no
 * data is ready yet (never blocks waiting for it), and
 * cloak_stream_feed_frame never blocks on backpressure -- see its own doc
 * comment.
 *
 * THE RECEIVE SIDE IS TWO DIFFERENT MACHINES AND `ordering` PICKS WHICH,
 * exactly as Go's makeStream picks between two recvBuffer implementations
 * from one bit (stream.go:59-63). Every field below is annotated with the
 * mode it belongs to, because roughly half of them are dead in either
 * mode and a reader who does not know that will look for bugs in the
 * wrong half:
 *
 *   ORDERED    heap + next_recv_seq + recv_bytes. Frames are sorted by
 *              sequence number into a gap-free byte stream; an
 *              out-of-order frame waits in the min-heap until its
 *              predecessors arrive. Go's streamBuffer wrapping a
 *              streamBufferedPipe.
 *   UNORDERED  recv_msgs alone. No sequence state at all, no heap, no
 *              duplicate check: one frame in is one whole datagram out,
 *              immediately, in arrival order, duplicates included. Go's
 *              datagramBufferedPipe.
 *
 * The two never both run: cloak_stream_init constructs only the queue its
 * mode uses, and cloak_stream_destroy tears down only that one. */
typedef struct {
    uint32_t id;

    /* The mode of the session that owns this stream, copied in at
     * construction. Never CLOAK_SESSION_ORDERING_INVALID on a constructed
     * stream. A stream cannot disagree with its session about this: every
     * stream this session ever creates -- locally opened or discovered by
     * an inbound frame -- is initialised from the one value the session
     * stored at cloak_session_init, and nothing writes it afterwards. See
     * cloak/ordering.h for what the two modes mean. */
    cloak_session_ordering_t ordering;

    const cloak_obfuscator_t *obfuscator; /* not owned -- must outlive the stream */
    cloak_stream_frame_sink_t sink;
    void *sink_userdata;

    size_t max_payload_per_frame;
    uint8_t *write_buf; /* owned scratch buffer for obfuscate() output */
    size_t write_buf_cap;
    uint64_t next_write_seq;
    int write_closed;

    cloak_bytequeue_t recv_bytes;     /* ORDERED only -- zeroed and unused when UNORDERED */
    uint64_t next_recv_seq;           /* ORDERED only */
    cloak_pending_frame_t *heap;      /* ORDERED only: owned, binary min-heap by .seq */
    size_t heap_len;                  /* ORDERED only */
    size_t heap_cap;                  /* ORDERED only */
    size_t max_pending_frames;        /* ORDERED only: defensive cap on out-of-order buffering */
    /* ORDERED only: bytes of payload currently on the heap. The cap is a
     * BYTE budget (max_pending_frames * max_payload_per_frame) rather
     * than a frame count, because the heap's occupancy is the peer's
     * reordering window and a count cannot tell one 16 KB frame from one
     * 16-byte frame. See heap_push. */
    size_t heap_bytes;

    cloak_msgqueue_t recv_msgs;       /* UNORDERED only -- zeroed and unused when ORDERED */

    /* UNORDERED only. Datagrams dropped because recv_msgs was full when
     * they arrived, i.e. the count of this port's one deliberate,
     * declared divergence from Go on the receive path: Go's
     * datagramBufferedPipe blocks the writing goroutine until the reader
     * makes room (datagramBufferedPipe.go:72-81), which a single-threaded
     * reactor cannot do, so a full queue drops the NEWEST datagram
     * instead. Dropping the newest rather than the oldest is the plan's
     * Ruling 2: nothing already accepted is ever discarded, which is what
     * a full socket receive buffer does and what a UDP application is
     * already written against. The counter exists because a silent drop
     * with no evidence is the thing that makes packet loss
     * un-diagnosable; it is not read by anything in the mux layer, and is
     * here for the relays (module 9 tasks 5 and 6) and for tests. A drop
     * is NOT an error: cloak_stream_feed_frame still returns 0, because
     * returning -1 would retire a stream over transient backpressure. */
    uint64_t recv_dropped_datagrams;

    /* ORDERED only: receive-side backpressure.
     *
     * The unordered comment above states this port's deliberate
     * divergence -- Go blocks the writer, a single-threaded reactor
     * cannot, so a full datagram queue drops the newest. For DATAGRAMS
     * that is defensible: a UDP application is already written against
     * loss. The ORDERED path inherited the same shape and it is NOT
     * defensible there, because a gap in the sequence can never be
     * filled: once one frame is dropped, next_recv_seq can never advance
     * past it and every later frame sits on the heap forever. Measured,
     * not argued: a 1 MiB transfer through the full stack stopped dead at
     * 606,569 bytes with `heap_len=64 max=64 recv_len=59392
     * recv_free=6144` and never moved again in 80 seconds of pumping.
     *
     * The premise "a single-threaded reactor cannot block the writer" is
     * true only of BLOCKING. It can stop READING, which is what TCP
     * backpressure is for and what these two fields drive: the stream
     * reports when it can no longer accept a maximum-size frame, the
     * session counts how many of its streams say so, and the switchboard
     * drops READABLE from every connection until they drain. */
    int recv_saturated;
    void (*on_saturation)(void *userdata, int saturated);
    void *on_saturation_userdata;

    /* BOTH modes, with subtly different meanings. ORDERED: a closing
     * frame has been drained INTO ORDER (it reached next_recv_seq).
     * UNORDERED: a closing frame has ARRIVED, full stop -- there is no
     * order for it to reach. The difference is divergence (c) of the
     * scouting report's §6.3 and it is observable: in unordered mode a
     * closing frame closes the stream before an earlier data frame that
     * is still in flight, which is what Go does
     * (datagramBufferedPipe.go:83-87 sets closed the moment the frame
     * lands, without consulting any sequence number). */
    int recv_closing_seen;
} cloak_stream_t;

/* max_on_wire_size is the same quantity as Go's SessionConfig.MsgOnWireSizeLimit
 * (the full framed-and-encrypted size budget per frame, e.g. 1<<14+256);
 * this function derives the actual per-frame payload budget from it the
 * same way Go's Session does (accounting for the frame header and the
 * worst-case padding/AEAD overhead).
 *
 * IN UNORDERED MODE recv_capacity SIZES THE DATAGRAM QUEUE INSTEAD and
 * max_pending_frames IS IGNORED ENTIRELY (there is no out-of-order
 * buffering to bound -- nothing is ever held back). The recv_capacity
 * bound below is deliberately left exactly as it is for both modes even
 * though the datagram queue's true requirement is 251 bytes laxer (see
 * cloak_msgqueue_write): one rule about which configurations are legal,
 * so the two modes cannot disagree about it, and so a session that
 * validated its capacity once at cloak_session_init does not have to
 * revalidate per mode.
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
 * no such cap). max_pending_frames also bounds the CPU cost of feeding each
 * frame (the duplicate-detection scan is O(max_pending_frames)) -- an
 * attacker who can arrange deep reordering pays for it linearly in this
 * cap, not unboundedly, but this is a real per-frame cost to weigh when
 * choosing the value, not just a memory bound.
 *
 * ordering is the owning session's mode, and is a PARAMETER here for a
 * reason that does not apply one layer up: this is a function, so a call
 * site that predates the mode does not compile at all -- there is no
 * zeroed struct to forget a field in. The trap that matters is on
 * cloak_session_config_t (cloak/ordering.h says why); this parameter's job
 * is only to make it impossible to construct a stream that disagrees with
 * its session, and to reject the zero value at this layer too so that the
 * session is not the single point holding the invariant up.
 *
 * sink must be non-NULL (rejected with -1 otherwise). max_pending_frames
 * == 0 is silently treated as 1 (a minimum of one out-of-order frame can
 * always be buffered) rather than rejected.
 *
 * Returns 0 on success, CLOAK_SESSION_ERR_INVALID_ORDERING if ordering is
 * not one of the two real modes (checked FIRST, before any other
 * parameter), and -1 on allocation failure or invalid parameters
 * (max_on_wire_size too small to fit a header, recv_capacity == 0, or
 * recv_capacity smaller than max_on_wire_size - CLOAK_FRAME_HEADER_LEN --
 * too small to ever hold this stream's own largest possible frame
 * payload, which would otherwise let a single oversized frame wedge the
 * stream permanently). */
/* Whether this stream can no longer accept a maximum-size frame. Always 0
 * in unordered mode, which drops rather than backpressures on purpose --
 * see recv_dropped_datagrams. */
int cloak_stream_recv_saturated(const cloak_stream_t *s);

/* Fires ONLY on a change, with the new value, so the owner can keep a
 * count rather than rescan. Set before the stream carries any traffic. */
void cloak_stream_set_saturation_cb(cloak_stream_t *s, void (*cb)(void *userdata, int saturated),
                                    void *userdata);

int cloak_stream_init(cloak_stream_t *s, uint32_t id, const cloak_obfuscator_t *obfuscator,
                       size_t max_on_wire_size, size_t recv_capacity, size_t max_pending_frames,
                       cloak_session_ordering_t ordering,
                       cloak_stream_frame_sink_t sink, void *sink_userdata);

void cloak_stream_destroy(cloak_stream_t *s);

/* ORDERED: chunks in[0,in_len) into one or more frames (each up to
 * max_payload_per_frame bytes), obfuscates and hands each to the sink, in
 * order. On success returns in_len (all bytes were chunked and handed off
 * -- matching Go's Stream.Write, which never partially writes in ordered
 * mode). Returns -1 if the stream's write side is already closed, or if
 * an obfuscate/sink call fails partway through (some frames may already
 * have reached the sink in this case -- the stream should be considered
 * broken and torn down by the caller, exactly as a mid-write failure in
 * Go leaves the stream in an unusable state).
 *
 * UNORDERED: THERE IS NO CHUNKING. One write is one datagram is one
 * frame, and a write LARGER than max_payload_per_frame is REFUSED with
 * CLOAK_STREAM_ERR_SHORT_BUFFER, having sent nothing at all -- not a
 * partial write, not a split, no sequence number consumed, and the write
 * side left open and usable. Go: `if s.session.Unordered { err =
 * io.ErrShortBuffer; return }` with n still 0 (stream.go:127-137).
 * Splitting would be silent corruption in this mode, because the far end
 * is a datagramBufferedPipe that does no reassembly: two frames arrive as
 * two datagrams, and the application reads half a message.
 *
 * WHERE THE BOUNDARY IS, and why it is not a number this header invents:
 * max_payload_per_frame is max_on_wire_size - CLOAK_FRAME_HEADER_LEN -
 * CLOAK_FRAME_MAX_EXTRA_LEN, exactly Go's maxStreamUnitWrite
 * (session.go:111). With the 16401 both ck-client and ck-server use
 * (appDataMaxLength, internal/client/TLS.go:11) that is 16401 - 14 - 255
 * = 16132, and 16133 is the first size refused. MEASURED against
 * unmodified upstream v2.12.0 at that configuration -- 16132 -> one frame
 * on the wire, 16133 -> zero frames and io.ErrShortBuffer, and the same
 * 16133 in ordered mode -> two frames -- and asserted here by
 * libcloak-mux/tests/test_stream_unordered.c's
 * test_oversize_write_refused_unordered_split_ordered, which pins the
 * derivation, both return values AND the frame counts.
 *
 * in_len == 0 returns 0 and sends nothing, in BOTH modes. See
 * test_zero_length_write_sends_nothing for why this port does not carry a
 * zero-length datagram even though it deliberately carries the 8193..16132
 * range Go loses: Go's frame encoder refuses an empty payload outright
 * (obfs.go:65-67), so the frame would be one no Go peer ever emits, and
 * its 30-byte record is a length no Go Cloak produces. That is the
 * "wire-visible" exception the plan's D7 wrote in. */
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
 * (That paragraph describes ORDERED mode. In UNORDERED mode there is no
 * reorder buffer and no deep copy at all: the payload is copied straight
 * into the datagram queue if it fits and DROPPED if it does not -- see
 * recv_dropped_datagrams, and cloak_msgqueue_write for why a drop is the
 * only non-blocking answer available.)
 *
 * Returns 0 (accepted, delivered and/or buffered for reassembly), 1 (a
 * closing frame -- the caller should tear this stream down after this
 * call), or -1 (protocol violation).
 *
 * WHAT -1 MEANS DIFFERS BY MODE, AND THIS IS THE SHARPEST EDGE IN THE
 * WHOLE FILE, because cloak_session_on_envelope reacts to a -1 by
 * RETIRING the stream (libcloak-mux/src/session.c:320-337 and :393-396:
 * `if (rc == 1 || rc == -1) session_retire_stream(...)`). A return value
 * is therefore a decision to kill a stream, not a diagnostic.
 *
 *   ORDERED    -1 for: a duplicate or already-delivered frame->seq, a
 *              frame->payload_len exceeding the receive queue's total
 *              capacity (can never fit, regardless of current free
 *              space), the max_pending_frames cap being exceeded, or an
 *              allocation failure. Unchanged by module 9; the
 *              duplicate-kills-the-stream behaviour is a deliberate,
 *              documented improvement over Go, and test_stream.c pins it
 *              (verified by mutation: deleting the heap_contains_seq
 *              half of stream.c's check fails test_stream).
 *
 *              WHAT GO ACTUALLY DOES, corrected. An earlier version of
 *              this paragraph said Go "has no error path there at all".
 *              THAT WAS FALSE. streamBuffer.Write
 *              (internal/multiplex/streamBuffer.go:65-97) has exactly
 *              one, at :79-81 -- `if f.Seq < sb.nextRecvSeq { return
 *              false, fmt.Errorf("seq %v is smaller than nextRecvSeq
 *              %v", ...) }` -- so an ALREADY-DELIVERED seq is an error
 *              in Go too, and the real divergence is narrower than the
 *              comment claimed: it is the PENDING duplicate, a seq at or
 *              above nextRecvSeq that is already sitting in Go's sorter
 *              heap. Go has no check for that one, and this port does
 *              (stream.c: `frame->seq < s->next_recv_seq ||
 *              heap_contains_seq(s, frame->seq)`).
 *
 *              AND THAT GAP IS GO BUG #10, REPRODUCED, NOT READ.
 *              streamBuffer.go:86 pushes the second copy onto the heap
 *              and the drain loop at :88 stops the moment
 *              sh[0].Seq != nextRecvSeq -- but nextRecvSeq has by then
 *              moved PAST the stale copy, so the head of the heap can
 *              never match again. The stream wedges permanently and the
 *              heap grows without bound. Measured against the reference
 *              tree at cbeuw/Cloak c3d5470 with a Go test driving
 *              NewStreamBuffer directly: frames seq 1, 1, 0 leave
 *              nextRecvSeq at 2 with a stale seq 1 at the heap's head;
 *              1000 further in-order frames then leave nextRecvSeq STILL
 *              2 and the heap at 1001 entries, and the reader sees only
 *              the two bytes that drained before the wedge and then a
 *              read deadline. It is reachable from a peer:
 *              Session.recvDataFromRemote -> Stream.recvFrame
 *              (stream.go:72) hands every deobfuscated frame straight to
 *              streamBuffer.Write, so an authenticated peer that repeats
 *              one pending frame wedges that stream and grows the
 *              process heap for as long as it keeps sending. Retiring
 *              the stream, as this port does, is the strictly safer
 *              answer and costs nothing our own sender can trip: it
 *              never duplicates a frame.
 *   UNORDERED  -1 ONLY for a frame->payload_len that exceeds the datagram
 *              queue's total capacity. Nothing else: a duplicate seq, a
 *              late seq, a seq that skips ahead, a full queue -- all
 *              return 0. THE DUPLICATE CASE IS THE ONE THAT MATTERS. Our
 *              own sender never duplicates a frame, so every C-to-C test
 *              in this tree agrees with itself either way; a real Go peer
 *              spreading one stream over NumConn connections reorders as
 *              a matter of course, and Go's datagramBufferedPipe accepts
 *              every one of those frames. Keeping the ordered path's
 *              duplicate check here would retire a stream that Go keeps
 *              alive, over traffic Go considers normal. See the scouting
 *              report's §6.3, divergences (b), (c) and (d): all three
 *              route through this single return value.
 *
 * Note: in ORDERED mode a closing frame that arrives out of order may not
 * drain immediately -- if it's buffered because earlier frames are still
 * missing, or if draining is backpressured, the close is only detected
 * later, when cloak_stream_read internally re-attempts the drain. A
 * caller must therefore also treat cloak_stream_read's own -1
 * (end-of-stream) return as a close signal, not rely solely on this
 * function ever returning 1. In UNORDERED mode the 1 is immediate and
 * unconditional -- a closing frame closes the stream on arrival, ahead of
 * any earlier data frame still in flight, and that earlier frame is then
 * discarded (this function returns 1 again for it, matching Go's
 * datagramBufferedPipe.Write returning toBeClosed on a closed pipe,
 * datagramBufferedPipe.go:73-75). Datagrams that arrived BEFORE the close
 * stay readable until drained; only the close-then-data order loses
 * data, and it loses it in Go too. */
int cloak_stream_feed_frame(cloak_stream_t *s, const cloak_frame_t *frame);

/* UNORDERED-only, and returned by BOTH directions -- Go uses one error,
 * io.ErrShortBuffer, for both, and so does this port:
 *
 *   cloak_stream_read   out_cap was smaller than the datagram at the head
 *                       of the queue. THE DATAGRAM IS STILL QUEUED --
 *                       call again with a buffer of at least that many
 *                       bytes and it is still there
 *                       (datagramBufferedPipe.go:58-60).
 *   cloak_stream_write  in_len exceeded max_payload_per_frame, so the
 *                       datagram could not be sent without splitting it.
 *                       NOTHING WAS SENT (stream.go:127-137).
 *
 * The two are the same shape -- "your buffer and this datagram are the
 * wrong sizes for each other, nothing has been consumed, try again" --
 * which is why one value carries both.
 *
 * A DISTINCT VALUE RATHER THAN -1 because -1 already means end of stream,
 * and those two call for opposite reactions: EOF means stop reading this
 * stream forever, short buffer means read it again with a bigger buffer.
 * Go distinguishes them (io.EOF versus io.ErrShortBuffer) and its own
 * client still conflates them in effect -- piper.go's reader goroutine
 * breaks out of its loop on ANY error, which is why a reply of 8193..16132
 * bytes silently tears the peer's tunnel down (scouting report §6.6, bug
 * 6, measured against ck-client v2.12.0). -2 rather than -1 is what lets
 * this port's relays not repeat that.
 *
 * -2 specifically, following CLOAK_CONN_ERR_INVALID_FRAMING and
 * CLOAK_SESSION_ERR_INVALID_ORDERING: in this tree a second named
 * negative on an existing -1 contract is -2.
 *
 * EVERY CALLER OF cloak_stream_read MUST HANDLE THIS SEPARATELY FROM -1,
 * and this paragraph exists because the two that already shipped did not.
 * Adding a third negative to a function whose callers were written
 * against "negative means the stream is over" made both of them reproduce
 * Go's bug 6:
 *
 *   libcloak-mux/src/stream_relay.c  read into a buffer sized by the free
 *       space in its outbound queue, so ordinary backpressure shrank it
 *       below the next datagram and PERMANENTLY ENDED A LIVE STREAM. Now
 *       treats a short buffer as backpressure, except when its queue is
 *       already empty (nothing could ever free more room), where it ends
 *       the stream deliberately rather than wedging.
 *   libcloak-server/src/adminapi.c   read 4096-byte chunks against
 *       datagrams of up to 16132 and tore the stream down with no answer
 *       to the client. Its chunk is now 16384 -- above the largest
 *       datagram any session at the shipping max_on_wire_size can produce
 *       -- and a short buffer has its own named branch.
 *
 * A new caller that writes `if (n < 0)` and stops there is correct for an
 * ordered stream and silently loses data on an unordered one. There is no
 * compiler check for this; there is only this paragraph and the two tests
 * named above, each of which fails if its -2 arm is folded back in. */
#define CLOAK_STREAM_ERR_SHORT_BUFFER (-2)

/* ORDERED: copies up to out_cap reassembled bytes into out. Returns bytes
 * copied (0 if none are ready yet -- not an error, just "nothing to read
 * right now"), or -1 once the stream has both seen a closing frame drain
 * into order AND fully delivered every byte before it (end of stream).
 * Calling this after a previous -1 return continues to return -1.
 *
 * UNORDERED: copies exactly ONE whole datagram and returns its length --
 * never part of one, never two concatenated. Boundaries are preserved end
 * to end: three writes of 1, 1500 and 8191 bytes come back as three reads
 * of exactly 1, 1500 and 8191. Returns 0 if no datagram is queued yet, -1
 * at end of stream (closed AND drained -- queued datagrams outlive the
 * close), or CLOAK_STREAM_ERR_SHORT_BUFFER if out_cap is too small for
 * the datagram at the head, WITHOUT consuming it.
 *
 * ONE DELIBERATE DIVERGENCE FROM GO, in unordered mode only: out_cap == 0
 * with a datagram queued returns CLOAK_STREAM_ERR_SHORT_BUFFER, where
 * Go's Stream.Read short-circuits `if len(buf) == 0 { return 0, nil }`
 * before ever reaching its recvBuffer (stream.go:83-85). Go's answer
 * makes a zero-length read indistinguishable from "nothing to read",
 * which on a non-blocking reactor is an invitation to spin; ours reports
 * the truth. It is not wire-visible, no caller in this tree passes 0, and
 * saying so here is cheaper than a reader later finding the difference
 * and assuming it is a bug. */
long cloak_stream_read(cloak_stream_t *s, uint8_t *out, size_t out_cap);

/* Readable APPLICATION bytes waiting: ORDERED, reassembled bytes in the
 * byte queue; UNORDERED, the total payload of all queued datagrams (the
 * queue's own per-datagram length prefixes are not counted -- see
 * cloak_msgqueue_payload_bytes). In unordered mode this is a
 * backpressure number, not a read size: a caller sizing a read buffer
 * wants the NEXT datagram's length, which is what a short-buffer return
 * from cloak_stream_read tells it to go and find. */
size_t cloak_stream_recv_available(const cloak_stream_t *s);

#endif
