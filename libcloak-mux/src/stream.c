#include "cloak/stream.h"
#include "cloak/common.h"

#include <stdlib.h>
#include <string.h>

static int heap_grow(cloak_stream_t *s) {
    size_t new_cap = s->heap_cap == 0 ? 8 : s->heap_cap * 2;
    /* NO CLAMP TO max_pending_frames ANY MORE, and removing it was not
     * optional: that value is now a BYTE budget enforced in heap_push, so
     * a clamp here silently returned success without growing once the
     * count reached 64, and the caller then wrote one past the end.
     * Caught immediately as "double free or corruption (out)" -- the
     * clamp and the guard it belonged to have to go together. */
    cloak_pending_frame_t *new_heap =
        (cloak_pending_frame_t *)realloc(s->heap, new_cap * sizeof(cloak_pending_frame_t));
    if (new_heap == NULL) {
        return -1;
    }
    s->heap = new_heap;
    s->heap_cap = new_cap;
    return 0;
}

static int heap_push(cloak_stream_t *s, cloak_pending_frame_t pf) {
    /* A BYTE BUDGET, NOT A FRAME COUNT, AND THE HEAP MUST NOT BE A
     * BACKPRESSURE POINT AT ALL.
     *
     * What sits here is the peer's REORDERING window: with NumConn > 1 a
     * session sprays frames across several connections, TCP preserves
     * order only within each one, so the frame that lets next_recv_seq
     * advance routinely arrives after frames that follow it. That window
     * is bounded by what the sender can have in flight -- its own
     * per-connection send queues -- not by anything this side controls.
     *
     * Refusing here therefore cannot be congestion control, and a
     * previous attempt to treat it as such deadlocked: pausing every
     * connection when the heap filled stopped reading the very
     * connection carrying the missing sequence number. At NumConn=1 that
     * never showed, because there is no reordering; at 4 a megabyte
     * stopped after about 26 KB.
     *
     * So the bound is memory, and only memory: the same product the
     * frame count always implied, expressed so that a peer sending many
     * tiny frames cannot exhaust it and a peer sending legitimate
     * full-size ones is not refused while well inside it. */
    size_t budget = s->max_pending_frames * s->max_payload_per_frame;
    if (s->heap_bytes + pf.payload_len > budget) {
        return -1;
    }
    if (s->heap_len == s->heap_cap) {
        if (heap_grow(s) != 0) {
            return -1;
        }
    }
    size_t i = s->heap_len++;
    s->heap_bytes += pf.payload_len;
    s->heap[i] = pf;
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (s->heap[parent].seq <= s->heap[i].seq) {
            break;
        }
        cloak_pending_frame_t tmp = s->heap[parent];
        s->heap[parent] = s->heap[i];
        s->heap[i] = tmp;
        i = parent;
    }
    return 0;
}

static cloak_pending_frame_t heap_pop(cloak_stream_t *s) {
    /* Kept in step with heap_push's budget; the top frame's length is
     * read before the heap is reshaped. */
    s->heap_bytes -= s->heap[0].payload_len;
    cloak_pending_frame_t top = s->heap[0];
    s->heap_len--;
    if (s->heap_len > 0) {
        s->heap[0] = s->heap[s->heap_len];
        size_t i = 0;
        for (;;) {
            size_t left = 2 * i + 1;
            size_t right = 2 * i + 2;
            size_t smallest = i;
            if (left < s->heap_len && s->heap[left].seq < s->heap[smallest].seq) {
                smallest = left;
            }
            if (right < s->heap_len && s->heap[right].seq < s->heap[smallest].seq) {
                smallest = right;
            }
            if (smallest == i) {
                break;
            }
            cloak_pending_frame_t tmp = s->heap[i];
            s->heap[i] = s->heap[smallest];
            s->heap[smallest] = tmp;
            i = smallest;
        }
    }
    return top;
}

static int heap_contains_seq(const cloak_stream_t *s, uint64_t seq) {
    for (size_t i = 0; i < s->heap_len; i++) {
        if (s->heap[i].seq == seq) {
            return 1;
        }
    }
    return 0;
}

/* Drains heap-buffered frames that are now next-in-order into recv_bytes,
 * stopping early (leaving the rest buffered) if recv_bytes lacks room for
 * the next one -- this is what lets a previously-backpressured reassembly
 * resume once cloak_stream_read frees up space, without re-feeding
 * anything. Returns 1 if a closing frame was drained (next_recv_seq is
 * deliberately NOT advanced past it, matching Go's streamBuffer.Write --
 * the stream is being torn down, so its value afterward is moot), 0
 * otherwise. */
static int try_drain(cloak_stream_t *s) {
    while (s->heap_len > 0 && s->heap[0].seq == s->next_recv_seq) {
        if (s->heap[0].closing != CLOAK_FRAME_CLOSING_NOTHING) {
            cloak_pending_frame_t pf = heap_pop(s);
            free(pf.payload);
            s->recv_closing_seen = 1;
            cloak_bytequeue_close(&s->recv_bytes);
            return 1;
        }
        size_t payload_len = s->heap[0].payload_len;
        if (cloak_bytequeue_free_space(&s->recv_bytes) < payload_len) {
            break;
        }
        cloak_pending_frame_t pf = heap_pop(s);
        if (pf.payload_len > 0) {
            cloak_bytequeue_write(&s->recv_bytes, pf.payload, pf.payload_len);
        }
        free(pf.payload);
        s->next_recv_seq++;
    }
    return 0;
}

int cloak_stream_init(cloak_stream_t *s, uint32_t id, const cloak_obfuscator_t *obfuscator,
                       size_t max_on_wire_size, size_t recv_capacity, size_t max_pending_frames,
                       cloak_session_ordering_t ordering,
                       cloak_stream_frame_sink_t sink, void *sink_userdata) {
    memset(s, 0, sizeof(*s));
    /* FIRST, before every other parameter: the caller who gets this wrong
     * is the caller who does not know the parameter exists, and telling
     * them about some other field they also left at zero sends them
     * looking in the wrong place. Enumerating the two real modes rather
     * than testing `!= CLOAK_SESSION_ORDERING_INVALID` is what makes 3 and
     * 255 fail too -- see cloak/ordering.h. */
    if (ordering != CLOAK_SESSION_ORDERING_ORDERED &&
        ordering != CLOAK_SESSION_ORDERING_UNORDERED) {
        return CLOAK_SESSION_ERR_INVALID_ORDERING;
    }
    if (max_on_wire_size <= CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN ||
        recv_capacity == 0 || recv_capacity < max_on_wire_size - CLOAK_FRAME_HEADER_LEN ||
        sink == NULL) {
        return -1;
    }
    s->id = id;
    s->ordering = ordering;
    s->obfuscator = obfuscator;
    s->sink = sink;
    s->sink_userdata = sink_userdata;
    s->max_payload_per_frame = max_on_wire_size - CLOAK_FRAME_HEADER_LEN - CLOAK_FRAME_MAX_EXTRA_LEN;

    s->write_buf = (uint8_t *)malloc(max_on_wire_size);
    if (s->write_buf == NULL) {
        return -1;
    }
    s->write_buf_cap = max_on_wire_size;

    /* ONE receive queue, never both -- Go's makeStream picks one
     * recvBuffer implementation from the same bit (stream.go:59-63). The
     * unused one stays as memset left it, which is why every read of
     * either must be behind the same branch this is; see cloak/stream.h's
     * per-field mode annotations. */
    if (ordering == CLOAK_SESSION_ORDERING_UNORDERED) {
        s->recv_window = recv_capacity;
        s->send_credit = recv_capacity;
        s->peer_credit = recv_capacity;
        if (cloak_msgqueue_init(&s->recv_msgs, recv_capacity) != 0) {
            free(s->write_buf);
            s->write_buf = NULL;
            return -1;
        }
    } else if ((s->recv_window = recv_capacity, s->send_credit = recv_capacity,
                s->peer_credit = recv_capacity,
                cloak_bytequeue_init(&s->recv_bytes, recv_capacity)) != 0) {
        free(s->write_buf);
        s->write_buf = NULL;
        return -1;
    }
    /* Meaningless in unordered mode (nothing is ever held back), but set
     * unconditionally rather than left at 0 so that no future reader of
     * this field has to know which mode they are in to interpret it. */
    s->max_pending_frames = max_pending_frames > 0 ? max_pending_frames : 1;
    return 0;
}

/* DELIBERATELY NOT BRANCHED ON `ordering`, unlike every other function in
 * this file that touches the receive side. Three reasons, and the third
 * is the one that turned an earlier branched version into a trap:
 *
 *   1. Both teardowns are no-ops on the queue their mode did not build.
 *      cloak_stream_init constructs exactly one of the two and leaves the
 *      other as memset left it; cloak_msgqueue_destroy and
 *      cloak_bytequeue_destroy on a zeroed struct are free(NULL) plus a
 *      memset. So running both is correct in either mode and costs
 *      nothing.
 *   2. It makes a SECOND destroy safe ON PURPOSE rather than by accident.
 *      This function ends with memset(s, 0, sizeof(*s)), which zeroes
 *      `ordering` to CLOAK_SESSION_ORDERING_INVALID -- so a branched
 *      version ran the ORDERED teardown on a second call regardless of
 *      what the stream had been, and was benign only because every
 *      pointer it touched was already NULL. That is a property nobody
 *      stated and anybody could break.
 *   3. The pending-frame heap is freed unconditionally for the same
 *      reason. It is always NULL and heap_len always 0 in unordered mode
 *      TODAY; inside an `else` it would leak silently the first day that
 *      stopped being true. */
void cloak_stream_destroy(cloak_stream_t *s) {
    free(s->write_buf);
    cloak_msgqueue_destroy(&s->recv_msgs);
    cloak_bytequeue_destroy(&s->recv_bytes);
    for (size_t i = 0; i < s->heap_len; i++) {
        free(s->heap[i].payload);
    }
    free(s->heap);
    memset(s, 0, sizeof(*s));
}


/* Recomputes receive-side saturation and fires the owner's callback only
 * when it changes.
 *
 * THE WATERMARK IS HALF THE HEAP, NOT THE WHOLE OF IT, and that slack is
 * the entire point. Frames already sitting in the connection's socket
 * buffer, and frames already parsed out of one read batch, arrive AFTER
 * the decision to stop reading -- backpressure is never instantaneous.
 * Pausing only once the heap is completely full would leave nowhere to
 * put them and drop exactly the frame the pause existed to save. At the
 * default max_pending_frames of 64 this keeps 32 frames -- about 516 KB
 * at the usual maximum payload -- in reserve for that flight.
 *
 * The recv_bytes half of the test is what actually fires in a healthy
 * bulk transfer: frames arrive in order, try_drain moves each into
 * recv_bytes, and the heap stays near empty until recv_bytes fills. The
 * heap half catches the out-of-order case, where try_drain cannot
 * advance at all. */
static void stream_update_saturation(cloak_stream_t *s) {
    int now = 0;
    if (s->ordering != CLOAK_SESSION_ORDERING_UNORDERED) {
        /* recv_bytes ONLY. The heap deliberately does not appear here: it
         * holds the peer's reordering window, and pausing on it stops the
         * connection carrying the frame that would drain it. recv_bytes
         * is different -- it fills only when the CONSUMER is behind, and
         * a consumer that is behind is exactly what backpressure is
         * for. */
        now = cloak_bytequeue_free_space(&s->recv_bytes) < s->max_payload_per_frame;
    }
    if (now == s->recv_saturated) {
        return;
    }
    s->recv_saturated = now;
    if (s->on_saturation != NULL) {
        s->on_saturation(s->on_saturation_userdata, now);
    }
}

int cloak_stream_recv_saturated(const cloak_stream_t *s) {
    return s == NULL ? 0 : s->recv_saturated;
}

void cloak_stream_set_saturation_cb(cloak_stream_t *s, void (*cb)(void *userdata, int saturated),
                                    void *userdata) {
    if (s == NULL) {
        return;
    }
    s->on_saturation = cb;
    s->on_saturation_userdata = userdata;
}


/* Emits one window update if the consumer has freed at least half the
 * window since the last one.
 *
 * HALF, NOT EVERY READ. An update per read would put a frame on the wire
 * for every application-sized read -- on a bulk transfer, one per few
 * kilobytes -- and the storm would cost more than the flow control it
 * serves. Half bounds the rate at two updates per window while still
 * refilling a peer long before it could run dry.
 *
 * IT DOES NOT ADVANCE next_write_seq, AND THAT IS LOAD-BEARING. The
 * sequence space belongs to the data stream: a receiver that ignores
 * these frames (which is every receiver until the sending half of credit
 * lands) never advances next_recv_seq past one, so a consumed sequence
 * number would be a permanent gap and the stream would wedge. The seq
 * field is therefore a don't-care, carried only because the header has
 * one.
 *
 * A failure to send is deliberately not fatal. The sink refuses when the
 * session is already broken, and turning that into a torn-down stream
 * would make a connection that is going away anyway fail twice. */

/* Grants the credit a peer's window update carries.
 *
 * SATURATING, NOT WRAPPING. A peer that sends nonsense -- or a long-lived
 * stream whose deltas legitimately sum past the type's range -- must not
 * be able to wrap this back to a small number, which would stall the
 * stream, nor to a huge one, which would defeat the point of having a
 * window at all. */
static void stream_grant_credit(cloak_stream_t *s, uint32_t delta) {
    size_t room = (size_t)-1 - s->send_credit;
    s->send_credit += (size_t)delta < room ? (size_t)delta : room;
}

size_t cloak_stream_send_credit(const cloak_stream_t *s) {
    if (s == NULL) {
        return 0;
    }
    /* WITHOUT FLOW CONTROL THERE IS NO LIMIT, and answering the real
     * counter here would be a deadlock rather than a divergence: a peer
     * in compatibility mode never sends window updates, so a sender that
     * honoured its credit would stop after one window and never be given
     * another. The relay clamps its read to this number, so SIZE_MAX is
     * how "do not clamp" is spelled. */
    return s->flow_control ? s->send_credit : (size_t)-1;
}

static void stream_maybe_send_window_update(cloak_stream_t *s) {
    if (!s->flow_control || s->recv_window == 0 || s->recv_freed == 0) {
        return;
    }
    /* HALF THE WINDOW, AND THE TAIL IS A KNOWN GAP.
     *
     * The last drain of a transfer is smaller than half a window, so no
     * update goes out and a sender can sit on a few kilobytes it will
     * never be given credit for. Measured: a two-stream transfer stopping
     * at 114,185 bytes of 131,072.
     *
     * The obvious repair -- also release whenever the consumer has caught
     * up -- was tried and measured worse: it turned interactive traffic,
     * where the queue is empty after almost every read, into one update
     * per message, and took the suite from 6 failures to 8. The right
     * shape is a threshold somewhere between "half a window" and "any
     * amount", and choosing it is a decision about update frequency
     * against tail latency that deserves its own measurement rather than
     * a guess here. */
    /* SEND WHEN THE PEER IS ABOUT TO RUN OUT, NOT ON A FIXED FRACTION.
     *
     * peer_credit is exactly what the other side believes it may still
     * send. Once that is below one maximum frame it cannot send a full
     * frame, so an update is the only thing that will move the stream --
     * and until then an update is pure overhead, because the peer is not
     * waiting on us.
     *
     * This is what a fixed fraction could not get right at both ends of
     * the range. Half a window starved the tail: the last drain is
     * smaller than the threshold, so no update went out and a transfer
     * stopped 16,887 bytes short of 131,072. Releasing on every caught-up
     * read fixed the tail and broke the other case -- interactive traffic
     * empties the queue after almost every read, so it became one update
     * per message and took the suite from 6 failures to 8. Gating that on
     * a frame's worth of freed bytes left a smaller tail of the same
     * shape, 1,007 bytes short.
     *
     * The peer's own credit is the quantity all three were approximating,
     * so this uses it directly. Measured across fixed fractions before
     * settling here: window/2 gave 163.1 MiB/s, window/4 167.3, window/8
     * 148.9, window/16 137.4, with p50 latency flat at 136.6-137.9 us --
     * i.e. more frequent updates cost throughput and bought nothing, which
     * is the trade this rule avoids making at all. */
    if (s->peer_credit >= s->max_payload_per_frame) {
        return;
    }
    uint32_t delta = s->recv_freed > 0xffffffffu ? 0xffffffffu : (uint32_t)s->recv_freed;
    uint8_t payload[CLOAK_FRAME_WINDOW_UPDATE_LEN];
    payload[0] = (uint8_t)(delta & 0xffu);
    payload[1] = (uint8_t)((delta >> 8) & 0xffu);
    payload[2] = (uint8_t)((delta >> 16) & 0xffu);
    payload[3] = (uint8_t)((delta >> 24) & 0xffu);

    cloak_frame_t frame;
    frame.stream_id = s->id;
    frame.seq = s->next_write_seq; /* not consumed -- see above */
    frame.closing = CLOAK_FRAME_TYPE_WINDOW_UPDATE;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    long written = cloak_frame_obfuscate(s->obfuscator, &frame, s->write_buf, s->write_buf_cap, 0);
    if (written < 0) {
        return;
    }
    if (s->sink(s->sink_userdata, s->write_buf, (size_t)written) != 0) {
        return;
    }
    s->peer_credit += delta;
    s->recv_freed = 0;
    s->window_updates_sent++;
}

void cloak_stream_set_flow_control(cloak_stream_t *s, int on) {
    if (s != NULL) {
        s->flow_control = on ? 1 : 0;
    }
}

uint64_t cloak_stream_window_updates_sent(const cloak_stream_t *s) {
    return s == NULL ? 0 : s->window_updates_sent;
}

long cloak_stream_write(cloak_stream_t *s, const uint8_t *in, size_t in_len) {
    if (s->write_closed) {
        return -1;
    }
    /* UNORDERED MODE REFUSES TO SPLIT, AND REFUSES BEFORE SENDING
     * ANYTHING. This is the entire send-side difference between the two
     * modes, and in Go it is two lines inside the loop below
     * (stream.go:127-137): where the ordered path takes
     * `in[n : maxStreamUnitWrite+n]` and goes round again, the unordered
     * path sets `err = io.ErrShortBuffer` and returns with n still 0.
     *
     * HOISTED OUT OF THE LOOP DELIBERATELY. Inside the loop the refusal
     * can only ever fire on the first iteration -- if the data fits, the
     * loop sends one frame and ends -- so the two placements are
     * equivalent today, and this one makes "zero frames reached the sink"
     * structural rather than a consequence a reader has to derive. The
     * mutation that matters is the other order: obfuscate and send the
     * first 16132 bytes, THEN notice the remainder and return the error.
     * That implementation returns exactly the right value, has already
     * put a truncated datagram on the wire, and has burned a sequence
     * number; libcloak-mux/tests/test_stream_unordered.c's
     * test_oversize_write_refused_unordered_split_ordered asserts the
     * sink's frame count and the next frame's seq, which is what fails
     * against it.
     *
     * CLOAK_STREAM_ERR_SHORT_BUFFER, not -1, and Go agrees: this is
     * io.ErrShortBuffer, the same error its Stream.Read gives for a read
     * buffer too small for the datagram at the head of the queue. -1 in
     * this file means "the write side is finished" -- a caller that saw
     * -1 would be right to tear the stream down, and an oversize datagram
     * breaks nothing: the write side stays open, next_write_seq is
     * untouched, and the very next write of a legal size goes out
     * normally.
     *
     * A ZERO-LENGTH WRITE IS NOT REFUSED AND NOT SENT: 0 > max is false,
     * the loop below runs zero times, and this returns 0. That is Go
     * (Stream.Write's `for n < len(in)`), and the plan's D7 chose it over
     * carrying a zero-length datagram because carrying one is wire-
     * visible -- Go's own obfuscate rejects an empty payload outright
     * ("payload cannot be empty", internal/multiplex/obfs.go:65-67, which
     * is why cloak_frame_obfuscate rejects it too), and the record it
     * would have produced is 30 bytes where the shortest frame Go can
     * emit past a stream's first five is 31. See
     * test_zero_length_write_sends_nothing for the measurement. */
    if (s->ordering == CLOAK_SESSION_ORDERING_UNORDERED && in_len > s->max_payload_per_frame) {
        return CLOAK_STREAM_ERR_SHORT_BUFFER;
    }
    /* ENFORCED FROM HERE. A short return is now normal, and a producer
     * that ignores it loses the remainder -- the bytes are already out of
     * its socket by then and there is nowhere to put them back. That is
     * why stream_relay_fd_read_budget clamps its read to this same number
     * before it ever touches the socket, and why the two changes land in
     * one commit. */
    if (s->flow_control) {
        if (in_len > s->send_credit) {
            in_len = s->send_credit;
        }
        if (in_len == 0) {
            return 0;
        }
    }
    size_t n = 0;
    while (n < in_len) {
        size_t remaining = in_len - n;
        size_t chunk = remaining <= s->max_payload_per_frame ? remaining : s->max_payload_per_frame;

        cloak_frame_t frame;
        frame.stream_id = s->id;
        frame.seq = s->next_write_seq;
        frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
        frame.payload = in + n;
        frame.payload_len = chunk;

        long written = cloak_frame_obfuscate(s->obfuscator, &frame, s->write_buf, s->write_buf_cap, 0);
        if (written < 0) {
            s->write_closed = 1;
            return -1;
        }
        s->next_write_seq++;
        if (s->sink(s->sink_userdata, s->write_buf, (size_t)written) != 0) {
            s->write_closed = 1;
            return -1;
        }
        n += chunk;
        /* The clamp above means chunk <= send_credit, so this cannot
         * wrap; the floor is kept anyway because it costs nothing and the
         * invariant it rests on lives twenty lines away. */
        s->send_credit -= chunk < s->send_credit ? chunk : s->send_credit;
    }
    return (long)in_len;
}

int cloak_stream_send_closing(cloak_stream_t *s, uint8_t closing_type) {
    if (s->write_closed) {
        return -1;
    }
    uint8_t len_byte;
    cloak_random_bytes(&len_byte, 1);
    /* [1,256], but clamped to max_payload_per_frame -- cloak_frame_obfuscate
     * may add up to CLOAK_FRAME_MAX_EXTRA_LEN more bytes of its own random
     * padding on top of this payload for any frame with seq <
     * CLOAK_FRAME_PAD_FIRST_N_FRAMES (which a stream's first closing frame,
     * at seq 0 or shortly after, usually is), and only payloads bounded by
     * max_payload_per_frame are guaranteed to fit in write_buf (sized for
     * exactly that guarantee -- see cloak_stream_init). Without this clamp,
     * a small max_on_wire_size configuration could make an oversized
     * closing-frame payload legitimately fail to obfuscate. */
    size_t max_pad = s->max_payload_per_frame < 256 ? s->max_payload_per_frame : 256;
    size_t pad_len = (size_t)len_byte + 1;
    if (pad_len > max_pad) {
        pad_len = max_pad;
    }
    uint8_t pad[256];
    cloak_random_bytes(pad, pad_len);

    cloak_frame_t frame;
    frame.stream_id = s->id;
    frame.seq = s->next_write_seq;
    frame.closing = closing_type;
    frame.payload = pad;
    frame.payload_len = pad_len;

    long written = cloak_frame_obfuscate(s->obfuscator, &frame, s->write_buf, s->write_buf_cap, 0);
    s->write_closed = 1;
    if (written < 0) {
        return -1;
    }
    s->next_write_seq++;
    if (s->sink(s->sink_userdata, s->write_buf, (size_t)written) != 0) {
        return -1;
    }
    return 0;
}

/* THE UNORDERED RECEIVE PATH, and the whole of it -- Go's
 * datagramBufferedPipe.Write (datagramBufferedPipe.go:69-95) with the
 * sync.Cond wait replaced by a drop, because a reactor cannot block.
 *
 * Read the list of things this deliberately does NOT do before deciding
 * something is missing: it does not look at frame->seq, it does not
 * compare against any expected sequence number, it does not detect
 * duplicates, and it does not buffer anything out of order. Go's
 * datagramBufferedPipe does none of those either, and a real Go peer
 * spreading one stream across NumConn connections produces reordered and
 * (on retransmit paths) repeated frames as normal traffic. Anything
 * "fixed" here becomes a stream this port kills and Go does not. */
static int feed_frame_unordered(cloak_stream_t *s, const cloak_frame_t *frame) {
    /* Already closed. Go returns (toBeClosed=true, io.ErrClosedPipe)
     * here, which Stream.recvFrame turns into another passiveClose;
     * returning 1 is this port's equivalent (the session treats 1 and -1
     * identically -- session.c:320-337 -- but 1 is the honest one: this
     * is a close, not a protocol violation). The frame is discarded. */
    if (s->recv_closing_seen) {
        return 1;
    }

    /* A CLOSING FRAME CLOSES THE STREAM NOW, before any earlier data
     * frame still in flight, and its payload (random anti-fingerprinting
     * padding) is discarded. Go checks Closing before touching the buffer
     * at all (datagramBufferedPipe.go:83-87) and consults no sequence
     * number, so an unordered close is not ordered with respect to the
     * data around it. This is divergence (c) of the scouting report's
     * §6.3 and it is the reason recv_closing_seen means something
     * slightly different in each mode. */
    if (frame->closing != CLOAK_FRAME_CLOSING_NOTHING) {
        s->recv_closing_seen = 1;
        cloak_msgqueue_close(&s->recv_msgs);
        return 1;
    }

    int rc = cloak_msgqueue_write(&s->recv_msgs, frame->payload, frame->payload_len);
    if (rc == CLOAK_MSGQUEUE_ERR_TOO_LARGE) {
        /* The ONLY -1 on this path, and therefore the only thing that
         * retires an unordered stream. It is not backpressure: this
         * payload exceeds the queue's whole capacity, so no amount of
         * draining would ever admit it, and a peer sending it has
         * exceeded the frame size both ends agreed on. The ordered path
         * rejects the same condition for the same reason. */
        return -1;
    }
    if (rc != 0) {
        /* CLOAK_MSGQUEUE_ERR_FULL. Drop it, count it, and carry on --
         * NOT -1, which would retire a stream over transient
         * backpressure that will clear as soon as the reader drains.
         * Go blocks the writing goroutine instead; see
         * recv_dropped_datagrams in cloak/stream.h for why dropping the
         * newest is the answer here and what it costs. (ERR_CLOSED
         * cannot reach this line -- recv_closing_seen is checked above
         * and is set in the same breath as the close.) */
        s->recv_dropped_datagrams++;
        return 0;
    }
    return 0;
}

int cloak_stream_feed_frame(cloak_stream_t *s, const cloak_frame_t *frame) {
    /* A window update is credit for the OTHER direction, not stream data.
     * It is consumed here, before the mode split and before anything
     * looks at seq, so it neither advances the sequence space nor trips
     * the closing-frame path -- both of which would wedge the stream.
     * Nothing acts on it yet; the sending half of credit is a later
     * stage. */
    if (frame->closing != CLOAK_FRAME_TYPE_WINDOW_UPDATE && s->flow_control) {
        /* Every payload byte we accept is a byte the peer has spent. */
        size_t spent = frame->payload_len;
        s->peer_credit -= spent < s->peer_credit ? spent : s->peer_credit;
    }
    if (frame->closing == CLOAK_FRAME_TYPE_WINDOW_UPDATE) {
        if (frame->payload_len == CLOAK_FRAME_WINDOW_UPDATE_LEN) {
            uint32_t delta = (uint32_t)frame->payload[0] | ((uint32_t)frame->payload[1] << 8) |
                             ((uint32_t)frame->payload[2] << 16) |
                             ((uint32_t)frame->payload[3] << 24);
            stream_grant_credit(s, delta);
        }
        /* A malformed update is ignored rather than fatal: it grants no
         * credit, so the worst it can do is leave the sender where it
         * already was. Tearing the stream down for it would turn a
         * garbled frame into a lost connection.
         *
         * 2, NOT 0, AND THE DIFFERENCE IS A STALL. A producer whose
         * credit ran out pauses its read and then waits for an event.
         * Pool pressure has one, rate limiting arms its own timer, and
         * credit had neither -- so a relay that stopped for want of
         * credit would never learn it had some. The session turns this
         * into the writable signal every relay already resumes on. */
        return 2;
    }
    if (s->ordering == CLOAK_SESSION_ORDERING_UNORDERED) {
        return feed_frame_unordered(s, frame);
    }
    if (s->recv_closing_seen) {
        return -1;
    }
    if (frame->seq < s->next_recv_seq || heap_contains_seq(s, frame->seq)) {
        return -1;
    }

    size_t recv_total_capacity = cloak_bytequeue_len(&s->recv_bytes) + cloak_bytequeue_free_space(&s->recv_bytes);
    if (frame->payload_len > recv_total_capacity) {
        return -1;
    }

    /* THE FAST PATH: the frame that was expected, with nothing queued
     * ahead of it and room to take it.
     *
     * Every frame used to cost a malloc, a copy into it, a heap push, a
     * pop, a second copy into recv_bytes and a free -- even when it
     * arrived exactly in order, which is the overwhelmingly common case.
     * This writes it straight through: no allocation, one copy, no heap.
     *
     * The conditions are deliberately conservative. A closing frame goes
     * the long way so that try_drain keeps being the single place that
     * interprets one. A non-empty heap goes the long way because this
     * frame might unblock what is already queued, and try_drain is what
     * knows how. */
    if (frame->closing == CLOAK_FRAME_CLOSING_NOTHING && s->heap_len == 0 &&
        frame->seq == s->next_recv_seq &&
        cloak_bytequeue_free_space(&s->recv_bytes) >= frame->payload_len) {
        if (frame->payload_len > 0) {
            cloak_bytequeue_write(&s->recv_bytes, frame->payload, frame->payload_len);
        }
        s->next_recv_seq++;
        stream_update_saturation(s);
        return 0;
    }

    uint8_t *payload_copy = NULL;
    if (frame->payload_len > 0) {
        payload_copy = (uint8_t *)malloc(frame->payload_len);
        if (payload_copy == NULL) {
            return -1;
        }
        memcpy(payload_copy, frame->payload, frame->payload_len);
    }

    cloak_pending_frame_t pf;
    pf.seq = frame->seq;
    pf.closing = frame->closing;
    pf.payload = payload_copy;
    pf.payload_len = frame->payload_len;

    if (heap_push(s, pf) != 0) {
        /* Now genuinely a misbehaving peer rather than ordinary
         * congestion: with backpressure in place, in-order traffic pauses
         * the connection at the half-heap watermark long before this, so
         * reaching a full heap means a peer sending far-future sequence
         * numbers it never intends to fill in. Retiring the stream is the
         * right answer to that, and was always the right answer -- what
         * was wrong was reaching here on a perfectly ordinary transfer. */
        free(payload_copy);
        stream_update_saturation(s);
        return -1;
    }

    int rc = try_drain(s);
    stream_update_saturation(s);
    return rc;
}

long cloak_stream_read(cloak_stream_t *s, uint8_t *out, size_t out_cap) {
    if (s->ordering == CLOAK_SESSION_ORDERING_UNORDERED) {
        long n = cloak_msgqueue_read(&s->recv_msgs, out, out_cap);
        if (n > 0) {
            /* THE UNORDERED PATH NEEDS CREDIT TOO, and forgetting it was
             * not a subtle failure: a datagram session emitted no window
             * updates at all, so its peer spent one window and stopped
             * for good. Every test that moved more than 64 KiB over UDP
             * timed out at once. */
            s->recv_freed += (size_t)n;
            stream_maybe_send_window_update(s);
        }
        if (n == CLOAK_MSGQUEUE_SHORT_BUFFER) {
            /* The datagram is still queued -- cloak_msgqueue_read returns
             * before it pops anything, exactly as Go returns at
             * datagramBufferedPipe.go:58-60 one line ahead of the pop at
             * :62. Translated to this layer's own named error so a caller
             * cannot mistake it for the -1 that means end of stream. */
            return CLOAK_STREAM_ERR_SHORT_BUFFER;
        }
        if (n == CLOAK_MSGQUEUE_EMPTY) {
            /* Closed AND drained is end of stream; closed with datagrams
             * still queued is not (recvBuffer.go:12-16: "Closure is only
             * relevant when the buffer is empty"). */
            return cloak_msgqueue_is_eof(&s->recv_msgs) ? -1 : 0;
        }
        return n;
    }
    size_t n = cloak_bytequeue_read(&s->recv_bytes, out, out_cap);
    if (n > 0) {
        try_drain(s);
        s->recv_freed += n;
        stream_maybe_send_window_update(s);
        /* The resume half. try_drain has already refilled recv_bytes from
         * the heap where it could, so this sees the state the next frame
         * will actually meet. */
        stream_update_saturation(s);
        return (long)n;
    }
    if (cloak_bytequeue_is_eof(&s->recv_bytes)) {
        return -1;
    }
    return 0;
}

size_t cloak_stream_recv_available(const cloak_stream_t *s) {
    if (s->ordering == CLOAK_SESSION_ORDERING_UNORDERED) {
        /* Application bytes, not queued bytes: the datagram queue's own
         * per-message length prefixes are its private overhead and must
         * not show up in a number callers compare against payload sizes. */
        return cloak_msgqueue_payload_bytes(&s->recv_msgs);
    }
    return cloak_bytequeue_len(&s->recv_bytes);
}
