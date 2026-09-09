#include "cloak/stream.h"
#include "cloak/common.h"

#include <stdlib.h>
#include <string.h>

static int heap_grow(cloak_stream_t *s) {
    size_t new_cap = s->heap_cap == 0 ? 8 : s->heap_cap * 2;
    if (new_cap > s->max_pending_frames) {
        new_cap = s->max_pending_frames;
    }
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
    if (s->heap_len >= s->max_pending_frames) {
        return -1;
    }
    if (s->heap_len == s->heap_cap) {
        if (heap_grow(s) != 0) {
            return -1;
        }
    }
    size_t i = s->heap_len++;
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
                       cloak_stream_frame_sink_t sink, void *sink_userdata) {
    memset(s, 0, sizeof(*s));
    if (max_on_wire_size <= CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN ||
        recv_capacity == 0 || recv_capacity < max_on_wire_size - CLOAK_FRAME_HEADER_LEN ||
        sink == NULL) {
        return -1;
    }
    s->id = id;
    s->obfuscator = obfuscator;
    s->sink = sink;
    s->sink_userdata = sink_userdata;
    s->max_payload_per_frame = max_on_wire_size - CLOAK_FRAME_HEADER_LEN - CLOAK_FRAME_MAX_EXTRA_LEN;

    s->write_buf = (uint8_t *)malloc(max_on_wire_size);
    if (s->write_buf == NULL) {
        return -1;
    }
    s->write_buf_cap = max_on_wire_size;

    if (cloak_bytequeue_init(&s->recv_bytes, recv_capacity) != 0) {
        free(s->write_buf);
        s->write_buf = NULL;
        return -1;
    }
    s->max_pending_frames = max_pending_frames > 0 ? max_pending_frames : 1;
    return 0;
}

void cloak_stream_destroy(cloak_stream_t *s) {
    free(s->write_buf);
    cloak_bytequeue_destroy(&s->recv_bytes);
    for (size_t i = 0; i < s->heap_len; i++) {
        free(s->heap[i].payload);
    }
    free(s->heap);
    memset(s, 0, sizeof(*s));
}

long cloak_stream_write(cloak_stream_t *s, const uint8_t *in, size_t in_len) {
    if (s->write_closed) {
        return -1;
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

int cloak_stream_feed_frame(cloak_stream_t *s, const cloak_frame_t *frame) {
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
        free(payload_copy);
        return -1;
    }

    return try_drain(s);
}

long cloak_stream_read(cloak_stream_t *s, uint8_t *out, size_t out_cap) {
    size_t n = cloak_bytequeue_read(&s->recv_bytes, out, out_cap);
    if (n > 0) {
        try_drain(s);
        return (long)n;
    }
    if (cloak_bytequeue_is_eof(&s->recv_bytes)) {
        return -1;
    }
    return 0;
}

size_t cloak_stream_recv_available(const cloak_stream_t *s) {
    return cloak_bytequeue_len(&s->recv_bytes);
}
