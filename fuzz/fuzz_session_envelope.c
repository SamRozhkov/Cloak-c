/* TARGET #1: the session's inbound envelope path -- session.c's
 * session_on_envelope and the cloak_frame_deobfuscate/cloak_stream_feed_frame
 * machinery behind it, driven with CLOAK_AEAD_NONE and an all-zero session
 * key.
 *
 * THIS IS GO'S session_fuzz.go, WITH ONE DELIBERATE DIFFERENCE. Go's
 * setupSesh_fuzz builds a session with EncryptionMethodPlain and
 * [32]byte{}, and its Fuzz(data []byte) calls
 * sesh.recvDataFromRemote(data) ONCE per input. This target uses the same
 * cipher and the same key -- `plain` is a real, parseable configuration
 * (libcloak-common/src/config_client.c), not a fuzzing-only backdoor, so
 * everything found here is reachable by a real peer -- but it drives MANY
 * envelopes per input rather than one, with each envelope's length taken
 * from the input itself.
 *
 * THE MANY-ENVELOPES DECISION IS THE WHOLE POINT OF THIS TARGET, and it
 * is not a stylistic preference. A scouting run of this module did
 * 11,321,022 executions at 185,590/s against the four most-quoted parsers
 * in this tree and found nothing (READ from that scout's report, not
 * re-measured here), because those parsers are pure
 * functions over one buffer -- bounded memcmp and load_beNN, already
 * bounded and already tested. Everything interesting about THIS path is
 * state that only exists ACROSS calls:
 *
 *   - cloak_strmtab_t insertion and tombstoning (strmtab.c) as stream
 *     ids appear, retire and reappear;
 *   - the ordered mode's pending-frame binary heap (stream.c heap_push /
 *     heap_pop / heap_grow / heap_contains_seq), which reallocs as it
 *     grows 8 -> 16 -> 32 and which only ever reorders anything if
 *     several frames with different seq are buffered simultaneously;
 *   - try_drain's RESUMABLE drain -- it stops mid-heap when recv_bytes
 *     has no room and must pick up exactly where it left off on the next
 *     cloak_stream_read, which cannot happen at all inside a single call;
 *   - the unordered mode's cloak_msgqueue_t ring, whose head/tail
 *     arithmetic (three separate `% q->cap` in msgqueue.c) is only
 *     exercised once writes and reads have wrapped the ring, i.e. after
 *     several hundred bytes have passed through a 256-byte queue.
 *
 * A one-envelope-per-input target reaches none of that and would be
 * strictly weaker than libcloak-mux/tests/test_session.c, which at least
 * feeds sequences by hand.
 *
 * INPUT FORMAT, and why it is shaped for the mutator rather than for a
 * reader:
 *
 *     byte 0        : mode selector. Bit 0 chooses the session's ordering
 *                     (0 = ordered, 1 = unordered). Go's Fuzz hardcodes
 *                     `false` here; both of this port's two modes have
 *                     their own receive-side implementation and their own
 *                     state, so both are driven.
 *     then, repeated: one length byte L, followed by L envelope bytes.
 *                     A final L longer than the bytes remaining is
 *                     clamped to what is left, so no input byte is ever
 *                     ignored and truncating an input never changes the
 *                     meaning of the bytes before the truncation point.
 *
 * The length byte is what lets libFuzzer steer the SEQUENCE and not just
 * the bytes: a one-byte mutation re-splits the whole remainder of the
 * input into different envelopes, which is a move the mutator makes
 * constantly and which no fixed-size framing would give it.
 *
 * WHY A ONE-BYTE LENGTH, AND WHAT IT DOES AND DOES NOT COVER.
 * cloak_conn_t refuses any inbound frame longer than its max_frame_len
 * before session_on_envelope ever sees it (conn.c:175 for the
 * TLS-record path, conn.c:328 and :412 for the WebSocket one), and
 * max_frame_len is this session's max_on_wire_size. This target
 * configures the SMALLEST max_on_wire_size cloak_session_init accepts
 * (CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 1 = 270), so a
 * single length byte covers 0..255 of the 0..270 a real connection could
 * deliver. That 256..270 band is a genuine gap and it is stated here
 * rather than glossed, but it gates nothing: the only length-sensitive
 * branch above 255 is cloak_stream_feed_frame's
 * `frame->payload_len > recv_total_capacity` (and the unordered path's
 * CLOAK_MSGQUEUE_ERR_TOO_LARGE), and BOTH are unreachable from ANY
 * envelope length, at any configuration, by the constructor's own
 * arithmetic rather than by anything chosen here:
 *
 *     cloak_session_init requires
 *         stream_recv_capacity >= max_on_wire_size - CLOAK_FRAME_HEADER_LEN
 *     and cloak_frame_deobfuscate requires
 *         extra_len >= tag_len_for_method(CLOAK_AEAD_NONE) == 8
 *     so a delivered payload is at most
 *         max_on_wire_size - CLOAK_FRAME_HEADER_LEN - 8
 *     which is 8 bytes BELOW the capacity it is compared against, always.
 *
 * Those two checks are therefore defensive code, not paths this or any
 * other target can exercise through the real entry point -- and that is
 * worth knowing before someone widens this harness's length field hoping
 * to reach them. (Derived from the code, not measured: no test asserts
 * it, and writing one would mean calling cloak_stream_feed_frame
 * directly with a hand-built cloak_frame_t, below the layer this target
 * drives.)
 *
 * THE CONFIGURATION IS THE TIGHTEST ONE THE CONSTRUCTOR ACCEPTS, on
 * purpose. Every bound in this file is a minimum rather than a
 * production value, because a bound that is never approached is a bound
 * that is never tested: 270/256 puts the receive queue two large frames
 * from full, so try_drain's backpressure break and its later resumption
 * are ordinary events here instead of once-in-a-corpus ones, and
 * max_pending_frames of 32 is three doublings from heap_grow's initial 8
 * AND low enough that heap_push's `heap_len >= max_pending_frames`
 * refusal is reachable within one input.
 *
 * WHY THE CALL GOES THROUGH sesh.sb.on_envelope. session_on_envelope is
 * `static`; this is the one call in the tree that reaches it without
 * either a socket or a #include of the .c file, and it is not a
 * workaround -- it is byte-for-byte the call switchboard.c:79 makes
 * (`sb->on_envelope(sb, bytes, len, sb->on_envelope_userdata)`) after a
 * cloak_conn_t has stripped the transport framing. Standing up a real
 * socketpair and a real cloak_conn_t would add TLS-record or WebSocket
 * parsing above the code under test, two syscalls per envelope, and
 * nothing else; those layers are other tasks' targets.
 *
 * MEMORY OWNERSHIP, which is the one thing a leak-checking fuzz target
 * has to get exactly right, because LeakSanitizer reports a harness leak
 * and a library leak identically. Per cloak/session.h, a stream's memory
 * is freed ONLY by cloak_session_release_stream -- retiring one (peer
 * close, protocol violation) does not free it, and cloak_session_destroy
 * reclaims only streams that are still ACTIVE when it runs. So this
 * harness records every stream on_new_stream hands it and releases every
 * one of them before cloak_session_destroy. Releasing FIRST is required,
 * not tidy: cloak_session_destroy frees the still-active ones itself, so
 * releasing after it would be a double free of exactly those.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "cloak/frame.h"
#include "cloak/ordering.h"
#include "cloak/reactor.h"
#include "cloak/session.h"
#include "cloak/stream.h"

/* The minimum cloak_session_init accepts: it rejects
 * max_on_wire_size <= CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN,
 * and then requires stream_recv_capacity >= max_on_wire_size -
 * CLOAK_FRAME_HEADER_LEN. Written as the expressions rather than as 270
 * and 256 so that a change to either macro moves this harness with it
 * instead of silently making it invalid. */
#define FUZZ_MAX_ON_WIRE (CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 1)
#define FUZZ_RECV_CAPACITY (FUZZ_MAX_ON_WIRE - CLOAK_FRAME_HEADER_LEN)
#define FUZZ_MAX_PENDING 32
#define FUZZ_SEND_QUEUE_CAP 4096

/* One envelope buffer, sized by the format's own one-byte length. */
#define FUZZ_MAX_ENVELOPE 255

/* The read buffer deliberately SMALLER than one maximum datagram, so that
 * cloak_stream_read's CLOAK_STREAM_ERR_SHORT_BUFFER branch (unordered
 * mode) and cloak_bytequeue_read's partial reads (ordered mode) are the
 * common case rather than a corner. The retry buffer below is what
 * actually drains the too-large datagram, so nothing stalls. */
#define FUZZ_READ_BUF 64

/* An input can at most create one stream per envelope, and an envelope
 * costs at least one byte, so this is a hard ceiling for any input
 * libFuzzer is configured to produce (-max_len=4096 in this target's
 * documented run command). Should an input ever exceed it, the excess
 * streams are released immediately inside the callback -- which
 * cloak_session_new_stream_cb explicitly permits -- rather than dropped,
 * because dropping one would be a harness leak reported as a finding. */
#define FUZZ_MAX_STREAMS 4096

typedef struct {
    cloak_stream_t *streams[FUZZ_MAX_STREAMS];
    size_t nstreams;
} fuzz_ctx_t;

/* Drains everything currently readable. This is not decoration: in
 * ordered mode, try_drain only ever resumes a backpressured reassembly
 * from inside cloak_stream_read, so a harness that never reads never
 * exercises the resumption at all and leaves the heap permanently full
 * after the first two large frames. */
static void fuzz_drain(cloak_stream_t *stream) {
    for (;;) {
        uint8_t small[FUZZ_READ_BUF];
        long n = cloak_stream_read(stream, small, sizeof(small));
        if (n == CLOAK_STREAM_ERR_SHORT_BUFFER) {
            /* Unordered mode, datagram larger than `small`. The datagram
             * is still queued (cloak_msgqueue_read returns before it
             * pops); read it with a buffer that certainly fits, which
             * is the whole queue capacity. */
            uint8_t big[FUZZ_RECV_CAPACITY];
            n = cloak_stream_read(stream, big, sizeof(big));
            if (n <= 0) {
                return;
            }
            continue;
        }
        if (n <= 0) {
            return; /* 0 = nothing available, -1 = end of stream */
        }
    }
}

static void fuzz_on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    fuzz_ctx_t *ctx = (fuzz_ctx_t *)userdata;
    fuzz_drain(stream);
    if (ctx->nstreams == FUZZ_MAX_STREAMS) {
        cloak_session_release_stream(sesh, stream);
        return;
    }
    ctx->streams[ctx->nstreams++] = stream;
}

static void fuzz_on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    (void)userdata;
    fuzz_drain(stream);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    cloak_reactor_t *reactor = cloak_reactor_create();
    if (reactor == NULL) {
        return 0; /* out of fds -- nothing to test, and not a finding */
    }

    static fuzz_ctx_t ctx; /* static only because 32 KiB of stream pointers is
                            * more than belongs on libFuzzer's stack; zeroed
                            * explicitly below, never carried between inputs. */
    memset(&ctx, 0, sizeof(ctx));

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* EncryptionMethodPlain and [32]byte{}: the memset above is the zero
     * key, and CLOAK_AEAD_NONE is 0. Spelled out anyway, because a key
     * this target depends on being zero should not be readable only as
     * the absence of a line. */
    cfg.obfuscator.method = CLOAK_AEAD_NONE;
    memset(cfg.obfuscator.session_key, 0, sizeof(cfg.obfuscator.session_key));
    cfg.ordering = (data[0] & 1u) ? CLOAK_SESSION_ORDERING_UNORDERED
                                  : CLOAK_SESSION_ORDERING_ORDERED;
    cfg.max_on_wire_size = FUZZ_MAX_ON_WIRE;
    cfg.stream_recv_capacity = FUZZ_RECV_CAPACITY;
    cfg.stream_max_pending_frames = FUZZ_MAX_PENDING;
    cfg.conn_send_queue_cap = FUZZ_SEND_QUEUE_CAP;
    /* Long enough that the inactivity timer is never due. Nothing here
     * ever runs the reactor's dispatch loop, so no timer can fire in any
     * case -- this target drives the envelope path directly, exactly as
     * a connection's read callback would, and timer-driven teardown is a
     * different target's subject. */
    cfg.inactivity_timeout_ms = 3600000;
    cfg.on_new_stream = fuzz_on_new_stream;
    cfg.on_new_stream_userdata = &ctx;
    cfg.on_stream_data = fuzz_on_stream_data;
    cfg.on_stream_data_userdata = &ctx;

    cloak_session_t sesh;
    if (cloak_session_init(&sesh, 0, reactor, &cfg) != 0) {
        cloak_reactor_destroy(reactor);
        return 0;
    }

    size_t pos = 1;
    while (pos < size) {
        size_t len = data[pos++];
        size_t remaining = size - pos;
        if (len > remaining) {
            len = remaining;
        }
        /* A COPY, and it is required rather than cautious:
         * cloak_frame_deobfuscate decrypts the header IN PLACE, so the
         * buffer it is handed must be writable. libFuzzer's `data` is
         * const and is reused across executions -- mutating it would
         * corrupt the mutator's own corpus entry and make findings
         * unreproducible. This copy is also what a real cloak_conn_t
         * hands over: its reused recv_scratch, not the socket's bytes. */
        uint8_t envelope[FUZZ_MAX_ENVELOPE];
        if (len > 0) {
            memcpy(envelope, data + pos, len);
        }
        pos += len;
        sesh.sb.on_envelope(&sesh.sb, envelope, len, sesh.sb.on_envelope_userdata);
    }

    /* Release before destroy -- see the ownership note at the top. */
    for (size_t i = 0; i < ctx.nstreams; i++) {
        cloak_session_release_stream(&sesh, ctx.streams[i]);
    }
    cloak_session_destroy(&sesh);
    cloak_reactor_destroy(reactor);
    return 0;
}
