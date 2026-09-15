#ifndef CLOAK_CONN_H
#define CLOAK_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/bytequeue.h"
#include "cloak/reactor.h"
#include "cloak/valve.h"

/* Number of bytes in the TLS application-data RECORD HEADER this module
 * wraps around every frame on the wire:
 *
 *     0x17  ContentType application_data
 *     0x03  \ legacy_record_version = 0x0303, which is what a TLS 1.3
 *     0x03  / record carries on the wire
 *     hi    \ big-endian u16 length of the frame that follows
 *     lo    /
 *
 * IT SERVES TWO PURPOSES AT ONCE, and that is the whole point.
 *
 * (1) Framing. cloak_frame_deobfuscate must know a frame's exact byte
 *     length before it can decrypt anything -- its header-decryption
 *     nonce is the trailing bytes of the WHOLE frame -- and a raw TCP
 *     byte stream does not carry that. The last two header bytes supply
 *     it. Big-endian u16, so max_frame_len must fit in 16 bits (see
 *     cloak_conn_init).
 *
 * (2) Disguise. Cloak exists to make this connection look like an
 *     ordinary TLS session to a censor's DPI equipment. The handshake was
 *     always disguised on both sides (a real ClientHello record, a real
 *     ServerHello + ChangeCipherSpec + Certificate reply); the data path
 *     was NOT. It carried a bare big-endian u16 length prefix, whose
 *     first byte is 0x00 for every ordinary frame where TLS demands 0x17.
 *     A DPI box therefore saw a valid TLS handshake followed immediately
 *     by bytes that are not TLS records at all -- the disguise applied
 *     for one round trip and then dropped, which is a LOUDER fingerprint
 *     than no disguise at all. That was a real defect in this port, not a
 *     hypothetical: Go has always written this record header
 *     (common.TLSConn.Write, /Users/sam/Cloak/internal/common/tls.go),
 *     and this port had reinvented the length prefix on its own and kept
 *     only purpose (1). The five bytes below are what corrected it.
 *
 * DO NOT "optimise" these five bytes back down to two. The three constant
 * bytes are not overhead; they are the product's reason to exist.
 *
 * ON READ, THE TYPE AND VERSION BYTES ARE DELIBERATELY NOT VALIDATED.
 * The length is taken from bytes 3-4 and bytes 0-2 are skipped unread,
 * exactly as Go's common.TLSConn.Read does. This is not an oversight, and
 * it matters twice over:
 *
 *   - A peer that is FUSSIER than the reference implementation is itself
 *     a behavioural distinguisher. If this port rejected a record that
 *     cbeuw/Cloak would have accepted, a censor could tell the two apart
 *     by probing -- which is the same class of leak the record header
 *     itself exists to close.
 *   - The AEAD one layer up is the real authenticator. Every frame inside
 *     these records is sealed under the session key, so a forged or
 *     corrupted record is rejected there no matter what its first three
 *     bytes said. Checking them here would buy nothing that layer does
 *     not already provide.
 *
 * If you are about to add validation here, change the reference
 * implementation's behaviour deliberately or not at all --
 * libcloak-mux/tests/test_conn_record.c pins this leniency on purpose.
 *
 * RECORD LENGTH BOUND. The length field is 16 bits, so the hard ceiling
 * this port enforces is max_frame_len <= 65535 (see cloak_conn_init),
 * which is the bound the field itself imposes and the only one that can
 * cause a wire-format error. Two softer bounds exist above it and neither
 * is enforced here: Go's common.TLSConn.Write refuses a record payload
 * over 1<<14 + 256 == 16640 (RFC 8446 s5.2's ciphertext limit), and real
 * TLS 1.3 caps record PLAINTEXT at 2^14 == 16384. Every configuration in
 * this tree sits under both (max_on_wire_size is 16401), so the stricter
 * bounds would reject nothing that is actually configured while adding a
 * second place for the limit to drift out of step with cloak_conn_init's.
 * Be aware, though, that a deployment configuring max_frame_len above
 * 16640 would emit records the reference implementation itself would
 * refuse to write and that no real TLS stack produces -- a fingerprint in
 * its own right. The u16 ceiling is a correctness bound, not a mimicry
 * one. */
#define CLOAK_CONN_RECORD_HEADER_LEN 5

typedef struct cloak_conn cloak_conn_t;

/* bytes points at CLOAK_CONN_RECORD_HEADER_LEN-stripped frame data, valid
 * only for the duration of this call (it points into conn's own reused
 * scratch buffer) -- copy or fully consume before returning. */
typedef void (*cloak_conn_envelope_cb)(cloak_conn_t *conn, const uint8_t *bytes, size_t len, void *userdata);

/* Called exactly once, the moment conn becomes unusable (peer EOF, a
 * hard read/write error, a declared frame length that violates
 * max_frame_len, or the outbound send queue's hard capacity being
 * exceeded). conn's fd is already deregistered from the reactor by the
 * time this fires, but conn's own memory is NOT yet freed -- the owner
 * must still call cloak_conn_destroy (and separately close() the fd,
 * which conn never owns) once it's done reacting. */
typedef void (*cloak_conn_closed_cb)(cloak_conn_t *conn, void *userdata);

/* Fired when this connection's outbound queue transitions from holding
 * buffered bytes to holding none -- the moment a producer that stopped
 * writing because of backpressure may resume. NOT fired for a send the
 * kernel accepted outright (nothing was ever queued, so nothing
 * transitioned), and not fired repeatedly while the queue stays empty.
 *
 * Fired either from inside the reactor's writable dispatch for this
 * connection, or synchronously from inside a cloak_conn_send call that
 * itself completes the drain (a backpressured connection whose kernel
 * send buffer has freed up enough room by the time a caller sends again,
 * without ever going through the reactor in between) -- there is no
 * single fixed call context this callback runs in. It is safe to call
 * cloak_conn_send from within it; it is NOT safe to destroy the
 * connection from within it. */
typedef void (*cloak_conn_drained_cb)(cloak_conn_t *c, void *userdata);

struct cloak_conn {
    int fd;
    cloak_reactor_t *reactor;

    cloak_bytequeue_t recv_acc;
    cloak_bytequeue_t send_q;
    uint8_t *recv_scratch; /* owned, max_envelope_len bytes, reused per extracted envelope */

    size_t max_frame_len;
    size_t max_envelope_len; /* CLOAK_CONN_RECORD_HEADER_LEN + max_frame_len */

    cloak_conn_envelope_cb on_envelope;
    void *on_envelope_userdata;
    cloak_conn_closed_cb on_closed;
    void *on_closed_userdata;
    cloak_conn_drained_cb on_drained;
    void *on_drained_userdata;

    /* Borrowed, may be NULL ("this connection is not metered"). Owned by
     * the panel, never by this connection -- see cloak/valve.h. */
    cloak_valve_t *valve;

    int broken;
    int want_writable; /* whether EPOLLWRITABLE is currently part of our registered interest */

    /* 1 while READABLE has been dropped from the registered interest
     * because the valve's rx token bucket is empty. Unlike every other
     * pause in this codebase, nothing in the system will resume this one
     * -- only the clock will -- so it is never set without
     * rx_resume_timer being armed in the same breath. */
    int read_paused;
    cloak_timer_id_t rx_resume_timer; /* CLOAK_TIMER_INVALID when none is pending */

    uint32_t interest; /* the mask currently registered with the reactor */
};

/* max_frame_len is the largest single frame's on-wire byte length this
 * connection will ever send or accept (must be 1..65535, since the
 * record's length field is a big-endian u16); a peer declaring a larger length
 * is treated as a protocol violation (connection marked broken).
 * send_queue_cap is a generous, fixed hard cap on buffered-but-not-yet-
 * written outbound bytes; exceeding it is treated exactly like a
 * connection failure (see this project's plan-level fault-model
 * documentation -- this port intentionally does not retry a different
 * path the way it might for a pool of independent connections, because
 * a single conn's own backlog filling up means that link is stuck, same
 * as Go's blocking Write() would be).
 *
 * Registers fd with reactor for CLOAK_REACTOR_READABLE immediately (and
 * keeps it registered for the connection's whole life -- see this
 * project's plan-level notes on why recv-side backpressure is never
 * needed here). fd must already be an open, non-blocking-capable socket;
 * this function does not create or configure fd itself, matching
 * cloak_reactor_add_fd's own convention of forcing O_NONBLOCK itself
 * without the caller having to.
 *
 * Returns 0 on success, -1 on invalid parameters (max_frame_len == 0,
 * max_frame_len > 65535, or send_queue_cap == 0) or allocation/reactor
 * registration failure. */
int cloak_conn_init(cloak_conn_t *c, int fd, cloak_reactor_t *reactor,
                     size_t max_frame_len, size_t send_queue_cap,
                     cloak_conn_envelope_cb on_envelope, void *on_envelope_userdata,
                     cloak_conn_closed_cb on_closed, void *on_closed_userdata);

/* Deregisters fd from the reactor (safe even if already deregistered,
 * e.g. because on_closed already fired) and frees c's own buffers. Does
 * NOT close(fd) -- matching cloak_reactor_destroy's own documented
 * convention, the caller owns fd's lifecycle. */
void cloak_conn_destroy(cloak_conn_t *c);

/* Frames frame_bytes[0, frame_len) in a TLS application-data record
 * header (CLOAK_CONN_RECORD_HEADER_LEN -- see its own comment) and enqueues
 * it for transmission, attempting an immediate non-blocking write.
 * Returns 0 on success (accepted -- may still be partially buffered,
 * draining asynchronously via EPOLLWRITABLE), or -1 if c is already
 * broken, frame_len + CLOAK_CONN_RECORD_HEADER_LEN exceeds max_envelope_len,
 * or the send queue's hard capacity would be exceeded (in the last two
 * cases, on_closed fires synchronously, before this call returns). Must
 * not block. */
int cloak_conn_send(cloak_conn_t *c, const uint8_t *frame_bytes, size_t frame_len);

/* Installs (or, with cb == NULL, removes) the drained notification.
 * Separate from cloak_conn_init so existing callers keep compiling. */
void cloak_conn_set_drained_cb(cloak_conn_t *c, cloak_conn_drained_cb cb, void *userdata);

/* Points this connection at the valve that meters the user it belongs to
 * (v == NULL, the default, means unmetered). This connection counts only
 * the RX half there -- every byte it reads off its socket, framing
 * included -- because this is where those bytes first exist; the TX half
 * is counted by cloak_switchboard_send, which is where an outbound frame
 * is handed off. See cloak/valve.h for the direction convention and for
 * why the valve's lifetime is never this connection's to manage. Not
 * passed to cloak_conn_init so existing callers keep compiling. */
void cloak_conn_set_valve(cloak_conn_t *c, cloak_valve_t *v);

/* Bytes currently buffered for transmission, and the hard cap given to
 * cloak_conn_init. A producer should treat queued approaching capacity as
 * "stop producing": cloak_conn_send fails once a frame no longer fits,
 * and that failure is fatal to the whole pool, not just this connection. */
size_t cloak_conn_send_queued(const cloak_conn_t *c);
size_t cloak_conn_send_capacity(const cloak_conn_t *c);

/* Free space left in THIS connection's own send queue right now
 * (cloak_conn_send_capacity(c) - cloak_conn_send_queued(c)) -- exactly
 * how many more bytes cloak_conn_send could still enqueue on this one
 * connection before its own hard cap fires conn_mark_broken. NULL
 * reports 0. See cloak_switchboard_send_min_conn_free's own doc comment
 * for why a caller spreading writes across a pool via
 * cloak_switchboard_send needs the MINIMUM of this over the whole pool,
 * not the sum cloak_conn_send_capacity/_queued would otherwise suggest. */
size_t cloak_conn_send_free(const cloak_conn_t *c);

#endif
