#ifndef CLOAK_CONN_H
#define CLOAK_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/bytequeue.h"
#include "cloak/reactor.h"
#include "cloak/valve.h"

/* Number of bytes in the length prefix this module adds around every
 * frame on the wire -- see this project's plan/design notes on why: in
 * short, cloak_frame_deobfuscate needs to know a frame's exact byte
 * length before it can decrypt anything (its header-decryption nonce is
 * the trailing bytes of the WHOLE frame), which a raw TCP byte stream
 * does not provide on its own. Big-endian u16, so max_frame_len must fit
 * in 16 bits (see cloak_conn_init). */
#define CLOAK_CONN_LEN_PREFIX_LEN 2

typedef struct cloak_conn cloak_conn_t;

/* bytes points at CLOAK_CONN_LEN_PREFIX_LEN-stripped frame data, valid
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
    size_t max_envelope_len; /* CLOAK_CONN_LEN_PREFIX_LEN + max_frame_len */

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
};

/* max_frame_len is the largest single frame's on-wire byte length this
 * connection will ever send or accept (must be 1..65535, since the
 * length prefix is a big-endian u16); a peer declaring a larger length
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

/* Frames frame_bytes[0, frame_len) with its length prefix and enqueues
 * it for transmission, attempting an immediate non-blocking write.
 * Returns 0 on success (accepted -- may still be partially buffered,
 * draining asynchronously via EPOLLWRITABLE), or -1 if c is already
 * broken, frame_len + CLOAK_CONN_LEN_PREFIX_LEN exceeds max_envelope_len,
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
