#ifndef CLOAK_CONN_H
#define CLOAK_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/bytequeue.h"
#include "cloak/reactor.h"
#include "cloak/valve.h"
#include "cloak/ws_frame.h"

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
 * RECORD LENGTH BOUND: see CLOAK_CONN_MAX_FRAME_LEN below. */
#define CLOAK_CONN_RECORD_HEADER_LEN 5

/* The largest record body this connection will send or accept, ENFORCED
 * by cloak_conn_init (and, eagerly, by cloak_session_init).
 *
 * 1<<14 + 256 == 16640 is the ciphertext limit RFC 8446 s5.2 puts on a
 * TLS 1.3 record, and it is exactly the bound Go's common.TLSConn.Write
 * refuses to exceed ("message is too long",
 * /Users/sam/Cloak/internal/common/tls.go). Real TLS 1.3 caps record
 * PLAINTEXT lower still, at 2^14 == 16384; the +256 is the headroom the
 * RFC allows a record's own encryption overhead.
 *
 * THIS IS A MIMICRY BOUND, WHICH IS WHY IT IS ENFORCED RATHER THAN
 * DOCUMENTED. The length field is 16 bits, so purely as a matter of
 * wire-format correctness anything up to 65535 would encode; an earlier
 * revision of this header enforced only that and described 16641..65535
 * as a window to be aware of. It is not merely a window to be aware of,
 * because it is REACHABLE: cloak_session_config_t::max_on_wire_size is
 * operator-supplied and is handed to cloak_conn_init as max_frame_len
 * unchanged, so nothing else in the stack stood between a configuration
 * file and a record no TLS stack on earth emits. One oversized record is
 * a single-probe distinguisher, in the one product whose entire purpose
 * is not being distinguishable -- so the configuration is rejected at
 * construction, where an operator gets an error, rather than at runtime,
 * where a censor gets a fingerprint.
 *
 * It does not drift, and that is why one constant can safely serve all
 * THREE of the validators that enforce it. 16640 is a wire-format
 * constant fixed by RFC 8446 and by the reference implementation, not a
 * local policy someone might retune; cloak_conn_init enforces it,
 * cloak_session_init checks max_on_wire_size against THIS macro before
 * there is a conn to construct, and cloak_switchboard_init checks the
 * max_frame_len it forwards -- each reading the macro rather than a
 * literal of its own, so they cannot disagree. (An earlier revision of
 * this paragraph said "two validators" and missed the switchboard, which
 * was at that moment still rejecting only > 65535: a header asserting
 * that drift is impossible while drift is present makes the resulting
 * behaviour harder to diagnose, not easier.) Every configuration in this
 * tree uses 16401, comfortably inside it.
 *
 * COMPATIBILITY NOTE, for anyone upgrading rather than deploying fresh:
 * this bound is NEW, and it is narrower than what shipped before. These
 * three functions previously accepted max_frame_len / max_on_wire_size up
 * to 65535, so a configuration anywhere in 16641..65535 that used to
 * start will now fail construction -- cloak_session_init returns -1 -- 
 * rather than quietly emitting records no TLS stack produces. The fix is
 * to lower max_on_wire_size to 16640 or below; 16401 is this project's
 * usual value. Deliberate, and preferred over the alternative, which was
 * shipping a single-probe distinguisher in a circumvention tool. */
#define CLOAK_CONN_MAX_FRAME_LEN 16640

/* WHICH FRAMING THIS CONNECTION PUTS AROUND A MUX FRAME.
 *
 * READ THE 46-LINE COMMENT AT THE TOP OF THIS FILE FIRST. It describes a
 * defect this port shipped for five modules: a two-byte length prefix
 * where Go writes a five-byte TLS application-data record header, so the
 * TLS mimicry held for exactly one round trip and then stopped. This enum
 * is THE EXACT INVERSE OF THAT DEFECT, and it is a trap in both
 * directions.
 *
 *   - On the CDN path the TLS record header must NOT be there. Go's
 *     WSOverTLS (internal/client/websocket.go:16-19 -- NOT
 *     internal/common/websocket.go, which an earlier version of this
 *     comment named, and which holds the WebSocketConn it wraps) embeds
 *     a *common.WebSocketConn, itself a thin binary-message wrapper
 *     around gorilla's *websocket.Conn
 *     (internal/common/websocket.go:14-28). There is no TLSConn anywhere
 *     in that chain: the real TLS session lives OUTSIDE the WebSocket,
 *     between this host and the CDN, and supplies its own records. A conn left in TLS_RECORD mode on a WebSocket connection
 *     emits 0x17 0x03 0x03 <len> INSIDE a WebSocket binary frame. That is
 *     wire-incompatible with Go -- the far end feeds those five bytes to
 *     a deobfuscator and fails -- and to anyone who can see inside the
 *     CDN's TLS (the CDN itself, always; a censor who has compelled it,
 *     sometimes) it is a perfect Cloak signature: nobody else puts a TLS
 *     record inside a WebSocket message.
 *   - WS framing leaking onto the direct path re-creates the original
 *     defect in a new costume: a censor's DPI box sees a valid TLS
 *     handshake followed by 0x82, which is not a TLS record either.
 *
 * AND THE WRONG CHOICE IS INVISIBLE TO EVERY ROUND-TRIP TEST, BECAUSE
 * BOTH ENDS AGREE. A C-to-C test passes identically whichever framing
 * both of its conns use. The only test that can see the difference is one
 * that reads raw bytes off a socket and compares them to a literal from
 * the RFC; libcloak-mux/tests/test_conn_ws_framing.c is that test, and
 * its first three cases exist for exactly this reason.
 *
 * ZERO IS DELIBERATELY INVALID, AND IT IS A FIELD RATHER THAN A
 * PARAMETER FOR THAT REASON. A mode passed only as an argument has no
 * zero value unless a caller types one, so it protects nothing; a mode
 * that is a field of cloak_conn_config_t has one on every memset, which
 * is how every struct in this tree is initialised. A zeroed or
 * partially-filled config therefore FAILS CONSTRUCTION with
 * CLOAK_CONN_ERR_INVALID_FRAMING instead of silently picking a default --
 * which is the one mechanical defence here that does not depend on
 * anybody remembering anything.
 *
 * The client/server split is RFC 6455 section 5.1 and is not negotiable
 * in either direction: a client MUST mask every frame it sends, a server
 * MUST NOT mask any, and each side rejects the other's mistake (gorilla
 * reports "bad MASK"; every browser does the same). The same rule is
 * enforced on RECEIPT -- an unmasked frame arriving at a WS_SERVER conn,
 * or a masked one arriving at a WS_CLIENT conn, breaks the connection. */
typedef enum {
    CLOAK_CONN_FRAMING_INVALID    = 0, /* deliberate: an un-updated call site FAILS */
    CLOAK_CONN_FRAMING_TLS_RECORD = 1, /* the direct path: CLOAK_CONN_RECORD_HEADER_LEN bytes */
    CLOAK_CONN_FRAMING_WS_CLIENT  = 2, /* CDN path, our end is the client: masks on send */
    CLOAK_CONN_FRAMING_WS_SERVER  = 3  /* CDN path, our end is the server: never masks on send */
} cloak_conn_framing_t;

/* The return value of every constructor on this path when framing is
 * CLOAK_CONN_FRAMING_INVALID or outside the enum. Distinct from the -1
 * that reports every other construction failure so that a caller -- and,
 * more to the point, a test -- can assert the specific diagnosis rather
 * than "something went wrong": a test that accepted any non-zero return
 * would pass unchanged against an implementation that never looked at
 * framing at all. Propagated verbatim by cloak_switchboard_add_conn_framed
 * and cloak_session_add_conn_framed. */
#define CLOAK_CONN_ERR_INVALID_FRAMING (-2)

typedef struct cloak_conn cloak_conn_t;

/* bytes points at framing-stripped frame data -- the record body on the
 * TLS path, the fully reassembled and unmasked payload of one WebSocket
 * BINARY message on the CDN path -- valid only for the duration of this
 * call (it points into conn's own reused scratch buffer); copy or fully
 * consume before returning.
 *
 * One WebSocket message is exactly one mux frame and nothing else, which
 * is why a fragmented message is reassembled before it reaches here
 * rather than delivered a fragment at a time: switchboard.deplex hands
 * whatever it receives straight to a deobfuscator that requires one whole
 * frame. Control frames (ping/pong/close) never reach this callback. */
typedef void (*cloak_conn_envelope_cb)(cloak_conn_t *conn, const uint8_t *bytes, size_t len, void *userdata);

/* Called exactly once, the moment conn becomes unusable (peer EOF, a
 * hard read/write error, a declared frame length that violates
 * max_frame_len, or the outbound send queue's hard capacity being
 * exceeded).
 *
 * On the WebSocket path this additionally covers every RFC 6455
 * protocol violation the peer can commit -- a malformed header, a frame
 * masked the wrong way for its direction, a CONTINUATION with no message
 * in progress, a reassembled message exceeding max_frame_len -- and a
 * CLOSE frame, which is an orderly hang-up rather than a fault but
 * reaches the owner through the same one callback, because from this
 * layer's point of view the connection is equally over.
 *
 * conn's fd is already deregistered from the reactor by the
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
    uint8_t *recv_scratch; /* owned, max_recv_envelope_len bytes, reused per extracted envelope */

    cloak_conn_framing_t framing; /* never CLOAK_CONN_FRAMING_INVALID on a constructed conn */

    size_t max_frame_len;

    /* The largest number of bytes one OUTBOUND frame of max_frame_len
     * occupies on the wire, framing included. Per mode:
     *
     *   TLS_RECORD  5             + max_frame_len
     *   WS_SERVER   2 + (0 or 2)  + max_frame_len
     *   WS_CLIENT   2 + (0 or 2)  + 4 + max_frame_len
     *
     * The "(0 or 2)" is RFC 6455 section 5.2's extended length: absent
     * for 0..125, two bytes for 126..65535 (max_frame_len can never reach
     * the 8-byte form, since CLOAK_CONN_MAX_FRAME_LEN is 16640). The 4 is
     * the client's mask key, which makes THE CLIENT'S ENVELOPE LARGER
     * THAN THE TLS ONE -- 16648 against 16645 at CLOAK_CONN_MAX_FRAME_LEN.
     * An implementation that sized the WebSocket path off the TLS path's
     * five bytes would be short by exactly three, and would fail only at
     * the maximum frame size: under load, in production, never in a unit
     * test. libcloak-mux/tests/test_conn_ws_framing.c pins all three
     * values as literals AND counts the bytes that actually reach the
     * socket, because a struct field agreeing with a wrong expression is
     * not evidence. */
    size_t max_envelope_len;

    /* The INBOUND equivalent, which is NOT the same number, because the
     * mask key sits on the other direction: a WS_SERVER conn sends
     * unmasked and receives masked. Sizing the receive accumulator off
     * max_envelope_len would leave a WS_SERVER conn four bytes short of
     * being able to hold one maximum-size incoming frame, which is a
     * deadlock (the frame never completes, so nothing is ever consumed,
     * so room never appears) rather than an overflow. Identical to
     * max_envelope_len on the TLS path, where both directions are five
     * bytes. */
    size_t max_recv_envelope_len;

    /* WebSocket receive reassembly (WS modes only). ws_msg_len counts the
     * payload bytes of the in-progress message already unmasked into
     * recv_scratch; ws_msg_active is 1 between a data frame with FIN
     * clear and the CONTINUATION frame that finally sets it. Go never
     * SENDS a fragmented message, but gorilla always accepts one and a
     * CDN is entitled to re-fragment what it forwards, so this is
     * load-bearing in production and invisible in a C-to-C test. */
    size_t ws_msg_len;
    int ws_msg_active;

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
 * connection will ever send or accept (must be
 * 1..CLOAK_CONN_MAX_FRAME_LEN -- see that macro for why the bound is the
 * TLS record limit and not the 16-bit length field's own 65535); a peer
 * declaring a larger length is treated as a protocol violation
 * (connection marked broken).
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
 * max_frame_len > CLOAK_CONN_MAX_FRAME_LEN, or send_queue_cap == 0) or
 * allocation/reactor registration failure. */
int cloak_conn_init(cloak_conn_t *c, int fd, cloak_reactor_t *reactor,
                     size_t max_frame_len, size_t send_queue_cap,
                     cloak_conn_envelope_cb on_envelope, void *on_envelope_userdata,
                     cloak_conn_closed_cb on_closed, void *on_closed_userdata);

/* Everything cloak_conn_init takes, plus the one thing it cannot take:
 * the framing mode, whose zero value must be a construction failure
 * rather than a default. See cloak_conn_framing_t for why that
 * requirement forces a struct here -- a mode passed as a parameter has no
 * zero value unless a caller types one.
 *
 * Fill this with a designated initialiser or a memset + assignments;
 * either way `framing` is the field that fails loudly if it is left out,
 * and it is validated BEFORE every other field so that the error a caller
 * gets names the thing they actually forgot. */
typedef struct {
    int fd;
    cloak_reactor_t *reactor;
    size_t max_frame_len;
    size_t send_queue_cap;
    cloak_conn_framing_t framing; /* REQUIRED -- 0 fails, see cloak_conn_framing_t */
    cloak_conn_envelope_cb on_envelope;
    void *on_envelope_userdata;
    cloak_conn_closed_cb on_closed;
    void *on_closed_userdata;
} cloak_conn_config_t;

/* The general constructor. cloak_conn_init is exactly this with
 * framing = CLOAK_CONN_FRAMING_TLS_RECORD, which is why the direct
 * path's call sites are untouched by this file's growth.
 *
 * Returns 0 on success, CLOAK_CONN_ERR_INVALID_FRAMING if cfg->framing is
 * not one of the three real modes (checked first, before anything else,
 * including before cfg is dereferenced for any other purpose), and -1 on
 * any other invalid parameter or on allocation/reactor registration
 * failure. cfg is copied; it need not outlive this call. */
int cloak_conn_init_cfg(cloak_conn_t *c, const cloak_conn_config_t *cfg);

/* Deregisters fd from the reactor (safe even if already deregistered,
 * e.g. because on_closed already fired) and frees c's own buffers. Does
 * NOT close(fd) -- matching cloak_reactor_destroy's own documented
 * convention, the caller owns fd's lifecycle. */
void cloak_conn_destroy(cloak_conn_t *c);

/* Frames frame_bytes[0, frame_len) according to this connection's framing
 * mode and enqueues it for transmission, attempting an immediate
 * non-blocking write.
 *
 *   TLS_RECORD  a TLS application-data record header
 *               (CLOAK_CONN_RECORD_HEADER_LEN -- see its own comment).
 *   WS_SERVER   one unmasked WebSocket BINARY frame, FIN set: 0x82 ...
 *   WS_CLIENT   the same, masked under a mask key drawn fresh PER FRAME
 *               from cloak_ws_frame_mask_key (i.e. from cloak_random_bytes,
 *               a deliberate improvement on gorilla's math/rand -- see
 *               that function's comment).
 *
 * Never fragments: one call is one whole message, matching gorilla's
 * WriteMessage, which is also why the far end can treat one message as
 * one mux frame.
 *
 * Returns 0 on success (accepted -- may still be partially buffered,
 * draining asynchronously via EPOLLWRITABLE), or -1 if c is already
 * broken, frame_len exceeds max_frame_len, the framed total exceeds
 * max_envelope_len, or the send queue's hard capacity would be exceeded
 * (in all of those but the first, on_closed fires synchronously, before
 * this call returns). Must not block. */
int cloak_conn_send(cloak_conn_t *c, const uint8_t *frame_bytes, size_t frame_len);

/* How many bytes one frame of frame_len will actually occupy on THIS
 * connection's socket, framing included -- five for a TLS record, two or
 * four for a WebSocket server frame, six or eight for a WebSocket client
 * frame (the extra four being the mask key). NULL reports 0.
 *
 * IT EXISTS BECAUSE THE TX METER WAS WRONG, and the defect was a
 * constant standing in for a question only this object can answer.
 * cloak_switchboard_send billed CLOAK_CONN_RECORD_HEADER_LEN + frame_len
 * for every frame regardless of what the connection put on the wire,
 * which on a CDN connection over-charged an interactive ~30-byte frame
 * by about 8.6% -- 3 bytes in 35 charged, i.e. 88 MiB per charged GiB of
 * a metered user's credit -- and, in the CLIENT direction, under-charged
 * a 16401-byte bulk frame by about 0.018% (the 3 bytes of mask key in
 * 16409: 196 kB per GiB, which is 191.7 KiB -- the units are worth
 * getting right in a comment about billing). The over-charging half is
 * the one that matters: it bills a user for bytes nobody sent.
 *
 * It is exactly the same arithmetic cloak_conn_send itself performs
 * before it enqueues, deliberately so: one function decides what an
 * envelope costs, and the meter asks it rather than reproducing it.
 * cloak_switchboard_send is the only caller today.
 *
 * NOTE THE ASYMMETRY WITH max_envelope_len, which is this function
 * evaluated at max_frame_len and is therefore an upper bound, not the
 * cost of a particular frame -- and note that the RECEIVE side needs
 * neither: conn.c counts raw wire bytes as they come off the socket,
 * which is already the true figure (and is why an RX equivalent of this
 * function would be the wrong shape entirely -- see that counting
 * point's own comment on why an envelope-level RX counter meters a peer
 * streaming garbage as zero). */
size_t cloak_conn_envelope_len(const cloak_conn_t *c, size_t frame_len);

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
