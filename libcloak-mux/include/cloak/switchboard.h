#ifndef CLOAK_SWITCHBOARD_H
#define CLOAK_SWITCHBOARD_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/conn.h" /* cloak_conn_framing_t, CLOAK_CONN_ERR_INVALID_FRAMING */
#include "cloak/reactor.h"
#include "cloak/valve.h"

/* ---------------------------------------------------------------------
 * THE CONNECTION PICK MUST BE UNPREDICTABLE, NOT MERELY UNIFORM.
 *
 * cloak_switchboard_send chooses which of the pool's NumConn connections
 * carries each frame. This block is the rationale for the generator that
 * choice uses. It exists because the field below used to cite a rationale
 * in this header that had never been written, and the generator it was
 * silently justifying was wrong -- see WHAT THIS REPLACED at the end.
 *
 * WHAT THE GENERATOR MUST PROVIDE, in the order these actually bind:
 *
 *  1. UNPREDICTABILITY FROM THE SEQUENCE ITSELF. The pick is public. One
 *     frame is one TLS record on exactly one of the pool's connections,
 *     all of them open to the same destination; a censor on the path
 *     reads "which connection carried record k" off the wire with no
 *     decryption and no key. UNORDERED MODE MAKES THIS MAXIMAL: Go drops
 *     Stream.assignedConn there ("not used in unordered connection
 *     mode"), so every datagram of every stream takes a fresh draw, and
 *     the censor gets one observation per datagram. So the sequence of
 *     picks is an output stream handed to an adversary who can collect
 *     as much of it as the session is long, and the requirement is the
 *     one a keystream has: seeing any prefix must not let him compute the
 *     next term. That is a cryptographic requirement, and nothing weaker
 *     states it -- a generator can be perfectly uniform in its marginal
 *     distribution AND in its lag-1 transitions and still hand its entire
 *     internal state to thirty-two observations.
 *
 *  2. UNIFORMITY OVER [0, conns_len), EXACTLY -- not "close enough".
 *     Connection load ratios are aggregatable across sessions and across
 *     users; a skew no other Cloak implementation produces is a
 *     fingerprint of THIS implementation. In particular the reduction
 *     onto conns_len must be rejection-sampled, never `%` on the raw
 *     draw: module 8 spent a whole fix wave removing exactly that shape
 *     from a one-byte pad draw in frame.c after it put a measured 2.009x
 *     bias on the wire.
 *
 *  3. INDEPENDENCE BETWEEN CONSECUTIVE PICKS. Round-robin satisfies (2)
 *     perfectly and is wire-visible on sight.
 *
 * (1) implies (3) and, with (2)'s rejection sampling bolted on, (2). That
 * is why the answer is a CSPRNG and not a better non-cryptographic
 * generator: the three requirements collapse into one.
 *
 * WHAT GO DOES, checked against Go rather than remembered. At the pinned
 * c3d5470 / v2.12.0, internal/multiplex/switchboard.go makes the pool
 *     randPool: sync.Pool{New: func() interface{} {
 *         var state [32]byte
 *         common.CryptoRandRead(state[:])
 *         return rand.New(rand.NewChaCha8(state)) }}
 * and pickRandConn draws `randReader.Uint32N(connsCount)`. The import is
 * "math/rand/v2", whose NewChaCha8 is documented in the Go source as "a
 * ChaCha8-based cryptographically strong random number generator", seeded
 * here from crypto/rand. Uint32N is unbiased by construction (Lemire's
 * reduction with the rejection step, math/rand/v2/rand.go's uint64n). So
 * Go's pick satisfies (1), (2) and (3) and always has: math/rand/v2 has
 * been ChaCha8-backed since Go 1.22, and this module's go.mod says
 * go 1.24.0. "math/rand means a weak generator" is a pre-1.22 habit.
 *
 * WHAT THIS PORT DOES: cloak_random_bytes (OpenSSL RAND_bytes) buffered
 * in the pool 256 bytes at a time, reduced by rejection sampling --
 * switchboard.c's switchboard_random_u32 and switchboard_random_below,
 * where the measured costs are. Structurally Go's arrangement: a CSPRNG
 * whose output is refilled in blocks, not consulted per draw.
 *
 * WHAT THIS REPLACED, recorded because the reason it survived matters
 * more than the defect. Through module 9 this line was
 * `xorshift32(&state) % conns_len`, and module 8's final fix wave looked
 * straight at it and left it, writing down as its reason "a 32-bit
 * non-crypto draw that matches Go's own pool". That reason was false --
 * Go's pool is ChaCha8, quoted above -- and nobody checked it against Go.
 * xorshift32 is F2-linear, so every output bit is a fixed XOR of the
 * state bits: Gaussian elimination over GF(2) on the 64 bits carried by
 * 32 OBSERVED PICKS recovered the exact 32-bit state in 4 of 4 seeds and
 * then predicted 100,000 of 100,000 subsequent picks (chance: 25%).
 * Berlekamp-Massey linear complexity of the pick's low bit over 512
 * picks: 32, 32, 32, 32, against 256 for a CSPRNG control.
 *
 * Both chi-squares in the suite passed it cleanly -- marginal 0.09-2.38
 * against a threshold of 30, lag-1 pair-transition 10.50-16.22 against
 * 60 -- which is the whole lesson: uniformity tests cannot see this, so
 * the property pinned in libcloak-server/tests/test_unordered_proof.c is
 * LINEAR COMPLEXITY, not a third distribution.
 * ------------------------------------------------------------------- */

typedef struct cloak_switchboard cloak_switchboard_t;

/* frame_bytes/len: an already record-header-stripped, still-obfuscated
 * frame's bytes, valid only for the duration of this call (points into
 * the originating cloak_conn_t's reused scratch buffer). */
typedef void (*cloak_switchboard_envelope_cb)(cloak_switchboard_t *sb, const uint8_t *frame_bytes, size_t frame_len, void *userdata);

/* Called exactly once, the moment ANY connection in the pool becomes
 * broken (matches Go's switchboard: a single connection's failure is
 * fatal to the whole pool, not just that connection -- see this
 * project's plan-level fault-model documentation). sb is NOT
 * automatically torn down when this fires -- the owner must still call
 * cloak_switchboard_close_all and/or cloak_switchboard_destroy once it's
 * done reacting (this lets the owner, e.g. a session, do its own
 * higher-layer cleanup first, matching Go's Session.closeSession()
 * running before switchboard.closeAll()). */
typedef void (*cloak_switchboard_broken_cb)(cloak_switchboard_t *sb, void *userdata);

/* Fired when any connection in the pool finishes draining its outbound
 * queue (see cloak_conn_drained_cb -- in particular, the same "no single
 * fixed call context" caveat applies here too: this can fire from
 * reactor dispatch, or synchronously from inside a cloak_switchboard_send
 * call that itself completes a connection's drain). Because the pool
 * spreads frames across connections, a producer should re-check
 * cloak_switchboard_send_queued rather than assume the whole pool is
 * empty when this fires. */
typedef void (*cloak_switchboard_drained_cb)(cloak_switchboard_t *sb, void *userdata);

struct cloak_switchboard {
    cloak_reactor_t *reactor;
    cloak_conn_t **conns; /* owned array of owned heap-allocated cloak_conn_t */
    size_t conns_len;
    size_t conns_cap;

    size_t max_frame_len;
    size_t conn_send_queue_cap;

    /* The connection pick's randomness -- see THE CONNECTION PICK MUST BE
     * UNPREDICTABLE, NOT MERELY UNIFORM at the top of this file for what
     * this must provide, and switchboard.c's switchboard_random_u32 for
     * how it provides it. CSPRNG bytes (cloak_random_bytes, i.e.
     * OpenSSL RAND_bytes) held four-at-a-time-ahead, never a recurrence
     * of any kind. rng_pos == sizeof(rng_buf) means "empty, refill". */
    uint8_t rng_buf[256];
    size_t rng_pos;

    int broken;
    cloak_switchboard_envelope_cb on_envelope;
    void *on_envelope_userdata;
    cloak_switchboard_broken_cb on_broken;
    void *on_broken_userdata;
    cloak_switchboard_drained_cb on_drained;
    void *on_drained_userdata;

    /* Borrowed, may be NULL ("this pool is not metered"). Forwarded to
     * every cloak_conn_t this pool creates -- see cloak/valve.h. */
    cloak_valve_t *valve;
    int rx_backpressure; /* 1 while every conn has READABLE dropped for a full stream */
};

/* max_frame_len/conn_send_queue_cap are forwarded unchanged to every
 * cloak_conn_t this switchboard creates (see cloak_conn_init's own
 * documentation for their meaning).
 *
 * Returns 0 on success, -1 on invalid parameters (same validation as
 * cloak_conn_init) or allocation failure. */
int cloak_switchboard_init(cloak_switchboard_t *sb, cloak_reactor_t *reactor,
                            size_t max_frame_len, size_t conn_send_queue_cap,
                            cloak_switchboard_envelope_cb on_envelope, void *on_envelope_userdata,
                            cloak_switchboard_broken_cb on_broken, void *on_broken_userdata);

/* Calls cloak_switchboard_close_all, then frees sb's own array. */
void cloak_switchboard_destroy(cloak_switchboard_t *sb);

/* Wraps fd in a new cloak_conn_t and adds it to the pool. fd must already
 * be an open, non-blocking-capable socket -- ownership of fd passes to
 * the switchboard (it will be close()d by cloak_switchboard_close_all).
 * Returns 0 on success, -1 if sb is already broken or on allocation/
 * cloak_conn_init failure. */
int cloak_switchboard_add_conn(cloak_switchboard_t *sb, int fd);

/* The same, with the connection's framing mode chosen explicitly --
 * cloak_switchboard_add_conn is exactly this with
 * CLOAK_CONN_FRAMING_TLS_RECORD.
 *
 * Framing is per CONNECTION, not per pool, because that is where it
 * actually belongs: it describes what is wrapped around bytes on one
 * socket. Nothing in this tree mixes modes within a pool today, and a
 * pool-wide setting would have read more simply -- but it would also have
 * made the mode something a conn inherits rather than something a conn
 * is constructed with, which is exactly the property
 * cloak_conn_framing_t's zero-value rule depends on.
 *
 * Returns 0 on success, CLOAK_CONN_ERR_INVALID_FRAMING if framing is not
 * one of the three real modes (in which case NOTHING is added and fd is
 * NOT adopted -- the caller still owns it), or -1 if sb is already broken
 * or on allocation/cloak_conn_init_cfg failure. */
int cloak_switchboard_add_conn_framed(cloak_switchboard_t *sb, int fd,
                                       cloak_conn_framing_t framing);

/* Picks one connection uniformly at random from the pool and sends
 * frame_bytes/frame_len through it (wrapped in a TLS record by that connection,
 * see cloak_conn_send). Returns 0 on success, -1 if sb is broken, the
 * pool is empty, or the picked connection's send fails (in the last
 * case, on_broken fires synchronously before this call returns -- see
 * this project's plan-level fault-model documentation: no retry among
 * other connections). Must not block. */
int cloak_switchboard_send(cloak_switchboard_t *sb, const uint8_t *frame_bytes, size_t frame_len);

/* Destroys and close()s every connection in the pool and empties it.
 * Idempotent (a second call is a harmless no-op). Does not fire
 * on_broken (that callback signals "something failed", not "cleanup
 * happened" -- a normal, expected close_all from the owner's own active
 * teardown is not a failure). */
void cloak_switchboard_close_all(cloak_switchboard_t *sb);

size_t cloak_switchboard_conn_count(const cloak_switchboard_t *sb);

void cloak_switchboard_set_drained_cb(cloak_switchboard_t *sb, cloak_switchboard_drained_cb cb,
                                       void *userdata);

/* Points this pool, and every connection in it (now and in future), at
 * the valve that meters the user it belongs to; v == NULL, the default a
 * zeroed/just-initialised switchboard already has, means unmetered.
 * Applies to connections added before this call as well as after, so the
 * order of set_valve and cloak_switchboard_add_conn does not matter.
 *
 * This pool counts the TX half itself (in cloak_switchboard_send, the
 * direct analogue of Go's switchboard.send calling AddTx after a
 * successful write); each connection counts the RX half as it reads. See
 * cloak/valve.h before touching either -- rx and tx are from the SERVER's
 * perspective and are NOT the user manager's up/down. */
/* Stops or resumes reading on EVERY connection in this switchboard
 * because a stream downstream is full. See cloak_conn_set_rx_backpressure.
 * A connection added while this is on starts paused. */
void cloak_switchboard_set_rx_backpressure(cloak_switchboard_t *sb, int on);

void cloak_switchboard_set_valve(cloak_switchboard_t *sb, cloak_valve_t *v);

/* Summed over every connection in the pool. An empty pool reports 0 for
 * both -- a producer must therefore treat capacity == 0 as "cannot send
 * right now", not as "no limit".
 *
 * These two are NOT the right pair to derive a safe write budget from,
 * for any caller (like cloak_stream_relay_t) whose writes eventually go
 * through cloak_switchboard_send: that function picks ONE connection
 * uniformly at random per call, it does not spread a write across the
 * pool. The realistic failure is one congested connection out of N: that
 * connection's own queue fills while the other N-1 stay near-empty, so
 * the AGGREGATE room these two report stays large right up until
 * cloak_switchboard_send happens to pick the congested one again and
 * cloak_conn_send's own per-connection cap fires conn_mark_broken --
 * fatal to the whole pool. See cloak_switchboard_send_min_conn_free
 * below for the accessor that actually bounds this. */
size_t cloak_switchboard_send_queued(const cloak_switchboard_t *sb);
size_t cloak_switchboard_send_capacity(const cloak_switchboard_t *sb);

/* The MINIMUM of cloak_conn_send_free over every connection in the pool
 * (0 for an empty pool) -- the number of bytes guaranteed to fit no
 * matter which connection cloak_switchboard_send's random pick lands on
 * next. This is the quantity a caller sizing a single upcoming
 * cloak_switchboard_send-driven write against the pool actually needs:
 * unlike the aggregate accessors above, it cannot be defeated by one
 * congested connection hiding behind (N-1) idle ones, because it does
 * not sum across the pool at all. O(n) over the pool, same as the
 * aggregate accessors. */
size_t cloak_switchboard_send_min_conn_free(const cloak_switchboard_t *sb);

#endif
