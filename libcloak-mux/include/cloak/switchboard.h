#ifndef CLOAK_SWITCHBOARD_H
#define CLOAK_SWITCHBOARD_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/reactor.h"

typedef struct cloak_switchboard cloak_switchboard_t;
typedef struct cloak_conn cloak_conn_t;

/* frame_bytes/len: an already length-prefix-stripped, still-obfuscated
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

    uint32_t rng_state; /* xorshift32, seeded once at init -- NOT cryptographic, see this file's header comment */

    int broken;
    cloak_switchboard_envelope_cb on_envelope;
    void *on_envelope_userdata;
    cloak_switchboard_broken_cb on_broken;
    void *on_broken_userdata;
    cloak_switchboard_drained_cb on_drained;
    void *on_drained_userdata;
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

/* Picks one connection uniformly at random from the pool and sends
 * frame_bytes/frame_len through it (length-prefixed by that connection,
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
