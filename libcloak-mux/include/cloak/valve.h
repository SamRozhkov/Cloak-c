#ifndef CLOAK_VALVE_H
#define CLOAK_VALVE_H

#include <stdint.h>

/* Meters one USER's traffic across every session that user holds.
 *
 * Go's internal/multiplex/qos.go. The object is shared BY REFERENCE
 * between sessions, which is exactly why it lives here as its own type
 * rather than as a field of cloak_session_t: one user may hold many
 * concurrent sessions, and their bytes all have to land in one place for
 * the panel to bill them against one credit balance.
 *
 * DIRECTION -- the single thing in this file that is dangerous to get
 * wrong, because getting it wrong is silent:
 *
 *   rx is client -> server. tx is server -> client. Both are from the
 *   SERVER's perspective, and this file never uses the words "up" or
 *   "down" for that reason -- Go's qos.go carries the same warning
 *   ("DO NOT use terms up or down as this is used in usermanager for
 *   bandwidth limiting"), and this port inherits it.
 *
 *   cloak/usermanager.h's up_credit/up_rate/up_usage (and their down_
 *   counterparts) are from the USER's perspective instead. A user's
 *   UPLOAD is the server's RX; a user's DOWNLOAD is the server's TX.
 *
 *   THIS MODULE DOES NOT CONVERT BETWEEN THE TWO VOCABULARIES. It only
 *   counts rx and tx. The conversion happens in exactly ONE place -- the
 *   panel's periodic drain, where a cloak_valve_nullify result is turned
 *   into a cloak_user_status_t -- and that is the only place it is
 *   allowed to happen. Anyone adding a second one has introduced the
 *   defect this comment exists to prevent: the wrong direction metered
 *   against the wrong limit, with no error raised anywhere, and every
 *   test that drives traffic symmetrically passing either way.
 *
 * WIRE BYTES, NOT PAYLOAD BYTES. The counters accumulate the bytes that
 * actually cross the socket: a stream's payload plus the frame header,
 * the AEAD tag, the obfuscator's random padding, and the connection's
 * own length prefix. A user therefore pays for the framing overhead they
 * cause, and their metered usage is legitimately larger than the number
 * of bytes their application transferred -- which is the same quantity
 * Go counts (switchboard.go counts conn.Write's and conn.Read's byte
 * counts, not stream payloads), and it is the first thing an operator
 * asks about, so it is stated here rather than left to be rediscovered.
 *
 * LIFETIME AND OWNERSHIP. A valve is owned by the panel (the per-user
 * bookkeeping layer), never by a session. A session holds a borrowed
 * pointer for as long as it lives and must NEVER free it; the panel must
 * outlive every session it handed the valve to. There is deliberately no
 * cloak_valve_create/destroy pair: the struct is a plain value the owner
 * embeds or allocates however it likes, zero-initialised (a zeroed
 * cloak_valve_t is a valid, empty valve -- no constructor call needed).
 *
 * A NULL cloak_valve_t * MEANS "NOT METERED". Every function here
 * tolerates NULL: adds are dropped, reads report 0. That is this port's
 * replacement for Go's UnlimitedValve, at no allocation and with a
 * branch the compiler predicts perfectly. It is what lets a bypass user
 * -- and any session whose config never set a valve -- run through the
 * exact same code path with no metering and no special case.
 *
 * THREADING. Plain non-atomic arithmetic, unlike Go's atomics: this port
 * runs every session on one single-threaded reactor (see cloak/reactor.h),
 * so the goroutine races qos.go's sync/atomic guards against do not
 * exist here. Sharing one valve between sessions on DIFFERENT threads
 * would be a data race; do not.
 *
 * EXTENSIBILITY. Task 6 adds token buckets (Go's rxtb/txtb and
 * rxWait/txWait) to this same struct, so that rate limiting lands at the
 * same call sites this counting already uses. Nothing may depend on this
 * struct's size or field order. */
typedef struct {
    int64_t rx; /* client -> server, wire bytes */
    int64_t tx; /* server -> client, wire bytes */
} cloak_valve_t;

/* Add n wire bytes to the corresponding counter. v == NULL is a no-op
 * (an unmetered session). n is expected to be a byte count from a
 * completed transfer and therefore >= 0; these functions do not validate
 * it, because there is no call site that can produce a negative one and
 * a check here would only hide a caller bug from the sanitizers. */
void cloak_valve_add_rx(cloak_valve_t *v, int64_t n);
void cloak_valve_add_tx(cloak_valve_t *v, int64_t n);

/* Bytes accumulated since the last cloak_valve_nullify. NULL reports 0. */
int64_t cloak_valve_rx(const cloak_valve_t *v);
int64_t cloak_valve_tx(const cloak_valve_t *v);

/* Reads both counters and zeroes them in one step -- Go's Nullify. The
 * caller receives exactly the bytes moved since the previous drain.
 *
 * This is one call rather than a read followed by a reset precisely so
 * that nothing can be counted between the two: bytes that arrive after
 * the read but before the reset would otherwise be zeroed away and the
 * user would have moved them for free. Either output pointer may be NULL
 * to discard that direction -- the counter is still reset.
 *
 * v == NULL writes 0 to both outputs. */
void cloak_valve_nullify(cloak_valve_t *v, int64_t *out_rx, int64_t *out_tx);

#endif
