#ifndef CLOAK_USERMANAGER_H
#define CLOAK_USERMANAGER_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/config.h"

/* The persistent user database: the whole of Go's
 * internal/server/usermanager (localManager + Voidmanager), backed by a
 * single SQLite file instead of bbolt.
 *
 * This module is the server's authorisation policy. Today dispatcher.c
 * decides who may connect by testing the UID against the bypass list in
 * the config file; once a panel is wired in front of this manager, THIS is
 * what answers that question for everyone else, and it is also where the
 * metering the panel collects is settled back into each user's credit.
 *
 * WHY SQLITE AND WHAT IT COSTS YOU
 * --------------------------------
 * The reactor is single-threaded (cloak/reactor.h). Every sqlite3_step
 * below that has to touch the disk stalls not just the session being
 * authorised but EVERY session on the server. Go does not have this
 * problem in the same visible way -- bolt's blocking I/O happens on a
 * goroutine and the scheduler runs everything else meanwhile -- so this
 * is a real cost the port pays, and it is stated here rather than hidden.
 *
 * Three things keep it small, all of them set up in
 * cloak_usermanager_open:
 *
 *   - WAL journalling with synchronous = NORMAL. A commit then costs an
 *     append to the write-ahead log and no fsync. The trade is explicit:
 *     an OS-level crash (not a process crash -- WAL survives that) can
 *     lose the last commits' worth of METERING, i.e. some traffic goes
 *     uncharged. It cannot lose the user table itself, because a torn WAL
 *     tail is discarded wholesale on recovery and the committed database
 *     is left intact. Losing a few seconds of accounting is the right
 *     thing to trade for not fsyncing on the reactor thread; losing a
 *     user's row would not be.
 *   - Every statement is prepared ONCE, at open, and cached for the
 *     manager's lifetime. The authorisation path never re-parses SQL; it
 *     binds, steps and resets. cloak_usermanager_close finalizes them all.
 *   - cloak_usermanager_upload_status commits the whole batch as ONE
 *     transaction, so a drain of N users costs one commit, not N.
 *
 * The residual is honest and unfixable from here: on a genuinely slow or
 * failing disk, a step blocks and the reactor blocks with it. If that ever
 * becomes the operational problem, the fix is an I/O thread or an
 * in-memory write-behind cache, not a tweak to this file.
 *
 * cloak_usermanager_open itself blocks, and that is FINE -- it runs once
 * at startup, in exactly the same phase as cloak_server_init, which
 * already blocks on DNS resolution before the reactor ever runs. Do not
 * "fix" it into something asynchronous.
 *
 * UNTRUSTED INPUT
 * ---------------
 * The admin API (the next module) exposes write/get/delete over the wire
 * to whoever holds the admin UID, so every argument here should be read
 * as attacker-influenced. Every value this module sends to SQLite is
 * bound as a parameter; no statement anywhere is built by string
 * concatenation, and the statement texts are compile-time constants.
 *
 * THREADING: none, like everything else in this project. One manager, one
 * SQLite connection, one thread. The vendored SQLite is built with
 * SQLITE_THREADSAFE=0, so using a manager from two threads is not a
 * performance question but undefined behaviour. */

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

/* One code per Go error, because the dispatcher and the admin API have to
 * tell them apart: the dispatcher logs different things for an expired
 * user and an unknown one, and the admin API reports them differently.
 * CLOAK_USER_ERR_ARG has no Go counterpart -- Go's nil-able slices make
 * most of these cases unrepresentable -- but C callers can pass NULL, and
 * conflating a caller bug with a database failure would send the admin
 * API's operator hunting a disk problem that is not there. */
#define CLOAK_USER_ERR_NOT_FOUND      (-1) /* UID does not correspond to a user */
#define CLOAK_USER_ERR_NO_UP_CREDIT   (-2)
#define CLOAK_USER_ERR_NO_DOWN_CREDIT (-3)
#define CLOAK_USER_ERR_EXPIRED        (-4)
#define CLOAK_USER_ERR_SESSIONS_CAP   (-5)
#define CLOAK_USER_ERR_VOID           (-6) /* manager has no database at all */
#define CLOAK_USER_ERR_DB             (-7) /* SQLite said no */
#define CLOAK_USER_ERR_ARG            (-8) /* NULL or otherwise invalid argument */
/* The file opened is a users database whose CONTENTS violate an invariant
 * this module requires -- distinct from _DB, which is SQLite reporting a
 * failure, because the operator's remedy is completely different. Only
 * cloak_usermanager_open returns it. */
#define CLOAK_USER_ERR_SCHEMA         (-9)
/* A transaction from an earlier failed batch could not be rolled back,
 * and the connection is therefore stuck inside it. Distinct from _DB
 * because it is PERMANENT for this manager: retrying will never succeed,
 * and the caller should stop metering and tell the operator rather than
 * loop. Only cloak_usermanager_upload_status returns it. */
#define CLOAK_USER_ERR_WEDGED         (-10)

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

/* THE ACCEPTED CREDIT RANGE, since the admin API will pass these values
 * through from the wire: the whole of int64 is accepted and stored
 * verbatim. Nothing is rejected and nothing is rescaled. INT64_MAX is the
 * idiomatic "effectively unlimited" and works as one -- metering can
 * subtract from it for longer than the universe has existed.
 *
 * What the range does NOT include is wrapping. Every credit adjustment in
 * cloak_usermanager_upload_status SATURATES: it clamps at INT64_MIN and
 * INT64_MAX instead of overflowing, which in C would be undefined
 * behaviour and in practice would flip an unlimited user into maximal
 * debt (a permanent lockout) or a maximally indebted user into unlimited
 * credit (a silent free pass). Both directions have been reproduced; see
 * cloak_usermanager_upload_status.
 *
 * The one thing an operator should know is that a credit clamped to
 * INT64_MIN is a permanent lockout no amount of further metering can
 * deepen, and only a cloak_usermanager_write can lift. That is a
 * consequence of saturating rather than wrapping, and it is the right
 * direction to fail in. */
typedef struct {
    uint8_t uid[CLOAK_UID_LEN];
    int32_t sessions_cap;
    int64_t up_rate, down_rate;   /* bytes/sec; 0 means unthrottled */
    int64_t up_credit, down_credit; /* bytes remaining; may be NEGATIVE */
    int64_t expiry_time;          /* unix seconds */
} cloak_user_info_t;

/* Which fields of a cloak_user_info_t a write should actually apply.
 * Go expresses this with nil-able pointers (MaybeInt32/MaybeInt64) so a
 * partial update leaves untouched fields alone; C has no such thing, so
 * the caller says explicitly. A write with no bits set creates a row with
 * the defaults documented on cloak_usermanager_write and changes nothing
 * about a row that already exists. */
typedef enum {
    CLOAK_USER_FIELD_SESSIONS_CAP = 1u << 0,
    CLOAK_USER_FIELD_UP_RATE      = 1u << 1,
    CLOAK_USER_FIELD_DOWN_RATE    = 1u << 2,
    CLOAK_USER_FIELD_UP_CREDIT    = 1u << 3,
    CLOAK_USER_FIELD_DOWN_CREDIT  = 1u << 4,
    CLOAK_USER_FIELD_EXPIRY_TIME  = 1u << 5,
} cloak_user_field_t;

#define CLOAK_USER_FIELD_ALL                                          \
    (CLOAK_USER_FIELD_SESSIONS_CAP | CLOAK_USER_FIELD_UP_RATE |       \
     CLOAK_USER_FIELD_DOWN_RATE | CLOAK_USER_FIELD_UP_CREDIT |        \
     CLOAK_USER_FIELD_DOWN_CREDIT | CLOAK_USER_FIELD_EXPIRY_TIME)

/* One user's metered traffic since the last upload, as the panel drains
 * it. up_usage/down_usage are from the USER's perspective and the
 * server's rx/tx are not: a user's UPLOAD is the server's RX. The one
 * place that conversion happens is the panel's queue drain, and it says
 * so there; nothing in this file ever sees rx/tx. Getting this backwards
 * meters the wrong direction against the wrong limit and is silent.
 *
 * Both usages are byte COUNTS and must be >= 0. The accounting module
 * that fills these in is expected never to produce a negative one; if it
 * does, cloak_usermanager_upload_status clamps it to 0 and logs, rather
 * than subtracting it. That is a boundary check, not a supported input:
 * a negative usage would CREDIT a user for traffic they did not send,
 * which is a way to obtain free service and not merely untidy.
 *
 * num_session, active and timestamp are carried for parity with Go's
 * StatusUpdate and for the admin API's reporting. localManager ignores
 * all three, and so does this module -- they are recorded here, not
 * acted on. */
typedef struct {
    uint8_t uid[CLOAK_UID_LEN];
    int64_t up_usage, down_usage;
    int     num_session;
    int     active;
    int64_t timestamp;
} cloak_user_status_t;

/* Reasons, verbatim from Go's localManager.UploadStatus so a panel log
 * line reads the same in both implementations. These are static storage
 * with program lifetime; a cloak_user_terminate_t.reason always points at
 * one of them and is never freed by the caller. */
#define CLOAK_USER_TERMINATE_NO_SUCH_USER   "User no longer exists"
#define CLOAK_USER_TERMINATE_NO_UP_CREDIT   "No upload credit left"
#define CLOAK_USER_TERMINATE_NO_DOWN_CREDIT "No download credit left"
#define CLOAK_USER_TERMINATE_EXPIRED        "User has expired"

/* What the manager tells the panel to do about a user after an upload.
 * Go models this as a slice of StatusResponse with an action enum; only
 * TERMINATE exists, and a user needing no action gets no entry at all --
 * so the action field is not reproduced here, since an entry's existence
 * IS the action. */
typedef struct {
    uint8_t     uid[CLOAK_UID_LEN];
    const char *reason; /* one of the CLOAK_USER_TERMINATE_* strings above */
} cloak_user_terminate_t;

/* The clock, injectable so expiry and credit behaviour can be tested
 * without touching the wall clock or writing timestamps relative to it
 * and hoping. Mirrors Go threading a common.WorldState through the
 * manager. Returns unix seconds. Passing NULL to
 * cloak_usermanager_open uses time(NULL). */
typedef int64_t (*cloak_now_fn)(void *userdata);

typedef struct cloak_usermanager cloak_usermanager_t;

/* ------------------------------------------------------------------ */
/* Lifetime                                                            */
/* ------------------------------------------------------------------ */

/* Opens (creating if needed) the database at db_path, applies the schema
 * with CREATE TABLE IF NOT EXISTS so an existing database is opened
 * unchanged, and prepares every statement this module will ever run.
 *
 * db_path == NULL opens a VOID manager: every operation below returns
 * CLOAK_USER_ERR_VOID and nothing touches a disk. This is not a degraded
 * mode to work around -- it is Go's Voidmanager, and a server configured
 * with no DatabasePath serves its bypass UIDs and nobody else, which is a
 * legitimate and common deployment.
 *
 * Blocks. See the top of this file for why that is correct here.
 *
 * VALIDATES THE EXISTING CONTENTS: a row whose uid is not exactly
 * CLOAK_UID_LEN bytes fails the open with CLOAK_USER_ERR_SCHEMA and a
 * message naming how many such rows there are. The current schema's CHECK
 * constraint makes such a row impossible to create, so this can only fire
 * on a database written before that constraint existed (or by another
 * tool). It is a hard failure rather than a warning because such a row is
 * unreachable through this entire API -- list skips it, and get and
 * delete take a fixed 16-byte UID whose lookup can never match it -- so
 * an operator could neither see nor remove a user that is nonetheless in
 * their database. A loud startup failure they can act on beats an
 * invisible user they cannot.
 *
 * Returns 0 and writes *out on success. On failure returns a negative
 * CLOAK_USER_ERR_*, sets *out to NULL (whatever it held before), and, if
 * err is non-NULL, writes a NUL-terminated message truncated to err_cap.
 * now_fn may be NULL for time(NULL); now_userdata is passed through
 * untouched and the manager never dereferences it itself. */
int cloak_usermanager_open(cloak_usermanager_t **out, const char *db_path,
                           cloak_now_fn now_fn, void *now_userdata,
                           char *err, size_t err_cap);

/* Finalizes every cached statement and closes the connection. Safe on
 * NULL and on a void manager. After this, m is freed; do not call
 * anything else with it. */
void cloak_usermanager_close(cloak_usermanager_t *m);

/* ------------------------------------------------------------------ */
/* The seven operations                                                */
/* ------------------------------------------------------------------ */

/* Checks, in this exact order, that the user exists, that up_credit > 0,
 * that down_credit > 0, and that the user has not expired -- returning
 * CLOAK_USER_ERR_NOT_FOUND, _NO_UP_CREDIT, _NO_DOWN_CREDIT or _EXPIRED
 * respectively. The order is Go's and is observable: a user who is both
 * out of credit and expired is reported as out of credit.
 *
 * THE EXPIRY BOUNDARY: Go's test is `expiryTime < now` -> expired, so a
 * user whose expiry_time is EXACTLY now is still valid. Ported as-is;
 * this is a one-second difference that a `<=` would silently invert.
 *
 * On success returns 0 and writes the user's configured rates through
 * out_up_rate/out_down_rate (bytes/sec, 0 meaning unthrottled). Either
 * may be NULL. On any failure NEITHER is written, so a caller that
 * ignores the return code sees its own initial values rather than a
 * plausible-looking zero. */
int cloak_usermanager_authenticate(cloak_usermanager_t *m,
                                   const uint8_t uid[CLOAK_UID_LEN],
                                   int64_t *out_up_rate, int64_t *out_down_rate);

/* Everything cloak_usermanager_authenticate checks, in the same order,
 * and THEN num_existing_sessions >= sessions_cap ->
 * CLOAK_USER_ERR_SESSIONS_CAP. The cap is checked last because a user who
 * has run out of credit should be told that, not told they have too many
 * sessions. Note the >=: a user with sessions_cap 3 and 3 sessions open
 * is refused a fourth. */
int cloak_usermanager_authorise_new_session(cloak_usermanager_t *m,
                                            const uint8_t uid[CLOAK_UID_LEN],
                                            int num_existing_sessions);

/* Settles a batch of metered usage into the database and reports which
 * users the caller should now terminate. The whole batch is ONE
 * transaction: either every row is updated or none is, and one commit
 * covers the lot.
 *
 * For each update, in order: a user that no longer exists yields a
 * terminate with CLOAK_USER_TERMINATE_NO_SUCH_USER and NO write (the
 * metering path must never resurrect a deleted user). Otherwise the
 * usages are subtracted from the respective credits and the new values
 * are written back EVEN WHEN NON-POSITIVE -- the debt is the point: it is
 * what makes cloak_usermanager_authenticate keep refusing the user on the
 * next connection attempt, rather than letting them reconnect at zero and
 * overdraw again.
 *
 * THE SUBTRACTION SATURATES rather than overflowing. Signed overflow is
 * undefined behaviour, and both directions of it are reachable from
 * values an operator would plausibly store: a user at INT64_MAX ("give
 * them everything") wraps to INT64_MIN on the first drain that carries a
 * negative usage, locking them out permanently; a user at INT64_MIN wraps
 * to INT64_MAX on any positive drain, silently handing maximal debt an
 * unlimited allowance and emitting no terminate. Credits therefore clamp
 * at INT64_MIN/INT64_MAX, and a usage below 0 is clamped to 0 and logged
 * at WARN before it is ever subtracted.
 *
 * A clamped usage does NOT fail the batch: one malformed entry must not
 * cost every other user in the drain their billing. It is logged and that
 * one entry contributes nothing.
 *
 * SELF-HEALING: if an earlier batch left a transaction open (only
 * possible if its rollback also failed), this attempts to roll it back
 * before beginning. If that cannot be done the manager is permanently
 * unusable for metering and this returns CLOAK_USER_ERR_WEDGED, which is
 * deliberately NOT the same code as a transient CLOAK_USER_ERR_DB -- a
 * caller must be able to tell "retry next drain" from "stop and tell the
 * operator", or it will retry against a dead connection forever.
 *
 * A terminate is emitted when a new credit is <= 0, or when the user has
 * expired (`now > expiry_time`, the same boundary authenticate uses).
 *
 * AT MOST ONE TERMINATE PER USER, and the reason that wins when several
 * conditions hold at once is: expired, else out of download credit, else
 * out of upload credit. Two things about that. First, Go genuinely emits
 * MORE than one entry for such a user -- its loop appends inside each
 * condition's branch, not once at the end -- and this port deliberately
 * does not, because a caller that terminates the same user twice is a bug
 * waiting to happen and every reason Go would emit is true anyway.
 * Second, the precedence is not arbitrary: it reports the condition the
 * user can do least about. Expiry is not fixable by a top-up, so it wins;
 * between the two credits Go's own final `resp` value is the download
 * one, and that is kept so the message a user sees matches upstream.
 *
 * out_terminate/out_cap is a caller buffer this never allocates. *out_n
 * is always the TRUE number of terminates the batch produced, even when
 * that exceeds out_cap; the buffer holds the first min(*out_n, out_cap)
 * of them, in the order of the updates array, and entries past that are
 * untouched. out_terminate may be NULL when out_cap is 0, which makes
 * this a "how many would there be?" probe -- but note the writes still
 * happen, so it is a probe of the result, not a dry run. out_n is
 * required.
 *
 * n_updates == 0 is a no-op returning 0 with *out_n == 0 and no
 * transaction at all, matching Go's early return. */
int cloak_usermanager_upload_status(cloak_usermanager_t *m,
                                    const cloak_user_status_t *updates,
                                    size_t n_updates,
                                    cloak_user_terminate_t *out_terminate,
                                    size_t out_cap, size_t *out_n);

/* Every user, every field, in ASCENDING UID ORDER (memcmp order over the
 * 16-byte blob). The order is a contract, not an accident: the admin API
 * pages through this, and a paging caller that cannot rely on a stable
 * total order cannot page at all.
 *
 * *out_n is always the TRUE number of users, even when that exceeds
 * out_cap; out holds the FIRST min(*out_n, out_cap) of them in that
 * order, and entries past that are untouched, so a caller that got
 * *out_n > out_cap can reallocate and retry knowing exactly what it is
 * missing. out may be NULL when out_cap is 0, making this a pure count.
 * out_n is required.
 *
 * Rows whose stored uid is not exactly CLOAK_UID_LEN bytes are skipped
 * and not counted. cloak_usermanager_open refuses to open a database that
 * already contains one, so this can only be reached by a row another
 * process wrote into an already-open database -- the check stays because
 * copying CLOAK_UID_LEN bytes out of a shorter blob would be an
 * over-read, which is a memory-safety guard and not a migration path. */
int cloak_usermanager_list(cloak_usermanager_t *m, cloak_user_info_t *out,
                           size_t out_cap, size_t *out_n);

/* One user, every field, or CLOAK_USER_ERR_NOT_FOUND. out->uid is filled
 * in from the argument, so a caller can pass the result straight back to
 * cloak_usermanager_write. On failure *out is untouched. */
int cloak_usermanager_get(cloak_usermanager_t *m, const uint8_t uid[CLOAK_UID_LEN],
                          cloak_user_info_t *out);

/* Upsert: creates info->uid's row if it is absent, and applies exactly
 * the fields named in the bitmask `fields` (a union of
 * cloak_user_field_t). Fields not named keep whatever the row already
 * had; on a CREATE they take these defaults, and the choice is
 * deliberate:
 *
 *     sessions_cap 0, up_credit 0, down_credit 0, expiry_time 0
 *
 * -- every one of which DENIES. A row created by a write that named none
 * of them exists (get finds it, list counts it) but cannot authenticate
 * and cannot open a session. That is the conservative direction, and it
 * matters because the admin API will let a remote operator create users
 * with partial field sets: the failure mode of a half-specified create
 * has to be a user who cannot connect, never one who can connect
 * unmetered and forever. In particular sessions_cap defaulting to 0 means
 * a freshly created user is locked out until someone sets a cap -- that
 * is intended, not an artefact of zeroing memory. expiry_time 0 is the
 * unix epoch, i.e. already expired against any real clock.
 *
 *     up_rate 0, down_rate 0
 *
 * -- which per the schema means UNTHROTTLED, the one default that is not
 * restrictive. It cannot be: 0 already means "no limit" everywhere else
 * in this codebase and to the valve that consumes it, so a "conservative"
 * rate default would have to be some arbitrary non-zero number. The rates
 * are a QoS knob, not an authorisation gate; all three actual gates (cap,
 * credit, expiry) default to deny, which is where the safety lives.
 *
 * Go has no defined behaviour here at all: its CreateBucketIfNotExists
 * simply leaves the unnamed keys absent, and a later read does
 * binary.BigEndian.Uint64(nil), which panics. Defining the defaults is a
 * deliberate divergence, not a port of anything.
 *
 * A `fields` mask carrying bits outside CLOAK_USER_FIELD_ALL is rejected
 * with CLOAK_USER_ERR_ARG rather than having the unknown bits ignored:
 * the admin API will forward a mask decoded off the wire, and a bit this
 * build does not understand means the caller and this module disagree
 * about what the request says. Applying the rest anyway would perform a
 * different update than the one that was asked for.
 *
 * The 16-byte UID length is enforced by a CHECK constraint in the schema
 * rather than by an argument test here, because the C signature already
 * makes a wrong-length UID unrepresentable in-process -- the guard has to
 * live where a FUTURE caller (the admin API, decoding UIDs off the wire,
 * or any tool writing this file directly) cannot route around it. */
int cloak_usermanager_write(cloak_usermanager_t *m, const cloak_user_info_t *info,
                            uint32_t fields);

/* Removes the user. Returns CLOAK_USER_ERR_NOT_FOUND if there was no such
 * row, matching Go's DeleteBucket returning bolt.ErrBucketNotFound rather
 * than succeeding silently -- the admin API needs to be able to tell an
 * operator that the UID they typed was not there. */
int cloak_usermanager_delete(cloak_usermanager_t *m, const uint8_t uid[CLOAK_UID_LEN]);

#endif
