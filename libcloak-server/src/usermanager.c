#define _POSIX_C_SOURCE 200809L
#include "cloak/usermanager.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sqlite3.h"

#include "cloak/log.h"

/* CLOAK_UID_LEN as an SQL literal, for the schema's CHECK constraint.
 * Stringified rather than written as a bare 16 so the constraint tracks
 * the constant if it ever changes, instead of silently disagreeing with
 * every other length in this file. */
#define UM_STR2(x) #x
#define UM_STR(x)  UM_STR2(x)

/* WITHOUT ROWID because this table is keyed by a 16-byte blob and is
 * never addressed by rowid: an ordinary table would store the rows in a
 * rowid btree plus a SECOND btree mapping uid -> rowid, and every lookup
 * here is by uid. Dropping the indirection removes an index, a level of
 * seeking per lookup, and the rowid column itself.
 *
 * The CHECK on the uid length is the only place a wrong-length UID can be
 * stopped for good. This module's own C signatures take a fixed-size
 * array, so no in-process caller can even express one -- but the admin
 * API decodes UIDs off the wire, and nothing stops a future caller (or a
 * separate tool) from binding a blob of its own length to this table.
 * Putting the invariant in the schema means the database refuses, not
 * some argument check that a new code path forgets to repeat. */
static const char UM_SCHEMA[] =
    "CREATE TABLE IF NOT EXISTS users ("
    "    uid          BLOB PRIMARY KEY NOT NULL"
    "                 CHECK(length(uid) = " UM_STR(CLOAK_UID_LEN) "),"
    "    sessions_cap INTEGER NOT NULL,"
    "    up_rate      INTEGER NOT NULL," /* bytes/sec, 0 = unlimited */
    "    down_rate    INTEGER NOT NULL,"
    "    up_credit    INTEGER NOT NULL," /* bytes remaining, may go negative */
    "    down_credit  INTEGER NOT NULL,"
    "    expiry_time  INTEGER NOT NULL"  /* unix seconds */
    ") WITHOUT ROWID;";

/* Every statement this module will ever run, prepared once at open and
 * kept for the manager's lifetime. The authorisation path is on the
 * critical path of every handshake and every new session on a
 * single-threaded reactor; re-parsing SQL there would be pure latency
 * added to every session on the server, not just the one being
 * authorised. Keeping them in a flat array (rather than named struct
 * members) is what makes "prepared exactly once, finalized exactly once"
 * two loops instead of sixteen hand-written lines that can drift apart. */
enum {
    UM_ST_GET = 0,
    UM_ST_LIST,
    UM_ST_WRITE,
    UM_ST_METER,
    UM_ST_DELETE,
    UM_ST_BEGIN,
    UM_ST_COMMIT,
    UM_ST_ROLLBACK,
    UM_ST_COUNT
};

/* String literals are single-quoted and identifiers bare throughout:
 * SQLite here is built with SQLITE_DQS=0, so a double-quoted string is an
 * error rather than SQLite's historical silent fallback.
 *
 * Every value is a bound parameter. Nothing in this file concatenates a
 * caller-supplied value into SQL, and every one of these texts is a
 * compile-time constant -- the admin API hands this module
 * attacker-influenced UIDs and field values, and parameter binding is
 * what makes that safe rather than careful escaping. */
static const char *const UM_SQL[UM_ST_COUNT] = {
    /* UM_ST_GET */
    "SELECT sessions_cap, up_rate, down_rate, up_credit, down_credit, expiry_time"
    " FROM users WHERE uid = ?1",

    /* UM_ST_LIST -- ORDER BY uid is a documented contract, not a
     * decoration: the admin API pages through cloak_usermanager_list and
     * needs a stable total order to page over. */
    "SELECT uid, sessions_cap, up_rate, down_rate, up_credit, down_credit,"
    " expiry_time FROM users ORDER BY uid",

    /* UM_ST_WRITE -- one statement covering all 64 field masks. An unnamed
     * field binds SQL NULL, and coalesce then picks the create-time
     * default (on INSERT) or the row's existing value (on conflict). The
     * defaults are spelled out here, in the statement, rather than being
     * whatever calloc happened to leave behind; see this function's doc
     * comment for why every gate defaults to deny. */
    "INSERT INTO users (uid, sessions_cap, up_rate, down_rate, up_credit,"
    " down_credit, expiry_time) VALUES (?1, coalesce(?2, 0), coalesce(?3, 0),"
    " coalesce(?4, 0), coalesce(?5, 0), coalesce(?6, 0), coalesce(?7, 0))"
    " ON CONFLICT(uid) DO UPDATE SET"
    "   sessions_cap = coalesce(?2, sessions_cap),"
    "   up_rate      = coalesce(?3, up_rate),"
    "   down_rate    = coalesce(?4, down_rate),"
    "   up_credit    = coalesce(?5, up_credit),"
    "   down_credit  = coalesce(?6, down_credit),"
    "   expiry_time  = coalesce(?7, expiry_time)",

    /* UM_ST_METER -- absolute new values rather than `up_credit = up_credit
     * - ?2`, because upload_status has already read the old values through
     * UM_ST_GET (to decide the terminate) and the subtraction has to agree
     * with the number the decision was made on. */
    "UPDATE users SET up_credit = ?2, down_credit = ?3 WHERE uid = ?1",

    /* UM_ST_DELETE */
    "DELETE FROM users WHERE uid = ?1",

    /* The transaction verbs are prepared too: upload_status runs them on
     * every panel drain, and there is no reason to re-parse three
     * keywords on a timer. IMMEDIATE takes the write lock up front rather
     * than discovering at the first UPDATE that it cannot upgrade. */
    "BEGIN IMMEDIATE",
    "COMMIT",
    "ROLLBACK",
};

struct cloak_usermanager {
    sqlite3      *db; /* NULL means a VOID manager -- Go's Voidmanager */
    sqlite3_stmt *st[UM_ST_COUNT];
    cloak_now_fn  now_fn;
    void         *now_userdata;
};

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static int64_t um_default_now(void *userdata) {
    (void)userdata;
    return (int64_t)time(NULL);
}

static void um_set_err(char *err, size_t err_cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void um_set_err(char *err, size_t err_cap, const char *fmt, ...) {
    va_list ap;
    if (err == NULL || err_cap == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(err, err_cap, fmt, ap);
    va_end(ap);
}

/* SQLITE_TRANSIENT rather than SQLITE_STATIC: 16 bytes is nothing to
 * copy, and STATIC would make every call site responsible for keeping the
 * caller's buffer alive until the statement is reset -- a lifetime rule
 * that is easy to state and easy to break silently later. */
static int um_bind_uid(sqlite3_stmt *st, const uint8_t *uid) {
    return sqlite3_bind_blob(st, 1, uid, CLOAK_UID_LEN, SQLITE_TRANSIENT);
}

/* Runs a statement expected to produce no rows, then resets it. Resetting
 * is unconditional: a statement left un-reset holds its read/write lock
 * and would make the next COMMIT fail with "SQL statements in progress". */
static int um_run(cloak_usermanager_t *m, int idx) {
    int rc = sqlite3_step(m->st[idx]);
    sqlite3_reset(m->st[idx]);
    if (rc != SQLITE_DONE) {
        CLOAK_LOGE("usermanager: statement failed: %s", sqlite3_errmsg(m->db));
        return CLOAK_USER_ERR_DB;
    }
    return 0;
}

/* Loads one user's fields. Returns 0, CLOAK_USER_ERR_NOT_FOUND or
 * CLOAK_USER_ERR_DB; *info is written only on success. */
static int um_load(cloak_usermanager_t *m, const uint8_t *uid,
                   cloak_user_info_t *info) {
    sqlite3_stmt *st = m->st[UM_ST_GET];
    int rc;

    if (um_bind_uid(st, uid) != SQLITE_OK) {
        sqlite3_reset(st);
        CLOAK_LOGE("usermanager: bind failed: %s", sqlite3_errmsg(m->db));
        return CLOAK_USER_ERR_DB;
    }
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        memcpy(info->uid, uid, CLOAK_UID_LEN);
        info->sessions_cap = sqlite3_column_int(st, 0);
        info->up_rate = sqlite3_column_int64(st, 1);
        info->down_rate = sqlite3_column_int64(st, 2);
        info->up_credit = sqlite3_column_int64(st, 3);
        info->down_credit = sqlite3_column_int64(st, 4);
        info->expiry_time = sqlite3_column_int64(st, 5);
        sqlite3_reset(st);
        return 0;
    }
    sqlite3_reset(st);
    if (rc == SQLITE_DONE) {
        return CLOAK_USER_ERR_NOT_FOUND;
    }
    CLOAK_LOGE("usermanager: lookup failed: %s", sqlite3_errmsg(m->db));
    return CLOAK_USER_ERR_DB;
}

/* The three authorisation gates common to authenticate and
 * authorise_new_session, in Go's order -- which is observable: a user who
 * is both out of credit and expired is reported as out of credit.
 *
 * The expiry test is `expiry_time < now`, exactly Go's, so a user whose
 * expiry is EXACTLY now is still valid. A `<=` here would cut every user
 * off one second early and nothing would ever notice. */
static int um_check_gates(const cloak_user_info_t *u, int64_t now) {
    if (u->up_credit <= 0) {
        return CLOAK_USER_ERR_NO_UP_CREDIT;
    }
    if (u->down_credit <= 0) {
        return CLOAK_USER_ERR_NO_DOWN_CREDIT;
    }
    if (u->expiry_time < now) {
        return CLOAK_USER_ERR_EXPIRED;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Lifetime                                                            */
/* ------------------------------------------------------------------ */

int cloak_usermanager_open(cloak_usermanager_t **out, const char *db_path,
                           cloak_now_fn now_fn, void *now_userdata,
                           char *err, size_t err_cap) {
    cloak_usermanager_t *m;
    char *sqlite_err = NULL;
    int i;
    int rc;

    if (out == NULL) {
        um_set_err(err, err_cap, "usermanager: out must not be NULL");
        return CLOAK_USER_ERR_ARG;
    }
    *out = NULL;

    /* Fully initialized BEFORE anything else is examined or attempted, so
     * that every failure path below can hand m to cloak_usermanager_close
     * and have it do exactly the right thing on a partially-opened
     * manager. */
    m = calloc(1, sizeof(*m));
    if (m == NULL) {
        um_set_err(err, err_cap, "usermanager: out of memory");
        return CLOAK_USER_ERR_DB;
    }
    m->db = NULL;
    for (i = 0; i < UM_ST_COUNT; i++) {
        m->st[i] = NULL;
    }
    m->now_fn = (now_fn != NULL) ? now_fn : um_default_now;
    m->now_userdata = now_userdata;

    /* The void manager: no database, no file, every operation refuses.
     * This is Go's Voidmanager and a legitimate deployment, not a
     * fallback for a failure. */
    if (db_path == NULL) {
        *out = m;
        return 0;
    }

    rc = sqlite3_open_v2(db_path, &m->db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        /* sqlite3_open_v2 leaves a handle behind even on failure, so that
         * errmsg can be read; close() reclaims it. */
        um_set_err(err, err_cap, "usermanager: cannot open '%s': %s", db_path,
                   m->db ? sqlite3_errmsg(m->db) : sqlite3_errstr(rc));
        cloak_usermanager_close(m);
        return CLOAK_USER_ERR_DB;
    }

    /* WAL + synchronous=NORMAL: a commit becomes an append to the
     * write-ahead log with no fsync. On this single-threaded reactor an
     * fsync would stall every session on the server, not just the one
     * being authorised. The trade is deliberate and asymmetric: an
     * OS-level crash can lose the last commits' worth of METERING (some
     * traffic goes uncharged), but not the user table -- a torn WAL tail
     * is discarded whole on recovery and the committed database is
     * intact. Losing seconds of accounting is acceptable; losing a user's
     * row would not be. */
    rc = sqlite3_exec(m->db,
                      "PRAGMA journal_mode = WAL;"
                      "PRAGMA synchronous = NORMAL;",
                      NULL, NULL, &sqlite_err);
    if (rc != SQLITE_OK) {
        um_set_err(err, err_cap, "usermanager: pragma failed: %s",
                   sqlite_err ? sqlite_err : sqlite3_errstr(rc));
        sqlite3_free(sqlite_err);
        cloak_usermanager_close(m);
        return CLOAK_USER_ERR_DB;
    }

    /* CREATE TABLE IF NOT EXISTS: an existing database is opened
     * unchanged, which also means a database created before the uid CHECK
     * existed keeps its old constraints. cloak_usermanager_list defends
     * against that by skipping wrong-length rows on read. */
    rc = sqlite3_exec(m->db, UM_SCHEMA, NULL, NULL, &sqlite_err);
    if (rc != SQLITE_OK) {
        um_set_err(err, err_cap, "usermanager: schema failed: %s",
                   sqlite_err ? sqlite_err : sqlite3_errstr(rc));
        sqlite3_free(sqlite_err);
        cloak_usermanager_close(m);
        return CLOAK_USER_ERR_DB;
    }

    for (i = 0; i < UM_ST_COUNT; i++) {
        rc = sqlite3_prepare_v2(m->db, UM_SQL[i], -1, &m->st[i], NULL);
        if (rc != SQLITE_OK) {
            um_set_err(err, err_cap, "usermanager: prepare failed: %s",
                       sqlite3_errmsg(m->db));
            cloak_usermanager_close(m);
            return CLOAK_USER_ERR_DB;
        }
    }

    *out = m;
    return 0;
}

void cloak_usermanager_close(cloak_usermanager_t *m) {
    int i;

    if (m == NULL) {
        return;
    }
    /* Finalize before close: sqlite3_close refuses while any statement is
     * still live. Both loops tolerate NULL entries, which is what makes
     * this safe on the partially-opened manager every failure path in
     * open hands over, and on a zeroed struct generally. */
    for (i = 0; i < UM_ST_COUNT; i++) {
        sqlite3_finalize(m->st[i]);
        m->st[i] = NULL;
    }
    if (m->db != NULL) {
        sqlite3_close(m->db);
        m->db = NULL;
    }
    free(m);
}

/* ------------------------------------------------------------------ */
/* The seven operations                                                */
/* ------------------------------------------------------------------ */

int cloak_usermanager_authenticate(cloak_usermanager_t *m,
                                   const uint8_t uid[CLOAK_UID_LEN],
                                   int64_t *out_up_rate, int64_t *out_down_rate) {
    cloak_user_info_t u;
    int rc;

    if (m == NULL) {
        return CLOAK_USER_ERR_ARG;
    }
    if (m->db == NULL) {
        return CLOAK_USER_ERR_VOID;
    }
    if (uid == NULL) {
        return CLOAK_USER_ERR_ARG;
    }

    rc = um_load(m, uid, &u);
    if (rc != 0) {
        return rc;
    }
    rc = um_check_gates(&u, m->now_fn(m->now_userdata));
    if (rc != 0) {
        return rc;
    }
    /* Written only once the answer is yes: a caller that ignores the
     * return code must see its own values, not a plausible zero. */
    if (out_up_rate != NULL) {
        *out_up_rate = u.up_rate;
    }
    if (out_down_rate != NULL) {
        *out_down_rate = u.down_rate;
    }
    return 0;
}

int cloak_usermanager_authorise_new_session(cloak_usermanager_t *m,
                                            const uint8_t uid[CLOAK_UID_LEN],
                                            int num_existing_sessions) {
    cloak_user_info_t u;
    int rc;

    if (m == NULL) {
        return CLOAK_USER_ERR_ARG;
    }
    if (m->db == NULL) {
        return CLOAK_USER_ERR_VOID;
    }
    if (uid == NULL) {
        return CLOAK_USER_ERR_ARG;
    }

    rc = um_load(m, uid, &u);
    if (rc != 0) {
        return rc;
    }
    rc = um_check_gates(&u, m->now_fn(m->now_userdata));
    if (rc != 0) {
        return rc;
    }
    /* The cap is checked LAST, after the credit and expiry gates, so a
     * user who has run out of credit is told that rather than being told
     * they have too many sessions. */
    if (num_existing_sessions >= u.sessions_cap) {
        return CLOAK_USER_ERR_SESSIONS_CAP;
    }
    return 0;
}

int cloak_usermanager_upload_status(cloak_usermanager_t *m,
                                    const cloak_user_status_t *updates,
                                    size_t n_updates,
                                    cloak_user_terminate_t *out_terminate,
                                    size_t out_cap, size_t *out_n) {
    sqlite3_stmt *meter;
    size_t total = 0;
    size_t i;
    int rc;

    if (m == NULL) {
        return CLOAK_USER_ERR_ARG;
    }
    if (m->db == NULL) {
        return CLOAK_USER_ERR_VOID;
    }
    if (out_n == NULL || (n_updates > 0 && updates == NULL) ||
        (out_cap > 0 && out_terminate == NULL)) {
        return CLOAK_USER_ERR_ARG;
    }

    *out_n = 0;
    /* Matches Go's early return: an empty batch opens no transaction. */
    if (n_updates == 0) {
        return 0;
    }

    meter = m->st[UM_ST_METER];

    /* ONE transaction for the whole batch: one commit for N users rather
     * than N, which on this reactor is the difference between one WAL
     * append and a stall proportional to the panel's drain size. It is
     * also all-or-nothing -- a batch that fails partway leaves no user
     * charged, which is easier to reason about than a half-applied drain. */
    rc = um_run(m, UM_ST_BEGIN);
    if (rc != 0) {
        return rc;
    }

    for (i = 0; i < n_updates; i++) {
        const cloak_user_status_t *s = &updates[i];
        const char *reason = NULL;
        cloak_user_info_t u;
        int64_t new_up, new_down;

        rc = um_load(m, s->uid, &u);
        if (rc == CLOAK_USER_ERR_NOT_FOUND) {
            /* No write at all: the metering path must never resurrect a
             * user an operator has deleted. */
            reason = CLOAK_USER_TERMINATE_NO_SUCH_USER;
            goto emit;
        }
        if (rc != 0) {
            goto fail;
        }

        new_up = u.up_credit - s->up_usage;
        new_down = u.down_credit - s->down_usage;

        /* The new value is written back EVEN WHEN NON-POSITIVE. The debt
         * is the point: it is what keeps cloak_usermanager_authenticate
         * refusing this user on the next connection attempt instead of
         * letting them reconnect at zero and overdraw again. */
        if (um_bind_uid(meter, s->uid) != SQLITE_OK ||
            sqlite3_bind_int64(meter, 2, new_up) != SQLITE_OK ||
            sqlite3_bind_int64(meter, 3, new_down) != SQLITE_OK) {
            sqlite3_reset(meter);
            CLOAK_LOGE("usermanager: bind failed: %s", sqlite3_errmsg(m->db));
            rc = CLOAK_USER_ERR_DB;
            goto fail;
        }
        rc = um_run(m, UM_ST_METER);
        if (rc != 0) {
            goto fail;
        }

        /* AT MOST ONE terminate per user. Go appends inside each
         * condition's branch and so emits several entries for a user who
         * matches several; this port emits one, because a caller that
         * terminates the same user twice is a bug waiting to happen and
         * every reason Go would emit is true anyway.
         *
         * The reason that wins is the one the user can do least about:
         * expiry is not fixable by a top-up, so it outranks both credits.
         * Between the two credits, download outranks upload, which is the
         * value Go's own local `resp` ends up holding -- so the message a
         * terminated user sees matches upstream. */
        if (new_up <= 0) {
            reason = CLOAK_USER_TERMINATE_NO_UP_CREDIT;
        }
        if (new_down <= 0) {
            reason = CLOAK_USER_TERMINATE_NO_DOWN_CREDIT;
        }
        if (m->now_fn(m->now_userdata) > u.expiry_time) {
            reason = CLOAK_USER_TERMINATE_EXPIRED;
        }
        if (reason == NULL) {
            continue;
        }

    emit:
        /* total counts every terminate, whether or not it fit, so the
         * caller can retry with a bigger buffer knowing the true size. */
        if (total < out_cap) {
            memcpy(out_terminate[total].uid, s->uid, CLOAK_UID_LEN);
            out_terminate[total].reason = reason;
        }
        total++;
    }

    rc = um_run(m, UM_ST_COMMIT);
    if (rc != 0) {
        goto fail;
    }
    *out_n = total;
    return 0;

fail:
    /* Best effort: if the rollback itself fails there is nothing further
     * this layer can do, and the caller is already being told the batch
     * did not apply. */
    (void)um_run(m, UM_ST_ROLLBACK);
    return rc;
}

int cloak_usermanager_list(cloak_usermanager_t *m, cloak_user_info_t *out,
                           size_t out_cap, size_t *out_n) {
    sqlite3_stmt *st;
    size_t total = 0;
    int rc;

    if (m == NULL) {
        return CLOAK_USER_ERR_ARG;
    }
    if (m->db == NULL) {
        return CLOAK_USER_ERR_VOID;
    }
    if (out_n == NULL || (out_cap > 0 && out == NULL)) {
        return CLOAK_USER_ERR_ARG;
    }

    *out_n = 0;
    st = m->st[UM_ST_LIST];

    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const void *uid = sqlite3_column_blob(st, 0);
        int uid_len = sqlite3_column_bytes(st, 0);

        /* A row whose uid is the wrong length cannot have come from this
         * module (the schema's CHECK forbids it) but could come from a
         * database created before that constraint existed. Skipping it --
         * and not counting it -- keeps the reported total equal to the
         * number of users a caller can actually be handed. */
        if (uid == NULL || uid_len != CLOAK_UID_LEN) {
            CLOAK_LOGW("usermanager: skipping row with a %d-byte uid", uid_len);
            continue;
        }
        if (total < out_cap) {
            cloak_user_info_t *u = &out[total];
            memcpy(u->uid, uid, CLOAK_UID_LEN);
            u->sessions_cap = sqlite3_column_int(st, 1);
            u->up_rate = sqlite3_column_int64(st, 2);
            u->down_rate = sqlite3_column_int64(st, 3);
            u->up_credit = sqlite3_column_int64(st, 4);
            u->down_credit = sqlite3_column_int64(st, 5);
            u->expiry_time = sqlite3_column_int64(st, 6);
        }
        total++;
    }
    sqlite3_reset(st);

    if (rc != SQLITE_DONE) {
        CLOAK_LOGE("usermanager: list failed: %s", sqlite3_errmsg(m->db));
        return CLOAK_USER_ERR_DB;
    }
    *out_n = total;
    return 0;
}

int cloak_usermanager_get(cloak_usermanager_t *m, const uint8_t uid[CLOAK_UID_LEN],
                          cloak_user_info_t *out) {
    if (m == NULL) {
        return CLOAK_USER_ERR_ARG;
    }
    if (m->db == NULL) {
        return CLOAK_USER_ERR_VOID;
    }
    if (uid == NULL || out == NULL) {
        return CLOAK_USER_ERR_ARG;
    }
    return um_load(m, uid, out);
}

int cloak_usermanager_write(cloak_usermanager_t *m, const cloak_user_info_t *info,
                            uint32_t fields) {
    sqlite3_stmt *st;
    int ok = SQLITE_OK;

    if (m == NULL) {
        return CLOAK_USER_ERR_ARG;
    }
    if (m->db == NULL) {
        return CLOAK_USER_ERR_VOID;
    }
    /* Unknown mask bits are refused rather than ignored: the admin API
     * will forward a mask decoded off the wire, and a bit this build does
     * not understand means the caller and this module disagree about what
     * the request says. Silently dropping it would apply a different
     * update than the one that was asked for. */
    if (info == NULL || (fields & ~(uint32_t)CLOAK_USER_FIELD_ALL) != 0) {
        return CLOAK_USER_ERR_ARG;
    }

    st = m->st[UM_ST_WRITE];

    /* Every parameter is bound on every call -- value when the mask names
     * the field, SQL NULL when it does not. Binding all seven
     * unconditionally rather than relying on sqlite3_reset preserving the
     * previous call's bindings is what keeps one write from leaking a
     * field into the next. */
    if (um_bind_uid(st, info->uid) != SQLITE_OK) {
        sqlite3_reset(st);
        CLOAK_LOGE("usermanager: bind failed: %s", sqlite3_errmsg(m->db));
        return CLOAK_USER_ERR_DB;
    }
    ok |= (fields & CLOAK_USER_FIELD_SESSIONS_CAP)
              ? sqlite3_bind_int(st, 2, info->sessions_cap)
              : sqlite3_bind_null(st, 2);
    ok |= (fields & CLOAK_USER_FIELD_UP_RATE)
              ? sqlite3_bind_int64(st, 3, info->up_rate)
              : sqlite3_bind_null(st, 3);
    ok |= (fields & CLOAK_USER_FIELD_DOWN_RATE)
              ? sqlite3_bind_int64(st, 4, info->down_rate)
              : sqlite3_bind_null(st, 4);
    ok |= (fields & CLOAK_USER_FIELD_UP_CREDIT)
              ? sqlite3_bind_int64(st, 5, info->up_credit)
              : sqlite3_bind_null(st, 5);
    ok |= (fields & CLOAK_USER_FIELD_DOWN_CREDIT)
              ? sqlite3_bind_int64(st, 6, info->down_credit)
              : sqlite3_bind_null(st, 6);
    ok |= (fields & CLOAK_USER_FIELD_EXPIRY_TIME)
              ? sqlite3_bind_int64(st, 7, info->expiry_time)
              : sqlite3_bind_null(st, 7);
    if (ok != SQLITE_OK) {
        sqlite3_reset(st);
        CLOAK_LOGE("usermanager: bind failed: %s", sqlite3_errmsg(m->db));
        return CLOAK_USER_ERR_DB;
    }

    return um_run(m, UM_ST_WRITE);
}

int cloak_usermanager_delete(cloak_usermanager_t *m,
                             const uint8_t uid[CLOAK_UID_LEN]) {
    sqlite3_stmt *st;
    int rc;
    int changed;

    if (m == NULL) {
        return CLOAK_USER_ERR_ARG;
    }
    if (m->db == NULL) {
        return CLOAK_USER_ERR_VOID;
    }
    if (uid == NULL) {
        return CLOAK_USER_ERR_ARG;
    }

    st = m->st[UM_ST_DELETE];
    if (um_bind_uid(st, uid) != SQLITE_OK) {
        sqlite3_reset(st);
        CLOAK_LOGE("usermanager: bind failed: %s", sqlite3_errmsg(m->db));
        return CLOAK_USER_ERR_DB;
    }
    rc = sqlite3_step(st);
    changed = sqlite3_changes(m->db);
    sqlite3_reset(st);
    if (rc != SQLITE_DONE) {
        CLOAK_LOGE("usermanager: delete failed: %s", sqlite3_errmsg(m->db));
        return CLOAK_USER_ERR_DB;
    }
    /* Go's DeleteBucket reports ErrBucketNotFound rather than succeeding
     * silently, and the admin API needs that distinction to tell an
     * operator the UID they typed was not there. */
    if (changed == 0) {
        return CLOAK_USER_ERR_NOT_FOUND;
    }
    return 0;
}
