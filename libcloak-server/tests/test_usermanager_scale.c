#define _POSIX_C_SOURCE 200809L
#include "cloak/usermanager.h"

#include "cloak/reactor.h"
#include "cloak/registry.h"
#include "cloak/userpanel.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>

#include "test_framework.h"

/* THE USER MANAGER AT THE SCALE THE REST OF THE SERVER CAN FORCE ON IT,
 * AND A NUMBER FOR THE STALL ITS PLAN ACCEPTED WITHOUT ONE.
 *
 * WHY THIS FILE EXISTS. test_usermanager.c has eighteen cases and the
 * largest number of users any of them puts in a database is a handful.
 * That is not an oversight about coverage; it is a gap about COST. This
 * module is SQLite-backed and sits on the authorisation path of every
 * connection, and
 * docs/superpowers/plans/2026-09-14-libcloak-server-usermanager-plan.md
 * D3 accepts, in writing, that "a genuinely slow or failing disk stalls
 * the reactor" -- a residual it takes deliberately, over a thread pool,
 * and then never measures. An accepted cost with no number attached is
 * not a trade a future reader can re-examine at their own disk and their
 * own user count. This file attaches the number.
 *
 * IT DOES NOT TRY TO SHOW THE STALL CANNOT HAPPEN. D3 already conceded
 * that it can. Case 4 says HOW LONG, from inside a running reactor, with
 * the disk's slowness induced rather than imagined.
 *
 * ------------------------------------------------------------------
 * THE TWO POPULATIONS, DERIVED
 * ------------------------------------------------------------------
 *
 * (1) SCALE_BATCH -- how many users can be settled in ONE call, on the
 * reactor thread, in one callback. This one is read off the tree rather
 * than assumed:
 *
 *     CLOAK_REGISTRY_MAX_SESSIONS         = 1024   (cloak/registry.h)
 *     CLOAK_USERPANEL_MAX_ACTIVE_USERS    = 1024   (= the session cap:
 *         worst case every session belongs to a DIFFERENT user, so the
 *         active-user table is one entry per session)
 *     CLOAK_USERPANEL_MAX_QUEUED_USERS    = 2048   (= 2x the active cap,
 *         because users that disconnect are drained onto the queue and
 *         replaced within one upload interval, so one interval's churn
 *         can hold twice the live population)
 *
 * so one cloak_usermanager_upload_status can be handed 2048 users, and
 * cloak/userpanel.h's periodic drain is the caller that does it, every
 * CLOAK_USERPANEL_DEFAULT_UPLOAD_INTERVAL_MS (60 s) by default. The
 * assertion below reads the symbol rather than the literal, so the two
 * cannot drift apart.
 *
 * (2) SCALE_USERS -- how many rows the table holds. Nothing in the tree
 * bounds this: it is the operator's subscriber base, not a cap. So it is
 * derived from the point where the manager's COST CHANGES CHARACTER,
 * which is a property of this code and is measurable.
 *
 * MEASURED, with the shim below counting every I/O the connection makes
 * (Debug, x86-64 Linux container, SQLite 3.50.4, page_size 4096,
 * mmap_size 0, cache_size -2000):
 *
 *     users    pages   disk reads per 1000 scattered authenticates
 *     21545      242                                             0
 *     40960      458                                             0
 *     43000      481                                             0
 *     43400      485                                            22
 *     44600      498                                           365
 *     64636      721                                           165
 *     65536      731                                           104
 *    262144     2918                                           997
 *
 * Two constants fall out of that table. The users table stores 89.4 rows
 * per 4 KiB page (43000/481, 65536/731 and 262144/2918 all agree to
 * within 0.5%), and the manager's page cache holds 482 +/- 3 of those
 * pages -- 481 pages still fit and 485 do not, which is SQLite's default
 * 2000 KiB cache divided by a page plus its per-page overhead.
 *
 * BELOW THAT LINE THE AUTHORISATION PATH NEVER TOUCHES THE DISK AT ALL,
 * and that is not a subtlety -- it is the single most important fact
 * about D3's residual. cloak_usermanager_open scans every row to
 * validate it (see its doc comment), which leaves the whole table in the
 * connection's page cache; while the table fits, every subsequent
 * authenticate is served from memory and NO disk, however slow, can stall
 * it. Above the line the cache thrashes and the reactor starts paying
 * disk latency per authentication.
 *
 *     SCALE_USERS = 1.5 * 482 pages * 89.4 rows/page = 64636
 *
 * The 1.5 is the one judgement here, and it is a measured one rather than
 * a taste: at 1.0x the cache the miss rate is 2.2% (485 pages, 22 reads
 * per 1000) and sits on a knee where a small change in SQLite's cache
 * accounting flips it to zero; at 1.5x it is 16.5% (721 pages, 165 reads
 * per 1000), an order of magnitude of margin for half again the
 * population. SCALE_SMALL_USERS is the same arithmetic at HALF the cache
 * (0.5 * 482 * 89.4 = 21545), which is the arm that has to read zero, and
 * it has the same factor of two of margin in the other direction.
 *
 * This is deliberately NOT sized from the session cap. Sessions bound how
 * many users can be CONNECTED at once; they say nothing about how many
 * rows are in the file, and sizing the table from the session cap would
 * repeat exactly the defect task 3 of this module diagnosed in the replay
 * cache -- a capacity derived from the server's concurrency with no term
 * for the thing that actually drives it.
 *
 * ------------------------------------------------------------------
 * WHAT THIS FILE WOULD CATCH THAT NOTHING ELSE DOES
 * ------------------------------------------------------------------
 *
 * Each of these was MUTATED into the module and the whole suite re-run,
 * rather than reasoned about.
 *
 *  - A MANAGER THAT ANSWERS authenticate FROM A CACHE INSTEAD OF THE
 *    DATABASE, and this is the one worth reading twice. Every row here is
 *    written by a SEPARATE sqlite3 connection and never through
 *    cloak_usermanager_write, and case 1 then has that sibling connection
 *    revoke a user's credit UNDERNEATH the open manager and requires the
 *    very next authenticate to refuse.
 *      MUTATED, one entry keyed on uid, invalidated by this module's own
 *      write/delete/upload_status -- which is the shape anyone optimising
 *      this would actually write: ALL 84 OTHER TESTS PASS and only this
 *      file fails, at the victim assertion in case 1. The suite could not
 *      see it because every other case writes through the manager, so an
 *      invalidation on its own writes is enough to keep them all green.
 *      A cruder cache with no invalidation at all is caught by
 *      test_usermanager.c too, so the distinction is exactly the one this
 *      case exists for.
 *  - A manager that returns the RIGHT answer for the WRONG user. Every
 *    user carries rates derived from its own index, and case 1 checks all
 *    64636 of them, so a bind that goes to a stale statement or an index
 *    that goes one row out is a mismatch count rather than a coincidence.
 *  - synchronous = FULL. MUTATED: test_usermanager.c passes, this file
 *    fails at case 3's saw_silent_commit -- the drain that wrote 500
 *    times and called fsync zero times writes zero times and syncs zero
 *    times instead, because every UPDATE has already been flushed. That
 *    assertion IS D3's first mitigation; there is nowhere else it is
 *    checked.
 *  - The whole batch in ONE transaction, D3's third mitigation. MUTATED
 *    by turning BEGIN/COMMIT/ROLLBACK into no-ops so each UPDATE
 *    autocommits: caught here AND by test_usermanager.c's rollback case,
 *    and this file additionally MEASURES what it costs -- the same drain
 *    goes from 3865 disk operations to 6459, and this file's own runtime
 *    from 3.5 s to 7.8 s.
 *  - The list contract at a size no other case reaches: 64636 rows in
 *    ascending uid order with the truncation rule holding.
 *
 * ------------------------------------------------------------------
 * COST AND FOOTPRINT, because this file is the expensive one
 * ------------------------------------------------------------------
 * The two databases are built ONCE and shared by all four cases; building
 * them per case would double the file's runtime for nothing. The large
 * one is 2.96 MB on disk, the small one 1.0 MB, and the write-ahead log
 * peaks at SQLite's 1000-frame autocheckpoint threshold, 4.1 MB. All of
 * it is unlinked at the end of the run and before it, the way
 * test_usermanager.c explains at its own top. */

/* ------------------------------------------------------------------ */
/* The I/O shim: a VFS that counts, and can slow down, every operation  */
/* the database connection performs.                                    */
/* ------------------------------------------------------------------ */

/* WHY A VFS AND NOT AN LD_PRELOAD. This file needs two things the write
 * shim beside it cannot give: a COUNT of the I/O a given call performs
 * (the shim only fails writes), and a delay applied to reads and fsyncs
 * as well as writes. A VFS wrapper is also the layer at which a slow disk
 * actually presents itself to SQLite, so what is induced here has the
 * same shape as the thing being modelled rather than merely the same
 * symptom. It is registered as the DEFAULT VFS, which is what lets it
 * cover cloak_usermanager_open unchanged: the manager calls
 * sqlite3_open_v2 with a NULL vfs name exactly as it does in production,
 * and nothing in the code under measurement is adjusted to accommodate
 * the measurement. */

typedef struct {
    long      reads, writes, syncs, opens;
    long      read_bytes, write_bytes;
    long long injected_ns; /* wall clock this shim deliberately burned */
} slow_counters_t;

static slow_counters_t slow_ctr;
static long slow_delay_io_ns = 0;

static long long slow_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* THE DELAY IS A BUSY WAIT ON CLOCK_MONOTONIC, NOT nanosleep, AND THE
 * REASON IS A MEASUREMENT. The first version of this shim slept. Against
 * a 2048-user drain it asked for 3417 ms of sleep across 3417 calls and
 * burned 8187 ms of wall clock doing it -- 2.4x its own nominal, because
 * a 1 ms nanosleep on a loaded container costs a scheduling round trip it
 * does not account for. Every one of those excess milliseconds would have
 * been reported below as reactor stall, and every one of them would have
 * been this harness rather than the code: precisely the class of defect
 * this project has now found five times in its own tests rather than in
 * what they test. A spin has no such term. It costs CPU, which is not
 * what is being measured, and it blocks the calling thread exactly as a
 * blocking read does, which is. */
static void slow_delay(void) {
    long long t0, target;
    if (slow_delay_io_ns <= 0) {
        return;
    }
    t0 = slow_mono_ns();
    target = t0 + slow_delay_io_ns;
    while (slow_mono_ns() < target) {
        /* spin */
    }
    slow_ctr.injected_ns += slow_mono_ns() - t0;
}

typedef struct {
    sqlite3_file  base;
    sqlite3_file *real;
} slow_file_t;

static sqlite3_vfs  slow_vfs;
static sqlite3_vfs *slow_base;

#define SLOW_REAL(p) (((slow_file_t *)(void *)(p))->real)

static int slow_f_close(sqlite3_file *p) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xClose(r);
}
static int slow_f_read(sqlite3_file *p, void *buf, int n, sqlite3_int64 off) {
    sqlite3_file *r = SLOW_REAL(p);
    slow_ctr.reads++;
    slow_ctr.read_bytes += n;
    slow_delay();
    return r->pMethods->xRead(r, buf, n, off);
}
static int slow_f_write(sqlite3_file *p, const void *buf, int n, sqlite3_int64 off) {
    sqlite3_file *r = SLOW_REAL(p);
    slow_ctr.writes++;
    slow_ctr.write_bytes += n;
    slow_delay();
    return r->pMethods->xWrite(r, buf, n, off);
}
static int slow_f_truncate(sqlite3_file *p, sqlite3_int64 sz) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xTruncate(r, sz);
}
static int slow_f_sync(sqlite3_file *p, int flags) {
    sqlite3_file *r = SLOW_REAL(p);
    slow_ctr.syncs++;
    slow_delay();
    return r->pMethods->xSync(r, flags);
}
static int slow_f_size(sqlite3_file *p, sqlite3_int64 *sz) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xFileSize(r, sz);
}
static int slow_f_lock(sqlite3_file *p, int l) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xLock(r, l);
}
static int slow_f_unlock(sqlite3_file *p, int l) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xUnlock(r, l);
}
static int slow_f_check_reserved(sqlite3_file *p, int *out) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xCheckReservedLock(r, out);
}
static int slow_f_control(sqlite3_file *p, int op, void *arg) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xFileControl(r, op, arg);
}
static int slow_f_sector(sqlite3_file *p) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xSectorSize(r);
}
static int slow_f_devchar(sqlite3_file *p) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xDeviceCharacteristics(r);
}
/* WAL needs the shared-memory methods; a wrapper that dropped them would
 * fail every open in journal_mode = WAL, which is the mode under test. */
static int slow_f_shm_map(sqlite3_file *p, int pg, int sz, int ext, void volatile **out) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xShmMap(r, pg, sz, ext, out);
}
static int slow_f_shm_lock(sqlite3_file *p, int off, int n, int flags) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xShmLock(r, off, n, flags);
}
static void slow_f_shm_barrier(sqlite3_file *p) {
    sqlite3_file *r = SLOW_REAL(p);
    r->pMethods->xShmBarrier(r);
}
static int slow_f_shm_unmap(sqlite3_file *p, int del) {
    sqlite3_file *r = SLOW_REAL(p);
    return r->pMethods->xShmUnmap(r, del);
}
/* THE ONE THING THIS SHIM CANNOT SEE, stated where it is relevant. If
 * SQLite ever serves a page through xFetch (mmap), the page-in is a fault
 * on mapped memory and neither the count nor the delay below applies to
 * it. This build measures mmap_size = 0, so every page today arrives
 * through xRead; a future build that turned mmap on would silently make
 * the read half of these numbers an undercount, which is why the case
 * below asserts a non-zero read count rather than trusting one. */
static int slow_f_fetch(sqlite3_file *p, sqlite3_int64 off, int n, void **out) {
    sqlite3_file *r = SLOW_REAL(p);
    if (r->pMethods->iVersion < 3 || r->pMethods->xFetch == NULL) {
        *out = NULL;
        return SQLITE_OK;
    }
    return r->pMethods->xFetch(r, off, n, out);
}
static int slow_f_unfetch(sqlite3_file *p, sqlite3_int64 off, void *q) {
    sqlite3_file *r = SLOW_REAL(p);
    if (r->pMethods->iVersion < 3 || r->pMethods->xUnfetch == NULL) {
        return SQLITE_OK;
    }
    return r->pMethods->xUnfetch(r, off, q);
}

static const sqlite3_io_methods slow_io = {
    3, slow_f_close, slow_f_read, slow_f_write, slow_f_truncate, slow_f_sync,
    slow_f_size, slow_f_lock, slow_f_unlock, slow_f_check_reserved,
    slow_f_control, slow_f_sector, slow_f_devchar, slow_f_shm_map,
    slow_f_shm_lock, slow_f_shm_barrier, slow_f_shm_unmap, slow_f_fetch,
    slow_f_unfetch
};

static int slow_open(sqlite3_vfs *v, const char *name, sqlite3_file *f, int flags,
                     int *out_flags) {
    slow_file_t *p = (slow_file_t *)(void *)f;
    int rc;
    (void)v;
    p->real = (sqlite3_file *)(void *)((char *)f + sizeof(slow_file_t));
    p->base.pMethods = NULL;
    rc = slow_base->xOpen(slow_base, name, p->real, flags, out_flags);
    /* A failed open can still leave pMethods NULL, and SQLite calls
     * xClose only when pMethods is set -- so the wrapper must be attached
     * exactly when the real one was. */
    if (rc == SQLITE_OK && p->real->pMethods != NULL) {
        slow_ctr.opens++;
        p->base.pMethods = &slow_io;
    }
    return rc;
}
static int slow_delete(sqlite3_vfs *v, const char *n, int s) {
    (void)v;
    return slow_base->xDelete(slow_base, n, s);
}
static int slow_access(sqlite3_vfs *v, const char *n, int f, int *o) {
    (void)v;
    return slow_base->xAccess(slow_base, n, f, o);
}
static int slow_fullpath(sqlite3_vfs *v, const char *n, int c, char *o) {
    (void)v;
    return slow_base->xFullPathname(slow_base, n, c, o);
}
static int slow_randomness(sqlite3_vfs *v, int n, char *o) {
    (void)v;
    return slow_base->xRandomness(slow_base, n, o);
}
static int slow_sleep(sqlite3_vfs *v, int us) {
    (void)v;
    return slow_base->xSleep(slow_base, us);
}
static int slow_current_time(sqlite3_vfs *v, double *o) {
    (void)v;
    return slow_base->xCurrentTime(slow_base, o);
}
static int slow_last_error(sqlite3_vfs *v, int n, char *o) {
    (void)v;
    return slow_base->xGetLastError(slow_base, n, o);
}
static int slow_current_time64(sqlite3_vfs *v, sqlite3_int64 *o) {
    (void)v;
    return slow_base->xCurrentTimeInt64(slow_base, o);
}

static void slow_vfs_install(void) {
    slow_base = sqlite3_vfs_find(NULL);
    memset(&slow_vfs, 0, sizeof(slow_vfs));
    slow_vfs.iVersion = 2;
    slow_vfs.szOsFile = (int)sizeof(slow_file_t) + slow_base->szOsFile;
    slow_vfs.mxPathname = slow_base->mxPathname;
    slow_vfs.zName = "cloak-slowfs";
    slow_vfs.xOpen = slow_open;
    slow_vfs.xDelete = slow_delete;
    slow_vfs.xAccess = slow_access;
    slow_vfs.xFullPathname = slow_fullpath;
    slow_vfs.xDlOpen = slow_base->xDlOpen;
    slow_vfs.xDlError = slow_base->xDlError;
    slow_vfs.xDlSym = slow_base->xDlSym;
    slow_vfs.xDlClose = slow_base->xDlClose;
    slow_vfs.xRandomness = slow_randomness;
    slow_vfs.xSleep = slow_sleep;
    slow_vfs.xCurrentTime = slow_current_time;
    slow_vfs.xGetLastError = slow_last_error;
    slow_vfs.xCurrentTimeInt64 = slow_current_time64;
    sqlite3_vfs_register(&slow_vfs, 1 /* make default */);
}

static void slow_reset(void) {
    memset(&slow_ctr, 0, sizeof(slow_ctr));
}

/* ------------------------------------------------------------------ */
/* The two populations                                                 */
/* ------------------------------------------------------------------ */

/* 1.5 * 482 cached pages * 89.4 rows per page -- see the derivation at
 * the top of this file. Both numbers are measured, and case 2 is the case
 * that fails if either has moved. */
#define SCALE_USERS       64636u
/* 0.5 * 482 * 89.4: the arm that must do no disk I/O at all. */
#define SCALE_SMALL_USERS 21545u

/* Read off cloak/userpanel.h rather than written as 2048, so that raising
 * the session cap moves this case with it instead of leaving it behind. */
#define SCALE_BATCH ((size_t)CLOAK_USERPANEL_MAX_QUEUED_USERS)

/* One terminate every 16 drained users: 128 of them, which is comfortably
 * more than the 64-entry buffer below, so one drain exercises both the
 * true-count contract and the truncation contract at a size no other case
 * reaches. */
#define SCALE_TERMINATE_EVERY 16u
#define SCALE_TERM_CAP        64u

/* The injected per-I/O latency of case 4, and the one number in this file
 * that is an assumption rather than a measurement: 1 ms is a contended
 * network block device, or a 7200 rpm spindle at about its best. It is a
 * parameter, not a finding -- the finding is the OPERATION COUNT the case
 * prints beside it, which is the property of this code, and a reader with
 * a different disk multiplies. */
#define SCALE_INJECT_NS 1000000L

static int64_t g_now = 1700000000;
static int64_t scale_now(void *ud) {
    (void)ud;
    return *(const int64_t *)ud;
}

static char g_big_path[512];
static char g_small_path[512];

static void scale_tmp_path(char *buf, size_t cap, const char *tag) {
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(buf, cap, "%s/cloak_ums_%ld_%s.db", dir, (long)getpid(), tag);
}

static void scale_unlink(const char *path) {
    char aux[600];
    unlink(path);
    snprintf(aux, sizeof(aux), "%s-wal", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-shm", path);
    unlink(aux);
}

/* Big-endian in the first four bytes, so memcmp order over the blob is
 * index order and cloak_usermanager_list's ascending-uid contract can be
 * checked against a counter rather than against a sort. */
static void scale_uid(uint8_t *uid, unsigned n) {
    memset(uid, 0, CLOAK_UID_LEN);
    uid[0] = (uint8_t)(n >> 24);
    uid[1] = (uint8_t)(n >> 16);
    uid[2] = (uint8_t)(n >> 8);
    uid[3] = (uint8_t)n;
}

/* Rates that identify their own row. An authenticate that returns the
 * wrong user's record, or a statement whose bindings have gone stale
 * under load, produces a rate that does not match the uid that asked --
 * which is a counted mismatch below rather than a plausible-looking
 * number nobody checks. */
static int64_t scale_up_rate(unsigned i) {
    return 1000 + (int64_t)i;
}
static int64_t scale_down_rate(unsigned i) {
    return 9000000 + (int64_t)i;
}
#define SCALE_CREDIT 1000000

/* POPULATED THROUGH A SEPARATE CONNECTION, ON PURPOSE. Nothing here goes
 * through cloak_usermanager_write, so every row the manager later returns
 * has to have come from the database itself; a manager that answered out
 * of any in-process cache would find nothing to answer with. It is also
 * what makes the build affordable: 64636 rows in ONE transaction instead
 * of 64636 commits. */
static int scale_populate(const char *path, unsigned n) {
    sqlite3      *db = NULL;
    sqlite3_stmt *st = NULL;
    unsigned      i;
    int           ok = 1;

    if (sqlite3_open(path, &db) != SQLITE_OK) {
        return 0;
    }
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db,
                           "INSERT INTO users (uid, sessions_cap, up_rate,"
                           " down_rate, up_credit, down_credit, expiry_time)"
                           " VALUES (?1, 4, ?2, ?3, ?4, ?4, ?5)",
                           -1, &st, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }
    for (i = 0; i < n && ok; i++) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, i);
        sqlite3_reset(st);
        ok = sqlite3_bind_blob(st, 1, uid, CLOAK_UID_LEN, SQLITE_TRANSIENT) == SQLITE_OK &&
             sqlite3_bind_int64(st, 2, scale_up_rate(i)) == SQLITE_OK &&
             sqlite3_bind_int64(st, 3, scale_down_rate(i)) == SQLITE_OK &&
             sqlite3_bind_int64(st, 4, SCALE_CREDIT) == SQLITE_OK &&
             sqlite3_bind_int64(st, 5, g_now + 86400) == SQLITE_OK &&
             sqlite3_step(st) == SQLITE_DONE;
    }
    sqlite3_finalize(st);
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        ok = 0;
    }
    sqlite3_close(db);
    return ok;
}

/* Creates the schema (by opening and closing a manager) and fills it. */
static int scale_build(const char *path, unsigned n) {
    cloak_usermanager_t *m = NULL;
    char err[256];
    scale_unlink(path);
    if (cloak_usermanager_open(&m, path, scale_now, &g_now, err, sizeof(err)) != 0) {
        fprintf(stderr, "scale_build: %s\n", err);
        return 0;
    }
    cloak_usermanager_close(m);
    return scale_populate(path, n);
}

static void case_build_databases(void) {
    slow_vfs_install();
    scale_tmp_path(g_big_path, sizeof(g_big_path), "big");
    scale_tmp_path(g_small_path, sizeof(g_small_path), "small");
    ASSERT_TRUE(scale_build(g_big_path, SCALE_USERS));
    ASSERT_TRUE(scale_build(g_small_path, SCALE_SMALL_USERS));
}

static void case_drop_databases(void) {
    scale_unlink(g_big_path);
    scale_unlink(g_small_path);
}

/* ------------------------------------------------------------------ */
/* Case 1: SCALE_USERS users, interleaved, each answered as itself.     */
/* ------------------------------------------------------------------ */
static void case_population_at_scale(void) {
    cloak_usermanager_t *m = NULL;
    char                 err[256];
    cloak_user_info_t   *listed = NULL;
    cloak_user_status_t *updates = NULL;
    cloak_user_terminate_t term[SCALE_TERM_CAP];
    size_t               n_out = 0, i;
    unsigned             k;
    unsigned             bad_rate = 0, bad_rc = 0, bad_get = 0, bad_cap = 0;
    unsigned             expect_terms;

    ASSERT_EQ_INT(cloak_usermanager_open(&m, g_big_path, scale_now, &g_now, err,
                                         sizeof(err)),
                  0);
    if (m == NULL) {
        return;
    }

    /* EVERY user authenticates, and every one is answered with ITS OWN
     * rates. Interleaved with authorise_new_session and get rather than
     * run as three separate passes, because a manager whose statements
     * are shared across the three calls is exactly what an interleaved
     * sequence disturbs and three clean passes do not. */
    for (k = 0; k < SCALE_USERS; k++) {
        uint8_t  uid[CLOAK_UID_LEN];
        int64_t  up = -1, down = -1;
        int      rc;

        scale_uid(uid, k);
        rc = cloak_usermanager_authenticate(m, uid, &up, &down);
        if (rc != 0) {
            bad_rc++;
        } else if (up != scale_up_rate(k) || down != scale_down_rate(k)) {
            bad_rate++;
        }

        /* sessions_cap is 4 for every row: three existing sessions may
         * open a fourth, four may not. Checked on every sixteenth user so
         * the cap is exercised across the whole table rather than at one
         * end of it. */
        if ((k % 16u) == 0u) {
            if (cloak_usermanager_authorise_new_session(m, uid, 3) != 0) {
                bad_cap++;
            }
            if (cloak_usermanager_authorise_new_session(m, uid, 4) !=
                CLOAK_USER_ERR_SESSIONS_CAP) {
                bad_cap++;
            }
            {
                cloak_user_info_t got;
                memset(&got, 0, sizeof(got));
                if (cloak_usermanager_get(m, uid, &got) != 0 ||
                    got.up_rate != scale_up_rate(k) ||
                    got.down_rate != scale_down_rate(k) ||
                    memcmp(got.uid, uid, CLOAK_UID_LEN) != 0) {
                    bad_get++;
                }
            }
        }
    }
    ASSERT_EQ_INT(bad_rc, 0);
    ASSERT_EQ_INT(bad_rate, 0);
    ASSERT_EQ_INT(bad_cap, 0);
    ASSERT_EQ_INT(bad_get, 0);

    /* THE DATABASE IS THE AUTHORITY, and this is the assertion that says
     * so. A sibling connection revokes one user's upload credit while the
     * manager is open and has just read that very row; the next
     * authenticate must refuse THAT user and must still admit its
     * neighbour. Any cache of a row, a page or a last answer passes every
     * other case in this tree and fails here. */
    {
        sqlite3 *raw = NULL;
        uint8_t  victim[CLOAK_UID_LEN], neighbour[CLOAK_UID_LEN];
        /* Deliberately NOT a multiple of the drain's stride, and not one
         * past a multiple either. The first version of this case used
         * SCALE_USERS/3, which is exactly 695 strides in, so revoking its
         * credit here made it a 129th terminate below and shifted twenty
         * of the buffered entries -- the case failed on its own setup.
         * The stride is SCALE_USERS/SCALE_BATCH; +5 lands between two
         * drained rows and beside neither. */
        const unsigned vi = SCALE_USERS / 3u + 5u;

        scale_uid(victim, vi);
        scale_uid(neighbour, vi + 1u);
        ASSERT_EQ_INT(cloak_usermanager_authenticate(m, victim, NULL, NULL), 0);

        ASSERT_EQ_INT(sqlite3_open(g_big_path, &raw), SQLITE_OK);
        {
            sqlite3_stmt *st = NULL;
            ASSERT_EQ_INT(sqlite3_prepare_v2(raw,
                                             "UPDATE users SET up_credit = 0"
                                             " WHERE uid = ?1",
                                             -1, &st, NULL),
                          SQLITE_OK);
            ASSERT_EQ_INT(sqlite3_bind_blob(st, 1, victim, CLOAK_UID_LEN,
                                            SQLITE_TRANSIENT),
                          SQLITE_OK);
            ASSERT_EQ_INT(sqlite3_step(st), SQLITE_DONE);
            sqlite3_finalize(st);
        }
        sqlite3_close(raw);

        ASSERT_EQ_INT(cloak_usermanager_authenticate(m, victim, NULL, NULL),
                      CLOAK_USER_ERR_NO_UP_CREDIT);
        ASSERT_EQ_INT(cloak_usermanager_authenticate(m, neighbour, NULL, NULL), 0);
    }

    /* The list contract at a size no other case reaches: the true count,
     * ascending uid order, and the truncation rule. */
    n_out = 0;
    ASSERT_EQ_INT(cloak_usermanager_list(m, NULL, 0, &n_out), 0);
    ASSERT_EQ_INT(n_out, SCALE_USERS);

    listed = (cloak_user_info_t *)calloc(SCALE_USERS, sizeof(*listed));
    ASSERT_TRUE(listed != NULL);
    if (listed != NULL) {
        unsigned out_of_order = 0, wrong_uid = 0;
        n_out = 0;
        ASSERT_EQ_INT(cloak_usermanager_list(m, listed, SCALE_USERS, &n_out), 0);
        ASSERT_EQ_INT(n_out, SCALE_USERS);
        for (k = 0; k < SCALE_USERS; k++) {
            uint8_t want[CLOAK_UID_LEN];
            scale_uid(want, k);
            if (memcmp(listed[k].uid, want, CLOAK_UID_LEN) != 0) {
                wrong_uid++;
            }
            if (k > 0 && memcmp(listed[k - 1].uid, listed[k].uid, CLOAK_UID_LEN) >= 0) {
                out_of_order++;
            }
        }
        ASSERT_EQ_INT(wrong_uid, 0);
        ASSERT_EQ_INT(out_of_order, 0);

        /* Truncated to a thousand: the first thousand in the same order,
         * and *out_n still the true total. */
        memset(listed, 0, (size_t)1000 * sizeof(*listed));
        n_out = 0;
        ASSERT_EQ_INT(cloak_usermanager_list(m, listed, 1000, &n_out), 0);
        ASSERT_EQ_INT(n_out, SCALE_USERS);
        {
            uint8_t want[CLOAK_UID_LEN];
            scale_uid(want, 999);
            ASSERT_MEM_EQ(listed[999].uid, want, CLOAK_UID_LEN);
        }
        free(listed);
    }

    /* ONE DRAIN OF SCALE_BATCH USERS -- the largest single unit of work
     * the panel can hand this module, spread across the whole table so
     * the transaction touches almost every page of it. */
    updates = (cloak_user_status_t *)calloc(SCALE_BATCH, sizeof(*updates));
    ASSERT_TRUE(updates != NULL);
    if (updates == NULL) {
        cloak_usermanager_close(m);
        return;
    }
    expect_terms = 0;
    for (i = 0; i < SCALE_BATCH; i++) {
        unsigned idx = (unsigned)i * (SCALE_USERS / (unsigned)SCALE_BATCH);
        scale_uid(updates[i].uid, idx);
        updates[i].num_session = 1;
        updates[i].active = 1;
        updates[i].timestamp = g_now;
        updates[i].down_usage = 11;
        if ((i % SCALE_TERMINATE_EVERY) == 0) {
            /* Exactly exhausts the upload credit -> a terminate. */
            updates[i].up_usage = SCALE_CREDIT;
            expect_terms++;
        } else {
            updates[i].up_usage = 7;
        }
    }
    memset(term, 0, sizeof(term));
    n_out = 0;
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, updates, SCALE_BATCH, term,
                                                  SCALE_TERM_CAP, &n_out),
                  0);
    /* The TRUE count, which exceeds the buffer, and the first
     * SCALE_TERM_CAP of them in the order of the updates array. */
    ASSERT_EQ_INT(n_out, expect_terms);
    ASSERT_TRUE(expect_terms > SCALE_TERM_CAP);
    {
        unsigned bad_term = 0;
        for (i = 0; i < SCALE_TERM_CAP; i++) {
            uint8_t want[CLOAK_UID_LEN];
            scale_uid(want, (unsigned)(i * SCALE_TERMINATE_EVERY) *
                                (SCALE_USERS / (unsigned)SCALE_BATCH));
            if (memcmp(term[i].uid, want, CLOAK_UID_LEN) != 0 ||
                term[i].reason == NULL ||
                strcmp(term[i].reason, CLOAK_USER_TERMINATE_NO_UP_CREDIT) != 0) {
                bad_term++;
            }
        }
        ASSERT_EQ_INT(bad_term, 0);
    }

    /* And the arithmetic landed on the right rows: a drained user is
     * charged exactly, and the row beside it -- which was not in the
     * batch -- is untouched. Checked across the whole table rather than
     * at one end. */
    {
        unsigned bad_credit = 0;
        for (i = 0; i < SCALE_BATCH; i += 97) {
            unsigned idx = (unsigned)i * (SCALE_USERS / (unsigned)SCALE_BATCH);
            cloak_user_info_t got;
            uint8_t uid[CLOAK_UID_LEN];
            int64_t want_up = (i % SCALE_TERMINATE_EVERY) == 0 ? 0
                                                               : SCALE_CREDIT - 7;
            scale_uid(uid, idx);
            memset(&got, 0, sizeof(got));
            if (cloak_usermanager_get(m, uid, &got) != 0 ||
                got.up_credit != want_up ||
                got.down_credit != SCALE_CREDIT - 11) {
                bad_credit++;
            }
            scale_uid(uid, idx + 1u);
            memset(&got, 0, sizeof(got));
            if (cloak_usermanager_get(m, uid, &got) != 0 ||
                got.up_credit != SCALE_CREDIT || got.down_credit != SCALE_CREDIT) {
                bad_credit++;
            }
        }
        ASSERT_EQ_INT(bad_credit, 0);
    }

    free(updates);
    cloak_usermanager_close(m);
}

/* ------------------------------------------------------------------ */
/* Case 2: where the authorisation path can reach the disk at all.      */
/* ------------------------------------------------------------------ */

/* Walks every user once, in an order that is scattered across the table
 * rather than sequential, and reports the disk reads it caused. 7919 is
 * prime and coprime with both populations, so k*7919 mod n visits every
 * row exactly once with no locality for the page cache to exploit --
 * which is the access pattern a server's authentications actually have.
 * Return codes are ignored: a previous case may have exhausted some
 * user's credit, and what is being counted here is I/O, not policy. */
static long scale_scattered_pass(cloak_usermanager_t *m, unsigned n) {
    unsigned k;
    slow_reset();
    for (k = 0; k < n; k++) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, (unsigned)(((unsigned long)k * 7919UL) % n));
        (void)cloak_usermanager_authenticate(m, uid, NULL, NULL);
    }
    return slow_ctr.reads;
}

static void case_page_cache_knee(void) {
    cloak_usermanager_t *m = NULL;
    char                 err[256];
    long                 small_reads, big_reads, open_reads;

    /* THE ARM THAT MUST NOT TOUCH THE DISK. At half the manager's page
     * cache, cloak_usermanager_open's validation scan leaves the whole
     * table resident and every authentication afterwards is served from
     * memory. This is the half of D3's residual that is NOT true: below
     * this line no disk, however slow, can stall an authentication,
     * because no authentication reads one. */
    ASSERT_EQ_INT(cloak_usermanager_open(&m, g_small_path, scale_now, &g_now, err,
                                         sizeof(err)),
                  0);
    if (m == NULL) {
        return;
    }
    small_reads = scale_scattered_pass(m, SCALE_SMALL_USERS);
    cloak_usermanager_close(m);
    ASSERT_EQ_INT(small_reads, 0);

    /* THE ARM THAT MUST. At one and a half times the cache the table
     * cannot stay resident and each authentication has a real chance of
     * a synchronous read on the reactor thread. MEASURED by this case at
     * 4898 reads for 64636 authentications (7.6%), and at 16.5% for the
     * same population read by a manager that had not just been used by
     * case 1; the assertion demands only 1%, which is most of an order of
     * magnitude of margin against SQLite's cache accounting moving under
     * us, while still being categorically different from the zero above.
     * The line this case prints carries the live number. */
    slow_reset();
    ASSERT_EQ_INT(cloak_usermanager_open(&m, g_big_path, scale_now, &g_now, err,
                                         sizeof(err)),
                  0);
    if (m == NULL) {
        return;
    }
    open_reads = slow_ctr.reads;
    big_reads = scale_scattered_pass(m, SCALE_USERS);
    cloak_usermanager_close(m);

    ASSERT_TRUE(big_reads > (long)(SCALE_USERS / 100u));

    /* cloak_usermanager_open reads the WHOLE table, because it validates
     * every row. That is a startup cost the header says is fine (it
     * blocks, once, in the same phase as DNS resolution) and it is also
     * the reason the small arm above reads nothing -- so it is worth
     * having the number rather than the assumption. One read per page,
     * 721 pages at this population. */
    ASSERT_TRUE(open_reads > 700);
    printf("[scale] open scan of %u users: %ld disk reads;"
           " scattered authenticate: %ld reads per %u at 1.5x the page cache,"
           " %ld per %u at 0.5x\n",
           SCALE_USERS, open_reads, big_reads, SCALE_USERS, small_reads,
           SCALE_SMALL_USERS);
}

/* ------------------------------------------------------------------ */
/* Case 3: what a commit actually costs, which is D3's mitigation.      */
/* ------------------------------------------------------------------ */
static void case_commit_does_not_fsync(void) {
    cloak_usermanager_t *m = NULL;
    char                 err[256];
    cloak_user_status_t *updates;
    size_t               n_out = 0, i;
    unsigned             round;
    int                  saw_silent_commit = 0, saw_checkpoint = 0;
    long                 silent_writes = 0;

    ASSERT_EQ_INT(cloak_usermanager_open(&m, g_small_path, scale_now, &g_now, err,
                                         sizeof(err)),
                  0);
    if (m == NULL) {
        return;
    }
    updates = (cloak_user_status_t *)calloc(SCALE_BATCH, sizeof(*updates));
    ASSERT_TRUE(updates != NULL);
    if (updates == NULL) {
        cloak_usermanager_close(m);
        return;
    }
    for (i = 0; i < SCALE_BATCH; i++) {
        scale_uid(updates[i].uid,
                  (unsigned)i * (SCALE_SMALL_USERS / (unsigned)SCALE_BATCH));
        updates[i].up_usage = 1;
        updates[i].down_usage = 1;
        updates[i].num_session = 1;
        updates[i].active = 1;
    }

    /* Eight drains. WAL-plus-NORMAL means a commit is an append to the
     * log and NO fsync -- so at least one of these must write hundreds of
     * pages and sync zero times. That single observation is what makes
     * D3's first mitigation a fact rather than a pragma nobody checks:
     * flip synchronous back to FULL and every commit syncs, and this
     * fails. The autocheckpoint is the other half: SQLite folds the log
     * back into the database once it passes 1000 frames, and THAT commit
     * does fsync. Both are required to have been seen, because a build
     * that never checkpointed would also never fsync and would pass a
     * one-sided assertion while quietly growing its log without bound. */
    for (round = 0; round < 8; round++) {
        slow_reset();
        ASSERT_EQ_INT(cloak_usermanager_upload_status(m, updates, SCALE_BATCH,
                                                      NULL, 0, &n_out),
                      0);
        if (slow_ctr.syncs == 0 && slow_ctr.writes > 100) {
            saw_silent_commit = 1;
            silent_writes = slow_ctr.writes;
        }
        if (slow_ctr.syncs > 0) {
            saw_checkpoint = 1;
        }
    }
    ASSERT_TRUE(saw_silent_commit);
    ASSERT_TRUE(saw_checkpoint);
    printf("[scale] drain of %zu users over %u rows: one commit wrote %ld times"
           " with 0 fsyncs; the WAL autocheckpoint is where the fsync lives\n",
           SCALE_BATCH, SCALE_SMALL_USERS, silent_writes);

    free(updates);
    cloak_usermanager_close(m);
}

/* ------------------------------------------------------------------ */
/* Case 4: the stall, measured from inside a running reactor.           */
/* ------------------------------------------------------------------ */

/* A heartbeat timer standing in for every other session on the server.
 * It re-arms itself BEFORE running any work, which is what a peer's
 * inactivity timer or handshake deadline has already done by the time a
 * drain begins: the peer's deadline is fixed, and the only question is
 * how late the reactor gets to it. The gap between one fire and the next
 * IS that lateness. */
typedef struct {
    cloak_reactor_t *r;
    uint64_t         period_ms;
    long long        prev_ns;
    long long        max_gap_ns;
    long long        gap_after_work_ns;
    long long        work_wall_ns;
    long long        work_injected_ns;
    long             work_reads, work_writes, work_syncs;
    int              fires;
    int              work_pending;
    int              work_ran_last;
    int              done;
    void           (*work)(void *);
    void            *work_ud;
} beat_t;

static void beat_cb(cloak_reactor_t *r, void *ud) {
    beat_t   *b = (beat_t *)ud;
    long long now = slow_mono_ns();

    if (b->prev_ns != 0) {
        long long gap = now - b->prev_ns;
        if (gap > b->max_gap_ns) {
            b->max_gap_ns = gap;
        }
        if (b->work_ran_last) {
            b->gap_after_work_ns = gap;
            b->work_ran_last = 0;
            b->done = 1;
        }
    }
    b->prev_ns = now;
    b->fires++;
    /* Armed before the stall, exactly as a peer's timer would already be. */
    cloak_reactor_add_timer(r, b->period_ms, beat_cb, b);

    if (b->work_pending) {
        long long t0;
        b->work_pending = 0;
        slow_reset();
        t0 = slow_mono_ns();
        b->work(b->work_ud);
        b->work_wall_ns = slow_mono_ns() - t0;
        b->work_injected_ns = slow_ctr.injected_ns;
        b->work_reads = slow_ctr.reads;
        b->work_writes = slow_ctr.writes;
        b->work_syncs = slow_ctr.syncs;
        b->work_ran_last = 1;
    }
}

typedef struct {
    cloak_usermanager_t *m;
    cloak_user_status_t *updates;
    long                 delay_ns;
} drain_work_t;

static void drain_work(void *ud) {
    drain_work_t *w = (drain_work_t *)ud;
    size_t        n_out = 0;
    slow_delay_io_ns = w->delay_ns;
    (void)cloak_usermanager_upload_status(w->m, w->updates, SCALE_BATCH, NULL, 0,
                                          &n_out);
    slow_delay_io_ns = 0;
}

/* Pumps the reactor until `pred` is satisfied or the wall-clock deadline
 * passes. Bounded by the clock and never by an iteration count. */
static void beat_pump(cloak_reactor_t *r, const int *stop, long long deadline_ns) {
    while ((stop == NULL || *stop == 0) && slow_mono_ns() < deadline_ns) {
        (void)cloak_reactor_run_once(r, 1);
    }
}

static void case_reactor_stall_under_slow_disk(void) {
    cloak_reactor_t     *r = NULL;
    cloak_usermanager_t *m = NULL;
    char                 err[256];
    cloak_user_status_t *updates;
    beat_t               b;
    drain_work_t         w;
    long long            baseline_max_ns;
    size_t               i;

    r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    ASSERT_EQ_INT(cloak_usermanager_open(&m, g_big_path, scale_now, &g_now, err,
                                         sizeof(err)),
                  0);
    if (m == NULL) {
        cloak_reactor_destroy(r);
        return;
    }
    updates = (cloak_user_status_t *)calloc(SCALE_BATCH, sizeof(*updates));
    ASSERT_TRUE(updates != NULL);
    if (updates == NULL) {
        cloak_usermanager_close(m);
        cloak_reactor_destroy(r);
        return;
    }
    for (i = 0; i < SCALE_BATCH; i++) {
        scale_uid(updates[i].uid,
                  (unsigned)i * (SCALE_USERS / (unsigned)SCALE_BATCH));
        updates[i].up_usage = 1;
        updates[i].down_usage = 1;
        updates[i].num_session = 1;
        updates[i].active = 1;
    }

    memset(&b, 0, sizeof(b));
    b.r = r;
    b.period_ms = 5;
    w.m = m;
    w.updates = updates;

    /* PHASE 1 -- the noise floor. The same timer, the same loop, no
     * database work at all, for 400 ms of wall clock. Whatever lateness
     * this reactor shows here is the harness and the scheduler, and it is
     * what the stall below has to be compared against; a stall reported
     * without it would be a number with no zero. */
    cloak_reactor_add_timer(r, b.period_ms, beat_cb, &b);
    beat_pump(r, NULL, slow_mono_ns() + 400000000LL);
    baseline_max_ns = b.max_gap_ns;
    ASSERT_TRUE(b.fires > 10);

    /* PHASE 2 -- one drain, on a disk made slow, inside a reactor
     * callback. This is the production shape exactly: cloak/userpanel.h
     * arms an upload timer and settles the whole queue from the callback
     * it fires. */
    b.max_gap_ns = 0;
    b.prev_ns = 0;
    b.done = 0;
    b.work = drain_work;
    b.work_ud = &w;
    w.delay_ns = SCALE_INJECT_NS;
    b.work_pending = 1;
    beat_pump(r, &b.done, slow_mono_ns() + 90000000000LL);
    ASSERT_TRUE(b.done);

    /* THE TWO ASSERTIONS, AND WHY THEY ARE THE ONLY TWO.
     *
     * The first is arithmetic rather than timing: the shim burned
     * work_injected_ns of wall clock inside the callback, so the reactor
     * cannot have serviced its next timer sooner than that. It cannot
     * flake, on any machine, at any load, and it is what turns "the
     * reactor stalls" from a claim into a lower bound.
     *
     * The second is the comparison with phase 1's floor. Neither is a
     * bound on a duration in milliseconds -- test_registry_scale.c case 3
     * gives the reason at length: this suite runs under ASan at -j4,
     * where an absolute duration assertion is flaky. The DURATIONS BELOW
     * ARE PRINTED, NOT ASSERTED, and they are the point of the case. */
    ASSERT_TRUE(b.gap_after_work_ns >= b.work_injected_ns);
    ASSERT_TRUE(b.gap_after_work_ns > baseline_max_ns);

    printf("[scale] REACTOR STALL, %u users, %zu-user drain, %ld us injected per"
           " disk op:\n"
           "        %ld reads + %ld writes + %ld fsyncs = %ld ops;"
           " injected %.0f ms of that\n"
           "        heartbeat gap: %.1f ms baseline -> %.1f ms across the drain"
           " (%.0fx); drain call itself %.1f ms\n",
           SCALE_USERS, SCALE_BATCH, SCALE_INJECT_NS / 1000,
           b.work_reads, b.work_writes, b.work_syncs,
           b.work_reads + b.work_writes + b.work_syncs,
           (double)b.work_injected_ns / 1e6,
           (double)baseline_max_ns / 1e6,
           (double)b.gap_after_work_ns / 1e6,
           baseline_max_ns > 0 ? (double)b.gap_after_work_ns / (double)baseline_max_ns
                               : 0.0,
           (double)b.work_wall_ns / 1e6);

    /* PHASE 3 -- the same drain on a disk that is NOT made slow, so the
     * report can separate what this container's storage costs today from
     * what the induced latency costs. Printed only. */
    b.max_gap_ns = 0;
    b.prev_ns = 0;
    b.done = 0;
    w.delay_ns = 0;
    b.work_pending = 1;
    beat_pump(r, &b.done, slow_mono_ns() + 90000000000LL);
    ASSERT_TRUE(b.done);
    printf("[scale] same drain, no induced latency: %ld ops,"
           " heartbeat gap %.1f ms, drain call %.1f ms\n",
           b.work_reads + b.work_writes + b.work_syncs,
           (double)b.gap_after_work_ns / 1e6, (double)b.work_wall_ns / 1e6);

    free(updates);
    cloak_usermanager_close(m);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
case_build_databases();
case_population_at_scale();
case_page_cache_knee();
case_commit_does_not_fsync();
case_reactor_stall_under_slow_disk();
case_drop_databases();
TEST_MAIN_END()
