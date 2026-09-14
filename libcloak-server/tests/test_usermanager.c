#define _POSIX_C_SOURCE 200809L
#include "cloak/usermanager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "test_framework.h"

/* Every case here gets its own database file, named after this process and
 * a per-case tag, and unlinks it BOTH before opening it and after closing
 * it. Unlinking up front is the load-bearing half: a case that dies on an
 * assertion (or a run killed under the sanitizer) leaves a populated file
 * behind, and the next run of the same case would otherwise open a
 * database that already has rows in it -- turning "list sees exactly one
 * user" green or red for reasons that have nothing to do with the code
 * under test. */

static void um_tmp_path(char *buf, size_t cap, const char *tag) {
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(buf, cap, "%s/cloak_um_%ld_%s.db", dir, (long)getpid(), tag);
}

/* WAL mode creates two sidecar files next to the database; leaving either
 * behind would carry committed-but-not-checkpointed rows into the next
 * run even after the main file is removed. */
static void um_unlink(const char *path) {
    char aux[512];
    unlink(path);
    snprintf(aux, sizeof(aux), "%s-wal", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-shm", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-journal", path);
    unlink(aux);
}

/* The injected clock reads through the userdata pointer rather than a
 * file-scope variable, so a manager that forgot to thread now_userdata
 * through would dereference NULL here instead of silently reading the
 * right answer from a global. */
static int64_t fake_now(void *userdata) {
    return *(const int64_t *)userdata;
}

/* Distinct in every byte per seed, and ordered by seed under memcmp --
 * case 11 depends on that ordering being different from insertion order. */
static void mk_uid(uint8_t *uid, uint8_t seed) {
    memset(uid, seed, CLOAK_UID_LEN);
}

static cloak_user_info_t mk_info(uint8_t seed, int32_t cap, int64_t up_rate,
                                 int64_t down_rate, int64_t up_credit,
                                 int64_t down_credit, int64_t expiry) {
    cloak_user_info_t u;
    memset(&u, 0, sizeof(u));
    mk_uid(u.uid, seed);
    u.sessions_cap = cap;
    u.up_rate = up_rate;
    u.down_rate = down_rate;
    u.up_credit = up_credit;
    u.down_credit = down_credit;
    u.expiry_time = expiry;
    return u;
}

static cloak_user_status_t mk_status(uint8_t seed, int64_t up_usage,
                                     int64_t down_usage) {
    cloak_user_status_t s;
    memset(&s, 0, sizeof(s));
    mk_uid(s.uid, seed);
    s.up_usage = up_usage;
    s.down_usage = down_usage;
    s.num_session = 1;
    s.active = 1;
    s.timestamp = 42;
    return s;
}

/* Compares a terminate reason without assuming one was written. A
 * regression that stops filling the buffer leaves these entries holding
 * whatever was on the stack; strcmp-ing that would crash instead of
 * printing which assertion broke. */
static int reason_is(const char *actual, const char *expected) {
    return actual != NULL && strcmp(actual, expected) == 0;
}

/* A time far from zero and from every credit/cap constant used below, so
 * an implementation that confused a timestamp with a credit, or that
 * defaulted a clock to 0, could not accidentally produce a passing
 * comparison. */
#define T_NOW 1600000000

/* ------------------------------------------------------------------ */
/* 1. Schema and rows survive a close/reopen cycle.                     */
/* ------------------------------------------------------------------ */
static void case_persistence(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u, got;
    int rc;

    um_tmp_path(path, sizeof(path), "persist");
    um_unlink(path);

    rc = cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err));
    ASSERT_EQ_INT(rc, 0);
    ASSERT_TRUE(m != NULL);

    u = mk_info(1, 5, 111, 222, 333333, 444444, T_NOW + 1000);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);
    cloak_usermanager_close(m);

    m = NULL;
    rc = cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err));
    ASSERT_EQ_INT(rc, 0);
    ASSERT_TRUE(m != NULL);

    memset(&got, 0xAA, sizeof(got));
    ASSERT_EQ_INT(cloak_usermanager_get(m, u.uid, &got), 0);
    ASSERT_MEM_EQ(got.uid, u.uid, CLOAK_UID_LEN);
    ASSERT_EQ_INT(got.sessions_cap, 5);
    ASSERT_EQ_INT(got.up_rate, 111);
    ASSERT_EQ_INT(got.down_rate, 222);
    ASSERT_EQ_INT(got.up_credit, 333333);
    ASSERT_EQ_INT(got.down_credit, 444444);
    ASSERT_EQ_INT(got.expiry_time, T_NOW + 1000);

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 2. The void manager: every operation refuses, nothing crashes.       */
/* ------------------------------------------------------------------ */
static void case_void(void) {
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u, got;
    cloak_user_status_t st;
    cloak_user_terminate_t term[4];
    size_t n = 12345;
    int64_t up = -1, down = -1;

    ASSERT_EQ_INT(cloak_usermanager_open(&m, NULL, fake_now, &now, err, sizeof(err)), 0);
    ASSERT_TRUE(m != NULL);

    u = mk_info(1, 5, 111, 222, 10, 10, T_NOW + 1);
    st = mk_status(1, 1, 1);

    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, &up, &down),
                  CLOAK_USER_ERR_VOID);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, u.uid, 0),
                  CLOAK_USER_ERR_VOID);
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, &st, 1, term, 4, &n),
                  CLOAK_USER_ERR_VOID);
    ASSERT_EQ_INT(cloak_usermanager_list(m, &got, 1, &n), CLOAK_USER_ERR_VOID);
    ASSERT_EQ_INT(cloak_usermanager_get(m, u.uid, &got), CLOAK_USER_ERR_VOID);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL),
                  CLOAK_USER_ERR_VOID);
    ASSERT_EQ_INT(cloak_usermanager_delete(m, u.uid), CLOAK_USER_ERR_VOID);

    /* A refused call must not have written through the out-params: a
     * caller that ignores the return code has to see nothing, not a
     * plausible-looking zero. */
    ASSERT_EQ_INT(up, -1);
    ASSERT_EQ_INT(down, -1);

    cloak_usermanager_close(m);
    /* Idempotent and safe on NULL. */
    cloak_usermanager_close(NULL);
}

/* ------------------------------------------------------------------ */
/* 3. write creates; get reads back every field; list sees exactly one. */
/* ------------------------------------------------------------------ */
static void case_write_get_list(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u, got, listed[4];
    size_t n = 0;

    um_tmp_path(path, sizeof(path), "wgl");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    /* Every field a different value, so a transposition of any two of
     * them (up_rate/down_rate, up_credit/down_credit) fails here. */
    u = mk_info(7, 3, 1111, 2222, 333333, 444444, T_NOW + 60);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);

    memset(&got, 0xAA, sizeof(got));
    ASSERT_EQ_INT(cloak_usermanager_get(m, u.uid, &got), 0);
    ASSERT_MEM_EQ(got.uid, u.uid, CLOAK_UID_LEN);
    ASSERT_EQ_INT(got.sessions_cap, 3);
    ASSERT_EQ_INT(got.up_rate, 1111);
    ASSERT_EQ_INT(got.down_rate, 2222);
    ASSERT_EQ_INT(got.up_credit, 333333);
    ASSERT_EQ_INT(got.down_credit, 444444);
    ASSERT_EQ_INT(got.expiry_time, T_NOW + 60);

    memset(listed, 0xAA, sizeof(listed));
    n = 999;
    ASSERT_EQ_INT(cloak_usermanager_list(m, listed, 4, &n), 0);
    ASSERT_EQ_INT(n, 1);
    ASSERT_MEM_EQ(listed[0].uid, u.uid, CLOAK_UID_LEN);
    ASSERT_EQ_INT(listed[0].up_credit, 333333);
    ASSERT_EQ_INT(listed[0].expiry_time, T_NOW + 60);

    /* get on a UID that was never written. */
    {
        uint8_t other[CLOAK_UID_LEN];
        mk_uid(other, 8);
        ASSERT_EQ_INT(cloak_usermanager_get(m, other, &got),
                      CLOAK_USER_ERR_NOT_FOUND);
    }

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 4. A partial field mask changes only the fields it names.            */
/* ------------------------------------------------------------------ */
static void case_partial_mask(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u, patch, got;

    um_tmp_path(path, sizeof(path), "mask");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    u = mk_info(7, 3, 1111, 2222, 333333, 444444, T_NOW + 60);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);

    /* Every field of the patch carries a value DIFFERENT from the stored
     * one, so a mask that is ignored (all fields applied) is caught on
     * any of the five unnamed fields. */
    patch = mk_info(7, 99, 9999, 8888, 777777, 666666, T_NOW + 5555);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &patch,
                                          CLOAK_USER_FIELD_UP_CREDIT |
                                              CLOAK_USER_FIELD_EXPIRY_TIME),
                  0);

    memset(&got, 0xAA, sizeof(got));
    ASSERT_EQ_INT(cloak_usermanager_get(m, u.uid, &got), 0);
    ASSERT_EQ_INT(got.up_credit, 777777);         /* named */
    ASSERT_EQ_INT(got.expiry_time, T_NOW + 5555); /* named */
    ASSERT_EQ_INT(got.sessions_cap, 3);           /* untouched */
    ASSERT_EQ_INT(got.up_rate, 1111);             /* untouched */
    ASSERT_EQ_INT(got.down_rate, 2222);           /* untouched */
    ASSERT_EQ_INT(got.down_credit, 444444);       /* untouched */

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* R1. The defaults a row created by a maskless write takes.            */
/* ------------------------------------------------------------------ */
static void case_create_defaults(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u, got;
    int64_t up = -1, down = -1;

    um_tmp_path(path, sizeof(path), "defaults");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    /* The info carries permissive values in every field; the mask names
     * none of them, so NONE may reach the row. */
    u = mk_info(4, 100, 1111, 2222, 999999, 999999, T_NOW + 99999);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, 0), 0);

    memset(&got, 0xAA, sizeof(got));
    ASSERT_EQ_INT(cloak_usermanager_get(m, u.uid, &got), 0);
    ASSERT_EQ_INT(got.sessions_cap, 0);
    ASSERT_EQ_INT(got.up_rate, 0);
    ASSERT_EQ_INT(got.down_rate, 0);
    ASSERT_EQ_INT(got.up_credit, 0);
    ASSERT_EQ_INT(got.down_credit, 0);
    ASSERT_EQ_INT(got.expiry_time, 0);

    /* The row EXISTS -- so the failure must be a credit refusal, not
     * _NOT_FOUND. That distinction is the whole point of the default. */
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, &up, &down),
                  CLOAK_USER_ERR_NO_UP_CREDIT);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, u.uid, 0),
                  CLOAK_USER_ERR_NO_UP_CREDIT);

    /* Give it everything EXCEPT a sessions cap: the default cap of 0 must
     * still keep it out, which is what makes the cap default conservative
     * rather than incidental. */
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u,
                                          CLOAK_USER_FIELD_UP_CREDIT |
                                              CLOAK_USER_FIELD_DOWN_CREDIT |
                                              CLOAK_USER_FIELD_EXPIRY_TIME),
                  0);
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, &up, &down), 0);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, u.uid, 0),
                  CLOAK_USER_ERR_SESSIONS_CAP);

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 5. authenticate: rates, and every refusal including the == boundary. */
/* ------------------------------------------------------------------ */
static void case_authenticate(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u;
    uint8_t unknown[CLOAK_UID_LEN];
    int64_t up = -1, down = -1;

    um_tmp_path(path, sizeof(path), "auth");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    /* up_rate != down_rate so a swapped assignment cannot pass. */
    u = mk_info(1, 5, 111, 222, 1000, 2000, T_NOW + 1);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);

    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, &up, &down), 0);
    ASSERT_EQ_INT(up, 111);
    ASSERT_EQ_INT(down, 222);

    mk_uid(unknown, 0xEE);
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, unknown, &up, &down),
                  CLOAK_USER_ERR_NOT_FOUND);

    /* up_credit exactly 0, then negative. */
    u.up_credit = 0;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_UP_CREDIT), 0);
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, &up, &down),
                  CLOAK_USER_ERR_NO_UP_CREDIT);
    u.up_credit = -500;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_UP_CREDIT), 0);
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, &up, &down),
                  CLOAK_USER_ERR_NO_UP_CREDIT);

    /* Restore up, then break down the same two ways. Down is checked only
     * AFTER up passes, so restoring up is what makes these assertions
     * capable of reporting _NO_DOWN_CREDIT at all. */
    u.up_credit = 1000;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_UP_CREDIT), 0);
    u.down_credit = 0;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_DOWN_CREDIT), 0);
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, &up, &down),
                  CLOAK_USER_ERR_NO_DOWN_CREDIT);
    u.down_credit = -1;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_DOWN_CREDIT), 0);
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, &up, &down),
                  CLOAK_USER_ERR_NO_DOWN_CREDIT);
    u.down_credit = 2000;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_DOWN_CREDIT), 0);

    /* The expiry boundary. Go's test is `expiryTime < now` -> expired, so
     * now-1 is expired and exactly now is NOT. Both sides are asserted
     * against the SAME clock value, one tick apart: an implementation
     * using <= fails the second, one ignoring expiry fails the first, and
     * one comparing against a zero clock fails both. */
    u.expiry_time = T_NOW - 1;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_EXPIRY_TIME), 0);
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, &up, &down),
                  CLOAK_USER_ERR_EXPIRED);

    u.expiry_time = T_NOW;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_EXPIRY_TIME), 0);
    up = down = -1;
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, &up, &down), 0);
    ASSERT_EQ_INT(up, 111);
    ASSERT_EQ_INT(down, 222);

    /* The clock is genuinely consulted per call, not cached at open: move
     * it forward one tick and the same row becomes expired. */
    now = T_NOW + 1;
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, &up, &down),
                  CLOAK_USER_ERR_EXPIRED);
    now = T_NOW;

    /* NULL out-params are permitted. */
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, NULL, NULL), 0);

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 6. authorise_new_session: the cap, and every authenticate condition. */
/* ------------------------------------------------------------------ */
static void case_authorise_session(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u;
    uint8_t unknown[CLOAK_UID_LEN];

    um_tmp_path(path, sizeof(path), "sess");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    u = mk_info(1, 3, 111, 222, 1000, 2000, T_NOW + 1);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);

    /* cap 3: 2 existing is allowed, 3 is not. An off-by-one in either
     * direction moves exactly one of these two. */
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, u.uid, 0), 0);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, u.uid, 2), 0);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, u.uid, 3),
                  CLOAK_USER_ERR_SESSIONS_CAP);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, u.uid, 9),
                  CLOAK_USER_ERR_SESSIONS_CAP);

    mk_uid(unknown, 0xEE);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, unknown, 0),
                  CLOAK_USER_ERR_NOT_FOUND);

    /* The credit and expiry gates are checked BEFORE the cap: each of
     * these would return _SESSIONS_CAP-free success if the gate were
     * skipped, and would return _SESSIONS_CAP if the order were reversed
     * (num_existing is 0, well under the cap, so only the gate can fail). */
    u.up_credit = 0;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_UP_CREDIT), 0);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, u.uid, 0),
                  CLOAK_USER_ERR_NO_UP_CREDIT);
    u.up_credit = 1000;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_UP_CREDIT), 0);

    u.down_credit = 0;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_DOWN_CREDIT), 0);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, u.uid, 0),
                  CLOAK_USER_ERR_NO_DOWN_CREDIT);
    u.down_credit = 2000;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_DOWN_CREDIT), 0);

    u.expiry_time = T_NOW - 1;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_EXPIRY_TIME), 0);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, u.uid, 0),
                  CLOAK_USER_ERR_EXPIRED);
    /* Same boundary as case 5: exactly now is still valid. */
    u.expiry_time = T_NOW;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_EXPIRY_TIME), 0);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, u.uid, 0), 0);

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 7. upload_status subtracts, terminates, and PERSISTS the debt.       */
/* ------------------------------------------------------------------ */
static void case_upload_basic(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u, got;
    cloak_user_status_t st;
    cloak_user_terminate_t term[4];
    size_t n = 999;

    um_tmp_path(path, sizeof(path), "upload");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    u = mk_info(1, 5, 111, 222, 1000, 5000, T_NOW + 100);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);

    /* A plain subtraction that leaves both credits healthy: no terminate.
     * The two usages differ so a single shared subtraction is caught. */
    st = mk_status(1, 300, 700);
    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, &st, 1, term, 4, &n), 0);
    ASSERT_EQ_INT(n, 0);
    ASSERT_EQ_INT(cloak_usermanager_get(m, u.uid, &got), 0);
    ASSERT_EQ_INT(got.up_credit, 700);
    ASSERT_EQ_INT(got.down_credit, 4300);

    /* Drive up_credit to exactly 0: Go terminates on <= 0, so 0 counts. */
    st = mk_status(1, 700, 0);
    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, &st, 1, term, 4, &n), 0);
    ASSERT_EQ_INT(n, 1);
    ASSERT_MEM_EQ(term[0].uid, u.uid, CLOAK_UID_LEN);
    ASSERT_TRUE(reason_is(term[0].reason, CLOAK_USER_TERMINATE_NO_UP_CREDIT));
    ASSERT_EQ_INT(cloak_usermanager_get(m, u.uid, &got), 0);
    ASSERT_EQ_INT(got.up_credit, 0);

    /* Overdraw past zero: the DEBT is what stops a reconnect, so the
     * stored value must be the negative number, not a clamp to 0. */
    st = mk_status(1, 500, 0);
    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, &st, 1, term, 4, &n), 0);
    ASSERT_EQ_INT(n, 1);
    ASSERT_EQ_INT(cloak_usermanager_get(m, u.uid, &got), 0);
    ASSERT_EQ_INT(got.up_credit, -500);
    /* ...and the debt is exactly what authenticate now refuses on. */
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, u.uid, NULL, NULL),
                  CLOAK_USER_ERR_NO_UP_CREDIT);

    /* An empty batch is a no-op that still reports zero terminates. */
    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, NULL, 0, term, 4, &n), 0);
    ASSERT_EQ_INT(n, 0);

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* R2. Which reason wins when a user matches several conditions.        */
/* ------------------------------------------------------------------ */
static void case_upload_reason_precedence(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u;
    cloak_user_status_t st;
    cloak_user_terminate_t term[8];
    size_t n = 999;

    um_tmp_path(path, sizeof(path), "reason");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    /* Out of BOTH credits, not expired -> exactly one entry, and the
     * download reason wins over the upload one. */
    u = mk_info(1, 5, 111, 222, 10, 10, T_NOW + 100);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);
    st = mk_status(1, 10, 10);
    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, &st, 1, term, 8, &n), 0);
    ASSERT_EQ_INT(n, 1);
    ASSERT_TRUE(reason_is(term[0].reason, CLOAK_USER_TERMINATE_NO_DOWN_CREDIT));

    /* Out of both credits AND expired -> still one entry, and expiry wins
     * over both, because it is the one condition a top-up cannot clear. */
    u = mk_info(2, 5, 111, 222, 10, 10, T_NOW - 1);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);
    st = mk_status(2, 10, 10);
    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, &st, 1, term, 8, &n), 0);
    ASSERT_EQ_INT(n, 1);
    ASSERT_TRUE(reason_is(term[0].reason, CLOAK_USER_TERMINATE_EXPIRED));

    /* Expiry alone, with both credits healthy. Go's test here is
     * `now > expiry`, so exactly-now is NOT expired -- assert both sides
     * one tick apart against the same clock. */
    u = mk_info(3, 5, 111, 222, 100000, 100000, T_NOW);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);
    st = mk_status(3, 1, 1);
    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, &st, 1, term, 8, &n), 0);
    ASSERT_EQ_INT(n, 0);

    u.expiry_time = T_NOW - 1;
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_EXPIRY_TIME), 0);
    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, &st, 1, term, 8, &n), 0);
    ASSERT_EQ_INT(n, 1);
    ASSERT_TRUE(reason_is(term[0].reason, CLOAK_USER_TERMINATE_EXPIRED));

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 8. upload_status for a user that no longer exists.                   */
/* ------------------------------------------------------------------ */
static void case_upload_missing_user(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u, got, listed[4];
    cloak_user_status_t st;
    cloak_user_terminate_t term[4];
    size_t n = 999;

    um_tmp_path(path, sizeof(path), "gone");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    u = mk_info(1, 5, 111, 222, 1000, 2000, T_NOW + 100);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);
    ASSERT_EQ_INT(cloak_usermanager_delete(m, u.uid), 0);

    st = mk_status(1, 50, 50);
    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, &st, 1, term, 4, &n), 0);
    ASSERT_EQ_INT(n, 1);
    ASSERT_MEM_EQ(term[0].uid, u.uid, CLOAK_UID_LEN);
    ASSERT_TRUE(reason_is(term[0].reason, CLOAK_USER_TERMINATE_NO_SUCH_USER));

    /* The metering path must never resurrect a deleted user. */
    ASSERT_EQ_INT(cloak_usermanager_get(m, u.uid, &got),
                  CLOAK_USER_ERR_NOT_FOUND);
    n = 999;
    ASSERT_EQ_INT(cloak_usermanager_list(m, listed, 4, &n), 0);
    ASSERT_EQ_INT(n, 0);

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 9. A batch where only some users terminate.                          */
/* ------------------------------------------------------------------ */
static void case_upload_batch(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t a, b, c, got;
    cloak_user_status_t st[4];
    cloak_user_terminate_t term[8];
    uint8_t gone[CLOAK_UID_LEN];
    size_t n = 999;

    um_tmp_path(path, sizeof(path), "batch");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    a = mk_info(1, 5, 111, 222, 100000, 100000, T_NOW + 100); /* stays healthy */
    b = mk_info(2, 5, 111, 222, 100, 100000, T_NOW + 100);    /* runs out of up */
    c = mk_info(3, 5, 111, 222, 100000, 100000, T_NOW - 1);   /* expired */
    ASSERT_EQ_INT(cloak_usermanager_write(m, &a, CLOAK_USER_FIELD_ALL), 0);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &b, CLOAK_USER_FIELD_ALL), 0);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &c, CLOAK_USER_FIELD_ALL), 0);
    mk_uid(gone, 9); /* never written */

    st[0] = mk_status(1, 10, 20);
    st[1] = mk_status(2, 100, 20);
    st[2] = mk_status(9, 1, 1);
    st[3] = mk_status(3, 10, 20);

    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, st, 4, term, 8, &n), 0);
    /* Exactly the three non-healthy ones, in the order of the updates. */
    ASSERT_EQ_INT(n, 3);
    ASSERT_MEM_EQ(term[0].uid, b.uid, CLOAK_UID_LEN);
    ASSERT_TRUE(reason_is(term[0].reason, CLOAK_USER_TERMINATE_NO_UP_CREDIT));
    ASSERT_MEM_EQ(term[1].uid, gone, CLOAK_UID_LEN);
    ASSERT_TRUE(reason_is(term[1].reason, CLOAK_USER_TERMINATE_NO_SUCH_USER));
    ASSERT_MEM_EQ(term[2].uid, c.uid, CLOAK_UID_LEN);
    ASSERT_TRUE(reason_is(term[2].reason, CLOAK_USER_TERMINATE_EXPIRED));

    /* Every user in the batch was metered, terminating or not -- and the
     * two directions were subtracted independently. */
    ASSERT_EQ_INT(cloak_usermanager_get(m, a.uid, &got), 0);
    ASSERT_EQ_INT(got.up_credit, 100000 - 10);
    ASSERT_EQ_INT(got.down_credit, 100000 - 20);
    ASSERT_EQ_INT(cloak_usermanager_get(m, b.uid, &got), 0);
    ASSERT_EQ_INT(got.up_credit, 0);
    ASSERT_EQ_INT(got.down_credit, 100000 - 20);
    ASSERT_EQ_INT(cloak_usermanager_get(m, c.uid, &got), 0);
    ASSERT_EQ_INT(got.up_credit, 100000 - 10);
    ASSERT_EQ_INT(got.down_credit, 100000 - 20);

    /* R3 for upload_status: a buffer too small still reports the true
     * total, and the writes still all happen. */
    st[0] = mk_status(1, 100000, 100000);
    st[1] = mk_status(2, 1, 1);
    st[2] = mk_status(3, 1, 1);
    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, st, 3, term, 1, &n), 0);
    ASSERT_EQ_INT(n, 3);
    ASSERT_MEM_EQ(term[0].uid, a.uid, CLOAK_UID_LEN);
    ASSERT_EQ_INT(cloak_usermanager_get(m, c.uid, &got), 0);
    ASSERT_EQ_INT(got.up_credit, 100000 - 10 - 1);

    /* out_cap 0 with a NULL buffer is a legal "how many would there be?"
     * probe. */
    n = 999;
    memset(term, 0, sizeof(term));
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, st, 3, NULL, 0, &n), 0);
    ASSERT_EQ_INT(n, 3);

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 10. delete removes; get then returns _NOT_FOUND.                     */
/* ------------------------------------------------------------------ */
static void case_delete(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t a, b, got, listed[4];
    size_t n = 999;

    um_tmp_path(path, sizeof(path), "delete");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    a = mk_info(1, 5, 111, 222, 1000, 2000, T_NOW + 100);
    b = mk_info(2, 5, 111, 222, 1000, 2000, T_NOW + 100);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &a, CLOAK_USER_FIELD_ALL), 0);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &b, CLOAK_USER_FIELD_ALL), 0);

    ASSERT_EQ_INT(cloak_usermanager_delete(m, a.uid), 0);
    ASSERT_EQ_INT(cloak_usermanager_get(m, a.uid, &got), CLOAK_USER_ERR_NOT_FOUND);
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, a.uid, NULL, NULL),
                  CLOAK_USER_ERR_NOT_FOUND);

    /* Deleting one user must not take its neighbour with it. */
    ASSERT_EQ_INT(cloak_usermanager_get(m, b.uid, &got), 0);
    n = 999;
    ASSERT_EQ_INT(cloak_usermanager_list(m, listed, 4, &n), 0);
    ASSERT_EQ_INT(n, 1);
    ASSERT_MEM_EQ(listed[0].uid, b.uid, CLOAK_UID_LEN);

    /* A second delete of the same UID reports _NOT_FOUND, matching Go's
     * DeleteBucket returning ErrBucketNotFound. */
    ASSERT_EQ_INT(cloak_usermanager_delete(m, a.uid), CLOAK_USER_ERR_NOT_FOUND);

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 11. R3: list with out_cap below the row count.                       */
/* ------------------------------------------------------------------ */
static void case_list_truncated(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u, listed[4];
    size_t n = 999;

    um_tmp_path(path, sizeof(path), "listcap");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    /* Inserted 3, 1, 2 -- so "the first two in ascending UID order" is a
     * different answer from "the first two inserted", and the documented
     * ordering contract is what this pins. */
    u = mk_info(3, 5, 111, 222, 1000, 2000, T_NOW + 100);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);
    u = mk_info(1, 5, 111, 222, 1000, 2000, T_NOW + 100);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);
    u = mk_info(2, 5, 111, 222, 1000, 2000, T_NOW + 100);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);

    memset(listed, 0xAA, sizeof(listed));
    n = 999;
    ASSERT_EQ_INT(cloak_usermanager_list(m, listed, 2, &n), 0);
    ASSERT_EQ_INT(n, 3); /* the TRUE total, not the number written */
    ASSERT_EQ_INT(listed[0].uid[0], 1);
    ASSERT_EQ_INT(listed[1].uid[0], 2);
    /* The entry past out_cap was not touched. */
    ASSERT_EQ_INT(listed[2].uid[0], 0xAA);

    /* out_cap 0 with a NULL buffer is the counting probe. */
    n = 999;
    ASSERT_EQ_INT(cloak_usermanager_list(m, NULL, 0, &n), 0);
    ASSERT_EQ_INT(n, 3);

    /* And a big enough buffer gets all three, still in ascending order. */
    n = 999;
    ASSERT_EQ_INT(cloak_usermanager_list(m, listed, 4, &n), 0);
    ASSERT_EQ_INT(n, 3);
    ASSERT_EQ_INT(listed[0].uid[0], 1);
    ASSERT_EQ_INT(listed[1].uid[0], 2);
    ASSERT_EQ_INT(listed[2].uid[0], 3);

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* 12. A UID that is not CLOAK_UID_LEN bytes cannot be stored.          */
/* ------------------------------------------------------------------ */
/* The C API takes uid as a fixed-size array, so no in-process caller can
 * even express a wrong-length UID -- which is exactly why the guard has
 * to live in the schema instead of in an argument check. The admin API is
 * the next module and will decode UIDs off the wire; this case opens a
 * SECOND sqlite3 handle on the same file and writes the way a careless
 * future caller would, to prove the database itself refuses. Drop the
 * CHECK constraint and this case fails. */
static void case_uid_length_enforced(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u, listed[8];
    sqlite3 *raw = NULL;
    sqlite3_stmt *ins = NULL;
    uint8_t bad[CLOAK_UID_LEN + 1];
    size_t n = 999;
    int rc;
    size_t i;
    static const size_t bad_lens[] = {0, 1, CLOAK_UID_LEN - 1, CLOAK_UID_LEN + 1};

    um_tmp_path(path, sizeof(path), "uidlen");
    um_unlink(path);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    u = mk_info(1, 5, 111, 222, 1000, 2000, T_NOW + 100);
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL), 0);

    memset(bad, 0x5A, sizeof(bad));
    ASSERT_EQ_INT(sqlite3_open(path, &raw), SQLITE_OK);
    ASSERT_EQ_INT(sqlite3_prepare_v2(raw,
                                     "INSERT INTO users (uid, sessions_cap, up_rate,"
                                     " down_rate, up_credit, down_credit, expiry_time)"
                                     " VALUES (?1, 9, 9, 9, 9, 9, 9)",
                                     -1, &ins, NULL),
                  SQLITE_OK);

    for (i = 0; i < sizeof(bad_lens) / sizeof(bad_lens[0]); i++) {
        /* Not asserted: sqlite3_reset returns the error code of the
         * statement's most recent step, so after a refused INSERT it
         * legitimately returns SQLITE_CONSTRAINT rather than SQLITE_OK. */
        sqlite3_reset(ins);
        ASSERT_EQ_INT(sqlite3_bind_blob(ins, 1, bad, (int)bad_lens[i],
                                        SQLITE_TRANSIENT),
                      SQLITE_OK);
        rc = sqlite3_step(ins);
        /* SQLITE_CONSTRAINT, not SQLITE_DONE: the row was refused. */
        ASSERT_EQ_INT(rc & 0xff, SQLITE_CONSTRAINT);
    }
    sqlite3_finalize(ins);
    sqlite3_close(raw);

    /* A well-formed UID still goes in through the same raw path, so the
     * loop above failed on the LENGTH and not on something incidental
     * about writing from a second handle. */
    ASSERT_EQ_INT(sqlite3_open(path, &raw), SQLITE_OK);
    ASSERT_EQ_INT(sqlite3_prepare_v2(raw,
                                     "INSERT INTO users (uid, sessions_cap, up_rate,"
                                     " down_rate, up_credit, down_credit, expiry_time)"
                                     " VALUES (?1, 9, 9, 9, 9, 9, 9)",
                                     -1, &ins, NULL),
                  SQLITE_OK);
    mk_uid(bad, 2);
    ASSERT_EQ_INT(sqlite3_bind_blob(ins, 1, bad, CLOAK_UID_LEN, SQLITE_TRANSIENT),
                  SQLITE_OK);
    ASSERT_EQ_INT(sqlite3_step(ins), SQLITE_DONE);
    sqlite3_finalize(ins);
    sqlite3_close(raw);

    n = 999;
    ASSERT_EQ_INT(cloak_usermanager_list(m, listed, 8, &n), 0);
    ASSERT_EQ_INT(n, 2); /* the original plus the one well-formed raw row */

    cloak_usermanager_close(m);
    um_unlink(path);
}

/* ------------------------------------------------------------------ */
/* Argument checking: NULL pointers are refused, not dereferenced.      */
/* ------------------------------------------------------------------ */
static void case_bad_args(void) {
    char path[512];
    char err[256];
    int64_t now = T_NOW;
    cloak_usermanager_t *m = NULL;
    cloak_user_info_t u;
    size_t n = 0;

    um_tmp_path(path, sizeof(path), "args");
    um_unlink(path);

    ASSERT_EQ_INT(cloak_usermanager_open(NULL, path, fake_now, &now, err, sizeof(err)),
                  CLOAK_USER_ERR_ARG);
    ASSERT_EQ_INT(cloak_usermanager_open(&m, path, fake_now, &now, err, sizeof(err)), 0);

    u = mk_info(1, 5, 111, 222, 1000, 2000, T_NOW + 100);
    ASSERT_EQ_INT(cloak_usermanager_write(m, NULL, CLOAK_USER_FIELD_ALL),
                  CLOAK_USER_ERR_ARG);
    /* A mask bit this build does not know is refused outright -- and the
     * refusal must not have written the fields it DID understand. */
    ASSERT_EQ_INT(cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL | (1u << 20)),
                  CLOAK_USER_ERR_ARG);
    ASSERT_EQ_INT(cloak_usermanager_get(m, u.uid, &u), CLOAK_USER_ERR_NOT_FOUND);
    ASSERT_EQ_INT(cloak_usermanager_get(m, u.uid, NULL), CLOAK_USER_ERR_ARG);
    ASSERT_EQ_INT(cloak_usermanager_get(m, NULL, &u), CLOAK_USER_ERR_ARG);
    ASSERT_EQ_INT(cloak_usermanager_delete(m, NULL), CLOAK_USER_ERR_ARG);
    ASSERT_EQ_INT(cloak_usermanager_authenticate(m, NULL, NULL, NULL),
                  CLOAK_USER_ERR_ARG);
    ASSERT_EQ_INT(cloak_usermanager_authorise_new_session(m, NULL, 0),
                  CLOAK_USER_ERR_ARG);
    ASSERT_EQ_INT(cloak_usermanager_list(m, NULL, 4, &n), CLOAK_USER_ERR_ARG);
    ASSERT_EQ_INT(cloak_usermanager_list(m, NULL, 0, NULL), CLOAK_USER_ERR_ARG);
    ASSERT_EQ_INT(cloak_usermanager_upload_status(m, NULL, 1, NULL, 0, &n),
                  CLOAK_USER_ERR_ARG);

    /* An unopenable path is a _DB failure with a message, and leaves *out
     * NULL rather than a half-built manager. */
    {
        cloak_usermanager_t *bad = (cloak_usermanager_t *)(void *)&n;
        err[0] = '\0';
        ASSERT_EQ_INT(cloak_usermanager_open(&bad, "/nonexistent-dir-xyz/db.sqlite",
                                             NULL, NULL, err, sizeof(err)),
                      CLOAK_USER_ERR_DB);
        ASSERT_TRUE(bad == NULL);
        ASSERT_TRUE(err[0] != '\0');
    }

    cloak_usermanager_close(m);
    um_unlink(path);
}

TEST_MAIN_BEGIN()
case_persistence();
case_void();
case_write_get_list();
case_partial_mask();
case_create_defaults();
case_authenticate();
case_authorise_session();
case_upload_basic();
case_upload_reason_precedence();
case_upload_missing_user();
case_upload_batch();
case_delete();
case_list_truncated();
case_uid_length_enforced();
case_bad_args();
TEST_MAIN_END()
