#include <string.h>

#include "sqlite3.h"
#include "test_framework.h"

/* Keep in sync with third_party/sqlite/VENDORING.md. */
#define VENDORED_SQLITE_VERSION_NUMBER 3050004

static void test_threadsafe_is_disabled(void) {
    /* SQLITE_THREADSAFE=0 is a correctness decision for this project's
     * single-threaded epoll reactor (see third_party/sqlite/CMakeLists.txt).
     * If that define were ever dropped, sqlite3_threadsafe() would report
     * nonzero here and this assertion is the only place that catches it. */
    ASSERT_EQ_INT(0, sqlite3_threadsafe());
}

static void test_version_is_the_vendored_one(void) {
    ASSERT_EQ_INT(VENDORED_SQLITE_VERSION_NUMBER, sqlite3_libversion_number());
}

static void test_insert_and_read_back_with_blob_key(void) {
    sqlite3 *db = NULL;
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_open(":memory:", &db));
    ASSERT_TRUE(db != NULL);

    char *errmsg = NULL;
    int rc = sqlite3_exec(
        db,
        "CREATE TABLE users (key BLOB PRIMARY KEY, credits INTEGER NOT NULL);",
        NULL, NULL, &errmsg);
    ASSERT_EQ_INT(SQLITE_OK, rc);
    if (rc != SQLITE_OK) {
        sqlite3_free(errmsg);
    }

    sqlite3_stmt *insert_stmt = NULL;
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_prepare_v2(
        db, "INSERT INTO users (key, credits) VALUES (?, ?);", -1,
        &insert_stmt, NULL));

    const unsigned char key_a[4] = {0xde, 0xad, 0xbe, 0xef};
    const unsigned char key_b[4] = {0xfe, 0xed, 0xfa, 0xce};

    ASSERT_EQ_INT(SQLITE_OK, sqlite3_bind_blob(
        insert_stmt, 1, key_a, (int)sizeof(key_a), SQLITE_STATIC));
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_bind_int64(insert_stmt, 2, 100));
    ASSERT_EQ_INT(SQLITE_DONE, sqlite3_step(insert_stmt));
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_reset(insert_stmt));

    ASSERT_EQ_INT(SQLITE_OK, sqlite3_bind_blob(
        insert_stmt, 1, key_b, (int)sizeof(key_b), SQLITE_STATIC));
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_bind_int64(insert_stmt, 2, 250));
    ASSERT_EQ_INT(SQLITE_DONE, sqlite3_step(insert_stmt));

    sqlite3_finalize(insert_stmt);

    sqlite3_stmt *select_stmt = NULL;
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_prepare_v2(
        db, "SELECT key, credits FROM users ORDER BY credits ASC;", -1,
        &select_stmt, NULL));

    ASSERT_EQ_INT(SQLITE_ROW, sqlite3_step(select_stmt));
    ASSERT_EQ_INT((int)sizeof(key_a), sqlite3_column_bytes(select_stmt, 0));
    ASSERT_EQ_INT(0, memcmp(key_a, sqlite3_column_blob(select_stmt, 0), sizeof(key_a)));
    ASSERT_EQ_INT(100, (int)sqlite3_column_int64(select_stmt, 1));

    ASSERT_EQ_INT(SQLITE_ROW, sqlite3_step(select_stmt));
    ASSERT_EQ_INT((int)sizeof(key_b), sqlite3_column_bytes(select_stmt, 0));
    ASSERT_EQ_INT(0, memcmp(key_b, sqlite3_column_blob(select_stmt, 0), sizeof(key_b)));
    ASSERT_EQ_INT(250, (int)sqlite3_column_int64(select_stmt, 1));

    ASSERT_EQ_INT(SQLITE_DONE, sqlite3_step(select_stmt));

    sqlite3_finalize(select_stmt);
    ASSERT_EQ_INT(SQLITE_OK, sqlite3_close(db));
}

TEST_MAIN_BEGIN()
    test_threadsafe_is_disabled();
    test_version_is_the_vendored_one();
    test_insert_and_read_back_with_blob_key();
TEST_MAIN_END()
