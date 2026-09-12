#define _POSIX_C_SOURCE 200809L
#include "cloak/log.h"
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>

/* Runs body with the log stream pointed at a temporary file, then reads
 * the whole file back into buf. */
static void capture(char *buf, size_t buf_cap, void (*body)(void)) {
    FILE *f = tmpfile();
    ASSERT_TRUE(f != NULL);
    cloak_log_set_stream(f);
    body();
    fflush(f);
    rewind(f);
    size_t n = fread(buf, 1, buf_cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    /* cloak/log.h documents that passing NULL restores stderr; restoring
     * that way (rather than passing stderr explicitly) puts that branch
     * of cloak_log_set_stream under test on every call to capture(). */
    cloak_log_set_stream(NULL);
}

static void emit_one_of_each(void) {
    CLOAK_LOGE("error %d", 1);
    CLOAK_LOGW("warn %d", 2);
    CLOAK_LOGI("info %d", 3);
    CLOAK_LOGD("debug %d", 4);
    CLOAK_LOGT("trace %d", 5);
}

static void test_default_level_is_info(void) {
    ASSERT_EQ_INT(CLOAK_LOG_INFO, cloak_log_get_level());
}

static void test_level_filters_lower_severity(void) {
    char buf[1024];
    cloak_log_set_level(CLOAK_LOG_INFO);
    capture(buf, sizeof(buf), emit_one_of_each);

    ASSERT_TRUE(strstr(buf, "error 1") != NULL);
    ASSERT_TRUE(strstr(buf, "warn 2") != NULL);
    ASSERT_TRUE(strstr(buf, "info 3") != NULL);
    ASSERT_TRUE(strstr(buf, "debug 4") == NULL);
    ASSERT_TRUE(strstr(buf, "trace 5") == NULL);
}

static void test_trace_level_lets_everything_through(void) {
    char buf[1024];
    cloak_log_set_level(CLOAK_LOG_TRACE);
    capture(buf, sizeof(buf), emit_one_of_each);

    ASSERT_TRUE(strstr(buf, "error 1") != NULL);
    ASSERT_TRUE(strstr(buf, "trace 5") != NULL);
}

static void test_error_level_suppresses_everything_else(void) {
    char buf[1024];
    cloak_log_set_level(CLOAK_LOG_ERROR);
    capture(buf, sizeof(buf), emit_one_of_each);

    ASSERT_TRUE(strstr(buf, "error 1") != NULL);
    ASSERT_TRUE(strstr(buf, "warn 2") == NULL);
    ASSERT_TRUE(strstr(buf, "info 3") == NULL);
}

static void emit_tagged(void) {
    CLOAK_LOGW("something happened");
}

static void test_line_carries_level_tag_and_timestamp(void) {
    char buf[1024];
    cloak_log_set_level(CLOAK_LOG_TRACE);
    capture(buf, sizeof(buf), emit_tagged);

    ASSERT_TRUE(strstr(buf, "WARN") != NULL);
    ASSERT_TRUE(strstr(buf, "something happened") != NULL);
    /* timestamp prefix "YYYY-MM-DD HH:MM:SS " -- check the shape, not the value */
    ASSERT_EQ_INT('-', buf[4]);
    ASSERT_EQ_INT('-', buf[7]);
    ASSERT_EQ_INT(' ', buf[10]);
    ASSERT_EQ_INT(':', buf[13]);
    ASSERT_EQ_INT(':', buf[16]);
    /* and exactly one line was written */
    ASSERT_EQ_INT(1, (int)(strchr(buf, '\n') == buf + strlen(buf) - 1));
}

static void test_level_from_string(void) {
    cloak_log_level_t level;

    ASSERT_EQ_INT(0, cloak_log_level_from_string("error", &level));
    ASSERT_EQ_INT(CLOAK_LOG_ERROR, level);
    ASSERT_EQ_INT(0, cloak_log_level_from_string("WARN", &level));
    ASSERT_EQ_INT(CLOAK_LOG_WARN, level);
    ASSERT_EQ_INT(0, cloak_log_level_from_string("Info", &level));
    ASSERT_EQ_INT(CLOAK_LOG_INFO, level);
    ASSERT_EQ_INT(0, cloak_log_level_from_string("debug", &level));
    ASSERT_EQ_INT(CLOAK_LOG_DEBUG, level);
    ASSERT_EQ_INT(0, cloak_log_level_from_string("trace", &level));
    ASSERT_EQ_INT(CLOAK_LOG_TRACE, level);

    ASSERT_EQ_INT(-1, cloak_log_level_from_string("verbose", &level));
    ASSERT_EQ_INT(-1, cloak_log_level_from_string("", &level));
    ASSERT_EQ_INT(-1, cloak_log_level_from_string(NULL, &level));
}

static void emit_long(void) {
    char big[8192];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    CLOAK_LOGE("%s", big);
}

static void test_long_message_is_truncated_not_crashing(void) {
    char buf[16384];
    cloak_log_set_level(CLOAK_LOG_TRACE);
    capture(buf, sizeof(buf), emit_long);

    /* whatever the cap is, the line is terminated and the process survived */
    ASSERT_TRUE(strlen(buf) > 0);
    ASSERT_EQ_INT('\n', buf[strlen(buf) - 1]);
}

TEST_MAIN_BEGIN()
    test_default_level_is_info();
    test_level_filters_lower_severity();
    test_trace_level_lets_everything_through();
    test_error_level_suppresses_everything_else();
    test_line_carries_level_tag_and_timestamp();
    test_level_from_string();
    test_long_message_is_truncated_not_crashing();
    cloak_log_set_level(CLOAK_LOG_INFO);
TEST_MAIN_END()
