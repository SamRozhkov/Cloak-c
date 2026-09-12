#ifndef CLOAK_LOG_H
#define CLOAK_LOG_H

#include <stdio.h>

/* A process-global leveled logger writing one line per message to a
 * settable stream (stderr by default). Not thread-safe -- like everything
 * else in this project it assumes the single-threaded reactor model.
 *
 * Levels are ordered by decreasing severity: a message is emitted when its
 * level is numerically <= the current level, so CLOAK_LOG_ERROR emits only
 * errors and CLOAK_LOG_TRACE emits everything. */
typedef enum {
    CLOAK_LOG_ERROR = 0,
    CLOAK_LOG_WARN = 1,
    CLOAK_LOG_INFO = 2,
    CLOAK_LOG_DEBUG = 3,
    CLOAK_LOG_TRACE = 4,
} cloak_log_level_t;

/* The default level, in effect until cloak_log_set_level is called. */
#define CLOAK_LOG_DEFAULT_LEVEL CLOAK_LOG_INFO

/* The maximum length of a single formatted message, excluding the
 * timestamp/level prefix and the newline. Longer messages are silently
 * truncated -- logging never fails and never allocates. */
#define CLOAK_LOG_MAX_MSG 2048

void cloak_log_set_level(cloak_log_level_t level);
cloak_log_level_t cloak_log_get_level(void);

/* Parses a level name, case-insensitively: "error", "warn", "info",
 * "debug", "trace". Returns 0 and writes *out on success, -1 on an
 * unknown name or a NULL argument (leaving *out untouched). */
int cloak_log_level_from_string(const char *s, cloak_log_level_t *out);

/* Redirects output. Passing NULL restores stderr. The logger does not take
 * ownership of stream and never closes it. */
void cloak_log_set_stream(FILE *stream);

/* Emits one line: "YYYY-MM-DD HH:MM:SS LEVEL message\n", using local time.
 * Does nothing if level is above the current level. Prefer the macros
 * below, which read better at call sites. */
void cloak_log_write(cloak_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define CLOAK_LOGE(...) cloak_log_write(CLOAK_LOG_ERROR, __VA_ARGS__)
#define CLOAK_LOGW(...) cloak_log_write(CLOAK_LOG_WARN, __VA_ARGS__)
#define CLOAK_LOGI(...) cloak_log_write(CLOAK_LOG_INFO, __VA_ARGS__)
#define CLOAK_LOGD(...) cloak_log_write(CLOAK_LOG_DEBUG, __VA_ARGS__)
#define CLOAK_LOGT(...) cloak_log_write(CLOAK_LOG_TRACE, __VA_ARGS__)

#endif
