#define _POSIX_C_SOURCE 200809L
#include "cloak/log.h"

#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static cloak_log_level_t g_level = CLOAK_LOG_DEFAULT_LEVEL;
static FILE *g_stream = NULL;

static const char *const level_names[] = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};
#define NUM_LEVELS ((int)(sizeof(level_names) / sizeof(level_names[0])))

void cloak_log_set_level(cloak_log_level_t level) { g_level = level; }

cloak_log_level_t cloak_log_get_level(void) { return g_level; }

void cloak_log_set_stream(FILE *stream) { g_stream = stream; }

int cloak_log_level_from_string(const char *s, cloak_log_level_t *out) {
    if (s == NULL || out == NULL) {
        return -1;
    }
    for (int i = 0; i < NUM_LEVELS; i++) {
        if (strcasecmp(s, level_names[i]) == 0) {
            *out = (cloak_log_level_t)i;
            return 0;
        }
    }
    return -1;
}

void cloak_log_write(cloak_log_level_t level, const char *fmt, ...) {
    if ((int)level > (int)g_level) {
        return;
    }
    if ((int)level < 0 || (int)level >= NUM_LEVELS) {
        return;
    }

    char msg[CLOAK_LOG_MAX_MSG];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (n < 0) {
        /* encoding error in the format string; emit nothing rather than
         * writing an uninitialised buffer */
        return;
    }

    char stamp[32];
    time_t now = time(NULL);
    struct tm tm_buf;
    if (localtime_r(&now, &tm_buf) == NULL ||
        strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm_buf) == 0) {
        strcpy(stamp, "0000-00-00 00:00:00");
    }

    FILE *out = g_stream != NULL ? g_stream : stderr;
    fprintf(out, "%s %s %s\n", stamp, level_names[level], msg);
}
