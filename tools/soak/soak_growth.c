#define _POSIX_C_SOURCE 200809L
#include "cloak/server_stack.h"

#include "cloak/base64.h"
#include "cloak/crypto.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/session.h"
#include "cloak/stream.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"
#include "test_framework.h"
#include "client_harness.h"

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
#include <malloc.h>
#define SOAK_HAVE_MALLINFO2 1
#else
#define SOAK_HAVE_MALLINFO2 0
#endif

/* ===================================================================== *
 * THE SOAK HARNESS: what LeakSanitizer structurally cannot see.
 *
 * WHY THIS IS NOT A ctest CASE, and the measurement that decided it.
 * Every test in this tree is bounded in seconds, and LSan's exit scan
 * answers exactly one question -- "is this allocation still reachable
 * from a root at exit?" -- which is silent on the whole family of
 * defects that matter to a process meant to run for months: a table that
 * is reachable and freed at exit but grows without bound while the
 * process lives; a timer heap that gains an entry per session and never
 * loses one; a counter that only rises. All three are green under
 * ASan+LSan and all three eventually kill the server.
 *
 * Seeing growth means separating a linear term from what else moves, and
 * the run length buys sensitivity in one of two regimes. Where the
 * samples scatter, the standard error of an ordinary-least-squares slope
 * falls as
 *
 *     SE(b) = s * sqrt(12 * dt) * T^(-3/2)
 *
 * (s = residual standard deviation). Where they do NOT scatter -- and on
 * this workload most columns do not; see below -- the floor is instead
 * set by quantisation, one unit over the run, so it falls as 1/T.
 *
 * MEASURED, SO THE SECOND REGIME IS NOT A GUESS: across 750 s and 31,876
 * churn cycles with the replay cache taken out of the way,
 * rss_anon_kb, rss_file_kb, uordblks, hblkhd, arena, fds, timers,
 * sessions and proxy_streams were every one of them BIT-IDENTICAL from
 * the first sample to the last. A column that never moves has no
 * scatter to average down, so what a longer run buys is resolution: a
 * 750 s window puts the floor at one unit per 750 s = 4.8 units/hour,
 * where a 60 s window -- already about twice the whole Debug suite's
 * wall clock -- puts it at 60 units/hour. Twelve and a half times
 * coarser, on every column, for time the suite does not have.
 *
 * The other two reasons this is not a ctest case, both measured and both
 * in the runbook: the sensitive column is INERT under the sanitizer
 * build, which is where this project asks its memory questions
 * (mallinfo2 reports uordblks 0 either side of a 1 MiB malloc under
 * ASan, gcc and clang alike); and there is no growth here for a case to
 * catch, so there is nothing to overturn the out-of-band default with.
 * Measuring for sixty seconds and reporting "no growth" is worse than
 * not measuring: it is a green light nobody should trust.
 *
 * WHAT IT EXERCISES. Churn, not idling -- growth needs objects created
 * and destroyed, because a structure that only ever grows in the create
 * path looks identical to a correct one until something is destroyed.
 * Each cycle closes the oldest of K live sessions and opens a fresh one:
 * a real ClientHello through the shipped client handshake, a registry
 * insert keyed by (uid, session_id), a replay-cache insert on a fresh
 * 32-byte random, a panel activation, a proxy stream that dials an
 * upstream, bytes both ways, then the whole thing torn down. That
 * touches, per cycle, every structure module 10b changed: the registry's
 * chained hash, the slot-indexed timer heap, the 2^21 replay cache and
 * the proxy's per-session stream table.
 *
 * WHAT IT SAMPLES, and why each one is here rather than RSS alone:
 *   rss_kb        VmRSS. The only number that maps to the operator's
 *                 complaint, and the least trustworthy: it moves in
 *                 4 KiB steps, does not fall when glibc keeps a freed
 *                 arena, and mixes in file pages the kernel is free to
 *                 add and reclaim. Reported, never fitted alone.
 *   rss_anon_kb   the anonymous half of it. THIS is the column a leak
 *                 has to show up in, and the one to fit.
 *   rss_file_kb   the file-backed half. It moves for reasons belonging
 *                 to the machine; see rss_read's comment for the 9.5 MB
 *                 episode that made this split necessary.
 *   rss_anon_huge_kb  how much of the anonymous half the kernel has
 *                 collapsed into 2 MiB transparent hugepages. On a
 *                 kernel with THP at `always` -- which this image's is
 *                 -- this accounts for both of the step changes a naive
 *                 reading of rss_kb would have reported as growth.
 *   arena         mallinfo2's arena size. Rises and never falls; rising
 *                 while uordblks is flat is fragmentation, not a leak.
 *   uordblks      mallinfo2's in-use ARENA bytes. Finer than RSS and
 *                 immune to the allocator's retention, so a small
 *                 per-cycle retention shows up here first -- measured at
 *                 96.0 bytes/cycle against a planted 64. Sensitive and
 *                 PARTIAL: it is exactly blind to whatever glibc mmaps,
 *                 which is why hblkhd sits beside it.
 *   hblkhd        mallinfo2's mmapped bytes, which uordblks does NOT
 *                 count. Measured: with 1 MiB retained per cycle,
 *                 uordblks and arena stay BIT-IDENTICAL and only this
 *                 column moves. Without it the harness would report "no
 *                 growth" against a server losing a megabyte per
 *                 handshake.
 *   fds           /proc/self/fd. LSan tracks allocations, not
 *                 descriptors; a leaked listener or SQLite handle is
 *                 invisible to it and fatal here.
 *   timers        cloak_reactor_pending_timers. Module 10b rewrote the
 *                 timer heap to be slot-indexed with generations, and
 *                 its author named the worst hazard as a stale handle
 *                 cancelling a recycled slot -- which shows up here as a
 *                 count that drifts, in either direction, per cycle.
 *   sessions      the registry's own count. Must return to K.
 *   proxy_streams the proxy's table. Must return to zero between cycles.
 *
 * THE HARNESS IS ALSO A SUSPECT. Three of this module's six wall-clock
 * defects were found by agents auditing their own instruments, and a
 * long run is exactly where a harness that grows looks like a leaking
 * server. So: nothing here allocates per cycle. The upstream's
 * connection contexts are a fixed array indexed by slot, the client
 * session slots are one allocation made before the first sample, and the
 * CSV is written line by line rather than accumulated. The one
 * deliberate exception is --leak-bytes, which exists to prove the
 * instrument notices growth when there is growth to notice.
 * ===================================================================== */

/* ------------------------------------------------------------------ */
/* Sampling primitives                                                  */
/* ------------------------------------------------------------------ */

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Counts /proc/self/fd, opendir's own descriptor included in every
 * sample so successive samples are directly comparable (the convention
 * test_server_stack.c's fd_count already set). -1 means the detector is
 * unavailable, which the caller reports rather than silently treating as
 * zero: a detector that stops detecting is the failure this project has
 * paid for most often. */
static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) {
        return -1;
    }
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') {
            continue;
        }
        n++;
    }
    closedir(d);
    return n;
}

/* VmRSS and its anonymous/file split, in kB, out of /proc/self/status.
 * -1 in a field means /proc did not offer it.
 *
 * THE SPLIT IS NOT DECORATION, and it was added because the undivided
 * number lied. A first run of this harness showed RSS stepping from
 * 7916 kB to 17468 kB in a single sample and then FALLING to 16572 kB
 * later, with mallinfo2's uordblks and hblkhd bit-identical across the
 * whole episode -- i.e. a 9.5 MB "leak" that the allocator had no part
 * in and that then partly gave itself back. Anonymous dirty memory
 * cannot do that without swap; file-backed pages can, because the kernel
 * reclaims them. Reporting VmRSS alone would have put that episode in a
 * report as growth. rss_anon is the column to fit a leak against;
 * rss_file is the one that moves for reasons belonging to the machine
 * rather than to the program. */
typedef struct {
    long rss;
    long anon;
    long file;
    long anon_huge;
} rss_sample_t;

/* AND THE HUGE-PAGE COLUMN, which is the other half of the same lesson
 * and was also found by measuring rather than by reading. This kernel
 * has transparent hugepages at `always`
 * (/sys/kernel/mm/transparent_hugepage/enabled), so khugepaged collapses
 * the heap into 2 MiB pages behind the program's back and RssAnon jumps
 * to the whole arena in one sample -- measured here as 2180 kB -> 13140 kB
 * inside two minutes, against an arena of 13256 kB, with AnonHugePages
 * then reading 12288 of 13136 kB anonymous. Nothing was allocated. The
 * same effect is far larger on the replay cache: a 2 MiB huge page is
 * faulted in for every slot touched, so the 80 MiB table is essentially
 * fully resident after the first few hundred handshakes rather than
 * filling in gradually.
 *
 * Without this column those are two unexplained step changes in RSS.
 * With it they are arithmetic. */
static rss_sample_t rss_read(void) {
    rss_sample_t s = {-1, -1, -1, -1};
    FILE *f = fopen("/proc/self/status", "r");
    if (f != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), f) != NULL) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                s.rss = strtol(line + 6, NULL, 10);
            } else if (strncmp(line, "RssAnon:", 8) == 0) {
                s.anon = strtol(line + 8, NULL, 10);
            } else if (strncmp(line, "RssFile:", 8) == 0) {
                s.file = strtol(line + 8, NULL, 10);
            }
        }
        fclose(f);
    }
    f = fopen("/proc/self/smaps_rollup", "r");
    if (f != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), f) != NULL) {
            if (strncmp(line, "AnonHugePages:", 14) == 0) {
                s.anon_huge = strtol(line + 14, NULL, 10);
                break;
            }
        }
        fclose(f);
    }
    return s;
}

/* glibc's in-use byte count, and the mmapped total beside it.
 *
 * BOTH, BECAUSE EITHER ONE ALONE IS A TRAP, and the sizes at which each
 * goes blind were measured here, not read. glibc serves a large request
 * either from the arena (counted in uordblks) or from its own mmap
 * (counted in hblkhd, NOT in uordblks), and which one it picks depends
 * on a threshold that is DYNAMIC -- it starts near 128 KiB and adapts.
 * Do not reason from the constant. What was measured, by planting a
 * retained allocation per churn cycle and fitting the slope:
 *
 *   1 MiB/cycle: uordblks 0 and arena 0 -- BIT-IDENTICAL while a
 *                megabyte per handshake was being retained -- and
 *                hblkhd 1.844e10 B/hr. The "sensitive" column is
 *                exactly blind.
 *   200 KB/cycle: the reverse. uordblks and arena both 6.885e9 B/hr,
 *                hblkhd exactly 0.
 *
 * So there is no single column to watch and no size at which to switch.
 * The 80 MiB replay cache is on the hblkhd side; a leak of session-sized
 * objects is on the uordblks side; and rss_anon sees the first one
 * 250x understated, because the pages of a fresh mmapped block are
 * never touched.
 *
 * Zero when unavailable, which the CSV header records (mallinfo2=0) so
 * the analysis can tell "no memory in use" from "column absent". Note
 * that ASan is one such case even where glibc is new enough: measured in
 * this image, an ASan build reports uordblks 0 before and after a 1 MiB
 * malloc under both gcc and clang, because ASan's allocator replaces
 * glibc's and glibc's accounting stays empty. That is the reason this
 * harness reports RSS as well, and part of the reason a sanitizer-build
 * ctest case could not have used these numbers. */
static unsigned long long uordblks(void) {
#if SOAK_HAVE_MALLINFO2
    struct mallinfo2 mi = mallinfo2();
    return (unsigned long long)mi.uordblks;
#else
    return 0ull;
#endif
}

static unsigned long long hblkhd(void) {
#if SOAK_HAVE_MALLINFO2
    struct mallinfo2 mi = mallinfo2();
    return (unsigned long long)mi.hblkhd;
#else
    return 0ull;
#endif
}

/* The arena's total size, which grows when the heap has to be extended
 * and does NOT shrink when the chunks in it are freed. uordblks flat
 * while arena rises is fragmentation, not a leak, and the two have to be
 * told apart because they look identical in RSS. */
static unsigned long long arena_bytes(void) {
#if SOAK_HAVE_MALLINFO2
    struct mallinfo2 mi = mallinfo2();
    return (unsigned long long)mi.arena;
#else
    return 0ull;
#endif
}

/* ------------------------------------------------------------------ */
/* The fake upstream: an echo that owns nothing per cycle               */
/* ------------------------------------------------------------------ */

/* A fixed slot table, deliberately. An upstream that malloc'd a context
 * per accepted connection would put an allocation on the per-cycle path
 * INSIDE the process being measured, and a bug in that one line would be
 * reported as a leak in the server. Slots are found by scanning for a
 * free one, which is O(UP_SLOTS) per accept and irrelevant at these
 * rates. */
#define UP_SLOTS 64

typedef struct up_slot {
    struct upstream *up;
    int idx;
    int fd;
} up_slot_t;

typedef struct upstream {
    cloak_reactor_t *reactor;
    unsigned long accepts;
    unsigned long closes;
    unsigned long echo_short_writes;
    up_slot_t slots[UP_SLOTS];
} upstream_t;

static void up_slot_close(upstream_t *up, int idx) {
    if (up->slots[idx].fd < 0) {
        return;
    }
    cloak_reactor_remove_fd(up->reactor, up->slots[idx].fd);
    close(up->slots[idx].fd);
    up->slots[idx].fd = -1;
    up->closes++;
}

static void up_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    up_slot_t *slot = userdata;
    upstream_t *up = slot->up;
    uint8_t buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            ssize_t w = send(fd, buf, (size_t)n, MSG_NOSIGNAL);
            if (w != n) {
                /* Counted rather than ignored: a short write here would
                 * stall the cycle's read-wait and show up as a falling
                 * cycle rate, which is a harness fault masquerading as a
                 * server fault. The payload is 32 bytes, so this is
                 * expected to stay at zero and the report says whether
                 * it did. */
                up->echo_short_writes++;
            }
            continue;
        }
        if (n == 0) {
            up_slot_close(up, slot->idx);
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        up_slot_close(up, slot->idx);
        return;
    }
}

static void up_on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    upstream_t *up = userdata;
    for (int i = 0; i < UP_SLOTS; i++) {
        if (up->slots[i].fd < 0) {
            up->slots[i].fd = fd;
            up->accepts++;
            (void)cloak_reactor_add_fd(up->reactor, fd, CLOAK_REACTOR_READABLE, up_on_readable,
                                       &up->slots[i]);
            return;
        }
    }
    /* Every slot busy means the harness is running more concurrent
     * relays than it budgeted for; dropping the connection keeps the
     * measurement honest (the cycle fails and is counted) instead of
     * growing an unbounded table inside the instrument. */
    close(fd);
}

static void up_destroy(upstream_t *up) {
    for (int i = 0; i < UP_SLOTS; i++) {
        up_slot_close(up, i);
    }
}

/* ------------------------------------------------------------------ */
/* The environment                                                      */
/* ------------------------------------------------------------------ */

#define T_NOW    ((int64_t)1600000000)
#define T_EXPIRY (T_NOW + 100000)

static int64_t fixed_now(void *userdata) {
    (void)userdata;
    return T_NOW;
}

struct env {
    cloak_reactor_t *reactor;
    cover_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;
    upstream_t up;
    cloak_listener_t up_listener;
    int have_up_listener;
    int up_port;
    char db_path[512];
    cloak_server_config_t cfg;
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_user[CLOAK_UID_LEN];
};

static void env_unlink(const char *path) {
    char aux[600];
    unlink(path);
    snprintf(aux, sizeof(aux), "%s-wal", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-shm", path);
    unlink(aux);
    snprintf(aux, sizeof(aux), "%s-journal", path);
    unlink(aux);
}

static int env_init(struct env *e) {
    memset(e, 0, sizeof(*e));
    char err[256] = {0};

    for (int i = 0; i < UP_SLOTS; i++) {
        e->up.slots[i].fd = -1;
        e->up.slots[i].idx = i;
        e->up.slots[i].up = &e->up;
    }
    e->cover.fd = -1;

    e->reactor = cloak_reactor_create();
    ASSERT_TRUE(e->reactor != NULL);
    if (e->reactor == NULL) {
        return -1;
    }

    e->cover.reactor = e->reactor;
    ASSERT_EQ_INT(0, cloak_listener_open(&e->cover_listener, e->reactor, "127.0.0.1:0",
                                         cover_on_accept, &e->cover, err, sizeof(err)));
    e->have_cover_listener = 1;
    int cover_port = cloak_listener_port(&e->cover_listener);
    ASSERT_TRUE(cover_port > 0);

    e->up.reactor = e->reactor;
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&e->up_listener, e->reactor, "127.0.0.1:0", up_on_accept,
                                         &e->up, err, sizeof(err)));
    e->have_up_listener = 1;
    e->up_port = cloak_listener_port(&e->up_listener);
    ASSERT_TRUE(e->up_port > 0);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, e->server_pub));
    memset(e->uid_user, 0xC0, CLOAK_UID_LEN);
    e->uid_user[0] = 0x11;

    char priv_b64[64];
    char user_b64[32];
    ASSERT_EQ_INT(
        0, cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64, sizeof(priv_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(e->uid_user, CLOAK_UID_LEN, user_b64, sizeof(user_b64)));

    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(e->db_path, sizeof(e->db_path), "%s/cloak_soak_%ld.db", dir, (long)getpid());
    env_unlink(e->db_path);

    /* A BypassUID and nothing else. DELIBERATE, and it is a disk
     * decision as much as a semantic one: a metered user writes a credit
     * row per upload cycle, so a run of this length against a database
     * user would grow the SQLite file and its WAL for the whole run --
     * on a host already at 99% that is the harness filling the disk and
     * calling it a finding. The bypass path still exercises the
     * registry, the replay cache, the timer heap, the panel and the
     * proxy; only the metered accounting is out. */
    char json[2048];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:%d\"]},"
             "\"BindAddr\":[\"127.0.0.1:0\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"AdminUID\":\"%s\",\"BypassUID\":[\"%s\"],"
             "\"DatabasePath\":\"%s\"}",
             e->up_port, cover_port, priv_b64, user_b64, user_b64, e->db_path);
    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &e->cfg, err, sizeof(err)));
    if (err[0] != '\0') {
        fprintf(stderr, "config parse: %s\n", err);
    }
    return 0;
}

static void env_destroy(struct env *e) {
    if (e->have_up_listener) {
        cloak_listener_close(&e->up_listener);
        e->have_up_listener = 0;
    }
    up_destroy(&e->up);
    if (e->have_cover_listener) {
        cloak_listener_close(&e->cover_listener);
        e->have_cover_listener = 0;
    }
    if (e->cover.fd >= 0) {
        cloak_reactor_remove_fd(e->reactor, e->cover.fd);
        close(e->cover.fd);
        e->cover.fd = -1;
    }
    if (e->reactor != NULL) {
        cloak_reactor_destroy(e->reactor);
        e->reactor = NULL;
    }
    if (e->db_path[0] != '\0') {
        env_unlink(e->db_path);
    }
}

static void seed_user(const char *db_path, const uint8_t uid[CLOAK_UID_LEN]) {
    cloak_usermanager_t *m = NULL;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, db_path, fixed_now, NULL, err, sizeof(err)));
    if (m == NULL) {
        return;
    }
    cloak_user_info_t row;
    memset(&row, 0, sizeof(row));
    memcpy(row.uid, uid, CLOAK_UID_LEN);
    row.sessions_cap = 0;
    row.up_credit = (int64_t)1 << 40;
    row.down_credit = (int64_t)1 << 40;
    row.expiry_time = T_EXPIRY;
    ASSERT_EQ_INT(0, cloak_usermanager_write(m, &row, CLOAK_USER_FIELD_ALL));
    cloak_usermanager_close(m);
}

/* ------------------------------------------------------------------ */
/* One churn cycle                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    client_session_t cs;
    cloak_stream_t *stream;
    int live;
} slot_t;

struct echo_wait {
    cloak_stream_t *stream;
    uint8_t *buf;
    size_t cap;
    size_t len;
};

static int echo_has(void *ctx) {
    struct echo_wait *w = ctx;
    for (;;) {
        if (w->len >= w->cap) {
            return 1;
        }
        long n = cloak_stream_read(w->stream, w->buf + w->len, w->cap - w->len);
        if (n > 0) {
            w->len += (size_t)n;
            continue;
        }
        return w->len >= w->cap;
    }
}

struct sess_wait {
    const cloak_server_stack_t *st;
    size_t want;
};

static int sess_count_is(void *ctx) {
    struct sess_wait *w = ctx;
    return cloak_server_stack_session_count(w->st) == w->want;
}

/* Pumps the reactor for ms milliseconds. THIS IS THE PACING KNOB and it
 * is not a sleep: the reactor keeps running, which is the only way the
 * server under measurement is allowed to wait. A sleep here would stop
 * the very timers whose count is being sampled. */
static int never_done(void *ctx) {
    (void)ctx;
    return 0;
}

static void pump_for_ms(cloak_reactor_t *r, int ms) {
    if (ms <= 0) {
        return;
    }
    (void)pump_until(r, never_done, NULL, ms, 1);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

static void usage(void) {
    fprintf(stderr,
            "usage: soak_growth [--seconds=N] [--sample-ms=N] [--concurrency=N]\n"
            "                   [--cycle-ms=N] [--replay-capacity=N] [--leak-bytes=N]\n"
            "                   [--csv=PATH]\n");
}

static long arg_long(const char *arg, const char *name, long dflt, int *matched) {
    size_t n = strlen(name);
    if (strncmp(arg, name, n) == 0 && arg[n] == '=') {
        *matched = 1;
        return strtol(arg + n + 1, NULL, 10);
    }
    *matched = 0;
    return dflt;
}

int main(int argc, char **argv) {
    long seconds = 600;
    long sample_ms = 1000;
    long concurrency = 16;
    long cycle_ms = 20;
    long replay_capacity = 0; /* 0 -> the shipping default, 2^21 */
    long leak_bytes = 0;
    const char *csv_path = NULL;

    for (int i = 1; i < argc; i++) {
        int m = 0;
        long v;
        v = arg_long(argv[i], "--seconds", seconds, &m);
        if (m) {
            seconds = v;
            continue;
        }
        v = arg_long(argv[i], "--sample-ms", sample_ms, &m);
        if (m) {
            sample_ms = v;
            continue;
        }
        v = arg_long(argv[i], "--concurrency", concurrency, &m);
        if (m) {
            concurrency = v;
            continue;
        }
        v = arg_long(argv[i], "--cycle-ms", cycle_ms, &m);
        if (m) {
            cycle_ms = v;
            continue;
        }
        v = arg_long(argv[i], "--replay-capacity", replay_capacity, &m);
        if (m) {
            replay_capacity = v;
            continue;
        }
        v = arg_long(argv[i], "--leak-bytes", leak_bytes, &m);
        if (m) {
            leak_bytes = v;
            continue;
        }
        if (strncmp(argv[i], "--csv=", 6) == 0) {
            csv_path = argv[i] + 6;
            continue;
        }
        usage();
        return 2;
    }
    if (concurrency < 1 || concurrency > UP_SLOTS / 2) {
        fprintf(stderr, "concurrency must be in [1, %d]\n", UP_SLOTS / 2);
        return 2;
    }

    struct env e;
    if (env_init(&e) != 0) {
        return 1;
    }
    seed_user(e.db_path, e.uid_user);

    cloak_server_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.reactor = e.reactor;
    sc.config = &e.cfg;
    sc.now_fn = fixed_now;
    sc.replay_cache_capacity = (size_t)replay_capacity;
    /* The panel's upload cycle left at its own default on purpose: it is
     * a periodic timer, and a periodic timer that never fires is a timer
     * whose arm/disarm path is never measured. */

    cloak_server_stack_t *st = NULL;
    char err[256] = {0};
    if (cloak_server_stack_open(&st, &sc, err, sizeof(err)) != 0 || st == NULL) {
        fprintf(stderr, "stack open failed: %s\n", err);
        env_destroy(&e);
        return 1;
    }
    int port = cloak_server_stack_listener_port(st, 0);

    slot_t *slots = calloc((size_t)concurrency, sizeof(slot_t));
    if (slots == NULL) {
        cloak_server_stack_close(st);
        env_destroy(&e);
        return 1;
    }

    /* The deliberate leak, and the only allocation on the per-cycle path.
     * It is RETAINED IN A REACHABLE LIST, which is the whole point: at
     * exit LeakSanitizer walks this list, finds every block reachable,
     * and reports nothing -- while RSS and uordblks climb linearly. That
     * is the defect class this harness exists for, and --leak-bytes is
     * how the harness proves it can see it. */
    struct leak_node {
        struct leak_node *next;
        unsigned char payload[1];
    };
    struct leak_node *leak_head = NULL;

    FILE *csv = stdout;
    if (csv_path != NULL) {
        csv = fopen(csv_path, "w");
        if (csv == NULL) {
            perror("fopen csv");
            free(slots);
            cloak_server_stack_close(st);
            env_destroy(&e);
            return 1;
        }
    }

    fprintf(csv, "# soak_growth seconds=%ld sample_ms=%ld concurrency=%ld cycle_ms=%ld\n", seconds,
            sample_ms, concurrency, cycle_ms);
    fprintf(csv, "# replay_capacity=%zu leak_bytes=%ld mallinfo2=%d\n",
            cloak_server_stack_replay_cache_capacity(st), leak_bytes, SOAK_HAVE_MALLINFO2);
    fprintf(csv, "t_ms,cycles,fails,rss_kb,rss_anon_kb,rss_file_kb,rss_anon_huge_kb,"
                 "fds,timers,sessions,proxy_sessions,proxy_streams,uordblks,hblkhd,arena,"
                 "up_accepts,up_closes,up_short\n");
    fflush(csv);

    uint64_t t0 = mono_ms();
    uint64_t deadline = t0 + (uint64_t)seconds * 1000u;
    uint64_t next_sample = t0;
    unsigned long cycles = 0;
    unsigned long fails = 0;
    uint32_t next_session_id = 1;

    for (;;) {
        uint64_t now = mono_ms();
        if (now >= deadline) {
            break;
        }
        if (now >= next_sample) {
            rss_sample_t rs = rss_read();
            int fds = fd_count();
            fprintf(csv, "%llu,%lu,%lu,%ld,%ld,%ld,%ld,%d,%zu,%zu,%zu,%zu,%llu,%llu,%llu,%lu,%lu,%lu\n",
                    (unsigned long long)(now - t0), cycles, fails, rs.rss, rs.anon, rs.file,
                    rs.anon_huge, fds,
                    cloak_reactor_pending_timers(e.reactor), cloak_server_stack_session_count(st),
                    cloak_server_stack_proxy_session_count(st),
                    cloak_server_stack_proxy_stream_count(st), uordblks(), hblkhd(), arena_bytes(),
                    e.up.accepts, e.up.closes, e.up.echo_short_writes);
            fflush(csv);
            do {
                next_sample += (uint64_t)sample_ms;
            } while (next_sample <= now);
        }

        size_t idx = (size_t)(cycles % (unsigned long)concurrency);
        slot_t *s = &slots[idx];

        /* ---- retire the slot's previous session, if any ---- */
        if (s->live) {
            size_t before = cloak_server_stack_session_count(st);
            if (s->stream != NULL) {
                cloak_session_release_stream(&s->cs.sesh, s->stream);
                s->stream = NULL;
            }
            client_session_close(&s->cs);
            s->live = 0;
            /* The server's own teardown is asynchronous: the close above
             * only drops our end. Waiting for the registry count to fall
             * is what makes "sessions" a steady-state number rather than
             * a sampling artefact -- and it is bounded, so a server that
             * stops tearing down shows up as a rising session count
             * rather than as a hang. */
            struct sess_wait sw = {st, before > 0 ? before - 1 : 0};
            (void)pump_until(e.reactor, sess_count_is, &sw, 200, 5);
        }

        /* ---- open a fresh one ---- */
        cloak_session_config_t ccfg;
        memset(&ccfg, 0, sizeof(ccfg));
        ccfg.ordering = CLOAK_SESSION_ORDERING_ORDERED;
        ccfg.max_on_wire_size = CLOAK_SERVER_STACK_DEFAULT_MAX_ON_WIRE_SIZE;
        ccfg.stream_recv_capacity = CLOAK_SERVER_STACK_DEFAULT_STREAM_RECV_CAPACITY;
        ccfg.stream_max_pending_frames = CLOAK_SERVER_STACK_DEFAULT_STREAM_MAX_PENDING;
        ccfg.conn_send_queue_cap = CLOAK_SERVER_STACK_DEFAULT_CONN_SEND_QUEUE_CAP;
        ccfg.inactivity_timeout_ms = CLOAK_SERVER_STACK_DEFAULT_INACTIVITY_TIMEOUT_MS;

        if (client_session_open(&s->cs, e.reactor, port, e.server_pub, e.uid_user, "ss",
                                next_session_id++, 0, &ccfg) != 0) {
            fails++;
            cycles++;
            pump_for_ms(e.reactor, (int)cycle_ms);
            continue;
        }
        s->live = 1;

        s->stream = cloak_session_open_stream(&s->cs.sesh, NULL);
        if (s->stream == NULL) {
            fails++;
        } else {
            static const uint8_t payload[32] = {0x5a};
            uint8_t back[32];
            if (cloak_stream_write(s->stream, payload, sizeof(payload)) != (long)sizeof(payload)) {
                fails++;
            } else {
                struct echo_wait ew = {s->stream, back, sizeof(back), 0};
                if (!pump_until(e.reactor, echo_has, &ew, 400, 5)) {
                    fails++;
                }
            }
        }

        if (leak_bytes > 0) {
            struct leak_node *n = malloc(sizeof(struct leak_node) + (size_t)leak_bytes);
            if (n != NULL) {
                n->next = leak_head;
                n->payload[0] = 0;
                leak_head = n;
            }
        }

        cycles++;
        pump_for_ms(e.reactor, (int)cycle_ms);
    }

    /* A final sample at the true end of the run, so the last interval is
     * not silently shorter than the rest. */
    {
        uint64_t now = mono_ms();
        rss_sample_t rs = rss_read();
        fprintf(csv, "%llu,%lu,%lu,%ld,%ld,%ld,%ld,%d,%zu,%zu,%zu,%zu,%llu,%llu,%llu,%lu,%lu,%lu\n",
                (unsigned long long)(now - t0), cycles, fails, rs.rss, rs.anon, rs.file,
                rs.anon_huge, fd_count(),
                cloak_reactor_pending_timers(e.reactor), cloak_server_stack_session_count(st),
                cloak_server_stack_proxy_session_count(st),
                cloak_server_stack_proxy_stream_count(st), uordblks(), hblkhd(), arena_bytes(),
                e.up.accepts, e.up.closes, e.up.echo_short_writes);
        fflush(csv);
    }

    fprintf(stderr, "soak: %lu cycles, %lu failed, %lu upstream accepts, %lu closes, %lu short\n",
            cycles, fails, e.up.accepts, e.up.closes, e.up.echo_short_writes);

    for (long i = 0; i < concurrency; i++) {
        if (slots[i].live) {
            if (slots[i].stream != NULL) {
                cloak_session_release_stream(&slots[i].cs.sesh, slots[i].stream);
            }
            client_session_close(&slots[i].cs);
        }
    }
    free(slots);
    while (leak_head != NULL) {
        struct leak_node *n = leak_head->next;
        free(leak_head);
        leak_head = n;
    }
    if (csv != stdout) {
        fclose(csv);
    }
    cloak_server_stack_close(st);
    env_destroy(&e);

    if (cloak_test_failures > 0) {
        fprintf(stderr, "%d setup assertion(s) failed\n", cloak_test_failures);
        return 1;
    }
    return 0;
}
