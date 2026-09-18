#define _POSIX_C_SOURCE 200809L

/* THE CORPUS REPLAY -- the one test in this directory, and the only
 * thing under fuzz/ that is add_test()ed.
 *
 * WHAT IT IS FOR. The eight libFuzzer targets beside this file are not
 * tests: they have no expected output and they run for as long as you
 * give them. The COMMITTED CORPUS is the artefact those campaigns
 * produced -- one minimised set of inputs per target, each one a
 * distinct path through the code under test -- and this program is what
 * turns that artefact into a regression. It feeds every committed unit
 * to the target that produced it, through the same
 * LLVMFuzzerTestOneInput and the same oracles a campaign would use, and
 * fails if any of them fires. No mutation, no randomness, no time
 * budget: the same 1,094 inputs in the same order on every run.
 *
 * WHY A REPLAY AND NOT A CAMPAIGN IN CI. Measured, at the commit that
 * added this file: the whole replay costs a couple of seconds, while the
 * shortest campaign anyone would call meaningful -- 60 seconds per
 * target across eight targets -- is eight minutes, which would more than
 * double a ~102 s suite for a search that finds nothing new by design.
 * So: THE CORPUS IS THE COMMITTED ARTEFACT, THE REPLAY IS THE
 * REGRESSION, AND CAMPAIGNS RUN OUT OF BAND. fuzz/README.md says how to
 * run one and what it can and cannot see.
 *
 * WHAT IT CAN CATCH THAT THE OTHER 75 TESTS CANNOT. At least one thing,
 * proven rather than claimed. Module 10a task 4 planted a denial of
 * service in client_transport.c's `feed` -- delete the h->body_total ==
 * 0 case from the header branch and a record declaring a zero-length
 * body parks the reader with nothing to wait for, pinning a registered
 * fd on the shared reactor until the 15-second deadline, bought by a
 * censor for a FIVE-BYTE record header. Measured at the commit that
 * added this file, with the plant live and both build directories
 * rebuilt: `ctest -j4` in Debug is 75 passed, 1 FAILED out of 76, and
 * the one failure is this test --
 *
 *   76 - test_fuzz_corpus_replay (Subprocess aborted)
 *   fuzz_client_reply: oracle failed: still pending after the peer
 *   closed: the reader parked with nothing to wait for
 *
 * on corpus unit client_reply/5a41d47a53ff8c4f999db11aecb6bf3b4873e05f,
 * from the committed corpus alone with no fuzzing at all. Reinstate the
 * plant and run `ctest` to see it again; the plant was reverted with cp
 * and both build directories rebuilt before any green number in this
 * tree was taken.
 *
 * HOW THE HARNESSES ARE LINKED IN. Each fuzz_*.c defines exactly one
 * LLVMFuzzerTestOneInput, so eight of them cannot be linked into one
 * program as they stand. fuzz/CMakeLists.txt compiles each into its own
 * OBJECT library with -DLLVMFuzzerTestOneInput=cloak_replay_<name> (and
 * -DLLVMFuzzerInitialize=cloak_replay_init_<name>), which renames the
 * entry point without editing a single harness: a harness file reads
 * exactly the same whether it is being fuzzed or replayed, which is the
 * property that keeps the two from drifting.
 *
 * ADDING A TARGET. Add its declaration and its table row below, and its
 * name to CLOAK_REPLAY_TARGETS in fuzz/CMakeLists.txt. IF THE NEW
 * HARNESS DEFINES AN LLVMFuzzerInitialize, ITS TABLE ROW MUST NAME THE
 * RENAMED INITIALIZER -- a row that leaves the init column NULL for a
 * harness that has one compiles, links and silently replays against
 * uninitialised state. Only fuzz_client_reply.c has one today.
 *
 * THE CAPS ARE ASSERTED HERE, NOT PROMISED IN A README. Ruling 2 caps
 * the whole fuzz/ corpus at 1 MiB of content; this module already had to
 * correct one cap that existed only as prose. Both dimensions are
 * checked below, and the FILE COUNT is the binding one: 1,094 files is
 * 27.5 % of the byte cap but it is what the replay's wall time and every
 * `git status` in this tree actually scale with.
 */

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifndef CLOAK_FUZZ_CORPUS_DIR
#error "CLOAK_FUZZ_CORPUS_DIR must be defined by the build (see fuzz/CMakeLists.txt)"
#endif

/* Ruling 2's cap, as an assertion. Content bytes only -- what the units
 * are, not what the filesystem rounds them up to. */
#define CORPUS_MAX_BYTES (1024u * 1024u)

/* The binding cost, and deliberately not a tight fit around today's
 * 1,094: a corpus that grows by a few dozen units after a campaign is
 * normal and should not fail the suite, while one that doubles is a
 * `-merge=1` somebody forgot to run. 2,048 is that line. */
#define CORPUS_MAX_FILES 2048u

/* A single unit larger than this is a corpus bug, not an input: the
 * largest committed unit today is 16,441 bytes (a clienthello) and every
 * target is run with -max_len=1024 or -max_len=4096. Bounded here so a
 * stray multi-megabyte file is reported as what it is rather than
 * silently malloc'd. */
#define UNIT_MAX_BYTES (1024u * 1024u)

typedef int (*replay_entry_fn)(const uint8_t *data, size_t size);
typedef int (*replay_init_fn)(int *argc, char ***argv);

int cloak_replay_base64(const uint8_t *data, size_t size);
int cloak_replay_client_reply(const uint8_t *data, size_t size);
int cloak_replay_init_client_reply(int *argc, char ***argv);
int cloak_replay_clienthello(const uint8_t *data, size_t size);
int cloak_replay_firstpacket(const uint8_t *data, size_t size);
int cloak_replay_http(const uint8_t *data, size_t size);
int cloak_replay_session_envelope(const uint8_t *data, size_t size);
int cloak_replay_ws_frame(const uint8_t *data, size_t size);
int cloak_replay_ws_handshake(const uint8_t *data, size_t size);

typedef struct {
    const char *name; /* also the corpus subdirectory name */
    replay_init_fn init;
    replay_entry_fn entry;
} replay_target_t;

static const replay_target_t g_targets[] = {
    {"base64", NULL, cloak_replay_base64},
    {"client_reply", cloak_replay_init_client_reply, cloak_replay_client_reply},
    {"clienthello", NULL, cloak_replay_clienthello},
    {"firstpacket", NULL, cloak_replay_firstpacket},
    {"http", NULL, cloak_replay_http},
    {"session_envelope", NULL, cloak_replay_session_envelope},
    {"ws_frame", NULL, cloak_replay_ws_frame},
    {"ws_handshake", NULL, cloak_replay_ws_handshake},
};

#define TARGET_COUNT (sizeof(g_targets) / sizeof(g_targets[0]))

static int g_failed;

static void fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void fail(const char *fmt, ...) {
    va_list ap;
    fputs("replay: FAIL: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    g_failed = 1;
}

/* readdir order is filesystem order, which differs between machines and
 * between checkouts. Sorting is what makes "the replay died on unit N"
 * mean the same thing to the next reader as it did to the one who saw
 * it. */
static int name_cmp(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Returns the unit's length, or (size_t)-1 on any error (reported). The
 * buffer is malloc'd exactly `size` bytes, never with slack: an
 * off-by-one read past the end of the input is the single most common
 * parser defect, and ASan can only see it if the allocation ends where
 * the input does. */
static uint8_t *read_unit(const char *path, size_t *out_size) {
    struct stat st;
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    size_t got;

    if (f == NULL) {
        fail("cannot open %s: %s", path, strerror(errno));
        return NULL;
    }
    if (fstat(fileno(f), &st) != 0) {
        fail("cannot stat %s: %s", path, strerror(errno));
        fclose(f);
        return NULL;
    }
    if (st.st_size < 0 || (unsigned long long)st.st_size > UNIT_MAX_BYTES) {
        fail("%s is %lld bytes, over the %u-byte per-unit ceiling", path,
             (long long)st.st_size, (unsigned)UNIT_MAX_BYTES);
        fclose(f);
        return NULL;
    }
    *out_size = (size_t)st.st_size;
    /* malloc(0) may legally return NULL; a zero-length unit is a real
     * and interesting input (every target must survive one), so it gets
     * a one-byte allocation it never reads rather than a NULL pointer
     * the loop below would have to special-case. */
    buf = malloc(*out_size != 0 ? *out_size : 1);
    if (buf == NULL) {
        fail("out of memory reading %s", path);
        fclose(f);
        return NULL;
    }
    got = fread(buf, 1, *out_size, f);
    if (got != *out_size) {
        fail("short read on %s: %zu of %zu bytes", path, got, *out_size);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    return buf;
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

int main(int argc, char **argv) {
    const char *root = (argc > 1) ? argv[1] : CLOAK_FUZZ_CORPUS_DIR;
    unsigned long long total_files = 0;
    unsigned long long total_bytes = 0;
    double t0 = now_ms();
    size_t ti;

    printf("replay: corpus root %s\n", root);

    for (ti = 0; ti < TARGET_COUNT; ti++) {
        const replay_target_t *t = &g_targets[ti];
        /* Half of path[]'s size, so that "<dir>/<name>" cannot be
         * truncated for any name a filesystem will hand back (NAME_MAX
         * is 255). Written this way rather than left to a runtime check
         * because gcc's -Wformat-truncation reasons about the sizes, not
         * about the checks, and this file is required to be warning-free
         * under both gcc and clang. */
        char dir[2048];
        DIR *d;
        struct dirent *de;
        char **names = NULL;
        size_t n_names = 0, cap = 0, i;
        unsigned long long dir_bytes = 0;

        if (snprintf(dir, sizeof(dir), "%s/%s", root, t->name) >= (int)sizeof(dir)) {
            fail("corpus path for %s does not fit in %zu bytes", t->name, sizeof(dir));
            continue;
        }
        d = opendir(dir);
        if (d == NULL) {
            /* Not a skip. A corpus directory that has gone missing is
             * exactly the regression this test exists to notice: the
             * units are the artefact, and losing them silently would
             * leave a green test covering nothing. */
            fail("cannot open corpus directory %s: %s", dir, strerror(errno));
            continue;
        }
        while ((de = readdir(d)) != NULL) {
            char path[4096];
            struct stat st;
            if (de->d_name[0] == '.') {
                continue;
            }
            if (snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) >= (int)sizeof(path)) {
                fail("corpus path for %s/%s does not fit", t->name, de->d_name);
                continue;
            }
            /* d_type is not populated on every filesystem; stat is. */
            if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
                fail("%s is not a regular file", path);
                continue;
            }
            if (n_names == cap) {
                char **grown;
                cap = (cap == 0) ? 64 : cap * 2;
                grown = realloc(names, cap * sizeof(*names));
                if (grown == NULL) {
                    fail("out of memory listing %s", dir);
                    break;
                }
                names = grown;
            }
            names[n_names] = strdup(de->d_name);
            if (names[n_names] == NULL) {
                fail("out of memory listing %s", dir);
                break;
            }
            n_names++;
        }
        closedir(d);

        if (n_names == 0) {
            fail("corpus directory %s is empty", dir);
        }
        qsort(names, n_names, sizeof(*names), name_cmp);

        if (t->init != NULL) {
            int fake_argc = argc;
            char **fake_argv = argv;
            if (t->init(&fake_argc, &fake_argv) != 0) {
                fail("%s: LLVMFuzzerInitialize returned non-zero", t->name);
            }
        }

        for (i = 0; i < n_names; i++) {
            char path[4096];
            uint8_t *buf;
            size_t size = 0;
            (void)snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
            /* Not re-checked for truncation: the same "%s/%s" from the
             * same dir[] was checked in the listing loop above, and
             * path[] is twice dir[]'s size. */
            /* Printed BEFORE the call, and flushed, because the failure
             * mode this test is built to produce is abort() from inside
             * a harness oracle -- at which point the last line on stderr
             * is the only record of which unit did it. */
            fprintf(stderr, "replay: %s: running %s\n", t->name, names[i]);
            fflush(stderr);
            buf = read_unit(path, &size);
            if (buf == NULL) {
                continue;
            }
            (void)t->entry(buf, size);
            free(buf);
            dir_bytes += size;
            total_bytes += size;
            total_files++;
        }
        for (i = 0; i < n_names; i++) {
            free(names[i]);
        }
        free(names);

        printf("replay: %-16s %4zu units, %8llu bytes\n", t->name, n_names, dir_bytes);
        fflush(stdout);
    }

    printf("replay: TOTAL %llu units, %llu bytes, %.0f ms\n", total_files, total_bytes,
           now_ms() - t0);

    /* Ruling 2's cap, enforced rather than described. */
    if (total_bytes > CORPUS_MAX_BYTES) {
        fail("corpus is %llu content bytes, over the %u-byte cap "
             "(re-minimise with -merge=1; see fuzz/README.md)",
             total_bytes, (unsigned)CORPUS_MAX_BYTES);
    }
    if (total_files > CORPUS_MAX_FILES) {
        fail("corpus is %llu files, over the %u-file cap "
             "(re-minimise with -merge=1; see fuzz/README.md)",
             total_files, (unsigned)CORPUS_MAX_FILES);
    }
    printf("replay: caps  %llu/%u bytes (%.1f%%), %llu/%u files (%.1f%%)\n", total_bytes,
           (unsigned)CORPUS_MAX_BYTES, 100.0 * (double)total_bytes / (double)CORPUS_MAX_BYTES,
           total_files, (unsigned)CORPUS_MAX_FILES,
           100.0 * (double)total_files / (double)CORPUS_MAX_FILES);

    if (g_failed) {
        printf("replay: FAILED\n");
        return 1;
    }
    printf("replay: OK\n");
    return 0;
}
