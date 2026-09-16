#define _POSIX_C_SOURCE 200809L

/* ck-server, driven as a subprocess.
 *
 * THIS FILE TESTS A PROGRAM, NOT A FUNCTION. Everything ck-server does
 * that is worth testing is observable only from outside it: an exit code,
 * what it printed, and whether a socket it claims to have opened accepts a
 * connection. So every case here forks, execs the real binary, and reads
 * its output -- nothing is linked against main.c, which has no external
 * symbols to link against anyway.
 *
 * WHAT EACH CASE IS FOR, and what would have to break for it to fail:
 *
 *   1. -h and -v exit 0 and print, EVEN THOUGH the config they were given
 *      does not exist -- which is the only way to show from outside that
 *      they returned before the config and the network were touched.
 *   2. -u/-uid and -k/-key. The UID is DECODED and its length pinned at
 *      exactly 16 on both sides; the key pair is ROUND-TRIPPED (the public
 *      key is re-derived from the private one by scalar-multiplying the
 *      curve base point) so an implementation handing back unrelated
 *      random bytes fails here, which "two non-empty strings that differ"
 *      would not. AND EVERY GENERATOR IS RUN TWICE: a hardcoded, valid,
 *      self-consistent pair -- one private key shared by every user of the
 *      build -- satisfies every other assertion in the case and is the
 *      worst failure this program has available. The human dress is
 *      rebuilt from the token and compared WHOLE, so "the same value in
 *      different dress" is exact rather than a substring search.
 *   3. A config path that does not exist: exit 2, and the message names
 *      the path.
 *   4. Inline JSON as -c's value, which Go's server cannot do (D3).
 *   5. No BindAddr at all -> :443 and :80, in that order. SEE THAT CASE'S
 *      COMMENT for which of the two possible outcomes this environment
 *      produces and how the case decides.
 *   6. SIGTERM: exit 0, within a bound, having logged the signal.
 *   7. Plugin mode, eight sub-cases: the ProxyBook injection and all three
 *      of parseSSBindAddr's rules, its exactly-one-pipe test, its IPv6
 *      bracketing, and both one-sided SS_REMOTE_* environments.
 *   8. A bind failure exits 3 and a configuration failure exits 2 -- the
 *      exit-code contract, pinned as a contract rather than a comment.
 *   9. Every BindAddr is RESOLVED and re-rendered, not copied: the step
 *      that makes case 7's comparisons meaningful at all.
 *  10. Exit 4, reached by starving the child of descriptors, with the
 *      neighbouring limits pinned to 3 and to a running server -- plus the
 *      descriptor census, which is what brief case 6's "no leaked
 *      descriptors" actually needs (LSan does not track descriptors).
 *  11. The small ones: a flag missing its value, -verbosity's EFFECT, and
 *      -c preferring a readable file to its own text.
 *
 * EVERY WAIT IS BOUNDED BY THE CLOCK. Nothing here spins forever waiting
 * for a child that will not speak; a child that misses its deadline is a
 * failed assertion, not a hung suite. */

#include "cloak/base64.h"
#include "cloak/crypto.h"
#include "test_framework.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef CK_SERVER_PATH
#error "CK_SERVER_PATH must be defined by the build"
#endif

#define OUT_CAP 65536

/* THREE DIFFERENT BOUNDS, BECAUSE THEY MEASURE THREE DIFFERENT THINGS.
 *
 * BOOT_MS is generous: an ASan build of this program resolves RedirAddr,
 * builds nine objects and opens its listeners before it says "ready", and
 * a loaded CI box can make that take seconds.
 *
 * EXIT_MS bounds a child that exits under its own power. Some of those
 * runs resolve a deliberately unresolvable name first, so the resolver's
 * own retry budget is inside this one.
 *
 * SHUTDOWN_MS bounds the gap between a signal and the child's exit, and it
 * is DELIBERATELY SMALL. A missing cloak_reactor_stop makes every one of
 * those reaps run to the bound; with all three bounds at 15 s, and more
 * than a dozen cases reaping a signalled child in sequence, ctest reported
 * that as "***Timeout 60.03 sec" -- a hang, not a named failure, and
 * indistinguishable from a genuine future hang. Shutdown is measured (see
 * shutdown_max_ms, printed at the end of the run) at well under 100 ms in
 * both builds, so 2 s fails by assertion, in seconds, naming the case.
 * The bracket is in the task report: 2000 passes, 20 fails. */
#define BOOT_MS     15000
#define EXIT_MS     10000
#define SHUTDOWN_MS 2000

/* ------------------------------------------------------------------ */
/* Clock-bounded subprocess plumbing                                    */
/* ------------------------------------------------------------------ */

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

typedef struct {
    pid_t pid;
    int fd; /* the child's stdout and stderr, merged */
    char out[OUT_CAP];
    size_t out_len;
} child_t;

/* env is a NULL-terminated list of "NAME=VALUE" strings set in the child
 * only -- the test process's own environment stays clean, so a case that
 * does not ask for plugin mode cannot accidentally inherit it.
 *
 * nofile, when non-zero, is an RLIMIT_NOFILE applied to the child and to
 * nothing else. It is how the runtime-failure exit code is reached from
 * outside: ck-server's descriptor budget is exact and public (see
 * test_runtime_exit_code_and_the_descriptor_budget), so a limit chosen one
 * descriptor short of what a step needs makes exactly that step fail. */
/* Closes everything above stderr in the freshly forked child, BEFORE exec.
 * These are the TEST process's descriptors -- ctest's, the capture pipe's,
 * whatever a future harness adds -- and every one of them that survived
 * into ck-server would be counted by the census below and would consume
 * part of the descriptor budget the runtime-failure case measures. Closing
 * them makes the child's starting descriptor set exactly {0, 1, 2},
 * whoever ran the test and however. (The server binary's own sanitizer
 * runtime initialises after the exec, so nothing here touches it.) */
static void close_inherited_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) {
        return;
    }
    int keep = dirfd(d);
    int doomed[256];
    size_t n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < sizeof(doomed) / sizeof(doomed[0])) {
        int fd = atoi(e->d_name);
        if (fd > STDERR_FILENO && fd != keep) {
            doomed[n++] = fd;
        }
    }
    closedir(d);
    for (size_t i = 0; i < n; i++) {
        close(doomed[i]);
    }
}

static int child_spawn_limited(child_t *c, char *const argv[], const char *const env[],
                               int nofile) {
    memset(c, 0, sizeof(*c));
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        close_inherited_fds();
        if (nofile > 0) {
            struct rlimit rl;
            rl.rlim_cur = (rlim_t)nofile;
            rl.rlim_max = (rlim_t)nofile;
            if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
                _exit(126);
            }
        }
        if (env != NULL) {
            for (size_t i = 0; env[i] != NULL; i++) {
                char buf[1024];
                snprintf(buf, sizeof(buf), "%s", env[i]);
                char *eq = strchr(buf, '=');
                if (eq != NULL) {
                    *eq = '\0';
                    setenv(buf, eq + 1, 1);
                }
            }
        }
        execv(CK_SERVER_PATH, argv);
        _exit(127);
    }
    close(pipefd[1]);
    c->pid = pid;
    c->fd = pipefd[0];
    return 0;
}

static int child_spawn(child_t *c, char *const argv[], const char *const env[]) {
    return child_spawn_limited(c, argv, env, 0);
}

/* Pulls whatever is readable right now into c->out. Returns 1 on EOF. */
static int child_drain(child_t *c, int wait_ms) {
    struct pollfd p;
    p.fd = c->fd;
    p.events = POLLIN;
    int rc = poll(&p, 1, wait_ms);
    if (rc <= 0) {
        return 0;
    }
    if (c->out_len + 1 >= sizeof(c->out)) {
        return 0;
    }
    ssize_t got = read(c->fd, c->out + c->out_len, sizeof(c->out) - c->out_len - 1);
    if (got > 0) {
        c->out_len += (size_t)got;
        c->out[c->out_len] = '\0';
        return 0;
    }
    if (got == 0) {
        return 1;
    }
    return (errno == EAGAIN || errno == EINTR) ? 0 : 1;
}

/* Reads until marker appears in the child's output or the clock runs out.
 * Returns 0 when the marker arrived, -1 otherwise. */
static int child_wait_for(child_t *c, const char *marker, int timeout_ms) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        if (strstr(c->out, marker) != NULL) {
            return 0;
        }
        if (now_ms() >= deadline) {
            return -1;
        }
        if (child_drain(c, 50) == 1) {
            /* EOF: one last look, then give up. */
            return strstr(c->out, marker) != NULL ? 0 : -1;
        }
    }
}

/* Reaps the child, draining output meanwhile. Returns the exit status
 * (>= 0) or -1 if it did not exit inside the bound. */
static int child_reap(child_t *c, int timeout_ms) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        int status = 0;
        pid_t r = waitpid(c->pid, &status, WNOHANG);
        if (r == c->pid) {
            while (child_drain(c, 10) == 0 && now_ms() < deadline) {
                /* flush the tail */
            }
            close(c->fd);
            c->fd = -1;
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        }
        if (now_ms() >= deadline) {
            kill(c->pid, SIGKILL);
            waitpid(c->pid, &status, 0);
            close(c->fd);
            c->fd = -1;
            return -1;
        }
        child_drain(c, 20);
    }
}

/* Runs to completion and returns the exit status. */
static int run_to_exit(child_t *c, char *const argv[], const char *const env[],
                       int timeout_ms) {
    if (child_spawn(c, argv, env) != 0) {
        return -1;
    }
    return child_reap(c, timeout_ms);
}

static int run_to_exit_limited(child_t *c, char *const argv[], const char *const env[],
                               int timeout_ms, int nofile) {
    if (child_spawn_limited(c, argv, env, nofile) != 0) {
        return -1;
    }
    return child_reap(c, timeout_ms);
}

/* The worst signal-to-exit latency this run measured, printed at the end.
 * SHUTDOWN_MS is pinned against this number and not against a guess. */
static uint64_t shutdown_max_ms = 0;

/* Signals the child and reaps it inside SHUTDOWN_MS, returning its exit
 * status. EVERY signalled shutdown in this file goes through here, so the
 * bound is one constant rather than a dozen literals, and so the measured
 * latency is collected from all of them. */
static int signal_and_reap(child_t *c, int signo) {
    uint64_t start = now_ms();
    kill(c->pid, signo);
    int rc = child_reap(c, SHUTDOWN_MS);
    uint64_t took = now_ms() - start;
    if (took > shutdown_max_ms) {
        shutdown_max_ms = took;
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Descriptor accounting                                               */
/* ------------------------------------------------------------------ */

/* LEAKSANITIZER DOES NOT TRACK DESCRIPTORS. The project's own
 * libcloak-client/tests/test_client_stack.c says so next to its
 * count_open_fds, and five client tests count /proc/self/fd for exactly
 * that reason. This is the same convention pointed at the CHILD -- a
 * leaked descriptor in ck-server's startup or shutdown path is invisible
 * to the child's exit status, ASan build or not.
 *
 * The census is classified rather than merely counted so a failure says
 * WHICH kind of descriptor appeared: a stray socket and a stray open file
 * are different bugs. */
typedef struct {
    int total;
    int sockets;
    int eventpolls;
    int signalfds;
} fd_census_t;

static int child_fd_census(pid_t pid, fd_census_t *out) {
    char dir[64];
    snprintf(dir, sizeof(dir), "/proc/%d/fd", (int)pid);
    DIR *d = opendir(dir);
    if (d == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
            continue;
        }
        out->total++;
        char link[512];
        char target[256];
        snprintf(link, sizeof(link), "%s/%s", dir, e->d_name);
        ssize_t n = readlink(link, target, sizeof(target) - 1);
        if (n < 0) {
            continue;
        }
        target[n] = '\0';
        if (strncmp(target, "socket:", 7) == 0) {
            out->sockets++;
        } else if (strcmp(target, "anon_inode:[eventpoll]") == 0) {
            out->eventpolls++;
        } else if (strcmp(target, "anon_inode:[signalfd]") == 0) {
            out->signalfds++;
        }
    }
    closedir(d);
    return 0;
}

/* stdin, stdout, stderr + the reactor's epoll + the signalfd + one socket
 * per listener. That is the COMPLETE inventory of what ck-server should
 * hold once it is ready; anything else is a leak.
 *
 * THE SAME NUMBER IN BOTH BUILDS. Measured, not assumed: the ASan/UBSan
 * runtime holds no descriptor of its own for the life of the process, so
 * there is no sanitizer allowance in this total. What DOES move it is the
 * harness -- ctest and the capture pipe hand the child descriptors of
 * their own -- which is why child_spawn_limited closes everything above
 * stderr before the exec, and what makes this number a property of
 * ck-server rather than of whoever ran the test. */
#define CK_FD_EXPECTED(listeners) (3 + 1 + 1 + (listeners))

/* Waits for the child's census to come back to `want` (an accepted
 * connection the peer has closed takes a reactor turn to disappear).
 * Returns 0 if it did, -1 if the clock ran out -- the caller asserts. */
static int child_fd_settle(pid_t pid, const fd_census_t *want, int timeout_ms,
                           fd_census_t *last) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        if (child_fd_census(pid, last) != 0) {
            return -1;
        }
        if (last->total == want->total && last->sockets == want->sockets &&
            last->eventpolls == want->eventpolls && last->signalfds == want->signalfds) {
            return 0;
        }
        if (now_ms() >= deadline) {
            return -1;
        }
        struct timespec ts = {0, 10 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
}

static size_t count_occurrences(const char *hay, const char *needle) {
    size_t n = 0;
    const char *p = hay;
    size_t len = strlen(needle);
    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += len;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Sockets                                                             */
/* ------------------------------------------------------------------ */

static int free_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(a);
    if (getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
        close(fd);
        return -1;
    }
    int port = ntohs(a.sin_port);
    close(fd);
    return port;
}

/* 0 if a TCP connection to 127.0.0.1:port completes. */
static int can_connect(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    int rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
    close(fd);
    return rc == 0 ? 0 : -1;
}

/* Connects and KEEPS the connection, returning the descriptor. The
 * descriptor census needs connections the server is still holding, which
 * can_connect (which closes immediately) cannot give it. */
static int connect_keep(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Can THIS process bind 127.0.0.1:port? Case 5 asks before it asserts. */
static int can_bind(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)port);
    int rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
    close(fd);
    return rc == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Config fixtures                                                     */
/* ------------------------------------------------------------------ */

/* A minimal but complete server config. RedirAddr is loopback so nothing
 * here depends on external DNS; PrivateKey is a fixed, throwaway 32-byte
 * value. bind_json is spliced in verbatim so a case can pass "[]", a list,
 * or omit the key entirely. */
static void make_config(char *out, size_t cap, const char *bind_json) {
    snprintf(out, cap,
             "{"
             "\"ProxyBook\":{\"shadowsocks\":[\"tcp\",\"127.0.0.1:8388\"]},"
             "%s"
             "\"RedirAddr\":\"127.0.0.1:1\","
             "\"PrivateKey\":\"SN6EG6BhjnLLpGCMqrLzZuSNmEWXOJgEnqN0uaPihgs=\""
             "}",
             bind_json);
}

static int write_temp(const char *path, const char *content) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    fputs(content, f);
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Case 1: -h and -v return before anything else happens                */
/* ------------------------------------------------------------------ */

/* Both are given a -c that could not possibly load. Go returns before
 * ParseConfig for both, and so must this: if either flag were handled
 * after the config load, the missing file would turn exit 0 into exit 2,
 * and the case fails. That is what makes this a test of ORDER and not
 * merely of "the flag prints something". */
static void test_version_and_help_exit_before_config(void) {
    char *const vargv[] = {(char *)"ck-server", (char *)"-c",
                           (char *)"/nonexistent/definitely-not-here.json", (char *)"-v", NULL};
    child_t c;
    ASSERT_EQ_INT(0, run_to_exit(&c, vargv, NULL, EXIT_MS));
    ASSERT_TRUE(strstr(c.out, "ck-server") != NULL);
    /* The version really is the library's, not a literal. */
    ASSERT_TRUE(strstr(c.out, "0.1.0-dev") != NULL);

    char *const hargv[] = {(char *)"ck-server", (char *)"-c",
                           (char *)"/nonexistent/definitely-not-here.json", (char *)"-h", NULL};
    child_t h;
    ASSERT_EQ_INT(0, run_to_exit(&h, hargv, NULL, EXIT_MS));
    /* Every flag Go's server documents is named in the usage text. */
    ASSERT_TRUE(strstr(h.out, "-c") != NULL);
    ASSERT_TRUE(strstr(h.out, "-verbosity") != NULL);
    ASSERT_TRUE(strstr(h.out, "-uid") != NULL);
    ASSERT_TRUE(strstr(h.out, "-key") != NULL);
}

/* ------------------------------------------------------------------ */
/* Case 2: -u/-uid and -k/-key                                          */
/* ------------------------------------------------------------------ */

/* Copies the longest run of base64 characters starting at or after the
 * n-th such run in s. Used to lift the value out of the human forms,
 * which wrap it in ANSI colour and English. */
static int nth_b64_token(const char *s, int n, char *out, size_t cap) {
    const char *p = s;
    int seen = 0;
    while (*p != '\0') {
        if (strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", *p) !=
            NULL) {
            const char *start = p;
            while (*p != '\0' &&
                   strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
                          *p) != NULL) {
                p++;
            }
            size_t len = (size_t)(p - start);
            /* Only runs that could be a padded base64 quantum qualify, so
             * the English around the value ("Your", "UID", "is") does not
             * get mistaken for one. */
            if (len >= 8 && len % 4 == 0) {
                if (seen == n) {
                    if (len + 1 > cap) {
                        return -1;
                    }
                    memcpy(out, start, len);
                    out[len] = '\0';
                    return 0;
                }
                seen++;
            }
        } else {
            p++;
        }
    }
    return -1;
}

static void assert_valid_uid(const char *b64) {
    uint8_t raw[64];
    size_t len = 0;
    ASSERT_EQ_INT(0, cloak_base64_decode(b64, raw, sizeof(raw), &len));
    /* Pinned on both sides: not "at least 16", not "at most 16". */
    ASSERT_EQ_INT(16, (long long)len);
}

/* The public key is recomputed from the private one by scalar-multiplying
 * the curve's base point (u = 9, RFC 7748), which is exactly what X25519
 * public-key derivation is. A generator that returned two unrelated random
 * blobs -- non-empty, different, correctly sized -- fails right here. */
static void assert_pair_round_trips(const char *pub_b64, const char *priv_b64) {
    uint8_t pub[CLOAK_X25519_KEY_LEN];
    uint8_t priv[CLOAK_X25519_KEY_LEN];
    size_t pub_len = 0;
    size_t priv_len = 0;
    ASSERT_EQ_INT(0, cloak_base64_decode(pub_b64, pub, sizeof(pub), &pub_len));
    ASSERT_EQ_INT(0, cloak_base64_decode(priv_b64, priv, sizeof(priv), &priv_len));
    ASSERT_EQ_INT(CLOAK_X25519_KEY_LEN, (long long)pub_len);
    ASSERT_EQ_INT(CLOAK_X25519_KEY_LEN, (long long)priv_len);

    uint8_t basepoint[CLOAK_X25519_KEY_LEN];
    memset(basepoint, 0, sizeof(basepoint));
    basepoint[0] = 9;
    uint8_t derived[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_shared_secret(priv, basepoint, derived));
    ASSERT_MEM_EQ(derived, pub, CLOAK_X25519_KEY_LEN);
}

/* Copies at most cap-1 bytes and strips trailing whitespace. A plain
 * snprintf("%s") here would be a truncating copy out of a 64 KiB capture
 * buffer, which -Wformat-truncation rightly objects to. */
static void copy_trimmed(char *dst, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
    while (n > 0 && (dst[n - 1] == '\n' || dst[n - 1] == '\r' || dst[n - 1] == ' ')) {
        dst[--n] = '\0';
    }
}

/* ONE invocation of `flag`, with its base64 tokens lifted out: t0 always,
 * t1 when the caller asks for it (the key pair prints two). Both come from
 * the SAME run, which is what makes a pair comparison meaningful. */
static void generate(const char *flag, char t0[128], char t1[128], char full[512]) {
    char *const argv[] = {(char *)"ck-server", (char *)flag, NULL};
    child_t c;
    ASSERT_EQ_INT(0, run_to_exit(&c, argv, NULL, EXIT_MS));
    ASSERT_EQ_INT(0, nth_b64_token(c.out, 0, t0, 128));
    if (t1 != NULL) {
        ASSERT_EQ_INT(0, nth_b64_token(c.out, 1, t1, 128));
    }
    if (full != NULL) {
        copy_trimmed(full, 512, c.out);
    }
}

static void test_uid_and_key_generation(void) {
    /* -u: the whole of stdout is the value, ready for $(...). */
    char *const uargv[] = {(char *)"ck-server", (char *)"-u", NULL};
    child_t u1;
    ASSERT_EQ_INT(0, run_to_exit(&u1, uargv, NULL, EXIT_MS));
    char uid1[128];
    copy_trimmed(uid1, sizeof(uid1), u1.out);
    assert_valid_uid(uid1);

    /* Fresh material every time -- a constant would pass every other
     * assertion in this case. */
    child_t u2;
    ASSERT_EQ_INT(0, run_to_exit(&u2, uargv, NULL, EXIT_MS));
    char uid2[128];
    copy_trimmed(uid2, sizeof(uid2), u2.out);
    assert_valid_uid(uid2);
    ASSERT_TRUE(strcmp(uid1, uid2) != 0);

    /* -uid: the same value, dressed for a human.
     *
     * THE DRESS IS ASSERTED EXACTLY, not by substring. Rebuilding the whole
     * line from the token this run printed and comparing it to the whole of
     * stdout is the strongest available form of "the two flags are one
     * value in two dresses": it says the human output is the script output
     * plus a fixed, known decoration and NOTHING ELSE. (Neither this port
     * nor Go can emit both dresses from one invocation -- each calls its
     * generator once and then picks a dress; see Go's ck-server.go, `uid :=
     * generateUID()` followed by an if/else on the flag. So the value the
     * two dresses share cannot be observed across a single process, and
     * freshness below is what closes the remaining gap.) */
    char uid_human[128];
    char uid_human_line[512];
    generate("-uid", uid_human, NULL, uid_human_line);
    assert_valid_uid(uid_human);
    char expect_line[512];
    snprintf(expect_line, sizeof(expect_line), "\x1B[35mYour UID is:\x1B[0m %s", uid_human);
    ASSERT_EQ_INT(0, strcmp(expect_line, uid_human_line));

    /* AND IT IS FRESH. Without this, -uid printing a constant, valid,
     * 16-byte UID unrelated to anything the program generated passes every
     * other assertion above. */
    char uid_human2[128];
    generate("-uid", uid_human2, NULL, NULL);
    assert_valid_uid(uid_human2);
    ASSERT_TRUE(strcmp(uid_human, uid_human2) != 0);

    /* -k: "<public>,<private>" on one line. */
    char *const kargv[] = {(char *)"ck-server", (char *)"-k", NULL};
    child_t k;
    ASSERT_EQ_INT(0, run_to_exit(&k, kargv, NULL, EXIT_MS));
    char line[256];
    copy_trimmed(line, sizeof(line), k.out);
    char *comma = strchr(line, ',');
    ASSERT_TRUE(comma != NULL);
    char pub_s[128] = {0};
    char priv_s[128] = {0};
    if (comma != NULL) {
        *comma = '\0';
        assert_pair_round_trips(line, comma + 1);
        copy_trimmed(pub_s, sizeof(pub_s), line);
        copy_trimmed(priv_s, sizeof(priv_s), comma + 1);
    }

    /* THE KEY PAIR IS FRESH TOO, and this is the assertion this case most
     * needed. assert_pair_round_trips proves the public key belongs to the
     * private one -- but a generator that returned one HARDCODED, VALID,
     * self-consistent X25519 pair on every invocation satisfies it, and
     * every other assertion in this file, forever. For a program whose
     * entire security rests on that private key being unique to the
     * operator, that is the worst failure available and the cheapest to
     * ship by accident. Two runs, both halves, must differ. */
    char pub_s2[128];
    char priv_s2[128];
    generate("-k", pub_s2, priv_s2, NULL);
    assert_pair_round_trips(pub_s2, priv_s2);
    ASSERT_TRUE(strcmp(pub_s, pub_s2) != 0);
    ASSERT_TRUE(strcmp(priv_s, priv_s2) != 0);

    /* -key: the same pair, labelled. Both halves round-trip together, so
     * the human path is verified in value and not merely in shape -- and
     * the dress, as with -uid, is rebuilt and compared whole. */
    char *const keyargv[] = {(char *)"ck-server", (char *)"-key", NULL};
    child_t kh;
    ASSERT_EQ_INT(0, run_to_exit(&kh, keyargv, NULL, EXIT_MS));
    ASSERT_TRUE(strstr(kh.out, "PUBLIC key") != NULL);
    ASSERT_TRUE(strstr(kh.out, "PRIVATE key") != NULL);
    char pub_h[128];
    char priv_h[128];
    ASSERT_EQ_INT(0, nth_b64_token(kh.out, 0, pub_h, sizeof(pub_h)));
    ASSERT_EQ_INT(0, nth_b64_token(kh.out, 1, priv_h, sizeof(priv_h)));
    assert_pair_round_trips(pub_h, priv_h);
    char key_line[512];
    copy_trimmed(key_line, sizeof(key_line), kh.out);
    char expect_key[512];
    snprintf(expect_key, sizeof(expect_key),
             "\x1B[36mYour PUBLIC key is:\x1B[0m %s\n"
             "\x1B[33mYour PRIVATE key is (keep it secret):\x1B[0m %s",
             pub_h, priv_h);
    ASSERT_EQ_INT(0, strcmp(expect_key, key_line));

    /* And fresh on the human path as well. */
    char pub_h2[128];
    char priv_h2[128];
    generate("-key", pub_h2, priv_h2, NULL);
    assert_pair_round_trips(pub_h2, priv_h2);
    ASSERT_TRUE(strcmp(pub_h, pub_h2) != 0);
    ASSERT_TRUE(strcmp(priv_h, priv_h2) != 0);
}

/* ------------------------------------------------------------------ */
/* Case 3: a bad config path                                            */
/* ------------------------------------------------------------------ */

static void test_missing_config_names_the_file(void) {
    char *const argv[] = {(char *)"ck-server", (char *)"-c",
                          (char *)"/nonexistent/ck-server-test.json", NULL};
    child_t c;
    ASSERT_EQ_INT(2, run_to_exit(&c, argv, NULL, EXIT_MS));
    ASSERT_TRUE(strstr(c.out, "/nonexistent/ck-server-test.json") != NULL);
    /* And it says why, not just that. */
    ASSERT_TRUE(strstr(c.out, "No such file") != NULL);
}

/* ------------------------------------------------------------------ */
/* Cases 4 and 6: inline JSON, then SIGTERM                             */
/* ------------------------------------------------------------------ */

/* D3: Go's server.ParseConfig unmarshals the empty buffer it failed to
 * read rather than the string it was given, so this exact invocation fails
 * under Go Cloak with "unexpected end of JSON input". Here it starts a
 * server -- and the assertion is not that the log says so but that the
 * port the inline config names ACCEPTS A CONNECTION. */
static void test_inline_json_starts_and_sigterm_stops(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);

    char bind_json[128];
    snprintf(bind_json, sizeof(bind_json), "\"BindAddr\":[\"127.0.0.1:%d\"],", port);
    char cfg[1024];
    make_config(cfg, sizeof(cfg), bind_json);

    char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, argv, NULL));
    ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));

    /* THE DESCRIPTOR CENSUS (brief case 6's "no leaked descriptors", which
     * LeakSanitizer does not and cannot provide -- it tracks memory, as
     * libcloak-client/tests/test_client_stack.c says next to its own
     * count_open_fds). Six connections accepted and then dropped must
     * leave the child's descriptor inventory exactly where it started;
     * this also serves as case 4's D3 assertion, since these connections
     * are to the port the INLINE config named.
     *
     * THE TOTAL IS ABSOLUTE, not a delta. A leak on the startup path leaks
     * once, so a before/after comparison around a connection cannot see it
     * -- and a descriptor opened and forgotten between the config load and
     * cloak_reactor_run is exactly the leak this program could plausibly
     * have (read_whole_file's fclose, a socket a constructor abandoned).
     * The classified counts say WHICH kind appeared.
     *
     * This child has no descriptor limit, deliberately: a leak can only be
     * counted in a child that had room to make it.
     *
     * IT IS PINNED ON BOTH SIDES OF A LOAD, AND THE BUSY SIDE COMES FIRST,
     * which is what makes it a measurement rather than a race. A TCP
     * connect completes against the listen backlog whether or not the
     * server ever calls accept, so connecting proves nothing about the
     * child's progress -- but SIX ACCEPTED SOCKETS APPEARING IN ITS
     * DESCRIPTOR TABLE prove the reactor is running, which puts the child
     * unambiguously past every statement a startup leak could hide in.
     * Only then is the idle inventory meaningful. Both sides are absolute:
     * 12 descriptors with six connections held open, 6 once they are
     * dropped. A leak fails both; a retained accepted socket fails the
     * second; a server that never accepts fails the first. */
    int held[6];
    for (size_t i = 0; i < sizeof(held) / sizeof(held[0]); i++) {
        held[i] = connect_keep(port);
        ASSERT_TRUE(held[i] >= 0);
    }
    fd_census_t busy;
    busy.total = CK_FD_EXPECTED(1) + 6;
    busy.sockets = 1 + 6;
    busy.eventpolls = 1;
    busy.signalfds = 1;
    fd_census_t got;
    ASSERT_EQ_INT(0, child_fd_settle(c.pid, &busy, 3000, &got));
    ASSERT_EQ_INT(busy.total, got.total);
    ASSERT_EQ_INT(busy.sockets, got.sockets);

    for (size_t i = 0; i < sizeof(held) / sizeof(held[0]); i++) {
        if (held[i] >= 0) {
            close(held[i]);
        }
    }
    fd_census_t idle;
    idle.total = CK_FD_EXPECTED(1);
    idle.sockets = 1;
    idle.eventpolls = 1;
    idle.signalfds = 1;
    ASSERT_EQ_INT(0, child_fd_settle(c.pid, &idle, 3000, &got));
    ASSERT_EQ_INT(idle.total, got.total);
    ASSERT_EQ_INT(idle.sockets, got.sockets);
    ASSERT_EQ_INT(idle.eventpolls, got.eventpolls);
    ASSERT_EQ_INT(idle.signalfds, got.signalfds);

    /* Case 6: SIGTERM, cleanly, inside the bound. */
    ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
    ASSERT_TRUE(strstr(c.out, "received signal 15") != NULL);
    ASSERT_TRUE(strstr(c.out, "ck-server stopped") != NULL);
}

/* SIGINT takes the same path, and a run under the ASan/LSan build makes
 * this the leak check for the whole startup/shutdown path: the child's own
 * exit status turns non-zero if anything it allocated is still live at
 * exit, and that status is what this asserts. */
static void test_sigint_shuts_down_cleanly(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);
    char bind_json[128];
    snprintf(bind_json, sizeof(bind_json), "\"BindAddr\":[\"127.0.0.1:%d\"],", port);
    char cfg[1024];
    make_config(cfg, sizeof(cfg), bind_json);

    char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, argv, NULL));
    ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));
    ASSERT_EQ_INT(0, signal_and_reap(&c, SIGINT));
    ASSERT_TRUE(strstr(c.out, "received signal 2") != NULL);
}

/* A file on disk still works -- D3 added a path, it did not replace one. */
static void test_config_from_a_file(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);
    char bind_json[128];
    snprintf(bind_json, sizeof(bind_json), "\"BindAddr\":[\"127.0.0.1:%d\"],", port);
    char cfg[1024];
    make_config(cfg, sizeof(cfg), bind_json);

    const char *path = "ck_server_test_config.json";
    ASSERT_EQ_INT(0, write_temp(path, cfg));

    char *const argv[] = {(char *)"ck-server", (char *)"-c", (char *)path, NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, argv, NULL));
    ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));
    ASSERT_EQ_INT(0, can_connect(port));
    ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
    remove(path);
}

/* ------------------------------------------------------------------ */
/* Case 5: no BindAddr -> :443 and :80                                  */
/* ------------------------------------------------------------------ */

/* WHICH OUTCOME THIS ENVIRONMENT PRODUCES. Ports 443 and 80 are
 * privileged, so whether ck-server can bind them is a property of the
 * process, not of ck-server. This case therefore MEASURES that property
 * first -- by trying the bind itself, from this process, which is subject
 * to exactly the same rules -- and then asserts ONE specific outcome:
 *
 *   binding is permitted  -> the server starts, and BOTH 443 and 80
 *                            accept a connection. (This is what the
 *                            project's Docker dev image produces: it runs
 *                            as uid 0 and has
 *                            net.ipv4.ip_unprivileged_port_start = 0.)
 *   binding is refused    -> the server exits 3, the bind-failure code,
 *                            and says which address it could not open.
 *
 * It is not a case that shrugs and accepts either: each branch pins a
 * different, complete outcome, and the run prints which branch it took. */
static void test_default_bind_addresses(void) {
    char cfg[1024];
    make_config(cfg, sizeof(cfg), "");

    int privileged = (can_bind(443) == 0 && can_bind(80) == 0);
    printf("case 5: privileged ports are %s in this environment\n",
           privileged ? "bindable" : "refused");

    char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, argv, NULL));

    if (privileged) {
        ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));
        /* The defaults really are :443 and :80, in that order, and they
         * really are listening. THE ORDER IS ASSERTED, not just described:
         * both lines are printed before anything binds, so a swapped
         * default changes which port an unprivileged operator sees refused
         * first and which listener index maps to which port in the
         * "listening on" lines -- and it is Go's order (":443" then ":80")
         * that this port claims to keep. */
        const char *at443 = strstr(c.out, "bind address: :443");
        const char *at80 = strstr(c.out, "bind address: :80");
        ASSERT_TRUE(at443 != NULL);
        ASSERT_TRUE(at80 != NULL);
        ASSERT_TRUE(at443 != NULL && at80 != NULL && at443 < at80);
        ASSERT_EQ_INT(2, (long long)count_occurrences(c.out, "bind address: "));
        ASSERT_EQ_INT(0, can_connect(443));
        ASSERT_EQ_INT(0, can_connect(80));
        ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
    } else {
        ASSERT_EQ_INT(3, child_reap(&c, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, ":443") != NULL);
    }
}

/* ------------------------------------------------------------------ */
/* Case 7: plugin mode (D5)                                             */
/* ------------------------------------------------------------------ */

/* Every sub-case reads the EFFECTIVE configuration back out of the
 * server's own log, which ck-server prints from the PARSED
 * cloak_server_config_t -- the struct the server actually reads -- and not
 * from the environment variables that produced it. A translation that
 * dropped on the floor between the environment and the struct would show
 * up here; a log line printed straight from getenv() would not have been
 * a test of anything. */

static void plugin_env(const char *opts, const char *remote_host, const char *remote_port,
                       char slots[5][512], const char *env[6]) {
    snprintf(slots[0], 512, "SS_LOCAL_HOST=127.0.0.1");
    snprintf(slots[1], 512, "SS_LOCAL_PORT=8388");
    snprintf(slots[2], 512, "SS_REMOTE_HOST=%s", remote_host);
    snprintf(slots[3], 512, "SS_REMOTE_PORT=%s", remote_port);
    snprintf(slots[4], 512, "SS_PLUGIN_OPTIONS=%s", opts);
    for (int i = 0; i < 5; i++) {
        env[i] = slots[i];
    }
    env[5] = NULL;
}

/* SS_PLUGIN_OPTIONS carries JSON for the server side, not the ssv the
 * client's SS_PLUGIN_OPTIONS carries -- Go's server.ParseConfig only ever
 * calls json.Unmarshal, whatever its comment says. */
static void test_plugin_injects_proxy_and_binds_ss_address(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);

    char cfg[1024];
    make_config(cfg, sizeof(cfg), "");
    char slots[5][512];
    const char *env[6];
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    plugin_env(cfg, "127.0.0.1", portbuf, slots, env);

    char *const argv[] = {(char *)"ck-server", NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, argv, env));
    ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));

    /* ProxyBook gained the shadowsocks entry, pointing at SS_LOCAL_*. The
     * fixture config's own shadowsocks entry named port 8388 on purpose:
     * SS_LOCAL_PORT is also 8388, so this alone would not prove the
     * injection -- what proves it is that it is there at all when the
     * bind address came from SS_REMOTE_*, and sub-case D below overwrites
     * a DIFFERENT value to pin the overwrite. */
    ASSERT_TRUE(strstr(c.out, "proxy book: shadowsocks -> tcp 127.0.0.1:8388") != NULL);

    /* The SS address was appended and is listening. */
    char expect[128];
    snprintf(expect, sizeof(expect), "bind address: 127.0.0.1:%d", port);
    ASSERT_TRUE(strstr(c.out, expect) != NULL);
    ASSERT_EQ_INT(1, (long long)count_occurrences(c.out, "bind address: "));
    ASSERT_EQ_INT(0, can_connect(port));

    ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
}

/* Go's "host|host" form means "both families". R3: an existing
 * "0.0.0.0:P" is UPGRADED in place to ":P" and NOT also appended. Go's own
 * code appends anyway and ends up binding ":P" twice; this asserts the
 * single entry, and asserts the de-duplication WARN is ABSENT, so the
 * result comes from the merge rule rather than from the safety net that
 * would have hidden a broken rule. */
static void test_plugin_v4_and_v6_upgrades_existing_entry(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);

    char bind_json[128];
    snprintf(bind_json, sizeof(bind_json), "\"BindAddr\":[\"0.0.0.0:%d\"],", port);
    char cfg[1024];
    make_config(cfg, sizeof(cfg), bind_json);
    char slots[5][512];
    const char *env[6];
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    plugin_env(cfg, "::|0.0.0.0", portbuf, slots, env);

    char *const argv[] = {(char *)"ck-server", NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, argv, env));
    ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));

    char expect[128];
    snprintf(expect, sizeof(expect), "bind address: :%d", port);
    ASSERT_TRUE(strstr(c.out, expect) != NULL);
    ASSERT_EQ_INT(1, (long long)count_occurrences(c.out, "bind address: "));
    ASSERT_TRUE(strstr(c.out, "dropping duplicate bind address") == NULL);
    ASSERT_EQ_INT(0, can_connect(port));

    ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
}

/* R2: the config already listens on every interface for that port, so the
 * SS address is not appended. Again with the WARN asserted absent. */
static void test_plugin_wildcard_entry_suppresses_append(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);

    char bind_json[128];
    snprintf(bind_json, sizeof(bind_json), "\"BindAddr\":[\":%d\"],", port);
    char cfg[1024];
    make_config(cfg, sizeof(cfg), bind_json);
    char slots[5][512];
    const char *env[6];
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    plugin_env(cfg, "127.0.0.1", portbuf, slots, env);

    char *const argv[] = {(char *)"ck-server", NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, argv, env));
    ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));

    char expect[128];
    snprintf(expect, sizeof(expect), "bind address: :%d", port);
    ASSERT_TRUE(strstr(c.out, expect) != NULL);
    ASSERT_EQ_INT(1, (long long)count_occurrences(c.out, "bind address: "));
    ASSERT_TRUE(strstr(c.out, "dropping duplicate bind address") == NULL);

    ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
}

/* Both families listed separately, SS asking for both: R3 upgrades each of
 * them to ":P" and the safety net then drops the duplicate -- the one
 * case where the WARN is SUPPOSED to appear, asserted present so the two
 * mechanisms cannot be confused with one another. And the injected
 * ProxyBook entry overwrites a pre-existing shadowsocks entry that named a
 * different address, which pins the overwrite rather than the insert. */
static void test_plugin_dedupes_both_families_and_overwrites_proxy(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);

    char bind_json[192];
    snprintf(bind_json, sizeof(bind_json), "\"BindAddr\":[\"0.0.0.0:%d\",\"[::]:%d\"],", port,
             port);
    char cfg[1024];
    snprintf(cfg, sizeof(cfg),
             "{"
             "\"ProxyBook\":{\"shadowsocks\":[\"tcp\",\"10.9.9.9:9999\"]},"
             "%s"
             "\"RedirAddr\":\"127.0.0.1:1\","
             "\"PrivateKey\":\"SN6EG6BhjnLLpGCMqrLzZuSNmEWXOJgEnqN0uaPihgs=\""
             "}",
             bind_json);

    char slots[5][512];
    const char *env[6];
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    plugin_env(cfg, "::|0.0.0.0", portbuf, slots, env);

    char *const argv[] = {(char *)"ck-server", NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, argv, env));
    ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));

    char expect[128];
    snprintf(expect, sizeof(expect), "bind address: :%d", port);
    ASSERT_TRUE(strstr(c.out, expect) != NULL);
    ASSERT_EQ_INT(1, (long long)count_occurrences(c.out, "bind address: "));
    ASSERT_TRUE(strstr(c.out, "dropping duplicate bind address") != NULL);

    /* The config's own entry is gone; SS_LOCAL_* replaced it. */
    ASSERT_TRUE(strstr(c.out, "proxy book: shadowsocks -> tcp 127.0.0.1:8388") != NULL);
    ASSERT_TRUE(strstr(c.out, "10.9.9.9:9999") == NULL);

    ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
}

/* Plugin mode with no SS_REMOTE_*: Go hands ":" to ResolveTCPAddr and
 * quietly ends up on port 0; this reports it. */
static void test_plugin_without_remote_is_a_config_error(void) {
    char cfg[1024];
    make_config(cfg, sizeof(cfg), "");
    char slots[5][512];
    const char *env[6];
    plugin_env(cfg, "", "", slots, env);

    char *const argv[] = {(char *)"ck-server", NULL};
    child_t c;
    ASSERT_EQ_INT(2, run_to_exit(&c, argv, env, EXIT_MS));
    ASSERT_TRUE(strstr(c.out, "SS_REMOTE_HOST") != NULL);
}

/* R1: the config ALREADY lists exactly the address SS asked for, so the
 * SS address is not appended. The WARN is asserted absent, which is what
 * separates "R1 suppressed the append" from "R1 did nothing and
 * bind_list_dedupe cleaned up after it" -- the two produce the same bind
 * list and only the WARN tells them apart. */
static void test_plugin_identical_entry_suppresses_append(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);

    char bind_json[128];
    snprintf(bind_json, sizeof(bind_json), "\"BindAddr\":[\"127.0.0.1:%d\"],", port);
    char cfg[1024];
    make_config(cfg, sizeof(cfg), bind_json);
    char slots[5][512];
    const char *env[6];
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    plugin_env(cfg, "127.0.0.1", portbuf, slots, env);

    char *const argv[] = {(char *)"ck-server", NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, argv, env));
    ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));

    char expect[128];
    snprintf(expect, sizeof(expect), "bind address: 127.0.0.1:%d", port);
    ASSERT_TRUE(strstr(c.out, expect) != NULL);
    ASSERT_EQ_INT(1, (long long)count_occurrences(c.out, "bind address: "));
    ASSERT_TRUE(strstr(c.out, "dropping duplicate bind address") == NULL);
    ASSERT_EQ_INT(0, can_connect(port));

    ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
}

/* An SS_REMOTE_HOST that is a bare IPv6 literal. Go joins it with
 * net.JoinHostPort, which BRACKETS it; without the brackets the result has
 * two colons outside any bracket, which cloak_net_split_hostport rejects
 * exactly as Go's net.SplitHostPort does -- so dropping the brackets turns
 * a working plugin deployment into a startup failure. Asserted from the
 * outside as the server coming up on "[::1]:P". */
static void test_plugin_ipv6_ss_host_is_bracketed(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);

    char cfg[1024];
    make_config(cfg, sizeof(cfg), "");
    char slots[5][512];
    const char *env[6];
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    plugin_env(cfg, "::1", portbuf, slots, env);

    char *const argv[] = {(char *)"ck-server", NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, argv, env));
    ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));

    char expect[128];
    snprintf(expect, sizeof(expect), "bind address: [::1]:%d", port);
    ASSERT_TRUE(strstr(c.out, expect) != NULL);
    ASSERT_EQ_INT(1, (long long)count_occurrences(c.out, "bind address: "));

    ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
}

/* EXACTLY ONE PIPE, which is Go's len(strings.Split(h, "|")) == 2 and not
 * "contains a pipe". Two pipes is not a family pair, so the whole string
 * goes to JoinHostPort and fails to resolve -- Go log.Fatals there and
 * this reports it. Relaxing the test to `pipes >= 1` would silently turn
 * this input into the wildcard ":P", which is a DIFFERENT bind address
 * from the one SS asked for: the case that made Go write the rule.
 *
 * The other side of the bracket is cases 7B/7C, where exactly one pipe
 * DOES produce ":P". */
static void test_plugin_two_pipes_is_not_a_family_pair(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);

    char cfg[1024];
    make_config(cfg, sizeof(cfg), "");
    char slots[5][512];
    const char *env[6];
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    plugin_env(cfg, "::|0.0.0.0|127.0.0.1", portbuf, slots, env);

    char *const argv[] = {(char *)"ck-server", NULL};
    child_t c;
    ASSERT_EQ_INT(2, run_to_exit(&c, argv, env, EXIT_MS));
    ASSERT_TRUE(strstr(c.out, "unable to resolve bind address provided by SS") != NULL);
    ASSERT_TRUE(strstr(c.out, "ck-server ready") == NULL);
}

/* HALF an SS environment is not half an error. Either variable missing on
 * its own is refused with the same message, and the message is asserted
 * rather than just the code: with only the host checked, an empty
 * SS_REMOTE_PORT still fails -- but as "unable to parse bind address
 * \"127.0.0.1:\"", from three frames deeper, which is the kind of error an
 * operator cannot act on. */
static void test_plugin_one_sided_remote_env_is_refused(void) {
    char cfg[1024];
    make_config(cfg, sizeof(cfg), "");
    const char *msg = "SS_REMOTE_HOST and SS_REMOTE_PORT must both be set";

    { /* host set, port empty */
        char slots[5][512];
        const char *env[6];
        plugin_env(cfg, "127.0.0.1", "", slots, env);
        char *const argv[] = {(char *)"ck-server", NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit(&c, argv, env, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, msg) != NULL);
    }
    { /* port set, host empty */
        char slots[5][512];
        const char *env[6];
        plugin_env(cfg, "", "8443", slots, env);
        char *const argv[] = {(char *)"ck-server", NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit(&c, argv, env, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, msg) != NULL);
    }
}

/* ------------------------------------------------------------------ */
/* Case 9: BindAddr is RESOLVED, not copied                             */
/* ------------------------------------------------------------------ */

/* Go's resolveBindAddr runs every BindAddr through ResolveTCPAddr and
 * listens on the RESULT's String(). That step is what makes
 * parseSSBindAddr's comparisons meaningful -- they compare canonical forms
 * -- so if canon_addr degenerated into a verbatim copy, every merge rule
 * above would be comparing operator-typed strings and would silently stop
 * matching. Nothing in this file noticed that, and this case is why it
 * would now.
 *
 * Three inputs, each of which a verbatim copy renders differently:
 *
 *   a fully expanded IPv6 literal, whose canonical form is FIXED by RFC
 *   5952 and needs no resolver, so the expectation is a literal here;
 *
 *   a hostname, which must not survive into the bind list as a name --
 *   what it resolves to is this host's business, that it no longer says
 *   "localhost" is ck-server's;
 *
 *   a name that does not resolve at all, which is a CONFIGURATION error
 *   (exit 2) and not a bind failure (exit 3) -- and that distinction is
 *   itself only true if the resolution happens here rather than inside
 *   cloak_listener_open. */
static void test_bind_addresses_are_resolved_not_copied(void) {
    { /* [0:0:0:0:0:0:0:1] is ::1 written the long way. */
        int port = free_port();
        ASSERT_TRUE(port > 0);
        char bind_json[192];
        snprintf(bind_json, sizeof(bind_json),
                 "\"BindAddr\":[\"[0:0:0:0:0:0:0:1]:%d\"],", port);
        char cfg[1024];
        make_config(cfg, sizeof(cfg), bind_json);
        char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};
        child_t c;
        ASSERT_EQ_INT(0, child_spawn(&c, argv, NULL));
        ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));
        char expect[128];
        snprintf(expect, sizeof(expect), "bind address: [::1]:%d", port);
        ASSERT_TRUE(strstr(c.out, expect) != NULL);
        char verbatim[128];
        snprintf(verbatim, sizeof(verbatim), "bind address: [0:0:0:0:0:0:0:1]:%d", port);
        ASSERT_TRUE(strstr(c.out, verbatim) == NULL);
        ASSERT_EQ_INT(1, (long long)count_occurrences(c.out, "bind address: "));
        ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
    }
    { /* a name, resolved to an address before anything binds it */
        int port = free_port();
        ASSERT_TRUE(port > 0);
        char bind_json[128];
        snprintf(bind_json, sizeof(bind_json), "\"BindAddr\":[\"localhost:%d\"],", port);
        char cfg[1024];
        make_config(cfg, sizeof(cfg), bind_json);
        char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};
        child_t c;
        ASSERT_EQ_INT(0, child_spawn(&c, argv, NULL));
        ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));
        ASSERT_EQ_INT(1, (long long)count_occurrences(c.out, "bind address: "));
        ASSERT_TRUE(strstr(c.out, "bind address: localhost:") == NULL);
        ASSERT_TRUE(strstr(c.out, "listening on localhost:") == NULL);
        ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
    }
    { /* a name that resolves to nothing: exit 2, not exit 3 */
        char cfg[1024];
        make_config(cfg, sizeof(cfg), "\"BindAddr\":[\"no-such-host.invalid:443\"],");
        char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit(&c, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "unable to resolve bind address") != NULL);
        ASSERT_TRUE(strstr(c.out, "no-such-host.invalid:443") != NULL);
    }
}

/* ------------------------------------------------------------------ */
/* Case 10: exit 4, and the descriptor budget that reaches it           */
/* ------------------------------------------------------------------ */

/* EXIT 4 IS THE ONE AN OPERATOR CANNOT AFFORD TO HAVE WRONG, and it was
 * the one code with no test: "runtime failure" reported as success loses a
 * server silently, because a supervisor with restart-on-failure sees a
 * clean exit and stops.
 *
 * It is reached here without touching ck-server: RLIMIT_NOFILE is a
 * property of the child, ck-server's descriptor use is exact, and the
 * three limits below select which step runs out. The bracket, measured in
 * both builds:
 *
 *   4 descriptors -> the LISTENER cannot be opened      -> exit 3
 *   5 descriptors -> the SIGNALFD cannot be created     -> exit 4
 *   6 descriptors -> everything fits, the server runs   -> ready
 *
 * That is 0,1,2 + epoll + one listener + the signalfd, and it is the same
 * inventory the census below asserts. Both neighbours are pinned, so a
 * change that shifted the budget by one descriptor fails here rather than
 * quietly moving which failure an operator sees. */
static void test_runtime_exit_code_and_the_descriptor_budget(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);
    char bind_json[128];
    snprintf(bind_json, sizeof(bind_json), "\"BindAddr\":[\"127.0.0.1:%d\"],", port);
    char cfg[1024];
    make_config(cfg, sizeof(cfg), bind_json);
    char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};

    { /* one short of the signalfd: RUNTIME, and it says what broke */
        child_t c;
        ASSERT_EQ_INT(4, run_to_exit_limited(&c, argv, NULL, EXIT_MS, 5));
        ASSERT_TRUE(strstr(c.out, "unable to install the signal handler") != NULL);
        ASSERT_TRUE(strstr(c.out, "ck-server ready") == NULL);
    }
    { /* one short of the listener: BIND, not RUNTIME */
        child_t c;
        ASSERT_EQ_INT(3, run_to_exit_limited(&c, argv, NULL, EXIT_MS, 4));
        ASSERT_TRUE(strstr(c.out, "(bind address)") != NULL);
    }
    { /* Exactly enough: the server runs. Six is the same number case 4's
       * census arrives at from the other direction -- three standard
       * descriptors, the epoll, the listener and the signalfd -- so the
       * budget and the inventory are one claim seen from two sides, and a
       * change to either fails here. (Case 4 does the counting: a leaked
       * descriptor cannot be counted in a child that had no room to open
       * it.) */
        child_t c;
        ASSERT_EQ_INT(0, child_spawn_limited(&c, argv, NULL, 6));
        ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));
        ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
    }
}

/* ------------------------------------------------------------------ */
/* Case 11: the small flag properties                                   */
/* ------------------------------------------------------------------ */

/* A flag that wants a value and did not get one is a usage error, not an
 * empty string: -c "" would go on to report a CONFIGURATION error (exit 2)
 * for a file nobody named, which sends an operator looking for a file
 * instead of at their command line. Documented as exit 1 in main.c's
 * header and untested until now. -c stands for both value flags: -c and
 * -verbosity reach the same branch of parse_args. */
static void test_a_flag_missing_its_value_is_a_usage_error(void) {
    char *const argv[] = {(char *)"ck-server", (char *)"-c", NULL};
    child_t c;
    ASSERT_EQ_INT(1, run_to_exit(&c, argv, NULL, EXIT_MS));
    ASSERT_TRUE(strstr(c.out, "flag needs an argument: -c") != NULL);
    ASSERT_TRUE(strstr(c.out, "Usage of ck-server") != NULL);
}

/* -verbosity's EFFECT, not its acceptance. The level is asserted from both
 * sides of the same invocation: at "error" the INFO lines are gone and the
 * ERROR line remains; at "debug" the INFO line is back. A
 * cloak_log_set_level that did nothing at all would pass an "is this level
 * accepted" test and fail this one, because the default level is info. */
static void test_verbosity_changes_what_is_logged(void) {
    const char *missing = "/nonexistent/ck-server-verbosity.json";
    {
        char *const argv[] = {(char *)"ck-server", (char *)"-verbosity", (char *)"error",
                              (char *)"-c", (char *)missing, NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit(&c, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "configuration error") != NULL);
        ASSERT_TRUE(strstr(c.out, "starting standalone mode") == NULL);
        ASSERT_TRUE(strstr(c.out, "INFO") == NULL);
    }
    {
        char *const argv[] = {(char *)"ck-server", (char *)"-verbosity", (char *)"debug",
                              (char *)"-c", (char *)missing, NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit(&c, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "configuration error") != NULL);
        ASSERT_TRUE(strstr(c.out, "starting standalone mode") != NULL);
    }
}

/* D3 IS AN ORDER, NOT A CHOICE: -c is a PATH first, and only the value
 * itself if no such file can be read. The two are distinguishable because
 * a bare integer is both a legal filename and a legal JSON document: with
 * the file tried first this starts a server, with the literal tried first
 * it parses "1234567" as a JSON number and dies on "config must be a JSON
 * object". An operator whose config file is named after a ticket number
 * gets the file. */
static void test_a_readable_file_beats_the_inline_reading(void) {
    int port = free_port();
    ASSERT_TRUE(port > 0);
    char bind_json[128];
    snprintf(bind_json, sizeof(bind_json), "\"BindAddr\":[\"127.0.0.1:%d\"],", port);
    char cfg[1024];
    make_config(cfg, sizeof(cfg), bind_json);

    const char *path = "1234567";
    ASSERT_EQ_INT(0, write_temp(path, cfg));

    char *const argv[] = {(char *)"ck-server", (char *)"-c", (char *)path, NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, argv, NULL));
    ASSERT_EQ_INT(0, child_wait_for(&c, "ck-server ready", BOOT_MS));
    ASSERT_TRUE(strstr(c.out, "config must be a JSON object") == NULL);
    ASSERT_EQ_INT(0, can_connect(port));
    ASSERT_EQ_INT(0, signal_and_reap(&c, SIGTERM));
    remove(path);
}

/* ------------------------------------------------------------------ */
/* Case 8: the exit-code contract                                       */
/* ------------------------------------------------------------------ */

/* Four distinct failures, four distinct codes. This is the case that
 * would fail if exit_code_for_stack_err collapsed back to Go's single
 * exit 1, which is the whole point of B3. */
static void test_exit_codes_are_distinct(void) {
    /* 1: usage. An unknown flag. */
    {
        char *const argv[] = {(char *)"ck-server", (char *)"-nope", NULL};
        child_t c;
        ASSERT_EQ_INT(1, run_to_exit(&c, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "Usage of ck-server") != NULL);
    }
    /* 1: usage. -d is recognised and refused (D6), not ignored. */
    {
        char *const argv[] = {(char *)"ck-server", (char *)"-d", (char *)"127.0.0.1:6060",
                              NULL};
        child_t c;
        ASSERT_EQ_INT(1, run_to_exit(&c, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "pprof") != NULL);
    }
    /* 1: usage. An unknown verbosity level. */
    {
        char cfg[1024];
        make_config(cfg, sizeof(cfg), "\"BindAddr\":[\"127.0.0.1:0\"],");
        char *const argv[] = {(char *)"ck-server", (char *)"-verbosity", (char *)"loud",
                              (char *)"-c", cfg, NULL};
        child_t c;
        ASSERT_EQ_INT(1, run_to_exit(&c, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "loud") != NULL);
    }
    /* 2: configuration. Valid JSON, unusable server state -- RedirAddr
     * cannot be resolved, which cloak_server_stack_open reports as
     * ERR_SERVER. */
    {
        char cfg[1024];
        snprintf(cfg, sizeof(cfg),
                 "{\"BindAddr\":[\"127.0.0.1:0\"],"
                 "\"RedirAddr\":\"no-such-host.invalid:443\","
                 "\"PrivateKey\":\"SN6EG6BhjnLLpGCMqrLzZuSNmEWXOJgEnqN0uaPihgs=\"}");
        char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit(&c, argv, NULL, EXIT_MS));
        /* The TYPED edge, not just the word: "(server state)" is the
         * parenthesised cloak_server_stack_strerror name, which the
         * "bind address: ..." lines printed earlier cannot supply. */
        ASSERT_TRUE(strstr(c.out, "(server state)") != NULL);
    }
    /* 3: bind. An address that exists as a string and not as an interface.
     * 192.0.2.0/24 is TEST-NET-1 (RFC 5737) and is never assigned. */
    {
        char cfg[1024];
        make_config(cfg, sizeof(cfg), "\"BindAddr\":[\"192.0.2.1:443\"],");
        char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};
        child_t c;
        ASSERT_EQ_INT(3, run_to_exit(&c, argv, NULL, EXIT_MS));
        /* Parenthesised for the same reason: ck-server logs "bind
         * address: 192.0.2.1:443" during startup regardless, so a bare
         * substring search here would pass without the failure ever
         * being classified. */
        ASSERT_TRUE(strstr(c.out, "(bind address)") != NULL);
        ASSERT_TRUE(strstr(c.out, "192.0.2.1:443") != NULL);
    }
}

TEST_MAIN_BEGIN()
    test_version_and_help_exit_before_config();
    test_uid_and_key_generation();
    test_missing_config_names_the_file();
    test_inline_json_starts_and_sigterm_stops();
    test_sigint_shuts_down_cleanly();
    test_config_from_a_file();
    test_default_bind_addresses();
    test_plugin_injects_proxy_and_binds_ss_address();
    test_plugin_v4_and_v6_upgrades_existing_entry();
    test_plugin_wildcard_entry_suppresses_append();
    test_plugin_dedupes_both_families_and_overwrites_proxy();
    test_plugin_without_remote_is_a_config_error();
    test_plugin_identical_entry_suppresses_append();
    test_plugin_ipv6_ss_host_is_bracketed();
    test_plugin_two_pipes_is_not_a_family_pair();
    test_plugin_one_sided_remote_env_is_refused();
    test_bind_addresses_are_resolved_not_copied();
    test_runtime_exit_code_and_the_descriptor_budget();
    test_a_flag_missing_its_value_is_a_usage_error();
    test_verbosity_changes_what_is_logged();
    test_a_readable_file_beats_the_inline_reading();
    test_exit_codes_are_distinct();
    /* The number SHUTDOWN_MS is pinned against. Printed rather than
     * asserted against a second constant: it is a measurement, and the
     * bound above is chosen from it. */
    printf("worst signal-to-exit latency this run: %llu ms (bound %d ms)\n",
           (unsigned long long)shutdown_max_ms, SHUTDOWN_MS);
TEST_MAIN_END()
