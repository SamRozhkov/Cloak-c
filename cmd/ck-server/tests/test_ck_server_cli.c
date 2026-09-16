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
 *      would not. The script and human forms are checked to agree in
 *      FORMAT and validity; they cannot agree in value, because each
 *      invocation generates fresh material -- and that is itself asserted
 *      (two runs of -u differ).
 *   3. A config path that does not exist: exit 2, and the message names
 *      the path.
 *   4. Inline JSON as -c's value, which Go's server cannot do (D3).
 *   5. No BindAddr at all -> :443 and :80. SEE THAT CASE'S COMMENT for
 *      which of the two possible outcomes this environment produces and
 *      how the case decides.
 *   6. SIGTERM: exit 0, within a bound, having logged the signal.
 *   7. Plugin mode, four sub-cases, including the bind-address merge rules
 *      Go's parseSSBindAddr implements.
 *   8. A bind failure exits 3 and a configuration failure exits 2 -- the
 *      exit-code contract, pinned as a contract rather than a comment.
 *
 * EVERY WAIT IS BOUNDED BY THE CLOCK. Nothing here spins forever waiting
 * for a child that will not speak; a child that misses its deadline is a
 * failed assertion, not a hung suite. */

#include "cloak/base64.h"
#include "cloak/crypto.h"
#include "test_framework.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef CK_SERVER_PATH
#error "CK_SERVER_PATH must be defined by the build"
#endif

#define OUT_CAP  65536
#define BOOT_MS  15000
#define EXIT_MS  15000

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
 * does not ask for plugin mode cannot accidentally inherit it. */
static int child_spawn(child_t *c, char *const argv[], const char *const env[]) {
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

    /* -uid: the same value, dressed for a human. Different format (it says
     * more than the value), same kind of value. */
    char *const uidargv[] = {(char *)"ck-server", (char *)"-uid", NULL};
    child_t uh;
    ASSERT_EQ_INT(0, run_to_exit(&uh, uidargv, NULL, EXIT_MS));
    ASSERT_TRUE(strstr(uh.out, "Your UID is:") != NULL);
    char uid_human[128];
    ASSERT_EQ_INT(0, nth_b64_token(uh.out, 0, uid_human, sizeof(uid_human)));
    assert_valid_uid(uid_human);
    /* The human form carries decoration the script form does not. */
    ASSERT_TRUE(strcmp(uh.out, uid_human) != 0);

    /* -k: "<public>,<private>" on one line. */
    char *const kargv[] = {(char *)"ck-server", (char *)"-k", NULL};
    child_t k;
    ASSERT_EQ_INT(0, run_to_exit(&k, kargv, NULL, EXIT_MS));
    char line[256];
    copy_trimmed(line, sizeof(line), k.out);
    char *comma = strchr(line, ',');
    ASSERT_TRUE(comma != NULL);
    if (comma != NULL) {
        *comma = '\0';
        assert_pair_round_trips(line, comma + 1);
    }

    /* -key: the same pair, labelled. Both halves round-trip together, so
     * the human path is verified in value and not merely in shape. */
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
    ASSERT_EQ_INT(0, can_connect(port));

    /* Case 6: SIGTERM, cleanly, inside the bound. */
    kill(c.pid, SIGTERM);
    ASSERT_EQ_INT(0, child_reap(&c, EXIT_MS));
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
    kill(c.pid, SIGINT);
    ASSERT_EQ_INT(0, child_reap(&c, EXIT_MS));
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
    kill(c.pid, SIGTERM);
    ASSERT_EQ_INT(0, child_reap(&c, EXIT_MS));
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
         * really are listening. */
        ASSERT_TRUE(strstr(c.out, "bind address: :443") != NULL);
        ASSERT_TRUE(strstr(c.out, "bind address: :80") != NULL);
        ASSERT_EQ_INT(2, (long long)count_occurrences(c.out, "bind address: "));
        ASSERT_EQ_INT(0, can_connect(443));
        ASSERT_EQ_INT(0, can_connect(80));
        kill(c.pid, SIGTERM);
        ASSERT_EQ_INT(0, child_reap(&c, EXIT_MS));
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

    kill(c.pid, SIGTERM);
    ASSERT_EQ_INT(0, child_reap(&c, EXIT_MS));
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

    kill(c.pid, SIGTERM);
    ASSERT_EQ_INT(0, child_reap(&c, EXIT_MS));
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

    kill(c.pid, SIGTERM);
    ASSERT_EQ_INT(0, child_reap(&c, EXIT_MS));
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

    kill(c.pid, SIGTERM);
    ASSERT_EQ_INT(0, child_reap(&c, EXIT_MS));
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
    test_exit_codes_are_distinct();
TEST_MAIN_END()
