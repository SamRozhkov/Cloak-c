#define _POSIX_C_SOURCE 200809L

/* ck-client, driven as a subprocess -- and, in cases 5 and 7, driven
 * ALONGSIDE a real ck-server.
 *
 * THIS IS THE FIRST TEST IN THIS PROJECT WHERE TWO BINARIES TALK TO EACH
 * OTHER. Everything before it linked libraries into a harness and drove
 * the object graph by hand from inside one process, which means every
 * failure that only exists once the program is STARTED -- a signal race, a
 * teardown order, a configuration path, an argument that never reaches the
 * struct it is supposed to override -- had nowhere to show itself. So the
 * shape of this file is deliberate: nothing here is linked against
 * main.c, every case forks and execs, and the only things the test itself
 * supplies are the two things a real deployment supplies from outside --
 * the application at the near end and the upstream proxy at the far end.
 *
 * WHAT EACH CASE IS FOR, and what would have to break for it to fail:
 *
 *   1. -h and -v exit 0 and print, EVEN THOUGH the -c they were handed
 *      cannot be loaded -- the only way to show from outside that they
 *      returned before the configuration was touched.
 *   2. FLAGS OVERRIDE THE JSON, and this case fails if the precedence is
 *      REVERSED and not merely if the flags are dropped. See its own
 *      comment: both values are ones the case can see the difference
 *      between, in both directions.
 *   3. No RemoteHost anywhere: exit 2, and the message names the field.
 *   4. -u and "UDP": true are HONOURED, and what they select is asserted
 *      by the SHAPE OF THE LOCAL SOCKET -- a TCP connect to it is refused
 *      and the TCP port is still free -- in both states, so a flag that
 *      is parsed and then dropped fails this and not merely a flag that
 *      is refused. BOTH KINDS OF -c ARE COVERED: -u reaches the document
 *      through a different branch for JSON and for an ssv option string,
 *      and the ssv branch was measured to drop the flag silently with all
 *      73 tests green. The usage line is Go's own wording, verbatim.
 *   4a. The MINIMAL udp configuration -- "UDP": true with no NumConn --
 *      is refused in a message that names NumConn, because omitting
 *      NumConn is what selects the singleplex this build cannot combine
 *      with udp, and a first attempt at a feature must not fail naming a
 *      mode the user never wrote. See the case for why the alternative
 *      (defaulting NumConn) was rejected as a wire-visible divergence.
 *   4b. THE BIT ON THE WIRE: the client's own ClientHello is captured and
 *      decrypted with the SERVER'S decrypter, and its unordered flag is
 *      asserted 1 with -u and 0 without. Everything in case 4 is about a
 *      socket this client opened for itself; only this says what it told
 *      the server, which is the half a Go server would act on.
 *   5. END TO END THROUGH BOTH BINARIES: an application socket into
 *      ck-client's local port, a real ck-client, a real ck-server, a fake
 *      upstream behind it, 256 KiB compared byte for byte in both
 *      directions. See that case's comment for why the upstream does not
 *      echo and why the payload is that size.
 *   6. SIGTERM shuts down cleanly: exit 0, the shutdown line logged, and
 *      NO DESCRIPTOR LEFT BEHIND -- counted from /proc/<pid>/fd across a
 *      batch of local connections, because LeakSanitizer does not track
 *      descriptors and the ASan build therefore cannot see that leak.
 *   7. -a reaches the ADMIN API on a real ck-server: one real request,
 *      one real response, 200 with a JSON body. The ProxyBook in that
 *      case points at an echo upstream on purpose, so a client whose
 *      session was dispatched to the PROXY instead of the admin API gets
 *      its own request text back and fails visibly rather than hanging.
 *
 * EVERY WAIT IS BOUNDED BY THE CLOCK, never by an iteration count: a
 * child that misses its deadline is a failed assertion, not a hung suite,
 * and a loop of N turns is not a bound on time when every turn can return
 * immediately. */

#include "cloak/base64.h"
#include "cloak/clienthello_parse.h"
#include "cloak/config.h"
#include "cloak/crypto.h"
#include "cloak/server_auth.h"
#include "cloak/usermanager.h"
#include "test_framework.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef CK_CLIENT_PATH
#error "CK_CLIENT_PATH must be defined by the build"
#endif
#ifndef CK_SERVER_PATH
#error "CK_SERVER_PATH must be defined by the build"
#endif

/* ck-client's exit code for "the endpoint could not be established", kept
 * here only so case 11 can tell a busy port from a broken default. */
#define CK_EXIT_BIND_CODE 3

#define OUT_CAP 65536
#define BOOT_MS 10000
#define EXIT_MS 10000
/* One end-to-end transfer's budget. Generous because the whole of it runs
 * through two processes, a real handshake and a real mux; a healthy run on
 * loopback finishes in well under a second, and the test prints what it
 * actually took. The whole file's waits still fit inside TIMEOUT 60,
 * because a HEALTHY run spends none of them. */
#define XFER_MS 15000

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

/* Closes everything above stderr in the freshly forked child, BEFORE exec.
 * These are the TEST process's descriptors -- ctest's, the capture pipe's,
 * the upstream listener's, whatever a future harness adds -- and every one
 * of them that survived into ck-client would consume part of the
 * descriptor budget the runtime-failure case measures, so the bracket
 * would depend on who ran the test. Closing them makes the child's
 * starting set exactly {0, 1, 2}, always. (The binary's own sanitizer
 * runtime initialises after the exec, so nothing here touches it.)
 *
 * Borrowed from cmd/ck-server/tests/test_ck_server_cli.c, where the same
 * budget argument was made first. */
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

/* env is a NULL-terminated list of "NAME=VALUE" strings set in the child
 * only, so a case that does not ask for plugin mode cannot inherit it.
 *
 * nofile, when non-zero, is an RLIMIT_NOFILE applied to the child and to
 * nothing else. It is how the runtime-failure exit code is reached from
 * outside the program: ck-client's startup descriptor use is exact and
 * ordered (epoll, then the local listener, then the signalfd), so a limit
 * chosen one descriptor short of a given step makes exactly that step
 * fail. See test_runtime_exit_code_and_the_descriptor_budget. */
static int child_spawn_limited(child_t *c, const char *path, char *const argv[],
                               const char *const env[], int nofile) {
    memset(c, 0, sizeof(*c));
    c->fd = -1;
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
        if (nofile > 0) {
            close_inherited_fds();
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
        execv(path, argv);
        _exit(127);
    }
    close(pipefd[1]);
    c->pid = pid;
    c->fd = pipefd[0];
    return 0;
}

static int child_spawn(child_t *c, const char *path, char *const argv[],
                       const char *const env[]) {
    return child_spawn_limited(c, path, argv, env, 0);
}

/* Pulls whatever is readable right now into c->out. Returns 1 on EOF. */
static int child_drain(child_t *c, int wait_ms) {
    if (c->fd < 0) {
        return 1;
    }
    struct pollfd p;
    p.fd = c->fd;
    p.events = POLLIN;
    int rc = poll(&p, 1, wait_ms);
    if (rc <= 0) {
        return 0;
    }
    if (c->out_len + 1 >= sizeof(c->out)) {
        /* Full: stop reading rather than spinning on a ready descriptor. */
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
            return strstr(c->out, marker) != NULL ? 0 : -1;
        }
    }
}

static int child_reap(child_t *c, int timeout_ms) {
    /* Already reaped -- by child_survives_signal, which reaps a child that
     * died when it should not have. Without this guard a later kill() in
     * the same case would carry a pid of 0 and signal the whole process
     * GROUP, so one failed assertion would take the test runner with it. */
    if (c->pid <= 0) {
        return -1;
    }
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        int status = 0;
        pid_t r = waitpid(c->pid, &status, WNOHANG);
        if (r == c->pid) {
            while (child_drain(c, 10) == 0 && now_ms() < deadline) {
                /* flush the tail */
            }
            if (c->fd >= 0) {
                close(c->fd);
            }
            c->fd = -1;
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        }
        if (now_ms() >= deadline) {
            kill(c->pid, SIGKILL);
            waitpid(c->pid, &status, 0);
            if (c->fd >= 0) {
                close(c->fd);
            }
            c->fd = -1;
            return -1;
        }
        child_drain(c, 20);
    }
}

/* SIGPIPE MUST NOT KILL THE CLIENT, and this is the only part of that
 * claim a test can assert directly.
 *
 * The race it protects against -- a write to a socket whose peer has gone
 * -- is not constructible on loopback, but the SIGNAL DISPOSITION is
 * directly observable: send a running client a real SIGPIPE and see
 * whether it is still there afterwards.
 *
 * For FIDELITY, not as a precaution: Go's runtime installs a SIGPIPE
 * handler that ignores the signal for every descriptor that is not
 * stdout/stderr, so a Go ck-client survives this and a C port that leaves
 * the default disposition in place is DIVERGING from Go.
 *
 * Returns 0 if the child is still running after settle_ms, and otherwise
 * the wait status it died with -- 128 + SIGPIPE == 141 for the failure
 * this exists to catch, so the assertion prints the signal number. */
static int child_survives_signal(child_t *c, int signo, int settle_ms) {
    kill(c->pid, signo);
    uint64_t deadline = now_ms() + (uint64_t)settle_ms;
    for (;;) {
        int status = 0;
        pid_t r = waitpid(c->pid, &status, WNOHANG);
        if (r == c->pid) {
            while (child_drain(c, 10) == 0) {
                /* flush whatever it managed to say */
            }
            if (c->fd >= 0) {
                close(c->fd);
            }
            c->fd = -1;
            c->pid = 0;
            if (WIFSIGNALED(status)) {
                return 128 + WTERMSIG(status);
            }
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }
        if (now_ms() >= deadline) {
            return 0;
        }
        child_drain(c, 10);
    }
}

/* SIGTERM, then reap. Used by every case that started something. */
static int child_stop(child_t *c) {
    if (c->pid <= 0) {
        return 0;
    }
    kill(c->pid, SIGTERM);
    return child_reap(c, EXIT_MS);
}

static int run_to_exit_limited(child_t *c, const char *path, char *const argv[],
                               const char *const env[], int timeout_ms, int nofile) {
    if (child_spawn_limited(c, path, argv, env, nofile) != 0) {
        return -1;
    }
    return child_reap(c, timeout_ms);
}

static int run_to_exit(child_t *c, const char *path, char *const argv[],
                       const char *const env[], int timeout_ms) {
    return run_to_exit_limited(c, path, argv, env, timeout_ms, 0);
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

static int listen_on(int *port_out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(a);
    if (getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(a.sin_port);
    return fd;
}

static int dial(int port) {
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

static int can_connect(int port) {
    int fd = dial(port);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

/* Same, at a NAMED loopback address rather than at 127.0.0.1. This is what
 * makes -i's override visible from outside: 127.0.0.0/8 is all local on
 * Linux, so a client told to listen on 127.0.0.2 and a client told to
 * listen on 127.0.0.1 both succeed -- and differ in which address answers.
 * A port number alone cannot tell the two apart. */
static int can_connect_at(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    int rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
    close(fd);
    return rc == 0 ? 0 : -1;
}

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ------------------------------------------------------------------ */
/* Descriptor census (case 6)                                           */
/* ------------------------------------------------------------------ */

/* LeakSanitizer tracks allocations and nothing else, so a client that
 * forgets a socket per local connection is invisible to the ASan build.
 * /proc/<pid>/fd is the only oracle that sees it, and it is read from
 * OUTSIDE the process under test -- so no test-only bookkeeping has to
 * exist inside ck-client for this to work. Returns -1 if /proc is not
 * there, and the caller skips rather than fails. */
static int fd_census(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/fd", (int)pid);
    DIR *d = opendir(path);
    if (d == NULL) {
        return -1;
    }
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
            continue;
        }
        n++;
    }
    closedir(d);
    return n;
}

/* ------------------------------------------------------------------ */
/* Key and UID fixtures                                                 */
/* ------------------------------------------------------------------ */

/* One throwaway X25519 private key, and the public key DERIVED FROM IT at
 * runtime rather than a second literal beside it. A hard-coded pair that
 * silently stopped matching would make every end-to-end case fail with
 * "the tunnel carried nothing", which is the least diagnosable failure
 * this file can produce. */
/* Macros rather than arrays so they can be pasted into a JSON literal at
 * compile time (make_server_config_bypass wants "\"" UID_B64 "\""). */
#define PRIV_B64 "SN6EG6BhjnLLpGCMqrLzZuSNmEWXOJgEnqN0uaPihgs="
/* Two distinct 16-byte UIDs: one ordinary, one for the admin API. */
#define UID_B64       "MTIzNDU2Nzg5MGFiY2RlZg=="   /* "1234567890abcdef" */
#define ADMIN_UID_B64 "QURNSU5hZG1pbjAxMjM0NQ==" /* "ADMINadmin012345" */

static void derive_pub_b64(char *out, size_t cap) {
    uint8_t priv[CLOAK_X25519_KEY_LEN];
    size_t priv_len = 0;
    ASSERT_EQ_INT(0, cloak_base64_decode(PRIV_B64, priv, sizeof(priv), &priv_len));
    ASSERT_EQ_INT(CLOAK_X25519_KEY_LEN, (long long)priv_len);
    uint8_t base[CLOAK_X25519_KEY_LEN];
    memset(base, 0, sizeof(base));
    base[0] = 9;
    uint8_t pub[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_shared_secret(priv, base, pub));
    ASSERT_EQ_INT(0, cloak_base64_encode(pub, sizeof(pub), out, cap));
}

/* ------------------------------------------------------------------ */
/* Config fixtures                                                      */
/* ------------------------------------------------------------------ */

/* extra is spliced in verbatim, so a case can add or replace any key.
 * bypass_json is the CONTENTS of the BypassUID array, also verbatim: every
 * case but one passes the ordinary UID, and the metering case passes ""
 * because a bypassed user is not metered at all (the dispatcher never
 * reaches the database for one) and metering is the whole of what it
 * measures. */
static void make_server_config_bypass(char *out, size_t cap, int bind_port,
                                      const char *proxy_addr, const char *bypass_json,
                                      const char *extra) {
    snprintf(out, cap,
             "{"
             "\"ProxyBook\":{\"shadowsocks\":[\"tcp\",\"%s\"]},"
             "\"BindAddr\":[\"127.0.0.1:%d\"],"
             "\"BypassUID\":[%s],"
             "\"RedirAddr\":\"127.0.0.1:1\","
             "\"PrivateKey\":\"%s\","
             "%s"
             "\"KeepAlive\":0"
             "}",
             proxy_addr, bind_port, bypass_json, PRIV_B64, extra);
}

/* (The ordinary "bypass the UID" form is pair_start_server below, which is
 * the only caller there has ever been; there is no second wrapper here
 * because an unused one is a warning, not documentation.) */

static void make_client_config(char *out, size_t cap, const char *pub_b64, const char *extra) {
    snprintf(out, cap,
             "{"
             "\"ServerName\":\"www.bing.com\","
             "\"ProxyMethod\":\"shadowsocks\","
             "\"EncryptionMethod\":\"aes-gcm\","
             "\"UID\":\"%s\","
             "\"PublicKey\":\"%s\","
             "\"NumConn\":2,"
             "%s"
             "\"BrowserSig\":\"chrome\""
             "}",
             UID_B64, pub_b64, extra);
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
/* A server + client pair, started and stopped together                 */
/* ------------------------------------------------------------------ */

typedef struct {
    child_t server;
    child_t client;
    int server_port;
    int local_port;
    int upstream_fd; /* the fake upstream's listening socket */
    int upstream_port;
    char pub_b64[64];
} pair_t;

static void pair_init(pair_t *p) {
    memset(p, 0, sizeof(*p));
    p->server.fd = -1;
    p->client.fd = -1;
    p->upstream_fd = -1;
    derive_pub_b64(p->pub_b64, sizeof(p->pub_b64));
}

/* Starts ck-server with the given extra config keys and an upstream that
 * this process owns. Returns 0 when the server logged that it is ready. */
static int pair_start_server_bypass(pair_t *p, const char *server_extra,
                                    const char *bypass_json) {
    p->upstream_fd = listen_on(&p->upstream_port);
    if (p->upstream_fd < 0) {
        return -1;
    }
    p->server_port = free_port();
    if (p->server_port <= 0) {
        return -1;
    }
    char upstream[64];
    snprintf(upstream, sizeof(upstream), "127.0.0.1:%d", p->upstream_port);
    char cfg[2048];
    make_server_config_bypass(cfg, sizeof(cfg), p->server_port, upstream, bypass_json,
                              server_extra);

    char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};
    if (child_spawn(&p->server, CK_SERVER_PATH, argv, NULL) != 0) {
        return -1;
    }
    return child_wait_for(&p->server, "ck-server ready", BOOT_MS);
}

static int pair_start_server(pair_t *p, const char *server_extra) {
    return pair_start_server_bypass(p, server_extra, "\"" UID_B64 "\"");
}

/* Starts ck-client against that server. client_extra goes into the JSON;
 * extra_argv (NULL-terminated, may be NULL) is appended to the command
 * line after -c. */
static int pair_start_client(pair_t *p, const char *client_extra, char *const extra_argv[]) {
    p->local_port = free_port();
    if (p->local_port <= 0) {
        return -1;
    }
    char extra[512];
    snprintf(extra, sizeof(extra),
             "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"%d\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"%d\",%s",
             p->server_port, p->local_port, client_extra);
    char cfg[2048];
    make_client_config(cfg, sizeof(cfg), p->pub_b64, extra);

    char *argv[16];
    size_t n = 0;
    argv[n++] = (char *)"ck-client";
    argv[n++] = (char *)"-c";
    argv[n++] = cfg;
    if (extra_argv != NULL) {
        for (size_t i = 0; extra_argv[i] != NULL && n < 15; i++) {
            argv[n++] = extra_argv[i];
        }
    }
    argv[n] = NULL;
    if (child_spawn(&p->client, CK_CLIENT_PATH, argv, NULL) != 0) {
        return -1;
    }
    return child_wait_for(&p->client, "ck-client ready", BOOT_MS);
}

static void pair_teardown(pair_t *p) {
    if (p->client.pid > 0) {
        child_stop(&p->client);
    }
    if (p->server.pid > 0) {
        child_stop(&p->server);
    }
    if (p->upstream_fd >= 0) {
        close(p->upstream_fd);
        p->upstream_fd = -1;
    }
}

/* ------------------------------------------------------------------ */
/* The exchange driver                                                  */
/* ------------------------------------------------------------------ */

/* Drives, in one clock-bounded poll loop:
 *   - writing `send_len` bytes of `send_buf` into the application socket,
 *   - accepting ONE upstream connection behind the server,
 *   - reading from it and writing a transformed reply back,
 *   - reading that reply on the application socket.
 *
 * THE UPSTREAM DOES NOT ECHO when xor_mask is non-zero: it replies with
 * every byte XORed. An echoing upstream would let this pass against a
 * client that never opened a stream and simply looped the application's
 * own bytes back at it -- and a session built on the WRONG key
 * establishes cleanly and then drops every frame silently, so "it
 * connected" proves nothing about the data path. Only transformed bytes
 * coming back do.
 *
 * Returns the number of reply bytes collected; *up_bytes gets the number
 * the upstream actually saw. */
static size_t exchange(int app_fd, int listen_fd, const uint8_t *send_buf, size_t send_len,
                       uint8_t xor_mask, uint8_t *reply_buf, size_t reply_cap,
                       size_t *up_bytes, int timeout_ms) {
    set_nonblock(app_fd);
    set_nonblock(listen_fd);

    int up_fd = -1;
    size_t sent = 0;
    size_t got = 0;
    size_t seen = 0;
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;

    while (now_ms() < deadline && got < reply_cap) {
        struct pollfd p[3];
        int n = 0;
        int app_idx = -1, lst_idx = -1, up_idx = -1;

        app_idx = n;
        p[n].fd = app_fd;
        p[n].events = POLLIN | (sent < send_len ? POLLOUT : 0);
        p[n].revents = 0;
        n++;

        if (up_fd < 0) {
            lst_idx = n;
            p[n].fd = listen_fd;
            p[n].events = POLLIN;
            p[n].revents = 0;
            n++;
        } else {
            up_idx = n;
            p[n].fd = up_fd;
            p[n].events = POLLIN;
            p[n].revents = 0;
            n++;
        }

        if (poll(p, (nfds_t)n, 20) < 0 && errno != EINTR) {
            break;
        }

        if (lst_idx >= 0 && (p[lst_idx].revents & POLLIN) != 0) {
            up_fd = accept(listen_fd, NULL, NULL);
            if (up_fd >= 0) {
                set_nonblock(up_fd);
            }
        }
        if (app_idx >= 0 && (p[app_idx].revents & POLLOUT) != 0 && sent < send_len) {
            ssize_t w = write(app_fd, send_buf + sent, send_len - sent);
            if (w > 0) {
                sent += (size_t)w;
                if (sent == send_len) {
                    /* Nothing more to say; the reply is all that is left.
                     * Not shutdown(2): the far end of this path is a
                     * proxy stream, and half-closing it would test the
                     * teardown rather than the transfer. */
                }
            } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                break;
            }
        }
        if (up_idx >= 0 && (p[up_idx].revents & POLLIN) != 0) {
            uint8_t buf[16384];
            ssize_t r = read(up_fd, buf, sizeof(buf));
            if (r > 0) {
                seen += (size_t)r;
                for (ssize_t i = 0; i < r; i++) {
                    buf[i] = (uint8_t)(buf[i] ^ xor_mask);
                }
                size_t off = 0;
                while (off < (size_t)r) {
                    ssize_t w = write(up_fd, buf + off, (size_t)r - off);
                    if (w > 0) {
                        off += (size_t)w;
                    } else if (w < 0 &&
                               (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                        struct pollfd wp = {up_fd, POLLOUT, 0};
                        if (now_ms() >= deadline) {
                            break;
                        }
                        poll(&wp, 1, 20);
                    } else {
                        break;
                    }
                }
            } else if (r == 0) {
                close(up_fd);
                up_fd = -1;
            }
        }
        if (app_idx >= 0 && (p[app_idx].revents & (POLLIN | POLLHUP)) != 0) {
            ssize_t r = read(app_fd, reply_buf + got, reply_cap - got);
            if (r > 0) {
                got += (size_t)r;
            } else if (r == 0) {
                break;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                break;
            }
        }
    }

    if (up_fd >= 0) {
        close(up_fd);
    }
    if (up_bytes != NULL) {
        *up_bytes = seen;
    }
    return got;
}

/* A deterministic, non-repeating payload. A constant-byte buffer would
 * pass against a relay that duplicated one frame over the whole
 * transfer. */
static void fill_payload(uint8_t *buf, size_t len, uint32_t seed) {
    uint32_t x = seed | 1u;
    for (size_t i = 0; i < len; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        buf[i] = (uint8_t)(x >> 16);
    }
}

/* ------------------------------------------------------------------ */
/* Case 1: -h and -v return before the configuration is touched          */
/* ------------------------------------------------------------------ */

static void test_version_and_help_exit_before_config(void) {
    char *const vargv[] = {(char *)"ck-client", (char *)"-c",
                           (char *)"/nonexistent/definitely-not-here.json", (char *)"-v", NULL};
    child_t c;
    ASSERT_EQ_INT(0, run_to_exit(&c, CK_CLIENT_PATH, vargv, NULL, EXIT_MS));
    ASSERT_TRUE(strstr(c.out, "ck-client") != NULL);
    /* The version is the library's, not a literal in main.c. */
    ASSERT_TRUE(strstr(c.out, "0.1.0-dev") != NULL);

    char *const hargv[] = {(char *)"ck-client", (char *)"-c",
                           (char *)"/nonexistent/definitely-not-here.json", (char *)"-h", NULL};
    child_t h;
    ASSERT_EQ_INT(0, run_to_exit(&h, CK_CLIENT_PATH, hargv, NULL, EXIT_MS));
    /* Every flag Go's client documents is named in the usage text. */
    ASSERT_TRUE(strstr(h.out, "-i") != NULL);
    ASSERT_TRUE(strstr(h.out, "-l") != NULL);
    ASSERT_TRUE(strstr(h.out, "-s") != NULL);
    ASSERT_TRUE(strstr(h.out, "-p") != NULL);
    ASSERT_TRUE(strstr(h.out, "-u") != NULL);
    ASSERT_TRUE(strstr(h.out, "-c") != NULL);
    ASSERT_TRUE(strstr(h.out, "-proxy") != NULL);
    ASSERT_TRUE(strstr(h.out, "-a") != NULL);
    ASSERT_TRUE(strstr(h.out, "-verbosity") != NULL);
}

/* ------------------------------------------------------------------ */
/* Case 2: the flags override the JSON, in both directions               */
/* ------------------------------------------------------------------ */

/* THE TRAP THIS CASE IS BUILT TO AVOID is a test that passes when the
 * precedence is REVERSED. Asserting "the client used 127.0.0.1" against a
 * JSON that also said 127.0.0.1 would do exactly that. So both keys carry
 * a value the case can tell apart in BOTH directions:
 *
 *   RemoteHost. The JSON says 192.0.2.1 -- TEST-NET-1 (RFC 5737), never
 *   routed, so a dial to it cannot complete. -s says 127.0.0.1, where a
 *   real ck-server is listening. If the flag wins, a session comes up. If
 *   the JSON wins, none ever does and "session up" never appears.
 *
 *   LocalPort. The JSON names a free port P1 that nothing holds; -l names
 *   a different free port P2. If the flag wins, P2 accepts a connection
 *   and P1 refuses one. If the JSON wins, exactly the opposite -- so this
 *   half fails under reversal too, and it fails in a way that says which
 *   port was actually opened.
 *
 * And the OTHER direction -- "the flag always wins, even unset" -- is
 * covered by case 5, which passes NO -s or -l at all and works entirely
 * from the JSON. Neither case can pass if the other's precedence rule is
 * the one implemented. */
static void test_flags_override_json(void) {
    pair_t p;
    pair_init(&p);
    ASSERT_EQ_INT(0, pair_start_server(&p, ""));

    int json_local = free_port();
    int flag_local = free_port();
    ASSERT_TRUE(json_local > 0 && flag_local > 0 && json_local != flag_local);

    char cfg[2048];
    char extra[512];
    snprintf(extra, sizeof(extra),
             "\"RemoteHost\":\"192.0.2.1\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"%d\",",
             json_local);
    make_client_config(cfg, sizeof(cfg), p.pub_b64, extra);

    char sport[16];
    char lport[16];
    snprintf(sport, sizeof(sport), "%d", p.server_port);
    snprintf(lport, sizeof(lport), "%d", flag_local);
    char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg,   (char *)"-s",
                          (char *)"127.0.0.1", (char *)"-p", sport, (char *)"-l",
                          lport,               NULL};
    ASSERT_EQ_INT(0, child_spawn(&p.client, CK_CLIENT_PATH, argv, NULL));
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "ck-client ready", BOOT_MS));

    /* The flag's remote is the one that was dialled: a session came up,
     * which 192.0.2.1 could never produce. */
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "session up", BOOT_MS));
    /* The flag's local port is the one that was opened, and the JSON's is
     * not. Both halves, so a reversal fails rather than half-passing. */
    ASSERT_EQ_INT(0, can_connect(flag_local));
    ASSERT_EQ_INT(-1, can_connect(json_local));

    pair_teardown(&p);
}

/* -i, pinned the same way -s is, and for the reason -s needed pinning:
 * four of the five overrides were asserted and this one was not, so an
 * implementation that filled -i in instead of overriding passed the whole
 * suite. (An independent reviewer's mutation R8 proved exactly that.)
 *
 * WHAT MAKES IT VISIBLE FROM OUTSIDE: 127.0.0.0/8 is entirely local on
 * Linux, so both candidate addresses bind successfully and the difference
 * is WHICH ONE ANSWERS. The document says 127.0.0.2, the flag says
 * 127.0.0.1, and the case asserts both directions -- 127.0.0.1 accepts and
 * 127.0.0.2 refuses -- on the SAME port, so a port number cannot be
 * standing in for the address. Reverse the precedence and both flip.
 *
 * NO SERVER, DELIBERATELY. What is under test is which local address the
 * listener was opened on, and that is decided and logged before the first
 * round can possibly finish -- so the remote points at a port nothing
 * holds and the round simply fails in the background. One fewer process
 * per run, which matters because this file's ASan runtime is dominated by
 * process startup rather than by anything it measures. */
static void test_local_host_flag_overrides_json(void) {
    char pub[64];
    derive_pub_b64(pub, sizeof(pub));
    int local = free_port();
    ASSERT_TRUE(local > 0);

    char extra[512];
    snprintf(extra, sizeof(extra),
             "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"1\","
             "\"LocalHost\":\"127.0.0.2\",\"LocalPort\":\"%d\",",
             local);
    char cfg[2048];
    make_client_config(cfg, sizeof(cfg), pub, extra);

    char *const argv[] = {(char *)"ck-client", (char *)"-c",        cfg,
                          (char *)"-i",        (char *)"127.0.0.1", NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, CK_CLIENT_PATH, argv, NULL));
    ASSERT_EQ_INT(0, child_wait_for(&c, "ck-client ready", BOOT_MS));
    ASSERT_TRUE(strstr(c.out, "listening on TCP 127.0.0.1:") != NULL);
    ASSERT_EQ_INT(0, can_connect_at("127.0.0.1", local));
    ASSERT_EQ_INT(-1, can_connect_at("127.0.0.2", local));
    ASSERT_EQ_INT(0, child_stop(&c));
}

/* -proxy overrides the JSON too, and its effect is visible on the SERVER:
 * a proxy method the server's ProxyBook does not carry is refused at
 * dispatch, so no session ever comes up. The JSON names the good method
 * and the flag a bad one -- the reverse polarity of the case above, so a
 * "the flag is ignored" implementation cannot pass both. */
static void test_proxy_flag_overrides_json(void) {
    pair_t p;
    pair_init(&p);
    ASSERT_EQ_INT(0, pair_start_server(&p, ""));
    ASSERT_TRUE((p.local_port = free_port()) > 0);

    char extra[256];
    snprintf(extra, sizeof(extra),
             "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"%d\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"%d\",",
             p.server_port, p.local_port);
    char cfg[2048];
    make_client_config(cfg, sizeof(cfg), p.pub_b64, extra);

    char *const argv[] = {(char *)"ck-client", (char *)"-c",     cfg,
                          (char *)"-proxy",    (char *)"notreal", NULL};
    ASSERT_EQ_INT(0, child_spawn(&p.client, CK_CLIENT_PATH, argv, NULL));
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "ck-client ready", BOOT_MS));
    /* The flag's method reached the wire: the server refused it, so the
     * round failed. If -proxy had been dropped, "shadowsocks" from the
     * JSON would have been accepted and this would be a session up. */
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "round failed", BOOT_MS));
    ASSERT_TRUE(strstr(p.client.out, "session up") == NULL);

    pair_teardown(&p);
}

/* ------------------------------------------------------------------ */
/* Case 3: a missing required field                                      */
/* ------------------------------------------------------------------ */

static void test_missing_remote_host_is_a_config_error(void) {
    char pub[64];
    derive_pub_b64(pub, sizeof(pub));
    char cfg[2048];
    /* Everything but RemoteHost, and no -s to supply it. */
    make_client_config(cfg, sizeof(cfg), pub, "\"RemotePort\":\"443\",");

    char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, NULL};
    child_t c;
    ASSERT_EQ_INT(2, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
    /* It names the FIELD, not merely that something was wrong. */
    ASSERT_TRUE(strstr(c.out, "RemoteHost") != NULL);

    /* A config path that does not exist is the same class of failure and
     * names the path. */
    char *const bad[] = {(char *)"ck-client", (char *)"-c",
                         (char *)"/nonexistent/ck-client-test.json", NULL};
    child_t b;
    ASSERT_EQ_INT(2, run_to_exit(&b, CK_CLIENT_PATH, bad, NULL, EXIT_MS));
    ASSERT_TRUE(strstr(b.out, "/nonexistent/ck-client-test.json") != NULL);
}

/* ------------------------------------------------------------------ */
/* Case 4: -u and "UDP": true are HONOURED                               */
/* ------------------------------------------------------------------ */

/* Binds a TCP socket to `port` on loopback WITHOUT SO_REUSEADDR and
 * reports whether it succeeded. That is the deterministic way to ask
 * "is there a TCP listener on this port": a port already in LISTEN
 * refuses a second bind with EADDRINUSE, and a port held only by a UDP
 * socket does not, because the two protocols carry separate port spaces.
 *
 * Deliberately NOT a UDP bind, which would be the more direct question
 * and is not deterministic here: cloak_udp_piper_t's socket sets
 * SO_REUSEADDR, and Linux lets a second UDP socket share a unicast
 * addr:port when every socket bound to it has that option -- so a UDP
 * probe would answer differently depending on whether the probe itself
 * set it. The TCP pair below has no such dependency. Returns 1 if the
 * bind succeeded (nothing is listening for TCP there), 0 if it did not. */
static int tcp_port_is_free(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    int rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
    close(fd);
    return rc == 0 ? 1 : 0;
}

/* The two inputs that select unordered mode, and the thing they select.
 *
 * WHAT WOULD HAVE TO BREAK FOR THIS TO FAIL, which is the only reason it
 * is shaped this way rather than as "it started":
 *
 *  - A `-u` that is parsed and then DROPPED -- the state this file's
 *    previous case could not have distinguished from a refusal, because
 *    a refused flag and an ignored one both fail to produce a UDP
 *    listener. Both halves of the local-port pair below flip: with -u the
 *    TCP port is FREE and a TCP connect is REFUSED, without it the port
 *    is TAKEN and a connect succeeds. An ignored -u gives the second
 *    answer to the first question.
 *  - A `"UDP": true` handled only in the library and not in main.c, or
 *    only in main.c and not in the library: the config-key half and the
 *    flag half are asserted separately and identically.
 *  - The usage line drifting away from Go's. The wording is Go's own,
 *    verbatim, because a pluggable transport's -h output is read by
 *    people migrating a working deployment.
 *
 * The bit this mode actually puts on the wire is case 4b's, not this
 * one's: a client can bind a UDP socket and still advertise an ordered
 * session, and only the wire says which. */
static void test_udp_is_honoured(void) {
    char pub[64];
    derive_pub_b64(pub, sizeof(pub));

    /* THE USAGE TEXT, in Go's words. -h returns before the configuration
     * is touched (case 1), so no -c is needed. */
    {
        char *const argv[] = {(char *)"ck-client", (char *)"-h", NULL};
        child_t c;
        ASSERT_EQ_INT(0, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out,
                           "udp: set this flag if the underlying proxy is using UDP "
                           "protocol") != NULL);
    }

    /* THE FLAG. RemotePort 1 is a port nothing answers on: the session
     * never comes up, which costs this case nothing -- the listener is
     * open before the first connection is dialled and stays open across
     * every retry (cloak/client_stack.h), and this case is about the
     * listener. */
    int local = free_port();
    ASSERT_TRUE(local > 0);
    char extra[512];
    snprintf(extra, sizeof(extra),
             "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"1\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"%d\",",
             local);
    char cfg[2048];
    make_client_config(cfg, sizeof(cfg), pub, extra);

    {
        char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, (char *)"-u", NULL};
        child_t c;
        ASSERT_EQ_INT(0, child_spawn(&c, CK_CLIENT_PATH, argv, NULL));
        ASSERT_EQ_INT(0, child_wait_for(&c, "ck-client ready", BOOT_MS));
        char line[128];
        snprintf(line, sizeof(line), "listening on UDP 127.0.0.1:%d", local);
        ASSERT_TRUE(strstr(c.out, line) != NULL);
        /* The local endpoint is a DATAGRAM socket, asserted twice over:
         * nothing accepts TCP there, and the TCP port is still free. */
        ASSERT_EQ_INT(-1, can_connect(local));
        ASSERT_EQ_INT(1, tcp_port_is_free(local));
        ASSERT_EQ_INT(0, child_stop(&c));
    }

    /* THE SAME FLAG ON THE OTHER KIND OF CONFIGURATION SOURCE: -c can be
     * an ssv OPTION STRING as well as JSON (case 10), and -u reaches the
     * document through a DIFFERENT branch of conf_set_bool for each.
     *
     * THAT SECOND BRANCH WAS UNPINNED AND THE GAP WAS MEASURED, which is
     * why this leg exists rather than being assumed covered by the JSON
     * one: making the ssv branch write "false" unconditionally passed all
     * 73 tests, and a direct probe of the mutated binary logged
     * `listening on TCP 127.0.0.1:46211` for `-c "<option string>" -u`.
     * That is precisely the accepted-and-ignored flag the two refusals
     * this module removed existed to prevent, surviving on the path next
     * door. The assertions are the same TCP pair as the JSON leg, so this
     * fails for an ssv branch that drops -u exactly as loudly.
     *
     * The string carries no UDP= of its own: the flag must be the only
     * thing that can put this endpoint on UDP, or the leg would pass
     * against a conf_set_bool that never ran. */
    {
        char ssv[1024];
        snprintf(ssv, sizeof(ssv),
                 "UID=%s;PublicKey=%s;ServerName=www.bing.com;"
                 "ProxyMethod=shadowsocks;EncryptionMethod=aes-gcm;NumConn=2;"
                 "RemoteHost=127.0.0.1;RemotePort=1;"
                 "LocalHost=127.0.0.1;LocalPort=%d",
                 UID_B64, pub, local);
        char *const argv[] = {(char *)"ck-client", (char *)"-c", ssv, (char *)"-u", NULL};
        child_t c;
        ASSERT_EQ_INT(0, child_spawn(&c, CK_CLIENT_PATH, argv, NULL));
        ASSERT_EQ_INT(0, child_wait_for(&c, "ck-client ready", BOOT_MS));
        char line[128];
        snprintf(line, sizeof(line), "listening on UDP 127.0.0.1:%d", local);
        ASSERT_TRUE(strstr(c.out, line) != NULL);
        ASSERT_EQ_INT(-1, can_connect(local));
        ASSERT_EQ_INT(1, tcp_port_is_free(local));
        ASSERT_EQ_INT(0, child_stop(&c));
    }

    /* THE CONFIG KEY, which reaches the same place by a different road. */
    {
        char udpextra[512];
        snprintf(udpextra, sizeof(udpextra),
                 "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"1\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"%d\",\"UDP\":true,",
                 local);
        char udpcfg[2048];
        make_client_config(udpcfg, sizeof(udpcfg), pub, udpextra);
        char *const argv[] = {(char *)"ck-client", (char *)"-c", udpcfg, NULL};
        child_t c;
        ASSERT_EQ_INT(0, child_spawn(&c, CK_CLIENT_PATH, argv, NULL));
        ASSERT_EQ_INT(0, child_wait_for(&c, "ck-client ready", BOOT_MS));
        ASSERT_EQ_INT(-1, can_connect(local));
        ASSERT_EQ_INT(1, tcp_port_is_free(local));
        ASSERT_EQ_INT(0, child_stop(&c));

        /* AND -u=false TURNS IT OFF AGAIN, which is Go's flag.Visit and
         * was NOT this file's behaviour: every bool flag here took its
         * inline value, threw it away and set true. That was harmless
         * while -u was refused outright and is a flag that does the
         * opposite of what it says now that it selects a tunnel. The
         * assertion is the TCP pair again, so it fails for a -u=false
         * that is ignored just as loudly as for one that is inverted. */
        char *const argv_off[] = {(char *)"ck-client", (char *)"-c", udpcfg,
                                  (char *)"-u=false", NULL};
        child_t off;
        ASSERT_EQ_INT(0, child_spawn(&off, CK_CLIENT_PATH, argv_off, NULL));
        ASSERT_EQ_INT(0, child_wait_for(&off, "ck-client ready", BOOT_MS));
        /* The TCP half of the log line lives here rather than in a
         * control run of its own, and that is this case's RUNTIME PLAN
         * rather than an accident: cmd/ck-client/CMakeLists.txt records
         * that this file's ASan margin is the last acceptable one, so the
         * ssv leg above was paid for by deleting the "same configuration
         * without the flag" run, whose every assertion -- the TCP log
         * line, can_connect, tcp_port_is_free, on this same port -- is
         * made here against a client that reached TCP by a sharper road.
         * Net subprocess count unchanged. */
        char offline[128];
        snprintf(offline, sizeof(offline), "listening on TCP 127.0.0.1:%d", local);
        ASSERT_TRUE(strstr(off.out, offline) != NULL);
        ASSERT_EQ_INT(0, can_connect(local));
        ASSERT_EQ_INT(0, tcp_port_is_free(local));
        ASSERT_EQ_INT(0, child_stop(&off));

        /* An unparseable one is a usage error, not a silent true. */
        char *const argv_bad[] = {(char *)"ck-client", (char *)"-c", udpcfg,
                                  (char *)"-u=perhaps", NULL};
        child_t bad;
        ASSERT_EQ_INT(1, run_to_exit(&bad, CK_CLIENT_PATH, argv_bad, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(bad.out, "perhaps") != NULL);
    }
}

/* ------------------------------------------------------------------ */
/* Case 4a: the minimal UDP configuration explains ITS OWN failure       */
/* ------------------------------------------------------------------ */

/* THE TRAP THIS TASK OPENED, and the reason it is a case of its own.
 *
 * NumConn <= 0 -- INCLUDING AN OMITTED NumConn -- means singleplex, in
 * this port and in Go (cloak/config.h, and Go's ProcessRawConfig). This
 * build does not implement singleplex WITH udp and refuses the pair. So
 * the very first configuration a reader of Go's documentation writes,
 *
 *     {"UDP": true, ... }
 *
 * is refused, naming a mode the user never typed. That is a message
 * about something they did not configure, which is the shape of error
 * report that sends somebody to the source.
 *
 * WHAT WAS NOT DONE, and why: defaulting NumConn to something above zero
 * when udp is set. It would start, and it would be WIRE-VISIBLE
 * divergence from Go -- a Go client reading this same configuration opens
 * ONE connection and this one would open several -- for a configuration
 * the user did not write. A refusal that explains itself costs the user
 * one line of configuration; a silent divergence costs them a
 * distinguishable client.
 *
 * So the message names the real cause instead. This case fails if it
 * stops doing so. */
static void test_udp_without_numconn_names_numconn(void) {
    char pub[64];
    derive_pub_b64(pub, sizeof(pub));
    /* NOT make_client_config, which always writes a NumConn: the whole
     * point here is the key's ABSENCE. */
    char cfg[2048];
    snprintf(cfg, sizeof(cfg),
             "{"
             "\"ServerName\":\"www.bing.com\","
             "\"ProxyMethod\":\"shadowsocks\","
             "\"EncryptionMethod\":\"aes-gcm\","
             "\"UID\":\"%s\","
             "\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"0\","
             "\"UDP\":true,"
             "\"BrowserSig\":\"chrome\""
             "}",
             UID_B64, pub);
    char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, NULL};
    child_t c;
    ASSERT_EQ_INT(2, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
    /* The cause the user can act on, not merely the mode they never
     * named. Both words, because "singleplex" alone is the message this
     * case exists to reject. */
    ASSERT_TRUE(strstr(c.out, "singleplex") != NULL);
    ASSERT_TRUE(strstr(c.out, "NumConn") != NULL);
    /* AND WHETHER TO EXPECT IT LATER. The remedy alone does not tell an
     * operator migrating a working Go deployment whether this is a gap in
     * this port or a thing nobody implements; Go's RouteUDP does take
     * Singleplex, so the message says so and this asserts it says so. */
    ASSERT_TRUE(strstr(c.out, "Go's client does support it") != NULL);
    ASSERT_TRUE(strstr(c.out, "ck-client ready") == NULL);

    /* And the same configuration with a NumConn starts, so the message
     * above is a fixable one rather than a description of a mode that
     * cannot be entered at all. */
    char cfg2[2048];
    snprintf(cfg2, sizeof(cfg2),
             "{"
             "\"ServerName\":\"www.bing.com\","
             "\"ProxyMethod\":\"shadowsocks\","
             "\"EncryptionMethod\":\"aes-gcm\","
             "\"UID\":\"%s\","
             "\"PublicKey\":\"%s\","
             "\"NumConn\":1,"
             "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"1\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"0\","
             "\"UDP\":true,"
             "\"BrowserSig\":\"chrome\""
             "}",
             UID_B64, pub);
    char *const argv2[] = {(char *)"ck-client", (char *)"-c", cfg2, NULL};
    child_t c2;
    ASSERT_EQ_INT(0, child_spawn(&c2, CK_CLIENT_PATH, argv2, NULL));
    ASSERT_EQ_INT(0, child_wait_for(&c2, "ck-client ready", BOOT_MS));
    ASSERT_EQ_INT(0, child_stop(&c2));
}

/* ------------------------------------------------------------------ */
/* Case 4b: the unordered bit, read OFF THE WIRE                         */
/* ------------------------------------------------------------------ */

/* THE ONLY EVIDENCE OUTSIDE THIS PROCESS THAT THE MODE EXISTS. Every
 * other assertion in case 4 is about a socket this client opened for
 * itself; a client that bound a UDP port and then advertised an ORDERED
 * session would pass all of them, and would be exactly the divergence
 * this task was dispatched to close -- our own server refuses that
 * combination, but a GO server does not, and Task 1 measured what it does
 * instead: it reorders. All three byte counts came back identical and
 * only a content comparison failed. So the flag is asserted where it is
 * actually decided, on the wire, in both states.
 *
 * The bytes are decrypted with the SERVER'S OWN decrypter
 * (cloak_server_auth_decrypt) rather than by indexing byte 41 by hand: a
 * hand-cut offset is a second copy of the layout, free to agree with a
 * mutated builder. This one cannot -- it is the code a real server runs.
 *
 * Nothing replies to the ClientHello: the handshake is abandoned after
 * the first record, the client retries in the background, and the case is
 * over. */

/* Reads exactly one TLS record -- 5-byte header, then the length that
 * header declares -- bounded by the clock. Returns the total number of
 * bytes in the record, or -1. */
static int read_one_tls_record(int fd, uint8_t *buf, size_t cap, int timeout_ms) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    size_t have = 0;
    size_t want = 5;
    for (;;) {
        if (have >= want) {
            if (want == 5) {
                size_t body = ((size_t)buf[3] << 8) | (size_t)buf[4];
                want = 5 + body;
                if (want > cap) {
                    return -1;
                }
                continue;
            }
            return (int)want;
        }
        uint64_t now = now_ms();
        if (now >= deadline) {
            return -1;
        }
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, (int)(deadline - now)) <= 0) {
            return -1;
        }
        ssize_t n = read(fd, buf + have, want - have);
        if (n <= 0) {
            return -1;
        }
        have += (size_t)n;
    }
}

/* Accepts one connection on `listen_fd`, reads its ClientHello, and
 * returns the unordered flag the server would have read out of it: 0, 1,
 * or -1 if anything went wrong. */
static int wire_unordered_flag(int listen_fd) {
    struct pollfd p = {listen_fd, POLLIN, 0};
    if (poll(&p, 1, BOOT_MS) <= 0) {
        return -1;
    }
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) {
        return -1;
    }
    uint8_t rec[8192];
    int n = read_one_tls_record(fd, rec, sizeof(rec), BOOT_MS);
    close(fd);
    if (n <= 0) {
        return -1;
    }
    cloak_clienthello_parsed_t parsed;
    if (cloak_clienthello_parse(rec, (size_t)n, &parsed) != 0) {
        return -1;
    }
    uint8_t priv[CLOAK_X25519_KEY_LEN];
    size_t priv_len = 0;
    if (cloak_base64_decode(PRIV_B64, priv, sizeof(priv), &priv_len) != 0 ||
        priv_len != CLOAK_X25519_KEY_LEN) {
        return -1;
    }
    cloak_server_clientinfo_t info;
    uint8_t secret[CLOAK_AEAD_KEY_LEN];
    if (cloak_server_auth_decrypt(parsed.random, parsed.session_id, parsed.session_id_len,
                                  parsed.x25519_key_share, priv, (int64_t)time(NULL), &info,
                                  secret) != 0) {
        return -1;
    }
    return info.unordered ? 1 : 0;
}

static void test_the_unordered_bit_is_on_the_wire(void) {
    char pub[64];
    derive_pub_b64(pub, sizeof(pub));

    for (int udp = 0; udp <= 1; udp++) {
        int front = 0;
        int listen_fd = listen_on(&front);
        ASSERT_TRUE(listen_fd >= 0);

        char extra[512];
        snprintf(extra, sizeof(extra),
                 "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"%d\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"0\",",
                 front);
        char cfg[2048];
        make_client_config(cfg, sizeof(cfg), pub, extra);

        char *const argv_u[] = {(char *)"ck-client", (char *)"-c", cfg, (char *)"-u", NULL};
        char *const argv_o[] = {(char *)"ck-client", (char *)"-c", cfg, NULL};
        child_t c;
        ASSERT_EQ_INT(0, child_spawn(&c, CK_CLIENT_PATH, udp ? argv_u : argv_o, NULL));

        int seen = wire_unordered_flag(listen_fd);
        ASSERT_EQ_INT(udp, seen);

        ASSERT_EQ_INT(0, child_stop(&c));
        close(listen_fd);
    }
}

/* ------------------------------------------------------------------ */
/* Case 5: end to end, through both binaries                             */
/* ------------------------------------------------------------------ */

/* 256 KiB. cloak_client_stack.h pins max_on_wire_size at 16401 bytes on
 * both ends of one tunnel, so this payload cannot cross in fewer than
 * ceil(262144 / 16401) = 16 records, and in practice crosses more because
 * a record also carries the mux frame header. A payload that fitted in
 * one record would leave the entire framing, reassembly and ordering path
 * untested -- which is exactly the layer two separately-started processes
 * are most likely to disagree about. */
#define E2E_PAYLOAD 262144
#define E2E_MIN_RECORDS ((E2E_PAYLOAD + 16400) / 16401)

static void test_end_to_end_through_both_binaries(void) {
    pair_t p;
    pair_init(&p);
    ASSERT_EQ_INT(0, pair_start_server(&p, ""));
    /* No -s, no -l, no -p: everything comes from the JSON, which is the
     * other half of case 2's precedence assertion. */
    ASSERT_EQ_INT(0, pair_start_client(&p, "", NULL));
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "session up", BOOT_MS));

    uint8_t *send_buf = malloc(E2E_PAYLOAD);
    uint8_t *reply_buf = malloc(E2E_PAYLOAD);
    ASSERT_TRUE(send_buf != NULL && reply_buf != NULL);
    if (send_buf == NULL || reply_buf == NULL) {
        pair_teardown(&p);
        free(send_buf);
        free(reply_buf);
        return;
    }
    fill_payload(send_buf, E2E_PAYLOAD, 0xC10Au);
    memset(reply_buf, 0, E2E_PAYLOAD);

    int app = dial(p.local_port);
    ASSERT_TRUE(app >= 0);

    size_t up_seen = 0;
    uint64_t t0 = now_ms();
    size_t got = exchange(app, p.upstream_fd, send_buf, E2E_PAYLOAD, 0xFF, reply_buf,
                          E2E_PAYLOAD, &up_seen, XFER_MS);
    uint64_t took = now_ms() - t0;
    close(app);

    printf("  [case 5] %zu bytes out, %zu back in %llu ms (>= %d records)\n", up_seen, got,
           (unsigned long long)took, (int)E2E_MIN_RECORDS);

    /* Every byte reached the upstream, and every byte came back. */
    ASSERT_EQ_INT(E2E_PAYLOAD, (long long)up_seen);
    ASSERT_EQ_INT(E2E_PAYLOAD, (long long)got);

    /* BYTE FOR BYTE, and transformed: the reply is the payload XORed,
     * which nothing on the client side of this path can produce. The
     * whole buffer is compared -- "some bytes arrived" is not the claim
     * -- and the first divergence is printed, because a byte index is the
     * difference between "the tunnel is broken" and "one frame was
     * dropped at offset 49203". */
    size_t bad = E2E_PAYLOAD;
    for (size_t i = 0; i < E2E_PAYLOAD && i < got; i++) {
        uint8_t want = (uint8_t)(send_buf[i] ^ 0xFFu);
        if (reply_buf[i] != want) {
            bad = i;
            break;
        }
    }
    if (bad < E2E_PAYLOAD) {
        printf("  [case 5] first mismatch at byte %zu: %02x != %02x\n", bad,
               (unsigned)reply_buf[bad], (unsigned)(uint8_t)(send_buf[bad] ^ 0xFFu));
    }
    ASSERT_EQ_INT((long long)E2E_PAYLOAD, (long long)bad);

    free(send_buf);
    free(reply_buf);
    pair_teardown(&p);
}

/* ------------------------------------------------------------------ */
/* Case 6: SIGTERM shuts down cleanly, leaving no descriptor behind       */
/* ------------------------------------------------------------------ */

static void test_sigterm_is_clean_and_leaks_no_descriptor(void) {
    pair_t p;
    pair_init(&p);
    ASSERT_EQ_INT(0, pair_start_server(&p, ""));
    ASSERT_EQ_INT(0, pair_start_client(&p, "", NULL));
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "session up", BOOT_MS));

    /* The baseline is taken AFTER the session is up, so the tunnel's own
     * connections are already counted and are not mistaken for a leak. */
    int before = fd_census(p.client.pid);
    if (before < 0) {
        printf("  [case 6] /proc not available; descriptor census skipped\n");
    }

    /* Eight local connections, each carrying a round trip and then
     * closing. A client that forgets one socket per connection shows up
     * as +8 here and is invisible to LeakSanitizer. */
    uint8_t out[64];
    uint8_t want[64];
    uint8_t in[64];
    fill_payload(out, sizeof(out), 0x5EEDu);
    for (size_t j = 0; j < sizeof(out); j++) {
        want[j] = (uint8_t)(out[j] ^ 0xFF);
    }
    for (int i = 0; i < 8; i++) {
        int app = dial(p.local_port);
        ASSERT_TRUE(app >= 0);
        size_t seen = 0;
        memset(in, 0, sizeof(in));
        size_t got = exchange(app, p.upstream_fd, out, sizeof(out), 0xFF, in, sizeof(in),
                              &seen, 5000);
        close(app);
        ASSERT_EQ_INT((long long)sizeof(out), (long long)got);
        ASSERT_MEM_EQ(in, want, sizeof(want));
    }

    if (before >= 0) {
        /* The census is retried against the clock: the client closes its
         * end when it notices ours, and that notice is one reactor turn
         * away -- a single reading here would be a race, not a bound. */
        int after = -1;
        uint64_t deadline = now_ms() + 5000;
        do {
            after = fd_census(p.client.pid);
            if (after <= before) {
                break;
            }
            struct timespec ts = {0, 20 * 1000 * 1000};
            nanosleep(&ts, NULL);
        } while (now_ms() < deadline);
        printf("  [case 6] descriptors: %d before, %d after 8 connections\n", before, after);
        ASSERT_TRUE(after >= 0 && after <= before);
    }

    /* SIGPIPE DOES NOT KILL IT, and neither does it kill the SERVER this
     * case already has running. Both are asserted here so neither costs a
     * process: see child_survives_signal for why the disposition is
     * assertable even though the race that provokes it is not, and why
     * ignoring SIGPIPE is FIDELITY to Go rather than a precaution. Before
     * the two main()s ignored it, both of these returned 141. */
    ASSERT_EQ_INT(0, child_survives_signal(&p.client, SIGPIPE, 200));
    ASSERT_EQ_INT(0, child_survives_signal(&p.server, SIGPIPE, 200));
    /* And both are still doing their jobs: the local listener still
     * accepts, which means the client's reactor is still turning. */
    ASSERT_EQ_INT(0, can_connect(p.local_port));

    ASSERT_TRUE(p.client.pid > 0);
    if (p.client.pid > 0) {
        kill(p.client.pid, SIGTERM);
    }
    ASSERT_EQ_INT(0, child_reap(&p.client, EXIT_MS));
    ASSERT_TRUE(strstr(p.client.out, "received signal 15") != NULL);
    ASSERT_TRUE(strstr(p.client.out, "ck-client stopped") != NULL);
    /* The listener really is gone, not merely unreferenced. */
    ASSERT_EQ_INT(-1, can_connect(p.local_port));

    p.client.pid = 0;
    pair_teardown(&p);
}

/* ------------------------------------------------------------------ */
/* Case 7: -a reaches the admin API                                      */
/* ------------------------------------------------------------------ */

/* ONE REAL REQUEST AND ONE REAL RESPONSE, over a session that the SERVER
 * decided was an admin session. That decision is
 * `cloak_server_is_admin(uid) && session_id == 0` -- both halves -- so
 * this case fails if -a forgets either the UID or the session id.
 *
 * WHAT MAKES A FAILURE VISIBLE RATHER THAN A HANG: the ProxyBook in this
 * case points at an upstream this test owns, and the loop below ACCEPTS
 * AND ECHOES it. A session that was NOT recognised as admin is dispatched
 * to the proxy instead, so the HTTP request text is relayed to that
 * upstream and comes straight back verbatim -- and the loop stops the
 * moment what came back is not an HTTP response, so the case fails in
 * milliseconds with the echoed request printed, rather than after a 15 s
 * read deadline with nothing to show.
 *
 * That last part is a repair. The first version of this case documented
 * the echo but never accepted the upstream connection, so the two
 * mutations that break admin routing both produced "[case 7] 0 response
 * bytes" after the full deadline: the assertions still failed, but slower
 * and less informatively than the comment promised. A comment that
 * describes a diagnostic the code does not produce is worse than no
 * comment. */
static void test_admin_flag_reaches_the_admin_api(void) {
    pair_t p;
    pair_init(&p);

    char extra[256];
    snprintf(extra, sizeof(extra), "\"AdminUID\":\"%s\",\"DatabasePath\":\"%s\",",
             ADMIN_UID_B64, "ck_client_test_admin.db");
    ASSERT_EQ_INT(0, pair_start_server(&p, extra));

    char *const cargv[] = {(char *)"-a", (char *)ADMIN_UID_B64, NULL};
    ASSERT_EQ_INT(0, pair_start_client(&p, "", cargv));
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "session up", BOOT_MS));
    /* -a really did take the admin path, and says so. */
    ASSERT_TRUE(strstr(p.client.out, "admin") != NULL);

    int app = dial(p.local_port);
    ASSERT_TRUE(app >= 0);
    static const char req[] = "GET /admin/users HTTP/1.1\r\n"
                              "Host: cloak-admin\r\n"
                              "\r\n";
    set_nonblock(app);
    size_t sent = 0;
    uint64_t deadline = now_ms() + 10000;
    while (sent < sizeof(req) - 1 && now_ms() < deadline) {
        ssize_t w = write(app, req + sent, sizeof(req) - 1 - sent);
        if (w > 0) {
            sent += (size_t)w;
        } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            break;
        } else {
            struct pollfd wp = {app, POLLOUT, 0};
            poll(&wp, 1, 20);
        }
    }
    ASSERT_EQ_INT((long long)(sizeof(req) - 1), (long long)sent);

    char resp[8192];
    size_t got = 0;
    int up_fd = -1;
    set_nonblock(p.upstream_fd);
    deadline = now_ms() + 15000;
    while (got + 1 < sizeof(resp) && now_ms() < deadline) {
        struct pollfd pf[3];
        int n = 0;
        int app_i = n;
        pf[n].fd = app;
        pf[n].events = POLLIN;
        pf[n].revents = 0;
        n++;
        int lst_i = -1, up_i = -1;
        if (up_fd < 0) {
            lst_i = n;
            pf[n].fd = p.upstream_fd;
            pf[n].events = POLLIN;
            pf[n].revents = 0;
            n++;
        } else {
            up_i = n;
            pf[n].fd = up_fd;
            pf[n].events = POLLIN;
            pf[n].revents = 0;
            n++;
        }
        if (poll(pf, (nfds_t)n, 50) <= 0) {
            continue;
        }
        if (lst_i >= 0 && (pf[lst_i].revents & POLLIN) != 0) {
            /* THE MISROUTE PATH: the request reached the proxy, not the
             * admin API. Accept it and echo, so the wrong answer arrives
             * instead of nothing at all. */
            up_fd = accept(p.upstream_fd, NULL, NULL);
            if (up_fd >= 0) {
                set_nonblock(up_fd);
            }
        }
        if (up_i >= 0 && (pf[up_i].revents & POLLIN) != 0) {
            char buf[2048];
            ssize_t r = read(up_fd, buf, sizeof(buf));
            if (r > 0) {
                ssize_t w = write(up_fd, buf, (size_t)r);
                (void)w;
            } else if (r == 0) {
                close(up_fd);
                up_fd = -1;
            }
        }
        if ((pf[app_i].revents & (POLLIN | POLLHUP)) == 0) {
            continue;
        }
        ssize_t r = read(app, resp + got, sizeof(resp) - 1 - got);
        if (r > 0) {
            got += (size_t)r;
            resp[got] = '\0';
            /* Not an HTTP response at all -- stop now and let the
             * assertions report what DID come back. */
            if (got >= 5 && memcmp(resp, "HTTP/", 5) != 0) {
                break;
            }
            /* A complete response: headers plus a body that closed. */
            if (strstr(resp, "\r\n\r\n") != NULL) {
                const char *body = strstr(resp, "\r\n\r\n") + 4;
                if (strchr(body, ']') != NULL) {
                    break;
                }
            }
        } else if (r == 0) {
            break;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            break;
        }
    }
    if (up_fd >= 0) {
        close(up_fd);
    }
    close(app);
    resp[got] = '\0';
    printf("  [case 7] %zu response bytes: %.60s\n", got, resp);

    /* A REAL HTTP RESPONSE, from the admin router: the status line, the
     * content type it sets, and a JSON array body. An echoed request (the
     * proxy path) matches none of these. */
    ASSERT_TRUE(strstr(resp, "HTTP/1.1 200") != NULL);
    ASSERT_TRUE(strstr(resp, "application/json") != NULL);
    const char *body = strstr(resp, "\r\n\r\n");
    ASSERT_TRUE(body != NULL);
    if (body != NULL) {
        ASSERT_EQ_INT('[', (long long)body[4]);
    }
    /* And it is NOT the request coming back. */
    ASSERT_TRUE(strstr(resp, "GET /admin/users") == NULL);

    /* -a DOES NOT SILENTLY REPAIR A SINGLEPLEX CONFIG; IT IS REFUSED.
     *
     * Go's admin branch sets exactly three things -- UID, SessionId and
     * NumConn -- and leaves Singleplex alone (ck-client.go:159-163, read
     * directly). This port used to set a FOURTH, zeroing singleplex, which
     * no comment declared and nothing tested: a reviewer deleted the line
     * and all 63 tests passed. Two things were wrong with it. It discarded
     * an operator's setting in total silence, in a binary that WARNs about
     * an ignored KeepAlive on the argument that a silently ignored setting
     * is the shape of bug only a packet capture finds. And it
     * pre-satisfied cloak_client_stack_config_t::admin_session's own
     * ERR_CONFIG guard, so that guard -- documented, and pinned by
     * test_client_stack.c -- could never fire from the only binary that
     * sets the field.
     *
     * Note which way fidelity points, because it is not the obvious way.
     * Both parsers, Go's (internal/client/state.go:212-217) and this one,
     * turn NumConn <= 0 into "NumConn 1, Singleplex true" -- so a config
     * that simply omits NumConn IS a singleplex config, in both. Go then
     * runs admin mode on it and every local connection gets a fresh
     * session id, while the server admits an admin session only at id 0:
     * Go's own admin mode is quietly broken for that config. Refusing is
     * therefore BOTH the faithful choice (no fourth assignment) and the
     * better one (Go's silent breakage becomes exit 2 with a message that
     * names the remedy). The remedy is "NumConn": 1, which is exactly what
     * makes Go's admin mode work as well.
     *
     * Costs no server: the guard is a configuration check inside
     * cloak_client_stack_open, reached before anything is resolved or
     * bound. */
    {
        char cfg[2048];
        snprintf(cfg, sizeof(cfg),
                 "{\"ServerName\":\"www.bing.com\",\"ProxyMethod\":\"shadowsocks\","
                 "\"EncryptionMethod\":\"aes-gcm\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
                 "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"%d\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"0\"}",
                 UID_B64, p.pub_b64, p.server_port);
        char *const a[] = {(char *)"ck-client", (char *)"-c",  cfg,
                           (char *)"-a",        (char *)ADMIN_UID_B64, NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit(&c, CK_CLIENT_PATH, a, NULL, EXIT_MS));
        /* The typed edge and the reason, so this cannot pass on some other
         * configuration error: the parenthesised strerror name plus the
         * guard's own wording. */
        ASSERT_TRUE(strstr(c.out, "(client config)") != NULL);
        ASSERT_TRUE(strstr(c.out, "admin mode requires NumConn 1 and no singleplex") != NULL);
        ASSERT_TRUE(strstr(c.out, "with singleplex") != NULL);
        /* It did NOT come up: no listener, no session, no silent repair. */
        ASSERT_TRUE(strstr(c.out, "ck-client ready") == NULL);
    }

    pair_teardown(&p);
    unlink("ck_client_test_admin.db");
}

/* ------------------------------------------------------------------ */
/* Case 7b: ck-server BILLS THE LAST INTERVAL before it exits           */
/* ------------------------------------------------------------------ */

/* THE SEAM A PER-TASK REVIEW CANNOT SEE: the library does the thing, and
 * nothing checked that the program asks it to.
 * cloak_server_stack_upload_now is well covered at library level
 * (test_server_stack.c), and a reviewer DELETED ck-server's call to it
 * from main's shutdown path with all 63 tests still passing. What
 * silently stops happening is the trade cloak/server_stack.h:408,422
 * documents: cloak_server_stack_close does NOT upload what the panel has
 * queued, so without that call the last metering interval is dropped on
 * every clean restart. The default interval is 60 s
 * (CLOAK_USERPANEL_DEFAULT_UPLOAD_INTERVAL_MS), so on a server restarted
 * more often than that, NOTHING is ever billed -- and nobody finds that
 * class of bug until an invoice is wrong.
 *
 * WHY IT IS IN THE CLIENT'S FILE. Metering comes off the session data
 * path, so producing a single billable byte needs a real client talking
 * to a real server -- which is exactly what this file already has and
 * test_ck_server_cli.c has no way to build. The case reuses the pair
 * machinery rather than growing a third subprocess harness.
 *
 * HOW IT IS OBSERVED. This test process opens the same SQLite file the
 * server used, through the same cloak_usermanager_* API the server does,
 * AFTER the server has exited. No admin API, no second server, no
 * parsing: the credit the database holds is the credit the panel
 * settled.
 *
 * THREE THINGS MAKE THE ASSERTION MEAN WHAT IT SAYS:
 *   - the UID is NOT in BypassUID, so it is a metered database user and
 *     not a bypass one (a bypass user has no valve at all);
 *   - the credit is seeded far above the transfer, so the user is never
 *     terminated mid-run and the drop measured is metering and not
 *     eviction;
 *   - the periodic upload timer is 60 s away and this case finishes in
 *     well under a second, so the only cycle that can have run is the
 *     one main() asks for at shutdown. */
/* SMALL ON PURPOSE, and the reason is another test's diagnostic. Case 5
 * above is the suite's sharpest single signal: mutating the server's
 * CLOAK_SERVER_STACK_DEFAULT_MAX_ON_WIRE_SIZE from 16401 to 8192 fails
 * case 5's two byte-count assertions AND NOTHING ELSE IN 63 TESTS, which
 * is what makes it point at the record size rather than at "the tunnel is
 * broken". Any case moving a payload larger than the mutated limit joins
 * that failure and blunts it. 4096 bytes, framing included, stays inside
 * even a halved record, so this case measures metering and leaves case
 * 5's signal alone -- and 4096 is far more than enough to see a credit
 * move, which is all that is asserted here. */
#define BILLED_PAYLOAD 4096
#define BILLED_CREDIT  (1024 * 1024 * 64)

static void test_shutdown_bills_the_last_interval(void) {
    const char *db = "ck_client_test_billing.db";
    unlink(db);
    unlink("ck_client_test_billing.db-wal");
    unlink("ck_client_test_billing.db-shm");

    uint8_t uid[CLOAK_UID_LEN];
    size_t uid_len = 0;
    ASSERT_EQ_INT(0, cloak_base64_decode(UID_B64, uid, sizeof(uid), &uid_len));
    ASSERT_EQ_INT(CLOAK_UID_LEN, (long long)uid_len);

    { /* seed the user, with credit far above what the transfer moves */
        cloak_usermanager_t *m = NULL;
        char err[256] = {0};
        ASSERT_EQ_INT(0, cloak_usermanager_open(&m, db, NULL, NULL, err, sizeof(err)));
        if (m == NULL) {
            printf("  [case 7b] could not open %s: %s\n", db, err);
            return;
        }
        cloak_user_info_t info;
        memset(&info, 0, sizeof(info));
        memcpy(info.uid, uid, CLOAK_UID_LEN);
        info.sessions_cap = 16;
        info.up_credit = BILLED_CREDIT;
        info.down_credit = BILLED_CREDIT;
        info.expiry_time = (int64_t)time(NULL) + 3600;
        ASSERT_EQ_INT(0, cloak_usermanager_write(m, &info, CLOAK_USER_FIELD_ALL));
        cloak_usermanager_close(m);
    }

    pair_t p;
    pair_init(&p);
    char extra[256];
    snprintf(extra, sizeof(extra), "\"DatabasePath\":\"%s\",", db);
    /* EMPTY BypassUID: this user must go through the database. */
    ASSERT_EQ_INT(0, pair_start_server_bypass(&p, extra, ""));
    ASSERT_EQ_INT(0, pair_start_client(&p, "", NULL));
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "session up", BOOT_MS));

    uint8_t *send_buf = malloc(BILLED_PAYLOAD);
    uint8_t *reply_buf = malloc(BILLED_PAYLOAD);
    ASSERT_TRUE(send_buf != NULL && reply_buf != NULL);
    if (send_buf == NULL || reply_buf == NULL) {
        free(send_buf);
        free(reply_buf);
        pair_teardown(&p);
        return;
    }
    fill_payload(send_buf, BILLED_PAYLOAD, 0xB111u);
    int app = dial(p.local_port);
    ASSERT_TRUE(app >= 0);
    size_t seen = 0;
    size_t got = exchange(app, p.upstream_fd, send_buf, BILLED_PAYLOAD, 0xA5, reply_buf,
                          BILLED_PAYLOAD, &seen, XFER_MS);
    close(app);
    /* The traffic really happened, in both directions -- otherwise there
     * would be nothing to bill and the assertion below would be vacuous. */
    ASSERT_EQ_INT((long long)BILLED_PAYLOAD, (long long)seen);
    ASSERT_EQ_INT((long long)BILLED_PAYLOAD, (long long)got);
    free(send_buf);
    free(reply_buf);

    /* The client goes first, then the SERVER is signalled and REAPED --
     * the reap is what guarantees the database file is complete before it
     * is read, rather than racing a process still in cloak_userpanel_close. */
    ASSERT_EQ_INT(0, child_stop(&p.client));
    p.client.pid = 0;
    ASSERT_TRUE(p.server.pid > 0);
    if (p.server.pid > 0) {
        kill(p.server.pid, SIGTERM);
    }
    ASSERT_EQ_INT(0, child_reap(&p.server, EXIT_MS));
    p.server.pid = 0;
    pair_teardown(&p);

    { /* what the database actually holds now */
        cloak_usermanager_t *m = NULL;
        char err[256] = {0};
        ASSERT_EQ_INT(0, cloak_usermanager_open(&m, db, NULL, NULL, err, sizeof(err)));
        if (m == NULL) {
            printf("  [case 7b] could not reopen %s: %s\n", db, err);
            return;
        }
        cloak_user_info_t after;
        memset(&after, 0, sizeof(after));
        ASSERT_EQ_INT(0, cloak_usermanager_get(m, uid, &after));
        printf("  [case 7b] credit after %d bytes each way: up %lld, down %lld "
               "(seeded %lld)\n",
               BILLED_PAYLOAD, (long long)after.up_credit, (long long)after.down_credit,
               (long long)BILLED_CREDIT);
        /* BOTH DIRECTIONS, and both STRICTLY below the seed. A shutdown
         * that never uploaded leaves both exactly at BILLED_CREDIT, which
         * is what the deleted call produced. The bound is >= the payload
         * rather than == it, because the tunnel's own framing is billed
         * too and counting it here would be asserting the mux's overhead,
         * not the upload. */
        ASSERT_TRUE(after.up_credit <= (int64_t)BILLED_CREDIT - (int64_t)BILLED_PAYLOAD);
        ASSERT_TRUE(after.down_credit <= (int64_t)BILLED_CREDIT - (int64_t)BILLED_PAYLOAD);
        cloak_usermanager_close(m);
    }

    unlink(db);
    unlink("ck_client_test_billing.db-wal");
    unlink("ck_client_test_billing.db-shm");
}

/* ------------------------------------------------------------------ */
/* Case 8: plugin mode takes SS_PLUGIN_OPTIONS as an ssv string          */
/* ------------------------------------------------------------------ */

/* Go's client hands SS_PLUGIN_OPTIONS straight to client.ParseConfig,
 * which switches on the STRING: a value containing both ';' and '=' is a
 * semicolon-separated option list, anything else is a path. That is a
 * different rule from the server's, whose plugin options are JSON, and
 * the difference is Go's own -- so it is asserted here rather than
 * described.
 *
 * The four SS_* variables also fill in the four jsonOptional fields, and
 * the option string deliberately omits all of them: if the environment
 * were ignored, there would be no remote to dial and no local port to
 * open, and the readiness line would never appear. */
static void test_plugin_mode_takes_an_ssv_string(void) {
    pair_t p;
    pair_init(&p);
    ASSERT_EQ_INT(0, pair_start_server(&p, ""));
    int local = free_port();
    ASSERT_TRUE(local > 0);

    char opts[1024];
    snprintf(opts, sizeof(opts),
             "UID=%s;PublicKey=%s;ServerName=www.bing.com;"
             "EncryptionMethod=aes-gcm;NumConn=2",
             UID_B64, p.pub_b64);

    char e0[1100], e1[64], e2[64], e3[64], e4[64];
    snprintf(e0, sizeof(e0), "SS_PLUGIN_OPTIONS=%s", opts);
    snprintf(e1, sizeof(e1), "SS_LOCAL_HOST=127.0.0.1");
    snprintf(e2, sizeof(e2), "SS_LOCAL_PORT=%d", local);
    snprintf(e3, sizeof(e3), "SS_REMOTE_HOST=127.0.0.1");
    snprintf(e4, sizeof(e4), "SS_REMOTE_PORT=%d", p.server_port);
    const char *const env[] = {e0, e1, e2, e3, e4, NULL};

    char *const argv[] = {(char *)"ck-client", NULL};
    ASSERT_EQ_INT(0, child_spawn(&p.client, CK_CLIENT_PATH, argv, env));
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "ck-client ready", BOOT_MS));
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "session up", BOOT_MS));
    /* ProxyMethod was not in the options at all: plugin mode defaults it
     * to "shadowsocks", which is what the server's ProxyBook carries --
     * and the session coming up is what proves it. */
    ASSERT_EQ_INT(0, can_connect(local));
    p.local_port = local;
    child_stop(&p.client);
    p.client.pid = 0;

    /* -V AND -fast-open ARE ACCEPTED, and every other flag is not. Go
     * registers exactly those two in plugin mode, both documented as
     * "ignored.", so their only observable property is that they do not
     * turn into a usage error where -s would. Both halves are asserted,
     * because "accepted" only means something against a refusal. */
    {
        char *const okargv[] = {(char *)"ck-client", (char *)"-V", (char *)"-fast-open",
                                NULL};
        child_t c;
        ASSERT_EQ_INT(0, child_spawn(&c, CK_CLIENT_PATH, okargv, env));
        ASSERT_EQ_INT(0, child_wait_for(&c, "ck-client ready", BOOT_MS));
        ASSERT_EQ_INT(0, child_stop(&c));
    }
    {
        char *const badargv[] = {(char *)"ck-client", (char *)"-s", (char *)"127.0.0.1",
                                 NULL};
        child_t c;
        ASSERT_EQ_INT(1, run_to_exit(&c, CK_CLIENT_PATH, badargv, env, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "plugin mode") != NULL);
    }

    /* SS_LOCAL_HOST ALONE *IS* PLUGIN MODE FOR THE CLIENT, which is the
     * one plugin-mode difference between the two binaries this branch
     * claims is deliberate. Go, verbatim:
     *
     *   ck-client.go:  ssPluginMode := os.Getenv("SS_LOCAL_HOST") != ""
     *   ck-server.go:  if os.Getenv("SS_LOCAL_HOST") != "" &&
     *                     os.Getenv("SS_LOCAL_PORT") != "" {
     *
     * Both ports are faithful and NEITHER WAS PINNED: a reviewer
     * strengthened this binary's test to require SS_LOCAL_PORT as well and
     * all 63 tests passed, because every plugin case in both suites sets
     * both variables and the distinguishing environment -- host set, port
     * unset -- was never constructed. test_ck_server_cli.c's
     * test_ss_local_host_alone_is_not_plugin_mode is the mirror, asserting
     * the OPPOSITE outcome from the same environment; the two together are
     * what make the asymmetry a tested property rather than a comment.
     *
     * ONE PROCESS, and -s is the whole discriminator: plugin mode refuses
     * it by name, standalone mode accepts it and goes on to fail over a
     * config file nobody named. The two outcomes differ in exit code AND
     * in message. */
    {
        const char *const host_only[] = {"SS_LOCAL_HOST=127.0.0.1", NULL};
        char *const argv2[] = {(char *)"ck-client", (char *)"-s", (char *)"127.0.0.1", NULL};
        child_t c;
        ASSERT_EQ_INT(1, run_to_exit(&c, CK_CLIENT_PATH, argv2, host_only, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "unknown flag \"-s\" in shadowsocks plugin mode") != NULL);
        /* A standalone client would have got as far as its configuration,
         * and would have failed there instead. */
        ASSERT_TRUE(strstr(c.out, "configuration error") == NULL);
    }

    pair_teardown(&p);
}

/* ------------------------------------------------------------------ */
/* Case 9: the exit-code contract                                        */
/* ------------------------------------------------------------------ */

/* ck-server pinned 0/1/2/3/4 as a contract rather than a comment because
 * an operator's restart policy keys on them. ck-client reuses the same
 * five, and this case is what keeps the two binaries from drifting into
 * two schemes. */
static void test_exit_codes_are_distinct(void) {
    char pub[64];
    derive_pub_b64(pub, sizeof(pub));

    /* 1: usage. An unknown flag. */
    {
        char *const argv[] = {(char *)"ck-client", (char *)"-nonsense", NULL};
        child_t c;
        ASSERT_EQ_INT(1, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "nonsense") != NULL);
    }
    /* 1: usage. A flag that needs a value and did not get one. */
    {
        char *const argv[] = {(char *)"ck-client", (char *)"-s", NULL};
        child_t c;
        ASSERT_EQ_INT(1, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
    }
    /* 2: configuration. Valid JSON, unusable client config. */
    {
        char cfg[2048];
        make_client_config(cfg, sizeof(cfg), pub,
                           "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"443\","
                           "\"LocalPort\":\"1984\",\"Transport\":\"cdn\",");
        char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
        /* The TYPED edge, parenthesised, so the assertion cannot be
         * satisfied by a startup line that merely mentions the word. */
        ASSERT_TRUE(strstr(c.out, "(client config)") != NULL);
    }
    /* 3: the local address could not be opened. A port this process is
     * holding is the one thing guaranteed to be busy. */
    {
        int busy_port = 0;
        int busy = listen_on(&busy_port);
        ASSERT_TRUE(busy >= 0);
        char extra[256];
        snprintf(extra, sizeof(extra),
                 "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"443\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"%d\",",
                 busy_port);
        char cfg[2048];
        make_client_config(cfg, sizeof(cfg), pub, extra);
        char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, NULL};
        child_t c;
        ASSERT_EQ_INT(3, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "(local address)") != NULL);
        close(busy);
    }
    /* 3: the remote name could not be resolved -- the same class, and the
     * same code, as a local address that could not be opened. */
    {
        char cfg[2048];
        make_client_config(cfg, sizeof(cfg), pub,
                           "\"RemoteHost\":\"no-such-host.invalid\",\"RemotePort\":\"443\","
                           "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"0\",");
        char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, NULL};
        child_t c;
        ASSERT_EQ_INT(3, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "(remote address)") != NULL);
    }
}

/* ------------------------------------------------------------------ */
/* Case 10: -c takes a file, an ssv string, or literal JSON              */
/* ------------------------------------------------------------------ */

static void test_config_from_a_file_and_from_ssv(void) {
    pair_t p;
    pair_init(&p);
    ASSERT_EQ_INT(0, pair_start_server(&p, ""));
    int local = free_port();
    ASSERT_TRUE(local > 0);

    char extra[256];
    snprintf(extra, sizeof(extra),
             "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"%d\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"%d\",",
             p.server_port, local);
    char cfg[2048];
    make_client_config(cfg, sizeof(cfg), p.pub_b64, extra);
    const char *path = "ck_client_test_config.json";
    ASSERT_EQ_INT(0, write_temp(path, cfg));

    char *const argv[] = {(char *)"ck-client", (char *)"-c", (char *)path, NULL};
    ASSERT_EQ_INT(0, child_spawn(&p.client, CK_CLIENT_PATH, argv, NULL));
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "ck-client ready", BOOT_MS));
    ASSERT_EQ_INT(0, child_wait_for(&p.client, "session up", BOOT_MS));
    p.local_port = local;
    child_stop(&p.client);
    p.client.pid = 0;
    unlink(path);

    /* The ssv form, in STANDALONE mode -- Go's ParseConfig switches on
     * the string and not on the mode, so this is the same code path
     * plugin mode uses, reached from the command line. */
    int local2 = free_port();
    ASSERT_TRUE(local2 > 0);
    char ssv[1024];
    snprintf(ssv, sizeof(ssv),
             "UID=%s;PublicKey=%s;ServerName=www.bing.com;ProxyMethod=shadowsocks;"
             "EncryptionMethod=aes-gcm;NumConn=2;RemoteHost=127.0.0.1;RemotePort=%d;"
             "LocalHost=127.0.0.1;LocalPort=%d",
             UID_B64, p.pub_b64, p.server_port, local2);
    char *const sargv[] = {(char *)"ck-client", (char *)"-c", ssv, NULL};
    child_t c2;
    ASSERT_EQ_INT(0, child_spawn(&c2, CK_CLIENT_PATH, sargv, NULL));
    ASSERT_EQ_INT(0, child_wait_for(&c2, "session up", BOOT_MS));
    child_stop(&c2);

    /* AND A FLAG OVERRIDING AN ssv FIELD, which is its own code path: an
     * option string is edited as TEXT, and an override that appended
     * without removing the field it replaces would leave the key twice
     * over -- with the STALE one first, and therefore winning. So the
     * option string names an unroutable remote and -s names the real one:
     * a duplicate-leaving setter dials 192.0.2.1 and no session comes up.
     * Nothing else in this file exercises that path, because every other
     * ssv case only ever FILLS IN an absent field. */
    int local3 = free_port();
    ASSERT_TRUE(local3 > 0);
    char ssv2[1024];
    snprintf(ssv2, sizeof(ssv2),
             "UID=%s;PublicKey=%s;ServerName=www.bing.com;ProxyMethod=shadowsocks;"
             "EncryptionMethod=aes-gcm;NumConn=2;RemoteHost=192.0.2.1;RemotePort=443;"
             "LocalHost=127.0.0.1;LocalPort=%d",
             UID_B64, p.pub_b64, local3);
    char sport[16];
    snprintf(sport, sizeof(sport), "%d", p.server_port);
    char *const oargv[] = {(char *)"ck-client", (char *)"-c", ssv2,  (char *)"-s",
                           (char *)"127.0.0.1", (char *)"-p", sport, NULL};
    child_t c3;
    ASSERT_EQ_INT(0, child_spawn(&c3, CK_CLIENT_PATH, oargv, NULL));
    ASSERT_EQ_INT(0, child_wait_for(&c3, "session up", BOOT_MS));
    child_stop(&c3);

    pair_teardown(&p);
}

/* ------------------------------------------------------------------ */
/* Case 11: the defaults fill in what neither the config nor a flag gave */
/* ------------------------------------------------------------------ */

/* Go's three jsonOptional fields with defaults -- LocalHost 127.0.0.1,
 * LocalPort 1984, RemotePort 443 -- are filled in only where the document
 * left them empty. Every other case in this file names all three
 * explicitly, so without this one an implementation that dropped the
 * fill-ins entirely would pass the whole suite.
 *
 * NOTHING HERE BINDS 1984, AND THAT IS THE POINT OF THE REWRITE. The first
 * version proved the defaults by BINDING them, so its coverage was
 * conditional on a fixed, global, shared port happening to be free -- on a
 * machine where something else holds 1984 the case contributed nothing and
 * said so, which is a test that stops testing for an environmental reason.
 *
 * Instead the client is started one descriptor short of what the local
 * listener needs (RLIMIT_NOFILE 4: {0,1,2} plus the reactor's epoll, and
 * nothing left for a socket). It gets far enough to DECIDE the local
 * address and to report it, and then fails to open it -- so the decision
 * is observable in the error message without a bind ever succeeding:
 *
 *   unable to start the client (local address): local address:
 *   "127.0.0.1:1984": listener: cannot bind ...: Too many open files
 *
 * which carries the LocalHost default and the LocalPort default in one
 * string, and exits 3. RemotePort's default is on the earlier "remote is"
 * line, which main.c logs before it creates the reactor at all.
 *
 * The descriptor limit is the bracket measured by case 12 below; this case
 * borrows its lower rung. */
static void test_defaults_fill_in_the_omitted_fields(void) {
    char pub[64];
    derive_pub_b64(pub, sizeof(pub));
    char cfg[2048];
    /* RemoteHost only: no RemotePort, no LocalHost, no LocalPort. */
    make_client_config(cfg, sizeof(cfg), pub, "\"RemoteHost\":\"127.0.0.1\",");

    char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, NULL};
    child_t c;
    int code = run_to_exit_limited(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS, 4);
    printf("  [case 11] exit %d: %.200s\n", code, c.out);

    /* RemotePort defaulted to 443. */
    ASSERT_TRUE(strstr(c.out, "remote is 127.0.0.1:443") != NULL);
    /* LocalHost defaulted to 127.0.0.1 and LocalPort to 1984 -- both in
     * the address the listener was asked for and could not open. */
    ASSERT_EQ_INT(CK_EXIT_BIND_CODE, code);
    ASSERT_TRUE(strstr(c.out, "(local address)") != NULL);
    ASSERT_TRUE(strstr(c.out, "\"127.0.0.1:1984\"") != NULL);
}

/* ------------------------------------------------------------------ */
/* Case 12: exit 4, and the ServerName bound that used to be exit 4     */
/* ------------------------------------------------------------------ */

/* EXIT 4 IS THE ONE AN OPERATOR CANNOT AFFORD TO HAVE WRONG, and it was
 * the one code this suite left open: an independent reviewer turned
 * exit_code_for_stack_err's default arm from CK_EXIT_RUNTIME into
 * CK_EXIT_OK and all 63 tests stayed green. A runtime failure reported as
 * success loses a client silently, because a supervisor with
 * restart-on-failure sees a clean exit and stops.
 *
 * There is exactly ONE way ck-client can still reach 4, and this case
 * pins it with both of its neighbours:
 *
 *   (a) main's own `return CK_EXIT_RUNTIME` when cloak_signalfd_create
 *       fails -- reached by RLIMIT_NOFILE below.
 *   (b) exit_code_for_stack_err's DEFAULT ARM is now UNREACHABLE from any
 *       configuration, and part (b) of this case is what documents and
 *       enforces that, rather than pretending otherwise. See below.
 *
 * ---- (a) THE DESCRIPTOR BUDGET -------------------------------------
 *
 * ck-client's startup descriptor use is exact and ordered: the reactor's
 * epoll, then the local listener, then the signalfd. A limit one short of
 * a given step makes exactly that step fail. MEASURED, both builds:
 *
 *   3 descriptors -> execv itself cannot load the binary  -> 127
 *   4 descriptors -> the LISTENER cannot be opened        -> exit 3
 *   5 descriptors -> the SIGNALFD cannot be created       -> exit 4
 *   6 descriptors -> everything fits, the client runs     -> ready
 *
 * BOTH NEIGHBOURS OF 5 ARE ASSERTED, so this is a bracket and not a
 * claimed margin: a change that shifted the budget by one descriptor in
 * either direction fails here rather than quietly moving which failure an
 * operator sees. Six is also the whole startup inventory -- 0, 1, 2, the
 * epoll, the listener, the signalfd -- which is the same number case 6's
 * census arrives at from the other direction.
 *
 * ---- (b) THE DEFAULT ARM, AND WHY IT IS NOW DEAD --------------------
 *
 * The default arm covers three codes, and none of them can be reached
 * from this binary. The proof is short enough to write down:
 *
 *   ERR_ARG      cloak_client_stack_open returns it only for a NULL out,
 *                cfg, reactor or config, or for its own calloc failing.
 *                main passes four non-NULL pointers, unconditionally.
 *   ERR_PIPER    cloak_client_piper_init (src/client_piper.c:789) returns
 *                -1 only for a NULL pp/cfg/reactor, or for singleplex
 *                with a NULL new_session. The stack always supplies its
 *                own reactor and its own stack_new_session.
 *   ERR_CONNECTOR  cloak_client_connector_init's config checks are now
 *                all strictly weaker than the parser's, so a config that
 *                parses cannot fail them. What is left is allocation.
 *
 * THE THIRD USED TO BE REACHABLE, AND THAT WAS A DEFECT, NOT COVERAGE.
 * cloak_client_connector_init refuses a server_name longer than
 * CLOAK_CLIENT_SERVER_NAME_MAX (253) while the parser used to accept up
 * to CLOAK_MAX_HOST_LEN - 1 (255), so a 254-character ServerName parsed,
 * opened, resolved, listened, and then died with exit 4 and a message
 * naming no field -- and exit 4's own contract says retrying may help, so
 * a supervisor keyed on these codes restarted forever over a typo. 253 is
 * the correct bound (RFC 1035 sec. 2.3.4 with RFC 4343 give 255 OCTETS on
 * the wire, which is 253 presentation characters once the first label's
 * length prefix and the root's zero length are taken off; RFC 6066 sec. 3
 * requires the SNI HostName to be a valid DNS hostname, and Go bounds it
 * nowhere -- so fidelity does not decide it and the DNS limit does). The
 * PARSER moved, to 253, and an over-long name is now a CONFIGURATION
 * error that names the field.
 *
 * MEASURED BRACKET, all four rungs asserted below:
 *
 *   253 characters -> the client starts                        -> ready
 *   254 characters -> "ServerName is too long (254 bytes...)"  -> exit 2
 *   255 characters -> the same, from the same check            -> exit 2
 *   256 characters -> the same, from cloak_config_get_string's
 *                     own capacity check                       -> exit 2
 *
 * The 256 rung matters: it is the bound that was ALREADY there, and
 * asserting it alongside 254 is what shows the two checks now say the
 * same thing rather than one shadowing the other. And the case asserts
 * that "(first bring-up)" is ABSENT, because that string is exactly what
 * the defect used to print. */
static void test_runtime_exit_code_and_the_descriptor_budget(void) {
    char pub[64];
    derive_pub_b64(pub, sizeof(pub));
    char cfg[2048];
    make_client_config(cfg, sizeof(cfg), pub,
                       "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"443\","
                       "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"0\",");
    char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, NULL};

    { /* one short of the signalfd: RUNTIME, and it says what broke */
        child_t c;
        ASSERT_EQ_INT(4, run_to_exit_limited(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS, 5));
        ASSERT_TRUE(strstr(c.out, "unable to install the signal handler") != NULL);
        ASSERT_TRUE(strstr(c.out, "ck-client ready") == NULL);
    }
    { /* one short of the listener: BIND, not RUNTIME */
        child_t c;
        ASSERT_EQ_INT(3, run_to_exit_limited(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS, 4));
        ASSERT_TRUE(strstr(c.out, "(local address)") != NULL);
    }
    { /* exactly enough: the client runs */
        child_t c;
        ASSERT_EQ_INT(0, child_spawn_limited(&c, CK_CLIENT_PATH, argv, NULL, 6));
        ASSERT_EQ_INT(0, child_wait_for(&c, "ck-client ready", BOOT_MS));
        ASSERT_EQ_INT(0, child_stop(&c));
    }

    /* (b) the ServerName bound, four rungs, one process each.
     *
     * 253 RUNS -- so the bound is not merely "rejects long things", it is
     * placed exactly where the connector's is. The other three are refused
     * as CONFIGURATION errors naming the field, which is the whole point:
     * exit 2 tells a supervisor to stop, and the message tells the
     * operator which key to shorten. The three refusals run with NO
     * descriptor limit on purpose, even though it would be cheaper: with
     * one, a regression that put the old 255 bound back would fail the
     * listener first and report exit 3, and this case would then be
     * pinning the wrong thing. Without one it reproduces the defect's own
     * measurement exactly -- exit 4 and "(first bring-up)" -- which is
     * what both of the assertions below are written against. They cost
     * nothing in a correct build, because the config is rejected before
     * the reactor is ever created. */
    char name[CLOAK_MAX_HOST_LEN + 8];
    memset(name, 'a', sizeof(name));
    {
        name[253] = '\0'; /* 253 characters: the DNS presentation limit */
        char c253[2048];
        snprintf(c253, sizeof(c253),
                 "{\"ServerName\":\"%s\",\"ProxyMethod\":\"shadowsocks\","
                 "\"EncryptionMethod\":\"aes-gcm\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
                 "\"NumConn\":2,\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"443\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"0\"}",
                 name, UID_B64, pub);
        char *const a[] = {(char *)"ck-client", (char *)"-c", c253, NULL};
        child_t c;
        ASSERT_EQ_INT(0, child_spawn(&c, CK_CLIENT_PATH, a, NULL));
        ASSERT_EQ_INT(0, child_wait_for(&c, "ck-client ready", BOOT_MS));
        ASSERT_EQ_INT(0, child_stop(&c));
    }
    for (size_t len = 254; len <= 256; len++) {
        memset(name, 'a', sizeof(name));
        name[len] = '\0';
        char over[2048];
        snprintf(over, sizeof(over),
                 "{\"ServerName\":\"%s\",\"ProxyMethod\":\"shadowsocks\","
                 "\"EncryptionMethod\":\"aes-gcm\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
                 "\"NumConn\":2,\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"443\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"0\"}",
                 name, UID_B64, pub);
        char *const a[] = {(char *)"ck-client", (char *)"-c", over, NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit(&c, CK_CLIENT_PATH, a, NULL, EXIT_MS));
        /* The FIELD is named, and the length is the one that was given --
         * an operator gets told what to shorten and by how much. */
        char expect[64];
        snprintf(expect, sizeof(expect), "ServerName is too long (%zu bytes", len);
        ASSERT_TRUE(strstr(c.out, expect) != NULL);
        /* And it is NOT the old defect's line. "(first bring-up)" is the
         * typed edge exit 4 used to print for exactly this input. */
        ASSERT_TRUE(strstr(c.out, "(first bring-up)") == NULL);
    }

    /* AlternativeNames feeds the SAME connector field -- client_stack.c's
     * stack_pick_server_name chooses between ServerName and the alt names
     * per round, at RANDOM -- so an alt name the parser accepted and the
     * connector would not is the same defect with an intermittent trigger.
     * It is bounded at 253 too, and this is what says so.
     *
     * THIS one runs one descriptor short of the listener, unlike the three
     * above, and the reason is the randomness: with the old bound restored
     * the client would accept the alt name, pick ServerName on most rounds
     * and then RUN, so an unlimited child would sit there until the reap
     * deadline killed it. Starved of the listener it fails in
     * milliseconds, and the exit code still separates 2 from 3. */
    {
        memset(name, 'b', sizeof(name));
        name[254] = '\0';
        char alt[2048];
        snprintf(alt, sizeof(alt),
                 "{\"ServerName\":\"www.bing.com\",\"AlternativeNames\":[\"%s\"],"
                 "\"ProxyMethod\":\"shadowsocks\","
                 "\"EncryptionMethod\":\"aes-gcm\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
                 "\"NumConn\":2,\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"443\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"0\"}",
                 name, UID_B64, pub);
        char *const a[] = {(char *)"ck-client", (char *)"-c", alt, NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit_limited(&c, CK_CLIENT_PATH, a, NULL, EXIT_MS, 4));
        ASSERT_TRUE(strstr(c.out, "AlternativeNames entry is too long (254 bytes") != NULL);
    }
}

/* ------------------------------------------------------------------ */
/* Case 13: -verbosity, and the one arm of it that was undocumented     */
/* ------------------------------------------------------------------ */

/* main.c documents a -verbosity that is not a level name as a USAGE
 * error, exit 1. It was asserted nowhere, and a reviewer's mutation
 * turning it into exit 0 passed the whole suite -- a client that silently
 * treats a typo'd log level as success is a client whose logs an operator
 * then cannot find.
 *
 * The EFFECT is asserted too, from both sides of the same invocation: at
 * "error" the INFO lines are gone and the ERROR line remains; at "debug"
 * the INFO line is back. A cloak_log_set_level that did nothing would
 * pass an "is this level accepted" test and fail this one, because the
 * default level is already info. */
static void test_verbosity_is_validated_and_takes_effect(void) {
    const char *missing = "/nonexistent/ck-client-verbosity.json";
    {
        char *const argv[] = {(char *)"ck-client", (char *)"-verbosity", (char *)"chatty",
                              (char *)"-c", (char *)missing, NULL};
        child_t c;
        ASSERT_EQ_INT(1, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "unknown verbosity level \"chatty\"") != NULL);
        ASSERT_TRUE(strstr(c.out, "Usage of ck-client") != NULL);
        /* It stopped at the flag: the config it was given does not exist,
         * and a client that had gone on to load it would exit 2. */
        ASSERT_TRUE(strstr(c.out, "configuration error") == NULL);
    }
    {
        char *const argv[] = {(char *)"ck-client", (char *)"-verbosity", (char *)"error",
                              (char *)"-c", (char *)missing, NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "configuration error") != NULL);
        ASSERT_TRUE(strstr(c.out, "starting standalone mode") == NULL);
    }
    {
        char *const argv[] = {(char *)"ck-client", (char *)"-verbosity", (char *)"debug",
                              (char *)"-c", (char *)missing, NULL};
        child_t c;
        ASSERT_EQ_INT(2, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
        ASSERT_TRUE(strstr(c.out, "starting standalone mode") != NULL);
    }
}

/* ------------------------------------------------------------------ */
/* Case 14: KeepAlive is configured, carried, and consumed by nothing   */
/* ------------------------------------------------------------------ */

/* A GAP MADE AUDIBLE. cloak/client_stack.h records that keep_alive_sec is
 * parsed and then used by no one -- nothing in this port sets SO_KEEPALIVE
 * -- and a binary that silently ignores a setting an operator wrote down
 * is the shape of bug that is only ever found by packet capture. It cannot
 * be fixed here (the socket layer is a later module's), so it is WARNED
 * about at startup, and the warning is asserted, which is what stops the
 * gap from being quietly closed by forgetting about it.
 *
 * Run under the same descriptor limit case 11 uses, so this case binds
 * nothing and needs no server: the warning is emitted before the reactor
 * exists. */
static void test_keepalive_is_warned_about(void) {
    char pub[64];
    derive_pub_b64(pub, sizeof(pub));
    {
        char cfg[2048];
        make_client_config(cfg, sizeof(cfg), pub,
                           "\"RemoteHost\":\"127.0.0.1\",\"KeepAlive\":30,");
        char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, NULL};
        child_t c;
        (void)run_to_exit_limited(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS, 4);
        ASSERT_TRUE(strstr(c.out, "KeepAlive 30") != NULL);
        ASSERT_TRUE(strstr(c.out, "ignored") != NULL);
    }
    { /* And NOT warned about when it was never configured -- otherwise the
       * warning is noise every operator learns to skip. */
        char cfg[2048];
        make_client_config(cfg, sizeof(cfg), pub, "\"RemoteHost\":\"127.0.0.1\",");
        char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, NULL};
        child_t c;
        (void)run_to_exit_limited(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS, 4);
        ASSERT_TRUE(strstr(c.out, "KeepAlive") == NULL);
    }
}

/* ------------------------------------------------------------------ */
/* ONE FILE, TWO BINARIES (module 10b task 8)                           */
/* ------------------------------------------------------------------ */

/* NOTHING ABOVE THIS LINE CHANGED. Every case function, every helper and
 * every assertion is byte-for-byte what the single binary ran; the ONLY
 * change is which PROCESS runs which case, and that is decided by the
 * table below and by -DCK_CLI_PART on the two executables the build
 * makes from this one source file.
 *
 * WHY. The single test_ck_client_cli measured 63.1 s warm at -j4 under
 * ASan+UBSan against its own TIMEOUT 120 -- a 1.90x margin, under the
 * 1.91x floor module 9 declared. The per-case measurement that chose this
 * split is in the ms comments on each row, taken from one serial
 * ASan+UBSan run (cmd/ck-client/CMakeLists.txt records the totals). They
 * say something more useful than any single case does. A COUNTER ON THE
 * fork() SITE was added for the measurement (temporary instrumentation,
 * not shipped) and the two columns line up almost exactly:
 *
 *   children   1     2     3     5     6     8
 *   ms       ~900 ~1800 ~2750 ~4500 ~5400 ~7220
 *
 * THE UNIT OF COST IS A FORKED CHILD, ~0.92 s EACH under LeakSanitizer's
 * exit scan -- not an assertion, not a transfer. Across this file's 56
 * children and the server file's 42, the figure is 918 ms and 919 ms
 * respectively. Size a new case by counting its fork/exec calls and
 * multiplying.
 *
 * WITH ONE MEASURED EXCEPTION, which is the most expensive case in either
 * file and is expensive for a reason the rule does not predict:
 * test_proxy_flag_overrides_json forks TWO children and costs 9503 ms.
 * The other ~8.6 s is the client's RETRY BACKOFF -- the case waits for
 * "round failed" from a server that refuses the flag's proxy method, and
 * that wait is the stack's, not the sanitizer's. A case that waits on a
 * real protocol event has to be costed by measuring it, not by counting
 * forks. (918 ms/child above is this file's 54 OTHER children over its
 * 49.6 s; including this case's backoff it reads 1056 ms.)
 *
 * HOW A NEW CASE PICKS ITS HALF. Both halves print their own per-case
 * costs and their own total on every run, so the rule is mechanical: add
 * the row to the half whose printed total is smaller, then read the two
 * totals back off the next run. The halves are near-equal today under
 * ASan+UBSan -- 29.4 s and 29.5 s serially, 31-32 s each warm at -j4 --
 * and are meant to stay that way. UNDER ASAN, and deliberately so: in a
 * plain Debug build the same halves are 7.15 s and 0.60 s, because with
 * no LeakSanitizer a fork is nearly free and the Debug cost is almost all
 * test_proxy_flag_overrides_json's retry backoff. The sanitizer build is
 * the one with a TIMEOUT to protect and a suite that is 3x longer, so it
 * is the one the balance is struck against. They are NOT a
 * theme with a cost as an afterthought, though they do read as one --
 * CONFIG is the command line and the configuration document, RUNTIME is
 * what the started process then does and logs.
 *
 * WHY THE TABLE AND NOT #if AROUND THE CALL LIST. A case function that is
 * compiled but never reached would be a static function nobody calls, and
 * this tree is required to build with zero warnings under both gcc and
 * clang: -Wunused-function would fire on every case the other half owns.
 * Referencing all of them from one table compiles both halves whole and
 * runs half of each. THAT IS ALSO THE GUARD AGAINST LOSING A CASE: a case
 * function left OUT of this table is referenced by nothing and becomes a
 * -Wunused-function warning, which this tree treats as a failure. A split
 * that silently drops a case cannot get past the compiler. */

#define CK_CLI_CONFIG 1
#define CK_CLI_RUNTIME 2

#ifndef CK_CLI_PART
#error "CK_CLI_PART must be defined by the build (1 = config, 2 = runtime)"
#endif
#if CK_CLI_PART != CK_CLI_CONFIG && CK_CLI_PART != CK_CLI_RUNTIME
#error "CK_CLI_PART must be 1 (config) or 2 (runtime)"
#endif

typedef struct {
    const char *name;
    void (*fn)(void);
    int part;
} cli_case_t;

/* The ms figures are the measurement this split was chosen from, and they
 * are a READING of one serial ASan+UBSan run on one machine -- no test
 * fails if they drift. What the run prints is the live number; these are
 * here so the next reader can see what the halves were balanced against. */
static const cli_case_t k_cases[] = {
    {"version_and_help_exit_before_config",
     test_version_and_help_exit_before_config, CK_CLI_CONFIG},  /*  1796 ms */
    {"flags_override_json",
     test_flags_override_json, CK_CLI_CONFIG},  /*  1828 ms */
    {"local_host_flag_overrides_json",
     test_local_host_flag_overrides_json, CK_CLI_CONFIG},  /*   904 ms */
    {"proxy_flag_overrides_json",
     test_proxy_flag_overrides_json, CK_CLI_CONFIG},  /*  9889 ms */
    {"missing_remote_host_is_a_config_error",
     test_missing_remote_host_is_a_config_error, CK_CLI_CONFIG},  /*  1787 ms */
    {"plugin_mode_takes_an_ssv_string",
     test_plugin_mode_takes_an_ssv_string, CK_CLI_CONFIG},  /*  4524 ms */
    {"exit_codes_are_distinct",
     test_exit_codes_are_distinct, CK_CLI_CONFIG},  /*  4499 ms */
    {"config_from_a_file_and_from_ssv",
     test_config_from_a_file_and_from_ssv, CK_CLI_CONFIG},  /*  3680 ms */
    {"defaults_fill_in_the_omitted_fields",
     test_defaults_fill_in_the_omitted_fields, CK_CLI_CONFIG},  /*   899 ms */
    {"udp_is_honoured",
     test_udp_is_honoured, CK_CLI_RUNTIME},  /*  5444 ms */
    {"udp_without_numconn_names_numconn",
     test_udp_without_numconn_names_numconn, CK_CLI_RUNTIME},  /*  1806 ms */
    {"the_unordered_bit_is_on_the_wire",
     test_the_unordered_bit_is_on_the_wire, CK_CLI_RUNTIME},  /*  1819 ms */
    {"end_to_end_through_both_binaries",
     test_end_to_end_through_both_binaries, CK_CLI_RUNTIME},  /*  1902 ms */
    {"sigterm_is_clean_and_leaks_no_descriptor",
     test_sigterm_is_clean_and_leaks_no_descriptor, CK_CLI_RUNTIME},  /*  2296 ms */
    {"admin_flag_reaches_the_admin_api",
     test_admin_flag_reaches_the_admin_api, CK_CLI_RUNTIME},  /*  2774 ms */
    {"shutdown_bills_the_last_interval",
     test_shutdown_bills_the_last_interval, CK_CLI_RUNTIME},  /*  1910 ms */
    {"runtime_exit_code_and_the_descriptor_budget",
     test_runtime_exit_code_and_the_descriptor_budget, CK_CLI_RUNTIME},  /*  7223 ms */
    {"verbosity_is_validated_and_takes_effect",
     test_verbosity_is_validated_and_takes_effect, CK_CLI_RUNTIME},  /*  2691 ms */
    {"keepalive_is_warned_about",
     test_keepalive_is_warned_about, CK_CLI_RUNTIME},  /*  1823 ms */
};

TEST_MAIN_BEGIN()
    /* LINE-BUFFERED, DELIBERATELY. stdout here is a pipe, so libc would
     * block-buffer it and a ctest TIMEOUT would arrive with
     * "<end of output>" and nothing else -- which is what the reviewer of
     * this file measured under 2x CPU oversubscription. A flake with no
     * diagnostic is a flake nobody can act on; line buffering costs
     * nothing at this volume and makes a timeout say which case it
     * reached. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    unsigned ran = 0;
    uint64_t total_ms = 0;
    for (size_t i = 0; i < sizeof(k_cases) / sizeof(k_cases[0]); i++) {
        if (k_cases[i].part != CK_CLI_PART) {
            continue;
        }
        uint64_t t0 = now_ms();
        k_cases[i].fn();
        uint64_t took = now_ms() - t0;
        total_ms += took;
        ran++;
        printf("[case] %-46s %6llu ms\n", k_cases[i].name,
               (unsigned long long)took);
    }
    /* A half that ran NOTHING is a build that mis-set CK_CLI_PART, and it
     * would otherwise print "All tests passed" and go green. */
    ASSERT_TRUE(ran > 0);
    printf("[part %d] %u case(s), %llu ms total\n", CK_CLI_PART, ran,
           (unsigned long long)total_ms);
TEST_MAIN_END()
