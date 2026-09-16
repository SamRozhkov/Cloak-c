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
 *   4. -u is REFUSED, naming unordered mode, rather than silently
 *      carrying TCP under a caller that asked for datagrams. The config
 *      key "UDP": true is refused too, and with a different exit code,
 *      because one is a wrong command line and the other a wrong config.
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
#include "cloak/crypto.h"
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

/* env is a NULL-terminated list of "NAME=VALUE" strings set in the child
 * only, so a case that does not ask for plugin mode cannot inherit it. */
static int child_spawn(child_t *c, const char *path, char *const argv[],
                       const char *const env[]) {
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

/* SIGTERM, then reap. Used by every case that started something. */
static int child_stop(child_t *c) {
    if (c->pid <= 0) {
        return 0;
    }
    kill(c->pid, SIGTERM);
    return child_reap(c, EXIT_MS);
}

static int run_to_exit(child_t *c, const char *path, char *const argv[],
                       const char *const env[], int timeout_ms) {
    if (child_spawn(c, path, argv, env) != 0) {
        return -1;
    }
    return child_reap(c, timeout_ms);
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
static const char PRIV_B64[] = "SN6EG6BhjnLLpGCMqrLzZuSNmEWXOJgEnqN0uaPihgs=";
/* Two distinct 16-byte UIDs: one ordinary, one for the admin API. */
static const char UID_B64[] = "MTIzNDU2Nzg5MGFiY2RlZg==";       /* "1234567890abcdef" */
static const char ADMIN_UID_B64[] = "QURNSU5hZG1pbjAxMjM0NQ=="; /* "ADMINadmin012345" */

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

/* extra is spliced in verbatim, so a case can add or replace any key. */
static void make_server_config(char *out, size_t cap, int bind_port, const char *proxy_addr,
                               const char *extra) {
    snprintf(out, cap,
             "{"
             "\"ProxyBook\":{\"shadowsocks\":[\"tcp\",\"%s\"]},"
             "\"BindAddr\":[\"127.0.0.1:%d\"],"
             "\"BypassUID\":[\"%s\"],"
             "\"RedirAddr\":\"127.0.0.1:1\","
             "\"PrivateKey\":\"%s\","
             "%s"
             "\"KeepAlive\":0"
             "}",
             proxy_addr, bind_port, UID_B64, PRIV_B64, extra);
}

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
static int pair_start_server(pair_t *p, const char *server_extra) {
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
    make_server_config(cfg, sizeof(cfg), p->server_port, upstream, server_extra);

    char *const argv[] = {(char *)"ck-server", (char *)"-c", cfg, NULL};
    if (child_spawn(&p->server, CK_SERVER_PATH, argv, NULL) != 0) {
        return -1;
    }
    return child_wait_for(&p->server, "ck-server ready", BOOT_MS);
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
/* Case 4: -u is refused, naming unordered mode                          */
/* ------------------------------------------------------------------ */

static void test_udp_is_refused(void) {
    char pub[64];
    derive_pub_b64(pub, sizeof(pub));
    char cfg[2048];
    make_client_config(cfg, sizeof(cfg), pub,
                       "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"443\",");

    /* The FLAG: a wrong command line, so exit 1. */
    char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, (char *)"-u", NULL};
    child_t c;
    ASSERT_EQ_INT(1, run_to_exit(&c, CK_CLIENT_PATH, argv, NULL, EXIT_MS));
    ASSERT_TRUE(strstr(c.out, "unordered") != NULL);
    /* And it is refused rather than accepted-then-ignored: nothing was
     * started, so there is no readiness line. */
    ASSERT_TRUE(strstr(c.out, "ck-client ready") == NULL);

    /* The CONFIG KEY: a wrong configuration, so exit 2. Two inputs, two
     * classes, two codes -- which is the distinction exit codes exist
     * for, and it is asserted rather than described. */
    char udpcfg[2048];
    make_client_config(udpcfg, sizeof(udpcfg), pub,
                       "\"RemoteHost\":\"127.0.0.1\",\"RemotePort\":\"443\","
                       "\"LocalPort\":\"1984\",\"UDP\":true,");
    char *const uargv[] = {(char *)"ck-client", (char *)"-c", udpcfg, NULL};
    child_t u;
    ASSERT_EQ_INT(2, run_to_exit(&u, CK_CLIENT_PATH, uargv, NULL, EXIT_MS));
    ASSERT_TRUE(strstr(u.out, "unordered") != NULL);
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

    kill(p.client.pid, SIGTERM);
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
 * case points at the same echo upstream every other case uses. A session
 * that was NOT recognised as admin is dispatched to the proxy instead, so
 * the HTTP request text is relayed to that upstream and comes back
 * verbatim -- a wrong answer that says exactly what went wrong, rather
 * than a timeout that says nothing. */
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
    deadline = now_ms() + 15000;
    while (got + 1 < sizeof(resp) && now_ms() < deadline) {
        struct pollfd rp = {app, POLLIN, 0};
        if (poll(&rp, 1, 50) <= 0) {
            continue;
        }
        ssize_t r = read(app, resp + got, sizeof(resp) - 1 - got);
        if (r > 0) {
            got += (size_t)r;
            resp[got] = '\0';
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

    pair_teardown(&p);
    unlink("ck_client_test_admin.db");
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
 * fill-ins entirely would pass the whole suite. The assertion is on the
 * two lines that report what was actually used, not on a flag being
 * echoed back.
 *
 * No server is needed: the point is what the client BOUND and what it is
 * DIALLING, both of which it reports before the first round can finish. */
static void test_defaults_fill_in_the_omitted_fields(void) {
    char pub[64];
    derive_pub_b64(pub, sizeof(pub));
    char cfg[2048];
    /* RemoteHost only: no RemotePort, no LocalHost, no LocalPort. */
    make_client_config(cfg, sizeof(cfg), pub, "\"RemoteHost\":\"127.0.0.1\",");

    char *const argv[] = {(char *)"ck-client", (char *)"-c", cfg, NULL};
    child_t c;
    ASSERT_EQ_INT(0, child_spawn(&c, CK_CLIENT_PATH, argv, NULL));
    if (child_wait_for(&c, "ck-client ready", BOOT_MS) != 0) {
        /* THE ONLY ACCEPTABLE REASON not to be ready is that port 1984 is
         * taken by something else on this machine, and that reason has to
         * be PROVEN rather than assumed: the client must have exited with
         * the bind code, naming the local address. Anything else -- a
         * configuration error because a default was not applied, most of
         * all -- is a failure of this case, not a skip.
         *
         * This is not a hypothetical. The first draft skipped on any
         * failure to become ready, and a mutation that deleted the
         * LocalHost fill-in walked straight through it: the client exited
         * 2 with "LocalHost cannot be empty" and this case reported a
         * skip. A skip branch that cannot tell why it is skipping is a
         * test that has quietly stopped testing. */
        int code = child_reap(&c, EXIT_MS);
        if (code == CK_EXIT_BIND_CODE && strstr(c.out, "1984") != NULL) {
            printf("  [case 11] port 1984 is busy on this machine; skipped\n");
            return;
        }
        printf("  [case 11] client did not become ready, exit %d: %.300s\n", code, c.out);
        ASSERT_TRUE(0);
        return;
    }
    ASSERT_TRUE(strstr(c.out, "remote is 127.0.0.1:443") != NULL);
    ASSERT_TRUE(strstr(c.out, "listening on TCP 127.0.0.1:1984") != NULL);
    ASSERT_EQ_INT(0, child_stop(&c));
}

TEST_MAIN_BEGIN()
    test_version_and_help_exit_before_config();
    test_flags_override_json();
    test_proxy_flag_overrides_json();
    test_missing_remote_host_is_a_config_error();
    test_udp_is_refused();
    test_end_to_end_through_both_binaries();
    test_sigterm_is_clean_and_leaks_no_descriptor();
    test_admin_flag_reaches_the_admin_api();
    test_plugin_mode_takes_an_ssv_string();
    test_exit_codes_are_distinct();
    test_config_from_a_file_and_from_ssv();
    test_defaults_fill_in_the_omitted_fields();
TEST_MAIN_END()
