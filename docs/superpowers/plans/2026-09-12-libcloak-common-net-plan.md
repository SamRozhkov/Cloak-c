# libcloak-common: Listener, Dialer and Relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `libcloak-common` the three socket primitives both binaries need — a reactor-driven TCP listener, a non-blocking connector, and a bidirectional relay that splices two sockets with backpressure — so the server dispatcher and the client's local proxy front end can be written without either inventing its own socket plumbing.

**Architecture:** All three are thin, single-responsibility wrappers over the existing `cloak_reactor_t`, holding no policy: the listener turns an address string into accepted file descriptors, the dialer turns an address into one connected file descriptor, and the relay moves bytes between two file descriptors until one of them ends. The relay is the piece that makes the spec's event-driven-splicing model concrete: each direction owns a byte queue, a full queue deregisters read interest on its source, and a drained queue re-arms it. Name resolution is deliberately split out of the dialer into a separate blocking call, so callers resolve once at startup rather than stalling the single-threaded reactor on DNS per connection. This plan also relocates the existing `cloak_bytequeue_t` from `libcloak-mux` to `libcloak-common`, where the relay needs it and where a general-purpose ring buffer belongs.

**Tech Stack:** C11, CMake, POSIX sockets (`getaddrinfo`, `accept4`, non-blocking `connect`), CTest with the project's existing assert-based test framework.

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` (§3 component layout and the single-threaded-reactor consequences; §6's "Data plane" paragraph, which this plan's relay implements; §7, whose `goWeb()` is the relay's first caller)

## Global Constraints

- Language: C11, `-Wall -Wextra` clean. Project code must produce zero warnings; the vendored `cjson` target keeps its own `-w`.
- Platform: Linux only (spec §2). POSIX APIs are reached by defining `_POSIX_C_SOURCE 200809L` as the first line of the `.c` file that needs them — the convention in `libcloak-common/src/reactor.c`. `accept4` and `getaddrinfo`'s `AI_*` flags additionally need `_GNU_SOURCE`; where a file needs that, define `_GNU_SOURCE` **instead of** `_POSIX_C_SOURCE` (it implies it) and say so in a comment on the line.
- Naming: every public symbol is prefixed `cloak_`; public headers live in `libcloak-common/include/cloak/` and use `CLOAK_<NAME>_H` include guards. Follow the doc-comment style of the existing headers (`crypto.h`, `reactor.h`, `config.h`): state the contract, the failure modes, and anything a caller could get wrong.
- **The reactor is edge-triggered.** `cloak_reactor_add_fd` registers with `EPOLLET` and forces the fd non-blocking itself. Every readable callback must `read()` until `EAGAIN`, and every writable callback must `write()` until `EAGAIN` or its buffer empties, or the callback will not fire again for data that was already available. The reactor also folds `EPOLLHUP`/`EPOLLERR` into `CLOAK_REACTOR_READABLE` regardless of the registered interest mask, so a writable-only registration can still be dispatched with `CLOAK_REACTOR_READABLE` set — callers must attempt a read (or check `SO_ERROR`) to tell a real hangup from genuine data.
- Ownership: each of these objects owns the file descriptors it is given or creates, and closes them in its own destroy/close path. A callback that hands a fd to another owner (the listener's accept callback handing off an accepted fd) transfers ownership at that moment.
- No allocation on the data path. The relay allocates its two queues once at start.
- Errors follow the project's existing convention: return 0/-1, and where a human-readable reason is useful, write it into a caller-supplied `char *err, size_t err_cap` (which may be NULL), exactly as `cloak/config.h`'s parsers do.
- Tests: one `test_<unit>.c` per unit in `libcloak-common/tests/`, registered in `libcloak-common/tests/CMakeLists.txt`, using `test_framework.h`. Socket tests use loopback or `socketpair` and drive the real reactor — no mocks. **Append to the two `CMakeLists.txt` files; never rewrite them.**
- Build and test command (run from the repository or worktree root — the project targets Linux, so all builds go through the existing `cloak-c-dev` image; adjust the `-w` path if your worktree differs):

  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src cloak-c-dev bash -c \
    'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
  ```

  Single test: add `-R test_relay` to `ctest`. Sanitizer build: substitute `-B build-asan` with `-DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"`.
- Baseline: 23 tests pass before this plan; 26 after it (bytequeue's existing test moves rather than adding one).
- Reference implementation: the Go original at `/Users/sam/Cloak`. The relay mirrors `internal/common/copy.go`'s `Copy` (both directions torn down together on the first EOF or error), and the dispatcher's `goWeb` in `internal/server/dispatcher.go` is the shape of its first caller.

---

### Task 1: Relocate `cloak_bytequeue_t` to `libcloak-common`

The relay needs a byte ring buffer, and the one that exists lives in `libcloak-mux`. It is a general-purpose ring buffer with no multiplexing concepts in it, so it belongs one layer down. Moving it now avoids `libcloak-common` depending upward on `libcloak-mux`, which would invert the project's layering.

This task changes no code: the public include path (`cloak/bytequeue.h`) is identical before and after, and `libcloak-mux` links `cloak-common` PUBLIC already, so every existing consumer keeps compiling untouched.

**Files:**
- Move: `libcloak-mux/include/cloak/bytequeue.h` → `libcloak-common/include/cloak/bytequeue.h`
- Move: `libcloak-mux/src/bytequeue.c` → `libcloak-common/src/bytequeue.c`
- Move: `libcloak-mux/tests/test_bytequeue.c` → `libcloak-common/tests/test_bytequeue.c`
- Modify: `libcloak-mux/CMakeLists.txt` (drop `src/bytequeue.c`)
- Modify: `libcloak-mux/tests/CMakeLists.txt` (drop the `test_bytequeue` block)
- Modify: `libcloak-common/CMakeLists.txt` (add `src/bytequeue.c`)
- Modify: `libcloak-common/tests/CMakeLists.txt` (add the `test_bytequeue` block)

**Interfaces:**
- Consumes: nothing.
- Produces: `cloak/bytequeue.h` available to `libcloak-common` itself and, transitively, to everything that links it. The API is unchanged: `cloak_bytequeue_init/destroy/write/read/peek/close/len/free_space/is_eof`.

- [ ] **Step 1: Move the three files with git**

```bash
git mv libcloak-mux/include/cloak/bytequeue.h libcloak-common/include/cloak/bytequeue.h
git mv libcloak-mux/src/bytequeue.c libcloak-common/src/bytequeue.c
git mv libcloak-mux/tests/test_bytequeue.c libcloak-common/tests/test_bytequeue.c
```

Do not edit the contents of any of the three. `#include "cloak/bytequeue.h"` resolves identically from both libraries' include directories.

- [ ] **Step 2: Update `libcloak-mux/CMakeLists.txt`**

Delete the `src/bytequeue.c` line from the `add_library(cloak-mux STATIC ...)` source list, leaving the rest of the list and the `target_link_libraries(cloak-mux PUBLIC cloak-common)` line exactly as they are.

- [ ] **Step 3: Update `libcloak-mux/tests/CMakeLists.txt`**

Delete the four-line `test_bytequeue` block (`add_executable` / `target_include_directories` / `target_link_libraries` / `add_test`). Leave every other block untouched.

- [ ] **Step 4: Update `libcloak-common/CMakeLists.txt`**

Add `src/bytequeue.c` to the `cloak-common` source list, immediately after `src/base64.c`.

- [ ] **Step 5: Update `libcloak-common/tests/CMakeLists.txt`**

Append:

```cmake
add_executable(test_bytequeue test_bytequeue.c)
target_include_directories(test_bytequeue PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_bytequeue PRIVATE cloak-common)
add_test(NAME test_bytequeue COMMAND test_bytequeue)
```

- [ ] **Step 6: Verify nothing broke**

Run the full suite. Expected: still exactly 23 tests, all passing — the same set as before, with `test_bytequeue` now built from `libcloak-common/tests/`. A link error naming `cloak_bytequeue_*` means a CMake list was edited wrong; a "No such file" means a `git mv` was missed.

- [ ] **Step 7: Commit**

```bash
git add -A libcloak-mux libcloak-common
git commit -m "Move bytequeue from libcloak-mux to libcloak-common"
```

---

### Task 2: `cloak_listener_t` — reactor-driven TCP listener

Turns one address string from `BindAddr` (server) or `LocalHost`/`LocalPort` (client) into a listening socket registered with the reactor, handing each accepted connection to a callback.

**Files:**
- Create: `libcloak-common/include/cloak/net.h`
- Create: `libcloak-common/src/listener.c`
- Create: `libcloak-common/tests/test_listener.c`
- Modify: `libcloak-common/CMakeLists.txt` (add `src/listener.c`)
- Modify: `libcloak-common/tests/CMakeLists.txt` (register `test_listener`)

**Interfaces:**
- Consumes: `cloak_reactor_t` (`cloak/reactor.h`) — `cloak_reactor_add_fd`, `cloak_reactor_remove_fd`, `CLOAK_REACTOR_READABLE`.
- Produces, all declared in the new `cloak/net.h`:
  - `typedef void (*cloak_listener_accept_cb)(cloak_listener_t *l, int fd, void *userdata);`
  - `int cloak_listener_open(cloak_listener_t *l, cloak_reactor_t *r, const char *addr, cloak_listener_accept_cb cb, void *userdata, char *err, size_t err_cap);`
  - `void cloak_listener_close(cloak_listener_t *l);`
  - `int cloak_listener_port(const cloak_listener_t *l);`
  - `int cloak_net_split_hostport(const char *addr, char *host, size_t host_cap, char *port, size_t port_cap);` — shared with Task 3.

- [ ] **Step 1: Write the failing test**

Create `libcloak-common/tests/test_listener.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/net.h"
#include "test_framework.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void test_split_hostport(void) {
    char host[64];
    char port[16];

    ASSERT_EQ_INT(0, cloak_net_split_hostport("127.0.0.1:1984", host, sizeof(host),
                                              port, sizeof(port)));
    ASSERT_EQ_INT(0, strcmp(host, "127.0.0.1"));
    ASSERT_EQ_INT(0, strcmp(port, "1984"));

    /* an empty host means "every interface", the ":443" form Go's BindAddr uses */
    ASSERT_EQ_INT(0, cloak_net_split_hostport(":443", host, sizeof(host), port, sizeof(port)));
    ASSERT_EQ_INT(0, strcmp(host, ""));
    ASSERT_EQ_INT(0, strcmp(port, "443"));

    /* bracketed IPv6 */
    ASSERT_EQ_INT(0, cloak_net_split_hostport("[::1]:443", host, sizeof(host),
                                              port, sizeof(port)));
    ASSERT_EQ_INT(0, strcmp(host, "::1"));
    ASSERT_EQ_INT(0, strcmp(port, "443"));

    ASSERT_EQ_INT(0, cloak_net_split_hostport("[::]:8080", host, sizeof(host),
                                              port, sizeof(port)));
    ASSERT_EQ_INT(0, strcmp(host, "::"));
    ASSERT_EQ_INT(0, strcmp(port, "8080"));

    /* a hostname, not an address */
    ASSERT_EQ_INT(0, cloak_net_split_hostport("localhost:51443", host, sizeof(host),
                                              port, sizeof(port)));
    ASSERT_EQ_INT(0, strcmp(host, "localhost"));
    ASSERT_EQ_INT(0, strcmp(port, "51443"));

    /* rejections */
    ASSERT_EQ_INT(-1, cloak_net_split_hostport("no-port", host, sizeof(host),
                                               port, sizeof(port)));
    ASSERT_EQ_INT(-1, cloak_net_split_hostport("", host, sizeof(host), port, sizeof(port)));
    ASSERT_EQ_INT(-1, cloak_net_split_hostport("host:", host, sizeof(host),
                                               port, sizeof(port)));
    /* unbracketed IPv6 is ambiguous and rejected, matching Go's net.SplitHostPort */
    ASSERT_EQ_INT(-1, cloak_net_split_hostport("::1:443", host, sizeof(host),
                                               port, sizeof(port)));
    /* a host that does not fit */
    char tiny[4];
    ASSERT_EQ_INT(-1, cloak_net_split_hostport("127.0.0.1:1984", tiny, sizeof(tiny),
                                               port, sizeof(port)));
}

struct accept_capture {
    cloak_reactor_t *reactor;
    int accepted_fd;
    int accept_count;
    char first_byte;
};

static void on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    struct accept_capture *cap = userdata;
    cap->accept_count++;
    cap->accepted_fd = fd;

    /* read the byte the client sent, to prove this is the same connection */
    char c = 0;
    ssize_t n = read(fd, &c, 1);
    if (n == 1) {
        cap->first_byte = c;
    }
    cloak_reactor_stop(cap->reactor);
}

/* Connects to 127.0.0.1:port with a blocking socket and sends one byte. */
static int connect_and_send(int port, char byte) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    if (write(fd, &byte, 1) != 1) {
        close(fd);
        return -1;
    }
    return fd;
}

static void test_accepts_a_connection(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct accept_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;
    cap.accepted_fd = -1;

    cloak_listener_t l;
    char err[128] = {0};
    /* port 0 asks the kernel for a free port */
    ASSERT_EQ_INT(0, cloak_listener_open(&l, r, "127.0.0.1:0", on_accept, &cap,
                                         err, sizeof(err)));

    int port = cloak_listener_port(&l);
    ASSERT_TRUE(port > 0);

    int client = connect_and_send(port, 'Q');
    ASSERT_TRUE(client >= 0);

    cloak_reactor_run(r);

    ASSERT_EQ_INT(1, cap.accept_count);
    ASSERT_TRUE(cap.accepted_fd >= 0);
    ASSERT_EQ_INT('Q', cap.first_byte);

    if (cap.accepted_fd >= 0) {
        close(cap.accepted_fd);
    }
    if (client >= 0) {
        close(client);
    }
    cloak_listener_close(&l);
    cloak_reactor_destroy(r);
}

struct multi_capture {
    cloak_reactor_t *reactor;
    int accept_count;
    int fds[4];
};

static void on_accept_multi(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    struct multi_capture *cap = userdata;
    if (cap->accept_count < 4) {
        cap->fds[cap->accept_count] = fd;
    }
    cap->accept_count++;
    if (cap->accept_count == 3) {
        cloak_reactor_stop(cap->reactor);
    }
}

static void test_drains_all_pending_connections(void) {
    /* The reactor is edge-triggered: if the accept callback stops after one
     * accept, the two connections that arrived in the same edge are never
     * reported. This is the test that catches that. */
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct multi_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;

    cloak_listener_t l;
    char err[128] = {0};
    ASSERT_EQ_INT(0, cloak_listener_open(&l, r, "127.0.0.1:0", on_accept_multi, &cap,
                                         err, sizeof(err)));
    int port = cloak_listener_port(&l);
    ASSERT_TRUE(port > 0);

    int clients[3];
    for (int i = 0; i < 3; i++) {
        clients[i] = connect_and_send(port, (char)('a' + i));
        ASSERT_TRUE(clients[i] >= 0);
    }

    cloak_reactor_run(r);
    ASSERT_EQ_INT(3, cap.accept_count);

    for (int i = 0; i < 3; i++) {
        if (cap.fds[i] >= 0) {
            close(cap.fds[i]);
        }
        close(clients[i]);
    }
    cloak_listener_close(&l);
    cloak_reactor_destroy(r);
}

static void test_open_rejects_bad_input(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_listener_t l;
    char err[128];

    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_listener_open(&l, r, "not-an-address", on_accept, NULL,
                                          err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');

    /* port 1 is privileged: binding it as a normal user fails. Skip the
     * assertion when running as root, where it would succeed. */
    if (geteuid() != 0) {
        err[0] = '\0';
        ASSERT_EQ_INT(-1, cloak_listener_open(&l, r, "127.0.0.1:1", on_accept, NULL,
                                              err, sizeof(err)));
        ASSERT_TRUE(err[0] != '\0');
    }

    cloak_reactor_destroy(r);
}

static void test_two_listeners_on_one_reactor(void) {
    /* The server binds every entry in BindAddr, so two listeners must
     * coexist on one reactor without confusing each other's callbacks. */
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct accept_capture cap_a;
    struct accept_capture cap_b;
    memset(&cap_a, 0, sizeof(cap_a));
    memset(&cap_b, 0, sizeof(cap_b));
    cap_a.reactor = r;
    cap_b.reactor = r;
    cap_a.accepted_fd = -1;
    cap_b.accepted_fd = -1;

    cloak_listener_t la;
    cloak_listener_t lb;
    char err[128] = {0};
    ASSERT_EQ_INT(0, cloak_listener_open(&la, r, "127.0.0.1:0", on_accept, &cap_a,
                                         err, sizeof(err)));
    ASSERT_EQ_INT(0, cloak_listener_open(&lb, r, "127.0.0.1:0", on_accept, &cap_b,
                                         err, sizeof(err)));
    ASSERT_TRUE(cloak_listener_port(&la) != cloak_listener_port(&lb));

    int client = connect_and_send(cloak_listener_port(&lb), 'B');
    ASSERT_TRUE(client >= 0);
    cloak_reactor_run(r);

    ASSERT_EQ_INT(0, cap_a.accept_count);
    ASSERT_EQ_INT(1, cap_b.accept_count);
    ASSERT_EQ_INT('B', cap_b.first_byte);

    if (cap_b.accepted_fd >= 0) {
        close(cap_b.accepted_fd);
    }
    close(client);
    cloak_listener_close(&la);
    cloak_listener_close(&lb);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_split_hostport();
    test_accepts_a_connection();
    test_drains_all_pending_connections();
    test_open_rejects_bad_input();
    test_two_listeners_on_one_reactor();
TEST_MAIN_END()
```

- [ ] **Step 2: Run the test to verify it fails**

Build. Expected: FAIL — `cloak/net.h: No such file or directory`.

- [ ] **Step 3: Write the header**

Create `libcloak-common/include/cloak/net.h`:

```c
#ifndef CLOAK_NET_H
#define CLOAK_NET_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/bytequeue.h"
#include "cloak/reactor.h"

/* Socket primitives shared by both binaries: a listener that turns an
 * address string into accepted connections, a connector that turns one
 * into a connected socket, and a relay that splices two sockets together.
 *
 * All three are reactor-driven and never block (with the single, clearly
 * marked exception of cloak_net_resolve, which performs a synchronous DNS
 * lookup and must therefore be called at startup, not per connection).
 *
 * Failure reporting matches the rest of this library: 0/-1, with a
 * human-readable reason written into a caller-supplied err buffer that may
 * be NULL. */

/* Splits "host:port" into its parts, matching Go's net.SplitHostPort
 * closely enough for the address forms Cloak's configs use:
 *   "127.0.0.1:1984"  -> host "127.0.0.1", port "1984"
 *   ":443"            -> host "",          port "443"   (all interfaces)
 *   "[::1]:443"       -> host "::1",       port "443"
 *   "localhost:51443" -> host "localhost", port "51443"
 * An IPv6 address MUST be bracketed; an unbracketed one is ambiguous and
 * rejected. Returns 0 on success, -1 if there is no port, the port is
 * empty, or either part does not fit its buffer (including the NUL). */
int cloak_net_split_hostport(const char *addr, char *host, size_t host_cap,
                             char *port, size_t port_cap);

typedef struct cloak_listener cloak_listener_t;

/* Fired once per accepted connection. fd is an already-non-blocking,
 * connected socket, and OWNERSHIP OF IT PASSES TO THIS CALLBACK: the
 * listener never closes it, so the callback must either take
 * responsibility for closing it or hand it to something that will (a
 * relay, a session). Losing the fd here leaks a descriptor. */
typedef void (*cloak_listener_accept_cb)(cloak_listener_t *l, int fd, void *userdata);

struct cloak_listener {
    cloak_reactor_t *reactor;
    int fd;
    int port; /* the bound port, resolved even when addr asked for port 0 */
    cloak_listener_accept_cb on_accept;
    void *on_accept_userdata;
};

/* Binds and listens on addr (see cloak_net_split_hostport for the accepted
 * forms), registers the socket with r, and calls cb for every connection
 * accepted from then on. An empty host binds every interface, dual-stack
 * where the kernel allows it. SO_REUSEADDR is always set, so a restart does
 * not have to wait out TIME_WAIT. Port 0 asks the kernel to choose a free
 * port, readable afterwards via cloak_listener_port.
 *
 * Returns 0 on success, -1 with the reason in err on a malformed address,
 * a resolution failure, or a socket/bind/listen failure. On failure l is
 * left safe to pass to cloak_listener_close. */
int cloak_listener_open(cloak_listener_t *l, cloak_reactor_t *r, const char *addr,
                        cloak_listener_accept_cb cb, void *userdata,
                        char *err, size_t err_cap);

/* Unregisters and closes the listening socket. Does NOT touch any fd
 * already handed to the accept callback -- those belong to whoever took
 * them. Idempotent, and safe on a listener left zeroed by a failed open. */
void cloak_listener_close(cloak_listener_t *l);

/* The bound port, or -1 if the listener is not open. */
int cloak_listener_port(const cloak_listener_t *l);

#endif
```

Note for the implementer: Tasks 3 and 4 append their own declarations to this same header, before the final `#endif`. Leave it tidy.

- [ ] **Step 4: Write the implementation**

Create `libcloak-common/src/listener.c`:

```c
/* _GNU_SOURCE (rather than _POSIX_C_SOURCE) for accept4; it implies the
 * POSIX definitions this file also needs. */
#define _GNU_SOURCE
#include "cloak/net.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int set_err(char *err, size_t err_cap, const char *fmt, ...) {
    if (err != NULL && err_cap > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, err_cap, fmt, ap);
        va_end(ap);
    }
    return -1;
}

int cloak_net_split_hostport(const char *addr, char *host, size_t host_cap,
                             char *port, size_t port_cap) {
    if (addr == NULL || host == NULL || port == NULL || host_cap == 0 || port_cap == 0) {
        return -1;
    }

    const char *host_start;
    size_t host_len;
    const char *colon;

    if (addr[0] == '[') {
        const char *close_bracket = strchr(addr, ']');
        if (close_bracket == NULL || close_bracket[1] != ':') {
            return -1;
        }
        host_start = addr + 1;
        host_len = (size_t)(close_bracket - host_start);
        colon = close_bracket + 1;
    } else {
        colon = strrchr(addr, ':');
        if (colon == NULL) {
            return -1;
        }
        /* an unbracketed address with more than one colon is an ambiguous
         * bare IPv6 literal -- rejected, as Go's net.SplitHostPort does */
        if (memchr(addr, ':', (size_t)(colon - addr)) != NULL) {
            return -1;
        }
        host_start = addr;
        host_len = (size_t)(colon - addr);
    }

    const char *port_start = colon + 1;
    size_t port_len = strlen(port_start);
    if (port_len == 0) {
        return -1;
    }
    if (host_len + 1 > host_cap || port_len + 1 > port_cap) {
        return -1;
    }

    memcpy(host, host_start, host_len);
    host[host_len] = '\0';
    memcpy(port, port_start, port_len + 1);
    return 0;
}

/* Reads back the port the socket is actually bound to, which is the only
 * way to learn it when the caller asked for port 0. */
static int bound_port(int fd) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &len) != 0) {
        return -1;
    }
    if (ss.ss_family == AF_INET) {
        return ntohs(((struct sockaddr_in *)&ss)->sin_port);
    }
    if (ss.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    }
    return -1;
}

static void listener_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    (void)events;
    cloak_listener_t *l = userdata;

    /* Edge-triggered: drain every pending connection, or the ones that
     * arrived within this same edge are never reported again. */
    for (;;) {
        int conn = accept4(l->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (conn < 0) {
            if (errno == EINTR) {
                continue;
            }
            /* EAGAIN/EWOULDBLOCK: drained. Anything else (ECONNABORTED, a
             * per-connection error) is also not fatal to the listener --
             * stop draining and wait for the next edge. */
            return;
        }
        if (l->on_accept != NULL) {
            l->on_accept(l, conn, l->on_accept_userdata);
        } else {
            close(conn);
        }
    }
}

int cloak_listener_open(cloak_listener_t *l, cloak_reactor_t *r, const char *addr,
                        cloak_listener_accept_cb cb, void *userdata,
                        char *err, size_t err_cap) {
    if (l == NULL || r == NULL || addr == NULL) {
        return set_err(err, err_cap, "listener: invalid argument");
    }

    memset(l, 0, sizeof(*l));
    l->fd = -1;
    l->port = -1;

    char host[256];
    char port[16];
    if (cloak_net_split_hostport(addr, host, sizeof(host), port, sizeof(port)) != 0) {
        return set_err(err, err_cap, "listener: malformed address %s", addr);
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host[0] != '\0' ? host : NULL, port, &hints, &res);
    if (rc != 0) {
        return set_err(err, err_cap, "listener: cannot resolve %s: %s", addr,
                       gai_strerror(rc));
    }

    int last_errno = 0;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                        ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }

        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (ai->ai_family == AF_INET6 && host[0] == '\0') {
            /* an empty host means every interface: ask for dual-stack, but
             * carry on with IPv6-only if the kernel refuses */
            int zero = 0;
            (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
        }

        if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            last_errno = errno;
            close(fd);
            continue;
        }
        if (listen(fd, 128) != 0) {
            last_errno = errno;
            close(fd);
            continue;
        }

        l->reactor = r;
        l->fd = fd;
        l->port = bound_port(fd);
        l->on_accept = cb;
        l->on_accept_userdata = userdata;

        if (cloak_reactor_add_fd(r, fd, CLOAK_REACTOR_READABLE, listener_on_readable, l) != 0) {
            close(fd);
            l->fd = -1;
            l->port = -1;
            freeaddrinfo(res);
            return set_err(err, err_cap, "listener: cannot register %s with the reactor",
                           addr);
        }

        freeaddrinfo(res);
        return 0;
    }

    freeaddrinfo(res);
    return set_err(err, err_cap, "listener: cannot bind %s: %s", addr,
                   last_errno != 0 ? strerror(last_errno) : "no usable address");
}

void cloak_listener_close(cloak_listener_t *l) {
    if (l == NULL || l->fd < 0) {
        return;
    }
    cloak_reactor_remove_fd(l->reactor, l->fd);
    close(l->fd);
    l->fd = -1;
    l->port = -1;
}

int cloak_listener_port(const cloak_listener_t *l) {
    if (l == NULL) {
        return -1;
    }
    return l->port;
}
```

- [ ] **Step 5: Wire it into the build**

Add `src/listener.c` to the `cloak-common` source list. Append to `libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_listener test_listener.c)
target_include_directories(test_listener PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_listener PRIVATE cloak-common)
add_test(NAME test_listener COMMAND test_listener)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run `ctest -R test_listener`. Expected: PASS. Then the full suite: 24 tests.

- [ ] **Step 7: Commit**

```bash
git add libcloak-common/include/cloak/net.h libcloak-common/src/listener.c \
        libcloak-common/tests/test_listener.c libcloak-common/CMakeLists.txt \
        libcloak-common/tests/CMakeLists.txt
git commit -m "Add listener: reactor-driven TCP accept loop"
```

---

### Task 3: `cloak_net_resolve` and `cloak_dial_t` — non-blocking connector

The server dials two things — the redirection host on every rejected connection, and the configured proxy endpoint on every accepted stream — and the client dials its remote. All three must not stall the reactor, so the connect is non-blocking and resolution is a separate, explicitly blocking call the caller makes once at startup.

**Files:**
- Modify: `libcloak-common/include/cloak/net.h` (append declarations before the final `#endif`)
- Create: `libcloak-common/src/dial.c`
- Create: `libcloak-common/tests/test_dial.c`
- Modify: `libcloak-common/CMakeLists.txt` (add `src/dial.c`)
- Modify: `libcloak-common/tests/CMakeLists.txt` (register `test_dial`)

**Interfaces:**
- Consumes: `cloak_net_split_hostport` (Task 2); `cloak_reactor_add_fd`/`mod_fd`/`remove_fd`/`add_timer`/`cancel_timer`.
- Produces:
  - `cloak_addr_t` and `int cloak_net_resolve(const char *addr, int is_udp, cloak_addr_t *out, char *err, size_t err_cap);`
  - `typedef void (*cloak_dial_cb)(int fd, void *userdata);`
  - `int cloak_dial_start(cloak_dial_t *d, cloak_reactor_t *r, const cloak_addr_t *addr, uint64_t timeout_ms, cloak_dial_cb cb, void *userdata);`
  - `void cloak_dial_cancel(cloak_dial_t *d);`

- [ ] **Step 1: Write the failing test**

Create `libcloak-common/tests/test_dial.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/net.h"
#include "test_framework.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct dial_capture {
    cloak_reactor_t *reactor;
    int fd;
    int calls;
};

static void on_dialed(int fd, void *userdata) {
    struct dial_capture *cap = userdata;
    cap->fd = fd;
    cap->calls++;
    cloak_reactor_stop(cap->reactor);
}

/* Opens a listening socket on loopback and returns it, writing the bound
 * port to *out_port. Not registered with any reactor -- the tests below
 * only need something for connect() to succeed against. */
static int open_listener(int *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        close(fd);
        return -1;
    }
    *out_port = ntohs(sa.sin_port);
    return fd;
}

static void test_resolve_loopback(void) {
    cloak_addr_t addr;
    char err[128] = {0};

    ASSERT_EQ_INT(0, cloak_net_resolve("127.0.0.1:8080", 0, &addr, err, sizeof(err)));
    ASSERT_TRUE(addr.len > 0);

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_net_resolve("localhost:8080", 0, &addr, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_net_resolve("no-port-here", 0, &addr, err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');

    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_net_resolve("this-host-does-not-exist.invalid:80", 0, &addr,
                                        err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');
}

static void test_dials_a_listening_port(void) {
    int port = 0;
    int listener = open_listener(&port);
    ASSERT_TRUE(listener >= 0);
    if (listener < 0) {
        return;
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        close(listener);
        return;
    }

    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%d", port);
    cloak_addr_t addr;
    char err[128] = {0};
    ASSERT_EQ_INT(0, cloak_net_resolve(addr_str, 0, &addr, err, sizeof(err)));

    struct dial_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;
    cap.fd = -2;

    cloak_dial_t d;
    ASSERT_EQ_INT(0, cloak_dial_start(&d, r, &addr, 5000, on_dialed, &cap));
    /* the contract: the callback never fires before start returns, even
     * when the connect completed immediately (which it does on loopback) */
    ASSERT_EQ_INT(0, cap.calls);

    cloak_reactor_run(r);

    ASSERT_EQ_INT(1, cap.calls);
    ASSERT_TRUE(cap.fd >= 0);

    if (cap.fd >= 0) {
        close(cap.fd);
    }
    close(listener);
    cloak_reactor_destroy(r);
}

static void test_dial_to_closed_port_fails(void) {
    /* Open a listener to get a port the kernel just handed out, then close
     * it -- connecting there gets a prompt ECONNREFUSED. */
    int port = 0;
    int listener = open_listener(&port);
    ASSERT_TRUE(listener >= 0);
    if (listener < 0) {
        return;
    }
    close(listener);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%d", port);
    cloak_addr_t addr;
    char err[128] = {0};
    ASSERT_EQ_INT(0, cloak_net_resolve(addr_str, 0, &addr, err, sizeof(err)));

    struct dial_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;
    cap.fd = -2;

    cloak_dial_t d;
    ASSERT_EQ_INT(0, cloak_dial_start(&d, r, &addr, 5000, on_dialed, &cap));
    cloak_reactor_run(r);

    ASSERT_EQ_INT(1, cap.calls);
    ASSERT_EQ_INT(-1, cap.fd);

    cloak_reactor_destroy(r);
}

static void test_cancel_before_completion(void) {
    int port = 0;
    int listener = open_listener(&port);
    ASSERT_TRUE(listener >= 0);
    if (listener < 0) {
        return;
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        close(listener);
        return;
    }

    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%d", port);
    cloak_addr_t addr;
    char err[128] = {0};
    ASSERT_EQ_INT(0, cloak_net_resolve(addr_str, 0, &addr, err, sizeof(err)));

    struct dial_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;
    cap.fd = -2;

    cloak_dial_t d;
    ASSERT_EQ_INT(0, cloak_dial_start(&d, r, &addr, 5000, on_dialed, &cap));
    cloak_dial_cancel(&d);

    /* Nothing is left registered, so the reactor has no work and returns
     * immediately once stopped. Give it one timer to end the loop. */
    cloak_reactor_stop(r);
    cloak_reactor_run(r);

    ASSERT_EQ_INT(0, cap.calls);

    close(listener);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_resolve_loopback();
    test_dials_a_listening_port();
    test_dial_to_closed_port_fails();
    test_cancel_before_completion();
TEST_MAIN_END()
```

Note: `test_dial.c` uses `snprintf`, so include `<stdio.h>` alongside the other headers.

- [ ] **Step 2: Run the test to verify it fails**

Build. Expected: FAIL — `cloak_net_resolve` and `cloak_dial_start` are undeclared.

- [ ] **Step 3: Append the declarations to `cloak/net.h`**

Insert before the closing `#endif`:

```c
/* A resolved socket address, ready to connect to without another lookup. */
typedef struct {
    struct sockaddr_storage ss;
    socklen_t len;
    int socktype; /* SOCK_STREAM or SOCK_DGRAM */
    int protocol;
} cloak_addr_t;

/* Resolves "host:port" into a connectable address.
 *
 * THIS CALL BLOCKS: it performs a synchronous DNS lookup. Call it at
 * startup (when parsing config, as Go Cloak's InitState does for RedirAddr
 * and ProxyBook), never per connection on the reactor's thread. A numeric
 * address resolves without touching the network.
 *
 * is_udp selects SOCK_DGRAM instead of SOCK_STREAM. Returns 0 on success,
 * -1 with the reason in err on a malformed address or a resolution
 * failure. The first result returned by the resolver is used. */
int cloak_net_resolve(const char *addr, int is_udp, cloak_addr_t *out,
                      char *err, size_t err_cap);

typedef struct cloak_dial cloak_dial_t;

/* Fired exactly once per cloak_dial_start, with a connected, non-blocking
 * socket, or fd < 0 if the connect failed or timed out. OWNERSHIP OF fd
 * PASSES TO THIS CALLBACK (it is already unregistered from the reactor);
 * closing it is the callback's responsibility.
 *
 * Guaranteed never to fire before cloak_dial_start returns -- even when
 * the connect completes immediately, as it does on loopback -- so a caller
 * can finish initializing its own state after calling start without
 * racing its own callback. */
typedef void (*cloak_dial_cb)(int fd, void *userdata);

struct cloak_dial {
    cloak_reactor_t *reactor;
    int fd;
    cloak_timer_id_t timeout_timer;
    cloak_timer_id_t immediate_timer;
    cloak_dial_cb cb;
    void *userdata;
    int finished;
};

/* Starts a non-blocking connect to addr. timeout_ms bounds the attempt (0
 * means no timeout). On completion, success or failure, cb fires exactly
 * once.
 *
 * Returns 0 if the attempt started, -1 if it could not be started at all
 * (bad argument, socket creation failure, or a reactor registration
 * failure) -- in which case cb never fires and the caller owns the
 * failure. */
int cloak_dial_start(cloak_dial_t *d, cloak_reactor_t *r, const cloak_addr_t *addr,
                     uint64_t timeout_ms, cloak_dial_cb cb, void *userdata);

/* Abandons an in-flight dial: closes the socket, cancels the timeout, and
 * guarantees cb will NOT fire. A no-op if the dial already completed.
 * Must not be called from within cb itself. */
void cloak_dial_cancel(cloak_dial_t *d);
```

Also add `#include <sys/socket.h>` to `cloak/net.h`'s include block, for `struct sockaddr_storage` and `socklen_t`.

- [ ] **Step 4: Write the implementation**

Create `libcloak-common/src/dial.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/net.h"

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int set_err(char *err, size_t err_cap, const char *fmt, ...) {
    if (err != NULL && err_cap > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, err_cap, fmt, ap);
        va_end(ap);
    }
    return -1;
}

int cloak_net_resolve(const char *addr, int is_udp, cloak_addr_t *out,
                      char *err, size_t err_cap) {
    if (addr == NULL || out == NULL) {
        return set_err(err, err_cap, "resolve: invalid argument");
    }

    char host[256];
    char port[16];
    if (cloak_net_split_hostport(addr, host, sizeof(host), port, sizeof(port)) != 0) {
        return set_err(err, err_cap, "resolve: malformed address %s", addr);
    }
    if (host[0] == '\0') {
        return set_err(err, err_cap, "resolve: %s has no host to connect to", addr);
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = is_udp ? SOCK_DGRAM : SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0 || res == NULL) {
        return set_err(err, err_cap, "resolve: cannot resolve %s: %s", addr,
                       gai_strerror(rc));
    }

    memset(out, 0, sizeof(*out));
    memcpy(&out->ss, res->ai_addr, res->ai_addrlen);
    out->len = res->ai_addrlen;
    out->socktype = res->ai_socktype;
    out->protocol = res->ai_protocol;
    freeaddrinfo(res);
    return 0;
}

/* Single exit point: unregisters, cancels timers, and fires cb exactly
 * once. fd is handed to cb on success (ownership passes) or closed here on
 * failure. */
static void dial_finish(cloak_dial_t *d, int success) {
    if (d->finished) {
        return;
    }
    d->finished = 1;

    if (d->timeout_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->reactor, d->timeout_timer);
        d->timeout_timer = CLOAK_TIMER_INVALID;
    }
    if (d->immediate_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->reactor, d->immediate_timer);
        d->immediate_timer = CLOAK_TIMER_INVALID;
    }

    int fd = d->fd;
    d->fd = -1;
    if (fd >= 0) {
        cloak_reactor_remove_fd(d->reactor, fd);
    }

    if (success) {
        d->cb(fd, d->userdata);
    } else {
        if (fd >= 0) {
            close(fd);
        }
        d->cb(-1, d->userdata);
    }
}

static void dial_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    (void)events;
    cloak_dial_t *d = userdata;

    /* The reactor folds HUP/ERR into READABLE regardless of the registered
     * interest, so never infer success from the event mask -- ask the
     * socket. */
    int soerr = 0;
    socklen_t len = sizeof(soerr);
    if (getsockopt(d->fd, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0 || soerr != 0) {
        dial_finish(d, 0);
        return;
    }
    dial_finish(d, 1);
}

static void dial_on_timeout(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_dial_t *d = userdata;
    d->timeout_timer = CLOAK_TIMER_INVALID;
    dial_finish(d, 0);
}

/* Used when connect() succeeded synchronously: defers the callback to the
 * reactor's next turn so it never fires before cloak_dial_start returns. */
static void dial_on_immediate(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_dial_t *d = userdata;
    d->immediate_timer = CLOAK_TIMER_INVALID;
    dial_finish(d, 1);
}

int cloak_dial_start(cloak_dial_t *d, cloak_reactor_t *r, const cloak_addr_t *addr,
                     uint64_t timeout_ms, cloak_dial_cb cb, void *userdata) {
    if (d == NULL || r == NULL || addr == NULL || cb == NULL || addr->len == 0) {
        return -1;
    }

    memset(d, 0, sizeof(*d));
    d->reactor = r;
    d->fd = -1;
    d->timeout_timer = CLOAK_TIMER_INVALID;
    d->immediate_timer = CLOAK_TIMER_INVALID;
    d->cb = cb;
    d->userdata = userdata;

    int fd = socket(((const struct sockaddr *)&addr->ss)->sa_family,
                    addr->socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, addr->protocol);
    if (fd < 0) {
        return -1;
    }
    d->fd = fd;

    int rc = connect(fd, (const struct sockaddr *)&addr->ss, addr->len);
    if (rc == 0) {
        /* completed immediately (loopback, or a datagram socket): defer the
         * callback rather than firing it from inside start */
        d->immediate_timer = cloak_reactor_add_timer(r, 0, dial_on_immediate, d);
        if (d->immediate_timer == CLOAK_TIMER_INVALID) {
            close(fd);
            d->fd = -1;
            return -1;
        }
        return 0;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        d->fd = -1;
        return -1;
    }

    if (cloak_reactor_add_fd(r, fd, CLOAK_REACTOR_WRITABLE, dial_on_event, d) != 0) {
        close(fd);
        d->fd = -1;
        return -1;
    }

    if (timeout_ms > 0) {
        d->timeout_timer = cloak_reactor_add_timer(r, timeout_ms, dial_on_timeout, d);
        if (d->timeout_timer == CLOAK_TIMER_INVALID) {
            cloak_reactor_remove_fd(r, fd);
            close(fd);
            d->fd = -1;
            return -1;
        }
    }
    return 0;
}

void cloak_dial_cancel(cloak_dial_t *d) {
    if (d == NULL || d->finished) {
        return;
    }
    d->finished = 1;

    if (d->timeout_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->reactor, d->timeout_timer);
        d->timeout_timer = CLOAK_TIMER_INVALID;
    }
    if (d->immediate_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->reactor, d->immediate_timer);
        d->immediate_timer = CLOAK_TIMER_INVALID;
    }
    if (d->fd >= 0) {
        cloak_reactor_remove_fd(d->reactor, d->fd);
        close(d->fd);
        d->fd = -1;
    }
}
```

- [ ] **Step 5: Wire it into the build**

Add `src/dial.c` to the `cloak-common` source list. Append to `libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_dial test_dial.c)
target_include_directories(test_dial PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_dial PRIVATE cloak-common)
add_test(NAME test_dial COMMAND test_dial)
```

- [ ] **Step 6: Run the tests to verify they pass**

`ctest -R test_dial`, then the full suite: 25 tests.

- [ ] **Step 7: Commit**

```bash
git add libcloak-common/include/cloak/net.h libcloak-common/src/dial.c \
        libcloak-common/tests/test_dial.c libcloak-common/CMakeLists.txt \
        libcloak-common/tests/CMakeLists.txt
git commit -m "Add dial: blocking resolve plus non-blocking connect"
```

---

### Task 4: `cloak_relay_t` — bidirectional splice with backpressure

This is the spec's data-plane model made concrete (§6): "a readable event on one side attempts to enqueue into the other side's write buffer; if that buffer is full, EPOLLIN is deregistered on the source (backpressure) until the destination drains and re-arms it." Its first caller is the dispatcher's `goWeb()`, which must forward an already-read first packet and then splice the rest.

**Files:**
- Modify: `libcloak-common/include/cloak/net.h` (append declarations before the final `#endif`)
- Create: `libcloak-common/src/relay.c`
- Create: `libcloak-common/tests/test_relay.c`
- Modify: `libcloak-common/CMakeLists.txt` (add `src/relay.c`)
- Modify: `libcloak-common/tests/CMakeLists.txt` (register `test_relay`)

**Interfaces:**
- Consumes: `cloak_bytequeue_t` (Task 1, now in `libcloak-common`) — `init`, `destroy`, `write`, `peek`, `read`, `len`, `free_space`; the reactor's `add_fd`/`mod_fd`/`remove_fd`.
- Produces:
  - `typedef void (*cloak_relay_done_cb)(cloak_relay_t *rl, void *userdata);`
  - `int cloak_relay_start(cloak_relay_t *rl, cloak_reactor_t *r, int fd_a, int fd_b, const uint8_t *preload, size_t preload_len, size_t buf_cap, cloak_relay_done_cb on_done, void *userdata);`
  - `void cloak_relay_stop(cloak_relay_t *rl);`

- [ ] **Step 1: Write the failing test**

Create `libcloak-common/tests/test_relay.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/net.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct done_capture {
    cloak_reactor_t *reactor;
    int calls;
};

static void on_done(cloak_relay_t *rl, void *userdata) {
    (void)rl;
    struct done_capture *cap = userdata;
    cap->calls++;
    cloak_reactor_stop(cap->reactor);
}

/* Builds two socketpairs and relays between their inner ends, so a test
 * can write on outer_a and read what arrives on outer_b. */
struct harness {
    int outer_a;
    int outer_b;
    int inner_a;
    int inner_b;
};

static int harness_init(struct harness *h) {
    int pa[2];
    int pb[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pa) != 0) {
        return -1;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pb) != 0) {
        close(pa[0]);
        close(pa[1]);
        return -1;
    }
    h->outer_a = pa[0];
    h->inner_a = pa[1];
    h->outer_b = pb[0];
    h->inner_b = pb[1];
    return 0;
}

static void test_forwards_both_directions(void) {
    struct harness h;
    ASSERT_EQ_INT(0, harness_init(&h));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;

    cloak_relay_t rl;
    ASSERT_EQ_INT(0, cloak_relay_start(&rl, r, h.inner_a, h.inner_b, NULL, 0, 4096,
                                       on_done, &cap));

    ASSERT_TRUE(write(h.outer_a, "ping", 4) == 4);
    ASSERT_TRUE(write(h.outer_b, "pong!!", 6) == 6);

    /* Close both outer ends so the relay sees EOF and finishes, ending the
     * reactor loop through on_done. */
    shutdown(h.outer_a, SHUT_WR);

    cloak_reactor_run(r);
    ASSERT_EQ_INT(1, cap.calls);

    char buf[16];
    memset(buf, 0, sizeof(buf));
    ssize_t n = read(h.outer_b, buf, sizeof(buf));
    ASSERT_TRUE(n >= 4);
    ASSERT_MEM_EQ(buf, "ping", 4);

    memset(buf, 0, sizeof(buf));
    n = read(h.outer_a, buf, sizeof(buf));
    ASSERT_TRUE(n >= 6);
    ASSERT_MEM_EQ(buf, "pong!!", 6);

    close(h.outer_a);
    close(h.outer_b);
    cloak_reactor_destroy(r);
}

static void test_preload_is_delivered_first(void) {
    /* goWeb's shape: the first packet was already read off fd_a before the
     * relay existed, and must reach fd_b ahead of anything else. */
    struct harness h;
    ASSERT_EQ_INT(0, harness_init(&h));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;

    const uint8_t preload[] = "GET / HTTP/1.1\r\n";
    cloak_relay_t rl;
    ASSERT_EQ_INT(0, cloak_relay_start(&rl, r, h.inner_a, h.inner_b, preload,
                                       sizeof(preload) - 1, 4096, on_done, &cap));

    ASSERT_TRUE(write(h.outer_a, "rest", 4) == 4);
    shutdown(h.outer_a, SHUT_WR);

    cloak_reactor_run(r);
    ASSERT_EQ_INT(1, cap.calls);

    char buf[64];
    memset(buf, 0, sizeof(buf));
    ssize_t n = read(h.outer_b, buf, sizeof(buf));
    ASSERT_TRUE(n == (ssize_t)(sizeof(preload) - 1 + 4));
    ASSERT_MEM_EQ(buf, "GET / HTTP/1.1\r\nrest", sizeof(preload) - 1 + 4);

    close(h.outer_a);
    close(h.outer_b);
    cloak_reactor_destroy(r);
}

static void test_large_transfer_survives_backpressure(void) {
    /* The payload is far larger than the relay's buffer and larger than
     * the socket buffers, so this only completes if the relay correctly
     * deregisters and re-arms read interest as its queues fill and drain. */
    struct harness h;
    ASSERT_EQ_INT(0, harness_init(&h));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;

    cloak_relay_t rl;
    ASSERT_EQ_INT(0, cloak_relay_start(&rl, r, h.inner_a, h.inner_b, NULL, 0, 4096,
                                       on_done, &cap));

    const size_t total = 512 * 1024;
    uint8_t *sent = malloc(total);
    ASSERT_TRUE(sent != NULL);
    if (sent == NULL) {
        return;
    }
    for (size_t i = 0; i < total; i++) {
        sent[i] = (uint8_t)(i * 31 + (i >> 8));
    }

    /* Feed and drain from the same loop: a blocking write of the whole
     * payload would deadlock against a relay that is not running yet. */
    size_t written = 0;
    size_t received = 0;
    uint8_t *got = malloc(total);
    ASSERT_TRUE(got != NULL);
    if (got == NULL) {
        free(sent);
        return;
    }

    int flags_a = fcntl(h.outer_a, F_GETFL, 0);
    fcntl(h.outer_a, F_SETFL, flags_a | O_NONBLOCK);
    int flags_b = fcntl(h.outer_b, F_GETFL, 0);
    fcntl(h.outer_b, F_SETFL, flags_b | O_NONBLOCK);

    /* Pump: alternate between pushing into the relay, letting the reactor
     * turn once, and draining the far end. */
    for (int spin = 0; spin < 100000 && received < total; spin++) {
        if (written < total) {
            ssize_t n = write(h.outer_a, sent + written, total - written);
            if (n > 0) {
                written += (size_t)n;
                if (written == total) {
                    shutdown(h.outer_a, SHUT_WR);
                }
            }
        }
        cloak_reactor_run_once(r, 10);
        for (;;) {
            ssize_t n = read(h.outer_b, got + received, total - received);
            if (n <= 0) {
                break;
            }
            received += (size_t)n;
            if (received == total) {
                break;
            }
        }
    }

    ASSERT_EQ_INT((long long)total, (long long)received);
    ASSERT_MEM_EQ(sent, got, total);

    free(sent);
    free(got);
    close(h.outer_a);
    close(h.outer_b);
    cloak_relay_stop(&rl);
    cloak_reactor_destroy(r);
}

static void test_stop_is_idempotent_and_suppresses_done(void) {
    struct harness h;
    ASSERT_EQ_INT(0, harness_init(&h));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct done_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;

    cloak_relay_t rl;
    ASSERT_EQ_INT(0, cloak_relay_start(&rl, r, h.inner_a, h.inner_b, NULL, 0, 4096,
                                       on_done, &cap));
    cloak_relay_stop(&rl);
    cloak_relay_stop(&rl);
    ASSERT_EQ_INT(0, cap.calls);

    close(h.outer_a);
    close(h.outer_b);
    cloak_reactor_destroy(r);
}

static void test_start_rejects_oversized_preload(void) {
    struct harness h;
    ASSERT_EQ_INT(0, harness_init(&h));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    uint8_t big[512];
    memset(big, 'x', sizeof(big));
    cloak_relay_t rl;
    ASSERT_EQ_INT(-1, cloak_relay_start(&rl, r, h.inner_a, h.inner_b, big, sizeof(big),
                                        256, on_done, NULL));

    close(h.inner_a);
    close(h.inner_b);
    close(h.outer_a);
    close(h.outer_b);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_forwards_both_directions();
    test_preload_is_delivered_first();
    test_large_transfer_survives_backpressure();
    test_stop_is_idempotent_and_suppresses_done();
    test_start_rejects_oversized_preload();
TEST_MAIN_END()
```

Note: this file uses `fcntl`/`O_NONBLOCK`, so include `<fcntl.h>`; and `test_large_transfer_survives_backpressure` calls `cloak_reactor_run_once`, which does not exist yet — Step 3a below adds it, because a pump-style test cannot use the blocking `cloak_reactor_run`.

- [ ] **Step 2: Run the test to verify it fails**

Build. Expected: FAIL — `cloak_relay_start` and `cloak_reactor_run_once` are undeclared.

- [ ] **Step 3a: Add `cloak_reactor_run_once` to the reactor**

The existing `cloak_reactor_run` blocks until `cloak_reactor_stop`, which suits production but not a test that must interleave its own socket I/O with reactor turns. Add a single-turn entry point beside it.

In `libcloak-common/include/cloak/reactor.h`, after `cloak_reactor_stop`'s declaration:

```c
/* Runs a single dispatch turn: waits up to timeout_ms for readiness (0
 * returns immediately, -1 waits indefinitely), dispatches whatever fired
 * along with any timers now due, and returns. Returns the number of fd
 * events dispatched, or -1 on a fatal epoll error.
 *
 * cloak_reactor_run is this called in a loop until stopped; tests and
 * callers that need to interleave their own work with the event loop use
 * this directly. */
int cloak_reactor_run_once(cloak_reactor_t *r, int timeout_ms);
```

In `libcloak-common/src/reactor.c`, the existing `cloak_reactor_run` already contains the body of one turn inside its loop. Extract that body into `cloak_reactor_run_once(r, timeout_ms)` — computing the epoll timeout from the timer heap exactly as it does today, but bounded by the caller's `timeout_ms` when that is smaller — and rewrite `cloak_reactor_run` as:

```c
void cloak_reactor_run(cloak_reactor_t *r) {
    r->stopped = 0;
    while (!r->stopped) {
        if (cloak_reactor_run_once(r, -1) < 0) {
            return;
        }
    }
}
```

Preserve every existing behaviour of the extracted body verbatim — the dead-watcher sweep, the `stop()` check between dispatches, and the timer dispatch order. `test_reactor.c` must keep passing unchanged; treat any failure there as a sign the extraction changed semantics, not as a test to adjust.

- [ ] **Step 3b: Append the relay declarations to `cloak/net.h`**

Insert before the closing `#endif`:

```c
typedef struct cloak_relay cloak_relay_t;

/* Fired exactly once, when the relay finishes: either side reaching EOF,
 * or either side erroring. Both file descriptors are already closed by the
 * time this fires. Never fired by cloak_relay_stop (an explicit teardown
 * is not a completion), and never before cloak_relay_start returns. */
typedef void (*cloak_relay_done_cb)(cloak_relay_t *rl, void *userdata);

struct cloak_relay {
    cloak_reactor_t *reactor;
    int fd[2];
    /* q[i] holds bytes read from fd[i] and awaiting write to fd[1 - i]. */
    cloak_bytequeue_t q[2];
    int read_eof[2];
    uint32_t interest[2];
    int done;
    cloak_relay_done_cb on_done;
    void *on_done_userdata;
};

/* Splices fd_a and fd_b together until one of them ends.
 *
 * Ownership of both descriptors passes to the relay: it closes both when
 * it finishes, and cloak_relay_stop closes both too. Each direction gets
 * its own buf_cap-byte queue; when a queue fills, read interest on its
 * source is deregistered until the destination drains it, which is what
 * keeps a fast producer from growing memory without bound.
 *
 * preload/preload_len is data already read from fd_a before the relay
 * existed, to be written to fd_b ahead of anything else -- the server
 * dispatcher's redirect path, which has already consumed its client's
 * first packet, is what this is for. preload_len must not exceed buf_cap.
 *
 * Teardown is symmetric and immediate, matching Go Cloak's own
 * common.Copy: the first EOF or error on either side ends the whole
 * relay. Before closing, it makes one best-effort non-blocking pass over
 * the data still in flight -- draining whatever the other side has
 * already sent, then flushing both queues -- so a short reply that
 * crossed paths with the EOF still gets delivered. Neither side is
 * half-closed and left running.
 *
 * Returns 0 on success, -1 on invalid arguments (including an oversized
 * preload), allocation failure, or a reactor registration failure. On
 * failure neither descriptor is closed -- the caller still owns them. */
int cloak_relay_start(cloak_relay_t *rl, cloak_reactor_t *r, int fd_a, int fd_b,
                      const uint8_t *preload, size_t preload_len, size_t buf_cap,
                      cloak_relay_done_cb on_done, void *userdata);

/* Tears the relay down without firing on_done: unregisters and closes both
 * descriptors and frees both queues. Idempotent, and safe on a relay left
 * zeroed by a failed start. */
void cloak_relay_stop(cloak_relay_t *rl);
```

- [ ] **Step 4: Write the implementation**

Create `libcloak-common/src/relay.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/net.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* Scratch size for one read()/write() syscall. Independent of the queue
 * capacity: the loop below keeps going until EAGAIN either way. */
#define RELAY_CHUNK 16384

static void relay_teardown(cloak_relay_t *rl, int fire_done);

/* What each side needs to be watched for, given the current queue state:
 * readable while its own queue has room and it has not hit EOF, writable
 * while the opposite queue has bytes waiting for it. */
static uint32_t desired_interest(const cloak_relay_t *rl, int i) {
    uint32_t ev = 0;
    if (!rl->read_eof[i] && cloak_bytequeue_free_space(&rl->q[i]) > 0) {
        ev |= CLOAK_REACTOR_READABLE;
    }
    if (cloak_bytequeue_len(&rl->q[1 - i]) > 0) {
        ev |= CLOAK_REACTOR_WRITABLE;
    }
    return ev;
}

static void sync_interest(cloak_relay_t *rl) {
    for (int i = 0; i < 2; i++) {
        if (rl->fd[i] < 0) {
            continue;
        }
        uint32_t want = desired_interest(rl, i);
        if (want != rl->interest[i]) {
            rl->interest[i] = want;
            /* Re-arming READABLE on an edge-triggered fd re-reports data
             * that is already sitting in the socket buffer, which is what
             * makes the backpressure release work. */
            (void)cloak_reactor_mod_fd(rl->reactor, rl->fd[i], want);
        }
    }
}

/* Reads from fd[i] into q[i] until the queue is full or the socket is
 * drained. Returns 0 to continue, -1 if the relay should tear down. */
static int pump_read(cloak_relay_t *rl, int i) {
    uint8_t buf[RELAY_CHUNK];
    for (;;) {
        size_t room = cloak_bytequeue_free_space(&rl->q[i]);
        if (room == 0) {
            return 0; /* backpressure: stop reading until the peer drains */
        }
        size_t want = room < sizeof(buf) ? room : sizeof(buf);
        ssize_t n = read(rl->fd[i], buf, want);
        if (n > 0) {
            cloak_bytequeue_write(&rl->q[i], buf, (size_t)n);
            continue;
        }
        if (n == 0) {
            rl->read_eof[i] = 1;
            return -1; /* Go's Copy tears both directions down on EOF */
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
}

/* Writes q[1 - i] out through fd[i] until the queue empties or the socket
 * blocks. Returns 0 to continue, -1 if the relay should tear down. */
static int pump_write(cloak_relay_t *rl, int i) {
    uint8_t buf[RELAY_CHUNK];
    for (;;) {
        size_t have = cloak_bytequeue_peek(&rl->q[1 - i], buf, sizeof(buf));
        if (have == 0) {
            return 0;
        }
        ssize_t n = write(rl->fd[i], buf, have);
        if (n > 0) {
            cloak_bytequeue_read(&rl->q[1 - i], buf, (size_t)n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        return -1;
    }
}

static void relay_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    cloak_relay_t *rl = userdata;
    if (rl->done) {
        return;
    }

    int i = (fd == rl->fd[0]) ? 0 : 1;

    /* Always attempt the write side first: draining frees queue space,
     * which may let the read side below make progress in the same turn. */
    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        if (pump_write(rl, i) != 0) {
            relay_teardown(rl, 1);
            return;
        }
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        if (pump_read(rl, i) != 0) {
            /* One side ended. Before tearing down, make a best-effort pass
             * over everything still in flight: drain whatever the OTHER
             * side has already sent (it may have been readable in this very
             * turn and not dispatched yet), then flush both queues. Without
             * the read, a short reply that crossed paths with the EOF is
             * silently dropped. */
            (void)pump_read(rl, 1 - i);
            (void)pump_write(rl, 1 - i);
            (void)pump_write(rl, i);
            relay_teardown(rl, 1);
            return;
        }
        /* the bytes just read may be immediately writable on the peer */
        if (pump_write(rl, 1 - i) != 0) {
            relay_teardown(rl, 1);
            return;
        }
    }

    sync_interest(rl);
}

static void relay_close_fds(cloak_relay_t *rl) {
    for (int i = 0; i < 2; i++) {
        if (rl->fd[i] >= 0) {
            cloak_reactor_remove_fd(rl->reactor, rl->fd[i]);
            close(rl->fd[i]);
            rl->fd[i] = -1;
        }
    }
}

static void relay_teardown(cloak_relay_t *rl, int fire_done) {
    if (rl->done) {
        return;
    }
    rl->done = 1;
    relay_close_fds(rl);
    cloak_bytequeue_destroy(&rl->q[0]);
    cloak_bytequeue_destroy(&rl->q[1]);
    if (fire_done && rl->on_done != NULL) {
        rl->on_done(rl, rl->on_done_userdata);
    }
}

int cloak_relay_start(cloak_relay_t *rl, cloak_reactor_t *r, int fd_a, int fd_b,
                      const uint8_t *preload, size_t preload_len, size_t buf_cap,
                      cloak_relay_done_cb on_done, void *userdata) {
    if (rl == NULL || r == NULL || fd_a < 0 || fd_b < 0 || buf_cap == 0) {
        return -1;
    }
    if (preload_len > buf_cap) {
        return -1;
    }
    if (preload_len > 0 && preload == NULL) {
        return -1;
    }

    memset(rl, 0, sizeof(*rl));
    rl->reactor = r;
    rl->fd[0] = -1;
    rl->fd[1] = -1;
    rl->on_done = on_done;
    rl->on_done_userdata = userdata;

    if (cloak_bytequeue_init(&rl->q[0], buf_cap) != 0) {
        return -1;
    }
    if (cloak_bytequeue_init(&rl->q[1], buf_cap) != 0) {
        cloak_bytequeue_destroy(&rl->q[0]);
        return -1;
    }
    if (preload_len > 0) {
        cloak_bytequeue_write(&rl->q[0], preload, preload_len);
    }

    /* Register both before touching either fd's state, so a failure on the
     * second leaves nothing half-registered. */
    if (cloak_reactor_add_fd(r, fd_a, CLOAK_REACTOR_READABLE, relay_on_event, rl) != 0) {
        cloak_bytequeue_destroy(&rl->q[0]);
        cloak_bytequeue_destroy(&rl->q[1]);
        return -1;
    }
    if (cloak_reactor_add_fd(r, fd_b, CLOAK_REACTOR_READABLE, relay_on_event, rl) != 0) {
        cloak_reactor_remove_fd(r, fd_a);
        cloak_bytequeue_destroy(&rl->q[0]);
        cloak_bytequeue_destroy(&rl->q[1]);
        return -1;
    }

    rl->fd[0] = fd_a;
    rl->fd[1] = fd_b;
    rl->interest[0] = CLOAK_REACTOR_READABLE;
    rl->interest[1] = CLOAK_REACTOR_READABLE;

    /* A freshly registered socket may already be writable with the preload
     * waiting, and an edge for that may never arrive on its own -- so ask
     * for it explicitly. */
    sync_interest(rl);
    return 0;
}

void cloak_relay_stop(cloak_relay_t *rl) {
    if (rl == NULL) {
        return;
    }
    relay_teardown(rl, 0);
}
```

- [ ] **Step 5: Wire it into the build**

Add `src/relay.c` to the `cloak-common` source list. Append to `libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_relay test_relay.c)
target_include_directories(test_relay PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_relay PRIVATE cloak-common)
add_test(NAME test_relay COMMAND test_relay)
```

- [ ] **Step 6: Run the full suite**

Expected: 26 tests passing — the 23 from before this plan, plus `test_listener`, `test_dial` and `test_relay` (`test_bytequeue` moved rather than added). `test_reactor` must still pass unchanged after the `run_once` extraction.

- [ ] **Step 7: Run the suite under ASan/UBSan**

```bash
docker run --rm -v /Users/sam/Cloak-c:/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
     -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
     -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" && \
   cmake --build build-asan -j8 && ctest --test-dir build-asan --output-on-failure'
```

Expected: 26/26 with no sanitizer reports. This step matters here more than anywhere else in this plan: the relay owns two heap queues and two descriptors across an asynchronous teardown, and the half-megabyte backpressure test is what exercises the queue-wrap arithmetic.

- [ ] **Step 8: Commit**

```bash
git add libcloak-common/include/cloak/net.h libcloak-common/include/cloak/reactor.h \
        libcloak-common/src/relay.c libcloak-common/src/reactor.c \
        libcloak-common/tests/test_relay.c libcloak-common/CMakeLists.txt \
        libcloak-common/tests/CMakeLists.txt
git commit -m "Add relay: bidirectional splice with backpressure"
```

---

## What comes after this plan

The server dispatcher (spec §7), which is the first real caller of all three primitives: `cloak_listener_t` binds each `BindAddr` entry, the first-packet state machine buffers a full ClientHello or HTTP request across non-blocking reads, `cloak_server_auth_decrypt` authenticates it, and either a `cloak_session_t` takes the connection or `cloak_dial_t` + `cloak_relay_t` forward it to `RedirAddr` as `goWeb()` does. That module also owns the server-side state this one deliberately has no opinion about: the proxy-method lookup, the session registry keyed by UID and session id, and the runtime bypass set — which, per the note in the config module's plan, **must union `admin_uid` into `bypass_uid`** when `has_admin_uid` is set.

Out of scope here: any policy about what gets relayed or dialed, UDP datagram handling (`cloak_addr_t` carries a `socktype` for it, but no datagram plumbing exists yet — that arrives with the unordered-mode module), and TLS of any kind (the CDN transport's real TLS is its own module).

## Self-review notes

- **Spec coverage:** §6's data-plane paragraph ("a readable event on one side attempts to enqueue into the other side's write buffer; if that buffer is full, EPOLLIN is deregistered on the source until the destination drains and re-arms it") is Task 4, implemented literally — `desired_interest`/`sync_interest` are that sentence. §7's `goWeb` shape is served by Task 3 (non-blocking dial to `RedirAddr`) plus Task 4's `preload` parameter (forwarding the already-read first packet). §3's "no blocking I/O anywhere in the data or control path" holds with one documented exception, `cloak_net_resolve`, which the header marks as startup-only. The listener has no direct spec sentence of its own; it exists because `BindAddr` is a list and both binaries need to accept connections.
- **Placeholder scan:** no TBD/TODO steps. Task 4 Step 3a is the one step that asks for a refactor rather than pasting a literal file — the body being extracted already exists in `reactor.c` and pasting a guessed copy of it would be worse than naming the transformation precisely, which is what that step does, along with the invariant that `test_reactor` must keep passing unchanged.
- **Type consistency:** `cloak_net_split_hostport` (Task 2) is consumed by `cloak_net_resolve` (Task 3) with the same `(addr, host, host_cap, port, port_cap)` signature. `cloak_addr_t` is produced in Task 3 and consumed only there. `cloak_bytequeue_t`'s API is used in Task 4 exactly as Task 1 relocated it (`init/destroy/write/read/peek/len/free_space`), with no signature change. All three units put their declarations in the single `cloak/net.h` created in Task 2 and appended to in Tasks 3 and 4, and all three follow the project's 0/-1 plus `err`-buffer convention.
- **Divergences from the Go original, deliberate:** Go dials with `net.Dialer` (blocking, one goroutine per connection); this port splits resolution from connection so the reactor never stalls on DNS. Go's `common.Copy` runs two goroutines with an unbounded implicit buffer; this relay's queues are fixed-capacity with explicit backpressure, which is the spec's stated requirement, and its teardown semantics (first EOF ends both directions) deliberately match Go's rather than adding half-close support Go does not have.
