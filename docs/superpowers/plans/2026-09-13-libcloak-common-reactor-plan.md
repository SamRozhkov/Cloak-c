# libcloak-common: epoll Reactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and unit-test a single-threaded epoll-based event loop (fd readiness dispatch + a timer heap) in `libcloak-common`, with no protocol or networking logic layered on top yet.

**Architecture:** One new module, `cloak/reactor.h` + `src/reactor.c`, exposing an opaque `cloak_reactor_t`. Callers register file descriptors with a readable/writable interest mask and a callback; the reactor's `run()` loop blocks in `epoll_wait`, dispatches readiness callbacks, and fires any expired timers, until a callback calls `cloak_reactor_stop`. Registration is edge-triggered (`EPOLLET`) per the design spec's architecture section — callers are responsible for draining a readable/writable fd fully (read/write until `EAGAIN`) since the reactor will not re-notify for data that arrived within the same edge. All state (the fd→watcher table, the timer min-heap) lives in the single `cloak_reactor_t` struct with no locking, since the whole project is single-threaded by design.

**Tech Stack:** C11, Linux `epoll(7)` (`sys/epoll.h`), `CLOCK_MONOTONIC` via `clock_gettime`, CMake, the existing custom assert-based test framework (`libcloak-common/tests/test_framework.h`, already built in the previous plan).

## Global Constraints

- Language: C11 (`-Wall -Wextra` clean build, already enforced globally by the root `CMakeLists.txt`).
- Platform: Linux only (per spec §2). This is not aspirational for this plan specifically: `sys/epoll.h` does not exist on macOS at all, so this code cannot even compile on the development machine's native toolchain.
- **Every build/test command in this plan runs inside the project's Linux dev container, not on the host.** The repo root now has `Dockerfile.dev` (Debian bookworm, `build-essential` + `cmake` + `libssl-dev`). The standard build/test command, run from the repo/worktree root, is:
  ```bash
  docker build -q -f Dockerfile.dev -t cloak-c-dev .
  docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure"
  ```
  Every "Run:" instruction in this plan that builds or tests means: run it via this Docker invocation, substituting the specific `cmake`/`ctest` command shown. `build/` is already gitignored (from the previous plan's `.gitignore`).
- Event loop: raw `epoll` directly, no `libevent`/`libuv` (per spec's key decisions log — no portability layer needed once the project committed to Linux-only).
- Concurrency: single-threaded reactor, no locks anywhere (per spec §3) — this plan's code must never spawn a thread or use pthread primitives.
- Edge-triggered readiness (`EPOLLET`) per spec §3's "single-threaded epoll reactor" architecture description.
- Testing: lightweight custom assert-based runner + CTest, no heavyweight framework (per spec §11) — reuse `libcloak-common/tests/test_framework.h` from the previous plan; do not introduce a new test framework.
- Build: CMake (per spec §10) — add new sources/tests to the existing `libcloak-common/CMakeLists.txt` and `libcloak-common/tests/CMakeLists.txt`, following the exact pattern already established there (see those files from the previous plan).

---

### Task 1: Reactor core — lifecycle, fd registration, dispatch, stop

**Files:**
- Create: `libcloak-common/include/cloak/reactor.h`
- Create: `libcloak-common/src/reactor.c`
- Modify: `libcloak-common/CMakeLists.txt` (add `src/reactor.c` to the `cloak-common` library's sources)
- Modify: `libcloak-common/tests/CMakeLists.txt` (add a `test_reactor` executable/test, same pattern as the existing `test_aead`/`test_salsa20`/`test_x25519` entries)
- Test: `libcloak-common/tests/test_reactor.c`

**Interfaces:**
- Consumes: nothing from earlier plans (this is the first task of a new module; it does not depend on `cloak/crypto.h` or `cloak/common.h`).
- Produces (final state of `cloak/reactor.h` after this task — Task 2 will *append* timer declarations to this same file, not replace anything below):
  ```c
  typedef struct cloak_reactor cloak_reactor_t;

  #define CLOAK_REACTOR_READABLE 0x1u
  #define CLOAK_REACTOR_WRITABLE 0x2u

  typedef void (*cloak_reactor_fd_cb)(cloak_reactor_t *r, int fd, uint32_t events, void *userdata);

  cloak_reactor_t *cloak_reactor_create(void);
  void cloak_reactor_destroy(cloak_reactor_t *r);

  int cloak_reactor_add_fd(cloak_reactor_t *r, int fd, uint32_t events,
                            cloak_reactor_fd_cb cb, void *userdata);
  int cloak_reactor_mod_fd(cloak_reactor_t *r, int fd, uint32_t events);
  int cloak_reactor_remove_fd(cloak_reactor_t *r, int fd);

  void cloak_reactor_run(cloak_reactor_t *r);
  void cloak_reactor_stop(cloak_reactor_t *r);
  ```
  `cloak_reactor_add_fd`/`mod_fd`/`remove_fd` return `0` on success, `-1` on failure. `cloak_reactor_run` blocks until `cloak_reactor_stop` is called from within a callback. The next task (timers) will call `cloak_reactor_add_timer`/`cloak_reactor_cancel_timer` from within fd callbacks and expects `cloak_reactor_run`'s dispatch loop and the `struct cloak_reactor` definition (private to `reactor.c`) to already exist exactly as built here, since Task 2 modifies (not replaces) `cloak_reactor_run`, `cloak_reactor_destroy`, and the `struct cloak_reactor` definition from this task.

- [ ] **Step 1: Write the failing test**

Create `libcloak-common/include/cloak/reactor.h`:

```c
#ifndef CLOAK_REACTOR_H
#define CLOAK_REACTOR_H

#include <stddef.h>
#include <stdint.h>

/* A cloak_reactor_t is a single-threaded epoll-based event loop: it
 * dispatches readiness callbacks for registered file descriptors and (from
 * a later task) fires timer callbacks after a delay. It is not
 * thread-safe -- every function here must be called from the same thread
 * that calls cloak_reactor_run. */
typedef struct cloak_reactor cloak_reactor_t;

#define CLOAK_REACTOR_READABLE 0x1u
#define CLOAK_REACTOR_WRITABLE 0x2u

/* events is the CLOAK_REACTOR_* bitmask that actually fired (a subset of
 * what the fd was registered/modified for). */
typedef void (*cloak_reactor_fd_cb)(cloak_reactor_t *r, int fd, uint32_t events, void *userdata);

cloak_reactor_t *cloak_reactor_create(void);

/* Frees the reactor and closes its underlying epoll fd. Does not close any
 * fd the caller registered with cloak_reactor_add_fd -- the caller owns
 * those. */
void cloak_reactor_destroy(cloak_reactor_t *r);

/* Registers fd for events (a CLOAK_REACTOR_READABLE/WRITABLE bitmask).
 * Registration is edge-triggered: cb fires once per readiness transition,
 * so on CLOAK_REACTOR_READABLE the caller must read() until EAGAIN (and
 * likewise write() until EAGAIN for CLOAK_REACTOR_WRITABLE), or it will
 * not be notified again for data/space that was already available within
 * the same edge.
 * Returns 0 on success, -1 if fd < 0, cb is NULL, fd is already
 * registered, or the underlying epoll_ctl call fails. */
int cloak_reactor_add_fd(cloak_reactor_t *r, int fd, uint32_t events,
                          cloak_reactor_fd_cb cb, void *userdata);

/* Changes the registered event mask for an already-added fd. Returns 0 on
 * success, -1 if fd isn't registered or epoll_ctl fails. */
int cloak_reactor_mod_fd(cloak_reactor_t *r, int fd, uint32_t events);

/* Deregisters fd. Safe to call from within that fd's own callback, or from
 * another fd's callback during the same dispatch batch -- a removed fd's
 * callback will not fire even if it was already ready in this batch.
 * Returns 0 on success, -1 if fd isn't registered. */
int cloak_reactor_remove_fd(cloak_reactor_t *r, int fd);

/* Blocks, dispatching fd callbacks, until cloak_reactor_stop is called
 * (typically from within a callback). */
void cloak_reactor_run(cloak_reactor_t *r);

/* Requests that the current cloak_reactor_run call return once the
 * in-progress dispatch batch finishes. Must be called from within a
 * callback running on the reactor's own thread during cloak_reactor_run. */
void cloak_reactor_stop(cloak_reactor_t *r);

#endif
```

Create `libcloak-common/tests/test_reactor.c`:

```c
#include "cloak/reactor.h"
#include "test_framework.h"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct read_ctx {
    int fired;
    uint32_t fired_events;
    char buf[64];
    long n;
};

static void on_readable_read_and_stop(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    struct read_ctx *ctx = (struct read_ctx *)userdata;
    ctx->fired = 1;
    ctx->fired_events = events;
    ctx->n = (long)read(fd, ctx->buf, sizeof(ctx->buf));
    cloak_reactor_stop(r);
}

static void test_add_and_dispatch_readable(void) {
    int fds[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct read_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_READABLE, on_readable_read_and_stop, &ctx), 0);

    const char msg[] = "hello reactor";
    ASSERT_TRUE(write(fds[1], msg, sizeof(msg)) == (long)sizeof(msg));

    cloak_reactor_run(r);

    ASSERT_TRUE(ctx.fired);
    ASSERT_TRUE((ctx.fired_events & CLOAK_REACTOR_READABLE) != 0);
    ASSERT_EQ_INT(ctx.n, sizeof(msg));
    ASSERT_MEM_EQ(ctx.buf, msg, sizeof(msg));

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

struct write_ctx {
    int fired;
    uint32_t fired_events;
};

static void on_writable_stop(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)fd;
    struct write_ctx *ctx = (struct write_ctx *)userdata;
    ctx->fired = 1;
    ctx->fired_events = events;
    cloak_reactor_stop(r);
}

static void test_dispatch_writable(void) {
    int fds[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct write_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_WRITABLE, on_writable_stop, &ctx), 0);

    /* A fresh socket's send buffer is empty, so it's immediately writable --
     * no write needed to trigger this. */
    cloak_reactor_run(r);

    ASSERT_TRUE(ctx.fired);
    ASSERT_TRUE((ctx.fired_events & CLOAK_REACTOR_WRITABLE) != 0);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_add_fd_rejects_duplicate(void) {
    int fds[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct write_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_WRITABLE, on_writable_stop, &ctx), 0);
    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_WRITABLE, on_writable_stop, &ctx), -1);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_mod_fd_changes_interest(void) {
    int fds[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct write_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Register for readable only -- a fresh socket has nothing to read, so
     * if mod_fd didn't actually take effect at the kernel level, run()
     * would block forever (this test would hang) instead of dispatching
     * writable. */
    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds[0], CLOAK_REACTOR_READABLE, on_writable_stop, &ctx), 0);
    ASSERT_EQ_INT(cloak_reactor_mod_fd(r, fds[0], CLOAK_REACTOR_WRITABLE), 0);

    cloak_reactor_run(r);

    ASSERT_TRUE(ctx.fired);
    ASSERT_TRUE((ctx.fired_events & CLOAK_REACTOR_WRITABLE) != 0);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

struct remove_ctx {
    int fire_count;
    int fds[2];
};

static void on_either_removes_other(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)events;
    struct remove_ctx *ctx = (struct remove_ctx *)userdata;
    ctx->fire_count++;
    int other = (fd == ctx->fds[0]) ? ctx->fds[1] : ctx->fds[0];
    cloak_reactor_remove_fd(r, other);
    cloak_reactor_stop(r);
}

static void test_remove_fd_stops_dispatch_in_same_batch(void) {
    int fds_a[2];
    int fds_b[2];
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds_a) == 0);
    ASSERT_TRUE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds_b) == 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct remove_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fds[0] = fds_a[0];
    ctx.fds[1] = fds_b[0];

    /* Both fds are writable-armed and both are immediately writable (fresh
     * sockets), so both are ready in the very first epoll_wait batch.
     * Whichever callback runs first removes the other one. If the reactor
     * dispatched from a stale copy of the ready-list without re-checking
     * whether the fd is still registered, fire_count would be 2 instead
     * of 1 -- this doesn't depend on which of the two fires first, so it's
     * deterministic regardless of epoll's (unspecified) ready-list order. */
    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds_a[0], CLOAK_REACTOR_WRITABLE, on_either_removes_other, &ctx), 0);
    ASSERT_EQ_INT(cloak_reactor_add_fd(r, fds_b[0], CLOAK_REACTOR_WRITABLE, on_either_removes_other, &ctx), 0);

    cloak_reactor_run(r);

    ASSERT_EQ_INT(ctx.fire_count, 1);

    cloak_reactor_destroy(r);
    close(fds_a[0]);
    close(fds_a[1]);
    close(fds_b[0]);
    close(fds_b[1]);
}

TEST_MAIN_BEGIN()
    test_add_and_dispatch_readable();
    test_dispatch_writable();
    test_add_fd_rejects_duplicate();
    test_mod_fd_changes_interest();
    test_remove_fd_stops_dispatch_in_same_batch();
TEST_MAIN_END()
```

Add to `libcloak-common/tests/CMakeLists.txt` (same pattern as the existing entries in that file):

```cmake
add_executable(test_reactor test_reactor.c)
target_link_libraries(test_reactor PRIVATE cloak-common)
add_test(NAME test_reactor COMMAND test_reactor)
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
docker build -q -f Dockerfile.dev -t cloak-c-dev .
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build && cmake --build build"
```
Expected: FAIL — linker error, `undefined reference to 'cloak_reactor_create'` (and the other `cloak_reactor_*` symbols), since `reactor.c` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `libcloak-common/src/reactor.c`:

```c
#include "cloak/reactor.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

struct watcher {
    int fd;
    uint32_t events;
    cloak_reactor_fd_cb cb;
    void *userdata;
};

struct cloak_reactor {
    int epoll_fd;
    struct watcher **watchers;
    size_t watchers_cap;
    int stopped;
};

static uint32_t to_epoll_events(uint32_t events) {
    uint32_t e = EPOLLET;
    if (events & CLOAK_REACTOR_READABLE) {
        e |= EPOLLIN;
    }
    if (events & CLOAK_REACTOR_WRITABLE) {
        e |= EPOLLOUT;
    }
    return e;
}

static int ensure_capacity(cloak_reactor_t *r, int fd) {
    if ((size_t)fd < r->watchers_cap) {
        return 0;
    }
    size_t new_cap = r->watchers_cap == 0 ? 16 : r->watchers_cap * 2;
    while (new_cap <= (size_t)fd) {
        new_cap *= 2;
    }
    struct watcher **grown = realloc(r->watchers, new_cap * sizeof(*grown));
    if (grown == NULL) {
        return -1;
    }
    for (size_t i = r->watchers_cap; i < new_cap; i++) {
        grown[i] = NULL;
    }
    r->watchers = grown;
    r->watchers_cap = new_cap;
    return 0;
}

cloak_reactor_t *cloak_reactor_create(void) {
    cloak_reactor_t *r = calloc(1, sizeof(*r));
    if (r == NULL) {
        return NULL;
    }
    r->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (r->epoll_fd < 0) {
        free(r);
        return NULL;
    }
    return r;
}

void cloak_reactor_destroy(cloak_reactor_t *r) {
    if (r == NULL) {
        return;
    }
    for (size_t i = 0; i < r->watchers_cap; i++) {
        free(r->watchers[i]);
    }
    free(r->watchers);
    close(r->epoll_fd);
    free(r);
}

int cloak_reactor_add_fd(cloak_reactor_t *r, int fd, uint32_t events,
                          cloak_reactor_fd_cb cb, void *userdata) {
    if (fd < 0 || cb == NULL) {
        return -1;
    }
    if (ensure_capacity(r, fd) != 0) {
        return -1;
    }
    if (r->watchers[fd] != NULL) {
        return -1;
    }

    struct watcher *w = malloc(sizeof(*w));
    if (w == NULL) {
        return -1;
    }
    w->fd = fd;
    w->events = events;
    w->cb = cb;
    w->userdata = userdata;

    struct epoll_event ev;
    ev.events = to_epoll_events(events);
    ev.data.ptr = w;
    if (epoll_ctl(r->epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        free(w);
        return -1;
    }
    r->watchers[fd] = w;
    return 0;
}

int cloak_reactor_mod_fd(cloak_reactor_t *r, int fd, uint32_t events) {
    if (fd < 0 || (size_t)fd >= r->watchers_cap || r->watchers[fd] == NULL) {
        return -1;
    }
    struct watcher *w = r->watchers[fd];
    w->events = events;

    struct epoll_event ev;
    ev.events = to_epoll_events(events);
    ev.data.ptr = w;
    if (epoll_ctl(r->epoll_fd, EPOLL_CTL_MOD, fd, &ev) != 0) {
        return -1;
    }
    return 0;
}

int cloak_reactor_remove_fd(cloak_reactor_t *r, int fd) {
    if (fd < 0 || (size_t)fd >= r->watchers_cap || r->watchers[fd] == NULL) {
        return -1;
    }
    epoll_ctl(r->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    free(r->watchers[fd]);
    r->watchers[fd] = NULL;
    return 0;
}

void cloak_reactor_stop(cloak_reactor_t *r) {
    r->stopped = 1;
}

void cloak_reactor_run(cloak_reactor_t *r) {
    struct epoll_event events[64];

    while (!r->stopped) {
        int n = epoll_wait(r->epoll_fd, events, 64, -1);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        for (int i = 0; i < n && !r->stopped; i++) {
            struct watcher *w = (struct watcher *)events[i].data.ptr;
            int fd = w->fd;
            if ((size_t)fd >= r->watchers_cap || r->watchers[fd] != w) {
                continue; /* removed (or replaced) earlier in this same batch */
            }

            uint32_t fired = 0;
            if (events[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
                fired |= CLOAK_REACTOR_READABLE;
            }
            if (events[i].events & EPOLLOUT) {
                fired |= CLOAK_REACTOR_WRITABLE;
            }
            if (fired != 0) {
                w->cb(r, fd, fired, w->userdata);
            }
        }
    }
}
```

Add `src/reactor.c` to the `add_library(cloak-common STATIC ...)` sources in `libcloak-common/CMakeLists.txt`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake --build build && ctest --test-dir build --output-on-failure"
```
Expected: `100% tests passed, 0 tests failed out of 6` (the 5 existing binaries plus `test_reactor`).

- [ ] **Step 5: Commit**

```bash
git add libcloak-common/include/cloak/reactor.h libcloak-common/src/reactor.c \
        libcloak-common/CMakeLists.txt libcloak-common/tests/CMakeLists.txt \
        libcloak-common/tests/test_reactor.c
git commit -m "Add epoll reactor core: fd registration, dispatch, stop"
```

---

### Task 2: Timers

**Files:**
- Modify: `libcloak-common/include/cloak/reactor.h` (append timer declarations)
- Modify: `libcloak-common/src/reactor.c` (extend `struct cloak_reactor`, `cloak_reactor_destroy`, `cloak_reactor_run`; add timer heap functions)
- Modify: `libcloak-common/tests/test_reactor.c` (append timer tests)

**Interfaces:**
- Consumes: the `struct cloak_reactor` definition, `cloak_reactor_run`'s dispatch loop, and `cloak_reactor_destroy` from Task 1 — this task modifies all three rather than adding independent new code.
- Produces (appended to `cloak/reactor.h`):
  ```c
  typedef uint64_t cloak_timer_id_t;
  #define CLOAK_TIMER_INVALID ((cloak_timer_id_t)0)

  typedef void (*cloak_reactor_timer_cb)(cloak_reactor_t *r, void *userdata);

  cloak_timer_id_t cloak_reactor_add_timer(cloak_reactor_t *r, uint64_t delay_ms,
                                            cloak_reactor_timer_cb cb, void *userdata);
  void cloak_reactor_cancel_timer(cloak_reactor_t *r, cloak_timer_id_t id);
  ```
  This is the complete, final state of the reactor's public API for this plan. Timers fire once (not periodic), measured from `CLOCK_MONOTONIC`. `cloak_reactor_run` now computes `epoll_wait`'s timeout from the earliest pending timer instead of always blocking forever, and fires expired timers after processing each batch of fd events. Later plans (the mux's session inactivity timeout, the server dispatcher's first-packet read timeout, the client's reconnect backoff) depend on this exact signature.

- [ ] **Step 1: Write the failing test**

Append to `libcloak-common/include/cloak/reactor.h`, before the final `#endif` (after the `cloak_reactor_stop` declaration):

```c
typedef uint64_t cloak_timer_id_t;
#define CLOAK_TIMER_INVALID ((cloak_timer_id_t)0)

typedef void (*cloak_reactor_timer_cb)(cloak_reactor_t *r, void *userdata);

/* Schedules cb to run once, delay_ms from now (CLOCK_MONOTONIC). Returns a
 * timer id usable with cloak_reactor_cancel_timer, or CLOAK_TIMER_INVALID
 * on failure (cb is NULL, or an allocation failure growing the timer
 * heap). */
cloak_timer_id_t cloak_reactor_add_timer(cloak_reactor_t *r, uint64_t delay_ms,
                                          cloak_reactor_timer_cb cb, void *userdata);

/* Cancels a pending timer. A no-op if id is CLOAK_TIMER_INVALID, already
 * fired, or already cancelled. */
void cloak_reactor_cancel_timer(cloak_reactor_t *r, cloak_timer_id_t id);
```

Append to `libcloak-common/tests/test_reactor.c`, before `TEST_MAIN_BEGIN()`:

```c
#include <time.h>

static uint64_t test_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

struct timer_fire_ctx {
    int fired;
};

static void on_timer_fire_and_stop(cloak_reactor_t *r, void *userdata) {
    struct timer_fire_ctx *ctx = (struct timer_fire_ctx *)userdata;
    ctx->fired = 1;
    cloak_reactor_stop(r);
}

static void test_timer_fires_after_delay(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct timer_fire_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    uint64_t start = test_now_ms();
    cloak_timer_id_t id = cloak_reactor_add_timer(r, 20, on_timer_fire_and_stop, &ctx);
    ASSERT_TRUE(id != CLOAK_TIMER_INVALID);

    cloak_reactor_run(r);
    uint64_t elapsed = test_now_ms() - start;

    ASSERT_TRUE(ctx.fired);
    ASSERT_TRUE(elapsed >= 15); /* small slack below the 20ms target */
    ASSERT_TRUE(elapsed < 2000); /* generous upper bound: catches a broken timeout computation that blocks forever */

    cloak_reactor_destroy(r);
}

struct cancel_ctx {
    int should_not_fire_flag;
    int stopper_flag;
};

static void on_should_not_fire(cloak_reactor_t *r, void *userdata) {
    (void)r;
    struct cancel_ctx *ctx = (struct cancel_ctx *)userdata;
    ctx->should_not_fire_flag = 1;
}

static void on_stopper(cloak_reactor_t *r, void *userdata) {
    struct cancel_ctx *ctx = (struct cancel_ctx *)userdata;
    ctx->stopper_flag = 1;
    cloak_reactor_stop(r);
}

static void test_cancel_timer_prevents_firing(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct cancel_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    cloak_timer_id_t id = cloak_reactor_add_timer(r, 10, on_should_not_fire, &ctx);
    ASSERT_TRUE(id != CLOAK_TIMER_INVALID);
    cloak_reactor_cancel_timer(r, id);

    ASSERT_TRUE(cloak_reactor_add_timer(r, 20, on_stopper, &ctx) != CLOAK_TIMER_INVALID);

    cloak_reactor_run(r);

    ASSERT_TRUE(ctx.stopper_flag);
    ASSERT_TRUE(!ctx.should_not_fire_flag);

    cloak_reactor_destroy(r);
}

struct order_ctx {
    int log[3];
    int log_len;
};

static void on_order_20ms(cloak_reactor_t *r, void *userdata) {
    (void)r;
    struct order_ctx *ctx = (struct order_ctx *)userdata;
    ctx->log[ctx->log_len++] = 20;
}
static void on_order_60ms(cloak_reactor_t *r, void *userdata) {
    (void)r;
    struct order_ctx *ctx = (struct order_ctx *)userdata;
    ctx->log[ctx->log_len++] = 60;
}
static void on_order_120ms(cloak_reactor_t *r, void *userdata) {
    struct order_ctx *ctx = (struct order_ctx *)userdata;
    ctx->log[ctx->log_len++] = 120;
    cloak_reactor_stop(r);
}

static void test_multiple_timers_fire_in_order(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    struct order_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Added out of chronological order on purpose, to prove the heap
     * orders by deadline, not insertion order. */
    ASSERT_TRUE(cloak_reactor_add_timer(r, 120, on_order_120ms, &ctx) != CLOAK_TIMER_INVALID);
    ASSERT_TRUE(cloak_reactor_add_timer(r, 20, on_order_20ms, &ctx) != CLOAK_TIMER_INVALID);
    ASSERT_TRUE(cloak_reactor_add_timer(r, 60, on_order_60ms, &ctx) != CLOAK_TIMER_INVALID);

    cloak_reactor_run(r);

    ASSERT_EQ_INT(ctx.log_len, 3);
    ASSERT_EQ_INT(ctx.log[0], 20);
    ASSERT_EQ_INT(ctx.log[1], 60);
    ASSERT_EQ_INT(ctx.log[2], 120);

    cloak_reactor_destroy(r);
}
```

Add these three calls inside `TEST_MAIN_BEGIN() ... TEST_MAIN_END()`, after the existing five:

```c
    test_timer_fires_after_delay();
    test_cancel_timer_prevents_firing();
    test_multiple_timers_fire_in_order();
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake --build build"
```
Expected: FAIL — linker error, `undefined reference to 'cloak_reactor_add_timer'`.

- [ ] **Step 3: Write the implementation**

In `libcloak-common/src/reactor.c`, add `#include <time.h>` to the top (alongside the existing includes), then replace the `struct cloak_reactor` definition with:

```c
struct timer_entry {
    uint64_t deadline_ms;
    uint64_t id;
    cloak_reactor_timer_cb cb;
    void *userdata;
    int cancelled;
};

struct cloak_reactor {
    int epoll_fd;
    struct watcher **watchers;
    size_t watchers_cap;
    int stopped;

    struct timer_entry *timers;
    size_t timer_count;
    size_t timer_cap;
    uint64_t next_timer_id;
};
```

Add these functions right after `ensure_capacity` (before `cloak_reactor_create`):

```c
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static void timer_swap(struct timer_entry *a, struct timer_entry *b) {
    struct timer_entry tmp = *a;
    *a = *b;
    *b = tmp;
}

static void heap_sift_up(cloak_reactor_t *r, size_t i) {
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (r->timers[parent].deadline_ms <= r->timers[i].deadline_ms) {
            break;
        }
        timer_swap(&r->timers[parent], &r->timers[i]);
        i = parent;
    }
}

static void heap_sift_down(cloak_reactor_t *r, size_t i) {
    for (;;) {
        size_t left = 2 * i + 1;
        size_t right = 2 * i + 2;
        size_t smallest = i;
        if (left < r->timer_count && r->timers[left].deadline_ms < r->timers[smallest].deadline_ms) {
            smallest = left;
        }
        if (right < r->timer_count && r->timers[right].deadline_ms < r->timers[smallest].deadline_ms) {
            smallest = right;
        }
        if (smallest == i) {
            break;
        }
        timer_swap(&r->timers[i], &r->timers[smallest]);
        i = smallest;
    }
}

static int timer_heap_ensure_capacity(cloak_reactor_t *r) {
    if (r->timer_count < r->timer_cap) {
        return 0;
    }
    size_t new_cap = r->timer_cap == 0 ? 8 : r->timer_cap * 2;
    struct timer_entry *grown = realloc(r->timers, new_cap * sizeof(*grown));
    if (grown == NULL) {
        return -1;
    }
    r->timers = grown;
    r->timer_cap = new_cap;
    return 0;
}

static void heap_pop(cloak_reactor_t *r) {
    r->timer_count--;
    r->timers[0] = r->timers[r->timer_count];
    if (r->timer_count > 0) {
        heap_sift_down(r, 0);
    }
}

/* Fires all expired (non-cancelled) timers whose deadline has passed,
 * discarding cancelled ones encountered along the way. */
static void process_expired_timers(cloak_reactor_t *r) {
    uint64_t now = now_ms();
    while (r->timer_count > 0) {
        struct timer_entry top = r->timers[0];
        if (top.cancelled) {
            heap_pop(r);
            continue;
        }
        if (top.deadline_ms > now) {
            break;
        }
        heap_pop(r);
        top.cb(r, top.userdata);
    }
}

/* Returns the epoll_wait timeout in ms: -1 if there are no live timers,
 * otherwise the ms remaining until the earliest one (>= 0). */
static int compute_timeout_ms(cloak_reactor_t *r) {
    while (r->timer_count > 0 && r->timers[0].cancelled) {
        heap_pop(r);
    }
    if (r->timer_count == 0) {
        return -1;
    }
    uint64_t now = now_ms();
    if (r->timers[0].deadline_ms <= now) {
        return 0;
    }
    uint64_t diff = r->timers[0].deadline_ms - now;
    return diff > (uint64_t)2147483647 ? 2147483647 : (int)diff;
}
```

Replace `cloak_reactor_destroy` with:

```c
void cloak_reactor_destroy(cloak_reactor_t *r) {
    if (r == NULL) {
        return;
    }
    for (size_t i = 0; i < r->watchers_cap; i++) {
        free(r->watchers[i]);
    }
    free(r->watchers);
    free(r->timers);
    close(r->epoll_fd);
    free(r);
}
```

Add these two functions after `cloak_reactor_stop` (before `cloak_reactor_run`):

```c
cloak_timer_id_t cloak_reactor_add_timer(cloak_reactor_t *r, uint64_t delay_ms,
                                          cloak_reactor_timer_cb cb, void *userdata) {
    if (cb == NULL) {
        return CLOAK_TIMER_INVALID;
    }
    if (timer_heap_ensure_capacity(r) != 0) {
        return CLOAK_TIMER_INVALID;
    }
    size_t idx = r->timer_count;
    struct timer_entry *e = &r->timers[idx];
    e->deadline_ms = now_ms() + delay_ms;
    e->id = ++r->next_timer_id;
    e->cb = cb;
    e->userdata = userdata;
    e->cancelled = 0;
    r->timer_count++;
    heap_sift_up(r, idx);
    return e->id;
}

void cloak_reactor_cancel_timer(cloak_reactor_t *r, cloak_timer_id_t id) {
    if (id == CLOAK_TIMER_INVALID) {
        return;
    }
    for (size_t i = 0; i < r->timer_count; i++) {
        if (r->timers[i].id == id) {
            r->timers[i].cancelled = 1;
            return;
        }
    }
}
```

Finally, replace `cloak_reactor_run`'s body to compute the timeout and process expired timers:

```c
void cloak_reactor_run(cloak_reactor_t *r) {
    struct epoll_event events[64];

    while (!r->stopped) {
        int timeout_ms = compute_timeout_ms(r);
        int n = epoll_wait(r->epoll_fd, events, 64, timeout_ms);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        for (int i = 0; i < n && !r->stopped; i++) {
            struct watcher *w = (struct watcher *)events[i].data.ptr;
            int fd = w->fd;
            if ((size_t)fd >= r->watchers_cap || r->watchers[fd] != w) {
                continue; /* removed (or replaced) earlier in this same batch */
            }

            uint32_t fired = 0;
            if (events[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
                fired |= CLOAK_REACTOR_READABLE;
            }
            if (events[i].events & EPOLLOUT) {
                fired |= CLOAK_REACTOR_WRITABLE;
            }
            if (fired != 0) {
                w->cb(r, fd, fired, w->userdata);
            }
        }
        if (!r->stopped) {
            process_expired_timers(r);
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake --build build && ctest --test-dir build --output-on-failure"
```
Expected: `100% tests passed, 0 tests failed out of 6` (all binaries, `test_reactor` now has 8 test cases: the 5 from Task 1 plus 3 timer tests).

- [ ] **Step 5: Commit**

```bash
git add libcloak-common/include/cloak/reactor.h libcloak-common/src/reactor.c libcloak-common/tests/test_reactor.c
git commit -m "Add timer heap to the reactor"
```

---

## What comes after this plan

This plan builds the reactor in isolation — no sockets are ever accepted or connected by this code, no protocol bytes are parsed. Per the design spec's module breakdown, the next plans in dependency order are:

1. **`libcloak-mux`: frame codec** — the `Frame` struct and `obfuscate`/`deobfuscate` logic (spec §4), built on `cloak_aead_seal/open` and `cloak_salsa20_xor` from the crypto plan. Does not depend on the reactor.
2. **`libcloak-common`: ClientHello templates** — captured browser bytes, offset table, SNI patcher (spec §5). Pure byte manipulation, does not depend on the reactor either.
3. **`libcloak-mux`: session/stream/switchboard** — multiplexing (spec §6), the first module that actually uses `cloak_reactor_t` to drive its data-plane splicing between a local proxy socket and a stream's buffers.
4. **`libcloak-server`**: dispatcher state machine (built directly on the reactor from this plan — the per-connection first-packet parsing described in spec §7 is exactly the kind of resumable-across-readable-events state machine this reactor is designed for), auth, redirect-on-fail, SQLite user manager, admin API.
5. **`libcloak-client`**: connector, direct transport, CDN/WebSocket transport via `libssl`.
6. **`cmd/ck-server`, `cmd/ck-client`**: CLI binaries.
7. Integration tests and fuzz targets spanning the assembled binaries.

## Self-review notes

- **Spec coverage:** spec §3's reactor requirements — fd registration, edge-triggered callbacks, timer heap — are each covered by a task. The struct/API is intentionally minimal (no periodic timers, no signal handling, no multi-fd batching beyond the fixed 64-event buffer) since nothing in spec §3 asks for those and later plans haven't been written yet to demand them (YAGNI).
- **Placeholder scan:** no TBD/TODO; every step has complete, runnable code.
- **Type consistency:** `cloak_reactor_t`, `CLOAK_REACTOR_READABLE`/`WRITABLE`, `cloak_reactor_fd_cb`, and all five Task 1 function signatures are defined once and used identically in Task 2 (which only *appends* to the same header and *modifies* specific functions/struct by name, never redefines them under a different name). `cloak_timer_id_t`, `CLOAK_TIMER_INVALID`, and `cloak_reactor_timer_cb` are defined once in Task 2 and used consistently across its own tests.
- **Docker constraint:** every build/test command in both tasks routes through the `docker build`/`docker run` invocation specified in Global Constraints, per the platform mismatch between the Linux-only target and the macOS development machine.
