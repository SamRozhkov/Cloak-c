# libcloak-mux: Backpressure Signals and the Stream Relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a multiplexed stream usable from the reactor the same way a socket already is — give `cloak_session_t` the two notifications a reactor-driven consumer needs (inbound data arrived on an existing stream; the outbound queue drained) plus queue-depth accessors, and build `cloak_stream_relay_t` on top: a bidirectional splice between one `cloak_stream_t` and one file descriptor, with backpressure in both directions.

**Architecture:** The session already routes deobfuscated frames into streams and already drains its outbound queues on `EPOLLOUT`; what it never did was tell anyone. Tasks 1 and 2 add exactly those two edges — a drained notification propagated `conn → switchboard → session`, and a stream-data notification fired when a frame lands on an already-known stream — plus accessors so a producer can ask how backed up the wire is before pushing more into it. Task 3 then builds the relay that the server dispatcher and the client's local listener both need. It is deliberately shaped like the socket-to-socket `cloak_relay_t` that already exists (`start`/`stop`, a `done` callback, one fixed-capacity queue per direction, read interest deregistered when a queue fills), so the two read as siblings rather than as two unrelated designs.

**Tech Stack:** C11, CMake, CTest with the project's existing assert-based test framework.

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` — §6's "Data plane" paragraph ("event-driven splicing between the local proxy socket and the stream's buffers: a readable event on one side attempts to enqueue into the other side's write buffer; if that buffer is full, EPOLLIN is deregistered on the source (backpressure) until the destination drains and re-arms it"), which this plan implements for the stream half. §3's no-blocking-anywhere consequence is what makes the notifications necessary at all.

## Global Constraints

- Language: C11, `-Wall -Wextra` clean. Project code must produce zero warnings.
- Platform: Linux only. POSIX APIs are reached by defining `_POSIX_C_SOURCE 200809L` as the first line of the `.c` file that needs them.
- Naming: public symbols prefixed `cloak_`; headers in each library's `include/cloak/` with `CLOAK_<NAME>_H` guards; doc comments in the style of `cloak/crypto.h` and `cloak/net.h` — contract, failure modes, and anything a caller could get wrong.
- **The reactor is edge-triggered.** Read until `EAGAIN`, write until `EAGAIN`, and re-arm deregistered interest to release backpressure. `EPOLLHUP`/`EPOLLERR` are folded into `CLOAK_REACTOR_READABLE` regardless of the registered mask, so never infer success from an event mask.
- **Do not break existing callers.** `cloak_conn_init`'s and `cloak_switchboard_init`'s signatures stay as they are — new callbacks are installed through setters, so `test_conn.c` and `test_switchboard.c` keep compiling unchanged. `cloak_session_config_t` is a struct, so new fields there cost existing callers nothing.
- Existing tests are the regression net for these changes: `test_conn`, `test_switchboard`, `test_session`, `test_stream` and `test_relay` must all keep passing **unmodified**. If one fails, the change altered semantics; fix the change, not the test.
- No allocation on the data path. The relay allocates its two queues once at start.
- Ownership: `cloak_stream_relay_t` owns its file descriptor and closes it when it finishes or is stopped; it does **not** own the stream or the session, and never frees either — releasing the stream stays the caller's job, exactly as `cloak_session_release_stream`'s doc requires.
- Lifetime: like `cloak_relay_t`, a `cloak_stream_relay_t` must stay live and at a fixed address until its terminal event — the reactor holds its address as callback userdata.
- Build and test command (Linux-only project, so everything runs in the `cloak-c-dev` image; adjust the `-w` path for your worktree and never point it at `/src` alone, which would silently build the main checkout):

  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/<branch> cloak-c-dev bash -c \
    'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
  ```

  Sanitizer build: `-B build-asan` with `-DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"`.
- Baseline: 27 tests pass before this plan; 30 after it.
- Reference implementation: the Go original at `/Users/sam/Cloak`. Go needs none of these notifications because every stream has a goroutine blocked on it and backpressure is a blocked `Write`; this plan is the reactor-model equivalent of that, not a port of a Go construct.

---

### Task 1: Send-queue depth and a drained notification

A producer pushing data into a stream faster than the network drains currently gets no warning: `cloak_conn_send` fills `send_q` until it is full, then returns -1, and the switchboard treats that as a broken pool and kills the session. An ordinary slow client is enough to trigger it. This task adds the two things a producer needs to avoid that — a way to ask how full the queue is, and a notification when it empties.

**Files:**
- Modify: `libcloak-mux/include/cloak/conn.h` (add the callback typedef, the setter, and two accessors)
- Modify: `libcloak-mux/src/conn.c` (fire the callback on the drained transition; implement the accessors)
- Modify: `libcloak-mux/include/cloak/switchboard.h` (same three, aggregated over the pool)
- Modify: `libcloak-mux/src/switchboard.c` (install an adapter on each conn it creates; implement the aggregates)
- Modify: `libcloak-mux/include/cloak/session.h` (two new config fields, two accessors)
- Modify: `libcloak-mux/src/session.c` (wire the switchboard callback through)
- Create: `libcloak-mux/tests/test_backpressure.c`
- Modify: `libcloak-mux/tests/CMakeLists.txt` (register `test_backpressure`)

**Interfaces:**
- Consumes: `cloak_bytequeue_len`/`_free_space` (`cloak/bytequeue.h`).
- Produces:
  - `typedef void (*cloak_conn_drained_cb)(cloak_conn_t *c, void *userdata);`
  - `void cloak_conn_set_drained_cb(cloak_conn_t *c, cloak_conn_drained_cb cb, void *userdata);`
  - `size_t cloak_conn_send_queued(const cloak_conn_t *c);` and `size_t cloak_conn_send_capacity(const cloak_conn_t *c);`
  - `typedef void (*cloak_switchboard_drained_cb)(cloak_switchboard_t *sb, void *userdata);`
  - `void cloak_switchboard_set_drained_cb(cloak_switchboard_t *sb, cloak_switchboard_drained_cb cb, void *userdata);`
  - `size_t cloak_switchboard_send_queued(const cloak_switchboard_t *sb);` and `size_t cloak_switchboard_send_capacity(const cloak_switchboard_t *sb);`
  - `typedef void (*cloak_session_writable_cb)(cloak_session_t *sesh, void *userdata);`, the config fields `on_writable`/`on_writable_userdata`, and `size_t cloak_session_send_queued(const cloak_session_t *sesh);` / `size_t cloak_session_send_capacity(const cloak_session_t *sesh);`

- [ ] **Step 1: Write the failing test**

Create `libcloak-mux/tests/test_backpressure.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/conn.h"
#include "cloak/switchboard.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* A socketpair whose receiving end is never read, so the sender's kernel
 * buffer fills and conn's own send_q starts accumulating -- the state
 * this task is about. */
struct pair {
    int local;
    int peer;
};

static int pair_init(struct pair *p) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return -1;
    }
    p->local = fds[0];
    p->peer = fds[1];
    return 0;
}

static void on_envelope_ignore(cloak_conn_t *c, const uint8_t *bytes, size_t len, void *ud) {
    (void)c;
    (void)bytes;
    (void)len;
    (void)ud;
}

static void on_closed_ignore(cloak_conn_t *c, void *ud) {
    (void)c;
    (void)ud;
}

struct drain_capture {
    int calls;
};

static void on_drained(cloak_conn_t *c, void *userdata) {
    (void)c;
    struct drain_capture *cap = userdata;
    cap->calls++;
}

static void test_conn_reports_queue_depth(void) {
    struct pair p;
    ASSERT_EQ_INT(0, pair_init(&p));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_conn_t c;
    ASSERT_EQ_INT(0, cloak_conn_init(&c, p.local, r, 4096, 65536,
                                     on_envelope_ignore, NULL, on_closed_ignore, NULL));

    ASSERT_EQ_INT(65536, (int)cloak_conn_send_capacity(&c));
    ASSERT_EQ_INT(0, (int)cloak_conn_send_queued(&c));

    /* Push until the kernel stops accepting and send_q starts holding
     * bytes. A 4 KiB frame at a time keeps this well under the cap. */
    uint8_t frame[4096];
    memset(frame, 'x', sizeof(frame));
    int sends = 0;
    while (cloak_conn_send_queued(&c) == 0 && sends < 64) {
        ASSERT_EQ_INT(0, cloak_conn_send(&c, frame, sizeof(frame)));
        sends++;
    }
    ASSERT_TRUE(cloak_conn_send_queued(&c) > 0);
    ASSERT_TRUE(cloak_conn_send_queued(&c) <= cloak_conn_send_capacity(&c));

    cloak_conn_destroy(&c);
    close(p.peer);
    cloak_reactor_destroy(r);
}

static void test_conn_fires_drained_on_the_transition(void) {
    struct pair p;
    ASSERT_EQ_INT(0, pair_init(&p));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_conn_t c;
    ASSERT_EQ_INT(0, cloak_conn_init(&c, p.local, r, 4096, 65536,
                                     on_envelope_ignore, NULL, on_closed_ignore, NULL));

    struct drain_capture cap;
    memset(&cap, 0, sizeof(cap));
    cloak_conn_set_drained_cb(&c, on_drained, &cap);

    uint8_t frame[4096];
    memset(frame, 'y', sizeof(frame));

    /* A send that the kernel swallows whole never queues anything, so it
     * must not fire the callback -- the callback marks a transition from
     * queued to empty, not "a write happened". */
    ASSERT_EQ_INT(0, cloak_conn_send(&c, frame, sizeof(frame)));
    ASSERT_EQ_INT(0, cap.calls);

    /* Fill until bytes are genuinely queued. */
    int sends = 0;
    while (cloak_conn_send_queued(&c) == 0 && sends < 64) {
        ASSERT_EQ_INT(0, cloak_conn_send(&c, frame, sizeof(frame)));
        sends++;
    }
    ASSERT_TRUE(cloak_conn_send_queued(&c) > 0);
    ASSERT_EQ_INT(0, cap.calls);

    /* Drain the peer so the kernel accepts the backlog, then turn the
     * reactor until the queue empties. */
    uint8_t sink[8192];
    for (int spin = 0; spin < 10000 && cloak_conn_send_queued(&c) > 0; spin++) {
        ssize_t n = read(p.peer, sink, sizeof(sink));
        (void)n;
        cloak_reactor_run_once(r, 10);
    }

    ASSERT_EQ_INT(0, (int)cloak_conn_send_queued(&c));
    ASSERT_EQ_INT(1, cap.calls);

    cloak_conn_destroy(&c);
    close(p.peer);
    cloak_reactor_destroy(r);
}

struct sb_drain_capture {
    int calls;
};

static void on_sb_envelope(cloak_switchboard_t *sb, const uint8_t *bytes, size_t len, void *ud) {
    (void)sb;
    (void)bytes;
    (void)len;
    (void)ud;
}

static void on_sb_broken(cloak_switchboard_t *sb, void *ud) {
    (void)sb;
    (void)ud;
}

static void on_sb_drained(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    struct sb_drain_capture *cap = userdata;
    cap->calls++;
}

static void test_switchboard_aggregates_and_forwards(void) {
    struct pair p1;
    struct pair p2;
    ASSERT_EQ_INT(0, pair_init(&p1));
    ASSERT_EQ_INT(0, pair_init(&p2));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    cloak_switchboard_t sb;
    ASSERT_EQ_INT(0, cloak_switchboard_init(&sb, r, 4096, 65536,
                                            on_sb_envelope, NULL, on_sb_broken, NULL));

    struct sb_drain_capture cap;
    memset(&cap, 0, sizeof(cap));
    cloak_switchboard_set_drained_cb(&sb, on_sb_drained, &cap);

    ASSERT_EQ_INT(0, cloak_switchboard_add_conn(&sb, p1.local));
    ASSERT_EQ_INT(0, cloak_switchboard_add_conn(&sb, p2.local));

    /* Capacity is the sum over the pool; nothing is queued yet. */
    ASSERT_EQ_INT(2 * 65536, (int)cloak_switchboard_send_capacity(&sb));
    ASSERT_EQ_INT(0, (int)cloak_switchboard_send_queued(&sb));

    uint8_t frame[4096];
    memset(frame, 'z', sizeof(frame));
    int sends = 0;
    while (cloak_switchboard_send_queued(&sb) == 0 && sends < 128) {
        ASSERT_EQ_INT(0, cloak_switchboard_send(&sb, frame, sizeof(frame)));
        sends++;
    }
    ASSERT_TRUE(cloak_switchboard_send_queued(&sb) > 0);

    uint8_t sink[8192];
    for (int spin = 0; spin < 20000 && cloak_switchboard_send_queued(&sb) > 0; spin++) {
        (void)read(p1.peer, sink, sizeof(sink));
        (void)read(p2.peer, sink, sizeof(sink));
        cloak_reactor_run_once(r, 10);
    }

    ASSERT_EQ_INT(0, (int)cloak_switchboard_send_queued(&sb));
    ASSERT_TRUE(cap.calls >= 1);

    cloak_switchboard_destroy(&sb);
    close(p1.peer);
    close(p2.peer);
    cloak_reactor_destroy(r);
}

static void test_accessors_tolerate_empty_pool(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(0, cloak_switchboard_init(&sb, r, 4096, 65536,
                                            on_sb_envelope, NULL, on_sb_broken, NULL));
    ASSERT_EQ_INT(0, (int)cloak_switchboard_send_queued(&sb));
    ASSERT_EQ_INT(0, (int)cloak_switchboard_send_capacity(&sb));
    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_conn_reports_queue_depth();
    test_conn_fires_drained_on_the_transition();
    test_switchboard_aggregates_and_forwards();
    test_accessors_tolerate_empty_pool();
TEST_MAIN_END()
```

- [ ] **Step 2: Run the test to verify it fails**

Build. Expected: FAIL — `cloak_conn_send_queued` and friends are undeclared.

- [ ] **Step 3: Extend `cloak/conn.h`**

Add, after the existing `cloak_conn_closed_cb` typedef:

```c
/* Fired when this connection's outbound queue transitions from holding
 * buffered bytes to holding none -- the moment a producer that stopped
 * writing because of backpressure may resume. NOT fired for a send the
 * kernel accepted outright (nothing was ever queued, so nothing
 * transitioned), and not fired repeatedly while the queue stays empty.
 *
 * Fired from inside the reactor's writable dispatch for this connection.
 * It is safe to call cloak_conn_send from within it; it is NOT safe to
 * destroy the connection from within it. */
typedef void (*cloak_conn_drained_cb)(cloak_conn_t *c, void *userdata);
```

Add the field `cloak_conn_drained_cb on_drained; void *on_drained_userdata;` to `struct cloak_conn`, and declare:

```c
/* Installs (or, with cb == NULL, removes) the drained notification.
 * Separate from cloak_conn_init so existing callers keep compiling. */
void cloak_conn_set_drained_cb(cloak_conn_t *c, cloak_conn_drained_cb cb, void *userdata);

/* Bytes currently buffered for transmission, and the hard cap given to
 * cloak_conn_init. A producer should treat queued approaching capacity as
 * "stop producing": cloak_conn_send fails once a frame no longer fits,
 * and that failure is fatal to the whole pool, not just this connection. */
size_t cloak_conn_send_queued(const cloak_conn_t *c);
size_t cloak_conn_send_capacity(const cloak_conn_t *c);
```

- [ ] **Step 4: Implement in `conn.c`**

`conn_try_drain_send` already detects the empty case. Change its `avail == 0` branch to fire the callback on the transition — only when something had been queued when this drain attempt began:

```c
static void conn_try_drain_send(cloak_conn_t *c) {
    uint8_t drain_buf[4096];
    /* "Were we in backpressure when this drain began?" -- want_writable
     * is set only when a previous write hit EAGAIN, so it is exactly the
     * state a producer is waiting to see cleared. Deliberately NOT
     * "was anything queued": cloak_conn_send enqueues and then calls this
     * function inline, so a send the kernel swallows whole would look
     * like a queued-then-drained transition and fire the callback on
     * every ordinary write. */
    int was_backpressured = c->want_writable;
    for (;;) {
        size_t avail = cloak_bytequeue_len(&c->send_q);
        if (avail == 0) {
            conn_set_want_writable(c, 0);
            /* The moment a backpressured producer may resume. Fired last,
             * after the interest mask is already correct, so a
             * cloak_conn_send from within the callback sees consistent
             * state. */
            if (was_backpressured && c->on_drained != NULL) {
                c->on_drained(c, c->on_drained_userdata);
            }
            return;
        }
        /* ... rest of the existing loop body, unchanged ... */
    }
}
```

Leave every other line of that function exactly as it is. Then add:

```c
void cloak_conn_set_drained_cb(cloak_conn_t *c, cloak_conn_drained_cb cb, void *userdata) {
    if (c == NULL) {
        return;
    }
    c->on_drained = cb;
    c->on_drained_userdata = userdata;
}

size_t cloak_conn_send_queued(const cloak_conn_t *c) {
    if (c == NULL) {
        return 0;
    }
    return cloak_bytequeue_len(&c->send_q);
}

size_t cloak_conn_send_capacity(const cloak_conn_t *c) {
    if (c == NULL) {
        return 0;
    }
    return cloak_bytequeue_len(&c->send_q) + cloak_bytequeue_free_space(&c->send_q);
}
```

`cloak_conn_init` must zero `on_drained`/`on_drained_userdata`; it already `memset`s or assigns every field, so add the two assignments alongside the existing ones rather than relying on the caller.

- [ ] **Step 5: Extend `cloak/switchboard.h` and `switchboard.c`**

Header, after `cloak_switchboard_broken_cb`:

```c
/* Fired when any connection in the pool finishes draining its outbound
 * queue (see cloak_conn_drained_cb). Because the pool spreads frames
 * across connections, a producer should re-check
 * cloak_switchboard_send_queued rather than assume the whole pool is
 * empty when this fires. */
typedef void (*cloak_switchboard_drained_cb)(cloak_switchboard_t *sb, void *userdata);
```

Add `cloak_switchboard_drained_cb on_drained; void *on_drained_userdata;` to `struct cloak_switchboard`, and declare:

```c
void cloak_switchboard_set_drained_cb(cloak_switchboard_t *sb, cloak_switchboard_drained_cb cb,
                                       void *userdata);

/* Summed over every connection in the pool. An empty pool reports 0 for
 * both -- a producer must therefore treat capacity == 0 as "cannot send
 * right now", not as "no limit". */
size_t cloak_switchboard_send_queued(const cloak_switchboard_t *sb);
size_t cloak_switchboard_send_capacity(const cloak_switchboard_t *sb);
```

In `switchboard.c`, add the adapter beside the two existing ones:

```c
static void switchboard_conn_drained_adapter(cloak_conn_t *c, void *userdata) {
    (void)c;
    cloak_switchboard_t *sb = (cloak_switchboard_t *)userdata;
    if (sb->on_drained != NULL) {
        sb->on_drained(sb, sb->on_drained_userdata);
    }
}
```

In `cloak_switchboard_add_conn`, immediately after the successful `cloak_conn_init`, install it:

```c
    cloak_conn_set_drained_cb(c, switchboard_conn_drained_adapter, sb);
```

And the three new public functions:

```c
void cloak_switchboard_set_drained_cb(cloak_switchboard_t *sb, cloak_switchboard_drained_cb cb,
                                       void *userdata) {
    if (sb == NULL) {
        return;
    }
    sb->on_drained = cb;
    sb->on_drained_userdata = userdata;
}

size_t cloak_switchboard_send_queued(const cloak_switchboard_t *sb) {
    if (sb == NULL) {
        return 0;
    }
    size_t total = 0;
    for (size_t i = 0; i < sb->conns_len; i++) {
        total += cloak_conn_send_queued(sb->conns[i]);
    }
    return total;
}

size_t cloak_switchboard_send_capacity(const cloak_switchboard_t *sb) {
    if (sb == NULL) {
        return 0;
    }
    size_t total = 0;
    for (size_t i = 0; i < sb->conns_len; i++) {
        total += cloak_conn_send_capacity(sb->conns[i]);
    }
    return total;
}
```

`cloak_switchboard_init` must zero the two new fields; it `memset`s `sb` already, so confirm rather than add.

- [ ] **Step 6: Extend `cloak/session.h` and `session.c`**

Header — a typedef beside the existing session callbacks:

```c
/* Fired when the session's outbound queues drain (see
 * cloak_switchboard_drained_cb). A producer that stopped feeding data
 * into a stream because cloak_session_send_queued was approaching
 * capacity resumes here. */
typedef void (*cloak_session_writable_cb)(cloak_session_t *sesh, void *userdata);
```

Two new fields at the end of `cloak_session_config_t`:

```c
    cloak_session_writable_cb on_writable;
    void *on_writable_userdata;
```

Two new fields on `struct cloak_session` mirroring them, and two accessors:

```c
/* The session's outbound pressure, summed over its underlying
 * connections. cloak_stream_write does not fail on a full queue -- the
 * failure surfaces one layer down as a broken pool that kills the whole
 * session -- so a producer MUST consult these before writing large
 * amounts, rather than relying on an error return that comes too late. */
size_t cloak_session_send_queued(const cloak_session_t *sesh);
size_t cloak_session_send_capacity(const cloak_session_t *sesh);
```

In `session.c`, add the adapter and wire it in `cloak_session_init` right after the switchboard is initialized:

```c
static void session_switchboard_drained_adapter(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    if (sesh->on_writable != NULL) {
        sesh->on_writable(sesh, sesh->on_writable_userdata);
    }
}
```

```c
    sesh->on_writable = config->on_writable;
    sesh->on_writable_userdata = config->on_writable_userdata;
    cloak_switchboard_set_drained_cb(&sesh->sb, session_switchboard_drained_adapter, sesh);
```

and:

```c
size_t cloak_session_send_queued(const cloak_session_t *sesh) {
    if (sesh == NULL) {
        return 0;
    }
    return cloak_switchboard_send_queued(&sesh->sb);
}

size_t cloak_session_send_capacity(const cloak_session_t *sesh) {
    if (sesh == NULL) {
        return 0;
    }
    return cloak_switchboard_send_capacity(&sesh->sb);
}
```

- [ ] **Step 7: Register the test and run everything**

Append to `libcloak-mux/tests/CMakeLists.txt`:

```cmake
add_executable(test_backpressure test_backpressure.c)
target_include_directories(test_backpressure PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_backpressure PRIVATE cloak-mux)
add_test(NAME test_backpressure COMMAND test_backpressure)
set_tests_properties(test_backpressure PROPERTIES TIMEOUT 60)
```

Run the full suite. Expected: 28 tests, all passing, with `test_conn`, `test_switchboard` and `test_session` passing **unmodified** — they are the regression net for the `conn_try_drain_send` change.

- [ ] **Step 8: Commit**

```bash
git add libcloak-mux/include/cloak/conn.h libcloak-mux/src/conn.c \
        libcloak-mux/include/cloak/switchboard.h libcloak-mux/src/switchboard.c \
        libcloak-mux/include/cloak/session.h libcloak-mux/src/session.c \
        libcloak-mux/tests/test_backpressure.c libcloak-mux/tests/CMakeLists.txt
git commit -m "Add send-queue depth accessors and a drained notification"
```

---

### Task 2: A stream-data notification

A reactor-driven consumer has no way to learn that bytes arrived on a stream it already knows about: `cloak_stream_read` is pull-only, and `on_new_stream` fires once. This adds the missing edge.

**Files:**
- Modify: `libcloak-mux/include/cloak/session.h` (typedef + two config fields + two struct fields)
- Modify: `libcloak-mux/src/session.c` (fire it on the existing-stream routing path)
- Modify: `libcloak-mux/tests/test_backpressure.c` — no; create: `libcloak-mux/tests/test_stream_data_cb.c`
- Modify: `libcloak-mux/tests/CMakeLists.txt` (register `test_stream_data_cb`)

**Interfaces:**
- Consumes: the session routing path in `session.c` (the `found && state == CLOAK_STRMTAB_ACTIVE` branch).
- Produces: `typedef void (*cloak_session_stream_data_cb)(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata);` plus the config fields `on_stream_data`/`on_stream_data_userdata`.

**The one design decision, and why:** this callback fires **only for frames routed to an already-known stream**, never for the frame that created a stream. That is not an oversight. `on_new_stream` already tells a consumer "this stream exists and may already have readable data" (its own doc comment says so), and firing a second callback afterwards would be actively unsafe: `on_new_stream` is explicitly allowed to call `cloak_session_release_stream`, which frees the stream, so a follow-up callback carrying that pointer would hand the consumer freed memory. Consumers drain on `on_new_stream` for the first frame and on `on_stream_data` for every frame after it. The header must say this plainly.

- [ ] **Step 1: Write the failing test**

Create `libcloak-mux/tests/test_stream_data_cb.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/session.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Two sessions wired to each other over a socketpair, so one can open a
 * stream and write to it and the other observes the callbacks. */
struct endpoint {
    cloak_session_t sesh;
    cloak_stream_t *accepted;
    int new_stream_calls;
    int data_calls;
    int last_data_len;
};

static void on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct endpoint *ep = userdata;
    ep->new_stream_calls++;
    ep->accepted = stream;
}

static void on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct endpoint *ep = userdata;
    ep->data_calls++;
    uint8_t buf[4096];
    long n = cloak_stream_read(stream, buf, sizeof(buf));
    ep->last_data_len = n > 0 ? (int)n : 0;
}

static void on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    (void)userdata;
}

static void fill_config(cloak_session_config_t *cfg, struct endpoint *ep,
                        const cloak_obfuscator_t *obfs) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->obfuscator = *obfs;
    cfg->max_on_wire_size = 16401;
    cfg->stream_recv_capacity = 65536;
    cfg->stream_max_pending_frames = 64;
    cfg->conn_send_queue_cap = 262144;
    cfg->inactivity_timeout_ms = 60000;
    cfg->on_new_stream = on_new_stream;
    cfg->on_new_stream_userdata = ep;
    cfg->on_stream_data = on_stream_data;
    cfg->on_stream_data_userdata = ep;
    cfg->on_broken = on_broken;
    cfg->on_broken_userdata = ep;
}

static void test_data_callback_fires_for_subsequent_frames_only(void) {
    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    uint8_t key[CLOAK_AEAD_KEY_LEN];
    memset(key, 0x5a, sizeof(key));
    cloak_obfuscator_t obfs;
    ASSERT_EQ_INT(0, cloak_obfuscator_init(&obfs, CLOAK_AEAD_AES_256_GCM, key));

    struct endpoint a;
    struct endpoint b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    cloak_session_config_t cfg_a;
    cloak_session_config_t cfg_b;
    fill_config(&cfg_a, &a, &obfs);
    fill_config(&cfg_b, &b, &obfs);

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 1, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 1, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }

    /* First write creates the stream on b: on_new_stream fires, and the
     * data callback deliberately does not. */
    ASSERT_EQ_INT(5, (int)cloak_stream_write(s, (const uint8_t *)"hello", 5));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);
    ASSERT_EQ_INT(0, b.data_calls);

    /* Drain what the first frame delivered, so the next assertion is
     * about the second frame's bytes and not leftovers. */
    uint8_t buf[64];
    ASSERT_EQ_INT(5, (int)cloak_stream_read(b.accepted, buf, sizeof(buf)));
    ASSERT_MEM_EQ(buf, "hello", 5);

    /* Second write lands on a stream b already knows: now the data
     * callback is the only notification, and it can read the bytes. */
    ASSERT_EQ_INT(6, (int)cloak_stream_write(s, (const uint8_t *)"world!", 6));
    for (int i = 0; i < 50 && b.data_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);
    ASSERT_EQ_INT(1, b.data_calls);
    ASSERT_EQ_INT(6, b.last_data_len);

    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

static void test_absent_callback_is_not_required(void) {
    /* A config that leaves on_stream_data NULL must still route frames --
     * the notification is optional, like every other session callback. */
    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    uint8_t key[CLOAK_AEAD_KEY_LEN];
    memset(key, 0x31, sizeof(key));
    cloak_obfuscator_t obfs;
    ASSERT_EQ_INT(0, cloak_obfuscator_init(&obfs, CLOAK_AEAD_AES_256_GCM, key));

    struct endpoint a;
    struct endpoint b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    cloak_session_config_t cfg_a;
    cloak_session_config_t cfg_b;
    fill_config(&cfg_a, &a, &obfs);
    fill_config(&cfg_b, &b, &obfs);
    cfg_b.on_stream_data = NULL;
    cfg_b.on_stream_data_userdata = NULL;

    ASSERT_EQ_INT(0, cloak_session_init(&a.sesh, 2, r, &cfg_a));
    ASSERT_EQ_INT(0, cloak_session_init(&b.sesh, 2, r, &cfg_b));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&a.sesh, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&b.sesh, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&a.sesh, NULL);
    ASSERT_TRUE(s != NULL);
    if (s == NULL) {
        return;
    }
    ASSERT_EQ_INT(3, (int)cloak_stream_write(s, (const uint8_t *)"abc", 3));
    for (int i = 0; i < 50 && b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, b.new_stream_calls);

    ASSERT_EQ_INT(3, (int)cloak_stream_write(s, (const uint8_t *)"def", 3));
    for (int i = 0; i < 50; i++) {
        cloak_reactor_run_once(r, 10);
    }
    /* No callback, but the bytes still arrived and are readable. */
    uint8_t buf[64];
    long total = 0;
    long n;
    while ((n = cloak_stream_read(b.accepted, buf, sizeof(buf))) > 0) {
        total += n;
    }
    ASSERT_EQ_INT(6, (int)total);
    ASSERT_EQ_INT(0, b.data_calls);

    cloak_session_release_stream(&b.sesh, b.accepted);
    cloak_session_release_stream(&a.sesh, s);
    cloak_session_destroy(&a.sesh);
    cloak_session_destroy(&b.sesh);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_data_callback_fires_for_subsequent_frames_only();
    test_absent_callback_is_not_required();
TEST_MAIN_END()
```

Note for the implementer: `test_session.c` already builds paired sessions over a socketpair — read how it constructs its obfuscator and config and follow that file's conventions where they differ from the sketch above. The sketch's field names must match `cloak_session_config_t` exactly; correct the sketch to the real names rather than the other way round.

- [ ] **Step 2: Run the test to verify it fails**

Build. Expected: FAIL — `cloak_session_config_t` has no `on_stream_data` member.

- [ ] **Step 3: Extend `cloak/session.h`**

```c
/* Fired when one or more frames are routed into a stream this session
 * already knows about, so a reactor-driven consumer knows to drain it
 * with cloak_stream_read.
 *
 * NOT fired for the frame that first creates a stream: on_new_stream
 * already reports that case, and its own doc comment notes the stream may
 * already have readable data when it fires. This is deliberate rather
 * than an omission -- on_new_stream is explicitly permitted to call
 * cloak_session_release_stream, which frees the stream, so firing a
 * second callback with that pointer afterwards would hand the consumer
 * freed memory. Drain on on_new_stream for a stream's first bytes, and on
 * this callback for everything after.
 *
 * Fires after the frame has been fed, so the data is already readable. If
 * the frame closed the stream, the stream is already retired by the time
 * this fires -- it is still safe to read from (draining whatever arrived
 * before the close) and still must be released by the caller. */
typedef void (*cloak_session_stream_data_cb)(cloak_session_t *sesh, cloak_stream_t *stream,
                                              void *userdata);
```

Add `on_stream_data`/`on_stream_data_userdata` to both `cloak_session_config_t` and `struct cloak_session`.

- [ ] **Step 4: Fire it in `session.c`**

In the `found && state == CLOAK_STRMTAB_ACTIVE` branch, after the existing feed-and-retire logic and before the `return`:

```c
    if (found && state == CLOAK_STRMTAB_ACTIVE) {
        cloak_stream_t *stream = (cloak_stream_t *)value;
        int rc = cloak_stream_feed_frame(stream, &frame);
        if (rc == 1 || rc == -1) {
            /* ... existing comment and retire call, unchanged ... */
            session_retire_stream(sesh, stream);
        }
        /* Notify last, after routing and any retirement, so the consumer
         * sees final state: the bytes are readable, and a stream closed
         * by this frame already reads as ended. Fired even when the frame
         * was a protocol violation (rc == -1) so a consumer holding this
         * stream learns to tear its own side down rather than waiting
         * forever for data that will never come. */
        if (sesh->on_stream_data != NULL) {
            sesh->on_stream_data(sesh, stream, sesh->on_stream_data_userdata);
        }
        return;
    }
```

Copy the config fields across in `cloak_session_init` beside the existing ones.

- [ ] **Step 5: Register the test and run everything**

```cmake
add_executable(test_stream_data_cb test_stream_data_cb.c)
target_include_directories(test_stream_data_cb PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_stream_data_cb PRIVATE cloak-mux)
add_test(NAME test_stream_data_cb COMMAND test_stream_data_cb)
set_tests_properties(test_stream_data_cb PROPERTIES TIMEOUT 60)
```

Expected: 29 tests passing, with `test_session` unmodified and still green.

- [ ] **Step 6: Commit**

```bash
git add libcloak-mux/include/cloak/session.h libcloak-mux/src/session.c \
        libcloak-mux/tests/test_stream_data_cb.c libcloak-mux/tests/CMakeLists.txt
git commit -m "Add a stream-data notification for already-known streams"
```

---

### Task 3: `cloak_stream_relay_t` — splice a stream with a socket

The server dispatcher connects an accepted stream to an upstream proxy socket; the client connects a local proxy socket to a stream. Both are this object. It is deliberately shaped like the socket-to-socket `cloak_relay_t` already in `libcloak-common` — `start`/`stop`, a `done` callback, a fixed-capacity queue, read interest dropped when a queue fills — so the two read as siblings.

**Files:**
- Create: `libcloak-mux/include/cloak/stream_relay.h`
- Create: `libcloak-mux/src/stream_relay.c`
- Create: `libcloak-mux/tests/test_stream_relay.c`
- Modify: `libcloak-mux/CMakeLists.txt` (add `src/stream_relay.c`)
- Modify: `libcloak-mux/tests/CMakeLists.txt` (register `test_stream_relay`)

**Interfaces:**
- Consumes: Task 1's `cloak_session_send_queued`/`_capacity`; Task 2's `on_stream_data` (the caller wires it, not this object); `cloak_stream_read`/`cloak_stream_write`; `cloak_session_close_stream`; `cloak_bytequeue_*`; the reactor's `add_fd`/`mod_fd`/`remove_fd`.
- Produces:
  - `typedef void (*cloak_stream_relay_done_cb)(cloak_stream_relay_t *sr, void *userdata);`
  - `int cloak_stream_relay_start(cloak_stream_relay_t *sr, cloak_reactor_t *r, cloak_session_t *sesh, cloak_stream_t *stream, int fd, size_t buf_cap, cloak_stream_relay_done_cb on_done, void *userdata);`
  - `void cloak_stream_relay_notify_stream_data(cloak_stream_relay_t *sr);`
  - `void cloak_stream_relay_notify_writable(cloak_stream_relay_t *sr);`
  - `void cloak_stream_relay_stop(cloak_stream_relay_t *sr);`

**Two things this object does not do,** and the header must say both: it never releases or frees the stream (that stays the caller's, per `cloak_session_release_stream`'s contract), and it is not wired to the session's callbacks by itself — the caller owns those callbacks and forwards them in via the two `notify` functions, because one session multiplexes many streams and only the caller knows which relay a given stream belongs to.

- [ ] **Step 1: Write the failing test**

Create `libcloak-mux/tests/test_stream_relay.c`. Build it on the paired-session harness `test_stream_data_cb.c` established in Task 2 — read that file and reuse its construction rather than inventing a second one. The cases to cover:

```c
/* 1. Bytes written into the stream at the far end come out of the
 *    socket; bytes written into the socket come out of the stream at the
 *    far end. This is the whole point of the object.
 *
 * 2. A large transfer -- at least 512 KiB, far exceeding both buf_cap and
 *    the session's conn_send_queue_cap -- completes intact in the
 *    socket-to-stream direction, which is the direction that can overrun
 *    the session's outbound queue and kill the session. Drive it with a
 *    pump loop (write what the socket accepts, run the reactor a turn,
 *    read what came out, repeat) and compare the received bytes to the
 *    sent ones byte for byte. Without the backpressure check this test
 *    fails by breaking the session, not by corrupting data -- assert the
 *    session is still open at the end, not just that the bytes matched.
 *
 * 3. Closing the socket end fires on_done exactly once, and the far end
 *    of the stream observes the stream ending (cloak_stream_read
 *    eventually returns -1 there).
 *
 * 4. Stream EOF (the far end closes its stream) fires on_done exactly
 *    once and closes the socket -- assert the peer of that socket reads
 *    EOF.
 *
 * 5. cloak_stream_relay_stop is idempotent, does not fire on_done, and is
 *    safe on a relay left by a failed start.
 *
 * 6. A failed cloak_stream_relay_start (buf_cap == 0) leaves the struct
 *    initialized: fill a FRESH cloak_stream_relay_t with 0xAA first,
 *    assert start returns -1, assert sr.fd == -1 directly, then call
 *    cloak_stream_relay_stop on it. Asserting the sentinel directly is
 *    the point -- a struct an earlier successful call already zeroed
 *    would pass whether or not the bug is present, which is exactly how
 *    an equivalent test elsewhere in this project failed to catch
 *    anything. On a failed start the caller still owns fd and must close
 *    it itself.
 */
```

Write those six as real test functions with real assertions, in the style of `test_relay.c` (which covers the same shape for two sockets) — that file is the model for the pump loop, the `on_done` capture struct, and the harness guards.

- [ ] **Step 2: Run the test to verify it fails**

Build. Expected: FAIL — `cloak/stream_relay.h` does not exist.

- [ ] **Step 3: Write the header**

Create `libcloak-mux/include/cloak/stream_relay.h`:

```c
#ifndef CLOAK_STREAM_RELAY_H
#define CLOAK_STREAM_RELAY_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/reactor.h"
#include "cloak/session.h"
#include "cloak/stream.h"

/* Splices one multiplexed stream with one file descriptor: everything
 * readable on the stream is written to the fd, everything readable on the
 * fd is written into the stream. The server dispatcher uses it to connect
 * an accepted stream to an upstream proxy socket; the client uses it to
 * connect a local proxy socket to a stream it opened.
 *
 * Shaped deliberately like cloak_relay_t (cloak/net.h), which does the
 * same job for two sockets: start/stop, a one-shot done callback, a
 * fixed-capacity queue, and read interest dropped when the destination
 * cannot keep up.
 *
 * Two things it does NOT do:
 *
 *  - It never releases or frees the stream. cloak_session_release_stream
 *    is the caller's responsibility, exactly as that function's own doc
 *    comment requires -- this object closes the stream (so the peer
 *    learns) but never frees it.
 *
 *  - It does not subscribe to the session's callbacks itself. One session
 *    multiplexes many streams and only the caller knows which relay a
 *    given stream belongs to, so the caller owns
 *    cloak_session_config_t.on_stream_data and .on_writable and forwards
 *    them in through the two notify functions below. A relay that is
 *    never notified will stall: it has no other way to learn that its
 *    stream became readable or that the session's queue drained. */
typedef struct cloak_stream_relay cloak_stream_relay_t;

/* Fired exactly once, when the relay finishes: the stream ended, the fd
 * ended, or either side errored. The fd is already closed and the stream
 * is already closed (but NOT released) by the time this fires. Never
 * fired by cloak_stream_relay_stop, and never before
 * cloak_stream_relay_start returns. */
typedef void (*cloak_stream_relay_done_cb)(cloak_stream_relay_t *sr, void *userdata);

/* The relay stops reading its fd once the session's outbound queue is
 * this fraction full, and resumes when cloak_stream_relay_notify_writable
 * reports it drained. It is deliberately conservative: cloak_stream_write
 * does not fail on a full queue -- the overrun surfaces one layer down as
 * a broken connection pool that kills the entire session, taking every
 * other stream with it -- so the watermark leaves room for the frames
 * already in flight rather than running the queue to its limit. */
#define CLOAK_STREAM_RELAY_HIGH_WATER_NUM 1
#define CLOAK_STREAM_RELAY_HIGH_WATER_DEN 2

struct cloak_stream_relay {
    cloak_reactor_t *reactor;
    cloak_session_t *sesh;
    cloak_stream_t *stream;
    int fd;

    /* Bytes read from the stream, awaiting write to the fd. The other
     * direction needs no queue: cloak_stream_write always accepts what it
     * is given, so the fd is only read while the session has room. */
    cloak_bytequeue_t to_fd;

    /* 1 while read interest on fd is deregistered because the session's
     * outbound queue is above the watermark. */
    int fd_read_paused;
    uint32_t interest;
    int stream_ended;
    int done;

    cloak_stream_relay_done_cb on_done;
    void *on_done_userdata;
};

/* Starts splicing stream and fd. Ownership of fd passes to the relay,
 * which closes it when it finishes or is stopped; on a FAILED start the
 * caller keeps it and must close it.
 *
 * buf_cap sizes the stream-to-fd queue. sesh must be the session stream
 * belongs to -- it is consulted for outbound pressure, never written to
 * directly.
 *
 * Like every reactor-driven object in this project, sr must stay live and
 * at a fixed address until its terminal event: the reactor holds its
 * address as callback userdata, so storing relays in a realloc-grown
 * array is a use-after-free.
 *
 * Returns 0 on success, -1 on invalid arguments, allocation failure, or a
 * reactor registration failure. On failure sr is left safe to pass to
 * cloak_stream_relay_stop. */
int cloak_stream_relay_start(cloak_stream_relay_t *sr, cloak_reactor_t *r,
                              cloak_session_t *sesh, cloak_stream_t *stream, int fd,
                              size_t buf_cap, cloak_stream_relay_done_cb on_done,
                              void *userdata);

/* Call from the session's on_stream_data callback when the frame was for
 * this relay's stream: drains the stream into the fd. A no-op once the
 * relay has finished. */
void cloak_stream_relay_notify_stream_data(cloak_stream_relay_t *sr);

/* Call from the session's on_writable callback: re-arms fd read interest
 * if it was paused for backpressure. A no-op once the relay has
 * finished, or if it was not paused. */
void cloak_stream_relay_notify_writable(cloak_stream_relay_t *sr);

/* Tears the relay down without firing on_done: unregisters and closes the
 * fd, closes the stream, frees the queue. Does NOT release the stream.
 * Idempotent, and safe on a relay left by a failed start. */
void cloak_stream_relay_stop(cloak_stream_relay_t *sr);

#endif
```

- [ ] **Step 4: Write the implementation**

Create `libcloak-mux/src/stream_relay.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/stream_relay.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define STREAM_RELAY_CHUNK 16384

static void stream_relay_teardown(cloak_stream_relay_t *sr, int fire_done);

/* True while the session's outbound queue is at or above the watermark,
 * so pushing more into the stream risks overrunning it. An empty pool
 * (capacity 0) counts as backed up: there is nowhere to send. */
static int session_is_backed_up(const cloak_stream_relay_t *sr) {
    size_t cap = cloak_session_send_capacity(sr->sesh);
    if (cap == 0) {
        return 1;
    }
    size_t queued = cloak_session_send_queued(sr->sesh);
    return queued * CLOAK_STREAM_RELAY_HIGH_WATER_DEN >=
           cap * CLOAK_STREAM_RELAY_HIGH_WATER_NUM;
}

static uint32_t desired_interest(const cloak_stream_relay_t *sr) {
    uint32_t ev = 0;
    if (!sr->fd_read_paused) {
        ev |= CLOAK_REACTOR_READABLE;
    }
    if (cloak_bytequeue_len(&sr->to_fd) > 0) {
        ev |= CLOAK_REACTOR_WRITABLE;
    }
    return ev;
}

static void sync_interest(cloak_stream_relay_t *sr) {
    if (sr->fd < 0) {
        return;
    }
    uint32_t want = desired_interest(sr);
    /* Suppressing the re-issue only when the mask is zero and was already
     * zero, for the same reason cloak_relay_t does: epoll delivers
     * ERR/HUP regardless of the registered mask, and re-arming a zero
     * mask every turn re-delivers it forever without the read path ever
     * being able to act on it. Any non-zero mask is re-issued
     * unconditionally, because an edge-triggered fd needs the re-arm to
     * re-report data already sitting in the socket buffer. */
    if (want == 0 && sr->interest == 0) {
        return;
    }
    sr->interest = want;
    (void)cloak_reactor_mod_fd(sr->reactor, sr->fd, want);
}

/* Drains the stream into the to_fd queue, then writes the queue out.
 * Returns 0 to continue, -1 if the relay should tear down. */
static int pump_stream_to_fd(cloak_stream_relay_t *sr) {
    uint8_t buf[STREAM_RELAY_CHUNK];

    if (!sr->stream_ended) {
        for (;;) {
            size_t room = cloak_bytequeue_free_space(&sr->to_fd);
            if (room == 0) {
                break; /* backpressure: the fd has not kept up */
            }
            size_t want = room < sizeof(buf) ? room : sizeof(buf);
            long n = cloak_stream_read(sr->stream, buf, want);
            if (n < 0) {
                sr->stream_ended = 1; /* peer closed: flush, then finish */
                break;
            }
            if (n == 0) {
                break; /* nothing ready right now */
            }
            cloak_bytequeue_write(&sr->to_fd, buf, (size_t)n);
        }
    }

    for (;;) {
        size_t have = cloak_bytequeue_peek(&sr->to_fd, buf, sizeof(buf));
        if (have == 0) {
            break;
        }
        ssize_t n = send(sr->fd, buf, have, MSG_NOSIGNAL);
        if (n > 0) {
            cloak_bytequeue_read(&sr->to_fd, buf, (size_t)n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        return -1;
    }

    if (sr->stream_ended && cloak_bytequeue_len(&sr->to_fd) == 0) {
        return -1; /* everything the stream ever sent has reached the fd */
    }
    return 0;
}

/* Reads the fd into the stream while the session has room. Returns 0 to
 * continue, -1 if the relay should tear down. */
static int pump_fd_to_stream(cloak_stream_relay_t *sr) {
    uint8_t buf[STREAM_RELAY_CHUNK];
    for (;;) {
        if (session_is_backed_up(sr)) {
            /* Stop reading; cloak_stream_relay_notify_writable re-arms. */
            sr->fd_read_paused = 1;
            return 0;
        }
        ssize_t n = read(sr->fd, buf, sizeof(buf));
        if (n > 0) {
            if (cloak_stream_write(sr->stream, buf, (size_t)n) < 0) {
                return -1;
            }
            continue;
        }
        if (n == 0) {
            return -1; /* the socket peer closed */
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

static void stream_relay_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    cloak_stream_relay_t *sr = (cloak_stream_relay_t *)userdata;
    if (sr->done) {
        return;
    }

    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        if (pump_stream_to_fd(sr) != 0) {
            stream_relay_teardown(sr, 1);
            return;
        }
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        if (pump_fd_to_stream(sr) != 0) {
            /* Best effort: push anything the stream already delivered out
             * to the fd before closing, mirroring cloak_relay_t's
             * teardown drain. */
            (void)pump_stream_to_fd(sr);
            stream_relay_teardown(sr, 1);
            return;
        }
    }
    sync_interest(sr);
}

static void stream_relay_teardown(cloak_stream_relay_t *sr, int fire_done) {
    if (sr->done) {
        return;
    }
    sr->done = 1;

    if (sr->fd >= 0) {
        cloak_reactor_remove_fd(sr->reactor, sr->fd);
        close(sr->fd);
        sr->fd = -1;
    }
    cloak_bytequeue_destroy(&sr->to_fd);

    /* Tell the peer the stream is over. Never release it -- that is the
     * caller's, per cloak_session_release_stream's contract. A stream
     * that already closed returns -1 here, which is fine. */
    if (sr->sesh != NULL && sr->stream != NULL) {
        (void)cloak_session_close_stream(sr->sesh, sr->stream);
    }

    if (fire_done && sr->on_done != NULL) {
        sr->on_done(sr, sr->on_done_userdata);
    }
}

int cloak_stream_relay_start(cloak_stream_relay_t *sr, cloak_reactor_t *r,
                              cloak_session_t *sesh, cloak_stream_t *stream, int fd,
                              size_t buf_cap, cloak_stream_relay_done_cb on_done,
                              void *userdata) {
    if (sr == NULL) {
        return -1;
    }
    /* Initialize before validating anything else, so every failure path
     * leaves a struct cloak_stream_relay_stop can safely be called on --
     * the same ordering cloak_listener_open and cloak_relay_start use. */
    memset(sr, 0, sizeof(*sr));
    sr->fd = -1;

    if (r == NULL || sesh == NULL || stream == NULL || fd < 0 || buf_cap == 0) {
        return -1;
    }

    if (cloak_bytequeue_init(&sr->to_fd, buf_cap) != 0) {
        return -1;
    }
    if (cloak_reactor_add_fd(r, fd, CLOAK_REACTOR_READABLE, stream_relay_on_event, sr) != 0) {
        cloak_bytequeue_destroy(&sr->to_fd);
        return -1;
    }

    sr->reactor = r;
    sr->sesh = sesh;
    sr->stream = stream;
    sr->fd = fd;
    sr->interest = CLOAK_REACTOR_READABLE;
    sr->on_done = on_done;
    sr->on_done_userdata = userdata;

    /* The stream may already hold bytes delivered before this relay
     * existed -- on_new_stream fires with the first frame already fed. */
    if (pump_stream_to_fd(sr) != 0) {
        stream_relay_teardown(sr, 0);
        return 0; /* started, then immediately finished: see note below */
    }
    sync_interest(sr);
    return 0;
}

void cloak_stream_relay_notify_stream_data(cloak_stream_relay_t *sr) {
    if (sr == NULL || sr->done) {
        return;
    }
    if (pump_stream_to_fd(sr) != 0) {
        stream_relay_teardown(sr, 1);
        return;
    }
    sync_interest(sr);
}

void cloak_stream_relay_notify_writable(cloak_stream_relay_t *sr) {
    if (sr == NULL || sr->done || !sr->fd_read_paused) {
        return;
    }
    if (session_is_backed_up(sr)) {
        return; /* drained, but not below the watermark yet */
    }
    sr->fd_read_paused = 0;
    sync_interest(sr);
}

void cloak_stream_relay_stop(cloak_stream_relay_t *sr) {
    if (sr == NULL) {
        return;
    }
    stream_relay_teardown(sr, 0);
}
```

**One thing to get right in Step 4, and to call out in your report:** the marked `return 0` after an immediate teardown inside `cloak_stream_relay_start` is a contract wrinkle — the start succeeded, but the relay is already finished and `on_done` was deliberately *not* fired, because the header promises `on_done` never fires before `start` returns. A caller would then wait forever for a callback that already cannot come. Resolve it rather than shipping it: either defer that teardown to a zero-delay reactor timer so `on_done` fires normally on the next turn (the approach `cloak_dial_start` already uses for its immediate-success case, and the one to prefer), or make the header state explicitly that a start which finishes immediately returns 0 with `sr->done` set and no callback, and give callers a way to see it. Pick one, implement it, and say which you picked and why.

- [ ] **Step 5: Wire it into the build**

Add `src/stream_relay.c` to `libcloak-mux/CMakeLists.txt`'s source list, and append to `libcloak-mux/tests/CMakeLists.txt`:

```cmake
add_executable(test_stream_relay test_stream_relay.c)
target_include_directories(test_stream_relay PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_stream_relay PRIVATE cloak-mux)
add_test(NAME test_stream_relay COMMAND test_stream_relay)
set_tests_properties(test_stream_relay PROPERTIES TIMEOUT 60)
```

- [ ] **Step 6: Run the full suite**

Expected: 30 tests passing — the 27 from before this plan plus `test_backpressure`, `test_stream_data_cb` and `test_stream_relay`. Every pre-existing test must still pass unmodified.

- [ ] **Step 7: Run the suite under ASan/UBSan**

Mandatory for this task: the relay owns a heap queue and a descriptor across an asynchronous teardown, and the large-transfer case is what exercises the queue's wrap arithmetic under real pressure. Use the sanitizer command from Global Constraints, with the worktree path in `-w`.

- [ ] **Step 8: Commit**

```bash
git add libcloak-mux/include/cloak/stream_relay.h libcloak-mux/src/stream_relay.c \
        libcloak-mux/tests/test_stream_relay.c libcloak-mux/CMakeLists.txt \
        libcloak-mux/tests/CMakeLists.txt
git commit -m "Add stream relay: splice a multiplexed stream with a socket"
```

---

## What comes after this plan

The server dispatcher (spec §7), which is now the only thing standing between this port and a server that runs: a per-connection state machine that sniffs the first byte (`0x16` TLS / `0x47` WebSocket `GET`), buffers a full first packet across non-blocking reads, authenticates it with the already-merged `cloak_server_auth_decrypt`, attaches the connection to a `cloak_session_t`, and on any failure forwards to `RedirAddr` with `cloak_dial_t` + `cloak_relay_t` as Go's `goWeb()` does. It wires `on_new_stream` to a dial plus a `cloak_stream_relay_t` from this plan, and owns the `on_stream_data`/`on_writable` callbacks that feed the two notify functions.

It also carries the obligation recorded in the config module's plan: when it builds the runtime bypass set it **must union `admin_uid` into `bypass_uid`** when `has_admin_uid` is set, or the admin user is subject to accounting.

Out of scope here: any policy about which stream connects to what, the UDP/datagram direction (this relay is stream-oriented only), and rate limiting — Go's `Valve` has no equivalent yet and belongs with the user manager.

## Self-review notes

- **Spec coverage:** §6's data-plane sentence is implemented for the stream half by Task 3 (`desired_interest`/`sync_interest` plus the `fd_read_paused` watermark), completing what the socket half already did. Tasks 1 and 2 exist because §3's "no blocking I/O anywhere" removes Go's mechanism for both signals: Go backpressures by blocking a goroutine inside `Write` and learns about inbound data by blocking in `Read`, neither of which a reactor can do. Nothing here has a Go counterpart to mirror, which is why the plan argues from the spec rather than from `/Users/sam/Cloak`.
- **Placeholder scan:** Tasks 1 and 2 contain complete literal code. Task 3's Step 1 deliberately specifies its six test cases in prose against a named model file (`test_relay.c`) rather than pasting ~400 lines of harness that would diverge from the real `cloak_session_config_t` field names; every case names its assertion and its failure mode. Task 3's Step 4 contains the full implementation, with one wrinkle flagged for the implementer to resolve rather than silently inherit.
- **Type consistency:** `cloak_conn_drained_cb` → `cloak_switchboard_drained_cb` → `cloak_session_writable_cb` form one adapter chain, each layer's adapter shown in its own task. The accessors keep one shape at all three layers (`_send_queued`/`_send_capacity`, `size_t`, NULL-tolerant). Task 3 consumes `cloak_session_send_queued`/`_capacity` from Task 1 and is driven by Task 2's `on_stream_data` through `cloak_stream_relay_notify_stream_data`, with the caller as the wiring in between — no layer reaches around another.
- **Known sharp edge, deliberately left to the dispatcher:** nothing here decides *which* relay a stream-data notification belongs to. The session hands the consumer a `cloak_stream_t *`; mapping that back to a relay is the dispatcher's bookkeeping, and doing it wrong (a linear scan that misses, or a stale pointer after a release) is the most likely integration bug in the next module.
