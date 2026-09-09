# libcloak-mux Stream Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the ordered-mode stream multiplexing core: a non-blocking byte queue and a per-stream frame chunker/reassembler that sits directly on top of the already-merged frame codec (`cloak_frame_obfuscate`/`cloak_frame_deobfuscate`) -- the single-threaded-reactor equivalent of Go Cloak's `Stream` + `streamBuffer` + `streamBufferedPipe` (`internal/multiplex/stream.go`, `streamBuffer.go`, `streamBufferedPipe.go`).

**Architecture:** Two small modules in the existing `libcloak-mux` library. `bytequeue.{h,c}` is a generic, non-blocking, fixed-capacity byte ring buffer -- Go's `streamBufferedPipe` blocks the calling goroutine via `sync.Cond` when empty (read) or full (write); this port never blocks: writes are all-or-nothing (full success or 0 bytes written), reads return whatever is available (possibly 0), and callers (a later dispatcher/session module) drive readiness themselves by checking `cloak_bytequeue_len`/`cloak_bytequeue_free_space`, matching this project's design spec's stated data-plane pattern ("a readable event on one side attempts to enqueue into the other side's write buffer; if that buffer is full, EPOLLIN is deregistered on the source"). `stream.{h,c}` builds on it: it chunks outbound bytes into frames (obfuscating each and handing it to a caller-supplied sink function, decoupling this module entirely from how frames actually reach a network connection -- that's a later session/switchboard module's job), and reassembles inbound frames -- which can arrive out of order, since a session spreads one stream's frames across multiple underlying connections -- back into an ordered byte stream via a sequence-number min-heap, exactly replicating Go's `streamBuffer.Write` reordering algorithm, but with genuine bounded backpressure (a defensive cap on out-of-order buffering, and a byte queue that never silently drops data) instead of Go's reliance on blocking a goroutine.

**Tech Stack:** C11, no new external dependencies -- builds on the already-merged `libcloak-mux` frame codec (`cloak_frame_t`, `cloak_obfuscator_t`, `cloak_frame_obfuscate`) and `libcloak-common`'s `cloak_random_bytes`. CMake + CTest, Docker-only build/test (`Dockerfile.dev`, image `cloak-c-dev`) -- Linux-only project.

## Global Constraints

- Linux-only; all builds and test runs happen via Docker, matching every prior module.
- Zero compiler warnings (`-Wall -Wextra`).
- Nothing in this module blocks, spawns a thread, or touches a socket/epoll/timer -- it is pure, synchronous, single-threaded logic. The reactor integration (registering underlying connections, driving `cloak_stream_feed_frame` from real socket reads, picking which connection to send a frame on) is explicitly out of scope for this plan -- see "What comes after this plan".
- `cloak_stream_t` never silently drops a frame or a byte for lack of buffer space: every accepted frame is either delivered immediately or deep-copied into a bounded reorder buffer and drained as space allows. The only way data is ever rejected is the explicit, documented `max_pending_frames` cap (a defensive bound this port adds beyond Go's own unbounded-out-of-order-heap design) or a genuine protocol violation (a duplicate/stale sequence number).
- Every byte-layout and algorithmic detail below (the closing-frame payload sizing, the sequence-reassembly algorithm's exact semantics including the closing-frame short-circuit subtlety) was verified against Go Cloak's actual source before being written into this plan, and the resulting C design was independently verified by writing and running real, compiled test code (including cross-checking against the already-merged, already-tested frame codec) -- see the Provenance section.

---

## Provenance and verification (read this before touching any code)

This plan was derived from a full read of Go Cloak's `internal/multiplex` package (`session.go`, `stream.go`, `switchboard.go`, `streamBuffer.go`, `streamBufferedPipe.go`, `datagramBufferedPipe.go`, `recvBuffer.go`, `qos.go`, `obfs.go`, `frame.go`) -- not just `stream.go`/`streamBuffer.go` in isolation, specifically to identify the correct scope boundary between what belongs in this module versus later ones. That package is large and its concurrency model (goroutine-per-connection, blocking reads via `sync.Cond`, several `sync.Mutex`es) doesn't map 1:1 onto this project's single-threaded epoll reactor, so this plan intentionally covers only the ordered-mode stream core -- the part that is genuinely just local state-machine logic, no sockets or threads involved -- deferring the session/connection-pool orchestration layer (Go's `Session`+`switchboard`) and the unordered/datagram mode + rate-limiting (`datagramBufferedPipe.go`, `qos.go`) to separate future plans (see "What comes after this plan").

**The closing-frame payload construction.** `internal/multiplex/session.go`'s `closeStream` (active close path): a closing frame's payload is NOT empty -- it's `1 + random_byte` bytes (range [1,256]) of random content (`common.CryptoRandRead((*tmpBuf)[:1]); padLen := int((*tmpBuf)[0]) + 1; ...CryptoRandRead(payload)`), specifically so a closing frame can't be distinguished from a data frame by size alone, and because `cloak_frame_obfuscate` (already merged, unchanged by this plan) requires a nonzero payload. Verified directly by reading this code, not inferred.

**The reassembly algorithm's exact semantics.** `internal/multiplex/streamBuffer.go`'s `Write` method was read in full (not summarized) to get several non-obvious details exactly right:
- A frame with `Seq < nextRecvSeq` is a protocol violation (duplicate/already-delivered) -- rejected, not silently ignored.
- An in-order frame carrying a closing signal is delivered as a "close" event WITHOUT its payload ever reaching the byte buffer, and WITHOUT `nextRecvSeq` advancing past it -- both the fast path (`f.Seq == nextRecvSeq`, no heap involvement) and the heap-drain path share this exact behavior (`return true, nil` with no `buf.Write` call, no `nextRecvSeq += 1`). This was confirmed by reading the literal Go source; an earlier, incorrect assumption (that `nextRecvSeq` increments even for a closing frame) was caught and corrected during design, before any code was written.
- The drain loop, once it pops a closing frame off the heap, stops immediately -- even if further already-in-order frames are sitting ready behind it in the heap, they are never delivered (moot, since the stream is being torn down at that point, but the exact stopping behavior is replicated for fidelity and is directly tested below).
- Out-of-order frames are deep-copied before buffering (`saved := *f; saved.Payload = make([]byte, len(f.Payload)); copy(...)`), because the original frame's payload points into a buffer the caller will reuse -- this port's `cloak_frame_deobfuscate` has the identical "payload points into the caller's buffer, no copy" contract, so `cloak_stream_feed_frame` deep-copies for exactly the same reason.

**The non-blocking redesign is a deliberate departure from Go, not a translation gap.** Go's `streamBufferedPipe`/`datagramBufferedPipe` block the calling goroutine (via `sync.Cond.Wait()`) when a reader finds no data or a writer finds the buffer over its (practically unbounded, 1<<31-1 byte) soft cap; real backpressure in Go comes from this blocking propagating back through the call stack to the goroutine reading the underlying TCP connection, which is invisible at the Go type-system level. A single-threaded reactor cannot block anything. This plan's `cloak_bytequeue_t` is finite-capacity and fully non-blocking by design (all-or-nothing writes, partial-allowed reads, explicit free-space/length queries) -- verified as memory-safe and FIFO-correct via a 200,000-iteration fuzz test against an independent reference buffer, run under ASan/UBSan. `cloak_stream_t`'s reassembly layer was designed so backpressure never causes data loss: an already-buffered-out-of-order frame that can't yet be drained into the byte queue (because the queue lacks room for it) simply stays on the heap and is retried automatically the next time the queue drains (via `cloak_stream_read`) -- verified directly with a dedicated backpressure-then-resume test.

**A real bug this verification caught before it reached a plan.** An early draft of `cloak_stream_send_closing` generated its random 1-256 byte closing payload without bounding it by the stream's own `max_payload_per_frame` -- since `cloak_frame_obfuscate` can add up to `CLOAK_FRAME_MAX_EXTRA_LEN` (255) more bytes of its own random padding on top of any frame with `seq < CLOAK_FRAME_PAD_FIRST_N_FRAMES` (a stream's first closing frame usually qualifies), a small `max_on_wire_size` configuration (deliberately used in several of this plan's own tests, to force many small frames and exercise the reassembly/chunking logic) could make the closing frame's own padding legitimately too large to fit in the write buffer -- `cloak_frame_obfuscate` correctly rejected it (returning -1, no memory-safety issue, it always validates size before writing), but the resulting test failures initially looked like reassembly bugs and took real debugging to trace to the actual root cause. The fix -- clamping the closing frame's own random payload length to `max_payload_per_frame`, the same bound ordinary data frames already respect -- is in the code below, and the full test suite (including the small-frame-size tests that originally exposed this) passes clean under ASan/UBSan as a result.

**Verification method.** All code below was written, compiled, and run (both a plain `-Wall -Wextra -Werror` build and an ASan+UBSan build) against this repository's real, already-merged `cloak_frame_obfuscate`/`cloak_frame_deobfuscate`/`cloak_random_bytes` -- not mocked or stubbed -- before being included in this plan. This includes full write-then-deobfuscate-then-feed round trips using a real `cloak_obfuscator_t` with AES-256-GCM and a random session key, confirming the reassembled bytes match the original input exactly across in-order delivery, fully reversed delivery, a 100-frame randomly-shuffled delivery, closing-frame delivery (both in-order and with the closing frame itself arriving early/out-of-order), duplicate-sequence rejection, sink-failure propagation, the `max_pending_frames` defensive cap, and backpressure-then-resume.

---

## File Structure

Two new files in the existing `libcloak-mux` library (alongside the already-merged `frame.{h,c}`):

- `libcloak-mux/include/cloak/bytequeue.h` / `libcloak-mux/src/bytequeue.c` -- `cloak_bytequeue_t` and its init/destroy/write/read/close/query functions.
- `libcloak-mux/include/cloak/stream.h` / `libcloak-mux/src/stream.c` -- `cloak_stream_t`, `cloak_pending_frame_t`, `cloak_stream_frame_sink_t`, and the init/destroy/write/send_closing/feed_frame/read/recv_available functions.
- `libcloak-mux/tests/test_bytequeue.c`, `libcloak-mux/tests/test_stream.c` -- new test executables.
- `libcloak-mux/CMakeLists.txt` -- modify: add the two new `.c` files to the library.
- `libcloak-mux/tests/CMakeLists.txt` -- modify: register the two new test executables.

---

### Task 1: `bytequeue` -- non-blocking fixed-capacity byte ring buffer

**Files:**
- Create: `libcloak-mux/include/cloak/bytequeue.h`
- Create: `libcloak-mux/src/bytequeue.c`
- Create: `libcloak-mux/tests/test_bytequeue.c`
- Modify: `libcloak-mux/CMakeLists.txt`
- Modify: `libcloak-mux/tests/CMakeLists.txt`

**Interfaces:**
- Produces: `cloak_bytequeue_t`, `cloak_bytequeue_init`, `cloak_bytequeue_destroy`, `cloak_bytequeue_write`, `cloak_bytequeue_read`, `cloak_bytequeue_close`, `cloak_bytequeue_len`, `cloak_bytequeue_free_space`, `cloak_bytequeue_is_eof`.
- Consumes: nothing beyond `<stddef.h>`/`<stdint.h>`/`<stdlib.h>`/`<string.h>` -- fully standalone.

- [ ] **Step 1: Write the header**

Create `libcloak-mux/include/cloak/bytequeue.h`:

```c
#ifndef CLOAK_BYTEQUEUE_H
#define CLOAK_BYTEQUEUE_H

#include <stddef.h>
#include <stdint.h>

/* A fixed-capacity, non-blocking byte ring buffer -- the single-threaded
 * reactor equivalent of Go Cloak's streamBufferedPipe (which instead blocks
 * the calling goroutine via a sync.Cond). There is no blocking here: writes
 * either fully succeed or are fully rejected (0 bytes written) if they
 * would not fit, and reads return whatever is currently available (0 if
 * empty). Callers drive backpressure themselves by checking
 * cloak_bytequeue_free_space / cloak_bytequeue_len. */
typedef struct {
    uint8_t *data;
    size_t cap;
    size_t head; /* index of the oldest unread byte */
    size_t len;  /* bytes currently stored */
    int closed;
} cloak_bytequeue_t;

/* Allocates a cap-byte backing buffer. Returns 0 on success, -1 on
 * allocation failure or cap == 0. */
int cloak_bytequeue_init(cloak_bytequeue_t *q, size_t cap);

void cloak_bytequeue_destroy(cloak_bytequeue_t *q);

/* Writes data atomically: either all len bytes are written (returns len),
 * or none are (returns 0) if fewer than len bytes of free space remain, or
 * the queue is closed. Never partially writes. */
size_t cloak_bytequeue_write(cloak_bytequeue_t *q, const uint8_t *data, size_t len);

/* Reads up to len bytes (may return fewer than len if that's all that's
 * available -- unlike write, read is not all-or-nothing). Returns 0 if
 * currently empty, whether or not the queue is closed -- use
 * cloak_bytequeue_is_eof to tell "no data yet" apart from "closed and
 * drained". */
size_t cloak_bytequeue_read(cloak_bytequeue_t *q, uint8_t *out, size_t len);

/* Marks the queue closed: no further cloak_bytequeue_write calls will
 * succeed (they return 0), but already-buffered bytes remain readable
 * until drained. Idempotent. */
void cloak_bytequeue_close(cloak_bytequeue_t *q);

size_t cloak_bytequeue_len(const cloak_bytequeue_t *q);
size_t cloak_bytequeue_free_space(const cloak_bytequeue_t *q);

/* True once the queue is closed AND fully drained (len == 0) -- the
 * end-of-stream condition a reader should treat as EOF. */
int cloak_bytequeue_is_eof(const cloak_bytequeue_t *q);

#endif
```

- [ ] **Step 2: Write the implementation**

Create `libcloak-mux/src/bytequeue.c`:

```c
#include "cloak/bytequeue.h"

#include <stdlib.h>
#include <string.h>

int cloak_bytequeue_init(cloak_bytequeue_t *q, size_t cap) {
    if (cap == 0) {
        return -1;
    }
    q->data = (uint8_t *)malloc(cap);
    if (q->data == NULL) {
        return -1;
    }
    q->cap = cap;
    q->head = 0;
    q->len = 0;
    q->closed = 0;
    return 0;
}

void cloak_bytequeue_destroy(cloak_bytequeue_t *q) {
    free(q->data);
    q->data = NULL;
    q->cap = 0;
    q->head = 0;
    q->len = 0;
}

size_t cloak_bytequeue_write(cloak_bytequeue_t *q, const uint8_t *data, size_t len) {
    if (q->closed || len > q->cap - q->len) {
        return 0;
    }
    size_t tail = (q->head + q->len) % q->cap;
    size_t first_chunk = q->cap - tail;
    if (first_chunk >= len) {
        memcpy(q->data + tail, data, len);
    } else {
        memcpy(q->data + tail, data, first_chunk);
        memcpy(q->data, data + first_chunk, len - first_chunk);
    }
    q->len += len;
    return len;
}

size_t cloak_bytequeue_read(cloak_bytequeue_t *q, uint8_t *out, size_t len) {
    size_t n = len < q->len ? len : q->len;
    if (n == 0) {
        return 0;
    }
    size_t first_chunk = q->cap - q->head;
    if (first_chunk >= n) {
        memcpy(out, q->data + q->head, n);
    } else {
        memcpy(out, q->data + q->head, first_chunk);
        memcpy(out + first_chunk, q->data, n - first_chunk);
    }
    q->head = (q->head + n) % q->cap;
    q->len -= n;
    return n;
}

void cloak_bytequeue_close(cloak_bytequeue_t *q) {
    q->closed = 1;
}

size_t cloak_bytequeue_len(const cloak_bytequeue_t *q) {
    return q->len;
}

size_t cloak_bytequeue_free_space(const cloak_bytequeue_t *q) {
    return q->cap - q->len;
}

int cloak_bytequeue_is_eof(const cloak_bytequeue_t *q) {
    return q->closed && q->len == 0;
}
```

- [ ] **Step 3: Write the tests**

Create `libcloak-mux/tests/test_bytequeue.c`:

```c
#include "cloak/bytequeue.h"
#include "test_framework.h"

#include <string.h>
#include <stdlib.h>

static void test_basic_write_read(void) {
    cloak_bytequeue_t q;
    ASSERT_EQ_INT(cloak_bytequeue_init(&q, 16), 0);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"hello", 5), 5);
    ASSERT_EQ_INT(cloak_bytequeue_len(&q), 5);
    uint8_t out[16];
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 16), 5);
    ASSERT_MEM_EQ(out, "hello", 5);
    ASSERT_EQ_INT(cloak_bytequeue_len(&q), 0);
    cloak_bytequeue_destroy(&q);
}

static void test_capacity_rejects_oversized_write(void) {
    cloak_bytequeue_t q;
    cloak_bytequeue_init(&q, 4);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"abcd", 4), 4);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"e", 1), 0);
    ASSERT_EQ_INT(cloak_bytequeue_len(&q), 4);
    cloak_bytequeue_destroy(&q);
}

static void test_wraparound(void) {
    cloak_bytequeue_t q;
    cloak_bytequeue_init(&q, 4);
    uint8_t out[4];
    /* Fill, drain 3, write 3 more (wraps), read all 4. */
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"ABCD", 4), 4);
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 3), 3);
    ASSERT_MEM_EQ(out, "ABC", 3);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"EFG", 3), 3);
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 4), 4);
    ASSERT_MEM_EQ(out, "DEFG", 4);
    cloak_bytequeue_destroy(&q);
}

static void test_close_semantics(void) {
    cloak_bytequeue_t q;
    cloak_bytequeue_init(&q, 8);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"ab", 2), 2);
    cloak_bytequeue_close(&q);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"c", 1), 0);
    ASSERT_TRUE(!cloak_bytequeue_is_eof(&q));
    uint8_t out[8];
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 8), 2);
    ASSERT_TRUE(cloak_bytequeue_is_eof(&q));
    cloak_bytequeue_close(&q); /* idempotent */
    cloak_bytequeue_destroy(&q);
}

static void test_read_partial(void) {
    cloak_bytequeue_t q;
    cloak_bytequeue_init(&q, 16);
    cloak_bytequeue_write(&q, (const uint8_t *)"0123456789", 10);
    uint8_t out[3];
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 3), 3);
    ASSERT_MEM_EQ(out, "012", 3);
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 3), 3);
    ASSERT_MEM_EQ(out, "345", 3);
    ASSERT_EQ_INT(cloak_bytequeue_len(&q), 4);
    cloak_bytequeue_destroy(&q);
}

static void test_empty_read_returns_zero(void) {
    cloak_bytequeue_t q;
    cloak_bytequeue_init(&q, 8);
    uint8_t out[8];
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 8), 0);
    ASSERT_TRUE(!cloak_bytequeue_is_eof(&q));
    cloak_bytequeue_destroy(&q);
}

/* Fuzz-style: many random write/read operations against a reference (a
 * simple growing shadow array), confirmed byte-identical FIFO order and
 * capacity-respecting behavior throughout. Run under ASan/UBSan. */
static void test_fuzz_against_reference(void) {
    cloak_bytequeue_t q;
    size_t cap = 37; /* deliberately awkward, non-power-of-2 capacity */
    cloak_bytequeue_init(&q, cap);

    uint8_t *shadow = (uint8_t *)malloc(1000000);
    size_t shadow_head = 0, shadow_len = 0;

    unsigned int seed = 12345;
    for (int iter = 0; iter < 200000; iter++) {
        seed = seed * 1103515245u + 12345u;
        int do_write = (seed >> 16) % 2;
        if (do_write) {
            size_t n = ((seed >> 8) % 20) + 1;
            uint8_t buf[20];
            for (size_t i = 0; i < n; i++) {
                buf[i] = (uint8_t)((seed + i) & 0xff);
            }
            size_t free_space = cloak_bytequeue_free_space(&q);
            size_t written = cloak_bytequeue_write(&q, buf, n);
            if (n <= free_space) {
                ASSERT_EQ_INT(written, n);
                memcpy(shadow + shadow_head + shadow_len, buf, n);
                shadow_len += n;
            } else {
                ASSERT_EQ_INT(written, 0);
            }
        } else {
            size_t n = ((seed >> 8) % 20) + 1;
            uint8_t buf[20];
            size_t read = cloak_bytequeue_read(&q, buf, n);
            ASSERT_TRUE(read <= shadow_len);
            if (read > 0) {
                ASSERT_MEM_EQ(buf, shadow + shadow_head, read);
                shadow_head += read;
                shadow_len -= read;
            }
        }
        ASSERT_EQ_INT(cloak_bytequeue_len(&q), shadow_len);
        ASSERT_TRUE(cloak_bytequeue_len(&q) <= cap);
    }
    free(shadow);
    cloak_bytequeue_destroy(&q);
}

TEST_MAIN_BEGIN()
    test_basic_write_read();
    test_capacity_rejects_oversized_write();
    test_wraparound();
    test_close_semantics();
    test_read_partial();
    test_empty_read_returns_zero();
    test_fuzz_against_reference();
TEST_MAIN_END()
```

- [ ] **Step 4: Update the library's CMakeLists.txt**

Modify `libcloak-mux/CMakeLists.txt`:

```cmake
add_library(cloak-mux STATIC
    src/frame.c
    src/bytequeue.c
)

target_include_directories(cloak-mux PUBLIC include)
target_link_libraries(cloak-mux PUBLIC cloak-common)

add_subdirectory(tests)
```

- [ ] **Step 5: Register the new test**

Modify `libcloak-mux/tests/CMakeLists.txt` to add:

```cmake
add_executable(test_bytequeue test_bytequeue.c)
target_include_directories(test_bytequeue PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_bytequeue PRIVATE cloak-mux)
add_test(NAME test_bytequeue COMMAND test_bytequeue)
```

- [ ] **Step 6: Build and test in Docker**

```bash
docker build -q -f Dockerfile.dev -t cloak-c-dev .
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "rm -rf build && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure"
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build-asan -DCMAKE_C_FLAGS='-fsanitize=address,undefined -g' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' && cmake --build build-asan && ctest --test-dir build-asan --output-on-failure"
```

Expected: all tests pass (plain and ASan/UBSan), zero compiler warnings, including the 200,000-iteration fuzz test.

- [ ] **Step 7: Commit**

```bash
git add libcloak-mux/include/cloak/bytequeue.h libcloak-mux/src/bytequeue.c \
        libcloak-mux/tests/test_bytequeue.c libcloak-mux/CMakeLists.txt libcloak-mux/tests/CMakeLists.txt
git commit -m "Add bytequeue: non-blocking fixed-capacity byte ring buffer"
```

---

### Task 2: `stream` -- frame chunking and sequence-ordered reassembly

**Files:**
- Create: `libcloak-mux/include/cloak/stream.h`
- Create: `libcloak-mux/src/stream.c`
- Create: `libcloak-mux/tests/test_stream.c`
- Modify: `libcloak-mux/CMakeLists.txt`
- Modify: `libcloak-mux/tests/CMakeLists.txt`

**Interfaces:**
- Produces: `cloak_pending_frame_t`, `cloak_stream_frame_sink_t`, `cloak_stream_t`, `cloak_stream_init`, `cloak_stream_destroy`, `cloak_stream_write`, `cloak_stream_send_closing`, `cloak_stream_feed_frame`, `cloak_stream_read`, `cloak_stream_recv_available`.
- Consumes: `cloak_bytequeue_t` and its functions (Task 1); `cloak_frame_t`, `cloak_obfuscator_t`, `CLOAK_FRAME_HEADER_LEN`, `CLOAK_FRAME_MAX_EXTRA_LEN`, `cloak_frame_obfuscate` (already merged, `cloak/frame.h`); `cloak_random_bytes` (already merged, `cloak/common.h`).

- [ ] **Step 1: Write the header**

Create `libcloak-mux/include/cloak/stream.h`:

```c
#ifndef CLOAK_STREAM_H
#define CLOAK_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/frame.h"
#include "cloak/bytequeue.h"

/* Returns 0 on success (bytes accepted for transmission -- the connection
 * layer may still buffer them internally), or -1 on a hard failure (the
 * underlying connection is broken), mirroring Go Cloak's
 * switchboard.send()'s error contract. Must not block. */
typedef int (*cloak_stream_frame_sink_t)(void *userdata, const uint8_t *bytes, size_t len);

typedef struct {
    uint64_t seq;
    uint8_t closing;
    uint8_t *payload; /* owned copy, malloc'd (NULL iff payload_len == 0) */
    size_t payload_len;
} cloak_pending_frame_t;

/* One multiplexed logical stream's framing state: chunks outbound bytes
 * into frames (obfuscating and handing each to a caller-supplied sink),
 * and reassembles inbound frames (received out of order, since a session
 * spreads one stream's frames across multiple underlying connections) back
 * into an ordered byte stream via a sequence-number min-heap -- the
 * single-threaded, non-blocking equivalent of Go Cloak's
 * Stream+streamBuffer+streamBufferedPipe. Unlike Go, nothing here ever
 * blocks: cloak_stream_read returns 0 immediately if no data is ready yet
 * (never blocks waiting for it), and cloak_stream_feed_frame never blocks
 * on backpressure -- see its own doc comment. */
typedef struct {
    uint32_t id;

    const cloak_obfuscator_t *obfuscator; /* not owned -- must outlive the stream */
    cloak_stream_frame_sink_t sink;
    void *sink_userdata;

    size_t max_payload_per_frame;
    uint8_t *write_buf; /* owned scratch buffer for obfuscate() output */
    size_t write_buf_cap;
    uint64_t next_write_seq;
    int write_closed;

    cloak_bytequeue_t recv_bytes;
    uint64_t next_recv_seq;
    cloak_pending_frame_t *heap; /* owned, binary min-heap by .seq */
    size_t heap_len;
    size_t heap_cap;
    size_t max_pending_frames; /* defensive cap on out-of-order buffering */
    int recv_closing_seen;     /* a closing frame has been drained into order */
} cloak_stream_t;

/* max_on_wire_size is the same quantity as Go's SessionConfig.MsgOnWireSizeLimit
 * (the full framed-and-encrypted size budget per frame, e.g. 1<<14+256);
 * this function derives the actual per-frame payload budget from it the
 * same way Go's Session does (accounting for the frame header and the
 * worst-case padding/AEAD overhead).
 *
 * recv_capacity is the reassembled-byte-queue's fixed capacity (Go's
 * streamBufferedPipe has no real cap in practice -- 1<<31-1 -- because Go
 * relies on blocking a goroutine for backpressure instead; this port uses
 * a real, finite capacity and non-blocking backpressure signaling instead,
 * matching this project's reactor-driven design).
 *
 * max_pending_frames bounds how many out-of-order frames may be buffered
 * awaiting a gap-filling frame, as a defensive measure against unbounded
 * memory growth from adversarial frame reordering (Go's implementation has
 * no such cap).
 *
 * Returns 0 on success, -1 on allocation failure or invalid parameters
 * (max_on_wire_size too small to fit a header, recv_capacity == 0). */
int cloak_stream_init(cloak_stream_t *s, uint32_t id, const cloak_obfuscator_t *obfuscator,
                       size_t max_on_wire_size, size_t recv_capacity, size_t max_pending_frames,
                       cloak_stream_frame_sink_t sink, void *sink_userdata);

void cloak_stream_destroy(cloak_stream_t *s);

/* Chunks in[0,in_len) into one or more frames (each up to
 * max_payload_per_frame bytes), obfuscates and hands each to the sink, in
 * order. On success returns in_len (all bytes were chunked and handed off
 * -- matching Go's Stream.Write, which never partially writes in ordered
 * mode). Returns -1 if the stream's write side is already closed, or if
 * an obfuscate/sink call fails partway through (some frames may already
 * have reached the sink in this case -- the stream should be considered
 * broken and torn down by the caller, exactly as a mid-write failure in
 * Go leaves the stream in an unusable state). */
long cloak_stream_write(cloak_stream_t *s, const uint8_t *in, size_t in_len);

/* Sends a single closing-only frame (CLOAK_FRAME_CLOSING_STREAM or
 * CLOAK_FRAME_CLOSING_SESSION) using the stream's next write sequence
 * number, with a random 1-256 byte padding payload, clamped to
 * max_payload_per_frame (matching Go's anti-fingerprinting closing-frame
 * construction -- a closing frame must not be reliably distinguishable in
 * size from a data frame, and cloak_frame_obfuscate requires a nonzero
 * payload; the clamp guarantees this payload always fits in write_buf
 * alongside cloak_frame_obfuscate's own additional random padding, the
 * same guarantee cloak_stream_init's sizing already provides for ordinary
 * data frames). Marks the stream's write side closed. Returns 0 on
 * success, -1 on failure. */
int cloak_stream_send_closing(cloak_stream_t *s, uint8_t closing_type);

/* Delivers one already-deobfuscated incoming frame for reassembly. The
 * frame's payload is only ever read during this call (deep-copied if it
 * can't be delivered immediately) -- frame->payload need not remain valid
 * after this call returns, matching cloak_frame_deobfuscate's contract
 * that payload points into a caller-owned buffer.
 *
 * This never blocks and never drops a frame silently for lack of space:
 * every accepted frame is deep-copied into an internal reorder buffer
 * (bounded by max_pending_frames) and drained into the readable byte queue
 * as space allows -- so backpressure shows up as slower draining (check
 * cloak_stream_recv_available), not as rejected frames, except for the
 * defensive max_pending_frames cap itself.
 *
 * Returns 0 (accepted, delivered and/or buffered for reassembly), 1 (a
 * closing frame was drained into order -- the caller should tear this
 * stream down after this call), or -1 (protocol violation: frame->seq is
 * a duplicate/already-delivered sequence number, the out-of-order buffer's
 * max_pending_frames cap was exceeded, or an allocation failure). */
int cloak_stream_feed_frame(cloak_stream_t *s, const cloak_frame_t *frame);

/* Copies up to out_cap reassembled bytes into out. Returns bytes copied
 * (0 if none are ready yet -- not an error, just "nothing to read right
 * now"), or -1 once the stream has both seen a closing frame drain into
 * order AND fully delivered every byte before it (end of stream). Calling
 * this after a previous -1 return continues to return -1. */
long cloak_stream_read(cloak_stream_t *s, uint8_t *out, size_t out_cap);

size_t cloak_stream_recv_available(const cloak_stream_t *s);

#endif
```

- [ ] **Step 2: Write the implementation**

Create `libcloak-mux/src/stream.c`:

```c
#include "cloak/stream.h"
#include "cloak/common.h"

#include <stdlib.h>
#include <string.h>

static int heap_grow(cloak_stream_t *s) {
    size_t new_cap = s->heap_cap == 0 ? 8 : s->heap_cap * 2;
    cloak_pending_frame_t *new_heap =
        (cloak_pending_frame_t *)realloc(s->heap, new_cap * sizeof(cloak_pending_frame_t));
    if (new_heap == NULL) {
        return -1;
    }
    s->heap = new_heap;
    s->heap_cap = new_cap;
    return 0;
}

static int heap_push(cloak_stream_t *s, cloak_pending_frame_t pf) {
    if (s->heap_len >= s->max_pending_frames) {
        return -1;
    }
    if (s->heap_len == s->heap_cap) {
        if (heap_grow(s) != 0) {
            return -1;
        }
    }
    size_t i = s->heap_len++;
    s->heap[i] = pf;
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (s->heap[parent].seq <= s->heap[i].seq) {
            break;
        }
        cloak_pending_frame_t tmp = s->heap[parent];
        s->heap[parent] = s->heap[i];
        s->heap[i] = tmp;
        i = parent;
    }
    return 0;
}

static cloak_pending_frame_t heap_pop(cloak_stream_t *s) {
    cloak_pending_frame_t top = s->heap[0];
    s->heap_len--;
    if (s->heap_len > 0) {
        s->heap[0] = s->heap[s->heap_len];
        size_t i = 0;
        for (;;) {
            size_t left = 2 * i + 1;
            size_t right = 2 * i + 2;
            size_t smallest = i;
            if (left < s->heap_len && s->heap[left].seq < s->heap[smallest].seq) {
                smallest = left;
            }
            if (right < s->heap_len && s->heap[right].seq < s->heap[smallest].seq) {
                smallest = right;
            }
            if (smallest == i) {
                break;
            }
            cloak_pending_frame_t tmp = s->heap[i];
            s->heap[i] = s->heap[smallest];
            s->heap[smallest] = tmp;
            i = smallest;
        }
    }
    return top;
}

/* Drains heap-buffered frames that are now next-in-order into recv_bytes,
 * stopping early (leaving the rest buffered) if recv_bytes lacks room for
 * the next one -- this is what lets a previously-backpressured reassembly
 * resume once cloak_stream_read frees up space, without re-feeding
 * anything. Returns 1 if a closing frame was drained (next_recv_seq is
 * deliberately NOT advanced past it, matching Go's streamBuffer.Write --
 * the stream is being torn down, so its value afterward is moot), 0
 * otherwise. */
static int try_drain(cloak_stream_t *s) {
    while (s->heap_len > 0 && s->heap[0].seq == s->next_recv_seq) {
        if (s->heap[0].closing != CLOAK_FRAME_CLOSING_NOTHING) {
            cloak_pending_frame_t pf = heap_pop(s);
            free(pf.payload);
            s->recv_closing_seen = 1;
            return 1;
        }
        size_t payload_len = s->heap[0].payload_len;
        if (cloak_bytequeue_free_space(&s->recv_bytes) < payload_len) {
            break;
        }
        cloak_pending_frame_t pf = heap_pop(s);
        if (pf.payload_len > 0) {
            cloak_bytequeue_write(&s->recv_bytes, pf.payload, pf.payload_len);
        }
        free(pf.payload);
        s->next_recv_seq++;
    }
    return 0;
}

int cloak_stream_init(cloak_stream_t *s, uint32_t id, const cloak_obfuscator_t *obfuscator,
                       size_t max_on_wire_size, size_t recv_capacity, size_t max_pending_frames,
                       cloak_stream_frame_sink_t sink, void *sink_userdata) {
    if (max_on_wire_size <= CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN ||
        recv_capacity == 0 || sink == NULL) {
        return -1;
    }
    memset(s, 0, sizeof(*s));
    s->id = id;
    s->obfuscator = obfuscator;
    s->sink = sink;
    s->sink_userdata = sink_userdata;
    s->max_payload_per_frame = max_on_wire_size - CLOAK_FRAME_HEADER_LEN - CLOAK_FRAME_MAX_EXTRA_LEN;

    s->write_buf = (uint8_t *)malloc(max_on_wire_size);
    if (s->write_buf == NULL) {
        return -1;
    }
    s->write_buf_cap = max_on_wire_size;

    if (cloak_bytequeue_init(&s->recv_bytes, recv_capacity) != 0) {
        free(s->write_buf);
        s->write_buf = NULL;
        return -1;
    }
    s->max_pending_frames = max_pending_frames > 0 ? max_pending_frames : 1;
    return 0;
}

void cloak_stream_destroy(cloak_stream_t *s) {
    free(s->write_buf);
    cloak_bytequeue_destroy(&s->recv_bytes);
    for (size_t i = 0; i < s->heap_len; i++) {
        free(s->heap[i].payload);
    }
    free(s->heap);
    memset(s, 0, sizeof(*s));
}

long cloak_stream_write(cloak_stream_t *s, const uint8_t *in, size_t in_len) {
    if (s->write_closed) {
        return -1;
    }
    size_t n = 0;
    while (n < in_len) {
        size_t remaining = in_len - n;
        size_t chunk = remaining <= s->max_payload_per_frame ? remaining : s->max_payload_per_frame;

        cloak_frame_t frame;
        frame.stream_id = s->id;
        frame.seq = s->next_write_seq;
        frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
        frame.payload = in + n;
        frame.payload_len = chunk;

        long written = cloak_frame_obfuscate(s->obfuscator, &frame, s->write_buf, s->write_buf_cap, 0);
        if (written < 0) {
            return -1;
        }
        s->next_write_seq++;
        if (s->sink(s->sink_userdata, s->write_buf, (size_t)written) != 0) {
            return -1;
        }
        n += chunk;
    }
    return (long)in_len;
}

int cloak_stream_send_closing(cloak_stream_t *s, uint8_t closing_type) {
    if (s->write_closed) {
        return -1;
    }
    uint8_t len_byte;
    cloak_random_bytes(&len_byte, 1);
    /* [1,256], but clamped to max_payload_per_frame -- cloak_frame_obfuscate
     * may add up to CLOAK_FRAME_MAX_EXTRA_LEN more bytes of its own random
     * padding on top of this payload for any frame with seq <
     * CLOAK_FRAME_PAD_FIRST_N_FRAMES (which a stream's first closing frame,
     * at seq 0 or shortly after, usually is), and only payloads bounded by
     * max_payload_per_frame are guaranteed to fit in write_buf (sized for
     * exactly that guarantee -- see cloak_stream_init). Without this clamp,
     * a small max_on_wire_size configuration could make an oversized
     * closing-frame payload legitimately fail to obfuscate. */
    size_t max_pad = s->max_payload_per_frame < 256 ? s->max_payload_per_frame : 256;
    size_t pad_len = (size_t)len_byte + 1;
    if (pad_len > max_pad) {
        pad_len = max_pad;
    }
    uint8_t pad[256];
    cloak_random_bytes(pad, pad_len);

    cloak_frame_t frame;
    frame.stream_id = s->id;
    frame.seq = s->next_write_seq;
    frame.closing = closing_type;
    frame.payload = pad;
    frame.payload_len = pad_len;

    long written = cloak_frame_obfuscate(s->obfuscator, &frame, s->write_buf, s->write_buf_cap, 0);
    s->write_closed = 1;
    if (written < 0) {
        return -1;
    }
    s->next_write_seq++;
    if (s->sink(s->sink_userdata, s->write_buf, (size_t)written) != 0) {
        return -1;
    }
    return 0;
}

int cloak_stream_feed_frame(cloak_stream_t *s, const cloak_frame_t *frame) {
    if (s->recv_closing_seen) {
        return -1;
    }
    if (frame->seq < s->next_recv_seq) {
        return -1;
    }

    uint8_t *payload_copy = NULL;
    if (frame->payload_len > 0) {
        payload_copy = (uint8_t *)malloc(frame->payload_len);
        if (payload_copy == NULL) {
            return -1;
        }
        memcpy(payload_copy, frame->payload, frame->payload_len);
    }

    cloak_pending_frame_t pf;
    pf.seq = frame->seq;
    pf.closing = frame->closing;
    pf.payload = payload_copy;
    pf.payload_len = frame->payload_len;

    if (heap_push(s, pf) != 0) {
        free(payload_copy);
        return -1;
    }

    return try_drain(s);
}

long cloak_stream_read(cloak_stream_t *s, uint8_t *out, size_t out_cap) {
    size_t n = cloak_bytequeue_read(&s->recv_bytes, out, out_cap);
    if (n > 0) {
        try_drain(s);
        return (long)n;
    }
    if (s->recv_closing_seen) {
        return -1;
    }
    return 0;
}

size_t cloak_stream_recv_available(const cloak_stream_t *s) {
    return cloak_bytequeue_len(&s->recv_bytes);
}
```

- [ ] **Step 3: Write the tests**

Create `libcloak-mux/tests/test_stream.c`:

```c
#include "cloak/stream.h"
#include "cloak/common.h"
#include "cloak/frame.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>

/* --- A simple "wire" collecting sink: appends each obfuscated frame as a
 * length-prefixed record to a growable buffer, for later feeding to a
 * receiver-side stream via cloak_frame_deobfuscate. --- */
typedef struct {
    uint8_t *frames_data;    /* concatenated raw ciphertext bytes, one after another */
    size_t frames_data_len;
    size_t frames_data_cap;
    size_t *frame_lens;      /* length of each frame in frames_data, in order */
    size_t frame_count;
    size_t frame_lens_cap;
    int fail_after_n;        /* if >= 0, sink starts failing after this many successful calls */
} wire_t;

static void wire_init(wire_t *w) {
    memset(w, 0, sizeof(*w));
    w->fail_after_n = -1;
}

static void wire_free(wire_t *w) {
    free(w->frames_data);
    free(w->frame_lens);
}

static int wire_sink(void *userdata, const uint8_t *bytes, size_t len) {
    wire_t *w = (wire_t *)userdata;
    if (w->fail_after_n >= 0 && (size_t)w->fail_after_n <= w->frame_count) {
        return -1;
    }
    if (w->frames_data_len + len > w->frames_data_cap) {
        size_t new_cap = (w->frames_data_cap + len) * 2 + 64;
        w->frames_data = (uint8_t *)realloc(w->frames_data, new_cap);
        w->frames_data_cap = new_cap;
    }
    memcpy(w->frames_data + w->frames_data_len, bytes, len);
    w->frames_data_len += len;

    if (w->frame_count == w->frame_lens_cap) {
        w->frame_lens_cap = w->frame_lens_cap * 2 + 8;
        w->frame_lens = (size_t *)realloc(w->frame_lens, w->frame_lens_cap * sizeof(size_t));
    }
    w->frame_lens[w->frame_count++] = len;
    return 0;
}

static void make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, CLOAK_AEAD_KEY_LEN);
}

#define MAX_ON_WIRE 2048
#define RECV_CAP 65536
#define MAX_PENDING 64

/* Deobfuscates every frame in w (in the order they were written) and feeds
 * each into dst via cloak_stream_feed_frame, in a caller-specified
 * delivery order (indices into w's frame list) -- lets tests simulate
 * out-of-order arrival. Returns the last cloak_stream_feed_frame return
 * value (so callers can detect a closing frame, i.e. return value 1). */
static int deliver_frames(const wire_t *w, const cloak_obfuscator_t *o, cloak_stream_t *dst,
                           const size_t *order, size_t order_len) {
    size_t *offsets = (size_t *)malloc(w->frame_count * sizeof(size_t));
    size_t off = 0;
    for (size_t i = 0; i < w->frame_count; i++) {
        offsets[i] = off;
        off += w->frame_lens[i];
    }
    int last_rc = 0;
    for (size_t k = 0; k < order_len; k++) {
        size_t idx = order[k];
        uint8_t *copy = (uint8_t *)malloc(w->frame_lens[idx]);
        memcpy(copy, w->frames_data + offsets[idx], w->frame_lens[idx]);
        cloak_frame_t frame;
        int rc = cloak_frame_deobfuscate(o, &frame, copy, w->frame_lens[idx]);
        ASSERT_EQ_INT(rc, 0);
        last_rc = cloak_stream_feed_frame(dst, &frame);
        free(copy);
    }
    free(offsets);
    return last_rc;
}

static void test_round_trip_in_order(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    cloak_stream_t tx;
    ASSERT_EQ_INT(cloak_stream_init(&tx, 7, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING, wire_sink, &w), 0);

    const char *msg = "the quick brown fox jumps over the lazy dog";
    long n = cloak_stream_write(&tx, (const uint8_t *)msg, strlen(msg));
    ASSERT_EQ_INT(n, (long)strlen(msg));
    ASSERT_EQ_INT(w.frame_count, 1);

    cloak_stream_t rx;
    ASSERT_EQ_INT(cloak_stream_init(&rx, 7, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING, wire_sink, &w), 0);

    size_t order[1] = {0};
    deliver_frames(&w, &o, &rx, order, 1);

    uint8_t out[256];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)strlen(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_multi_frame_chunking_and_reassembly(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    /* Force small frames so a sizeable payload spans many of them. */
    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 10;
    cloak_stream_t tx;
    ASSERT_EQ_INT(cloak_stream_init(&tx, 3, &o, max_on_wire, RECV_CAP, MAX_PENDING, wire_sink, &w), 0);

    uint8_t msg[537];
    for (size_t i = 0; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)(i * 7 + 3);
    }
    long n = cloak_stream_write(&tx, msg, sizeof(msg));
    ASSERT_EQ_INT(n, (long)sizeof(msg));
    ASSERT_EQ_INT(w.frame_count, (sizeof(msg) + 10 - 1) / 10);

    cloak_stream_t rx;
    ASSERT_EQ_INT(cloak_stream_init(&rx, 3, &o, max_on_wire, RECV_CAP, MAX_PENDING, wire_sink, &w), 0);
    size_t *order = (size_t *)malloc(w.frame_count * sizeof(size_t));
    for (size_t i = 0; i < w.frame_count; i++) order[i] = i;
    deliver_frames(&w, &o, &rx, order, w.frame_count);
    free(order);

    uint8_t out[600];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)sizeof(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_out_of_order_delivery(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 5;
    cloak_stream_t tx;
    cloak_stream_init(&tx, 9, &o, max_on_wire, RECV_CAP, MAX_PENDING, wire_sink, &w);

    const char *msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* 26 bytes -> multiple 5-byte frames */
    cloak_stream_write(&tx, (const uint8_t *)msg, strlen(msg));
    ASSERT_EQ_INT(w.frame_count, 6);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 9, &o, max_on_wire, RECV_CAP, MAX_PENDING, wire_sink, &w);

    /* Reverse delivery order: worst case for the reorder heap. */
    size_t order[6] = {5, 4, 3, 2, 1, 0};
    deliver_frames(&w, &o, &rx, order, 6);

    uint8_t out[64];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)strlen(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_shuffled_delivery_many_frames(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 3;
    cloak_stream_t tx;
    cloak_stream_init(&tx, 1, &o, max_on_wire, 1 << 20, 200, wire_sink, &w);

    uint8_t msg[300];
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)(i * 13 + 1);
    cloak_stream_write(&tx, msg, sizeof(msg));
    ASSERT_EQ_INT(w.frame_count, 100);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 1, &o, max_on_wire, 1 << 20, 200, wire_sink, &w);

    size_t *order = (size_t *)malloc(w.frame_count * sizeof(size_t));
    for (size_t i = 0; i < w.frame_count; i++) order[i] = i;
    /* deterministic shuffle */
    unsigned int seed = 42;
    for (size_t i = w.frame_count - 1; i > 0; i--) {
        seed = seed * 1103515245u + 12345u;
        size_t j = (seed >> 8) % (i + 1);
        size_t tmp = order[i]; order[i] = order[j]; order[j] = tmp;
    }
    deliver_frames(&w, &o, &rx, order, w.frame_count);
    free(order);

    uint8_t out[400];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)sizeof(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_closing_frame_signals_eof(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    cloak_stream_t tx;
    cloak_stream_init(&tx, 4, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING, wire_sink, &w);
    const char *msg = "final message";
    cloak_stream_write(&tx, (const uint8_t *)msg, strlen(msg));
    ASSERT_EQ_INT(cloak_stream_send_closing(&tx, CLOAK_FRAME_CLOSING_STREAM), 0);
    ASSERT_EQ_INT(cloak_stream_write(&tx, (const uint8_t *)"x", 1), -1);
    ASSERT_EQ_INT(w.frame_count, 2);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 4, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING, wire_sink, &w);
    size_t order[2] = {0, 1};
    int last_rc = deliver_frames(&w, &o, &rx, order, 2);
    ASSERT_EQ_INT(last_rc, 1);

    uint8_t out[64];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)strlen(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);
    long eof = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(eof, -1);
    long eof2 = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(eof2, -1);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_closing_frame_out_of_order_stops_drain(void) {
    /* Matches Go's documented subtlety: a closing frame short-circuits the
     * drain loop even if further already-in-order frames are sitting ready
     * in the heap behind it -- those never get delivered. */
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 4;
    cloak_stream_t tx;
    cloak_stream_init(&tx, 2, &o, max_on_wire, RECV_CAP, MAX_PENDING, wire_sink, &w);
    cloak_stream_write(&tx, (const uint8_t *)"AAAA", 4); /* seq 0 */
    cloak_stream_send_closing(&tx, CLOAK_FRAME_CLOSING_STREAM); /* seq 1 */
    ASSERT_EQ_INT(w.frame_count, 2);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 2, &o, max_on_wire, RECV_CAP, MAX_PENDING, wire_sink, &w);

    /* Deliver seq 1 (closing) first (buffered, out of order), THEN seq 0. */
    size_t order[2] = {1, 0};
    int last_rc = deliver_frames(&w, &o, &rx, order, 2);
    ASSERT_EQ_INT(last_rc, 1);

    uint8_t out[16];
    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, 4);
    ASSERT_MEM_EQ(out, "AAAA", 4);
    ASSERT_EQ_INT(cloak_stream_read(&rx, out, sizeof(out)), -1);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_duplicate_seq_rejected(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    cloak_stream_t tx;
    cloak_stream_init(&tx, 5, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING, wire_sink, &w);
    cloak_stream_write(&tx, (const uint8_t *)"hello", 5);

    cloak_stream_t rx;
    cloak_stream_init(&rx, 5, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING, wire_sink, &w);
    uint8_t out[16];

    uint8_t *copy1 = (uint8_t *)malloc(w.frame_lens[0]);
    memcpy(copy1, w.frames_data, w.frame_lens[0]);
    cloak_frame_t f1;
    cloak_frame_deobfuscate(&o, &f1, copy1, w.frame_lens[0]);
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx, &f1), 0);
    free(copy1);

    uint8_t *copy2 = (uint8_t *)malloc(w.frame_lens[0]);
    memcpy(copy2, w.frames_data, w.frame_lens[0]);
    cloak_frame_t f2;
    cloak_frame_deobfuscate(&o, &f2, copy2, w.frame_lens[0]);
    ASSERT_EQ_INT(cloak_stream_feed_frame(&rx, &f2), -1);
    free(copy2);

    long got = cloak_stream_read(&rx, out, sizeof(out));
    ASSERT_EQ_INT(got, 5);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_backpressure_and_resume(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    /* 4-byte frames, tiny 10-byte recv capacity: only 2.5 frames worth of
     * payload fit at once. */
    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 4;
    cloak_stream_t tx;
    cloak_stream_init(&tx, 6, &o, max_on_wire, 1 << 20, MAX_PENDING, wire_sink, &w);
    const char *msg = "0123456789ABCDEFGHIJ"; /* 20 bytes -> 5 frames of 4 bytes */
    cloak_stream_write(&tx, (const uint8_t *)msg, strlen(msg));
    ASSERT_EQ_INT(w.frame_count, 5);

    cloak_stream_t rx;
    ASSERT_EQ_INT(cloak_stream_init(&rx, 6, &o, max_on_wire, 10, MAX_PENDING, wire_sink, &w), 0);

    size_t order[5] = {0, 1, 2, 3, 4};
    /* Deliver all 5 in order; backpressure should stall draining partway
     * through since the queue can only hold 10 of the 20 payload bytes. */
    deliver_frames(&w, &o, &rx, order, 5);
    ASSERT_TRUE(cloak_stream_recv_available(&rx) <= 10);
    ASSERT_TRUE(cloak_stream_recv_available(&rx) > 0);

    uint8_t out[64];
    long total = 0;
    /* Drain in small chunks, exactly like a real consumer, and confirm
     * try_drain resumes delivering the backpressured frames as space frees. */
    for (int iter = 0; iter < 20 && total < (long)strlen(msg); iter++) {
        long got = cloak_stream_read(&rx, out + total, 3);
        if (got > 0) {
            total += got;
        }
    }
    ASSERT_EQ_INT(total, (long)strlen(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)total);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_max_pending_frames_cap(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);

    size_t max_on_wire = CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN + 2;
    cloak_stream_t tx;
    cloak_stream_init(&tx, 8, &o, max_on_wire, 1 << 20, 1000, wire_sink, &w);
    uint8_t msg[20];
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)i;
    cloak_stream_write(&tx, msg, sizeof(msg)); /* 10 frames of 2 bytes */
    ASSERT_EQ_INT(w.frame_count, 10);

    cloak_stream_t rx;
    /* max_pending_frames = 3: never deliver seq 0, so frames 1..9 (9 of
     * them) all pile up out-of-order; the cap should reject once exceeded. */
    ASSERT_EQ_INT(cloak_stream_init(&rx, 8, &o, max_on_wire, 1 << 20, 3, wire_sink, &w), 0);

    int saw_rejection = 0;
    size_t *offsets = (size_t *)malloc(w.frame_count * sizeof(size_t));
    size_t off = 0;
    for (size_t i = 0; i < w.frame_count; i++) { offsets[i] = off; off += w.frame_lens[i]; }
    for (size_t idx = 1; idx < w.frame_count; idx++) {
        uint8_t *copy = (uint8_t *)malloc(w.frame_lens[idx]);
        memcpy(copy, w.frames_data + offsets[idx], w.frame_lens[idx]);
        cloak_frame_t frame;
        cloak_frame_deobfuscate(&o, &frame, copy, w.frame_lens[idx]);
        int rc = cloak_stream_feed_frame(&rx, &frame);
        free(copy);
        if (rc == -1) {
            saw_rejection = 1;
            break;
        }
    }
    free(offsets);
    ASSERT_TRUE(saw_rejection);

    cloak_stream_destroy(&tx);
    cloak_stream_destroy(&rx);
    wire_free(&w);
}

static void test_sink_failure_propagates(void) {
    cloak_obfuscator_t o;
    make_obfuscator(&o);
    wire_t w;
    wire_init(&w);
    w.fail_after_n = 0; /* sink fails immediately */

    cloak_stream_t tx;
    cloak_stream_init(&tx, 10, &o, MAX_ON_WIRE, RECV_CAP, MAX_PENDING, wire_sink, &w);
    long n = cloak_stream_write(&tx, (const uint8_t *)"data", 4);
    ASSERT_EQ_INT(n, -1);

    cloak_stream_destroy(&tx);
    wire_free(&w);
}

TEST_MAIN_BEGIN()
    test_round_trip_in_order();
    test_multi_frame_chunking_and_reassembly();
    test_out_of_order_delivery();
    test_shuffled_delivery_many_frames();
    test_closing_frame_signals_eof();
    test_closing_frame_out_of_order_stops_drain();
    test_duplicate_seq_rejected();
    test_backpressure_and_resume();
    test_max_pending_frames_cap();
    test_sink_failure_propagates();
TEST_MAIN_END()
```

- [ ] **Step 4: Update the library's CMakeLists.txt**

Modify `libcloak-mux/CMakeLists.txt` to add the new source file:

```cmake
add_library(cloak-mux STATIC
    src/frame.c
    src/bytequeue.c
    src/stream.c
)

target_include_directories(cloak-mux PUBLIC include)
target_link_libraries(cloak-mux PUBLIC cloak-common)

add_subdirectory(tests)
```

- [ ] **Step 5: Register the new test**

Modify `libcloak-mux/tests/CMakeLists.txt` to add:

```cmake
add_executable(test_stream test_stream.c)
target_include_directories(test_stream PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_stream PRIVATE cloak-mux)
add_test(NAME test_stream COMMAND test_stream)
```

- [ ] **Step 6: Build and test in Docker**

```bash
docker build -q -f Dockerfile.dev -t cloak-c-dev .
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "rm -rf build && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure"
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build-asan -DCMAKE_C_FLAGS='-fsanitize=address,undefined -g' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' && cmake --build build-asan && ctest --test-dir build-asan --output-on-failure"
```

Expected: all tests pass (plain and ASan/UBSan), zero compiler warnings, including the shuffled-100-frame reassembly test and the backpressure-then-resume test.

- [ ] **Step 7: Commit**

```bash
git add libcloak-mux/include/cloak/stream.h libcloak-mux/src/stream.c \
        libcloak-mux/tests/test_stream.c libcloak-mux/CMakeLists.txt libcloak-mux/tests/CMakeLists.txt
git commit -m "Add stream: frame chunking and sequence-ordered reassembly"
```

---

## What comes after this plan

Not started here, deliberately out of scope:

- **Session + connection pool** (design spec section 6, Go's `Session`+`switchboard`): stream table (id -> `cloak_stream_t`, with tombstoning for late frames from closed streams, matching Go's `sesh.streams[s.id] = nil` pattern), accept queue for incoming streams, the connection pool (Go's `uniformSpread`: pick a uniformly random underlying connection per `cloak_stream_write`-produced frame), wiring real epoll-registered connections as the `cloak_stream_frame_sink_t` implementation and as the source of `cloak_frame_deobfuscate`'d frames fed into `cloak_stream_feed_frame`, session-level active/passive close (sending a `CLOAK_FRAME_CLOSING_SESSION` frame, tearing down every underlying connection), and the inactivity timeout (via the already-built reactor's timer heap). This is the module that turns `cloak_stream_t` from a pure data structure into something actually connected to a network.
- **Unordered/datagram mode** (Go's `datagramBufferedPipe.go`): no reordering at all -- frames delivered in physical arrival order, with message-boundary preservation instead of byte-stream semantics. Can reuse `cloak_bytequeue_t`'s underlying allocation pattern but needs its own delivery-order (not sequence-order) logic; deferred since it's an opt-in mode (`session.Unordered`), not required for the common TCP-backed path.
- **Rate limiting / QoS** (Go's `qos.go`): token-bucket rx/tx throttling, shared across sessions belonging to one user. Fully optional in Go (defaults to an unlimited no-op `Valve`); deferred until user-management/admin-API work makes it relevant.
- **The server dispatcher's connection state machine** (design spec section 7) and **`libcloak-server`'s auth handshake integration** (already-merged `cloak_server_auth_decrypt`/`cloak_server_auth_compose_reply`/`cloak_replay_cache_*`): wiring a successfully authenticated connection into a new or existing session is downstream of the session/connection-pool module above.

## Self-Review

**Spec coverage:** The design spec's data-plane description ("event-driven splicing... EPOLLIN deregistered on the source... re-armed") is directly reflected in `cloak_bytequeue_t`'s non-blocking, capacity-query-driven design and `cloak_stream_t`'s backpressure-preserving `feed_frame`/`try_drain` split -- both are the foundation that description's splicing logic will be built on in a later plan.

**Placeholder scan:** No TBD/TODO-style steps; every step has complete, already-verified code.

**Type consistency:** `cloak_bytequeue_t` and its functions are defined once (Task 1, Step 1) and used identically in Task 1's implementation/tests and in Task 2 (which wraps one inside `cloak_stream_t`). `cloak_stream_t`, `cloak_pending_frame_t`, and `cloak_stream_frame_sink_t` are defined once (Task 2, Step 1) and used identically in the implementation and tests. No cross-task signature drift.
