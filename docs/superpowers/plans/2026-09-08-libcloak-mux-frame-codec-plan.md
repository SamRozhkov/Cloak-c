# libcloak-mux: Frame Codec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and unit-test the frame serialization/obfuscation codec — `cloak_frame_obfuscate`/`cloak_frame_deobfuscate` — in a new `libcloak-mux` static library, with no session/stream/switchboard or networking logic on top yet.

**Architecture:** A new module, `cloak/frame.h` + `src/frame.c`, depending on `libcloak-common`'s already-built crypto primitives (`cloak_aead_seal/open/overhead`, `cloak_salsa20_xor`). Mirrors Go Cloak's `internal/multiplex/obfs.go` design exactly (already reviewed in this project's design spec as proven-against-DPI, kept deliberately rather than reinvented): a 14-byte header (stream ID, sequence number, closing flag, extra-length byte) is written in plaintext, the payload (plus random padding for the first 5 frames of a session) is AEAD-encrypted using the plaintext header's first 12 bytes (stream ID + sequence number) as the AEAD nonce, and finally the header itself is XORed with a Salsa20 keystream whose nonce is the trailing 8 bytes of the AEAD tag (or, in `plain`/no-encryption mode, 8 bytes of random filler serving the same nonce-source role). Both directions operate on a single caller-supplied buffer with no extra allocation: `obfuscate` writes in place, `deobfuscate` decrypts in place and returns a `payload` pointer into the same buffer.

**Tech Stack:** C11, CMake, OpenSSL indirectly via `libcloak-common`, the existing custom assert-based test framework (`libcloak-common/tests/test_framework.h`, reused — not duplicated).

## Global Constraints

- Language: C11 (`-Wall -Wextra` clean build, enforced project-wide by the root `CMakeLists.txt`).
- Platform: Linux only (per spec §2). Unlike the reactor, nothing in this module uses a Linux-specific API — it's portable C11 plus calls into `libcloak-common`. Build/test through Docker anyway, for process consistency with the rest of the project:
  ```bash
  docker build -q -f Dockerfile.dev -t cloak-c-dev .
  docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure"
  ```
  Run every "Run:" instruction in this plan through this Docker invocation, substituting the specific `cmake`/`ctest` command shown, from the repo/worktree root.
- No wire compatibility with Go Cloak is required (per spec §1) — the frame format mirrors Go Cloak's design because it's already DPI-proven, not because interop is needed. Exact numeric closing-flag values, byte order, and internal layout below are this project's own choice, consistent throughout.
- Frame header layout (per spec §4, 14 bytes total): `stream_id` (`uint32_t`, big-endian, bytes 0-3), `seq` (`uint64_t`, big-endian, bytes 4-11), `closing` (`uint8_t`, byte 12), `extra_len` (`uint8_t`, byte 13).
- AEAD nonce for the payload is the plaintext header's first 12 bytes (`stream_id` + `seq` concatenated) — this equals `CLOAK_AEAD_NONCE_LEN` (12) exactly, guaranteeing a unique nonce per (stream, sequence) pair with no extra nonce material needed.
- Salsa20 nonce for the header is the trailing `CLOAK_SALSA20_NONCE_LEN` (8) bytes of the frame (the last 8 bytes of the real AEAD tag for non-`plain` methods, or 8 bytes of random filler for `plain` mode, which uses no AEAD tag at all).
- Padding: the first `CLOAK_FRAME_PAD_FIRST_N_FRAMES` (5) frames of a session (i.e. `seq` in `[0, 5)`) get a random amount of padding in the AEAD-protected region, in the range `[0, CLOAK_FRAME_MAX_EXTRA_LEN - tag_len]` where `CLOAK_FRAME_MAX_EXTRA_LEN` is 255 (the field is one byte) and `tag_len` is 16 for any AEAD method or 8 for `plain`. Frames with `seq >= 5` get no padding. This defeats TLS-in-TLS record-size fingerprinting on the frames most likely to be observed during a handshake.
- Crypto method IDs, sizes, and function signatures consumed from `libcloak-common/include/cloak/crypto.h` (already built and merged): `cloak_aead_method_t` (`CLOAK_AEAD_NONE=0, CLOAK_AEAD_AES_256_GCM=1, CLOAK_AEAD_CHACHA20_POLY1305=2, CLOAK_AEAD_AES_128_GCM=3`), `CLOAK_AEAD_KEY_LEN` (32), `CLOAK_AEAD_NONCE_LEN` (12), `CLOAK_AEAD_TAG_LEN` (16), `CLOAK_SALSA20_KEY_LEN` (32), `CLOAK_SALSA20_NONCE_LEN` (8), `cloak_aead_seal`, `cloak_aead_open`, `cloak_aead_overhead`, `cloak_salsa20_xor`. This plan does not modify any file under `libcloak-common/`.
- Testing: reuse `libcloak-common/tests/test_framework.h` (do not copy or reimplement it) — no new test framework.
- Build: CMake. New static library `cloak-mux`, publicly depending on `cloak-common`.

---

### Task 1: Frame struct, `plain`-mode obfuscate/deobfuscate, padding, and buffer-safety checks

**Files:**
- Create: `libcloak-mux/CMakeLists.txt`
- Create: `libcloak-mux/include/cloak/frame.h`
- Create: `libcloak-mux/src/frame.c`
- Create: `libcloak-mux/tests/CMakeLists.txt`
- Create: `libcloak-mux/tests/test_frame.c`
- Modify: `CMakeLists.txt` (root — add `add_subdirectory(libcloak-mux)` after the existing `add_subdirectory(libcloak-common)`)

**Interfaces:**
- Consumes: `cloak_random_bytes` (`cloak/common.h`), `cloak_salsa20_xor`, `CLOAK_SALSA20_NONCE_LEN`, `CLOAK_AEAD_NONCE_LEN`, `cloak_aead_method_t`, `CLOAK_AEAD_NONE` (`cloak/crypto.h`) — all from `libcloak-common`, already built and merged. This task's tests only exercise `CLOAK_AEAD_NONE`; `cloak_aead_seal`/`cloak_aead_open`/`cloak_aead_overhead` are wired into `frame.c` in this task but only actually invoked for non-`NONE` methods, which Task 2 tests.
- Produces (final state of `cloak/frame.h` — Task 2 adds no new declarations, only exercises the non-`NONE` code path already present here):
  ```c
  #define CLOAK_FRAME_HEADER_LEN 14
  #define CLOAK_FRAME_MAX_EXTRA_LEN 255
  #define CLOAK_FRAME_PAD_FIRST_N_FRAMES 5

  #define CLOAK_FRAME_CLOSING_NOTHING 0
  #define CLOAK_FRAME_CLOSING_STREAM 1
  #define CLOAK_FRAME_CLOSING_SESSION 2

  typedef struct {
      uint32_t stream_id;
      uint64_t seq;
      uint8_t closing;
      const uint8_t *payload;
      size_t payload_len;
  } cloak_frame_t;

  typedef struct {
      cloak_aead_method_t method;
      uint8_t session_key[CLOAK_AEAD_KEY_LEN];
  } cloak_obfuscator_t;

  long cloak_frame_obfuscate(const cloak_obfuscator_t *o, const cloak_frame_t *frame,
                              uint8_t *buf, size_t buf_cap, size_t payload_offset_in_buf);

  int cloak_frame_deobfuscate(const cloak_obfuscator_t *o, cloak_frame_t *out_frame,
                               uint8_t *buf, size_t buf_len);
  ```
  `cloak_frame_obfuscate` returns the number of bytes written (`> 0`) on success, `-1` on failure (empty payload, buffer too small). If `payload_offset_in_buf == CLOAK_FRAME_HEADER_LEN`, the caller has already placed `frame->payload_len` bytes at `buf[CLOAK_FRAME_HEADER_LEN:]` and `obfuscate` skips the copy (an optimization the future session/stream code will use); any other value causes `frame->payload` to be copied into place. `cloak_frame_deobfuscate` mutates `buf` in place (the header is decrypted in place; on success `out_frame->payload` points into `buf`, no separate output buffer) and returns `0` on success, `-1` on failure (buffer too short, corrupt `extra_len`, AEAD authentication failure — the latter only reachable once Task 2 wires in non-`NONE` methods, but the bounds-check failure path is exercised by this task).

- [ ] **Step 1: Write the failing test**

Create `libcloak-mux/include/cloak/frame.h`:

```c
#ifndef CLOAK_FRAME_H
#define CLOAK_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/crypto.h"

#define CLOAK_FRAME_HEADER_LEN 14
#define CLOAK_FRAME_MAX_EXTRA_LEN 255
#define CLOAK_FRAME_PAD_FIRST_N_FRAMES 5

#define CLOAK_FRAME_CLOSING_NOTHING 0
#define CLOAK_FRAME_CLOSING_STREAM 1
#define CLOAK_FRAME_CLOSING_SESSION 2

typedef struct {
    uint32_t stream_id;
    uint64_t seq;
    uint8_t closing;
    const uint8_t *payload;
    size_t payload_len;
} cloak_frame_t;

typedef struct {
    cloak_aead_method_t method;
    uint8_t session_key[CLOAK_AEAD_KEY_LEN];
} cloak_obfuscator_t;

/* Serializes and encrypts frame into buf (capacity buf_cap). frame->payload_len
 * must be nonzero.
 *
 * If payload_offset_in_buf == CLOAK_FRAME_HEADER_LEN, the caller has already
 * written frame->payload_len bytes at buf[CLOAK_FRAME_HEADER_LEN:] and this
 * function skips copying frame->payload (frame->payload itself is then
 * unused). Any other value causes frame->payload to be copied into place.
 *
 * Returns the number of bytes written to buf (> 0) on success, or -1 on
 * failure (empty payload, buf_cap too small, or an AEAD failure). */
long cloak_frame_obfuscate(const cloak_obfuscator_t *o, const cloak_frame_t *frame,
                            uint8_t *buf, size_t buf_cap, size_t payload_offset_in_buf);

/* Decrypts and parses a frame from buf IN PLACE: the header is decrypted in
 * place, and on success out_frame->payload points into buf (no copy, no
 * separate output buffer). buf must not be read again as ciphertext after
 * this call.
 *
 * Returns 0 on success, -1 on failure (buf_len too short, a corrupt
 * extra_len field pointing past the available data, or an AEAD
 * authentication failure). */
int cloak_frame_deobfuscate(const cloak_obfuscator_t *o, cloak_frame_t *out_frame,
                             uint8_t *buf, size_t buf_len);

#endif
```

Create `libcloak-mux/tests/test_frame.c`:

```c
#include "cloak/frame.h"
#include "cloak/common.h"
#include "test_framework.h"

#include <string.h>

static void make_plain_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_NONE;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

static void test_round_trip_plain(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    const uint8_t payload[] = "hello frame";
    cloak_frame_t frame;
    frame.stream_id = 7;
    frame.seq = 100; /* >= CLOAK_FRAME_PAD_FIRST_N_FRAMES, so no padding -- deterministic length */
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[128];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);
    /* seq >= 5 means pad_len == 0; plain mode's tag_len is CLOAK_SALSA20_NONCE_LEN (8). */
    ASSERT_EQ_INT(n, CLOAK_FRAME_HEADER_LEN + (long)frame.payload_len + CLOAK_SALSA20_NONCE_LEN);

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(out.stream_id, frame.stream_id);
    ASSERT_EQ_INT(out.seq, frame.seq);
    ASSERT_EQ_INT(out.closing, frame.closing);
    ASSERT_EQ_INT(out.payload_len, frame.payload_len);
    ASSERT_MEM_EQ(out.payload, payload, frame.payload_len);
}

static void test_padding_varies_for_first_n_frames_only(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    const uint8_t payload[] = "x";
    uint8_t buf[512];

    /* seq >= CLOAK_FRAME_PAD_FIRST_N_FRAMES: length must be identical every time. */
    long first_len = -1;
    for (int i = 0; i < 10; i++) {
        cloak_frame_t frame;
        frame.stream_id = 1;
        frame.seq = 5 + (uint64_t)i;
        frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
        frame.payload = payload;
        frame.payload_len = sizeof(payload);
        long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
        ASSERT_TRUE(n > 0);
        if (first_len < 0) {
            first_len = n;
        } else {
            ASSERT_EQ_INT(n, first_len);
        }
    }

    /* seq < CLOAK_FRAME_PAD_FIRST_N_FRAMES: across enough samples, length
     * must vary at least once (padding is randomized). Not fully
     * deterministic by construction, but with a 240-value range and 40
     * samples the chance every single call lands on the exact same pad
     * length is astronomically small (this only asserts "at least two
     * distinct lengths seen", not a specific distribution). */
    int distinct_lengths_seen = 0;
    long seen_len = -1;
    for (int i = 0; i < 40; i++) {
        cloak_frame_t frame;
        frame.stream_id = 1;
        frame.seq = 0; /* always within the padded range */
        frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
        frame.payload = payload;
        frame.payload_len = sizeof(payload);
        long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
        ASSERT_TRUE(n > 0);
        ASSERT_TRUE(n >= first_len); /* padding only adds bytes, never removes */
        if (seen_len < 0) {
            seen_len = n;
        } else if (n != seen_len) {
            distinct_lengths_seen = 1;
        }
    }
    ASSERT_TRUE(distinct_lengths_seen);
}

static void test_payload_offset_optimization_skips_copy(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    uint8_t buf[128];
    const uint8_t payload[] = "preplaced";
    memcpy(buf + CLOAK_FRAME_HEADER_LEN, payload, sizeof(payload));

    cloak_frame_t frame;
    frame.stream_id = 2;
    frame.seq = 50;
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = NULL; /* must be unused when payload_offset_in_buf == CLOAK_FRAME_HEADER_LEN */
    frame.payload_len = sizeof(payload);

    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), CLOAK_FRAME_HEADER_LEN);
    ASSERT_TRUE(n > 0);

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_MEM_EQ(out.payload, payload, sizeof(payload));
}

static void test_obfuscate_rejects_empty_payload(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 10;
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = (const uint8_t *)"";
    frame.payload_len = 0;

    uint8_t buf[64];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_EQ_INT(n, -1);
}

static void test_obfuscate_rejects_buffer_too_small(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    const uint8_t payload[32] = {0};
    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 10; /* no padding, so required size is exactly known */
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    /* Required: CLOAK_FRAME_HEADER_LEN + 32 + CLOAK_SALSA20_NONCE_LEN (plain mode). One byte short. */
    uint8_t buf[CLOAK_FRAME_HEADER_LEN + 32 + CLOAK_SALSA20_NONCE_LEN - 1];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_EQ_INT(n, -1);
}

static void test_deobfuscate_rejects_short_buffer(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    uint8_t buf[10]; /* shorter than CLOAK_FRAME_HEADER_LEN + CLOAK_SALSA20_NONCE_LEN (22) */
    memset(buf, 0, sizeof(buf));

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, sizeof(buf));
    ASSERT_EQ_INT(rc, -1);
}

static void test_deobfuscate_rejects_corrupt_extra_len(void) {
    cloak_obfuscator_t o;
    make_plain_obfuscator(&o);

    const uint8_t payload[] = "short";
    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 100; /* no padding, deterministic layout */
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[128];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);

    /* Decrypt the header, corrupt extra_len to an implausibly large value,
     * then re-encrypt the header (Salsa20 XOR is its own inverse under the
     * same nonce/key) so deobfuscate will "successfully" decrypt the
     * header but find a corrupt extra_len pointing past the available
     * payload+overhead region. */
    const uint8_t *header_nonce = buf + n - CLOAK_SALSA20_NONCE_LEN;
    cloak_salsa20_xor(buf, buf, CLOAK_FRAME_HEADER_LEN, header_nonce, o.session_key);
    buf[13] = 255;
    cloak_salsa20_xor(buf, buf, CLOAK_FRAME_HEADER_LEN, header_nonce, o.session_key);

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, -1);
}

TEST_MAIN_BEGIN()
    test_round_trip_plain();
    test_padding_varies_for_first_n_frames_only();
    test_payload_offset_optimization_skips_copy();
    test_obfuscate_rejects_empty_payload();
    test_obfuscate_rejects_buffer_too_small();
    test_deobfuscate_rejects_short_buffer();
    test_deobfuscate_rejects_corrupt_extra_len();
TEST_MAIN_END()
```

Create `libcloak-mux/tests/CMakeLists.txt`:

```cmake
add_executable(test_frame test_frame.c)
target_include_directories(test_frame PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_frame PRIVATE cloak-mux)
add_test(NAME test_frame COMMAND test_frame)
```

Create `libcloak-mux/CMakeLists.txt`:

```cmake
add_library(cloak-mux STATIC
    src/frame.c
)

target_include_directories(cloak-mux PUBLIC include)
target_link_libraries(cloak-mux PUBLIC cloak-common)

add_subdirectory(tests)
```

Modify the root `CMakeLists.txt`: add `add_subdirectory(libcloak-mux)` as a new line right after the existing `add_subdirectory(libcloak-common)` line.

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
docker build -q -f Dockerfile.dev -t cloak-c-dev .
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build && cmake --build build"
```
Expected: FAIL — `libcloak-mux/src/frame.c` doesn't exist yet, so `add_library(cloak-mux STATIC src/frame.c)` fails cmake's configure/build step with a missing-source-file error (or, if CMake configure itself succeeds by treating it as absent, a build failure). Either way, `cmake --build build` does not produce a working `test_frame` binary at this point.

- [ ] **Step 3: Write the implementation**

Create `libcloak-mux/src/frame.c`:

```c
#include "cloak/frame.h"
#include "cloak/common.h"

#include <string.h>

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint64_t load_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static void store_be64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

/* tag_len is the number of trailing bytes reserved after the payload+padding:
 * the real AEAD tag for any non-NONE method, or CLOAK_SALSA20_NONCE_LEN
 * bytes of random filler in NONE mode (used purely as the Salsa20 header
 * nonce, since there is no AEAD tag to borrow bytes from). */
static size_t tag_len_for_method(cloak_aead_method_t method) {
    if (method == CLOAK_AEAD_NONE) {
        return CLOAK_SALSA20_NONCE_LEN;
    }
    return cloak_aead_overhead(method);
}

static uint8_t random_pad_len(size_t max_inclusive) {
    uint8_t b;
    cloak_random_bytes(&b, 1);
    return (uint8_t)(b % (max_inclusive + 1));
}

long cloak_frame_obfuscate(const cloak_obfuscator_t *o, const cloak_frame_t *frame,
                            uint8_t *buf, size_t buf_cap, size_t payload_offset_in_buf) {
    if (frame->payload_len == 0) {
        return -1;
    }

    size_t tag_len = tag_len_for_method(o->method);

    size_t pad_len = 0;
    if (frame->seq < CLOAK_FRAME_PAD_FIRST_N_FRAMES) {
        pad_len = random_pad_len(CLOAK_FRAME_MAX_EXTRA_LEN - tag_len);
    }

    size_t useful_len = CLOAK_FRAME_HEADER_LEN + frame->payload_len + pad_len + tag_len;
    if (buf_cap < useful_len) {
        return -1;
    }

    uint8_t *payload_region = buf + CLOAK_FRAME_HEADER_LEN;
    if (payload_offset_in_buf != CLOAK_FRAME_HEADER_LEN) {
        memmove(payload_region, frame->payload, frame->payload_len);
    }

    store_be32(buf + 0, frame->stream_id);
    store_be64(buf + 4, frame->seq);
    buf[12] = frame->closing;
    buf[13] = (uint8_t)(pad_len + tag_len);

    /* Random padding plus the trailing tag_len bytes that either become the
     * real AEAD tag (overwritten below) or, in NONE mode, stay as the
     * Salsa20 nonce source. */
    cloak_random_bytes(payload_region + frame->payload_len, pad_len + tag_len);

    if (o->method != CLOAK_AEAD_NONE) {
        uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
        memcpy(nonce, buf, CLOAK_AEAD_NONCE_LEN); /* plaintext stream_id+seq, before header encryption */
        size_t sealed_len = 0;
        int rc = cloak_aead_seal(o->method, o->session_key, nonce,
                                  payload_region, frame->payload_len + pad_len,
                                  payload_region, &sealed_len);
        if (rc != 0) {
            return -1;
        }
    }

    const uint8_t *header_nonce = buf + useful_len - CLOAK_SALSA20_NONCE_LEN;
    cloak_salsa20_xor(buf, buf, CLOAK_FRAME_HEADER_LEN, header_nonce, o->session_key);

    return (long)useful_len;
}

int cloak_frame_deobfuscate(const cloak_obfuscator_t *o, cloak_frame_t *out_frame,
                             uint8_t *buf, size_t buf_len) {
    if (buf_len < CLOAK_FRAME_HEADER_LEN + CLOAK_SALSA20_NONCE_LEN) {
        return -1;
    }

    const uint8_t *header_nonce = buf + buf_len - CLOAK_SALSA20_NONCE_LEN;
    cloak_salsa20_xor(buf, buf, CLOAK_FRAME_HEADER_LEN, header_nonce, o->session_key);

    uint32_t stream_id = load_be32(buf + 0);
    uint64_t seq = load_be64(buf + 4);
    uint8_t closing = buf[12];
    uint8_t extra_len = buf[13];

    uint8_t *pld_with_overhead = buf + CLOAK_FRAME_HEADER_LEN;
    size_t pld_with_overhead_len = buf_len - CLOAK_FRAME_HEADER_LEN;

    if ((size_t)extra_len > pld_with_overhead_len) {
        return -1;
    }
    size_t useful_payload_len = pld_with_overhead_len - extra_len;

    if (o->method != CLOAK_AEAD_NONE) {
        uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
        memcpy(nonce, buf, CLOAK_AEAD_NONCE_LEN); /* now-decrypted plaintext stream_id+seq */
        size_t opened_len = 0;
        int rc = cloak_aead_open(o->method, o->session_key, nonce,
                                  pld_with_overhead, pld_with_overhead_len,
                                  pld_with_overhead, &opened_len);
        if (rc != 0) {
            return -1;
        }
        if (useful_payload_len > opened_len) {
            return -1;
        }
    }

    out_frame->stream_id = stream_id;
    out_frame->seq = seq;
    out_frame->closing = closing;
    out_frame->payload = pld_with_overhead;
    out_frame->payload_len = useful_payload_len;
    return 0;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake --build build && ctest --test-dir build --output-on-failure"
```
Expected: `100% tests passed, 0 tests failed out of 7` (the 6 existing `libcloak-common` binaries plus the new `test_frame`, which has 7 test cases).

- [ ] **Step 5: Commit**

```bash
git add CMakeLists.txt libcloak-mux/CMakeLists.txt libcloak-mux/include/cloak/frame.h \
        libcloak-mux/src/frame.c libcloak-mux/tests/CMakeLists.txt libcloak-mux/tests/test_frame.c
git commit -m "Add frame codec: struct + plain-mode obfuscate/deobfuscate with padding"
```

---

### Task 2: AEAD-mode obfuscate/deobfuscate — round trip, tamper detection, wrong-key rejection

**Files:**
- Modify: `libcloak-mux/tests/test_frame.c` (append new test functions)

**Interfaces:**
- Consumes: `cloak_aead_seal`, `cloak_aead_open` (already wired into `frame.c`'s non-`NONE` branch by Task 1 — this task adds no new production code, only tests that exercise the branch Task 1 already wrote). `cloak_frame_obfuscate`/`cloak_frame_deobfuscate` signatures from Task 1, unchanged.
- Produces: nothing new — this is the complete, final state of `libcloak-mux`'s frame codec for this plan. The future session/stream/switchboard plan will call `cloak_frame_obfuscate`/`cloak_frame_deobfuscate` exactly as defined in Task 1, for all four `cloak_aead_method_t` values.

- [ ] **Step 1: Write the failing test**

This task's tests are expected to already PASS against Task 1's implementation (Task 1 wired the AEAD branch in `frame.c`, it just wasn't exercised by any test yet) — so "RED" here means confirming the new tests compile and reveal whatever gap exists, not necessarily a guaranteed failure. Append to `libcloak-mux/tests/test_frame.c`, before `TEST_MAIN_BEGIN()`:

```c
static void round_trip_for_method(cloak_aead_method_t method) {
    cloak_obfuscator_t o;
    o.method = method;
    cloak_random_bytes(o.session_key, sizeof(o.session_key));

    const uint8_t payload[] = "round trip across every AEAD method the frame codec supports";
    cloak_frame_t frame;
    frame.stream_id = 42;
    frame.seq = 1000; /* no padding, deterministic layout */
    frame.closing = CLOAK_FRAME_CLOSING_STREAM;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[256];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);
    ASSERT_EQ_INT(n, CLOAK_FRAME_HEADER_LEN + (long)frame.payload_len + CLOAK_AEAD_TAG_LEN);

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(out.stream_id, frame.stream_id);
    ASSERT_EQ_INT(out.seq, frame.seq);
    ASSERT_EQ_INT(out.closing, frame.closing);
    ASSERT_EQ_INT(out.payload_len, frame.payload_len);
    ASSERT_MEM_EQ(out.payload, payload, frame.payload_len);
}

static void test_aes256gcm_round_trip(void) {
    round_trip_for_method(CLOAK_AEAD_AES_256_GCM);
}

static void test_aes128gcm_round_trip(void) {
    round_trip_for_method(CLOAK_AEAD_AES_128_GCM);
}

static void test_chacha20poly1305_round_trip(void) {
    round_trip_for_method(CLOAK_AEAD_CHACHA20_POLY1305);
}

static void test_tamper_detected_after_obfuscate(void) {
    cloak_obfuscator_t o;
    o.method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o.session_key, sizeof(o.session_key));

    const uint8_t payload[] = "tamper with me if you can";
    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 1000;
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[256];
    long n = cloak_frame_obfuscate(&o, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);

    /* Flip a bit inside the encrypted payload region (well after the
     * header, well before the very end) -- must break AEAD authentication. */
    buf[CLOAK_FRAME_HEADER_LEN] ^= 0x01;

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&o, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, -1);
}

static void test_wrong_key_rejected(void) {
    cloak_obfuscator_t sender;
    sender.method = CLOAK_AEAD_CHACHA20_POLY1305;
    cloak_random_bytes(sender.session_key, sizeof(sender.session_key));

    cloak_obfuscator_t wrong_receiver;
    wrong_receiver.method = CLOAK_AEAD_CHACHA20_POLY1305;
    cloak_random_bytes(wrong_receiver.session_key, sizeof(wrong_receiver.session_key));

    const uint8_t payload[] = "secret";
    cloak_frame_t frame;
    frame.stream_id = 1;
    frame.seq = 1000;
    frame.closing = CLOAK_FRAME_CLOSING_NOTHING;
    frame.payload = payload;
    frame.payload_len = sizeof(payload);

    uint8_t buf[256];
    long n = cloak_frame_obfuscate(&sender, &frame, buf, sizeof(buf), 0);
    ASSERT_TRUE(n > 0);

    cloak_frame_t out;
    int rc = cloak_frame_deobfuscate(&wrong_receiver, &out, buf, (size_t)n);
    ASSERT_EQ_INT(rc, -1);
}
```

Add these five calls inside `TEST_MAIN_BEGIN() ... TEST_MAIN_END()`, after the existing seven:

```c
    test_aes256gcm_round_trip();
    test_aes128gcm_round_trip();
    test_chacha20poly1305_round_trip();
    test_tamper_detected_after_obfuscate();
    test_wrong_key_rejected();
```

- [ ] **Step 2: Run test to verify the suite builds and passes**

Run:
```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake --build build && ctest --test-dir build --output-on-failure"
```
Expected: `100% tests passed, 0 tests failed out of 7` (all 12 cases in `test_frame` now pass, since `frame.c`'s AEAD branch was already correctly wired in Task 1 — this step confirms it, it doesn't require a code change). If any of these 5 new tests fail, that means Task 1's AEAD branch has a bug; fix `libcloak-mux/src/frame.c` (not the tests) and re-run until green.

- [ ] **Step 3: No new implementation needed**

Task 1 already wired `cloak_aead_seal`/`cloak_aead_open` into `frame.c`'s non-`NONE` branches. This task adds no production code — only the tests above, which prove that branch works for all three AEAD methods, detects tampering, and rejects a wrong key.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "ctest --test-dir build --output-on-failure"
```
Expected: `100% tests passed, 0 tests failed out of 7`.

- [ ] **Step 5: Commit**

```bash
git add libcloak-mux/tests/test_frame.c
git commit -m "Add AEAD-mode frame codec tests: round trip, tamper detection, wrong-key rejection"
```

---

## What comes after this plan

This plan builds only the frame codec — no session, stream, or switchboard state, no networking, no reactor integration. Per the design spec's module breakdown, the next plans in dependency order are:

1. **`libcloak-common`: ClientHello templates** — captured browser bytes, offset table, SNI patcher (spec §5). Independent of both this plan and the reactor; pure byte manipulation.
2. **`libcloak-mux`: session/stream/switchboard** — multiplexing (spec §6), the first module to combine the reactor (already built) with the frame codec (this plan): `switchboard.deplex()` will call `cloak_frame_deobfuscate` on data read via reactor callbacks, and `Stream.Write` will call `cloak_frame_obfuscate` (using the `payload_offset_in_buf` optimization from Task 1) before handing bytes to the switchboard for sending.
3. **`libcloak-server`**: dispatcher state machine, auth, redirect-on-fail, SQLite user manager, admin API.
4. **`libcloak-client`**: connector, direct transport, CDN/WebSocket transport via `libssl`.
5. **`cmd/ck-server`, `cmd/ck-client`**: CLI binaries.
6. Integration tests and fuzz targets spanning the assembled binaries (spec §11 explicitly calls out fuzzing frame deobfuscation, mirroring Go's `session_fuzz.go`) — a natural target once this module exists.

## Self-review notes

- **Spec coverage:** spec §4's wire protocol section — 14-byte header layout, AEAD nonce = plaintext header's first 12 bytes, Salsa20 header nonce = trailing tag bytes, first-5-frames padding — is fully implemented and each element has a dedicated test (`test_round_trip_plain` for the base layout, `test_padding_varies_for_first_n_frames_only` for the padding rule, the AEAD round-trip tests for the nonce derivation, `test_tamper_detected_after_obfuscate` for AEAD authentication). Nothing from later plans (session/stream/switchboard, reactor integration) is included here.
- **Placeholder scan:** no TBD/TODO; every step has complete, runnable code.
- **Type consistency:** `cloak_frame_t`, `cloak_obfuscator_t`, `CLOAK_FRAME_HEADER_LEN` (14), `CLOAK_FRAME_MAX_EXTRA_LEN` (255), `CLOAK_FRAME_PAD_FIRST_N_FRAMES` (5), and the `cloak_frame_obfuscate`/`cloak_frame_deobfuscate` signatures are defined once in Task 1 and used identically in Task 2 (which adds only tests, no new declarations). All crypto-layer types/constants (`cloak_aead_method_t`, `CLOAK_AEAD_KEY_LEN`, `CLOAK_AEAD_NONCE_LEN`, `CLOAK_AEAD_TAG_LEN`, `CLOAK_SALSA20_NONCE_LEN`) are consumed exactly as already defined in the merged `libcloak-common/include/cloak/crypto.h`, not redefined here.
- **Known non-goal, noted for later:** `cloak_aead_seal`/`cloak_aead_open` each create and destroy a fresh `EVP_CIPHER_CTX` per call rather than reusing one across all frames of a session. This is functionally correct (verified by every test in this plan) but is a per-frame allocation on what will become a hot path once real traffic flows through the session/stream/switchboard plan. Deliberately not addressed here: doing so would mean changing the already-merged `libcloak-common` crypto API to support a cached/reusable context, which is a real design change better scoped against actual profiling data from real usage rather than spec'd speculatively now (YAGNI). Flagged here so it isn't forgotten if a future performance pass is needed.
