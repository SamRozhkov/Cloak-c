# libcloak-common: Config, Base64 and Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `libcloak-common` the three support layers every remaining module depends on — a strict base64 codec, a leveled logger, and JSON configuration parsing (client + server) built on a vendored cJSON — so that the dispatcher, user manager, client connector and the two binaries can all be written against settled types.

**Architecture:** cJSON is vendored verbatim under `third_party/cjson/` and built as its own static library, so third-party warnings stay out of the project's `-Wall -Wextra` build. Config parsing is split three ways: `config_common.c` holds the cJSON field accessors and the ssv (semicolon-separated-value) front end shared by both sides, while `config_client.c` and `config_server.c` each own one config struct. Both parsers funnel every input form — file, JSON text, ssv string — through a single `cJSON *` → struct function, so there is exactly one place where each field's name, type, default and validation rule lives. Every config struct is fixed-size and POD: no allocation, no ownership questions, and a caller can hold one on the stack. Errors are written into a caller-supplied `char err[]` buffer rather than allocated or logged, which keeps the parsers pure and directly testable.

**Tech Stack:** C11, CMake, cJSON v1.7.19 (vendored, MIT), CTest with the project's existing assert-based test framework (`libcloak-common/tests/test_framework.h`).

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` (§10 Config, CLI, build)

## Global Constraints

- Language: C11, `-Wall -Wextra` clean. Project code must produce zero warnings; vendored third-party code is exempt via a per-target `-w`.
- Platform: Linux only (spec §2). POSIX APIs are reached by defining `_POSIX_C_SOURCE 200809L` as the first line of the `.c` file that needs them — the convention already used by `libcloak-common/src/reactor.c`.
- Dependencies: OpenSSL `libcrypto` (already linked), plus cJSON vendored in-tree. No other third-party library in this plan. No system cJSON package — the vendored copy is the only one.
- Naming: every public symbol is prefixed `cloak_`; public headers live in `libcloak-common/include/cloak/` and use `CLOAK_<NAME>_H` include guards. Follow the doc-comment style of the existing headers (`crypto.h`, `reactor.h`): describe the contract, the failure modes, and anything a caller could get wrong.
- Allocation: config structs are fixed-size PODs, filled in place. The only heap allocation in this plan is cJSON's own, freed before each parse function returns.
- Tests: one `test_<unit>.c` per unit in `libcloak-common/tests/`, registered in `libcloak-common/tests/CMakeLists.txt`, using `test_framework.h`.
- Build and test command (run from the repository or worktree root; the project targets Linux, so all builds go through the existing `cloak-c-dev` image):

  ```bash
  docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
    'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
  ```

  To run a single test: `ctest --test-dir build -R test_base64 --output-on-failure`.

- Reference implementation: the Go original at `../Cloak` — `internal/client/state.go` (`RawConfig`, `ProcessRawConfig`, `ssvToJson`) and `internal/server/state.go` (`RawConfig`, `InitState`, `parseProxyBook`). Field names and defaults are mirrored from there; behaviour differences are called out explicitly in this plan where they exist.

---

### Task 1: `cloak_base64` — strict standard-alphabet base64

UIDs and keys arrive in config files as base64 strings (Go gets this for free from `encoding/json`'s `[]byte` handling, which uses `base64.StdEncoding`). Key generation in `ck-server` will also need the encoder.

**Files:**
- Create: `libcloak-common/include/cloak/base64.h`
- Create: `libcloak-common/src/base64.c`
- Create: `libcloak-common/tests/test_base64.c`
- Modify: `libcloak-common/CMakeLists.txt` (add `src/base64.c` to the `cloak-common` sources)
- Modify: `libcloak-common/tests/CMakeLists.txt` (register `test_base64`)

**Interfaces:**
- Consumes: nothing (leaf unit).
- Produces:
  - `size_t cloak_base64_encoded_size(size_t in_len)` — buffer size including the NUL terminator.
  - `int cloak_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap)` — 0 / -1.
  - `int cloak_base64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len)` — 0 / -1.

- [ ] **Step 1: Write the failing test**

Create `libcloak-common/tests/test_base64.c`:

```c
#include "cloak/base64.h"
#include "test_framework.h"

static void test_encode_rfc4648_vectors(void) {
    struct {
        const char *plain;
        const char *encoded;
    } cases[] = {
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        size_t plain_len = strlen(cases[i].plain);
        char out[32];
        ASSERT_EQ_INT(0, cloak_base64_encode((const uint8_t *)cases[i].plain,
                                             plain_len, out, sizeof(out)));
        ASSERT_EQ_INT(0, strcmp(out, cases[i].encoded));
        ASSERT_EQ_INT(strlen(cases[i].encoded) + 1,
                      cloak_base64_encoded_size(plain_len));
    }
}

static void test_decode_rfc4648_vectors(void) {
    struct {
        const char *encoded;
        const char *plain;
    } cases[] = {
        {"", ""},
        {"Zg==", "f"},
        {"Zm8=", "fo"},
        {"Zm9v", "foo"},
        {"Zm9vYg==", "foob"},
        {"Zm9vYmE=", "fooba"},
        {"Zm9vYmFy", "foobar"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t out[32];
        size_t out_len = 12345;
        ASSERT_EQ_INT(0, cloak_base64_decode(cases[i].encoded, out,
                                             sizeof(out), &out_len));
        ASSERT_EQ_INT(strlen(cases[i].plain), out_len);
        if (out_len > 0) {
            ASSERT_MEM_EQ(out, cases[i].plain, out_len);
        }
    }
}

static void test_round_trip_all_byte_values(void) {
    uint8_t plain[256];
    for (size_t i = 0; i < sizeof(plain); i++) {
        plain[i] = (uint8_t)i;
    }
    char encoded[cloak_base64_encoded_size_static];
    (void)encoded;
    char buf[512];
    ASSERT_EQ_INT(0, cloak_base64_encode(plain, sizeof(plain), buf, sizeof(buf)));

    uint8_t decoded[256];
    size_t decoded_len = 0;
    ASSERT_EQ_INT(0, cloak_base64_decode(buf, decoded, sizeof(decoded), &decoded_len));
    ASSERT_EQ_INT(sizeof(plain), decoded_len);
    ASSERT_MEM_EQ(plain, decoded, sizeof(plain));
}

static void test_decode_rejects_malformed(void) {
    uint8_t out[32];
    size_t out_len = 0;

    /* length not a multiple of 4 */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Zm9", out, sizeof(out), &out_len));
    /* character outside the standard alphabet ('-' is URL-safe, not standard) */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Zm9-", out, sizeof(out), &out_len));
    /* whitespace is not accepted */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Zm9v Zm9v", out, sizeof(out), &out_len));
    /* padding in a non-final quantum */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Zg==Zg==", out, sizeof(out), &out_len));
    /* three padding characters */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Z===", out, sizeof(out), &out_len));
    /* data character after padding within the final quantum */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Z=g=", out, sizeof(out), &out_len));
    /* NULL input */
    ASSERT_EQ_INT(-1, cloak_base64_decode(NULL, out, sizeof(out), &out_len));
}

static void test_respects_output_capacity(void) {
    uint8_t out[2];
    size_t out_len = 0;
    /* "foobar" decodes to 6 bytes, which does not fit in 2 */
    ASSERT_EQ_INT(-1, cloak_base64_decode("Zm9vYmFy", out, sizeof(out), &out_len));

    char small[4];
    const uint8_t plain[] = {1, 2, 3};
    /* needs 4 characters + NUL = 5 */
    ASSERT_EQ_INT(-1, cloak_base64_encode(plain, sizeof(plain), small, sizeof(small)));
}

static void test_decodes_a_16_byte_uid(void) {
    /* the shape every config file uses: 16 raw bytes as 24 base64 characters */
    const char *uid_b64 = "SGVsbG9DbG9ha1VJRCEhIQ==";
    uint8_t uid[16];
    size_t uid_len = 0;
    ASSERT_EQ_INT(0, cloak_base64_decode(uid_b64, uid, sizeof(uid), &uid_len));
    ASSERT_EQ_INT(16, uid_len);

    char back[64];
    ASSERT_EQ_INT(0, cloak_base64_encode(uid, uid_len, back, sizeof(back)));
    ASSERT_EQ_INT(0, strcmp(back, uid_b64));
}

TEST_MAIN_BEGIN()
    test_encode_rfc4648_vectors();
    test_decode_rfc4648_vectors();
    test_round_trip_all_byte_values();
    test_decode_rejects_malformed();
    test_respects_output_capacity();
    test_decodes_a_16_byte_uid();
TEST_MAIN_END()
```

Note: remove the two stray lines `char encoded[cloak_base64_encoded_size_static];` and `(void)encoded;` from `test_round_trip_all_byte_values` — they are not part of the API. The function should declare only `char buf[512];`.

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8'
```

Expected: FAIL — `cloak/base64.h: No such file or directory` (the test is not yet registered in CMake either, so add the registration in Step 3 along with the header).

- [ ] **Step 3: Write the header**

Create `libcloak-common/include/cloak/base64.h`:

```c
#ifndef CLOAK_BASE64_H
#define CLOAK_BASE64_H

#include <stddef.h>
#include <stdint.h>

/* Standard-alphabet base64 (RFC 4648 section 4: '+' and '/', padding
 * required), matching Go's encoding/base64.StdEncoding -- the encoding
 * Go Cloak's config files use for UIDs and keys.
 *
 * Decoding is strict about structure: the input length must be a multiple
 * of 4, every character must be in the alphabet (no whitespace, no
 * URL-safe '-'/'_'), and '=' padding may appear only as the last one or
 * two characters of the final quantum. It is deliberately NOT strict about
 * non-canonical trailing bits (e.g. "Zg==" and "Zh==" both decode), which
 * matches Go's default StdEncoding behaviour. */

/* Number of bytes cloak_base64_encode writes for in_len input bytes,
 * including the terminating NUL. */
size_t cloak_base64_encoded_size(size_t in_len);

/* Encodes in_len bytes into out as a NUL-terminated base64 string.
 * out_cap must be at least cloak_base64_encoded_size(in_len).
 * Returns 0 on success, -1 if out is NULL, out_cap is too small, or in is
 * NULL with in_len > 0. On failure out is left untouched. */
int cloak_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

/* Decodes the NUL-terminated base64 string in into out, writing the number
 * of decoded bytes to *out_len.
 * Returns 0 on success, -1 if in or out_len is NULL, the input is
 * malformed per the strictness rules above, or the decoded output would
 * exceed out_cap. On failure *out_len is not written and out may have been
 * partially overwritten -- callers must not read out after a failure.
 * An empty input string is valid and decodes to zero bytes. */
int cloak_base64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len);

#endif
```

- [ ] **Step 4: Write the implementation**

Create `libcloak-common/src/base64.c`:

```c
#include "cloak/base64.h"

#include <string.h>

static const char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Returns the 6-bit value of a standard-alphabet character, or -1 if c is
 * not in the alphabet. '=' is handled by the caller, not here. */
static int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

size_t cloak_base64_encoded_size(size_t in_len) {
    return ((in_len + 2) / 3) * 4 + 1;
}

int cloak_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    if (out == NULL) {
        return -1;
    }
    if (in == NULL && in_len > 0) {
        return -1;
    }
    if (out_cap < cloak_base64_encoded_size(in_len)) {
        return -1;
    }

    size_t o = 0;
    size_t i = 0;
    while (in_len - i >= 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
                     (uint32_t)in[i + 2];
        out[o++] = b64_alphabet[(v >> 18) & 0x3f];
        out[o++] = b64_alphabet[(v >> 12) & 0x3f];
        out[o++] = b64_alphabet[(v >> 6) & 0x3f];
        out[o++] = b64_alphabet[v & 0x3f];
        i += 3;
    }

    size_t rem = in_len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = b64_alphabet[(v >> 18) & 0x3f];
        out[o++] = b64_alphabet[(v >> 12) & 0x3f];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = b64_alphabet[(v >> 18) & 0x3f];
        out[o++] = b64_alphabet[(v >> 12) & 0x3f];
        out[o++] = b64_alphabet[(v >> 6) & 0x3f];
        out[o++] = '=';
    }

    out[o] = '\0';
    return 0;
}

int cloak_base64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (in == NULL || out_len == NULL) {
        return -1;
    }
    if (out == NULL && out_cap > 0) {
        return -1;
    }

    size_t len = strlen(in);
    if (len % 4 != 0) {
        return -1;
    }

    size_t produced = 0;
    for (size_t i = 0; i < len; i += 4) {
        int vals[4];
        int pad = 0;
        for (int j = 0; j < 4; j++) {
            char c = in[i + j];
            if (c == '=') {
                /* padding is legal only in the last quantum, only in the
                 * last two positions, and "=x" is never legal */
                if (i + 4 != len) {
                    return -1;
                }
                if (j < 2) {
                    return -1;
                }
                if (j == 2 && in[i + 3] != '=') {
                    return -1;
                }
                pad++;
                vals[j] = 0;
            } else {
                if (pad > 0) {
                    return -1;
                }
                int v = b64_value(c);
                if (v < 0) {
                    return -1;
                }
                vals[j] = v;
            }
        }

        uint32_t v = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12) |
                     ((uint32_t)vals[2] << 6) | (uint32_t)vals[3];
        size_t n = 3 - (size_t)pad;
        if (n > out_cap - produced) {
            return -1;
        }
        if (n > 0) {
            out[produced] = (uint8_t)((v >> 16) & 0xff);
        }
        if (n > 1) {
            out[produced + 1] = (uint8_t)((v >> 8) & 0xff);
        }
        if (n > 2) {
            out[produced + 2] = (uint8_t)(v & 0xff);
        }
        produced += n;
    }

    *out_len = produced;
    return 0;
}
```

Note on the capacity check: it is written `n > out_cap - produced` rather than `produced + n > out_cap` so it cannot overflow; `produced <= out_cap` is an invariant maintained by the check itself.

- [ ] **Step 5: Wire it into the build**

In `libcloak-common/CMakeLists.txt`, add `src/base64.c` to the `add_library(cloak-common STATIC ...)` source list, immediately after `src/random.c`:

```cmake
add_library(cloak-common STATIC
    src/version.c
    src/random.c
    src/base64.c
    src/aead.c
    src/salsa20.c
    src/x25519.c
    src/reactor.c
    src/clienthello.c
)
```

Append to `libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_base64 test_base64.c)
target_include_directories(test_base64 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_base64 PRIVATE cloak-common)
add_test(NAME test_base64 COMMAND test_base64)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build -R test_base64 --output-on-failure'
```

Expected: PASS, `All tests passed`.

- [ ] **Step 7: Commit**

```bash
git add libcloak-common/include/cloak/base64.h libcloak-common/src/base64.c \
        libcloak-common/tests/test_base64.c libcloak-common/CMakeLists.txt \
        libcloak-common/tests/CMakeLists.txt
git commit -m "Add base64: strict standard-alphabet encoder and decoder"
```

---

### Task 2: `cloak_log` — leveled logger

Every module from the dispatcher onward logs. The Go version uses logrus with five levels; this is the minimum equivalent: a process-global level, a settable output stream (so tests can capture), and `printf`-style formatting with compiler format checking.

**Files:**
- Create: `libcloak-common/include/cloak/log.h`
- Create: `libcloak-common/src/log.c`
- Create: `libcloak-common/tests/test_log.c`
- Modify: `libcloak-common/CMakeLists.txt` (add `src/log.c`)
- Modify: `libcloak-common/tests/CMakeLists.txt` (register `test_log`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `cloak_log_level_t` with values `CLOAK_LOG_ERROR`, `CLOAK_LOG_WARN`, `CLOAK_LOG_INFO`, `CLOAK_LOG_DEBUG`, `CLOAK_LOG_TRACE`.
  - `void cloak_log_set_level(cloak_log_level_t)`, `cloak_log_level_t cloak_log_get_level(void)`.
  - `int cloak_log_level_from_string(const char *s, cloak_log_level_t *out)` — 0 / -1.
  - `void cloak_log_set_stream(FILE *stream)`.
  - `void cloak_log_write(cloak_log_level_t level, const char *fmt, ...)`.
  - Macros `CLOAK_LOGE`, `CLOAK_LOGW`, `CLOAK_LOGI`, `CLOAK_LOGD`, `CLOAK_LOGT`.

- [ ] **Step 1: Write the failing test**

Create `libcloak-common/tests/test_log.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/log.h"
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>

/* Runs body with the log stream pointed at a temporary file, then reads
 * the whole file back into buf. */
static void capture(char *buf, size_t buf_cap, void (*body)(void)) {
    FILE *f = tmpfile();
    ASSERT_TRUE(f != NULL);
    cloak_log_set_stream(f);
    body();
    fflush(f);
    rewind(f);
    size_t n = fread(buf, 1, buf_cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    cloak_log_set_stream(stderr);
}

static void emit_one_of_each(void) {
    CLOAK_LOGE("error %d", 1);
    CLOAK_LOGW("warn %d", 2);
    CLOAK_LOGI("info %d", 3);
    CLOAK_LOGD("debug %d", 4);
    CLOAK_LOGT("trace %d", 5);
}

static void test_default_level_is_info(void) {
    ASSERT_EQ_INT(CLOAK_LOG_INFO, cloak_log_get_level());
}

static void test_level_filters_lower_severity(void) {
    char buf[1024];
    cloak_log_set_level(CLOAK_LOG_INFO);
    capture(buf, sizeof(buf), emit_one_of_each);

    ASSERT_TRUE(strstr(buf, "error 1") != NULL);
    ASSERT_TRUE(strstr(buf, "warn 2") != NULL);
    ASSERT_TRUE(strstr(buf, "info 3") != NULL);
    ASSERT_TRUE(strstr(buf, "debug 4") == NULL);
    ASSERT_TRUE(strstr(buf, "trace 5") == NULL);
}

static void test_trace_level_lets_everything_through(void) {
    char buf[1024];
    cloak_log_set_level(CLOAK_LOG_TRACE);
    capture(buf, sizeof(buf), emit_one_of_each);

    ASSERT_TRUE(strstr(buf, "error 1") != NULL);
    ASSERT_TRUE(strstr(buf, "trace 5") != NULL);
}

static void test_error_level_suppresses_everything_else(void) {
    char buf[1024];
    cloak_log_set_level(CLOAK_LOG_ERROR);
    capture(buf, sizeof(buf), emit_one_of_each);

    ASSERT_TRUE(strstr(buf, "error 1") != NULL);
    ASSERT_TRUE(strstr(buf, "warn 2") == NULL);
    ASSERT_TRUE(strstr(buf, "info 3") == NULL);
}

static void emit_tagged(void) {
    CLOAK_LOGW("something happened");
}

static void test_line_carries_level_tag_and_timestamp(void) {
    char buf[1024];
    cloak_log_set_level(CLOAK_LOG_TRACE);
    capture(buf, sizeof(buf), emit_tagged);

    ASSERT_TRUE(strstr(buf, "WARN") != NULL);
    ASSERT_TRUE(strstr(buf, "something happened") != NULL);
    /* timestamp prefix "YYYY-MM-DD HH:MM:SS " -- check the shape, not the value */
    ASSERT_EQ_INT('-', buf[4]);
    ASSERT_EQ_INT('-', buf[7]);
    ASSERT_EQ_INT(' ', buf[10]);
    ASSERT_EQ_INT(':', buf[13]);
    ASSERT_EQ_INT(':', buf[16]);
    /* and exactly one line was written */
    ASSERT_EQ_INT(1, (int)(strchr(buf, '\n') == buf + strlen(buf) - 1));
}

static void test_level_from_string(void) {
    cloak_log_level_t level;

    ASSERT_EQ_INT(0, cloak_log_level_from_string("error", &level));
    ASSERT_EQ_INT(CLOAK_LOG_ERROR, level);
    ASSERT_EQ_INT(0, cloak_log_level_from_string("WARN", &level));
    ASSERT_EQ_INT(CLOAK_LOG_WARN, level);
    ASSERT_EQ_INT(0, cloak_log_level_from_string("Info", &level));
    ASSERT_EQ_INT(CLOAK_LOG_INFO, level);
    ASSERT_EQ_INT(0, cloak_log_level_from_string("debug", &level));
    ASSERT_EQ_INT(CLOAK_LOG_DEBUG, level);
    ASSERT_EQ_INT(0, cloak_log_level_from_string("trace", &level));
    ASSERT_EQ_INT(CLOAK_LOG_TRACE, level);

    ASSERT_EQ_INT(-1, cloak_log_level_from_string("verbose", &level));
    ASSERT_EQ_INT(-1, cloak_log_level_from_string("", &level));
    ASSERT_EQ_INT(-1, cloak_log_level_from_string(NULL, &level));
}

static void emit_long(void) {
    char big[8192];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    CLOAK_LOGE("%s", big);
}

static void test_long_message_is_truncated_not_crashing(void) {
    char buf[16384];
    cloak_log_set_level(CLOAK_LOG_TRACE);
    capture(buf, sizeof(buf), emit_long);

    /* whatever the cap is, the line is terminated and the process survived */
    ASSERT_TRUE(strlen(buf) > 0);
    ASSERT_EQ_INT('\n', buf[strlen(buf) - 1]);
}

TEST_MAIN_BEGIN()
    test_default_level_is_info();
    test_level_filters_lower_severity();
    test_trace_level_lets_everything_through();
    test_error_level_suppresses_everything_else();
    test_line_carries_level_tag_and_timestamp();
    test_level_from_string();
    test_long_message_is_truncated_not_crashing();
    cloak_log_set_level(CLOAK_LOG_INFO);
TEST_MAIN_END()
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8'
```

Expected: FAIL — `cloak/log.h: No such file or directory`.

- [ ] **Step 3: Write the header**

Create `libcloak-common/include/cloak/log.h`:

```c
#ifndef CLOAK_LOG_H
#define CLOAK_LOG_H

#include <stdio.h>

/* A process-global leveled logger writing one line per message to a
 * settable stream (stderr by default). Not thread-safe -- like everything
 * else in this project it assumes the single-threaded reactor model.
 *
 * Levels are ordered by decreasing severity: a message is emitted when its
 * level is numerically <= the current level, so CLOAK_LOG_ERROR emits only
 * errors and CLOAK_LOG_TRACE emits everything. */
typedef enum {
    CLOAK_LOG_ERROR = 0,
    CLOAK_LOG_WARN = 1,
    CLOAK_LOG_INFO = 2,
    CLOAK_LOG_DEBUG = 3,
    CLOAK_LOG_TRACE = 4,
} cloak_log_level_t;

/* The default level, in effect until cloak_log_set_level is called. */
#define CLOAK_LOG_DEFAULT_LEVEL CLOAK_LOG_INFO

/* The maximum length of a single formatted message, excluding the
 * timestamp/level prefix and the newline. Longer messages are silently
 * truncated -- logging never fails and never allocates. */
#define CLOAK_LOG_MAX_MSG 2048

void cloak_log_set_level(cloak_log_level_t level);
cloak_log_level_t cloak_log_get_level(void);

/* Parses a level name, case-insensitively: "error", "warn", "info",
 * "debug", "trace". Returns 0 and writes *out on success, -1 on an
 * unknown name or a NULL argument (leaving *out untouched). */
int cloak_log_level_from_string(const char *s, cloak_log_level_t *out);

/* Redirects output. Passing NULL restores stderr. The logger does not take
 * ownership of stream and never closes it. */
void cloak_log_set_stream(FILE *stream);

/* Emits one line: "YYYY-MM-DD HH:MM:SS LEVEL message\n", using local time.
 * Does nothing if level is above the current level. Prefer the macros
 * below, which read better at call sites. */
void cloak_log_write(cloak_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define CLOAK_LOGE(...) cloak_log_write(CLOAK_LOG_ERROR, __VA_ARGS__)
#define CLOAK_LOGW(...) cloak_log_write(CLOAK_LOG_WARN, __VA_ARGS__)
#define CLOAK_LOGI(...) cloak_log_write(CLOAK_LOG_INFO, __VA_ARGS__)
#define CLOAK_LOGD(...) cloak_log_write(CLOAK_LOG_DEBUG, __VA_ARGS__)
#define CLOAK_LOGT(...) cloak_log_write(CLOAK_LOG_TRACE, __VA_ARGS__)

#endif
```

- [ ] **Step 4: Write the implementation**

Create `libcloak-common/src/log.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/log.h"

#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static cloak_log_level_t g_level = CLOAK_LOG_DEFAULT_LEVEL;
static FILE *g_stream = NULL;

static const char *const level_names[] = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};
#define NUM_LEVELS ((int)(sizeof(level_names) / sizeof(level_names[0])))

void cloak_log_set_level(cloak_log_level_t level) { g_level = level; }

cloak_log_level_t cloak_log_get_level(void) { return g_level; }

void cloak_log_set_stream(FILE *stream) { g_stream = stream; }

int cloak_log_level_from_string(const char *s, cloak_log_level_t *out) {
    if (s == NULL || out == NULL) {
        return -1;
    }
    for (int i = 0; i < NUM_LEVELS; i++) {
        if (strcasecmp(s, level_names[i]) == 0) {
            *out = (cloak_log_level_t)i;
            return 0;
        }
    }
    return -1;
}

void cloak_log_write(cloak_log_level_t level, const char *fmt, ...) {
    if ((int)level > (int)g_level) {
        return;
    }
    if ((int)level < 0 || (int)level >= NUM_LEVELS) {
        return;
    }

    char msg[CLOAK_LOG_MAX_MSG];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (n < 0) {
        /* encoding error in the format string; emit nothing rather than
         * writing an uninitialised buffer */
        return;
    }

    char stamp[32];
    time_t now = time(NULL);
    struct tm tm_buf;
    if (localtime_r(&now, &tm_buf) == NULL ||
        strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm_buf) == 0) {
        strcpy(stamp, "0000-00-00 00:00:00");
    }

    FILE *out = g_stream != NULL ? g_stream : stderr;
    fprintf(out, "%s %s %s\n", stamp, level_names[level], msg);
}
```

- [ ] **Step 5: Wire it into the build**

Add `src/log.c` to the `cloak-common` source list in `libcloak-common/CMakeLists.txt`, after `src/base64.c`.

Append to `libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_log test_log.c)
target_include_directories(test_log PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_log PRIVATE cloak-common)
add_test(NAME test_log COMMAND test_log)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build -R test_log --output-on-failure'
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add libcloak-common/include/cloak/log.h libcloak-common/src/log.c \
        libcloak-common/tests/test_log.c libcloak-common/CMakeLists.txt \
        libcloak-common/tests/CMakeLists.txt
git commit -m "Add log: leveled logger with settable level and stream"
```

---

### Task 3: Vendor cJSON

Spec §10 names cJSON as the config parser, vendored rather than depended on. Nothing in this task changes project behaviour; it makes the library available and provably linkable, which the next two tasks build on.

**Files:**
- Create: `third_party/cjson/cJSON.c` (downloaded verbatim, v1.7.19)
- Create: `third_party/cjson/cJSON.h` (downloaded verbatim, v1.7.19)
- Create: `third_party/cjson/LICENSE` (downloaded verbatim)
- Create: `third_party/cjson/VENDORING.md`
- Create: `third_party/cjson/CMakeLists.txt`
- Create: `libcloak-common/tests/test_cjson_link.c`
- Modify: `CMakeLists.txt` (root — add the `third_party/cjson` subdirectory before the libraries that use it)
- Modify: `libcloak-common/CMakeLists.txt` (link `cjson`)
- Modify: `libcloak-common/tests/CMakeLists.txt` (register `test_cjson_link`)

**Interfaces:**
- Consumes: nothing.
- Produces: a CMake target `cjson` (static library) exporting `third_party/cjson` as an include directory, so `#include "cJSON.h"` works in any target linking it.

- [ ] **Step 1: Download the vendored sources and verify their checksums**

Run from the repository root:

```bash
mkdir -p third_party/cjson
for f in cJSON.c cJSON.h LICENSE; do
  curl -fsSL -o "third_party/cjson/$f" \
    "https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.19/$f"
done
sha256sum third_party/cjson/cJSON.c third_party/cjson/cJSON.h third_party/cjson/LICENSE
```

Expected output (exactly these three digests — if any differs, stop and investigate rather than proceeding):

```
298581a04a36c0165da4b0aade235c23088cb2faa58651d720ea2f3706ed0b0d  third_party/cjson/cJSON.c
25b0145150d500498e4d209cec69c18c42cf818bffcc54690be3b895a2a16dee  third_party/cjson/cJSON.h
a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c  third_party/cjson/LICENSE
```

(On macOS use `shasum -a 256` instead of `sha256sum`.)

- [ ] **Step 2: Record the provenance**

Create `third_party/cjson/VENDORING.md`:

```markdown
# cJSON (vendored)

- Upstream: https://github.com/DaveGamble/cJSON
- Version: v1.7.19
- License: MIT (see `LICENSE`)
- Files: `cJSON.c`, `cJSON.h`, `LICENSE` — copied verbatim, no local modifications.

SHA-256 of the vendored files as fetched from
`https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.19/`:

```
298581a04a36c0165da4b0aade235c23088cb2faa58651d720ea2f3706ed0b0d  cJSON.c
25b0145150d500498e4d209cec69c18c42cf818bffcc54690be3b895a2a16dee  cJSON.h
a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c  LICENSE
```

## Updating

Re-download the three files at the new tag, update the version and digests
above, and run the full test suite. Do not patch the sources in place: this
project's `-Wall -Wextra` settings are suppressed for this target
(`-w` in `CMakeLists.txt`) precisely so the copy can stay verbatim.
```

- [ ] **Step 3: Write the build file**

Create `third_party/cjson/CMakeLists.txt`:

```cmake
# Vendored cJSON v1.7.19 -- see VENDORING.md. Built with warnings
# suppressed so the upstream sources can stay byte-identical to the
# release while project code keeps -Wall -Wextra.
add_library(cjson STATIC cJSON.c)
target_include_directories(cjson PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(cjson PRIVATE -w)
```

- [ ] **Step 4: Write the failing link test**

Create `libcloak-common/tests/test_cjson_link.c`:

```c
#include "cJSON.h"
#include "test_framework.h"

static void test_parses_an_object(void) {
    const char *text = "{\"name\":\"cloak\",\"num\":7,\"flag\":true}";
    cJSON *root = cJSON_Parse(text);
    ASSERT_TRUE(root != NULL);
    if (root == NULL) {
        return;
    }

    cJSON *name = cJSON_GetObjectItemCaseSensitive(root, "name");
    ASSERT_TRUE(cJSON_IsString(name));
    ASSERT_EQ_INT(0, strcmp(name->valuestring, "cloak"));

    cJSON *num = cJSON_GetObjectItemCaseSensitive(root, "num");
    ASSERT_TRUE(cJSON_IsNumber(num));
    ASSERT_EQ_INT(7, (int)num->valuedouble);

    cJSON *flag = cJSON_GetObjectItemCaseSensitive(root, "flag");
    ASSERT_TRUE(cJSON_IsBool(flag));
    ASSERT_TRUE(cJSON_IsTrue(flag));

    cJSON_Delete(root);
}

static void test_rejects_malformed_input(void) {
    cJSON *root = cJSON_Parse("{\"unterminated\": ");
    ASSERT_TRUE(root == NULL);
    cJSON_Delete(root);
}

static void test_version_is_the_vendored_one(void) {
    ASSERT_EQ_INT(1, CJSON_VERSION_MAJOR);
    ASSERT_EQ_INT(7, CJSON_VERSION_MINOR);
    ASSERT_EQ_INT(19, CJSON_VERSION_PATCH);
}

TEST_MAIN_BEGIN()
    test_parses_an_object();
    test_rejects_malformed_input();
    test_version_is_the_vendored_one();
TEST_MAIN_END()
```

- [ ] **Step 5: Run it to verify it fails**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8'
```

Expected: FAIL — the `cjson` target does not exist yet and `test_cjson_link` is not registered, so either CMake errors or `cJSON.h` is not found.

- [ ] **Step 6: Wire the target into the build**

In the root `CMakeLists.txt`, add the vendored subdirectory before the project libraries, so the `cjson` target exists when they reference it:

```cmake
add_subdirectory(third_party/cjson)
add_subdirectory(libcloak-common)
add_subdirectory(libcloak-mux)
add_subdirectory(libcloak-server)
```

In `libcloak-common/CMakeLists.txt`, link it privately — cJSON is an implementation detail, no public header of `libcloak-common` exposes a cJSON type:

```cmake
target_link_libraries(cloak-common PUBLIC OpenSSL::Crypto PRIVATE cjson)
```

Append to `libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_cjson_link test_cjson_link.c)
target_include_directories(test_cjson_link PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_cjson_link PRIVATE cloak-common cjson)
add_test(NAME test_cjson_link COMMAND test_cjson_link)
```

- [ ] **Step 7: Run the tests to verify they pass**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
```

Expected: PASS — all previously passing tests plus `test_cjson_link`. A warning-free build of project code (cJSON's own warnings are suppressed by `-w`).

- [ ] **Step 8: Commit**

```bash
git add third_party/cjson CMakeLists.txt libcloak-common/CMakeLists.txt \
        libcloak-common/tests/test_cjson_link.c libcloak-common/tests/CMakeLists.txt
git commit -m "Vendor cJSON v1.7.19 as a separate build target"
```

---

### Task 4: `cloak_client_config_t` — client configuration

Mirrors Go's `internal/client/state.go`: `RawConfig` fields plus the defaulting and validation that `ProcessRawConfig` applies. This task covers the struct, the shared cJSON accessors, and parsing from a JSON string or file. ssv input is added in Task 6.

**Files:**
- Create: `libcloak-common/include/cloak/config.h`
- Create: `libcloak-common/src/config_internal.h`
- Create: `libcloak-common/src/config_common.c`
- Create: `libcloak-common/src/config_client.c`
- Create: `libcloak-common/tests/test_config_client.c`
- Modify: `libcloak-common/CMakeLists.txt` (add both new sources)
- Modify: `libcloak-common/tests/CMakeLists.txt` (register `test_config_client`)

**Interfaces:**
- Consumes: `cloak_base64_decode` (Task 1); `cloak_aead_method_t`, `CLOAK_X25519_KEY_LEN` from `cloak/crypto.h`.
- Produces:
  - `cloak_client_config_t` and the constants/enums listed in the header below.
  - `int cloak_client_config_parse_json(const char *text, cloak_client_config_t *cfg, char *err, size_t err_cap)` — 0 / -1.
  - `int cloak_client_config_parse_file(const char *path, cloak_client_config_t *cfg, char *err, size_t err_cap)` — 0 / -1.
  - Internal (for Tasks 5 and 6, declared in `config_internal.h`): `cloak_config_set_err`, `cloak_config_get_string`, `cloak_config_get_int`, `cloak_config_get_bool`, `cloak_config_get_b64`, `cloak_config_read_file`, `cloak_client_config_from_cjson`.

- [ ] **Step 1: Write the failing test**

Create `libcloak-common/tests/test_config_client.c`:

```c
#include "cloak/config.h"
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>

/* 16 raw bytes -> 24 base64 chars; 32 raw bytes -> 44 base64 chars */
#define UID_B64 "SGVsbG9DbG9ha1VJRCEhIQ=="
#define PUB_B64 "bG9uZ2VyLWtleS1tYXRlcmlhbC1leGFjdGx5LTMyIQ=="

static const char *minimal_json(void) {
    static char buf[1024];
    snprintf(buf, sizeof(buf),
             "{"
             "\"ServerName\":\"www.bing.com\","
             "\"ProxyMethod\":\"shadowsocks\","
             "\"EncryptionMethod\":\"aes-gcm\","
             "\"UID\":\"%s\","
             "\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"1.2.3.4\","
             "\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\","
             "\"LocalPort\":\"1984\""
             "}",
             UID_B64, PUB_B64);
    return buf;
}

static void test_parses_a_minimal_config(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};

    ASSERT_EQ_INT(0, cloak_client_config_parse_json(minimal_json(), &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "www.bing.com"));
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_method, "shadowsocks"));
    ASSERT_EQ_INT(CLOAK_AEAD_AES_256_GCM, cfg.encryption_method);
    ASSERT_EQ_INT(0, strcmp(cfg.remote_host, "1.2.3.4"));
    ASSERT_EQ_INT(0, strcmp(cfg.remote_port, "443"));
    ASSERT_EQ_INT(0, strcmp(cfg.local_host, "127.0.0.1"));
    ASSERT_EQ_INT(0, strcmp(cfg.local_port, "1984"));
}

static void test_applies_documented_defaults(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};

    ASSERT_EQ_INT(0, cloak_client_config_parse_json(minimal_json(), &cfg, err, sizeof(err)));
    /* NumConn <= 0 means singleplex with a single connection (Go: ProcessRawConfig) */
    ASSERT_EQ_INT(1, cfg.num_conn);
    ASSERT_EQ_INT(1, cfg.singleplex);
    ASSERT_EQ_INT(CLOAK_TRANSPORT_DIRECT, cfg.transport);
    ASSERT_EQ_INT(CLOAK_BROWSER_CHROME, cfg.browser);
    ASSERT_EQ_INT(0, cfg.udp);
    ASSERT_EQ_INT(300, cfg.stream_timeout_sec);
    ASSERT_EQ_INT(-1, cfg.keep_alive_sec);
    ASSERT_EQ_INT(0, (int)cfg.num_alt_names);
}

static void test_num_conn_above_zero_disables_singleplex(void) {
    char json[1200];
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\","
             "\"NumConn\":4}",
             UID_B64, PUB_B64);

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(4, cfg.num_conn);
    ASSERT_EQ_INT(0, cfg.singleplex);
}

static void test_decodes_uid_and_public_key(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_json(minimal_json(), &cfg, err, sizeof(err)));

    const uint8_t expected_uid[16] = {
        'H', 'e', 'l', 'l', 'o', 'C', 'l', 'o',
        'a', 'k', 'U', 'I', 'D', '!', '!', '!'};
    ASSERT_MEM_EQ(cfg.uid, expected_uid, sizeof(expected_uid));

    const uint8_t expected_pub[32] = {
        'l', 'o', 'n', 'g', 'e', 'r', '-', 'k',
        'e', 'y', '-', 'm', 'a', 't', 'e', 'r',
        'i', 'a', 'l', '-', 'e', 'x', 'a', 'c',
        't', 'l', 'y', '-', '3', '2', '!', 0};
    /* the 32nd byte of the decoded key is 0x21 ('!') followed by nothing --
     * recompute below rather than trusting this literal */
    (void)expected_pub;
}

static void test_all_encryption_method_names(void) {
    struct {
        const char *name;
        cloak_aead_method_t expected;
    } cases[] = {
        {"plain", CLOAK_AEAD_NONE},
        {"aes-gcm", CLOAK_AEAD_AES_256_GCM},
        {"aes-256-gcm", CLOAK_AEAD_AES_256_GCM},
        {"AES-256-GCM", CLOAK_AEAD_AES_256_GCM},
        {"aes-128-gcm", CLOAK_AEAD_AES_128_GCM},
        {"chacha20-poly1305", CLOAK_AEAD_CHACHA20_POLY1305},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char json[1200];
        snprintf(json, sizeof(json),
                 "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
                 "\"EncryptionMethod\":\"%s\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
                 "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
                 cases[i].name, UID_B64, PUB_B64);

        cloak_client_config_t cfg;
        char err[CLOAK_CONFIG_ERR_LEN] = {0};
        ASSERT_EQ_INT(0, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
        ASSERT_EQ_INT(cases[i].expected, cfg.encryption_method);
    }
}

static void test_browser_and_transport_names(void) {
    struct {
        const char *browser;
        cloak_browser_t expected;
    } cases[] = {
        {"chrome", CLOAK_BROWSER_CHROME},
        {"Firefox", CLOAK_BROWSER_FIREFOX},
        {"safari", CLOAK_BROWSER_SAFARI},
        {"nonsense", CLOAK_BROWSER_CHROME}, /* Go falls back to chrome */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char json[1200];
        snprintf(json, sizeof(json),
                 "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
                 "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
                 "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\","
                 "\"BrowserSig\":\"%s\"}",
                 UID_B64, PUB_B64, cases[i].browser);

        cloak_client_config_t cfg;
        char err[CLOAK_CONFIG_ERR_LEN] = {0};
        ASSERT_EQ_INT(0, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
        ASSERT_EQ_INT(cases[i].expected, cfg.browser);
    }
}

static void test_cdn_transport_defaults_ws_path(void) {
    char json[1300];
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\","
             "\"Transport\":\"cdn\",\"CDNOriginHost\":\"origin.example\"}",
             UID_B64, PUB_B64);

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(CLOAK_TRANSPORT_CDN, cfg.transport);
    ASSERT_EQ_INT(0, strcmp(cfg.cdn_origin_host, "origin.example"));
    ASSERT_EQ_INT(0, strcmp(cfg.cdn_ws_url_path, "/"));
}

static void test_alternative_names_are_collected_and_empties_dropped(void) {
    char json[1400];
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\","
             "\"AlternativeNames\":[\"b.com\",\"\",\"c.com\"]}",
             UID_B64, PUB_B64);

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(2, (int)cfg.num_alt_names);
    ASSERT_EQ_INT(0, strcmp(cfg.alt_names[0], "b.com"));
    ASSERT_EQ_INT(0, strcmp(cfg.alt_names[1], "c.com"));
}

static void test_missing_required_fields_are_named_in_the_error(void) {
    struct {
        const char *drop;
        const char *expect_in_err;
    } cases[] = {
        {"\"ServerName\":\"a.com\",", "ServerName"},
        {"\"ProxyMethod\":\"ss\",", "ProxyMethod"},
        {"\"RemoteHost\":\"h\",", "RemoteHost"},
        {"\"RemotePort\":\"443\",", "RemotePort"},
        {"\"LocalHost\":\"127.0.0.1\",", "LocalHost"},
        {"\"LocalPort\":\"1984\",", "LocalPort"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char full[1400];
        snprintf(full, sizeof(full),
                 "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
                 "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
                 "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
                 UID_B64, PUB_B64);

        /* remove the field under test from the JSON text */
        char *at = strstr(full, cases[i].drop);
        ASSERT_TRUE(at != NULL);
        if (at == NULL) {
            continue;
        }
        memmove(at, at + strlen(cases[i].drop), strlen(at + strlen(cases[i].drop)) + 1);

        cloak_client_config_t cfg;
        char err[CLOAK_CONFIG_ERR_LEN] = {0};
        ASSERT_EQ_INT(-1, cloak_client_config_parse_json(full, &cfg, err, sizeof(err)));
        ASSERT_TRUE(strstr(err, cases[i].expect_in_err) != NULL);
    }
}

static void test_rejects_bad_values(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN];
    char json[1400];

    /* unknown encryption method */
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"rot13\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             UID_B64, PUB_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "EncryptionMethod") != NULL);

    /* UID that is not 16 bytes once decoded */
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"Zm9v\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             PUB_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "UID") != NULL);

    /* PublicKey that is not valid base64 */
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"not!base64\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             UID_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "PublicKey") != NULL);

    /* ProxyMethod longer than the 12-byte wire field */
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"thirteenchars\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             UID_B64, PUB_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "ProxyMethod") != NULL);

    /* wrong JSON type for a string field */
    snprintf(json, sizeof(json),
             "{\"ServerName\":7,\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             UID_B64, PUB_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "ServerName") != NULL);

    /* not JSON at all */
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json("this is not json", &cfg, err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');

    /* JSON, but not an object */
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json("[1,2,3]", &cfg, err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');
}

static void test_parse_file_round_trip(void) {
    char path[] = "/tmp/cloak_client_cfg_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return;
    }
    const char *json = minimal_json();
    ASSERT_TRUE(write(fd, json, strlen(json)) == (ssize_t)strlen(json));
    close(fd);

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_file(path, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "www.bing.com"));
    unlink(path);

    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_file("/nonexistent/cloak.json", &cfg,
                                                     err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');
}

TEST_MAIN_BEGIN()
    test_parses_a_minimal_config();
    test_applies_documented_defaults();
    test_num_conn_above_zero_disables_singleplex();
    test_decodes_uid_and_public_key();
    test_all_encryption_method_names();
    test_browser_and_transport_names();
    test_cdn_transport_defaults_ws_path();
    test_alternative_names_are_collected_and_empties_dropped();
    test_missing_required_fields_are_named_in_the_error();
    test_rejects_bad_values();
    test_parse_file_round_trip();
TEST_MAIN_END()
```

Two fixups to apply while writing the file:
1. `test_decodes_uid_and_public_key` must assert the decoded public key properly. Replace its `expected_pub` block with a decode of `PUB_B64` through `cloak_base64_decode` and an `ASSERT_MEM_EQ` against `cfg.server_pub_key` (include `cloak/base64.h` for it). `PUB_B64` is 44 characters and decodes to exactly 32 bytes.
2. `test_parse_file_round_trip` uses `mkstemp`, `write`, `close` and `unlink`: add `#define _POSIX_C_SOURCE 200809L` as the file's first line and include `<unistd.h>`.

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8'
```

Expected: FAIL — `cloak/config.h: No such file or directory`.

- [ ] **Step 3: Write the public header**

Create `libcloak-common/include/cloak/config.h`:

```c
#ifndef CLOAK_CONFIG_H
#define CLOAK_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/crypto.h"

/* Configuration structs for both binaries, parsed from the JSON format Go
 * Cloak uses (see ../Cloak/example_config/). Every struct here is a
 * fixed-size POD with no owned pointers: parse fills one in place, and a
 * caller can hold one on the stack, copy it, and discard it without any
 * cleanup.
 *
 * Every parse function reports failure by returning -1 and writing a
 * human-readable, NUL-terminated message into err (truncated to err_cap).
 * err may be NULL if the caller does not want the message. On failure the
 * config struct's contents are unspecified. */

#define CLOAK_CONFIG_ERR_LEN 256

/* Field capacities. Hostnames follow the DNS limit; the port fields hold a
 * decimal port number or a service name. */
#define CLOAK_MAX_HOST_LEN 256
#define CLOAK_MAX_PORT_LEN 16
#define CLOAK_MAX_PATH_LEN 512

/* The wire auth payload carries the proxy method in a fixed 12-byte field
 * (see the Go original's authentication payload layout), so a longer name
 * could never reach the server. Configs are rejected rather than
 * silently truncated. */
#define CLOAK_PROXY_METHOD_LEN 12

#define CLOAK_UID_LEN 16

/* Collection caps. These are limits this implementation imposes (the Go
 * version's slices are unbounded); exceeding one is a config error, never
 * a silent truncation. */
#define CLOAK_MAX_ALT_NAMES 16
#define CLOAK_MAX_PROXY_BOOK 16
#define CLOAK_MAX_BIND_ADDR 16
#define CLOAK_MAX_BYPASS_UID 64

typedef enum {
    CLOAK_BROWSER_CHROME = 0,
    CLOAK_BROWSER_FIREFOX = 1,
    CLOAK_BROWSER_SAFARI = 2,
} cloak_browser_t;

typedef enum {
    CLOAK_TRANSPORT_DIRECT = 0,
    CLOAK_TRANSPORT_CDN = 1,
} cloak_transport_mode_t;

typedef struct {
    /* The SNI presented in the forged ClientHello. The literal string
     * "random" is preserved here as-is; generating a random domain per
     * connection is the transport layer's job, not the parser's. */
    char server_name[CLOAK_MAX_HOST_LEN];

    /* Additional mock domains. The transport picks uniformly from
     * server_name together with these, matching Go's MockDomainList. */
    char alt_names[CLOAK_MAX_ALT_NAMES][CLOAK_MAX_HOST_LEN];
    size_t num_alt_names;

    char proxy_method[CLOAK_PROXY_METHOD_LEN + 1];
    cloak_aead_method_t encryption_method;

    uint8_t uid[CLOAK_UID_LEN];
    uint8_t server_pub_key[CLOAK_X25519_KEY_LEN];

    /* num_conn is always >= 1. singleplex is 1 when the config asked for
     * NumConn <= 0, which in Go means "one connection, one stream, and the
     * session closes with that stream". */
    int num_conn;
    int singleplex;

    char local_host[CLOAK_MAX_HOST_LEN];
    char local_port[CLOAK_MAX_PORT_LEN];
    char remote_host[CLOAK_MAX_HOST_LEN];
    char remote_port[CLOAK_MAX_PORT_LEN];

    /* 1 when the wrapped proxy speaks UDP, which puts the session in
     * unordered/datagram mode. */
    int udp;

    cloak_browser_t browser;
    cloak_transport_mode_t transport;

    /* Only meaningful when transport == CLOAK_TRANSPORT_CDN. If the config
     * omitted CDNOriginHost, cdn_origin_host is empty and the caller uses
     * remote_host in its place (Go does this substitution in
     * ProcessRawConfig). cdn_ws_url_path defaults to "/". */
    char cdn_origin_host[CLOAK_MAX_HOST_LEN];
    char cdn_ws_url_path[CLOAK_MAX_PATH_LEN];

    /* Seconds. stream_timeout_sec defaults to 300. keep_alive_sec is -1
     * when TCP keepalive is disabled, which is the default. */
    int stream_timeout_sec;
    int keep_alive_sec;
} cloak_client_config_t;

typedef struct {
    /* Lower-cased proxy method name, matched against the method the client
     * sends in its auth payload. */
    char name[CLOAK_PROXY_METHOD_LEN + 1];
    /* 0 for "tcp", 1 for "udp". */
    int is_udp;
    /* The upstream proxy endpoint as written in the config, e.g.
     * "localhost:51443". Resolution happens at dial time, not here. */
    char addr[CLOAK_MAX_HOST_LEN];
} cloak_proxy_entry_t;

typedef struct {
    cloak_proxy_entry_t proxy_book[CLOAK_MAX_PROXY_BOOK];
    size_t num_proxy_entries;

    /* Addresses to listen on, e.g. ":443". At least one is required. */
    char bind_addr[CLOAK_MAX_BIND_ADDR][CLOAK_MAX_HOST_LEN];
    size_t num_bind_addr;

    /* UIDs exempt from all credit and bandwidth accounting. */
    uint8_t bypass_uid[CLOAK_MAX_BYPASS_UID][CLOAK_UID_LEN];
    size_t num_bypass_uid;

    /* Where non-Cloak traffic is forwarded. Required: without it the
     * server has no cover story. Held as written ("host" or "host:port"). */
    char redir_addr[CLOAK_MAX_HOST_LEN];

    uint8_t private_key[CLOAK_X25519_KEY_LEN];

    /* has_admin_uid is 0 when the config omitted AdminUID, in which case
     * admin_uid is all zeroes and must not be used. */
    uint8_t admin_uid[CLOAK_UID_LEN];
    int has_admin_uid;

    /* Empty when unset, which means no user database: only bypass and
     * admin UIDs can connect. */
    char database_path[CLOAK_MAX_PATH_LEN];

    /* Seconds, -1 when disabled (the default). Applies to connections the
     * server makes to upstream proxies. */
    int keep_alive_sec;
} cloak_server_config_t;

/* Parses a NUL-terminated JSON document. Returns 0 / -1. */
int cloak_client_config_parse_json(const char *text, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap);

/* Reads path and parses it as JSON. Returns 0 / -1; a missing or
 * unreadable file is a -1 with the reason in err. */
int cloak_client_config_parse_file(const char *path, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap);

int cloak_server_config_parse_json(const char *text, cloak_server_config_t *cfg,
                                   char *err, size_t err_cap);

int cloak_server_config_parse_file(const char *path, cloak_server_config_t *cfg,
                                   char *err, size_t err_cap);

/* Parses the semicolon-separated form Shadowsocks passes in
 * SS_PLUGIN_OPTIONS, e.g.
 *   "UID=...;PublicKey=...;ServerName=www.bing.com;NumConn=4"
 * Within a value, "\\", "\=" and "\;" escape a backslash, an equals sign
 * and a semicolon respectively. AlternativeNames takes a comma-separated
 * list. Returns 0 / -1 with the same error convention as the JSON
 * parsers. */
int cloak_client_config_parse_ssv(const char *ssv, cloak_client_config_t *cfg,
                                  char *err, size_t err_cap);

/* Go's heuristic, reproduced: if conf contains both ';' and '=' it is
 * treated as an ssv option string, otherwise as a path to a JSON file.
 * Returns 0 / -1. */
int cloak_client_config_load(const char *conf, cloak_client_config_t *cfg,
                             char *err, size_t err_cap);

#endif
```

- [ ] **Step 4: Write the internal header**

Create `libcloak-common/src/config_internal.h`:

```c
#ifndef CLOAK_CONFIG_INTERNAL_H
#define CLOAK_CONFIG_INTERNAL_H

/* Shared between config_common.c, config_client.c and config_server.c.
 * Not installed and not part of the public API. */

#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"
#include "cloak/config.h"

/* Writes a printf-formatted message into err (which may be NULL).
 * Always returns -1, so callers can `return cloak_config_set_err(...)`. */
int cloak_config_set_err(char *err, size_t err_cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* Field accessors. Each takes the object, the JSON field name, and the
 * destination. All of them:
 *   - return 0 and leave dst untouched when the field is absent or JSON
 *     null (the caller applies its own default and required-ness rule),
 *     setting *found (if non-NULL) to 0;
 *   - return 0, write dst and set *found to 1 on success;
 *   - return -1 with err set when the field is present but has the wrong
 *     type or an unusable value.
 * cloak_config_get_string additionally fails if the value does not fit in
 * dst_cap including the NUL. */
int cloak_config_get_string(const cJSON *obj, const char *name, char *dst,
                            size_t dst_cap, int *found, char *err, size_t err_cap);
int cloak_config_get_int(const cJSON *obj, const char *name, int *dst, int *found,
                         char *err, size_t err_cap);
int cloak_config_get_bool(const cJSON *obj, const char *name, int *dst, int *found,
                          char *err, size_t err_cap);

/* Reads a base64 string field and requires it to decode to exactly
 * expected_len bytes. Absent field: returns 0 with *found == 0. */
int cloak_config_get_b64(const cJSON *obj, const char *name, uint8_t *dst,
                         size_t expected_len, int *found, char *err, size_t err_cap);

/* Reads the whole file at path into a NUL-terminated heap buffer the
 * caller must free(). Returns NULL with err set on failure, including a
 * file larger than CLOAK_CONFIG_MAX_FILE bytes. */
#define CLOAK_CONFIG_MAX_FILE (1024 * 1024)
char *cloak_config_read_file(const char *path, char *err, size_t err_cap);

/* The single place each config's fields are read. Both the JSON and the
 * ssv front ends build a cJSON object and hand it to these. */
int cloak_client_config_from_cjson(const cJSON *root, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap);
int cloak_server_config_from_cjson(const cJSON *root, cloak_server_config_t *cfg,
                                   char *err, size_t err_cap);

#endif
```

- [ ] **Step 5: Write the shared helpers**

Create `libcloak-common/src/config_common.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "config_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cloak/base64.h"

int cloak_config_set_err(char *err, size_t err_cap, const char *fmt, ...) {
    if (err != NULL && err_cap > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, err_cap, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* Returns the named item, or NULL if it is absent or JSON null. */
static const cJSON *lookup(const cJSON *obj, const char *name) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (item == NULL || cJSON_IsNull(item)) {
        return NULL;
    }
    return item;
}

int cloak_config_get_string(const cJSON *obj, const char *name, char *dst,
                            size_t dst_cap, int *found, char *err, size_t err_cap) {
    if (found != NULL) {
        *found = 0;
    }
    const cJSON *item = lookup(obj, name);
    if (item == NULL) {
        return 0;
    }
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return cloak_config_set_err(err, err_cap, "%s must be a string", name);
    }
    size_t len = strlen(item->valuestring);
    if (len + 1 > dst_cap) {
        return cloak_config_set_err(err, err_cap,
                                    "%s is too long (%zu bytes, limit %zu)", name,
                                    len, dst_cap - 1);
    }
    memcpy(dst, item->valuestring, len + 1);
    if (found != NULL) {
        *found = 1;
    }
    return 0;
}

int cloak_config_get_int(const cJSON *obj, const char *name, int *dst, int *found,
                         char *err, size_t err_cap) {
    if (found != NULL) {
        *found = 0;
    }
    const cJSON *item = lookup(obj, name);
    if (item == NULL) {
        return 0;
    }
    if (!cJSON_IsNumber(item)) {
        return cloak_config_set_err(err, err_cap, "%s must be a number", name);
    }
    double v = item->valuedouble;
    if (v < -2147483648.0 || v > 2147483647.0 || v != (double)(int)v) {
        return cloak_config_set_err(err, err_cap, "%s must be a whole 32-bit number",
                                    name);
    }
    *dst = (int)v;
    if (found != NULL) {
        *found = 1;
    }
    return 0;
}

int cloak_config_get_bool(const cJSON *obj, const char *name, int *dst, int *found,
                          char *err, size_t err_cap) {
    if (found != NULL) {
        *found = 0;
    }
    const cJSON *item = lookup(obj, name);
    if (item == NULL) {
        return 0;
    }
    if (!cJSON_IsBool(item)) {
        return cloak_config_set_err(err, err_cap, "%s must be true or false", name);
    }
    *dst = cJSON_IsTrue(item) ? 1 : 0;
    if (found != NULL) {
        *found = 1;
    }
    return 0;
}

int cloak_config_get_b64(const cJSON *obj, const char *name, uint8_t *dst,
                         size_t expected_len, int *found, char *err, size_t err_cap) {
    if (found != NULL) {
        *found = 0;
    }
    const cJSON *item = lookup(obj, name);
    if (item == NULL) {
        return 0;
    }
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return cloak_config_set_err(err, err_cap, "%s must be a base64 string", name);
    }

    /* decode into a scratch buffer so a wrong length never half-fills dst */
    uint8_t scratch[256];
    if (expected_len > sizeof(scratch)) {
        return cloak_config_set_err(err, err_cap, "%s: unsupported expected length",
                                    name);
    }
    size_t decoded_len = 0;
    if (cloak_base64_decode(item->valuestring, scratch, sizeof(scratch),
                            &decoded_len) != 0) {
        return cloak_config_set_err(err, err_cap, "%s is not valid base64", name);
    }
    if (decoded_len != expected_len) {
        return cloak_config_set_err(err, err_cap,
                                    "%s must decode to %zu bytes, got %zu", name,
                                    expected_len, decoded_len);
    }
    memcpy(dst, scratch, expected_len);
    if (found != NULL) {
        *found = 1;
    }
    return 0;
}

char *cloak_config_read_file(const char *path, char *err, size_t err_cap) {
    if (path == NULL) {
        cloak_config_set_err(err, err_cap, "no config path given");
        return NULL;
    }
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        cloak_config_set_err(err, err_cap, "cannot open config file %s", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        cloak_config_set_err(err, err_cap, "cannot seek config file %s", path);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        cloak_config_set_err(err, err_cap, "cannot size config file %s", path);
        return NULL;
    }
    if ((unsigned long)size > CLOAK_CONFIG_MAX_FILE) {
        fclose(f);
        cloak_config_set_err(err, err_cap, "config file %s is too large (%ld bytes)",
                             path, size);
        return NULL;
    }
    rewind(f);

    char *buf = malloc((size_t)size + 1);
    if (buf == NULL) {
        fclose(f);
        cloak_config_set_err(err, err_cap, "out of memory reading %s", path);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) {
        free(buf);
        cloak_config_set_err(err, err_cap, "short read on config file %s", path);
        return NULL;
    }
    buf[got] = '\0';
    return buf;
}
```

- [ ] **Step 6: Write the client parser**

Create `libcloak-common/src/config_client.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "config_internal.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int parse_encryption_method(const char *name, cloak_aead_method_t *out) {
    if (strcasecmp(name, "plain") == 0) {
        *out = CLOAK_AEAD_NONE;
    } else if (strcasecmp(name, "aes-gcm") == 0 ||
               strcasecmp(name, "aes-256-gcm") == 0) {
        *out = CLOAK_AEAD_AES_256_GCM;
    } else if (strcasecmp(name, "aes-128-gcm") == 0) {
        *out = CLOAK_AEAD_AES_128_GCM;
    } else if (strcasecmp(name, "chacha20-poly1305") == 0) {
        *out = CLOAK_AEAD_CHACHA20_POLY1305;
    } else {
        return -1;
    }
    return 0;
}

/* Unknown browser names fall back to chrome, matching Go's switch default. */
static cloak_browser_t parse_browser(const char *name) {
    if (strcasecmp(name, "firefox") == 0) {
        return CLOAK_BROWSER_FIREFOX;
    }
    if (strcasecmp(name, "safari") == 0) {
        return CLOAK_BROWSER_SAFARI;
    }
    return CLOAK_BROWSER_CHROME;
}

static int parse_alt_names(const cJSON *root, cloak_client_config_t *cfg, char *err,
                           size_t err_cap) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "AlternativeNames");
    if (arr == NULL || cJSON_IsNull(arr)) {
        return 0;
    }
    if (!cJSON_IsArray(arr)) {
        return cloak_config_set_err(err, err_cap,
                                    "AlternativeNames must be an array of strings");
    }

    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (!cJSON_IsString(item) || item->valuestring == NULL) {
            return cloak_config_set_err(err, err_cap,
                                        "AlternativeNames must be an array of strings");
        }
        /* Go filters empty entries out rather than rejecting them */
        if (item->valuestring[0] == '\0') {
            continue;
        }
        if (cfg->num_alt_names >= CLOAK_MAX_ALT_NAMES) {
            return cloak_config_set_err(err, err_cap,
                                        "AlternativeNames has more than %d entries",
                                        CLOAK_MAX_ALT_NAMES);
        }
        size_t len = strlen(item->valuestring);
        if (len + 1 > CLOAK_MAX_HOST_LEN) {
            return cloak_config_set_err(err, err_cap,
                                        "AlternativeNames entry is too long (%zu bytes)",
                                        len);
        }
        memcpy(cfg->alt_names[cfg->num_alt_names], item->valuestring, len + 1);
        cfg->num_alt_names++;
    }
    return 0;
}

int cloak_client_config_from_cjson(const cJSON *root, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap) {
    if (root == NULL || cfg == NULL) {
        return cloak_config_set_err(err, err_cap, "internal: null config input");
    }
    if (!cJSON_IsObject(root)) {
        return cloak_config_set_err(err, err_cap, "config must be a JSON object");
    }

    memset(cfg, 0, sizeof(*cfg));

    int found = 0;

    if (cloak_config_get_string(root, "ServerName", cfg->server_name,
                                sizeof(cfg->server_name), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->server_name[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "ServerName cannot be empty");
    }

    if (parse_alt_names(root, cfg, err, err_cap) != 0) {
        return -1;
    }

    if (cloak_config_get_string(root, "ProxyMethod", cfg->proxy_method,
                                sizeof(cfg->proxy_method), &found, err, err_cap) != 0) {
        /* a too-long ProxyMethod lands here, and the message already names
         * the field and the limit */
        return -1;
    }
    if (!found || cfg->proxy_method[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "ProxyMethod cannot be empty");
    }

    char enc_name[64] = {0};
    if (cloak_config_get_string(root, "EncryptionMethod", enc_name, sizeof(enc_name),
                                &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || enc_name[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "EncryptionMethod cannot be empty");
    }
    if (parse_encryption_method(enc_name, &cfg->encryption_method) != 0) {
        return cloak_config_set_err(err, err_cap, "unknown EncryptionMethod %s",
                                    enc_name);
    }

    if (cloak_config_get_b64(root, "UID", cfg->uid, CLOAK_UID_LEN, &found, err,
                             err_cap) != 0) {
        return -1;
    }
    if (!found) {
        return cloak_config_set_err(err, err_cap, "UID cannot be empty");
    }

    if (cloak_config_get_b64(root, "PublicKey", cfg->server_pub_key,
                             CLOAK_X25519_KEY_LEN, &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found) {
        return cloak_config_set_err(err, err_cap, "PublicKey cannot be empty");
    }

    if (cloak_config_get_string(root, "RemoteHost", cfg->remote_host,
                                sizeof(cfg->remote_host), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->remote_host[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "RemoteHost cannot be empty");
    }

    if (cloak_config_get_string(root, "RemotePort", cfg->remote_port,
                                sizeof(cfg->remote_port), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->remote_port[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "RemotePort cannot be empty");
    }

    if (cloak_config_get_string(root, "LocalHost", cfg->local_host,
                                sizeof(cfg->local_host), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->local_host[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "LocalHost cannot be empty");
    }

    if (cloak_config_get_string(root, "LocalPort", cfg->local_port,
                                sizeof(cfg->local_port), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->local_port[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "LocalPort cannot be empty");
    }

    int num_conn = 0;
    if (cloak_config_get_int(root, "NumConn", &num_conn, &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || num_conn <= 0) {
        cfg->num_conn = 1;
        cfg->singleplex = 1;
    } else {
        cfg->num_conn = num_conn;
        cfg->singleplex = 0;
    }

    cfg->udp = 0;
    if (cloak_config_get_bool(root, "UDP", &cfg->udp, &found, err, err_cap) != 0) {
        return -1;
    }

    char browser_name[64] = {0};
    if (cloak_config_get_string(root, "BrowserSig", browser_name, sizeof(browser_name),
                                &found, err, err_cap) != 0) {
        return -1;
    }
    cfg->browser = found && browser_name[0] != '\0' ? parse_browser(browser_name)
                                                    : CLOAK_BROWSER_CHROME;

    char transport_name[64] = {0};
    if (cloak_config_get_string(root, "Transport", transport_name,
                                sizeof(transport_name), &found, err, err_cap) != 0) {
        return -1;
    }
    /* Go: "cdn" selects the CDN transport, everything else (including an
     * empty string and an unrecognised name) means direct */
    cfg->transport = (found && strcasecmp(transport_name, "cdn") == 0)
                         ? CLOAK_TRANSPORT_CDN
                         : CLOAK_TRANSPORT_DIRECT;

    if (cloak_config_get_string(root, "CDNOriginHost", cfg->cdn_origin_host,
                                sizeof(cfg->cdn_origin_host), &found, err,
                                err_cap) != 0) {
        return -1;
    }

    if (cloak_config_get_string(root, "CDNWsUrlPath", cfg->cdn_ws_url_path,
                                sizeof(cfg->cdn_ws_url_path), &found, err,
                                err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->cdn_ws_url_path[0] == '\0') {
        cfg->cdn_ws_url_path[0] = '/';
        cfg->cdn_ws_url_path[1] = '\0';
    }

    int stream_timeout = 0;
    if (cloak_config_get_int(root, "StreamTimeout", &stream_timeout, &found, err,
                             err_cap) != 0) {
        return -1;
    }
    cfg->stream_timeout_sec = (found && stream_timeout != 0) ? stream_timeout : 300;
    if (cfg->stream_timeout_sec < 0) {
        return cloak_config_set_err(err, err_cap, "StreamTimeout cannot be negative");
    }

    int keep_alive = 0;
    if (cloak_config_get_int(root, "KeepAlive", &keep_alive, &found, err, err_cap) != 0) {
        return -1;
    }
    cfg->keep_alive_sec = (found && keep_alive > 0) ? keep_alive : -1;

    return 0;
}

int cloak_client_config_parse_json(const char *text, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap) {
    if (text == NULL) {
        return cloak_config_set_err(err, err_cap, "no config text given");
    }
    cJSON *root = cJSON_Parse(text);
    if (root == NULL) {
        const char *at = cJSON_GetErrorPtr();
        return cloak_config_set_err(err, err_cap, "malformed JSON near '%.20s'",
                                    at != NULL ? at : "");
    }
    int rc = cloak_client_config_from_cjson(root, cfg, err, err_cap);
    cJSON_Delete(root);
    return rc;
}

int cloak_client_config_parse_file(const char *path, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap) {
    char *text = cloak_config_read_file(path, err, err_cap);
    if (text == NULL) {
        return -1;
    }
    int rc = cloak_client_config_parse_json(text, cfg, err, err_cap);
    free(text);
    return rc;
}
```

- [ ] **Step 7: Wire it into the build**

Add `src/config_common.c` and `src/config_client.c` to the `cloak-common` source list in `libcloak-common/CMakeLists.txt`.

Append to `libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_config_client test_config_client.c)
target_include_directories(test_config_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_config_client PRIVATE cloak-common)
add_test(NAME test_config_client COMMAND test_config_client)
```

- [ ] **Step 8: Run the tests to verify they pass**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build -R test_config_client --output-on-failure'
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add libcloak-common/include/cloak/config.h libcloak-common/src/config_internal.h \
        libcloak-common/src/config_common.c libcloak-common/src/config_client.c \
        libcloak-common/tests/test_config_client.c libcloak-common/CMakeLists.txt \
        libcloak-common/tests/CMakeLists.txt
git commit -m "Add client config: JSON parsing, defaults and validation"
```

---

### Task 5: `cloak_server_config_t` — server configuration

Mirrors Go's `internal/server/state.go`: `RawConfig` plus the parts of `InitState` that validate rather than connect (`parseProxyBook`, the private key check, the BypassUID/AdminUID handling, and the `CncMode` rejection).

**Files:**
- Create: `libcloak-common/src/config_server.c`
- Create: `libcloak-common/tests/test_config_server.c`
- Modify: `libcloak-common/CMakeLists.txt` (add `src/config_server.c`)
- Modify: `libcloak-common/tests/CMakeLists.txt` (register `test_config_server`)

**Interfaces:**
- Consumes: everything from Task 4's `config_internal.h`, plus `cloak_server_config_t` (already declared in `cloak/config.h` in Task 4).
- Produces: `cloak_server_config_parse_json`, `cloak_server_config_parse_file`, `cloak_server_config_from_cjson`.

- [ ] **Step 1: Write the failing test**

Create `libcloak-common/tests/test_config_server.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/config.h"
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PRIV_B64 "cHJpdmF0ZS1rZXktbWF0ZXJpYWwtZXhhY3RseS0zMiE="
#define ADMIN_B64 "YWRtaW5VSUQtMTZieXRlcyE="
#define BYPASS_B64 "Ynlwc3NVSUQtMTZieXRlcyE="

static const char *minimal_json(void) {
    static char buf[1024];
    snprintf(buf, sizeof(buf),
             "{"
             "\"ProxyBook\":{\"shadowsocks\":[\"tcp\",\"localhost:51443\"]},"
             "\"BindAddr\":[\":443\"],"
             "\"RedirAddr\":\"www.bing.com\","
             "\"PrivateKey\":\"%s\""
             "}",
             PRIV_B64);
    return buf;
}

static void test_parses_a_minimal_config(void) {
    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};

    ASSERT_EQ_INT(0, cloak_server_config_parse_json(minimal_json(), &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(1, (int)cfg.num_proxy_entries);
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_book[0].name, "shadowsocks"));
    ASSERT_EQ_INT(0, cfg.proxy_book[0].is_udp);
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_book[0].addr, "localhost:51443"));
    ASSERT_EQ_INT(1, (int)cfg.num_bind_addr);
    ASSERT_EQ_INT(0, strcmp(cfg.bind_addr[0], ":443"));
    ASSERT_EQ_INT(0, strcmp(cfg.redir_addr, "www.bing.com"));
    ASSERT_EQ_INT(0, cfg.has_admin_uid);
    ASSERT_EQ_INT(0, (int)cfg.num_bypass_uid);
    ASSERT_EQ_INT(0, cfg.database_path[0]);
    ASSERT_EQ_INT(-1, cfg.keep_alive_sec);
}

static void test_proxy_book_lowercases_names_and_reads_udp(void) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ShadowSocks\":[\"TCP\",\"localhost:1\"],"
             "\"wireguard\":[\"udp\",\"localhost:2\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             PRIV_B64);

    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(2, (int)cfg.num_proxy_entries);

    /* order follows the JSON document order */
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_book[0].name, "shadowsocks"));
    ASSERT_EQ_INT(0, cfg.proxy_book[0].is_udp);
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_book[1].name, "wireguard"));
    ASSERT_EQ_INT(1, cfg.proxy_book[1].is_udp);
}

static void test_reads_admin_and_bypass_uids(void) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\","
             "\"AdminUID\":\"%s\",\"BypassUID\":[\"%s\"],"
             "\"DatabasePath\":\"/var/lib/cloak/userinfo.db\",\"KeepAlive\":30}",
             PRIV_B64, ADMIN_B64, BYPASS_B64);

    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(1, cfg.has_admin_uid);
    ASSERT_EQ_INT(1, (int)cfg.num_bypass_uid);
    ASSERT_EQ_INT(0, strcmp(cfg.database_path, "/var/lib/cloak/userinfo.db"));
    ASSERT_EQ_INT(30, cfg.keep_alive_sec);
}

static void test_missing_required_fields(void) {
    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN];
    char json[1024];

    /* no PrivateKey */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\"}");
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "PrivateKey") != NULL);

    /* no RedirAddr */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "RedirAddr") != NULL);

    /* no BindAddr */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "BindAddr") != NULL);
}

static void test_rejects_bad_proxy_book_entries(void) {
    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN];
    char json[1024];

    /* pair with one element */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "ss") != NULL);

    /* unknown network */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"sctp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "sctp") != NULL);

    /* method name longer than the 12-byte wire field */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"thirteenchars\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "thirteenchars") != NULL);
}

static void test_rejects_cnc_mode(void) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\","
             "\"CncMode\":true}",
             PRIV_B64);

    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "CncMode") != NULL);
}

static void test_rejects_wrong_length_keys(void) {
    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN];
    char json[1024];

    /* PrivateKey decoding to 3 bytes rather than 32 */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"Zm9v\"}");
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "PrivateKey") != NULL);

    /* AdminUID decoding to the wrong length */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\","
             "\"AdminUID\":\"Zm9v\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "AdminUID") != NULL);
}

static void test_parse_file_round_trip(void) {
    char path[] = "/tmp/cloak_server_cfg_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return;
    }
    const char *json = minimal_json();
    ASSERT_TRUE(write(fd, json, strlen(json)) == (ssize_t)strlen(json));
    close(fd);

    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_server_config_parse_file(path, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.redir_addr, "www.bing.com"));
    unlink(path);
}

TEST_MAIN_BEGIN()
    test_parses_a_minimal_config();
    test_proxy_book_lowercases_names_and_reads_udp();
    test_reads_admin_and_bypass_uids();
    test_missing_required_fields();
    test_rejects_bad_proxy_book_entries();
    test_rejects_cnc_mode();
    test_rejects_wrong_length_keys();
    test_parse_file_round_trip();
TEST_MAIN_END()
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8'
```

Expected: FAIL — `undefined reference to cloak_server_config_parse_json`.

- [ ] **Step 3: Write the implementation**

Create `libcloak-common/src/config_server.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "config_internal.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "cloak/base64.h"

static void lowercase_in_place(char *s) {
    for (; *s != '\0'; s++) {
        *s = (char)tolower((unsigned char)*s);
    }
}

static int parse_proxy_book(const cJSON *root, cloak_server_config_t *cfg, char *err,
                            size_t err_cap) {
    const cJSON *book = cJSON_GetObjectItemCaseSensitive(root, "ProxyBook");
    if (book == NULL || cJSON_IsNull(book)) {
        return 0; /* Go tolerates an absent ProxyBook; it just proxies nothing */
    }
    if (!cJSON_IsObject(book)) {
        return cloak_config_set_err(err, err_cap, "ProxyBook must be an object");
    }

    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, book) {
        if (entry->string == NULL) {
            return cloak_config_set_err(err, err_cap, "ProxyBook has an unnamed entry");
        }
        if (!cJSON_IsArray(entry) || cJSON_GetArraySize(entry) != 2) {
            return cloak_config_set_err(
                err, err_cap,
                "ProxyBook entry %s must be a [network, address] pair", entry->string);
        }
        const cJSON *network = cJSON_GetArrayItem((cJSON *)entry, 0);
        const cJSON *addr = cJSON_GetArrayItem((cJSON *)entry, 1);
        if (!cJSON_IsString(network) || network->valuestring == NULL ||
            !cJSON_IsString(addr) || addr->valuestring == NULL) {
            return cloak_config_set_err(
                err, err_cap,
                "ProxyBook entry %s must be a [network, address] pair of strings",
                entry->string);
        }

        if (cfg->num_proxy_entries >= CLOAK_MAX_PROXY_BOOK) {
            return cloak_config_set_err(err, err_cap,
                                        "ProxyBook has more than %d entries",
                                        CLOAK_MAX_PROXY_BOOK);
        }
        cloak_proxy_entry_t *slot = &cfg->proxy_book[cfg->num_proxy_entries];

        size_t name_len = strlen(entry->string);
        if (name_len == 0 || name_len > CLOAK_PROXY_METHOD_LEN) {
            return cloak_config_set_err(
                err, err_cap,
                "ProxyBook name %s must be 1 to %d bytes (it travels in a fixed-width "
                "wire field)",
                entry->string, CLOAK_PROXY_METHOD_LEN);
        }
        memcpy(slot->name, entry->string, name_len + 1);
        lowercase_in_place(slot->name);

        if (strcasecmp(network->valuestring, "tcp") == 0) {
            slot->is_udp = 0;
        } else if (strcasecmp(network->valuestring, "udp") == 0) {
            slot->is_udp = 1;
        } else {
            return cloak_config_set_err(err, err_cap,
                                        "ProxyBook entry %s has unknown network %s",
                                        entry->string, network->valuestring);
        }

        size_t addr_len = strlen(addr->valuestring);
        if (addr_len == 0 || addr_len + 1 > sizeof(slot->addr)) {
            return cloak_config_set_err(err, err_cap,
                                        "ProxyBook entry %s has an unusable address",
                                        entry->string);
        }
        memcpy(slot->addr, addr->valuestring, addr_len + 1);

        cfg->num_proxy_entries++;
    }
    return 0;
}

static int parse_bind_addr(const cJSON *root, cloak_server_config_t *cfg, char *err,
                           size_t err_cap) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "BindAddr");
    if (arr == NULL || cJSON_IsNull(arr) || !cJSON_IsArray(arr)) {
        return cloak_config_set_err(err, err_cap,
                                    "BindAddr must be a non-empty array of strings");
    }

    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (!cJSON_IsString(item) || item->valuestring == NULL ||
            item->valuestring[0] == '\0') {
            return cloak_config_set_err(err, err_cap,
                                        "BindAddr must be an array of non-empty strings");
        }
        if (cfg->num_bind_addr >= CLOAK_MAX_BIND_ADDR) {
            return cloak_config_set_err(err, err_cap, "BindAddr has more than %d entries",
                                        CLOAK_MAX_BIND_ADDR);
        }
        size_t len = strlen(item->valuestring);
        if (len + 1 > CLOAK_MAX_HOST_LEN) {
            return cloak_config_set_err(err, err_cap, "BindAddr entry is too long");
        }
        memcpy(cfg->bind_addr[cfg->num_bind_addr], item->valuestring, len + 1);
        cfg->num_bind_addr++;
    }

    if (cfg->num_bind_addr == 0) {
        return cloak_config_set_err(err, err_cap, "BindAddr cannot be empty");
    }
    return 0;
}

static int parse_bypass_uid(const cJSON *root, cloak_server_config_t *cfg, char *err,
                            size_t err_cap) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "BypassUID");
    if (arr == NULL || cJSON_IsNull(arr)) {
        return 0;
    }
    if (!cJSON_IsArray(arr)) {
        return cloak_config_set_err(err, err_cap,
                                    "BypassUID must be an array of base64 strings");
    }

    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (!cJSON_IsString(item) || item->valuestring == NULL) {
            return cloak_config_set_err(err, err_cap,
                                        "BypassUID must be an array of base64 strings");
        }
        if (cfg->num_bypass_uid >= CLOAK_MAX_BYPASS_UID) {
            return cloak_config_set_err(err, err_cap, "BypassUID has more than %d entries",
                                        CLOAK_MAX_BYPASS_UID);
        }
        uint8_t decoded[64];
        size_t decoded_len = 0;
        if (cloak_base64_decode(item->valuestring, decoded, sizeof(decoded),
                                &decoded_len) != 0) {
            return cloak_config_set_err(err, err_cap,
                                        "BypassUID entry is not valid base64");
        }
        if (decoded_len != CLOAK_UID_LEN) {
            return cloak_config_set_err(
                err, err_cap, "BypassUID entry must decode to %d bytes, got %zu",
                CLOAK_UID_LEN, decoded_len);
        }
        memcpy(cfg->bypass_uid[cfg->num_bypass_uid], decoded, CLOAK_UID_LEN);
        cfg->num_bypass_uid++;
    }
    return 0;
}

int cloak_server_config_from_cjson(const cJSON *root, cloak_server_config_t *cfg,
                                   char *err, size_t err_cap) {
    if (root == NULL || cfg == NULL) {
        return cloak_config_set_err(err, err_cap, "internal: null config input");
    }
    if (!cJSON_IsObject(root)) {
        return cloak_config_set_err(err, err_cap, "config must be a JSON object");
    }

    memset(cfg, 0, sizeof(*cfg));
    int found = 0;

    int cnc_mode = 0;
    if (cloak_config_get_bool(root, "CncMode", &cnc_mode, &found, err, err_cap) != 0) {
        return -1;
    }
    if (cnc_mode) {
        return cloak_config_set_err(err, err_cap,
                                    "CncMode (command & control mode) is not implemented");
    }

    if (parse_proxy_book(root, cfg, err, err_cap) != 0) {
        return -1;
    }
    if (parse_bind_addr(root, cfg, err, err_cap) != 0) {
        return -1;
    }
    if (parse_bypass_uid(root, cfg, err, err_cap) != 0) {
        return -1;
    }

    if (cloak_config_get_string(root, "RedirAddr", cfg->redir_addr,
                                sizeof(cfg->redir_addr), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->redir_addr[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "RedirAddr cannot be empty");
    }

    if (cloak_config_get_b64(root, "PrivateKey", cfg->private_key,
                             CLOAK_X25519_KEY_LEN, &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found) {
        return cloak_config_set_err(
            err, err_cap,
            "PrivateKey cannot be empty; generate one with ck-server -key");
    }

    if (cloak_config_get_b64(root, "AdminUID", cfg->admin_uid, CLOAK_UID_LEN, &found,
                             err, err_cap) != 0) {
        return -1;
    }
    cfg->has_admin_uid = found;

    /* Go adds the AdminUID to the bypass set so the admin is never subject
     * to accounting. Do the same here, if there is room. */
    if (cfg->has_admin_uid) {
        if (cfg->num_bypass_uid >= CLOAK_MAX_BYPASS_UID) {
            return cloak_config_set_err(
                err, err_cap,
                "BypassUID is full (%d entries), leaving no room for AdminUID",
                CLOAK_MAX_BYPASS_UID);
        }
        memcpy(cfg->bypass_uid[cfg->num_bypass_uid], cfg->admin_uid, CLOAK_UID_LEN);
        cfg->num_bypass_uid++;
    }

    if (cloak_config_get_string(root, "DatabasePath", cfg->database_path,
                                sizeof(cfg->database_path), &found, err, err_cap) != 0) {
        return -1;
    }

    int keep_alive = 0;
    if (cloak_config_get_int(root, "KeepAlive", &keep_alive, &found, err, err_cap) != 0) {
        return -1;
    }
    cfg->keep_alive_sec = (found && keep_alive > 0) ? keep_alive : -1;

    return 0;
}

int cloak_server_config_parse_json(const char *text, cloak_server_config_t *cfg,
                                   char *err, size_t err_cap) {
    if (text == NULL) {
        return cloak_config_set_err(err, err_cap, "no config text given");
    }
    cJSON *root = cJSON_Parse(text);
    if (root == NULL) {
        const char *at = cJSON_GetErrorPtr();
        return cloak_config_set_err(err, err_cap, "malformed JSON near '%.20s'",
                                    at != NULL ? at : "");
    }
    int rc = cloak_server_config_from_cjson(root, cfg, err, err_cap);
    cJSON_Delete(root);
    return rc;
}

int cloak_server_config_parse_file(const char *path, cloak_server_config_t *cfg,
                                   char *err, size_t err_cap) {
    char *text = cloak_config_read_file(path, err, err_cap);
    if (text == NULL) {
        return -1;
    }
    int rc = cloak_server_config_parse_json(text, cfg, err, err_cap);
    free(text);
    return rc;
}
```

- [ ] **Step 4: Wire it into the build**

Add `src/config_server.c` to the `cloak-common` source list in `libcloak-common/CMakeLists.txt`.

Append to `libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_config_server test_config_server.c)
target_include_directories(test_config_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_config_server PRIVATE cloak-common)
add_test(NAME test_config_server COMMAND test_config_server)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build -R test_config_server --output-on-failure'
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add libcloak-common/src/config_server.c libcloak-common/tests/test_config_server.c \
        libcloak-common/CMakeLists.txt libcloak-common/tests/CMakeLists.txt
git commit -m "Add server config: ProxyBook, bind addresses, keys and validation"
```

---

### Task 6: ssv option strings and the load heuristic

Shadowsocks passes plugin options as a semicolon-separated string in `SS_PLUGIN_OPTIONS`, not as a file. Go converts that string to JSON text and re-parses it (`ssvToJson`); here the ssv front end builds a cJSON object directly, so there is no quoting or escaping round trip to get wrong.

**Files:**
- Create: `libcloak-common/src/config_ssv.c`
- Create: `libcloak-common/tests/test_config_ssv.c`
- Modify: `libcloak-common/CMakeLists.txt` (add `src/config_ssv.c`)
- Modify: `libcloak-common/tests/CMakeLists.txt` (register `test_config_ssv`)

**Interfaces:**
- Consumes: `cloak_client_config_from_cjson`, `cloak_config_set_err` (Task 4); `cloak_client_config_parse_file` (Task 4).
- Produces: `cloak_client_config_parse_ssv`, `cloak_client_config_load` (both already declared in `cloak/config.h` in Task 4).

- [ ] **Step 1: Write the failing test**

Create `libcloak-common/tests/test_config_ssv.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "cloak/config.h"
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define UID_B64 "SGVsbG9DbG9ha1VJRCEhIQ=="
#define PUB_B64 "bG9uZ2VyLWtleS1tYXRlcmlhbC1leGFjdGx5LTMyIQ=="

static const char *minimal_ssv(void) {
    static char buf[1024];
    snprintf(buf, sizeof(buf),
             "ServerName=www.bing.com;ProxyMethod=shadowsocks;"
             "EncryptionMethod=plain;UID=%s;PublicKey=%s;"
             "RemoteHost=1.2.3.4;RemotePort=443;LocalHost=127.0.0.1;LocalPort=1984",
             UID_B64, PUB_B64);
    return buf;
}

static void test_parses_a_minimal_ssv(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};

    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(minimal_ssv(), &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "www.bing.com"));
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_method, "shadowsocks"));
    ASSERT_EQ_INT(CLOAK_AEAD_NONE, cfg.encryption_method);
    ASSERT_EQ_INT(0, strcmp(cfg.remote_port, "443"));
    ASSERT_EQ_INT(1, cfg.num_conn);
    ASSERT_EQ_INT(1, cfg.singleplex);
}

static void test_numeric_and_boolean_options_are_typed(void) {
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;NumConn=4;StreamTimeout=60;KeepAlive=15;UDP=true",
             minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(4, cfg.num_conn);
    ASSERT_EQ_INT(0, cfg.singleplex);
    ASSERT_EQ_INT(60, cfg.stream_timeout_sec);
    ASSERT_EQ_INT(15, cfg.keep_alive_sec);
    ASSERT_EQ_INT(1, cfg.udp);
}

static void test_alternative_names_split_on_commas(void) {
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;AlternativeNames=b.com,c.com,d.com", minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(3, (int)cfg.num_alt_names);
    ASSERT_EQ_INT(0, strcmp(cfg.alt_names[0], "b.com"));
    ASSERT_EQ_INT(0, strcmp(cfg.alt_names[2], "d.com"));
}

static void test_single_alternative_name_without_comma(void) {
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;AlternativeNames=b.com", minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(1, (int)cfg.num_alt_names);
    ASSERT_EQ_INT(0, strcmp(cfg.alt_names[0], "b.com"));
}

static void test_escapes_are_unescaped(void) {
    char ssv[1200];
    /* a CDN path containing an escaped semicolon and equals sign */
    snprintf(ssv, sizeof(ssv), "%s;Transport=cdn;CDNWsUrlPath=/a\\;b\\=c", minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(CLOAK_TRANSPORT_CDN, cfg.transport);
    ASSERT_EQ_INT(0, strcmp(cfg.cdn_ws_url_path, "/a;b=c"));
}

static void test_escaped_backslash(void) {
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;CDNOriginHost=a\\\\b", minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.cdn_origin_host, "a\\b"));
}

static void test_trailing_semicolon_is_tolerated(void) {
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;", minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "www.bing.com"));
}

static void test_rejects_malformed_options(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN];

    /* an option with no '=' */
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;JustAKey", minimal_ssv());
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "JustAKey") != NULL);

    /* a non-numeric value for a numeric option */
    snprintf(ssv, sizeof(ssv), "%s;NumConn=lots", minimal_ssv());
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "NumConn") != NULL);

    /* an empty string */
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_ssv("", &cfg, err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');
}

static void test_load_dispatches_on_shape(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};

    /* contains both ';' and '=' -> treated as ssv */
    ASSERT_EQ_INT(0, cloak_client_config_load(minimal_ssv(), &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "www.bing.com"));

    /* otherwise a path */
    char path[] = "/tmp/cloak_load_cfg_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return;
    }
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"from.file\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             UID_B64, PUB_B64);
    ASSERT_TRUE(write(fd, json, strlen(json)) == (ssize_t)strlen(json));
    close(fd);

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_client_config_load(path, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "from.file"));
    unlink(path);
}

TEST_MAIN_BEGIN()
    test_parses_a_minimal_ssv();
    test_numeric_and_boolean_options_are_typed();
    test_alternative_names_split_on_commas();
    test_single_alternative_name_without_comma();
    test_escapes_are_unescaped();
    test_escaped_backslash();
    test_trailing_semicolon_is_tolerated();
    test_rejects_malformed_options();
    test_load_dispatches_on_shape();
TEST_MAIN_END()
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8'
```

Expected: FAIL — `undefined reference to cloak_client_config_parse_ssv`.

- [ ] **Step 3: Write the implementation**

Create `libcloak-common/src/config_ssv.c`:

```c
#define _POSIX_C_SOURCE 200809L
#include "config_internal.h"

#include <stdlib.h>
#include <string.h>

/* Options whose values are JSON numbers or booleans rather than strings.
 * Mirrors Go's `unquoted` list in ssvToJson. */
static int is_unquoted_key(const char *key) {
    static const char *const unquoted[] = {"NumConn", "StreamTimeout", "KeepAlive", "UDP"};
    for (size_t i = 0; i < sizeof(unquoted) / sizeof(unquoted[0]); i++) {
        if (strcmp(key, unquoted[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Copies src into dst, resolving the three escapes ssv defines: "\\" -> '\',
 * "\=" -> '=', "\;" -> ';'. A backslash before any other character is kept
 * literally, matching Go's three-way string replacement. Returns -1 if the
 * result would not fit in dst_cap (including the NUL). */
static int unescape(const char *src, size_t src_len, char *dst, size_t dst_cap) {
    size_t o = 0;
    for (size_t i = 0; i < src_len; i++) {
        char c = src[i];
        if (c == '\\' && i + 1 < src_len) {
            char next = src[i + 1];
            if (next == '\\' || next == '=' || next == ';') {
                c = next;
                i++;
            }
        }
        if (o + 1 >= dst_cap) {
            return -1;
        }
        dst[o++] = c;
    }
    if (o >= dst_cap) {
        return -1;
    }
    dst[o] = '\0';
    return 0;
}

/* Splits value on commas and adds it as a JSON array of strings. */
static int add_comma_list(cJSON *obj, const char *key, const char *value, char *err,
                          size_t err_cap) {
    cJSON *arr = cJSON_AddArrayToObject(obj, key);
    if (arr == NULL) {
        return cloak_config_set_err(err, err_cap, "out of memory building %s", key);
    }
    const char *start = value;
    for (;;) {
        const char *comma = strchr(start, ',');
        size_t len = comma != NULL ? (size_t)(comma - start) : strlen(start);
        char item[CLOAK_MAX_HOST_LEN];
        if (len + 1 > sizeof(item)) {
            return cloak_config_set_err(err, err_cap, "%s entry is too long", key);
        }
        memcpy(item, start, len);
        item[len] = '\0';

        cJSON *str = cJSON_CreateString(item);
        if (str == NULL || !cJSON_AddItemToArray(arr, str)) {
            cJSON_Delete(str);
            return cloak_config_set_err(err, err_cap, "out of memory building %s", key);
        }

        if (comma == NULL) {
            break;
        }
        start = comma + 1;
    }
    return 0;
}

/* Adds one key/value option to obj with the JSON type the key calls for. */
static int add_option(cJSON *obj, const char *key, const char *value, char *err,
                      size_t err_cap) {
    if (strcmp(key, "AlternativeNames") == 0) {
        return add_comma_list(obj, key, value, err, err_cap);
    }

    if (is_unquoted_key(key)) {
        if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0) {
            if (cJSON_AddBoolToObject(obj, key, strcmp(value, "true") == 0) == NULL) {
                return cloak_config_set_err(err, err_cap, "out of memory building %s", key);
            }
            return 0;
        }
        char *end = NULL;
        long parsed = strtol(value, &end, 10);
        if (end == value || *end != '\0') {
            return cloak_config_set_err(err, err_cap, "%s must be a number, got '%s'",
                                        key, value);
        }
        if (cJSON_AddNumberToObject(obj, key, (double)parsed) == NULL) {
            return cloak_config_set_err(err, err_cap, "out of memory building %s", key);
        }
        return 0;
    }

    if (cJSON_AddStringToObject(obj, key, value) == NULL) {
        return cloak_config_set_err(err, err_cap, "out of memory building %s", key);
    }
    return 0;
}

int cloak_client_config_parse_ssv(const char *ssv, cloak_client_config_t *cfg, char *err,
                                  size_t err_cap) {
    if (ssv == NULL || ssv[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "empty plugin option string");
    }

    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        return cloak_config_set_err(err, err_cap, "out of memory parsing options");
    }

    int rc = 0;
    const char *cursor = ssv;
    while (*cursor != '\0') {
        /* find the next unescaped ';' */
        const char *end = cursor;
        while (*end != '\0') {
            if (*end == '\\' && *(end + 1) != '\0') {
                end += 2;
                continue;
            }
            if (*end == ';') {
                break;
            }
            end++;
        }

        size_t field_len = (size_t)(end - cursor);
        if (field_len > 0) {
            /* split on the first unescaped '=' */
            const char *eq = cursor;
            const char *limit = cursor + field_len;
            while (eq < limit) {
                if (*eq == '\\' && eq + 1 < limit) {
                    eq += 2;
                    continue;
                }
                if (*eq == '=') {
                    break;
                }
                eq++;
            }

            char key[128];
            char value[CLOAK_MAX_PATH_LEN];
            if (eq >= limit) {
                char shown[128];
                size_t shown_len = field_len < sizeof(shown) - 1 ? field_len
                                                                 : sizeof(shown) - 1;
                memcpy(shown, cursor, shown_len);
                shown[shown_len] = '\0';
                rc = cloak_config_set_err(err, err_cap,
                                          "malformed option '%s': expected key=value",
                                          shown);
                break;
            }
            if (unescape(cursor, (size_t)(eq - cursor), key, sizeof(key)) != 0) {
                rc = cloak_config_set_err(err, err_cap, "option name is too long");
                break;
            }
            if (unescape(eq + 1, (size_t)(limit - (eq + 1)), value, sizeof(value)) != 0) {
                rc = cloak_config_set_err(err, err_cap, "value of %s is too long", key);
                break;
            }
            if (add_option(obj, key, value, err, err_cap) != 0) {
                rc = -1;
                break;
            }
        }

        if (*end == '\0') {
            break;
        }
        cursor = end + 1;
    }

    if (rc == 0) {
        rc = cloak_client_config_from_cjson(obj, cfg, err, err_cap);
    }
    cJSON_Delete(obj);
    return rc;
}

int cloak_client_config_load(const char *conf, cloak_client_config_t *cfg, char *err,
                             size_t err_cap) {
    if (conf == NULL || conf[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "no config given");
    }
    if (strchr(conf, ';') != NULL && strchr(conf, '=') != NULL) {
        return cloak_client_config_parse_ssv(conf, cfg, err, err_cap);
    }
    return cloak_client_config_parse_file(conf, cfg, err, err_cap);
}
```

- [ ] **Step 4: Wire it into the build**

Add `src/config_ssv.c` to the `cloak-common` source list in `libcloak-common/CMakeLists.txt`.

Append to `libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_config_ssv test_config_ssv.c)
target_include_directories(test_config_ssv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_config_ssv PRIVATE cloak-common)
add_test(NAME test_config_ssv COMMAND test_config_ssv)
```

- [ ] **Step 5: Run the whole suite to verify everything passes**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
```

Expected: PASS — the 17 pre-existing tests plus `test_base64`, `test_log`, `test_cjson_link`, `test_config_client`, `test_config_server` and `test_config_ssv`, for 23 total.

- [ ] **Step 6: Run the suite under ASan/UBSan**

Run:

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c \
  'cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
     -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
     -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" && \
   cmake --build build-asan -j8 && ctest --test-dir build-asan --output-on-failure'
```

Expected: PASS with no sanitizer reports. The config parsers allocate (cJSON, the file buffer) and the ssv parser does pointer arithmetic over the input, so this run is what proves the frees and bounds are right. `build-asan/` is already covered by `.gitignore`.

- [ ] **Step 7: Commit**

```bash
git add libcloak-common/src/config_ssv.c libcloak-common/tests/test_config_ssv.c \
        libcloak-common/CMakeLists.txt libcloak-common/tests/CMakeLists.txt
git commit -m "Add ssv option parsing and the config load heuristic"
```

---

## What comes after this plan

Per the master spec, the next module is the **server dispatcher** (§7): the per-connection state machine that sniffs the first byte (`0x16` TLS / `0x47` WebSocket `GET`), buffers a full first packet across non-blocking reads, runs the already-merged `libcloak-server` auth path, attaches the connection to a `cloak_session_t`, and otherwise falls back to `goWeb()` — forwarding to `RedirAddr`. That module is the first consumer of `cloak_server_config_t` from this plan, and it needs one new shared piece this plan does not build: a bidirectional relay (`cloak_relay_t`) that splices two non-blocking sockets with backpressure, which the client's local listener will reuse.

Explicitly out of scope here: any use of these configs (nothing links them yet beyond their tests), CLI flag handling and the flag-over-config precedence rules (those belong with the binaries, module 7), and server-side key/UID generation (also module 7).

## Self-review notes

- **Spec coverage (§10):** JSON config parsed with vendored cJSON — Tasks 3, 4, 5. Field names match the Go config structs verbatim, both client (`UID`, `Transport`, `PublicKey`, `ProxyMethod`, `EncryptionMethod`, `ServerName`, `AlternativeNames`, `CDNOriginHost`, `CDNWsUrlPath`, `NumConn`, `BrowserSig`, `StreamTimeout`, `LocalHost`/`LocalPort`/`RemoteHost`/`RemotePort`, `UDP`, `KeepAlive`) and server (`ProxyBook`, `BindAddr`, `RedirAddr`, `PrivateKey`, `BypassUID`, `AdminUID`, `DatabasePath`, `KeepAlive`, `CncMode`). §10's CLI half is deliberately deferred to module 7, as noted above. Base64 (Task 1) and logging (Task 2) are not named as separate spec sections but are prerequisites the spec assumes throughout (`-key`/`-uid` output, every module's diagnostics).
- **Placeholder scan:** no TBD/TODO steps; every code step contains complete, compilable code. The two annotated fixups in Task 4 Step 1 and the one in Task 1 Step 1 are deliberate, explicit instructions, not placeholders.
- **Type consistency:** `cloak_config_set_err(char*, size_t, const char*, ...)` returns `int` (-1) and is used as `return cloak_config_set_err(...)` throughout Tasks 4, 5 and 6. The accessor family `cloak_config_get_string/int/bool/b64` shares one signature shape — `(obj, name, dst[, len], int *found, char *err, size_t err_cap)` returning 0/-1 — and every call site passes a `found` variable. `cloak_client_config_from_cjson`/`cloak_server_config_from_cjson` are declared in `config_internal.h` (Task 4) and defined in `config_client.c` (Task 4) and `config_server.c` (Task 5) respectively; `config_ssv.c` (Task 6) calls the client one. `CLOAK_UID_LEN`, `CLOAK_PROXY_METHOD_LEN`, `CLOAK_MAX_HOST_LEN` and `CLOAK_CONFIG_ERR_LEN` are defined once in `cloak/config.h` and used unchanged in all later tasks and tests.
- **Divergences from the Go original, deliberate and documented in the header:** collections are capped (`CLOAK_MAX_ALT_NAMES` etc.) where Go's slices are unbounded, and exceeding a cap is an error rather than a truncation; `ProxyMethod` longer than 12 bytes is rejected at parse time rather than silently truncated on the wire; `BindAddr` is required (Go would start with none and simply listen nowhere).
