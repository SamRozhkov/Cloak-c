# libcloak-common: Crypto Primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and unit-test the cryptographic primitives layer of `libcloak-common` — AEAD seal/open (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305), the Salsa20 stream cipher used for frame-header obfuscation, X25519 key generation and ECDH, and a CSPRNG helper — with no networking or protocol logic on top yet.

**Architecture:** A single static library `cloak-common` built with CMake. AEAD and X25519 wrap OpenSSL's EVP API (`libcrypto`). Salsa20 is not available as an OpenSSL EVP cipher, so it is implemented directly from the published Salsa20/20 core algorithm (public-domain construction, no external dependency). Every function is a pure, allocation-free primitive operating on caller-supplied buffers — no I/O, no global state — so later layers (frame codec, TLS ClientHello patching, auth handshake) can depend on this library without pulling in the reactor or any networking code.

**Tech Stack:** C11, CMake, OpenSSL (`libcrypto`), CTest with a small custom assert-based test runner (no external test framework).

## Global Constraints

- Language: C11 (`-Wall -Wextra` clean build).
- Platform: Linux only (per spec §2 — no portability shims).
- Crypto dependency: OpenSSL `libcrypto` only. No other crypto library.
- No wire compatibility with Go Cloak is required or attempted (per spec §1) — the crypto formats mirror Go Cloak's design choices because they're proven, not because interop is needed.
- AEAD method IDs match Go Cloak's `internal/multiplex/obfs.go` enum ordering exactly, since later plans (frame codec) will read this ID off the wire: `0 = none/plain, 1 = AES-256-GCM, 2 = ChaCha20-Poly1305, 3 = AES-128-GCM` (per spec §4).
- AEAD nonce length is fixed at 12 bytes and tag length at 16 bytes for all three ciphers (per spec §4 frame format, which reserves exactly this much room).
- Testing: lightweight custom assert-based runner + CTest, no heavyweight framework (per spec §11).
- Build: CMake (per spec §10).

---

### Task 1: Project scaffolding and build pipeline

**Files:**
- Create: `/Users/sam/Cloak-c/CMakeLists.txt`
- Create: `/Users/sam/Cloak-c/libcloak-common/CMakeLists.txt`
- Create: `/Users/sam/Cloak-c/libcloak-common/include/cloak/common.h`
- Create: `/Users/sam/Cloak-c/libcloak-common/src/version.c`
- Create: `/Users/sam/Cloak-c/libcloak-common/tests/CMakeLists.txt`
- Create: `/Users/sam/Cloak-c/libcloak-common/tests/test_framework.h`
- Test: `/Users/sam/Cloak-c/libcloak-common/tests/test_version.c`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `const char *cloak_common_version(void);` — declared in `cloak/common.h`, defined in `src/version.c`.
  - `test_framework.h` macros used by every later test file in this plan: `ASSERT_TRUE(cond)`, `ASSERT_EQ_INT(a, b)`, `ASSERT_MEM_EQ(a, b, len)`, `TEST_MAIN_BEGIN()`, `TEST_MAIN_END()`.

- [ ] **Step 1: Write the test framework header and the first failing test**

Create `/Users/sam/Cloak-c/libcloak-common/tests/test_framework.h`:

```c
#ifndef CLOAK_TEST_FRAMEWORK_H
#define CLOAK_TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>

static int cloak_test_failures = 0;

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: ASSERT_TRUE(%s)\n", __FILE__, __LINE__, #cond); \
            cloak_test_failures++; \
        } \
    } while (0)

#define ASSERT_EQ_INT(a, b) \
    do { \
        long long _a = (long long)(a); \
        long long _b = (long long)(b); \
        if (_a != _b) { \
            fprintf(stderr, "FAIL %s:%d: ASSERT_EQ_INT(%s, %s) -> %lld != %lld\n", \
                    __FILE__, __LINE__, #a, #b, _a, _b); \
            cloak_test_failures++; \
        } \
    } while (0)

#define ASSERT_MEM_EQ(a, b, len) \
    do { \
        if (memcmp((a), (b), (len)) != 0) { \
            fprintf(stderr, "FAIL %s:%d: ASSERT_MEM_EQ(%s, %s, %s)\n", \
                    __FILE__, __LINE__, #a, #b, #len); \
            cloak_test_failures++; \
        } \
    } while (0)

#define ASSERT_MEM_NE(a, b, len) \
    do { \
        if (memcmp((a), (b), (len)) == 0) { \
            fprintf(stderr, "FAIL %s:%d: ASSERT_MEM_NE(%s, %s, %s)\n", \
                    __FILE__, __LINE__, #a, #b, #len); \
            cloak_test_failures++; \
        } \
    } while (0)

#define TEST_MAIN_BEGIN() int main(void) {

#define TEST_MAIN_END() \
    if (cloak_test_failures > 0) { \
        fprintf(stderr, "%d assertion(s) failed\n", cloak_test_failures); \
        return 1; \
    } \
    printf("All tests passed\n"); \
    return 0; \
    }

#endif
```

Create `/Users/sam/Cloak-c/libcloak-common/tests/test_version.c`:

```c
#include "cloak/common.h"
#include "test_framework.h"

static void test_version_returns_nonempty_string(void) {
    const char *v = cloak_common_version();
    ASSERT_TRUE(v != NULL);
    ASSERT_TRUE(strlen(v) > 0);
}

TEST_MAIN_BEGIN()
    test_version_returns_nonempty_string();
TEST_MAIN_END()
```

- [ ] **Step 2: Confirm there is no build system yet (expected failure)**

Run: `cd /Users/sam/Cloak-c && cmake -S . -B build`
Expected: FAIL — `CMakeLists.txt` does not exist at the source root.

- [ ] **Step 3: Write the CMake build files and the library stub**

Create `/Users/sam/Cloak-c/CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.16)
project(cloak-c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra)

enable_testing()

add_subdirectory(libcloak-common)
```

Create `/Users/sam/Cloak-c/libcloak-common/CMakeLists.txt`:

```cmake
find_package(OpenSSL REQUIRED)

add_library(cloak-common STATIC
    src/version.c
)

target_include_directories(cloak-common PUBLIC include)
target_link_libraries(cloak-common PUBLIC OpenSSL::Crypto)

add_subdirectory(tests)
```

Create `/Users/sam/Cloak-c/libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_version test_version.c)
target_link_libraries(test_version PRIVATE cloak-common)
add_test(NAME test_version COMMAND test_version)
```

Create `/Users/sam/Cloak-c/libcloak-common/include/cloak/common.h`:

```c
#ifndef CLOAK_COMMON_H
#define CLOAK_COMMON_H

const char *cloak_common_version(void);

#endif
```

Create `/Users/sam/Cloak-c/libcloak-common/src/version.c`:

```c
#include "cloak/common.h"

const char *cloak_common_version(void) {
    return "cloak-c-0.1.0-dev";
}
```

- [ ] **Step 4: Build and run the test to verify it passes**

Run:
```bash
cd /Users/sam/Cloak-c
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```
Expected: build succeeds, `ctest` reports `100% tests passed, 0 tests failed out of 1`.

- [ ] **Step 5: Commit**

```bash
cd /Users/sam/Cloak-c
git add CMakeLists.txt libcloak-common/CMakeLists.txt libcloak-common/include/cloak/common.h \
        libcloak-common/src/version.c libcloak-common/tests/CMakeLists.txt \
        libcloak-common/tests/test_framework.h libcloak-common/tests/test_version.c
git commit -m "Set up CMake build, CTest wiring, and assert-based test framework"
```

---

### Task 2: Secure random bytes helper

**Files:**
- Modify: `/Users/sam/Cloak-c/libcloak-common/include/cloak/common.h`
- Create: `/Users/sam/Cloak-c/libcloak-common/src/random.c`
- Modify: `/Users/sam/Cloak-c/libcloak-common/CMakeLists.txt`
- Modify: `/Users/sam/Cloak-c/libcloak-common/tests/CMakeLists.txt`
- Test: `/Users/sam/Cloak-c/libcloak-common/tests/test_random.c`

**Interfaces:**
- Consumes: nothing new.
- Produces: `void cloak_random_bytes(uint8_t *buf, size_t len);` — fills `buf` with `len` cryptographically secure random bytes; aborts the process if the underlying CSPRNG fails (unrecoverable — matches the project's stance that RNG failure is not something callers should have to handle). Declared in `cloak/common.h`. Used by every later task in this plan that needs fresh key/nonce material for tests, and by the future frame-codec and CLI keygen work.

- [ ] **Step 1: Write the failing test**

Create `/Users/sam/Cloak-c/libcloak-common/tests/test_random.c`:

```c
#include "cloak/common.h"
#include "test_framework.h"
#include <stdint.h>
#include <string.h>

static void test_random_bytes_fills_buffer_differently_each_call(void) {
    uint8_t a[32];
    uint8_t b[32];
    memset(a, 0, sizeof(a));
    memset(b, 0, sizeof(b));

    cloak_random_bytes(a, sizeof(a));
    cloak_random_bytes(b, sizeof(b));

    ASSERT_MEM_NE(a, b, sizeof(a));
}

static void test_random_bytes_zero_length_is_a_no_op(void) {
    uint8_t canary[4] = {1, 2, 3, 4};
    cloak_random_bytes(canary, 0);
    uint8_t expected[4] = {1, 2, 3, 4};
    ASSERT_MEM_EQ(canary, expected, sizeof(canary));
}

TEST_MAIN_BEGIN()
    test_random_bytes_fills_buffer_differently_each_call();
    test_random_bytes_zero_length_is_a_no_op();
TEST_MAIN_END()
```

Add to `/Users/sam/Cloak-c/libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_random test_random.c)
target_link_libraries(test_random PRIVATE cloak-common)
add_test(NAME test_random COMMAND test_random)
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd /Users/sam/Cloak-c
cmake --build build
```
Expected: FAIL — linker error, `undefined reference to 'cloak_random_bytes'`.

- [ ] **Step 3: Write the implementation**

Add to `/Users/sam/Cloak-c/libcloak-common/include/cloak/common.h` (inside the header, before the closing `#endif`):

```c
#include <stddef.h>
#include <stdint.h>

void cloak_random_bytes(uint8_t *buf, size_t len);
```

Create `/Users/sam/Cloak-c/libcloak-common/src/random.c`:

```c
#include "cloak/common.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

void cloak_random_bytes(uint8_t *buf, size_t len) {
    if (len == 0) {
        return;
    }
    if (RAND_bytes(buf, (int)len) != 1) {
        fprintf(stderr, "cloak: fatal: RAND_bytes failed, CSPRNG unavailable\n");
        abort();
    }
}
```

Add `src/random.c` to the `add_library(cloak-common STATIC ...)` call in `/Users/sam/Cloak-c/libcloak-common/CMakeLists.txt`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/sam/Cloak-c
cmake --build build
ctest --test-dir build --output-on-failure
```
Expected: `100% tests passed, 0 tests failed out of 2`.

- [ ] **Step 5: Commit**

```bash
cd /Users/sam/Cloak-c
git add libcloak-common/include/cloak/common.h libcloak-common/src/random.c \
        libcloak-common/CMakeLists.txt libcloak-common/tests/CMakeLists.txt \
        libcloak-common/tests/test_random.c
git commit -m "Add CSPRNG wrapper (cloak_random_bytes)"
```

---

### Task 3: AEAD seal/open — AES-256-GCM

**Files:**
- Create: `/Users/sam/Cloak-c/libcloak-common/include/cloak/crypto.h`
- Create: `/Users/sam/Cloak-c/libcloak-common/src/aead.c`
- Modify: `/Users/sam/Cloak-c/libcloak-common/CMakeLists.txt`
- Modify: `/Users/sam/Cloak-c/libcloak-common/tests/CMakeLists.txt`
- Test: `/Users/sam/Cloak-c/libcloak-common/tests/test_aead.c`

**Interfaces:**
- Consumes: `cloak_random_bytes` (Task 2, for generating test keys/nonces).
- Produces (in `cloak/crypto.h`):
  ```c
  typedef enum {
      CLOAK_AEAD_NONE = 0,
      CLOAK_AEAD_AES_256_GCM = 1,
      CLOAK_AEAD_CHACHA20_POLY1305 = 2,
      CLOAK_AEAD_AES_128_GCM = 3,
  } cloak_aead_method_t;

  #define CLOAK_AEAD_KEY_LEN 32
  #define CLOAK_AEAD_NONCE_LEN 12
  #define CLOAK_AEAD_TAG_LEN 16

  int cloak_aead_seal(cloak_aead_method_t method,
                       const uint8_t key[CLOAK_AEAD_KEY_LEN],
                       const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                       const uint8_t *plaintext, size_t plaintext_len,
                       uint8_t *out, size_t *out_len);

  int cloak_aead_open(cloak_aead_method_t method,
                       const uint8_t key[CLOAK_AEAD_KEY_LEN],
                       const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                       const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t *out_len);

  size_t cloak_aead_overhead(cloak_aead_method_t method);
  ```
  This task implements only the `CLOAK_AEAD_AES_256_GCM` and `CLOAK_AEAD_NONE` cases; `CLOAK_AEAD_CHACHA20_POLY1305` and `CLOAK_AEAD_AES_128_GCM` are added in Task 4 by extending the same functions (they share the dispatch structure, added there to keep this task reviewable on its own).
  For all non-`NONE` methods, `out` must have room for `plaintext_len + CLOAK_AEAD_TAG_LEN` bytes on seal, and `out` must have room for `in_len - CLOAK_AEAD_TAG_LEN` bytes on open. `CLOAK_AEAD_NONE` is a pass-through copy with zero overhead (mirrors Go Cloak's "plain" encryption method, used only when the wrapped proxy protocol already provides AEAD).

- [ ] **Step 1: Write the failing test**

Create `/Users/sam/Cloak-c/libcloak-common/include/cloak/crypto.h` (full contents for this task — Task 4 will extend the enum's usage but the file itself is already complete):

```c
#ifndef CLOAK_CRYPTO_H
#define CLOAK_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    CLOAK_AEAD_NONE = 0,
    CLOAK_AEAD_AES_256_GCM = 1,
    CLOAK_AEAD_CHACHA20_POLY1305 = 2,
    CLOAK_AEAD_AES_128_GCM = 3,
} cloak_aead_method_t;

#define CLOAK_AEAD_KEY_LEN 32
#define CLOAK_AEAD_NONCE_LEN 12
#define CLOAK_AEAD_TAG_LEN 16

/* On success returns 0 and writes plaintext_len + cloak_aead_overhead(method)
 * bytes to out, setting *out_len. Returns -1 on an unknown method or an
 * OpenSSL-level failure. */
int cloak_aead_seal(cloak_aead_method_t method,
                     const uint8_t key[CLOAK_AEAD_KEY_LEN],
                     const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                     const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *out, size_t *out_len);

/* in is ciphertext||tag for non-NONE methods (in_len includes the tag).
 * On success returns 0 and writes in_len - cloak_aead_overhead(method) bytes
 * to out, setting *out_len. Returns -1 on authentication failure, an unknown
 * method, or in_len too short to contain a tag. */
int cloak_aead_open(cloak_aead_method_t method,
                     const uint8_t key[CLOAK_AEAD_KEY_LEN],
                     const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len);

size_t cloak_aead_overhead(cloak_aead_method_t method);

#endif
```

Create `/Users/sam/Cloak-c/libcloak-common/tests/test_aead.c`:

```c
#include "cloak/common.h"
#include "cloak/crypto.h"
#include "test_framework.h"
#include <string.h>

static void test_overhead(void) {
    ASSERT_EQ_INT(cloak_aead_overhead(CLOAK_AEAD_NONE), 0);
    ASSERT_EQ_INT(cloak_aead_overhead(CLOAK_AEAD_AES_256_GCM), CLOAK_AEAD_TAG_LEN);
}

static void test_none_is_passthrough(void) {
    uint8_t key[CLOAK_AEAD_KEY_LEN] = {0};
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN] = {0};
    const uint8_t plaintext[] = "hello cloak";
    uint8_t out[64];
    size_t out_len = 0;

    int rc = cloak_aead_seal(CLOAK_AEAD_NONE, key, nonce, plaintext, sizeof(plaintext), out, &out_len);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(out_len, sizeof(plaintext));
    ASSERT_MEM_EQ(out, plaintext, sizeof(plaintext));
}

static void test_aes256gcm_round_trip(void) {
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[] = "the quick brown fox jumps over the lazy dog";
    uint8_t ciphertext[sizeof(plaintext) + CLOAK_AEAD_TAG_LEN];
    size_t ciphertext_len = 0;

    int rc = cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, key, nonce, plaintext, sizeof(plaintext),
                              ciphertext, &ciphertext_len);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(ciphertext_len, sizeof(plaintext) + CLOAK_AEAD_TAG_LEN);

    uint8_t decrypted[sizeof(plaintext)];
    size_t decrypted_len = 0;
    rc = cloak_aead_open(CLOAK_AEAD_AES_256_GCM, key, nonce, ciphertext, ciphertext_len,
                          decrypted, &decrypted_len);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(decrypted_len, sizeof(plaintext));
    ASSERT_MEM_EQ(decrypted, plaintext, sizeof(plaintext));
}

static void test_aes256gcm_tamper_detection(void) {
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[] = "tamper me if you can";
    uint8_t ciphertext[sizeof(plaintext) + CLOAK_AEAD_TAG_LEN];
    size_t ciphertext_len = 0;
    cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, key, nonce, plaintext, sizeof(plaintext),
                     ciphertext, &ciphertext_len);

    ciphertext[0] ^= 0x01; /* flip a bit in the ciphertext */

    uint8_t decrypted[sizeof(plaintext)];
    size_t decrypted_len = 0;
    int rc = cloak_aead_open(CLOAK_AEAD_AES_256_GCM, key, nonce, ciphertext, ciphertext_len,
                              decrypted, &decrypted_len);
    ASSERT_EQ_INT(rc, -1);
}

static void test_aes256gcm_wrong_key_fails(void) {
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    uint8_t wrong_key[CLOAK_AEAD_KEY_LEN];
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(wrong_key, sizeof(wrong_key));
    cloak_random_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[] = "secret";
    uint8_t ciphertext[sizeof(plaintext) + CLOAK_AEAD_TAG_LEN];
    size_t ciphertext_len = 0;
    cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, key, nonce, plaintext, sizeof(plaintext),
                     ciphertext, &ciphertext_len);

    uint8_t decrypted[sizeof(plaintext)];
    size_t decrypted_len = 0;
    int rc = cloak_aead_open(CLOAK_AEAD_AES_256_GCM, wrong_key, nonce, ciphertext, ciphertext_len,
                              decrypted, &decrypted_len);
    ASSERT_EQ_INT(rc, -1);
}

TEST_MAIN_BEGIN()
    test_overhead();
    test_none_is_passthrough();
    test_aes256gcm_round_trip();
    test_aes256gcm_tamper_detection();
    test_aes256gcm_wrong_key_fails();
TEST_MAIN_END()
```

Add to `/Users/sam/Cloak-c/libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_aead test_aead.c)
target_link_libraries(test_aead PRIVATE cloak-common)
add_test(NAME test_aead COMMAND test_aead)
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd /Users/sam/Cloak-c
cmake --build build
```
Expected: FAIL — compile error, `cloak/crypto.h` exists but `cloak_aead_seal`/`cloak_aead_open`/`cloak_aead_overhead` are undefined (no `aead.c` yet, so this is a linker error: `undefined reference to 'cloak_aead_seal'`).

- [ ] **Step 3: Write the implementation**

Create `/Users/sam/Cloak-c/libcloak-common/src/aead.c`:

```c
#include "cloak/crypto.h"

#include <openssl/evp.h>
#include <string.h>

static const EVP_CIPHER *pick_cipher(cloak_aead_method_t method) {
    switch (method) {
        case CLOAK_AEAD_AES_256_GCM:
            return EVP_aes_256_gcm();
        default:
            return NULL;
    }
}

size_t cloak_aead_overhead(cloak_aead_method_t method) {
    if (method == CLOAK_AEAD_NONE) {
        return 0;
    }
    return CLOAK_AEAD_TAG_LEN;
}

int cloak_aead_seal(cloak_aead_method_t method,
                     const uint8_t key[CLOAK_AEAD_KEY_LEN],
                     const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                     const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *out, size_t *out_len) {
    if (method == CLOAK_AEAD_NONE) {
        memmove(out, plaintext, plaintext_len);
        *out_len = plaintext_len;
        return 0;
    }

    const EVP_CIPHER *cipher = pick_cipher(method);
    if (cipher == NULL) {
        return -1;
    }

    int ok = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    int len = 0;
    int ciphertext_len = 0;
    uint8_t tag[CLOAK_AEAD_TAG_LEN];

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, CLOAK_AEAD_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, out, &len, plaintext, (int)plaintext_len) != 1) goto done;
        ciphertext_len = len;
    }
    if (EVP_EncryptFinal_ex(ctx, out + ciphertext_len, &len) != 1) goto done;
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, CLOAK_AEAD_TAG_LEN, tag) != 1) goto done;
    memcpy(out + ciphertext_len, tag, CLOAK_AEAD_TAG_LEN);

    *out_len = (size_t)ciphertext_len + CLOAK_AEAD_TAG_LEN;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int cloak_aead_open(cloak_aead_method_t method,
                     const uint8_t key[CLOAK_AEAD_KEY_LEN],
                     const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len) {
    if (method == CLOAK_AEAD_NONE) {
        memmove(out, in, in_len);
        *out_len = in_len;
        return 0;
    }

    if (in_len < CLOAK_AEAD_TAG_LEN) {
        return -1;
    }

    const EVP_CIPHER *cipher = pick_cipher(method);
    if (cipher == NULL) {
        return -1;
    }

    int ok = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    size_t ciphertext_len = in_len - CLOAK_AEAD_TAG_LEN;
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, CLOAK_AEAD_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx, out, &len, in, (int)ciphertext_len) != 1) goto done;
        plaintext_len = len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, CLOAK_AEAD_TAG_LEN,
                             (void *)(in + ciphertext_len)) != 1) goto done;

    if (EVP_DecryptFinal_ex(ctx, out + plaintext_len, &len) != 1) goto done; /* auth failure lands here */
    plaintext_len += len;

    *out_len = (size_t)plaintext_len;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}
```

Add `src/aead.c` to the `add_library(cloak-common STATIC ...)` sources in `/Users/sam/Cloak-c/libcloak-common/CMakeLists.txt`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/sam/Cloak-c
cmake --build build
ctest --test-dir build --output-on-failure
```
Expected: `100% tests passed, 0 tests failed out of 3`.

- [ ] **Step 5: Commit**

```bash
cd /Users/sam/Cloak-c
git add libcloak-common/include/cloak/crypto.h libcloak-common/src/aead.c \
        libcloak-common/CMakeLists.txt libcloak-common/tests/CMakeLists.txt \
        libcloak-common/tests/test_aead.c
git commit -m "Add AEAD seal/open with AES-256-GCM and plain pass-through"
```

---

### Task 4: AEAD — add AES-128-GCM and ChaCha20-Poly1305

**Files:**
- Modify: `/Users/sam/Cloak-c/libcloak-common/src/aead.c`
- Modify: `/Users/sam/Cloak-c/libcloak-common/tests/test_aead.c`

**Interfaces:**
- Consumes: the `cloak_aead_seal`/`cloak_aead_open`/`pick_cipher` structure from Task 3.
- Produces: no new public functions — `cloak_aead_seal`/`cloak_aead_open` now also accept `CLOAK_AEAD_AES_128_GCM` and `CLOAK_AEAD_CHACHA20_POLY1305`. This is the complete, final state of the AEAD API for this plan; the frame codec (future `libcloak-mux` plan) depends on all four `cloak_aead_method_t` values working from this point on.

- [ ] **Step 1: Write the failing test**

Append to `/Users/sam/Cloak-c/libcloak-common/tests/test_aead.c`, before `TEST_MAIN_BEGIN()`:

```c
static void round_trip_for_method(cloak_aead_method_t method) {
    uint8_t key[CLOAK_AEAD_KEY_LEN];
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[] = "round trip across every supported AEAD method";
    uint8_t ciphertext[sizeof(plaintext) + CLOAK_AEAD_TAG_LEN];
    size_t ciphertext_len = 0;

    int rc = cloak_aead_seal(method, key, nonce, plaintext, sizeof(plaintext), ciphertext, &ciphertext_len);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(ciphertext_len, sizeof(plaintext) + CLOAK_AEAD_TAG_LEN);

    uint8_t decrypted[sizeof(plaintext)];
    size_t decrypted_len = 0;
    rc = cloak_aead_open(method, key, nonce, ciphertext, ciphertext_len, decrypted, &decrypted_len);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(decrypted_len, sizeof(plaintext));
    ASSERT_MEM_EQ(decrypted, plaintext, sizeof(plaintext));
}

static void test_aes128gcm_round_trip(void) {
    round_trip_for_method(CLOAK_AEAD_AES_128_GCM);
}

static void test_chacha20poly1305_round_trip(void) {
    round_trip_for_method(CLOAK_AEAD_CHACHA20_POLY1305);
}

static void test_unknown_method_fails(void) {
    uint8_t key[CLOAK_AEAD_KEY_LEN] = {0};
    uint8_t nonce[CLOAK_AEAD_NONCE_LEN] = {0};
    uint8_t plaintext[8] = {0};
    uint8_t out[8 + CLOAK_AEAD_TAG_LEN];
    size_t out_len = 0;

    int rc = cloak_aead_seal((cloak_aead_method_t)99, key, nonce, plaintext, sizeof(plaintext), out, &out_len);
    ASSERT_EQ_INT(rc, -1);
}
```

Add these calls inside `TEST_MAIN_BEGIN() ... TEST_MAIN_END()`:

```c
    test_aes128gcm_round_trip();
    test_chacha20poly1305_round_trip();
    test_unknown_method_fails();
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd /Users/sam/Cloak-c
cmake --build build
ctest --test-dir build -R test_aead --output-on-failure
```
Expected: FAIL — `test_aes128gcm_round_trip` and `test_chacha20poly1305_round_trip` fail with `ASSERT_EQ_INT(rc, 0) -> -1 != 0` (since `pick_cipher` currently returns `NULL` for those methods).

- [ ] **Step 3: Extend the implementation**

In `/Users/sam/Cloak-c/libcloak-common/src/aead.c`, replace the `pick_cipher` function:

```c
static const EVP_CIPHER *pick_cipher(cloak_aead_method_t method) {
    switch (method) {
        case CLOAK_AEAD_AES_256_GCM:
            return EVP_aes_256_gcm();
        case CLOAK_AEAD_AES_128_GCM:
            return EVP_aes_128_gcm();
        case CLOAK_AEAD_CHACHA20_POLY1305:
            return EVP_chacha20_poly1305();
        default:
            return NULL;
    }
}
```

No other changes are needed — `cloak_aead_seal`/`cloak_aead_open` already dispatch through `pick_cipher`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/sam/Cloak-c
cmake --build build
ctest --test-dir build --output-on-failure
```
Expected: `100% tests passed, 0 tests failed out of 3`.

- [ ] **Step 5: Commit**

```bash
cd /Users/sam/Cloak-c
git add libcloak-common/src/aead.c libcloak-common/tests/test_aead.c
git commit -m "Add AES-128-GCM and ChaCha20-Poly1305 to the AEAD dispatch"
```

---

### Task 5: Salsa20 stream cipher (frame-header obfuscation primitive)

**Files:**
- Modify: `/Users/sam/Cloak-c/libcloak-common/include/cloak/crypto.h`
- Create: `/Users/sam/Cloak-c/libcloak-common/src/salsa20.c`
- Modify: `/Users/sam/Cloak-c/libcloak-common/CMakeLists.txt`
- Modify: `/Users/sam/Cloak-c/libcloak-common/tests/CMakeLists.txt`
- Test: `/Users/sam/Cloak-c/libcloak-common/tests/test_salsa20.c`

**Interfaces:**
- Consumes: `cloak_random_bytes` (Task 2).
- Produces:
  ```c
  #define CLOAK_SALSA20_KEY_LEN 32
  #define CLOAK_SALSA20_NONCE_LEN 8

  void cloak_salsa20_xor(uint8_t *dst, const uint8_t *src, size_t len,
                          const uint8_t nonce[CLOAK_SALSA20_NONCE_LEN],
                          const uint8_t key[CLOAK_SALSA20_KEY_LEN]);
  ```
  Always starts keystream generation at block counter 0 (matching how Cloak uses Salsa20: a fresh call per 14-byte frame header, never resumed mid-stream). `dst` and `src` may be the same pointer (in-place XOR), matching the frame codec's usage pattern.

Note on scope: OpenSSL does not expose Salsa20 (the plain Bernstein stream cipher, distinct from XSalsa20) as an EVP cipher, so this task implements the Salsa20/20 core directly from the public-domain specification rather than wrapping a library. Correctness here is checked with round-trip and differential tests (encrypting then decrypting recovers the input; different nonces produce different keystreams; the function is deterministic). This does **not** cross-check against an external reference-implementation test vector — doing so from memory would risk hard-coding an incorrectly transcribed "known-good" value into the test suite. Before relying on this in a security-sensitive path, cross-validate the keystream output against a trusted reference (e.g. `libsodium`'s `crypto_stream_salsa20` or RFC/eSTREAM published vectors, read directly from the source rather than from memory) as a manual follow-up — tracked as a note for the code-review pass on this task, not blocking it.

- [ ] **Step 1: Write the failing test**

Add to `/Users/sam/Cloak-c/libcloak-common/include/cloak/crypto.h`, before the final `#endif`:

```c
#define CLOAK_SALSA20_KEY_LEN 32
#define CLOAK_SALSA20_NONCE_LEN 8

/* XORs len bytes of src with the Salsa20 keystream (starting at block
 * counter 0) into dst. dst and src may alias (in-place XOR). */
void cloak_salsa20_xor(uint8_t *dst, const uint8_t *src, size_t len,
                        const uint8_t nonce[CLOAK_SALSA20_NONCE_LEN],
                        const uint8_t key[CLOAK_SALSA20_KEY_LEN]);
```

Create `/Users/sam/Cloak-c/libcloak-common/tests/test_salsa20.c`:

```c
#include "cloak/common.h"
#include "cloak/crypto.h"
#include "test_framework.h"
#include <string.h>

static void test_round_trip_short_buffer(void) {
    uint8_t key[CLOAK_SALSA20_KEY_LEN];
    uint8_t nonce[CLOAK_SALSA20_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[14] = "cloak-frame-hd"; /* 14 bytes: frame header size */
    uint8_t ciphertext[14];
    uint8_t roundtrip[14];

    cloak_salsa20_xor(ciphertext, plaintext, sizeof(plaintext), nonce, key);
    ASSERT_MEM_NE(ciphertext, plaintext, sizeof(plaintext));

    cloak_salsa20_xor(roundtrip, ciphertext, sizeof(ciphertext), nonce, key);
    ASSERT_MEM_EQ(roundtrip, plaintext, sizeof(plaintext));
}

static void test_round_trip_multi_block(void) {
    uint8_t key[CLOAK_SALSA20_KEY_LEN];
    uint8_t nonce[CLOAK_SALSA20_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    uint8_t plaintext[100];
    for (size_t i = 0; i < sizeof(plaintext); i++) {
        plaintext[i] = (uint8_t)i;
    }
    uint8_t ciphertext[100];
    uint8_t roundtrip[100];

    cloak_salsa20_xor(ciphertext, plaintext, sizeof(plaintext), nonce, key);
    cloak_salsa20_xor(roundtrip, ciphertext, sizeof(ciphertext), nonce, key);
    ASSERT_MEM_EQ(roundtrip, plaintext, sizeof(plaintext));
}

static void test_in_place_xor(void) {
    uint8_t key[CLOAK_SALSA20_KEY_LEN];
    uint8_t nonce[CLOAK_SALSA20_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    uint8_t buf[14] = "in-place-test!";
    uint8_t original[14];
    memcpy(original, buf, sizeof(buf));

    cloak_salsa20_xor(buf, buf, sizeof(buf), nonce, key);
    ASSERT_MEM_NE(buf, original, sizeof(buf));

    cloak_salsa20_xor(buf, buf, sizeof(buf), nonce, key);
    ASSERT_MEM_EQ(buf, original, sizeof(buf));
}

static void test_different_nonces_give_different_keystreams(void) {
    uint8_t key[CLOAK_SALSA20_KEY_LEN];
    uint8_t nonce_a[CLOAK_SALSA20_NONCE_LEN];
    uint8_t nonce_b[CLOAK_SALSA20_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce_a, sizeof(nonce_a));
    cloak_random_bytes(nonce_b, sizeof(nonce_b));

    uint8_t zeros[32];
    memset(zeros, 0, sizeof(zeros));

    uint8_t keystream_a[32];
    uint8_t keystream_b[32];
    cloak_salsa20_xor(keystream_a, zeros, sizeof(zeros), nonce_a, key);
    cloak_salsa20_xor(keystream_b, zeros, sizeof(zeros), nonce_b, key);

    ASSERT_MEM_NE(keystream_a, keystream_b, sizeof(keystream_a));
}

static void test_deterministic_for_same_inputs(void) {
    uint8_t key[CLOAK_SALSA20_KEY_LEN];
    uint8_t nonce[CLOAK_SALSA20_NONCE_LEN];
    cloak_random_bytes(key, sizeof(key));
    cloak_random_bytes(nonce, sizeof(nonce));

    uint8_t zeros[32];
    memset(zeros, 0, sizeof(zeros));

    uint8_t out_a[32];
    uint8_t out_b[32];
    cloak_salsa20_xor(out_a, zeros, sizeof(zeros), nonce, key);
    cloak_salsa20_xor(out_b, zeros, sizeof(zeros), nonce, key);

    ASSERT_MEM_EQ(out_a, out_b, sizeof(out_a));
}

TEST_MAIN_BEGIN()
    test_round_trip_short_buffer();
    test_round_trip_multi_block();
    test_in_place_xor();
    test_different_nonces_give_different_keystreams();
    test_deterministic_for_same_inputs();
TEST_MAIN_END()
```

Add to `/Users/sam/Cloak-c/libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_salsa20 test_salsa20.c)
target_link_libraries(test_salsa20 PRIVATE cloak-common)
add_test(NAME test_salsa20 COMMAND test_salsa20)
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd /Users/sam/Cloak-c
cmake --build build
```
Expected: FAIL — linker error, `undefined reference to 'cloak_salsa20_xor'`.

- [ ] **Step 3: Write the implementation**

Create `/Users/sam/Cloak-c/libcloak-common/src/salsa20.c`:

```c
#include "cloak/crypto.h"

#include <string.h>

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* Salsa20/20 core: produces one 64-byte keystream block for the given
 * 256-bit key, 64-bit nonce, and 64-bit little-endian block counter.
 * Follows the standard diagonal state layout and the columnround/rowround
 * construction from the published Salsa20 specification. */
static void salsa20_block(const uint8_t key[CLOAK_SALSA20_KEY_LEN],
                           const uint8_t nonce[CLOAK_SALSA20_NONCE_LEN],
                           uint64_t counter, uint8_t out[64]) {
    static const uint32_t sigma[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};

    uint32_t x[16];
    x[0]  = sigma[0];
    x[1]  = load_le32(key + 0);
    x[2]  = load_le32(key + 4);
    x[3]  = load_le32(key + 8);
    x[4]  = load_le32(key + 12);
    x[5]  = sigma[1];
    x[6]  = load_le32(nonce + 0);
    x[7]  = load_le32(nonce + 4);
    x[8]  = (uint32_t)(counter & 0xffffffffu);
    x[9]  = (uint32_t)(counter >> 32);
    x[10] = sigma[2];
    x[11] = load_le32(key + 16);
    x[12] = load_le32(key + 20);
    x[13] = load_le32(key + 24);
    x[14] = load_le32(key + 28);
    x[15] = sigma[3];

    uint32_t w[16];
    memcpy(w, x, sizeof(w));

#define QR(a, b, c, d) \
    do { \
        w[b] ^= rotl32(w[a] + w[d], 7); \
        w[c] ^= rotl32(w[b] + w[a], 9); \
        w[d] ^= rotl32(w[c] + w[b], 13); \
        w[a] ^= rotl32(w[d] + w[c], 18); \
    } while (0)

    for (int i = 0; i < 10; i++) {
        /* columnround */
        QR(0, 4, 8, 12);
        QR(5, 9, 13, 1);
        QR(10, 14, 2, 6);
        QR(15, 3, 7, 11);
        /* rowround */
        QR(0, 1, 2, 3);
        QR(5, 6, 7, 4);
        QR(10, 11, 8, 9);
        QR(15, 12, 13, 14);
    }
#undef QR

    for (int i = 0; i < 16; i++) {
        store_le32(out + 4 * i, w[i] + x[i]);
    }
}

void cloak_salsa20_xor(uint8_t *dst, const uint8_t *src, size_t len,
                        const uint8_t nonce[CLOAK_SALSA20_NONCE_LEN],
                        const uint8_t key[CLOAK_SALSA20_KEY_LEN]) {
    uint8_t block[64];
    uint64_t counter = 0;
    size_t offset = 0;

    while (offset < len) {
        salsa20_block(key, nonce, counter, block);
        size_t chunk = len - offset;
        if (chunk > 64) {
            chunk = 64;
        }
        for (size_t i = 0; i < chunk; i++) {
            dst[offset + i] = (uint8_t)(src[offset + i] ^ block[i]);
        }
        offset += chunk;
        counter++;
    }
}
```

Add `src/salsa20.c` to the `add_library(cloak-common STATIC ...)` sources in `/Users/sam/Cloak-c/libcloak-common/CMakeLists.txt`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/sam/Cloak-c
cmake --build build
ctest --test-dir build --output-on-failure
```
Expected: `100% tests passed, 0 tests failed out of 4`.

- [ ] **Step 5: Commit**

```bash
cd /Users/sam/Cloak-c
git add libcloak-common/include/cloak/crypto.h libcloak-common/src/salsa20.c \
        libcloak-common/CMakeLists.txt libcloak-common/tests/CMakeLists.txt \
        libcloak-common/tests/test_salsa20.c
git commit -m "Add Salsa20 stream cipher for frame-header obfuscation"
```

---

### Task 6: X25519 key generation and ECDH shared secret

**Files:**
- Modify: `/Users/sam/Cloak-c/libcloak-common/include/cloak/crypto.h`
- Create: `/Users/sam/Cloak-c/libcloak-common/src/x25519.c`
- Modify: `/Users/sam/Cloak-c/libcloak-common/CMakeLists.txt`
- Modify: `/Users/sam/Cloak-c/libcloak-common/tests/CMakeLists.txt`
- Test: `/Users/sam/Cloak-c/libcloak-common/tests/test_x25519.c`

**Interfaces:**
- Consumes: nothing new (uses OpenSSL directly, like `aead.c`).
- Produces:
  ```c
  #define CLOAK_X25519_KEY_LEN 32

  int cloak_x25519_generate_keypair(uint8_t priv[CLOAK_X25519_KEY_LEN],
                                     uint8_t pub[CLOAK_X25519_KEY_LEN]);

  int cloak_x25519_shared_secret(const uint8_t priv[CLOAK_X25519_KEY_LEN],
                                  const uint8_t peer_pub[CLOAK_X25519_KEY_LEN],
                                  uint8_t out_secret[CLOAK_X25519_KEY_LEN]);
  ```
  Both return `0` on success, `-1` on failure. This is the last primitive this plan builds; together with `cloak_aead_*` and `cloak_salsa20_xor` it gives the future auth-handshake plan (in `libcloak-server`/`libcloak-client`) everything it needs: `cloak_x25519_generate_keypair` for the client's ephemeral keypair and the server's static keypair (also reachable from the `ck-server -key` CLI flag), `cloak_x25519_shared_secret` for the ECDH step, `cloak_aead_seal`/`open` to encrypt/decrypt the auth payload, and `cloak_random_bytes` for UID generation (`ck-server -uid`).

- [ ] **Step 1: Write the failing test**

Add to `/Users/sam/Cloak-c/libcloak-common/include/cloak/crypto.h`, before the final `#endif`:

```c
#define CLOAK_X25519_KEY_LEN 32

/* Generates a fresh X25519 keypair. Returns 0 on success, -1 on failure. */
int cloak_x25519_generate_keypair(uint8_t priv[CLOAK_X25519_KEY_LEN],
                                   uint8_t pub[CLOAK_X25519_KEY_LEN]);

/* Computes the ECDH shared secret between priv and peer_pub. Returns 0 on
 * success, -1 on failure. */
int cloak_x25519_shared_secret(const uint8_t priv[CLOAK_X25519_KEY_LEN],
                                const uint8_t peer_pub[CLOAK_X25519_KEY_LEN],
                                uint8_t out_secret[CLOAK_X25519_KEY_LEN]);
```

Create `/Users/sam/Cloak-c/libcloak-common/tests/test_x25519.c`:

```c
#include "cloak/crypto.h"
#include "test_framework.h"
#include <string.h>

static void test_keypair_generation_is_not_all_zero(void) {
    uint8_t priv[CLOAK_X25519_KEY_LEN];
    uint8_t pub[CLOAK_X25519_KEY_LEN];
    uint8_t zeros[CLOAK_X25519_KEY_LEN];
    memset(zeros, 0, sizeof(zeros));

    int rc = cloak_x25519_generate_keypair(priv, pub);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_MEM_NE(priv, zeros, sizeof(priv));
    ASSERT_MEM_NE(pub, zeros, sizeof(pub));
}

static void test_two_keypairs_are_different(void) {
    uint8_t priv_a[CLOAK_X25519_KEY_LEN];
    uint8_t pub_a[CLOAK_X25519_KEY_LEN];
    uint8_t priv_b[CLOAK_X25519_KEY_LEN];
    uint8_t pub_b[CLOAK_X25519_KEY_LEN];

    cloak_x25519_generate_keypair(priv_a, pub_a);
    cloak_x25519_generate_keypair(priv_b, pub_b);

    ASSERT_MEM_NE(pub_a, pub_b, sizeof(pub_a));
}

static void test_ecdh_agreement(void) {
    uint8_t alice_priv[CLOAK_X25519_KEY_LEN];
    uint8_t alice_pub[CLOAK_X25519_KEY_LEN];
    uint8_t bob_priv[CLOAK_X25519_KEY_LEN];
    uint8_t bob_pub[CLOAK_X25519_KEY_LEN];

    ASSERT_EQ_INT(cloak_x25519_generate_keypair(alice_priv, alice_pub), 0);
    ASSERT_EQ_INT(cloak_x25519_generate_keypair(bob_priv, bob_pub), 0);

    uint8_t secret_from_alice[CLOAK_X25519_KEY_LEN];
    uint8_t secret_from_bob[CLOAK_X25519_KEY_LEN];

    ASSERT_EQ_INT(cloak_x25519_shared_secret(alice_priv, bob_pub, secret_from_alice), 0);
    ASSERT_EQ_INT(cloak_x25519_shared_secret(bob_priv, alice_pub, secret_from_bob), 0);

    ASSERT_MEM_EQ(secret_from_alice, secret_from_bob, CLOAK_X25519_KEY_LEN);
}

static void test_ecdh_with_wrong_peer_gives_different_secret(void) {
    uint8_t alice_priv[CLOAK_X25519_KEY_LEN];
    uint8_t alice_pub[CLOAK_X25519_KEY_LEN];
    uint8_t bob_priv[CLOAK_X25519_KEY_LEN];
    uint8_t bob_pub[CLOAK_X25519_KEY_LEN];
    uint8_t eve_priv[CLOAK_X25519_KEY_LEN];
    uint8_t eve_pub[CLOAK_X25519_KEY_LEN];

    cloak_x25519_generate_keypair(alice_priv, alice_pub);
    cloak_x25519_generate_keypair(bob_priv, bob_pub);
    cloak_x25519_generate_keypair(eve_priv, eve_pub);

    uint8_t secret_with_bob[CLOAK_X25519_KEY_LEN];
    uint8_t secret_with_eve[CLOAK_X25519_KEY_LEN];
    cloak_x25519_shared_secret(alice_priv, bob_pub, secret_with_bob);
    cloak_x25519_shared_secret(alice_priv, eve_pub, secret_with_eve);

    ASSERT_MEM_NE(secret_with_bob, secret_with_eve, CLOAK_X25519_KEY_LEN);
}

TEST_MAIN_BEGIN()
    test_keypair_generation_is_not_all_zero();
    test_two_keypairs_are_different();
    test_ecdh_agreement();
    test_ecdh_with_wrong_peer_gives_different_secret();
TEST_MAIN_END()
```

Add to `/Users/sam/Cloak-c/libcloak-common/tests/CMakeLists.txt`:

```cmake
add_executable(test_x25519 test_x25519.c)
target_link_libraries(test_x25519 PRIVATE cloak-common)
add_test(NAME test_x25519 COMMAND test_x25519)
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd /Users/sam/Cloak-c
cmake --build build
```
Expected: FAIL — linker error, `undefined reference to 'cloak_x25519_generate_keypair'`.

- [ ] **Step 3: Write the implementation**

Create `/Users/sam/Cloak-c/libcloak-common/src/x25519.c`:

```c
#include "cloak/crypto.h"

#include <openssl/evp.h>

int cloak_x25519_generate_keypair(uint8_t priv[CLOAK_X25519_KEY_LEN],
                                   uint8_t pub[CLOAK_X25519_KEY_LEN]) {
    int ok = -1;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t priv_len = CLOAK_X25519_KEY_LEN;
    size_t pub_len = CLOAK_X25519_KEY_LEN;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (pctx == NULL) goto done;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto done;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto done;

    if (EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) <= 0) goto done;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) <= 0) goto done;

    ok = 0;

done:
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return ok;
}

int cloak_x25519_shared_secret(const uint8_t priv[CLOAK_X25519_KEY_LEN],
                                const uint8_t peer_pub[CLOAK_X25519_KEY_LEN],
                                uint8_t out_secret[CLOAK_X25519_KEY_LEN]) {
    int ok = -1;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t secret_len = CLOAK_X25519_KEY_LEN;

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, CLOAK_X25519_KEY_LEN);
    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, CLOAK_X25519_KEY_LEN);
    if (pkey == NULL || peer == NULL) goto done;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) goto done;

    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) goto done;
    if (EVP_PKEY_derive(ctx, out_secret, &secret_len) <= 0) goto done;

    ok = 0;

done:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (peer) EVP_PKEY_free(peer);
    return ok;
}
```

Add `src/x25519.c` to the `add_library(cloak-common STATIC ...)` sources in `/Users/sam/Cloak-c/libcloak-common/CMakeLists.txt`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/sam/Cloak-c
cmake --build build
ctest --test-dir build --output-on-failure
```
Expected: `100% tests passed, 0 tests failed out of 5`.

- [ ] **Step 5: Commit**

```bash
cd /Users/sam/Cloak-c
git add libcloak-common/include/cloak/crypto.h libcloak-common/src/x25519.c \
        libcloak-common/CMakeLists.txt libcloak-common/tests/CMakeLists.txt \
        libcloak-common/tests/test_x25519.c
git commit -m "Add X25519 key generation and ECDH shared secret"
```

---

## What comes after this plan

This plan only builds `libcloak-common`'s crypto primitives. Per the design spec's module breakdown, the next plans in dependency order are:

1. **`libcloak-common`: epoll reactor** — fd registration, edge-triggered callbacks, timer heap (spec §3).
2. **`libcloak-mux`: frame codec** — the `Frame` struct and `obfuscate`/`deobfuscate` logic (spec §4), built directly on `cloak_aead_seal/open` and `cloak_salsa20_xor` from this plan.
3. **`libcloak-common`: ClientHello templates** — captured browser bytes, offset table, SNI patcher (spec §5).
4. **`libcloak-mux`: session/stream/switchboard** — multiplexing on top of the reactor and frame codec (spec §6).
5. **`libcloak-server`**: dispatcher state machine, auth (using `cloak_x25519_shared_secret` + `cloak_aead_open` from this plan), redirect-on-fail, SQLite user manager, admin API (spec §7–8).
6. **`libcloak-client`**: connector, direct transport (using the ClientHello templates), CDN/WebSocket transport via `libssl` (spec §9).
7. **`cmd/ck-server`, `cmd/ck-client`**: CLI binaries wiring the above together, config parsing via `cJSON` (spec §10).
8. Integration tests and fuzz targets spanning the assembled binaries (spec §11).

Each will get its own plan document once the preceding one is implemented and reviewed.

## Self-review notes

- **Spec coverage** (of what this plan claims to cover — crypto primitives from spec §4 and the crypto half of §10's key generation): AEAD (3 methods + none), Salsa20 header XOR, X25519 keygen/ECDH, and CSPRNG are all covered by a task each. Frame struct/obfuscate-deobfuscate, ClientHello templates, reactor, mux, dispatcher, SQLite, admin API, and CDN/WS transport are explicitly deferred to the follow-up plans listed above, not silently dropped.
- **Placeholder scan:** no TBD/TODO; every step has complete, runnable code.
- **Type consistency:** `cloak_aead_method_t`, `CLOAK_AEAD_KEY_LEN` (32), `CLOAK_AEAD_NONCE_LEN` (12), `CLOAK_AEAD_TAG_LEN` (16), `CLOAK_SALSA20_KEY_LEN` (32), `CLOAK_SALSA20_NONCE_LEN` (8), and `CLOAK_X25519_KEY_LEN` (32) are defined once (Task 3, 5, 6 respectively) and used with the same names and sizes in every later task and in the "what comes after" dependency notes.
