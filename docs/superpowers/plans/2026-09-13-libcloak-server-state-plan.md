# libcloak-server: First Packet, Server State and Session Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the three pieces the server dispatcher stands on — a resumable first-packet accumulator that never over-reads, the runtime state derived once from a parsed config, and a registry that owns sessions keyed by UID and session ID — so the dispatcher itself is left to be wiring rather than invention.

**Architecture:** Each piece is independently testable without a socket, or with nothing more than a socketpair. `cloak_firstpacket_t` is a pure state machine over bytes: the caller asks it how many bytes to read next, reads exactly that many, and feeds them back, which is what makes over-reading structurally impossible rather than merely avoided. `cloak_server_t` is the one place a `cloak_server_config_t` turns into things the data path can use without blocking — resolved addresses, a replay cache, and a bypass set that finally includes the admin UID. `cloak_server_registry_t` owns `cloak_session_t` objects and, critically, the teardown discipline the stream relay's contract demands: nothing may free a session while a relay still points at it.

**Tech Stack:** C11, CMake, CTest with the project's existing assert-based test framework.

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` §7 (server dispatcher and redirect-on-fail) — this plan builds everything §7's `dispatch_conn()` needs except the dispatch loop itself.

## Global Constraints

- Language: C11, `-Wall -Wextra` clean. Project code must produce zero warnings.
- Platform: Linux only. POSIX APIs are reached by defining `_POSIX_C_SOURCE 200809L` as the first line of the `.c` file that needs them.
- Naming: public symbols prefixed `cloak_`; headers in `libcloak-server/include/cloak/` with `CLOAK_<NAME>_H` guards; doc comments in the style of `cloak/crypto.h`, `cloak/net.h` and `cloak/stream_relay.h` — contract, failure modes, and anything a caller could get wrong.
- Errors: 0/-1, with a human-readable reason written into a caller-supplied `char *err, size_t err_cap` that may be NULL, matching `cloak/config.h` and `cloak/net.h`.
- **Everything on the data path must be non-blocking.** The one permitted exception is name resolution, which `cloak_net_resolve` documents as startup-only — `cloak_server_init` is exactly the startup moment where it is allowed, and the only place in this plan where it may appear.
- Existing tests are the regression net: every test in the suite must keep passing **unmodified**.
- **Append to `libcloak-server/CMakeLists.txt` and `libcloak-server/tests/CMakeLists.txt`; never rewrite them.** All three tasks touch both. The test include-dir convention in that file is `${CMAKE_SOURCE_DIR}/libcloak-common/tests`, where `test_framework.h` lives. Give every new test a `TIMEOUT 60` property — this project has produced two flaky hanging tests already, both found only by repetition.
- `libcloak-server` currently links `cloak-common` PUBLIC. Task 3 needs `cloak-mux` as well; add it there, not earlier.
- Build and test (Linux-only project, so everything runs in the `cloak-c-dev` image; `-w /src` would silently build the main checkout, which has bitten this project before):

  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/<branch> cloak-c-dev bash -c \
    'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
  ```

  Sanitizer build: `-B build-asan` with `-DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"`.
- Baseline: 30 tests pass before this plan; 33 after it.
- Reference implementation: the Go original at `/Users/sam/Cloak` — `internal/server/dispatcher.go` (`readFirstPacket`, `dispatchConnection`), `internal/server/state.go` (`InitState`, `IsBypass`), `internal/server/userpanel.go` and `activeuser.go` (the session registry this plan's Task 3 is a reduced form of).

---

### Task 1: `cloak_firstpacket_t` — a first-packet accumulator that cannot over-read

Go's `readFirstPacket` uses blocking `io.ReadFull` calls sized to exactly what it needs, so it never consumes a byte past the first packet. A reactor cannot block, but it can preserve the same property: this object tells the caller exactly how many bytes to read next, and the caller reads exactly that many.

That matters more than it looks. After a successful handshake the file descriptor is handed to `cloak_session_add_conn`, which wraps it in a `cloak_conn_t` that starts reading from wherever the kernel left off. Any byte this layer read past the first packet would be silently lost, and the session would desynchronise on its very first frame.

**Files:**
- Create: `libcloak-server/include/cloak/firstpacket.h`
- Create: `libcloak-server/src/firstpacket.c`
- Create: `libcloak-server/tests/test_firstpacket.c`
- Modify: `libcloak-server/CMakeLists.txt` (add `src/firstpacket.c`)
- Modify: `libcloak-server/tests/CMakeLists.txt` (register `test_firstpacket`)

**Interfaces:**
- Consumes: nothing (a pure state machine over bytes).
- Produces:
  - `cloak_firstpacket_t`, `cloak_firstpacket_status_t`, `cloak_firstpacket_transport_t`, `CLOAK_FIRSTPACKET_MAX`.
  - `void cloak_firstpacket_init(cloak_firstpacket_t *fp);`
  - `size_t cloak_firstpacket_want(const cloak_firstpacket_t *fp);`
  - `cloak_firstpacket_status_t cloak_firstpacket_feed(cloak_firstpacket_t *fp, const uint8_t *data, size_t len);`
  - `const uint8_t *cloak_firstpacket_data(const cloak_firstpacket_t *fp);` and `size_t cloak_firstpacket_len(const cloak_firstpacket_t *fp);`
  - `int cloak_firstpacket_redirect_on_error(const cloak_firstpacket_t *fp);`

- [ ] **Step 1: Write the failing test**

Create `libcloak-server/tests/test_firstpacket.c`:

```c
#include "cloak/firstpacket.h"
#include "test_framework.h"

#include <string.h>

/* Feeds data one byte at a time, never offering more than want() asks
 * for, and returns the final status. This is the calling discipline the
 * dispatcher itself will use, so testing through it tests the real
 * contract rather than a convenient shortcut. */
static cloak_firstpacket_status_t feed_all(cloak_firstpacket_t *fp,
                                           const uint8_t *data, size_t len,
                                           size_t *consumed_out) {
    size_t off = 0;
    cloak_firstpacket_status_t st = CLOAK_FIRSTPACKET_NEED_MORE;
    while (off < len) {
        size_t want = cloak_firstpacket_want(fp);
        if (want == 0) {
            break;
        }
        size_t chunk = len - off;
        if (chunk > want) {
            chunk = want;
        }
        st = cloak_firstpacket_feed(fp, data + off, chunk);
        off += chunk;
        if (st != CLOAK_FIRSTPACKET_NEED_MORE) {
            break;
        }
    }
    if (consumed_out != NULL) {
        *consumed_out = off;
    }
    return st;
}

/* A minimal but structurally valid TLS record: 0x16, version, length,
 * then length bytes of body. The body's contents do not matter here --
 * this layer only frames the record, it does not parse the ClientHello. */
static size_t make_tls_record(uint8_t *out, size_t body_len) {
    out[0] = 0x16;
    out[1] = 0x03;
    out[2] = 0x01;
    out[3] = (uint8_t)((body_len >> 8) & 0xff);
    out[4] = (uint8_t)(body_len & 0xff);
    for (size_t i = 0; i < body_len; i++) {
        out[5 + i] = (uint8_t)(i & 0xff);
    }
    return 5 + body_len;
}

static void test_tls_record_assembled_from_single_bytes(void) {
    uint8_t record[1024];
    size_t record_len = make_tls_record(record, 512);

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    size_t consumed = 0;
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE, feed_all(&fp, record, record_len, &consumed));
    ASSERT_EQ_INT((int)record_len, (int)consumed);
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_TRANSPORT_TLS, (int)fp.transport);
    ASSERT_EQ_INT((int)record_len, (int)cloak_firstpacket_len(&fp));
    ASSERT_MEM_EQ(cloak_firstpacket_data(&fp), record, record_len);
}

static void test_never_asks_for_more_than_the_record(void) {
    /* The property the whole object exists for: after the record is
     * complete, want() is 0, so a caller driven by want() cannot consume
     * a byte that belongs to the session's first frame. */
    uint8_t record[1024];
    size_t record_len = make_tls_record(record, 100);

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    /* Offer far more than the record contains, in one go. */
    uint8_t stream[2048];
    memcpy(stream, record, record_len);
    memset(stream + record_len, 0xEE, sizeof(stream) - record_len);

    size_t consumed = 0;
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE, feed_all(&fp, stream, sizeof(stream), &consumed));
    ASSERT_EQ_INT((int)record_len, (int)consumed);
    ASSERT_EQ_INT(0, (int)cloak_firstpacket_want(&fp));
    ASSERT_EQ_INT((int)record_len, (int)cloak_firstpacket_len(&fp));
}

static void test_http_request_terminated_by_blank_line(void) {
    const char *req =
        "GET /ws HTTP/1.1\r\n"
        "Host: cdn.example\r\n"
        "Upgrade: websocket\r\n"
        "hidden: QUJD\r\n"
        "\r\n";
    size_t req_len = strlen(req);

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    size_t consumed = 0;
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE,
                  feed_all(&fp, (const uint8_t *)req, req_len, &consumed));
    ASSERT_EQ_INT((int)req_len, (int)consumed);
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET, (int)fp.transport);
    ASSERT_EQ_INT((int)req_len, (int)cloak_firstpacket_len(&fp));
    ASSERT_MEM_EQ(cloak_firstpacket_data(&fp), req, req_len);
}

static void test_http_stops_exactly_at_the_blank_line(void) {
    /* Same over-read property as the TLS case: a pipelined body after the
     * headers must not be consumed. */
    const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    size_t req_len = strlen(req);
    uint8_t stream[256];
    memcpy(stream, req, req_len);
    memset(stream + req_len, 'Z', sizeof(stream) - req_len);

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    size_t consumed = 0;
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE, feed_all(&fp, stream, sizeof(stream), &consumed));
    ASSERT_EQ_INT((int)req_len, (int)consumed);
    ASSERT_EQ_INT(0, (int)cloak_firstpacket_want(&fp));
}

static void test_unrecognised_first_byte_is_a_redirectable_error(void) {
    /* Go's readFirstPacket returns redirOnErr = true here: an unknown
     * protocol is exactly the case the server must forward to RedirAddr
     * rather than drop. */
    const uint8_t junk[] = {0x41, 0x42, 0x43};

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_ERROR, cloak_firstpacket_feed(&fp, junk, 1));
    ASSERT_EQ_INT(1, cloak_firstpacket_redirect_on_error(&fp));
    /* the byte that revealed the protocol is still buffered, because
     * goWeb must forward everything the client already sent */
    ASSERT_EQ_INT(1, (int)cloak_firstpacket_len(&fp));
    ASSERT_EQ_INT(0x41, cloak_firstpacket_data(&fp)[0]);
}

static void test_oversized_tls_record_is_a_redirectable_error(void) {
    /* A record whose declared length cannot fit in the buffer. Go treats
     * this as io.ErrShortBuffer with redirOnErr = true. */
    uint8_t header[5];
    header[0] = 0x16;
    header[1] = 0x03;
    header[2] = 0x01;
    header[3] = 0xff;
    header[4] = 0xff; /* 65535 bytes, far beyond CLOAK_FIRSTPACKET_MAX */

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    cloak_firstpacket_status_t st = CLOAK_FIRSTPACKET_NEED_MORE;
    for (size_t i = 0; i < sizeof(header) && st == CLOAK_FIRSTPACKET_NEED_MORE; i++) {
        st = cloak_firstpacket_feed(&fp, header + i, 1);
    }
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_ERROR, st);
    ASSERT_EQ_INT(1, cloak_firstpacket_redirect_on_error(&fp));
}

static void test_oversized_http_headers_are_a_redirectable_error(void) {
    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    uint8_t byte = 'G';
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_NEED_MORE, cloak_firstpacket_feed(&fp, &byte, 1));

    /* Feed a header line that never ends. */
    cloak_firstpacket_status_t st = CLOAK_FIRSTPACKET_NEED_MORE;
    byte = 'x';
    for (size_t i = 0; i < CLOAK_FIRSTPACKET_MAX + 16; i++) {
        st = cloak_firstpacket_feed(&fp, &byte, 1);
        if (st != CLOAK_FIRSTPACKET_NEED_MORE) {
            break;
        }
    }
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_ERROR, st);
    ASSERT_EQ_INT(1, cloak_firstpacket_redirect_on_error(&fp));
    ASSERT_TRUE(cloak_firstpacket_len(&fp) <= CLOAK_FIRSTPACKET_MAX);
}

static void test_feed_after_done_is_rejected(void) {
    uint8_t record[64];
    size_t record_len = make_tls_record(record, 8);

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE, feed_all(&fp, record, record_len, NULL));

    uint8_t extra = 0x00;
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE, cloak_firstpacket_feed(&fp, &extra, 1));
    /* and the buffered packet is unchanged */
    ASSERT_EQ_INT((int)record_len, (int)cloak_firstpacket_len(&fp));
}

static void test_zero_length_tls_record_is_an_error(void) {
    uint8_t header[5] = {0x16, 0x03, 0x01, 0x00, 0x00};

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    cloak_firstpacket_status_t st = CLOAK_FIRSTPACKET_NEED_MORE;
    for (size_t i = 0; i < sizeof(header) && st == CLOAK_FIRSTPACKET_NEED_MORE; i++) {
        st = cloak_firstpacket_feed(&fp, header + i, 1);
    }
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_ERROR, st);
    ASSERT_EQ_INT(1, cloak_firstpacket_redirect_on_error(&fp));
}

TEST_MAIN_BEGIN()
    test_tls_record_assembled_from_single_bytes();
    test_never_asks_for_more_than_the_record();
    test_http_request_terminated_by_blank_line();
    test_http_stops_exactly_at_the_blank_line();
    test_unrecognised_first_byte_is_a_redirectable_error();
    test_oversized_tls_record_is_a_redirectable_error();
    test_oversized_http_headers_are_a_redirectable_error();
    test_feed_after_done_is_rejected();
    test_zero_length_tls_record_is_an_error();
TEST_MAIN_END()
```

- [ ] **Step 2: Run the test to verify it fails**

Build. Expected: FAIL — `cloak/firstpacket.h: No such file or directory`.

- [ ] **Step 3: Write the header**

Create `libcloak-server/include/cloak/firstpacket.h`:

```c
#ifndef CLOAK_FIRSTPACKET_H
#define CLOAK_FIRSTPACKET_H

#include <stddef.h>
#include <stdint.h>

/* Accumulates a connection's first packet across non-blocking reads,
 * identifying which transport it belongs to, without ever consuming a
 * byte past the end of that packet.
 *
 * That last property is the reason this object exists rather than a plain
 * buffer. After a successful handshake the file descriptor is handed to
 * cloak_session_add_conn, which wraps it in a cloak_conn_t that reads
 * from wherever the kernel left off -- so a byte read past the first
 * packet here would be silently lost and the session would desynchronise
 * on its very first frame. The caller therefore does not choose how much
 * to read: it asks cloak_firstpacket_want, reads exactly that many bytes,
 * and feeds them back. Go gets the same guarantee from blocking
 * io.ReadFull calls sized to exactly what it needs
 * (internal/server/dispatcher.go, readFirstPacket).
 *
 * This layer only FRAMES the packet -- it decides where the packet ends
 * and which transport it is, nothing more. Parsing a ClientHello is
 * cloak_clienthello_parse's job, and authenticating it is
 * cloak_server_auth_decrypt's. */

/* Go Cloak's firstPacketSize. Large enough for a modern Chrome
 * ClientHello, which passed 1500 bytes when uTLS updated its
 * fingerprints. */
#define CLOAK_FIRSTPACKET_MAX 3000

typedef enum {
    CLOAK_FIRSTPACKET_NEED_MORE = 0,
    CLOAK_FIRSTPACKET_DONE = 1,
    CLOAK_FIRSTPACKET_ERROR = -1,
} cloak_firstpacket_status_t;

typedef enum {
    CLOAK_FIRSTPACKET_TRANSPORT_UNKNOWN = 0,
    CLOAK_FIRSTPACKET_TRANSPORT_TLS = 1,      /* first byte 0x16: a TLS record */
    CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET = 2, /* first byte 'G': an HTTP GET */
} cloak_firstpacket_transport_t;

typedef struct {
    uint8_t buf[CLOAK_FIRSTPACKET_MAX];
    size_t len;

    cloak_firstpacket_transport_t transport;
    cloak_firstpacket_status_t status;

    /* For the TLS path: the total packet length once the 5-byte record
     * header has been read, or 0 while it has not. */
    size_t record_total;

    /* For the WebSocket path: how many of the four bytes of the
     * terminating CRLFCRLF have been matched so far. */
    unsigned crlf_state;

    /* Go's redirOnErr: whether a failure here should still be forwarded
     * to RedirAddr rather than dropped. */
    int redirect_on_error;
} cloak_firstpacket_t;

/* Resets fp to its starting state. Must be called before any other
 * function; a cloak_firstpacket_t is not usable zero-initialized. */
void cloak_firstpacket_init(cloak_firstpacket_t *fp);

/* How many bytes the caller should read and feed next. Never returns more
 * than the packet has left, which is what makes over-reading impossible.
 * Returns 0 once the packet is complete or an error has been reported --
 * a caller that reads when want() is 0 is reading bytes that belong to
 * the next layer.
 *
 * On the WebSocket path this returns 1: HTTP headers have no length to
 * read ahead of, so the request is consumed one byte at a time, exactly
 * as Go's connReadLine does. That is a handshake-time cost of a few
 * hundred syscalls per connection, paid once, in exchange for the
 * no-over-read guarantee. */
size_t cloak_firstpacket_want(const cloak_firstpacket_t *fp);

/* Feeds len bytes. len must not exceed cloak_firstpacket_want(fp); bytes
 * beyond that are ignored rather than buffered, so a caller that ignores
 * want() loses data rather than corrupting the packet.
 *
 * Returns CLOAK_FIRSTPACKET_NEED_MORE (feed more), CLOAK_FIRSTPACKET_DONE
 * (the packet is complete and available via cloak_firstpacket_data), or
 * CLOAK_FIRSTPACKET_ERROR. Once DONE or ERROR is returned, further feeds
 * change nothing and return that same status.
 *
 * Every error this object can report is a REDIRECTABLE one -- an
 * unrecognised protocol, an oversized record, a request whose headers
 * never end. Those are all cases where Go forwards the connection to
 * RedirAddr rather than closing it, because closing would tell a prober
 * that something other than a web server is listening. Check
 * cloak_firstpacket_redirect_on_error rather than assuming. */
cloak_firstpacket_status_t cloak_firstpacket_feed(cloak_firstpacket_t *fp,
                                                   const uint8_t *data, size_t len);

/* The bytes accumulated so far. Valid until fp is re-initialized. After
 * an error this holds everything read before the error was detected,
 * which is exactly what the redirect path must forward -- a prober must
 * see its own bytes reach a real web server. */
const uint8_t *cloak_firstpacket_data(const cloak_firstpacket_t *fp);
size_t cloak_firstpacket_len(const cloak_firstpacket_t *fp);

/* 1 if a reported error should be handled by forwarding to RedirAddr.
 * Meaningless unless cloak_firstpacket_feed returned
 * CLOAK_FIRSTPACKET_ERROR. */
int cloak_firstpacket_redirect_on_error(const cloak_firstpacket_t *fp);

#endif
```

- [ ] **Step 4: Write the implementation**

Create `libcloak-server/src/firstpacket.c`:

```c
#include "cloak/firstpacket.h"

#include <string.h>

#define TLS_RECORD_HEADER_LEN 5

void cloak_firstpacket_init(cloak_firstpacket_t *fp) {
    if (fp == NULL) {
        return;
    }
    memset(fp, 0, sizeof(*fp));
    fp->transport = CLOAK_FIRSTPACKET_TRANSPORT_UNKNOWN;
    fp->status = CLOAK_FIRSTPACKET_NEED_MORE;
}

size_t cloak_firstpacket_want(const cloak_firstpacket_t *fp) {
    if (fp == NULL || fp->status != CLOAK_FIRSTPACKET_NEED_MORE) {
        return 0;
    }
    switch (fp->transport) {
    case CLOAK_FIRSTPACKET_TRANSPORT_UNKNOWN:
        return 1; /* the first byte decides which protocol this is */
    case CLOAK_FIRSTPACKET_TRANSPORT_TLS:
        if (fp->len < TLS_RECORD_HEADER_LEN) {
            return TLS_RECORD_HEADER_LEN - fp->len;
        }
        return fp->record_total - fp->len;
    case CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET:
        return 1; /* headers have no length to read ahead of */
    }
    return 0;
}

static cloak_firstpacket_status_t fail(cloak_firstpacket_t *fp, int redirect) {
    fp->status = CLOAK_FIRSTPACKET_ERROR;
    fp->redirect_on_error = redirect;
    return fp->status;
}

/* Appends one byte, or fails if the buffer is full. */
static int push_byte(cloak_firstpacket_t *fp, uint8_t b) {
    if (fp->len >= CLOAK_FIRSTPACKET_MAX) {
        return -1;
    }
    fp->buf[fp->len++] = b;
    return 0;
}

cloak_firstpacket_status_t cloak_firstpacket_feed(cloak_firstpacket_t *fp,
                                                   const uint8_t *data, size_t len) {
    if (fp == NULL) {
        return CLOAK_FIRSTPACKET_ERROR;
    }
    if (fp->status != CLOAK_FIRSTPACKET_NEED_MORE) {
        return fp->status;
    }
    if (data == NULL || len == 0) {
        return fp->status;
    }

    size_t want = cloak_firstpacket_want(fp);
    if (len > want) {
        len = want; /* a caller that ignores want() loses the excess */
    }

    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];

        if (fp->transport == CLOAK_FIRSTPACKET_TRANSPORT_UNKNOWN) {
            /* Buffer the deciding byte first: the redirect path must
             * forward everything the client already sent, including the
             * byte that made us give up on it. */
            if (push_byte(fp, b) != 0) {
                return fail(fp, 1);
            }
            if (b == 0x16) {
                fp->transport = CLOAK_FIRSTPACKET_TRANSPORT_TLS;
            } else if (b == 'G') {
                fp->transport = CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET;
            } else {
                /* Go's ErrUnrecognisedProtocol, with redirOnErr = true. */
                return fail(fp, 1);
            }
            continue;
        }

        if (push_byte(fp, b) != 0) {
            return fail(fp, 1);
        }

        if (fp->transport == CLOAK_FIRSTPACKET_TRANSPORT_TLS) {
            if (fp->len == TLS_RECORD_HEADER_LEN) {
                size_t body = ((size_t)fp->buf[3] << 8) | (size_t)fp->buf[4];
                if (body == 0) {
                    /* A record with no body is not a ClientHello and
                     * would leave want() at 0 with nothing parsed. */
                    return fail(fp, 1);
                }
                size_t total = TLS_RECORD_HEADER_LEN + body;
                if (total > CLOAK_FIRSTPACKET_MAX) {
                    /* Go's io.ErrShortBuffer path, redirOnErr = true. */
                    return fail(fp, 1);
                }
                fp->record_total = total;
            }
            if (fp->record_total != 0 && fp->len == fp->record_total) {
                fp->status = CLOAK_FIRSTPACKET_DONE;
                return fp->status;
            }
            continue;
        }

        /* WebSocket: consume until a blank line ends the headers. The
         * state machine matches CR, LF, CR, LF in order; any other byte
         * restarts it, except that a CR restarts it at 1 rather than 0
         * so "\r\r\n\r\n" is still recognised. */
        if (b == '\r') {
            fp->crlf_state = (fp->crlf_state == 2) ? 3 : 1;
        } else if (b == '\n') {
            if (fp->crlf_state == 1) {
                fp->crlf_state = 2;
            } else if (fp->crlf_state == 3) {
                fp->status = CLOAK_FIRSTPACKET_DONE;
                return fp->status;
            } else {
                fp->crlf_state = 0;
            }
        } else {
            fp->crlf_state = 0;
        }
    }

    return fp->status;
}

const uint8_t *cloak_firstpacket_data(const cloak_firstpacket_t *fp) {
    return fp == NULL ? NULL : fp->buf;
}

size_t cloak_firstpacket_len(const cloak_firstpacket_t *fp) {
    return fp == NULL ? 0 : fp->len;
}

int cloak_firstpacket_redirect_on_error(const cloak_firstpacket_t *fp) {
    return fp == NULL ? 0 : fp->redirect_on_error;
}
```

- [ ] **Step 5: Wire it into the build**

Add `src/firstpacket.c` to `libcloak-server/CMakeLists.txt`'s source list, and append to `libcloak-server/tests/CMakeLists.txt`:

```cmake
add_executable(test_firstpacket test_firstpacket.c)
target_include_directories(test_firstpacket PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_firstpacket PRIVATE cloak-server)
add_test(NAME test_firstpacket COMMAND test_firstpacket)
set_tests_properties(test_firstpacket PROPERTIES TIMEOUT 60)
```

- [ ] **Step 6: Run the tests to verify they pass**

`ctest -R test_firstpacket`, then the full suite: 31 tests.

- [ ] **Step 7: Commit**

```bash
git add libcloak-server/include/cloak/firstpacket.h libcloak-server/src/firstpacket.c \
        libcloak-server/tests/test_firstpacket.c libcloak-server/CMakeLists.txt \
        libcloak-server/tests/CMakeLists.txt
git commit -m "Add firstpacket: frame a connection's first packet without over-reading"
```

---

### Task 2: `cloak_server_t` — runtime state derived once from a config

`cloak_server_config_t` holds what the config file said. This holds what the data path needs: resolved addresses (because resolution blocks and may only happen at startup), a replay cache, and the bypass set with the admin UID finally folded in.

**That last item is an obligation carried forward from the config module's own plan**, recorded there and in `cloak/config.h`: `cloak_server_config_t.bypass_uid` holds exactly what the file listed and deliberately excludes `admin_uid`, because Go performs that union in `InitState` — runtime state, not config. This task is that `InitState`. Getting it wrong means the admin user is subject to credit and bandwidth accounting.

**Files:**
- Create: `libcloak-server/include/cloak/server.h`
- Create: `libcloak-server/src/server.c`
- Create: `libcloak-server/tests/test_server_state.c`
- Modify: `libcloak-server/CMakeLists.txt` (add `src/server.c`)
- Modify: `libcloak-server/tests/CMakeLists.txt` (register `test_server_state`)

**Interfaces:**
- Consumes: `cloak_server_config_t`, `CLOAK_UID_LEN`, `CLOAK_MAX_PROXY_BOOK`, `CLOAK_MAX_BYPASS_UID` (`cloak/config.h`); `cloak_net_resolve`, `cloak_addr_t` (`cloak/net.h`); `cloak_replay_cache_init/destroy/check_and_insert` (`cloak/replay_cache.h`); `CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS` (`cloak/server_auth.h`).
- Produces:
  - `cloak_server_t` and `int cloak_server_init(cloak_server_t *srv, const cloak_server_config_t *cfg, size_t replay_cache_capacity, char *err, size_t err_cap);`
  - `void cloak_server_destroy(cloak_server_t *srv);`
  - `int cloak_server_is_bypass(const cloak_server_t *srv, const uint8_t uid[CLOAK_UID_LEN]);`
  - `int cloak_server_is_admin(const cloak_server_t *srv, const uint8_t uid[CLOAK_UID_LEN]);`
  - `const cloak_addr_t *cloak_server_lookup_proxy(const cloak_server_t *srv, const char *proxy_method);`
  - `int cloak_server_redir_addr(const cloak_server_t *srv, uint16_t local_port, cloak_addr_t *out);`
  - `int cloak_server_check_replay(cloak_server_t *srv, const uint8_t random[32], int64_t now_unix);`

**Two details that are easy to get wrong, and why:**

1. **`RedirAddr` may have no port.** Go's `parseRedirAddr` accepts a bare host, and `goWeb` then uses the port the client connected to — so a prober hitting :443 gets forwarded to the cover site's :443, and one hitting :80 gets :80. Resolution must still happen once at startup, so `cloak_server_init` resolves the host with whatever port the config gave (or a placeholder), records whether the config supplied one, and `cloak_server_redir_addr` copies the resolved address and patches in the per-connection port when it did not. Patching a port is a two-line switch on `sa_family`; re-resolving per connection would put a blocking DNS lookup on the accept path, which is exactly what the design forbids.

2. **Proxy-method lookup is case-insensitive on a name that arrives from the wire.** `cloak_server_config_parse_json` already lower-cases the `ProxyBook` keys; the method in an authenticated payload is attacker-chosen and arrives as written. Compare case-insensitively, and bound the comparison by `CLOAK_PROXY_METHOD_LEN` — `cloak_server_clientinfo_t.proxy_method` is NUL-terminated, but treating a wire string as trustworthy is how this kind of code goes wrong.

- [ ] **Step 1: Write the failing test**

Create `libcloak-server/tests/test_server_state.c`. It needs no sockets — build a `cloak_server_config_t` by parsing JSON through `cloak_server_config_parse_json` (the real path, not a hand-filled struct), then assert on the runtime state. Cover:

```c
/* 1. The admin UID is in the bypass set. Parse a config with one
 *    BypassUID and a distinct AdminUID, and assert cloak_server_is_bypass
 *    returns 1 for BOTH, while the config struct itself still reports
 *    num_bypass_uid == 1. This is the carried-forward obligation; assert
 *    both halves so a future change that "simplifies" either layer fails
 *    here.
 *
 * 2. A config with no AdminUID leaves the bypass set at exactly the
 *    file's entries, and cloak_server_is_admin returns 0 for everything.
 *
 * 3. Proxy lookup: a ProxyBook entry written "ShadowSocks" in the file is
 *    found by the wire name "shadowsocks", "SHADOWSOCKS" and
 *    "ShadowSocks"; an unknown method returns NULL; a method that is a
 *    prefix of a real one ("shadow") returns NULL.
 *
 * 4. RedirAddr with an explicit port resolves to that port regardless of
 *    the local_port argument; RedirAddr without a port takes local_port.
 *    Use 127.0.0.1 so the test never depends on DNS. Assert on the port
 *    actually present in the returned sockaddr, not merely on the return
 *    code.
 *
 * 5. Replay: the same 32-byte random is accepted once and rejected the
 *    second time; a different random is accepted. (The replay cache has
 *    its own thorough tests -- this only pins that the server wired it up
 *    with the right age limit, so also assert a key inserted more than
 *    CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS ago is accepted
 *    again by passing a later now_unix.)
 *
 * 6. cloak_server_init rejects a config whose RedirAddr cannot resolve,
 *    with the reason in err, and leaves srv safe to pass to
 *    cloak_server_destroy. Use the fresh-0xAA-struct pattern and assert a
 *    sentinel directly -- a struct an earlier successful call zeroed
 *    would pass either way, which is how an equivalent test elsewhere in
 *    this project failed to catch anything.
 *
 * 7. cloak_server_destroy is idempotent and safe on a zeroed struct.
 */
```

Write these as real test functions with real assertions, following the style of `libcloak-common/tests/test_config_server.c` for building config JSON with `snprintf`.

- [ ] **Step 2: Run the test to verify it fails**

Expected: FAIL — `cloak/server.h: No such file or directory`.

- [ ] **Step 3: Write the header**

Create `libcloak-server/include/cloak/server.h`:

```c
#ifndef CLOAK_SERVER_H
#define CLOAK_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/config.h"
#include "cloak/net.h"
#include "cloak/replay_cache.h"

/* The server's runtime state: everything derived once, at startup, from a
 * parsed cloak_server_config_t so the data path never has to block or
 * re-derive it. This is the equivalent of Go Cloak's InitState
 * (internal/server/state.go).
 *
 * It borrows the config rather than copying it: cfg must outlive the
 * cloak_server_t. */
typedef struct {
    const cloak_server_config_t *cfg;

    cloak_replay_cache_t replay;

    /* Resolved once. redir_has_port records whether the config supplied
     * one; when it did not, cloak_server_redir_addr patches in the port
     * the client connected to. */
    cloak_addr_t redir;
    int redir_has_port;

    /* Parallel to cfg->proxy_book, resolved. */
    cloak_addr_t proxy[CLOAK_MAX_PROXY_BOOK];

    /* The config's BypassUID entries PLUS admin_uid when the config had
     * one -- the union Go performs in InitState. cfg->bypass_uid
     * deliberately does not include the admin UID; see cloak/config.h. */
    uint8_t bypass[CLOAK_MAX_BYPASS_UID + 1][CLOAK_UID_LEN];
    size_t num_bypass;
} cloak_server_t;

/* Derives runtime state from cfg. Resolves RedirAddr and every ProxyBook
 * entry, which BLOCKS -- that is permitted here and only here, because
 * this runs at startup, and it is why the data path can dial without a
 * lookup. Allocates the replay cache with replay_cache_capacity slots.
 *
 * Returns 0 on success, -1 with the reason in err on an unresolvable
 * address or an allocation failure. On failure srv is left safe to pass
 * to cloak_server_destroy. */
int cloak_server_init(cloak_server_t *srv, const cloak_server_config_t *cfg,
                      size_t replay_cache_capacity, char *err, size_t err_cap);

/* Frees the replay cache. Idempotent, and safe on a zeroed struct. Does
 * not touch cfg, which the caller owns. */
void cloak_server_destroy(cloak_server_t *srv);

/* 1 if uid is exempt from credit and bandwidth accounting. The admin UID
 * always is. */
int cloak_server_is_bypass(const cloak_server_t *srv, const uint8_t uid[CLOAK_UID_LEN]);

/* 1 if uid is the configured admin UID. Go gates its admin API on this
 * together with session id 0. */
int cloak_server_is_admin(const cloak_server_t *srv, const uint8_t uid[CLOAK_UID_LEN]);

/* The resolved upstream for a proxy method, or NULL if the ProxyBook has
 * no such entry. proxy_method arrives from an authenticated but
 * attacker-chosen payload: the comparison is case-insensitive (the config
 * parser lower-cases its keys) and bounded, and a name that is merely a
 * prefix of a configured one does not match. */
const cloak_addr_t *cloak_server_lookup_proxy(const cloak_server_t *srv,
                                               const char *proxy_method);

/* Writes the redirection target to *out. local_port is the port the
 * client connected to, used only when the config's RedirAddr carried no
 * port of its own -- so a prober reaching :443 is forwarded to the cover
 * site's :443 and one reaching :80 to its :80, matching Go's goWeb.
 * Returns 0 on success, -1 if srv or out is NULL. */
int cloak_server_redir_addr(const cloak_server_t *srv, uint16_t local_port,
                             cloak_addr_t *out);

/* Records random as seen. Returns 1 if it was already seen within the
 * replay window (reject this handshake) and 0 otherwise. Wraps
 * cloak_replay_cache_check_and_insert with the age limit
 * cloak/server_auth.h requires; call it BEFORE decrypting, matching Go's
 * AuthFirstPacket, which checks replay against the raw not-yet-
 * authenticated random. */
int cloak_server_check_replay(cloak_server_t *srv, const uint8_t random[32],
                               int64_t now_unix);

#endif
```

- [ ] **Step 4: Write the implementation**

Create `libcloak-server/src/server.c`. Points to get right:

- `_POSIX_C_SOURCE 200809L` first line; include `<strings.h>` for `strncasecmp`, `<netinet/in.h>` for the port patching.
- A local `set_err` helper matching the convention (`vsnprintf` into a possibly-NULL buffer, always returns -1).
- `cloak_server_init` must `memset(srv, 0, sizeof(*srv))` immediately after the `srv != NULL` check and before validating anything else, so every failure path leaves a struct `cloak_server_destroy` can safely take. This project has had the reverse ordering twice and both times it was a crash.
- Resolving `RedirAddr`: try `cloak_net_split_hostport` first. If it succeeds, the config supplied a port — resolve as given and set `redir_has_port = 1`. If it fails, the config supplied a bare host — resolve it with a placeholder service (`"443"` is fine, the port is overwritten per connection) and set `redir_has_port = 0`. Report an unresolvable host as an error with the host named.
- Resolving the proxy book: one `cloak_net_resolve` per entry, passing `entry->is_udp`. An unresolvable entry is an error naming that entry.
- The bypass union: copy `cfg->bypass_uid[0 .. num_bypass_uid)`, then append `cfg->admin_uid` when `cfg->has_admin_uid`. The array is sized `CLOAK_MAX_BYPASS_UID + 1` precisely so this cannot overflow — but assert the count anyway rather than trusting the sizing.
- `cloak_server_redir_addr`: copy `srv->redir`, and when `!redir_has_port` patch the port via a `switch` on `((struct sockaddr *)&out->ss)->sa_family` setting `sin_port` or `sin6_port` to `htons(local_port)`.
- `cloak_server_is_bypass` / `is_admin`: constant-time comparison is not required here (the UID has already been authenticated by this point, and Go uses plain equality), but say so in a comment rather than leaving the next reader to wonder.

- [ ] **Step 5: Wire it into the build, run the tests**

Add `src/server.c`; register `test_server_state` with a `TIMEOUT`. Expected: 32 tests.

- [ ] **Step 6: Commit**

```bash
git add libcloak-server/include/cloak/server.h libcloak-server/src/server.c \
        libcloak-server/tests/test_server_state.c libcloak-server/CMakeLists.txt \
        libcloak-server/tests/CMakeLists.txt
git commit -m "Add server state: resolved addresses, replay cache, bypass union"
```

---

### Task 3: `cloak_server_registry_t` — sessions keyed by UID and session ID

Go keys sessions per user (`userPanel` → `ActiveUser` → `sessions map[uint32]*mux.Session`). Until there is a user manager, one flat table keyed by the pair is the whole of it — but the lifetime discipline is not optional, and it is the reason this is its own task rather than a map inside the dispatcher.

**The discipline:** `cloak_session_broken_cb`'s contract frees every still-active stream immediately after `on_broken` returns, and `cloak_stream_relay_t` holds its stream and session as raw pointers it can never validate. So a relay must be stopped before its session's teardown sweep runs. The registry's own `on_broken` adapter therefore calls the owner's callback **first** — the dispatcher's chance to stop every relay bound to that session — and only then does its own bookkeeping. Freeing the session is deferred to the reactor's next turn rather than done inside the callback, for the same reason the session defers its own sweep: this project has produced seven use-after-free bugs and every one of them was someone freeing something whose callback was still on the stack.

**Files:**
- Create: `libcloak-server/include/cloak/registry.h`
- Create: `libcloak-server/src/registry.c`
- Create: `libcloak-server/tests/test_registry.c`
- Modify: `libcloak-server/CMakeLists.txt` (add `src/registry.c`; add `cloak-mux` to `target_link_libraries`)
- Modify: `libcloak-server/tests/CMakeLists.txt` (register `test_registry`)

**Interfaces:**
- Consumes: `cloak_session_t`, `cloak_session_config_t`, `cloak_session_init/destroy/is_closed` (`cloak/session.h`); `cloak_reactor_add_timer`/`cancel_timer` (`cloak/reactor.h`).
- Produces:
  - `cloak_server_registry_t`, `CLOAK_REGISTRY_MAX_SESSIONS`.
  - `typedef void (*cloak_registry_broken_cb)(cloak_server_registry_t *reg, cloak_session_t *sesh, const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id, void *userdata);`
  - `int cloak_server_registry_init(cloak_server_registry_t *reg, cloak_reactor_t *r, cloak_registry_broken_cb on_broken, void *userdata);`
  - `void cloak_server_registry_destroy(cloak_server_registry_t *reg);`
  - `cloak_session_t *cloak_server_registry_get_or_create(cloak_server_registry_t *reg, const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id, const cloak_session_config_t *config, int *out_created);`
  - `cloak_session_t *cloak_server_registry_find(cloak_server_registry_t *reg, const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id);`
  - `void cloak_server_registry_close(cloak_server_registry_t *reg, const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id);`
  - `size_t cloak_server_registry_count(const cloak_server_registry_t *reg);`

**Design notes the implementer must follow:**

- Each entry is heap-allocated and holds the `cloak_session_t` **by value**, plus the UID, the session id, and a back-pointer to the registry. The entry's address is what the session's callbacks carry as userdata, so an entry must never move — do not store entries by value in a growable array. A fixed-size array of pointers, or an intrusive list, is fine.
- `get_or_create` fills in the caller's `config` template, overwriting only `on_broken`/`on_broken_userdata` with the registry's own adapter. Every other field — obfuscator, sizes, `on_new_stream`, `on_stream_data`, `on_writable` and their userdata — is the caller's and must be passed through untouched. Document that the caller's `on_broken` is not used and why.
- The registry's adapter: mark the entry dead, invoke the owner's `on_broken` (so relays get stopped), then schedule a single deferred sweep if one is not already pending. The sweep destroys and frees every dead entry. Marking dead **before** invoking the owner's callback matters: the owner may call `cloak_server_registry_close` on the same session from inside it, and that must be a no-op rather than a second teardown.
- `cloak_server_registry_destroy` must run the sweep itself for anything still pending, cancel the sweep timer, and destroy every live session — in that order.
- Cap the table at `CLOAK_REGISTRY_MAX_SESSIONS` (256 is ample for this stage) and return NULL from `get_or_create` when full, so an attacker opening sessions cannot exhaust memory. Say in the header that a NULL return there is a resource limit, not an error in the arguments.

- [ ] **Step 1: Write the failing test**

Create `libcloak-server/tests/test_registry.c`. It needs real sessions, so build on the paired-session harness in `libcloak-mux/tests/test_stream_data_cb.c` — read it and follow its construction. Cover:

```c
/* 1. get_or_create returns a new session the first time (out_created ==
 *    1) and the same pointer for the same (uid, session_id) afterwards
 *    (out_created == 0). A different session_id for the same uid, and the
 *    same session_id for a different uid, both get their own session --
 *    assert all three pointers differ, since keying on only half the pair
 *    is the obvious bug.
 *
 * 2. The caller's config fields survive: pass a config with a recognisable
 *    on_new_stream/on_stream_data/on_writable and their userdata, and
 *    assert after creation that the session actually carries them (drive
 *    a frame through and observe the callback fire, rather than reading
 *    struct fields -- the point is that the registry did not clobber the
 *    wiring).
 *
 * 3. When a session breaks, the owner's on_broken fires exactly once,
 *    with the right uid and session_id, and the session is still usable
 *    for the duration of that callback -- that is the window in which the
 *    dispatcher stops its relays. Afterwards, find() returns NULL and
 *    count() has dropped.
 *
 * 4. Calling cloak_server_registry_close from inside the owner's
 *    on_broken is a no-op rather than a double teardown. Run this one
 *    under ASan; it is the exact shape of the use-after-free class this
 *    project keeps producing.
 *
 * 5. cloak_server_registry_close on a live session tears it down, fires
 *    nothing (it is the owner's own action, not a failure -- match
 *    cloak_session_destroy's reasoning), and removes it from the table.
 *
 * 6. Filling the table to CLOAK_REGISTRY_MAX_SESSIONS and asking for one
 *    more returns NULL, and the existing sessions are untouched.
 *
 * 7. cloak_server_registry_destroy with live sessions destroys them all
 *    and leaves nothing leaked -- assert under ASan, with at least one
 *    session that has an open stream.
 */
```

Write these as real test functions. Bound every reactor loop.

- [ ] **Step 2: Run the test to verify it fails**

Expected: FAIL — `cloak/registry.h` does not exist.

- [ ] **Step 3: Write the header and implementation**

Follow the design notes above. The header's doc comments must state, prominently:
- that the owner's `on_broken` is the last moment at which any relay bound to this session may be stopped, and that failing to do so is a use-after-free (cross-reference `cloak/stream_relay.h`, which states the same obligation from the other side);
- that entries never move, so callback userdata stays valid;
- that a full table returns NULL from `get_or_create`.

- [ ] **Step 4: Wire it into the build**

Add `src/registry.c` to `libcloak-server/CMakeLists.txt` and extend its `target_link_libraries` to include `cloak-mux` (it currently links only `cloak-common`). Register `test_registry` with a `TIMEOUT`.

- [ ] **Step 5: Run the full suite**

Expected: 33 tests — the 30 from before this plan plus `test_firstpacket`, `test_server_state` and `test_registry`. Every pre-existing test unmodified.

- [ ] **Step 6: Run the suite under ASan/UBSan**

Mandatory for this task: the registry frees sessions across an asynchronous sweep, and cases 4 and 7 exist specifically to catch the use-after-free class this project has produced seven times.

- [ ] **Step 7: Commit**

```bash
git add libcloak-server/include/cloak/registry.h libcloak-server/src/registry.c \
        libcloak-server/tests/test_registry.c libcloak-server/CMakeLists.txt \
        libcloak-server/tests/CMakeLists.txt
git commit -m "Add session registry: sessions keyed by UID and session id"
```

---

## What comes after this plan

The dispatcher itself, which is now wiring rather than invention: accept a connection, drive a `cloak_firstpacket_t` to completion, parse and authenticate it with the already-merged `cloak_clienthello_parse` + `cloak_server_check_replay` + `cloak_server_auth_decrypt`, look the UID up against `cloak_server_is_bypass`, get-or-create through the registry, compose and write the reply with `cloak_server_auth_compose_reply`, and hand the fd to `cloak_session_add_conn`. On any failure along that path — unrecognised protocol, oversized packet, bad decrypt, replayed random, unknown proxy method, unauthorised UID — forward to `cloak_server_redir_addr` with `cloak_dial_t` + `cloak_relay_t`, preloading everything `cloak_firstpacket_data` accumulated.

It then owns the three obligations the stream-relay plan carried forward: stopping every relay from the registry's `on_broken`, tolerating a spurious `cloak_stream_relay_start` rejection when the pool is transiently busy, and knowing that per-relay read budgets do not coordinate across relays on one session.

Out of scope here and there: the user manager and its accounting (Go's `userpanel`/`activeuser`, which is why this registry has no per-user session cap yet), the admin API, the WebSocket/CDN transport's own handshake, and UDP.

### What a paper walk of that loop already established

This branch's final review walked `dispatch_conn()` end to end against the merged interfaces. Everything above composes; these are the parts worth knowing before writing it, most now stated in the headers themselves.

**Confirmed, so nobody has to re-derive them:**
- `cloak_listener_port(l)` in the accept callback gives exactly the `local_port` that `cloak_server_redir_addr` wants — per listener, so each `BindAddr` entry redirects to its own port, matching Go's `net.SplitHostPort(conn.LocalAddr())`. No `getsockname` needed.
- The read loop must run **inside** the readable callback until `EAGAIN` or `want() == 0`. One exact-sized read per readiness edge stalls permanently on an edge-triggered reactor.
- `cloak_reactor_remove_fd` must precede `cloak_session_add_conn`, or `cloak_conn_init`'s own registration fails and `add_conn` returns -1. Bytes already sitting in the socket are **not** lost: `EPOLL_CTL_ADD` on a ready fd enqueues an event even under `EPOLLET`. On `add_conn` failure nobody closes the fd — the dispatcher keeps ownership.
- `CLOAK_FIRSTPACKET_DONE` on the TLS path delivers exactly the one un-fragmented record `cloak_clienthello_parse` assumes.

**Gaps the dispatcher must fill itself:**
- **No non-blocking write-then-handover primitive exists.** Go writes its ≤256-byte reply with a blocking `conn.Write` before `AddConnection`. Here the fd is non-blocking, so a partial write or `EAGAIN` on the reply has to be handled before `cloak_session_add_conn` — and neither `cloak_relay_t` (which wants to own both fds) nor `cloak_bytequeue_t` (storage, not a writer) does that job. Small, but it is hand-rolled code nobody has budgeted for.
- **`ci.unordered` has nowhere to go.** Go sets `SessionConfig.Unordered`; `cloak_session_config_t` has no such field and nothing in `libcloak-mux` implements unordered mode. UDP is a later module, but an authenticated payload can request it today, and silently ignoring an attacker-visible flag is itself a fingerprint. Decide deliberately what to do with it.
- **The 15-second first-packet deadline** (`firstpacket.h` states it as a caller obligation) and **treating `CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET` as a redirect case** until the CDN module exists.

## Self-review notes

- **Spec coverage (§7):** the first-byte sniff and incremental first-packet buffering are Task 1; the resolved `RedirAddr`/`ProxyBook` and the authorisation inputs are Task 2; "attach the connection to a `cloak_session_t` (new or existing, keyed by UID+session ID)" is Task 3. §7's step 4, `goWeb()` itself, needs only `cloak_server_redir_addr` from this plan plus the already-merged dialer and relay, and belongs with the dispatch loop.
- **Placeholder scan:** Tasks 1's code is complete and literal. Tasks 2 and 3 specify their tests in prose and Task 2's implementation as a list of points-to-get-right rather than a pasted body — deliberate, because both must match real API surfaces (`cloak_server_config_t`'s exact field names, the paired-session harness) that a sketch would drift from, and both name every behaviour to implement. No step says "add error handling" or defers a decision.
- **Type consistency:** `CLOAK_UID_LEN` and `CLOAK_MAX_PROXY_BOOK`/`CLOAK_MAX_BYPASS_UID` come from `cloak/config.h` and are used unchanged in all three tasks. `cloak_addr_t` is produced by `cloak_net_resolve` (already merged) and consumed by Task 2's accessors. Task 3's config template is `cloak_session_config_t` verbatim, with exactly two fields overwritten and that documented.
- **The carried-forward obligation from the config plan** (union `admin_uid` into the bypass set) lands in Task 2 and is pinned by its test case 1, which asserts both that the runtime set includes it and that the config struct still does not.
