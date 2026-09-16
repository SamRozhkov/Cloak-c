# Module 8: the CDN / WebSocket transport, server side

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** teach `ck-server` to accept Cloak sessions arriving as CDN-fronted WebSocket upgrades, wire-compatible with Go's `WSOverTLS` client, without disturbing the direct-TLS path.

**Architecture:** the first-packet reader already recognises a WebSocket upgrade and hands over a complete request with nothing read past it. Module 8 adds three pieces behind that: a purpose-built upgrade parser that validates and extracts `Hidden`, a flat 60-byte reply composer to sit beside the existing scattered-TLS one, and a **framing mode** on `cloak_conn_t` so the data path emits WebSocket binary frames instead of TLS application-data records. The dispatcher branches once, at the site that today returns "redirect to the cover site" for anything that is not TLS.

**Tech Stack:** C11, OpenSSL `libcrypto` (SHA-1 for the accept, already linked), the existing `cloak_base64_*`, `cloak_random_bytes`, `cloak_bytequeue_t`, `cloak_reactor_t`. **No WebSocket library is vendored** — see D2.

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md`
**Scouting report:** `docs/superpowers/plans/2026-09-16-module-8-scouting.md` — every byte layout, measurement and file:line citation below comes from it.

## Global Constraints

- C11, `-Wall -Wextra` clean, **zero warnings**. Linux only; `_POSIX_C_SOURCE 200809L` as the first line of every `.c`.
- Nothing may block the reactor. Every Go blocking idiom becomes a resumable state machine.
- ASan+UBSan mandatory alongside Debug. Run tests through `ctest`, never a test binary directly, or `LD_PRELOAD` is absent and the shims do not load.
- Docker image `cloak-c-dev`, `-w /src/.worktrees/<branch>`. **Never `-w /src`.**
- `TIMEOUT 120` on new tests, and **do not raise it further** — make a slow case cheaper instead.
- **Ephemeral ports everywhere.** Two fixed-port defects were introduced and removed on the previous branch alone.
- Every wait bounded by the clock, never by an iteration count.
- 63 tests pass at `7138056`. **Every existing test must pass UNMODIFIED**, except the four listed in D6, which pin behaviour this module deliberately changes.
- Revert a mutation with `cp`, never `mv`: `mv` preserves mtime, the build skips, and the test passes against the un-reverted binary.

---

## Decisions already made

**D1 — this module is the SERVER side only; the client CDN leg becomes module 8b.**
Go's `WSOverTLS.Handshake` performs a real uTLS handshake unconditionally (`internal/client/websocket.go:26-39`). A CDN genuinely terminates TLS, so a C client would need a real TLS stack — and this tree links `OpenSSL::Crypto` only, with no `libssl`; `clienthello.c` builds a costume and negotiates nothing. That is a new dependency *and* a fingerprint decision (an OpenSSL ClientHello is not `HelloChrome_Auto`), and it is a product question, not an engineering one.
The server leg needs no TLS at all — the CDN terminates it and the first byte at the origin is `'G'`. It is immediately useful (a C `ck-server` can serve real Go clients behind a CDN), and it is the half with genuine outside oracles. Ship it first. **`ck-client` keeps refusing CDN in this module**, and its refusal sites stay.

**D2 — no WebSocket library is vendored.**
Cloak touches six gorilla entry points. Deflate, subprotocols, text frames, and close-frame *sending* are provably unused. What is load-bearing is small: the handshake, single-frame binary messages, receive-side continuation reassembly, ping→pong, and MASK-bit enforcement. That is a few hundred lines, not an RFC 6455 stack, and vendoring one would add a dependency larger than the feature.

**D3 — validate the upgrade headers BEFORE authorising the UID.** This is the fix for Go bug #5 (below) and it is also better mimicry: the server must look identically like a web server whether a `GET` carries a bad `Hidden` or a bad `Upgrade`. Go checks `Hidden` alone in `processFirstPacket` and lets `Upgrader.Upgrade` check the rest — *after* `dispatchConnection` has authorised the UID, made the user active and called `finishHandshake`. Do not mirror that ordering.

**D4 — the framing mode's zero value is INVALID.**
`cloak_conn_t` hard-codes the 5-byte TLS application-data record, and `conn.h:20-66` is a 46-line warning about why those five bytes exist: the port shipped a defect for five modules where the disguise applied for exactly one round trip and then dropped. The CDN path is the **exact inverse** — a TLS record header inside a WebSocket frame is both wire-incompatible with Go and a perfect Cloak signature to anyone inside the CDN's TLS. So the mode is an explicit parameter chosen once, at `cloak_session_add_conn` time, from the transport that produced the fd, and an un-updated call site must **fail construction** rather than silently pick a default.

**D5 — the reply is one coalesced write.** Measured: a server that writes the 101 response and the 62-byte binary frame in a single `write()` is handled correctly by a gorilla client, because `http.ReadResponse` reads from the same buffered reader the frame reader then uses. So the existing single-write reply state machine (`dispatcher.c:803-881`, an opaque byte buffer) stays exactly as it is. Note the asymmetry: a *client* must not pipeline a frame with its `GET` — a gorilla server rejects that with "client sent data before handshake is complete" — which is 8b's problem, not this module's.

**D6 — four existing tests pin behaviour this module changes**, and they change with it: `libcloak-server/tests/test_dispatcher_redirect.c:356` (a bare `GET` with no `Hidden` must still reach the cover site — this one **stays true** and is the regression anchor), plus the server-side refusal at `dispatcher.c:399-401` and the prose at `firstpacket.h:57-64` and `dispatcher.c:236-241`. The three **client**-side refusals (`client_stack.c:872-879`, `client_connector.c:464-466`) and the three tests pinning them (`test_client_connector.c:1735-1740`, `test_client_stack.c:2177-2186`, `test_ck_client_cli.c:1698-1710`) **stay untouched** — they are 8b's.

**D7 — `cloak_random_bytes` for mask keys, and this is not a fidelity divergence.** gorilla uses `math/rand`, not `crypto/rand` (`conn.go:184-187` with `"math/rand"` at `conn.go:12`), against RFC 6455 §5.3's explicit requirement. Impact is low — the payload is already AEAD-sealed and mask keys look uniformly random either way — and using a CSPRNG is strictly better and free. Note it, do not agonise.

## Go bug #5, measured

`internal/server/websocket.go:47-50` calls `http.Serve(...)` then blocks on `<-handler.finished`, but `websocketAux.go:129-138` returns **without sending** when `upgrader.Upgrade` fails, and `finished` is unbuffered (`:126`). The goroutine, the socket, the `firstBuffedConn` and the `ActiveUser`/session bookkeeping leak permanently. Three reachable triggers were reproduced with verbatim-copied Cloak types: no `Connection: Upgrade`; a malformed `Sec-WebSocket-Key`; a cross-`Origin` header. Because auth reads `Hidden` alone, it fires *after* the UID is authorised — so any client with a valid UID wedges one goroutine and one fd per request, and **a CDN that rewrites any of those three headers wedges every connection**. This is the fifth bug this port has found in the Go original. D3 is the fix.

---

## File structure

| file | new/changed | responsibility |
|---|---|---|
| `libcloak-server/include/cloak/ws_handshake.h` | new | the upgrade parser's interface and its error taxonomy |
| `libcloak-server/src/ws_handshake.c` | new | header scan over `fp.buf`, validation, `Hidden` extraction, accept computation, 101 composition |
| `libcloak-mux/include/cloak/ws_frame.h` | new | frame encode/decode as pure functions over byte buffers — no reactor, no socket, fuzzable |
| `libcloak-mux/src/ws_frame.c` | new | header parse, length forms, masking, control-frame classification |
| `libcloak-mux/include/cloak/conn.h`, `src/conn.c` | changed | the framing mode; per-mode `max_envelope_len`; continuation reassembly; ping→pong |
| `libcloak-mux/include/cloak/session.h`, `src/session.c` | changed | plumb the mode to `cloak_session_add_conn` |
| `libcloak-server/include/cloak/server_auth.h`, `src/server_auth.c` | changed | `cloak_server_auth_compose_ws_reply` — the flat 60 bytes |
| `libcloak-server/src/dispatcher.c` | changed | the branch at `:399`; WS reply composition; the step-1 prose |
| `libcloak-server/include/cloak/firstpacket.h` | changed | rewrite the "no consumer anywhere" paragraph, which stops being true |

---

### Task 1: the WebSocket frame codec

**Files:**
- Create: `libcloak-mux/include/cloak/ws_frame.h`, `libcloak-mux/src/ws_frame.c`
- Test: `libcloak-mux/tests/test_ws_frame.c`
- Modify: `libcloak-mux/CMakeLists.txt`, `libcloak-mux/tests/CMakeLists.txt`

**Interfaces — produces:** pure functions over caller-owned buffers, no allocation, no fd, no reactor:

```c
typedef enum {
    CLOAK_WS_OP_CONTINUATION = 0x0,
    CLOAK_WS_OP_TEXT         = 0x1,
    CLOAK_WS_OP_BINARY       = 0x2,
    CLOAK_WS_OP_CLOSE        = 0x8,
    CLOAK_WS_OP_PING         = 0x9,
    CLOAK_WS_OP_PONG         = 0xA
} cloak_ws_opcode_t;

typedef struct {
    cloak_ws_opcode_t opcode;
    int      fin;            /* 1 if FIN set */
    int      masked;         /* 1 if MASK set */
    uint8_t  mask_key[4];
    uint64_t payload_len;
    size_t   header_len;     /* 2, 4, 6, 8, 10, or +4 when masked */
} cloak_ws_frame_header_t;

/* Returns the header length on success, 0 if more bytes are needed,
 * and -1 on a malformed header. Never reads past buf + len. */
ssize_t cloak_ws_frame_parse_header(const uint8_t *buf, size_t len,
                                    cloak_ws_frame_header_t *out);

/* payload[i] ^= key[i & 3], with pos carried across chunks. Returns the
 * next pos. Masking in place before enqueueing avoids needing this across
 * partial writes; it exists for the receive side. */
size_t cloak_ws_frame_mask(uint8_t *payload, size_t len,
                           const uint8_t key[4], size_t pos);

/* Writes a complete frame header into buf. Returns the length written, or
 * -1 if cap is too small. mask_key may be NULL for the server direction. */
ssize_t cloak_ws_frame_write_header(uint8_t *buf, size_t cap,
                                    cloak_ws_opcode_t op, int fin,
                                    const uint8_t mask_key[4], uint64_t payload_len);
```

**Constraints that make this correct:**
- RSV1/RSV2/RSV3 set → malformed. No extensions are negotiated, so they are always zero.
- Length form: `0-125` inline; `126` + u16 for 126..65535; `127` + u64 above. Go **never emits** the 64-bit form (every message is ≤ 16401), but a hostile peer may send one — this is a receive-side concern, and `CLOAK_CONN_MAX_FRAME_LEN` (16640) already bounds it.
- A `127` header whose u64 has the high bit set is malformed per RFC 6455.
- Control frames (opcode ≥ 0x8): payload ≤ 125 and FIN must be set, or malformed.

- [ ] **Step 1: Write the failing tests**

```
1.  RFC 6455's own sample frames, as literals: a 5-byte masked client
    message decodes to "Hello"; the unmasked server echo decodes the same.
2.  Every length boundary, from BOTH sides: 125 inline / 126 takes the u16
    form; 65535 takes u16 / 65536 takes u64. Record a MEASURED BRACKET for
    each, never a claimed margin.
3.  A 127 header with the high bit of the u64 set -> -1.
4.  RSV1, RSV2, RSV3 each set alone -> -1 (three cases, not one).
5.  A control frame with a 126-byte payload -> -1; with FIN clear -> -1.
6.  Partial input: for a masked 200-byte message, feed the header one byte
    at a time and assert parse_header returns 0 at every prefix and the
    correct header_len at exactly the right byte, not one earlier.
7.  Masking round-trips at every pos in 0..3, and across a chunk split at
    every offset in a 7-byte payload.
8.  write_header with cap one byte short -> -1, and with cap exactly
    sufficient -> success. Both sides.
```

- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (64 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Add a WebSocket frame codec"`

---

### Task 2: the framing mode on `cloak_conn_t`

**Files:**
- Modify: `libcloak-mux/include/cloak/conn.h`, `libcloak-mux/src/conn.c`, `libcloak-mux/include/cloak/session.h`, `libcloak-mux/src/session.c`
- Test: `libcloak-mux/tests/test_conn_ws_framing.c`

**Interfaces — consumes** Task 1's codec. **Produces:**

```c
typedef enum {
    CLOAK_CONN_FRAMING_INVALID    = 0,   /* deliberate: an un-updated call site FAILS */
    CLOAK_CONN_FRAMING_TLS_RECORD = 1,
    CLOAK_CONN_FRAMING_WS_CLIENT  = 2,   /* masks on send */
    CLOAK_CONN_FRAMING_WS_SERVER  = 3    /* never masks on send */
} cloak_conn_framing_t;

int cloak_session_add_conn_framed(cloak_session_t *sesh, int fd,
                                  cloak_conn_framing_t framing);
```

`cloak_session_add_conn(sesh, fd)` keeps its signature and means `TLS_RECORD`, so the direct path's call sites are untouched and the new parameter cannot be forgotten *into* the wrong mode — only into a construction failure.

**This is the riskiest task in the plan.** It is a change to the one file whose header spends 46 lines asking not to change it carelessly; it introduces a mode that is correct in one configuration and a perfect fingerprint in the other; and the wrong choice is invisible to every round-trip test because both ends agree.

`max_envelope_len` per mode — **get this wrong by four bytes and it fails only at the maximum frame size**, i.e. under load, in production, never in a unit test:

| mode | envelope |
|---|---|
| `TLS_RECORD` | `5 + max_frame_len` |
| `WS_SERVER` | `2 + (0 or 2) + max_frame_len` |
| `WS_CLIENT` | `2 + (0 or 2) + 4 + max_frame_len` — the mask key makes the client's envelope **larger than the TLS one** |

- [ ] **Step 1: Write the failing tests**

```
1.  THE ASSERTION THAT WOULD HAVE CAUGHT THE ORIGINAL DEFECT IN ONE LINE:
    read the raw bytes off a socket and assert the first byte of the DATA
    PATH is 0x17 in TLS_RECORD mode and 0x82 in both WS modes. Positional,
    against a constant from the RFC and from conn.h -- not against our own
    other end.
2.  CLOAK_CONN_FRAMING_INVALID (i.e. a zeroed config) fails construction.
    Assert the named error, not merely non-zero.
3.  WS_SERVER never sets the MASK bit; WS_CLIENT always does. Two cases.
4.  max_envelope_len for each of the three modes at max_frame_len, as
    literals. Then a MEASURED BRACKET: a frame at max_frame_len succeeds
    and one at max_frame_len + 1 is refused, in every mode.
5.  Receive-side continuation reassembly: one logical message split into
    three frames (BINARY/FIN=0, CONTINUATION/FIN=0, CONTINUATION/FIN=1)
    arrives as ONE mux frame. Neither end of a C<->C test would ever
    produce this, so it must be synthesised by hand.
6.  A ping injected mid-stream is answered with a pong carrying the SAME
    payload, within one turn, and does NOT appear as session data.
7.  A close frame received ends the conn cleanly and is not forwarded as
    data.
8.  A masked frame arriving at a WS_SERVER conn is accepted; an UNMASKED
    one is rejected (RFC 6455 requires clients to mask).
```

- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (65 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Give cloak_conn_t a framing mode whose zero value is invalid"`

---

### Task 3: the server-side upgrade parser and the accept computation

**Files:**
- Create: `libcloak-server/include/cloak/ws_handshake.h`, `libcloak-server/src/ws_handshake.c`
- Test: `libcloak-server/tests/test_ws_handshake.c`

**Interfaces — produces:**

```c
typedef enum {
    CLOAK_WS_HS_OK = 0,
    CLOAK_WS_HS_ERR_NOT_UPGRADE,     /* no Upgrade: websocket, or no Upgrade token in Connection */
    CLOAK_WS_HS_ERR_BAD_VERSION,     /* Sec-WebSocket-Version != 13 */
    CLOAK_WS_HS_ERR_BAD_KEY,         /* Sec-WebSocket-Key absent, or not base64 of 16 bytes */
    CLOAK_WS_HS_ERR_BAD_HIDDEN,      /* Hidden absent, not base64, or not exactly 96 bytes */
    CLOAK_WS_HS_ERR_MALFORMED        /* not a request line we can parse at all */
} cloak_ws_hs_result_t;

typedef struct {
    uint8_t hidden[96];              /* randPubKey[32] || ciphertextWithTag[64] */
    char    accept[29];              /* base64(SHA1(key || GUID)), NUL-terminated */
} cloak_ws_hs_t;

cloak_ws_hs_result_t cloak_ws_handshake_parse(const uint8_t *req, size_t len,
                                              cloak_ws_hs_t *out);

/* Writes the four-line 101 response. Returns the length, or -1 if cap is short. */
ssize_t cloak_ws_handshake_compose_101(uint8_t *buf, size_t cap, const char *accept);
```

**The exact bytes, measured against live gorilla.** The response is four lines and **nothing else** — no `Date`, no `Server`, because gorilla hijacks the connection so `net/http` adds neither:

```
HTTP/1.1 101 Switching Protocols\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Accept: <28 chars>\r\n
\r\n
```

**What must survive a CDN's rewriting** — every one of these is a production-only failure that a naive test suite passes:
- **`Hidden` may arrive lowercased.** Cloudflare and any HTTP/2-fronted edge normalise header names. Go survives free via `textproto.CanonicalMIMEHeaderKey`. **A C parser matching `"Hidden"` with `memcmp` fails only in production.** Match case-insensitively, on every header name.
- **Unknown headers will be injected** — `X-Forwarded-For`, `CF-Connecting-IP`, `CF-RAY`, `CDN-Loop`, `Accept-Encoding`, … A bare client sends 335 bytes; a Cloudflare-fronted request is typically 700-900. `CLOAK_FIRSTPACKET_MAX` is 3000 and holds, but it is now a *real* bound, and overflowing it silently redirects to the cover site.
- **`Connection` may be rewritten** to `Connection: Upgrade, keep-alive`. **Token-list matching, case-insensitive, not equality.**
- **`Host` and the request target may be rewritten.** The server reads neither. **Do not add a path check the Go server does not have** — being fussier than the reference is itself a distinguisher, which is the argument `conn.h` already makes about not validating record type bytes.
- **`Sec-WebSocket-Key` may be regenerated by the CDN** on the origin leg. Compute the accept over the key **received**, never over a stored one.

`Hidden` is `base64(randPubKey[0:32] || ciphertextWithTag[0:64])` — 96 bytes plaintext, **128 base64 characters, no padding** (96 % 3 == 0). Go's checks are `len < 96` then `len(hidden[32:]) != 64`, so the accepted length is **exactly 96**.

- [ ] **Step 1: Write the failing tests**

```
1.  THE OUTSIDE ORACLE, and it is free: RFC 6455 section 1.3's own sample.
    Key "dGhlIHNhbXBsZSBub25jZQ==" -> accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".
    Independently confirmed against live gorilla. A pure unit test.
2.  The 335-byte request Go actually sends, frozen as a golden literal,
    parses to OK with the right 96 bytes.
3.  The same request with `hidden:` lowercased -- and with `HIDDEN:`, and
    `HiDdEn:` -- all parse identically. This is the Cloudflare case.
4.  `Connection: Upgrade, keep-alive` and `Connection: keep-alive, Upgrade`
    both accepted; `Connection: keep-alive` alone -> ERR_NOT_UPGRADE.
5.  Twelve injected CDN headers before, between and after the real ones:
    still OK.
6.  Hidden of 95 and 97 bytes -> ERR_BAD_HIDDEN. A MEASURED BRACKET on
    both sides of exactly 96.
7.  Sec-WebSocket-Version 12 and 14 -> ERR_BAD_VERSION. Both sides.
8.  Sec-WebSocket-Key that is valid base64 of 15 and of 17 bytes ->
    ERR_BAD_KEY. Both sides of exactly 16.
9.  compose_101 against the four-line golden response, byte for byte, with
    the accept masked out. This catches a stray Date: or Server:.
10. compose_101 with cap one short -> -1.
```

- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (66 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Parse the CDN WebSocket upgrade, and compute its accept"`

---

### Task 4: the dispatcher branch, and the flat reply

**Files:**
- Modify: `libcloak-server/src/dispatcher.c` (the branch at `:399`, reply composition near `:578`, the step-1 prose at `:236-241`), `libcloak-server/src/server_auth.c`, `libcloak-server/include/cloak/server_auth.h`, `libcloak-server/include/cloak/firstpacket.h` (the "no consumer anywhere" paragraph stops being true)
- Test: `libcloak-server/tests/test_dispatcher_ws.c`

**Interfaces — consumes** Tasks 1-3. **Produces:**

```c
/* The CDN reply is FLAT: [12-byte nonce][48 bytes AES-GCM(sessionKey) + tag]
 * = 60 bytes, written as one unmasked binary frame -> 62 bytes on the wire
 * (0x82 0x3C then the payload). Contrast direct mode, where the same 60
 * bytes are SCATTERED across a fake ServerHello -- nonce at [6:18),
 * ciphertext[0:20) at [18:38), ciphertext[20:48) inside the key_share at
 * [84:112) -- plus two more records. cloak_server_auth_compose_reply builds
 * the scattered form and is NOT reusable here. */
int cloak_server_auth_compose_ws_reply(uint8_t out[60], const uint8_t session_key[32],
                                       const uint8_t shared_secret[32]);
```

**The ordering is the point of this task (D3).** Validate the upgrade headers **with** `Hidden`, before authorising the UID and before touching the user panel. A malformed upgrade becomes an ordinary redirect to the cover site, exactly like an unrecognised protocol. Go does the opposite and wedges forever.

The reply path needs no change: `dispatcher.c:824` is a plain `send()` loop over an opaque byte buffer, so one `c->reply` holding the 101 response followed by the 62-byte frame works as-is (D5).

- [ ] **Step 1: Write the failing tests**

```
1.  A full CDN upgrade with a valid UID reaches an established session, and
    the 60 decrypted bytes yield the same session key the direct path
    produces for the same inputs.
2.  THE ORDERING, tested as a byte-stream and timing equivalence claim:
    capture the complete byte stream and the wall-clock shape for (bad
    Hidden), (bad Upgrade), and (an unrecognised protocol). Assert all
    three are the same modulo the cover site's own variability. A test
    that only checks "all three redirect" does not establish this.
3.  The user panel is NOT touched on a malformed upgrade. Assert on the
    panel's own counters, not on the connection's outcome -- a counter
    scoped to the wrong object is one of this project's named patterns.
4.  The reply is ONE write: assert the coalesced buffer's length is
    101-response-length + 62, and that the frame header is exactly 0x82 0x3C.
5.  test_dispatcher_redirect.c:356's bare GET (no Hidden) still reaches the
    cover site. This is the regression anchor and it must pass UNMODIFIED.
6.  A request that fills CLOAK_FIRSTPACKET_MAX exactly succeeds; one byte
    more redirects. A measured bracket on the bound that now actually binds.
```

- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (67 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Accept CDN WebSocket sessions, validating the upgrade before the UID"`

---

### Task 5: interoperability against Go, and the fragmenting proxy

**Files:**
- Test: `libcloak-server/tests/test_ws_interop.c`
- Modify: `cmd/ck-server/main.c` only if a flag or a log line is needed — **the server needs no CDN configuration at all**; Go's server does not know a CDN is in front of it.

**This is the task that earns the module.** Everything before it has both ends written by us, and this project's most expensive lesson is that **round-trip tests cannot see a self-consistent error**. Here, for once, real outside oracles are cheap.

- [ ] **Step 1: Write the failing tests**

```
1.  A stock gorilla client (Go, built at test time from /usr/local/go/bin/go)
    completes a session against the C ck-server through a CDN-shaped
    request. Byte for byte through the data path.
2.  gorilla as a DECODER ORACLE for our frames: feed C-produced frames into
    gorilla's advanceFrame and assert no "bad MASK", no "RSV1 set", no
    "bad opcode". gorilla is a fussy, independently-written validator --
    exactly the oracle role the server played for the client last module.
3.  A HAND-WRITTEN FRAGMENTING PROXY between the Go client and the C
    server: split every message into 2-3 continuation frames and interleave
    a ping. Neither end of a C<->C test would produce this, and neither
    would a Go peer -- it has to be synthesised deliberately. This is the
    only defence against the CDN-rewriting class of bug, every one of which
    passes the whole suite and fails in production.
4.  Pong-on-ping via a gorilla client with SetPongHandler: the C server
    answers within one turn, with the same payload.
5.  The no-over-read guarantee, asserted STRUCTURALLY: after the handshake
    completes, ioctl(FIONREAD) on the fd holds exactly the bytes the test
    wrote after the reply, not one fewer.
6.  Partial-read resumption with no oracle available, so assert it
    exhaustively: drive the handshake at EVERY split point from 1 byte to
    the full request length, and assert the same session key each time.
```

- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (68 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Prove the CDN server against Go, a fragmenting proxy, and gorilla as a decoder"`

---

## Fuzz targets, written here while the invariants are fresh

Both are pure functions over a byte buffer with no reactor, and both belong in module 10's corpus:
1. `cloak_ws_handshake_parse` over `fp.buf` — attacker-controlled and **unauthenticated**, so a bug here is fingerprint-class per `http.h:17-30`'s taxonomy.
2. `cloak_ws_frame_parse_header` — attacker-controlled; after the handshake it is authenticated only in the sense that the peer completed an upgrade, and the AEAD is one layer above, so a memory-safety bug here is serious.

## Self-review

- **Spec coverage:** the spec's CDN section is the server half here and the client half in 8b; D1 states why, with the measurement that forces it.
- **Placeholder scan:** every task names its files, its interfaces and its test cases with exact values. D1-D7 are settled. No task says "similar to Task N".
- **Type consistency:** `cloak_ws_frame_header_t` and the parse/mask/write triple are produced in Task 1 and consumed in Task 2; `cloak_conn_framing_t` and `cloak_session_add_conn_framed` in Task 2 and consumed in Task 4; `cloak_ws_hs_t` and `cloak_ws_handshake_parse` in Task 3 and consumed in Task 4; `cloak_server_auth_compose_ws_reply` in Task 4 and exercised in Task 5. Counts chain 63 → 64 → 65 → 66 → 67 → 68.
- **The riskiest task is 2**, for the reason stated in it: it is the same *shape* as the defect that survived five modules, in the file whose header begs you not to change it carelessly, and the wrong mode is invisible to every round-trip test. Its mitigations are the raw-first-byte assertion, an enum whose zero value is invalid, and gorilla as an external decoder in Task 5.
- **The most consequential thing here** is that Task 5 is the first time this port is tested against an implementation nobody here wrote. Every previous module's tests had our code on both ends.

---

## What this branch left for the next ones

### The premise was right, and here is the measurement that proves it

This plan's closing line said Task 5 would be the first time the port met an implementation nobody
here wrote. It found, on that first meeting, that **this port could not exchange a single data frame
with the Go implementation it is a port of.**

`cloak_frame_obfuscate` passed header bytes 12-13 as AES-GCM associated data; Go passes nil. The tag
covers the AAD, so every frame we produced was unopenable by Go and vice versa. Measured: the Go
client completed the CDN handshake, derived the **correct session key**, sent frame one, and the
server **dropped it silently**. Two arguments changed. The pre-fix tree fails **1 of 68 tests — the
interop test and nothing else.**

It survived five modules because **both ends of every test were our own code.** That is the same
reason the record-framing defect survived five modules, and it is now the second time this exact
blindness has shipped. The plan for the call had **no** AAD; it was added during implementation and
then **pinned by a test**. A test can lock in a defect as firmly as it can protect against one.

### The class had four members, and three were found by looking rather than by accident

Asked to hunt for a second instance, the final review found one **one function above the first**:
`frame.c` computed the padding length as `b % 240` on a single random byte where Go
rejection-samples. Measured over 200,000 samples: sixteen of 240 values were **twice** as likely
(low-16 mass 12.547 % against Go's 6.667 %). That length goes **straight into the on-wire frame
length on the first five frames of every stream, on both transports** — a passive size-distribution
distinguisher from Go, **inside the padding whose stated purpose is defeating a size side channel.**

A grep for every `%` on a random draw then found two more, including the SNI `alt_names` pick
(one byte modulo ≤ 17, skewed up to 6.7 %, on the wire). **After this branch no `%` on a one-byte
random draw survives in the tree.** Two remain deliberately: an 8-byte draw whose bias is below
1e-18, with a comment now stating the argument holds *only* at 8 bytes, and a 32-bit non-crypto draw
matching Go's own pool.

The lesson is not "we had a modulo bug". It is that **an oracle that checks frames *decode* cannot
see how long they are.** Interop proves agreement on semantics, never on distributions.

### The direct path is still tested only against itself, and that is module 9's opening task

The mux layer is now transitively oracle-covered. The direct *transport* — ClientHello placement,
the 5-byte record header, the ServerHello reply — and **the entire C client** are not, and that
transport is where the first instance fired.

The cost is measured, not estimated: Go's real `ck-client` and `ck-server` build from **unmodified
upstream** with 13 modules and 114 MB of cache into ~10 MB binaries. So it is **one
`go mod download` line in `Dockerfile.dev` plus one test file driving real binaries in both roles —
zero copied lines — covering strictly more than the CDN oracle.** Do it first, not last.

### A fifth bug in the Go original, and the ordering that avoids it

A failed WebSocket upgrade **wedges the Go server forever**: `websocketAux.go` returns without
sending on an unbuffered channel `websocket.go` then blocks on, leaking the goroutine, the socket
and the ActiveUser bookkeeping. Three reachable triggers were reproduced with verbatim-copied Cloak
types. It fires *after* the UID is authorised, so **a CDN that rewrites `Connection`, regenerates a
malformed key, or injects `Origin` wedges every connection.**

This port validates the upgrade *with* `Hidden`, before the UID. Verified at the built binary: 200
connections per shape, **zero hung across all five**, and the cross-`Origin` case answers 101 where
gorilla answers 403. Ignoring `Origin` is now declared and pinned, because it was correct by
accident as far as any reader could tell.

### Compatibility, stated plainly

The AAD fix changed the **direct path's** wire bytes too — `frame.c` has no framing branch. An
old-AAD tag is now refused. **A pre-fix C client cannot talk to a post-fix C server.** That break
with our own prior builds was taken deliberately, to gain compatibility with Go.

### What we gave up to get it

Bytes 12-13 are now **unauthenticated, full stop** — Salsa20-XOR provides zero integrity. A keyless
on-path attacker can blind-flip byte 12 to reach `session_passive_close` and **kill the mux session
in a way a redial does not recover**, or flip byte 13 to truncate the stream or inject padding as
data. Go has the identical hole. We inherit it on purpose; the alternative is not talking to Go.

### Methodology: what changed this module

- **The oracle has to exist before the plan depends on it.** Task 5 rested entirely on Go and
  gorilla being available to `ctest`. They were not — `go` was on the host, absent from the image,
  and a darwin binary cannot run in a Linux container. Found in the pre-flight scan; had it been
  found during Task 5, four tasks would have been built on a promise. **Scan for the tools a plan
  assumes, not just for conflicts between its tasks.**
- **A self-written mutation log is the least reliable document in the repository.** Reviews this
  module killed 25 of 27, 62 of 65, 17 of 19, 10 of 10 and 17 of 19 — strong — but the previous
  branch reported "11 of 11 caught" against an outside reviewer's **15 live**.
- **An equivalence claim can be a symptom of the defect it describes.** One mutant was honestly
  declared equivalent during Task 4; after the seal fix it became **killable**. It had been
  equivalent *because the code was wrong* — the seal wrote into the caller's buffer before the check
  ran, so deleting the check changed nothing observable. **An equivalent mutant on a guard deserves
  a second look at why the guard cannot matter.**
- **A comment asserting a measurement needs a failing test behind it, or an admission.** This module
  corrected **five**: a header telling the next task a bound was handled; a guard claiming to
  *prevent* an overflow it could only detect; a security note claiming Salsa20 covered bytes it
  cannot; and two more. A 45-claim sweep over one file pair found **three false** that a
  read-and-check pass had missed — because re-reading a claim is the same act that produced it.
  **Every false claim in that file shared one cause: a request literal with no `Host` header.** The
  fix was to require it by construction, not to correct four sentences.
- **Flakes are bugs.** A 1-in-8 ASan failure was traced to `gap + elapsed` being constant at
  301-309 ms against a 300 ms deadline across 0-12 CPU hogs: the timer was never late, only the
  pre-`t0` consumption moved, and ASan inflated that gap fourfold. Fixed by **moving the origin, not
  widening the tolerance** — the tolerance was deleted. A second case with identical construction
  and 21 ms of slack was fixed as latent and reported as latent.
- **Isolate every shared surface, not the one that just bit you.** Two worktrees made the repository
  safe; the shared scratchpad then cost an agent its mutation driver mid-round; then a fix round
  entered a review worktree while the reviewer was still confirming it. **"Leave it byte-identical
  and confirm it" is unsatisfiable if a second agent may enter before the confirmation is read.**

### Costs and budgets for module 9

- The suite is **68/68 in ~20 s Debug and ~60 s ASan at `-j4`**. Stop quoting serial figures.
- `test_random`'s 2M-draw leg costs 3.05 s under ASan and the measurement shows it is load-bearing:
  at 200,000 draws the biased 7-way statistic straddles the threshold and **the test would pass on a
  biased build.** Sample size is a measurement, not a preference.
- The two distribution tests are **statistical** — a ~1e-11 false-failure rate with clouds 30×
  apart. Not a flake in any practical sense, but a different kind of test; whoever sees one fail
  should know it was designed.
- **Split fast/slow `ctest` tiers before adding another forking test.** The four slowest tests all
  fork processes.
- **`detect_leaks=0` for children: do not take it.** Measured here: this test forks nothing, `-j4`
  was 0/12, and it would hide `ck-server`/`ck-client` exit-path leaks.
- Add a **disk-space precondition** to the dev loop. The host hit 99 % twice and wedged the Docker
  daemon, costing one review its ASan leg and one agent 17 minutes.
- The build **hard-fails** without Go or the gorilla module, with `CLOAK_REQUIRE_GO=OFF` visibly
  removing the test (68 → 67) rather than skipping it. Justified by a project-specific fact — the
  suite count is part of the contract, so a skip here is invisible. **Do not cite it as a general
  precedent.**

### Out of scope, carried forward

Module 8b is the client's CDN leg: Go's `WSOverTLS` does a real uTLS handshake, this tree links
`libcrypto` without `libssl`, and the choice between an OpenSSL ClientHello and mimicking Chrome is
a product decision about the fingerprint, not an engineering one. Also unverified: a Go **server**
against our CDN client, HTTP/2 downgrade, and a real CDN's coalescing.

### Tally

Fifty-eight coverage defects across seven branches became **sixty-eight across eight**, plus one
interoperability defect and four distribution biases that no coverage metric would have named. Every
one was found by measuring or mutating. **None was found by reading.**
