# libcloak-client: Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give this project a client. After this plan a `cloak_client_transport_t` can dial a Cloak server, complete the authentication handshake without blocking the reactor, and hand back a session key and a connected socket ready to carry frames — the half of the protocol that until now has existed only as hand-rolled code inside a test harness.

**Architecture:** A new `libcloak-client` with three pieces. `cloak_client_auth_make_payload` builds the 48-byte authenticated payload and the ephemeral key material — the exact mirror of the already-merged `cloak_server_auth_decrypt`, which is what will verify it. `cloak_client_transport_t` is a resumable state machine that writes the ClientHello, reads the server's three-record reply incrementally, recovers the session key, and consumes the trailing records; a non-blocking `read()` can return a partial TLS record, so every step must survive being fed one byte at a time. And before either of those, one correction to already-merged code, described below, because the client is the piece that would otherwise cement the defect in both halves of the protocol at once.

**Tech Stack:** C11, CMake, CTest with the project's existing assert-based framework.

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` §4 (the resumable-state-machine requirement), §5 (ClientHello mimicry, already built), and §12's "ClientHello mimicry | Static captured byte templates" decision.

**Reference:** `/Users/sam/Cloak/internal/client/{auth.go,TLS.go,transport.go}`, and `/Users/sam/Cloak/internal/common/tls.go` — which is the source of the defect Task 1 fixes.

## The defect this plan corrects first

**The data path does not look like TLS, and it is supposed to.**

Go wraps every post-handshake message in a five-byte TLS application-data record header — `0x17 0x03 0x03` followed by a big-endian length (`internal/common/tls.go`, `TLSConn.Write`). This port instead writes a bare two-byte big-endian length prefix (`CLOAK_CONN_LEN_PREFIX_LEN`, `libcloak-mux/src/conn.c`). I checked the whole tree: no record layer exists on the data path anywhere.

The handshake itself is fine on both sides — the client's ClientHello carries a handshake record layer, and `cloak_server_auth_compose_reply` emits a full ServerHello + ChangeCipherSpec + fake-Certificate reply. So a DPI box that parses TLS sees a valid handshake, and then bytes that are not TLS records at all. The first byte of each of our envelopes is the high byte of a frame length, which for ordinary frames is `0x00`, where TLS demands `0x17`. **The disguise is applied for one round trip and then dropped**, which is precisely the fingerprint this entire program exists to avoid.

`conn.h` justifies the prefix by observing that a raw TCP stream does not tell you a frame's length. That is true, and Go solves the same problem *with the record header*, which supplies the length and the disguise together. This port reinvented the length prefix and lost the second half.

The spec did not mandate the prefix — it mentions TLS records only for the handshake and first packet — so this was an implementation decision inside the multiplexer module, not a specified one.

**It is fixed here, first, because the client must speak the server's framing.** Writing the client against the wrong format would cement it in both halves and double the cost of the correction. The blast radius is small: two byte-manipulation sites in `conn.c`, one constant, and a handful of test helpers that hand-build envelopes. Thirty-nine uses of the constant already go through the macro and adapt by themselves.

## Global Constraints

- C11, `-Wall -Wextra` clean, zero warnings in project code.
- Linux only. `#define _POSIX_C_SOURCE 200809L` as the **first line** of any `.c` needing POSIX APIs.
- Public symbols prefixed `cloak_`; headers under `<module>/include/cloak/` with `CLOAK_<NAME>_H` guards; doc comments stating the contract and **why**.
- Every constructor fully initializes its struct **before** validating its other arguments. Every destroy is idempotent and safe on a zeroed struct.
- **Nothing may block the reactor**, and no step may assume a `read()` returns a whole anything.
- Append to every `CMakeLists.txt`; never rewrite one. `libcloak-server/tests/CMakeLists.txt` lines 46-126 carry a load-bearing ASan/LD_PRELOAD block that must stay byte-identical.
- Test registration: copy an existing entry, always `TIMEOUT 60`. Every test wait bounded; **a bound whose comment names a duration must assert it reached that duration**.
- Build and test (note the `-w` path — `-w /src` silently builds the main checkout):
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/libcloak-client cloak-c-dev bash -c \
    'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
  ```
- ASan/UBSan, mandatory for every task in this plan:
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/libcloak-client cloak-c-dev bash -c \
    'cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
       -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
       -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
       -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" && \
     cmake --build build-asan -j8 && ctest --test-dir build-asan --output-on-failure'
  ```
- Test counts: **50 before**, 51 after Task 1, 52 after Task 2, 53 after Task 3, 54 after Task 4.

## Decisions taken before execution

**D1 — emit exactly Go's bytes; be exactly as lenient as Go on read.** Write `0x17 0x03 0x03` then the big-endian length. On read, take the length from bytes 3-4 and **do not validate the type or version bytes** — Go's `TLSConn.Read` does not, and matching that matters twice over: a peer that is fussier than the reference implementation is itself a behavioural distinguisher, and the AEAD one layer up is the real authenticator, so validation here would buy nothing it does not already provide. Say both halves of that reasoning in the header, because "we do not validate this" always looks like an oversight until it says why.

**D2 — re-derive the envelope arithmetic rather than adjusting a number.** `max_envelope_len` becomes `5 + max_frame_len`, and every place that computes on-wire cost picks the new constant up through the macro. Check that the largest configured frame still fits a record's length field, and note in the header that Go caps a record payload at `1<<14 + 256` while real TLS 1.3 caps plaintext at `2^14` — say which bound this port enforces and why.

**D3 — the handshake is a resumable state machine, not a loop.** §4 of the spec requires it in as many words: a non-blocking `read()` can return a partial TLS record. The client reads a reply of at most `CLOAK_SERVER_AUTH_REPLY_MAX_BYTES` spread over three records, and must make progress on any split, including one that lands inside a record header. The existing `cloak_firstpacket_t` (server side) is this project's worked precedent for that shape and is worth reading before designing.

**D4 — the payload builder is the mirror of a merged function, and that is the test oracle.** `cloak_server_auth_decrypt` already exists, is well tested, and is exactly what will consume this. Every test of the payload builder should verify against it rather than against a hand-computed vector: a round trip that the real verifier accepts is stronger evidence than a literal, and it cannot drift.

**D5 — the client's ClientHello construction is already built.** `cloak_clienthello_build` (merged, with Chrome/Firefox/Safari templates, region refilling, SNI patching and ECH handling) does the work Go delegates to uTLS. This plan consumes it and adds nothing to it.

---

### Task 1: TLS record framing on the data path

**Files:**
- Modify: `libcloak-mux/include/cloak/conn.h`, `libcloak-mux/src/conn.c`
- Modify: `libcloak-server/tests/client_harness.h` and any test that hand-builds an envelope (find them; `test_clienthello_parse.c` and `test_firstpacket.c` were flagged by a grep, verify which actually build data-path envelopes rather than handshake records)
- Create: `libcloak-mux/tests/test_conn_record.c`
- Modify: `libcloak-mux/tests/CMakeLists.txt`

**What to change**, and nothing more:

- `CLOAK_CONN_LEN_PREFIX_LEN` (2) becomes a five-byte record header. **Rename it** — a constant called `LEN_PREFIX_LEN` describing a record header will mislead every future reader — and update the 39 uses, which are mechanical.
- `cloak_conn_send`: emit `0x17 0x03 0x03` then the two length bytes.
- `conn_extract_and_dispatch`: peek five bytes, take the length from the last two, skip the rest per D1.
- The header comment that explains the prefix must be rewritten to explain the record header, including that it serves two purposes at once and that dropping the disguise was the defect this replaced.

**What NOT to change:** frame contents, the AEAD, the padding, the handshake framing (already correct), or any sizing constant other than what D2 requires.

- [ ] **Step 1: Write the failing test** — `libcloak-mux/tests/test_conn_record.c`:
```
1. A sent frame appears on the wire with EXACTLY the bytes 0x17 0x03 0x03
   followed by the big-endian length, then the frame. Assert the three
   header bytes as literals -- this is the whole point of the task and it
   is the one assertion that must not be computed from the implementation.
2. A received record is accepted and its payload dispatched intact.
3. Byte-at-a-time delivery of a record reaches the same result as one
   write, including a split inside the five-byte header.
4. Two records in one read are both dispatched.
5. Per D1, a record whose type and version bytes are NOT 0x17/0x0303 is
   still accepted -- assert the leniency deliberately, so a later
   "hardening" change has to argue with a test rather than a comment.
6. A declared length over max_frame_len breaks the connection, as before.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (51 tests) Debug and ASan.** Every pre-existing test must pass — but note that tests which hand-build envelopes will need their helper updated; that is expected for this task and only this task. Report exactly which files you touched and why each one had to change.
- [ ] **Step 5: Mutation-verify** — change the emitted type byte from `0x17` to anything else and confirm case 1 fails; that assertion is the entire security value of this task.
- [ ] **Step 6: Commit** — `git commit -m "Wrap data-path frames in a TLS application-data record"`

---

### Task 2: The client's authentication payload

**Files:**
- Create: `libcloak-client/CMakeLists.txt`, `libcloak-client/include/cloak/client_auth.h`, `libcloak-client/src/client_auth.c`, `libcloak-client/tests/CMakeLists.txt`, `libcloak-client/tests/test_client_auth.c`
- Modify: the root `CMakeLists.txt` (append the subdirectory)

**Interfaces:**
- Consumes: `cloak/crypto.h` (X25519, AES-GCM), `cloak/random.h`, `cloak/config.h` (`CLOAK_UID_LEN`).
- Produces: the payload builder. Task 3 is its only consumer; the server's merged `cloak_server_auth_decrypt` is its test oracle (D4).

**The wire layout is already documented** in `cloak/server_auth.h`, byte for byte, because the decrypting half was written first. Build exactly that: UID at [0:16), proxy method NUL-padded at [16:28), encryption method at [28], big-endian Unix timestamp at [29:37), big-endian session id at [37:41), flags at [41] with bit 0 the unordered flag, [42:48) reserved.

Generate an ephemeral X25519 key pair, derive the shared secret against the server's public key, and AES-256-GCM-seal the 48-byte plaintext under that secret with the **first 12 bytes of the ephemeral public key as the nonce** — Go does exactly that (`auth.go`), and it is load-bearing: the server recovers the nonce from the `random` field it is about to read.

Output: the 32-byte ephemeral public key (which becomes the ClientHello's `random`), the 64-byte ciphertext-with-tag (which becomes `session_id` ++ `key_share`), and the shared secret (which the client needs later to decrypt the reply).

- [ ] **Step 1: Write the failing test**
```
1. Round trip: build a payload, feed random/session_id/key_share to
   cloak_server_auth_decrypt with the matching private key, and assert
   every field comes back exactly as supplied. This is D4 and it is the
   primary test.
2. The shared secret the builder returns equals the one the verifier
   derives -- assert equality, since the reply decryption depends on it.
3. The unordered flag round-trips in both states.
4. A proxy method shorter than 12 bytes is NUL-padded, and one of exactly
   12 bytes is not truncated; a longer one is rejected rather than cut.
5. Two calls with identical inputs produce DIFFERENT output, because the
   ephemeral key is fresh -- a builder that cached or zeroed its key pair
   would pass every other case here.
6. A timestamp outside the server's tolerance window is rejected BY THE
   SERVER -- proving the field is where the server thinks it is, not
   merely that some byte was written.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (52 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Add the client's authentication payload builder"`

---

### Task 3: The direct-TLS handshake state machine

**Files:**
- Create: `libcloak-client/include/cloak/client_transport.h`, `libcloak-client/src/client_transport.c`
- Create: `libcloak-client/tests/test_client_transport.c`
- Modify: `libcloak-client/CMakeLists.txt`, `libcloak-client/tests/CMakeLists.txt`

**The flow**, mirroring `TLS.go`'s `Handshake`:

1. Build the payload (Task 2), then the ClientHello via `cloak_clienthello_build` with `random` = the ephemeral public key, `session_id` = ciphertext[0:32), `x25519_key_share` = ciphertext[32:64), and the configured server name — with `"random"` meaning *generate a plausible random hostname*, as Go does (three to twelve lowercase letters plus a top-level domain from a fixed list; port Go's list).
2. Wrap it in a handshake record layer and write it, tolerating a partial write.
3. Read the reply incrementally. Recover the session key from the ServerHello's `random` and key-share fields — the layout is specified in `cloak_server_auth_compose_reply`'s doc comment, and `client_harness.h`'s existing `extract_session_key_from_reply` is a working implementation worth reading before writing a second one.
4. Consume the ChangeCipherSpec and fake-Certificate records that follow, without parsing their contents.
5. Report completion with the session key, or a typed failure.

**The state machine must survive any split.** Feed it one byte at a time in tests. It must also bound what it will read: a server that sends a valid ServerHello and then dribbles forever must hit a deadline rather than pinning the connection, the same obligation `cloak_firstpacket_t` documents on the server side.

- [ ] **Step 1: Write the failing test**
```
1. Against a REAL server -- the merged dispatcher, registry and server
   state from libcloak-server -- the handshake completes and the session
   key the client derives equals the one the server chose. Drive both
   ends on one reactor, as the existing server tests do.
2. Byte-at-a-time: the same handshake succeeds when the server's reply is
   delivered one byte per reactor turn, including splits inside a record
   header.
3. A partial ClientHello write (a small socket buffer) completes.
4. A server that closes mid-reply fails cleanly with a typed error and
   frees everything.
5. A server that sends a valid ServerHello and then stops hits the
   deadline. Assert the deadline was actually reached, not merely that
   the call returned.
6. serverName "random" produces a plausible hostname: 3-12 lowercase
   letters, a dot, and a listed TLD -- and two calls differ.
7. The three browser templates each produce a ClientHello the merged
   server parses and authenticates.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (53 tests) Debug and ASan, plus the new test 50x**
- [ ] **Step 5: Mutation-verify cases 1, 2 and 5** — the key agreement, the incremental path, and the deadline. Report any not caught.
- [ ] **Step 6: Commit** — `git commit -m "Add the client's direct-TLS handshake"`

---

### Task 4: End to end, and retire the hand-rolled harness

**Files:**
- Create: `libcloak-client/tests/test_client_e2e.c`
- Modify: `libcloak-server/tests/client_harness.h`
- Modify: `libcloak-client/tests/CMakeLists.txt`

**Two things.**

First, an end-to-end test: a real client transport completes a handshake against a real server, brings up a client-side `cloak_session_t` with the derived key, opens a stream, and passes bytes through the merged proxy path to a fake upstream. That is the first time both halves of this protocol have been exercised by library code on both sides.

Second — and this is the consolidation that makes the module worth its weight — **`client_harness.h`'s hand-rolled handshake should delegate to the new library** rather than duplicating it. That harness has been the de facto client for four modules; making it call `cloak_client_transport_t` proves the library is the same thing every existing test has been exercising, and removes a second implementation of the protocol that could drift from the first.

If that conversion turns out to be larger than it looks — the harness may depend on building malformed or adversarial handshakes that a well-behaved library will not produce — **say so and convert only what converts cleanly**, leaving the deliberately-malformed builders alone with a comment saying why they stay. A harness that can still construct a bad handshake is worth keeping; a harness that duplicates the good one is not.

```
1. Handshake, session, stream, bytes to a fake upstream and back.
2. Two client connections joining one session, both carrying streams.
3. The client's own session teardown frees everything, under ASan.
4. Every pre-existing test still passes after the harness conversion --
   this is the assertion that the library and the hand-rolled code were
   in fact the same protocol.
```

- [ ] **Step 1: Write the test**
- [ ] **Step 2: Convert the harness; report exactly what converted and what did not**
- [ ] **Step 3: Full suite (54 tests) Debug and ASan, the new test 50x**
- [ ] **Step 4: Commit** — `git commit -m "Add a client end-to-end test and fold the harness onto the library"`

---

## What the previous branches learned

Eighteen test-coverage defects across three branches, every one found by measuring or mutating, none by reading. Six share one shape: **a test whose green comes from a path other than the one it names.** The instances worth remembering while writing this plan's tests:

- A constant chosen so the mechanism under test and its absence produce the same number — twice, including a UID that encoded identically under both base64 alphabets.
- A test bounded by *the constant it was testing*, so it moved with the mutation instead of pinning it.
- An assertion on the wrong side of a connection, which said nothing about the code under test.
- A property whose test covered only the safe half.

Two standing disciplines: **mutate the call sites, not the helper** — twice a helper-body mutation was killed by one covered site while five others were not — and **treat an intermittent failure as a bug rather than noise**; the last branch's final defect was a permanent production stall that appeared as a one-in-two-hundred flake.

## Self-review notes

- **Spec coverage:** §4's resumable-state-machine requirement is Task 3; §5's ClientHello mimicry is consumed, already built. Task 1 is not in the spec — it corrects an implementation decision that contradicted the spec's own threat model, and the reasoning is stated in full above rather than assumed.
- **Placeholder scan:** every task names its files, interfaces and test cases. D1-D5 are settled here. Two decisions are delegated with a stated requirement to justify them: which record-length bound to enforce (D2), and how much of the harness converts (Task 4).
- **Type consistency:** the payload builder's outputs feed `cloak_clienthello_build`'s documented inputs and `cloak_server_auth_decrypt`'s documented inputs, both merged and unchanged. Test counts chain 50 → 51 → 52 → 53 → 54.
- **The riskiest thing here** is Task 1, because it changes the wire format of merged, well-tested code. It is also the only task whose absence would be a security defect rather than a missing feature, which is why it is first.
- **The most consequential thing here** is that Task 1 exists at all. The disguise this program is built to maintain was being dropped one round trip in, and no test noticed, because every test spoke the same wrong dialect to itself.
