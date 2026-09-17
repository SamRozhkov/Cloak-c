# Module 9: unordered (datagram) mode

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** carry datagrams end to end — a UDP application socket at the client, a UDP upstream at the server, and an unordered Cloak session between them — wire-compatible with Go, and prove it against Go's own binaries.

**Architecture:** the Cloak connection stays TCP. "Unordered" is a receive-side policy, not a transport: the stream's receive buffer becomes message-granular with no sorting, no duplicate suppression and no sequence state, and the stream's writer refuses to split instead of splitting. Around that, two new relays — a UDP listener at the client keyed by peer address, and a UDP upstream at the server — plus an ordering mode threaded through session construction the way module 8 threaded the framing mode.

**Tech Stack:** C11, the existing `cloak_reactor_t`, `cloak_bytequeue_t`, `cloak_stream_t`, `cloak_dial_start` (which already handles `SOCK_DGRAM`), and Go 1.25.6 + gorilla in the dev image.

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md`
**Scouting report:** `docs/superpowers/plans/2026-09-17-module-9-scouting.md` — every byte layout, file:line citation and measurement below comes from it.

## Global Constraints

- C11, `-Wall -Wextra` clean, **zero warnings**. Linux only; `_POSIX_C_SOURCE 200809L` first line of every `.c`.
- **Nothing may block the reactor.** Single-threaded, edge-triggered; every Go blocking idiom becomes a resumable state machine.
- ASan+UBSan mandatory alongside Debug. Run tests through `ctest`, **never a test binary directly**, or `LD_PRELOAD` is absent and the shims do not load.
- Docker image `cloak-c-dev`, `-w /src/.worktrees/<branch>`. **Never `-w /src`.**
- `TIMEOUT 120`; **do not raise it** — make a slow case cheaper instead. Every wait bounded by the clock, never by an iteration count.
- **Ephemeral ports everywhere.**
- 68 tests pass at `bc7e936`. **Every existing test must pass UNMODIFIED**, except the two named in D6, which pin behaviour this module deliberately reverses.
- **Revert a mutation with `cp`, never `mv`** — `mv` preserves mtime, the build skips, and the test passes against the un-reverted binary.
- **Per-agent scratch directory and per-agent worktree.** Both were learned the hard way on module 8: a shared scratchpad overwrote an agent's mutation driver mid-round, and a fix round entered a review worktree while the reviewer was still confirming it.
- A comment that asserts a measurement must **either cite a test that would fail, or say plainly that it was read rather than measured.** Module 8 needed five such corrections.

---

## Decisions already made

**D1 — the module's name is wrong and the plan uses the right one: this is unordered semantics over TCP.** Settled with evidence: the Cloak connection is always TCP (`internal/client/connector.go:29` literal `"tcp"`; `cmd/ck-server/ck-server.go:183` `net.Listen("tcp", ...)`). Only the application-side and ProxyBook-side sockets are UDP, and `ProxyMethod`/`ProxyBook` picks the upstream socket type **independently** of the `Unordered` flag — nothing cross-checks them. Do not open a UDP socket for the Cloak connection anywhere.

**D2 — the behavioural surface in Go is two lines, and the plan must not invent a third.** `grep -n Unordered internal/multiplex/*.go` returns exactly three lines, one of which is the config field. The other two are `stream.go:58-62` (which receive buffer) and `stream.go:127-137` (refuse to split rather than splitting). **The session does nothing else differently, the switchboard nothing at all, and the frame layer nothing bit for bit.** An unordered frame and an ordered frame with the same field values are byte-identical.

**D3 — `fixedConnMapping` is dead upstream and must not be ported.** `makeSwitchboard` hardcodes `uniformSpread`; commit `5988b43` (2024-04-14) deleted the `if sesh.Unordered` branch. The comment at `stream.go:37-42` still describes the old behaviour and **is false**. The C port already omits both; record that as deliberate so nobody "restores" it. The consequence matters: with the default `NumConn: 4`, consecutive frames of one stream go down four different TCP connections, so **ordered mode's sorter is the only thing holding the stream together** — it is not belt-and-braces over TCP.

**D4 — the ordering mode is an enum whose zero value is INVALID, and it is a field, not a parameter.** Module 8 bought this discipline and it held: forcing `CLOAK_CONN_FRAMING_INVALID` failed 19 tests, and the trap proved undefeatable from the dispatcher. The identical blindness applies here — **a C↔C test passes whichever ordering mode both ends use.** So:

```c
typedef enum {
    CLOAK_SESSION_ORDERING_INVALID   = 0, /* an un-updated call site FAILS construction */
    CLOAK_SESSION_ORDERING_ORDERED   = 1,
    CLOAK_SESSION_ORDERING_UNORDERED = 2
} cloak_session_ordering_t;
```

as a **field of `cloak_session_config_t`**, with a **distinct error code** so a test can assert the diagnosis rather than "non-zero". Every existing `cloak_session_config_t` and `cloak_stream_init` call site must be updated — `client_stack.c`, `proxy.c`, `registry.c` and roughly 15 test files. **That churn is the mechanism, not a cost to avoid.** Do not add an `int unordered` defaulting to 0; 0 would then be a valid mode and the mechanism would protect nothing.

**D5 — under backpressure we DROP, Go BLOCKS, and this is a declared divergence no oracle can adjudicate.** Go gives each peer a goroutine and lets a blocking write stall it. A single-threaded reactor cannot stall one peer without stalling all of them, so a full datagram queue drops. Say so in the code, with the reasoning, and test the drop policy directly — no test against Go can decide it for us.

**D6 — two tests pin behaviour this module reverses**, and they change with it: `cmd/ck-client/tests/test_ck_client_cli.c:1007-1040` (`test_udp_is_refused`, which asserts both exit codes and the word "unordered" in both messages) becomes `test_udp_is_honoured`, and its file-header case 4 at `:27-30` moves with it. Everything else stays untouched.

**D7 — fidelity and correctness point in different directions at three datagram sizes, and the plan chooses in writing.** Go has bugs here (below). For each size the C port does the **correct** thing and documents the divergence, because these are application-visible data corruption, not protocol details:
- **> 16132 bytes outbound**: refuse with the `io.ErrShortBuffer` analogue, matching Go's stream layer. Same as Go.
- **8193 … 16132 bytes**: carry it. **Go loses it and tears down the stream** (bug #6). We do not.
- **> 8192 bytes read from the local UDP socket**: read the whole datagram up to 16132. **Go silently truncates to 8192** (bug #7). We do not.
- **zero-length datagram**: **swallow it, matching Go.** *(Reversed from the original wording after Task 4 measured it. The criterion was whether carrying it is wire-visible; it is, and worse — "carry it" was never reachable in the first place. Go's frame **encoder** refuses an empty payload outright, not just `Stream.Write`'s loop, and our `cloak_frame_obfuscate` refuses identically, so `stream.c` could not have carried one. A Go receiver fed a hand-built zero-length frame accepts it silently, so the peer's reaction does not decide it — the 30-byte record does, against Go's 31-byte floor past seq 4. Bug #8 therefore stands as a Go observation we deliberately reproduce, not a divergence.)*

## Three more bugs in the Go original, all reproduced at the built `v2.12.0` binaries

- **#6 — a reply datagram of 8193…16132 bytes is silently lost *and* tears down that peer's stream.** The server reads up to `maxStreamUnitWrite` = 16132; the client's reader goroutine uses an 8192 buffer (`piper.go:60`); `datagramBufferedPipe.Read` returns `ErrShortBuffer` **without consuming**. Measured: 8192 works, 8193 vanishes, "stream 1 actively closed", the next datagram opens stream 2.
- **#7 — an outbound datagram > 8192 is silently truncated.** `piper.go:25`'s 8192 buffer plus Go's UDP `ReadFrom` dropping the excess without error. Measured: 8193 arrived upstream as 8192; 20000 arrived as 8192. **Application-visible corruption with 16132 bytes of protocol budget unused.**
- **#8 (minor) — a zero-length datagram is swallowed.** `Stream.Write` with `len == 0` runs its loop zero times and sends nothing. Measured.

That is eight bugs this port has found in the reference implementation.

---

## The two things that will get us, and why the oracle cannot see either

**The mode is invisible on the wire.** The only evidence of it anywhere is **bit 0 of byte 41 of the encrypted 48-byte auth payload**. An interop test that checks datagrams arrive cannot distinguish the modes at all. So "it works against Go" will be true of an implementation that ignores the flag entirely.

**`Seq` is still generated, still monotonic, and still half the AEAD nonce — the unordered receiver just ignores it.** Pinning `Seq = 0` as an "obvious" simplification is **silent GCM nonce reuse**, and a C↔C round-trip test passes perfectly. This needs its own white-box test; no oracle will ever see it. This is the same shape as the defect module 8 found, one layer up.

---

### Task 0: the fast/slow `ctest` split

**Files:** the `CMakeLists.txt` of each test directory; no source changes.

Measured today at `-j4`: **68/68 in 23.1 s**, with `test_adminapi` at 12.2 s and `test_dispatcher_ws` at 12.0 s — **the wall-clock floor is already set by a single test, not by the total.** Module 9 adds at least two more forking tests, and the oracle tests fork two foreign binaries plus a UDP echo each; they land straight at the top of that table.

Label the forking tests `slow`; make `ctest -L fast` the edit-loop target; **keep the default `ctest` running everything** so the test count stays part of the contract, exactly as `CLOAK_REQUIRE_GO=OFF`'s visible 68→67 does.

- [ ] **Step 1: measure and record the per-test table before the change** (`ctest -j4 --output-on-failure` timings), so the split's effect is a measurement and not a claim.
- [ ] **Step 2: add the labels; verify `ctest` still reports 68 and `ctest -L fast` reports fewer, with the difference exactly the labelled set.**
- [ ] **Step 3: record the measured `-L fast` wall time.**
- [ ] **Step 4: Commit** — `git commit -m "Split the suite into fast and slow tiers"`

---

### Task 1: the Go-binary oracle for the direct path

**Files:** `Dockerfile.dev` (multi-stage); `libcloak-server/tests/test_go_interop.c` (or the directory the reviewer prefers); its CMake registration.

**This task exists because the direct TLS path and the entire C client have never been tested against foreign code**, and module 8 found that the first such test discovered the port could not exchange a single frame with Go. **It may well find something before a line of unordered code is written.** Run it in both roles: Go client → C server exercises our ClientHello parser, auth decrypt and relay; C client → Go server exercises our ClientHello *generator*, our byte 41 and our frame generator.

**Cost, measured in the dev image:** 10 modules, **114 MB** module cache, binaries **9,806,033** and **10,259,237** bytes; cold fetch+build 21.8 s, compile-only 9.2 s, warm rebuild 0.14 s.

**`go install …@v2.12.0` does not work** — Cloak's `go.mod` has no `/v2`, so the proxy serves no v2 tags and Go falls back to git, which the image lacks. Use a **multi-stage build fetching the release tarball with the existing `curl`: +30 MB, 22.5 s.** A git-plus-single-stage variant costs +450 MB. `v2.12.0` == `c3d5470` == local HEAD, verified.

- [ ] **Step 1: Write the failing test**
```
1.  Go ck-client -> C ck-server: a TCP session, bytes through the proxy,
    compared byte for byte, with a payload crossing several frames.
2.  C ck-client -> Go ck-server: the same, the other way.
3.  Negative control: corrupt one byte of the C server's ServerHello and
    assert the Go client refuses. A positive-only interop test proves
    nothing -- module 8's controls bit, which is what made its passes mean
    something.
4.  Byte 41 asserted 0 in both directions (ordered), so task 7 has a
    baseline to flip.
```
- [ ] **Step 2: Run to verify it fails** (before the Dockerfile change, it must fail for a *named* reason — a missing binary — not a timeout)
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (69 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Prove the direct path against Go's own binaries"`

---

### Task 2: `cloak_session_ordering_t`

**Files:** `libcloak-mux/include/cloak/session.h`, `src/session.c`, `include/cloak/stream.h`, `src/stream.c`; every call site — `libcloak-client/src/client_stack.c`, `libcloak-server/src/proxy.c`, `libcloak-server/src/registry.c`, ~15 test files.

**Interfaces — produces:** the enum from D4, as a field of `cloak_session_config_t`, plus a distinct error code (`CLOAK_SESSION_ERR_INVALID_ORDERING`, or the surrounding convention's spelling) so a test asserts the diagnosis.

- [ ] **Step 1: Write the failing tests**
```
1.  A memset-zeroed cloak_session_config_t FAILS construction with the
    NAMED error code, not merely non-zero. Module 8's precedent exists
    because "any non-zero return" passes against an implementation that
    never looked at the field.
2.  Both valid values construct.
3.  An out-of-range value (3, 255) fails with the same named code.
4.  cloak_stream_init carries the mode from its session; a stream cannot
    disagree with the session that owns it.
```
- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement, and update every call site**
- [ ] **Step 4: Full suite (69 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Give the session an ordering mode whose zero value is invalid"`

---

### Task 3: the datagram receive queue

**Files:** `libcloak-mux/include/cloak/msgqueue.h`, `src/msgqueue.c` (new); the unordered branch in `libcloak-mux/src/stream.c`.
**Interfaces — consumes** Task 2's mode. **Produces** a message-granular queue.

Go's `datagramBufferedPipe`, verbatim in behaviour: **no sequence state, no heap, no duplicate check.** An out-of-order frame is delivered immediately, out of order. A duplicate frame is **accepted and delivered again**. A closing frame sets closed **immediately on arrival**, before any earlier data frame still in flight. Read granularity is **one whole datagram**; a short read buffer returns the `ErrShortBuffer` analogue **and does not consume the datagram** (`datagramBufferedPipe.go:58-60` returns before `:62` pops `pLens`).

Note the interaction that will bite: **`cloak_stream_feed_frame`'s `-1` return retires the stream today**, and three of the scouting report's six divergences route through that one value. A duplicate frame must not retire an unordered stream.

- [ ] **Step 1: Write the failing tests**
```
1.  Out-of-order delivery: feed seq 2 then seq 1; both are delivered, in
    ARRIVAL order. The ordered mode sorts them. Same fixture, both modes.
2.  A duplicate frame is accepted and delivered TWICE in unordered mode
    and dropped in ordered mode -- and in neither case does the stream
    retire.
3.  Read with a buffer one byte short: returns the ErrShortBuffer analogue
    and the datagram is STILL QUEUED -- assert by reading it again
    successfully with a large enough buffer. A test that only checks the
    error code would pass against an implementation that consumed it.
4.  A closing frame arriving before an earlier data frame closes the
    stream immediately, matching Go.
5.  Message boundaries survive: three writes of 1, 1500 and 8191 bytes
    come back as exactly three reads of exactly those sizes.
```
- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (70 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Add the datagram receive queue"`

---

### Task 4: the writer refuses to split

**Files:** `libcloak-mux/src/stream.c`.

`maxStreamUnitWrite` = `16401 − 14 − 255` = **16132**, and the C port already derives the same number. In unordered mode a write larger than that returns the `ErrShortBuffer` analogue and **sends nothing at all** — not a partial write, not a split.

- [ ] **Step 1: Write the failing tests**
```
1.  MEASURED BRACKET: 16132 succeeds and sends exactly one frame; 16133
    refuses and sends ZERO frames. Assert the frame count on the wire,
    not just the return code -- a refusal that has already written half
    the data is the failure this test exists to catch.
2.  The same two sizes in ORDERED mode: 16133 splits into two frames and
    succeeds. Same fixture, both modes.
3.  A zero-length write in unordered mode is SWALLOWED, matching Go --
    see D7, which Task 4 reversed by measurement. Assert that nothing
    reaches the wire, and say in the test that the frame encoder, not the
    stream layer, is what refuses it.
```
- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (70 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Refuse to split an oversize datagram"`

---

### Task 5: the client's UDP local listener

**Files:** `libcloak-client/include/cloak/udp_piper.h`, `src/udp_piper.c` (new); wiring in `client_stack.c`.

**This is the riskiest task in the plan and the only one with no precedent in the tree to copy.** `cloak_listener_open` is `listen()`/`accept4()` and is not reusable. One edge-triggered fd multiplexes many peers; one peer's backpressure must not stall the others; Go's goroutine-per-peer blocking model does not translate. **D5's drop policy is a declared divergence and no test against Go can validate it.**

Go's model for reference (`internal/client/piper.go:15-100`): one `*net.UDPConn`, a map keyed by `addr.String()`, one stream and one reader goroutine per source address, lifetime governed by the `streamTimeout` read deadline refreshed on every datagram in either direction.

- [ ] **Step 1: Write the failing tests**
```
1.  Two peers on one socket get two distinct streams, and traffic does not
    cross between them.
2.  A slow peer does NOT stall a fast one: fill one peer's queue and
    assert the other still completes. This is D5's whole point.
3.  The drop policy, asserted directly: a full queue drops the NEWEST or
    the OLDEST -- decide which in the code and pin whichever you chose,
    with a counter, not with "the connection survived".
4.  Per-peer deadline: a silent peer's stream is retired after the
    deadline, and its descriptor is released -- assert via /proc/self/fd,
    because LeakSanitizer does not track descriptors.
5.  A datagram of 16132 is carried whole (D7: Go truncates at 8192).
6.  Peer-map eviction under churn: 1000 short-lived peers leave no
    descriptors and no unbounded growth.
```
- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (71 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Route UDP from the client's local socket"`

---

### Task 6: the server's UDP upstream

**Files:** `libcloak-server/src/proxy.c` — remove the guards at `:609-611` and `:634-640`; `libcloak-server/include/cloak/proxy.h:545-575` — reasons 1 and 3 of the four-case list.

`cloak_dial_start` already handles `SOCK_DGRAM` correctly and comments the case.

**Re-verify, do not inherit, `proxy.h`'s reason 1**: it claims checking only on the CREATE path is the complete check, because an additional connection joining an already-ordered session never reaches the callback. That is true of Go and stays true — **but once unordered is implemented, a second connection whose flag disagrees with the live session silently joins it.** That is a real cross-mode hazard that today's refusal hides. Decide what it should do and pin it.

- [ ] **Step 1: Write the failing tests**
```
1.  A datagram reaches a UDP upstream and its reply returns, byte for
    byte, with the boundary preserved.
2.  A datagram of 16132 round-trips (Go loses 8193..16132 -- bug #6).
3.  The cross-mode hazard: a second connection advertising the opposite
    ordering joins a live session. Assert whatever this plan decides --
    refuse at join, or accept and log -- but assert it, because today's
    refusal is what hides it.
4.  The prose at proxy.h:545-575 is updated in THIS commit, not later.
```
- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (72 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Relay datagrams to a UDP upstream"`

---

### Task 7: wire the flag through

**Files:** `cmd/ck-client/main.c` — remove `:758-764` and `:863-868`, fix the usage line at `:206` to Go's own wording (`"udp: set this flag if the underlying proxy is using UDP protocol"`), and the file-header block at `:96-103`; `cmd/ck-client/tests/test_ck_client_cli.c:1007-1040` and its header case at `:27-30`.

**And close the gap that is not a refusal**: `libcloak-client/src/client_stack.c:460` already does `cc.unordered = c->udp;`, which reaches `client_auth.c:81` and sets wire bit `[41]&0x01`. **So a library consumer can today advertise unordered to the server while running the ordered data path.** Our own server refuses it, so it fails closed — but it fails at the *peer*, and **against a Go server it would not fail at all.** Pin this with a test.

- [ ] **Step 1: Write the failing tests**
```
1.  test_udp_is_refused becomes test_udp_is_honoured: -u and "UDP": true
    both start, and the usage text matches Go's wording.
2.  Byte 41 bit 0 is 1 with -u and 0 without -- asserted on the wire, both
    ways round. This is the ONLY on-wire evidence the mode exists.
3.  The library-consumer gap: setting udp = 1 through libcloak-client
    now genuinely selects the unordered data path, not just the bit.
```
- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (72 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Honour -u and \"UDP\": true"`

---

### Task 8: prove it, including what no oracle can see

**Files:** extend Task 1's interop test; a reordering harness; white-box frame-level tests.

- [ ] **Step 1: Write the failing tests**
```
1.  Datagram size ladder, BOTH roles: 1, 2, 1500, 8191, 8192, 8193, 16131,
    16132, 16133 -- asserting the EXACT received sizes, not arrival. This
    is the test that would have caught Go's bugs #6 and #7, and the one
    that catches a C port that splits. Expect asymmetric results against
    Go and record each as measured behaviour.
2.  DELIBERATE REORDERING. A harness that buffers frames from two
    connections and releases them reversed. Unordered delivers both in
    arrival order; ordered delivers them sorted. This is the only test
    that proves the mode does anything at all -- over loopback with
    NumConn 4, frames essentially never arrive out of order by themselves.
3.  NO ORACLE, WHITE BOX: seq strictly increasing per stream, observed
    with our own deobfuscator on a captured connection. A Seq = 0
    "simplification" is silent AEAD NONCE REUSE and passes every
    round-trip test. Name this in the test as an unoracled property.
4.  NO ORACLE, DISTRIBUTION: the pad/no-pad boundary at frame index 5, and
    the padding length distribution, in unordered mode. Module 8 found
    four distribution biases that no interop test could see; this is where
    module 9 would hide a fifth.
5.  Duplicate/late frame replay, both modes (see Task 3 case 2), end to
    end rather than at the unit.
```
- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (73 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Prove unordered mode, including what the oracle cannot see"`

---

## Properties with no oracle — carry forward explicitly

Every distribution; sequence-number generation and therefore AEAD nonce uniqueness; the drop-versus-block policy (D5); peer-map eviction; and the `unordered × WebSocket` cross product, which Go permits and which stays untestable until module 8b exists.

**Could not be determined by scouting, and the plan should not pretend otherwise:** whether real reordering ever occurs over loopback with `NumConn: 4` — it could not be forced, which is why Task 8's injection harness is not optional. And whether the C switchboard's connection pick is bias-free like Go's `Uint32N`; it was flagged for measurement and not measured. **Measure it in Task 8 case 4.**

## Self-review

- **Spec coverage:** the spec's unordered section is Tasks 2-7; Tasks 0, 1 and 8 are infrastructure and proof, and D1 corrects the spec's implied transport.
- **Placeholder scan:** every task names its files, interfaces and test cases with exact values. D1-D7 are settled. No task says "similar to Task N".
- **Type consistency:** `cloak_session_ordering_t` is produced in Task 2 and consumed in Tasks 3, 4, 6 and 7; the message queue in Task 3 and consumed in Tasks 5 and 6. Counts chain 68 → 68 → 69 → 70 → 70 → 71 → 72 → 72 → 73.
- **The riskiest task is 5**, for the reason stated in it: no precedent in the tree, a model that does not translate from Go, and a correct behaviour under pressure that no test against Go can validate.
- **The most consequential thing here is Task 1**, which is not about unordered mode at all. The direct path and the whole C client have never met foreign code, and the last time this port did that it discovered it could not exchange a single frame with Go.
