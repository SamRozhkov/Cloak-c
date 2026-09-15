# libcloak-client: Connector and Piper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the client transport into a client. After this plan, an application can point a SOCKS or HTTP proxy at a local port and have its traffic carried over a Cloak session: `cloak_client_connector_t` brings up a session across several underlying connections, and `cloak_client_piper_t` accepts local connections and routes each onto a stream.

**Architecture:** Two objects, both event-driven, neither with a thread. The connector runs N handshake state machines concurrently on the reactor and completes when all N have finished, then builds one client-side `cloak_session_t` and attaches every connection to it. The piper is a local listener: each accepted connection reads its first bytes under a deadline, opens a stream, and is spliced to it by `cloak_stream_relay_t` — the same primitive the server's proxy path uses, mirrored.

**Tech Stack:** C11, CMake, CTest with the project's existing assert-based framework.

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` §6's data-plane model (event-driven splicing with backpressure, already implemented by `cloak_stream_relay_t`) and §10's client configuration fields, all of which the config module already parses.

**Reference:** `/Users/sam/Cloak/internal/client/connector.go` (83 lines) and `piper.go`'s `RouteTCP` (the second half). `RouteUDP` is **out of scope** — unordered/datagram mode is its own module later in this project's plan.

## Global Constraints

- C11, `-Wall -Wextra` clean, zero warnings in project code.
- Linux only. `#define _POSIX_C_SOURCE 200809L` as the **first line** of any `.c` needing POSIX APIs.
- Public symbols prefixed `cloak_`; headers under `libcloak-client/include/cloak/` with `CLOAK_<NAME>_H` guards; doc comments stating the contract and **why**.
- Every constructor fully initializes its struct **before** validating its other arguments. Every destroy is idempotent and safe on a zeroed struct.
- **Nothing may block the reactor**, and nothing may sleep.
- `cloak-client` links only `cloak-common` and `cloak-mux`. Tests may link `cloak-server`; the library must not.
- Append to every `CMakeLists.txt`; never rewrite one. `libcloak-server/tests/CMakeLists.txt` lines 46-126 carry a load-bearing ASan/LD_PRELOAD block that must stay byte-identical.
- Test registration: copy an existing entry, always `TIMEOUT 60`. Every test wait bounded; **a bound whose comment names a duration must assert it reached that duration**.
- Build and test (note the `-w` path — `-w /src` silently builds the main checkout):
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/libcloak-connector cloak-c-dev bash -c \
    'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
  ```
- ASan/UBSan, mandatory for every task:
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/libcloak-connector cloak-c-dev bash -c \
    'cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
       -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
       -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
       -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" && \
     cmake --build build-asan -j8 && ctest --test-dir build-asan --output-on-failure'
  ```
- Test counts: **54 before**, 55 after Task 1, 56 after Task 2, 57 after Task 3, 58 after Task 4.

## Decisions taken before execution

**D1 — N concurrent state machines, not N threads.** Go spawns a goroutine per connection and `wg.Wait()`s for all of them. The connector runs N `cloak_client_handshake_t` on one reactor and completes when the last finishes. That is the same shape the dispatcher already uses for many in-flight connections, and it needs no new machinery.

**D2 — do not retry forever; Go's loop is wrong for a library.** Go's `makeconn:` label retries indefinitely with a three-second sleep and a `TODO` admitting the interval should back off. A library that never reports failure to its caller cannot be used by a binary that wants to exit, log, or try a different server. Bound the attempts, back off between them, and **report failure**. Choose the bound and the backoff, justify both against a real network's transient failures, and say in the header that the caller — module 7's `ck-server`'s sibling `ck-client` — is where an operator-visible retry loop belongs if one is wanted.

**D3 — port the Chrome-to-Firefox fallback, and port the reason with it.** Go falls back to the Firefox fingerprint when a direct-mode handshake fails with Chrome, because Cloak v2.11.0's uTLS update pushed Chrome's first packet above 1500 bytes and some networks drop it. This port's Chrome template is 1720 bytes, so the same hazard exists. The fallback is per-connection and sticky for that connection's retries, as in Go. **A comment must carry the reason**, because a reader who does not know it will read the fallback as superstition and delete it.

**D4 — verify every connection agreed on the session key; Go does not.** Go stores each connection's key into an atomic and reads whichever landed last, assuming they are identical. They should be: the server composes each additional connection's reply with the live session's key, which is a rule this project already enforces and tests. But *assuming* it is different from *checking* it, and a disagreement means either a bug on one side or an attacker splitting connections across two servers. **Check, and fail the whole session if they differ.** This is a deliberate improvement on the reference, and the header must say so and say why.

**D5 — the piper's splice is `cloak_stream_relay_t`, not a second implementation.** The client's local-socket-to-stream splice is the exact mirror of the server's upstream-socket-to-stream splice, and that object already handles backpressure, pause/resume, budgets and teardown ordering — all of it learned over two review rounds. Reuse it. `libcloak-server/src/proxy.c` is the worked example of driving it from session callbacks; read it before writing the piper.

**D6 — read the first bytes before opening a stream, as Go does.** `RouteTCP` does `io.ReadAtLeast(localConn, data, 1)` under the stream timeout before it calls `OpenStream`. Port that, and say why in the header: a local connection that opens and sends nothing — a port scanner, a health check, a browser's speculative socket — otherwise consumes a stream and a server-side relay for nothing. The deadline on that read is what stops it pinning resources.

---

### Task 1: `cloak_client_connector_t` — N handshakes into one session

**Files:**
- Create: `libcloak-client/include/cloak/client_connector.h`, `libcloak-client/src/client_connector.c`
- Create: `libcloak-client/tests/test_client_connector.c`
- Modify: `libcloak-client/CMakeLists.txt`, `libcloak-client/tests/CMakeLists.txt`

**Interfaces:**
- Consumes: `cloak_client_handshake_t` (`cloak/client_transport.h`), `cloak_dial_t` (`cloak/net.h`), `cloak_session_t` (`cloak/session.h`), `cloak_client_config_t` (`cloak/config.h`).
- Produces: the connector. Tasks 2-4 consume it.

**The shape.** One context per underlying connection — a `cloak_dial_t`, then a `cloak_client_handshake_t`, then a connected fd and a session key — plus a retry timer and an attempt count. The connector owns N of them and a completion callback that fires once, with either a live `cloak_session_t *` or a typed failure.

**The sequence per connection:** dial → handshake → record the fd and key. On a dial failure or a handshake failure, apply D3's fallback if applicable, back off, and retry until the attempt bound is reached. When all N have succeeded, run D4's key check, build the obfuscator from the agreed key and the configured encryption method, `cloak_session_init` with the configured session id, and `cloak_session_add_conn` every fd.

**Two things to get right that Go gets for free from its runtime:**
- **The completion callback fires exactly once**, whether the outcome is success or failure, and never from inside `cloak_client_connector_start`. Every other one-shot object in this project defers that to a reactor turn (`cloak_dial_t`, `cloak_stream_relay_t`); follow the precedent.
- **Teardown at any point** — after two of five connections have handshaken, with three dials in flight and one timer armed — must free everything and close every fd exactly once. This is the part a reviewer will attack hardest.

- [ ] **Step 1: Write the failing test** — against the real merged server, driving both ends on one reactor as the existing tests do:
```
1. NumConn = 1: a session comes up, and the key matches what the server
   chose.
2. NumConn = 4: one session, four connections attached -- assert the
   server's own switchboard sees four, not that the client thinks it
   sent four.
3. A server that refuses the first connection attempt and accepts the
   retry: the session still comes up. Assert the retry actually happened
   (an attempt counter), not merely that the result was success.
4. Attempts exhausted: the completion callback fires once with a typed
   failure, and nothing leaks.
5. D4: a key disagreement fails the whole session. Force it -- the
   cleanest way is a test-only seam that corrupts one connection's
   recovered key -- and assert the failure is reported rather than the
   session coming up with a wrong key on one connection.
6. Destroy mid-flight, at three distinct points: during dials, during
   handshakes, and after some connections have completed. Under ASan.
7. The completion callback never fires synchronously from start.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (55 tests) Debug and ASan, plus the new test 50x**
- [ ] **Step 5: Mutation-verify cases 2, 3 and 5** — the connection count, the retry, and the key check. Report any not caught.
- [ ] **Step 6: Commit** — `git commit -m "Add cloak_client_connector_t: N handshakes into one session"`

---

### Task 2: `cloak_client_piper_t` — the local listener

**Files:**
- Create: `libcloak-client/include/cloak/client_piper.h`, `libcloak-client/src/client_piper.c`
- Create: `libcloak-client/tests/test_client_piper.c`
- Modify: both CMakeLists

**The shape** mirrors `cloak_proxy_t` on the server, which is the worked example: one context per accepted local connection, an intrusive list, a deadline per context, and a teardown that runs from the session's own callbacks. Read `proxy.c` first — its ownership rules, its save-`next`-before-calling-out iteration and its teardown ordering were established over two review rounds and must not be rediscovered.

**Per accepted connection:** arm a deadline, read at least one byte (D6), open a stream on the session, write those first bytes into it, then start a `cloak_stream_relay_t` splicing the local fd with the stream. From then on the relay owns both.

**The session callbacks** — `on_stream_data` and `on_writable` — must reach the right relay, exactly as `cloak_proxy_t` routes them. The client also needs `on_new_stream`: a server that opens a stream toward the client is a protocol violation for this transport, so decide what to do and say why (refusing is defensible; silently accepting is not).

- [ ] **Step 1: Write the failing test**
```
1. A local connection's bytes reach the server's upstream, and the
   reply reaches the local connection -- byte for byte, both ways.
   Byte-level, because a session with a wrong key establishes cleanly
   and drops every frame silently.
2. Two concurrent local connections get two streams, and their traffic
   does not cross. Different payloads per connection; a crossed route
   passes a single-connection test.
3. A local connection that connects and sends nothing is closed by the
   deadline WITHOUT consuming a stream -- assert the stream count, which
   is the whole point of D6.
4. A large transfer (at least 512 KiB) arrives intact and the session is
   still usable afterwards.
5. The local peer closing its side closes the stream; the stream ending
   closes the local fd.
6. Session broken mid-transfer: every relay stopped, every context freed,
   under ASan.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (56 tests) Debug and ASan, plus the new test 50x**
- [ ] **Step 5: Mutation-verify cases 2, 3 and 6**
- [ ] **Step 6: Commit** — `git commit -m "Add cloak_client_piper_t: the local listener"`

---

### Task 3: Singleplex

**Files:**
- Modify: `libcloak-client/include/cloak/client_piper.h`, `libcloak-client/src/client_piper.c`
- Create: `libcloak-client/tests/test_client_singleplex.c`
- Modify: `libcloak-client/tests/CMakeLists.txt`

Go's `singleplex` gives **each local connection its own session** rather than sharing one. `RouteTCP` calls `newSeshFunc()` per connection when it is set, and closes that session when the stream fails.

The config module already parses the flag. What this task adds is the lifecycle: a session per local connection, brought up by the connector, torn down when its one stream ends — and the failure modes that come with it, since a local connection now waits for a full handshake before its first byte moves.

**Decide and justify:** what a local connection does while its own session is still handshaking. Buffering its first bytes is the obvious answer; so is refusing to accept until the session is ready. Whichever you choose, a slow or failing handshake must not pin an unbounded amount of local data.

```
1. Two local connections in singleplex mode produce TWO sessions on the
   server, not one -- assert the server's registry count.
2. Each session is torn down when its own local connection closes,
   without disturbing the other.
3. A handshake that fails while a local connection is waiting closes
   that local connection cleanly and does not affect any other.
4. Non-singleplex still shares one session -- the same assertion
   inverted, so that a mode flag that did nothing would fail one of them.
```

- [ ] **Step 1: Write the failing test**
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (57 tests) Debug and ASan**
- [ ] **Step 5: Mutation-verify case 1 and case 4 together** — a flag that is ignored must fail one of them.
- [ ] **Step 6: Commit** — `git commit -m "Add singleplex mode to the piper"`

---

### Task 4: End to end — a client and a server, both library code

**Files:**
- Create: `libcloak-client/tests/test_client_full_e2e.c`
- Modify: `libcloak-client/tests/CMakeLists.txt`

The whole thing, wired as two binaries will be: a `cloak_client_piper_t` over a `cloak_client_connector_t` on one side, the merged listener, dispatcher, registry, server state, user manager, panel and proxy on the other, a fake upstream beyond that, and an application socket at the near end.

```
1. An application connection's bytes reach the fake upstream and the
   reply comes back -- byte for byte, through four sockets and two
   sessions' worth of machinery.
2. Several concurrent application connections over one session, each
   with distinct payloads.
3. The server terminating a user mid-transfer (out of credit) tears the
   client down cleanly rather than hanging it.
4. NumConn > 1 with traffic in flight: kill one underlying connection
   and confirm the session survives on the others, or fails cleanly if
   it cannot -- whichever this implementation actually does. Assert what
   it does and record it; do not assume resilience it may not have.
5. Clean shutdown from both ends, under ASan.
```

**A scouting report for module 7 is a deliverable of this task**, as it was for the server modules. `ck-client` will assemble the connector, the piper, a config, a reactor and a signal handler. Count the lines, name every ordering edge that is forced but unenforced, and say whether the `cloak_server_stack_t` helper the server modules recommended has a client-side twin worth building.

- [ ] **Step 1: Write the test**
- [ ] **Step 2: Run it; fix what it finds, or report it if it is a finding rather than a fix**
- [ ] **Step 3: Full suite (58 tests) Debug and ASan, the new test 50x**
- [ ] **Step 4: Commit** — `git commit -m "Add a full client-to-server end-to-end test"`

---

## What the previous branches learned

Twenty-four test-coverage defects across five branches, every one found by measuring or mutating, none by reading. Six share one shape — a test whose green comes from a path other than the one it names — and two sharper variants have been named since:

- **A boundary test must fail on both sides.** A case that only rejects something far outside the range passes with the bound set anywhere. One such gap hid a remotely triggerable heap overflow; another made three newly added bytes invisible in a window of exactly `{2,3,4}`.
- **A test written against the symbol it is testing cannot pin that symbol.** Bound a fixture by the constant under test and it moves with the mutation instead of catching it.

And the lesson the last branch's framing defect taught, which applies directly here because this module is again testing our code against our code: **round-trip tests cannot see a self-consistent error.** Both ends of every test in this project are its own code. Where an outside oracle exists — the real Go implementation, run against our bytes — it is worth the cost.

## Self-review notes

- **Spec coverage:** §6's event-driven splicing is reused rather than reimplemented (D5); §10's client fields are already parsed by the config module and are consumed here. `RouteUDP` is deliberately out of scope and named as such.
- **Placeholder scan:** every task names its files, interfaces and test cases. D1-D6 are settled here. Three decisions are delegated with a stated requirement to justify them: the retry bound and backoff (D2), what the client does with a server-opened stream (Task 2), and what a local connection does while its singleplex session handshakes (Task 3).
- **Type consistency:** `cloak_client_connector_t` is produced in Task 1 and consumed in Tasks 3 and 4; `cloak_client_piper_t` in Task 2 and extended in Task 3. Test counts chain 54 → 55 → 56 → 57 → 58.
- **The riskiest thing here** is Task 1's teardown: N connections in three different states, each owning an fd, a dial, a handshake or a timer. Every previous module in this project has found its worst bug in exactly that shape.
- **The most consequential thing here** is D4. Go assumes all connections agreed on the session key; this port checks. A disagreement is either a bug or an attacker splitting connections across two servers, and silently taking whichever landed last is not a safe default for software whose users are targets.
