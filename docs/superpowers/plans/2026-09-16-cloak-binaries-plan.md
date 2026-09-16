# ck-server and ck-client: Binaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two programs a person can run. After this plan `ck-server` and `ck-client` exist, take the same flags and configuration files as the Go originals, generate keys and UIDs, run as shadowsocks plugins, and shut down cleanly on a signal.

**Architecture:** Two construct-and-teardown helpers and two thin binaries. Every previous module's scouting report reached the same conclusion independently: the object graphs are too easy to wire wrong — nine objects and nine forced-but-unenforced ordering edges on each side, two of the client's not the reverse of construction, and at least one on each side that fails *silently*. So `cloak_server_stack_t` and `cloak_client_stack_t` own the wiring, the chains, the trampolines and the teardown order, and become the only supported way to assemble either side. The binaries above them are argument parsing, configuration loading, logging, signals, and a loop.

**Tech Stack:** C11, CMake, CTest with the project's existing assert-based framework.

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` §10 — "CLI: `getopt_long`, mirroring the Go flags (`-c -s -p -l -i -u -k -uid -key -v -h -verbosity`). Key/UID generation (`-k`/`-key`, `-u`/`-uid`) uses OpenSSL `RAND_bytes` + X25519 keygen."

**Reference:** `/Users/sam/Cloak/cmd/ck-server/{ck-server.go,keygen.go}` and `/Users/sam/Cloak/cmd/ck-client/ck-client.go`.

## What three modules' scouting reports asked for, and why this plan starts with it

- **Server side:** about 129 lines of wiring — 68 construction, 34 teardown, 27 trampolines — across nine objects, three `chain` assignments plus the registry callback, and a destruction order with two inversions. **Nine forced edges, all silent, exactly one enforced anywhere** (`cloak_userpanel_open` refuses to start without `on_session_closing`).
- **Client side:** 76 lines for the object graph, about 325 for a realistic `main.c`. Nine forced-but-unenforced edges, **two of them not the reverse of construction**, and one that fails silently — install-after-init connects and then moves no bytes.
- Every report reached the same verdict without being told the others had: build the helper, and make it the only supported wiring.

The failure these prevent is not a crash at startup. It is a server that runs, serves traffic, and then produces a use-after-free on the next upstream byte after a user is terminated — because an owner installed the panel's broken callback directly as the registry's, which is exactly what every pre-adminapi caller did.

## Global Constraints

- C11, `-Wall -Wextra` clean, zero warnings in project code.
- Linux only. `#define _POSIX_C_SOURCE 200809L` as the **first line** of any `.c` needing POSIX APIs.
- Public symbols prefixed `cloak_`; headers with `CLOAK_<NAME>_H` guards; doc comments stating the contract and **why**.
- Every constructor fully initializes its struct **before** validating its other arguments. Every destroy is idempotent and safe on a zeroed struct.
- **Nothing may block the reactor**, including in `main`.
- Append to every `CMakeLists.txt`; never rewrite one. `libcloak-server/tests/CMakeLists.txt` lines 46-126 carry a load-bearing ASan/LD_PRELOAD block that must stay byte-identical.
- Test registration: copy an existing entry, always `TIMEOUT 60`. Every test wait bounded by the clock; **a bound whose comment names a duration must assert it reached that duration** — and note `pump_until` is now a real time bound, fixed in seven copies last branch.
- Build and test (note the `-w` path — `-w /src` silently builds the main checkout):
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/cloak-binaries cloak-c-dev bash -c \
    'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
  ```
- ASan/UBSan, mandatory for every task:
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/cloak-binaries cloak-c-dev bash -c \
    'cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
       -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
       -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
       -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" && \
     cmake --build build-asan -j8 && ctest --test-dir build-asan --output-on-failure'
  ```
- Test counts: **58 before**, 59 after Task 1, 60 after Task 2, 61 after Task 3, 62 after Task 4, 63 after Task 5.

## Decisions taken before execution

**D1 — the stacks are the only supported wiring, and they enforce what they can.** Documentation has been tried for three modules and the edges are still silent. Each stack validates what a caller can still get wrong (a NULL where a callback is mandatory, a configuration the layers below will reject later, an order the API cannot express) and returns a typed error naming the edge. Where enforcement is impossible, the header says so at that edge rather than in a preamble.

**D2 — signals reach the reactor as a file descriptor.** `signalfd` is the natural fit for an epoll loop and avoids every async-signal-safety question a handler would raise. Block the signals, register the fd, and treat a delivered `SIGINT`/`SIGTERM` as an ordinary readable event that begins shutdown. Say in the header why a plain handler was not used.

**D3 — Go's server cannot actually take inline configuration, and this port will.** `server.ParseConfig` reads the path, and **when the read fails it unmarshals the empty buffer it just failed to fill** rather than the string itself — so the flag help's "path to the configuration file or its content" is false for the server. Our `cloak_server_config_parse_file` / `_parse_json` split already makes the correct behaviour easy. Implement it correctly, and record the divergence where a reader comparing the two will find it.

**D4 — the client's reconnect loop owns an obligation the library deliberately left it.** The connector bounds its retries and reports failure (a previous module's D2), so the binary is where an operator-visible loop belongs. That loop **must use a fresh session id each time and back off**: when one connection exhausts its attempts the whole session fails, abandoning N−1 already-authenticated sockets, and the server holds that session until its inactivity timeout. Reusing the id on a flaky network multiplies server-side sessions per client.

**D5 — plugin mode is in scope, because it is how most people run Cloak.** Both binaries detect `SS_LOCAL_HOST`/`SS_LOCAL_PORT` and take their configuration from `SS_PLUGIN_OPTIONS`. The client's is an ssv string (`cloak_client_config_parse_ssv` exists); the server's is JSON in Go too, so no server-side ssv parser is needed — confirm that against `ParseConfig` rather than trusting this sentence. The server additionally injects `ProxyBook["shadowsocks"]` from `SS_LOCAL_HOST`/`PORT` and merges `SS_REMOTE_HOST`/`PORT` into its bind list, including Go's `host|host` IPv4-and-IPv6 form.

**D6 — no `pprof`.** Go's `-d` flag starts a profiling HTTP server. There is no equivalent here and adding one would be a second listening socket in a program whose entire purpose is not being noticed. Reject the flag with a message saying so.

---

### Task 1: `cloak_server_stack_t`

**Files:**
- Create: `libcloak-server/include/cloak/server_stack.h`, `libcloak-server/src/server_stack.c`
- Create: `libcloak-server/tests/test_server_stack.c`
- Modify: `libcloak-server/CMakeLists.txt`, `libcloak-server/tests/CMakeLists.txt`

**What it owns:** a reactor (borrowed), a `cloak_server_t`, a `cloak_usermanager_t`, a `cloak_userpanel_t`, a `cloak_proxy_t`, a `cloak_adminapi_t`, a `cloak_server_registry_t`, a `cloak_dispatcher_t`, and one `cloak_listener_t` per bind address. It owns the four-link broken chain (registry → proxy → adminapi → panel → owner), the `on_session_closing` trampoline the panel refuses to start without, and the teardown order.

**Read before designing:** `libcloak-server/tests/test_admin_e2e.c` and `test_server_e2e.c` — their fixtures are the working prototype this task generalises, and the scouting reports named them as such.

**What must be enforced, not documented:** every edge a caller can still get wrong once the stack exists. At minimum, the stack must make it impossible to install the panel's broken callback as the registry's head, to forget the `on_session_closing` trampoline, or to destroy in an order that leaves a relay holding a freed stream. Where the C API genuinely cannot prevent something, say so at that edge.

- [ ] **Step 1: Write the failing test**
```
1. A stack built from a parsed config serves a real handshake and moves
   bytes end to end -- the same property test_server_e2e.c asserts, now
   through the helper.
2. The four-link chain runs end to end: break a session with both a live
   proxy relay and a live admin stream, and assert every link observed
   it, in order. Then mutate each link's wiring INSIDE the stack and
   confirm the test fails for each -- the previous module proved this is
   the only way that chain gets pinned.
3. Teardown in the stack's own order frees everything, under ASan, with
   traffic in flight.
4. Every enforced edge rejects: a config the layers below would reject,
   a missing mandatory callback, whatever else Task 1 chooses to
   enforce. One case per edge, each naming the edge in its error.
5. Multiple bind addresses all accept.
6. A stack built and destroyed twice in one process leaves nothing
   behind -- fd accounting via /proc/self/fd, since LeakSanitizer does
   not track descriptors.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (59 tests) Debug and ASan**
- [ ] **Step 5: Mutation-verify case 2 per link and case 4 per edge**
- [ ] **Step 6: Commit** — `git commit -m "Add cloak_server_stack_t: the server's only supported wiring"`

---

### Task 2: `cloak_client_stack_t`

**Files:**
- Create: `libcloak-client/include/cloak/client_stack.h`, `libcloak-client/src/client_stack.c`
- Create: `libcloak-client/tests/test_client_stack.c`
- Modify: both CMakeLists

**What it owns:** a reactor (borrowed), a `cloak_client_connector_t` per session, a `cloak_client_piper_t`, the session-maker callback the piper calls, and **the reconnect loop of D4**. Singleplex makes the graph dynamic — a session per local connection — so the stack must handle instances created and destroyed on a hot path.

**The reconnect loop is the substance.** When a session fails or dies, the stack brings up a new one with a **fresh session id** and a backoff, and the piper's waiting connections either wait or fail according to the piper's own contract. State the backoff and the bound, and what happens to a local connection whose session never comes up.

- [ ] **Step 1: Write the failing test**
```
1. A stack against a real server carries application bytes end to end.
2. The session dying brings up a replacement with a DIFFERENT session id
   -- assert the id changed, which is D4's whole point, not merely that
   traffic resumed.
3. Backoff is observed between attempts: assert the elapsed time reached
   its bound, with a measured bracket rather than a claimed margin.
4. Singleplex: two local connections, two sessions, each torn down with
   its own connection.
5. A local connection whose session never comes up is dealt with
   according to the stated contract, within a bound.
6. Teardown at every stage -- mid-handshake, mid-traffic, mid-backoff --
   under ASan.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (60 tests) Debug and ASan, plus the new test 50x**
- [ ] **Step 5: Mutation-verify cases 2, 3 and 6**
- [ ] **Step 6: Commit** — `git commit -m "Add cloak_client_stack_t and the reconnect loop"`

---

### Task 3: The shared binary runtime

**Files:**
- Create: `libcloak-common/include/cloak/signals.h`, `libcloak-common/src/signals.c`
- Create: `libcloak-common/include/cloak/keygen.h`, `libcloak-common/src/keygen.c`
- Create: `libcloak-common/tests/test_signals.c`
- Modify: both CMakeLists

**Two small things both binaries need.**

`cloak_signalfd_t` (D2): block `SIGINT` and `SIGTERM`, create a `signalfd`, register it with the reactor, and invoke a callback when one arrives. Restore the previous mask on destroy. Say in the header why `signalfd` rather than a handler, and what happens to a signal delivered before the fd exists.

Key and UID generation, mirroring `keygen.go`: a 16-byte UID and an X25519 key pair, each base64 standard-encoded. The primitives all exist — `cloak_random_bytes`, `cloak_x25519_generate_keypair`, `cloak_base64_encode`. This is assembly, not invention, and its value is that both binaries and any test can call it.

- [ ] **Step 1: Write the failing test**
```
1. A signal delivered while the reactor runs invokes the callback
   exactly once and the reactor returns.
2. The previous signal mask is restored on destroy -- assert with
   sigprocmask, not by inspection.
3. Two signals deliver two callbacks (or one, if that is the documented
   contract -- state it and assert it).
4. Generated UIDs are 16 bytes and decode back to what was generated;
   two calls differ.
5. A generated key pair round-trips: the public key derived from the
   private one equals the public one reported.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (61 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Add signalfd shutdown and key generation"`

---

### Task 4: `ck-server`

**Files:**
- Create: `cmd/ck-server/main.c`, `cmd/ck-server/CMakeLists.txt`
- Create: `cmd/ck-server/tests/test_ck_server_cli.c` (or wherever the project's test layout puts a binary's tests — follow the existing convention)
- Modify: the root `CMakeLists.txt`

**What it does**, in order: parse arguments; handle `-v`, `-h`, `-u`/`-uid`, `-k`/`-key` and exit; set the log level from `-verbosity`; detect plugin mode; load the configuration (D3 — a path *or* inline content, unlike Go); resolve bind addresses, defaulting to `:443` and `:80` when none is given and not in plugin mode; apply the plugin-mode `ProxyBook` and bind-address merging (D5); build a `cloak_server_stack_t`; install the signal handler; run the reactor; shut down.

**Flags to mirror exactly:** `-c`, `-v`, `-h`, `-u`, `-k`, `-uid`, `-key`, `-verbosity`. `-d` is rejected with a message (D6).

**Exit codes matter for a daemon.** Decide them and document them: success, configuration error, bind failure, runtime failure. Go uses `log.Fatal` throughout, which is exit 1 for everything; a daemon under a supervisor deserves better, so this is a deliberate improvement — say so.

- [ ] **Step 1: Write the failing test.** Drive the binary as a subprocess:
```
1. -h and -v print and exit 0 without touching the network.
2. -u and -uid produce a 16-byte UID (decode it); -k and -key produce a
   valid X25519 pair (verify the public key derives from the private).
   The script and human forms differ in format but agree in value.
3. A bad config path exits with the configuration error code and says
   which file.
4. Inline JSON content works where Go's server would fail (D3).
5. A config with no BindAddr listens on :443 and :80 -- or fails
   cleanly if unprivileged, which is what a test will actually see;
   assert whichever, and say which.
6. SIGTERM shuts down cleanly: exit 0, no leaked descriptors.
7. Plugin mode: with the SS_ environment set, the ProxyBook gains the
   shadowsocks entry and the bind list gains the SS address.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (62 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Add the ck-server binary"`

---

### Task 5: `ck-client`

**Files:**
- Create: `cmd/ck-client/main.c`, `cmd/ck-client/CMakeLists.txt`
- Create: its test, following Task 4's convention
- Modify: the root `CMakeLists.txt`

**What it does:** parse arguments (`-i`, `-l`, `-s`, `-p`, `-u`, `-c`, `-proxy`, `-a`, `-v`, `-h`, `-verbosity`), where **command-line arguments override the JSON**, as Go documents; detect plugin mode and take `SS_PLUGIN_OPTIONS` as an ssv string; load and validate the configuration; build a `cloak_client_stack_t`; install signals; run; shut down.

**`-a` (admin mode)** sets the UID to the admin UID, the session id to 0 and `NumConn` to 1, exactly as Go does — and with the admin API merged, this client can actually drive it.

**`-u` (UDP) is out of scope** and must be rejected with a message saying so, not silently ignored: unordered mode is a later module, and a client that accepts the flag and then carries TCP would be worse than one that refuses.

- [ ] **Step 1: Write the failing test**
```
1. -h and -v print and exit 0.
2. Flags override the JSON: a config naming one remote host plus -s
   naming another uses the flag's.
3. A missing required field (no remote host anywhere) fails with the
   configuration error code and names the field.
4. -u is rejected with a message naming unordered mode.
5. End to end as a subprocess: a real ck-server, a real ck-client, an
   application socket through the client's local port to a fake
   upstream behind the server, byte for byte. This is the first time
   the two BINARIES have talked to each other.
6. SIGTERM shuts down cleanly.
7. -a against a real server reaches the admin API -- one request, one
   response.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (63 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Add the ck-client binary"`

---

## What the previous branches learned

Thirty-three test-coverage defects across six branches, every one found by measuring or mutating, none by reading. The patterns that keep recurring, in the order they have cost the most:

1. **A test whose green comes from a path other than the one it names** — six instances, including a browser test that exercised one template three times and a fingerprint list validated against itself.
2. **A boundary test that fails on only one side** — three instances on one branch, and the third was inside the fix for the second. The form that works: record a **measured bracket** (0.8× fails one side, 1.1× passes, 1.2× fails the other) rather than claiming a margin in prose.
3. **A test written against the symbol it is testing** — two instances, including a ceiling whose test derived both sides from the constant, so it could be set 256× too high unnoticed.
4. **A counter scoped to the wrong object** — the tell was a header describing a property the code did not implement.
5. **A bound that is not the bound that binds** — an iteration count standing in for a time bound, in seven identical copies; a 2000-iteration "2 second" wait completed in 4.2 ms.

And two lessons about where the real defects came from:

- **Round-trip tests cannot see a self-consistent error.** Both ends of every test here are our own code. The record-layer defect — the disguise dropped one round trip into every connection — survived five modules for exactly this reason. Where an outside oracle exists, use it.
- **An unexplained observation is worth a day.** Chasing one produced two real defects nobody had looked for, including a missing `TCP_NODELAY` that silently diverged from Go on every socket.

## Self-review notes

- **Spec coverage:** §10's CLI list and key generation are Tasks 3-5; the stacks are not in the spec but are the accumulated demand of three scouting reports, and the reasoning is stated above rather than assumed.
- **Placeholder scan:** every task names its files, interfaces and test cases. D1-D6 are settled. Four decisions are delegated with a stated requirement to justify them: what each stack can enforce versus only document, the client's backoff and bound, the server's exit codes, and the signal-delivery contract.
- **Type consistency:** `cloak_server_stack_t` is produced in Task 1 and consumed in Task 4; `cloak_client_stack_t` in Task 2 and consumed in Task 5; `cloak_signalfd_t` and the keygen helpers in Task 3 and consumed in both. Counts chain 58 → 59 → 60 → 61 → 62 → 63.
- **The riskiest thing here** is Task 1, because it is the first code that has to get the four-link chain and the teardown order right *without* a test fixture's freedom to special-case, and because every module that came before it found its worst bug in that exact area.
- **The most consequential thing here** is that after this plan the project has something a person can run. Everything so far has been libraries and tests; a bug that only appears when the program is actually started — a signal race, a teardown order, a config path — has had nowhere to show itself until now.

---

## What this branch left for the next ones

### The prediction at the top of this plan was right, and here is the measurement

"A bug that only appears when the program is actually started has had nowhere to show itself
until now." It showed itself immediately, and one measurement settles the argument: mutating the
**server's** `MAX_ON_WIRE_SIZE` from 16401 to 8192 fails the end-to-end case **and nothing else in
the 63-test suite**. Five modules of library tests could not see it, for the reason this project
already knew and kept paying for anyway — *both ends of every library test are our own code*. The
same shape produced the record-layer defect that dropped the TLS disguise one round trip into every
connection and survived five modules.

That single assertion survived three fix rounds and four independent attempts to blunt it. Keep it.

### Defects this branch found that were real

- **Neither binary disabled SIGPIPE.** A running `ck-server` sent `kill -PIPE` died with status 141.
  `dispatcher.c` held the tree's only socket write without `MSG_NOSIGNAL`, in a retry loop on a
  peer-controlled descriptor. **Go's runtime ignores SIGPIPE for non-stdio descriptors by default,
  so not doing it was a divergence from the original, not a missing precaution.** The race itself
  was never reproduced — 840 RST-after-ClientHello replays across a 0–1600 µs sweep all survived,
  because loopback finishes the reply in one write. Fixed anyway: latent is not absent.
- **The config parser accepted a 255-character `ServerName` while the connector capped it at 253.**
  253 is correct — RFC 1035/4343 give 255 octets on the wire, 253 presentation characters, and
  RFC 6066 requires a valid DNS hostname. Go bounds it nowhere, so neither number was "Go's". The
  symptom was an operator with a 254-character name getting an exit code whose own contract says
  retrying may help, so a supervisor keyed on it would restart forever over a typo.
- **`AlternativeNames` had the same unbounded defect**, and nobody had named it. Because the SNI is
  drawn per session, an over-long alternative name would have failed **intermittently** — the worst
  shape a bug can take here.
- **`-a` silently zeroed `Singleplex`**, which Go's admin branch does not, and which made the
  `admin_session` guard unreachable from the only binary that sets the field.
- **A fourth bug in the Go original.** `parseSSBindAddr`'s R3 writes the SS address over an existing
  entry *and* sets `shouldAppend`, so `["0.0.0.0:P"]` + `::|0.0.0.0` yields `[":P", ":P"]`, the
  second `net.Listen` dies EADDRINUSE, and it resurrects appends R1/R2 had suppressed. Confirmed
  independently. The port implements it correctly.
- **Go's server cannot accept inline configuration** — `ParseConfig` unmarshals the empty buffer it
  failed to fill — so its own flag help is false. Go's *client* fails differently: the literal takes
  the ReadFile branch. Inline config is a deliberate superset on **both** binaries here.

### The methodological result, stated as plainly as it can be

**A mutation log written by the author of the code is the least reliable document in the repository,
because the author picks mutations they expect to die.** The evidence on this branch alone:

| | self-reported | found by an outside reviewer |
|---|---|---|
| `ck-server` (Task 4) | 11 of 11 caught, 0 escaped | **15 of 26 escaped** |
| `ck-client` (Task 5) | 14 applied, none escaped | 4 of 17 escaped |
| whole branch | — | 6 of 26 escaped |

Task 4 mutated only itself. Task 5 mutated the **server** to test the client — an outside oracle —
and had a quarter of the escape rate. That is the whole difference, and it is reproducible advice:
**where an outside oracle exists, use it.**

Among the fifteen that escaped `ck-server`: a **hardcoded constant valid key pair passed the entire
suite.** In a circumvention tool, key generation that silently returns a constant means every user
of that build shares one key.

And the fix round's headline: **`main.c` did not change.** All eight ordered items were test gaps.
The server was correct and nothing proved it.

### Two rulings worth inheriting

**"Repairing this would unpin that test" is not an argument.** It was offered here in good faith,
for the `ServerName` mismatch, and overruled. It is this project's most expensive recurring pattern
said out loud — a test green from a path other than the one it names, six instances across seven
branches. When a working alternative sits in the same file (`RLIMIT_NOFILE`, bracket 4→3, 5→4,
6→ready), a defect kept alive for a test's convenience is never the trade.

**An honestly declared equivalent mutant beats a manufactured kill.** Three were declared on this
branch — the client piper's callback clears, the client's `default:` arm, the server's — and all
three held up under independent proof. Declaring one costs nothing and is checkable; inflating a
count is neither.

### Gaps handed on, by owner

- **`keep_alive_sec` is parsed, carried, and consumed by nobody.** Both binaries now warn at
  startup. **It must not survive the session module unrecorded.**
- **Reconnect-after-server-restart through the binaries is unasserted**, while being the stated
  justification for there being no sixth exit code. Whoever adds the sixth code, or argues again
  that five suffice, owes this test.
- **UDP end-to-end** is module 9's, **CDN** module 8's; both are refused at open today.
- `cloak_server_stack_upload_now`'s *library* coverage was always there; only the binary's call was
  missing, and the whole-branch view is what made the cost visible (one billing interval lost per
  restart). Per-task review structurally cannot see that class.
- `read_whole_file` and `ck_err` are duplicated verbatim in the two mains. Thirty lines did not
  justify a shared unit at the end of a branch. **If a third binary appears, it does.**

### The suite is now a resource, and module 8 inherits a budget

Debug 62.4 s serial / 17.7 s at `-j4`; ASan 207.5 s / 75.7 s. The two CLI files are ~94 s of the
ASan total, almost entirely LeakSanitizer's exit scans on forked children (measured at ~0.93 s per
child). `test_ck_client_cli` sits at 54 s against a 120 s bound — a margin that fell from 2.7× to
2.3× in a single round.

**Module 8, in this order:** take the children-only `detect_leaks=0` win *before* adding any case to
those files; use ephemeral ports everywhere (two fixed-port defects were introduced and removed on
this branch alone, one of them one commit after the other was fixed); reuse a server process rather
than starting another; and **stop raising `TIMEOUT`** — make a slow case cheaper instead. Raising it
was correct exactly once here, when a fix replaced a timeout with named assertions and the failing
run needed room to print them.

### Three process notes that cost real results

- **Revert a mutation with `cp`, never `mv`.** `mv` preserves mtime, the build skips, and the test
  "passes" against the un-reverted binary — a manufactured kill. Warned about in three separate
  dispatches; still landed twice.
- **Run through `ctest`, never the test binary directly**, or `LD_PRELOAD` is absent and the shims
  do not load. Three results lost that way.
- **A mutating reviewer is not file-disjoint even when its findings are.** Two agents in one
  worktree collided once on this branch; after that, reviewers got their own worktree and the
  collisions stopped.

### Tally

Thirty-three coverage defects across six branches became **fifty-eight across seven**. Every one was
found by measuring or mutating. **None was found by reading.**
