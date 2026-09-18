# Module 10a: fuzzing

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** give every attacker-reachable parser in this port a libFuzzer target, a committed corpus, and a fast corpus-replay regression in `ctest` — and say honestly what fuzzing here can and cannot find.

**Architecture:** a second compiler (clang) alongside gcc in the dev image; one `LLVMFuzzerTestOneInput` per target, linked against the real libraries; a committed seed corpus per target; and **one** new ctest case that replays every corpus under ASan+UBSan. Long campaigns run out of band, never in `ctest`.

**Tech Stack:** Debian clang 14.0.6 + `libclang-rt-14-dev`, libFuzzer, the existing CMake, and the libraries as they stand.

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` §11
**Scouting report:** `docs/superpowers/plans/2026-09-17-module-10-scouting.md` — §3 contains every measurement below, taken by building rather than by reading.

## Global Constraints

- C11, `-Wall -Wextra` clean, **zero warnings** — under **both** gcc and clang.
- **Nothing may block the reactor.**
- ASan+UBSan mandatory alongside Debug. Run tests through `ctest`, **never a test binary directly**.
- Docker image `cloak-c-dev`, `-w /src/.worktrees/<branch>`. **Never `-w /src`.**
- **Every wait bounded by the clock.** Ephemeral ports everywhere.
- 75 tests pass at `2e6f2f6`. **Every existing test must pass UNMODIFIED**, under gcc as before and now under clang too.
- **Revert a mutation with `cp`, never `mv`** — and **always rebuild before trusting a number**: `mv` preserves mtime so the build silently skips (false pass), and a `cp` revert without a rebuild leaves a stale binary (false fail). Both have happened here.
- **Per-agent scratch directory and per-agent worktree.**
- A comment that asserts a measurement must **cite a test that would fail, or say plainly it was read rather than measured.** Module 8 needed five such corrections; module 9 found a divergence justification that was false about Go, behind a pointer to a rationale that did not exist.
- **THE HOST DISK IS AT 98 % WITH ~4.6 GiB FREE.** An ASan build directory is ~760 MB, a fuzz build ~128 MB, and the image change costs **264 MB**. A full disk has wedged the Docker daemon twice. Delete build directories as you go; on an I/O-shaped failure, **stop and report rather than retrying.**

---

## Decisions already made

**D1 — module 10 is two modules, and this is the first.** "Integration" and "fuzzing" share a number in the original list and nothing else: fuzzing is ~600 lines of new, isolated code that touches no existing behaviour, while integration is ~2,900 lines that changes shipped code and carries every inherited obligation. Doing fuzzing first is also ordered, not arbitrary — **anything it finds changes what 10b must fix.** Module 10b follows with integration, the untested combinations, and the defects §5 of the scouting report names.

**D2 — the image gains clang, and this was verified by building, not by reading.** **The dev image has no `clang` at all** (gcc 12.2.0; gcc has no libFuzzer, `-fsanitize=fuzzer` being a clang/compiler-rt feature). And **installing `clang` alone is not enough** — Debian ships compiler-rt separately, so the link fails with `cannot find .../libclang_rt.fuzzer-aarch64.a`. **`clang` + `libclang-rt-14-dev` works**: Debian clang 14.0.6, **45.4 MB download, 264 MB image growth, 1.01 GB → ~1.27 GB.** A plan that said "libFuzzer, bundled with clang" and stopped would be the module-8 mistake verbatim — that module's entire proving task rested on a toolchain the image did not have, found only in the pre-flight scan.

**The tree already compiles under that clang**: a full Debug build of libraries, binaries and all 75 test executables succeeded with **exactly one warning**, benign and in a test (`test_clienthello_parse.c:158`, a `volatile uint8_t sink` defeating dead-store elimination). **No portability work is needed.**

**D3 — the CI artefact is a corpus replay, not a campaign.** Measured: a 60-second run does **11,321,022 executions at 185,590/s**; replaying the resulting **393-unit corpus costs 875 ms** including process start, under ASan+UBSan. A per-target campaign would more than double the suite; a replay is an ordinary ctest case. **The corpus is committed, the replay is the regression, and campaigns run out of band.**

**D4 — the target set is #1, #2, #3, #4, #5, #7**, with #6 and #9 as cheap add-ons to the same plumbing. Numbering follows the scouting report's §3.3 table.

**D5 — honest expectations, and the plan is written around them.** The 60-second run against the four most-quoted parsers found **zero crashes**. Those parsers have been read, bounded and tested hard for nine modules. So this plan is **not** written around "the fuzzer will find bugs in `cloak_ws_frame_parse_header`". It is written around the two targets that are genuinely new:
- **#1 is where the expected yield is.** It is the only target that allocates, grows and frees across calls — `strmtab` insertion, the ordered reorder heap, `msgqueue`'s ring arithmetic (three separate `% q->cap`), the unordered datagram queue. Everything upstream of it is a `memcmp`.
- **#7 is where the expected novelty is.** The client's handshake-reply reader is **a whole attack surface no list in this project has ever included**, and it is reachable by any on-path censor who can answer the client's TCP connection — you do not have to be the server to feed it.
- **#3, #4, #5 are regression insurance.** Write them, commit the corpus, and expect them to earn their keep the day someone edits those files.

**D6 — say plainly what fuzzing cannot see.** Every defect in this project's 79-item ledger that was about a **distribution** or a **divergence** is invisible to a fuzzer: a biased modulo, a predictable connection pick, a padding-length distribution, an AAD mismatch with Go. Those are module 10b's. The plan must not let a green fuzz job read as coverage of them.

---

### Task 0: clang in the image, verified by finding a planted bug

**Files:** `Dockerfile.dev`; no source changes.

- [ ] **Step 1: Measure first.** Record the image size before, and the host's free space. Confirm `clang --version` fails today, and that `-fsanitize=fuzzer` with gcc does not exist.
- [ ] **Step 2: Add `clang` and `libclang-rt-14-dev`** to the existing stage. Rebuild, record the actual size delta against the expected 264 MB.
- [ ] **Step 3: Prove the toolchain, do not assume it.** Build a throwaway target whose body contains a **deliberate null dereference behind a magic prefix**, run it, and confirm libFuzzer **finds and minimises** it, printing the crashing unit. A toolchain that links but cannot find a planted bug is not a working toolchain.
- [ ] **Step 4: Prove the tree still builds under both compilers** — full gcc build 75/75, full clang build 75/75, and record clang's warning count (expected: exactly one, in `test_clienthello_parse.c:158`). **Fix it or justify it in writing.**
- [ ] **Step 5: Commit** — `git commit -m "Put clang and libFuzzer in the dev image"`

---

### Task 1: the stateful target, where the yield is

**Files:** Create `fuzz/fuzz_session_envelope.c`, `fuzz/CMakeLists.txt`; modify the root `CMakeLists.txt`.

**Target #1** — `cloak_session_on_envelope` / `cloak_frame_deobfuscate` with `CLOAK_AEAD_NONE` and a zero key. **This is Go's `session_fuzz.go` exactly** (`setupSesh_fuzz` uses `EncryptionMethodPlain` and `[32]byte{}`), and `plain` is a real, parseable configuration — **the richest state in the tree behind the thinnest gate.**

**Interfaces — produces:** a `fuzz/` directory convention every later target follows: one file per target, `LLVMFuzzerTestOneInput`, built only when `CLOAK_FUZZ=ON`, never part of the default build.

- [ ] **Step 1: Write the target so it can fail.** Drive **many envelopes per input**, not one — the state is the point. Derive each envelope's length from the input itself.
- [ ] **Step 2: Run 60 s and record execs/s, new units and peak RSS.** The scouting baseline is 185,590 exec/s and 732 MB peak.
- [ ] **Step 3: Plant a bug and confirm the target finds it** — an off-by-one in the reorder heap or the msgqueue ring. **A target that has never caught anything is unproven**, and this is the cheapest moment to prove it.
- [ ] **Step 4: Minimise and commit the corpus.**
- [ ] **Step 5: Commit** — `git commit -m "Fuzz the session's envelope path"`

---

### Task 2: the two pre-auth parsers on the server's front door

**Files:** Create `fuzz/fuzz_firstpacket.c`, `fuzz/fuzz_clienthello.c`.

**Target #2** — `cloak_firstpacket_feed` driven through `cloak_firstpacket_want`. **The value is the chunking axis, not the bytes**: feed sizes must be **derived from the input**, or the target is strictly weaker than `test_dispatcher_limits.c:812` already is. A resumable state machine gets the split boundary wrong, and every existing test feeds convenient chunks.

**Target #3** — `cloak_clienthello_parse`, the spec's own first named target: six nested length fields, and **its own header concedes it "does not validate the record layer's own declared length field against len."**

- [ ] **Step 1: Write both, with #2's chunking derived from the input.**
- [ ] **Step 2: Prove #2's chunking is real** — a variant that always feeds the whole buffer must reach strictly fewer states; show the number.
- [ ] **Step 3: 60 s each, record the numbers.**
- [ ] **Step 4: Plant one bug in each and confirm each finds it.**
- [ ] **Step 5: Commit** — `git commit -m "Fuzz the first packet and the ClientHello"`

---

### Task 3: module 8's deferred pair, and the cheap add-ons

**Files:** Create `fuzz/fuzz_ws_handshake.c`, `fuzz/fuzz_ws_frame.c`, `fuzz/fuzz_base64.c`, `fuzz/fuzz_http.c`.

**#4** `cloak_ws_handshake_parse` and **#5** `cloak_ws_frame_parse_header` are the two module 8 specified and deferred. **#9** base64 costs nothing and sits on the unauthenticated path. **#6** `cloak_http_parser_*` has the highest per-bug cost in the tree and the lowest reachability — **`http.h:19-27` says it itself: "A memory-safety bug in here is remote code execution, not a fingerprint."**

- [ ] **Step 1: Write all four.**
- [ ] **Step 2: 60 s each; record.** Expect nothing from #4 and #5 — they are regression insurance and should be labelled as such in the source.
- [ ] **Step 3: Plant a bug in #6 specifically and confirm it is found**, because that is the one whose cost justifies the target.
- [ ] **Step 4: Commit** — `git commit -m "Fuzz the WebSocket parsers, base64 and the HTTP parser"`

---

### Task 4: the client's own pre-auth parser, which nobody has ever listed

**Files:** Create `fuzz/fuzz_client_reply.c`.

**Target #7** — the client's handshake-reply reader (`client_transport.h:186-194`, states `READ_RECORD_HEADER` and `READ_RECORD_BODY`), over up to `CLOAK_CLIENT_HANDSHAKE_MAX_REPLY_BYTES` (49,935).

**Read this before writing it.** Every fuzz list in this project — the spec's, module 8's, module 9's — names server-side parsers only. **This is the only client-side pre-auth parser, and it is reachable by any on-path censor who can answer the client's TCP connection.** You do not have to be the server to feed it. That asymmetry is why it was missed, and it is the single most interesting target in the module.

- [ ] **Step 1: Write it, chunking derived from the input**, exactly as for target #2 — this is a resumable state machine and the split boundary is the axis.
- [ ] **Step 2: 60 s; record.**
- [ ] **Step 3: Plant a bug and confirm.**
- [ ] **Step 4: Commit** — `git commit -m "Fuzz the client's handshake-reply reader"`

---

### Task 5: the corpus replay, and saying what this does not cover

**Files:** Create `fuzz/corpus/<target>/`, `fuzz/replay_main.c` or equivalent, its test registration; modify `fuzz/CMakeLists.txt`.

- [ ] **Step 1: Write the replay** — one ctest case replaying **every** committed corpus under ASan+UBSan. Baseline: **875 ms for 393 units.** Label it per the suite's tiering; **`TIMEOUT` in the same `set_tests_properties` call as `LABELS`**, because a `TIMEOUT` documented in a comment and never set is a defect this project shipped one module ago.
- [ ] **Step 2: Prove the replay can fail** — reintroduce one planted bug and confirm the replay catches it from the committed corpus alone, with no fuzzing.
- [ ] **Step 3: Measure the suite's new wall time**, Debug and ASan, at `-j4`. **The runtime budget is already at 1.91×** against `TIMEOUT 120` on `test_ck_client_cli`, below the 1.95–2.01× the previous module declared the floor. Report the number; if the replay pushes the suite materially, say so rather than absorbing it.
- [ ] **Step 4: Write `fuzz/README.md`** stating **what fuzzing here cannot see** — every distribution and divergence defect in the 79-item ledger — and how to run a campaign out of band.
- [ ] **Step 5: Commit** — `git commit -m "Replay the fuzz corpus as a regression, and say what it misses"`

---

## Self-review

- **Spec coverage:** §11's fuzzing is this module; its unit and integration tests are already over-satisfied by the nine modules, which is why 10b exists for the obligations the spec does not name.
- **Placeholder scan:** every task names its files and its acceptance step. D1-D6 are settled, each on a measurement.
- **Type consistency:** Task 1 establishes the `fuzz/` convention; Tasks 2-4 follow it; Task 5 consumes all of them. Test count 75 → 76, once, in Task 5.
- **Every target must be proven by a planted bug.** A fuzz target that has never caught anything is an unproven instrument, and this plan's own baseline says the pure parsers will find nothing real — so the planted bug is the only evidence the target works at all.
- **The riskiest task is 1**, because it is the only stateful target and the only one where a crash would be a live defect rather than a planted one.
- **The most consequential task is 4**, because it adds an attack surface nobody in this project had listed — and the adversary this port is built against can reach it without being the server.

---

## What this branch left for the next ones

### Eight targets, zero real findings, and that was the expectation going in

A scouting run measured **11,321,022 executions at 185,590/s against the four most-quoted parsers,
zero crashes**, before a line of this module was written. So the plan was built around honest
expectations rather than hope, and the outcome matched: **no target found a live defect.** The value
delivered is regression insurance on eight parsers, **two attack surfaces nobody in this project had
ever listed**, and — unexpectedly — a set of measurements about fuzzing itself that are worth more
than a crash would have been.

### The rule that made every target real: a planted-bug proof

**On this codebase a green fuzz run is the expected outcome and carries no information about whether
the target works.** So every target had to plant a bug and show libFuzzer finding it. That rule
earned its keep immediately:

- **Task 2's first ClientHello target had in-range-only oracles, and its planted bug survived
  25,402,060 executions.** A target running at **438,051 exec/s** was proving nothing. It was the
  planted bug, not the throughput, that revealed it.
- **Task 3 recorded a plant that survived 5,885,563 executions** — hoisting a Content-Length cap out
  of the digit loop, a twenty-digit wrap — and wrote the gap into the source **with its measurement
  beside it** rather than leaving it for rediscovery.

**A target with no planted-bug proof is an unconnected instrument.**

### The gate question got four different answers, every one measured

Before seeding a corpus, ask whether the mutator can reach the code at all. The answer was different
every time, and **not once was it guessable**:

| target | answer |
|---|---|
| session envelope | a `seq == 0` gate **2^64 wide with no coverage gradient** — the plant was **not found in 623,089 blind executions**, then found **in ~8 s from seeds** |
| ClientHello | first written up as "unclimbable", then **measured**: libFuzzer passes the equality gate in ~1.4–2.4M executions on **two of three seeds**, not at all on the third. Seeding bought **reliability and 100x, not reachability** |
| WS handshake / HTTP | corpora **load-bearing**: with the plant in and no corpus, one target was **not reached in 26,567,643 executions** |
| client reply reader | **no corpus can ever pass the gate** — the shared secret is a fresh ephemeral X25519 key **per execution** — so the harness seals the first record itself at runtime |

### And ask whether the suite already catches your plant

Also different per target, and the answer changes the target's justification:
- Task 1's two: **caught by the 75 tests**, so its value narrowed honestly to unenumerated
  *sequences* rather than one-token mutations.
- Task 2's two: **not caught** — real marginal coverage.
- Task 3's six: all caught.
- Task 4's: one caught, **one not — and that one is a denial-of-service that pins a descriptor for
  the full 15-second deadline, on the only client-side pre-auth parser in the tree.**

### The surface nobody had listed

**Every fuzz list this project ever wrote — the spec's, module 8's, module 9's, the scouting
report's first six entries — names server-side parsers only.** The client's handshake-reply reader is
**reachable by any on-path censor who can answer the client's TCP connection.** You do not have to be
the server to feed it. That asymmetry is why it survived nine modules unlisted, and it is where the
module's one uniquely-caught defect shape lives.

### What fuzzing here cannot see, and `fuzz/README.md` says so

**Every defect in this project's seventy-nine-item ledger that was about a distribution or a
divergence is invisible to a fuzzer**: a biased modulo, a predictable connection pick, a
padding-length distribution, an AAD mismatch with Go. A green fuzz job must not read as coverage of
those. They are module 10b's.

### Three flakes in one test file, three different mechanisms, none found by reading

`test_udp_piper.c` produced three wall-clock defects, **every one found by running under load**:

1. **Module 9's** — an assertion demanding that a **TCP** bind to the UDP listener's ephemeral port
   *succeed*, defeatable by any concurrent process because **ephemeral port ranges are shared across
   protocol families.** It could also have **passed spuriously.** Cure: ask the socket its own type.
2. **The wedged peer** — `peer_timeout_ms` runs from a peer's last activity, so the 150 ms deadline
   was **also the budget for the case's own twenty-datagram setup**; the peer it never fed reached
   the assertion at **120 ms of 150**. Poll-bound; moved by CPU **quota** (7/20 at `--cpus=2`),
   untouched by spinners. Cure: move the origin — both peers speak once per setup turn, and the
   deadline is measured from that instant.
3. **The churn case** — waited on `pump_until(peer_count_is 1000, …)`, **a level that can only recede
   once the loop stops feeding it**, so the wait watched 662 more peers expire and **turned a
   338-peer shortfall into `peer_count 0`, destroying the evidence.** CPU-bound; moved by
   **contention** (14/20 at `--cpus=1` + spinners), untouched by quota alone. Its idle margin was
   **8x** — better than #2's 1.25x — so **the margin did not predict the failure; the amplifier
   did.** Cure: wait on `peers_created`, which only rises.

**A wait must be on something that can only move toward you.** And the worst consequence of #3 was
silent: before the fix, on a slow machine the three-refusal cap assertion **was not testing the cap
at all.**

**Two rejected fixes with numbers, which are worth more than the accepted ones**: a single post-loop
keepalive **measured 3/20 still failing** because peers expire *during* the loop; and `getpid()`
stamping was **provably useless** in an earlier fix because PIDs are namespaced and `$$` is 1 in
every container.

### The sweep, and its most useful result is negative

**524 wait sites across 78 test files; 74 level-predicate; 11 timeout-then-work. No silent site
exists outside `test_udp_piper.c`** — because the suite pairs `ASSERT_TRUE(pump_until(...))` with an
exact restating `ASSERT_EQ_INT` **nearly everywhere**, so a receding predicate fails loudly instead
of quietly ceasing to check. **Look where that pairing is missing** — a cheaper rule than auditing
every wait.

And the top suspects were **measured, which retired them**: one has a **1.14x margin — tighter than
the 1.25x that did fail** — yet 0/20 under both levers. A margin tighter than a known-failing one,
proven safe. A read-only audit would have got that backwards.

### False results caught, in both directions

- **`mv` preserves mtime**, so a revert without a rebuild gives a **false pass**. Hence `cp`.
- **`cp` updates mtime**, so a revert without a rebuild gives a **false fail** — which fired twice
  this session and was caught both times. **The rule is "always rebuild before you trust a number",
  and `cp`-not-`mv` is only half of it.**
- A sweep's clang check reported **zero warnings because `python3` does not exist in the image, so
  nothing compiled.** Caught by someone asking what their own zero meant.
- An agent's assembly diff reported **"IDENTICAL" on two empty files** because it matched an
  inlined-away symbol. Caught and redone.

### Costs and budgets for module 10b

- **76 tests.** Debug ~22.5 s at `-j4`; ASan **67–71 s warm**. The ~102 s figure quoted all module
  was **cold-cache** — every runtime argument made here rested on it.
- **`test_ck_client_cli` measured 59.5–64.9 s, i.e. 1.85x–2.02x against `TIMEOUT 120`.** The 1.91x
  floor declared a module ago **has been crossed.** Splitting the two CLI tests into separate
  binaries remains the only lever.
- The corpus replay costs **+0.1 s Debug, +1.4 s ASan** — inside the control's own spread.
- **Corpus caps are asserted, not documented**: 288,427 / 1,048,576 bytes and 1,094 / 2,048 files.
  **File count is the binding cost**, at ~58 bytes per file for one target.
- The image is **~1.42 GB** (clang + compiler-rt + llvm-symbolizer, measured at **+350 MB** against a
  predicted 264, then +55 MB).
- **`llvm-symbolizer` is not shipped by clang on Debian.** Without `llvm-14` every crash prints raw
  addresses, and the obvious remedy — putting a path on `PATH` — **looks like it works** while
  leaving every report unsymbolized.
- **Recorded, unbounded by any test**: `cloak_reactor_cancel_timer` is a linear heap scan,
  `peer_find_addr` a linear list walk, and **`registry_find_live` and `panel_find` scan a fixed 256
  entries regardless of occupancy.** Five more sites share the shape.

### Tally

Seventy-nine coverage defects across nine branches became **eighty-two across ten** — three flakes,
each with its own mechanism, none shared with another. Plus two named, measured blind spots inside
the new targets themselves. Every one found by measuring or mutating. **None was found by reading.**
