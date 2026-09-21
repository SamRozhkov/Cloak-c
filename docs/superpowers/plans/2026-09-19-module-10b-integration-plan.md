# Module 10b: integration, and the defects nine modules left behind

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** run the combinations nobody has run, fix the defects a fresh reading found, and discharge the obligations three modules wrote down and deferred — leaving the port with no known untested seam and no known unfixed defect.

**Architecture:** no new subsystem. This module is coverage and repair: the existing Go-binary oracle driven across the configuration matrix it has never left, two real defects in shipped code, one stale cap with an expired justification, and the written debts of modules 7, 8 and 9.

**Tech Stack:** as it stands — Go 1.25.6 and gorilla in the image, clang 14.0.6 and the eight fuzz targets from 10a, the existing CMake and test framework.

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md`
**Scouting report:** `docs/superpowers/plans/2026-09-17-module-10-scouting.md` — §4, §5 and §6 carry every citation and measurement below.

## Global Constraints

- C11, `-Wall -Wextra` clean, **zero warnings under BOTH gcc and clang**.
- **Nothing may block the reactor.**
- ASan+UBSan mandatory alongside Debug. Run tests through `ctest`, **never a test binary directly**.
- Docker image `cloak-c-dev`, `-w /src/.worktrees/<branch>`. **Never `-w /src`.**
- **Every wait bounded by the clock, never by an iteration count.** Ephemeral ports everywhere.
- 76 tests pass at `5f6e0d0`. **Every existing test must pass UNMODIFIED** unless a task names it.
- **Revert with `cp`, never `mv` — and always rebuild before trusting a number.** `mv` preserves mtime so the build silently skips (false pass); a `cp` revert without a rebuild leaves a stale binary (false fail). **Both fired this week.**
- **Per-agent scratch directory and per-agent worktree.**
- A comment asserting a measurement must **cite a test that would fail, or say plainly it was read rather than measured.**
- **A comment justifying a divergence from Go must cite the Go file and symbol**, and a reviewer must check it there. Module 9 found one that was false about Go behind a pointer to a rationale that did not exist; §5.1 of the scouting report found another.
- **`TIMEOUT` goes in the same `set_tests_properties` call as `LABELS`.** Forking tests are labelled `slow`; the default `ctest` still runs everything.
- **THE HOST DISK IS AT 98 % WITH ~4.5 GiB FREE** and the Docker VM's disk does not shrink. An ASan build directory is ~760 MB. Delete build directories as you go; on an I/O-shaped failure **stop and report rather than retrying**.

---

## Decisions already made

**D1 — the configuration matrix comes first, and it is not a formality.** The three oracle tests pin **one point**: `chrome` + `aes-gcm` + one ordering mode. The port and Go both support **3 browsers × 4 encryption methods × 2 ordering modes**, so **2 of 24 combinations have ever met foreign code.** The spec itself calls ClientHello mimicry *"the highest-risk, highest-value component"*, and **a wrong offset in the Firefox or Safari table passes every C↔C test because both ends read the same table.** That is the AAD defect's exact shape, sitting unexercised, with a free oracle already installed.

**D2 — the replay cache is a security defect, not a tuning question.** Capacity **1024**, slot = `fnv1a(key,32) % capacity` — **an unkeyed, non-cryptographic hash over a fully attacker-chosen 32-byte value** — and **the cache is written before authentication** (`dispatcher.c:280-281`, `:595`). So an unauthenticated prober evicts a *specific* captured handshake's entry with **one packet** (~1024 offline trials to collide a chosen slot) or the whole table with **1024**, inside the 180-second tolerance window. **And with no attacker at all, any server doing more than 1024 handshakes per 12 hours evicts continuously.** The header's own argument carves out *"an attacker who does not already possess a valid, not-yet-expired ciphertext"* — **which is precisely the GFW's active-probing attack**: a censor watched a real client connect, holds that ciphertext, and replays it to confirm the host is Cloak rather than a web server. **Bounding the cache was right; 1024 is the wrong number, and the header's own argument is what hid it.**

**D3 — raising the session cap without fixing the scan is a trap, and the plan says so up front.** `CLOAK_REGISTRY_MAX_SESSIONS` is **256 server-wide**, defended by a comment reading *"ample for this stage: **there is no user manager yet***" — there has been one since module 4. Go has no equivalent cap. But `registry.h:122-125` is a fixed array with **linear scans**, so raising the number makes the scan the new defect. **This is an engineering task, not a constant bump.** The same shape sits in `registry_find_live` and `panel_find`, which scan a fixed 256 entries **regardless of occupancy**, and in five further sites — none bounded by any test.

**D4 — `admin && udp` is an unrecorded divergence either way, and this module records it.** Go accepts it and produces something broken: `ck-client.go:165` forces `NumConn = 1` in the admin branch but **leaves `authInfo.Unordered` alone**, and `:191` routes the admin API over `RouteUDP`. The C client refuses `admin && (num_conn != 1 || singleplex)` but **has no opinion on `admin && udp`.** Decide — refuse it, or test it — and write the decision down with its Go citation.

**DECIDED BY TASK 5: ACCEPT AND TEST.** Go's citation re-read in the reference tree — the admin branch is `ck-client.go:159-167` and the `if authInfo.Unordered` that picks `RouteUDP` over `RouteTCP` is `:191-200`, outside it. Refusing would be a divergence with nothing behind it, and the combination **already worked**: `test_ck_client_cli.c` case 7a (`admin_over_udp_is_served`) now drives `-a` with `-u` through both real binaries and gets a real `200` with a JSON body back, 123 bytes in **one** datagram. What is *not* claimed: a response longer than one frame's payload still leaves as several datagrams that nothing joins up — the local endpoint is a UDP socket and this port does not pretend otherwise.

**D5 — the restart test discharges a written debt and is not optional.** `cmd/ck-client/main.c:41-47` justifies there being no sixth exit code **on the grounds that** a client that cannot connect retries forever. Nothing proves it does, through the binaries, across a real restart. Module 7 said whoever argues five codes suffice owes this test. **This module owes it.**

**D6 — what this module does NOT do.** `-u` × CDN stays unreachable (module 8b's; it needs a real TLS stack and a fingerprint decision). `singleplex + udp` stays unimplemented and refused by name. `read_whole_file`/`ck_err` stay duplicated in the two binaries — module 7 said a third binary makes sharing worth it, and there is no third binary. **Say so; do not re-litigate.**

## Two more candidate bugs in the reference

- **#10 — a duplicate of a *pending* seq wedges Go's stream permanently and grows its heap without bound.** Found by checking `stream.h:266`'s justification for our ordered-duplicate divergence, which claims *"Go … has no error path there at all"* — **that is false** (`streamBuffer.go:79-81`). The false comment is what hid the candidate.

  **PROMOTED TO A FINDING BY TASK 5 — REPRODUCED, NOT READ.** Measured against the reference tree at `cbeuw/Cloak` `c3d5470` (a copy of it, with one added `_test.go`; the reference checkout itself was not modified), `go1.25.6`, driving `NewStreamBuffer` directly in-package:

  ```
  frames seq 1, 1, 0  ->  nextRecvSeq = 2, heap = [seq 1]   (the stale copy)
  + 1000 in-order frames (seq 2..1001)
                      ->  nextRecvSeq = 2 STILL, heap = 1001 entries
  reader             ->  "AB" once, then deadline exceeded, forever
  ```

  The mechanism: `streamBuffer.go:79-81` only rejects `f.Seq < nextRecvSeq`, so a second copy of a seq still **pending** in the sorter heap is pushed again at `:86`; the drain loop at `:88` stops as soon as `sh[0].Seq != nextRecvSeq`, and by then `nextRecvSeq` has moved **past** the stale copy, which therefore sits at the head of the heap where it can never match again. **Reachable from a peer:** `Session.recvDataFromRemote` → `Stream.recvFrame` (`stream.go:72`) hands every deobfuscated frame straight to `streamBuffer.Write`, so an authenticated peer that repeats one pending frame wedges that stream and grows the process heap for as long as it keeps sending. **This port is immune** — `stream.c`'s check is `frame->seq < s->next_recv_seq || heap_contains_seq(s, frame->seq)` — and `cloak/stream.h`'s `ORDERED` paragraph now carries the corrected citation.

- **#12 — Go's replay-cache cleaner sleeps `replayCacheAgeLimit` = 12 hours between passes** (`state.go:214-225`), so an unauthenticated flood grows `UsedRandom` unboundedly for up to twelve hours: a memory DoS from packets that never authenticate.

**#12 is still read, not measured.** A task that reproduces it promotes it to a finding; a task that cannot must say so.

---

### Task 1: the ClientHello matrix against Go's parser

**Files:** extend `libcloak-server/tests/test_go_interop.c`; no source changes expected.

**Why first:** the spec calls this the highest-risk component, the oracle is already built and installed, and **a wrong offset in the Firefox or Safari table passes every C↔C test because both ends read the same table.** Go's `internal/server/TLSAux.go` parser is the outside oracle.

- [ ] **Step 1: Write the failing tests**
```
1. All three browser templates -- chrome, firefox, safari -- as a C
   client against a real Go ck-server, asserting a completed session and
   bytes through, not merely a 101 or a connect.
2. The negative control: corrupt one offset in EACH template and confirm
   Go refuses. Without this, a passing run proves the templates parse,
   not that the assertions would notice if they did not.
3. Assert WHICH template was sent, on the wire -- a test that passes
   because all three fall back to chrome is the failure mode here.
```
- [ ] **Step 2: Run to verify they fail** (before the code exists, for a **named** reason, not a timeout)
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (77) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Prove all three ClientHello templates against Go"`

---

### Task 2: the encryption matrix against Go

**Files:** extend `libcloak-server/tests/test_go_interop.c`.

`aes-128-gcm`, `chacha20-poly1305` and `plain` have **never met Go**. Only `aes-256-gcm` has. The AAD defect was in `cloak_frame_obfuscate`, and **key-length and nonce handling differ per method** — `crypto.h:18-32` notes `CLOAK_AEAD_AES_128_GCM` *"only consumes the first 16 bytes of key"*. A per-method divergence is invisible to every C↔C test.

- [ ] **Step 1: Write the failing tests**
```
1. All four methods, both directions (C client -> Go server, Go client ->
   C server), bytes compared byte for byte across several frames.
2. Assert the method actually in use, not just that data crossed --
   the same trap as Task 1's case 3.
3. For `plain`, assert what "plain" means on the wire rather than
   assuming it: it is the mode 10a's richest fuzz target uses, so its
   behaviour is already characterised in `fuzz/`.
```
- [ ] **Step 2-4:** as Task 1. **Full suite (78).**
- [ ] **Step 5: Commit** — `git commit -m "Prove all four encryption methods against Go"`

---

### Task 3: the replay cache

**Files:** `libcloak-server/include/cloak/replay_cache.h`, `src/replay_cache.c`; `libcloak-server/include/cloak/server_stack.h` (the capacity); tests.

**The fix has three parts and the plan names all three**, because fixing one is worse than fixing none:
1. **Key the hash.** An unkeyed hash over attacker-chosen bytes is what makes targeted eviction ~1024 offline trials. A per-process random key makes the slot unpredictable.
2. **Raise the capacity to something a real server's handshake rate does not overrun in 12 hours** — and **justify the number with an arithmetic you write down**, not a round figure.
3. **Decide what happens when it is full**, and say why. Eviction and refusal have different failure modes, and refusing is a distinguisher.

**Do not remove the pre-authentication write.** It is deliberate and Go does the same (`auth.go:76`, before `decryptClientInfo` at `:81`); checking replay before decryption is what makes the check cheap enough to survive a flood.

- [ ] **Step 1: Write the failing tests**
```
1. TARGETED EVICTION, the actual attack: insert a victim entry, then
   compute a colliding key offline and evict it with ONE insert.
   Assert the victim survives after the fix. This is the test that
   must fail before the fix and pass after.
2. Whole-table eviction with N inserts -- assert N is now infeasible
   within the 180 s tolerance window, with the arithmetic in the test.
3. Steady-state: a server doing more than the old 1024 handshakes per
   12 hours no longer evicts. A MEASURED bracket, not a claim.
4. The keyed hash is per-process: two instances put the same key in
   different slots. Assert it, or the keying is decorative.
```
- [ ] **Step 2-4:** as above. **Full suite (79).**
- [ ] **Step 5: Commit** — `git commit -m "Key the replay cache and size it to its threat model"`

---

### Task 4: the session cap and the scans behind it

**Files:** `libcloak-server/include/cloak/registry.h`, `src/registry.c`; `libcloak-server/src/userpanel.c`; tests.

**Raising 256 without fixing the linear scan is the trap (D3).** `registry_find_live` and `panel_find` scan a fixed 256 entries **regardless of occupancy**, so today they are O(256) even for one session; raise the cap and they become O(n) at the new n. Five further sites share the shape (`cloak_reactor_cancel_timer`'s heap scan, `peer_find_addr`'s list walk, and three more named in 10a's sweep). **Nothing in the suite bounds any of them.**

- [ ] **Step 1: Write the failing tests**
```
1. A scale case: open sessions to the new cap and assert they all
   establish. Nothing in the tree has ever done this.
2. A COST bracket, which is the point: measure lookup at 1 session and
   at the cap, and assert the ratio is bounded. A test asserting only
   "it still works" would pass against an O(n^2) implementation.
3. The refusal at the cap is still a refusal, and it is still
   indistinguishable from the cover-site redirect -- module 9 measured
   a 15 us log line into a probe oracle, so check this one.
4. The stale justification in registry.h is corrected IN THIS COMMIT.
```
- [ ] **Step 2-4:** as above. **Full suite (80).**
- [ ] **Step 5: Commit** — `git commit -m "Lift the session cap, and make the lookups afford it"`

---

### Task 5: `admin && udp`, and the divergences nobody wrote down

**Files:** `libcloak-client/src/client_stack.c`; `libcloak-mux/include/cloak/stream.h:266`; `libcloak-client/src/udp_piper.c:359`; `cmd/ck-client/main.c`; tests.

Four items, all small, all recorded rather than fixed-and-forgotten:
- **`admin && udp`** (D4): decide, implement, test, and cite Go.
- **`stream.h:266`'s justification is FALSE about Go** — it claims Go *"has no error path there at all"* and `streamBuffer.go:79-81` is one. **Correct it, and record candidate bug #10** (a duplicate of a pending seq wedges Go's stream and grows its heap without bound), stating plainly that it is **read, not reproduced** — or reproduce it and promote it.
- **`udp_piper.c:359`** describes Go's buggy delete-by-key as the model **without noting we are immune**. Say so.
- **Go's own SNI pick is a one-byte modulo** (`ck-client.go:181`) that this port fixed away from — **an unrecorded, wire-visible divergence.** Write it down with its citation.

- [ ] **Step 1: Write the failing tests** (one per decided behaviour; the comment corrections need no test but **must not be split from this commit**)
- [ ] **Step 2-4:** as above. **Full suite (81).**
- [ ] **Step 5: Commit** — `git commit -m "Decide admin-with-udp, and correct three claims about Go"`

---

### Task 6: session resumption across a server restart

**Files:** `cmd/ck-client/tests/` — a new test, or an extension of the CLI suite. **Forking; label it `slow`.**

D5: this discharges module 7's written debt. `cmd/ck-client/main.c:41-47` argues there is no sixth exit code **because** a client that cannot connect retries forever, and **nothing proves it does through the binaries across a real restart.**

- [ ] **Step 1: Write the failing tests**
```
1. Real ck-client, real ck-server, traffic flowing. Kill the server,
   assert the client does NOT exit. Restart it, assert traffic resumes.
2. Assert the session id is FRESH after the restart -- module 9 measured
   exactly this by hand and got a fresh id; a test that only checks
   "bytes flow again" would pass against a client that silently
   reused a dead session.
3. A bracket on how long the client keeps trying: it must still be
   retrying after N seconds, with N justified.
```
- [ ] **Step 2-4:** as above. **Full suite (82). Watch the runtime budget** — see the constraint below.
- [ ] **Step 5: Commit** — `git commit -m "Prove the client retries across a server restart"`

---

### Task 7: the user manager at scale, and the stall nobody has measured

**Files:** `libcloak-server/tests/test_usermanager.c`.

`test_usermanager.c` has 19 cases and **not one is a scale case**; the largest loop anywhere in the server tests is 100. And `2026-09-14-libcloak-server-usermanager-plan.md` **D3 accepts in writing that "a genuinely slow or failing disk stalls the reactor"** — **nothing measures the stall.**

- [ ] **Step 1: Write the failing tests**
```
1. Many users, concurrently -- a number you justify, not a round one.
2. MEASURE the reactor stall under a slow disk rather than asserting it
   cannot happen. The written acceptance says it can; the test's job is
   to say how long. If it cannot be induced in this environment, say so
   with what you tried -- an honest negative retires a suspicion.
```
- [ ] **Step 2-4:** as above. **Full suite (83).**
- [ ] **Step 5: Commit** — `git commit -m "Measure the user manager at scale, and the stall its plan accepted"`

---

### Task 8: split the CLI tests, and pay the runtime debt

**Files:** `cmd/ck-client/tests/CMakeLists.txt`, `cmd/ck-server/tests/CMakeLists.txt`, and whatever splitting the files requires.

**This is the only remaining lever and it now gates the module.** `test_ck_client_cli` measured **59.5–64.9 s, i.e. 1.85×–2.02× against `TIMEOUT 120`** — **the 1.91× floor declared a module ago has been crossed.** The trick that funded the last addition (deleting a subprocess run and merging its assertions) is **spent**. Tasks 1, 2 and 6 all add forking tests.

Note the warm/cold correction: the ~102 s ASan suite figure quoted through module 10a was **cold-cache**; warm runs are **67–71 s**. Use warm numbers and say which you took.

- [ ] **Step 1: Measure the per-case cost** inside both CLI test binaries before splitting — the split should be informed, not arbitrary.
- [ ] **Step 2: Split**, keeping `TIMEOUT` and `LABELS` in one `set_tests_properties` call and verifying in the **generated** file.
- [ ] **Step 3: Re-measure** the suite, Debug and ASan, warm, at `-j4`, against a paired control.
- [ ] **Step 4: Full suite** (count rises by the number of new binaries).
- [ ] **Step 5: Commit** — `git commit -m "Split the CLI tests so the suite's floor is not one case"`

---

### Task 9: long-running stability, and the growth ASan cannot see

**Files:** a new test, or an out-of-band harness with a committed runbook. **Decide which and justify it** — if it cannot be a ctest case within the runtime budget, an out-of-band harness with a documented procedure is the honest answer.

**Nothing in the tree runs long.** Every test is bounded in seconds, and that hides the classes LeakSanitizer's exit scan cannot see: **unbounded growth that never leaks** (the replay cache is bounded — Go's is not), a timer wheel that grows, `retired_dropped` counters that only rise.

- [ ] **Step 1:** decide ctest-case or out-of-band, with the runtime budget as the deciding argument.
- [ ] **Step 2:** measure **growth rates**, not absence — RSS, descriptor count, timer count, session count — over a run long enough for a linear term to separate from noise, and **state the separation**.
- [ ] **Step 3: Commit** — `git commit -m "Watch what does not leak but still grows"`

---

### Task 10: the citation audit

**Files:** across the tree; documentation only unless a claim turns out to be false.

**168 uncited claims about Go sit in the `.c` files against 60 total `.go:` citations.** Module 9 shipped a divergence justification that was **false about Go**, behind a pointer to a rationale **that did not exist**; §5.1 of the scouting report found a second false one; Task 5 of this plan corrects a third. **The base rate is not reassuring.**

- [ ] **Step 1:** enumerate every claim about Go's behaviour in the source, and classify: **cited and checkable**, **cited and wrong**, **uncited**.
- [ ] **Step 2: re-measure a sample of the uncited ones against the Go tree**, sized so the result means something, and **report the false rate**.
- [ ] **Step 3:** add citations where cheap; **correct anything false in the same commit**; and where a claim cannot be checked, say so in the comment rather than leaving it assertive.
- [ ] **Step 4: Commit** — `git commit -m "Cite what we claim about Go, and correct what was wrong"`

---

## Self-review

- **Spec coverage:** §11's integration testing is Tasks 1, 2, 6, 7 and 9; the rest are defects and debts the spec does not name, which is why the scouting report exists.
- **Placeholder scan:** every task names its files and its acceptance. D1-D6 are settled, each on a citation or a measurement.
- **Ordering:** the matrix first (D1 — free oracle, highest-risk component), then the two real defects, then the debts, then the runtime lever, which **gates Tasks 1, 2 and 6 if the budget is already crossed** — a task may need to run 8 early, and should say so rather than silently blowing the bound.
- **Counts chain** 76 → 77 → 78 → 79 → 80 → 81 → 82 → 83 → (8 raises it by the split) → (9 may add none).
- **The riskiest task is 4**, because raising a cap and changing a data structure under the whole server is the only task here that can break something that currently works.
- **The most consequential is 1**, because the spec names ClientHello mimicry the highest-risk component and **two of three templates have never been seen by foreign code** — the AAD defect's exact shape, with the oracle already installed.

---

## What this branch leaves for the next ones

Twenty commits. The suite goes from 76 `ctest` binaries to 85, and from a
floor of one CLI case to twelve. But the count is the least interesting
number here, and two of this module's own corrections were about exactly
that: `ctest` registers binaries, not cases, so the twelve cases added after
Task 1 raised the count by zero. An agent asked to report a rising count
declined and called 86 "the easy wrong answer".

### The shape every defect in this module had

Seven distinct instances, and they are one shape: **the configured intent
said one thing, the wire carried another, and the suite stayed green because
no test read the wire.** A test whose two ends are both our own code cannot
see this, which is why the AAD divergence survived five modules. The
corrective is mechanical and worth stating as a rule: *assert against what
the hello, the frame, or the socket actually carries, never against the
structure that produced it.*

N1 is the cleanest specimen. The GREASE test read back the positions the
template itself declared as `GROUP` and asserted they agreed -- definitional,
and therefore empty. Re-tagging two offsets left the suite at 85/85 while 15
of 16 hellos offered a `key_share` naming a group `supported_groups` did not
list: an illegal ClientHello, guarded by an assertion that could not fail.

### The GREASE change, and what it costs to keep

`clienthello.c` now draws GREASE per connection from `cloak_random_bytes`
over OpenSSL `RAND_bytes`, six (offset, role) positions per template. The
frozen constant it replaced was a static per-build distinguisher -- the worst
shape this class takes in a circumvention tool.

Three traps are now written into the tests, and all three were found by
running uTLS v1.8.0 rather than reading it:

- A naive byte scan for `0x?A?A` **gets Safari wrong**: offset 72 is the
  cipher-list length, `0x002a`. Only a structural walk finds the real slots.
- GREASE must be written **before** the ECH `memmove`, or Chrome's trailing
  GREASE extension is not carried.
- `group(supported_groups)` must equal `group(key_share)` -- uTLS holds it
  200/200 -- and `ext2 != ext1` holds 0/200. Firefox emits no GREASE at all.

**Still owed:** Go shuffles Chrome's extension order every connection
(measured: 200/200 distinct normalised orders for Chrome, **1/200 for
Safari** -- the shuffle is Chrome-only). We pin ours. Our Chrome profile is
therefore distinguishable from real Chrome by invariant extension order.
Deferred deliberately: it reaches far deeper into the pinned byte vectors
than a branch at its end could afford.

### Reference bug #12, promoted from read to measured

Go's replay cache is unbounded. `UsedRandom` is pruned only by a cleaner that
sleeps `replayCacheAgeLimit` = 12 h **first**
(`internal/server/state.go:214-225`). Measured on host Go, the map costs
61.6-100.5 B/entry, so above roughly **19-31 sustained handshakes/s** an
unauthenticated flood exceeds our entire 2^21 table and keeps going for up to
twelve hours. Ours is bounded, keyed, and evict-never-refuse.

The residual that policy accepts is now measured rather than argued: **37.2
of 12,288 in-window handshakes are already replayable for zero attacker
packets** (theory 35.93), and a prober's real cost is ~C/M, not ~C.

### Growth: what the soak can and cannot see

`tools/soak/` plus `docs/runbooks/soak-growth.md`, deliberately **outside
`ctest`** -- a 60 s case would be 3.8x the longest test for 12.5x less
sensitivity, and its most sensitive column is inert under ASan (`mallinfo2`
reports `uordblks` 0 on both sides of a 1 MiB malloc).

What it establishes: at ~42 handshakes/s over 900 s, nothing grows but the
replay cache becoming resident, and that is bounded (94,832 kB measured
against 95,400 kB computed independently). The positive control reads 96.0
B/cycle +/- 0.06 % for a 64 B/cycle retained-and-reachable leak **that
LeakSanitizer does not report** -- the class an exit scan cannot see.

What it cannot see, stated as limits rather than discovered later:

- **A quantisation floor of 1/T -- 4.8 units/hour at 750 s.** A 4 fd/hour
  leak is below it and is *not* excluded.
- **A peak-concurrency ratchet.** K is pinned all run and the reactor's slot
  array never shrinks.
- **One column is never enough.** At 1 MiB retained per cycle `uordblks` and
  `arena` are bit-identical while `hblkhd` shows 1.844e10 B/hr; at 200 KB the
  split reverses. glibc's mmap threshold is dynamic.
- **THP.** `always` on the reference host, so `rss_anon_kb` is not flat even
  in a clean run -- 10,240 of an 11,052 kB rise is `rss_anon_huge_kb`. A
  non-THP host should see run B near-flat and that rise simply absent.

The 240 s A/B/C artefact is committed under `tools/soak/artefacts/` and
reproduces byte-identically through the committed analyzer. **The 900 s
numbers quoted in prose are not reproducible from anything in the tree** --
that is said plainly in the runbook, and it is the reason the artefact exists
at all.

### Comments that claim things about Go

Two audit passes. The bulk rate of false claims is 2.6 % (1/39, Wilson 95 %
[0.5 %, 13.2 %]); the stratum of blocks claiming a *divergence* runs
**10.5 % misleading (4/38)**. Stratifying was the right call, and sampling
the bulk would have missed all four.

The audit's own blind spot, found afterwards: it enumerated blocks
**mentioning Go**, so a security-cost comment naming no Go symbol was never
in the population -- which is how `replay_cache.h` kept quoting a capacity
two doublings out of date through both passes. The cheap recurring grep worth
keeping is for **numbers that name a suite size or an open decision**: five
were found here, none wrong when written, all wrong by now.

### Carried forward

- **Module 8b** -- the client CDN leg. Needs a real TLS stack and a
  fingerprint decision.
- **Chrome's extension shuffle** (above).
- `singleplex + udp`, and `-u` x CDN.
- **The client UDP peer map was never exercised** under churn -- read only
  (`max_peers` 256, 300 s timeout, over-cap refused and counted).
- The soak covers **one workload shape**: ordered TCP, BypassUID. No
  unordered, no UDP, no admin, no metered user.
- `test_client_transport` compares the wire against the same template struct
  it built from, so a flipped non-GREASE byte leaves it passing while the
  matrix test catches it. Pre-existing; not this branch's debt, but it is the
  module's own defect shape sitting unfixed.

---

## Post-merge addendum: three flakes, and one that was never named

The first `ctest` run on merged `main` reported **1 failure out of 85**. The
name was lost — the command that ran it piped ctest through a `grep` matching
the summary line but not the name on the line after it. That is a defect in
the instrument, not in the tree, and it is the reason this addendum exists
instead of a one-line fix.

Hunting it found **three real test defects**, none of them a regression from
this module and none of them in shipping code:

**`da380b1` — `test_valve_rate.c:1556`**, `ASSERT_TRUE(resumed > 0)` after
`HANDOVER STALL: nothing relayed in 300 ms`. 7 of 12 at `--cpus=1` with seven
spinners. The valve was fine: instrumented, every run relayed ~395.2 kB to
within 0.2 %, pass and fail alike. The test released the pool, pumped 20
turns, and only *then* took its origin, while the bucket was 2 ms in debt — so
the resume fired inside the pump. Fixed by moving the origin before the
release and changing the quantity from `p.drained` to `cloak_valve_tx`, which
is charged at enqueue. 0 of 20 after.

**`ae89178` — `test_signals.c:191`**, `ASSERT_EQ_INT(ctx.count, 2) -> 1 != 2`.
3 of 12 at the same lever. The test asserted that two SIGINTs 40 ms apart
cannot coalesce; instrumented, both timers fire in **one** reactor turn ~100 ms
late, the two `raise()`s land back to back with SIGINT blocked, and **the
kernel merges them** — which `cloak/signals.h`'s second-signal contract already
disclaims. (It is `signalfd(2)`, not a self-pipe.) Fixed by raising the second
signal from inside the first delivery, causally after that siginfo left the fd.
0 of 20 after.

**`f8f8966` — `test_dispatcher_ws.c:1476,1486`**, a 1000 µs spread over 31
runs. Its own comment already argued the clock detected nothing, and that was
right: porting Go's ordering in as a mutation, the clock-free assertion fails
deterministically while the old brackets **pass** — median spread 686/663 µs,
fastest 313/394 µs, all inside the bound. Brackets removed, every number still
printed, replaced by a clock-free check after each of the 31x5 probes.

### What makes these three worth reading together

All three were fixed the same way — **anchor, do not widen.** Not one
tolerance was loosened, no `ctest` TIMEOUT moved, nothing skipped or wrapped
in a retry. And each fix was proved by a **mutation pair**, where the second
mutation is the one that earns its keep:

- valve: the same broken arming read from the early origin with the *old*
  quantity **passes** — a false green off 32 KiB of already-billed residue.
- signals: the obvious alternative fix (keep both timers, raise SIGTERM
  second) removes the flake **and passes with the latch defect still in** —
  which is why the repeat must stay the same signal.
- ws: the old brackets pass against a real ordering defect.

**A fix seen only to pass is not a fix.**

### What is still not known

- **Which test failed on merged `main` is still unidentified.** It was
  unconstrained; all three flakes above reproduce only under starvation. The
  candidate set is now smaller by three, and that is all that can be said.
- **Defect 2 was never observed failing** — 0 of 12 before at the lever that
  gives `test_signals` 3 of 12. Its removal rests entirely on the mutation,
  not on a sighting.
- The `--cpus=1` + 4-spinner lever, which an earlier sweep ran 20 times
  against the 75-test suite for 0/20, now breaks several tests at once. At a
  ~8 %/run rate a clean twenty has roughly one chance in five, so the old
  result does not conflict with these flakes having been there all along.
  `test_valve_rate` dates from when the suite held 45 tests, so suite growth
  did not introduce it. Neither explanation is asserted.
- `test_client_stack.c:1845,2140` are unanchored wall-clock upper bounds, and
  every `ASSERT_TRUE(pump_until(...))` in that file is wall-clock budgeted:
  starvation candidates, unexamined.
- `test_replay_cache_keyed` (TIMEOUT 600) **dominates a starved full-suite
  run** — it alone ran for minutes after the other 84 finished.
