# `fuzz/` — eight libFuzzer targets, one committed corpus, and what none of it can see

This directory is module 10a. It holds **eight fuzz targets**, **one committed corpus per
target**, and **one ctest case** (`test_fuzz_corpus_replay`) that replays every committed
unit on every run of the suite.

Read the second half of this file before you read a green fuzz run as coverage. **Zero real
defects were found across all eight targets and roughly 100 million executions**, and the
classes of defect this project has actually shipped are, with one exception, classes a
fuzzer here cannot see at all.

---

## 1. What is here

| target | subject | reachable by | corpus | `-max_len` | 60 s exec/s |
|---|---|---|---|---|---|
| `fuzz_session_envelope` | the session's envelope path: frame codec, `strmtab`, the ordered reorder heap, `msgqueue`'s ring arithmetic, the unordered datagram queue (`libcloak-mux`) | an authenticated peer | 137 units | 4096 | 12,476 |
| `fuzz_firstpacket` | the server's first-packet classifier (`libcloak-server/src/firstpacket.c`) | **anyone who can open a TCP connection** | 96 | 4096 | 158,219 |
| `fuzz_clienthello` | the server's ClientHello parser (`clienthello_parse.c`) | **anyone who can open a TCP connection** | 64 | 4096 | 438,051 |
| `fuzz_ws_handshake` | the CDN front door's WebSocket upgrade (`ws_handshake.c`) | **anyone who can open a TCP connection** | 327 | 4096 | 115,758 |
| `fuzz_ws_frame` | the RFC 6455 frame header decoder on the CDN data path (`libcloak-mux/src/ws_frame.c`) | an unauthenticated CDN peer | 97 | 64 | 275,800 |
| `fuzz_base64` | both alphabets, both directions (`libcloak-common/src/base64.c`) | via the two above | 97 | 4096 | 81,685 |
| `fuzz_http` | the admin API's HTTP/1.1 request parser (`libcloak-server/src/http.c`) | an admin-API client | 211 | 4096 | 95,399 |
| `fuzz_client_reply` | the **client's** handshake-reply reader (`libcloak-client/src/client_transport.c`) | **anyone who can answer the client's connection** — an on-path censor, a DNS or BGP hijack, the operator of the IP the client was pointed at | 65 | 1024 | 489 |

Every number above is a measurement, recorded with its conditions in
`.superpowers/sdd/2026-09-17-module-10a-fuzzing-plan/task-{1,2,3,4}-report.md`. **Compare
`exec/s` between rows only with care**: `fuzz_session_envelope` builds a session and a
reactor per execution and `fuzz_client_reply` generates an X25519 key, performs an ECDH and
creates a socketpair per execution, while the middle rows are one parse of one buffer.

The convention every target follows — one file per target, one `LLVMFuzzerTestOneInput`, no
shared harness, nothing built in the default build — is documented at the top of
`CMakeLists.txt` and is not restated here.

---

## 2. The one test: `test_fuzz_corpus_replay`

**The corpus is the committed artefact, the replay is the regression, and campaigns run out
of band.** The replay feeds all **1,094 committed units (288,427 bytes)** to the harness that
produced each one, once, in sorted order, through the same oracles a campaign uses — no
mutation, no randomness, no time budget.

Measured at the commit that added it, Docker `cloak-c-dev`, arm64, `-j4`:

* **Debug: 0.32 s. ASan+UBSan: 1.33-1.39 s.** `TIMEOUT 60` — a 43x margin, against the
  1.89-2.02x the suite's longest test lives at.
* The alternative CI shape, a 60-second campaign per target, is **eight minutes** against a
  ~100 s ASan suite. That is what settled the question.

It asserts the corpus caps rather than describing them (`replay_main.c`): **1 MiB of content
bytes** (Ruling 2) and **2,048 files**. Today: 288,427 bytes (27.5 %) and 1,094 files
(53.4 %). **File count is the binding cost**, not bytes. It also fails on a corpus directory
that is missing or empty, because losing the units silently would leave a green test covering
nothing.

**It has gone red, from the committed corpus alone, with no fuzzing.** Module 10a task 4's
planted denial of service — delete the zero-length-record case from `feed`'s header branch in
`client_transport.c` and a record declaring a zero-length body parks the reader with nothing
to wait for, pinning a registered fd on the shared reactor for the full 15-second deadline,
bought by a censor for a five-byte record header. Measured with the plant live, `ctest -j4`
in Debug:

```
99% tests passed, 1 tests failed out of 76
    76 - test_fuzz_corpus_replay (Subprocess aborted)
fuzz_client_reply: oracle failed: still pending after the peer closed:
the reader parked with nothing to wait for
```

on corpus unit `client_reply/5a41d47a53ff8c4f999db11aecb6bf3b4873e05f`, caught by that
target's O7 liveness oracle. **The other 75 tests all pass with that plant live** — the
suite's replies all come from a real or scripted Cloak server, and a real reply has no
zero-length record. Reinstate the plant and run `ctest` to see it again.

---

## 3. Running a campaign, out of band

```sh
# Configure ONCE. CC=clang is required: the dev image's default compiler is gcc,
# which has no libFuzzer. A directory already configured with gcc must be DELETED.
CC=clang cmake -S . -B /tmp/fuzzbuild -DCMAKE_BUILD_TYPE=Debug \
      -DCLOAK_FUZZ=ON -DCLOAK_REQUIRE_GO=OFF

# Build ONE target, so the 76 test binaries are not also built under ASan.
cmake --build /tmp/fuzzbuild --target fuzz_http -j4

# Run it against its committed corpus. -max_len is per target (table above) and
# MATTERS: with a corpus, libFuzzer silently adopts the longest seed as the limit,
# so a minimised corpus can shrink the search space without anybody choosing to.
/tmp/fuzzbuild/fuzz/fuzz_http fuzz/corpus/http -max_len=4096 -max_total_time=60
```

To fold what a campaign found back into the tree:

```sh
mkdir /tmp/merged
/tmp/fuzzbuild/fuzz/fuzz_http -merge=1 -max_len=4096 /tmp/merged fuzz/corpus/http
# then replace fuzz/corpus/http with /tmp/merged and run the replay:
ctest -R test_fuzz_corpus_replay
```

**Minimise before committing.** A 60-second run of `fuzz_ws_handshake` produces 1,657 new
units; committing them unminimised would blow the file cap the replay asserts within two
campaigns. If the replay fails on the cap, that is the message, and `-merge=1` is the fix.

`fuzz_session_envelope` has a companion seed generator, `gen_seeds_session_envelope`, for the
reason its own file header gives. `fuzz_client_reply` cannot have one: see §5.

---

## 4. WHAT FUZZING HERE CANNOT SEE

This is the section that exists so that a green fuzz job is not read as coverage it does not
have.

### 4.1 Every distribution defect, and every divergence from Go

**Of this project's 79-item defect ledger, every entry that was about a *distribution* or a
*divergence* is invisible to every target in this directory.** A fuzzer's oracle is "did this
input crash, or violate an invariant I wrote down". It has no notion of *how often*, and no
notion of *what the other implementation would have done*. Concretely, and these are real
defects this project shipped and then fixed, not hypotheticals:

* **A biased modulo.** `rand() % n` is not uniform. Every individual output is legal, so every
  oracle in this directory passes on every one of them. Detecting it needs a statistical test
  over many outputs, which is a test, not a fuzz target.
* **A predictable connection pick.** The session's choice of connection was uniform and
  *predictable*; fixing it (`a02d5a5`) changed no input, no output format and no invariant a
  parser could check. A fuzzer would have been green before and after.
* **A padding-length distribution.** Padding that is always the same length, or drawn from the
  wrong distribution, is a traffic-analysis defect — the thing this transport exists to
  prevent — and is perfectly well-formed on the wire.
* **An AAD mismatch with Go.** `cloak_frame_obfuscate` sealed with the wrong associated data.
  Both ends of every C↔C test agreed with each other, so every C↔C test passed; only Go
  disagreed. **A fuzzer is the purest possible C↔C test**: the harness and the code under test
  are the same implementation. It cannot find a divergence by construction.

Those belong to **module 10b**. Nothing in this directory discharges them, and a plan that
counts fuzzing against them is miscounting.

### 4.2 The combinations, which are a matrix problem and not a byte problem

The port supports **3 browser signatures × 4 encryption methods × 2 ordering modes = 24
combinations**, and **2 of them have ever met foreign code**. A wrong offset in the Firefox or
Safari ClientHello template passes every test in this tree *and* every target in this
directory — both ends read the same offset table — and is exactly the AAD defect's shape.
`fuzz_clienthello` fuzzes the server's *parser* of a ClientHello; it says nothing about
whether the client's *template* is what a Chrome, Firefox or Safari actually sends. That is
the highest-risk component in the spec and it is 10b's, not this directory's.

### 4.3 Anything that needs time, scale, or a second process

Every target here is one process, bounded in milliseconds. Out of reach by construction:
session resumption across a server restart; more than two concurrent sessions, let alone
`CLOAK_REGISTRY_MAX_SESSIONS`; the rate limiter under competing metered users; a slow or
failing disk stalling the reactor under the SQLite user manager; and unbounded growth that
never leaks, which ASan's exit scan cannot see either.

### 4.4 Two named blind spots inside the targets themselves

Both are recorded in the source with their measurements, and both are honest reports of the
instrument's limits rather than of the code's:

* **`fuzz_http` does not see the Content-Length cap.** Hoisting the cap check out of the
  accumulation loop to after it **survived 5,885,563 executions**. The oracles do not model
  peak intermediate allocation, only the final answer. Three unit tests in `test_http_parse`
  are the only thing in the tree that catches it.
* **`fuzz_client_reply` leaves two `feed` edges uncovered**, with the subject's own reasoning
  cited in the harness header: `feed`'s internal `min_size()` clamps are dead under the
  object's only real caller, so fuzzing them would be fuzzing a caller that does not exist.

---

## 5. What the module actually learned

**The gate question got four different answers, every one measured.** "Is a seed corpus worth
committing?" has no single answer even within one directory:

1. **`fuzz_session_envelope`: seeds buy reachability.** A dropped `% q->cap` was **not found in
   623,089 blind executions** and fell **in about 8 seconds from seeds** — the gate is 2^64
   wide with no coverage gradient.
2. **`fuzz_firstpacket` / `fuzz_clienthello`: seeds buy reliability and ~100×, not
   reachability.** The first draft of that task's report called the gate "unclimbable"; the
   measurement said otherwise — libFuzzer passes the equality gate in ≈1.4–2.4M executions on
   **two of three** seeds, and did not reach it in 13.6M on the third. From the corpus:
   ≈21,000. The claim was corrected to match the measurement.
3. **`fuzz_ws_handshake` / `fuzz_http`: the corpora are load-bearing.** With a bug planted and
   no corpus, one target was **not reached in 26,567,643 executions**.
4. **`fuzz_client_reply`: no corpus can ever pass its gate.** The shared secret is a fresh
   ephemeral X25519 key per execution, so no fixed byte string authenticates twice. The
   harness seals record 0 itself, at runtime, on request from a flag bit in the input.

**A target can run at 438,051 exec/s and prove nothing.** The first version of
`fuzz_clienthello` had in-range-only oracles; a planted bug that hands a caller a short key
share to read 32 bytes out of **survived 25,402,060 executions**. It was green, fast, and
useless. The oracles were rewritten to re-derive the answer rather than bound it.

**Whether the existing suite already catches each plant differs per target, and all eight were
asked.** Twelve plants:

| plants | caught by the existing 75 tests? | what that means for the target |
|---|---|---|
| `fuzz_session_envelope` (2) | **yes, both** | its justification narrows to combinations the unit tests do not enumerate |
| `fuzz_firstpacket`, `fuzz_clienthello` (2) | **no** | real marginal coverage |
| task 3's four targets (6) | **yes, all six** | regression insurance, not new coverage |
| `fuzz_client_reply` (2) | **one yes, one no** | the "no" is a **five-byte censor denial of service**, and it is what the replay now regresses |

**Zero real findings across all eight targets.** That is the expected outcome, not a
disappointment: these are parsers nine modules have read, bounded and unit-tested, and the
scouting run found nothing in 11.3M executions before a single target was written. The value
delivered is (a) **regression insurance** — 1,094 committed units replayed on every `ctest`
run, one of which already catches a defect the rest of the suite does not — and (b) **two
attack surfaces nobody in this project had listed**: the client's handshake-reply reader,
reachable by anyone who can answer the client's connection, and the CDN front door's upgrade
path. Neither had appeared in the spec's fuzz list, module 8's, module 9's, or the first six
entries of module 10's.
