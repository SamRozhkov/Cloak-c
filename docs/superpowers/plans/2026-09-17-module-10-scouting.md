# Module 10 scouting: integration and fuzzing

Date: 2026-09-17
Tree: `Cloak-c` `main` @ `2e6f2f6`, 75 tests
Reference: `/Users/sam/Cloak` @ `c3d5470` (v2.12.0)
Status: scouting only — nothing in either tree was modified.

Everything below that is stated as a number was measured in the dev image during this scout, or is
quoted from a named file and line. Where a claim is reasoned from reading rather than measured, it
says so in the same sentence, because this project's whole ledger says reading does not find
defects.

**Measurements taken for this report** (dev image `cloak-c-dev`, `-j4`, aarch64):

| what | measured |
|---|---|
| Debug suite | 75/75, **28.36 s** |
| ASan+UBSan suite | 75/75, **100.93 s** |
| `test_ck_client_cli` under ASan | **59.77 s** and **62.89 s** over two runs |
| `test_ck_server_cli` under ASan | **40.03 s** and **41.29 s** |
| next three: `test_adminapi` / `test_dispatcher_ws` / `test_go_interop` | 14.10 / 13.39 / 9.64 s |
| ASan build directory | **799 MB** |
| whole tree under `clang` 14.0.6 | **builds, 1 warning**, and it is in a test |
| `-fsanitize=fuzzer` in the image today | **cannot link** (see §3) |
| `-fsanitize=fuzzer` after `apt-get install clang libclang-rt-14-dev` | **links and runs** |
| a 4-target libFuzzer harness over the real libraries | **11,321,022 execs in 61 s = 185,590/s, 0 crashes** |
| replaying the 393-unit corpus that run produced | **875 ms**, whole process |

---

## 1. What the spec says module 10 is, and what is actually left

The spec's testing section is `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` §11, and it
is three bullets long:

- **Unit tests** — "frame obfuscate/deobfuscate round-trip, ClientHello offset patching (including
  SNI length-rewrite correctness), auth encrypt/decrypt round-trip, switchboard connection
  distribution."
- **Integration test** — "local `ck-server` + `ck-client` against a dummy TCP echo target standing
  in for the underlying proxy; verify byte-exact data integrity across multiple concurrent streams
  and multiple underlying connections."
- **Fuzz targets** — "(libFuzzer, bundled with clang): ClientHello parsing and frame deobfuscation —
  mirrors Go's `first_packet_fuzz.go` / `session_fuzz.go`."

**Said plainly: of those three, two are done and one does not exist.**

- Every unit test the spec names exists and is far past what it asks (`test_frame.c`,
  `test_clienthello.c`, `test_server_auth.c`, `test_switchboard.c`, plus 71 more).
- The integration test the spec names exists **twice over and better than specified**:
  `cmd/ck-client/tests/test_ck_client_cli.c:1439` (`test_end_to_end_through_both_binaries`) is
  literally the spec's sentence, and `libcloak-server/tests/test_go_interop.c` replaces the "dummy
  echo target" premise with Go Cloak's own binaries in both roles. The spec's integration bullet is
  **over**-satisfied.
- **Fuzzing does not exist.** `grep -rn "LLVMFuzzerTestOneInput"` over the tree returns nothing.
  What exists is *fuzz-shaped interfaces* and *seeded pseudo-fuzz loops inside ordinary tests*:
  `test_dispatcher_limits.c:812` (`test_fuzz_first_packets_never_crash_or_leak`, 300 connections of
  `rand_r`-generated first packets) says so itself at `:784` — "NOT a substitute for the libFuzzer
  targets the project's own spec calls for". Also `test_http_parse.c:923`, `test_user_json.c:884`,
  `test_bytequeue.c:81`. Four headers promise module 10 will fuzz them:
  `libcloak-mux/include/cloak/ws_frame.h:40`, `libcloak-server/include/cloak/ws_handshake.h:26`,
  `libcloak-server/include/cloak/ws_handshake.h:236`, `:259`.

So the honest scope statement is: **module 10 is not "finish the spec's testing section". The spec's
testing section is 2/3 finished, and the third is a toolchain change plus a handful of harnesses.
The real content of module 10 is the inherited obligations (§2), the combinations nobody has run
(§4), and the defects a fresh reading of the tree turns up (§5) — none of which the spec names.**

One genuine spec gap worth stating: the spec's integration bullet says "**multiple** concurrent
streams and **multiple** underlying connections" and says nothing about **multiple concurrent
sessions**, which is where §5.4's hard ceiling lives.

---

## 2. The inherited obligations, verified one by one

Each was checked against the tree as it stands today, not against the handoff text.

### 2.1 The runtime budget — **STANDS, and is one notch tighter than inherited**

Module 9 recorded `test_ck_client_cli` at 61.6 s with "a measured 1.95–2.01×" margin against
`TIMEOUT 120`. Measured here across two ASan runs in one container: **59.77 s and 62.89 s**, i.e.
**2.01× and 1.91×**. The inherited lower bound is now broken; the margin is **1.91×**.

Context, measured: the whole ASan suite is **100.93 s** at `-j4`, of which the two CLI files are
**~103 s of CPU** and, being the two longest single tests, set the wall clock. The next three tests
are 14.10, 13.39 and 9.64 s. `test_ck_client_cli` alone is **62 % of the suite's wall clock.**

**The named lever is still available and is still the only one.** `cmd/ck-client/tests/test_ck_client_cli.c`
is 2564 lines holding **19 top-level cases** (`grep -c '^static void test_'`), and they divide on a
clean seam that is already visible in their names:

- *exit-before-network* (config/CLI): `version_and_help`, `flags_override_json`,
  `local_host_flag`, `proxy_flag`, `missing_remote_host`, `udp_without_numconn_names_numconn`,
  `plugin_mode_takes_an_ssv_string`, `exit_codes_are_distinct`, `config_from_a_file_and_from_ssv`,
  `defaults_fill_in_the_omitted_fields`, `verbosity_is_validated`, `keepalive_is_warned_about`.
- *runtime pair* (forks a `ck-server` **and** a `ck-client` and moves bytes): `udp_is_honoured`,
  `the_unordered_bit_is_on_the_wire`, `end_to_end_through_both_binaries`,
  `sigterm_is_clean_and_leaks_no_descriptor`, `admin_flag_reaches_the_admin_api`,
  `shutdown_bills_the_last_interval`, `runtime_exit_code_and_the_descriptor_budget`.

The cost is LeakSanitizer's exit scan per forked child (module 7 measured ~0.93 s/child), so the
split must be **by child count, not by line count** — and the plan should *measure* per-case child
counts before choosing the cut, because guessing that seam is exactly the mistake module 9's task-0
comment (`CMakeLists.txt:20-45`) documents someone making about "the four slowest tests all fork".

**Price:** one new directory-scope `add_executable` + `add_test` + the shared harness moved into a
header or a small static lib. Mechanical. But note the second-order cost: **two tests at ~31 s each
run concurrently under `-j4`, so the suite wall clock falls toward `test_ck_server_cli`'s 41 s**, and
that file then becomes the binding constraint. **Budget after the split: ~41 s of headroom before
`test_ck_server_cli` needs the same treatment.**

### 2.2 `-u` × CDN is unreachable — **STANDS**

`libcloak-client/src/client_stack.c:915-918` refuses `Transport "cdn"` at stack open:
`"client config: Transport \"cdn\" is not supported by this build"`, and
`libcloak-client/src/client_connector.c:472` restates it. `libcloak-client/include/cloak/client_stack.h:356-358`
documents the refusal. Module 8b (a real TLS stack plus a fingerprint decision) is unwritten. **Not
module 10's, and module 10 must not pretend to close it.**

### 2.3 `singleplex + udp` is unimplemented — **STANDS**

`libcloak-client/src/client_stack.c:922` (`if (c->udp && c->singleplex)`) → `:969`, refused by name
with the honest message "(Go's client does support it)". Go does: `cmd/ck-client/ck-client.go:198`
passes `remoteConfig.Singleplex` straight into `RouteUDP`, and `internal/client/piper.go:39-41`
makes a fresh session per peer. **This is the one place where the port is knowingly a subset of Go's
feature set**, and the project's own scope statement is "full feature parity". It is small — one
session per peer instead of one shared — but §5.5 shows the Go code it would be ported from is the
buggiest function in the reference.

### 2.4 The two module-8 fuzz targets — **STAND, and nothing else fuzz-shaped landed either**

`2026-09-16-module-8-cdn-server-plan.md:390` deferred `cloak_ws_handshake_parse` and
`cloak_ws_frame_parse_header` to module 10's corpus. Both functions exist with exactly the promised
pure signatures (`ws_handshake.h:277`, `ws_frame.h:181`) and **neither has a libFuzzer target.**

### 2.5 `keep_alive_sec` is parsed and consumed by nobody — **STANDS**

Full consumer census (`grep -rn keep_alive`, non-test, non-build):

- parsed: `config_client.c:244-248`, `config_server.c:231-235` (`KeepAlive` → `-1` when absent/≤0);
- stored: `config.h:124`, `config.h:174`;
- **read by exactly two sites, both of which only print it**: `cmd/ck-server/main.c:856-859` and
  `cmd/ck-client/main.c:956-959`, each a startup warning;
- `libcloak-client/include/cloak/client_stack.h:356` states plainly: "Nothing in this port sets
  `SO_KEEPALIVE` yet."

Module 7 wrote "**It must not survive the session module unrecorded.**" It survived modules 8 and 9.
It is now two modules past its deadline and this is the last module. The implementation is two
`setsockopt` calls (`SO_KEEPALIVE` + `TCP_KEEPIDLE`) at the two places a Cloak-carrying TCP socket is
created; the test is white-box (`getsockopt` on the accepted fd), because no oracle can see it.

### 2.6 Ordered-mode duplicate retirement as a declared Go divergence — **THE DIVERGENCE STANDS; ITS WRITTEN JUSTIFICATION IS FALSE**

This is §5.1. It is the single most important item in §2 and it is broken out below.

### 2.7 The unconfirmed ninth Go bug (`RouteUDP` deletes by address) — **CONFIRMED BY READING, STILL NOT MEASURED; THE PORT IS IMMUNE BY CONSTRUCTION**

Copied verbatim from `/Users/sam/Cloak/internal/client/piper.go` (the `internal/` package is not
importable, so this is a copy, as instructed):

```go
			go func(stream *mux.Stream, localConn *net.UDPConn) {
				buf := make([]byte, 8192)
				for {
					n, err := stream.Read(buf)
					if err != nil { ... break }
					...
				}
				streamsMutex.Lock()
				delete(streams, addr.String())
				streamsMutex.Unlock()
				stream.Close()
				return
			}(stream, localConn)
```

and, in the same loop's write path (`piper.go:83-91`):

```go
		_, err = stream.Write(data[:i])
		if err != nil {
			...
			streamsMutex.Lock()
			delete(streams, addr.String())
			streamsMutex.Unlock()
			stream.Close()
			continue
		}
```

The goroutine deletes **by key**, never checking that the entry still names *its* stream. The
eviction sequence, read off those two blocks: (1) peer A's `stream.Write` fails, the main loop
deletes `streams["A"]` and closes S1, G1 is still in `stream.Read`; (2) the next datagram from A
misses the map and creates S2 with a new goroutine G2, `streams["A"] = S2`; (3) G1's read finally
errors on the closed S1, it takes the mutex and **deletes S2's entry**. S2 is now live, has a live
goroutine writing replies to A, and is unreachable from the map — so datagram three creates S3, and
A now receives interleaved replies from two streams while a third leaks. **Reproducing it needs the
race window and was not attempted here.**

The C port cannot have it: `libcloak-client/src/udp_piper.c:186` `peer_retire(peer, ...)` ends at
`:219` with `peer_unlink(pp, peer)` — **by pointer, on a single-threaded reactor**, so there is no
key lookup and no window. This immunity is *undocumented*: `udp_piper.c:359` says "Go's reader
goroutine does exactly this — break, delete its own key, close the stream", which is a description
of the buggy code with no note that copying its *shape* would have copied the bug.

---

## 3. Fuzzing: the honest state, and what the image can actually build

### 3.1 The toolchain question, answered by building rather than by reading

**The dev image has no `clang` at all.** `docker run --rm cloak-c-dev sh -c 'clang --version'` →
`sh: 1: clang: not found`. `Dockerfile.dev`'s base stage installs `build-essential cmake libssl-dev
ca-certificates curl` and nothing else; the compiler is **gcc (Debian 12.2.0-14+deb12u1) 12.2.0**,
and **gcc has no libFuzzer** — `-fsanitize=fuzzer` is a clang/compiler-rt feature with no GCC
equivalent. A plan that says "libFuzzer, bundled with clang" and stops there is the module-8 mistake
verbatim.

**Installing `clang` alone is also not enough, and this was measured:**

```
apt-get install -y --no-install-recommends clang
clang -g -fsanitize=fuzzer,address -o fuzz_probe fuzz_probe.c
/usr/bin/ld: cannot find /usr/lib/llvm-14/lib/clang/14.0.6/lib/linux/libclang_rt.fuzzer-aarch64.a
/usr/bin/ld: cannot find .../libclang_rt.asan_static-aarch64.a
/usr/bin/ld: cannot find .../libclang_rt.asan-aarch64.a
```

Debian ships the compiler-rt runtimes in a separate package. **`clang` + `libclang-rt-14-dev` works:**

```
Debian clang version 14.0.6   (target aarch64-unknown-linux-gnu)
BUILD_OK
==289==ABORTING  ... SUMMARY: AddressSanitizer: SEGV
Test unit written to ./crash-f5c5e0c...   Base64: RlVaWlpaJYA=   ("FUZZZZ%\200")
```

— i.e. the probe's deliberate null-deref behind a `FUZZ` magic prefix was found and minimised.

**Cost of the image change, measured:** `Need to get 45.4 MB of archives. After this operation, 264
MB of additional disk space will be used.` The image goes from **1.01 GB to ~1.27 GB**.

**The tree compiles under that clang.** A full `-DCMAKE_C_COMPILER=clang` Debug build of everything
(libraries, binaries and all 75 test executables) succeeded with **exactly one warning**, and it is
benign and in a test: `libcloak-server/tests/test_clienthello_parse.c:158:22: warning: variable
'sink' set but not used [-Wunused-but-set-variable]` (a `volatile uint8_t sink` used to defeat
dead-store elimination). **No portability work is needed to add a second compiler.**

### 3.2 A real target was built and run against the real libraries

To prove the plan is buildable rather than plausible, a 4-way harness in `/tmp/scout10/fuzz_real.c`
was compiled against `libcloak-server.a` + `libcloak-mux.a` + `libcloak-common.a`, built with
`-fsanitize=fuzzer-no-link,address,undefined` and linked with `-fsanitize=fuzzer,address,undefined`:

| result | value |
|---|---|
| libraries build under the fuzz flags | **LIBS_OK** |
| harness links | **FUZZ_LINK_OK** |
| 60-second run | **11,321,022 execs, 185,590 exec/s, 4,414 new units, peak RSS 732 MB** |
| crashes | **zero** |
| fuzz build directory (libs only) | **128 MB** |
| replaying the resulting 393-unit corpus | **875 ms** including process start |

Two conclusions the plan should take from that and not re-derive:

1. **CI shape.** A 60-second-per-target fuzz job would more than double the suite. A **corpus
   replay** costs **875 ms** for 393 units under ASan+UBSan — that is a normal ctest test, and it is
   the right CI artefact: the corpus is committed, the replay is the regression, and long campaigns
   run out of band.
2. **Expectation setting.** 11.3M executions against the four most-quoted parsers found nothing.
   These parsers have been read, bounded and tested hard for nine modules, so the plan should
   **not** be written around "the fuzzer will find bugs in `cloak_ws_frame_parse_header`". It should
   be written around targets that reach *state*, and around structure-aware seeds — see §3.4.

### 3.3 The target inventory, ranked by what a memory-safety bug costs

Selection criteria as asked: (a) attacker-controlled, (b) unauthenticated or weakly authenticated,
(c) pure over a byte buffer or close to it. The cost column uses `http.h:17-30`'s own taxonomy.

| # | target | reachable by | auth | shape | cost of a bug |
|---|---|---|---|---|---|
| 1 | `cloak_session_on_envelope` / `cloak_frame_deobfuscate` (`frame.h:51`) with `CLOAK_AEAD_NONE` + zero key | anyone, on a `plain` session | **none in `plain` mode** | stateful: strmtab, reorder heap, msgqueue, bytequeue allocation | **heap corruption in the data plane.** This is Go's `session_fuzz.go` exactly (`setupSesh_fuzz` uses `EncryptionMethodPlain, [32]byte{}`), and `plain` is a real, parseable config (`config_client.c:9`). The richest state in the tree behind the thinnest gate. |
| 2 | `cloak_firstpacket_feed` (`firstpacket.h:145`) driven through `cloak_firstpacket_want` | first bytes of any TCP connection | **none** | resumable state machine over ≤3000 bytes | **fingerprint-class + pre-auth memory safety.** This is Go's `first_packet_fuzz.go`. The `want()`-chunked driver is the part no existing test covers: the split boundary is the axis a resumable machine gets wrong, and every current test feeds convenient chunks. |
| 3 | `cloak_clienthello_parse` (`clienthello_parse.h:53`) | same bytes as #2 | **none** | pure | **the spec's own first named target.** Six nested length fields, and its own header concedes it "does not validate the record layer's own declared length field against len". |
| 4 | `cloak_ws_handshake_parse` (`ws_handshake.h:277`) | any `GET` to the origin | **none** | pure | module 8's deferred #1; fingerprint-class per `http.h:17-30`. |
| 5 | `cloak_ws_frame_parse_header` (`ws_frame.h:181`) | any peer past the upgrade | **upgrade only**; AEAD is a layer above | pure | module 8's deferred #2. |
| 6 | `cloak_http_parser_*` (`http.h`) | admin UID holder | **operator** | incremental parser + body allocation | **`http.h:19-27` says it itself: "A memory-safety bug in here is remote code execution, not a fingerprint."** Highest per-bug cost in the tree, lowest reachability. |
| 7 | the client's handshake-reply reader (`client_transport.h:186-194`, states `READ_RECORD_HEADER`/`READ_RECORD_BODY`) | **anyone who can answer the client's TCP connection** — i.e. any on-path censor | **none until the AEAD opens** | state machine over ≤49,935 bytes (`CLOAK_CLIENT_HANDSHAKE_MAX_REPLY_BYTES`) | **the only client-side pre-auth parser, and it is missing from every prior list in this project.** A censor does not have to be the server to feed it. |
| 8 | `cloak_ws_frame_mask` at a resumed `pos` | any peer past the upgrade | upgrade only | pure, in-place | low memory risk, high *correctness* risk — `ws_frame.h:213-222` says implementations reliably get `pos` wrong. A differential target, not a crash target. |
| 9 | `cloak_base64_decode` / `cloak_base64url_decode` (`base64.h:35,76`) | reached from #4's `Hidden` and from config | none / operator | pure | small, cheap, and on the unauthenticated path; include it because it costs nothing. |
| 10 | `cloak_user_json_*`, `cloak_config_*_load` | operator | operator | pure over cJSON | low. Already has seeded smoke fuzz (`test_user_json.c:884`). Not worth a libFuzzer target. |

**Recommended set for module 10: #1, #2, #3, #4, #5, #7** — the two the spec names, the two module 8
deferred, the two nobody has named (#1's stateful form and #7's client side). #6 and #9 are cheap
add-ons to the same CMake plumbing.

### 3.4 What the fuzzer would actually catch, stated honestly

- **#1 is the one with real expected yield.** It is the only target that allocates, grows and frees
  across calls: `strmtab` insertion, the ordered reorder heap (`stream.c:92`, `heap_contains_seq` at
  `:386`), `msgqueue`'s ring arithmetic (`msgqueue.c:73-110`, three separate `% q->cap`), and the
  unordered datagram queue. Everything upstream of it is a memcmp.
- **#7 is the one with real expected *novelty*.** It is a whole attack surface — the client's — that
  no list in this project has ever included, and it is reachable by the adversary the project is
  built against.
- **#2's value is the chunking axis, not the bytes.** Feed sizes must be derived from the input, not
  fixed, or the target is strictly weaker than `test_dispatcher_limits.c:812` already is.
- **#3, #4, #5 are regression insurance.** 11.3M executions found nothing; write them, commit the
  corpus, and expect them to earn their keep the day someone edits those files, not today.
- **What fuzzing cannot see, and the plan must not claim it can:** every defect in this project's
  79-item ledger that was about a *distribution* or a *divergence*. A fuzzer cannot see a biased
  modulo, a predictable connection pick, a padding length distribution, or an AAD mismatch with Go.
  Those are §7's business.

---

## 4. Integration: the combinations nobody has run

The three oracle tests (`test_go_interop.c`, `test_ws_interop.c`, `test_unordered_proof.c`) between
them pin **one** point in configuration space. Grepping their generated configs:
`"ProxyMethod":"shadowsocks"`, `"EncryptionMethod":"aes-gcm"`, `"BrowserSig":"chrome"`, `NumConn` 1
or 2 or 4. Both the port and Go support **3 browsers × 4 encryption methods × 2 ordering modes**
(`config.h:66-68` vs `internal/client/TLS.go:23-25`; `crypto.h:8-11` vs
`internal/multiplex/obfs.go:27-30`). **2 of 24 combinations have ever met foreign code.**

| combination | state today | would a censor or operator hit it? |
|---|---|---|
| **Firefox and Safari ClientHello templates against Go's parser** | **never run.** Only `chrome`. | **YES, and this is the biggest one.** The spec calls ClientHello mimicry "the highest-risk, highest-value component". A wrong offset in the Firefox or Safari offset table passes every C↔C test — both ends read the same table — and Go's `internal/server/TLSAux.go` parser is a free, already-installed oracle for it. This is the AAD defect's exact shape, sitting unexercised. |
| **`aes-128-gcm`, `chacha20-poly1305`, `plain` frame crypto against Go** | **never run.** Only `aes-256-gcm`. | **YES.** The AAD defect was in `cloak_frame_obfuscate`; the key-length and nonce handling differ per method (`crypto.h:18-32`: "`CLOAK_AEAD_AES_128_GCM` only consumes the first 16 bytes of key"). A per-method divergence is invisible to every C↔C test. |
| **CDN × unordered** | unreachable — the C client refuses `cdn` (§2.2). | Not until 8b. Out of scope, say so. |
| **admin API × unordered** | **not covered at all** — `grep` for admin+unordered in the test tree returns nothing. In Go this combination is *reachable and nonsensical*: `cmd/ck-client/ck-client.go:165` forces `NumConn = 1` in the admin branch but leaves `authInfo.Unordered` alone, and `:191` then routes the admin API over `RouteUDP`. The C client refuses `admin && (num_conn != 1 \|\| singleplex)` (`client_stack.c:887`) but **has no opinion on `admin && udp`**. | An operator who leaves `"UDP": true` in a config and adds `-a`. Cheap to close: refuse it, or test it. **This is an unrecorded divergence either way** — Go accepts it and produces something broken; we accept it and produce something untested. |
| **multiple concurrent sessions** | one case: `test_admin_e2e.c:1148` (admin + proxy, two sessions). Nothing tests more than two, and nothing approaches `CLOAK_REGISTRY_MAX_SESSIONS`. | **YES — see §5.4.** This is a hard 256 ceiling with an O(n) scan, defended by a comment whose premise expired three modules ago. |
| **session resumption across a server restart** | **still unasserted**, exactly as module 7 handed it over. Every `restart` hit in the CLI tests is about supervisor policy or billing (`test_ck_client_cli.c:1810,2064,2266,2317`). The reconnect ladder is covered at library level only (`test_client_stack.c:1497-1517`). | **YES, and it is load-bearing:** `cmd/ck-client/main.c:41-47` justifies there being no sixth exit code *on the grounds that* a client that cannot connect retries forever. Nothing proves it does, through the binaries, across a real restart. Module 7 said whoever argues five suffice owes this test. |
| **many users under the SQLite manager at once** | `test_usermanager.c` has 19 cases and **none of them is a scale case**; the largest loop anywhere in the server tests is 100 (`test_adminapi.c:1678`). | **YES, and it is the one with a physical failure mode.** `2026-09-14-libcloak-server-usermanager-plan.md` D3 accepts, in writing, that "a genuinely slow or failing disk stalls the reactor". Nothing measures the stall. |
| **the rate limiter under real traffic** | 12 cases in `test_valve_rate.c`, all in-process, several simulated-clock. `test_real_connection_holds_its_rate` (`:461`) is the closest to real. Never through the binaries, never with several metered users competing. | **YES for an operator** — this is what a paid deployment sells. Low censorship relevance. |
| **long-running stability** | nothing. Every test in the tree is bounded in seconds. | **YES for an operator**, and it is the only way to see the leak classes ASan's exit scan cannot: an unbounded growth that never leaks (the replay cache is bounded — Go's is not, §5.6), a timer wheel that grows, `retired_dropped` counters. |

**Ranking for a plan.** The two configuration-matrix rows are first: they reuse an oracle that is
already built, already in the image, and already driven by an existing harness, and they cover the
component the spec itself calls highest-risk. The restart row is second because it discharges a
written debt. The session-cap row is second-and-a-half because it is a *fix*, not just a test.

---

## 5. What a fresh pair of eyes finds wrong with the port today

### 5.1 A divergence justification that is false about Go — the same failure mode module 9 named, in a different file

`libcloak-mux/include/cloak/stream.h:261-268`:

> `ORDERED` — `-1` for: a duplicate or already-delivered `frame->seq` … the
> duplicate-kills-the-stream behaviour is **a deliberate, documented improvement over Go (which has
> no error path there at all)** and `test_stream.c` pins it.

**Go has an error path there.** Copied verbatim from
`/Users/sam/Cloak/internal/multiplex/streamBuffer.go:79-81`:

```go
	if f.Seq < sb.nextRecvSeq {
		return false, fmt.Errorf("seq %v is smaller than nextRecvSeq %v", f.Seq, sb.nextRecvSeq)
	}
```

That error reaches `stream.go:72` → `session.go:255` → `switchboard.go:161-164`, where it is
`log.Error(err)` and the loop continues. So the true divergence is **"Go logs and continues, we
retire the stream"**, not "Go has nothing". The parenthetical is wrong, it has no `.go:` citation,
and it is the exact species module 9 ruled on: *"a comment that justifies a divergence from Go must
cite the Go file and symbol, and a reviewer must check it there."*

**And checking it turns up something bigger, which is why the rule exists.** Go's check covers only
`Seq < nextRecvSeq`. A duplicate of a seq that is **still pending in the heap** (`Seq >= nextRecvSeq`)
is pushed twice (`streamBuffer.go:86`). After the original is popped and delivered,
`nextRecvSeq` increments, the stale twin is now the strict minimum of a min-heap ordered by `Seq`,
and the drain loop's condition `sb.sh[0].Seq == sb.nextRecvSeq` (`:88`) **can never be true again.**

Consequences, read off those lines:

- **the stream delivers no further byte, ever** — a silent permanent wedge with no error and no
  close, so neither peer learns;
- **the heap grows without bound** — every subsequent frame for that stream is pushed and never
  popped.

Reachability: Cloak's sender never duplicates, so this needs an on-path attacker replaying one
captured record while `uniformSpread` has that stream's frames out of order — which is the normal
state with `NumConn > 1`. Our port detects it (`stream.c:386`, `heap_contains_seq`) and retires the
stream, which a redial recovers.

**This is a tenth candidate bug in the reference, found by reading, and it must be measured before
it is claimed.** It is cheap to measure: `test_go_interop.c` already interposes a man-in-the-middle
relay that flips one byte of a ServerHello (`:1381`), and `test_unordered_proof.c` already has a
duplicating middle box (`run_replay`, `MB_DUPLICATE1`). Duplicating a *pending* record against a
real `go-ck-client`/`go-ck-server` is those two machines joined. It simultaneously discharges the
false-comment defect, tests our ordered duplicate policy against a real Go peer for the first time,
and settles bug #10.

The existing replay case (`test_unordered_proof.c:2362`, `run_replay`) covers only the
*already-delivered* duplicate — it sends one datagram, replays it, then sends a second — so it
tests Go's `:79` branch shape and **not** the heap branch at all, and it is C↔C on both ends.

### 5.2 The Go oracle covers one browser and one cipher — see §4

Restated here because it is a *coverage* defect and not only an integration gap: the direct-TLS
client path is oracle-covered for `chrome` + `aes-gcm` only. `test_go_interop.c:68-73` is honest
about its limits ("no distribution of any kind … no real reordering … no CDN/WebSocket leg") but
does **not** mention that it pins one browser template and one AEAD. Two-thirds of the ClientHello
templates — the artefact the spec calls the highest-risk component — have never been shown to a
parser that is not ours.

### 5.3 Every `%` on a random draw in the shipped code is now clean — but Go's is not, and nobody wrote that down

`grep -rnE "% *[0-9A-Za-z_]+"` over `libcloak-*/src` and `cmd` finds exactly two modulos on a random
draw, and **both are the reduction step of a rejection sampler**: `random.c:33` inside
`cloak_random_below`, and `switchboard.c:70` inside its buffered-CSPRNG port of `common.RandInt`
(`switchboard.c:66`: `limit = 0x100000000ULL - (0x100000000ULL % n)`). The third,
`client_transport.c:45`, is the declared 8-byte draw whose bias is below 1e-18 and whose comment now
states the argument's scope. `replay_cache.c:51` is a hash reduction, not a draw. **The class is
closed in this tree.** (Verified by reading every hit, not by trusting the handoff.)

**But the class is open in the reference, at a site this port deliberately fixed, and the tree does
not say so.** Copied verbatim from `/Users/sam/Cloak/cmd/ck-client/ck-client.go:181`:

```go
			authInfo.MockDomain = localConfig.MockDomainList[int(randByte[0])%len(localConfig.MockDomainList)]
```

One byte, modulo a list of up to 17 — the seventh member of the distribution class, in Go, **on the
wire, in the SNI of every ClientHello**, exactly the defect module 8 found and fixed in our copy
(`client_stack.c:449`, `cloak_random_below`). Two things follow that nothing in the tree records:

1. **It is another reference bug** (candidate #11), unreported here and upstream.
2. **It makes our SNI distribution differ measurably from Go Cloak's.** Everywhere else this project
   fixed a bias it moved *toward* Go (`common.RandInt` is `crypto/rand.Int`,
   `internal/common/crypto.go:86-97` — unbiased). Here it moved *away*. If a censor's baseline model
   of "Cloak" is built from Go Cloak deployments, an unbiased SNI draw is itself a discriminator.
   That is probably still the right trade — the biased draw is the louder signal in absolute terms —
   but it is a trade nobody has written down, and **an unrecorded divergence is what this project
   has ruled against four times.**

Two smaller comment defects at the same site: `client_stack.c:417` attributes the pick to "Go's
`randomServerName` selection over its own list", but `internal/client/TLS.go:35` `randomServerName`
is the *random-domain generator* used only when `ServerName == "random"` (`TLS.go:127`); the list
pick is `ck-client.go:181`. And the granularity claim at `:419-424` is **correct** — Go picks inside
`seshMaker` (`ck-client.go:177-181`), i.e. per session — but is uncited, so nobody can check it
without doing what this paragraph just did.

**The size of that debt, measured.** Across `libcloak-*/src` and `cmd/*/main.c`, **168 lines assert
something about Go's behaviour** (`Go does` / `Go's` / `matching Go` / `mirrors Go` / `unlike Go` /
`Go never` / `Go always` / `Go sets` / `Go uses`) **without a `.go:` citation on that line.** The
whole tree contains **60 distinct `file.go:line` citations.** `libcloak-client` is the thinnest: 46
mentions of Go, 7 citations. `cmd/` is worse: 23 and 1. Module 10 cannot check 168 claims. It can
check the ones that justify a **divergence**, which is the narrow rule module 9 actually wrote.

### 5.4 The session registry caps the whole server at 256, defended by a comment whose premise expired in module 4

`libcloak-server/include/cloak/registry.h:57-60`:

> `CLOAK_REGISTRY_MAX_SESSIONS` is **ample for this stage: there is no user manager yet** to spread
> sessions across, so this is the entire server's session budget, not a per-user one.
> `#define CLOAK_REGISTRY_MAX_SESSIONS 256`

There has been a user manager since module 4 (`libcloak-server/src/usermanager.c`, SQLite). The
justification is stale, the number was never revisited, and it is **the entire server's concurrent
session budget** — not per user. Go has no equivalent cap (`sesh.streams` and the server's session
map are maps).

Three distinct consequences:

- **Capacity.** One Cloak session per client instance means **256 simultaneous clients, server-wide**.
  A deployment with 300 users is a hard refusal (`:242`: "this is a RESOURCE LIMIT"), and it fails
  at the least visible moment.
- **Cost.** `registry.h:122-125` is `struct cloak_registry_entry *entries[256]` with linear scans
  (`:331` names them), so lookup is O(n) per connection — fine at 256, which is precisely the
  argument that stops anyone raising it.
- **Nothing tests it.** No test in the tree opens anything approaching 256 sessions.

**Fixing the number without fixing the scan is a trap**, and that is the interesting part for a plan:
raising the cap to a production figure makes the linear scan the new defect. This is a real
engineering task, not a constant bump.

### 5.5 The replay cache is smaller than its own threat model, and its header's argument carves out the attacker who matters

`libcloak-server/include/cloak/replay_cache.h:12-25` describes a direct-mapped table and argues:

> an attacker deliberately flooding collisions can at most cause some replay-window entries to be
> forgotten early, which **only weakens (never strengthens) an attacker's ability to replay a key
> they don't already possess a valid, not-yet-expired ciphertext for**

The carve-out in that sentence is the GFW's actual active-probing attack: a censor **does** possess a
captured, not-yet-expired ciphertext — it watched a real client connect — and replaying it is how it
confirms the host is Cloak rather than a web server. The numbers:

- capacity **1024** (`server_stack.h:176`), age limit **12 h**
  (`server_auth.h:22`), timestamp tolerance **180 s** (`server_auth.h:12`);
- the slot is `fnv1a(key,32) % capacity` (`replay_cache.c:51`) — **an unkeyed, non-cryptographic hash
  over a fully attacker-chosen 32-byte value**, so finding a second 32-byte string landing in a
  chosen slot is ~1024 offline trials;
- **the cache is written before authentication**, in both implementations: `dispatcher.c:280-281`
  ("`cloak_server_check_replay` against the RAW, not-yet-authenticated `ch.random` — BEFORE any
  decryption") and `:595`; Go the same at `internal/server/auth.go:76`, before
  `decryptClientInfo` at `:81`.

So an unauthenticated prober evicts a *specific* captured handshake's entry with **one packet**
(collide its slot) or the whole table with **1024** — and it has 180 s to do it in. And with no
attacker at all, **any server doing more than 1024 handshakes per 12 hours is evicting continuously**;
protection then rests entirely on the 180-second window, degrading with load.

Go does not have the eviction hole (exact map). Go has the opposite one: `state.go:214-225`'s
cleaner sleeps `replayCacheAgeLimit` = **12 hours** between passes, so an unauthenticated flood grows
`UsedRandom` unboundedly for up to 12 hours — a memory DoS from packets that never authenticate
(candidate reference bug #12). **Bounding the cache was the right call; 1024 is the wrong number,
and the header's own argument is what hid it.**

### 5.6 Smaller things, listed without ceremony

- `libcloak-client/src/udp_piper.c:359` describes Go's buggy delete-by-key as the model without
  noting we are immune (§2.7).
- The C client has **no opinion on `admin && udp`** (§4), where it has opinions on
  `admin && num_conn != 1` and `udp && singleplex`.
- `cmd/ck-client/main.c` and `cmd/ck-server/main.c` still duplicate `read_whole_file` and `ck_err`
  verbatim; module 7 said a third binary makes it worth sharing. There is no third binary. **Leave
  it**, and say so, rather than re-litigating.

---

## 6. The actual risk profile, ranked by consequence

### Tier 1 — silently corrupts or silently loses data

1. **The ordered-mode duplicate divergence, in whichever direction it is wrong.** We retire a stream
   where Go continues; Go wedges one permanently where we retire. Nobody has run either against the
   other (§5.1). A wrongly-retired stream is a dropped TCP connection inside the tunnel, which a
   proxy reports as a network failure and a user reports as "it's flaky".
2. **Untested encryption methods.** `aes-128-gcm` uses 16 of the 32 key bytes (`crypto.h:18-20`);
   `plain` authenticates nothing. A per-method divergence from Go is exactly the AAD defect, and the
   AAD defect was silent — correct handshake, correct key, frames dropped.
3. **`keep_alive_sec` consumed by nobody (§2.5).** An operator who configures `KeepAlive` believes
   dead peers get reaped. They do not. The failure is a slow accumulation of half-open sessions
   against the 256-session cap in §5.4 — the two compose badly.

### Tier 2 — a distinguisher a censor could use

4. **The replay cache's effective capacity (§5.5).** This is the highest-consequence security item
   in the report: it is the mechanism that defeats active probing, it is bypassable for one packet by
   an unauthenticated attacker, and at load it decays on its own. A successful probe tells the censor
   the host is Cloak, which is the outcome the entire ClientHello-mimicry design exists to prevent.
5. **Firefox and Safari ClientHello templates, never checked against a foreign parser (§5.2).** A
   wrong offset table is not a crash — it is a ClientHello that a DPI box can tell from the browser
   it claims to be. The spec calls this the highest-risk component; it is the one with the thinnest
   oracle coverage.
6. **The SNI distribution now differs from Go's, deliberately and unrecorded (§5.3).** Small, and
   probably the right trade, but it is the class this project has paid for six times.
7. **`cloak_ws_frame_mask`'s resumed `pos` (§3.3 #8).** A chunked send that restarts `pos` produces
   frames whose first chunk decodes and whose rest is garbage — visible to the CDN, not just to us.

### Tier 3 — fails loudly

8. **The 256-session cap (§5.4).** A refused session is loud; the deployment simply stops growing.
   Loud, but it stops an operator cold at a number nobody chose on purpose.
9. **SQLite stalling the reactor** under many users (`usermanager` plan D3). Accepted in writing,
   never measured. Loud (everything pauses), diagnosable.
10. **`singleplex + udp` refused by name (§2.3).** A named refusal at startup — the best kind of
    missing feature.
11. **CDN refused at open (§2.2).** Same.

**One-line summary of the profile:** *the things that would actually hurt in production are a replay
cache that is a tenth the size of its own threat model, two ClientHello templates that have never
met a foreign parser, and a duplicate-frame policy that diverges from Go on an argument that is
false. None of them is what "integration and fuzzing" sounds like it is about.*

---

## 7. How to test it: the remaining oracles, and what has none

The governing lesson is the project's own: **a round-trip test cannot see a self-consistent error.**
The corollary module 8 added is sharper: **an oracle that checks that frames decode cannot see how
long they are.** So the design question for every property below is *which foreign thing decides it*.

### Oracles that exist and are already installed

| oracle | in the image | decides |
|---|---|---|
| `go-ck-client` / `go-ck-server` v2.12.0 | yes (`Dockerfile.dev` `gobuild` stage → `/usr/local/bin`) | ClientHello templates (all three), auth payload, frame codec (all four AEADs), ordered and unordered semantics, duplicate policy, the stream wedge of §5.1 |
| `gorilla/websocket` v1.5.3 | yes (module cache, `GOPROXY=off`) | RFC 6455 framing, upgrade validation |
| the Linux kernel | yes | `SO_KEEPALIVE`/`TCP_KEEPIDLE` via `getsockopt`; socket type via `SO_TYPE` (module 9 already switched a test to this); fd census via `/proc/self/fd` |
| SQLite, read back out of band | yes | metering, already used at `test_ck_client_cli.c:1820-1826` |
| libFuzzer + ASan/UBSan | **after the image change** | memory safety over any byte buffer |
| RFC vectors | free | base64 (RFC 4648), `Sec-WebSocket-Accept` (RFC 6455 §1.3), Salsa20/ChaCha20 (already used in `test_salsa20.c`, `test_aead.c`) |

**The unused capacity is the important line in that table.** `go-ck-client` already accepts
`BrowserSig` and `EncryptionMethod` as ordinary config strings. Covering 3 browsers × 4 AEADs is
*parameterising an existing harness*, not building one — and it is the single highest ratio of
coverage gained to lines written anywhere in this report.

### Properties with **no** oracle — these must be pinned white-box, and the plan must say so at each site

1. **Distributions.** Padding length, SNI choice, connection pick. Go agrees on *semantics* and says
   nothing about *shape*; and on SNI (§5.3) Go is now the wrong answer. Method: chi-square +
   lag-1 pair transition + **linear complexity**, as `test_unordered_proof.c:2863` already does. Note
   the standing caveat: the linear-complexity assertion sees F2-linear structure only.
2. **The replay cache's effective capacity (§5.5).** Go's design is different, so Go cannot
   adjudicate. Method: white-box — insert *k* randoms, then assert a target key inserted before them
   is still recognised as a replay; the test that fails today at k≈1024 is the measurement that
   justifies the new number. And a second test that computes an FNV-1a slot collision and shows one
   packet evicts a chosen entry, because *that* is the property, not the capacity.
3. **`keep_alive_sec`'s effect.** The kernel is the oracle, via `getsockopt`. There is no Go
   behaviour to match — Go's is also `SetKeepAlive` on its own sockets — so it is white-box either
   way.
4. **The 256-session cap and its scan cost (§5.4).** Nothing foreign has an opinion. Method: open
   N sessions, assert the (N+1)th behaves as designed, and **measure** the per-connection lookup at
   the new N so the scan is a number and not a hope.
5. **Long-running stability.** No oracle at all, and ASan's exit scan cannot see bounded-but-growing
   state. Method: a soak that asserts *derivatives* — fd count, RSS, `cloak_udp_piper_dropped_datagrams`,
   registry occupancy — are flat across a fixed number of session cycles, not that they are small.
6. **Reconnect across a restart (§4).** Semi-oracled: `go-ck-server` can be the thing that restarts,
   which makes the C client's ladder observable against a foreign peer. Prefer that over a C-only
   restart, for the usual reason.
7. **The fuzz corpus itself.** Its oracle is ASan/UBSan and a non-zero exit — nothing else. Which is
   why the corpus must be committed and replayed (875 ms, measured) rather than regenerated: a
   campaign that finds nothing today is worthless as a regression unless its inputs are kept.

### One rule worth carrying in, stated once

Every negative control this project has written has earned its place (`test_go_interop.c:33-45`
says why: "A positive-only interoperability test proves nothing"). **Each new oracle case in module
10 needs its negative twin**, and for the matrix in §4 the cheapest twins are: a deliberately wrong
Firefox offset, and a client configured for `aes-128-gcm` talking to a server configured for
`aes-256-gcm`.

---

## 8. How big is this, in what order, and should it be one module or two

### 8.1 It should be **two**, and the argument is not aesthetic

**Integration and fuzzing do not belong together here**, for four concrete reasons:

1. **They have different toolchains.** Fuzzing needs a change to `Dockerfile.dev` (+264 MB, a second
   compiler) and a second CMake configuration. Integration needs neither. Coupling them means an
   integration task cannot start until an image rebuild lands.
2. **They have different budgets.** Every integration case costs ASan seconds against a margin that
   is now **1.91×** (§2.1). Fuzzing costs **875 ms** for a corpus replay and nothing else in CI.
3. **They have different expected yields, and this was measured.** 11.3M executions found zero
   crashes (§3.2). Integration's first two rows (§4) exercise 22 configuration combinations that
   have never met foreign code, in the component the spec calls highest-risk. If they are one module
   and the schedule slips, the wrong half survives.
4. **One of them has a prerequisite.** The CLI-test split (§2.1) must land before any integration
   case is added. Fuzzing has no such ordering constraint and could be built in parallel by someone
   else entirely.

**Proposal: 10a = fuzzing (small, self-contained, low risk). 10b = integration and the fixes (large,
risky, ordered).** If they must be one module, 10a's tasks go *last*, not first, because 10b's
budget task gates everything.

### 8.2 Module 10a — fuzzing

| file | new/changed | est. lines |
|---|---|---|
| `Dockerfile.dev` | `clang` + `libclang-rt-14-dev` in the `base` stage, with the measured 45.4 MB / 264 MB and the `libclang_rt.fuzzer` link error in the comment, so nobody installs `clang` alone again | 15 |
| `CMakeLists.txt` | `CLOAK_FUZZ` option: requires clang, adds `-fsanitize=fuzzer-no-link,address,undefined` to the libraries, guards the whole `fuzz/` subdirectory | 60 |
| `fuzz/CMakeLists.txt` | one `add_executable` per target, `-fsanitize=fuzzer` at link | 60 |
| `fuzz/fuzz_firstpacket.c` | target #2, **driving the `want()` chunking from the input** | 80 |
| `fuzz/fuzz_clienthello.c` | target #3 | 40 |
| `fuzz/fuzz_ws.c` | targets #4 and #5 | 60 |
| `fuzz/fuzz_session.c` | target #1 — `CLOAK_AEAD_NONE` + zero key, mirroring `session_fuzz.go` | 120 |
| `fuzz/fuzz_client_reply.c` | target #7 — the client-side reply reader | 120 |
| `fuzz/corpus/<target>/` | committed seeds: real captured ClientHellos from `test_clienthello.c`, real upgrade requests from `test_ws_handshake.c`, plus campaign output | data |
| `fuzz/tests/test_fuzz_corpus.c` or a ctest wrapper | replays every committed corpus under ASan/UBSan, 75 → 76 | 80 |
| `docs/` | how to run a campaign; that `gcc` cannot | doc |

**~600 lines, 6 targets, 4–5 tasks.** Riskiest part: nothing, and that is the point — the toolchain
question that would have made it risky has already been answered by building it.

### 8.3 Module 10b — integration and the fixes

| task | files | est. lines | note |
|---|---|---|---|
| **0. Split the CLI tests** (§2.1) | `cmd/ck-client/tests/` +1 file +1 `add_test`, shared harness extracted | 150 moved, ~80 new | **Gates every other task.** Measure per-case child counts first. 75 → 76 |
| **1. The configuration matrix against Go** (§4, §5.2) | `test_go_interop.c` parameterised, or a new `test_go_matrix.c` | 400 | 3 browsers × 4 AEADs + 2 negative controls. **Highest value per line in the whole module.** |
| **2. The duplicate/wedge question against Go** (§5.1) | `test_go_interop.c` MITM + `test_unordered_proof.c`'s duplicating box | 250 | Settles reference bug #10, fixes a false comment, first foreign test of our duplicate policy |
| **3. Reconnect across a restart, through the binaries** (§4) | `cmd/ck-client/tests/` (new split file) | 200 | Discharges module 7's debt on the sixth exit code |
| **4. Replay cache: size it to its threat model** (§5.5) | `replay_cache.h/.c`, `server_stack.h`, `test_replay_cache.c` | 150 + 200 test | Includes the FNV-collision eviction test. **Rewrite the header's carve-out sentence.** |
| **5. Session cap: raise it and fix the scan** (§5.4) | `registry.h/.c`, `test_registry.c` | 200 + 200 test | **The riskiest task — see below** |
| **6. `keep_alive_sec`** (§2.5) | `client_stack.c`, `server_stack.c` or `dial.c`/`listener.c`, tests | 60 + 120 test | Two `setsockopt`s and a `getsockopt` assertion |
| **7. Many users + the rate limiter under real traffic** (§4) | `test_usermanager.c`, a binaries-level case | 300 | Measures the D3 stall instead of accepting it in prose |
| **8. A bounded soak** (§4, §7.5) | new test, `slow` label | 250 | Asserts derivatives are flat, not that values are small |
| **9. Divergence-comment audit** (§5.3) | `stream.h`, `client_stack.c`, `udp_piper.c`, `registry.h`, `replay_cache.h` | doc only | **Only the comments that justify a divergence**, not all 168 |

**~1,200 lines of implementation and ~1,700 of tests, 9–10 tasks, 75 → ~85 tests.**

### 8.4 The riskiest part, named

**Task 5, the session cap.** Not because the constant is hard, but because §5.4's three properties
are coupled: the array is fixed-size *because* entries are held by address and a realloc would be a
use-after-free under live callback userdata (`registry.h:45-50`, and it is right about that); the
scan is linear *because* the array is 256; and the 256 is defended by a premise that expired. Change
one and the other two become wrong. It is a data-structure change in the object that owns every live
session's callback userdata, on a single-threaded reactor with no locks to hide behind — which is the
same shape as every module's worst bug, per module 7's own note.

**Second riskiest: Task 1**, for the opposite reason. It is mechanically easy and will be tempting to
scope down to "add firefox". Twenty-two untested combinations against a free oracle is the finding;
running two of them is not.

**And the standing budget hazard:** Task 0 buys about 41 s of headroom (§2.1), Tasks 1, 2, 3 and 7
all add forked-binary cases, and `test_ck_server_cli` is next in line at 41 s. **Measure the ASan
wall clock after every one of those tasks, not at the end of the module.** The margin has already
fallen from 2.7× (module 7) to 2.3× to 2.01× to **1.91×** measured today, and nobody noticed a step
until the module after it.

---

## What could not be determined by scouting

- **Whether Go's ordered-mode stream really wedges on a pending duplicate (§5.1).** Read off
  `streamBuffer.go:79-94` and `switchboard.go:161-164`; **not reproduced.** It is candidate bug #10
  and must not be written down as a finding until Task 2 measures it at the binaries.
- **Whether `RouteUDP`'s delete-by-key eviction fires in practice (§2.7).** The sequence is legible
  in `piper.go:73-77` and `:83-91`; the race window was not opened.
- **Whether the SNI modulo in `ck-client.go:181` is observable in aggregate at realistic handshake
  volumes.** The bias is arithmetic (up to 6.7 % at 15 entries); whether a censor collects enough
  handshakes per host to see it was not modelled.
- **Where exactly `test_ck_client_cli`'s 62 s is spent, case by case.** Only the file total was
  measured. Task 0 must measure per-case before choosing the cut.
- **Whether `clang` 14's UBSan finds anything the gcc build does not.** The clang build was compiled
  and the fuzz targets run, but the full 75-test suite was never executed under a clang-built
  ASan/UBSan. Cheap, and worth one run in Task 0 of 10a.
