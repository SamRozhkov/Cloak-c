# libcloak-server: The Proxy Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carry traffic. A stream accepted on an authenticated session is dialed through to its configured upstream proxy and spliced to it, and when the session ends every relay it owns is stopped first. After this plan the server is functionally complete for the direct-TLS, ordered, bypass-authorised case — a real Shadowsocks client could pass bytes through it end to end.

**Architecture:** One `cloak_proxy_t` supplies the wiring the dispatcher deliberately left to a caller. It provides `cloak_dispatch_prepare_session_cb` and `cloak_dispatch_attached_cb` for the dispatcher's config, installs its own `on_new_stream`/`on_stream_data`/`on_writable` into each new session's `cloak_session_config_t`, allocates one context per session and one per stream, and routes each notification to the right `cloak_stream_relay_t`. It owns no socket of its own: the dial's fd becomes the relay's the moment the relay starts. Teardown is the part that matters — `cloak_session_broken_cb` frees every still-active stream immediately after `on_broken` returns, so the registry's broken callback is the only window in which a relay may be stopped, and `cloak_proxy_t` therefore supplies that callback too rather than hanging cleanup off anything of its own.

**Tech Stack:** C11, CMake, CTest with the project's existing assert-based test framework (`libcloak-common/tests/test_framework.h`).

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` — §7 step 3's second half ("start relaying to the configured `ProxyBook` target"), and §6's data-plane model, which `cloak_stream_relay_t` already implements and which nothing has consumed until now.

**Reference:** `/Users/sam/Cloak/internal/server/dispatcher.go` — the `serveSession` half of `dispatchConnection` that the previous branch deliberately did not port.

## Global Constraints

- Language: C11. Project code must compile `-Wall -Wextra` clean — zero warnings.
- Platform: Linux only. POSIX APIs via `#define _POSIX_C_SOURCE 200809L` as the **first line** of any `.c` file that needs them.
- Naming: public symbols prefixed `cloak_`; headers under `libcloak-server/include/cloak/` with `CLOAK_<NAME>_H` include guards; doc comments in the established style of `cloak/registry.h` and `cloak/stream_relay.h` — say what the contract is and *why*, not what the code does.
- Every constructor initializes its own struct fully **before** validating its other arguments, so a failed init still leaves a struct safe to pass to its destroy. Five tasks in this project got that ordering wrong and it crashed every time.
- Every destroy is idempotent and safe on a zeroed struct.
- Existing tests are the regression net. Task 1 moves test helpers between files and must leave every existing test's *behaviour* identical; Tasks 2-4 must leave every existing test file untouched.
- **Append to `libcloak-server/CMakeLists.txt` and `libcloak-server/tests/CMakeLists.txt`. Never rewrite either file** — `tests/CMakeLists.txt` carries a load-bearing ASan/LD_PRELOAD block at lines 46-126 that must survive intact.
- Test registration convention, copied from the existing entries verbatim:
  ```cmake
  add_executable(test_X test_X.c)
  target_include_directories(test_X PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
  target_link_libraries(test_X PRIVATE cloak-server)
  add_test(NAME test_X COMMAND test_X)
  set_tests_properties(test_X PROPERTIES TIMEOUT 60)
  ```
- **Every wait in a test is bounded.** Use the `pump_until(reactor, done_fn, ctx, max_iters, per_iter_ms)` idiom that already exists in the dispatcher tests — never an unbounded loop, never a blocking `read()` on a peer socket. Three tests in this project have hung or flaked in CI; every one was found only by repetition, and two were blocking peer reads.
- Build and test. **Note the `-w` path**: `-w /src` silently builds the main checkout instead of the worktree, which has bitten this project before.
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/libcloak-proxy cloak-c-dev bash -c \
    'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
  ```
- Sanitizer run, required for every task in this plan (all four are lifetime-sensitive):
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/libcloak-proxy cloak-c-dev bash -c \
    'cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
       -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
       -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
       -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" && \
     cmake --build build-asan -j8 && ctest --test-dir build-asan --output-on-failure'
  ```
- Test counts: **36 before this plan**, 36 after Task 1 (a refactor adds none), 37 after Task 2, 38 after Task 3, 39 after Task 4.

## The five obligations this plan inherits

Earlier branches' reviews recorded these rather than let them be rediscovered. They are not background reading — each one lands in a named task.

1. **A relay MUST be stopped before its session tears down.** `cloak_session_broken_cb`'s contract (`cloak/session.h`) is that immediately after `on_broken` returns, every still-active stream is destroyed and freed. A `cloak_stream_relay_t` holds `sr->stream` and `sr->sesh` as raw pointers it can never validate — it has no third notification through which it could learn the session died. Both `stream_relay.h` and `registry.h` state this as a MUST, from both sides, and `registry.h` calls it "the single most likely mistake for a caller wiring up all four session callbacks to make". **This is Task 3, and it is where this module is either correct or not.**
2. **`cloak_stream_relay_start` can fail for a transient reason.** It rejects a start when `cloak_session_send_min_conn_free(sesh)` is currently smaller than one worst-case frame. That measures the pool's *current* free space, not its capacity, so a pool momentarily busy with another stream's traffic refuses a relay whose configuration is perfectly fine. Treat a rejection as retryable rather than fatal. (Task 2.)
3. **Per-relay read budgets do not coordinate across relays.** Each relay independently budgets against the same `cloak_session_send_min_conn_free`, so N concurrent relays can each believe they have room that only one of them actually has. Strictly better than what it replaced and safe for one relay; the next thing that needs attention when one session carries many busy streams. **Documented in Task 2, deliberately not solved here** — see "What comes after this plan".
4. **Nothing yet proves bytes already in the socket survive the hand-off.** `conn_handoff` does `cloak_reactor_remove_fd` then `cloak_session_add_conn`, and the re-registration re-arms the edge and picks up whatever the kernel buffered. Reasoned about on paper across three branches, never asserted, because until now nothing consumed session bytes. (Task 4.)

   **Corrected before Task 4 was dispatched.** Three branches, this plan's first draft included, described this as "a client that pipelines its first frame immediately behind its ClientHello". That client cannot exist: the session key is generated by the SERVER and delivered inside the reply, so a client has nothing to encrypt a frame with until it has read that reply (`extract_session_key_from_reply` in `client_harness.h` is where it learns it). The real window is narrower and still real -- between the server finishing its reply write and `cloak_session_add_conn` registering the fd, which are NOT in the same reactor turn whenever the reply write takes the WRITABLE path. A fast client's first frame lands in the socket buffer inside that window. Task 4 tests that window, not the impossible one.
5. **`ci.unordered` has nowhere to go.** `cloak_server_auth_first_packet` parses the flag into `cloak_server_clientinfo_t.unordered` and every caller ignores it. `cloak_session_config_t` has no such field and nothing in `libcloak-mux` implements unordered delivery. Silently ignoring an attacker-visible flag is itself a fingerprint. (Task 2 decides it deliberately.)

---

### Task 1: Extract the duplicated client harness from the dispatcher tests

**Why this comes first:** `test_dispatcher_auth.c` (1020 lines) and `test_dispatcher_limits.c` (1451 lines) each carry a verbatim copy of the same ~250 lines of handshake-building helpers; `test_dispatcher_limits.c:33-38` documents the duplication as a deliberate convention. This plan adds three more test files that all need the same helpers. Three copies is a convention; six is a liability — and every one of this plan's tests needs a *client-side* `cloak_session_t` on top of that handshake, which is another block that would be copied three more times. Extract once, here, with the existing suite as the verifier.

**Files:**
- Create: `libcloak-server/tests/client_harness.h`
- Modify: `libcloak-server/tests/test_dispatcher_auth.c`, `libcloak-server/tests/test_dispatcher_limits.c`
- Modify: `libcloak-server/tests/CMakeLists.txt` (only if a new include directory is needed; the test files live in the same directory, so `#include "client_harness.h"` should resolve without any CMake change — confirm and say which)

**Interfaces:**
- Consumes: `cloak/base64.h`, `cloak/clienthello.h`, `cloak/crypto.h`, `cloak/reactor.h`, `cloak/server_auth.h`, `cloak/session.h`, `cloak/stream.h`, `test_framework.h`.
- Produces: the header below. Tasks 2, 3 and 4 all include it.

**What to extract.** These helpers are byte-identical (or trivially so) between the two existing files; move them, do not rewrite them:

- `pump_done_fn` / `pump_until` — the bounded reactor pump.
- `cover_site_t`, `cover_on_readable`, `cover_on_accept`, `struct len_wait`, `cover_has_len` — the fake cover site.
- `client_connect(port)`, `client_local_port(fd)`.
- `build_auth_payload(...)`, `build_client_record(...)`.
- `read_reply(...)`, `extract_session_key_from_reply(...)`.

Everything is `static` in a header included by exactly one translation unit per test binary, which is how this project's `test_framework.h` already works — a helper that ends up unused in one includer must not produce an `-Wunused-function` warning, so mark each one `static inline` (a `static inline` function that is never called is not diagnosed; a plain `static` one is). Verify that claim by building, not by asserting it.

**What to add** (new, not extracted — this is what Tasks 2-4 actually need):

```c
/* A fully established CLIENT side of a Cloak session, for tests that need
 * to pass real traffic rather than only complete a handshake. Wraps what
 * every such test would otherwise repeat: connect, send a ClientHello
 * built by build_client_record, read the reply, recover the session key
 * from it, build a matching obfuscator, and bring up a client-side
 * cloak_session_t over the same socket.
 *
 * The client session runs on the SAME reactor as the server under test --
 * one pump_until loop drives both ends, exactly as the existing tests
 * already drive their fake cover site. */
typedef struct {
    cloak_session_t sesh;
    int sesh_ready;
    int fd;                 /* owned by sesh once client_session_open returns 0 */
    uint8_t session_key[CLOAK_AEAD_KEY_LEN];
    int broken;             /* set by the harness's own on_broken */
} client_session_t;

/* port: the dispatcher's front listener port. server_pub / uid /
 * proxy_method / session_id / unordered are passed straight through to
 * build_client_record. cfg supplies the mux parameters; its obfuscator,
 * on_broken and on_broken_userdata are overwritten by this call.
 *
 * Pumps r internally (bounded) to complete the handshake. Returns 0 on
 * success with cs fully live, -1 otherwise with cs safe to pass to
 * client_session_close. */
static inline int client_session_open(client_session_t *cs, cloak_reactor_t *r, int port,
                                      const uint8_t server_pub[CLOAK_X25519_KEY_LEN],
                                      const uint8_t uid[CLOAK_UID_LEN],
                                      const char *proxy_method, uint32_t session_id,
                                      int unordered, cloak_session_config_t *cfg);

static inline void client_session_close(client_session_t *cs);
```

`client_session_open` does exactly what `test_valid_handshake_attaches` already does through `extract_session_key_from_reply`, and then: builds a `cloak_obfuscator_t` from the recovered key with the same AEAD method the record requested, fills the rest of `*cfg`, calls `cloak_session_init` and `cloak_session_add_conn(&cs->sesh, cs->fd)`. **Read `test_dispatcher_auth.c:511-560` and `extract_session_key_from_reply` and copy their exact sequence** rather than reconstructing it — the key derivation and the reply layout are the two places this would silently go wrong, and a session built with the wrong key establishes cleanly and then fails every frame with no error anywhere.

- [ ] **Step 1: Create `client_harness.h` by moving the helpers**

Move, do not retype. Keep each helper's existing doc comment with it; where a comment says "copied verbatim from ..." (as `test_dispatcher_limits.c:33-38` does), replace it with a statement of what the header now is.

- [ ] **Step 2: Delete the moved copies from both test files and add the include**

- [ ] **Step 3: Build and run the full suite — 36 tests, all passing, in both the Debug and the ASan build**

The whole verification of this step is that the existing suite is unchanged and still green. If any test needed a behavioural change to keep passing, stop and report it: that means the two copies were not actually identical, which is a finding about the existing tests, not a thing to paper over.

- [ ] **Step 4: Add `client_session_open` / `client_session_close`**

Nothing consumes them yet. Prove them with a `-Wall -Wextra` clean build; Task 2's first test is their real verification.

- [ ] **Step 5: Commit** — `git commit -m "test: extract the shared dispatcher client harness"`

---

### Task 2: `cloak_proxy_t` — dial the upstream and splice the stream

**Files:**
- Create: `libcloak-server/include/cloak/proxy.h`
- Create: `libcloak-server/src/proxy.c`
- Create: `libcloak-server/tests/test_proxy_stream.c`
- Modify: `libcloak-server/CMakeLists.txt` (append `src/proxy.c` to the `cloak-server` source list), `libcloak-server/tests/CMakeLists.txt` (append the test)

**Interfaces:**
- Consumes: `cloak_dispatch_prepare_session_cb`, `cloak_dispatch_attached_cb`, `cloak_dispatcher_config_t` (`cloak/dispatcher.h`); `cloak_server_lookup_proxy`, `cloak_addr_t` (`cloak/server.h`, `cloak/net.h`); `cloak_session_config_t`'s `on_new_stream`/`on_stream_data`/`on_writable`, `cloak_session_release_stream`, `cloak_session_close_stream` (`cloak/session.h`); `cloak_stream_relay_start/stop/notify_stream_data/notify_writable` (`cloak/stream_relay.h`); `cloak_dial_start`, `cloak_dial_cancel` (`cloak/net.h`); `cloak_reactor_timer_*` (`cloak/reactor.h`).
- Produces: `cloak_proxy_t`, `cloak_proxy_config_t`, `cloak_proxy_init`, `cloak_proxy_destroy`, `cloak_proxy_prepare_session`, `cloak_proxy_attached`, `cloak_proxy_session_count`, `cloak_proxy_stream_count`. Task 3 adds `cloak_proxy_registry_broken`; Task 4 consumes all of them.

**The shape.** Both structs are heap-allocated and never move — their addresses are reactor and session callback userdata:

```c
/* One accepted stream, being connected to or spliced with its upstream. */
typedef struct cloak_proxy_stream {
    struct cloak_proxy_session *ps;
    cloak_stream_t *stream;         /* owned by the session; released by us */

    cloak_dial_t dial;              /* live only while dialing != 0 */
    int dialing;

    cloak_stream_relay_t relay;     /* live only while relaying != 0 */
    int relaying;

    /* Obligation 2: a transient cloak_stream_relay_start rejection. */
    cloak_timer_id_t retry_timer;
    int fd_pending;                 /* the connected fd, held across a retry; -1 otherwise */
    unsigned retries;

    struct cloak_proxy_stream *prev, *next;
} cloak_proxy_stream_t;

/* One authenticated session's proxy state. Allocated in prepare_session,
 * freed once the registry's broken callback has let us stop every relay. */
typedef struct cloak_proxy_session {
    cloak_proxy_t *p;
    cloak_session_t *sesh;          /* NULL until attached; never dereferenced after broken */
    const cloak_addr_t *upstream;   /* resolved once at prepare; owned by cloak_server_t */
    cloak_proxy_stream_t *streams;
    size_t stream_count;
    struct cloak_proxy_session *prev, *next;
} cloak_proxy_session_t;

typedef struct {
    cloak_reactor_t *reactor;       /* borrowed; must outlive the proxy */
    cloak_server_t *srv;            /* borrowed; supplies the ProxyBook */
    size_t relay_buf_cap;           /* 0 -> CLOAK_PROXY_DEFAULT_RELAY_BUF_CAP */
    uint64_t dial_timeout_ms;       /* 0 -> CLOAK_PROXY_DEFAULT_DIAL_TIMEOUT_MS */
    uint64_t retry_delay_ms;        /* 0 -> CLOAK_PROXY_DEFAULT_RETRY_DELAY_MS */
    unsigned max_retries;           /* 0 -> CLOAK_PROXY_DEFAULT_MAX_RETRIES */
} cloak_proxy_config_t;
```

Pick the four defaults and give each one a comment saying what would go wrong with a much larger or much smaller value; `cloak/dispatcher.h`'s own `CLOAK_DISPATCHER_DEFAULT_*` block is the model for how much justification a constant carries in this project. `relay_buf_cap` and `dial_timeout_ms` have direct dispatcher analogues to match.

**The flows, each with the reason it is shaped that way:**

1. **`cloak_proxy_prepare_session`** (a `cloak_dispatch_prepare_session_cb`, installed as `dcfg.prepare_session` with the proxy as `prepare_session_userdata`):
   - **Obligation 5 lands here.** If `info->unordered` is set, return -1: the connection is redirected exactly as if authentication had failed. Go treats `Unordered` as a session-level property fixed at creation, so a create-path check is the complete check — an additional connection joining an already-ordered session never reaches this callback and its own flag is meaningless. Comment it: a client that asked for UDP against a server with no UDP data path is better served by a redirect (it learns nothing and falls back) than by a stream that would silently mangle its datagrams. Nothing about this may be left implicit; a reader must be able to find the decision without reading `server_auth.c`.
   - Resolve the upstream once: `cloak_server_lookup_proxy(p->srv, info->proxy_method)`. The dispatcher already rejected an unknown proxy method before calling this, so NULL here is a programming error rather than an attacker's doing — but return -1 rather than dereferencing it, and say in a comment which of the two it is.
   - **If `upstream->socktype != SOCK_STREAM`, return -1.** A ProxyBook entry declared `udp` resolves to `SOCK_DGRAM`, and `cloak_stream_relay_t` splices a stream with a *stream* socket. This is out of scope (module 9), and redirecting is the honest response; a comment must say so rather than letting a future reader think datagram upstreams work.
   - Allocate the `cloak_proxy_session_t`, link it onto `p->sessions`, and install `on_new_stream`/`on_stream_data`/`on_writable` into `*config` with it as all three userdata values. Return -1 on allocation failure (the dispatcher redirects, nothing is left in the registry).
   - **MUST NOT** touch `config->on_broken` or `config->on_broken_userdata` — `cloak_server_registry_get_or_create` overwrites both unconditionally and anything written here is discarded. `cloak/dispatcher.h` states this; restate it in `proxy.h`.
   - **MUST NOT** call `cloak_dispatcher_destroy` or anything that could free the in-flight connection: this fires from deep inside that connection's own dispatch call chain. Read `cloak_dispatch_prepare_session_cb`'s "CALLING CONTEXT" paragraph in `cloak/dispatcher.h` before writing this function.

2. **`cloak_proxy_attached`** (a `cloak_dispatch_attached_cb`): records `sesh` on the session context the first time it sees it and is otherwise a no-op. The context necessarily exists before the session does (it goes into the config), so this is where the two are joined. On the `created == 0` path there is nothing to do — the context already has its `sesh`. Note the header's warning that this fires *before* the connection is unlinked and freed, with the same do-not-destroy rule.

3. **`on_new_stream`**: allocate a `cloak_proxy_stream_t`, link it onto the session context, and `cloak_dial_start` to `ps->upstream` with `p->dial_timeout_ms`. Do **not** touch the stream's data here: bytes that arrived with the first frame sit in the stream's receive buffer and the relay's own initial pump drains them when it starts. If the dial cannot even be started, `cloak_session_close_stream` then `cloak_session_release_stream` and free the context — `on_new_stream` is explicitly permitted to release the stream it was handed (`cloak/session.h:26-32`).

4. **The dial callback**: `fd < 0` means the connect failed or timed out — close that one stream, leave the session alone. Otherwise `cloak_stream_relay_start(&pst->relay, reactor, ps->sesh, pst->stream, fd, p->relay_buf_cap, on_relay_done, pst)`.
   - **Obligation 2 lands here.** `cloak_stream_relay_start` returns -1 for two very different reasons and the interface does not distinguish them: an argument/allocation/registration failure (permanent) and "the session's pool could never hold even a single worst-case frame right now" (transient — see its doc comment). Since the caller cannot tell them apart, take the conservative branch: **retry on a timer**, up to `max_retries`, holding the fd in `fd_pending` (on a failed start the caller keeps the fd and must close it — re-read that doc comment for the one narrow exception where the relay closes it itself, and handle it). Exhausting the retries closes that one stream, not the session. Write down in a comment that the retry exists because the interface conflates the two cases, so that a later change to `stream_relay.h` that *does* distinguish them has a pointer to what should then be simplified.
   - If arming the retry timer itself fails, close the stream immediately — an ENOMEM-class failure with no way left to ever make progress.

5. **`on_stream_data`**: find this session context's `cloak_proxy_stream_t` for the supplied `cloak_stream_t *` and call `cloak_stream_relay_notify_stream_data` on it. A linear scan of the session's own list is correct here — a session's live stream count is small and Go indexes no better — but **say that in a comment**, because the next reader will wonder whether it should be a hash table. A stream still dialing or retrying has no relay yet and needs no notification: its data waits in the stream's own receive buffer and the relay's initial pump takes it.

6. **`on_writable`**: walk the session context's list and call `cloak_stream_relay_notify_writable` on every started relay. That is obligation 3's shape — each relay re-checks its own budget independently, and they do not coordinate. **Comment obligation 3 here**, at the one place in the code where the lack of coordination is visible, naming what a fix would look like.

7. **`on_relay_done`**: `cloak_session_release_stream(ps->sesh, pst->stream)`, unlink, free. This is the only place a stream is released on the normal path; Task 3 owns the teardown path.

8. **`cloak_proxy_init` / `cloak_proxy_destroy`**: init zeroes and fills before validating, and returns -1 on a NULL `reactor` or `srv`. `destroy` is implemented **completely** here — it walks every session context and every stream context, stopping relays, cancelling dials, cancelling retry timers and closing `fd_pending`, then frees them; it is idempotent and safe on a zeroed struct. Task 3 does not rewrite it; Task 3 adds the *registry-broken* path beside it and two fields to `cloak_proxy_config_t` (`chain`, `chain_userdata`), which `destroy` deliberately never fires. Leave the config struct in a shape those two fields extend cleanly.

**Ownership, stated in the header once:** `cloak_proxy_t` never owns a socket. A dialed fd belongs to `cloak_dial_t` until the dial callback, to `fd_pending` across a retry window, and to the relay from a successful `cloak_stream_relay_start` onward. The one field that says which is which is `fd_pending` (-1 when the proxy does not hold one), exactly as `cloak_dispatch_conn_t.fd` does in the dispatcher.

- [ ] **Step 1: Write the failing test**

Create `libcloak-server/tests/test_proxy_stream.c`. Build its fixture on `client_harness.h` (Task 1) plus a fake upstream — an echo listener on `127.0.0.1:0`, with the `ProxyBook` entry in the server's JSON config pointing at its port. Model the fixture on `test_dispatcher_auth.c`'s `fixture_init`/`fixture_destroy`, including the destroy ordering (dispatcher before registry). **Every peer socket in this file is non-blocking and every wait is `pump_until`** — a blocking `read()` on a peer is what made `test_backpressure` flake at 15-20% on an earlier branch.

```
1. One stream, bytes both ways. The client handshakes, opens a stream and
   writes "ping"; the fake upstream receives exactly that and replies;
   the client reads exactly the reply. The whole module in one test.

2. Data that arrived before the relay started. Write to the stream in the
   same reactor turn it is opened, so the bytes are in the stream's
   receive buffer before the dial completes, and assert they still reach
   the upstream in order. The relay's own initial pump is what makes this
   work; without it the first frame is stranded silently.

3. Two streams on one session to the same upstream, with interleaved
   traffic on both. Assert each stream's bytes reach its OWN upstream
   connection -- a routing bug that crossed them passes test 1.

4. A large transfer (at least 512 KiB) through one stream, asserted byte
   for byte, with the session still open and usable at the end. Without
   working backpressure this fails by breaking the session rather than by
   corrupting data, so assert liveness as well as bytes.

5. The upstream closing its side ends the stream: the client observes the
   stream end, and cloak_proxy_stream_count drops to 0.

6. The client closing its stream closes the upstream connection: the fake
   upstream reads EOF.

7. An upstream that refuses the connection (a port bound then closed, or
   127.0.0.1 on a closed port) closes that one stream and leaves the
   session alive -- assert by opening a SECOND stream afterwards, to a
   working upstream, and passing bytes through it.

8. Obligation 5: a handshake with the unordered flag set is REDIRECTED --
   the client receives the cover site's response, not a ServerHello, and
   the registry session count stays 0. build_client_record already takes
   an `unordered` argument; test_dispatcher_auth.c's redirect assertions
   are the model for what to assert.

9. A ProxyBook entry declared "udp" redirects rather than attaching, for
   the same reason and asserted the same way.
```

- [ ] **Step 2: Run it to verify it fails** — `cloak/proxy.h` does not exist; the build fails.

- [ ] **Step 3: Write `proxy.h` and `proxy.c`**

The header must state, in this project's established style: that `cloak_proxy_t` supplies the dispatcher's two callbacks and the session's three, and must outlive every session it ever prepared a context for; that it never owns a socket, with the `fd_pending` rule; that a stream is released in exactly two places (the relay's done callback, and Task 3's teardown); the retry policy with the reason it exists; and the unordered/UDP redirect decisions with their reasons.

- [ ] **Step 4: Wire into both CMakeLists, run the suite (37 tests) and the ASan suite**

Then run the new test 50 times in a loop and require 50/50 — the flake history above is why.

- [ ] **Step 5: Commit** — `git commit -m "Add proxy: dial the upstream and splice accepted streams"`

---

### Task 3: Teardown — stop every relay before the session frees its streams

**This is obligation 1.** `cloak_session_broken_cb` frees every still-active stream immediately after `on_broken` returns. A relay holds its stream and session as raw pointers it cannot validate, and a relay left running past that point still has its fd registered in the reactor — the next byte that arrives runs `cloak_stream_write` on freed memory. The registry's broken callback fires while the session is still alive and is the only window.

**Files:**
- Modify: `libcloak-server/src/proxy.c`, `libcloak-server/include/cloak/proxy.h`
- Create: `libcloak-server/tests/test_proxy_teardown.c`
- Modify: `libcloak-server/tests/CMakeLists.txt`

**Interfaces:**
- Consumes: `cloak_registry_broken_cb`, `cloak_server_registry_init` (`cloak/registry.h`).
- Produces: `cloak_proxy_registry_broken` — a `cloak_registry_broken_cb` the owner passes to `cloak_server_registry_init` with the `cloak_proxy_t *` as its userdata.

**The wiring decision, and why.** `cloak_server_registry_init` takes exactly one `on_broken` for the whole registry, so the proxy cannot install a second one beside the owner's. Two options: expose `cloak_proxy_on_session_broken(p, sesh)` for the owner to call from its own callback, or have the proxy *be* the callback and chain the owner's after it. **Take the second**, and add an optional chain to `cloak_proxy_config_t`:

```c
    cloak_registry_broken_cb chain;   /* optional; invoked AFTER the proxy's own cleanup */
    void *chain_userdata;
```

The first option makes the correctness of this whole module depend on every owner remembering to call one function from the right place, which is precisely the mistake `registry.h` says is the most likely one. The second makes it the default: an owner that wires the proxy in at all gets the cleanup, and an owner with its own bookkeeping gets it too, after. Say this in the header, with the ordering stated: the proxy's cleanup runs first because a chained callback is permitted to call `cloak_server_registry_destroy`, and by then every relay must already be stopped.

**What to build:**

1. **`cloak_proxy_registry_broken(reg, sesh, uid, session_id, userdata)`**: find the `cloak_proxy_session_t` for `sesh` (linear scan of `p->sessions`, same reasoning and same comment as the per-stream scan). For every stream context on it, in this order:
   - `cloak_stream_relay_stop` if relaying, else `cloak_dial_cancel` if dialing, else `cloak_reactor_timer_cancel` + `close(fd_pending)` if retrying;
   - then `cloak_session_release_stream`;
   - then unlink and free.

   **The order is the whole task.** `cloak_stream_relay_stop` closes the stream so the peer learns, then the release frees it. Releasing first hands the relay a freed pointer. Comment the ordering at the site, not only in the header.

   Then unlink and free the session context, then invoke the chain. A `sesh` with no context (it was created by something other than this proxy, or `prepare_session` returned -1 so no context exists) is not an error — skip straight to the chain.

   Note `cloak_registry_broken_cb`'s own calling-context rules before writing this: it runs in exactly the context `cloak_session_broken_cb` documents, and `cloak_session_destroy` must not be called from it.

2. **`cloak_proxy_destroy`**: the same cleanup for every session context still alive, but it is the owner's own shutdown rather than a failure path, so it fires no chain and reports nothing. Idempotent; safe on a zeroed struct.

3. **`cloak_proxy_session_count` / `cloak_proxy_stream_count`** (added in Task 2, exercised here): `stream_count` counts every live stream context across every session, so a test can assert cleanup happened rather than infer it from not crashing.

- [ ] **Step 1: Write the failing test**

`libcloak-server/tests/test_proxy_teardown.c`, same fixture shape as Task 2's, wiring `cloak_proxy_registry_broken` into `cloak_server_registry_init`:

```
1. A session broken by its underlying connection dying, with one stream
   mid-transfer: assert the broken callback ran, cloak_proxy_stream_count
   and cloak_proxy_session_count both reach 0, and nothing leaks. This is
   the case obligation 1 exists for and it shows ONLY under ASan -- run it
   there and say so in the test's own comment.

2. The same with a stream still DIALING (an upstream that accepts nothing
   -- bind a listener, never accept, so connect stays pending): the dial
   must be cancelled, not left to fire into freed memory.

3. The same with a stream in RETRY (a relay start that was rejected and a
   retry timer armed): the timer must be cancelled AND fd_pending closed.
   If provoking a genuine start rejection is impractical, say so and
   drive the retry state directly through the smallest test-visible seam
   rather than skipping the case -- a cancelled-timer path that no test
   ever enters is exactly where the next use-after-free will live.

4. Several sessions with several streams each, all broken in the same
   reactor turn.

5. cloak_proxy_destroy with everything live: sessions, relays, a pending
   dial and an armed retry timer, all at once.

6. The chain runs, after the proxy's cleanup: a chained callback that
   reads cloak_proxy_stream_count observes 0 for that session's streams.

7. A session broken that this proxy has no context for (prepare_session
   returned -1) reaches the chain without touching anything.
```

- [ ] **Step 2: Run it to verify it fails**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Full suite (38 tests) and ASan suite; then the two new test files 50 times each, 50/50 required**

- [ ] **Step 5: Verify the regression tests actually regress**

For cases 1, 2 and 3: revert the specific cleanup line (the `cloak_stream_relay_stop`, the `cloak_dial_cancel`, the timer cancel) and confirm the test fails under ASan; restore it. **Three separate regression tests on an earlier branch would have passed against the very bug they were written for**, which is why this step is not optional. Record what each mutation produced in the commit message.

- [ ] **Step 6: Commit** — `git commit -m "Add proxy teardown: stop relays before the session frees its streams"`

---

### Task 4: End to end

One test that drives the whole server the way a binary would — the thing that proves the modules compose rather than each working alone.

**Files:**
- Create: `libcloak-server/tests/test_server_e2e.c`
- Modify: `libcloak-server/tests/CMakeLists.txt`

**What it must cover, beyond Tasks 2 and 3:**

```
1. The full stack wired as ck-server will wire it: a cloak_listener_t, a
   cloak_dispatcher_t, a cloak_server_registry_t, a cloak_server_t built
   from a parsed JSON config, and a cloak_proxy_t -- in the order a
   binary would build and destroy them. If that wiring needs more than a
   few dozen lines, or if the destroy ordering is non-obvious, SAY SO in
   the report: module 7 builds exactly this, and an awkward seam found
   here is cheaper than one found there.

2. Obligation 4, in its CORRECTED form (see the obligation's own entry --
   the literal "pipelined behind the ClientHello" client cannot exist,
   because the server generates the session key and delivers it in the
   reply). The window to test is: the server finishes writing its reply,
   and the client's first data frame arrives in the socket buffer BEFORE
   conn_handoff runs cloak_reactor_remove_fd + cloak_session_add_conn.
   Force it deterministically rather than racing for it -- the
   LD_PRELOAD write shim (tests/test_write_shim.c, already wired for
   test_dispatcher_auth and test_dispatcher_limits) can make the reply
   write take EAGAIN so the hand-off is deferred to a later reactor turn,
   giving the client's frame a guaranteed place to land in between.
   Assert the bytes arrive at the upstream. This is the "bytes survive
   the re-registration" property three branches have reasoned about on
   paper and none has tested. If it does NOT hold, that is a real bug in
   the hand-off and the single most valuable thing this plan will find --
   report it, do not work around it.

3. Two connections on one session (same uid, same session_id), each
   carrying a stream, asserted byte for byte. This is the live-session-key
   rule end to end: composing the second connection's reply with a fresh
   key instead of the live session's yields a session that establishes
   cleanly and then fails every frame silently, so only a byte-level
   assertion distinguishes the two.

4. A redirected connection and a proxied one against the same listener,
   in the same test, proving the dispatcher's two paths coexist.

5. Clean shutdown with traffic in flight, under ASan: destroy in the
   binary's order while a transfer is mid-flight.
```

- [ ] **Step 1: Write the test**
- [ ] **Step 2: Run it; fix what it finds, or report it if it is a finding rather than a fix**
- [ ] **Step 3: Full suite (39 tests) and ASan suite; the new test 50 times, 50/50**
- [ ] **Step 4: Commit** — `git commit -m "Add an end-to-end server test"`

---

## What comes after this plan

The server is functionally complete for the direct-TLS, ordered case with bypass-only authorisation. Next, in the order the user set: the SQLite user manager and its accounting (Go's `userpanel`/`activeuser`, which also gives the registry the per-user session cap it currently lacks), the admin API over session 0, the client, the binaries, CDN/WebSocket, and UDP.

**Obligation 3 is deliberately unsolved.** Per-relay read budgets do not coordinate across relays on one session: each budgets off `cloak_session_send_min_conn_free` independently, so N relays can each believe they have room only one of them has. A fix needs either a session-level budget the relays draw from or an explicit scheduler, and the right time to design that is when there is a real multi-stream workload to measure it against. Task 2 comments it at the one place in the code where it is visible.

**Obligation 5's residual:** rejecting `unordered` at session creation matches Go's own session-level treatment of the flag, but it means this server answers a UDP-requesting client with a redirect. That is the honest answer while there is no UDP data path; module 9 replaces it with a real one.

## Self-review notes

- **Spec coverage:** §7 step 3's second half is Task 2; §6's data plane, implemented by `cloak_stream_relay_t` two branches ago, is finally exercised by Tasks 2-4. Each of the five inherited obligations is assigned to a numbered task rather than left as background — that mechanism is what has kept the previous three branches' findings from being rediscovered.
- **Placeholder scan:** Task 1 names every helper to move. Task 2 gives both structs and the config literally, and its flows as an ordered list with the reason for each. Tasks 3 and 4 are behaviour specs with named, numbered test cases. No step defers a decision: obligation 5 is settled in Task 2 with its rationale, obligation 3 is explicitly deferred with the reason and the place it is documented, and the registry-wiring choice is made in Task 3 with the alternative and why it loses.
- **Type consistency:** `cloak_proxy_stream_t`/`cloak_proxy_session_t`/`cloak_proxy_config_t` are defined once in Task 2 and used under those names in Tasks 3 and 4. `cloak_proxy_registry_broken` is produced in Task 3 and consumed in Task 4. `client_session_open`/`client_session_close` are produced in Task 1 and consumed in Tasks 2, 3 and 4. Test counts chain 36 → 36 → 37 → 38 → 39.
- **The riskiest thing here** is Task 3's ordering: stop the relay, then release the stream, and do both from the registry's broken callback rather than anywhere else. Every other bug in this module degrades a connection; that one is a use-after-free in the ordinary case of a client disconnecting mid-transfer.
- **The most valuable thing here** is Task 4's case 2. If the hand-off reasoning is wrong, every session whose client is quick off the mark loses its first frame — silently, since the frame is simply never delivered and nothing anywhere reports an error.
