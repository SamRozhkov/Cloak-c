# libcloak-server: The Dispatcher's Connection Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the pieces already merged into a server that answers: accept a connection, frame and authenticate its first packet, attach it to a session — and, on any failure at all, forward it to the cover site so a prober cannot tell the difference. After this plan the server completes a real Cloak handshake; after the next one it also carries proxied traffic.

**Architecture:** One `cloak_dispatcher_t` owns a per-connection state machine allocated at accept and freed at hand-off, and nothing else: sessions belong to the registry, runtime state to `cloak_server_t`, and streams to the module after this one. The redirect path is built first and used as the failure path for everything, so "something went wrong" has exactly one implementation rather than one per error site — which is also how it stays indistinguishable from the success path to an observer. The authenticated path then replaces a deliberate always-fail stub, so every redirect case is already under test before the first byte of crypto is wired in.

**Tech Stack:** C11, CMake, CTest with the project's existing assert-based test framework.

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` §7 — this plan is §7 steps 1, 2, 3 (attach) and 4 (`goWeb`). Step 3's proxy relaying is the next plan.

## Global Constraints

- Language: C11, `-Wall -Wextra` clean. Project code must produce zero warnings.
- Platform: Linux only. POSIX APIs via `_POSIX_C_SOURCE 200809L` as the first line of the `.c` file that needs them.
- Naming: public symbols prefixed `cloak_`; headers in `libcloak-server/include/cloak/` with `CLOAK_<NAME>_H` guards; doc comments in the style of `cloak/registry.h` and `cloak/stream_relay.h` — contract, failure modes, and every lifetime obligation stated where the caller will read it.
- **Nothing on this path may block.** `cloak_net_resolve` was already called at startup by `cloak_server_init`; the dispatcher dials resolved addresses only.
- **Every failure is a redirect, not a close.** Closing a connection tells a prober that something other than a web server is listening, which is the property this whole product exists to protect. The only cases that close are ones where redirecting is impossible (the redirect dial itself failing) or where the peer already went away.
- Errors: 0/-1 with a reason in a caller-supplied `err` buffer that may be NULL, where a caller can act on it. Internal per-connection failures are not reported to anyone — they redirect.
- Existing tests are the regression net: every test in the suite must keep passing **unmodified**.
- **Append to `libcloak-server/CMakeLists.txt` and `libcloak-server/tests/CMakeLists.txt`; never rewrite them.** All three tasks touch both. Test include-dir convention: `${CMAKE_SOURCE_DIR}/libcloak-common/tests`. Every new test gets `TIMEOUT 60`.
- Build and test (`-w /src` would silently build the main checkout, which has bitten this project before):

  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/<branch> cloak-c-dev bash -c \
    'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
  ```

  Sanitizer: `-B build-asan` with `-DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"`.
- Baseline: 33 tests pass before this plan; 36 after it.
- Reference: `/Users/sam/Cloak/internal/server/dispatcher.go` — `dispatchConnection` is the function this plan ports, minus its `serveSession` half.

## What the previous branch already established

Its final review walked this loop on paper and recorded the results in `docs/superpowers/plans/2026-09-13-libcloak-server-state-plan.md` under "What a paper walk of that loop already established". **Read that section before starting Task 1.** In particular it settles, so nobody re-derives them:

- `cloak_listener_port(l)` in the accept callback is exactly the `local_port` `cloak_server_redir_addr` wants.
- The first-packet read loop must run inside the readable callback until `EAGAIN` or `want() == 0`; one exact-sized read per readiness edge stalls forever on an edge-triggered reactor.
- `cloak_reactor_remove_fd` must precede `cloak_session_add_conn`, and bytes already in the socket survive the re-registration.
- On `cloak_session_add_conn` failure nobody closes the fd — the dispatcher still owns it.
- **On the existing-session path the reply must be composed with the live session's key** (`sesh->obfuscator`), not a freshly generated one, or every frame fails authentication silently.
- Allocate a per-session context only after `cloak_server_registry_find` returns NULL, or it leaks on the existing path.
- There is no non-blocking write-then-handover primitive; Task 2 writes one.

---

### Task 1: `cloak_dispatcher_t` and the redirect path

Build the connection state machine and the failure path, with authentication stubbed to always fail. The result is a server that forwards every connection to the cover site — which is exactly Go's behaviour for non-Cloak traffic, so this is a real, testable milestone rather than scaffolding.

**Files:**
- Create: `libcloak-server/include/cloak/dispatcher.h`
- Create: `libcloak-server/src/dispatcher.c`
- Create: `libcloak-server/tests/test_dispatcher_redirect.c`
- Modify: `libcloak-server/CMakeLists.txt`, `libcloak-server/tests/CMakeLists.txt`

**Interfaces:**
- Consumes: `cloak_listener_t`/`cloak_listener_port`, `cloak_dial_t`, `cloak_relay_t`, `cloak_addr_t` (`cloak/net.h`); `cloak_firstpacket_t` (`cloak/firstpacket.h`); `cloak_server_t`/`cloak_server_redir_addr` (`cloak/server.h`); the reactor's fd and timer APIs.
- Produces: `cloak_dispatcher_t`, `cloak_dispatcher_config_t`, `cloak_dispatcher_init/destroy`, `cloak_dispatcher_accept`, `cloak_dispatcher_conn_count`.

**The shape, which the implementer should follow rather than reinvent:**

```c
/* One in-flight, not-yet-authenticated connection. Heap-allocated at
 * accept, freed when it is handed off, redirected, or dropped. Its
 * address is the reactor's callback userdata, so it must never move. */
typedef struct cloak_dispatch_conn {
    cloak_dispatcher_t *d;
    int fd;                       /* -1 once ownership has left */
    uint16_t local_port;          /* for a portless RedirAddr */
    cloak_firstpacket_t fp;
    cloak_timer_id_t deadline;

    /* Redirect state. Only one of these is live at a time. */
    cloak_dial_t dial;
    int dialing;
    cloak_relay_t relay;
    int relaying;

    struct cloak_dispatch_conn *prev, *next; /* dispatcher's intrusive list */
} cloak_dispatch_conn_t;
```

The dispatcher keeps every in-flight connection on an intrusive doubly-linked list so `cloak_dispatcher_destroy` can tear them all down; a connection removes itself the moment it is finished with.

**States and transitions:**

1. **Reading the first packet.** `cloak_dispatcher_accept` allocates the connection, links it, arms the deadline timer, and registers the fd readable. The readable callback loops: `want()` → `read(fd, buf, want)` → `feed()`, until `want() == 0`, `read` returns `EAGAIN`, or the packet errors. `read` returning 0 (peer closed) drops the connection without redirecting — there is nobody to redirect to. Any `CLOAK_FIRSTPACKET_ERROR` goes straight to redirect, since every error this object reports is a redirectable one.
2. **Authentication.** On `CLOAK_FIRSTPACKET_DONE`, call `dispatcher_authenticate(conn)`. **In this task that function is a stub that always returns -1**, with a comment saying Task 2 replaces it. Every `-1` goes to redirect.
3. **Redirect.** Cancel the deadline, compute the target with `cloak_server_redir_addr(srv, conn->local_port, &addr)`, `cloak_reactor_remove_fd` the client fd (the relay re-registers it), and `cloak_dial_start` to the cover site. On dial success, `cloak_relay_start` with the client fd, the dialed fd, and **`cloak_firstpacket_data`/`_len` as the preload** — everything the client already sent must reach the real web server, or the cover story is visibly broken. On dial failure, close the client fd: there is nothing to forward to.
4. **Deadline.** 15 seconds by default, matching Go's `readFirstPacket`. Firing before the packet completes drops the connection — a client that opens a socket and says nothing gets nothing, exactly as a web server would behave. Cancel it on every path that leaves the reading state.

**Ownership, stated once and obeyed everywhere:** the connection owns `fd` until it hands it to `cloak_relay_start` (which takes both fds) or, in Task 2, to `cloak_session_add_conn`. Every early exit closes it. Set `conn->fd = -1` at the moment ownership leaves so the teardown path cannot double-close — this project has produced seven use-after-free and double-free bugs and the ones that survived review were all "two paths both think they own it".

**The relay's done callback** frees the connection state. The relay owns both fds by then, so the connection must not touch `fd` again.

- [ ] **Step 1: Write the failing test**

Create `libcloak-server/tests/test_dispatcher_redirect.c`. It needs a fake cover site: a listener on loopback that accepts one connection and echoes, or simply records what it received. Cover:

```
1. Junk first byte. Connect, send "HELLO\n", and assert the fake cover
   site receives exactly those bytes. This is the whole redirect
   contract: the prober's own bytes reach a real web server.

2. A well-formed TLS record that is not Cloak. Build a record with a
   0x16 header and a body of random bytes, send it, and assert the cover
   site receives the whole record byte for byte — including the 5-byte
   header, which cloak_firstpacket_t buffers and the preload must carry.

3. A complete HTTP GET. Same, for the 'G' path: the cover site must
   receive the entire request including its terminating blank line.

4. Bidirectionality. After the redirect is established, the cover site
   writes a response and the client must receive it — the relay is a
   splice, not a one-way forward.

5. The deadline. Connect, send a single 0x16 byte, and stop. With a
   short handshake_timeout_ms configured, assert the connection is
   dropped: the client's next read returns EOF, and the cover site
   received nothing. (Use a short timeout in the config rather than
   waiting 15 seconds.)

6. Peer closes mid-packet. Send 0x16 then close. Assert no redirect
   happens (the cover site sees nothing) and no crash.

7. Redirect dial failure. Point RedirAddr at a closed port and assert
   the client connection is closed rather than hanging, and that the
   dispatcher's connection count returns to zero.

8. cloak_dispatcher_destroy with connections in flight, at least one
   mid-read and one mid-relay, leaves nothing leaked. Run under ASan.
```

Write these as real test functions with real assertions, driving the reactor with bounded loops. `libcloak-common/tests/test_relay.c` and `test_listener.c` are the models for the socket harness.

- [ ] **Step 2: Run it to verify it fails** — `cloak/dispatcher.h` does not exist.

- [ ] **Step 3: Write the header, then the implementation**

The header must document: that the caller wires `cloak_dispatcher_accept` into `cloak_listener_open`'s accept callback and that ownership of the fd passes at that call; that every failure redirects rather than closes, and why; that `cloak_dispatcher_destroy` tears down every in-flight connection; and the 15-second default with the reason (Go's value, and the fd-pinning failure mode it prevents).

`cloak_dispatcher_init` initializes the struct before validating its other arguments, like every other constructor on this project — four earlier tasks got that ordering wrong and it was a crash every time.

- [ ] **Step 4: Wire into the build, run the suite (34 tests) and the sanitizer suite**

- [ ] **Step 5: Commit** — `git commit -m "Add dispatcher: connection state machine and the redirect path"`

---

### Task 2: Authentication and session attach

Replace the stub. This is §7 steps 2 and 3, and it is where the previous branch's paper walk pays off — read its findings before writing a line.

**Files:**
- Modify: `libcloak-server/src/dispatcher.c` (replace the stub; add the reply-write state)
- Modify: `libcloak-server/include/cloak/dispatcher.h` (the config gains the registry, the session template, and two callbacks)
- Create: `libcloak-server/tests/test_dispatcher_auth.c`
- Modify: both CMakeLists

**Interfaces:**
- Consumes: `cloak_clienthello_parse` (`cloak/clienthello_parse.h`); `cloak_server_check_replay`, `cloak_server_is_bypass`, `cloak_server_is_admin`, `cloak_server_lookup_proxy` (`cloak/server.h`); `cloak_server_auth_decrypt`, `cloak_server_auth_compose_reply`, `cloak_server_auth_cert_lens` (`cloak/server_auth.h`); `cloak_server_registry_find`/`_get_or_create` (`cloak/registry.h`); `cloak_session_add_conn` (`cloak/session.h`); `cloak_random_bytes` (`cloak/common.h`).
- Produces: two new config callbacks —
  - `typedef int (*cloak_dispatch_prepare_session_cb)(cloak_dispatcher_t *d, const cloak_server_clientinfo_t *info, cloak_session_config_t *config, void *userdata);` — invoked **only** when a new session is about to be created, so the owner can install per-session callbacks and userdata. Returning -1 abandons the handshake and redirects. The owner must not touch `on_broken`/`on_broken_userdata`; the registry owns those.
  - `typedef void (*cloak_dispatch_attached_cb)(cloak_dispatcher_t *d, cloak_session_t *sesh, const cloak_server_clientinfo_t *info, int created, void *userdata);` — fired after the connection is attached.

**The authenticated path, in order, with the reason each step is where it is:**

1. **Only the TLS transport proceeds.** `CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET` has no consumer until the CDN module exists, so it redirects — `firstpacket.h` says so and this is the code that must honour it.
2. **Parse.** `cloak_clienthello_parse` over the framed record. Failure redirects.
3. **Replay check before decryption.** `cloak_server_check_replay(srv, ch.random, now)`. Both headers state this ordering and Go does the same: the check runs against the raw, not-yet-authenticated random, so an attacker replaying a captured handshake is rejected without the server doing any asymmetric work.
4. **Decrypt.** `cloak_server_auth_decrypt(ch.random, ch.session_id, ch.session_id_len, ch.x25519_key_share, srv->cfg->private_key, now, &info, shared_secret)`. Failure redirects. Everything in `info` is attacker-chosen until authorised.
5. **Validate the encryption method** with `cloak_aead_method_is_valid` before it is used to size or configure anything — `crypto.h` requires this of any wire-sourced method byte, and skipping it is how a wire byte becomes an out-of-range array index.
6. **Authorise the UID.** Until the user manager exists, `cloak_server_is_bypass` is the whole policy: not on the list means redirect. Log nothing — a prober learns nothing from a silent redirect.
7. **Look up the proxy method.** `cloak_server_lookup_proxy` returning NULL redirects. (The address it returns is what the next plan dials; this task only checks it exists, because Go rejects an unknown method before creating a session.)
8. **Find, then create.** `cloak_server_registry_find` first. If found, this is an additional connection for an existing session: **compose the reply with that session's own key** (`sesh->obfuscator`'s session key), not a fresh one. If not found, generate a fresh 32-byte session key with `cloak_random_bytes`, build the session config from the template plus the decrypted encryption method, invoke the owner's prepare callback, and `cloak_server_registry_get_or_create`.
9. **Compose the reply.** `cloak_server_auth_compose_reply(shared_secret, session_key, nonce, ch.session_id, pad4, fake_cert, cert_len, out, cap)` with a fresh random nonce, a fresh random `pad4`, and a `cert_len` chosen uniformly from `cloak_server_auth_cert_lens` — the varying length is a DPI-plausibility measure, so choose it randomly per connection rather than fixing it.
10. **Write the reply to completion, non-blocking.** This is the primitive the paper walk found missing. Write what the socket takes; on a short write or `EAGAIN`, register for writable and finish from the writable callback. Only when the last byte is out does the connection proceed. A write error at this point closes rather than redirects: the client has already had a ServerHello, so the cover story is no longer available.
11. **Hand off.** `cloak_reactor_remove_fd`, then `cloak_session_add_conn`. On failure the dispatcher still owns the fd and must close it. On success set `conn->fd = -1`, fire the attached callback, unlink and free the connection state.

**On the unwind path:** if anything after the session was *created* fails, `cloak_server_registry_close` that session — but only when `get_or_create` reported `created == 1`. Closing unconditionally would tear down a live multi-connection session because one new handshake went wrong, which `registry.h` warns about explicitly.

- [ ] **Step 1: Write the failing test**

Create `libcloak-server/tests/test_dispatcher_auth.c`. The test client builds a **real** Cloak handshake from the primitives already merged — this is what makes the test meaningful rather than a mock:

- `cloak_x25519_generate_keypair` for the ephemeral pair, `cloak_x25519_shared_secret` against the server's configured public key;
- the 48-byte payload laid out exactly as `server_auth.h` documents (UID, 12-byte NUL-padded proxy method, encryption method, big-endian timestamp, big-endian session id, flags, reserved);
- `cloak_aead_seal` with AES-256-GCM, key = shared secret, nonce = the first 12 bytes of the ephemeral public key;
- `cloak_clienthello_build(&cloak_clienthello_chrome, eph_pub, ct, ct + 32, "www.example.com", out, cap)`.

Cover:

```
1. A valid handshake attaches. The attached callback fires with
   created == 1, the registry holds one session, and the client receives
   a reply of plausible length. Assert on the client having received
   SOMETHING well-formed rather than on exact bytes — the reply contains
   random padding by design.

2. A SECOND connection with the same UID and session id attaches to the
   SAME session (created == 0, registry count still 1) — and the reply it
   receives decrypts, with the client's own shared secret, to the SAME
   session key as the first. This is the live-key rule, and it is the
   single most valuable assertion in this plan: composing with a fresh
   key here produces a session that establishes cleanly and then fails
   every frame silently.

3. A different session id for the same UID creates a second session.

4. Replay. Send the exact same ClientHello bytes twice. The second is
   redirected, and the cover site receives them.

5. An unauthorised UID redirects, and the cover site receives the whole
   ClientHello.

6. An unknown proxy method redirects.

7. A stale timestamp (outside the tolerance window) redirects.

8. The prepare callback returning -1 redirects, and no session is left
   in the registry.

9. The admin UID with session id 0 is recognised — assert via the info
   passed to the attached callback, since the admin API itself is a
   later module.
```

- [ ] **Step 2: Run it to verify it fails**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Full suite (35 tests) plus the sanitizer suite**

- [ ] **Step 5: Commit** — `git commit -m "Add dispatcher authentication and session attach"`

---

### Task 3: Limits, teardown and the failure matrix

The dispatcher is the only code in this project that runs on wholly unauthenticated input from anyone who can reach the port. This task bounds it and proves the failure modes.

**Files:**
- Modify: `libcloak-server/src/dispatcher.c`, `libcloak-server/include/cloak/dispatcher.h`
- Create: `libcloak-server/tests/test_dispatcher_limits.c`
- Modify: both CMakeLists

**What to add:**

1. **A cap on in-flight connections.** `max_pending_conns` in the config (default 512). At the cap, `cloak_dispatcher_accept` closes the new fd immediately rather than allocating. Document that this is a deliberate divergence: Go has no such cap and relies on the runtime, while a C server that allocates ~3 KB per unauthenticated connection needs one. Closing rather than redirecting is correct here — under resource exhaustion the cover story costs a second fd and a dial.
2. **`cloak_dispatcher_destroy` correctness under load**: connections mid-read, mid-reply-write, mid-dial and mid-relay must all be torn down exactly once, with every fd closed and every timer cancelled.
3. **A count accessor** so a caller (and the tests) can observe in-flight state.

**Tests:**

```
1. The cap. Open max_pending_conns + 1 connections that send nothing;
   assert the last is closed immediately and the count stays at the cap.
   Then let one complete and assert a new one is accepted.

2. Teardown at every stage. Build one connection in each state — mid
   first-packet, mid reply-write, mid dial, mid relay — then destroy the
   dispatcher and assert clean under ASan. Getting a connection reliably
   into the mid-reply-write state needs a client that does not read;
   a small socket buffer plus a full reply is the lever.

3. A slow-loris client: many connections each dribbling one byte per
   turn. Assert the deadline reaps them all and the count returns to
   zero.

4. Fuzz-shaped robustness: for a few hundred pseudo-random first packets
   (fixed seed, so failures reproduce), assert the dispatcher either
   redirects or drops, never crashes and never leaks. This is not a
   substitute for the libFuzzer targets the spec calls for, and should
   say so in a comment.
```

- [ ] **Step 1: Write the failing test**
- [ ] **Step 2: Run it to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (36 tests), sanitizer suite, and the repeat loop on the new tests**
- [ ] **Step 5: Commit** — `git commit -m "Add dispatcher limits and teardown hardening"`

---

## What comes after this plan

The proxy path: `on_new_stream` dials the upstream from `cloak_server_lookup_proxy`'s resolved address, starts a `cloak_stream_relay_t`, routes `on_stream_data` and `on_writable` to the right relay, and tears every relay down from the registry's `on_broken` — the obligation `stream_relay.h` and `registry.h` both state. That plan also owns the three carried-forward items from the stream-relay branch: relays must be stopped before a session tears down; a transiently busy pool can make `cloak_stream_relay_start` fail spuriously and the dispatcher should retry rather than treat it as fatal; and per-relay read budgets do not coordinate across relays on one session.

Then, in the order the user set: the SQLite user manager and accounting, the admin API over session 0, the client, the binaries, CDN/WebSocket, and UDP.

## Self-review notes

- **Spec coverage (§7):** step 1 (sniff and buffer) is Task 1 via `cloak_firstpacket_t`; step 2 (authenticate) and step 3's attach are Task 2; step 4 (`goWeb`) is Task 1, built first on purpose so it is the tested failure path for everything Task 2 adds. Step 3's "start relaying to the configured ProxyBook target" is the next plan, and this plan's Task 2 still validates the proxy method so an unknown one is rejected before a session exists, as Go does.
- **Placeholder scan:** Task 1's structure is given as a literal struct and an ordered state list; Tasks 2 and 3 are ordered behaviour specs with every step's rationale. No step defers a decision or says "handle errors". The one deliberate stub — Task 1's always-failing `dispatcher_authenticate` — is named as such, with the task that replaces it.
- **Carried-forward items honoured:** the live-key rule (Task 2 step 8, pinned by its test 2), find-before-allocate (step 8), `created == 1` as the unwind discriminator, `remove_fd` before `add_conn`, the fd still being the dispatcher's on `add_conn` failure, the 15-second deadline, and WebSocket redirecting until the CDN module exists — all from the previous branch's paper walk, each landing in a specific step rather than a general exhortation.
- **The riskiest thing here** is step 10, the non-blocking reply write: it is the one primitive nobody has built, it sits between "the client has a ServerHello" and "the session exists", and a bug there desynchronises a session that otherwise looks healthy. Its failure mode is deliberately different from every other step's — close, not redirect — and that asymmetry is the thing a reviewer should check hardest.
