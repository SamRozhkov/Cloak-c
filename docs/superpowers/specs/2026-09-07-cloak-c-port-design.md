# Cloak-C: independent C port of Cloak — design

Date: 2026-09-07
Status: approved for planning

## 1. Background and goal

[Cloak](https://github.com/cbeuw/Cloak) is a Go pluggable transport (~10k LOC) that masquerades
proxied traffic (Shadowsocks, OpenVPN, Tor, ...) as ordinary HTTPS/WebSocket traffic to evade DPI
censorship, using TLS ClientHello steganography, ECDH+AEAD authentication, and multiplexing over
several TCP connections.

Goal of this project: a full, independent, feature-equivalent reimplementation in C, covering
everything the Go version has (masquerading, multiplexing, multi-user + bandwidth/credit
management with admin API, CDN/WebSocket transport). It does **not** need to be wire-compatible
with the Go implementation — protocol details may be redesigned, and in most cases we deliberately
keep the Go design because it's already proven against real DPI, rather than because compatibility
is required.

This spec covers the whole system in one document; it will still be built in an order chosen by the
implementation plan (module dependencies force a build order regardless of how the spec is scoped).

## 2. Non-goals

- Wire compatibility with Go Cloak (C client cannot talk to a Go server or vice versa).
- Any platform other than Linux (no Android, Windows, macOS). No client-side network "protector"
  callback (Android-only concept in the Go version).
- A pprof-equivalent built-in profiler. Standard Linux tooling (`perf`, `valgrind`, sanitizers) is
  used instead; the server binary should build cleanly with debug symbols and without stripping.
- Automatic TLS-fingerprint updates. Browser ClientHello templates are captured and vendored by
  hand; keeping them current as browsers update is an ongoing maintenance task, same as it is for
  Go's uTLS dependency.

## 3. High-level architecture

Two binaries, `ck-server` and `ck-client`, each a **single-threaded epoll reactor** — no threads,
no blocking I/O anywhere in the data or control path. This is the central structural difference
from the Go version, where every connection/stream is a goroutine doing blocking `Read`/`Write`.

Consequences of this choice:
- No locks anywhere in the process — all state is mutated from the one event-loop thread. This
  eliminates the entire class of concurrency bugs the Go version manages with `sync.Mutex` /
  `sync.Map` (`Session.streamsM`, `Stream.writingM`, `switchboard.conns`).
- All protocol parsing that the Go version does with blocking, sequential code
  (`readFirstPacket`, TLS record reads, WS line reads, the auth handshake) must be rewritten as
  explicit resumable state machines: a non-blocking `read()` can return a partial TLS record or a
  partial HTTP line, and the reactor must be able to pick parsing back up on the next readable
  event without re-entering from the top.
- Timers (inactivity timeout, stream idle timeout, reconnect backoff) are driven by a timer wheel
  / min-heap integrated into the reactor loop, not `time.AfterFunc`.

### Component layout

```
libcloak-common/    crypto primitives, ClientHello templates, config, reactor (epoll wrapper + timers)
libcloak-mux/        session / stream / switchboard (multiplexing)
libcloak-server/     dispatcher, auth, user manager (SQLite), admin API, redirect-on-fail
libcloak-client/     connector, transport selection (direct / CDN+WS), local proxy routing
cmd/ck-server/       server binary (links common+mux+server)
cmd/ck-client/       client binary (links common+mux+client)
```

This mirrors the Go module boundaries (`internal/common`, `internal/multiplex`, `internal/server`,
`internal/client`) so the two codebases stay easy to cross-reference.

## 4. Wire protocol

Kept identical in spirit to Go Cloak's own design (chosen deliberately — it's already
DPI-tested), just not byte-compatible since keys/IDs are independently generated per side.

**Frame** (14-byte header + payload + padding + AEAD tag):
- Header: `stream_id (u32) | seq (u64) | closing (u8) | extra_len (u8)`.
- Payload encrypted with AEAD (AES-256-GCM / AES-128-GCM / ChaCha20-Poly1305, matching the Go
  encryption method options; "plain" = no payload encryption, for use only when the wrapped proxy
  protocol already provides its own AEAD).
- Header is XORed with Salsa20, keyed by session key, nonce = trailing bytes of the AEAD tag (or
  random bytes in plain mode). Authenticates the header transitively through the AEAD.
- First 5 frames of a session get random padding to defeat TLS-in-TLS record-size fingerprinting.

**Handshake / auth**: client's X25519 ephemeral public key is embedded in the ClientHello
`random` field; an AEAD ciphertext carrying UID, proxy method, encryption method, timestamp, and
session ID is embedded across `session_id` and the X25519 `key_share` extension. Server computes
the ECDH shared secret with its static private key, decrypts, checks the timestamp window, and
checks a replay cache keyed by `random` (bounded hash set, entries evicted once they age out of
the timestamp tolerance window — no external dependency needed for this).

## 5. TLS ClientHello mimicry

The highest-risk, highest-value component for DPI evasion.

- Byte-exact ClientHello templates captured from real browsers (Chrome, Firefox, Safari) via
  `openssl s_client -msg` / Wireshark, vendored as byte arrays in
  `libcloak-common/clienthello_templates.c`.
- Each template ships an offset table: `{random_off, session_id_off, sni_off, sni_len,
  keyshare_off, total_len}`. Building a ClientHello = copy template, splice in our
  random/session_id/key_share payload bytes in place (fixed size, no length change), and — if SNI
  differs from the template's captured domain — rewrite the SNI extension, which requires patching
  three nested length fields (TLS record length, handshake message length, extensions block
  length, SNI extension length). This patching logic is a self-contained, heavily unit-tested
  function (`clienthello_set_sni`).
- `ServerName: random` mode generates a random domain the same way the Go version does.
- Server-side: a minimal ClientHello *parser* (not a TLS stack) that extracts `random`,
  `session_id`, SNI, and the X25519 key_share — mirrors `internal/server/TLSAux.go`.
- Maintenance note (documented, not solved by this spec): when browsers change their TLS
  fingerprint, templates must be recaptured by hand. Same maintenance burden Go's uTLS dependency
  carries; we're just not depending on someone else's library to carry it for us.

## 6. Multiplexing (session / stream / switchboard)

- `session_t`: stream table (hash map, stream_id -> `stream_t*`; single-threaded, no map locking
  needed), ring-buffer accept queue, list of underlying `conn_t` (switchboard).
- Switchboard distribution strategy: `uniformSpread` — pick a random underlying connection per
  frame (ChaCha8-seeded PRNG, matching Go's approach), same tradeoff Go documents: spreads load
  and avoids single-connection buffer stalls, at the cost of out-of-order delivery that the
  receiving stream must resequence.
- `stream_t` in ordered mode: a growable byte queue (no reordering needed — TCP already orders
  bytes within a single underlying connection, and cross-connection reordering is handled by
  sequence numbers before data reaches the queue). Unordered/datagram mode (`UDP: true` on the
  client, backing local UDP sockets registered in the same epoll reactor) uses a small reorder
  buffer keyed by sequence number, mirroring Go's `datagramBufferedPipe` — in scope, since full
  parity with the Go feature set was the explicit requirement.
- **Data plane**: not `io.Copy` on two goroutines. Instead, event-driven splicing between the local
  proxy socket and the stream's buffers: a readable event on one side attempts to enqueue into the
  other side's write buffer; if that buffer is full, EPOLLIN is deregistered on the source
  (backpressure) until the destination drains and re-arms it.

## 7. Server dispatcher and redirect-on-fail

`dispatch_conn()` is a per-connection state machine driven by epoll readiness:
1. Sniff first byte (`0x16` = TLS record, `0x47` = WebSocket `GET`), buffering incrementally since
   a non-blocking read may return a partial TLS record or a partial HTTP line.
2. Run `AuthFirstPacket` equivalent once the full first packet is buffered.
3. On success: derive session key, attach connection to a `session_t` (new or existing, keyed by
   UID+session ID), start relaying to the configured `ProxyBook` target.
4. On failure (bad decrypt, unknown UID, unknown proxy method, malformed protocol): `goWeb()` —
   non-blocking dial to `RedirAddr`, forward the already-buffered first packet, then splice
   bidirectionally. This is what makes the server indistinguishable from a plain web host to both
   passive observation and active probing, exactly as in the Go version.

## 8. User management and admin API

- SQLite (vendored amalgamation `sqlite3.c`, no system dependency) — a `users` table: `uid BLOB
  PRIMARY KEY, bypass INTEGER, rx INTEGER, tx INTEGER, rx_limit INTEGER, tx_limit INTEGER, expiry
  INTEGER`, mirroring the fields `usermanager` tracks in Go's bbolt store.
- The admin API is **not** a separate HTTP port — like the Go version, it's served over the Cloak
  tunnel itself (a session with ID 0, authenticated as `AdminUID`). This means a small hand-rolled
  HTTP/1.1 request parser + router reading directly off the muxed stream's byte queue (a few JSON
  CRUD routes: list/add/remove/modify user) — a general-purpose web framework doesn't fit here
  since there's no real listening socket to hand it, only a `stream_t`.

## 9. CDN / WebSocket transport

Important asymmetry from the rest of the client: CDN mode requires a **real** TLS handshake to the
CDN edge (the CDN terminates and validates TLS — a fake ClientHello would fail validation), so this
path uses full `libssl` (not just `libcrypto` as used for frame/auth crypto elsewhere). After the
real TLS session is up, the client sends an HTTP `Upgrade: websocket` request with `Host:
<CDNOriginHost>` (domain fronting) and `CDNWsUrlPath`; once switched, Cloak frames are wrapped in
WS frames. Server-side: parse the HTTP Upgrade request (already sniffed via the `0x47` branch in
the dispatcher), reply `101 Switching Protocols`, then unwrap/wrap Cloak frames in WS frames for
the rest of the connection's life.

## 10. Config, CLI, build

- Config file format: JSON, parsed with `cJSON` (vendored, single file, MIT). Fields match the Go
  config structs (`ProxyBook`, `BindAddr`, `RedirAddr`, `PrivateKey`, `BypassUID`, `AdminUID`,
  `DatabasePath`, `KeepAlive` server-side; `UID`, `Transport`, `PublicKey`, `ProxyMethod`,
  `EncryptionMethod`, `ServerName`, `AlternativeNames`, `CDNOriginHost`, `CDNWsUrlPath`, `NumConn`,
  `BrowserSig`, `StreamTimeout` client-side).
- CLI: `getopt_long`, mirroring the Go flags (`-c -s -p -l -i -u -k -uid -key -v -h -verbosity`).
  Key/UID generation (`-k`/`-key`, `-u`/`-uid`) uses OpenSSL `RAND_bytes` + X25519 keygen.
- Build: CMake. Dependencies: OpenSSL (system), cJSON and SQLite (vendored). No libevent/libuv —
  raw epoll per the earlier platform decision (Linux-only removes the need for a portability
  layer).

## 11. Testing

- Unit tests (lightweight custom assert-based runner + CTest — no heavyweight framework, matching
  the project's minimal-dependency stance): frame obfuscate/deobfuscate round-trip, ClientHello
  offset patching (including SNI length-rewrite correctness), auth encrypt/decrypt round-trip,
  switchboard connection distribution.
- Integration test: local `ck-server` + `ck-client` against a dummy TCP echo target standing in for
  the underlying proxy; verify byte-exact data integrity across multiple concurrent streams and
  multiple underlying connections.
- Fuzz targets (libFuzzer, bundled with clang): ClientHello parsing and frame deobfuscation —
  mirrors Go's `first_packet_fuzz.go` / `session_fuzz.go`.

## 12. Key decisions log

| Decision | Choice | Reason |
|---|---|---|
| Scope | Full feature parity with Go Cloak, one spec | User's explicit choice over phased MVP |
| Wire compatibility | None — independent protocol | User's explicit choice |
| Concurrency model | Single-threaded epoll reactor | User's choice; simplest correct model for this workload on Linux-only |
| Crypto library | OpenSSL (libcrypto + libssl for CDN mode) | AES-NI support, ubiquity, one library covers both AEAD primitives and real TLS for CDN |
| Platforms | Linux only | Server is always Linux; drops the need for a portability layer |
| Event loop | Raw epoll (no libevent/libuv) | No external dependency needed once cross-platform portability is off the table |
| Frame/crypto format | Same design as Go Cloak | Already proven against DPI; no reason to invent a new scheme |
| ClientHello mimicry | Static captured byte templates | Simpler and more predictable than programmatic construction; same update burden as uTLS either way |
| User DB | SQLite | ACID, familiar SQL, good tooling; acceptable single added vendored dependency |
| Project location | Separate sibling repo `Cloak-c` | Independent implementation on a different language/architecture |
