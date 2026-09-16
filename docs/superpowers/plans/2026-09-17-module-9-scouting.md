# Module 9 scouting report — UDP / unordered mode

Written 2026-09-17 against `/Users/sam/Cloak` at `c3d5470` (= tag `v2.12.0`, verified: a
`--depth 1 --branch v2.12.0` clone resolves to the same commit hash as the local tree's HEAD) and
`/Users/sam/Cloak-c` at `bc7e936`, 68/68 passing.

Neither tree was modified. Probes live in `/tmp/scout9`. Where Go's `internal/` code is quoted it is
**copied verbatim from the source files named**, because `internal/` is not importable from outside
the module — that is what every code block attributed to a Go file below is.

The framing this report is written under is module 8's closing note: this port could not exchange a
single data frame with Go for five modules because both ends of every test were our own code, and
the four biases found afterwards were *distributions*, not semantics. Both of those classes are
live again here, and §6 names exactly where.

---

## 1. What is "unordered mode" in Go, exactly?

### 1.1 The flag's whole path, config inward

| Site | File:line | Effect |
|---|---|---|
| CLI flag | `cmd/ck-client/ck-client.go:54` | `flag.BoolVar(&udp, "u", false, "udp: set this flag if the underlying proxy is using UDP protocol")` |
| Config key | `internal/client/state.go:36` | `UDP bool // nullable`; `config_ssv` treats `UDP` as an unquoted (bool/number) key, `internal/client/state.go:86` |
| CLI→config | `cmd/ck-client/ck-client.go:125` | `rawConfig.UDP = udp` (standalone mode only; plugin mode never sets it) |
| config→auth | `internal/client/state.go:154` | `auth.Unordered = raw.UDP` |
| auth→wire | `internal/client/auth.go:44-46` | `if authInfo.Unordered { plaintext[41] \|= UNORDERED_FLAG }`, `UNORDERED_FLAG = 0x01` (`:12`) |
| wire→server | `internal/server/auth.go:49` | `Unordered: plaintext[41]&UNORDERED_FLAG != 0`, `UNORDERED_FLAG = 0x01` (`:30`) |
| server→session | `internal/server/dispatcher.go:195` | `Unordered: ci.Unordered` in the `mux.SessionConfig` |
| client→session | `internal/client/connector.go:71` | `Unordered: authInfo.Unordered` in the `mux.SessionConfig` |
| client data path | `cmd/ck-client/ck-client.go:192-198` | `if authInfo.Unordered { ... client.RouteUDP(...) } else { ... client.RouteTCP(...) }` |

The 48-byte authentication plaintext (`internal/client/auth.go:23-29`, verbatim):

```
+----------+----------------+---------------------+-------------+--------------+--------+------------+
|  _UID_   | _Proxy Method_ | _Encryption Method_ | _Timestamp_ | _Session Id_ | _Flag_ | _reserved_ |
+----------+----------------+---------------------+-------------+--------------+--------+------------+
| 16 bytes | 12 bytes       | 1 byte              | 8 bytes     | 4 bytes      | 1 byte | 6 bytes    |
+----------+----------------+---------------------+-------------+--------------+--------+------------+
```

Byte `[41]`, bit 0. Nothing else on the wire ever says "unordered" — see §6.1, this is the single
most important fact in the report.

### 1.2 What changes in the mux layer

**`grep -n Unordered internal/multiplex/*.go` (non-test) returns exactly three lines.** One is the
config field. The other two are the entire behavioural surface:

```go
// internal/multiplex/stream.go:58-62  (verbatim)
	if sesh.Unordered {
		stream.recvBuf = NewDatagramBufferedPipe()
	} else {
		stream.recvBuf = NewStreamBuffer()
	}
```

```go
// internal/multiplex/stream.go:127-137  (verbatim, inside Stream.Write)
		if len(in)-n <= s.session.maxStreamUnitWrite {
			// if we can fit remaining data of in into one frame
			framePayload = in[n:]
		} else {
			// if we have to split
			if s.session.Unordered {
				// but we are not allowed to
				err = io.ErrShortBuffer
				return
			}
			framePayload = in[n : s.session.maxStreamUnitWrite+n]
		}
```

That is all. **The session does nothing else differently. The switchboard does nothing differently
at all** (see 1.3). The frame layer does nothing differently (§1.5).

### 1.3 The switchboard: a documentation trap, already sprung upstream

`internal/multiplex/switchboard.go` still declares two strategies:

```go
const (
	fixedConnMapping switchboardStrategy = iota
	uniformSpread
)
```

but `makeSwitchboard` (`switchboard.go:40-51`) hardcodes `strategy: uniformSpread`. Commit
`5988b43 "Stop using fixedConnMapping"` (2024-04-14) deleted the `if sesh.Unordered` branch that
used to pick between them. **Since that commit, ordered and unordered sessions spread frames across
the connection pool identically — uniformly at random, per frame.** `fixedConnMapping` is dead code
and `Stream.assignedConn` is a vestigial field threaded through `obfuscateAndSend` →
`switchboard.send(data, &s.assignedConn)` for nothing.

The comment on `Stream.assignedConn` (`stream.go:37-42`) still says "When we want order guarantee
(i.e. session.Unordered is false), we assign each stream a fixed underlying connection… This is not
used in unordered connection mode." **That comment is false as of `5988b43`.** Do not port it, and
do not port `fixedConnMapping`.

The practical consequence is large and easy to miss: with `NumConn: 4` (the default), **ordered mode
genuinely needs its sorter heap on every connection**, because consecutive frames of one stream go
down four different TCP connections. Ordering is not "belt and braces over TCP" here; it is the only
thing holding the stream together.

### 1.4 The two receive buffers, side by side

`recvBuffer` is the interface both satisfy (`internal/multiplex/recvBuffer.go:12-19`, verbatim):

```go
type recvBuffer interface {
	// Read calls' err must be nil | io.EOF | io.ErrShortBuffer
	// Read should NOT return error on a closed streamBuffer with a non-empty buffer.
	io.ReadCloser
	Write(*Frame) (toBeClosed bool, err error)
	SetReadDeadline(time time.Time)
}
```

| Property | ordered (`streamBuffer` + `streamBufferedPipe`) | unordered (`datagramBufferedPipe`) |
|---|---|---|
| State | `nextRecvSeq uint64`, `sh sorterHeap` (`container/heap` of `*Frame`), a `bytes.Buffer` | `pLens []int`, a `bytes.Buffer`. **No sequence state at all.** |
| Uses `Frame.Seq` | yes — sorts, gap-fills, rejects `Seq < nextRecvSeq` with an error | **never reads it** |
| Duplicate frame | `fmt.Errorf("seq %v is smaller than nextRecvSeq %v")`, frame dropped | **accepted and delivered again** |
| Out-of-order frame | heap-buffered until the gap fills | **delivered immediately, out of order** |
| Read granularity | bytes (`buf.Read(target)` — takes as much as fits) | **one whole datagram**, `dataLen := d.pLens[0]` |
| Short read buffer | impossible (partial read) | `io.ErrShortBuffer`, **and the datagram is NOT consumed** (`datagramBufferedPipe.go:58-60` returns before `d.pLens = d.pLens[1:]` at `:62`) |
| Closing frame | `toBeClosed` only once it reaches `nextRecvSeq`; the pipe is closed later by `closeStream` | `d.closed = true` **immediately on arrival**, before any earlier data frame that is still in flight |
| Backpressure | blocks the writer while `buf.Len() > recvBufferSizeLimit` | same |
| `recvBufferSizeLimit` | `1<<31 - 1` (`recvBuffer.go:24`) — **2 GiB, i.e. no practical flow control in either mode** | same |

**Ordering guarantees dropped, precisely:** in-order delivery, duplicate suppression, and
ordered close. **Retransmission:** there is none in either mode — Cloak never retransmits; TCP
underneath does. **Sequence numbers:** still generated, still monotonic per stream, still on the
wire, still in the AEAD nonce — **only the receiver's use of them is dropped.** That asymmetry is
trap §6.1.

### 1.5 The frame layer: unchanged, bit for bit

`internal/multiplex/obfs.go`, `frameHeaderLength = 14` (`:15`):

```
offset  0..3    StreamID   uint32 BE
offset  4..11   Seq        uint64 BE
offset 12       Closing    uint8   (0 nothing / 1 stream / 2 session)
offset 13       extraLen   uint8   (padLen + tagLen)
offset 14..     payload ‖ padding ‖ tag
```

`maxExtraLen = 1<<8 - 1` (`:20`), `padFirstNFrames = 5` (`:24`),
`padLen = common.RandInt(maxExtraLen - tagLen + 1)` when `f.Seq < padFirstNFrames` (`:76-78`).
AEAD nonce is `header[:NonceSize()]` = StreamID‖Seq, AAD is **nil**. Salsa20 nonce is the last 8
bytes of the frame. **Not one of these depends on `Unordered`.** An unordered frame and an ordered
frame with the same field values are byte-identical.

### 1.6 The stream API to a caller, per mode

| | ordered | unordered |
|---|---|---|
| `Write(in []byte)` | splits `in` into `ceil(len/16132)` frames, always returns `len(in), nil` | **one frame or nothing**: `len(in) > maxStreamUnitWrite` ⇒ `(0, io.ErrShortBuffer)`, nothing sent |
| `Write(nil)` / `Write([]byte{})` | no-op, `(0, nil)` — **nothing goes on the wire** | identical; an empty UDP datagram is therefore silently swallowed (§6 measured) |
| `Read(buf)` | fills `buf` with as many reassembled bytes as are ready | returns **exactly one datagram**; `len(buf) < datagram` ⇒ `(0, io.ErrShortBuffer)` with the datagram still queued |
| `ReadFrom(r)` | loop of `r.Read(buf[14:14+16132])` → one frame each | identical code path; each `r.Read` on a UDP socket is one datagram, so boundaries survive |
| Close / deadline | identical | identical |

`maxStreamUnitWrite = MsgOnWireSizeLimit - frameHeaderLength - maxExtraLen`
(`session.go:111`) `= 16401 - 14 - 255 = `**`16132`** on both client (`internal/client/TLS.go:11`)
and server (`internal/server/TLS.go:16`). **The C port's `CLOAK_CLIENT_STACK_DEFAULT_MAX_ON_WIRE_SIZE`
is already 16401 and `cloak_stream_init` derives the same 16132**, so the numbers already agree.

### 1.7 The client's local end: `RouteUDP`

`internal/client/piper.go:15-100`. One `*net.UDPConn`; a `map[string]*mux.Stream` keyed by
`addr.String()`; per source address, one stream and one reader goroutine. Note the buffer sizes,
because §6 turns on them:

- `data := make([]byte, 8192)` (`:25`) — the **receive** buffer for the local socket.
- `buf := make([]byte, 8192)` (`:60`) — the **per-stream** buffer the reader goroutine reads into.
- `RouteTCP`'s equivalent is `10240` (`:114`). Neither is `16132`.

Stream lifetime is the `streamTimeout` read deadline, refreshed on every datagram in either
direction. There is no explicit flush of the map other than each goroutine deleting its own key.

---

## 2. Is this UDP on the wire, or unordered semantics over TCP?

**Settled, with evidence: the Cloak connection is always TCP. Nothing in Cloak ever opens a UDP
socket for its own traffic, in any supported configuration. Only the two ends of the tunnel — the
local proxy client's socket and the upstream proxy server's socket — are datagram sockets.**

Three hard citations, all unconditional (no `if Unordered` anywhere near them):

- Client dial: `internal/client/connector.go:29` — `remoteConn, err := dialer.Dial("tcp", connConfig.RemoteAddr)`.
  The literal `"tcp"` is in the source. `MakeSession` has no other dial.
- Server bind: `cmd/ck-server/ck-server.go:183` — `listener, err := net.Listen("tcp", bindAddr.String())`.
- Everything the session sends goes through `switchboard.send` → `conn.Write(data)` on one of those
  TCP conns.

`ProxyMethod` / `ProxyBook` is the **other** half, and it is orthogonal to `Unordered`:

```go
// internal/server/state.go:84-108 (parseProxyBook, verbatim excerpt)
		switch network {
		case "tcp":
			addr, err := net.ResolveTCPAddr("tcp", pair[1])
			...
		case "udp":
			addr, err := net.ResolveUDPAddr("udp", pair[1])
```

and `internal/server/dispatcher.go:291`:
`localConn, err := sta.ProxyDialer.Dial(proxyAddr.Network(), proxyAddr.String())` — the network comes
from the *ProxyBook entry*, not from `ci.Unordered`. So the shape is:

```
  app ──UDP──► ck-client :1984 ──TCP (×NumConn, TLS-record or WebSocket framed)──►
      ck-server :443 ──UDP (because ProxyBook["openvpn"][0] == "udp")──► openvpn
```

**Nothing negotiates the two halves against each other.** A client with `UDP: true` against a server
whose `ProxyBook` entry says `"tcp"` produces datagram-shaped frames spliced into a stream socket:
boundaries lost, no error anywhere. The reverse (`UDP: false` + a `"udp"` ProxyBook entry) produces
TCP byte-stream chunks each sent as one datagram: also silent. **This is Go's behaviour, measured
by reading; module 9 should decide deliberately whether to reproduce it or to refuse it, and say
which.** The C port's `cloak_proxy_prepare_session` already refuses *both* mismatches by refusing
both halves outright (§4), so today it is the stricter of the two.

Corollary worth stating in the plan: **"UDP mode" is a misnomer for the module.** What module 9
implements is (a) a datagram-preserving receive buffer in the mux layer, (b) a UDP local listener
with source-address demultiplexing on the client, (c) a UDP upstream dial + datagram relay on the
server. None of it touches the Cloak transport, the ClientHello, the record framing, or the
WebSocket framing.

---

## 3. What already exists in the C port that this must plug into?

### 3.1 Interfaces

`libcloak-mux/include/cloak/stream.h` — `cloak_stream_t`:

```c
int  cloak_stream_init(cloak_stream_t *s, uint32_t id, const cloak_obfuscator_t *obfuscator,
                       size_t max_on_wire_size, size_t recv_capacity, size_t max_pending_frames,
                       cloak_stream_frame_sink_t sink, void *sink_userdata);
long cloak_stream_write(cloak_stream_t *s, const uint8_t *in, size_t in_len);
int  cloak_stream_send_closing(cloak_stream_t *s, uint8_t closing_type);
int  cloak_stream_feed_frame(cloak_stream_t *s, const cloak_frame_t *frame); /* 0 / 1 closed / -1 */
long cloak_stream_read(cloak_stream_t *s, uint8_t *out, size_t out_cap);     /* n / 0 / -1 EOF */
size_t cloak_stream_recv_available(const cloak_stream_t *s);
```

`cloak/session.h` — `cloak_session_init` + a `cloak_session_config_t` carrying
`max_on_wire_size`, `stream_recv_capacity`, `stream_max_pending_frames`, `conn_send_queue_cap`,
`inactivity_timeout_ms`, four callbacks (`on_new_stream`, `on_broken`, `on_writable`,
`on_stream_data`) and a borrowed `valve`. Streams are created by `cloak_session_open_stream` or
implicitly by `session_on_envelope` on a first frame for an unknown `stream_id`.

`cloak/switchboard.h` / `cloak/conn.h` — `cloak_switchboard_send` picks a connection uniformly at
random (matching Go post-`5988b43`); `cloak_conn_t` owns framing.

`cloak/stream_relay.h` — `cloak_stream_relay_t` splices one `cloak_stream_t` with one `fd`, in bytes,
with a `cloak_bytequeue_t to_fd` and a per-read budget taken from
`cloak_session_send_min_conn_free`.

### 3.2 Where ordering is enforced today — every site

All in `libcloak-mux/src/stream.c` unless noted:

| Site | Line | What it does |
|---|---|---|
| `cloak_stream_t::next_recv_seq` | `stream.h:57` | the receive cursor |
| `cloak_stream_t::heap / heap_len / heap_cap / max_pending_frames` | `stream.h:58-61` | the reorder min-heap |
| `heap_push` / `heap_pop` / `heap_grow` | `stream.c:7-71` | the heap itself |
| `heap_contains_seq` | `stream.c:73-80` | **O(n) duplicate scan** |
| `try_drain` | `stream.c:88-110` | `while (heap[0].seq == next_recv_seq)`; `next_recv_seq++` |
| dup / late rejection | `stream.c:229-231` | `if (frame->seq < s->next_recv_seq \|\| heap_contains_seq(...)) return -1;` |
| every inbound frame goes through the heap | `stream.c:262` | `heap_push(...)` then `try_drain` — **even an in-order frame** |
| byte-oriented receive queue | `stream.h:56`, `stream.c:100-107` | `cloak_bytequeue_t recv_bytes` — boundaries destroyed on write |
| byte-oriented read | `stream.c:268-277` | `cloak_bytequeue_read(&s->recv_bytes, out, out_cap)` |
| write splitting | `stream.c:152-180` | `chunk = remaining <= max_payload_per_frame ? remaining : max_payload_per_frame` — **splits**, where unordered Go refuses |
| session reacts to `-1` by killing the stream | `session.c:322-337` | `session_retire_stream` on a protocol violation |
| relay is a byte splice | `stream_relay.h:107-112` | `cloak_bytequeue_t to_fd` |
| listener is stream-only | `libcloak-common/src/listener.c:165`, `:198`, `:99` | `hints.ai_socktype = SOCK_STREAM`; `listen(fd, 128)`; `accept4` |
| proxy upstream is stream-only | `libcloak-server/src/proxy.c:634-640` | refuses `socktype != SOCK_STREAM` |

### 3.3 Change versus add

**Add, do not change:**

- A **datagram receive buffer**. `cloak_bytequeue_t` cannot carry boundaries; the C analogue of
  `pLens []int` is a small ring of lengths beside the existing byte ring, or a second type
  (`cloak_msgqueue_t`). Prefer a second type with the same read/write/close/eof/len/free_space
  shape, selected by a union or a function-pointer pair inside `cloak_stream_t`, so `stream.c`'s
  heap code is *not compiled into* the unordered path at all. A `mode` branch inside `try_drain`
  would leave the dup-rejection and the heap reachable from unordered frames, which is exactly the
  divergence in §6.3.
- A **UDP local listener** on the client: `cloak_listener_open` cannot be reused (it calls
  `listen()` and `accept4()`). Unordered needs one `SOCK_DGRAM` fd registered with the reactor plus
  a `peer-addr → stream` table — the C equivalent of Go's `map[string]*mux.Stream`.
- A **datagram relay**: one datagram in, one `cloak_stream_write` out; one `cloak_stream_read` in,
  one `sendto` out. `cloak_stream_relay_t` cannot be reused for the client's side (its `fd` is a
  connected stream socket and its `to_fd` queue is byte-shaped), but it *can* on the server's side
  if the upstream UDP socket is `connect()`ed — which `cloak_dial_start` already does correctly for
  `SOCK_DGRAM` (`dial.c:170-188`: `connect()` returns 0 immediately and the "completed immediately
  (loopback, or a datagram socket)" path already exists and is already commented for this case).

**Change:** `cloak_stream_write`'s splitting (must become a refusal in unordered mode, to match
`io.ErrShortBuffer`), and the three refusal sites in §4.

### 3.4 Does the module-8 framing precedent apply? **Yes, and it is the single best structural idea
available for module 9.**

`cloak_conn_framing_t` (`conn.h:167-172`):

```c
typedef enum {
    CLOAK_CONN_FRAMING_INVALID    = 0, /* deliberate: an un-updated call site FAILS */
    CLOAK_CONN_FRAMING_TLS_RECORD = 1,
    CLOAK_CONN_FRAMING_WS_CLIENT  = 2,
    CLOAK_CONN_FRAMING_WS_SERVER  = 3
} cloak_conn_framing_t;
```

with `CLOAK_CONN_ERR_INVALID_FRAMING (-2)` distinct from `-1` so a test can assert *the diagnosis*,
and the header's own argument for why it is a **field** rather than a parameter: "A mode passed only
as an argument has no zero value unless a caller types one, so it protects nothing; a mode that is a
field of `cloak_conn_config_t` has one on every memset."

The identical argument holds here, and the identical blindness: **a C↔C test passes whichever
ordering mode both ends use.** Recommendation for the plan:

```c
typedef enum {
    CLOAK_SESSION_ORDERING_INVALID   = 0, /* an un-updated call site FAILS construction */
    CLOAK_SESSION_ORDERING_ORDERED   = 1,
    CLOAK_SESSION_ORDERING_UNORDERED = 2
} cloak_session_ordering_t;
```

as a **field of `cloak_session_config_t`**, with a distinct error code, and `cloak_stream_init`
taking it too. Note the cost that must be paid honestly and priced into the task list: **every
existing `cloak_session_config_t` and `cloak_stream_init` call site must be updated**, in
`libcloak-client/src/client_stack.c`, `libcloak-server/src/proxy.c`, `libcloak-server/src/registry.c`
and roughly 15 test files. That is the point — it is what makes forgetting impossible. Do not add an
`int unordered` that defaults to 0, because 0 is then a valid mode and the mechanism protects
nothing. (`cloak_session_add_conn` / `cloak_session_add_conn_framed` is the precedent for *not*
doing a defaulted overload: the zero-value discipline is what module 8 bought.)

---

## 4. Where does the C port already refuse this? — the exact removal list

Five sites, plus two headers of prose that pin them. **The plan must remove precisely these and
nothing else**, and must update the prose in the same commit, because module 8's lesson is that a
comment asserting a measurement needs a test behind it or an admission.

1. **`cmd/ck-client/main.c:758-764`** — the `-u` flag refusal:
   ```c
   if (args.udp) {
       fprintf(stderr, "ck-client: -u selects unordered (datagram) mode, which this build does "
               "not implement; it is refused rather than silently carrying TCP under a "
               "caller that asked for UDP\n");
       return CK_EXIT_USAGE;
   }
   ```
2. **`cmd/ck-client/main.c:863-868`** — the config-key refusal, deliberately a *different* exit code:
   ```c
   if (cfg.udp) {
       CLOAK_LOGE("configuration error in %s: \"UDP\": true selects unordered (datagram) "
                  "mode, which this build does not implement", source);
       return CK_EXIT_CONFIG;
   }
   ```
3. **`cmd/ck-client/main.c:206`** — the usage line
   `"  -u    udp: NOT IMPLEMENTED -- unordered mode is not in this build\n"`, which must become Go's
   own wording: `"udp: set this flag if the underlying proxy is using UDP protocol"`.
4. **`libcloak-server/src/proxy.c:609-611`** — the session-layer guard:
   ```c
   if (info->unordered) {
       return -1;
   }
   ```
5. **`libcloak-server/src/proxy.c:634-640`** — the ProxyBook guard:
   ```c
   if (upstream->socktype != SOCK_STREAM) { ... return -1; }
   ```

Prose that pins them and must move with them:

- **`cmd/ck-client/main.c:96-103`** — the "`-u` IS REFUSED" block in the file header.
- **`libcloak-server/include/cloak/proxy.h:545-575`** — reasons 1 and 3 of
  `cloak_proxy_prepare_session`'s four-case list. Reason 1 contains a claim the plan should re-verify
  rather than inherit: *"Checking only here, on the CREATE path, is the complete check… an additional
  connection joining an already-ordered session never reaches this callback at all and its own flag
  is meaningless."* That is true of Go (`user.GetSession` returns the existing session and
  `seshConfig` is discarded for it) and it stays true — but once unordered is implemented, **a second
  connection whose flag disagrees with the live session's silently joins it.** That is a real
  cross-mode hazard that today's refusal hides.
- **`docs/superpowers/plans/2026-09-16-cloak-binaries-plan.md:220`, `:229`, `:352`** — the three
  prose lines declaring `-u` out of scope.

**There is no config validation to remove.** `libcloak-common/src/config_client.c:194-195` parses
`"UDP"` into `cfg->udp` and validates nothing; `config_ssv.c:10` already lists `UDP` among the
unquoted keys, matching Go's `internal/client/state.go:86`. Both are correct as they stand.

**And one gap that is not a refusal at all, which the plan must state:**
`libcloak-client/src/client_stack.c:460` already does `cc.unordered = c->udp;`, which flows to
`client_connector.c:495` → `:360` → `client_transport.c:467` → `client_auth.c:81` and sets wire bit
`[41]&0x01`. **So a library consumer of `libcloak-client` can today bring up a session that
*advertises* unordered to the server while running the ordered data path.** Only the `ck-client`
binary refuses. The server refuses to serve it (site 4), so it fails closed — but it fails at the
*peer*, not at construction, and against a **Go** server it would not fail at all: the Go server
would happily build an unordered session and the C client would feed it split, sequenced frames that
the Go server's `datagramBufferedPipe` would hand to the openvpn socket as separate datagrams, in
whatever order they arrived. **This is reachable today and is worth a test in module 9's first
task**, because it is precisely a defect that only a foreign peer can see.

Tests that pin the refusals and must be rewritten, not deleted:
`cmd/ck-client/tests/test_ck_client_cli.c:1007-1040` (`test_udp_is_refused`, asserting both exit
codes and the word "unordered" in both messages), and its file-header case 4 at `:27-30`.

---

## 5. What will fight us? — the reactor

The reactor is single-threaded and edge-triggered (`cloak/reactor.h:35-41`: "Registration is
edge-triggered: cb fires once per readiness transition… a blocking fd combined with the
edge-triggered read-until-EAGAIN"). Go's `RouteUDP` is a blocking `ReadFrom` loop plus one goroutine
per peer with a blocking `stream.Read`. Both become one callback.

**Buffering.** Unordered *removes* the reorder heap but *adds* a boundary-preserving queue. Net
memory is similar; the shape is different. `cloak_bytequeue_t`'s `free_space` check in `try_drain`
(`stream.c:99-101`) has an exact analogue: a datagram either fits whole or waits whole. **A
half-written datagram is not a legal state**, so the queue's admission test must be
`free_space >= payload_len`, never a partial write. `cloak_stream_init` already rejects
`recv_capacity < max_on_wire_size - CLOAK_FRAME_HEADER_LEN` for exactly this reason on the ordered
side ("too small to ever hold this stream's own largest possible frame payload, which would
otherwise let a single oversized frame wedge the stream permanently") — the same bound, for the same
reason, is mandatory in the datagram queue, and the length ring must be sized so it cannot be the
thing that overflows first.

**Out-of-order arrival.** With `uniformSpread` and `NumConn > 1`, out-of-order arrival is the normal
case, not an edge case. In unordered mode the correct action is simply "deliver now". The trap is
that the C port's `cloak_stream_feed_frame` currently *errors* on `seq < next_recv_seq` and the
session *retires the stream* on that error (`session.c:322-337`). In unordered mode Go accepts that
frame. **If the unordered path reaches that check at all, a reordered or duplicated frame kills a
stream that Go keeps alive.** Both ends of a C↔C test agree (our sender never duplicates); Go does
not. §6.3.

**A frame for a stream that has not been created yet** is already handled and is already the normal
way the server learns about streams: `session_on_envelope` (`session.c:349-401`) mallocs an entry,
`cloak_stream_init`s it, `cloak_strmtab_insert_active`, `active_stream_count++`, feeds the revealing
frame, **then** fires `on_new_stream`. The ordering (feed before callback) is required because
`on_new_stream` may call `cloak_session_release_stream`. Unordered changes nothing here except that
the revealing frame may have any `seq`, not necessarily 0 — **`next_recv_seq` starts at 0 and the
unordered path must not care.** Note also `cloak_strmtab`'s tombstone: a late frame for a closed
stream is dropped (`session.c:314-317`), matching Go's `sesh.streams[id] = nil` sentinel. That stays
correct in unordered mode and is more load-bearing there, because unordered close is not ordered
(§1.4) so late frames are *expected*.

**Datagram boundary versus the existing framing modes.** There is no interaction, and saying so
crisply avoids a design mistake. The tunnel's boundary hierarchy is:

```
TLS_RECORD:  [5-byte record header][ one mux frame ]
WS_CLIENT:   [2 or 4 byte header][4-byte mask][ one mux frame ]   (one WS message == one mux frame)
WS_SERVER:   [2 or 4 byte header][ one mux frame ]
mux frame:   [14-byte header][ payload ‖ padding ‖ tag ]
payload:     unordered ⇒ exactly one application datagram; ordered ⇒ an arbitrary byte run
```

`cloak_conn_t` already reassembles a fragmented WebSocket message into exactly one mux frame
(`conn.h:192-196`), so the datagram boundary rides entirely inside the mux payload and is invisible
to both framing modes. **`unordered` and `framing` are fully orthogonal, and Go allows the cross
product** — `Transport: "cdn"` with `UDP: true` is a legal Go client config. The C port cannot test
that cross product because module 8b (the client's CDN leg) is deferred; say so rather than implying
coverage.

**One genuinely new reactor problem.** The client's UDP listener is a *single* fd serving *many*
peers, so edge-triggered read-until-EAGAIN must drain every pending datagram in one callback, and
a peer whose stream is backpressured cannot be allowed to stall the socket for every other peer. Go
does not face this: it reads one datagram, does a blocking `stream.Write`, and loops. The C port's
options are (a) drop the datagram when the session's `send_min_conn_free` cannot take a whole frame
— which is what UDP semantics permit and what a datagram transport should do, or (b) queue per-peer.
**(a) is the right answer and it is a deliberate, wire-visible divergence from Go**, which blocks;
it must be declared, not discovered.

**Two smaller frictions.** Go's per-peer read deadline (`stream.SetReadDeadline(now+streamTimeout)`
refreshed on every datagram in both directions, `piper.go:56,66,95`) becomes a reactor timer per
peer entry; the existing `cloak_client_piper_t` already has per-context deadlines to copy. And Go's
`RouteUDP` never expires the map itself — only each goroutine deleting its own key — so a C port
with a hash table needs an explicit eviction that Go gets for free from goroutine exit.

---

## 6. Where are the traps?

### 6.1 The mode is invisible on the wire. **This is the headline.**

Per §1.5, an unordered frame is byte-identical to an ordered one. The *only* wire evidence of the
mode is bit 0 of byte 41 of the 48-byte auth plaintext, inside AES-256-GCM inside the ClientHello.
Consequences:

- **An interop test that checks "the datagrams arrive" cannot distinguish an unordered session from
  an ordered one at all.** If the C client sent ordered-mode frames while advertising unordered, a
  Go server would reassemble them into datagrams via `datagramBufferedPipe` anyway and the test
  would pass — because our sender happens never to split, never to duplicate, and never to reorder.
  The divergence only appears under `NumConn > 1` with real reordering, or with a payload > 16132.
- The corollary test that *does* see it: assert that `plaintext[41] == 0x01` for a UDP client and
  `0x00` otherwise, against a **Go server's** parse, and separately assert the **negative** — a
  client that sets the bit and then splits a 20000-byte write into two frames must be caught. Go
  catches it by returning `io.ErrShortBuffer`; a C port that "helpfully" split would be silently
  wrong. `cloak_stream_write` splits today (`stream.c:160-161`).

### 6.2 Sequence numbers: the most dangerous available "optimisation"

The unordered receiver ignores `Seq` entirely. The unordered **sender must not.** `Seq` does three
things that survive:

1. It is **half the AEAD nonce** (`header[:NonceSize()]` = StreamID‖Seq, `obfs.go:105`). A sender
   that pinned `Seq = 0` in unordered mode — a plausible, defensible-looking simplification, since
   nothing reads it — would **reuse the GCM nonce for every frame of a stream under a fixed session
   key**. That is a catastrophic, silent, *cryptographic* break, and **a C↔C round-trip test passes
   perfectly.**
2. It gates padding: `if f.Seq < padFirstNFrames` (`obfs.go:76`). `Seq = 0` forever ⇒ *every* frame
   padded ⇒ a wire-visible length distribution nothing like Go's.
3. It is what an eventual replay or reordering defence would key on.

So: **assert, in a test, that consecutive frames from one unordered stream carry strictly increasing
`Seq`, and that frame 6 of a stream is unpadded.** Neither is observable end to end.

### 6.3 Behaviours where both C ends would agree and Go would not

| # | Divergence | Why a C↔C test cannot see it |
|---|---|---|
| a | Splitting a write larger than 16132 instead of returning short-buffer | our receiver reassembles happily; Go's would deliver two datagrams |
| b | Rejecting a duplicate or late `seq` (`stream.c:229-231`) and retiring the stream | our sender never duplicates; a Go peer over 4 conns will |
| c | Honouring a closing frame only once it reaches `next_recv_seq` | our sender sends close last; Go's unordered close fires on arrival |
| d | Preserving `Seq` ordering semantics anywhere in the unordered path | nothing in a C↔C test reorders |
| e | Delivering a zero-length datagram | Go's `Stream.Write` with `len == 0` sends nothing at all (measured, §6.6) — a C port that framed an empty payload would produce a frame Go's `obfuscate` refuses to even construct (`errors.New("payload cannot be empty")`) |
| f | Buffer sizes 8192 / 8192 on the client's local socket | invisible unless a test sends a datagram above 8192 (measured, §6.6) |

### 6.4 Distributions, not semantics — the module-8 class

Grep every random draw the unordered path touches, and note that **the padding draw is the same
code** the `b % 240` bug lived in, so it is already fixed and must stay fixed:

- Frame padding: `common.RandInt(maxExtraLen - tagLen + 1)`. The C port rejection-samples after
  module 8. **Unordered does not change this — but it changes *which frames get padded*, because a
  datagram session's streams are short-lived (one per peer address) and `padFirstNFrames = 5`
  applies per stream.** A UDP client with many peers therefore pads a far higher *fraction* of its
  traffic than a TCP one. Any C-side caching or reuse of `seq` across peers would change that
  fraction. Worth one distribution test: over N single-datagram streams, the padded fraction should
  be 1.0, and the pad-length histogram uniform over `[0, 255-tagLen]`.
- Closing-frame padding: `padLen := int(tmpBuf[0]) + 1`, uniform over 1..256. Same in both modes.
  `cloak_stream_send_closing` clamps to `max_payload_per_frame`, which at 16132 never bites —
  **but on a small `max_on_wire_size` it does, and the clamp is not uniform.** It is already
  documented; unordered does not worsen it. Do not "fix" it into a divergence.
- Switchboard connection pick: `randReader.Uint32N(connsCount)` on a ChaCha8 pool
  (`switchboard.go:45-49, 115`). Go's `Uint32N` is unbiased; check the C port's equivalent is too,
  since unordered traffic exercises it per-datagram rather than per-16 KiB chunk and a bias is a
  per-connection load skew a censor can measure.
- **No new random draws are introduced by unordered mode.** Say so explicitly, so the next reviewer
  does not go looking.

### 6.5 Timeouts and buffer sizes to pin as literals

- `maxStreamUnitWrite` = 16132 (`= 16401 - 14 - 255`). Already matched.
- `connReceiveBufferSize` = 20480 (`session.go:113`, "for backwards compatibility"). Not
  mode-dependent.
- `recvBufferSizeLimit` = `1<<31 - 1` (`recvBuffer.go:24`) — **Go has no real receive flow control in
  either mode.** The C port uses a real finite `recv_capacity` and says so in `stream.h`. In ordered
  mode the difference is backpressure timing; **in unordered mode it is packet loss**, because a
  full datagram queue must drop rather than block. Declare the drop policy.
- Client local socket: `8192` receive (`piper.go:25`) and `8192` per-stream (`piper.go:60`). Neither
  is 16132. §6.6.
- `defaultInactivityTimeout` = 30 s (`session.go:19`); `StreamTimeout` default 300 s. Unchanged.

### 6.6 A sixth and seventh bug in the Go original, both reproduced at the built binaries

Measured in the dev image against **real upstream `ck-client` and `ck-server` built from
`v2.12.0`**, with a C UDP echo as the upstream proxy and a C UDP client as the application, config
`ProxyBook {"openvpn": ["udp","127.0.0.1:8389"]}`, `NumConn: 4`, `UDP: true`. Harness in
`/tmp/scout9/h/`.

**Bug 6 — a reply datagram of 8193..16132 bytes is lost *and* kills the peer's stream.**

The Cloak server's `Stream.ReadFrom` reads up to `maxStreamUnitWrite` = **16132** bytes per datagram
from the upstream (`stream.go:154`). The Cloak client's reader goroutine reads into
`buf := make([]byte, 8192)` (`piper.go:60`). `datagramBufferedPipe.Read` returns `io.ErrShortBuffer`
when `len(target) < dataLen` (`datagramBufferedPipe.go:58-60`) **without consuming the datagram**,
the goroutine breaks on the error, and the stream is actively closed.

Measured, one socket, one 5-tuple, `-verbosity trace`:

```
SEND 16       -> [16] RECV 16                          stream 1: "16 read from stream 1 with err <nil>"
SEND BIG:8192 -> [BIG:8192] RECV 8192                  stream 1: "8192 read from stream 1 with err <nil>"
SEND BIG:8193 -> [BIG:8193] (no more)                  stream 1: "0 read from stream 1 with err short buffer"
                                                       "copying stream to proxy client: short buffer"
                                                       "stream 1 actively closed."
SEND 17       -> [17] RECV 17                          stream 2 opened
```

8192 works; 8193 is lost with **no error visible to the application**, and the tunnel state for that
peer is torn down and silently rebuilt on the next datagram. For OpenVPN — the ProxyBook example
Cloak ships — this is a real-world reachable size.

**Bug 7 — an outbound datagram larger than 8192 is silently truncated.**

`RouteUDP`'s `data := make([]byte, 8192)` + `localConn.ReadFrom(data)` (`piper.go:25,27`): Go's UDP
`ReadFrom` discards the excess and reports no error. Measured:

```
SEND 8192 -> echo saw 8192,  app got 8192 back
SEND 8193 -> echo saw 8192,  app got 8192 back        <- 1 byte silently deleted
SEND 20000 -> echo saw 8192, app got 8192 back        <- 11808 bytes silently deleted
```

Silent application-visible data corruption, with 16132 bytes of protocol budget going unused.

**A third, smaller one — an empty datagram is swallowed.** `Stream.Write` with `len(in) == 0` runs
its `for n < len(in)` loop zero times and returns `(0, nil)`; nothing goes on the wire. Measured: a
0-byte datagram at the client produced nothing at the echo server, and the following 18-byte
datagram worked normally. Legal and meaningful in several UDP protocols.

**Recommendation.** Fixing bug 7 in the C port (reading up to 16132, or up to 65507 and refusing
above 16132 with an explicit log) is a *wire-visible* divergence from Go — the C client would emit a
frame Go's client never emits. Fixing bug 6 (reading into a 16132-byte buffer) is a *local*
divergence with no wire effect at all and is strictly safer than Go. **Take bug 6's fix; take bug 7's
fix only with an explicit declaration, and pin both with tests against the Go binaries so the
divergence is measured rather than assumed.** These are Cloak bugs 6, 7 and 8 found by this port.

### 6.7 One more Go oddity, not a bug: the dead strategy

`fixedConnMapping` and `Stream.assignedConn` (§1.3) are dead since `5988b43`, and `stream.go:37-42`'s
comment about them is stale. A port that reproduced them would be reproducing 2024 Cloak, not
today's. The C port already omits both — **record that this omission is deliberate and correct**,
because a future reader comparing the trees will find `assignedConn` missing and may "restore" it.

---

## 7. How would you test it?

### 7.1 The Go-binary oracle: cost claim verified, and it is cheaper than module 8 estimated

Module 8's claim was "13 modules and 114 MB of cache into ~10 MB binaries… one `go mod download`
line in `Dockerfile.dev` plus one test file". **Measured in `cloak-c-dev` (go1.25.6 linux/arm64):**

| Quantity | Measured |
|---|---|
| Modules downloaded to build both binaries | **10** (11 module paths counting `github.com/cbeuw/Cloak` itself) — module 8 said 13 |
| Module cache after a build-only fetch | **114 MB** — exactly as claimed |
| Module cache after `go mod download` (all, incl. test deps) | 142 MB, 37 modules in `go list -m all` |
| `ck-client` | **9,806,033 bytes (9.35 MiB)** |
| `ck-server` | **10,259,237 bytes (9.78 MiB)** |
| Cold: fetch + compile both | **21.8 s** |
| `go mod download` alone (cold, network) | 13.2 s |
| Compile both from a warm module cache, cold build cache | **9.2 s** |
| Warm rebuild of one binary after touching its `main` | **0.14 s** |
| No-op rebuild | 0.12 s |
| Go build cache after | 124 MB |

**The claim holds.** One correction and one addition:

- **`go install github.com/cbeuw/Cloak/cmd/ck-client@v2.12.0` does not work**, and the plan must not
  assume it does. Cloak's `go.mod` declares `module github.com/cbeuw/Cloak` with no `/v2` suffix, so
  `v2.x` tags are `+incompatible` and are **not served by proxy.golang.org** (measured:
  `https://proxy.golang.org/github.com/cbeuw/!cloak/@v/list` returns only `v0.x` and `v1.x`). Go
  falls back to direct VCS and fails with `exec: "git": executable file not found in $PATH`, since
  the dev image has no git.
- **The cheapest correct recipe is a multi-stage build fetching the release tarball with the `curl`
  that is already in the image** — no git, no Go source in this repository, zero copied lines:

  ```dockerfile
  FROM debian:bookworm-slim AS ...   # existing stage, renamed
  ...
  FROM <existing image> AS gobuild
  ARG CLOAK_UPSTREAM=v2.12.0
  RUN mkdir -p /tmp/up \
   && curl -fsSL "https://github.com/cbeuw/Cloak/archive/refs/tags/${CLOAK_UPSTREAM}.tar.gz" \
      | tar -xz -C /tmp/up --strip-components=1 \
   && cd /tmp/up \
   && go build -o /out/go-ck-client ./cmd/ck-client \
   && go build -o /out/go-ck-server ./cmd/ck-server

  FROM <existing image>
  COPY --from=gobuild /out/go-ck-client /out/go-ck-server /usr/local/bin/
  ```

  **Measured: image 980 MB → 1.01 GB, i.e. +30 MB, 22.5 s of image build.** A single-stage variant
  that clones with git and leaves the caches behind costs **+450 MB** (measured: 1.43 GB) — take the
  multi-stage one. The binaries are then present at a fixed path at *test* time with no Go step in
  CMake at all, which is simpler than module 8's build-time `add_custom_command` and removes the
  oracle from the build's critical path entirely. The existing `CLOAK_REQUIRE_GO` machinery is for
  the *source* oracle (`ws_interop_oracle`) and stays as it is.
- Verified the tag is the right one: `v2.12.0` == `c3d5470ef76bba68d7812f5d06e4181dc1b1a5d6` ==
  `/Users/sam/Cloak` HEAD. Pin the tag, not a branch.
- One wart to expect: the binaries are built without upstream's `-ldflags -X main.version=`, so
  `go-ck-client -v` prints `ck-client ` with an empty version. Harmless; do not assert on it.

### 7.2 What the oracle covers, and what it does not

**Covers** (this is the first coverage the direct path and the C client have ever had against
foreign code): ClientHello construction and placement, the 5-byte record header, the ServerHello
reply, the ECDH + AES-GCM auth payload including **byte 41**, session key agreement, the frame
header layout, the Salsa20 header encryption, the AEAD (nil AAD — the defect module 8 found), stream
open/close, closing-session frames, `ProxyMethod`/`ProxyBook` routing, and — new here — the whole
unordered data path in both directions.

Both roles are worth running, and they cover different things:
- **Go client → C server**: exercises our ClientHello *parser*, our auth decrypt, our
  `datagramBufferedPipe` equivalent, our UDP upstream dial and datagram relay.
- **C client → Go server**: exercises our ClientHello *generator*, our bit 41, our frame generator,
  our UDP local listener — and, uniquely, whether our sender obeys the no-split rule, because Go's
  receiver is the only thing that will notice.

**Does not cover**, and the plan must say so:
- Distributions of any kind (padding length, pad/no-pad boundary at seq 5, SNI choice, connection
  pick). §6.4. Module 8's whole lesson.
- Sequence-number generation, since the unordered receiver ignores it (§6.2). **The nonce-reuse
  disaster is completely invisible to the oracle.**
- Real reordering: over loopback with `NumConn: 4`, frames essentially never arrive out of order, so
  the property the mode exists for is never exercised. Needs deliberate injection.
- The CDN leg of the client (module 8b, deferred), hence the `unordered × WebSocket` cross product.
- Anything about a real network: MTU, fragmentation, NAT rebinding of the local peer address.

### 7.3 How unordered should be tested on top of it

1. **Byte 41, both directions.** C client's auth plaintext parsed by a Go server; Go client's parsed
   by ours. Assert the bit, and assert the negative (ordered ⇒ 0).
2. **Datagram boundary fidelity, both roles.** Send a size ladder — 1, 2, 1500, 8191, 8192, 8193,
   16131, 16132, 16133 — and assert the *exact* received sizes, not just arrival. **This is the test
   that would have caught Go's bugs 6 and 7, and it is the test that catches a C port that splits.**
   Expect asymmetric results against Go and document each one as measured behaviour.
3. **Sequence monotonicity and the padding boundary**, observed at the *frame* level with our own
   deobfuscator on a captured connection, not end to end. Assert `seq` strictly increasing per
   stream and frame index 5 unpadded. No oracle; pure white-box. **Name this as an unoracled
   property in the plan.**
4. **Deliberate reordering.** A middle-box harness that buffers frames from two connections and
   releases them reversed. Unordered must deliver both, in arrival order; ordered must deliver them
   sorted. This is the only test that proves the mode does anything at all.
5. **Duplicate and late frames.** Replay a captured frame. Unordered must accept it (Go does);
   ordered must drop it. Today's `cloak_stream_feed_frame` would retire the stream — §6.3b.
6. **Empty and oversize writes.** `cloak_stream_write(s, NULL, 0)` and a 20000-byte write in
   unordered mode: the latter must refuse, matching `io.ErrShortBuffer`, not split.
7. **The mixed-mode hazard from §4**: a `libcloak-client` consumer setting `udp = 1` today
   advertises unordered and sends ordered frames. Pin whatever module 9 decides that should do.
8. **The mode enum's zero value** must fail construction with a distinct error code, asserted
   directly — the module-8 precedent (`CLOAK_CONN_ERR_INVALID_FRAMING`) exists because "any non-zero
   return" would pass against an implementation that never looked at the field.

### 7.4 Properties with no oracle at all — carry these forward explicitly

- Every distribution (§6.4).
- Sequence-number generation and therefore AEAD nonce uniqueness (§6.2).
- The drop-versus-block policy for a backpressured datagram queue (§5) — Go blocks, we must drop, and
  no test against Go can adjudicate that. It is a declared divergence.
- Peer-map eviction on the client.
- The cross product with WebSocket framing, until 8b exists.

---

## 8. How big is this, and in what order?

### 8.1 Shape

Roughly **6 new/changed source files and ~10 test files**. Estimated tasks:

| # | Task | Risk |
|---|---|---|
| 0 | **Fast/slow `ctest` split.** See 8.3. | none |
| 1 | **Go-binary oracle for the direct path** (multi-stage Dockerfile.dev + one test file driving real `ck-client` and `ck-server` in both roles, TCP/ordered only). Module 8 decided this; the cost is verified in §7.1. | low, and it may well find something before a line of module 9 is written |
| 2 | `cloak_session_ordering_t` enum + config field + distinct error code; update **every** call site (§3.4). Mechanical, wide, and the whole point. | low, high churn |
| 3 | Datagram receive queue (`cloak_msgqueue_t` or equivalent) + the unordered branch in `cloak_stream_t`: no heap, no dup check, no `next_recv_seq`, message-granular read, `ErrShortBuffer` analogue that does not consume. | medium |
| 4 | `cloak_stream_write` refuses rather than splits in unordered mode. | low |
| 5 | Client UDP local listener + peer→stream table + datagram relay + per-peer deadline. **No existing component is reusable**; `cloak_listener_open` is `listen()`/`accept4()`. | **highest** |
| 6 | Server UDP upstream: remove the two `proxy.c` guards, datagram relay against the already-working `SOCK_DGRAM` dial. | medium |
| 7 | Wire `ck-client -u` and `"UDP": true` through; rewrite `test_udp_is_refused` into `test_udp_is_honoured`; fix the usage line and the two header prose blocks. | low |
| 8 | Unordered oracle tests (§7.3 items 1–8), reordering harness, distribution/monotonicity white-box tests. | medium |

### 8.2 Riskiest part, and why

**Task 5, the client's UDP listener, by a wide margin.** Every other task has a precedent in the
tree to copy. This one has none: a single edge-triggered fd multiplexing many peers, where one
peer's backpressure must not stall the others, where Go's model (goroutine per peer, blocking write)
does not translate, and where the correct behaviour under pressure — **drop, don't block** — is a
deliberate divergence from Go that no test against Go can validate. It is also where Go's own bugs 6
and 7 live (§6.6), so it is simultaneously the place where fidelity and correctness point in
different directions and the plan has to choose, in writing, for each of the three sizes.

Second-riskiest is **task 3's interaction with `cloak_stream_feed_frame`'s `-1` contract**: today a
`-1` retires the stream, and three of the six divergences in §6.3 route through that one return
value.

### 8.3 Should module 9 do the fast/slow `ctest` split first? **Yes — first, before task 1.**

Measured today, Debug, `-j4`, in the dev image: **68/68 in 23.1 s wall.** Slowest tests:

| Test | s |
|---|---|
| `test_adminapi` | 12.2 |
| `test_dispatcher_ws` | 12.0 |
| `test_ck_client_cli` | 8.1 |
| `test_client_connector` | 6.9 |
| `test_client_stack` | 4.2 |
| `test_dispatcher_limits` | 2.9 |

The top two alone are ~12 s each, so **the suite's wall-clock floor at `-j4` is already set by a
single test, not by the total.** Module 8's note that "the four slowest tests all fork processes"
is confirmed by the list. Module 9 adds *at least* two more forking tests, and the oracle tests fork
**two** foreign binaries plus a UDP echo each — they will land straight at the top of that table and
become the new floor. Doing the split as task 0 costs one CMake change and makes every subsequent
task's inner loop cheaper; doing it after task 8 means eight tasks of slow iteration and a split
designed around tests that already exist rather than the ones about to be added.

Concretely: label the forking tests `slow`, keep `ctest -L fast` as the edit-loop target, and make
the default `ctest` still run everything so the 68→N count stays part of the contract, exactly as
`CLOAK_REQUIRE_GO=OFF`'s visible 68→67 does.

---

## Appendix: probe artefacts

- `/tmp/scout9/measure2.sh`, `measure4.sh` — Go build cost measurements (§7.1).
- `/tmp/scout9/Dockerfile.probe2` — the multi-stage recipe measured at +30 MB.
- `/tmp/scout9/h/udpecho.c`, `udpsend.c`, `udpseq.c`, `run_udp.sh`, `run_udp2.sh` — the Go-to-Go
  UDP harness that reproduced bugs 6, 7 and the empty-datagram case (§6.6).
- Nothing was written to either repository other than this file.
