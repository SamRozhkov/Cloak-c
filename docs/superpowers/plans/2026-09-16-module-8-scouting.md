# Module 8 scouting report: the CDN / WebSocket transport

Read-only survey of `/Users/sam/Cloak` (cbeuw/Cloak, `go.mod` go 1.24,
`github.com/gorilla/websocket v1.5.3`) and `/Users/sam/Cloak-c` @ `7138056`.
Nothing in either tree was modified. Where a claim is measured rather than read,
the probe program is named and its output quoted; probes live in the session
scratchpad (`/private/tmp/claude-501/.../scratchpad/{wsprobe,wsprobe2,leakprobe}`)
and are outside both repositories.

Go `internal/` packages are not importable from outside the module, so where a
probe needed Cloak's own code (`leakprobe`) the relevant types were **copied
verbatim** out of `internal/server/websocketAux.go` lines 70-138 and
`internal/server/websocket.go` lines 44-50, with only the logrus call and the
`common.WebSocketConn` wrapper replaced. That is stated again at the point of
use.

---

## 1. What does Go actually do here?

### 1.1 The shape of it, before any bytes

The client's transport abstraction is three lines
(`/Users/sam/Cloak/internal/client/transport.go:7-10`):

```go
type Transport interface {
	Handshake(rawConn net.Conn, authInfo AuthInfo) (sessionKey [32]byte, err error)
	net.Conn
}
```

and the factory (`transport.go:20-33`) returns `&WSOverTLS{wsUrl: ...}` for mode
`"cdn"` and `&DirectTLS{browser: ...}` for `"direct"`. Both implement
`net.Conn`, and after `Handshake` returns, `connector.go:54` pushes the transport
object itself (`connsCh <- transportConn`) into `mux.Session.AddConnection`. So
**the transport object IS the framing layer for the data path** — the session
reads and writes through it, and its `Read`/`Write` decide what a "message"
means on the wire.

The critical structural fact, which drives everything else:

- `DirectTLS` embeds `*common.TLSConn` — its `Write` prepends a 5-byte TLS
  application-data record header, its `Read` strips one
  (`/Users/sam/Cloak/internal/common/tls.go:74-108`).
- `WSOverTLS` embeds `*common.WebSocketConn` and **nothing else**
  (`/Users/sam/Cloak/internal/client/websocket.go:16-19`). Its `Write` is one
  WebSocket **binary message**; its `Read` is one WebSocket binary message.
  There is **no TLS record header on the CDN data path at all** — the WebSocket
  frame header replaces it.

See §6.3; this is the single most dangerous thing in the module.

### 1.2 The outer layer: a real TLS session, always

`WSOverTLS.Handshake` (`internal/client/websocket.go:21-77`) starts by doing a
**genuine uTLS handshake**, not a synthetic ClientHello:

```go
utlsConfig := &utls.Config{ServerName: authInfo.MockDomain, InsecureSkipVerify: true}
uconn := utls.UClient(rawConn, utlsConfig, utls.HelloChrome_Auto)
err = uconn.BuildHandshakeState()
...
for i, extension := range uconn.Extensions {        // lines 31-37
	_, ok := extension.(*utls.ALPNExtension)
	if ok { uconn.Extensions = append(uconn.Extensions[:i], uconn.Extensions[i+1:]...); break }
}
err = uconn.Handshake()                              // line 39: a REAL handshake
```

Unconditionally, regardless of `RemotePort` and regardless of the `ws://` scheme
in the URL. `InsecureSkipVerify: true` — the certificate is not checked
(intentional: the CDN presents its own cert, and the Cloak authentication inside
is what actually authenticates the server). The ALPN extension is **surgically
removed** so the CDN cannot negotiate HTTP/2, which `gorilla` and `net/http`'s
`ReadResponse` could not speak. See §3.4 for why that removal is the loudest
fingerprint in this transport.

So the topology is asymmetric and that asymmetry is the whole module:

```
ck-client  --[ real TLS 1.2/1.3, Chrome-shaped ClientHello minus ALPN ]-->  CDN edge
                     (HTTP/1.1 WebSocket upgrade inside the TLS session)
CDN edge   --[ PLAINTEXT HTTP/1.1 WebSocket upgrade ]-->  ck-server (port 443/80)
```

The Cloak **server** never speaks TLS on this path. It recognises the connection
by its first byte being `'G'` (0x47) — `internal/server/dispatcher.go:100`.

### 1.3 The upgrade request: exact bytes

Measured with `wsprobe` (gorilla v1.5.3 `websocket.NewClient` over a `net.Pipe`,
the same call Cloak makes at `internal/client/websocket.go:52`, with the same
`hidden` header and the same 16480/16480 buffer sizes). Verbatim output:

```
GET /ws/path HTTP/1.1\r\n
Host: cdn.example.com:443\r\n
User-Agent: Go-http-client/1.1\r\n
Connection: Upgrade\r\n
Hidden: AAAA...(128 base64 chars)...AAAA\r\n
Sec-WebSocket-Key: VTYLSW9Clf1O0HAS1Fdpng==\r\n
Sec-WebSocket-Version: 13\r\n
\r\n
```

335 bytes for a 9-byte path. Field by field:

| Field | Value | Source |
|---|---|---|
| request line | `GET <CDNWsUrlPath> HTTP/1.1` | `u.Path` from `state.go:235`; `net/http` writes origin-form |
| `Host` | `u.Host`, **port included** | `client.go:196` `Host: u.Host`; built by `net.JoinHostPort` at `state.go:225/227` |
| `User-Agent` | `Go-http-client/1.1` | `net/http`'s `defaultUserAgent`, emitted because Cloak sets no `User-Agent` |
| `Connection` | `Upgrade` | `client.go:212`, exact capitalisation |
| `Hidden` | base64(96 bytes) | `websocket.go:51` — see below |
| `Sec-WebSocket-Key` | base64(16 CSPRNG bytes) | `client.go:213`, `util.go:26-32` (`crypto/rand`) |
| `Sec-WebSocket-Version` | `13` | `client.go:214` |
| `Upgrade` | `websocket` | `client.go:211` |

Header **order** is: `Host`, `User-Agent`, then everything else in Go's
`Header.writeSubset` sorted-key order (`Connection` < `Hidden` <
`Sec-WebSocket-Key` < `Sec-WebSocket-Version` < `Upgrade`). No `Origin`, no
`Sec-WebSocket-Protocol`, no `Sec-WebSocket-Extensions`, no `Accept-Encoding`,
no `Cookie`.

Note the capitalisation of `Hidden`: Cloak writes
`header.Add("hidden", ...)` (`websocket.go:51`) and `http.Header.Add`
canonicalises the key to `Hidden`, so `Hidden:` is what goes on the wire.
The server reads `req.Header.Get("hidden")` (`internal/server/websocket.go:30`),
which canonicalises the *lookup* the same way — and `http.ReadRequest`
canonicalises incoming names too. **Matching is effectively case-insensitive in
Go; a C implementation must be explicitly case-insensitive on both sides**
(§3.3).

### 1.4 The auth payload, carried as a header instead of a ClientHello

Direct-TLS mode smuggles the payload in three ClientHello fields
(`internal/client/TLS.go:119-124`): `random` = 32-byte ephemeral pubkey,
`sessionId` = ciphertext[0:32], the X25519 key share = ciphertext[32:64].

CDN mode concatenates the same two pieces and base64s them
(`internal/client/websocket.go:51`):

```
hidden = base64.StdEncoding( randPubKey[0:32] || ciphertextWithTag[0:64] )
```

- **96 bytes** plaintext → **128 base64 characters**, no padding needed
  (96 % 3 == 0). Measured: `hiddenLen=128`, `hidden decoded len=96`.
- `ciphertextWithTag` is 64 = 48 bytes of AES-GCM ciphertext over the 48-byte
  `ClientInfo` block + 16-byte tag. Identical construction to direct mode;
  `makeAuthenticationPayload` is shared (`internal/client/auth.go`).

Server side, `internal/server/websocket.go:75-103`:

```go
if len(hidden) < 96 { return ErrBadGET }
copy(fragments.randPubKey[:], hidden[0:32])
ephPub, ok := ecdh.Unmarshal(...)
sharedSecret = ecdh.GenerateSharedSecret(staticPv, ephPub)
if len(hidden[32:]) != 64 { return ErrCiphertextLength }   // so: exactly 96
copy(fragments.ciphertextWithTag[:], hidden[32:])
```

The `< 96` then `!= 64` pair means the accepted length is **exactly 96**. The
resulting `authFragments` go into the same `AuthFirstPacket` as the TLS path, so
replay checking, UID authorisation, session lookup and the proxy-method check are
all shared and unchanged.

### 1.5 What the server sends back

`internal/server/websocket.go:43-71`. Two writes:

**(a) the 101 response.** Produced by `gorilla`'s `Upgrader.Upgrade`
(`server.go:219-248`), hijacking the connection so `net/http` adds no `Date` or
`Server` header. Measured exactly (`wsprobe2` case A, against a live
`gorilla` server with `Upgrader{}` defaults):

```
HTTP/1.1 101 Switching Protocols\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Accept: <base64(SHA1(key || "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))>\r\n
\r\n
```

Four lines, nothing else. `Sec-WebSocket-Protocol` and
`Sec-WebSocket-Extensions` are omitted because `Upgrader{}` has no subprotocols
and `EnableCompression` is false. `wsprobe2` also confirms the accept
computation against RFC 6455's own sample: key `dGhlIHNhbXBsZSBub25jZQ==` →
`s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`. **That is a ready-made C test vector.**

**(b) the 60-byte Cloak reply, as one binary message.**
`internal/server/websocket.go:55-62`:

```
reply := [12 bytes nonce][48 bytes AES-GCM(sessionKey[32]) + tag[16]]   // 60 bytes
```

written through `common.WebSocketConn.Write` → `WriteMessage(BinaryMessage, …)`,
so on the wire it is **62 bytes**: `82 3C` followed by the 60 payload bytes,
unmasked. Measured in `wsprobe2` case A: `...\r\n\r\n\x82<\x00\x00…`.

Compare direct mode, where the same 60 bytes are *scattered* across a fake
ServerHello (nonce at `[6:18)`, ciphertext[0:20) at `[18:38)`, ciphertext[20:48)
inside the key_share at `[84:112)`) plus two more records. **CDN mode's reply is
flat and contiguous.** The C port's `cloak_server_auth_compose_reply` builds the
scattered TLS form and is therefore *not* reusable as-is; the CDN branch needs a
sibling that emits the flat 60 bytes.

Client side (`internal/client/websocket.go:59-74`): read one message into a
128-byte buffer, **require exactly 60 bytes**, `AESGCMDecrypt(reply[:12],
sharedSecret, reply[12:])` → session key.

### 1.6 Frame types, masking, and message boundaries

| | client → server | server → client |
|---|---|---|
| opcode | `0x2` binary, FIN set → first header byte **`0x82`** | same, **`0x82`** |
| MASK bit | **set** (gorilla `isServer == false`) | **clear** |
| mask key | 4 bytes after the length | — |
| length encoding | `0-125` inline; `126` + u16 for 126..65535 | same |
| fragmentation on send | **never** — `WriteMessage` emits one frame per message | never |
| fragmentation on receive | **accepted** — `NextReader` walks continuation frames | accepted |

Measured (`wsprobe`, client→server): a 5-byte message is
`82 85 <4-byte mask> <5 masked bytes>`; a 200-byte message is
`82 fe 00 c8 <4-byte mask> <200 masked bytes>` — i.e. the `126`/u16 extended
form at 200 bytes, exactly as RFC 6455 requires (inline length is only valid to
125).

**Message boundaries are Cloak's framing.** `switchboard.deplex`
(`internal/multiplex/switchboard.go:147-166`) does `n, err := conn.Read(buf)`
then `sesh.recvDataFromRemote(buf[:n])`, and `recvDataFromRemote`
(`internal/multiplex/session.go:229-233`) immediately calls `sesh.deobfuscate`,
which requires **exactly one whole obfuscated frame**. So:

> **one WebSocket binary message == one Cloak mux frame, and nothing else.**

`connReceiveBufferSize` is hard-coded 20480 (`session.go:113`, comment "for
backwards compatibility") and `MsgOnWireSizeLimit` is 16401
(`internal/client/TLS.go:11`, `internal/server/dispatcher.go:196`), so every real
message is ≤ 16401 bytes and always uses the `126`+u16 length form or the inline
form — the 64-bit (`127`) form is never *emitted*, though a hostile peer could
send it.

64-bit lengths are a receive-side concern only. `CLOAK_CONN_MAX_FRAME_LEN`
(16640) already bounds this in the C port.

---

## 2. Which WebSocket library, and how much of it is load-bearing?

**`github.com/gorilla/websocket v1.5.3`** (go.mod), used on both sides. The
answer to your question is: **this is a handshake plus unmasked/masked single-frame
binary messages and essentially nothing else.** A conformant C implementation of
what Cloak actually exercises is a few hundred lines, not an RFC 6455 stack.

### 2.1 Every gorilla entry point Cloak touches

| call | site | what it must do |
|---|---|---|
| `websocket.NewClient(conn, u, header, 16480, 16480)` | `client/websocket.go:52` | write the GET, read the 101, verify status + `Upgrade` + `Connection` + `Sec-WebSocket-Accept`, hand back a framing conn whose read buffer already holds any bytes that arrived with the response |
| `upgrader.Upgrade(w, r, nil)` (zero-value `Upgrader{}`) | `server/websocketAux.go:130-131` | validate `Connection`/`Upgrade`/method/version/origin/key, write the 101 |
| `Conn.WriteMessage(BinaryMessage, data)` | `common/websocket.go:21` | one FIN binary frame |
| `Conn.NextReader()` + `io.Reader.Read` | `common/websocket.go:31,42` | one whole message, reassembling continuations, transparently handling control frames |
| `Conn.Close()` | `common/websocket.go:64` | `conn.go:344-346`: **closes the TCP socket directly, no close frame** |
| `Conn.SetReadDeadline` / `SetWriteDeadline` | `common/websocket.go:68,71` | pass-through |

That is the entire surface. `ReadMessage`, `NextWriter`, `WriteControl`,
`SetPingHandler`, `SetCompressionLevel`, `Subprotocols`, `Dialer` (beyond the
`NewClient` shim) — none are called by Cloak.

### 2.2 Genuinely unused RFC 6455 features (safe to omit)

- **`permessage-deflate` / any extension.** `EnableCompression` is false on both
  sides. The client never sends `Sec-WebSocket-Extensions`
  (`client.go:238-240` is gated on `d.EnableCompression`); the server never
  emits one (`server.go:227-229`, same gate). RSV1 set on a received frame is a
  protocol error (`conn.go:823-828`). **Do not implement, and reject RSV≠0.**
- **Subprotocols.** Never requested, never selected
  (`server.go:101-115` with `Subprotocols == nil` and `responseHeader == nil`
  returns `""`).
- **Text frames.** Never sent. On receive, `common/websocket.go:35-37` returns
  `(0, nil)` for any non-binary message, and `deplex` then calls
  `recvDataFromRemote(buf[:0])`, which fails the AEAD open, logs, and **continues
  the loop**. So a text frame is tolerated-and-ignored, not fatal. Worth
  matching, but the C port's equivalent can just skip the message.
- **Close frames on the send side.** `Conn.Close()` bypasses the close
  handshake entirely. Cloak never initiates a WebSocket close. On the receive
  side gorilla's default handler echoes a close and the read returns a
  `CloseError`, which `deplex` treats as connection death — the same outcome as
  a TCP FIN. **A C port can treat a received close frame as EOF and never send
  one.**
- **`Origin` checking.** Server-side `checkSameOrigin` (`server.go:89-99`)
  passes trivially because Cloak's client sends no `Origin`. But see §6.5: it
  does *not* pass if something else injects one.

### 2.3 Load-bearing and must be reimplemented

1. **`Sec-WebSocket-Key` generation**: 16 bytes from `crypto/rand`, standard
   base64, 24 characters (`util.go:26-32`).
2. **`Sec-WebSocket-Accept`**: `base64(SHA1(key_ascii || GUID))` where GUID is
   `258EAFA5-E914-47DA-95CA-C5AB0DC85B11` (`util.go:17-24`). Computed over the
   key **as received**, not re-encoded.
3. **Client-side response validation** (`client.go:394-397`): status `101`, AND
   `Upgrade` token-list contains `websocket`, AND `Connection` token-list
   contains `upgrade`, AND `Sec-Websocket-Accept` equals the computed value.
   Token-list, not equality — `Connection: keep-alive, Upgrade` passes
   (`tokenListContainsValue`, `util.go:200-225`). A CDN that appends tokens must
   still work.
4. **Server-side request validation** (`server.go:128-159`): `Connection`
   contains `upgrade`, `Upgrade` contains `websocket`, method is GET,
   `Sec-Websocket-Version` contains `13`, the key base64-decodes to exactly 16
   bytes (`isValidChallengeKey`, `util.go:286-298`).
5. **Masking**, both directions of the check: client sets MASK, server clears it,
   and each side **rejects** a frame whose MASK bit is on the wrong side
   (`conn.go:861-863`, `"bad MASK"`).
6. **Receive-side fragmentation.** `advanceFrame` accepts continuation frames
   (`conn.go:852-856`) and `NextReader`/`messageReader` reassemble. A CDN is
   entitled to re-fragment. **This one is not optional on the read path** even
   though Cloak never sends fragments.
7. **Receive-side control-frame handling interleaved mid-message.** A ping can
   arrive between two continuation frames of a data message; gorilla handles it
   and continues (`conn.go:934-975`). A ping **must** be answered with a pong —
   Cloudflare and most CDNs ping idle WebSocket connections and close them if
   the pong does not come. gorilla does this silently via the default ping
   handler (`conn.go:1158-1171`); the C port must do it explicitly. **This is
   the one control-frame feature that is genuinely load-bearing in production
   and invisible in a Go-to-Go test.**
8. **Frame-header sanity**: RSV bits zero, control frames ≤125 bytes and FIN set,
   no data frame before FIN of the previous one, unknown opcodes rejected
   (`conn.go:814-867`).

Verdict for your vendoring decision: **do not vendor.** The needed subset is
one `ws_frame.c` (encode one frame, decode a frame stream with continuations
and control frames) plus one handshake builder/parser per side. Vendoring a C
WebSocket library would drag in its own HTTP parser, its own allocator
discipline, and its own blocking assumptions, and this project's whole
architecture is that every blocking idiom is a resumable state machine.

---

## 3. What is the CDN part?

### 3.1 Configuration surface

Client (`internal/client/state.go:23-43, 221-236`):

- `Transport`: `"cdn"` (case-insensitive) selects it; **anything else,
  including an empty string, falls through to `"direct"`** (`state.go:237-239`
  is `case "direct": fallthrough; default:`).
- `CDNOriginHost`: nullable. If empty, the **Host header uses `RemoteHost`**;
  otherwise it uses `CDNOriginHost`. Either way `RemotePort` is appended.
- `CDNWsUrlPath`: nullable, defaults to `"/"`.

```go
cdnDomainPort = net.JoinHostPort(raw.CDNOriginHost or raw.RemoteHost, raw.RemotePort)
wsUrl         = "ws://" + cdnDomainPort + raw.CDNWsUrlPath
```

The `ws://` scheme is a fiction: gorilla rewrites it to `http` (`client.go:175-182`)
and then `NetDial` returns the already-TLS-wrapped conn regardless
(`client.go:39-46, 321`), so the scheme never reaches the wire. **`wss://` is
never used and would behave identically here.** The TCP/TLS endpoint is always
`RemoteHost:RemotePort` (the connector dials `connConfig.RemoteAddr`,
`connector.go:28`); `CDNOriginHost` affects **only the `Host` header**.

Server side: there is **no CDN-specific server configuration at all**. The
server does not know or care that a CDN is in front of it. `-p`/`ProxyBook` is
unrelated — it maps `ProxyMethod` names to backend addresses and is shared with
direct mode (`internal/server/dispatcher.go:219, 290`). The server's only
CDN-adjacent knob is `RedirAddr`, the cover site an unrecognised connection is
proxied to.

### 3.2 How the CDN connection differs from a direct WebSocket

There is no "direct WebSocket" mode in Cloak. `WSOverTLS` is the only
WebSocket client and it always wraps in TLS. The differences that matter versus
**direct TLS** mode are:

| | direct | cdn |
|---|---|---|
| outer layer | a *synthetic* ClientHello, never a real handshake | a **real** uTLS session, `InsecureSkipVerify` |
| server reply | 3 fake TLS records, key scattered | HTTP 101 + one 60-byte binary message |
| data framing | 5-byte TLS app-data record per frame | WebSocket binary frame per frame |
| server dispatch | first byte `0x16` | first byte `'G'` |
| who terminates TLS | nobody (it is a costume) | the **CDN**, genuinely |

### 3.3 What must survive the CDN's rewriting

The CDN is an HTTP/1.1 (or /2 → /1.1) reverse proxy. What reaches the origin is
*not* byte-identical to what the client sent. The origin-side parser must be
built for that:

- **`Hidden` may arrive lowercased.** Cloudflare (and any HTTP/2-fronted edge)
  normalises header names to lowercase internally and may re-emit them
  lowercase to a HTTP/1.1 origin. Go survives this for free via
  `textproto.CanonicalMIMEHeaderKey`. **A C parser matching `"Hidden"` with
  `memcmp` is a production-only failure that every test will pass.**
- **Extra headers will be injected**: `X-Forwarded-For`, `X-Forwarded-Proto`,
  `CF-Connecting-IP`, `CF-IPCountry`, `CF-RAY`, `CF-Visitor`, `CDN-Loop`,
  `Accept-Encoding`, `X-Real-IP`, … The parser must skip unknown headers, and
  the **total request size grows well past the 335 bytes a bare client sends**.
  Go's ceiling is `firstPacketSize = 3000` (`dispatcher.go:23`); the C port
  mirrors it as `CLOAK_FIRSTPACKET_MAX 3000`
  (`libcloak-server/include/cloak/firstpacket.h:46`). A Cloudflare-fronted
  request is typically 700-900 bytes, so 3000 holds — but it is now a *real*
  bound rather than a theoretical one, and overflowing it silently redirects the
  connection to the cover site.
- **`Connection` may be rewritten** to `Connection: Upgrade, keep-alive` or
  similar. Token-list matching, not equality (§2.3 item 3/4).
- **`Host` may be rewritten** to the origin's hostname. The server never reads
  `Host`, so this is harmless.
- **The request target may be rewritten** (path prefix stripping, query
  appending). The server never reads the path either — `CDNWsUrlPath` exists
  purely so the operator can route the CDN to the right origin. Do not add a
  path check the Go server does not have; being fussier than the reference is
  itself a distinguisher (the argument `libcloak-mux/include/cloak/conn.h`
  already makes about not validating record type bytes).
- **`Sec-WebSocket-Key` may be regenerated by the CDN** on the origin leg. That
  is fine — the origin echoes back an accept computed over whatever key it
  received, and the CDN computes the client's accept from the client's key.
  The C server must compute over the received key, never over a stored one.
- **Frames may be re-fragmented**, and the CDN may **inject pings** (§2.3 items
  6/7).

### 3.4 Attacker-visible bytes, and where this is fingerprintable

Divide by observer:

**(A) A censor on the client↔CDN leg sees only the TLS handshake.** Everything
after it is encrypted by a real TLS session. What they see:

1. **The ClientHello is `HelloChrome_Auto` with the ALPN extension deleted**
   (`internal/client/websocket.go:31-37`). Real Chrome **always** sends
   `application_layer_protocol_negotiation: h2, http/1.1`. A ClientHello that is
   byte-for-byte Chrome in cipher order, extension order, GREASE placement and
   supported_groups, but is *missing ALPN entirely*, is not a fingerprint
   Chrome has ever produced. JA3 hashes on the extension list; JA4 encodes the
   ALPN value explicitly and would render `00` where Chrome renders `h2`.
   **This is the loudest single artefact in the CDN transport and it is inherent
   to the design**, because gorilla and `net/http.ReadResponse` cannot speak
   HTTP/2. Worth recording as a known divergence the C port inherits rather than
   invents.
2. **SNI = `ServerName` from the config**, unchanged, and `"random"` is **not**
   honoured here — `randomServerName()` is only consulted on the direct path
   (`internal/client/TLS.go:126-128`). CDN mode passes `authInfo.MockDomain`
   straight into `utls.Config.ServerName`. For a CDN that is correct (the SNI
   must route), but it means the CDN transport has no SNI randomisation.
3. **Timing/size shape**: 335-byte request, ~150-byte response, then a 62-byte
   frame — indistinguishable from any small WebSocket app inside TLS.

**(B) An observer on the CDN↔origin leg (or the CDN operator) sees plaintext**:

4. **`User-Agent: Go-http-client/1.1`**. A WebSocket client identifying as the
   Go standard library, sending a non-standard `Hidden:` header holding 128
   base64 characters, to a CDN. If this leg is ever unencrypted (Cloudflare
   "Flexible" SSL, an origin on port 80), that is an unambiguous signature.
5. **`Hidden:` itself** — a 128-char high-entropy header with a name no real
   protocol uses.
6. **`Host` carries an explicit `:443`** (`net.JoinHostPort` at
   `state.go:225/227`). Browsers and every real HTTP client omit the default
   port for the scheme. `Host: example.com:443` inside a TLS-443 WebSocket is a
   small, free distinguisher.
7. **Header ordering** — `Host, User-Agent, Connection, Hidden,
   Sec-WebSocket-Key, Sec-WebSocket-Version, Upgrade`. Browsers order these
   very differently (`Host, Connection, Pragma, Cache-Control, User-Agent,
   Upgrade, Origin, Sec-WebSocket-Version, Accept-Encoding, Accept-Language,
   Sec-WebSocket-Key, Sec-WebSocket-Extensions`). If the C port is to match Go
   it must reproduce Go's order **exactly** — and note that matching Go here is
   matching *Go*, not matching a browser.

**(C) An active prober hitting the origin directly** sees the cover site for any
GET without a valid `Hidden` (redirect path), which is the same behaviour as the
TLS path. Good. But see §6.5.

Recommendation for the plan: the C port should emit **byte-identical** request
bytes to Go's (including the Go `User-Agent` and the `:443` in `Host`), and any
improvement should be an explicit, separately-documented divergence — because a
Cloak-C client that is *more* browser-like than a Cloak-Go client is
distinguishable from the fleet it is trying to hide in. That is the same
argument `client_transport.h:76-82` already makes about the TLD list.

---

## 4. What exists in the C port that this must plug into?

### 4.1 The client "transport abstraction" — there isn't one

This is the finding most likely to change the plan's shape.

`/Users/sam/Cloak-c/libcloak-client/include/cloak/client_transport.h` is **not**
an abstraction. It is one concrete object, `cloak_client_handshake_t`, whose name,
states, error enum and struct fields are all specific to direct TLS. There is no
vtable, no function-pointer table, no `transport` union. Concretely:

```c
int  cloak_client_handshake_init (cloak_client_handshake_t *h,
                                  const cloak_client_handshake_config_t *cfg);   /* :371 */
int  cloak_client_handshake_start(cloak_client_handshake_t *h);                  /* :382 */
void cloak_client_handshake_destroy(cloak_client_handshake_t *h);                /* :391 */
cloak_client_handshake_status_t cloak_client_handshake_status(const ... *h);     /* :395 */
cloak_client_handshake_error_t  cloak_client_handshake_error (const ... *h);     /* :399 */
const uint8_t *cloak_client_handshake_session_key(const ... *h);                 /* :403 */
const char    *cloak_client_handshake_server_name(const ... *h);                 /* :407 */

typedef void (*cloak_client_handshake_cb)(cloak_client_handshake_t *h,
                                          cloak_client_handshake_status_t status,
                                          void *userdata);                       /* :253 */
```

State machine (`client_transport.h:186-192`), five states:

```
WRITE_HELLO(0) -> READ_RECORD_HEADER(1) <-> READ_RECORD_BODY(2) -> DONE(3) | FAILED(4)
```

with position kept as `(state, hello_sent | header_len | body_len, record_index)`
— explicitly designed to survive a one-byte-per-turn split
(`client_transport.h:18-38`).

Contracts a second transport must honour, all stated in that header and all
non-negotiable:

- **Never read past the end of the handshake reply** (`:30-38`). On success the
  fd is handed to `cloak_session_add_conn`, which reads from wherever the kernel
  left off. One over-read byte desynchronises the session on frame one. For
  WebSocket this is *harder* than for TLS: after the 101 response the very next
  bytes are the 60-byte reply frame, and after that the session's frames.
- **Never close the fd, on any path** (`:246-252`). The caller owns it from
  before `start` to after `on_done`.
- **Fire `on_done` exactly once, never re-entrantly from `start`**
  (`:234-237`, `notified` field at `:352`), and always as the last statement
  touching `h` so `on_done` may free it.
- **Own a whole-handshake deadline** (`:50-59`), default 15000 ms
  (`CLOAK_CLIENT_HANDSHAKE_DEFAULT_TIMEOUT_MS`, `:230`). Go has none; this is a
  deliberate divergence.
- **`h` must be fully zeroed as the first act of `init`** so a rejected call is
  still safe to `destroy` (`:363-367`).

So a WebSocket transport must either (a) add a second object with the same
lifecycle contract and let the connector branch on `transport`, or (b) introduce
the vtable this module never needed. (a) is smaller and matches how the tree
does everything else.

### 4.2 Where the connector and stack refuse CDN today — the exact sites to remove

| # | file:line | what it does |
|---|---|---|
| 1 | `libcloak-client/src/client_stack.c:872-879` | `if (c->transport != CLOAK_TRANSPORT_DIRECT)` → `stack_err(..., "client config: Transport \"cdn\" is not supported by this build")`, `cloak_client_stack_close`, return `CLOAK_CLIENT_STACK_ERR_CONFIG`. **This is what makes `ck-client` exit 2 on a CDN config**; there is no CDN check in `cmd/ck-client/main.c` itself. |
| 2 | `libcloak-client/src/client_connector.c:464-466` | `if (cfg->transport != CLOAK_TRANSPORT_DIRECT) return -1;` in `cloak_client_connector_init`. The belt to (1)'s braces. |
| 3 | `libcloak-server/src/dispatcher.c:399-401` | `if (c->fp.transport != CLOAK_FIRSTPACKET_TRANSPORT_TLS) return -1;` — step 1 of `dispatcher_authenticate`. `-1` here means "redirect to the cover site", so **today a real CDN WebSocket upgrade is proxied to `RedirAddr`**. There is no CDN check in `cmd/ck-server/main.c` either. |

Plus the prose and tests that pin those three, all of which the plan must
update in the same breath (a stale comment asserting a guard is unreachable, when
it has become reachable, is exactly the failure mode `conn.h`'s "two validators /
three validators" paragraph warns about):

| kind | site | note |
|---|---|---|
| doc | `libcloak-client/include/cloak/client_stack.h:349-351` | "`transport == CLOAK_TRANSPORT_CDN` is REJECTED at open" |
| doc | `libcloak-client/include/cloak/client_stack.h:486-487` | CONFIG error list names CDN |
| doc | `libcloak-client/src/client_connector.c:305-320` | the D3 Chrome→Firefox fallback's `transport == CLOAK_TRANSPORT_DIRECT` conjunct is documented as **structurally dead because of (2)**. Removing (2) makes it live. The comment says so and says not to delete it. |
| doc | `libcloak-client/src/client_connector.c:467-469` | "NOTE, paired with on_handshake_done's D3 guard" |
| doc | `libcloak-server/include/cloak/firstpacket.h:57-64` | "has NO consumer anywhere in this codebase yet … MUST treat this transport the same as any other case it has no handler for" |
| doc | `libcloak-server/src/dispatcher.c:236-241` | step 1's rationale |
| test | `libcloak-client/tests/test_client_connector.c:1735-1740` | asserts `init` returns -1 for CDN |
| test | `libcloak-client/tests/test_client_stack.c:2177-2186` | asserts `open` returns `ERR_CONFIG` for CDN |
| test | `cmd/ck-client/tests/test_ck_client_cli.c:1698-1710` | asserts `ck-client` **exits 2** and prints `(client config)` for `"Transport":"cdn"` |
| test | `libcloak-server/tests/test_dispatcher_redirect.c:356` | a bare `GET / HTTP/1.1\r\nHost: example.com\r\n\r\n` must reach the cover site — this one **stays true** (no `Hidden` header) and is a good regression anchor |

### 4.3 What already works on the server side

`cloak_firstpacket_t` already frames a WebSocket upgrade correctly and
completely (`libcloak-server/src/firstpacket.c:78-79, 113-130`): first byte
`'G'` → `CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET`, then consume to CRLFCRLF,
`DONE`, with the whole request in `fp.buf[0, fp.len)` and **no byte read past
it**. `cloak_firstpacket_want()` returns 1 on this path
(`firstpacket.c:28-29`) to preserve that, mirroring Go's `connReadLine`
(`dispatcher.go:46-58`). Tests already exercise it
(`libcloak-server/tests/test_firstpacket.c:88-104, 209`).

So the server-side hook is small and well-placed: at `dispatcher.c:399`, branch
on `fp.transport`; the WebSocket branch parses `fp.buf`, and on success fills
the same `c->reply / c->reply_len / c->auth_*` fields that `conn_handoff` and
`conn_continue_reply_write` (`dispatcher.c:712, 803-881`) already consume. The
reply write path is a plain `send()` loop over an opaque byte buffer
(`dispatcher.c:824`), so it does not care that the bytes are an HTTP response
followed by a WebSocket frame.

**And a coalesced reply is safe.** Measured (`wsprobe2` case B): a server that
writes the 101 response and the 62-byte binary frame in **one** `write()` is
correctly handled by a gorilla client — `type=2 len=60 err=<nil>`. gorilla's
`http.ReadResponse` reads from the same `bufio.Reader` it then uses for frames,
so leftover bytes are preserved. The C server can therefore build one
`c->reply` buffer and keep the existing single-write state machine unchanged.

### 4.4 The framing layer, and where WebSocket has to be taught to it

`cloak_conn_t` (`libcloak-mux/include/cloak/conn.h`) hard-codes the TLS
application-data record:

- `CLOAK_CONN_RECORD_HEADER_LEN 5` (`conn.h:68`), `max_envelope_len = 5 +
  max_frame_len` (`conn.c:346`).
- Send: `conn.c:427-433` writes a 5-byte header then the frame.
- Receive: `conn.c:133-164` peeks 5 bytes, takes the length from `[3:5]`,
  dispatches `recv_scratch + 5`.

There is exactly one knob into this from above: `cloak_session_add_conn(sesh,
fd)` (`session.h:230`), which builds the `cloak_conn_t` internally. So module 8
must add a **framing mode** — `CLOAK_CONN_FRAMING_TLS_RECORD` (default) vs
`CLOAK_CONN_FRAMING_WS_CLIENT` / `CLOAK_CONN_FRAMING_WS_SERVER` — plumbed through
`cloak_session_config_t` or a `cloak_session_add_conn_framed()` sibling. The
client and server variants differ only in masking.

Note that `conn.h:20-66` is an eight-paragraph warning about *why* those five
bytes exist. A WebSocket framing mode is exactly the kind of change that
paragraph is guarding against being made carelessly, and the plan should quote
it. See §6.3.

### 4.5 Building blocks that already exist

| need | available |
|---|---|
| CSPRNG | `cloak_random_bytes` (`libcloak-common/include/cloak/common.h:9`), OpenSSL `RAND_bytes`, **aborts on failure** (`src/random.c:11-14`) |
| standard base64 encode/decode | `cloak_base64_encode` / `cloak_base64_decode` (`libcloak-common/include/cloak/base64.h`), strict, matching Go's `StdEncoding` — **exactly what both `Hidden` and `Sec-WebSocket-Key`/`-Accept` need** |
| SHA-1 | not used anywhere yet, but `OpenSSL::Crypto` is already linked (`libcloak-common/CMakeLists.txt:26`), so `SHA1()`/`EVP_Digest` is free |
| AES-GCM | `libcloak-common/src/aead.c` |
| byte buffering | `cloak_bytequeue_t` (`libcloak-common/include/cloak/bytequeue.h`) — fixed-cap ring, atomic writes, `peek` without consuming. Exactly the primitive a partial-frame reader needs. |
| reactor | `cloak_reactor_t`, edge-triggered, with timers (`libcloak-common/include/cloak/reactor.h`) |
| **TLS client** | **NONE.** Only `OpenSSL::Crypto` is linked; `libssl` is not. See §5.1. |

---

## 5. What will fight us

### 5.1 The thing that will fight us most is not WebSocket. It is TLS.

**`libcloak-common` links `OpenSSL::Crypto` only** (`CMakeLists.txt:26`), and the
Dockerfile installs `libssl-dev` (which supplies both, so the build would find
libssl if asked). Today the port has no TLS implementation of any kind:
`libcloak-common/src/clienthello.c` *builds a ClientHello byte string* from a
template and never negotiates anything; the server writes three fake records.
That costume works because both ends are Cloak.

**A CDN is not Cloak.** The client leg terminates against Cloudflare (or
whoever), which will complete a real TLS 1.3 handshake, derive real traffic
keys, and reject anything else. So a client-side CDN transport needs a genuine
TLS client — key exchange, key schedule, record encryption, the lot — driven
from a non-blocking edge-triggered reactor.

Three options, and the plan has to pick one explicitly:

- **(a) Ship the server side of module 8 only.** The C `ck-server` learns to
  accept CDN-fronted WebSocket connections from Go clients (and from any
  standard client), which is *immediately useful and fully testable against an
  outside oracle* (§7). The C `ck-client` keeps refusing CDN. Smallest, safest,
  and it gets the interoperability win.
- **(b) Link `libssl` and use `SSL_connect` in non-blocking mode** with
  `SSL_set_bio` over the existing fd, pumped from the reactor via
  `SSL_ERROR_WANT_READ/WANT_WRITE`. This is mechanical and well-trodden, and it
  fits the reactor model. The cost is that OpenSSL's ClientHello is **not**
  Chrome's — cipher order, extension order, no GREASE, different
  `supported_groups`, a real ALPN. The transport would still work, and would be
  more obviously "not a browser" than Go's (which is Chrome-minus-ALPN). Given
  §3.4 item 1 this is a *degradation of an already-degraded* fingerprint, not a
  new class of problem, but it must be a recorded decision, not an accident.
- **(c) Write a minimal TLS 1.3 client that emits the existing
  `chrome_template` ClientHello.** X25519 + HKDF + AES-GCM are all already in
  the tree; the missing pieces are the handshake transcript, key schedule,
  record layer, and a whole state machine. This is a module of its own, easily
  larger than module 8, with a large attack surface. **Not recommended as part
  of module 8.**

My recommendation: **(a) now, and file (b)/(c) as module 8b.** The server half
is where the outside oracle lives, where the leverage is, and where the
fingerprint risk is lowest.

### 5.2 The handshake as a resumable state machine

Go's version is blocking straight-line code on both sides. Here is the shape each
side has to take.

**Server (easy — most of it already exists).** `cloak_firstpacket_t` already
delivers the complete request, so the handshake is *not* streaming at all: it is
a pure function over `fp.buf`. New states are zero; the only new asynchrony is
that the reply is longer (101 response + 62-byte frame ≈ 190 bytes instead of
~170) and still goes through the existing `conn_continue_reply_write` partial-write
loop (`dispatcher.c:803-881`).

**Client (new).** Suggested `cloak_client_ws_handshake_t`, modelled on
`cloak_client_handshake_t`'s discipline:

```
WRITE_REQUEST        -- the full GET, byte-counted (request_sent / request_len)
READ_STATUS_LINE     -- one byte at a time, or peek-and-consume; to CRLF
READ_HEADERS         -- line at a time, to CRLFCRLF; accumulate only the
                        four fields that matter; bound the block
VERIFY               -- synchronous: 101 + Upgrade + Connection + Accept
READ_REPLY_HEADER    -- 2 bytes, then 0/2/8 more length bytes as the first
                        two dictate (mask must be CLEAR from a server)
READ_REPLY_PAYLOAD   -- exactly `len` bytes; require len == 60
DONE | FAILED
```

Seven states versus direct TLS's five. Positions to keep: `request_sent`,
`line_len`, `header_block_len`, the four captured header values, `hdr_len`,
`payload_len`, `payload_have`.

**Where partial reads can land, exhaustively** — every one of these must be
survivable at one byte per reactor turn:

1. mid-request-line of the response (`HTTP/1.1 10` | `1 Switching…`);
2. mid-header-name, mid-header-value, or between the CR and the LF of any
   header line — this last one is the classic: `pending_cr` state, which
   `libcloak-server/src/http.c` already models;
3. between the final header's CRLF and the terminating CRLF;
4. **between the end of the 101 response and the first byte of the WebSocket
   frame** — and, symmetrically, they may arrive *together* (§4.3 measurement
   B). Both must work;
5. between byte 0 and byte 1 of the frame header;
6. inside the 2-byte extended length (server sends 60 < 126, so inline — but a
   hostile or CDN-rewritten server could send `126 00 3C`, which gorilla would
   accept, so the C client should too);
7. mid-payload, at any of the 60 offsets;
8. **after the 60-byte payload, with session frames already in the same read.**
   This is the `client_transport.h:30-38` no-over-read rule, and WebSocket makes
   it sharper than TLS did: the handshake object must hand its leftover bytes to
   the session's `cloak_conn_t`, or refuse to read them at all. Given
   edge-triggered epoll and the `bytequeue` that `cloak_conn_t` already owns,
   **the cleanest answer is a "prefill" entry point on `cloak_conn_t`** that
   seeds `recv_acc` with bytes the handshake already consumed — rather than
   trying to read exactly-and-only 62 bytes with per-byte `recv()` calls.
   Decide this in the plan; it is the one place where the existing contract and
   WebSocket framing genuinely pull against each other.

### 5.3 Is the existing HTTP parser reusable? Plainly: no, on both sides.

`libcloak-server/include/cloak/http.h` + `src/http.c` is a fine incremental
parser, and it is the wrong tool twice over:

- **It is a REQUEST parser only.** There is no status-line path, no
  `HTTP/1.1 101` handling, no response state at all. The client side of the
  WebSocket handshake needs a *response* parser. Nothing here helps.
- **It stores no headers.** `cloak_http_request_t` (`http.h:149-205`) has
  `method`, `path`, `content_length`, `have_content_length`, `body`, `body_len`,
  `status` — and that is the complete list. `http.h:120-125` says so explicitly:
  "a flood of tiny headers is cheap to send and, in a parser that stored them,
  expensive to keep — **this one stores none**". The WebSocket server handshake
  needs `Hidden`, `Sec-WebSocket-Key`, `Connection`, `Upgrade` and
  `Sec-WebSocket-Version` **by value**. Adding header capture to this parser
  means touching the one file in the tree whose header says a memory-safety bug
  in it is remote code execution as the operator (`http.h:17-30`). Do not.
- Its caps are also wrong for the job: `CLOAK_HTTP_MAX_HEADERS 32` is plausibly
  exceeded by a Cloudflare-fronted request plus the client's own seven;
  `CLOAK_HTTP_MAX_HEADER_LINE 512` happens to fit `Hidden: ` + 128 chars, but by
  luck rather than design.

**Recommendation: a separate, small, single-purpose parser per side**, in
`libcloak-server/src/ws_handshake.c` and `libcloak-client/src/ws_client.c`. Reuse
`http.c`'s *discipline* — strict CRLF, `pending_cr`, bounds-before-storage,
caps with named constants — and cite it, but not its code. The server side has
the additional simplification that `cloak_firstpacket_t` hands it a complete,
already-bounded buffer, so it is a one-shot scan, not an incremental machine.

### 5.4 Smaller frictions

- **`cloak_firstpacket_want()` returns 1 on the WebSocket path**, so a
  900-byte CDN request costs ~900 `recv()` syscalls inside one edge-triggered
  dispatch. Go pays the same (`connReadLine` is `io.ReadFull(conn, buf[i:i+1])`),
  so it is fidelity, not a regression. If it matters, `recv(..., MSG_PEEK)` to
  find CRLFCRLF and then one sized `recv()` preserves the no-over-read guarantee
  exactly; that is a contained optimisation, and `firstpacket.h:96-107` already
  invites it by explaining the cost.
- **Masking cost.** Every client→server frame XORs its whole payload. At 16 KiB
  frames that is real work but trivial next to AES-GCM, which the frame already
  pays. Do the word-at-a-time thing gorilla does (`mask.go:14-40`) only if a
  profile asks for it.
- **No `Sec-WebSocket-Key` reuse.** 16 CSPRNG bytes per connection, and
  `num_conn` defaults to 4 — 64 bytes of entropy per session bring-up.
  Irrelevant, but note `cloak_random_bytes` **aborts the process** if
  `RAND_bytes` fails (`random.c:11-14`), so it must not be called
  speculatively in a hot loop where an abort would be surprising.

---

## 6. Traps

### 6.1 Base64 of `Sec-WebSocket-Key`

- 16 bytes → 24 characters with one `=` of padding, **standard alphabet**
  (`+`/`/`), never URL-safe. `cloak_base64_encode` is correct;
  `cloak_base64url_encode` is not. The port has both and they are one character
  apart in the call (`base64.h`) — an easy and silent mistake, because a
  Go server would reject it with `isValidChallengeKey` only if the decode
  failed, and `-`/`_` *do* fail Go's `StdEncoding`, so it would fail loudly
  against a Go server but pass a self-consistent C↔C test. §7 case.
- On the **server** side, the key must be treated as an **opaque ASCII string**
  and fed to SHA-1 exactly as received, **not** decoded and re-encoded. gorilla
  does `h.Write([]byte(challengeKey))` on the raw header value
  (`util.go:19-24`). A CDN that re-pads or re-cases the base64 would then still
  work, because both sides hash the same bytes. Decoding and re-encoding would
  break that and would also break the RFC 6455 sample vector.
- The server **does** separately validate that the key decodes to 16 bytes
  (`server.go:157-159`, `util.go:286-298`) and 400s otherwise — but it hashes
  the string, not the decoded bytes. Two different uses of the same field.
- `cloak_base64_decode` is strict about length%4 and the alphabet, which matches
  Go. For the `Hidden` header, 128 characters → 96 bytes exactly; anything else
  must be refused (§1.4).

### 6.2 The SHA-1 accept computation

- GUID is `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`, **36 ASCII bytes, uppercase,
  no NUL, no braces**. Appended to the key string with no separator.
- Output is the raw 20-byte digest, standard-base64'd → 28 characters with one
  `=`.
- Test vector, verified against live gorilla in `wsprobe2`:
  `dGhlIHNhbXBsZSBub25jZQ==` → `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`. This is also
  RFC 6455 §1.3's own example, so it is an **outside** vector, not a
  self-consistent one.
- Comparison must be exact (`resp.Header.Get(...) != computeAcceptKey(...)`,
  `client.go:397` — a byte comparison, not case-insensitive). Use a constant-time
  compare out of habit, though nothing secret is involved.

### 6.3 THE BIG ONE: WebSocket framing vs the TLS record framing already shipped

`libcloak-mux/include/cloak/conn.h:20-66` documents, at length, a defect this
port shipped for five modules: the data path carried a bare big-endian u16 length
prefix instead of a TLS application-data record header, so **the disguise applied
for exactly one round trip and then dropped** — a louder fingerprint than no
disguise at all. Five bytes fixed it, and the header says in capitals: *"DO NOT
'optimise' these five bytes back down to two."*

**The CDN path is the exact inverse, and it is a trap in both directions:**

- On the CDN path the TLS record header **must not be there**. Go's `WSOverTLS`
  embeds `*common.WebSocketConn` and nothing else
  (`internal/client/websocket.go:16-19`); the outer TLS session is real and
  supplies its own records. A C `cloak_conn_t` left in TLS-record mode on a
  WebSocket connection would emit `0x17 0x03 0x03 <len>` *inside* a WebSocket
  binary frame, which is both wire-incompatible with Go and, to anyone who can
  see inside the CDN's TLS, a perfect Cloak signature — a TLS record header
  where a WebSocket payload should be.
- And symmetrically: a WebSocket framing mode that leaked onto the direct path
  would undo the five-byte fix.

So the framing mode must be **selected once, at `cloak_session_add_conn` time,
from the transport that produced the fd**, and it must be impossible to get it
from anywhere else. Concretely for the plan:

1. make the framing mode an explicit parameter with no default that silently
   works (an `enum` whose zero value is *invalid*, not `TLS_RECORD`), so an
   un-updated call site fails construction rather than picking a mode;
2. assert in `cloak_conn_send` that the mode matches the role (client masks,
   server does not) — a server that masks is rejected by gorilla with
   `"bad MASK"` and by every browser;
3. add a test that reads the raw bytes off a socket and asserts the **first byte
   of the data path** is `0x17` on direct and `0x82` on CDN. That is the
   assertion that would have caught the original defect in one line, and it is
   the same assertion in a new place.

Related sizing check: `max_envelope_len = header + max_frame_len`. For TLS that
is `5 + 16401`. For WebSocket server→client it is `2 + (0 or 2) + 16401`; for
client→server `2 + (0 or 2) + 4 + 16401`. The masking key makes the client's
envelope **larger** than the TLS one, and the receive scratch buffer is sized
off `max_envelope_len` (`conn.c:346`). Get this wrong by four bytes and it fails
only at the maximum frame size — i.e. under load, in production, never in a
unit test.

### 6.4 Masking keys and the CSPRNG — and a real Go deviation

`cloak_random_bytes` (OpenSSL `RAND_bytes`) is a CSPRNG and is the right source.
**gorilla's is not.** `conn.go:184-187`:

```go
func newMaskKey() [4]byte {
	n := rand.Uint32()
	return [4]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
}
```

with `"math/rand"` imported at `conn.go:12` — **not** `crypto/rand`, and not
`math/rand/v2`. RFC 6455 §5.3 requires: *"The masking key needs to be
unpredictable; thus, the masking key MUST be derived from a strong source of
entropy."* This is a long-standing gorilla deviation.

Practical impact for Cloak: **low**. Since Go 1.20 the global `math/rand` source
is randomly seeded and since 1.22 it is ChaCha8-based, so it is not trivially
predictable; and the masked payload is already AEAD-sealed under the session
key, so a recovered mask reveals ciphertext the attacker could already see. It
is also **not a distinguisher** — mask keys look uniformly random either way.

Consequence for the plan: using `cloak_random_bytes` is strictly better and
costs nothing, and it is **not** a fidelity divergence worth agonising over.
Note it and move on. Do call `cloak_random_bytes` once per frame (4 bytes) or
batch it; do not call it per byte.

One genuine correctness note: the mask must be applied with `pos` running over
the **whole payload from offset 0**, `payload[i] ^= key[i & 3]`. When the
payload is written out in chunks by a partial-write loop, the running `pos`
must be carried across chunks — gorilla threads exactly this through
`maskBytes(key, pos, b)` returning `pos & 3` (`mask.go:14-21`). Masking in
place *before* enqueueing (which is what the C port's `bytequeue` design
naturally does) sidesteps it entirely; that is the safer shape.

### 6.5 Go bug #5: a failed WebSocket upgrade wedges the Cloak server forever

**This is the new one, and it is measured, not inferred.**

`internal/server/websocket.go:44-50`:

```go
respond := func(originalConn net.Conn, sessionKey [32]byte, randSource io.Reader) (preparedConn net.Conn, err error) {
	handler := newWsHandshakeHandler()
	// For an explanation of the following 3 lines, see the comments in websocketAux.go
	http.Serve(newWsAcceptor(originalConn, reqPacket), handler)
	<-handler.finished          // <-- unconditional receive
	preparedConn = handler.conn
```

and `internal/server/websocketAux.go:129-138`:

```go
func (ws *wsHandshakeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("failed to upgrade connection to ws: %v", err)
		return                  // <-- returns WITHOUT writing to ws.finished
	}
	ws.conn = &common.WebSocketConn{Conn: c}
	ws.finished <- struct{}{}
}
```

`finished` is an **unbuffered** channel (`websocketAux.go:126`). If `Upgrade`
fails, nothing is ever sent, and `<-handler.finished` blocks **forever**. The
goroutine, the socket, the `firstBuffedConn`, and the `ActiveUser`/session
bookkeeping already done by `dispatchConnection` all leak permanently.

Measured with `leakprobe` — `firstBuffedConn`, `wsOnceListener`,
`wsHandshakeHandler` **copied verbatim** from `websocketAux.go:70-138`, and
`respond`'s three lines copied from `websocket.go:47-50`:

```
=== well-formed upgrade ===
  respond() returned
=== GET with the hidden header but NO Upgrade headers ===
  [handler] failed to upgrade connection to ws: websocket: the client is not using
     the websocket protocol: 'upgrade' token not found in 'Connection' header
  *** respond() STILL BLOCKED after 1.5s; goroutines 3 -> 3 ***
=== upgrade with a malformed Sec-WebSocket-Key ===
  [handler] failed to upgrade ...: 'Sec-WebSocket-Key' header must be Base64
     encoded value of 16-byte in length
  *** respond() STILL BLOCKED after 1.5s; goroutines 4 -> 5 ***
=== upgrade with a cross-Origin header ===
  [handler] failed to upgrade ...: request origin not allowed by Upgrader.CheckOrigin
  *** respond() STILL BLOCKED after 1.5s; goroutines 6 -> 7 ***
```

Three distinct reachable triggers. Reachability: `processFirstPacket`
(`websocket.go:22-41`) authenticates on the `Hidden` header **alone** — it never
looks at `Upgrade`, `Connection`, `Sec-WebSocket-Key` or `Sec-WebSocket-Version`.
Those are checked later, by `Upgrader.Upgrade`, *after* `dispatchConnection` has
already authorised the UID, made the user active, and called `finishHandshake`
(`dispatcher.go:204` for admin, `:254` for ordinary sessions). So any client
holding a valid UID can wedge one goroutine + one fd per request, forever, by
omitting a header.

And the accidental path is the alarming one: **a CDN that strips or rewrites
`Connection: Upgrade`, regenerates a malformed `Sec-WebSocket-Key`, or injects
an `Origin` header turns every single connection attempt into a permanent
goroutine and fd leak on the origin server.** `Origin` in particular:
`checkSameOrigin` (`server.go:89-99`) compares `url.Parse(origin).Host` against
`r.Host` — and a CDN that sets `Origin` while also rewriting `Host` to the
origin's internal name fails that comparison. This is a plausible
misconfiguration, not a contrived attack.

Fixes for the C port (which will not have this shape at all, since there is no
goroutine and no channel, but the *ordering* lesson transfers):
**validate the WebSocket upgrade headers as part of `processFirstPacket`'s
equivalent — before authorising the UID and before touching the user panel — so
a malformed upgrade is an ordinary redirect-to-cover-site, exactly like an
unrecognised protocol.** That is both more robust and, per §3.4(C), better
mimicry: the server should look identically like a web server whether the GET
carries a bad `Hidden` or a bad `Upgrade`.

### 6.6 Go oddity: the discarded base64 error

`internal/server/websocket.go:30-32`:

```go
hiddenData, err = base64.StdEncoding.DecodeString(req.Header.Get("hidden"))

fragments, err = WebSocket{}.unmarshalHidden(hiddenData, privateKey)
```

The decode's `err` is overwritten one line later without being checked.
`DecodeString` returns the bytes decoded **before** the error, so malformed
input silently proceeds with a short/partial buffer. The `len < 96` and
`len(hidden[32:]) != 64` checks in `unmarshalHidden` (`websocket.go:76, 96`)
happen to contain it — the accepted length is exactly 96 either way — so this is
a latent defect, not an exploitable one. Worth a comment in the C port
explaining that the C version checks the decode result *because* the Go one does
not, rather than looking like gratuitous divergence.

### 6.7 Go oddity: `firstBuffedConn.Read` can return `n > len(buf)`

`internal/server/websocketAux.go:76-85`:

```go
func (c *firstBuffedConn) Read(buf []byte) (int, error) {
	if !c.firstRead {
		c.firstRead = true
		copy(buf, c.firstPacket)        // truncates silently
		n := len(c.firstPacket)         // but reports the FULL length
		...
		return n, nil
	}
```

`copy` truncates to `len(buf)` but the returned `n` is `len(c.firstPacket)`,
violating `io.Reader`'s contract (`0 <= n <= len(p)`). A `bufio.Reader` that
received `n > len(buf)` would advance `b.w` past the end of its buffer and panic
on the next slice. Unreachable today: `firstPacketSize` is 3000
(`dispatcher.go:23`) and `net/http`'s connection reader uses a 4096-byte
`bufio.Reader`. But it is one constant change away from a panic, and the C port
should not reproduce the shape.

### 6.8 A gorilla server rejects a client that pipelines

`server.go:185-188`:

```go
if brw.Reader.Buffered() > 0 {
	netConn.Close()
	return nil, errors.New("websocket: client sent data before handshake is complete")
}
```

Measured (`wsprobe2` case C): sending the GET and a binary frame in one `write()`
gets `server Upgrade err = websocket: client sent data before handshake is
complete` and the connection is closed (`client saw 0 bytes, err=EOF`).

So **the C client must never coalesce its first data frame with the upgrade
request**, and its state machine must reach `DONE` (having read the 60-byte
reply) before the session may write anything. Go's client naturally obeys this
because `Handshake` reads the reply before returning
(`internal/client/websocket.go:59-63`). Note that this is asymmetric: the
**server** side coalescing its 101 and its 60-byte reply is fine (§4.3 B). Easy
to get backwards.

Also note this interacts with §6.5: the C *server*, unlike gorilla, does not
have to reject pipelining (`cloak_firstpacket_t` stops exactly at CRLFCRLF and
the leftover bytes belong to the session anyway). Being *more* permissive than
gorilla here is a behavioural difference a prober could measure. Being stricter
would be worse. Flag it as a decision rather than letting it fall out.

### 6.9 Silent-failure list

- `cloak_base64url_encode` where `cloak_base64_encode` was meant (§6.1).
- Case-sensitive `Hidden` lookup (§3.3) — works in every test, fails behind a
  CDN.
- Equality instead of token-list matching on `Connection`/`Upgrade` (§2.3) —
  works against Go, fails behind a CDN that appends `keep-alive`.
- Forgetting the pong reply (§2.3 item 7) — works for hours, then the CDN
  reaps idle connections.
- Forgetting receive-side continuation frames (§2.3 item 6) — works against a
  Go peer, which never fragments, fails behind an edge that does.
- `max_envelope_len` short by the 4 mask bytes (§6.3) — fails only at the
  largest frame size.

---

## 7. How would you test it

The project's lesson stands: **round-trip tests cannot see a self-consistent
error, because both ends are our own code.** For WebSocket, unusually, real
oracles are available and cheap. Use them.

### 7.1 Outside oracles, per property

| property | oracle | how |
|---|---|---|
| `Sec-WebSocket-Accept` | **RFC 6455 §1.3's own sample** | `dGhlIHNhbXBsZSBub25jZQ==` → `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`, independently confirmed against live gorilla in `wsprobe2`. A pure unit test, no network. |
| the client's upgrade request, byte for byte | **`wsprobe`'s captured output** | Freeze Go's 335-byte request as a golden file and diff the C client's bytes against it, with the `hidden` and `Sec-WebSocket-Key` fields masked out. Catches header order, `User-Agent`, the `:443` in `Host`, capitalisation. |
| the server's 101 response, byte for byte | **`wsprobe2` case A's captured output** | Same treatment for the four-line response, with the accept masked. Catches a stray `Date:` or `Server:` header. |
| **the C server against a real client** | **Go `ck-client` in cdn mode**, and separately a stock `gorilla` client, and separately `websocat`/a browser | The highest-value test on this module. The C server is the piece that can ship first (§5.1) and the piece an outside client can fully exercise. |
| **the C client against a real server** (if 8b happens) | **Go `ck-server`** | Mirrors the above. |
| frame encoding | **a stock gorilla server/client as decoder** | Feed C-produced frames into `gorilla`'s `advanceFrame` and assert no `"bad MASK"`, no `"RSV1 set"`, no `"bad opcode"`. gorilla is a fussy, independently-written validator — exactly the oracle role the *server* played for the *client* on the last branch. |
| behaviour under fragmentation | **a hand-written fragmenting proxy** | Split every C→peer message into 2-3 continuation frames and interleave a ping. Neither end of a C↔C test would ever produce this; a Go peer would not either. It has to be synthesised. |
| pong-on-ping | **gorilla client with `SetPongHandler`** | Assert the C server answers a ping within one turn, with the same payload. |
| the framing-mode assertion (§6.3) | **raw socket bytes** | Assert first data-path byte is `0x17` on direct and `0x82` on CDN. Self-consistent but *positional* — it asserts against a constant from the RFC and from `conn.h`, not against our own other end. |

### 7.2 Properties with no oracle — handle with care

- **Partial-read resumption.** No outside system can tell you the C state
  machine resumes correctly at every split. The technique the tree already uses
  is the right one: a one-byte-per-turn driver plus an exposed `state` field
  (`client_transport.h:168-192` says the state enum is exposed precisely so a
  test can assert the machine resumes *mid-piece*, not just mid-record). Extend
  it: drive the CDN handshake at every split point from 1 to the full reply
  length, and assert the same session key comes out each time.
- **The no-over-read guarantee.** Also unobservable from outside. Assert it
  structurally: after `on_done` fires, the fd's kernel receive queue
  (`ioctl(FIONREAD)`) must hold exactly the bytes the test wrote *after* the
  reply and not one fewer — or, if the prefill design of §5.2 item 8 is chosen,
  assert the prefilled `bytequeue` length equals what was deliberately
  over-read.
- **Fingerprint fidelity in aggregate.** Whether a Cloak-C CDN client is
  distinguishable from a Cloak-Go one across many connections. No test can
  answer this; the golden-file diffs in §7.1 are the proxy for it, and the
  `ALPN`-stripped ClientHello (§3.4) remains an untested inherited property.
- **The §6.5 ordering fix.** That the C server redirects (rather than wedging)
  on a malformed upgrade is testable, but "it behaves identically to a bad
  `Hidden`" is a *timing and byte-stream equivalence* claim. Test it as such:
  capture the full byte stream and the wall-clock shape for (bad `Hidden`),
  (bad `Upgrade`), (unrecognised protocol) and assert all three are the same
  modulo the cover site's own variability.

### 7.3 Fuzz targets

`libcloak-server/src/firstpacket.c` already has a fuzz-shaped interface. Add two
more for module 8, both pure functions over a byte buffer with no reactor:

1. the server-side upgrade-request parser over `fp.buf` (attacker-controlled,
   unauthenticated — a fingerprint-class bug, per `http.h:17-30`'s taxonomy);
2. the WebSocket frame decoder (attacker-controlled; after the handshake it is
   *authenticated* only in the sense that the peer completed an upgrade, and the
   AEAD is one layer above, so a memory-safety bug here is serious).

Both belong in module 10's fuzzing corpus but should be written in module 8
while the invariants are fresh.

---

## 8. How big is this?

### 8.1 Server side (recommended scope for module 8)

| file | new/changed | est. lines (impl) |
|---|---|---|
| `libcloak-server/include/cloak/ws_handshake.h` | new | 200 (this tree's comment density) |
| `libcloak-server/src/ws_handshake.c` | new — header scan over `fp.buf`, validation, accept, 101 + framed-reply composition | 350 |
| `libcloak-server/src/server_auth.c` + `.h` | add `cloak_server_auth_compose_ws_reply` (flat 60 bytes) | 60 |
| `libcloak-server/src/dispatcher.c` | branch at `:399`; WS reply composition next to `:578`; update the step-1 prose at `:236-241` | 120 |
| `libcloak-mux/include/cloak/conn.h` + `src/conn.c` | framing mode; masking; continuation reassembly; control frames; `max_envelope_len` per mode | 400 |
| `libcloak-mux/include/cloak/session.h` + `src/session.c` | plumb the mode to `cloak_session_add_conn` | 60 |
| `libcloak-server/include/cloak/firstpacket.h` | rewrite the "no consumer" paragraph | doc only |
| tests: `test_ws_handshake.c`, `test_conn_ws_framing.c`, `test_dispatcher_ws.c`, additions to `test_server_e2e.c` | new | 2000+ |

**~1200 lines of implementation, ~2000 of tests, 8-11 tasks.**

### 8.2 Client side

Without a TLS client it is not shippable at all (§5.1). With option (b),
`libssl` + non-blocking `SSL_connect`:

| file | est. lines |
|---|---|
| `libcloak-common/src/tls_client.c` + header — reactor-driven `SSL_connect`, `SSL_read`/`SSL_write` pumped on `WANT_READ`/`WANT_WRITE` | 450 |
| `libcloak-client/src/client_ws.c` + header — the 7-state handshake of §5.2 | 450 |
| `libcloak-client/src/client_connector.c` — branch on transport; the D3 guard at `:305-320` becomes live | 100 |
| `libcloak-client/src/client_stack.c` — remove the refusal at `:872`; plumb `cdn_origin_host`/`cdn_ws_url_path` (today documented as unreachable at `client_stack.h:349-351`) | 80 |
| tests, incl. a Go-`ck-server` interop harness | 1500+ |

**~1100 lines of implementation, 7-9 more tasks** — and a genuinely new
dependency and a new fingerprint story. That is why I would make it module 8b.

### 8.3 Riskiest part, and why

Ranked:

1. **The framing-mode plumbing in `cloak_conn_t` (§6.3).** Not because it is
   hard — it is a couple of hundred lines — but because it is the *same shape*
   as the defect that survived five modules. It is a change to the one file in
   the tree whose header spends 46 lines begging you not to change it
   carelessly; it introduces a mode that is correct in one configuration and a
   perfect fingerprint in the other; the wrong choice is invisible to every
   round-trip test because both ends agree; and the `max_envelope_len`
   arithmetic is off-by-four in a way that only manifests at maximum frame size.
   **Mitigation: the raw-first-byte assertion of §6.3 item 3, plus gorilla as a
   decoder oracle (§7.1), plus an enum whose zero value is invalid.**

2. **The TLS decision (§5.1).** Not risky to *implement* under option (b), but
   risky to *decide*: it is the difference between module 8 being two weeks and
   being two months, and it changes the product's fingerprint story. It needs to
   be settled before the plan is written, not during it.

3. **CDN-rewriting robustness (§3.3, §6.9).** Every one of these bugs passes
   the entire test suite and fails in production, behind an intermediary we do
   not control and cannot fully simulate. The fragmenting/ping-injecting proxy
   of §7.1 is the only defence, and it has to be written deliberately because
   nothing else in the system produces those inputs.

4. **The §6.5 ordering.** Low implementation risk, high value: getting the
   validation order right (upgrade headers checked *with* `Hidden`, before the
   user panel is touched) both avoids Go's wedge and improves the cover-site
   mimicry. Cheap, and easy to get wrong by mirroring Go's structure too
   faithfully.
