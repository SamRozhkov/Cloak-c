# Cloak-c

A C11 port of [Cloak](https://github.com/cbeuw/Cloak) — a pluggable transport
that disguises a proxy server as a normal web server, so that the traffic
resists active probing and protocol fingerprinting.

The port targets parity with the Go original: the same wire format, the same
configuration keys, the same command-line flags. A deployment that works with
`ck-server`/`ck-client` from upstream should work with these binaries without
changing anything but the executables.

**Status:** the server side is complete. The client speaks the direct TLS
transport; the CDN/WebSocket leg is implemented on the *server* only. See
[What is not here yet](#what-is-not-here-yet).

---

## Building

You need a C11 compiler, CMake ≥ 3.16, and OpenSSL's libcrypto. SQLite and
cJSON are vendored under `third_party/` — nothing to install.

On Debian/Ubuntu:

```sh
sudo apt-get install build-essential cmake libssl-dev
```

Then:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

This produces two binaries:

```
build/cmd/ck-server/ck-server
build/cmd/ck-client/ck-client
```

### With Docker

The repository ships a development image with the toolchain, the sanitizers
and the fuzzing dependencies already installed:

```sh
docker build -f Dockerfile.dev -t cloak-c-dev .
docker run --rm -v "$PWD":/src -w /src cloak-c-dev \
    bash -c 'cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j'
```

---

## Quick start

### 1. On the server, generate a key pair and a user ID

```sh
ck-server -k    # prints <public key>,<private key>
ck-server -u    # prints a UID
```

Keep the private key on the server. The public key and the UID go to the
client.

### 2. Write `server.json`

```json
{
  "ProxyBook": {
    "shadowsocks": ["tcp", "127.0.0.1:8388"],
    "openvpn":     ["tcp", "127.0.0.1:1194"]
  },
  "BindAddr":     [":443"],
  "BypassUID":    ["<the UID you generated>"],
  "RedirAddr":    "example.com",
  "PrivateKey":   "<the private key>",
  "AdminUID":     "<a separate UID, optional>",
  "DatabasePath": "userinfo.db",
  "KeepAlive":    0
}
```

`RedirAddr` is where anything that fails authentication is forwarded — that is
what an active prober sees, so point it at a real host that looks plausible
for your server name.

Run it:

```sh
ck-server -c server.json
```

### 3. Write `ckclient.json`

```json
{
  "Transport":        "direct",
  "ProxyMethod":      "shadowsocks",
  "EncryptionMethod": "aes-gcm",
  "UID":              "<the UID>",
  "PublicKey":        "<the public key>",
  "ServerName":       "www.bing.com",
  "NumConn":          4,
  "BrowserSig":       "chrome",
  "StreamTimeout":    300,
  "KeepAlive":        0
}
```

Run it:

```sh
ck-client -c ckclient.json -s <server ip> -p 443 -i 127.0.0.1 -l 1984
```

Your proxy client now connects to `127.0.0.1:1984` instead of the server
directly.

---

## Command-line reference

### `ck-server`

| Flag | Meaning |
|---|---|
| `-c <string>` | Path to the config file, or the config itself (default `server.json`) |
| `-k`, `-key` | Generate a public/private key pair on stdout as `<public>,<private>` |
| `-u`, `-uid` | Generate a UID on stdout |
| `-verbosity <level>` | `error`, `warn`, `info`, `debug` or `trace` (default `info`) |
| `-v` | Print the version |
| `-h` | Print usage |

### `ck-client`

| Flag | Meaning |
|---|---|
| `-c <string>` | Config file path, semicolon-separated options, or the config itself (default `ckclient.json`) |
| `-s <string>` | `remoteHost` — the IP of your proxy server |
| `-p <string>` | `remotePort` — should be 443 (default `443`) |
| `-i <string>` | `localHost` — where Cloak listens for proxy clients (default `127.0.0.1`) |
| `-l <string>` | `localPort` — where Cloak listens for proxy clients (default `1984`) |
| `-proxy <string>` | Proxy method name; must match an entry in the server's `ProxyBook` exactly |
| `-u` | The underlying proxy speaks UDP |
| `-a <string>` | `adminUID` — serve the admin API instead of proxying |
| `-verbosity <level>` | `error`, `warn`, `info`, `debug` or `trace` (default `info`) |
| `-v` | Print the version |
| `-h` | Print usage |

Command-line flags override the config file.

---

## Configuration reference

### Client (`ckclient.json`)

| Key | Values | Default |
|---|---|---|
| `Transport` | `direct`, `cdn` | `direct` |
| `ProxyMethod` | any name in the server's `ProxyBook` | — |
| `EncryptionMethod` | `plain`, `aes-gcm`, `aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305` | — |
| `UID` | base64 UID from `ck-server -u` | — |
| `PublicKey` | base64 public key from `ck-server -k` | — |
| `ServerName` | the SNI to present | — |
| `AlternativeNames` | list of further names, one picked per connection | — |
| `BrowserSig` | `chrome`, `firefox`, `safari` | — |
| `NumConn` | number of underlying TCP connections | `1` |
| `StreamTimeout` | seconds | `300` |
| `KeepAlive` | seconds; `0` or absent leaves the system default | off |
| `UDP` | the underlying proxy speaks UDP | `false` |
| `LocalHost`, `LocalPort`, `RemoteHost`, `RemotePort` | | see flags above |
| `CDNOriginHost`, `CDNWsUrlPath` | only with `"Transport": "cdn"` | — |

### Server (`server.json`)

| Key | Meaning |
|---|---|
| `ProxyBook` | map of proxy method name → `[network, address]` |
| `BindAddr` | list of addresses to listen on, e.g. `[":443"]` |
| `PrivateKey` | base64 private key from `ck-server -k` |
| `BypassUID` | list of UIDs that skip the user database entirely |
| `AdminUID` | UID authorised to use the admin API |
| `DatabasePath` | SQLite file holding per-user credit and limits |
| `RedirAddr` | where unauthenticated traffic is forwarded |
| `CncMode` | reserved; not implemented |
| `KeepAlive` | seconds |

Unknown keys are ignored, key matching is case-insensitive, and on a duplicate
key the last one wins — all three matching Go's `encoding/json`, verified by
running it.

---

## Running the tests

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
cd build && ctest -j4
```

85 test binaries, about 45 seconds wall-clock at `-j4`. Always go through
`ctest` rather than running a test binary directly — several tests need the
working directory and the fixtures CTest sets up.

Under the sanitizers:

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g"
cmake --build build-asan -j && (cd build-asan && ctest -j4)
```

### Optional build targets

Neither is part of the default build or the test suite:

| Option | What it builds |
|---|---|
| `-DCLOAK_FUZZ=ON` | the libFuzzer targets under `fuzz/` (needs clang) |
| `-DCLOAK_BUILD_SOAK=ON` | the long-running growth harness under `tools/soak/` |

The soak harness measures whether anything grows over a long run — memory,
descriptors, timers, sessions. It lives outside `ctest` deliberately; see
[`docs/runbooks/soak-growth.md`](docs/runbooks/soak-growth.md) for how to run
it and, just as importantly, what it cannot see.

---

## What is not here yet

- **Linux only.** Two files stand between this tree and FreeBSD or macOS:
  `libcloak-common/src/reactor.c` (five `epoll_create1`/`epoll_ctl`/
  `epoll_wait` calls, plus the translation of `EPOLLIN`/`EPOLLOUT`) and
  `libcloak-common/src/signals.c` (95 lines built on `signalfd`). Nothing
  else needs porting: the reactor already hides the backend behind
  `CLOAK_REACTOR_READABLE`/`CLOAK_REACTOR_WRITABLE`, so no caller names an
  `EPOLL*` constant outside a comment, and the remaining Linux-flavoured
  calls — `accept4` with `SOCK_NONBLOCK|SOCK_CLOEXEC` in `listener.c`, and
  `MSG_NOSIGNAL` on every send — exist on FreeBSD too. There is no `pipe2`,
  `eventfd`, `timerfd` or `splice` anywhere in the tree. Two tests count
  descriptors through `/proc/self/fd` and would need a local equivalent.
- **The client's CDN/WebSocket leg.** The server accepts CDN-fronted
  WebSocket connections; the client cannot yet originate them. This needs a
  real TLS stack and a decision about what fingerprint to present.
- **Chrome's extension shuffle.** Go reorders the ClientHello extensions on
  every connection for the Chrome profile (measured: 200/200 distinct orders
  for Chrome, 1/200 for Safari). This port pins the order, so its Chrome
  profile is distinguishable from real Chrome by that invariance. GREASE
  *is* drawn per connection, as Go does.
- `singleplex` combined with `UDP`, and `-u` combined with the CDN transport.

---

## Layout

```
libcloak-common/   config, logging, crypto, the ClientHello, the reactor
libcloak-mux/      sessions, streams, frames, the switchboard
libcloak-server/   dispatcher, user manager, admin API, replay cache
libcloak-client/   transport, connector, piper
cmd/ck-server/     the server binary
cmd/ck-client/     the client binary
fuzz/              libFuzzer targets
tools/soak/        the growth harness
docs/              design specs, plans and runbooks
```

The whole thing is a single-threaded, edge-triggered epoll reactor: every
place the Go original blocks a goroutine, this port keeps a resumable state
machine instead.

---

## Licence

See [LICENSE](LICENSE). Cloak is the work of [cbeuw](https://github.com/cbeuw);
this is a port of it, not a fork of the upstream project.
