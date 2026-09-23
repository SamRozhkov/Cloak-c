#!/usr/bin/env bash
# End-to-end benchmark: drives real traffic through a real ck-client and a
# real ck-server and prints what it measured, one key=value per line.
#
# THE POINT IS THE MATRIX, NOT ANY SINGLE ROW. Both ends can be ours or Go
# Cloak's, and a run that only ever measures ours against ours cannot tell
# "our stack is faster" from "our client is lighter". Swapping one end at a
# time is the whole design, and it is the same discipline the correctness
# tests already use in go_oracle_harness.h -- applied to time instead of
# to bytes.
#
# WHAT IT DOES NOT MEASURE, stated here because the numbers do not say it
# themselves: the Cloak handshake. It happens once, at client start-up,
# before the load generator connects. Every figure below describes an
# established tunnel. Handshake cost needs its own harness.
#
# Usage:
#   bench.sh --server=ours|go --client=ours|go --build=DIR [options]
#
#   --bytes=N     payload each way for the throughput run (default 64 MiB)
#   --rounds=N    round trips for the latency run          (default 2000)
#   --size=N      payload per latency round trip           (default 64)
#   --repeat=N    whole-measurement repetitions            (default 3)
#   --numconn=N   the client's NumConn                     (default 4)
#
# Every measurement is repeated and every repetition is printed. A single
# trial on shared hardware is an anecdote; this project has been bitten
# twice by numbers that were true once.

set -euo pipefail

SERVER=ours
CLIENT=ours
BUILD=""
BYTES=$((64 * 1024 * 1024))
ROUNDS=2000
SIZE=64
REPEAT=3
NUMCONN=4

for arg in "$@"; do
    case "$arg" in
        --server=*)  SERVER="${arg#*=}" ;;
        --client=*)  CLIENT="${arg#*=}" ;;
        --build=*)   BUILD="${arg#*=}" ;;
        --bytes=*)   BYTES="${arg#*=}" ;;
        --rounds=*)  ROUNDS="${arg#*=}" ;;
        --size=*)    SIZE="${arg#*=}" ;;
        --repeat=*)  REPEAT="${arg#*=}" ;;
        --numconn=*) NUMCONN="${arg#*=}" ;;
        *) echo "bench.sh: unknown argument $arg" >&2; exit 2 ;;
    esac
done

[ -n "$BUILD" ] || { echo "bench.sh: --build=DIR is required" >&2; exit 2; }

CK_SERVER="$BUILD/cmd/ck-server/ck-server"
CK_CLIENT="$BUILD/cmd/ck-client/ck-client"
GO_SERVER=/usr/local/bin/go-ck-server
GO_CLIENT=/usr/local/bin/go-ck-client
UPSTREAM="$BUILD/tools/bench/bench_upstream"
LOAD="$BUILD/tools/bench/bench_load"

for f in "$UPSTREAM" "$LOAD"; do
    [ -x "$f" ] || { echo "bench.sh: missing $f -- configure with -DCLOAK_BUILD_BENCH=ON" >&2; exit 1; }
done

case "$SERVER" in
    ours) SERVER_BIN="$CK_SERVER" ;;
    go)   SERVER_BIN="$GO_SERVER" ;;
    *) echo "bench.sh: --server must be ours or go" >&2; exit 2 ;;
esac
case "$CLIENT" in
    ours) CLIENT_BIN="$CK_CLIENT" ;;
    go)   CLIENT_BIN="$GO_CLIENT" ;;
    *) echo "bench.sh: --client must be ours or go" >&2; exit 2 ;;
esac
[ -x "$SERVER_BIN" ] || { echo "bench.sh: missing $SERVER_BIN" >&2; exit 1; }
[ -x "$CLIENT_BIN" ] || { echo "bench.sh: missing $CLIENT_BIN" >&2; exit 1; }

WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# A free port, checked rather than hoped for. bash's /dev/tcp connect
# succeeds only if something is already listening, so a failure is the
# signal we want.
pick_port() {
    local p
    for _ in $(seq 1 200); do
        p=$(( 20000 + RANDOM % 35000 ))
        if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
            echo "$p"; return 0
        fi
    done
    echo "bench.sh: no free port found" >&2; return 1
}

wait_for_port() {
    local port="$1" tries="${2:-300}"
    for _ in $(seq 1 "$tries"); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    return 1
}

# ---- keys. Ours generates them; the format is shared with Go, which is
# ---- itself a small interoperability check every run performs for free.
KEYS="$("$CK_SERVER" -k)"
PUBKEY="${KEYS%%,*}"
PRIVKEY="${KEYS##*,}"
UID_B64="$("$CK_SERVER" -u)"

UPSTREAM_PORT=""
SERVER_PORT="$(pick_port)"
LOCAL_PORT="$(pick_port)"

# ---- upstream
"$UPSTREAM" > "$WORK/upstream.port" 2>"$WORK/upstream.err" &
PIDS+=($!)
for _ in $(seq 1 100); do
    UPSTREAM_PORT="$(cat "$WORK/upstream.port" 2>/dev/null || true)"
    [ -n "$UPSTREAM_PORT" ] && break
    sleep 0.05
done
[ -n "$UPSTREAM_PORT" ] || { echo "bench.sh: upstream did not report a port" >&2; exit 1; }

cat > "$WORK/server.json" <<EOF
{
  "ProxyBook":    { "bench": ["tcp", "127.0.0.1:${UPSTREAM_PORT}"] },
  "BindAddr":     [":${SERVER_PORT}"],
  "BypassUID":    ["${UID_B64}"],
  "RedirAddr":    "127.0.0.1:${UPSTREAM_PORT}",
  "PrivateKey":   "${PRIVKEY}",
  "DatabasePath": "${WORK}/userinfo.db",
  "KeepAlive":    0
}
EOF

cat > "$WORK/client.json" <<EOF
{
  "Transport":        "direct",
  "ProxyMethod":      "bench",
  "EncryptionMethod": "aes-gcm",
  "UID":              "${UID_B64}",
  "PublicKey":        "${PUBKEY}",
  "ServerName":       "www.bing.com",
  "NumConn":          ${NUMCONN},
  "BrowserSig":       "chrome",
  "StreamTimeout":    300,
  "KeepAlive":        0
}
EOF

"$SERVER_BIN" -c "$WORK/server.json" >"$WORK/server.log" 2>&1 &
PIDS+=($!)
wait_for_port "$SERVER_PORT" || { echo "bench.sh: server never listened"; sed -n '1,40p' "$WORK/server.log"; exit 1; }

"$CLIENT_BIN" -c "$WORK/client.json" -s 127.0.0.1 -p "$SERVER_PORT" \
              -i 127.0.0.1 -l "$LOCAL_PORT" >"$WORK/client.log" 2>&1 &
PIDS+=($!)
wait_for_port "$LOCAL_PORT" || { echo "bench.sh: client never listened"; sed -n '1,40p' "$WORK/client.log"; exit 1; }

echo "server=$SERVER"
echo "client=$CLIENT"
echo "numconn=$NUMCONN"
echo "server_version=$("$SERVER_BIN" -v 2>&1 | head -1)"
echo "client_version=$("$CLIENT_BIN" -v 2>&1 | head -1)"

# One discarded pass before the measured ones. The first connection
# through a fresh tunnel pays for the proxy's upstream dial and for
# whatever the kernel has not yet sized; folding that into repetition 1
# would make the first row look slow for a reason that is not the code.
"$LOAD" --mode=latency --port="$LOCAL_PORT" --rounds=200 --size="$SIZE" >/dev/null 2>&1 || true

# A failed repetition must not abort the run. The logs printed below are
# the most diagnostic part of this script, and `set -e` skipping them
# exactly when a measurement failed is the opposite of useful -- the
# first run of this harness lost three of four rows' logs that way.
FAILURES=0
for r in $(seq 1 "$REPEAT"); do
    echo "--- repetition $r ---"
    if ! "$LOAD" --mode=throughput --port="$LOCAL_PORT" --bytes="$BYTES"; then
        echo "throughput_failed=1"
        FAILURES=$((FAILURES + 1))
    fi
    if ! "$LOAD" --mode=latency --port="$LOCAL_PORT" --rounds="$ROUNDS" --size="$SIZE"; then
        echo "latency_failed=1"
        FAILURES=$((FAILURES + 1))
    fi
done
echo "failed_measurements=$FAILURES" 

# Server and client logs are part of the result: a run that quietly lost
# a connection and re-handshaked is not the run the numbers describe.
echo "--- server log (tail) ---"
tail -30 "$WORK/server.log" || true
echo "--- client log (tail) ---"
tail -30 "$WORK/client.log" || true
