# Benchmark runbook

How fast an established Cloak tunnel moves bytes, and how much latency it
adds — measured for this port and for Go Cloak v2.12.0 on the same machine
in the same run.

## What this measures, and what it does not

**Measured:** throughput and round-trip latency through a tunnel that is
already up.

**Not measured: the Cloak handshake.** It completes once, at client
start-up, before the load generator connects. X25519, the AEAD-sealed
authentication payload inside the ClientHello, and the replay-cache insert
all live there, so it is arguably the more interesting half of the system —
and it has no harness. Nothing in this repository measures it.

**And one number that looks like it does, but does not.** `tools/soak`
prints a `cycles` column, and a full session open lives inside each cycle.
Its rate is **not** a capacity figure: `soak_growth.c`'s loop ends every
cycle with `pump_for_ms(reactor, cycle_ms)` — a deliberate 20 ms idle pump.
The ~45 cycles/s in the committed artefacts is `1/0.020` minus overheads,
i.e. the harness's own pacing. The only thing honestly derivable from it is
the residual work per cycle: 21.93 ms per cycle on x86_64 and 25.03 ms on
aarch64, so roughly 1.9 ms and 5.0 ms of actual work. Those are two
different machines with one trial each, and the figure is a difference with
a constant subtracted — treat it as an order of magnitude, not a result.

## The matrix, and why there is one

Four rows: `ours/ours`, `ours/go`, `go/ours`, `go/go`. One end swapped at a
time, because `ours/ours` against `go/go` alone tells you which stack is
faster and never which **half** of it is. This is the same discipline
`go_oracle_harness.h` already applies to correctness, pointed at time.

`go/go` is the reference row in the summary, deliberately: comparing
against Go rather than against our own best row is the comparison that can
embarrass us.

## Running it

In CI, which is where the Go binaries live:

> Actions → **Bench** → Run workflow. Inputs: `bytes` (throughput payload
> each way, default 64 MiB), `rounds` (latency round trips, default 2000),
> `repeat` (repetitions per row, default 3).

Locally, inside `cloak-c-dev` (Go Cloak's `go-ck-client` and `go-ck-server`
are in its `/usr/local/bin`):

```sh
docker run --rm -v "$PWD":/src -w /src cloak-c-dev bash -c '
  cmake -S /src -B /src/build-bench -DCMAKE_BUILD_TYPE=Release \
        -DCLOAK_REQUIRE_GO=OFF -DCLOAK_BUILD_BENCH=ON &&
  cmake --build /src/build-bench -j \
        --target ck-server ck-client bench_upstream bench_load &&
  bash tools/bench/bench.sh --server=ours --client=ours --build=/src/build-bench'
```

`summarise.py` runs on the host, **not** in the image — `cloak-c-dev` has
no python3, a fact this project has now paid for twice.

## How to read the output

Every repetition is printed, and the summary shows **median, min and max**
rather than a mean with an interval. Three trials on a shared runner do not
justify a confidence interval; printing one would dress three numbers up as
statistics. If two rows differ by less than the spread within either of
them, they have not been shown to differ.

`Release`, never `Debug` — a benchmark of an unoptimised build measures the
build.

## The pieces

| File | What it is |
|---|---|
| `tools/bench/upstream.c` | The thing behind the proxy: a forking TCP echo server. It **echoes** rather than sinking, so every byte crosses both relays — the client's and the server's are separate state machines and an asymmetry between them is what a benchmark is for. Binds `:0` and prints its port. |
| `tools/bench/load.c` | The measuring end. Links nothing from this project on purpose: it speaks plain TCP from outside the tunnel, so the same binary measures our client and Go's. Throughput drives both directions with one `poll()` loop — writing everything then reading everything deadlocks as soon as the payload exceeds the socket buffers. Latency is sequential round trips with ten discarded warm-ups. |
| `tools/bench/bench.sh` | Generates keys and configs, starts upstream, server and client, waits for each port to accept, runs the load, prints `key=value` lines and the tail of both logs. |
| `tools/bench/summarise.py` | The table. |

Both helpers are off by default (`-DCLOAK_BUILD_BENCH=ON`) and neither is
an `add_test`. A timing assertion that can fail a build on shared hardware
is a flake generator, and three wall-clock assertions in this project were
already true on one machine and false on another.

## Known limits

- **The handshake is absent.** Stated twice on purpose.
- **Loopback only.** No RTT, no loss, no reordering, no MTU. A number here
  is an upper bound on a real path, and the gap between them is not
  measured.
- **One connection per measurement.** `NumConn` defaults to 4 underlying
  connections, but the load generator opens a single stream through them.
  Concurrency across many simultaneous streams is not covered.
- **One payload shape.** 128 KiB writes for throughput, 64 bytes for
  latency. Nothing probes the frame-size boundary at
  `maxStreamUnitWrite` = 16132, which is where a per-frame cost would show
  itself most clearly.
- **`aes-gcm` only.** The other three encryption methods are not timed,
  though `test_go_encryption_matrix` proves all four interoperate.
