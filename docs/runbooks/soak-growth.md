# Runbook: measuring what does not leak but still grows

Module 10b, task 9. Owner: whoever next needs a number for "does the
server grow?".

## What this is for, and what it is not for

LeakSanitizer answers one question at process exit: *is this allocation
still reachable from a root?* A structure that grows without bound for
the life of the process, and is then freed correctly at exit, is **green
under ASan+LSan and fatal in production**. So is a timer heap that gains
an entry per session, a descriptor table that never shrinks, and a
counter that only rises. Nothing in this tree's 85 tests runs long
enough to see any of them: every test is bounded in seconds, by design.

This runbook produces **growth rates with uncertainties** — a slope, an
interval, and the run length that would have been needed to tell that
slope from zero. It does not produce a pass/fail. That is deliberate;
see "Why this is not a ctest case".

It measures **our** server. It says nothing about Go's, which differs in
at least one structure that matters (see "The comparison this does not
make").

## Prerequisites

- Docker image `cloak-c-dev`.
- Free disk: the build directory below is ~250 MB in Debug. The harness
  itself writes one CSV line per sample (about 90 bytes), so a one-hour
  run at the default cadence writes ~320 KB. **It does not grow a
  database**: the harness authenticates a BypassUID, so no credit rows
  are written and the SQLite file stays at its initial size. Check free
  space first anyway; this project has been at 99 % for three modules.

## Procedure

Configure and build the harness. It is **off by default** and is not a
ctest target, so it must be asked for by name:

```sh
docker run --rm -v /path/to/Cloak-c:/src -v /tmp/soak:/work \
  -w /src/.worktrees/<branch> cloak-c-dev bash -lc '
    cmake -S /src/.worktrees/<branch> -B /work/build -DCMAKE_BUILD_TYPE=Debug \
          -DCLOAK_BUILD_SOAK=ON &&
    cmake --build /work/build --target soak_growth -j8'
```

Run it. Three runs are what makes the result readable; they are
independent processes and can run at the same time on one host.

```sh
docker run --rm -v /path/to/Cloak-c:/src -v /tmp/soak:/work -w /work cloak-c-dev bash -lc '
  # A: the shipping configuration, 2^21-slot replay cache.
  /work/build/tools/soak/soak_growth --seconds=900 --sample-ms=1000 \
      --concurrency=16 --cycle-ms=20 --csv=/work/runA.csv &
  # B: the same, with the replay cache shrunk out of the way, so the
  #    residual slope is everything ELSE.
  /work/build/tools/soak/soak_growth --seconds=900 --sample-ms=1000 \
      --concurrency=16 --cycle-ms=20 --replay-capacity=4096 --csv=/work/runB.csv &
  # C: the positive control. 64 retained bytes per cycle, reachable at
  #    exit, i.e. invisible to LeakSanitizer. If C does not light up,
  #    the instrument is broken and A and B mean nothing.
  /work/build/tools/soak/soak_growth --seconds=900 --sample-ms=1000 \
      --concurrency=16 --cycle-ms=20 --replay-capacity=4096 --leak-bytes=64 \
      --csv=/work/runC.csv &
  wait'
```

Fit:

```sh
python3 tools/soak/analyze.py /tmp/soak/runA.csv --skip-seconds=30
python3 tools/soak/analyze.py /tmp/soak/runB.csv --skip-seconds=30 --window=60
python3 tools/soak/analyze.py /tmp/soak/runC.csv --skip-seconds=30
```

`--skip-seconds=30` drops the warm-up: the first cycles fill the K live
session slots and fault in the code that serves them, and a fit that
includes the warm-up measures the warm-up.

## Reading the output

Two tables per run.

The first gives, per column, the first and last value, the fitted slope
per hour, the lag-1 autocorrelation `r` of the residuals, the AR(1)
inflation factor `k = sqrt((1+r)/(1-r))`, and two 2-sigma intervals —
the textbook one and the autocorrelation-corrected one. **Quote the
corrected one.** Memory arrives in steps and stays, so successive
residuals are not independent and the textbook interval is optimistic.

The second gives the residual scatter, the run length `T_req` at which
the measured slope would have reached 2 sigma, and the smallest slope a
60-second and a 900-second run could have separated from zero. `T_req`
is the honest answer to "is this real?": if it is larger than the run
you did, **the run was too short to tell**, and that is a result to
report, not a failure to hide.

`--window=N` fits disjoint N-second windows and prints the spread of the
resulting slopes. That spread — not the in-window standard error — is
what a short test would really have produced run to run, and is the
number any threshold would have to clear.

### The columns, and what a bad value means

| column | growth means |
|---|---|
| `rss_kb` | the operator's complaint, and the least trustworthy column. Confounded by lazy faulting, by glibc retaining freed arenas, and by file pages the kernel adds and reclaims on its own. Never fit it alone. |
| `rss_anon_kb` | the anonymous half. **This** is where a leak has to appear. |
| `rss_file_kb` | the file-backed half. Moves for reasons belonging to the machine. |
| `rss_anon_huge_kb` | how much of the anonymous half the kernel has collapsed into 2 MiB transparent hugepages. Explains step changes that are not allocations. |
| `arena` | glibc's arena size. Rises, never falls. Rising while `uordblks` is flat is fragmentation, not a leak. |
| `uordblks` | glibc's in-use arena bytes. Steady state here should be **bit-exact** between cycles — and it is blind to whatever glibc chose to mmap. |
| `hblkhd` | mmapped bytes, which `uordblks` does **not** count. Measured: with 1 MiB retained per cycle, `uordblks` and `arena` stay bit-identical and only this column moves; at 200 KB the reverse. glibc's threshold is dynamic, so **read all four memory columns together** and never conclude from one. |
| `fds` | a descriptor leak. LSan cannot see these at all. |
| `timers` | the reactor's pending timers. Drift in *either* direction is a finding: module 10b's slot-indexed heap can lose a timer to a stale handle cancelling a recycled slot as easily as it can gain one. |
| `sessions` | the registry is not retiring sessions. Should sit at `--concurrency`. |
| `proxy_streams` | the proxy's per-session table is not retiring streams. |

### The two confounds you will hit first

**The replay cache is a real, bounded ramp and it dominates run A.** At
the shipping capacity of 2^21 slots x 40 bytes = 80 MiB, the table is one
`calloc`, so its pages become resident as handshakes touch them and RSS
climbs until they all are. That is growth, it is real, and it
**saturates** — which is exactly the property Go's equivalent does not
have. Run B exists to measure everything else without it.

**Transparent hugepages make that ramp much faster than the arithmetic
says, and they produce step changes that are not allocations at all.**
This image's kernel has THP at `always`
(`/sys/kernel/mm/transparent_hugepage/enabled`), so a touch anywhere in a
2 MiB region makes the whole region resident, and khugepaged separately
collapses the heap behind the program's back. Both were observed: the
heap's anonymous RSS stepped 2180 kB -> 13140 kB inside two minutes with
`uordblks`, `hblkhd` and `arena` bit-identical across the episode, and
`AnonHugePages` then read 12288 of 13136 kB. Without the
`rss_anon_huge_kb` column those are unexplained jumps that look exactly
like a leak. **Fit `rss_anon_kb`, and read `rss_anon_huge_kb` beside it
before believing any step.**

**`uordblks` is blind under ASan.** Measured in this image, under both
gcc and clang, an ASan build reports `uordblks` 0 before and after a
1 MiB malloc, because ASan's allocator replaces glibc's. Do not build
this harness with sanitizers and expect the sensitive column to work;
build it plain, which is what the procedure above does.

## Why this is not a ctest case

The decision was made on the runtime budget, as module 10b's Ruling 2
required, and the numbers are in `task-9-report.md`. The argument in
one paragraph:

Three measured reasons, in the order they decide it.

**There is no growth to find.** Over 750 s and 31,876 churn cycles with
the replay cache out of the way, every watched column was bit-identical
from the first sample to the last. The ruling's condition for overturning
the default was a ctest case that *finds real growth within the budget*;
no such growth exists here, so the condition is not met.

**The budget.** Sixty seconds is about twice the entire Debug suite's
measured wall clock at `-j4`, and roughly five times its longest Debug
test. One test would more than double the suite.

**The sensitive column does not work where it would be run.** Under ASan
— the configuration in which this project asks memory questions —
`mallinfo2` reports `uordblks` 0 on both sides of a 1 MiB malloc, under
gcc and clang alike, because ASan replaces the allocator. A cheap
in-process assertion would be inert in exactly the build that wanted it.

What the long run buys, stated plainly: with columns that do not
scatter, the detection floor is one unit per run, so it falls as **1/T**.
A 750 s window resolves 4.8 units/hour; a 60 s window resolves 60
units/hour. Twelve and a half times coarser, on every column.

A "no growth detected" from a 60-second run is not a small measurement.
It is a green light for a class of defect nobody has actually looked
for.

## The comparison this does not make

Go's replay cache is the obvious contrast and this harness does not
measure it. Upstream's cleaner sleeps `replayCacheAgeLimit` (12 h)
between passes, so an unauthenticated flood grows `UsedRandom` for up to
twelve hours, where ours is a fixed-capacity table that evicts. **That
is read, not measured** — see `task-9-report.md` for what was and was
not checked. Anyone extending this runbook should point the same sampler
at `go-ck-server`'s `/proc/<pid>/status` under a handshake flood; the
image already carries the binary.
