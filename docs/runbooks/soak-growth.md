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
| `proxy_sessions` | the proxy's session table. Live (0 → K). It was written by the harness from the start but missing from `analyze.py`'s `DEFAULT_COLUMNS`, so it was sampled and never fitted until module 10b's fix wave. |

### What NO column can see: growth proportional to PEAK concurrency

**This is a limit of the workload, not of the column list, and adding a
column does not fix it.** `soak_growth` pins `--concurrency` for the
whole run and recycles the same K slots, so every structure sized by
*peak* rather than by *rate* sits at its K plateau from the warm-up
onward and cannot move again. Thirty-eight thousand cycles at a constant
K = 16 will never show it, in any column, however long the run.

The reactor's timer-slot array is exactly that shape: `timer_slot_free`
returns a slot to a free list and **never shrinks `r->slots`**, and a
slot whose generation counter is exhausted is retired and leaked by
design. The registry's chains and the strmtab are the same. A server
that ratchets 16 → 512 → 16 keeps the 512-slot allocation for the rest
of its life, and this harness would report every column bit-identical
throughout.

Closing it needs a **`--concurrency-sweep`** that walks K up and back
down and then asserts the columns return to their pre-sweep values.
Cheap, no new column, and carried out of module 10b rather than done.

### Two more limits worth stating before you quote a number

**`rss_anon_huge_kb` is host-dependent.** It reads identically 0 wherever
transparent hugepages are not `always` — including in `cloak-c-dev` on
some hosts — and it was the chief confounder on the host that produced
the published A/B/C numbers. Check
`/sys/kernel/mm/transparent_hugepage/enabled` before comparing your
numbers to anyone else's. **On a host where it is not `always`, the
baseline to expect is not the published one:** `rss_anon_huge_kb` reads 0
throughout *and* run B's `rss_anon_kb` should be flat or nearly so — the
~11 MB rise published here (2188 → 13,240 kB) should simply be absent,
not relocated into some other column, since every malloc column is
bit-identical across it either way. A non-THP host that *does* see run B
climb has found something this harness did not, and that is worth
chasing.

**`analyze.py` has a self-check; run it.** `python3 tools/soak/analyze.py
--self-check` drives the tool against synthetic data with known answers.
It is deliberately not a ctest case (`cloak-c-dev` has no python3, so it
would silently not register), and it exists because two defects in this
instrument shipped — one printing a detectable-slope of **zero** for
every column that does not scatter, one switching the AR(1) correction
off at exactly the autocorrelation where it mattered. Run it whenever
`analyze.py` changes.

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

**There is no growth to find — IN RUN B.** Over 750 s and 31,876 churn
cycles, every watched column was bit-identical from the first sample to
the last. **State which run that is, because it matters: it is run B,
the `--replay-capacity=4096` configuration, which the server does not
ship.** In run A — the shipping 2^21 cache — `rss_anon_kb` is *not* flat
and is not supposed to be: it rose 1052 → 15356 kB over a 90 s
re-measurement and was still rising linearly at the end (531,054 kB/hr
over 30–60 s, 502,528 kB/hr over 60–90 s, i.e. no decay at all). That is
the 80 MiB replay table faulting in at the handshake rate; at ~510,000
kB/hr it needs **~578 s** to become fully resident, so in a 900 s run A
that column is a warm-up transient for roughly two thirds of the fit
window even after `--skip-seconds=30`. **A genuine anonymous leak of up
to ~500 MB/hr is not separable from it in run A.**

The shipping configuration is therefore defended not by a flat column
but by an **independent arithmetic cross-check**: run A's observed
94,832 kB against 82,144 (the table) + 13,256 (everything else, from run
B) = 95,400 computed. That is sound, and it is a different kind of
evidence from "the column did not move" — say so when you quote it.

The ruling's condition for overturning the ctest default was a case that
*finds real growth within the budget*; no such growth exists in run B, so
the condition is not met.

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

## The committed artefact, and what it is NOT

`tools/soak/artefacts/` holds a **240-second** A/B/C run and the
`analyze.py` output for it (`short-A.csv`, `short-B.csv`, `short-C.csv`,
`short-analysis.txt`). It is committed because module 10b's final review
could not verify Task 9's central claim at all: `/tmp/soak` was gone, the
900 s A/B/C CSVs had never been committed, and the number the ledger
quotes as fact was reproducible from nothing in the tree. **A
measurement quoted as fact with no surviving artefact is not a
measurement.**

**Say this plainly, because it is the whole point of the section: the
committed artefact is the SHORT run. The 900 s numbers this runbook
quotes elsewhere — 750 s, 31,876 cycles, 94,832 kB against 95,400
computed — are NOT reproducible from anything in this repository.** They
are the ledger's prose and nothing more. Re-run them if you need them.

What the short artefact does establish, on the host that produced it
(THP `always`, 40 cycles/s, 8,400 cycles per fitted window):

- **Run C, the positive control, lights up and B does not.** `uordblks`
  goes 1.354e7 → 1.435e7 B in C (slope 1.39e7 B/hr against an AR(1)
  2-sigma interval of 1.29e4) and is **bit-identical** in B. 64 retained
  bytes per cycle, reachable at exit and therefore invisible to LSan, is
  seen. The instrument works.
- **Run B: nine of the twelve columns are bit-identical** over the fitted
  window — `uordblks`, `hblkhd`, `arena`, `fds`, `timers`, `sessions`,
  `proxy_streams`, `proxy_sessions`, `rss_file_kb`.
- **The three anonymous-RSS columns are NOT flat even in run B on this
  host, and that is THP, not a leak.** `rss_anon_kb` rises 2188 → 13240
  kB while `rss_anon_huge_kb` rises 0 → 10240 kB, i.e. the kernel
  collapsing the heap accounts for almost the whole rise, with
  `uordblks`, `hblkhd` and `arena` bit-identical throughout. This is the
  confound documented above, reproduced. **The review's host had THP off
  and saw `rss_anon_huge_kb` identically 0; ours does not. Check your own
  host before comparing.**
- **Run A is the shipping configuration and its `rss_anon_kb` is a
  ramp**, 6784 → 90,960 kB in 240 s, still climbing at the end. Every
  counter column is bit-identical throughout. With THP on, the 80 MiB
  table faults in far faster than the ~578 s the review measured without
  it — another reason that figure is host-specific.

240 seconds is a quarter of the published run, so by the 1/T floor the
artefact resolves 15 units/hour on a non-scattering column against the
750 s fit's 4.8. It is an artefact that proves the instrument and the
procedure, **not** a replacement for the long run.

## The comparison this does not make

Go's replay cache is the obvious contrast and this harness does not
measure it. Upstream's cleaner sleeps `replayCacheAgeLimit` (12 h)
between passes, so an unauthenticated flood grows `UsedRandom` for up to
twelve hours, where ours is a fixed-capacity table that evicts. **That
is read, not measured** — see `task-9-report.md` for what was and was
not checked. Anyone extending this runbook should point the same sampler
at `go-ck-server`'s `/proc/<pid>/status` under a handshake flood; the
image already carries the binary.
