#!/usr/bin/env python3
"""Fit a growth rate, with its uncertainty, to a soak_growth CSV.

WHY A FIT AND NOT A DIFFERENCE. "RSS went from 40 MB to 41 MB" is not a
measurement: without the scatter around the trend it is indistinguishable
from a single 4 KiB page arriving late. What an operator needs is a slope
and an interval, and what a reviewer needs after that is the run length
that would have been required to distinguish that slope from zero. All
three are printed below, per column.

THE ARITHMETIC, stated so it can be checked rather than trusted. For an
ordinary least-squares fit y = a + b*t over n samples evenly spaced dt
apart across a run of length T = (n-1)*dt:

    Sxx      = sum (t_i - mean t)^2  ~= n*T^2/12
    s        = sqrt( sum residual^2 / (n - 2) )
    SE(b)    = s / sqrt(Sxx) ~= s * sqrt(12*dt) * T^(-3/2)

The T^(-3/2) is the whole economics of a soak test: halving the
uncertainty costs 2^(2/3) = 1.59x the run, and buying a factor of ten
costs 4.6x. Inverting it gives the run length at which a slope of a given
size becomes 2-sigma separable:

    T_req    = ( 2 * k * s * sqrt(12*dt) / |b| ) ^ (2/3)

and the smallest slope a run of length T could have separated:

    b_min(T) = 2 * k * s * sqrt(12*dt) * T^(-3/2)

TWO REGIMES, AND THE SECOND ONE IS THE ONE THIS WORKLOAD IS IN. The
formulae above assume the samples scatter. Several of these columns do
not scatter at all -- they hold one value for the whole run -- and for
those the limit is not statistical but quantisation: the smallest
detectable slope is one unit over the run, falling as 1/T rather than
T^(-3/2). The tables below print that floor -- 3600/T units per hour,
marked "q" -- for such a column, and "n/a (quantised)" in T_req. They
used to print 0 and "0 (no scatter)", which read as "a 60-second run
separates an arbitrarily small leak in fds, timers and sessions". Run
--self-check to see that regression caught.

k IS THE HONEST PART. Samples of RSS and of an allocator's in-use total
are strongly autocorrelated -- memory arrives in steps and stays -- so the
textbook SE above, which assumes independent residuals, is optimistic.
k = sqrt((1+r)/(1-r)) from the lag-1 residual autocorrelation r is the
usual AR(1) correction for the effective sample size; it is reported
alongside r so a reader can see how much of the claimed precision is
being given back. Where r is near 1 the corrected interval is the one to
quote.

--window=N ANSWERS A DIFFERENT AND MORE OPERATIONAL QUESTION: what would
a test of length N actually have reported? It splits the run into disjoint
N-second windows, fits each one independently, and prints the spread of
the resulting slopes. That spread is the number a ctest threshold would
have to clear, because it is the run-to-run variation a short test really
produces -- where the in-window standard error assumes independent
residuals and a stationary process, and memory is neither. Use it, not
the SE, to argue about whether a short case is worth having.

Usage:
    analyze.py FILE.csv [--skip-seconds=N] [--columns=a,b,c] [--window=N]
    analyze.py --self-check

--self-check RUNS THIS TOOL AGAINST SYNTHETIC DATA WITH KNOWN ANSWERS,
and it exists because this is a measuring instrument whose output a
ledger quotes as fact. It is NOT a ctest case: the cloak-c-dev image has
no python3 at all, so registering it would either fail the build or, far
worse, silently not register and leave the suite count looking right.
Run it on the host, by hand, whenever this file changes:

    python3 tools/soak/analyze.py --self-check

It reproduces the two defects a review found here and asserts they stay
fixed. See self_check() for what each one was.
"""

import math
import sys

DEFAULT_COLUMNS = [
    "rss_kb",
    "rss_anon_kb",
    "rss_file_kb",
    "rss_anon_huge_kb",
    "uordblks",
    "hblkhd",
    "arena",
    "fds",
    "timers",
    "sessions",
    "proxy_streams",
    "proxy_sessions",  # F8: written by soak_growth.c and live (0 -> K); was never fitted
]


def read_csv(path):
    header = None
    rows = []
    meta = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                meta.append(line)
                continue
            if header is None:
                header = line.split(",")
                continue
            parts = line.split(",")
            if len(parts) != len(header):
                continue
            rows.append([float(p) for p in parts])
    return meta, header, rows


def ols(ts, ys):
    n = len(ts)
    tbar = sum(ts) / n
    ybar = sum(ys) / n
    sxx = sum((t - tbar) ** 2 for t in ts)
    sxy = sum((ts[i] - tbar) * (ys[i] - ybar) for i in range(n))
    if sxx == 0.0:
        return 0.0, ybar, [0.0] * n, 0.0
    b = sxy / sxx
    a = ybar - b * tbar
    resid = [ys[i] - (a + b * ts[i]) for i in range(n)]
    return b, a, resid, sxx


# The clamp on the lag-1 autocorrelation, and the largest k it can
# produce. THESE TWO MUST BE KEPT CONSISTENT WITH THE GUARD IN ar1_k:
# the previous version clamped r to 0.999 and then wrote
# `k = ... if r1 < 0.999 else 1.0`, so every column whose true
# autocorrelation reached the clamp silently got NO correction at all --
# k printed as 1.00, indistinguishable in the output from an
# uncorrelated column, at exactly the autocorrelation where the
# correction matters most. Just below the boundary the same code gives
# k = 44.7, so the interval jumped by 43x across a boundary the data
# could not see, always in the optimistic direction. See self_check().
R_CLAMP = 0.9999
K_MAX = math.sqrt((1.0 + R_CLAMP) / (1.0 - R_CLAMP))  # ~141.4


def lag1_autocorr(resid):
    n = len(resid)
    if n < 3:
        return 0.0
    num = sum(resid[i] * resid[i + 1] for i in range(n - 1))
    den = sum(r * r for r in resid)
    if den == 0.0:
        return 0.0
    r = num / den
    return max(-R_CLAMP, min(R_CLAMP, r))


def ar1_k(r1):
    """The AR(1) variance-inflation factor, and whether it was capped.

    Returns (k, capped). k is never silently 1.0 for a strongly
    autocorrelated column: at the clamp it is K_MAX and `capped` is True,
    which the tables mark with a '*' so a reader can see the number is a
    FLOOR on the correction rather than an estimate of it.
    """
    if r1 >= R_CLAMP:
        return K_MAX, True
    if r1 <= -R_CLAMP:
        return math.sqrt((1.0 + -R_CLAMP) / (1.0 - -R_CLAMP)), True
    return math.sqrt((1.0 + r1) / (1.0 - r1)), False


def fmt(x):
    if x == 0.0:
        return "0"
    ax = abs(x)
    if ax >= 1e5 or ax < 1e-3:
        return "%.3e" % x
    return "%.4g" % x


def analyse(path, skip_seconds, columns):
    meta, header, rows = read_csv(path)
    for m in meta:
        print(m)
    if not rows:
        print("no data rows")
        return
    t_idx = header.index("t_ms")
    rows = [r for r in rows if r[t_idx] / 1000.0 >= skip_seconds]
    if len(rows) < 4:
        print("too few samples after --skip-seconds=%g" % skip_seconds)
        return
    ts = [r[t_idx] / 1000.0 for r in rows]
    n = len(ts)
    T = ts[-1] - ts[0]
    dt = T / (n - 1) if n > 1 else 0.0
    print("samples=%d  window=[%.1f, %.1f] s  T=%.1f s  dt=%.3f s" % (n, ts[0], ts[-1], T, dt))
    if "cycles" in header:
        c0 = rows[0][header.index("cycles")]
        c1 = rows[-1][header.index("cycles")]
        print("cycles over window: %d  (%.2f/s)" % (c1 - c0, (c1 - c0) / T if T else 0.0))
    if "fails" in header:
        f0 = rows[0][header.index("fails")]
        f1 = rows[-1][header.index("fails")]
        print("failed cycles over window: %d" % (f1 - f0))
    print("")
    hdr = ("%-14s %12s %12s %12s %7s %6s %14s %14s"
           % ("column", "first", "last", "slope/hr", "r_lag1", "k", "+-2se_naive/hr",
              "+-2se_ar1/hr"))
    print(hdr)
    print("-" * len(hdr))
    any_capped = False
    for col in columns:
        if col not in header:
            continue
        idx = header.index(col)
        ys = [r[idx] for r in rows]
        b, _a, resid, sxx = ols(ts, ys)
        dof = n - 2
        s = math.sqrt(sum(x * x for x in resid) / dof) if dof > 0 else 0.0
        se = s / math.sqrt(sxx) if sxx > 0 else 0.0
        r1 = lag1_autocorr(resid)
        k, k_capped = ar1_k(r1)
        any_capped = any_capped or k_capped
        print("%-14s %12s %12s %12s %7.4f %6s %14s %14s"
              % (col, fmt(ys[0]), fmt(ys[-1]), fmt(b * 3600.0), r1,
                 ("%.2f*" % k) if k_capped else ("%.2f" % k),
                 fmt(2 * se * 3600.0), fmt(2 * se * k * 3600.0)))
    if any_capped:
        print("")
        print("* k is CAPPED at %.2f (residual autocorrelation r reached the +-%.4f clamp)."
              % (K_MAX, R_CLAMP))
        print("  The true AR(1) inflation is LARGER, so the starred interval is a FLOOR on the")
        print("  uncertainty, not an estimate of it. Do not read a starred column as precise.")
    print("")
    print("Separation: run length T_req needed for |slope| to reach 2 sigma (AR1-corrected),")
    print("and the smallest slope a run of the given length could separate.")
    print("")
    hdr2 = ("%-14s %14s %14s %14s %14s"
            % ("column", "resid_sd", "T_req(s)", "bmin@60s/hr", "bmin@900s/hr"))
    print(hdr2)
    print("-" * len(hdr2))
    any_quant = False
    any_capped2 = False
    for col in columns:
        if col not in header:
            continue
        idx = header.index(col)
        ys = [r[idx] for r in rows]
        b, _a, resid, sxx = ols(ts, ys)
        dof = n - 2
        s = math.sqrt(sum(x * x for x in resid) / dof) if dof > 0 else 0.0
        r1 = lag1_autocorr(resid)
        k, k_capped = ar1_k(r1)
        any_capped2 = k_capped or any_capped2
        c = 2.0 * k * s * math.sqrt(12.0 * dt) if dt > 0 else 0.0

        def bmin(tt):
            """Smallest slope a run of tt seconds could separate, per SECOND.

            TWO REGIMES, and printing the statistical one for a column in
            the quantisation regime is how this tool used to claim a
            60-second run could separate an ARBITRARILY SMALL leak in
            fds, timers, sessions and the malloc counters: with s == 0
            the standard error is 0 and c * tt**-1.5 is 0.

            A column that does not scatter is not infinitely sensitive;
            it is INTEGER-VALUED and flat, and the smallest slope it
            could have hidden is one unit over the whole run, i.e.
            1/tt per second (3600/tt per hour). That floor is what gets
            printed for such a column, marked 'q'.
            """
            if tt <= 0:
                return float("inf"), False
            if c == 0.0:
                return 1.0 / tt, True
            return c * tt ** -1.5, False

        if b != 0.0 and c > 0.0:
            t_req = (c / abs(b)) ** (2.0 / 3.0)
            t_req_s = "%.0f" % t_req
        elif c == 0.0:
            # NOT "0", which read as "no more run needed". A column with
            # no scatter has no statistical separation problem at all --
            # its limit is the quantisation floor in the bmin columns,
            # and no amount of extra run moves it below 1 unit / T.
            t_req_s = "n/a (quantised)"
        else:
            t_req_s = "inf (slope 0)"
        b60, q60 = bmin(60.0)
        b900, q900 = bmin(900.0)
        any_quant = any_quant or q60 or q900
        print("%-14s %14s %14s %14s %14s"
              % (col, fmt(s), t_req_s,
                 fmt(b60 * 3600.0) + (" q" if q60 else ""),
                 fmt(b900 * 3600.0) + (" q" if q900 else "")))
    if any_quant:
        print("")
        print("q = QUANTISATION FLOOR, 3600/T units per hour, not a standard error. The column")
        print("  did not scatter, so its limit is one integer unit over the run. This tool used")
        print("  to print 0 here, which read as 'a 60-second run separates an arbitrarily small")
        print("  leak in fds/timers/sessions'. It does not.")
    if any_capped2:
        print("  (One or more columns had k capped at %.2f; their bmin is correspondingly a"
              % K_MAX)
        print("   floor.)")


def window_slopes(path, skip_seconds, columns, window):
    _meta, header, rows = read_csv(path)
    t_idx = header.index("t_ms")
    rows = [r for r in rows if r[t_idx] / 1000.0 >= skip_seconds]
    if len(rows) < 4:
        print("too few samples for windowing")
        return
    t0 = rows[0][t_idx] / 1000.0
    buckets = {}
    for r in rows:
        w = int((r[t_idx] / 1000.0 - t0) // window)
        buckets.setdefault(w, []).append(r)
    keys = sorted(k for k in buckets if len(buckets[k]) >= 4)
    print("")
    print("What a %g-second test would have reported: %d disjoint windows" % (window, len(keys)))
    hdr = ("%-14s %12s %12s %12s %12s %12s"
           % ("column", "mean/hr", "sd/hr", "min/hr", "max/hr", "span/hr"))
    print(hdr)
    print("-" * len(hdr))
    for col in columns:
        if col not in header:
            continue
        idx = header.index(col)
        slopes = []
        for k in keys:
            rs = buckets[k]
            ts = [r[t_idx] / 1000.0 for r in rs]
            ys = [r[idx] for r in rs]
            b, _a, _resid, _sxx = ols(ts, ys)
            slopes.append(b * 3600.0)
        if not slopes:
            continue
        m = sum(slopes) / len(slopes)
        sd = (math.sqrt(sum((x - m) ** 2 for x in slopes) / (len(slopes) - 1))
              if len(slopes) > 1 else 0.0)
        print("%-14s %12s %12s %12s %12s %12s"
              % (col, fmt(m), fmt(sd), fmt(min(slopes)), fmt(max(slopes)),
                 fmt(max(slopes) - min(slopes))))


def _synth_csv(path, n, dt_s, cols):
    """Writes a CSV in soak_growth.c's format. cols maps name -> f(i)."""
    names = list(cols.keys())
    with open(path, "w") as f:
        f.write("# synthetic, analyze.py --self-check\n")
        f.write(",".join(["t_ms"] + names) + "\n")
        for i in range(n):
            vals = [str(int(round(i * dt_s * 1000.0)))]
            vals += ["%.6f" % cols[c](i) for c in names]
            f.write(",".join(vals) + "\n")


def _capture(fn, *a, **kw):
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*a, **kw)
    return buf.getvalue()


def self_check():
    """Regression checks for the two defects a review found in this file.

    F1 -- A COLUMN THAT DOES NOT SCATTER WAS REPORTED AS INFINITELY
    SENSITIVE. For s == 0 the code computed c = 2*k*s*sqrt(12*dt) = 0 and
    printed bmin = c * T**-1.5 = 0 under a heading reading "the smallest
    slope a run of the given length could separate", and "0 (no scatter)"
    under T_req. Read literally, that table said a 60-second run could
    separate an arbitrarily small leak in fds, timers, sessions and every
    malloc counter -- the exact columns run A reports as flat. The true
    limit is quantisation: one integer unit over the run, 3600/T per
    hour. The check below asserts 60.0/hr at T=60 and 4.0/hr at T=900,
    and that the literal string "0" is no longer what appears there.

    F2 -- THE AR(1) CORRECTION SWITCHED ITSELF OFF AT THE
    AUTOCORRELATION WHERE IT MATTERED MOST. lag1_autocorr clamped r to
    0.999 and the caller guarded `if r1 < 0.999 else 1.0`, so a column
    at or above r = 0.999 got k = 1.00 -- no correction, and printed
    indistinguishably from an uncorrelated column. Just below the
    boundary the same code gives k = 44.7, a 43x wider interval, so the
    discontinuity ran in the optimistic direction: the more
    autocorrelated the samples, the narrower the reported interval. It is
    reachable at --sample-ms=100, which is the obvious thing to do to buy
    sensitivity. The check below drives a smoothly drifting column at
    that cadence and asserts the AR1 interval is much wider than the
    naive one, and that k is neither 1.00 nor silently unmarked.
    """
    import tempfile
    import os
    failures = []

    def check(cond, msg):
        if not cond:
            failures.append(msg)
            print("SELF-CHECK FAIL: " + msg)

    tmp = tempfile.mkdtemp(prefix="analyze_selfcheck_")

    # ---- F1: a column that never moves, 900 samples at 1 s ----
    f1 = os.path.join(tmp, "flat.csv")
    _synth_csv(f1, 900, 1.0, {"fds": lambda i: 76.0, "timers": lambda i: 33.0})
    out1 = _capture(analyse, f1, 0.0, ["fds", "timers"])
    check("q" in out1, "F1: no quantisation-floor marker in the bmin columns")
    check("n/a (quantised)" in out1, "F1: T_req still reads as though no more run were needed")
    check("0 (no scatter)" not in out1, "F1: the old T_req string is back")
    # The floors, read out of the table-2 rows directly. Both bmin cells
    # end in the "q" marker, so parse from the right.
    got = {}
    for line in out1.splitlines():
        p = line.split()
        if len(p) >= 5 and p[0] in ("fds", "timers") and p[-1] == "q" and p[-3] == "q":
            got[p[0]] = (float(p[-4]), float(p[-2]))
    check(len(got) == 2, "F1: could not parse the two quantisation rows out of the table")
    for col, (b60, b900) in got.items():
        check(abs(b60 - 60.0) < 1e-6, "F1: %s bmin@60s is %r, want 3600/60 = 60" % (col, b60))
        check(abs(b900 - 4.0) < 1e-6, "F1: %s bmin@900s is %r, want 3600/900 = 4" % (col, b900))

    # ---- F2: a smoothly drifting column at --sample-ms=100 ----
    # A near-integrated series: residuals about the OLS line are strongly
    # autocorrelated, which is exactly the RSS shape the harness watches.
    f2 = os.path.join(tmp, "drift.csv")
    # An INTEGRATED random walk (twice-integrated noise), not a plain one:
    # a plain walk at this length detrends to r ~ 0.998, just BELOW the
    # old 0.999 boundary, so it would not have reached the collapse at
    # all. Memory that arrives in steps and stays is smoother than a
    # random walk, and this reaches r = 0.9999 -- i.e. the clamp, which
    # is precisely the regime the old code answered with k = 1.00.
    state = [0.0, 0.0]
    import random
    rnd = random.Random(20260921)

    def rss(i):
        state[1] += rnd.gauss(0.0, 1.0)
        state[0] += state[1]
        return 100000.0 + 0.18 * i + 0.05 * state[0]

    _synth_csv(f2, 9000, 0.1, {"rss_anon_kb": rss})
    out2 = _capture(analyse, f2, 0.0, ["rss_anon_kb"])
    row = [l for l in out2.splitlines() if l.startswith("rss_anon_kb")][0].split()
    r1 = float(row[4])
    kstr = row[5]
    se_naive = float(row[6])
    se_ar1 = float(row[7])
    check(r1 >= 0.999,
          "F2: the synthetic column (r=%r) does not reach the regime the defect lived in" % r1)
    check(kstr not in ("1.00",), "F2: k collapsed to 1.00 at r=%r -- the correction is off" % r1)
    check(se_ar1 > 5.0 * se_naive,
          "F2: AR1 interval %r is not meaningfully wider than naive %r at r=%r"
          % (se_ar1, se_naive, r1))
    # And the discontinuity itself: k must not jump across the old 0.999
    # boundary, and must never be 1.0 for a strongly correlated column.
    k_lo, _ = ar1_k(0.9989)
    k_hi, _ = ar1_k(0.9991)
    check(k_hi > k_lo, "F2: k is not monotone across the old 0.999 boundary")
    check(k_hi / k_lo < 2.0, "F2: k jumps by %.1fx across the old boundary" % (k_hi / k_lo))
    k_clamp, capped = ar1_k(1.0)
    check(capped, "F2: r at the clamp is not reported as capped")
    check(abs(k_clamp - K_MAX) < 1e-9, "F2: k at the clamp is %r, want K_MAX" % k_clamp)

    for f in (f1, f2):
        os.unlink(f)
    os.rmdir(tmp)

    if failures:
        print("")
        print("SELF-CHECK: %d FAILURE(S)" % len(failures))
        return 1
    print("")
    print("SELF-CHECK OK: F1 (quantisation floor printed, not 0) and F2 (AR(1) correction")
    print("does not collapse to k=1 at r >= 0.999) both verified against synthetic data.")
    return 0


def main():
    args = sys.argv[1:]
    if "--self-check" in args:
        return self_check()
    if not args:
        print(__doc__)
        return 2
    path = None
    skip = 0.0
    window = 0.0
    columns = list(DEFAULT_COLUMNS)
    for a in args:
        if a.startswith("--skip-seconds="):
            skip = float(a.split("=", 1)[1])
        elif a.startswith("--window="):
            window = float(a.split("=", 1)[1])
        elif a.startswith("--columns="):
            columns = a.split("=", 1)[1].split(",")
        else:
            path = a
    if path is None:
        print(__doc__)
        return 2
    analyse(path, skip, columns)
    if window > 0:
        window_slopes(path, skip, columns, window)
    return 0


if __name__ == "__main__":
    sys.exit(main())
