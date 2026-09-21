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
T^(-3/2). The tables below print "0 (no scatter)" for such a column
rather than an interval, and the right thing to quote for it is that
floor: 3600/T units per hour.

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


def lag1_autocorr(resid):
    n = len(resid)
    if n < 3:
        return 0.0
    num = sum(resid[i] * resid[i + 1] for i in range(n - 1))
    den = sum(r * r for r in resid)
    if den == 0.0:
        return 0.0
    r = num / den
    return max(-0.999, min(0.999, r))


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
        k = math.sqrt((1.0 + r1) / (1.0 - r1)) if r1 < 0.999 else 1.0
        print("%-14s %12s %12s %12s %7.3f %6.2f %14s %14s"
              % (col, fmt(ys[0]), fmt(ys[-1]), fmt(b * 3600.0), r1, k,
                 fmt(2 * se * 3600.0), fmt(2 * se * k * 3600.0)))
    print("")
    print("Separation: run length T_req needed for |slope| to reach 2 sigma (AR1-corrected),")
    print("and the smallest slope a run of the given length could separate.")
    print("")
    hdr2 = ("%-14s %14s %14s %14s %14s"
            % ("column", "resid_sd", "T_req(s)", "bmin@60s/hr", "bmin@900s/hr"))
    print(hdr2)
    print("-" * len(hdr2))
    for col in columns:
        if col not in header:
            continue
        idx = header.index(col)
        ys = [r[idx] for r in rows]
        b, _a, resid, sxx = ols(ts, ys)
        dof = n - 2
        s = math.sqrt(sum(x * x for x in resid) / dof) if dof > 0 else 0.0
        r1 = lag1_autocorr(resid)
        k = math.sqrt((1.0 + r1) / (1.0 - r1)) if r1 < 0.999 else 1.0
        c = 2.0 * k * s * math.sqrt(12.0 * dt) if dt > 0 else 0.0

        def bmin(tt):
            return c * tt ** -1.5 if tt > 0 else float("inf")

        if b != 0.0 and c > 0.0:
            t_req = (c / abs(b)) ** (2.0 / 3.0)
            t_req_s = "%.0f" % t_req
        elif c == 0.0:
            # A column with zero residual scatter: any non-zero slope is
            # separable from the first two samples, and a zero slope is
            # exactly zero for as long as the run lasted. Both are real
            # answers and neither is "more run would help".
            t_req_s = "0 (no scatter)"
        else:
            t_req_s = "inf (slope 0)"
        print("%-14s %14s %14s %14s %14s"
              % (col, fmt(s), t_req_s, fmt(bmin(60.0) * 3600.0), fmt(bmin(900.0) * 3600.0)))


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


def main():
    args = sys.argv[1:]
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
