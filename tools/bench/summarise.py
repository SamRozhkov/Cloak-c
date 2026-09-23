#!/usr/bin/env python3
"""Turn bench.sh's key=value output into one table, with the spread shown.

WHY THE SPREAD AND NOT A MEAN. Three repetitions on a shared runner do not
justify a confidence interval, and printing one would dress up three
numbers as statistics. What IS defensible from three trials is the range
they actually covered, so that is what this prints: median, min and max,
side by side. A reader can then see for themselves whether a 5% gap
between two rows is outside the noise or inside it.

It reads the per-combination files bench.yml writes -- one per row of the
matrix, named server-<s>-client-<c>.txt -- and ignores anything else in
the directory, so a stray log does not become a row.

Runs on the RUNNER, not in cloak-c-dev: that image has no python3, which
is a fact this project has now paid for twice.
"""

import os
import re
import statistics
import sys

ROW = re.compile(r"^server-(?P<server>ours|go)-client-(?P<client>ours|go)\.txt$")
KV = re.compile(r"^([a-z0-9_]+)=([-0-9.]+)$")

# Printed in this order. Everything bench.sh emits that is not here is
# still in the raw artefact; this is the reading, not the record.
METRICS = [
    ("mib_per_s_one_way", "MiB/s one way", "%.1f", True),
    ("us_p50", "latency p50 us", "%.0f", False),
    ("us_p95", "latency p95 us", "%.0f", False),
    ("us_p99", "latency p99 us", "%.0f", False),
]


def parse(path):
    """Collect every repetition's values as {metric: [v, v, v]}."""
    out = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = KV.match(line.strip())
            if m:
                out.setdefault(m.group(1), []).append(float(m.group(2)))
    return out


def main(argv):
    if len(argv) != 2:
        print("usage: summarise.py BENCH_OUT_DIR", file=sys.stderr)
        return 2
    d = argv[1]

    rows = []
    for name in sorted(os.listdir(d)):
        m = ROW.match(name)
        if not m:
            continue
        rows.append((m.group("server"), m.group("client"), parse(os.path.join(d, name))))

    if not rows:
        print("no matrix files found in %s" % d, file=sys.stderr)
        return 1

    for key, label, fmt, higher_better in METRICS:
        print("\n%s  (%s is better)" % (label, "higher" if higher_better else "lower"))
        print("  %-8s %-8s %12s %12s %12s %6s" %
              ("server", "client", "median", "min", "max", "n"))
        base = None
        for server, client, vals in rows:
            v = vals.get(key)
            if not v:
                print("  %-8s %-8s %12s" % (server, client, "no data"))
                continue
            med = statistics.median(v)
            if server == "go" and client == "go":
                base = med
            print("  %-8s %-8s %12s %12s %12s %6d" %
                  (server, client, fmt % med, fmt % min(v), fmt % max(v), len(v)))
        # Go against Go is the reference point, so the comparison is
        # stated against it rather than against our own best row -- which
        # is the number that would flatter us.
        if base:
            print("  (go/go = %s is the reference)" % (fmt % base))

    print("\nNOT MEASURED: the Cloak handshake. It completes at client")
    print("start-up, before the load generator connects, so none of the")
    print("above includes X25519, the sealed auth payload or the replay")
    print("cache. See docs/runbooks/bench.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
