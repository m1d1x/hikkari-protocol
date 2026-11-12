#!/usr/bin/env python3
"""Summary of bench/run.sh results: per implementation and users, the median
and the spread (min-max) of the three repeats."""
import sys, collections, statistics
rows = collections.defaultdict(list)
for line in open(sys.argv[1] if len(sys.argv) > 1 else "bench/out/results.txt"):
    kv = dict(p.split("=", 1) for p in line.split() if "=" in p)
    if "label" not in kv:
        continue
    impl = kv["label"].split("#")[0]
    rows[(impl, int(kv["users"]))].append(kv)
keys = ["us_per_pkt", "us_per_user_dgram", "cpu_pct", "gaps60_per_min", "gaps150_per_min", "gap_max_ms", "rtt_p50_ms", "rtt_p99_ms"]
print("| impl | users | n | pkt/s | " + " | ".join(keys) + " | lost voice/game/ack |")
print("|" + "---|" * (len(keys) + 5))
for (impl, u) in sorted(rows, key=lambda k: (k[1], k[0])):
    rs = rows[(impl, u)]
    cells = []
    for k in keys:
        v = [float(r[k]) for r in rs]
        cells.append(f"{statistics.median(v):.2f} ({min(v):.2f}–{max(v):.2f})" if len(v) > 1 else f"{v[0]:.2f}")
    lost = []
    for k in ("voice", "game", "ack"):
        lost.append(str(sum(int(r[k].split("/")[1]) - int(r[k].split("/")[0]) for r in rs)))
    pps = statistics.median(float(r["pkts_per_s"]) for r in rs)
    print(f"| {impl} | {u} | {len(rs)} | {pps:.0f} | " + " | ".join(cells) + " | " + "/".join(lost) + " |")
