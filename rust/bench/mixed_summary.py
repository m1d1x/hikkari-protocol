#!/usr/bin/env python3
"""Summary of bench/mixed.sh results (R1.5): per implementation, users and
load, the median and the spread (min-max) of the repeats.

The entry's CPU over hk-loadgen's window carries both paths. The price of a
user's packet is us_per_pkt of the runs without a download; the price of a
MiB of the download is the CPU the download added over the same impl and
users without one (the median of those runs), per MiB carried in the window
(tcp MiB/s x window; each MiB crosses the entry twice, up and echoed down)."""
import sys, collections, statistics

rows = collections.defaultdict(list)
for line in open(sys.argv[1] if len(sys.argv) > 1 else "bench/out/results-mixed.txt"):
    kv = dict(p.split("=", 1) for p in line.split() if "=" in p)
    if "label" not in kv or "load" not in kv:
        continue
    rows[(kv["label"].split("#")[0], int(kv["users"]), kv["load"])].append(kv)


def med(v):
    return f"{statistics.median(v):.2f} ({min(v):.2f}–{max(v):.2f})" if len(v) > 1 else f"{v[0]:.2f}"


order = {"none": 0, "rate": 1, "flood": 2}
print("| load | users | impl | n | cpu % | us/pkt | us/MiB added | tcp MiB/s | gaps60/min | gaps150/min | gap_max ms | rtt p50 / p99 ms | lost voice/game/ack | tcp bad |")
print("|" + "---|" * 14)
for key in sorted(rows, key=lambda k: (order[k[2]], k[1], k[0])):
    impl, users, load = key
    rs = rows[key]
    f = lambda k: [float(r[k]) for r in rs]
    base = rows.get((impl, users, "none"))
    added = "-"
    mibs = "-"
    if load != "none":
        mibs = med(f("tcp_MiB/s"))
        if base:
            cpu0 = statistics.median(float(r["cpu_pct"]) for r in base)
            v = [(float(r["cpu_pct"]) - cpu0) / 100 * 1e6 / float(r["tcp_MiB/s"]) for r in rs if float(r["tcp_MiB/s"]) > 0]
            added = f"{statistics.median(v):.0f} ({min(v):.0f}–{max(v):.0f})" if v else "-"
    lost = "/".join(str(sum(int(r[k].split("/")[1]) - int(r[k].split("/")[0]) for r in rs)) for k in ("voice", "game", "ack"))
    bad = sum(int(r.get("tcp_bad", 0)) for r in rs)
    rtt = f"{statistics.median(f('rtt_p50_ms')):.2f} / {statistics.median(f('rtt_p99_ms')):.2f}"
    print(f"| {load} | {users} | {impl} | {len(rs)} | {med(f('cpu_pct'))} | {med(f('us_per_pkt')) if load == 'none' else '-'} | {added} | {mibs} | "
          f"{med(f('gaps60_per_min'))} | {med(f('gaps150_per_min'))} | {med(f('gap_max_ms'))} | {rtt} | {lost} | {bad} |")
