#!/usr/bin/env python3
"""
Sanity-check sliding-window PPS math (no network required).

Run: python scripts/bench_sliding_stats.py
"""
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.stats import TrafficStatistics  # noqa: E402


def main() -> None:
    tstat = TrafficStatistics(graph_depth=60)
    t0 = time.perf_counter()
    # 500 events spread across ~0.5s → expect ~1000 pps instantaneous order of magnitude
    for i in range(500):
        tstat.record(nbytes=80, proto="TCP", direction="INBOUND", t_mono=t0 + i * 0.001)
    p1 = tstat.pps_1s()
    p10 = tstat.pps_10s_avg()
    bps = tstat.bytes_per_sec_1s(None)
    print(f"pps_1s (approx): {p1:.1f}")
    print(f"pps_10s_avg: {p10:.3f}")
    print(f"bytes/sec (1s window): {bps:.0f}")
    if p1 < 100:
        raise SystemExit("unexpected low PPS — check window logic")
    print("ok")


if __name__ == "__main__":
    main()
