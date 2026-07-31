#!/usr/bin/env python3
"""SYN port scan across a range. Lab use only."""

import argparse
import random
import sys
import time

from scapy.all import IP, TCP, send


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("--start", type=int, default=1)
    p.add_argument("--end", type=int, default=1024)
    p.add_argument("--delay", type=float, default=0.01)
    args = p.parse_args()
    for port in range(args.start, args.end + 1):
        pkt = IP(dst=args.target) / TCP(
            sport=random.randint(20000, 60000),
            dport=port,
            flags="S",
            seq=random.randint(0, 0xFFFF),
        )
        send(pkt, verbose=0)
        print(f"  probe {port}", end="\r", flush=True)
        time.sleep(args.delay)
    print(f"\ndone {args.start}-{args.end}")


if __name__ == "__main__":
    main()
