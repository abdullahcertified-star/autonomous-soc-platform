#!/usr/bin/env python3
"""ICMP echo burst for IDS testing. Requires admin. Use only with permission."""

import argparse
import sys
import time

from scapy.all import IP, ICMP, send


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("--rate", type=float, default=150.0)
    args = p.parse_args()
    delay = 1.0 / max(args.rate, 1.0)
    print(f"ICMP echo → {args.target}")
    while True:
        send(IP(dst=args.target) / ICMP(), verbose=0)
        time.sleep(delay)


if __name__ == "__main__":
    main()
