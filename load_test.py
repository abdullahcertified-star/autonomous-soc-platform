"""
load_test.py — Injects real Scapy packets via the analyzer path (no mock layers).

Requires the Flask app (sniffer thread) to be running so state is shared, or run
this from a Python shell after importing sniffer.

Usage:
  python load_test.py
"""
import random
import threading
import time

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

import sniffer


def _eth_ip_tcp_udp(src: str, dst: str, proto: str = "TCP", dport: int = 80):
    if proto == "TCP":
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=random.randint(1024, 65535), dport=dport, flags="S")
    elif proto == "UDP":
        p = Ether() / IP(src=src, dst=dst) / UDP(sport=random.randint(1024, 65535), dport=dport) / (b"x" * 32)
    else:
        p = Ether() / IP(src=src, dst=dst) / ICMP()
    return p


ATTACKER_IPS = ["10.0.0.99", "192.168.1.200", "172.16.0.50"]
NORMAL_IPS = [f"10.0.{i}.{j}" for i in range(1, 5) for j in range(1, 10)]
SERVER_IP = "10.0.0.1"


def flood_attack(attacker_ip: str, rate: int = 150, duration: int = 15) -> None:
    print(f"  Flood: {attacker_ip} → {SERVER_IP}  ({rate} pps)")
    end = time.time() + duration
    interval = 1.0 / rate
    while time.time() < end:
        sniffer.inject_packet(_eth_ip_tcp_udp(attacker_ip, SERVER_IP, "TCP"), iface="inject")
        time.sleep(interval)
    print(f"  Flood ended: {attacker_ip}")


def normal_traffic(duration: int = 90) -> None:
    print("  Normal traffic…")
    end = time.time() + duration
    protos = ["TCP", "UDP", "OTHER"]
    while time.time() < end:
        src = random.choice(NORMAL_IPS)
        proto = random.choices(protos, weights=[70, 25, 5])[0]
        try:
            sniffer.inject_packet(_eth_ip_tcp_udp(src, SERVER_IP, proto), iface="inject")
        except Exception:
            pass
        time.sleep(random.uniform(0.05, 0.3))


if __name__ == "__main__":
    print("\nLoad test — start app.py first; dashboard at http://127.0.0.1:5000\n")
    t = threading.Thread(target=normal_traffic, args=(90,), daemon=True)
    t.start()
    time.sleep(3)
    for ip in ATTACKER_IPS:
        threading.Thread(target=flood_attack, args=(ip, 160, 20), daemon=True).start()
        time.sleep(4)
    t.join()
    print("\nLoad test complete.")
