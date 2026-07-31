"""
analyzer.py — Packet processing + detection bridge (clean version)
"""
from __future__ import annotations

import threading
import time
from datetime import datetime
from collections import deque

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether

from detection import detection
from core import firewall as fw
from utils import ts
from utils.network import classify_direction, is_noise_service_port
from utils.stats import traffic_stats, top_talkers, estimate_packet_size_layers


class DedupCache:
    def __init__(self, window_sec: float = 0.06):
        self.window = window_sec
        self.seen = {}
        self.lock = threading.Lock()

    def is_duplicate(self, key, now):
        with self.lock:
            last = self.seen.get(key)
            if last and (now - last) < self.window:
                return True
            self.seen[key] = now
            return False


def fingerprint(pkt):
    try:
        if ARP in pkt:
            return ("ARP", pkt[ARP].psrc, pkt[ARP].pdst, pkt[ARP].hwsrc)

        if IP not in pkt:
            return None

        ip = pkt[IP]

        if TCP in pkt:
            t = pkt[TCP]
            return ("TCP", ip.src, ip.dst, t.sport, t.dport, t.seq)

        if UDP in pkt:
            u = pkt[UDP]
            return ("UDP", ip.src, ip.dst, u.sport, u.dport)

        if ICMP in pkt:
            ic = pkt[ICMP]
            return ("ICMP", ip.src, ip.dst, ic.type, ic.code)

        return ("IP", ip.src, ip.dst, ip.proto)

    except Exception:
        return None


class PacketAnalyzer:
    def __init__(
        self,
        *,
        host,
        packets,
        alerts,
        arp_events,
        scan_events,
        attack_map_events,
        protocol_stats,
        network_stats,
        port_stats,
        hourly_stats,
        capture_status,
    ):
        self.host = host
        self.packets = packets
        self.alerts = alerts

        self.arp_events = arp_events
        self.scan_events = scan_events
        self.attack_map_events = attack_map_events

        self.protocol_stats = protocol_stats
        self.network_stats = network_stats
        self.port_stats = port_stats
        self.hourly_stats = hourly_stats
        self.capture_status = capture_status

        self.dedup = DedupCache()
        self.lock = threading.Lock()

        self.alert_last = {}

    # ─────────────────────────────────────────────

    def handle_arp(self, pkt):
        if ARP not in pkt:
            return

        arp = pkt[ARP]
        event = {
            "time": ts(),
            "src_ip": arp.psrc,
            "src_mac": arp.hwsrc,
            "dst_ip": arp.pdst,
            "type": "ARP",
        }
        self.arp_events.append(event)

    # ─────────────────────────────────────────────

    def process(self, pkt, *, iface=""):
        try:
            now = time.perf_counter()

            # ARP handling
            if ARP in pkt and IP not in pkt:
                self.handle_arp(pkt)
                return

            if IP not in pkt:
                return

            fp = fingerprint(pkt)
            if not fp:
                return

            if self.dedup.is_duplicate(fp, now):
                return

            ip = pkt[IP]
            src, dst = ip.src, ip.dst

            if fw.is_blocked(src):
                return

            proto = "OTHER"
            sport = dport = 0
            flags = 0

            if TCP in pkt:
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = int(pkt[TCP].flags)

            elif UDP in pkt:
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            elif ICMP in pkt:
                proto = "ICMP"

            size = estimate_packet_size_layers(pkt)
            direction = classify_direction(src, dst, self.host)

            # ── Detection Engine ─────────────────────
            severity, confidence, rate = detection.record_packet(
                src,
                dst,
                is_syn=bool(flags & 0x02),
                is_ack=bool(flags & 0x10),
                dst_port=dport,
                proto=proto,
                pkt_bytes=size,
                tcp_flags=flags if proto == "TCP" else None,
            )

            # ── Stats ────────────────────────────────
            traffic_stats.record(nbytes=size, proto=proto, direction=direction, t_mono=now)
            top_talkers.record(src, now)

            with self.lock:
                self.network_stats["total_packets"] += 1
                self.protocol_stats[proto] = self.protocol_stats.get(proto, 0) + 1

                if dport:
                    self.port_stats[dport] = self.port_stats.get(dport, 0) + 1

                self.hourly_stats[datetime.now().hour] += 1

            # ── Alerts ───────────────────────────────
            if severity:
                if now - self.alert_last.get(src, 0) > 3:
                    self.alert_last[src] = now

                    msg = f"{severity} attack from {src} | {rate:.1f} pps"
                    self.alerts.append({
                        "time": ts(),
                        "ip": src,
                        "dst": dst,
                        "severity": severity,
                        "confidence": confidence,
                        "msg": msg,
                    })

            # ── Packet store (only important ones) ───
            if severity or direction != "OUTBOUND":
                self.packets.append({
                    "time": ts(),
                    "src": src,
                    "dst": dst,
                    "proto": proto,
                    "port": dport,
                    "severity": severity or "NORMAL",
                    "rate": rate,
                })

        except Exception:
            pass

    # ─────────────────────────────────────────────

    def reset_dedup(self):
        self.dedup = DedupCache()