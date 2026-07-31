"""
dashboard.py — Aggregated read models for SOC dashboard / API endpoints.

Keeps Flask blueprints thin: numeric fields are sourced from traffic_stats
(PPS/BPS) instead of mis-labeled detector window counts.
"""
from __future__ import annotations

from typing import Any

from detection import sniffer
from detection import detection
from core import firewall as fw
from utils.stats import traffic_stats, top_talkers


def live_traffic_metrics() -> dict[str, Any]:
    return {
        "pps_1s": round(traffic_stats.pps_1s(), 2),
        "pps_10s_avg": round(traffic_stats.pps_10s_avg(), 2),
        "bytes_per_sec": round(traffic_stats.bytes_per_sec_1s(None), 2),
        "bytes_in_sec": round(traffic_stats.bytes_per_sec_1s("INBOUND"), 2),
        "bytes_out_sec": round(traffic_stats.bytes_per_sec_1s("OUTBOUND"), 2),
        "proto_1s": traffic_stats.protocol_counts_1s(),
        "drops": int(getattr(traffic_stats, "drop_count", 0)),
    }


def system_status_block() -> dict[str, Any]:
    cs = sniffer.capture_status
    active_incs = [
        i
        for i in sniffer.incidents.values()
        if i.get("status") in ("OPEN", "ACTIVE")
    ]
    # Include victim-side (target) incidents so active_attacks reflects both
    # attacker-keyed incidents and rand-source flood victim incidents.
    active_target_incs = [
        i
        for i in sniffer.target_incidents.values()
        if i.get("status") in ("OPEN", "ACTIVE")
    ]
    total_active = len(active_incs) + len(active_target_incs)
    return {
        "ids_engine": "ACTIVE" if cs.get("mode") == "live" else "STANDBY",
        "capture_mode": cs.get("mode", "idle"),
        "interface": cs.get("interface", "auto"),
        "interfaces": cs.get("interfaces", []),
        "real_packets": cs.get("real_packets", 0),
        "packets_per_second": sniffer.current_pps(),
        "pps_10s_avg": cs.get("pps_10s_avg", traffic_stats.pps_10s_avg()),
        "bytes_per_sec": cs.get("bytes_per_sec", traffic_stats.bytes_per_sec_1s(None)),
        "dropped_capture": cs.get("dropped_packets", 0),
        "active_attacks": total_active,
        "blocked_ips": fw.blocked_count(),
        "suspicious_ips": len(sniffer.network_stats["suspicious_ips"]),
        "arp_alerts": len(list(sniffer.arp_events)),
        "scan_alerts": len(list(sniffer.scan_events)),
        "total_packets": sniffer.network_stats["total_packets"],
    }


def top_talker_rows(limit: int = 10) -> list[dict[str, Any]]:
    rows = []
    for ip, n in top_talkers.top(limit):
        rows.append({"ip": ip, "pps_1s": n})
    return rows
