#!/usr/bin/env python3
"""
remote_agent.py — SOC Lightweight Remote Sensor Agent

Run this on ANY machine you want to monitor. It captures packet METADATA only
(no payload content, no usernames, no passwords) and sends JSON reports to
the central SOC via UDP every 5 seconds.

Even on a fully switched network, each machine sees 100% of traffic TO and
FROM itself. Running this agent on every host gives network-wide coverage
from the edge in — without needing a SPAN port or gateway reconfiguration.

Requirements
────────────
    pip install scapy

On Windows : run as Administrator (required for Npcap raw capture)
On Linux   : run as root, or: sudo python remote_agent.py ...

Usage
─────
    python remote_agent.py --soc-ip 192.168.1.100 --soc-port 9876
    python remote_agent.py --soc-ip 192.168.1.100 --iface eth0 --interval 3

What is transmitted (JSON, UDP)
────────────────────────────────
    agent_id     — random 8-char hex ID (generated once per run)
    hostname     — this machine's hostname
    timestamp    — Unix epoch float
    packet_count — total packets seen since last report
    proto_counts — {TCP: N, UDP: N, ICMP: N, OTHER: N}
    alerts       — list of {src_ip, dst_ip, rate, severity} for HIGH/MEDIUM
    version      — agent version string

Nothing sensitive is ever sent. Severity uses the same thresholds as the
central SOC (≤2400 = NORMAL, 2401–5900 = MEDIUM, >5900 = HIGH).

Privacy note
────────────
    The agent sends per-IP packet RATES only, not content.
    It is equivalent to reading NetFlow/IPFIX counters.
"""
from __future__ import annotations

import argparse
import json
import platform
import socket
import sys
import time
import threading
import uuid
from collections import defaultdict, deque

# ─── thresholds match the central SOC ────────────────────────────────────────
ABS_NORMAL_RATE  = 2400   # pkts/5 s  → NORMAL
ABS_ATTACK_RATE  = 5900   # pkts/5 s  → HIGH (2401–5900 = MEDIUM)
RATE_WINDOW      = 5.0    # seconds — must match SOC detection.py rate_window
REPORT_INTERVAL  = 5.0    # seconds between UDP reports

AGENT_VERSION    = "1.0"
AGENT_ID         = uuid.uuid4().hex[:8]
HOSTNAME         = socket.gethostname()

# ─── per-IP tracking ─────────────────────────────────────────────────────────
_src_ts:   dict = defaultdict(deque)   # {src_ip: [timestamps]}
_flow_ts:  dict = defaultdict(deque)   # {(src, dst, dport): [timestamps]}
_proto:    dict = defaultdict(int)     # {proto_name: count}
_pkt_total = [0]
_lock = threading.Lock()


def _classify(rate: int) -> str | None:
    if rate > ABS_ATTACK_RATE:
        return "HIGH"
    if rate > ABS_NORMAL_RATE:
        return "MEDIUM"
    return None


def _detect_proto(pkt) -> str:
    """Classify transport protocol without importing layer names at module level."""
    try:
        from scapy.all import TCP, UDP, ICMP
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
    except Exception:
        pass
    return "OTHER"


def _process_pkt(pkt) -> None:
    """Per-packet callback — extracts metadata only, never stores payload."""
    try:
        from scapy.all import IP, TCP, UDP
        if not pkt.haslayer(IP):
            return

        src   = pkt[IP].src
        dst   = pkt[IP].dst
        now   = time.time()
        proto = _detect_proto(pkt)

        # Skip loopback
        if src.startswith("127.") or dst.startswith("127."):
            return

        dport = 0
        if pkt.haslayer(TCP):
            dport = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            dport = int(pkt[UDP].dport)

        cutoff = now - RATE_WINDOW

        with _lock:
            _pkt_total[0] += 1
            _proto[proto]  += 1

            # Per-source rate window
            _src_ts[src].append(now)
            while _src_ts[src] and _src_ts[src][0] < cutoff:
                _src_ts[src].popleft()

            # Per-flow tracking (for future aggregation)
            fk = (src, dst, dport)
            _flow_ts[fk].append(now)
            while _flow_ts[fk] and _flow_ts[fk][0] < cutoff:
                _flow_ts[fk].popleft()

    except Exception:
        pass


def _build_report() -> dict:
    """Build a JSON-safe report dict from current tracking state."""
    now    = time.time()
    cutoff = now - RATE_WINDOW
    alerts = []

    with _lock:
        # Prune and collect per-IP rates
        for src in list(_src_ts.keys()):
            while _src_ts[src] and _src_ts[src][0] < cutoff:
                _src_ts[src].popleft()
            rate = len(_src_ts[src])
            sev  = _classify(rate)
            if sev:
                alerts.append({
                    "src_ip":   src,
                    "rate":     rate,
                    "severity": sev,
                })

        proto_snap = dict(_proto)
        total      = _pkt_total[0]

    return {
        "agent_id":     AGENT_ID,
        "hostname":     HOSTNAME,
        "timestamp":    now,
        "packet_count": total,
        "proto_counts": proto_snap,
        "alerts":       alerts,
        "version":      AGENT_VERSION,
    }


def _sender_loop(soc_ip: str, soc_port: int, interval: float) -> None:
    """Background thread: send reports to the SOC on a fixed interval."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        time.sleep(interval)
        report = _build_report()
        try:
            data = json.dumps(report).encode("utf-8")
            sock.sendto(data, (soc_ip, soc_port))
            alert_count = len(report.get("alerts", []))
            if alert_count:
                print(
                    f"[Agent {AGENT_ID}] Sent report — "
                    f"pkts={report['packet_count']}  alerts={alert_count}"
                )
        except Exception as e:
            print(f"[Agent {AGENT_ID}] Send error: {e}")


def _start_capture(iface: str | None, bpf_filter: str) -> None:
    """Start Scapy capture. Blocks until interrupted."""
    try:
        from scapy.config import conf as _sc
        _sc.use_pcap = True
        from scapy.all import sniff

        iface_str = iface or "all interfaces"
        print(f"[Agent {AGENT_ID}] Capturing on {iface_str} | filter='{bpf_filter}'")

        kwargs: dict = {
            "prn":    _process_pkt,
            "store":  False,
            "filter": bpf_filter,
        }
        if iface:
            kwargs["iface"] = iface

        sniff(**kwargs)

    except PermissionError:
        print(
            "[Agent] Permission denied.\n"
            "  Windows: run 'python remote_agent.py ...' as Administrator\n"
            "  Linux  : run as root or with CAP_NET_RAW"
        )
        sys.exit(1)
    except ImportError:
        print("[Agent] Scapy not installed. Run: pip install scapy")
        sys.exit(1)
    except Exception as e:
        print(f"[Agent] Capture error: {e}")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC Remote Sensor Agent — sends packet metadata to central SOC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--soc-ip",    required=True,
                        help="IP address of the central SOC machine")
    parser.add_argument("--soc-port",  type=int, default=9876,
                        help="UDP port on the SOC (default: 9876)")
    parser.add_argument("--iface",     default=None,
                        help="Network interface to sniff (default: auto-select)")
    parser.add_argument("--interval",  type=float, default=REPORT_INTERVAL,
                        help=f"Report interval in seconds (default: {REPORT_INTERVAL})")
    parser.add_argument("--filter",    default="ip",
                        help="BPF filter for capture (default: 'ip')")
    args = parser.parse_args()

    print("=" * 60)
    print(f"  SOC Remote Sensor Agent  v{AGENT_VERSION}")
    print(f"  Agent ID  : {AGENT_ID}")
    print(f"  Hostname  : {HOSTNAME}")
    print(f"  Reporting : {args.soc_ip}:{args.soc_port} every {args.interval}s")
    print(f"  Thresholds: NORMAL≤{ABS_NORMAL_RATE} | MEDIUM≤{ABS_ATTACK_RATE} | HIGH>{ABS_ATTACK_RATE} pkts/5s")
    print("=" * 60)

    # Start background sender
    sender = threading.Thread(
        target=_sender_loop,
        args=(args.soc_ip, args.soc_port, args.interval),
        daemon=True,
        name="AgentSender",
    )
    sender.start()

    # Capture in main thread (blocks)
    try:
        _start_capture(args.iface, args.filter)
    except KeyboardInterrupt:
        print(f"\n[Agent {AGENT_ID}] Stopped.")


if __name__ == "__main__":
    main()
