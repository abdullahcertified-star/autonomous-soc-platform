"""
network_sensor.py — Extended Network Visibility Layer

CONSTRAINT: This module NEVER modifies detection.py, sniffer.py internals,
            firewall.py, or any threshold value. It is purely additive.

WHAT THIS SOLVES
────────────────
A switched network only delivers frames addressed to your MAC.
  • promiscuous mode  — cannot help; the frame was never delivered to your port
  • Npcap/WinPcap    — captures what the NIC receives; cannot create traffic
  • cross-host attack — PC-A → PC-B is invisible unless you are in the path

SOLUTIONS IMPLEMENTED
─────────────────────
  1. Topology self-assessment  — detect whether this host can see cross-LAN traffic
  2. SPAN/mirror detection     — detect if a switch mirror port is feeding this NIC
  3. Gateway mode detection    — detect if this host routes traffic for the subnet
  4. Passive broadcast map     — ARP/DHCP/mDNS broadcasts ARE visible on switched LANs
  5. Distributed sensor        — UDP receiver; remote_agent.py sends from other hosts
  6. Guidance engine           — actionable, topology-aware advice
"""
from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

VERSION          = "1.0"
RECEIVER_PORT    = 9876          # UDP port for remote agent reports
RECEIVER_HOST    = "0.0.0.0"
_MAX_AGENT_EVENTS = 5000

# ─────────────────────────────────────────────────────────────────────────────
# Shared state
# ─────────────────────────────────────────────────────────────────────────────

_topology_cache: dict = {}
_topology_ts:    float = 0.0
_topology_ttl:   float = 60.0   # re-assess at most once per minute

_span_cache: dict  = {}
_span_ts:    float = 0.0
_span_ttl:   float = 120.0      # SPAN check blocks 2 s; cache for 2 min

_passive_map:  Dict[str, dict] = {}
_passive_lock  = threading.Lock()

_remote_events: deque = deque(maxlen=_MAX_AGENT_EVENTS)
_remote_agents: Dict[str, dict] = {}
_remote_lock    = threading.Lock()

_receiver_thread: Optional[threading.Thread] = None
_receiver_active = threading.Event()


# ═════════════════════════════════════════════════════════════════════════════
# 1. TOPOLOGY SELF-ASSESSMENT
# ═════════════════════════════════════════════════════════════════════════════

def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def _default_gateway() -> Optional[str]:
    """Return the default gateway IP from the OS routing table."""
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                ["route", "print", "0.0.0.0"], text=True, timeout=5
            )
            for line in out.splitlines():
                parts = line.split()
                # Lines like: "0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.100  ..."
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw = parts[2]
                    if gw and gw != "0.0.0.0":
                        return gw
        else:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"], text=True, timeout=5
            )
            for line in out.splitlines():
                parts = line.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


def _ip_forwarding_enabled() -> bool:
    """Check whether IP forwarding (routing) is active on this host."""
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                ["netsh", "interface", "ipv4", "show", "global"],
                text=True, timeout=5
            )
            return "enabled" in out.lower()
        else:
            with open("/proc/sys/net/ipv4/ip_forward") as f:
                return f.read().strip() == "1"
    except Exception:
        return False


def _is_gateway() -> bool:
    """
    True if this host IS the default gateway, OR if IP forwarding is enabled.
    Either condition means traffic from other hosts passes through here.
    """
    local   = _local_ip()
    gateway = _default_gateway()
    if local != "unknown" and gateway and local == gateway:
        return True
    return _ip_forwarding_enabled()


def _count_real_interfaces() -> int:
    """Count non-loopback interfaces with a valid IPv4 address."""
    try:
        from scapy.all import get_working_ifaces
        return len([
            i for i in get_working_ifaces()
            if i.ip and not str(i.ip).startswith("127.")
        ])
    except Exception:
        return 1


def _is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def assess_topology() -> dict:
    """
    Full topology self-assessment. Cached for _topology_ttl seconds.

    Returns a dict with visibility_score (0–100) and notes explaining
    WHY traffic is or is not visible, plus actionable guidance tags.
    """
    global _topology_cache, _topology_ts
    now = time.time()
    if now - _topology_ts < _topology_ttl and _topology_cache:
        return _topology_cache

    local_ip  = _local_ip()
    gateway   = _default_gateway()
    is_gw     = _is_gateway()
    iface_cnt = _count_real_interfaces()
    admin     = _is_admin()
    fwd       = _ip_forwarding_enabled()

    # Build visibility score
    score = 10   # baseline: always see own traffic
    notes = []

    if is_gw or fwd:
        score += 60
        notes.append(
            "GATEWAY MODE ACTIVE: all subnet traffic passes through this host "
            "— full LAN visibility possible"
        )
    else:
        notes.append(
            "NOT a gateway: switched network delivers only frames addressed to "
            "this MAC. Cross-host traffic between other devices is invisible."
        )

    if iface_cnt >= 2:
        score += 15
        notes.append(
            f"MULTI-NIC ({iface_cnt} interfaces): bridge mode is possible — "
            "place this host inline between the router and the LAN switch "
            "to capture all traffic transparently"
        )

    if admin:
        score += 10
        notes.append(
            "ADMIN MODE: promiscuous capture + SIO_RCVALL active — "
            "maximum capture fidelity for traffic that reaches this NIC"
        )
    else:
        notes.append(
            "NON-ADMIN: promiscuous capture unavailable — "
            "run as Administrator for better capture coverage"
        )

    # Determine mode label
    if score >= 75:
        mode = "NETWORK_IDS"
        mode_note = "Operating as a network-wide IDS"
    elif score >= 40:
        mode = "PARTIAL_IDS"
        mode_note = "Partial visibility — some cross-host traffic captured"
    else:
        mode = "HOST_IDS"
        mode_note = (
            "Operating as a host-based IDS only. "
            "Configure SPAN port, ICS gateway, or bridge mode to expand coverage."
        )

    result = {
        "local_ip":          local_ip,
        "default_gateway":   gateway,
        "is_gateway":        is_gw,
        "ip_forwarding":     fwd,
        "interface_count":   iface_cnt,
        "is_admin":          admin,
        "visibility_score":  min(100, score),
        "mode":              mode,
        "mode_note":         mode_note,
        "notes":             notes,
        "assessed_at":       datetime.now().isoformat(),
        "sensor_version":    VERSION,
    }

    _topology_cache = result
    _topology_ts    = now
    return result


# ═════════════════════════════════════════════════════════════════════════════
# 2. SPAN / MIRROR PORT DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def _collect_foreign_macs(duration_s: float = 2.0) -> dict:
    """
    Capture frames for duration_s seconds and count frames whose destination
    MAC is not this host's MAC and not a broadcast/multicast address.

    If foreign destination MACs appear, a switch mirror/SPAN port is active:
    the switch is delivering frames intended for other hosts to this port.

    Blocks for duration_s seconds — call from a background thread only.
    """
    result = {
        "active": False,
        "foreign_dst_macs": [],
        "sample_frames":    0,
        "note": "SPAN detection requires Scapy + admin",
    }

    if not _is_admin():
        result["note"] = "Admin required for SPAN detection"
        return result

    try:
        from scapy.all import sniff, Ether, get_working_ifaces

        own_macs: set = set()
        for iface in get_working_ifaces():
            if hasattr(iface, "mac") and iface.mac:
                own_macs.add(iface.mac.lower())

        foreign: set = set()
        total = [0]

        def _check(pkt):
            total[0] += 1
            if pkt.haslayer(Ether):
                dst = pkt[Ether].dst.lower()
                if (
                    dst not in own_macs
                    and dst != "ff:ff:ff:ff:ff:ff"
                    and not dst.startswith("01:")   # multicast
                    and not dst.startswith("33:33") # IPv6 multicast
                ):
                    foreign.add(dst)

        sniff(prn=_check, store=False, timeout=duration_s)

        result["sample_frames"]    = total[0]
        result["foreign_dst_macs"] = list(foreign)[:20]
        result["active"]           = len(foreign) > 0
        result["note"] = (
            f"SPAN/mirror ACTIVE — receiving frames for {len(foreign)} foreign MACs. "
            "Your NIC is on a switch mirror port. All switch traffic is visible."
            if result["active"]
            else
            "No SPAN detected — NIC receives only frames addressed to itself. "
            "Configure a switch mirror port to capture cross-host traffic."
        )
    except Exception as e:
        result["note"] = f"SPAN detection error: {e}"

    return result


def _span_detect_background() -> None:
    """Run SPAN detection in a background thread and cache result."""
    global _span_cache, _span_ts
    result = _collect_foreign_macs(2.0)
    _span_cache = result
    _span_ts    = time.time()


def get_span_status(force: bool = False) -> dict:
    """
    Return cached SPAN detection result (non-blocking).
    Set force=True to trigger a fresh 2-second capture in a background thread.
    """
    global _span_cache, _span_ts
    now = time.time()

    if force or not _span_cache or (now - _span_ts > _span_ttl):
        t = threading.Thread(target=_span_detect_background, daemon=True)
        t.start()
        if not _span_cache:
            return {"active": False, "note": "SPAN detection running (first check)..."}

    return _span_cache


# ═════════════════════════════════════════════════════════════════════════════
# 3. PASSIVE BROADCAST MAP
# ════════════════════════════════════════════════════════════════════════════
# Broadcast frames (ARP, DHCP, mDNS, SSDP) are flooded to ALL switch ports.
# This is the one category of cross-host traffic always visible without SPAN.
# record_broadcast_device() is called from sniffer.process_arp() — no new
# capture path required.

def record_broadcast_device(ip: str, mac: str, proto: str) -> None:
    """
    Register a device seen via broadcast/multicast traffic.

    Called from sniffer.process_arp() for ARP frames, and optionally from
    the packet processor for DHCP/mDNS. Thread-safe; no lock held long.
    """
    if not ip or ip.startswith("127.") or ip in ("0.0.0.0", "255.255.255.255"):
        return
    now = time.time()
    mac = (mac or "unknown").lower().strip()

    with _passive_lock:
        if ip not in _passive_map:
            _passive_map[ip] = {
                "ip":         ip,
                "mac":        mac,
                "protos":     set(),
                "first_seen": now,
                "last_seen":  now,
                "pkt_count":  0,
            }
        e = _passive_map[ip]
        e["last_seen"] = now
        e["pkt_count"] += 1
        e["protos"].add(proto)
        if mac and mac != "unknown":
            e["mac"] = mac


def get_passive_map() -> List[dict]:
    """All devices seen via broadcast traffic — serialisable snapshot."""
    with _passive_lock:
        out = []
        now = time.time()
        for e in _passive_map.values():
            d = dict(e)
            d["protos"]          = sorted(d["protos"])
            d["last_seen_ago_s"] = round(now - d["last_seen"], 1)
            out.append(d)
        return sorted(out, key=lambda x: x["last_seen"], reverse=True)


# ═════════════════════════════════════════════════════════════════════════════
# 4. DISTRIBUTED SENSOR RECEIVER
# ════════════════════════════════════════════════════════════════════════════
# remote_agent.py runs on other machines and sends JSON metadata reports
# to this UDP port. The receiver decodes them and optionally calls the
# main detection pipeline with the received packet metadata.
#
# Nothing sensitive is transmitted: only (src_ip, proto, rate, severity).
# No payload content, usernames, or passwords.

def _udp_receiver_loop(port: int, detection_cb) -> None:
    """Background thread: listen for remote agent JSON reports."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((RECEIVER_HOST, port))
        sock.settimeout(1.0)
        print(f"[SOC-Sensor] Remote agent receiver active on UDP:{port}")
    except Exception as e:
        print(f"[SOC-Sensor] Cannot bind UDP:{port} — {e}")
        _receiver_active.clear()
        return

    while _receiver_active.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            continue

        try:
            report = json.loads(data.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, ValueError):
            continue

        _handle_agent_report(report, addr[0], detection_cb)

    try:
        sock.close()
    except Exception:
        pass


def _handle_agent_report(report: dict, sender_ip: str, detection_cb) -> None:
    """Store the report and optionally forward alerts to the detection callback."""
    agent_id = report.get("agent_id", sender_ip)
    now      = time.time()

    with _remote_lock:
        prev = _remote_agents.get(agent_id, {})
        _remote_agents[agent_id] = {
            "agent_id":    agent_id,
            "sender_ip":   sender_ip,
            "hostname":    report.get("hostname", ""),
            "last_seen":   now,
            "packet_count": prev.get("packet_count", 0) + report.get("packet_count", 0),
            "version":     report.get("version", "?"),
        }

        enriched = dict(report)
        enriched["_from_agent"]    = True
        enriched["_sender_ip"]     = sender_ip
        enriched["_received_at"]   = now
        _remote_events.append(enriched)

    # Forward HIGH/MEDIUM alerts from remote agents to the local detection callback.
    if detection_cb:
        for alert in report.get("alerts", []):
            try:
                detection_cb(
                    src_ip   = alert.get("src_ip", sender_ip),
                    severity = alert.get("severity"),
                    rate     = alert.get("rate", 0),
                    agent_id = agent_id,
                )
            except Exception:
                pass


def start_sensor_receiver(port: int = RECEIVER_PORT,
                          detection_callback=None) -> None:
    """
    Start the background UDP receiver for remote agents.
    Safe to call multiple times — only one receiver runs at a time.
    """
    global _receiver_thread
    if _receiver_thread and _receiver_thread.is_alive():
        return
    _receiver_active.set()
    _receiver_thread = threading.Thread(
        target=_udp_receiver_loop,
        args=(port, detection_callback),
        daemon=True,
        name="SOC-SensorReceiver",
    )
    _receiver_thread.start()


def stop_sensor_receiver() -> None:
    _receiver_active.clear()


def get_remote_events(limit: int = 200) -> List[dict]:
    with _remote_lock:
        return list(_remote_events)[-limit:]


def get_agent_status() -> List[dict]:
    now = time.time()
    with _remote_lock:
        return [
            {
                **a,
                "last_seen_ago_s": round(now - a["last_seen"], 1),
                "status": "ACTIVE" if now - a["last_seen"] < 30 else "STALE",
            }
            for a in _remote_agents.values()
        ]


# ═════════════════════════════════════════════════════════════════════════════
# 5. GUIDANCE ENGINE
# ════════════════════════════════════════════════════════════════════════════
# Returns topology-aware, prioritised guidance so the operator knows EXACTLY
# what to do to expand visibility — ordered by impact and difficulty.

_GUIDANCE_DB = {
    "gateway_ics": {
        "priority":    1,
        "title":       "Enable Windows ICS — Make This Host the LAN Gateway",
        "difficulty":  "Low (10 minutes)",
        "coverage":    "100% of traffic from all ICS client devices",
        "impact":      "HIGH",
        "when":        "You have two NICs (or Wi-Fi + Ethernet) and can reconfig devices",
        "steps": [
            "1. Open Network Connections (ncpa.cpl)",
            "2. Right-click the INTERNET-FACING adapter → Properties → Sharing",
            "3. Check 'Allow other network users to connect through this computer's Internet connection'",
            "4. Select the LAN-facing NIC in the dropdown",
            "5. Click OK — Windows assigns 192.168.137.1 to the LAN NIC automatically",
            "6. Change other devices' gateway to 192.168.137.1 (or enable DHCP)",
            "7. Restart the SOC sniffer — it will now see ALL client traffic",
        ],
        "scapy_note": (
            "# All client traffic now arrives on the LAN NIC\n"
            "# Existing sniffer.py captures it automatically — no code change needed\n"
            "sniff(iface='LAN_NIC', promisc=True, store=False, prn=process_any_packet)"
        ),
        "warning": None,
    },
    "span_port": {
        "priority":    2,
        "title":       "Configure Switch SPAN / Monitor Port",
        "difficulty":  "Medium (requires managed switch)",
        "coverage":    "100% of all traffic on monitored switch ports",
        "impact":      "HIGH",
        "when":        "You have a managed switch (Cisco, HP, Netgear, TP-Link smart)",
        "steps": [
            "CISCO IOS:",
            "  monitor session 1 source interface GigabitEthernet0/1 both",
            "  monitor session 1 destination interface GigabitEthernet0/8",
            "  (G0/8 is the port your SOC NIC is connected to)",
            "",
            "HP ProCurve:",
            "  mirror-port 8",
            "  interface 1-7 monitor",
            "",
            "TP-Link Smart Switch (web UI):",
            "  Switching → Mirroring → Enable, set destination port to SOC port",
            "",
            "Once configured, connect SOC to the mirror port.",
            "The existing sniffer.py with promisc=True captures all mirrored traffic.",
        ],
        "scapy_note": (
            "# No code change needed — promisc=True already in sniffer.py\n"
            "# network_sensor.get_span_status(force=True) confirms SPAN is active\n"
            "conf.sniff_promisc = True  # already set in admin mode"
        ),
        "warning": None,
    },
    "network_tap": {
        "priority":    3,
        "title":       "Install a Hardware Network TAP",
        "difficulty":  "Low (once purchased)",
        "coverage":    "100% of tapped link traffic — passive, zero impact",
        "impact":      "HIGH",
        "when":        "You want zero-impact passive capture with no switch config",
        "steps": [
            "1. Purchase a TAP (Garland Technology, Dualcomm DCSW-1005PT, or similar)",
            "2. Place TAP inline between router and switch:",
            "   Router ─── [TAP] ─── Switch",
            "                │",
            "             Monitor port ─── SOC NIC",
            "3. Connect the TAP monitor port to a spare NIC on the SOC machine",
            "4. The existing sniffer.py picks up the new NIC automatically",
            "   via _pick_interfaces() — no code change needed",
        ],
        "scapy_note": (
            "# _pick_interfaces() in sniffer.py already selects secondary NICs\n"
            "# TAP monitor NIC appears as a normal interface — captured automatically"
        ),
        "warning": None,
    },
    "bridge_mode": {
        "priority":    4,
        "title":       "Windows Network Bridge (Transparent Inline)",
        "difficulty":  "Medium",
        "coverage":    "100% of traffic across the bridged segment",
        "impact":      "HIGH",
        "when":        "You have two NICs and can re-patch one cable",
        "steps": [
            "1. Open Network Connections (ncpa.cpl)",
            "2. Hold Ctrl and select BOTH NICs (upstream NIC + downstream NIC)",
            "3. Right-click → Bridge Connections",
            "4. Windows creates a 'Network Bridge' adapter",
            "5. All traffic crossing the bridge is visible to both member NICs",
            "6. Sniff on either member NIC — the existing sniffer.py works as-is",
            "",
            "Physical topology after bridging:",
            "  Router ─── [SOC NIC-1]╔═BRIDGE═╗[SOC NIC-2] ─── LAN Switch",
            "                        ╚════════╝",
            "           All frames crossing the bridge visible to Scapy",
        ],
        "scapy_note": (
            "# Sniff on BOTH bridge member interfaces for complete coverage\n"
            "# _pick_interfaces() already returns secondary interfaces\n"
            "sniff(iface=['NIC1', 'NIC2'], promisc=True, store=False, prn=process_any_packet)"
        ),
        "warning": None,
    },
    "distributed_agents": {
        "priority":    5,
        "title":       "Deploy remote_agent.py on Monitored Machines",
        "difficulty":  "Low",
        "coverage":    "Each agent sees 100% of traffic to/from its host",
        "impact":      "MEDIUM (aggregate coverage scales with agent count)",
        "when":        "You cannot change switch config or network topology",
        "steps": [
            "1. Copy remote_agent.py to each machine you want to monitor",
            "2. Install Scapy: pip install scapy",
            "3. Run as Administrator/root:",
            "   python remote_agent.py --soc-ip <THIS_MACHINE_IP> --soc-port 9876",
            "4. The SOC receiver (started automatically) collects all reports",
            "5. View via GET /api/sensor/agents and /api/sensor/remote-events",
            "",
            "What agents transmit (no payload, no content):",
            "  - Source IP, destination IP, protocol",
            "  - Packet rate per source",
            "  - Severity classification (using same 2400/5900 thresholds)",
            "  - Agent hostname and ID",
        ],
        "scapy_note": (
            "# SOC receiver started automatically by network_sensor.start()\n"
            "# No sniffer.py changes needed\n"
            f"# Remote agents report to UDP port {RECEIVER_PORT}"
        ),
        "warning": None,
    },
    "arp_poison_lab": {
        "priority":    6,
        "title":       "ARP Poisoning — LAB / CTF ONLY (never on production)",
        "difficulty":  "Low (technically)",
        "coverage":    "Traffic between two specific hosts",
        "impact":      "MEDIUM (targeted, not full LAN)",
        "when":        "Isolated lab environment, all machines are yours, CTF testing",
        "steps": [
            "ON KALI (or another Linux machine):",
            "  sudo arpspoof -i eth0 -t <VICTIM_IP> <GATEWAY_IP>",
            "  sudo arpspoof -i eth0 -t <GATEWAY_IP> <VICTIM_IP>",
            "  sudo sysctl net.ipv4.ip_forward=1  # must forward or traffic drops",
            "",
            "The SOC machine must be the Kali machine OR Kali must forward to SOC.",
            "",
            "WARNING: ARP poisoning disrupts legitimate traffic.",
            "It is a man-in-the-middle attack and is illegal on networks you",
            "do not own/administer. Use ONLY in an isolated lab.",
        ],
        "scapy_note": (
            "# Scapy alternative (lab only):\n"
            "from scapy.all import ARP, send\n"
            "send(ARP(op=2, pdst=victim, hwdst='ff:ff:ff:ff:ff:ff', psrc=gateway), loop=1)"
        ),
        "warning": "ILLEGAL on unauthorized networks. LAB/CTF USE ONLY.",
    },
}


def get_guidance(topology: dict = None) -> dict:
    """
    Return prioritised, topology-filtered guidance explaining how to expand
    network visibility beyond host-based detection.
    """
    if topology is None:
        topology = assess_topology()

    is_gw     = topology.get("is_gateway", False)
    iface_cnt = topology.get("interface_count", 1)
    score     = topology.get("visibility_score", 10)

    # Filter and annotate guidance by current topology
    items = []
    for key, g in sorted(_GUIDANCE_DB.items(), key=lambda x: x[1]["priority"]):
        item = dict(g)
        item["key"] = key

        # Mark already-active solutions
        if key == "gateway_ics" and is_gw:
            item["_status"] = "ACTIVE"
            item["_note"]   = "Gateway/forwarding already enabled on this host"
        elif key == "span_port" and _span_cache.get("active"):
            item["_status"] = "ACTIVE"
            item["_note"]   = "SPAN/mirror port detected as active"
        elif key == "bridge_mode" and iface_cnt < 2:
            item["_status"] = "REQUIRES_SECOND_NIC"
            item["_note"]   = "Only one NIC detected — add a second NIC to use bridge mode"
        elif key == "distributed_agents":
            with _remote_lock:
                active_agents = sum(
                    1 for a in _remote_agents.values()
                    if time.time() - a["last_seen"] < 30
                )
            item["_status"] = f"ACTIVE ({active_agents} agent(s))" if active_agents else "NOT_DEPLOYED"
        else:
            item["_status"] = "NOT_CONFIGURED"

        items.append(item)

    active_agents_count = 0
    with _remote_lock:
        active_agents_count = sum(
            1 for a in _remote_agents.values()
            if time.time() - a["last_seen"] < 30
        )

    return {
        "visibility_score":    score,
        "current_mode":        topology.get("mode", "HOST_IDS"),
        "mode_note":           topology.get("mode_note", ""),
        "is_gateway":          is_gw,
        "interface_count":     iface_cnt,
        "span_active":         _span_cache.get("active", False),
        "active_remote_agents": active_agents_count,
        "guidance":            items,
        "visibility_explanation": {
            "switched_network": (
                "Modern switches are MAC-learning bridges. They only forward a frame "
                "to the specific port where the destination MAC was last seen. "
                "Your SOC NIC only receives frames explicitly addressed to it."
            ),
            "promiscuous_mode": (
                "Promiscuous mode tells the NIC driver to stop discarding frames "
                "whose destination MAC does not match the NIC's own MAC. "
                "It CANNOT make the switch deliver frames that were never sent "
                "to your port. It only helps when you ARE in the traffic path."
            ),
            "npcap_limit": (
                "Npcap injects a kernel filter driver that copies every frame "
                "arriving at the NIC. It has no way to request frames from the "
                "switch. It can only observe what physically arrives on the wire."
            ),
            "cross_host_invisibility": (
                "PC-A attacking PC-B: the frame goes switch-port-A → switch-port-B "
                "directly. Your SOC (on switch-port-C) never sees this frame. "
                "The only fix is to be in the traffic path: SPAN port, TAP, gateway, "
                "or bridge mode."
            ),
            "what_is_always_visible": (
                "Broadcast frames (ARP, DHCP, mDNS, SSDP) are flooded to ALL ports "
                "by the switch because their destination MAC is ff:ff:ff:ff:ff:ff. "
                "These reveal all devices on the LAN and are captured by the "
                "existing passive_map in network_sensor."
            ),
        },
    }


# ═════════════════════════════════════════════════════════════════════════════
# 6. PUBLIC API — called by main.py endpoints and sniffer.py
# ═════════════════════════════════════════════════════════════════════════════

def get_full_status() -> dict:
    """Single-call summary: topology + guidance + agent status."""
    topology = assess_topology()
    return {
        "topology":           topology,
        "span":               _span_cache or {"active": False, "note": "Not checked yet"},
        "guidance_summary": {
            "visibility_score": topology["visibility_score"],
            "mode":             topology["mode"],
            "mode_note":        topology["mode_note"],
        },
        "passive_devices":    len(_passive_map),
        "remote_agents":      get_agent_status(),
        "remote_events_total": len(_remote_events),
        "receiver_port":      RECEIVER_PORT,
        "receiver_active":    (
            _receiver_active.is_set()
            and bool(_receiver_thread and _receiver_thread.is_alive())
        ),
        "sensor_version":     VERSION,
        "timestamp":          datetime.now().isoformat(),
    }


def start(detection_callback=None,
          receiver_port: int = RECEIVER_PORT,
          run_span_check: bool = True) -> None:
    """
    Called from sniffer.start_sniffer() to activate the visibility module.

    Parameters
    ----------
    detection_callback : callable, optional
        Signature: (src_ip, severity, rate, agent_id) → None
        Called when a remote agent reports a HIGH/MEDIUM severity event.
        Wire to detection.record_packet() or a custom handler.
    receiver_port : int
        UDP port for remote agent reports (default 9876).
    run_span_check : bool
        If True, run a background SPAN detection probe at startup.
    """
    assess_topology()
    start_sensor_receiver(port=receiver_port, detection_callback=detection_callback)

    if run_span_check:
        threading.Thread(target=_span_detect_background, daemon=True).start()

    print(
        f"[SOC-Sensor] Visibility module v{VERSION} started | "
        f"topology={_topology_cache.get('mode', '?')} | "
        f"score={_topology_cache.get('visibility_score', '?')}% | "
        f"UDP receiver={receiver_port}"
    )
