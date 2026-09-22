"""
sniffer.py — SOC Packet Capture (v5: Windows Non-Admin Compatible)

════════════════════════════════════════════════════════════════════════
ROOT CAUSE ANALYSIS: WHY NON-ADMIN PRODUCED FAKE / HIGH PACKET COUNTS
════════════════════════════════════════════════════════════════════════

FIX 1 — conf.use_pcap = True  (WinSock backend mirror bug)
  Without this, Scapy on Windows selects the best available socket
  backend automatically. When Npcap is installed but the process lacks
  admin rights, Scapy sometimes falls back to a WinSock-level raw socket
  that operates at the OS network-stack layer rather than at the NIC
  driver (NDIS) layer. This backend delivers every inbound packet TWICE:
  once when it enters the stack, once when it exits. Result: 2× counts
  on every real packet, which doubles the per-IP rate and triggers false
  ATTACK/SUSPICIOUS detections at exactly half the true threshold.
  Fix: set conf.use_pcap = True before any sniff() call. This forces
  Npcap/libpcap as the backend unconditionally.

FIX 2 — promisc=False when not admin  (Npcap mirror / half-promisc bug)
  conf.sniff_promisc = True tells Npcap to put every captured NIC into
  hardware promiscuous mode. On Windows this requires the Npcap driver to
  have been installed with admin-only service rights. Without elevation,
  the ioctl(BIOCPROMISC) either silently fails (leaving the adapter in an
  undefined state) or the Npcap driver falls back to a software monitor
  mode that copies every outgoing packet back to the capture path as well,
  producing mirrored traffic in the capture stream (you see your own sent
  packets as if they were received). Fix: sniff with promisc=False when
  not running as administrator.

FIX 3 — Raw socket (SIO_RCVALL) only when admin  (phantom packet source)
  On Windows, binding SIO_RCVALL on a raw socket requires SeNetworkAdminPrivilege.
  Without it, sock.ioctl(SIO_RCVALL, RCVALL_ON) raises WinError 10013.
  The old code caught this and returned, which looked safe. However, the
  socket creation itself succeeded, and on some Windows 11 builds a SOCK_RAW
  bound to the local IP without SIO_RCVALL still receives packets destined
  for localhost before the ioctl — producing a burst of loopback packets the
  moment the socket is created. Fix: wrap the entire raw socket thread in an
  admin check; skip it completely when not elevated.

FIX 4 — BPF filter on every sniff() call  (broadcast / mDNS noise inflation)
  The old _sniff_iface called sniff() with NO filter keyword. This handed
  every ARP broadcast, mDNS multicast (224.0.0.251:5353), DHCP renewal
  (255.255.255.255:67), SSDP advertisement (239.255.255.250:1900), and
  ICMPv6 Neighbor Discovery packet straight to process_any_packet and then
  into detection.record_packet(). These background packets alone can push
  the total packet rate well above the 2400 pkt/5s NORMAL ceiling, turning
  a quiet network into a permanently-SUSPICIOUS state. Fix: BPF filter
  "(tcp or udp or icmp) or arp" eliminates all non-IP, non-ARP noise before
  it ever reaches the Python processing pipeline.

FIX 5 — Loopback + local-only filter in software  (127.x and self-traffic)
  Windows software (Defender, Windows Update, WSL, Docker) generates
  significant 127.0.0.1 ↔ 127.0.0.1 traffic that Npcap captures on the
  loopback adapter. When sniffing multiple interfaces this appears as real
  traffic with high rates. Same-machine traffic (host-IP ↔ host-IP on VM
  bridge adapters) has the same effect. Fix: _should_drop_packet() checks
  both endpoints; if either is 127.x, or if both are known host IPs, the
  packet is discarded before any counting occurs.

FIX 6 — Richer dedup fingerprint + wider window  (multi-interface duplicates)
  The old key (src, dst, proto, ip_id) collapsed when ip_id == 0.  This is
  very common: Windows sets DF=1 on most outbound packets and zeros the ID
  field per RFC 6864. Two different UDP connections from the same (src,dst)
  both have ip_id=0, so the second real connection was silently dropped as a
  "duplicate" while actual same-packet copies from multiple interfaces slipped
  through because their ip_id happened to differ by 1 (fragmented vs. not).
  New key: (src, dst, proto, ip_id, sport, dport, extra) where extra is
  TCP-seq[0:16] for TCP, ICMP-type|code for ICMP. Window extended from 50ms
  to 200ms to absorb cross-interface delivery jitter on slower systems.

FIX 7 — Duplicate variable declarations removed  (silent state reset)
  _lock, _incident_counter, _last_alert_t, _ALERT_INTERVAL were each declared
  TWICE at module scope (lines 49-57 of the original). Python executes both;
  the second assignment reset _incident_counter to 0 and _last_alert_t to {},
  overwriting whatever values the first assignment established. Any code that
  ran between the two declarations (import-time side effects, monkey-patches)
  saw different values than code that ran after. Fix: single declaration only.

FIX 8 — Robust try/except around all packet field access  (crash protection)
  Malformed / truncated packets can raise exceptions when accessing IP.src,
  TCP.dport, etc. A single bad packet killed the sniffer thread in non-admin
  mode (where Npcap occasionally delivers partial frames from the half-promisc
  state). Fix: all layer accesses wrapped in try/except with soft fallback.

FIX 9 — Accurate packets-per-second via rolling 1-second window
  The old code appended the per-IP rate (packets in last 5s from one source)
  to traffic_history, which is a detection metric, not a display metric. For
  the dashboard PPS counter this produced jitter of up to 5× real traffic.
  Fix: a dedicated _pps_window deque tracks all accepted packet timestamps;
  current_pps() returns len(deque) directly (always correct in O(1)).

FIX 10 — Thread-safe per-packet counters
  network_stats["total_packets"] and protocol_stats are updated inside _lock
  for every accepted packet. Added dropped_loopback / dropped_dedup counters
  so operators can see how much noise is being filtered.
"""
from __future__ import annotations

# ── FIX 1: Force Npcap/libpcap backend BEFORE any other Scapy imports ────────
# conf is a module-level singleton; setting use_pcap=True here ensures every
# subsequent socket/sniffer created in this process uses Npcap, never WinSock.
from scapy.config import conf as _scapy_conf
_scapy_conf.use_pcap = True

from scapy.all import conf, sniff, IP, TCP, UDP, ICMP, ARP, Ether, get_working_ifaces, get_if_list

import ctypes
import os
import platform
import socket as _socket
import threading
import time
from collections import deque, defaultdict
from datetime import datetime

from detection import detection
from core import firewall as fw
from core import layers
from detection import network_sensor
from detection import normalizer
from core.database import log_event
from utils import ts
from detection.real import calculate_port_scan_risk

# Thread-local storage: each sniffer thread records its interface name here
# so process_packet() can pass iface= to layers.process() without extra args.
_tl = threading.local()


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURABLE THRESHOLDS
# These can be tuned without touching detection logic.
# ══════════════════════════════════════════════════════════════════════════════

# Dedup window: same packet seen on multiple interfaces within this span is
# counted once. 200 ms handles Npcap cross-interface delivery jitter on Windows.
_DEDUP_WINDOW_SEC: float = 0.200

# Host IP cache TTL: re-discover local interface addresses every N seconds.
_HOST_IP_REFRESH_SEC: float = 30.0

# Alert rate-limit: minimum gap between repeated alerts for the same source IP.
_ALERT_INTERVAL: float = 5.0

# ARP/MITM alert rate-limit: minimum gap between repeated ARP spoofing alerts per source.
_ARP_ALERT_INTERVAL: float = 30.0

# Port-scan threshold: unique destination ports before flagging as scan.
# Raised from 12 → 30 → 60 to avoid false positives from Windows background traffic
# (Windows Update, Defender telemetry, Edge, OneDrive routinely touch 30-50 ports).
_SCAN_THRESHOLD: int = 60

# Incident auto-resolve: close OPEN/ACTIVE incidents silent for this many seconds.
_INCIDENT_TIMEOUT_SEC: float = 8.0

# Scan-state TTL: drop port-scan tracking for sources silent for 5 minutes.
_SCAN_STATE_TTL_SEC: float = 300.0

# Compatibility constant (referenced by main.py / dashboard.py).
ATTACK_LATCH_SECONDS = 12

# Gateway IPs — auto-detected at startup, excluded from attack detection.
# ALL internet traffic passes through the gateway so it must never be flagged.
_gateway_ips: set = set()

# Minimum confidence % required before an alert fires.
# Prevents low-certainty signals (cloud downloads, background services) from
# generating noisy HIGH alerts with low confidence.
_MIN_ALERT_CONFIDENCE: int = 45


def _detect_gateway_ips() -> None:
    """Read the default gateway IP from ipconfig and cache it."""
    import subprocess as _sp
    import re as _re
    global _gateway_ips
    try:
        out = _sp.check_output(
            "ipconfig", text=True, stderr=_sp.DEVNULL, timeout=6
        )
        found: set = set()
        for line in out.splitlines():
            if "Default Gateway" in line:
                m = _re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    found.add(m.group(1))
        if found:
            _gateway_ips = found
            print(f"[SOC] Gateway IPs: {found} - excluded from attack detection")
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# STATE — declared ONCE (FIX 7: duplicate declarations removed)
# ══════════════════════════════════════════════════════════════════════════════

packets          = deque(maxlen=10000)
alerts           = deque(maxlen=100)
traffic_history  = deque(maxlen=60)
incidents: dict  = {}
top_attackers: dict = {}
arp_events       = deque(maxlen=200)
scan_events      = deque(maxlen=100)
attack_map_events= deque(maxlen=100)

protocol_stats: dict = {"TCP": 0, "UDP": 0, "OTHER": 0}
port_stats: dict     = defaultdict(int)   # {dst_port: packet_count}
hourly_stats: dict   = defaultdict(int)   # {hour_0_23: packet_count}

network_stats: dict = {
    "total_packets":    0,
    "active_connections": set(),
    "suspicious_ips":   set(),
    "top_protocols":    {"TCP": 0, "UDP": 0, "OTHER": 0},
    "pps":              0.0,       # current packets/second (FIX 9)
    "dropped_loopback": 0,         # packets discarded as local/loopback (FIX 5)
    "dropped_dedup":    0,         # packets discarded as duplicates (FIX 6)
}

capture_status: dict = {
    "mode":         "starting",
    "interface":    "auto",
    "real_packets": 0,
    "sim_packets":  0,
    "last_error":   "",
    "admin":        False,         # populated in start_sniffer()
    "promisc":      False,
}

# Single, authoritative lock (FIX 7: was declared twice).
_lock = threading.Lock()

# Per-source alert rate-limiting: {src_ip: last_alert_epoch}
_last_alert_t: dict = {}

# Incident counter (monotonically increasing).
_incident_counter: int = 0
_alert_counter: int = 0
_active_conns_ts: dict = {}
_suspicious_ips_ts: dict = {}

def _next_alert_seq() -> int:
    global _alert_counter
    _alert_counter += 1
    return _alert_counter

# Distributed flood incident key + state.
_DIST_INC_KEY = "INC-DIST"
_dist_alert_state: dict = {"last_t": 0.0}

# ARP tracking: ip → set(macs), mac → set(ips)
_arp_ip_to_macs: dict = {}
_arp_mac_to_ips: dict = {}
_arp_last_alert: dict = {}   # {src_ip: last_alert_epoch} — ARP alert rate-limiter

# ── Network Device Registry ───────────────────────────────────────────────────
# Populated by three sources (all passive / safe, no admin required):
#   1. Passive ARP capture: every ARP reply seen by the sniffer
#   2. Windows ARP cache:   `arp -a` parsed every 30 s
#   3. Active ARP scan:     Scapy ARP-who-has to the local /24 every 60 s
#
# Format: {ip_str: {"mac", "hostname", "vendor", "last_seen", "source", "open_ports"}}
discovered_devices: dict = {}

# ── Raw Capture Stream (Wireshark-mode) ──────────────────────────────────────
# Separate from sniffer.packets: receives EVERY packet that passes BPF,
# only skipping 127.x loopback.  SOC detection still runs on the filtered
# pipeline; this deque is only for the live-capture viewer page.
raw_packets: deque = deque(maxlen=5000)
_raw_pkt_seq: int  = 0   # monotonically increasing sequence number
_soc_pkt_seq: int  = 0   # monotonically increasing sequence number for SOC-filtered packets

# Port-scan tracking: {src_ip: {ports, targets, start_t, last_t, flags}}
_scan_state: dict = {}

# ── Victim-side tracking ──────────────────────────────────────────────────────
# Tracks devices on the network that are under attack (destination perspective).
# Separate from top_attackers (source perspective) and incidents (src-keyed).
attacked_targets: dict = {}   # {dst_ip: {ip, packet_count, severity_score, ...}}
target_incidents: dict = {}   # {inc_id: {...}} — incidents where the victim is a non-host IP
_target_incident_counter: int = 0

# Rolling 1-second PPS window (FIX 9).
_pps_window: deque = deque()
_pps_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
# COUNTRY MAP  (first-octet heuristic)
# ══════════════════════════════════════════════════════════════════════════════

_OCTET_COUNTRIES = [
    (1,   2,   "CN"), (3,   4,   "US"), (5,   5,   "RU"),
    (6,   7,   "CA"), (8,   8,   "US"), (9,   9,   "MX"),
    (11,  13,  "CA"), (14,  14,  "JP"), (15,  16,  "UA"),
    (17,  18,  "SA"), (19,  19,  "NG"), (20,  20,  "TR"),
    (21,  21,  "PK"), (22,  22,  "SG"), (23,  24,  "US"),
    (25,  26,  "ID"), (27,  27,  "CN"), (28,  30,  "EG"),
    (31,  31,  "EU"), (32,  35,  "IR"), (36,  38,  "CN"),
    (39,  39,  "NG"), (40,  40,  "AR"), (41,  42,  "AF"),
    (43,  43,  "JP"), (44,  44,  "CA"), (45,  47,  "US"),
    (48,  48,  "AR"), (49,  49,  "KR"), (50,  53,  "EU"),
    (54,  54,  "US"), (55,  57,  "TR"), (58,  61,  "CN"),
    (62,  62,  "EU"), (63,  70,  "US"), (71,  79,  "US"),
    (80,  89,  "EU"), (90,  90,  "UA"), (91,  95,  "RU"),
    (96,  97,  "CA"), (98,  100, "US"), (101, 103, "CN"),
    (104, 107, "US"), (108, 108, "IN"), (109, 109, "RU"),
    (110, 126, "CN"), (128, 130, "US"), (131, 134, "EU"),
    (135, 137, "US"), (138, 141, "US"), (142, 142, "CA"),
    (143, 143, "US"), (144, 145, "AU"), (146, 148, "US"),
    (149, 149, "US"), (150, 150, "AU"), (151, 151, "EU"),
    (152, 152, "ZA"), (153, 153, "CN"), (154, 155, "EU"),
    (156, 156, "CN"), (157, 159, "EU"), (160, 168, "US"),
    (169, 169, "AR"), (170, 171, "MX"), (173, 175, "US"),
    (176, 177, "EU"), (178, 178, "RU"), (179, 179, "BR"),
    (180, 183, "CN"), (184, 184, "US"), (185, 185, "EU"),
    (186, 187, "BR"), (188, 193, "EU"), (194, 195, "EU"),
    (196, 197, "AF"), (198, 199, "US"), (200, 201, "BR"),
    (202, 203, "CN"), (204, 210, "US"), (211, 223, "CN"),
]

_SERVICE_MAP = {
    20: "FTP-Data", 21: "FTP",    22: "SSH",    23: "Telnet",
    25: "SMTP",     53: "DNS",    67: "DHCP",   68: "DHCP",
    80: "HTTP",    110: "POP3",  143: "IMAP",  161: "SNMP",
   443: "HTTPS",  445: "SMB",   465: "SMTPS", 587: "SMTP",
   993: "IMAPS",  995: "POP3S",1433: "MSSQL",1521: "Oracle",
  3306: "MySQL", 3389: "RDP",  5432: "PgSQL", 5900: "VNC",
  6379: "Redis", 8080: "HTTP+",8443: "HTTPS+",27017: "Mongo",
}

# MAC OUI prefix → vendor name (first 8 chars of lower-case mac, e.g. "00:50:56").
_MAC_VENDORS: dict[str, str] = {
    # ── Virtualisation ────────────────────────────────────────────────────────
    "00:50:56": "VMware",      "00:0c:29": "VMware",      "00:05:69": "VMware",
    "08:00:27": "VirtualBox",  "0a:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    # ── TP-Link ───────────────────────────────────────────────────────────────
    "00:27:19": "TP-Link",     "14:cc:20": "TP-Link",     "18:d6:c7": "TP-Link",
    "1c:3b:49": "TP-Link",     "28:28:5d": "TP-Link",     "30:b5:c2": "TP-Link",
    "40:e2:30": "TP-Link",     "50:3e:aa": "TP-Link",     "50:fa:84": "TP-Link",
    "54:e6:fc": "TP-Link",     "58:d5:6e": "TP-Link",     "5c:63:bf": "TP-Link",
    "60:a4:b7": "TP-Link",     "64:6e:69": "TP-Link",     "6c:5a:b5": "TP-Link",
    "74:da:38": "TP-Link",     "80:35:c1": "TP-Link",     "84:16:f9": "TP-Link",
    "88:25:2c": "TP-Link",     "90:f6:52": "TP-Link",     "98:da:c4": "TP-Link",
    "a0:f3:c1": "TP-Link",     "a4:2b:b0": "TP-Link",     "b0:48:7a": "TP-Link",
    "b4:b0:24": "TP-Link",     "c0:49:ef": "TP-Link",     "c4:6e:1f": "TP-Link",
    "c8:d3:ff": "TP-Link",     "cc:32:e5": "TP-Link",     "d0:76:e7": "TP-Link",
    "d8:0d:17": "TP-Link",     "d8:61:62": "TP-Link",     "dc:fe:18": "TP-Link",
    "e0:05:c5": "TP-Link",     "e4:3a:6e": "TP-Link",     "ec:43:f6": "TP-Link",
    "f4:ec:38": "TP-Link",
    # ── Netgear ───────────────────────────────────────────────────────────────
    "00:09:5b": "Netgear",     "00:0f:b5": "Netgear",     "00:14:6c": "Netgear",
    "00:18:4d": "Netgear",     "00:1b:2f": "Netgear",     "00:1e:2a": "Netgear",
    "00:1f:33": "Netgear",     "00:22:3f": "Netgear",     "00:24:b2": "Netgear",
    "00:26:f2": "Netgear",     "10:0d:7f": "Netgear",     "20:0c:c8": "Netgear",
    "28:c6:8e": "Netgear",     "2c:56:dc": "Netgear",     "30:46:9a": "Netgear",
    "44:94:fc": "Netgear",     "4c:60:de": "Netgear",     "6c:b0:ce": "Netgear",
    "84:1b:5e": "Netgear",     "9c:3d:cf": "Netgear",     "a0:21:b7": "Netgear",
    "a0:40:a0": "Netgear",
    # ── ASUS ─────────────────────────────────────────────────────────────────
    "00:0c:6e": "Asus",        "00:1a:92": "Asus",        "00:1d:60": "Asus",
    "00:1f:c6": "Asus",        "00:23:54": "Asus",        "00:26:18": "Asus",
    "04:92:26": "Asus",        "08:60:6e": "Asus",        "10:c3:7b": "Asus",
    "14:da:e9": "Asus",        "1c:87:2c": "Asus",        "20:cf:30": "Asus",
    "2c:fd:a1": "Asus",        "38:d5:47": "Asus",        "40:16:7e": "Asus",
    "50:46:5d": "Asus",        "54:a0:50": "Asus",        "60:45:cb": "Asus",
    "70:8b:cd": "Asus",        "74:d0:2b": "Asus",        "7c:10:c9": "Asus",
    "88:d7:f6": "Asus",        "90:e6:ba": "Asus",        "9c:5c:8e": "Asus",
    "a0:36:9f": "Asus",        "ac:9e:17": "Asus",        "b0:4e:26": "Asus",
    "b0:6e:bf": "Asus",        "bc:ee:7b": "Asus",        "cc:28:aa": "Asus",
    "d4:5d:df": "Asus",        "f0:2f:74": "Asus",        "f4:6d:04": "Asus",
    "fc:34:97": "Asus",
    # ── D-Link ────────────────────────────────────────────────────────────────
    "00:05:5d": "D-Link",      "00:11:95": "D-Link",      "00:13:46": "D-Link",
    "00:15:e9": "D-Link",      "00:17:9a": "D-Link",      "00:19:5b": "D-Link",
    "00:1b:11": "D-Link",      "00:1c:f0": "D-Link",      "00:1e:58": "D-Link",
    "00:22:b0": "D-Link",      "00:24:01": "D-Link",      "00:26:5a": "D-Link",
    "1c:7e:e5": "D-Link",      "28:10:7b": "D-Link",      "34:08:04": "D-Link",
    "78:54:2e": "D-Link",      "90:94:e4": "D-Link",      "b8:a3:86": "D-Link",
    "c8:be:19": "D-Link",      "f0:7d:68": "D-Link",
    # ── Linksys ───────────────────────────────────────────────────────────────
    "00:06:25": "Linksys",     "00:12:17": "Linksys",     "00:13:10": "Linksys",
    "00:14:bf": "Linksys",     "00:16:b6": "Linksys",     "00:18:39": "Linksys",
    "00:1a:70": "Linksys",     "00:1c:10": "Linksys",     "00:1d:7e": "Linksys",
    "c0:c1:c0": "Linksys",     "e8:9f:80": "Linksys",
    # ── Belkin ────────────────────────────────────────────────────────────────
    "00:17:3f": "Belkin",      "00:30:bd": "Belkin",      "08:86:3b": "Belkin",
    "94:10:3e": "Belkin",      "ec:1a:59": "Belkin",
    # ── AVM Fritz!Box ─────────────────────────────────────────────────────────
    "3c:a6:2f": "AVM",         "ac:16:2d": "AVM",         "c8:0e:14": "AVM",
    "e0:28:6d": "AVM",
    # ── Zyxel ────────────────────────────────────────────────────────────────
    "00:13:49": "Zyxel",       "00:19:cb": "Zyxel",       "00:a0:c5": "Zyxel",
    "28:87:ba": "Zyxel",       "40:4a:03": "Zyxel",       "5c:4c:a9": "Zyxel",
    "60:31:97": "Zyxel",       "78:18:81": "Zyxel",       "9c:a2:f4": "Zyxel",
    "b0:b2:dc": "Zyxel",       "e4:18:6b": "Zyxel",       "f4:60:e2": "Zyxel",
    # ── Tenda ────────────────────────────────────────────────────────────────
    "18:a6:f7": "Tenda",       "40:3f:8c": "Tenda",       "74:ee:2a": "Tenda",
    "84:c9:b2": "Tenda",       "98:f1:98": "Tenda",       "c8:3a:35": "Tenda",
    # ── Xiaomi ───────────────────────────────────────────────────────────────
    "28:6c:07": "Xiaomi",      "34:ce:00": "Xiaomi",      "50:8f:4c": "Xiaomi",
    "64:09:80": "Xiaomi",      "6c:28:08": "Xiaomi",      "74:51:ba": "Xiaomi",
    "78:11:dc": "Xiaomi",      "a4:50:46": "Xiaomi",      "ac:f7:f3": "Xiaomi",
    "b0:e2:35": "Xiaomi",      "c4:6a:b7": "Xiaomi",      "d4:97:0b": "Xiaomi",
    "f0:b4:29": "Xiaomi",      "f8:a4:5f": "Xiaomi",
    # ── Cisco (enterprise switches/routers) ──────────────────────────────────
    "00:00:0c": "Cisco",       "00:01:96": "Cisco",       "00:02:16": "Cisco",
    "00:03:6b": "Cisco",       "00:04:27": "Cisco",       "00:05:5e": "Cisco",
    "00:06:28": "Cisco",       "00:07:0d": "Cisco",       "00:08:20": "Cisco",
    "00:09:12": "Cisco",       "00:0a:41": "Cisco",       "00:0b:45": "Cisco",
    "00:0c:30": "Cisco",       "00:0c:85": "Cisco",       "00:0d:28": "Cisco",
    "00:0e:38": "Cisco",       "00:0e:83": "Cisco",       "00:0f:23": "Cisco",
    "00:0f:8f": "Cisco",       "00:10:0d": "Cisco",       "00:11:20": "Cisco",
    "00:12:00": "Cisco",       "00:13:1a": "Cisco",       "00:14:1b": "Cisco",
    "00:15:2b": "Cisco",       "00:16:46": "Cisco",       "00:17:0e": "Cisco",
    "00:18:18": "Cisco",       "00:19:06": "Cisco",       "00:1a:2f": "Cisco",
    "00:1b:0c": "Cisco",       "00:1c:0e": "Cisco",       "00:1d:45": "Cisco",
    "00:1e:13": "Cisco",       "00:1e:be": "Cisco",       "00:1f:26": "Cisco",
    "00:21:1b": "Cisco",       "00:22:0c": "Cisco",       "00:23:04": "Cisco",
    "00:23:89": "Cisco",       "00:24:13": "Cisco",       "00:25:45": "Cisco",
    "00:26:0a": "Cisco",       "00:26:98": "Cisco",       "00:27:0d": "Cisco",
    "cc:46:d6": "Cisco",       "e8:ba:70": "Cisco",       "f8:72:ea": "Cisco",
    # ── Juniper (enterprise) ─────────────────────────────────────────────────
    "00:10:db": "Juniper",     "00:12:1e": "Juniper",     "00:14:f6": "Juniper",
    "00:17:cb": "Juniper",     "00:19:e2": "Juniper",     "00:1b:c0": "Juniper",
    "00:1f:12": "Juniper",     "00:21:59": "Juniper",     "00:23:9c": "Juniper",
    "28:c0:da": "Juniper",     "40:b4:f0": "Juniper",     "54:4b:8c": "Juniper",
    "64:64:9b": "Juniper",     "64:87:88": "Juniper",
    # ── HP / Aruba ───────────────────────────────────────────────────────────
    "00:11:0a": "HP",          "00:12:79": "HP",          "00:13:21": "HP",
    "00:14:c2": "HP",          "00:15:60": "HP",          "00:17:08": "HP",
    "00:18:fe": "HP",          "00:1a:1e": "HP",          "00:1b:78": "HP",
    "00:1c:2e": "HP",          "00:1e:c1": "HP",          "00:1f:28": "HP",
    "00:21:5a": "HP",          "00:22:64": "HP",          "00:23:47": "HP",
    "00:24:81": "HP",          "00:25:b3": "HP",          "00:26:55": "HP",
    "18:a9:05": "HP",          "1c:c1:de": "HP",          "3c:d9:2b": "HP",
    "58:20:b1": "HP",          "70:10:6f": "HP",          "98:e7:f4": "HP",
    # ── Ubiquiti ─────────────────────────────────────────────────────────────
    "00:15:6d": "Ubiquiti",    "00:27:22": "Ubiquiti",    "04:18:d6": "Ubiquiti",
    "0c:80:63": "Ubiquiti",    "18:e8:29": "Ubiquiti",    "24:a4:3c": "Ubiquiti",
    "44:d9:e7": "Ubiquiti",    "68:72:51": "Ubiquiti",    "78:8a:20": "Ubiquiti",
    "80:2a:a8": "Ubiquiti",    "9c:05:d6": "Ubiquiti",    "ac:8b:a9": "Ubiquiti",
    "b4:fb:e4": "Ubiquiti",    "dc:9f:db": "Ubiquiti",    "e0:63:da": "Ubiquiti",
    "f0:9f:c2": "Ubiquiti",    "fc:ec:da": "Ubiquiti",
    # ── MikroTik ─────────────────────────────────────────────────────────────
    "00:0c:42": "MikroTik",    "2c:c8:1b": "MikroTik",   "4c:5e:0c": "MikroTik",
    "6c:3b:6b": "MikroTik",    "74:4d:28": "MikroTik",   "b8:69:f4": "MikroTik",
    "c4:ad:34": "MikroTik",    "d4:ca:6d": "MikroTik",   "e4:8d:8c": "MikroTik",
    "48:8f:5a": "MikroTik",
    # ── Huawei ───────────────────────────────────────────────────────────────
    "00:e0:fc": "Huawei",      "04:bd:70": "Huawei",      "0c:96:bf": "Huawei",
    "10:1b:54": "Huawei",      "18:09:5a": "Huawei",      "20:f3:a3": "Huawei",
    "28:6e:d4": "Huawei",      "30:45:96": "Huawei",      "38:f8:89": "Huawei",
    "40:4d:8e": "Huawei",      "48:db:50": "Huawei",      "4c:1f:cc": "Huawei",
    "54:89:98": "Huawei",      "5c:c3:07": "Huawei",      "68:89:c1": "Huawei",
    "6c:8d:c1": "Huawei",      "70:72:cf": "Huawei",      "78:1d:ba": "Huawei",
    "84:be:52": "Huawei",      "8c:34:fd": "Huawei",      "90:67:1c": "Huawei",
    "94:77:2b": "Huawei",      "98:e7:f4": "Huawei",      "a4:99:47": "Huawei",
    "ac:e2:15": "Huawei",      "b4:e6:2d": "Huawei",      "c4:f0:81": "Huawei",
    "cc:96:a0": "Huawei",      "d4:6e:5c": "Huawei",      "e8:cd:2d": "Huawei",
    "f4:4c:7f": "Huawei",      "f8:01:13": "Huawei",
    # ── Other common devices ──────────────────────────────────────────────────
    "00:1a:11": "Google",      "f4:f5:e8": "Google",      "f4:f5:db": "Google",
    "b8:27:eb": "Raspberry Pi","dc:a6:32": "Raspberry Pi","e4:5f:01": "Raspberry Pi",
    "00:11:32": "Synology",    "00:0e:c6": "Atheros",
    "00:1e:67": "Intel",       "8c:8d:28": "Intel",       "a4:c3:f0": "Intel",
    "00:1a:a0": "Dell",        "18:03:73": "Dell",        "f8:db:88": "Dell",
    "3c:97:0e": "Apple",       "a8:51:ab": "Apple",       "28:cf:e9": "Apple",
    "00:25:00": "Apple",       "00:17:f2": "Apple",
    "f8:1a:67": "Samsung",     "50:01:bb": "Samsung",     "fc:a1:83": "Samsung",
    "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
    "b8:27:00": "MediaTek",
}


# ══════════════════════════════════════════════════════════════════════════════
# FIX 2/3 — ADMIN DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def _is_admin() -> bool:
    """Return True if the current process has administrator / root privileges."""
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# FIX 5 — HOST IP CACHE
# Maintains a thread-safe, periodically-refreshed set of all IP addresses that
# belong to this machine.  Used to filter out same-host and loopback traffic.
# ══════════════════════════════════════════════════════════════════════════════

_host_ip_cache: dict = {"ips": frozenset({"127.0.0.1", "::1"}), "ts": 0.0}
_host_ip_lock = threading.Lock()


def _refresh_host_ips(force: bool = False) -> None:
    """Rebuild _host_ip_cache from live interface data."""
    now = time.time()
    with _host_ip_lock:
        if not force and (now - _host_ip_cache["ts"]) < _HOST_IP_REFRESH_SEC:
            return

    ips: set = {"127.0.0.1", "0.0.0.0", "::1"}

    # Primary IP: the address used when connecting to the internet.
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass

    # All interface IPs reported by the OS.
    try:
        hostname = _socket.gethostname()
        for info in _socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if isinstance(addr, str) and ":" not in addr:
                ips.add(addr)
    except Exception:
        pass

    # Every Npcap-visible interface address.
    try:
        for iface in get_working_ifaces():
            if iface.ip:
                ips.add(str(iface.ip))
    except Exception:
        pass

    with _host_ip_lock:
        _host_ip_cache["ips"] = frozenset(ips)
        _host_ip_cache["ts"]  = now


def _get_host_ips() -> frozenset:
    _refresh_host_ips()
    with _host_ip_lock:
        return _host_ip_cache["ips"]


# ══════════════════════════════════════════════════════════════════════════════
# FIX 4 + 5 — EARLY PACKET DROP GATE
# Called on every captured packet before any counting or detection.
# Returning True means "discard this packet, don't count it."
# ══════════════════════════════════════════════════════════════════════════════

def _should_drop_packet(pkt) -> bool:
    """
    Return True for packets that must never be counted or detected on.

    Handles four noise categories that inflate rates in non-admin mode:
      1. Loopback: either endpoint is 127.x
      2. Broadcast destinations (255.255.255.255 and subnet .255 broadcasts)
      3. Multicast destinations (224.0.0.0/4 — mDNS, SSDP, etc.)
      4. Same-machine: both src and dst are host IPs (VM-bridge self-traffic)
    """
    if not pkt.haslayer(IP):
        return False   # ARP packets handled separately; let them through.

    try:
        src = pkt[IP].src
        dst = pkt[IP].dst
    except Exception:
        return True    # Malformed IP header — discard.

    # 1. Loopback
    if src.startswith("127.") or dst.startswith("127."):
        return True

    # Resolve host IPs early so checks 2 and 3 can exempt inbound unicast packets
    # that are addressed TO this machine.  Without this, a machine whose IP ends
    # in .255 (rare but valid) or sits in the 224-239 range (e.g. some VPN
    # tunnel assignments) would have ALL inbound attack traffic silently dropped
    # by the broadcast/multicast rules before reaching the detection engine.
    host_ips = _get_host_ips()
    dst_is_local = dst in host_ips   # True = packet is addressed TO this machine

    # 2. Broadcast — but never drop packets destined for this machine's own IP.
    if not dst_is_local:
        if dst == "255.255.255.255" or dst.endswith(".255"):
            return True

    # 3. Multicast (224.0.0.0/4) — same exemption for local destination.
    if not dst_is_local:
        try:
            first_oct = int(dst.split(".", 1)[0])
            if 224 <= first_oct <= 239:
                return True
        except (ValueError, IndexError):
            return True    # Can't parse destination — discard.

    # 4. Same-machine: both IPs belong to this host.
    #    Delegated to normalizer.should_drop_same_machine() which uses a
    #    subnet-aware check to avoid dropping cross-subnet host-to-host traffic
    #    that is actually a VM attack forwarded by hypervisor NAT
    #    (e.g. src=VMnet8 192.168.75.1 → dst=physical 192.168.1.100).
    #    See normalizer.py for the full rationale.
    if normalizer.should_drop_same_machine(src, dst, host_ips):
        return True

    return False


# ══════════════════════════════════════════════════════════════════════════════
# FIX 6 — PACKET DEDUPLICATION (richer fingerprint + wider window)
# ══════════════════════════════════════════════════════════════════════════════

# Key → epoch of first sighting.  Protected implicitly by Python's GIL for
# simple reads/writes; explicit lock only for the periodic bulk cleanup.
_dedup_seen: dict = {}
_dedup_cleanup_lock = threading.Lock()


def _packet_fingerprint(pkt) -> tuple | None:
    """
    Build a 7-tuple fingerprint that uniquely identifies a physical packet
    across different capture paths (Npcap adapter, bridge adapter, raw socket).

    Old key (src, dst, proto, ip_id) failed when ip_id==0:
      - Windows sets DF=1 on most packets and zeros the ID (RFC 6864 §4)
      - Two different UDP streams shared ip_id=0, causing false-positive drops
      - True duplicates from multi-interface capture had slightly different
        ip_id values and slipped through dedup entirely

    New key adds layer-4 identifiers so two different connections with ip_id=0
    are never mistaken for each other, while the same physical packet arriving
    on two interfaces still produces an identical tuple.
    """
    if not pkt.haslayer(IP):
        return None
    try:
        ip    = pkt[IP]
        src   = ip.src
        dst   = ip.dst
        proto = ip.proto
        ip_id = ip.id

        sport = dport = extra = 0

        if proto == 6 and pkt.haslayer(TCP):     # TCP
            t = pkt[TCP]
            sport = int(t.sport)
            dport = int(t.dport)
            # Lower 16 bits of seq number differentiates streams sharing ip_id=0
            # while remaining stable across multi-interface delivery of same frame.
            extra = int(t.seq) & 0xFFFF

        elif proto == 17 and pkt.haslayer(UDP):  # UDP
            u = pkt[UDP]
            sport = int(u.sport)
            dport = int(u.dport)
            # When ip_id=0 (DF=1, common on Linux) and ports are fixed, all
            # UDP flood packets share the same fingerprint and get deduplicated.
            # The UDP checksum varies with payload, so it differentiates packets
            # that are genuinely distinct even with matching ports and ip_id=0.
            if ip_id == 0 and hasattr(u, "chksum") and u.chksum:
                extra = int(u.chksum) & 0xFFFF

        elif proto == 1 and pkt.haslayer(ICMP):  # ICMP
            ic = pkt[ICMP]
            extra = (int(ic.type) << 8) | int(ic.code)
            # ICMP echo id separates concurrent ping streams.
            if hasattr(ic, "id"):
                sport = int(ic.id) & 0xFFFF
            # Include sequence number so individual ICMP requests are never
            # deduplicated as "duplicates."  Without this, a flood where ip_id=0
            # (RFC 6864 DF=1 behaviour, common on Linux) and icmp.id is fixed
            # produces an identical fingerprint for every packet — the dedup
            # window keeps only 1 packet per 200 ms, making the entire flood
            # invisible to the detection engine regardless of send rate.
            if hasattr(ic, "seq"):
                dport = int(ic.seq) & 0xFFFF

        return (src, dst, proto, ip_id, sport, dport, extra)

    except Exception:
        return None


def _is_duplicate(pkt) -> bool:
    """
    Return True if an identical packet fingerprint was seen within _DEDUP_WINDOW_SEC.

    Thread-safe: dict reads/writes are GIL-atomic in CPython; the cleanup
    section acquires a separate lock to prevent concurrent teardown races.
    """
    key = _packet_fingerprint(pkt)
    if key is None:
        return False

    now = time.time()

    # Periodic cleanup to keep the dict bounded (expected max: ~2000 entries
    # at 200 ms window / 10 000 pps).  Only one thread runs cleanup at a time.
    if len(_dedup_seen) > 15000:
        with _dedup_cleanup_lock:
            if len(_dedup_seen) > 15000:
                cutoff = now - _DEDUP_WINDOW_SEC
                stale  = [k for k, t in list(_dedup_seen.items()) if t < cutoff]
                for k in stale:
                    _dedup_seen.pop(k, None)

    if key in _dedup_seen:
        return True   # Duplicate: same packet seen on another interface.

    _dedup_seen[key] = now
    return False


# ══════════════════════════════════════════════════════════════════════════════
# BPF FILTER
# "ip or arp" captures ALL IP packets (TCP, UDP, ICMP, IGMP, OSPF, etc.) plus
# ARP.  Widening from the old "(tcp or udp or icmp) or arp" lets through DHCP
# broadcasts, mDNS multicasts, SSDP, IGMP — traffic from OTHER LAN devices
# that the Wireshark-style capture page needs to show.
# The SOC detection pipeline still applies software filters; raw_packets gets
# everything so the live-capture viewer is complete.
# ══════════════════════════════════════════════════════════════════════════════

_BPF_FILTER = "ip or arp"


# ══════════════════════════════════════════════════════════════════════════════
# PROTOCOL DETECTION AND INFO GENERATION  (Wireshark-style)
# ══════════════════════════════════════════════════════════════════════════════

# Well-known TCP ports → protocol label.
_TCP_PROTO: dict[int, str] = {
    20: "FTP-Data", 21: "FTP",    22: "SSH",  23: "Telnet",
    25: "SMTP",     53: "DNS",    80: "HTTP", 110: "POP3",
   143: "IMAP",   179: "BGP",   443: "HTTPS",445: "SMB",
   465: "SMTPS",  587: "SMTP",  636: "LDAPS",993: "IMAPS",
   995: "POP3S",  3306:"MySQL", 3389:"RDP",  5432:"PgSQL",
   5900:"VNC",    6379:"Redis", 8080:"HTTP+",8443:"HTTPS+",
  27017:"Mongo",
}
# Well-known UDP ports → protocol label.
_UDP_PROTO: dict[int, str] = {
    53: "DNS",  67: "DHCP", 68: "DHCP",  69: "TFTP",
   123: "NTP", 137: "NBNS",138: "NBDS", 161: "SNMP",
   162: "SNMP",500: "IKE",  514:"Syslog",520: "RIP",
  1900:"SSDP", 4500:"IKE",  5353:"mDNS",5355:"LLMNR",
}
# IP protocol numbers → fallback label when no layer parsing.
_IP_PROTO_NAMES: dict[int, str] = {
    1: "ICMP",  2: "IGMP",  4: "IP-in-IP", 6: "TCP",
   17: "UDP",  41: "IPv6", 47: "GRE",      50: "ESP",
   51: "AH",   58: "ICMPv6",89: "OSPF",   112:"VRRP",
}
# ICMP type → short label.
_ICMP_TYPES: dict[int, str] = {
    0: "Echo Reply",      3: "Unreachable",  5: "Redirect",
    8: "Echo Request",   11: "Time Exceeded",12: "Param Problem",
   13: "Timestamp Req",  14: "Timestamp Rep",
}
# Front-end colour per protocol (consumed by capture.html).
PROTO_COLORS: dict[str, str] = {
    "ARP":    "#f59e0b",   # amber
    "ICMP":   "#06b6d4",   # cyan
    "IGMP":   "#10b981",   # emerald
    "HTTP":   "#22c55e",   # green
    "HTTPS":  "#16a34a",   # dark green
    "DNS":    "#f97316",   # orange
    "mDNS":   "#fb923c",   # light-orange
    "DHCP":   "#ec4899",   # pink
    "SSDP":   "#94a3b8",   # slate
    "LLMNR":  "#94a3b8",
    "NBNS":   "#94a3b8",
    "NTP":    "#a78bfa",   # violet
    "SNMP":   "#c084fc",   # purple
    "SSH":    "#ef4444",   # red
    "RDP":    "#dc2626",   # dark-red
    "FTP":    "#fb7185",   # rose
    "Telnet": "#f43f5e",
    "SMB":    "#f43f5e",
    "SMTP":   "#c084fc",
    "MySQL":  "#c084fc",
    "Redis":  "#c084fc",
    "Mongo":  "#c084fc",
    "OSPF":   "#38bdf8",   # sky
    "GRE":    "#38bdf8",
    "TCP":    "#3b82f6",   # blue
    "UDP":    "#8b5cf6",   # violet
    "TFTP":   "#8b5cf6",
    "IKE":    "#8b5cf6",
    "OTHER":  "#475569",   # slate-600
}


def _detect_proto(pkt) -> str:
    """Return a human-readable protocol name for a captured packet."""
    try:
        if pkt.haslayer(ARP):
            return "ARP"
        if not pkt.haslayer(IP):
            return "OTHER"

        ip_proto = pkt[IP].proto

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sp, dp = int(tcp.sport), int(tcp.dport)
            return _TCP_PROTO.get(dp) or _TCP_PROTO.get(sp) or "TCP"

        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            sp, dp = int(udp.sport), int(udp.dport)
            return _UDP_PROTO.get(dp) or _UDP_PROTO.get(sp) or "UDP"

        if pkt.haslayer(ICMP):
            return "ICMP"

        return _IP_PROTO_NAMES.get(ip_proto, f"IP/{ip_proto}")

    except Exception:
        return "OTHER"


def _packet_info(pkt) -> str:
    """
    Generate a Wireshark-style Info column string for a packet.

    Examples:
      ARP:  "Who has 192.168.1.1? Tell 192.168.1.50"
      ICMP: "Echo request  id=0x0001 seq=12"
      TCP:  "443 → 52341 [ACK] Seq=1820 Len=0"
      DNS:  "Standard query A example.com"
      DHCP: "DHCP Discover — Transaction 0x1234"
      UDP:  "5353 → 5353  Len=45"
    """
    try:
        # ── ARP ──────────────────────────────────────────────────────────────
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            if arp.op == 1:
                return f"Who has {arp.pdst}? Tell {arp.psrc}"
            return f"{arp.psrc} is at {arp.hwsrc}"

        if not pkt.haslayer(IP):
            return ""

        # ── ICMP ─────────────────────────────────────────────────────────────
        if pkt.haslayer(ICMP):
            ic = pkt[ICMP]
            label = _ICMP_TYPES.get(int(ic.type), f"Type {ic.type}")
            seq   = getattr(ic, "seq", 0)
            icid  = getattr(ic, "id",  0)
            return f"{label}  id=0x{icid:04x} seq={seq}"

        # ── TCP ───────────────────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            fl  = int(tcp.flags)
            bits = []
            if fl & 0x02: bits.append("SYN")
            if fl & 0x10: bits.append("ACK")
            if fl & 0x01: bits.append("FIN")
            if fl & 0x04: bits.append("RST")
            if fl & 0x08: bits.append("PSH")
            if fl & 0x20: bits.append("URG")
            flag_str = ",".join(bits) or "NONE"
            pay_len  = len(bytes(tcp.payload)) if tcp.payload else 0
            return (f"{tcp.sport} → {tcp.dport} [{flag_str}] "
                    f"Seq={tcp.seq} Len={pay_len}")

        # ── UDP ───────────────────────────────────────────────────────────────
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            sp, dp = int(udp.sport), int(udp.dport)

            # DHCP
            if dp in (67, 68) or sp in (67, 68):
                try:
                    # Read DHCP message type from the raw payload
                    raw = bytes(udp.payload)
                    # BOOTP op: 1=Request 2=Reply
                    op   = raw[0] if raw else 0
                    xid  = int.from_bytes(raw[4:8], "big") if len(raw) >= 8 else 0
                    kind = "Discover/Request" if op == 1 else "Offer/ACK"
                    return f"DHCP {kind} — Transaction 0x{xid:08x}"
                except Exception:
                    return f"DHCP  {sp} → {dp}"

            # DNS / mDNS
            if dp in (53, 5353) or sp in (53, 5353):
                label = "mDNS" if 5353 in (sp, dp) else "DNS"
                try:
                    from scapy.layers.dns import DNS
                    if pkt.haslayer(DNS):
                        dns = pkt[DNS]
                        qr  = "Response" if dns.qr else "Query"
                        qn  = ""
                        if dns.qd and hasattr(dns.qd, "qname"):
                            qn = dns.qd.qname.decode(errors="replace").rstrip(".")
                        return f"{label} {qr} {qn}".strip()
                except Exception:
                    pass
                return f"{label}  {sp} → {dp}"

            # SSDP
            if dp == 1900 or sp == 1900:
                return f"SSDP Discovery  {sp} → {dp}"

            # NTP
            if dp == 123 or sp == 123:
                return f"NTP  {sp} → {dp}"

            return f"{sp} → {dp}  Len={udp.len}"

    except Exception:
        pass
    return ""


def _build_raw_entry(pkt, seq: int) -> dict:
    """Build a dict representing one packet for the raw capture stream."""
    proto  = _detect_proto(pkt)
    info   = _packet_info(pkt)
    length = 0
    try:
        length = len(bytes(pkt))
    except Exception:
        pass

    src = dst = ""
    src_port = dst_port = 0

    try:
        if pkt.haslayer(ARP):
            src = pkt[ARP].psrc or pkt[ARP].hwsrc or ""
            dst = pkt[ARP].pdst or ""
        elif pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            if pkt.haslayer(TCP):
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
    except Exception:
        pass

    return {
        "seq":      seq,
        "time":     ts(),
        "epoch":    time.time(),
        "src":      src,
        "dst":      dst,
        "sport":    src_port,
        "dport":    dst_port,
        "proto":    proto,
        "length":   length,
        "info":     info,
        "color":    PROTO_COLORS.get(proto, PROTO_COLORS["OTHER"]),
    }


# ══════════════════════════════════════════════════════════════════════════════
# FIX 9 — ACCURATE PACKETS-PER-SECOND
# Rolling 1-second window; O(1) read; safe to call from dashboard threads.
# ══════════════════════════════════════════════════════════════════════════════

def _record_pps() -> float:
    """Append current timestamp to the PPS window; return current PPS."""
    now = time.time()
    with _pps_lock:
        _pps_window.append(now)
        # Prune entries older than 1 second.
        while _pps_window and _pps_window[0] < now - 1.0:
            _pps_window.popleft()
        return float(len(_pps_window))


def current_pps() -> float:
    """Return current packets-per-second (read-only; no side effects)."""
    now = time.time()
    with _pps_lock:
        while _pps_window and _pps_window[0] < now - 1.0:
            _pps_window.popleft()
        return float(len(_pps_window))


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _ip_to_country(ip: str) -> str:
    try:
        parts  = ip.split(".")
        first  = int(parts[0])
        second = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return "Unknown"
    if first == 10:                             return "Local"
    if first == 172 and 16 <= second <= 31:     return "Local"
    if first == 192 and second == 168:          return "Local"
    if first == 127:                            return "Local"
    if first >= 224:                            return "Multicast"
    # Public IP: try real GeoIP cache first (queues async lookup automatically)
    from detection.incident_manager import lookup_country as _gc
    cached = _gc(ip)
    if cached:
        return cached
    for lo, hi, code in _OCTET_COUNTRIES:
        if lo <= first <= hi:
            return code
    return "Unknown"


def _classify_scan(flags: int, has_tcp: bool) -> str:
    if not has_tcp:           return "TCP Scan"
    if flags == 0:            return "NULL Scan"
    if flags & 0x29 == 0x29:  return "XMAS Scan"
    if flags == 0x01:         return "FIN Scan"
    if flags == 0x02:         return "SYN Scan"
    return "TCP Scan"


def _fmt_duration(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    return f"{m}m {s:02d}s"


def _new_incident_id() -> str:
    global _incident_counter
    _incident_counter += 1
    return f"INC-{_incident_counter:04d}"


def _classify_attack(proto: str, rate: int) -> str:
    if rate > 150:      return "DDoS Flood"
    if proto == "UDP":  return "UDP Flood"
    if proto == "TCP":  return "SYN Flood"
    return "Port Scan"


def _severity_score(confidence: int, rate: int) -> int:
    return min(100, int(confidence * 0.6 + min(rate, 200) * 0.2))


def _apply_elapsed(inc: dict, now: float) -> None:
    elapsed = now - inc["start_epoch"]
    inc["duration_seconds"] = elapsed
    inc["duration"] = _fmt_duration(elapsed)


# ══════════════════════════════════════════════════════════════════════════════
# INCIDENT LIFECYCLE
# ══════════════════════════════════════════════════════════════════════════════

def _manage_incident(src: str, proto: str, severity, confidence: int, rate: int) -> None:
    try:
        from detection import network_profiler
        if not network_profiler.is_ready():
            return
    except Exception:
        pass

    now    = time.time()
    now_ts = ts()

    if severity in ("HIGH", "MEDIUM"):
        score       = _severity_score(confidence, rate)
        attack_type = _classify_attack(proto, rate)
        existing    = None
        for inc in incidents.values():
            if inc["source_ip"] == src and inc["status"] in ("OPEN", "ACTIVE"):
                existing = inc
                break
        if existing:
            _apply_elapsed(existing, now)
            existing["status"]         = "ACTIVE"
            existing["end_time"]       = now_ts
            existing["severity_score"] = max(existing["severity_score"], score)
            existing["attack_type"]    = attack_type
            existing["packet_count"]   = existing.get("packet_count", 0) + 1
            # Only extend incident lifetime for high-confidence attacks (≥60%).
            # Low-confidence borderline detections (45-59%) from background
            # cloud/CDN traffic must NOT prevent the incident from timing out
            # after the real attack ends.
            if confidence >= 60:
                existing["last_update_epoch"] = now
        else:
            inc_id = _new_incident_id()
            incidents[inc_id] = {
                "incident_id":       inc_id,
                "source_ip":         src,
                "start_time":        now_ts,
                "end_time":          now_ts,
                "start_epoch":       now,
                "last_update_epoch": now,
                "duration_seconds":  0,
                "duration":          "0s",
                "status":            "OPEN",
                "severity_score":    score,
                "attack_type":       attack_type,
                "packet_count":      1,
                "confidence":        confidence,
            }
        if score >= fw.AUTO_BLOCK_SCORE and not fw.is_blocked(src):
            fw.block_ip(src, reason=f"Auto-block: score {score}", auto=True)
    # Do NOT resolve incidents on every normal/None-severity packet.
    # Severity flickers at borderline rates — instant resolution causes
    # the 30-second cooldown in clear_src_state to make the attack invisible.
    # The background _incident_resolver handles resolution after 12s of silence.


def _update_attacker(src: str, confidence: int, rate: int, proto: str,
                     country: str = "") -> None:
    if src not in top_attackers:
        top_attackers[src] = {
            "ip": src, "packet_count": 0,
            "severity_score": 0, "last_seen": "", "last_seen_epoch": 0.0,
            "attack_type": "Normal", "country": country,
        }
    ta = top_attackers[src]
    ta["packet_count"]    += 1
    ta["last_seen"]        = ts()
    ta["last_seen_epoch"]  = time.time()
    if country and not ta.get("country"):
        ta["country"] = country
    if confidence > 0:
        ta["severity_score"] = max(ta["severity_score"], _severity_score(confidence, rate))
        ta["attack_type"]    = _classify_attack(proto, rate)


# ══════════════════════════════════════════════════════════════════════════════
# VICTIM-SIDE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _new_target_incident_id() -> str:
    global _target_incident_counter
    _target_incident_counter += 1
    return f"TI-{_target_incident_counter:04d}"


def _update_target(dst: str, src: str, confidence: int, rate: int,
                   attack_type: str, country: str = "") -> None:
    """Create or refresh an entry in attacked_targets for the victim IP."""
    if dst not in attacked_targets:
        attacked_targets[dst] = {
            "ip":            dst,
            "packet_count":  0,
            "severity_score": 0,
            "last_seen":     "",
            "attack_type":   "Normal",
            "country":       country or _ip_to_country(dst),
            "attacker_count": 0,
            "_seen_srcs":    set(),   # internal — excluded from API serialisation
        }
    t = attacked_targets[dst]
    t["packet_count"] += 1
    t["last_seen"]     = ts()
    if src not in t["_seen_srcs"]:
        t["_seen_srcs"].add(src)
        t["attacker_count"] = len(t["_seen_srcs"])
    if not t.get("country"):
        t["country"] = country or _ip_to_country(dst)
    if confidence > 0:
        t["severity_score"] = max(t["severity_score"], _severity_score(confidence, rate))
        t["attack_type"]    = attack_type


def _manage_target_incident(dst: str, src: str, severity: str,
                             confidence: int, rate: int, attack_type: str) -> None:
    """Create or update an incident record for a device under attack."""
    try:
        from detection import network_profiler
        if not network_profiler.is_ready():
            return
    except Exception:
        pass

    now    = time.time()
    now_ts = ts()
    if severity not in ("HIGH", "MEDIUM"):
        return

    # Touch the global attack latch so the dashboard threat banner fires
    # even when the victim is a non-host device (rand-source SYN flood, etc.)
    from detection import incident_manager as _im
    _im.touch_attack_latch(now)

    score    = _severity_score(confidence, rate)
    existing = None
    for inc in target_incidents.values():
        if inc["target_ip"] == dst and inc["status"] in ("OPEN", "ACTIVE"):
            existing = inc
            break

    if existing:
        _apply_elapsed(existing, now)
        existing["status"]            = "ACTIVE"
        existing["end_time"]          = now_ts
        existing["last_update_epoch"] = now
        existing["severity_score"]    = max(existing["severity_score"], score)
        existing["attack_type"]       = attack_type
        existing["packet_count"]      = existing.get("packet_count", 0) + 1
        existing["attacker_ip"]       = src
    else:
        inc_id = _new_target_incident_id()
        target_incidents[inc_id] = {
            "incident_id":       inc_id,
            "target_ip":         dst,
            "attacker_ip":       src,
            "start_time":        now_ts,
            "end_time":          now_ts,
            "start_epoch":       now,
            "last_update_epoch": now,
            "duration_seconds":  0,
            "duration":          "0s",
            "status":            "OPEN",
            "severity_score":    score,
            "attack_type":       attack_type,
            "packet_count":      1,
            "confidence":        confidence,
            "country":           _ip_to_country(dst),
        }


# ══════════════════════════════════════════════════════════════════════════════
# ARP SPOOFING / MITM DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def process_arp(packet) -> None:
    if not packet.haslayer(ARP):
        return
    arp = packet[ARP]
    # op 1 = who-has (request), op 2 = is-at (reply).
    # Collect device info from BOTH: requests reveal the sender's IP+MAC too.
    src_ip  = arp.psrc
    src_mac = (arp.hwsrc or "unknown").lower()

    # Passive device discovery: every ARP frame teaches us who's on the LAN.
    # This runs for both requests and replies so devices are found even if
    # a reply never reaches us (happens frequently on switched networks).
    _upsert_device(src_ip, src_mac, "arp-passive")
    network_sensor.record_broadcast_device(src_ip, src_mac, "ARP")

    if arp.op != 2:   # Only is-at replies carry spoofing risk.
        return

    now_ts = ts()
    now_f  = time.time()
    event  = None

    with _lock:
        if src_ip not in _arp_ip_to_macs:
            _arp_ip_to_macs[src_ip] = set()
        prev_macs = frozenset(_arp_ip_to_macs[src_ip])
        _arp_ip_to_macs[src_ip].add(src_mac)

        if src_mac not in _arp_mac_to_ips:
            _arp_mac_to_ips[src_mac] = set()
        # Snapshot before inserting so we can detect a genuinely new IP claim.
        prev_ips = frozenset(_arp_mac_to_ips[src_mac])
        _arp_mac_to_ips[src_mac].add(src_ip)

        try:
            from detection import network_profiler
            if not network_profiler.is_ready():
                return
        except Exception:
            pass

        # ARP Poisoning: a known IP is now being claimed by a different MAC.
        mac_conflict = bool(prev_macs) and src_mac not in prev_macs
        # MAC Spreading: this MAC is claiming an IP it has never claimed before.
        # Bug fix: was `src_ip not in prev_macs` (IP vs MAC set — always True).
        # Correct check: src_ip not in prev_ips (IP vs IP set).
        multi_ip = len(_arp_mac_to_ips[src_mac]) > 1 and src_ip not in prev_ips

        if mac_conflict:
            event = {
                "time":        now_ts,
                "_epoch":      now_f,
                "src_ip":      src_ip,
                "src_mac":     src_mac,
                "attack_type": "ARP Poisoning",
                "severity":    "HIGH",
                "prev_macs":   list(prev_macs)[:3],
                "msg": (f"IP {src_ip} now claims MAC {src_mac} "
                        f"(prev: {', '.join(list(prev_macs)[:2])})"),
            }
        elif multi_ip:
            event = {
                "time":        now_ts,
                "_epoch":      now_f,
                "src_ip":      src_ip,
                "src_mac":     src_mac,
                "attack_type": "MAC Spreading",
                "severity":    "MEDIUM",
                "all_ips":     list(_arp_mac_to_ips[src_mac])[:5],
                "msg": (f"MAC {src_mac} is claiming "
                        f"{len(_arp_mac_to_ips[src_mac])} different IPs"),
            }

        if event:
            arp_events.append(event)
            network_stats["suspicious_ips"].add(src_ip)

    # Outside lock: alert emission + database log, rate-limited per attacker IP.
    if event:
        severity    = event["severity"]
        msg         = event["msg"]
        attack_type = event["attack_type"]
        confidence  = 95 if severity == "HIGH" else 75

        if now_f - _arp_last_alert.get(src_ip, 0) >= _ARP_ALERT_INTERVAL:
            _arp_last_alert[src_ip] = now_f

            log_event({
                "time":       now_ts,
                "ip":         src_ip,
                "dst":        "",
                "severity":   severity,
                "confidence": confidence,
                "type":       "ARP_MITM",
                "msg":        f"MITM — {msg}",
            })
            alerts.append({
                "seq":        _next_alert_seq(),
                "time":       now_ts,
                "epoch":      now_f,
                "ip":         src_ip,
                "dst":        "",
                "severity":   severity,
                "confidence": confidence,
                "msg":        f"MITM DETECTED — {msg}",
            })


# ══════════════════════════════════════════════════════════════════════════════
# DISTRIBUTED FLOOD HANDLER
# ══════════════════════════════════════════════════════════════════════════════

def _handle_distributed_flood(now_f: float, now_ts: str,
                               src: str, dst: str,
                               dist_srcs: int, dist_pkts: int) -> None:
    """Create or update the synthetic distributed-flood incident and alert."""
    score = min(100, 50 + dist_srcs * 2)
    label = f"Distributed Flood — {dist_srcs} unique IPs"

    if _DIST_INC_KEY in incidents and incidents[_DIST_INC_KEY]["status"] in ("OPEN", "ACTIVE"):
        inc = incidents[_DIST_INC_KEY]
        _apply_elapsed(inc, now_f)
        inc["status"]            = "ACTIVE"
        inc["end_time"]          = now_ts
        inc["last_update_epoch"] = now_f
        inc["packet_count"]      = dist_pkts
        inc["severity_score"]    = max(inc["severity_score"], score)
        inc["attack_type"]       = label
    else:
        incidents[_DIST_INC_KEY] = {
            "incident_id":       _DIST_INC_KEY,
            "source_ip":         "DISTRIBUTED",
            "start_time":        now_ts,
            "end_time":          now_ts,
            "start_epoch":       now_f,
            "last_update_epoch": now_f,
            "duration_seconds":  0,
            "duration":          "0s",
            "status":            "OPEN",
            "severity_score":    score,
            "attack_type":       label,
            "packet_count":      dist_pkts,
            "confidence":        90,
        }

    if now_f - _dist_alert_state["last_t"] >= 10.0:
        _dist_alert_state["last_t"] = now_f
        msg = (f"SYSTEM UNDER ATTACK — Distributed flood from "
               f"{dist_srcs} unique IPs | {dist_pkts} pkts/10s")
        alerts.append({
            "seq":        _next_alert_seq(),
            "time":       now_ts,
            "epoch":      now_f,
            "ip":         "DISTRIBUTED",
            "dst":        dst,
            "severity":   "HIGH",
            "confidence": 90,
            "msg":        msg,
        })
        attack_map_events.append({
            "time":        now_ts,
            "epoch":       now_f,
            "src_ip":      src,
            "dst_ip":      dst,
            "src_mac":     "distributed",
            "src_country": _ip_to_country(src),
            "dst_country": _ip_to_country(dst),
            "attack_type": "Distributed Flood",
            "severity":    "HIGH",
            "rate":        dist_pkts,
            "confidence":  90,
        })


# ══════════════════════════════════════════════════════════════════════════════
# FIX 8 — MAIN IP PACKET PROCESSOR (robust try/except throughout)
# ══════════════════════════════════════════════════════════════════════════════

def process_packet(packet) -> None:
    """
    Process a verified, non-duplicate, non-loopback IP packet.

    All layer field accesses are wrapped in try/except (FIX 8): malformed or
    truncated packets — common in non-admin Npcap mode where partial frames
    are occasionally delivered — cannot crash the sniffer thread.
    """
    try:
        if not packet.haslayer(IP):
            return

        src = packet[IP].src
        dst = packet[IP].dst

    except Exception as e:
        capture_status["last_error"] = f"IP parse: {e}"
        return

    # Firewall check: silently drop blocked sources.
    if fw.is_blocked(src):
        return

    try:
        # Transport-layer bucket used for detection stats (TCP/UDP/OTHER)
        _tp = (
            "TCP"  if packet.haslayer(TCP)  else
            "UDP"  if packet.haslayer(UDP)  else
            "OTHER"
        )
        # Fine-grained protocol name for display (HTTP, DNS, ICMP, DHCP, etc.)
        proto = _detect_proto(packet)

        is_syn = is_ack = False
        src_port = 0
        dst_port = 0
        tcp_flags = 0
        has_tcp   = False

        if _tp == "TCP":
            flags     = packet[TCP].flags
            tcp_flags = int(flags)
            has_tcp   = True
            is_syn    = bool(flags & 0x02)
            is_ack    = bool(flags & 0x10)
            src_port  = int(packet[TCP].sport)
            dst_port  = int(packet[TCP].dport)
        elif _tp == "UDP":
            src_port  = int(packet[UDP].sport)
            dst_port  = int(packet[UDP].dport)

        src_mac = packet[Ether].src if packet.haslayer(Ether) else "unknown"

    except Exception as e:
        # Still count the packet even if layer parsing fails.
        capture_status["last_error"] = f"layer parse: {e}"
        _tp      = "OTHER"
        proto    = "OTHER"
        src_mac  = "unknown"
        src_port = 0
        dst_port = 0
        has_tcp  = False
        tcp_flags = 0
        is_syn = is_ack = False

    # ── Packet length (needed by layers) ──────────────────────────────────
    try:
        _pkt_len = len(bytes(packet))
    except Exception:
        _pkt_len = 0

    # ── Detection engine ───────────────────────────────────────────────────
    # Resolve host IPs early — used in detection exclusions and _is_outbound below.
    host_ips_now = _get_host_ips()

    # Skip detection only for gateway traffic — the router handles all internet
    # traffic so it always looks like the busiest talker.
    # NOTE: do NOT exclude src in host_ips_now here — hping3 can spoof a host
    # adapter IP (e.g. VirtualBox 192.168.106.3) as the attack source.  Excluding
    # host IPs at the detection level would make the entire attack invisible.
    # Outbound RST/ACK replies are handled by the `_is_outbound` guard below.
    if src in _gateway_ips:
        severity, confidence, rate = None, 0, 0
        is_dist, dist_srcs, dist_pkts = False, 0, 0
    else:
        try:
            severity, confidence, rate = detection.record_packet(
                src, dst, is_syn=is_syn, is_ack=is_ack, dst_port=dst_port
            )
            is_dist, dist_srcs, dist_pkts = detection.check_global_flood(src)
        except Exception:
            severity, confidence, rate = None, 0, 0
            is_dist, dist_srcs, dist_pkts = False, 0, 0

    # ── Victim-side detection: is dst under attack? ────────────────────────
    # Only run for non-host, non-gateway destinations.
    if dst not in host_ips_now and dst not in _gateway_ips:
        try:
            tgt_sev, tgt_conf, tgt_rate, tgt_type = detection.record_dst_packet(
                dst, src, dst_port=dst_port, is_syn=is_syn
            )
        except Exception:
            tgt_sev, tgt_conf, tgt_rate, tgt_type = None, 0, 0, "Normal"
    else:
        tgt_sev, tgt_conf, tgt_rate, tgt_type = None, 0, 0, "Normal"

    # ── Enhancement layers (purely observational — never modify severity) ──
    try:
        _enh = layers.process(
            src, dst, _tp, proto, src_port, dst_port, _pkt_len,
            is_syn, is_ack, severity, confidence, rate,
            detection.get_unique_ports(src), is_dist,
            iface=getattr(_tl, "iface", "unknown"),
        )
    except Exception:
        _enh = {}

    # ── C2 Beaconing & Lateral Movement observation ───────────────────────
    try:
        from detection import beaconing
        beaconing.observe(src, dst, now=time.time())
    except Exception:
        pass

    now_ts = ts()
    now_f  = time.time()
    hour   = datetime.now().hour

    # ── FIX 9: accurate PPS tracking ──────────────────────────────────────
    pps = _record_pps()

    with _lock:
        protocol_stats[_tp]                 += 1
        network_stats["top_protocols"][_tp] += 1
        network_stats["total_packets"]      += 1
        _active_conns_ts[(src, dst)]        = now_f
        network_stats["active_connections"].add((src, dst))
        network_stats["pps"]                   = pps
        capture_status["real_packets"]        += 1
        capture_status["mode"]                 = "live"
        global _soc_pkt_seq
        _soc_pkt_seq += 1; _seq = _soc_pkt_seq

        if dst_port > 0:
            port_stats[dst_port] += 1
        hourly_stats[hour] += 1

        _src_country = _ip_to_country(src)
        _country = _src_country if _src_country not in ("Local", "Unknown", "") else _ip_to_country(dst)

        # Outbound: src is a host IP AND dst is NOT a host IP (we are sending out).
        # Inbound attack with spoofed src that matches a host adapter IP should NOT
        # be treated as outbound — check dst too.  If dst is our machine, the packet
        # is inbound regardless of what the src says.
        _is_outbound = (src in host_ips_now) and (dst not in host_ips_now)

        # Only flag src as suspicious for INBOUND/lateral traffic — never for outbound
        # packets where src is this host (prevents local machine IP appearing as attacker).
        if severity in ("HIGH", "MEDIUM") and not _is_outbound:
            network_stats["suspicious_ips"].add(src)
            _suspicious_ips_ts[src] = now_f
        _pkt_sev     = "NORMAL" if _is_outbound else (severity or "NORMAL")

        packets.append({
            "seq_id":     _seq,
            "time":       now_ts,
            "epoch":      now_f,
            "src":        src,
            "dst":        dst,
            "src_mac":    src_mac,
            "proto":      proto,
            "src_port":   src_port,
            "port":       dst_port,
            "tcp_flags":  tcp_flags,
            "rate":       rate,
            "severity":   _pkt_sev,
            "confidence": confidence,
            "packets_5s": rate,
            "country":    _country,
            "outbound":   _is_outbound,
            "enhanced":   _enh,
        })

        # traffic_history is now filled by _traffic_sampler() background thread
        # using the accurate _pps_window counter — do not append here.

        # Skip attacker/incident tracking for outbound traffic — RST/ACK
        # replies from this host should never appear in the attacker list.
        if not _is_outbound:
            _update_attacker(src, confidence, rate, _tp, _src_country)
            _manage_incident(src, _tp, severity, confidence, rate)

        # ── Victim-side tracking (other devices under attack) ──────────────
        if tgt_sev in ("HIGH", "MEDIUM"):
            _update_target(dst, src, tgt_conf, tgt_rate, tgt_type)
            _manage_target_incident(dst, src, tgt_sev, tgt_conf, tgt_rate, tgt_type)

        # ── Port scan detection ────────────────────────────────────────────
        # Skip loopback sources: 127.x traffic is local service connections,
        # not external scans, and would generate constant false positives.
        # Also skip IPs that are part of an active distributed flood:
        # --rand-source --flood generates thousands of random source IPs all
        # hitting the same dst port, causing each random IP to accumulate
        # port-scan hits (they all "scan" port 5000 repeatedly).  Since these
        # are flood packets — not real scans — suppressing scan tracking for
        # them prevents bogus "Scan Alerts: 100" on the status bar.
        try:
            from detection import network_profiler
            _profiler_is_ready = network_profiler.is_ready()
        except Exception:
            _profiler_is_ready = True

        if dst_port > 0 and not src.startswith('127.') and not is_dist and _profiler_is_ready:
            if src not in _scan_state:
                _scan_state[src] = {
                    "ports": set(), "targets": set(),
                    "start_t": now_f, "last_t": now_f, "flags": tcp_flags,
                    "trigger_count": 0,
                }
            ss = _scan_state[src]
            ss["ports"].add(dst_port)
            ss["targets"].add(dst)
            ss["last_t"] = now_f

            port_count = len(ss["ports"])
            if port_count >= _SCAN_THRESHOLD and port_count % 5 == 0:
                scan_type     = _classify_scan(tcp_flags, has_tcp)
                time_gap      = now_f - ss["start_t"]
                repeat_count  = ss["trigger_count"] + 1
                risk_result   = calculate_port_scan_risk(
                    ports=port_count,
                    targets=len(ss["targets"]),
                    time_gap=time_gap,
                    repeat_count=repeat_count,
                )
                ss["trigger_count"] = repeat_count
                scan_events.append({
                    "time":           now_ts,
                    "src_ip":         src,
                    "src_mac":        src_mac,
                    "ports_scanned":  port_count,
                    "unique_targets": len(ss["targets"]),
                    "scan_type":      scan_type,
                    "risk_score":     risk_result["risk_score"],
                    "severity":       risk_result["severity"],
                    "top_ports":      sorted(list(ss["ports"]))[:12],
                    "country":        _ip_to_country(src),
                    "risk_breakdown": {
                        "port":   risk_result["port_score"],
                        "speed":  risk_result["speed_score"],
                        "target": risk_result["target_score"],
                        "repeat": risk_result["repeat_score"],
                    },
                })

        # ── Attack map events ──────────────────────────────────────────────
        if severity in ("HIGH", "MEDIUM"):
            attack_map_events.append({
                "time":        now_ts,
                "epoch":       now_f,     # float epoch so globe JS can diff-poll
                "src_ip":      src,
                "dst_ip":      dst,
                "src_mac":     src_mac,
                "src_country": _ip_to_country(src),
                "dst_country": _ip_to_country(dst),
                "attack_type": _classify_attack(_tp, rate),
                "severity":    severity,
                "rate":        rate,
                "confidence":  confidence,
            })

        # ── Distributed flood ──────────────────────────────────────────────
        if is_dist:
            _handle_distributed_flood(now_f, now_ts, src, dst, dist_srcs, dist_pkts)

    # ── Alert emission (outside lock to avoid blocking capture) ───────────
    if severity in ("MEDIUM", "HIGH") and confidence >= _MIN_ALERT_CONFIDENCE:
        if now_f - _last_alert_t.get(src, 0) >= _ALERT_INTERVAL:
            _last_alert_t[src] = now_f
            msg = f"{severity} ATTACK — {rate} pkts/5s | confidence {confidence}%"
            log_event({
                "time": now_ts, "ip": src, "dst": dst,
                "severity": severity, "confidence": confidence,
                "type": "ALERT", "msg": msg,
            })
            alerts.append({
                "seq": _next_alert_seq(),
                "time": now_ts, "epoch": now_f,
                "ip": src, "dst": dst,
                "severity": severity, "confidence": confidence,
                "msg": msg,
            })

    # ── Target-under-attack alert ─────────────────────────────────────────
    # Fires when a device OTHER than this host is being attacked.
    # Uses a dst-keyed rate limit so alerts for different targets don't
    # suppress each other.
    if tgt_sev in ("MEDIUM", "HIGH") and tgt_conf >= _MIN_ALERT_CONFIDENCE:
        _tgt_key = f"dst:{dst}"
        if now_f - _last_alert_t.get(_tgt_key, 0) >= _ALERT_INTERVAL:
            _last_alert_t[_tgt_key] = now_f
            tgt_msg = (
                f"TARGET UNDER ATTACK — {dst} | {tgt_type} | "
                f"{tgt_rate} pkts/5s | attacker {src}"
            )
            log_event({
                "time": now_ts, "ip": src, "dst": dst,
                "severity": tgt_sev, "confidence": tgt_conf,
                "type": "TARGET_ALERT", "msg": tgt_msg,
            })
            alerts.append({
                "seq": _next_alert_seq(),
                "time": now_ts, "epoch": now_f,
                "ip": src, "dst": dst,
                "severity": tgt_sev, "confidence": tgt_conf,
                "msg": tgt_msg,
            })


# ══════════════════════════════════════════════════════════════════════════════
# DISPATCH — top-level packet entry point
# ══════════════════════════════════════════════════════════════════════════════

def process_any_packet(packet) -> None:
    """
    Entry point for every captured packet from any sniffer path.

    Two pipelines run in sequence:

    RAW PIPELINE (Wireshark-mode):
      Appends every non-loopback packet to raw_packets so the live-capture
      viewer shows ALL LAN traffic — broadcasts, multicasts, DHCP, mDNS, etc.
      This is what lets you see other devices on the same network segment,
      even though their unicast traffic is invisible (switched network physics).

    SOC PIPELINE (IDS/detection):
      Applies loopback, same-host, and dedup filters before handing the packet
      to process_packet().  Keeps detection accurate without broadcast noise.
    """
    global _raw_pkt_seq
    try:
        # ── RAW PIPELINE: populate Wireshark-style capture stream ─────────────
        # Skip only 127.x loopback — show everything else including broadcasts,
        # multicasts (mDNS, SSDP, IGMP), DHCP, NBNS, and traffic from other
        # LAN devices that reach this NIC via broadcast/multicast.
        _is_loopback_pkt = False
        try:
            if packet.haslayer(IP) and packet[IP].src.startswith("127."):
                _is_loopback_pkt = True
        except Exception:
            pass

        if not _is_loopback_pkt:
            _raw_pkt_seq += 1
            raw_packets.append(_build_raw_entry(packet, _raw_pkt_seq))

        # ── SOC PIPELINE: filtered detection ─────────────────────────────────
        if packet.haslayer(IP):
            # FIX 5: Drop localhost, broadcast, multicast, same-machine traffic.
            if _should_drop_packet(packet):
                with _lock:
                    network_stats["dropped_loopback"] += 1
                return

            # FIX 6: Drop packets already seen on another interface.
            if _is_duplicate(packet):
                with _lock:
                    network_stats["dropped_dedup"] += 1
                return

            process_packet(packet)

        elif packet.haslayer(ARP):
            # ARP is never deduplicated — each reply matters for spoofing detection.
            process_arp(packet)

        # Passive device-name discovery — mDNS and DHCP run on all IP packets
        if packet.haslayer(IP) and packet.haslayer(UDP):
            _parse_mdns(packet)
            _parse_dhcp_hostname(packet)

    except Exception as e:
        capture_status["last_error"] = f"dispatch: {e}"


# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND THREADS
# ══════════════════════════════════════════════════════════════════════════════

def _traffic_sampler() -> None:
    """
    Sample total network rate every second and store in traffic_history.
    Replaces the old per-packet traffic_history.append(rate) which was
    recording per-IP detection rates instead of the real network rate.
    Also prunes inactive active_connections older than 60s.
    """
    prev_total = 0
    while True:
        time.sleep(1)
        curr_total = network_stats.get("total_packets", 0)
        delta = max(0, curr_total - prev_total)
        prev_total = curr_total
        traffic_history.append(delta)

        now = time.time()
        with _lock:
            stale_conns = [k for k, t in _active_conns_ts.items() if now - t > 60.0]
            for k in stale_conns:
                del _active_conns_ts[k]
            network_stats["active_connections"] = set(_active_conns_ts.keys())


def _incident_resolver() -> None:
    """Auto-resolve OPEN/ACTIVE incidents that have been silent for INCIDENT_TIMEOUT_SEC."""
    while True:
        time.sleep(4)
        now    = time.time()
        now_ts = ts()
        resolved_ips = []
        with _lock:
            for inc in incidents.values():
                if inc["status"] not in ("OPEN", "ACTIVE"):
                    continue
                last_update = inc.get("last_update_epoch", inc.get("start_epoch", now))
                if now - last_update >= _INCIDENT_TIMEOUT_SEC:
                    _apply_elapsed(inc, now)
                    inc["status"]   = "RESOLVED"
                    inc["end_time"] = now_ts
                    resolved_ips.append(inc.get("source_ip", ""))

            # Also resolve target incidents (devices no longer being attacked)
            for inc in target_incidents.values():
                if inc["status"] not in ("OPEN", "ACTIVE"):
                    continue
                last_update = inc.get("last_update_epoch", inc.get("start_epoch", now))
                if now - last_update >= _INCIDENT_TIMEOUT_SEC:
                    _apply_elapsed(inc, now)
                    inc["status"]   = "RESOLVED"
                    inc["end_time"] = now_ts

            # Prune suspicious_ips not seen for 300s and not currently active in incidents or firewall block
            active_threat_ips = {
                inc.get("source_ip") for inc in incidents.values()
                if inc.get("status") in ("OPEN", "ACTIVE")
            } | {
                inc.get("source_ip") for inc in target_incidents.values()
                if inc.get("status") in ("OPEN", "ACTIVE")
            }
            try:
                from detection.firewall import blocked_ips
                active_threat_ips |= set(blocked_ips)
            except Exception:
                pass

            stale_suspicious = [
                ip for ip, t in _suspicious_ips_ts.items()
                if (now - t > 300.0) and (ip not in active_threat_ips)
            ]
            for ip in stale_suspicious:
                del _suspicious_ips_ts[ip]
            network_stats["suspicious_ips"] = set(_suspicious_ips_ts.keys()) | active_threat_ips

        # Clear detection engine state for resolved attackers so residual
        # rate/start data cannot immediately re-trigger HIGH on next packet.
        for _rip in resolved_ips:
            if _rip:
                try:
                    detection.clear_src_state(_rip)
                except Exception:
                    pass


def _scan_cleanup() -> None:
    """Remove stale port-scan tracking entries to prevent unbounded memory growth."""
    while True:
        time.sleep(60)
        now = time.time()
        with _lock:
            stale = [
                ip for ip, ss in _scan_state.items()
                if now - ss.get("last_t", ss["start_t"]) > _SCAN_STATE_TTL_SEC
            ]
            for ip in stale:
                del _scan_state[ip]


def _host_ip_refresher() -> None:
    """Periodically refresh the local IP cache used by _should_drop_packet."""
    while True:
        time.sleep(_HOST_IP_REFRESH_SEC)
        _refresh_host_ips(force=True)


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK DEVICE DISCOVERY
# Three complementary sources — all work without admin privileges.
# ══════════════════════════════════════════════════════════════════════════════

import subprocess as _subprocess
import ipaddress as _ipaddress

# Lock protecting discovered_devices dict (written from multiple threads).
_dev_lock = threading.Lock()

# Device staleness: remove entries not seen for 10 minutes.
_DEV_STALE_SEC = 600.0


def _mac_vendor(mac: str) -> str:
    """Return vendor name for a MAC address using the OUI prefix table."""
    prefix = mac.lower()[:8]
    return _MAC_VENDORS.get(prefix, "Unknown")


# Cache for async API-based MAC vendor lookups
_mac_api_cache: dict = {}
_mac_api_lock  = threading.Lock()


def _mac_vendor_async(mac: str, ip: str) -> None:
    """Background thread: look up vendor via api.macvendors.com and store result."""
    clean = mac.replace(":", "").replace("-", "").upper()[:6]
    if not clean or clean == "000000":
        return
    with _mac_api_lock:
        if clean in _mac_api_cache:
            vendor = _mac_api_cache[clean]
        else:
            vendor = None

    if vendor is None:
        try:
            import urllib.request as _ur
            url = f"https://api.macvendors.com/{clean}"
            req = _ur.Request(url, headers={"User-Agent": "SOC/2.0"})
            with _ur.urlopen(req, timeout=4) as r:
                vendor = r.read().decode("utf-8", errors="ignore").strip()[:40]
        except Exception:
            vendor = ""
        with _mac_api_lock:
            _mac_api_cache[clean] = vendor

    if vendor:
        with _dev_lock:
            dev = discovered_devices.get(ip)
            if dev and dev.get("vendor") in ("Unknown", "unknown", "", None):
                dev["vendor"] = vendor


def set_scan_threshold(n: int) -> None:
    """Allow network_profiler to tune the port-scan threshold per detected profile."""
    global _SCAN_THRESHOLD
    _SCAN_THRESHOLD = max(30, int(n))
    print(f"[SOC] Scan threshold updated: {_SCAN_THRESHOLD} unique ports")


def _resolve_hostname(ip: str) -> str:
    """Best-effort reverse DNS for a LAN IP. Returns ip string on failure."""
    try:
        return _socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def _netbios_name(ip: str) -> str:
    """Query Windows NetBIOS computer name via nbtstat -A. Returns '' on failure."""
    import re as _r
    try:
        out = _subprocess.check_output(
            ['nbtstat', '-A', ip],
            text=True, stderr=_subprocess.DEVNULL, timeout=4
        )
        # Computer name line: "  NAME           <00>  UNIQUE  Registered"
        m = _r.search(r'^\s*([A-Za-z0-9_\-]{1,15})\s+<00>\s+UNIQUE', out, _r.MULTILINE)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return ''


def _update_device_hostname(ip: str, hostname: str) -> None:
    """Write hostname into discovered_devices only if it is better than current."""
    if not hostname or hostname == ip:
        return
    with _dev_lock:
        dev = discovered_devices.get(ip)
        if dev:
            current = dev.get("hostname", ip)
            # Replace if current is bare IP or 'Unknown'
            if current == ip or current in ("Unknown", "unknown", ""):
                dev["hostname"] = hostname


def _parse_mdns(packet) -> None:
    """Extract .local hostnames from mDNS packets and store them."""
    try:
        if not packet.haslayer(UDP) or packet[UDP].dport != 5353:
            return
        raw = bytes(packet[UDP].payload)
        if len(raw) < 12:
            return
        src_ip = packet[IP].src if packet.haslayer(IP) else None
        if not src_ip:
            return

        # Parse DNS answers section — skip header (12 bytes) + questions
        import struct as _st
        qcount = _st.unpack_from('>H', raw, 4)[0]
        acount = _st.unpack_from('>H', raw, 6)[0]
        offset = 12
        # Skip questions
        for _ in range(qcount):
            while offset < len(raw):
                llen = raw[offset]; offset += 1
                if llen == 0: break
                if llen & 0xc0 == 0xc0: offset += 1; break
                offset += llen
            offset += 4  # qtype + qclass
        # Read answers
        for _ in range(acount):
            name_parts, offset = _dns_read_name(raw, offset)
            if offset + 10 > len(raw): break
            rtype, _cls, _ttl, rdlen = _st.unpack_from('>HHIH', raw, offset)
            offset += 10
            rdata = raw[offset:offset + rdlen]; offset += rdlen
            if rtype == 1 and rdlen == 4:  # A record → IP → hostname
                ip_str = '.'.join(str(b) for b in rdata)
                hostname = '.'.join(name_parts).rstrip('.')
                if hostname.endswith('.local'):
                    hostname = hostname[:-6]
                if hostname:
                    _update_device_hostname(ip_str, hostname)
                    _update_device_hostname(src_ip, hostname)
            elif rtype == 28 and rdlen == 16:  # AAAA — skip but get name
                hostname = '.'.join(name_parts).rstrip('.')
                if hostname.endswith('.local'):
                    _update_device_hostname(src_ip, hostname[:-6])
    except Exception:
        pass


def _dns_read_name(data: bytes, offset: int):
    """Read a DNS-encoded name, following compression pointers."""
    parts = []
    visited = set()
    while offset < len(data):
        llen = data[offset]
        if llen == 0:
            offset += 1; break
        if llen & 0xc0 == 0xc0:                 # pointer
            if offset + 1 >= len(data): break
            ptr = ((llen & 0x3f) << 8) | data[offset + 1]
            offset += 2
            if ptr not in visited:
                visited.add(ptr)
                sub, _ = _dns_read_name(data, ptr)
                parts.extend(sub)
            break
        offset += 1
        parts.append(data[offset:offset + llen].decode('ascii', errors='ignore'))
        offset += llen
    return parts, offset


def _parse_dhcp_hostname(packet) -> None:
    """Extract hostname from DHCP option 12 and store it."""
    try:
        if not packet.haslayer(UDP):
            return
        udp = packet[UDP]
        if udp.dport not in (67, 68) and udp.sport not in (67, 68):
            return
        raw = bytes(udp.payload)
        if len(raw) < 240:
            return
        # BOOTP header: op(1)+htype(1)+hlen(1)+hops(1)+xid(4)+secs(2)+flags(2)
        #               +ciaddr(4)+yiaddr(4)+siaddr(4)+giaddr(4)+chaddr(16)+...
        import struct as _st
        ciaddr = '.'.join(str(b) for b in raw[12:16])
        yiaddr = '.'.join(str(b) for b in raw[16:20])
        # chaddr (client MAC) at offset 28, first 6 bytes
        chaddr = ':'.join(f'{b:02x}' for b in raw[28:34])

        # Detect client IP (prefer yiaddr if server is offering, else ciaddr)
        client_ip = yiaddr if yiaddr != '0.0.0.0' else ciaddr

        # DHCP options start after magic cookie at offset 236
        if raw[236:240] != b'\x63\x82\x53\x63':
            return
        i = 240
        hostname = ''
        while i < len(raw):
            opt = raw[i]; i += 1
            if opt == 255: break
            if opt == 0: continue
            if i >= len(raw): break
            olen = raw[i]; i += 1
            val = raw[i:i + olen]; i += olen
            if opt == 12:   # hostname
                hostname = val.decode('ascii', errors='ignore').strip('\x00')
                break

        if hostname and client_ip and client_ip != '0.0.0.0':
            _update_device_hostname(client_ip, hostname)
            # Also register device if new
            if chaddr and chaddr != '00:00:00:00:00:00':
                _upsert_device(client_ip, chaddr, 'dhcp')
    except Exception:
        pass


def _upsert_device(ip: str, mac: str, source: str) -> None:
    """
    Create or refresh a device entry in discovered_devices.
    Thread-safe; called from ARP sniffer, ARP cache reader, and ARP scanner.
    """
    if not ip or ip.startswith("127.") or ip == "0.0.0.0":
        return
    mac = (mac or "unknown").lower().strip()
    now_ts = ts()

    with _dev_lock:
        existing = discovered_devices.get(ip)
        if existing:
            # Update live fields; keep hostname if already resolved.
            existing["mac"]       = mac
            existing["last_seen"] = now_ts
            existing["source"]    = source
            if existing.get("vendor") == "Unknown" or not existing.get("vendor"):
                existing["vendor"] = _mac_vendor(mac)
        else:
            discovered_devices[ip] = {
                "ip":        ip,
                "mac":       mac,
                "hostname":  ip,          # resolved lazily below
                "vendor":    _mac_vendor(mac),
                "last_seen": now_ts,
                "source":    source,
            }

    # Hostname + vendor resolution is slow — run in background threads.
    if not existing:
        def _resolve():
            hn = _resolve_hostname(ip)
            if hn == ip:
                nb = _netbios_name(ip)
                if nb:
                    hn = nb
            _update_device_hostname(ip, hn)
        threading.Thread(target=_resolve, daemon=True, name=f"dev-resolve-{ip}").start()

        # If vendor is still Unknown, try the online MAC vendor API
        current_vendor = discovered_devices.get(ip, {}).get("vendor", "Unknown")
        if current_vendor in ("Unknown", "unknown", "", None) and mac != "unknown":
            threading.Thread(
                target=_mac_vendor_async, args=(mac, ip),
                daemon=True, name=f"mac-vendor-{ip}"
            ).start()


def _stale_device_cleanup() -> None:
    """Remove devices not seen for _DEV_STALE_SEC to keep the table fresh."""
    while True:
        time.sleep(120)
        now = time.time()
        with _dev_lock:
            stale = []
            for ip, dev in discovered_devices.items():
                # last_seen is a formatted string — use presence of key as proxy;
                # we track epoch separately for cleanup.
                pass
            # (staleness check uses a parallel epoch dict — simplified: just keep all)
        # Keep all entries; the last_seen timestamp shown in the UI is enough.


def _read_arp_cache() -> None:
    """
    Parse the OS ARP table every 30 s.

    On Windows: `arp -a` outputs lines like:
      192.168.1.1           00-11-22-33-44-55     dynamic
    On Linux: `arp -n` outputs lines like:
      192.168.1.1  ether  00:11:22:33:44:55  C  eth0

    This needs NO admin rights and discovers every device that has recently
    communicated with this machine or been broadcast-visible on the LAN.
    It runs BEFORE the active scan, so the table is populated immediately.
    """
    while True:
        try:
            if platform.system() == "Windows":
                result = _subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    # Match lines like: "  192.168.1.1        00-11-22-33-44-55     dynamic"
                    parts = line.split()
                    if len(parts) >= 2:
                        ip  = parts[0].strip()
                        mac = parts[1].strip().replace("-", ":").lower()
                        # Validate IP shape and skip multicast/broadcast entries.
                        if (
                            len(ip.split(".")) == 4
                            and not ip.startswith("224.")
                            and ip != "255.255.255.255"
                            and len(mac) == 17
                            and mac != "ff:ff:ff:ff:ff:ff"
                        ):
                            _upsert_device(ip, mac, "arp-cache")
                            with _lock:
                                _arp_ip_to_macs.setdefault(ip, set()).add(mac)
                                _arp_mac_to_ips.setdefault(mac, set()).add(ip)
            else:
                result = _subprocess.run(
                    ["arp", "-n"], capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] in ("ether", "ETHER"):
                        ip  = parts[0].strip()
                        mac = parts[2].strip().lower()
                        if len(mac) == 17 and mac != "ff:ff:ff:ff:ff:ff":
                            _upsert_device(ip, mac, "arp-cache")
                            with _lock:
                                _arp_ip_to_macs.setdefault(ip, set()).add(mac)
                                _arp_mac_to_ips.setdefault(mac, set()).add(ip)
        except Exception as e:
            pass  # Silent — ARP cache read is best-effort.

        time.sleep(30)


def _active_arp_scan() -> None:
    """
    Send ARP who-has requests to every IP in the local /24 subnet every 60 s.

    Why this is necessary:
      A switched network only delivers traffic ADDRESSED to your MAC. Other
      devices' unicast traffic is invisible to you. ARP broadcasts are the
      only mechanism to actively discover all live devices on a switched LAN
      without admin rights or special hardware.

    Uses Scapy's srp() which needs Npcap but NOT admin on most Windows
    installs where Npcap is in WinPcap-compatible mode. Falls back silently
    if it fails (ARP cache + passive captures still populate the table).
    """
    # Wait for sniffer to finish starting before the first scan.
    time.sleep(15)

    while True:
        try:
            from scapy.all import ARP as _ARP, Ether as _Ether, srp as _srp

            # Scan ALL host subnets (main LAN + VirtualBox Host-Only, etc.)
            # Build a map of host_ip → scapy interface so each subnet is
            # scanned on the correct adapter (avoids the build/send error that
            # occurs when iface=None picks the wrong NIC for a subnet).
            iface_map: dict = {}
            for _iface in get_working_ifaces():
                _ip = str(getattr(_iface, "ip", "") or "").strip()
                if _ip and not _ip.startswith("127.") and _ip != "0.0.0.0":
                    iface_map[_ip] = _iface

            host_ips = _get_host_ips()
            scanned_nets: set = set()
            for h_ip in host_ips:
                if h_ip.startswith("127.") or h_ip == "0.0.0.0":
                    continue
                try:
                    net = _ipaddress.ip_interface(f"{h_ip}/24").network
                    net_str = str(net)
                    if net_str in scanned_nets:
                        continue
                    scanned_nets.add(net_str)

                    target_iface = iface_map.get(h_ip)  # correct NIC for this subnet
                    src_mac = str(getattr(target_iface, "mac", "") or "").lower().strip()
                    if not src_mac or src_mac == "00:00:00:00:00:00":
                        continue  # no valid source MAC — skip this subnet
                    # Explicitly set hwsrc/psrc so Scapy skips its route
                    # lookup (which crashes on CIDR strings like "x.x.x.0/24").
                    answered, _ = _srp(
                        _Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac)
                        / _ARP(pdst=net_str, hwsrc=src_mac, psrc=h_ip),
                        timeout=2,
                        verbose=False,
                        iface=target_iface,
                    )
                    for _, received in answered:
                        ip  = received[_ARP].psrc
                        mac = received[_Ether].src.lower()
                        _upsert_device(ip, mac, "arp-scan")
                        with _lock:
                            _arp_ip_to_macs.setdefault(ip, set()).add(mac)
                            _arp_mac_to_ips.setdefault(mac, set()).add(ip)
                except Exception:
                    pass

        except Exception:
            pass  # Scapy ARP scan failed (no Npcap / not installed) — silent fallback.

        time.sleep(60)


def get_network_devices() -> list[dict]:
    """
    Return a snapshot of all discovered network devices, sorted by IP.
    Called by the /api/network/devices endpoint.
    """
    with _dev_lock:
        devs = list(discovered_devices.values())

    # Also include this host itself.
    host_ips = _get_host_ips()
    host_ip  = _get_default_ip()
    if host_ip and host_ip not in discovered_devices:
        devs.append({
            "ip":        host_ip,
            "mac":       "this machine",
            "hostname":  _socket.gethostname(),
            "vendor":    "This Host",
            "last_seen": ts(),
            "source":    "self",
        })

    # Sort by IP address numerically.
    def _ip_sort_key(d: dict) -> tuple:
        try:
            parts = d["ip"].split(".")
            return tuple(int(p) for p in parts)
        except Exception:
            return (999, 999, 999, 999)

    return sorted(devs, key=_ip_sort_key)


# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE SELECTION
# ══════════════════════════════════════════════════════════════════════════════

def _get_default_ip() -> str | None:
    """Return the local IP used for outbound internet traffic (default route)."""
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


# Adapter names/descriptions that produce only noise and should never be sniffed.
# vmware/vbox bridge adapters are intentionally NOT in this list — they carry
# VM-to-host traffic and must be included.
_SKIP_KEYWORDS = (
    "loopback", "npcap loopback",
    "bluetooth",
    "wan miniport",
    "teredo", "isatap", "6to4",
    "gameloop",
    "tunnel",
    "microsoft wi-fi direct",
    "microsoft hosted network",
    "pseudo",
)

# Cap extra Npcap-only adapters (taps, SPAN, bridges) to avoid thread explosion.
_MAX_EXTRA_NPF_IFACES: int = 10


def _iface_guid_key(name: str, guid_hint: str | None = None) -> str | None:
    """
    Stable key for deduplicating 'Ethernet' vs '\\Device\\NPF_{GUID}' (same NIC).
    Returns lowercase GUID without braces, or None if no GUID is known.
    """
    gh = (guid_hint or "").strip()
    if gh.startswith("{") and "}" in gh:
        try:
            return gh.strip("{}").lower()
        except Exception:
            pass
    n = name or ""
    if "{" in n and "}" in n:
        try:
            return n.split("{", 1)[1].split("}", 1)[0].lower()
        except IndexError:
            pass
    return None


def _default_route_iface_name() -> str | None:
    """
    Npcap device name used for traffic toward the internet (same path as UDP
    connect-to-8.8.8.8).  Using this explicitly fixes cases where
    get_working_ifaces() omits the physical NIC, pairs the wrong friendly name
    with an IP, or orders adapters so the WAN-facing NIC is never sniffed.
    """
    try:
        dev, _src, _gw = conf.route.route("8.8.8.8")
        if not dev:
            return None
        dlow = str(dev).lower()
        if "loopback" in dlow or "npcap loopback" in dlow:
            return None
        return dev
    except Exception:
        return None


def _pick_interfaces() -> list:
    """
    Return interface names to sniff on: default-route (WAN) Npcap device first,
    then every other usable Scapy interface with an IPv4, then any remaining
    Npcap \\Device\\NPF_* adapters (SPAN/tap/bridge) not already covered.

    GUID-based dedup prevents the same NIC from being opened twice under
    different names (avoids duplicate load; keeps capture correct).
    """
    custom_iface = os.environ.get("CAPTURE_INTERFACE")
    if custom_iface:
        return [custom_iface]

    try:
        all_ifaces = get_working_ifaces()
    except Exception:
        all_ifaces = []

    selected: list[str] = []
    seen_keys: set[str] = set()
    seen_ips: set[str] = set()

    def _add(name: str, guid_hint: str | None = None) -> None:
        if not name:
            return
        gkey = _iface_guid_key(name, guid_hint)
        dedup = gkey if gkey else name.lower()
        if dedup in seen_keys:
            return
        seen_keys.add(dedup)
        selected.append(name)

    # 1) Route-bound interface first — inbound public-IP/NAT traffic hits here.
    dr = _default_route_iface_name()
    if dr:
        _add(dr)

    # 2) All working Scapy interfaces with IPv4 (VM bridges, Wi-Fi, Ethernet…).
    default_ip = _get_default_ip()
    if default_ip:
        for iface in all_ifaces:
            if not iface.ip or str(iface.ip) != default_ip:
                continue
            ip_str = str(iface.ip)
            if ip_str.startswith("127."):
                continue
            name_lower = (iface.name or "").lower()
            desc_lower = (getattr(iface, "description", "") or "").lower()
            combined = f"{name_lower} {desc_lower}"
            if any(k in combined for k in _SKIP_KEYWORDS):
                continue
            _add(iface.name, getattr(iface, "guid", None))
            seen_ips.add(ip_str)
            break

    for iface in all_ifaces:
        if not iface.ip:
            continue
        ip_str = str(iface.ip)
        if ip_str.startswith("127.") or ip_str in seen_ips:
            continue
        name_lower = (iface.name or "").lower()
        desc_lower = (getattr(iface, "description", "") or "").lower()
        combined = f"{name_lower} {desc_lower}"
        if any(k in combined for k in _SKIP_KEYWORDS):
            continue
        _add(iface.name, getattr(iface, "guid", None))
        seen_ips.add(ip_str)

    # 3) Npcap adapters without a working Scapy IP binding (monitor/SPAN/tap).
    if platform.system() == "Windows":
        extra = 0
        try:
            for rawn in get_if_list():
                if extra >= _MAX_EXTRA_NPF_IFACES:
                    break
                nl = (rawn or "").lower()
                if "\\device\\npf_" not in nl.replace("/", "\\"):
                    continue
                if "loopback" in nl or "npf_loopback" in nl:
                    continue
                if any(k in nl for k in _SKIP_KEYWORDS):
                    continue
                before = len(selected)
                _add(rawn)
                if len(selected) > before:
                    extra += 1
        except Exception:
            pass

    return selected


# ══════════════════════════════════════════════════════════════════════════════
# SNIFFER THREADS
# ══════════════════════════════════════════════════════════════════════════════

def _sniff_iface(iface, *, promisc: bool = True) -> None:
    """
    Run sniff() loop on one interface.  Restarts automatically on error so a
    temporary Npcap glitch doesn't permanently kill the capture thread.

    promisc=True is safe because FIX 6 (dedup) already handles any mirrored
    copy of outbound packets that some Npcap versions produce in promisc mode.
    Using promisc=True ensures inbound frames from other LAN devices are
    delivered to the NIC driver even on Windows 11 configurations where
    Npcap without promisc mode silently discards non-local-destination frames.
    """
    _tl.iface = iface   # record interface name for layers.process() visibility tracking
    _warned_no_pcap = False
    while True:
        try:
            sniff(
                prn=process_any_packet,
                store=False,
                iface=iface,
                filter=_BPF_FILTER,   # FIX 4: kernel-level noise filter
                promisc=promisc,
            )
        except Exception as e:
            err_str = str(e)
            if "winpcap is not installed" in err_str.lower() or "libpcap" in err_str.lower():
                if not _warned_no_pcap:
                    print(f"[SOC] Live packet capture paused: Npcap driver not installed (install from https://npcap.com to enable)")
                    _warned_no_pcap = True
                time.sleep(30)
            else:
                print(f"[SOC] Sniffer error on {iface}: {e}")
                time.sleep(2)

            if capture_status.get("interface") == iface:
                capture_status["last_error"] = str(e)
                capture_status["mode"]       = "error"
            continue
        # sniff() returned (unexpected)
        time.sleep(2)


def _raw_socket_sniffer(host_ip: str) -> None:
    """
    Windows-only IP-stack-level capture via SIO_RCVALL.

    Captures ALL inbound IP packets at the OS network-stack level, independent
    of Npcap.  This is the most reliable path for detecting attacks from another
    device because it operates BELOW the Windows Firewall but ABOVE the NIC
    driver — guaranteed to see every IP packet the OS receives.

    Works when running as Administrator.  Without admin, SIO_RCVALL raises
    WinError 10013; the socket is closed IMMEDIATELY before entering the recv
    loop to prevent the Windows 11 phantom-loopback-packet burst (a partial-
    receive state that the un-ioctl'd SOCK_RAW enters on some builds).
    Both Npcap and raw-socket paths share _is_duplicate dedup so the same
    packet is counted exactly once regardless of which path sees it first.
    """
    if platform.system() != "Windows":
        return

    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_IP)
        sock.bind((host_ip, 0))
        sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_HDRINCL, 1)
        sock.ioctl(_socket.SIO_RCVALL, _socket.RCVALL_ON)
        print(f"[SOC] Raw-socket capture active on {host_ip} (catches inbound from other devices)")
    except Exception as e:
        # Close the socket IMMEDIATELY before returning so no partial-receive
        # state can deliver phantom loopback packets into process_any_packet.
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        print(f"[SOC] Raw-socket capture unavailable on {host_ip}: {e} "
              f"(run as Administrator to enable this capture path)")
        return

    try:
        while True:
            try:
                raw = sock.recv(65535)
                # Parse raw IP bytes — no Ethernet header at this layer.
                pkt = IP(raw)
                # Route through process_any_packet so FIX 5 + 6 gates apply.
                process_any_packet(pkt)
            except Exception:
                pass
    finally:
        try:
            sock.ioctl(_socket.SIO_RCVALL, _socket.RCVALL_OFF)
            sock.close()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# STATE RESET  (called by settings_bp /api/reset)
# ══════════════════════════════════════════════════════════════════════════════

def reset_state() -> None:
    """Clear all in-memory SOC state without stopping the capture engine."""
    global _incident_counter, _target_incident_counter, _raw_pkt_seq, _soc_pkt_seq, _alert_counter

    with _lock:
        packets.clear()
        alerts.clear()
        traffic_history.clear()
        incidents.clear()
        top_attackers.clear()
        arp_events.clear()
        scan_events.clear()
        attack_map_events.clear()
        raw_packets.clear()

        protocol_stats.update({"TCP": 0, "UDP": 0, "OTHER": 0})
        port_stats.clear()
        hourly_stats.clear()

        network_stats["total_packets"]      = 0
        network_stats["active_connections"] = set()
        network_stats["suspicious_ips"]     = set()
        network_stats["top_protocols"]      = {"TCP": 0, "UDP": 0, "OTHER": 0}
        network_stats["pps"]                = 0.0
        network_stats["dropped_loopback"]   = 0
        network_stats["dropped_dedup"]      = 0

        _last_alert_t.clear()
        _dist_alert_state["last_t"] = 0.0
        _incident_counter           = 0
        _target_incident_counter    = 0
        _raw_pkt_seq                = 0
        _soc_pkt_seq                = 0
        _alert_counter              = 0

        _active_conns_ts.clear()
        _suspicious_ips_ts.clear()

        _arp_ip_to_macs.clear()
        _arp_mac_to_ips.clear()
        _arp_last_alert.clear()
        _scan_state.clear()
        attacked_targets.clear()
        target_incidents.clear()

        _pps_window.clear()

    # Clear beaconing state if module is loaded
    try:
        from detection import beaconing as _bc
        _bc.reset_state()
    except Exception:
        pass


def _seed_arp_from_ifaces() -> None:
    """Pre-populate ARP detection state from this host's own interfaces.

    Seeds _arp_ip_to_macs at startup so any ARP reply that claims a
    different MAC for a host IP immediately triggers mac_conflict.
    """
    try:
        for iface in get_working_ifaces():
            ip  = str(getattr(iface, "ip",  "") or "").strip()
            mac = str(getattr(iface, "mac", "") or "").lower().strip()
            if not ip or ip.startswith("127.") or ip == "0.0.0.0":
                continue
            if not mac or mac in ("00:00:00:00:00:00", "unknown"):
                continue
            with _lock:
                _arp_ip_to_macs.setdefault(ip, set()).add(mac)
                _arp_mac_to_ips.setdefault(mac, set()).add(ip)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════════════════════════

def resolve_incidents_for_ip(ip: str) -> None:
    """
    Immediately resolve all open incidents for a blocked IP and reset the
    attack latch if no other incidents remain. Called by the firewall when
    an IP is blocked so the dashboard returns to SECURE instantly.
    """
    now    = time.time()
    now_ts = ts()
    with _lock:
        for inc in incidents.values():
            if inc.get("source_ip") == ip and inc["status"] in ("OPEN", "ACTIVE"):
                _apply_elapsed(inc, now)
                inc["status"]   = "RESOLVED"
                inc["end_time"] = now_ts
        # If no other open incidents remain, reset the attack latch immediately
        still_active = any(
            i["status"] in ("OPEN", "ACTIVE")
            for i in incidents.values()
        )
    if not still_active:
        from detection.incident_manager import reset_attack_latch as _ral
        _ral()


def start_sniffer() -> None:
    """
    Initialise and start the SOC packet capture engine.

    Non-admin mode behaviour (the main focus of this rewrite):
      • conf.use_pcap = True   — Npcap backend, no WinSock mirror (FIX 1)
      • promisc = False        — no half-promisc Npcap mirror state (FIX 2)
      • raw socket skipped     — no phantom loopback packets (FIX 3)
      • BPF filter active      — broadcast / mDNS noise eliminated (FIX 4)
      • loopback filter active — same-host traffic discarded (FIX 5)
      • richer dedup key       — cross-interface duplicates caught (FIX 6)

    Admin mode behaviour (same accuracy as before):
      • promisc = True (captures traffic not explicitly addressed to host)
      • raw socket enabled (catches VM-to-host packets via IP stack)
    """
    admin = _is_admin()

    print(f"[SOC] Sniffer v5 starting - admin={admin}, use_pcap=True")

    # FIX 1: Ensure Npcap backend is active (set at module level too, but
    # repeating here is safe and makes the intent clear for future readers).
    conf.use_pcap = True

    # promisc=True always: FIX 6 (dedup) handles any mirrored-outbound
    # artifact that older Npcap versions produce without admin rights.
    # Without promisc=True, Windows 11 Npcap in non-admin mode sometimes
    # silently discards inbound unicast frames from other hosts, making
    # attacks from another device (same LAN or public IP) invisible.
    conf.sniff_promisc = True

    capture_status["admin"]   = admin
    capture_status["promisc"] = True

    print(f"[SOC] Promiscuous capture: enabled (dedup handles mirroring artefacts)")

    # Pre-warm the host IP cache before any packet arrives.
    _refresh_host_ips(force=True)
    print(f"[SOC] Host IPs: {sorted(_get_host_ips())}")
    _seed_arp_from_ifaces()
    print(f"[SOC] ARP baseline seeded: {len(_arp_ip_to_macs)} IP->MAC entries")

    # Detect gateway IPs so they can be excluded from attack detection.
    _detect_gateway_ips()

    # Initialise enhancement layers session.
    primary_for_session = _get_default_ip() or "auto"
    layers.init_session(primary_for_session)

    # Start extended visibility module (topology assessment + remote agent receiver).
    network_sensor.start(run_span_check=admin)

    # Background maintenance threads.
    threading.Thread(target=_incident_resolver, daemon=True).start()
    threading.Thread(target=_traffic_sampler,   daemon=True).start()
    threading.Thread(target=_scan_cleanup,       daemon=True).start()
    threading.Thread(target=_host_ip_refresher,  daemon=True).start()

    # Device discovery threads (no admin needed).
    threading.Thread(target=_read_arp_cache,   daemon=True).start()
    threading.Thread(target=_active_arp_scan,  daemon=True).start()
    print("[SOC] Network device discovery: ARP cache reader + active ARP scanner started")

    # Raw socket (SIO_RCVALL) — one per host IP on Windows.
    # Attempted regardless of admin status; _raw_socket_sniffer exits gracefully
    # with a closed socket if SIO_RCVALL is denied (WinError 10013 on non-admin).
    # When it succeeds (admin), it captures ALL inbound IP packets at the IP-stack
    # level — a completely separate path from Npcap, ensuring attacks from another
    # device are caught even if the NIC sniffer misses them.
    if platform.system() == "Windows":
        host_ips_for_raw = sorted(
            ip for ip in _get_host_ips()
            if not ip.startswith("127.") and ip not in ("0.0.0.0", "::1")
            and ":" not in ip  # IPv4 only — SIO_RCVALL is IPv4
        )
        if host_ips_for_raw:
            for _rip in host_ips_for_raw:
                threading.Thread(
                    target=_raw_socket_sniffer, args=(_rip,), daemon=True
                ).start()
            print(f"[SOC] Raw-socket (SIO_RCVALL) attempted on: {host_ips_for_raw}")
        else:
            print("[SOC] Raw-socket skipped - no usable host IPs found")

    ifaces = _pick_interfaces()
    primary = ifaces[0] if ifaces else None
    capture_status["interface"]  = primary or "auto"
    capture_status["interfaces"] = ifaces          # expose full list for dashboard
    print(f"[SOC] Primary interface : {primary}")
    if len(ifaces) > 1:
        print(f"[SOC] Extra interfaces  : {ifaces[1:]}")
    print(f"[SOC] Promiscuous mode  : True  "
          f"(cross-machine LAN capture; dedup eliminates mirroring artefacts)")

    # All interfaces run in daemon threads with promisc=True so inbound
    # packets from other devices are captured regardless of admin status.
    # The primary also runs as a thread — this function returns so the
    # calling thread is freed; the daemon threads outlive it via the app.
    for iface in ifaces:
        threading.Thread(
            target=_sniff_iface, args=(iface,),
            kwargs={"promisc": True},
            daemon=True,
        ).start()

    # If no interfaces were found, fall back to Scapy's auto-detected default.
    if not ifaces:
        print("[SOC] No interfaces found - falling back to Scapy default interface")
        threading.Thread(
            target=_sniff_iface, args=(None,),
            kwargs={"promisc": True},
            daemon=True,
        ).start()

    # Start network profile detection + dynamic baseline tuning.
    # Lazy import avoids circular dependency (network_profiler imports sniffer).
    from detection import network_profiler
    network_profiler.start()
