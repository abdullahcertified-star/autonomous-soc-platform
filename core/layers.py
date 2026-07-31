"""
layers.py — SOC Enhancement Layers (purely additive; Layer 1 is untouched)

CONSTRAINT: This module NEVER imports from detection.py or modifies its state.
            Every function here is observational — results are attached to
            packet records as an 'enhanced' dict; severity/confidence from
            detection.record_packet() are NEVER overwritten here.

Layer 3 : Protocol Correction Overlay      — transport-first labeling
Layer 4 : Flow Observation                 — flow-level metrics
Layer 5 : Visibility Validation            — interface health monitor
+       : TCP Handshake Validation         — SYN→ACK completion rate
+       : Entropy Detection                — source IP diversity (DDoS signal)
+       : Bytes + Size Tracking            — bandwidth and uniformity
+       : Multi-Dimensional Risk Scoring   — weighted feature aggregation (0-100)
+       : Time-of-Day Baseline             — hourly adaptive profiles
+       : Attack Explanation               — reason tagging (why was it flagged?)
+       : Live Session Management          — Wireshark-style session state
"""
from __future__ import annotations

import math
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — PROTOCOL CORRECTION OVERLAY
# ══════════════════════════════════════════════════════════════════════════════
# Adds 'corrected_proto' alongside the original 'proto'.  Original is never
# modified.  Rules: transport-layer identity first; application label only when
# a confirmed port match exists.

_TLS_PORTS  = frozenset({443, 8443, 465, 993, 995, 636, 5061, 5986})
_DNS_PORTS  = frozenset({53, 5353})
_HTTP_PORTS = frozenset({80, 8080, 8000, 3000, 8888})

# Labels that detection.py may assign via port-only matching but that require
# confirmation to be trustworthy.
_UNCONFIRMED_APP_LABELS = frozenset({"HTTPS", "DNS", "mDNS"})


def correct_protocol(transport: str, proto: str, sport: int, dport: int) -> str:
    """
    Transport-first protocol reclassification.

    Hierarchy (applied in order):
      1. Non-TCP/UDP (ICMP, IGMP, GRE …) → trust existing label, no change
      2. UDP  → DNS only on port 53/5353; else strip HTTPS/DNS labels → UDP_UNKNOWN
      3. TCP  → keep label on TLS-port match; HTTP on HTTP-port match;
                TCP on non-TLS port labeled HTTPS → TCP_UNKNOWN
    """
    if transport not in ("TCP", "UDP"):
        return proto  # ICMP, IGMP, GRE — existing label is authoritative

    if transport == "UDP":
        if dport in _DNS_PORTS or sport in _DNS_PORTS:
            return proto if proto in ("DNS", "mDNS") else "DNS"
        if proto in _UNCONFIRMED_APP_LABELS:
            return "UDP_UNKNOWN"  # e.g. UDP labeled HTTPS without port confirmation
        return proto  # NTP, DHCP, SNMP, SSDP, etc. — trust label

    # TCP
    if dport in _TLS_PORTS or sport in _TLS_PORTS:
        return proto  # Port match sufficient for TLS; keep HTTPS/IMAPS/etc.
    if dport in _HTTP_PORTS or sport in _HTTP_PORTS:
        return "HTTP"
    if proto == "HTTPS":
        # TCP on a non-TLS port labelled HTTPS — reclassify to avoid false label
        return "TCP_UNKNOWN"
    return proto  # SSH, RDP, SMB, MySQL, Redis — keep well-known labels


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4 — FLOW OBSERVATION
# ══════════════════════════════════════════════════════════════════════════════
# Tracks flows: (src, dst, dport, transport) → per-flow stats.
# Purely observational; output never feeds back into detection decisions.

_FLOW_TTL     = 120.0   # seconds of idle before a flow is evicted
_FLOW_MAX     = 2000    # maximum concurrent flows tracked

_flows: Dict[Tuple, dict] = {}
_flow_lock              = threading.Lock()
_flow_last_cleanup      = [0.0]


def record_flow(src: str, dst: str, dport: int, transport: str,
                pkt_len: int, now: float) -> None:
    """Update or create a flow record. Called on every SOC-processed packet."""
    key = (src, dst, dport, transport)
    with _flow_lock:
        if key in _flows:
            f           = _flows[key]
            f["packets"] += 1
            f["bytes"]   += pkt_len
            f["last_t"]   = now
            f["duration"] = now - f["start_t"]
            f["pps"]      = f["packets"] / max(f["duration"], 1)
            f["bps"]      = f["bytes"]   / max(f["duration"], 1)
        else:
            if len(_flows) >= _FLOW_MAX:
                _flows.pop(min(_flows, key=lambda k: _flows[k]["last_t"]))
            _flows[key] = {
                "src": src, "dst": dst, "dport": dport, "transport": transport,
                "packets": 1, "bytes": pkt_len,
                "start_t": now, "last_t": now,
                "duration": 0.0, "pps": 0.0, "bps": 0.0,
            }

        if now - _flow_last_cleanup[0] >= 30.0:
            _flow_last_cleanup[0] = now
            cutoff = now - _FLOW_TTL
            for k in [k for k, f in _flows.items() if f["last_t"] < cutoff]:
                del _flows[k]


def get_flow_stats(limit: int = 50) -> List[dict]:
    """Return top flows sorted by packet count descending."""
    with _flow_lock:
        ranked = sorted(_flows.values(), key=lambda f: f["packets"], reverse=True)
        return [
            {
                "src": f["src"], "dst": f["dst"],
                "dport": f["dport"], "transport": f["transport"],
                "packets":  f["packets"],
                "bytes":    f["bytes"],
                "duration": round(f["duration"], 1),
                "pps":      round(f["pps"], 1),
                "bps":      round(f["bps"], 1),
            }
            for f in ranked[:limit]
        ]


def get_src_flows(src_ip: str) -> List[dict]:
    """Return all flows originating from a specific source IP."""
    with _flow_lock:
        return [
            {
                "dst": f["dst"], "dport": f["dport"], "transport": f["transport"],
                "packets":  f["packets"], "bytes": f["bytes"],
                "duration": round(f["duration"], 1), "pps": round(f["pps"], 1),
            }
            for f in _flows.values() if f["src"] == src_ip
        ]


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5 — VISIBILITY VALIDATION
# ══════════════════════════════════════════════════════════════════════════════
# Tracks which interfaces are actively delivering packets.
# Returns FULL / LIMITED / NONE so operators know whether the absence of
# alerts means "no attack" or "attack not visible to this host".

_VIS_TIMEOUT = 10.0   # seconds of silence → interface goes SILENT

_iface_stats: Dict[str, dict] = {}
_iface_lock  = threading.Lock()
_vis_total   = [0]


def mark_packet_seen(iface: str = "unknown") -> None:
    """Called once per captured packet to update interface health."""
    now = time.time()
    with _iface_lock:
        if iface not in _iface_stats:
            _iface_stats[iface] = {"count": 0, "last_t": now, "start_t": now}
        _iface_stats[iface]["count"] += 1
        _iface_stats[iface]["last_t"]  = now
        _vis_total[0] += 1


def get_visibility() -> dict:
    """
    Returns visibility_status: FULL | LIMITED | NONE

    FULL    — ≥1 interface received a packet within the last 10 s
    LIMITED — interfaces known but all have been silent > 10 s
    NONE    — no interfaces registered yet (sniffer just started)
    """
    now = time.time()
    with _iface_lock:
        if not _iface_stats:
            return {
                "visibility_status": "NONE",
                "reason": "No interfaces have received packets yet",
                "interfaces": [],
                "total_packets_observed": _vis_total[0],
            }
        ifaces_out = []
        any_active = False
        for name, s in _iface_stats.items():
            age    = now - s["last_t"]
            active = age < _VIS_TIMEOUT
            if active:
                any_active = True
            ifaces_out.append({
                "interface":         name,
                "packets":           s["count"],
                "last_packet_ago_s": round(age, 1),
                "status":            "ACTIVE" if active else "SILENT",
            })

        if any_active:
            status = "FULL"
            reason = "Traffic is being observed on active interface(s)"
        else:
            status = "LIMITED"
            reason = (
                f"No packets received in last {_VIS_TIMEOUT:.0f}s. "
                "If an attack is underway it may not be routed through this host. "
                "Ensure the attacker targets this machine's IP directly, "
                "or configure a network port mirror / run as gateway."
            )

        return {
            "visibility_status":      status,
            "reason":                 reason,
            "interfaces":             ifaces_out,
            "total_packets_observed": _vis_total[0],
        }


# ══════════════════════════════════════════════════════════════════════════════
# TCP HANDSHAKE VALIDATION
# ══════════════════════════════════════════════════════════════════════════════
# Independent of detection.py. Tracks SYN and ACK counts per source IP in a
# 10-second window.  High SYN / low ACK completion = half-open connections
# — one of the strongest SYN flood indicators.

_HS_WINDOW   = 10.0   # seconds

_hs_syn_ts: Dict[str, deque] = defaultdict(deque)
_hs_ack_ts: Dict[str, deque] = defaultdict(deque)


def record_handshake(src: str, is_syn: bool, is_ack: bool,
                     now: float) -> dict:
    """
    Update SYN/ACK counters for src and return handshake completion stats.

    Returns:
      syn_count       — pure SYN packets (no ACK) in last 10 s
      ack_count       — pure ACK packets (no SYN) in last 10 s
      half_open_ratio — syn / (syn + ack), 0-1;  > 0.8 = SYN flood
      syn_ack_ratio   — syn / max(ack, 1);  mirrors detection.py's ratio
    """
    cutoff = now - _HS_WINDOW

    if is_syn and not is_ack:
        _hs_syn_ts[src].append(now)
    if is_ack and not is_syn:
        _hs_ack_ts[src].append(now)

    while _hs_syn_ts[src] and _hs_syn_ts[src][0] < cutoff:
        _hs_syn_ts[src].popleft()
    while _hs_ack_ts[src] and _hs_ack_ts[src][0] < cutoff:
        _hs_ack_ts[src].popleft()

    syn = len(_hs_syn_ts[src])
    ack = len(_hs_ack_ts[src])
    total = syn + ack

    half_open = (syn / total) if total > 5 else 0.0
    sa_ratio  = (syn / max(ack, 1)) if syn > 5 else 0.0

    return {
        "syn_count":       syn,
        "ack_count":       ack,
        "half_open_ratio": round(half_open, 3),
        "syn_ack_ratio":   round(sa_ratio, 2),
    }


# ══════════════════════════════════════════════════════════════════════════════
# ENTROPY DETECTION
# ══════════════════════════════════════════════════════════════════════════════
# Shannon entropy H of source IP distribution over a 10-second sliding window.
#
#   H > 3.5 bits  → many unique source IPs  → DDoS / distributed attack
#   H < 0.5 bits  → one or two sources only → single-source flood
#   H ≈ 0.0       → only one source         → concentrated single-IP flood

_ENT_WINDOW = 10.0

_ent_window: deque     = deque()   # [(timestamp, src_ip), ...]
_ent_lock   = threading.Lock()


def _shannon(counts: dict) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def record_entropy(src: str, now: float) -> float:
    """
    Append src to rolling window; return current Shannon entropy (bits).
    Higher = more source diversity = more likely distributed attack.
    """
    with _ent_lock:
        _ent_window.append((now, src))
        cutoff = now - _ENT_WINDOW
        while _ent_window and _ent_window[0][0] < cutoff:
            _ent_window.popleft()
        counts: dict = defaultdict(int)
        for _, ip in _ent_window:
            counts[ip] += 1
    return round(_shannon(counts), 3)


# ══════════════════════════════════════════════════════════════════════════════
# BYTES + PACKET-SIZE TRACKING
# ══════════════════════════════════════════════════════════════════════════════
# Tracks bytes/sec and packet-size variance per source IP.
# Uniform packet sizes (low variance) = scripted flood.
# Extreme variance = mixed payload or amplification attempt.

_BW_WINDOW     = 5.0
_SIZE_MAX_HIST = 60    # last N sizes per IP

_bytes_ts:  Dict[str, deque] = defaultdict(deque)   # {src: [(t, len), ...]}
_size_hist: Dict[str, deque] = defaultdict(deque)   # {src: [len, ...]}


def record_bytes(src: str, pkt_len: int, now: float) -> Tuple[float, float]:
    """
    Track per-IP bandwidth and size distribution.
    Returns (bytes_per_sec, size_variance).
    """
    _bytes_ts[src].append((now, pkt_len))
    cutoff = now - _BW_WINDOW
    while _bytes_ts[src] and _bytes_ts[src][0][0] < cutoff:
        _bytes_ts[src].popleft()
    bps = sum(ln for _, ln in _bytes_ts[src]) / _BW_WINDOW

    _size_hist[src].append(pkt_len)
    if len(_size_hist[src]) > _SIZE_MAX_HIST:
        _size_hist[src].popleft()
    sizes = list(_size_hist[src])
    if len(sizes) >= 2:
        mean = sum(sizes) / len(sizes)
        var  = sum((s - mean) ** 2 for s in sizes) / len(sizes)
    else:
        var = 0.0

    return round(bps, 1), round(var, 1)


# ══════════════════════════════════════════════════════════════════════════════
# MULTI-DIMENSIONAL RISK SCORING
# ══════════════════════════════════════════════════════════════════════════════
# Weighted combination of per-IP behavioral features → 0-100 risk score.
# This is supplementary to Layer 1's confidence (0-100).  It does NOT replace
# or override it.  High risk_score with low Layer-1 confidence = pre-attack
# reconnaissance or slow-rate attack that hasn't crossed rate thresholds yet.

_WEIGHTS = {
    "syn_rate":     0.28,   # strongest flood signal
    "half_open":    0.22,   # incomplete handshakes
    "entropy":      0.18,   # source diversity (DDoS)
    "port_scan":    0.12,   # unique destination ports
    "pkt_rate":     0.10,   # raw pps (weakest alone)
    "size_variance": 0.10,  # packet uniformity anomaly
}

# Values at which the corresponding factor saturates to 1.0
_NORM = {
    "syn_rate":     2000.0,   # SYNs per 10 s
    "port_scan":      50.0,   # unique ports
    "pkt_rate":     5900.0,   # pps (attack threshold)
    "size_variance": 50000.0, # bytes²
    "entropy":          4.0,  # bits
}


def compute_risk(rate: int, syn_count: int, half_open_ratio: float,
                 unique_ports: int, size_var: float, entropy: float) -> dict:
    """
    Multi-dimensional risk score (0-100).

    Inputs are all available without touching detection.py internals.
    The score surfaces attack signals that are invisible to single-metric
    thresholds (e.g. a slow port scan below the pps threshold).
    """
    f_syn  = min(1.0, syn_count      / _NORM["syn_rate"])
    f_ho   = min(1.0, half_open_ratio)
    f_ent  = min(1.0, entropy        / _NORM["entropy"])
    f_port = min(1.0, unique_ports   / _NORM["port_scan"])
    f_rate = min(1.0, rate           / _NORM["pkt_rate"])
    f_svar = min(1.0, size_var       / _NORM["size_variance"])

    raw = (
        f_syn  * _WEIGHTS["syn_rate"]
        + f_ho   * _WEIGHTS["half_open"]
        + f_ent  * _WEIGHTS["entropy"]
        + f_port * _WEIGHTS["port_scan"]
        + f_rate * _WEIGHTS["pkt_rate"]
        + f_svar * _WEIGHTS["size_variance"]
    )
    return {
        "risk_score": round(raw * 100),
        "factors": {
            "syn_rate":     round(f_syn,  3),
            "half_open":    round(f_ho,   3),
            "entropy":      round(f_ent,  3),
            "port_scan":    round(f_port, 3),
            "packet_rate":  round(f_rate, 3),
            "size_variance":round(f_svar, 3),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# TIME-OF-DAY BASELINE
# ══════════════════════════════════════════════════════════════════════════════
# Maintains 24 separate hourly baseline buckets.  Morning traffic != night
# traffic; a per-hour baseline prevents false positives during predictable
# traffic spikes (e.g. 09:00 office start) and missed detections during
# normally-quiet hours.
#
# Uses the same bottom-half filtering as detection.py's _get_baseline() to
# prevent sustained attacks from drifting the mean upward.

_TOD_KEEP_SECS   = 7 * 24 * 3600   # retain up to 1 week of hourly samples
_TOD_MIN_SAMPLES = 10

_tod: Dict[int, deque] = defaultdict(deque)   # {hour_0_23: [(epoch, rate), ...]}
_tod_lock = threading.Lock()
_tod_last_sample = [0.0]


def sample_tod(hour: int, rate: float, now: float) -> None:
    """Add a per-second rate sample to the current hour's bucket."""
    with _tod_lock:
        _tod[hour].append((now, rate))
        cutoff = now - _TOD_KEEP_SECS
        while _tod[hour] and _tod[hour][0][0] < cutoff:
            _tod[hour].popleft()


def get_tod_stats(hour: int, current_rate: float) -> dict:
    """
    Compare current_rate to the historical baseline for this hour.
    Returns {ready, samples, mean, std, z_score, deviation_ratio}.
    deviation_ratio > 2.0 = SUSPICIOUS for this time of day.
    deviation_ratio > 5.0 = ATTACK level for this time of day.
    """
    with _tod_lock:
        n = len(_tod[hour])
        if n < _TOD_MIN_SAMPLES:
            return {"ready": False, "samples": n, "hour": hour,
                    "z_score": 0.0, "deviation_ratio": 0.0,
                    "mean": 0.0, "std": 0.0}
        rates = sorted(s[1] for s in _tod[hour])
        half  = rates[: max(_TOD_MIN_SAMPLES, n // 2)]
        mean  = sum(half) / len(half)
        std   = math.sqrt(sum((r - mean) ** 2 for r in half) / max(len(half) - 1, 1))
        z     = round((current_rate - mean) / std, 2) if std > 0 else 0.0
        ratio = round(current_rate / mean, 2) if mean > 0 else 0.0
        return {
            "ready":            True,
            "samples":          n,
            "hour":             hour,
            "mean":             round(mean,  1),
            "std":              round(std,   1),
            "z_score":          z,
            "deviation_ratio":  ratio,
        }


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK EXPLANATION / REASON TAGGING
# ══════════════════════════════════════════════════════════════════════════════
# Translates numeric signals into human-readable reason strings.
# Implements the "≥2 independent signals required" confirmation rule.
# NEVER modifies severity or confidence from Layer 1.

def explain(severity: Optional[str], confidence: int, rate: int,
            syn_ack_ratio: float, half_open_ratio: float,
            is_dist: bool, entropy: float, risk_score: int,
            unique_ports: int, bytes_sec: float,
            tod_deviation: float) -> dict:
    """
    Produce reason tags for the existing detection decision.
    Returns the explanation dict that is merged into the packet 'enhanced' field.
    """
    reasons: List[str] = []

    # Rate
    if rate > 5900:
        reasons.append("EXTREME_PACKET_RATE")
    elif rate > 2400:
        reasons.append("HIGH_PACKET_RATE")

    # SYN flood (computed from handshake tracker — no detection.py access needed)
    if syn_ack_ratio >= 10.0:
        reasons.append("SYN_FLOOD_ATTACK")
    elif syn_ack_ratio >= 3.0:
        reasons.append("SYN_FLOOD_SUSPICIOUS")

    # Half-open connections
    if half_open_ratio > 0.80:
        reasons.append("HIGH_HALF_OPEN_CONNECTIONS")
    elif half_open_ratio > 0.50:
        reasons.append("ELEVATED_HALF_OPEN")

    # Distributed
    if is_dist:
        reasons.append("DISTRIBUTED_FLOOD")

    # Source diversity
    if entropy > 3.5:
        reasons.append("HIGH_SOURCE_ENTROPY_DDOS")
    elif entropy < 0.5 and rate > 1000:
        reasons.append("LOW_ENTROPY_CONCENTRATED_FLOOD")

    # Port scanning
    if unique_ports >= 50:
        reasons.append("PORT_SCAN_HEAVY")
    elif unique_ports >= 12:
        reasons.append("PORT_SCAN_SUSPECTED")

    # Bandwidth
    if bytes_sec > 10_000_000:   # 10 MB/s
        reasons.append("HIGH_BANDWIDTH_FLOOD")

    # Time-of-day anomaly
    if tod_deviation > 5.0:
        reasons.append("TOD_EXTREME_DEVIATION")
    elif tod_deviation > 2.0:
        reasons.append("TOD_SUSPICIOUS_DEVIATION")

    # Risk label
    if risk_score >= 70:
        risk_label = "HIGH_RISK"
    elif risk_score >= 40:
        risk_label = "MEDIUM_RISK"
    else:
        risk_label = "LOW_RISK"

    # Multi-signal confirmation (rule: ≥2 independent signals for ATTACK)
    signals = sum([
        rate > 5900,
        syn_ack_ratio >= 10.0,
        half_open_ratio > 0.80,
        is_dist,
        entropy > 3.5,
        unique_ports >= 50,
        bytes_sec > 10_000_000,
    ])
    confirmed = signals >= 2 or (severity == "HIGH" and signals >= 1)

    if not reasons:
        reasons = ["NORMAL_TRAFFIC"] if not severity else ["RATE_THRESHOLD_ONLY"]

    return {
        "reasons":                reasons,
        "risk_label":             risk_label,
        "attack_signal_count":    signals,
        "multi_signal_confirmed": confirmed,
    }


# ══════════════════════════════════════════════════════════════════════════════
# LIVE SESSION MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
# A Wireshark-style session object that accumulates per-session statistics
# without interfering with the detection engine.

_session: dict = {
    "session_id":       "",
    "status":           "IDLE",
    "start_time":       "",
    "interface_name":   "",
    "packet_count":     0,
    "bytes_total":      0,
    "attack_count":     0,
    "suspicious_count": 0,
    "protocol_stats": {
        "TCP": 0, "UDP": 0, "ICMP": 0,
        "HTTP": 0, "HTTPS": 0, "DNS": 0, "ARP": 0,
        "TCP_UNKNOWN": 0, "UDP_UNKNOWN": 0, "OTHER": 0,
    },
}
_session_lock = threading.Lock()


def init_session(iface: str = "auto") -> None:
    """Initialize a fresh live capture session. Called at sniffer startup."""
    with _session_lock:
        _session.update({
            "session_id":       uuid.uuid4().hex[:8],
            "status":           "ACTIVE",
            "start_time":       datetime.now().isoformat(),
            "interface_name":   iface,
            "packet_count":     0,
            "bytes_total":      0,
            "attack_count":     0,
            "suspicious_count": 0,
            "protocol_stats": {k: 0 for k in _session["protocol_stats"]},
        })


def update_session(corrected_proto: str, pkt_len: int,
                   severity: Optional[str]) -> None:
    """Increment session counters for one packet."""
    with _session_lock:
        _session["packet_count"] += 1
        _session["bytes_total"]  += pkt_len
        bucket = (corrected_proto
                  if corrected_proto in _session["protocol_stats"]
                  else "OTHER")
        _session["protocol_stats"][bucket] += 1
        if severity == "HIGH":
            _session["attack_count"] += 1
        elif severity == "MEDIUM":
            _session["suspicious_count"] += 1


def get_session() -> dict:
    with _session_lock:
        return dict(_session)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# Called from sniffer.process_packet() after the existing detection pipeline.
# Returns an 'enhanced' dict that is stored on each packet record.
# ══════════════════════════════════════════════════════════════════════════════

_tod_tick = [0.0]   # tracks last time-of-day sample epoch


def process(src: str, dst: str, transport: str, proto: str,
            sport: int, dport: int, pkt_len: int,
            is_syn: bool, is_ack: bool,
            severity: Optional[str], confidence: int, rate: int,
            unique_ports: int, is_dist: bool,
            iface: str = "unknown") -> dict:
    """
    Run all enhancement layers for one packet and return an 'enhanced' dict.

    All parameters are already available inside sniffer.process_packet()
    without any changes to detection.py or its state.

    Calling convention (sniffer.py):
        _enh = layers.process(
            src, dst, _tp, proto, src_port, dst_port, _pkt_len,
            is_syn, is_ack, severity, confidence, rate,
            detection.get_unique_ports(src), is_dist,
            iface=getattr(_tl, 'iface', 'unknown'),
        )

    The returned dict is attached to the packet record as 'enhanced'.
    severity and confidence from detection.record_packet() are NEVER
    modified here.
    """
    now  = time.time()
    hour = datetime.now().hour

    # L5 — visibility
    mark_packet_seen(iface)

    # L3 — protocol correction
    corrected = correct_protocol(transport, proto, sport, dport)

    # L4 — flow observation
    record_flow(src, dst, dport, transport, pkt_len, now)

    # Handshake tracking (SYN / ACK completion)
    hs = record_handshake(src, is_syn, is_ack, now)

    # Entropy
    entropy = record_entropy(src, now)

    # Bandwidth + size variance
    bytes_sec, size_var = record_bytes(src, pkt_len, now)

    # Risk score
    risk = compute_risk(
        rate=rate,
        syn_count=hs["syn_count"],
        half_open_ratio=hs["half_open_ratio"],
        unique_ports=unique_ports,
        size_var=size_var,
        entropy=entropy,
    )

    # Time-of-day baseline (sample once per second per process() call)
    if now - _tod_tick[0] >= 1.0:
        _tod_tick[0] = now
        sample_tod(hour, float(rate), now)
    tod = get_tod_stats(hour, float(rate))

    # Attack explanation
    exp = explain(
        severity=severity,
        confidence=confidence,
        rate=rate,
        syn_ack_ratio=hs["syn_ack_ratio"],
        half_open_ratio=hs["half_open_ratio"],
        is_dist=is_dist,
        entropy=entropy,
        risk_score=risk["risk_score"],
        unique_ports=unique_ports,
        bytes_sec=bytes_sec,
        tod_deviation=tod.get("deviation_ratio", 0.0),
    )

    # Session update
    update_session(corrected, pkt_len, severity)

    return {
        "corrected_proto": corrected,
        "bytes_sec":       bytes_sec,
        "size_variance":   size_var,
        "entropy":         entropy,
        "handshake":       hs,
        "risk":            risk,
        "tod":             tod,
        "explanation":     exp,
    }
