"""
main.py — Dashboard & Network Overview Blueprint
"""
from flask import Blueprint, render_template, jsonify, redirect, url_for, request
from flask_login import login_required, current_user
from datetime import datetime
import time as _time

from detection import sniffer
from detection import detection
from core import firewall as fw
from core import layers
from detection import network_sensor
from reporting import dashboard as dash_data
from detection.incident_manager import get_last_attack_epoch
from rbac import require_permission

main_bp = Blueprint("main", __name__)


def _is_public_ip(ip: str) -> bool:
    try:
        parts  = ip.split(".")
        first  = int(parts[0])
        second = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return False
    if first == 10:                             return False
    if first == 172 and 16 <= second <= 31:     return False
    if first == 192 and second == 168:          return False
    if first == 127:                            return False
    if first == 169 and second == 254:          return False
    if first >= 224:                            return False
    return True


@main_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)


@main_bp.route("/network")
@login_required
def network():
    return render_template("network.html")


@main_bp.route("/globe")
@login_required
def globe():
    return render_template("globe.html", user=current_user)


@main_bp.route("/capture")
@login_required
def capture():
    return render_template("capture.html", user=current_user)


@main_bp.route("/mitm")
@login_required
def mitm():
    return render_template("mitm.html", user=current_user)


@main_bp.route("/api/network-profile")
@login_required
def api_network_profile():
    from detection import network_profiler
    return jsonify(network_profiler.get_state())


@main_bp.route("/api/incidents/clear-all", methods=["POST"])
@require_permission("incidents", "write")
def api_clear_all_incidents():
    """Force-resolve all open incidents and reset the attack latch.
    Used when the system gets stuck in ATTACK state after an attack ends."""
    import time as _t
    from detection.incident_manager import reset_attack_latch as _ral
    now    = _t.time()
    now_ts = datetime.now().strftime("%I:%M:%S %p")
    count  = 0
    with sniffer._lock:
        for inc in sniffer.incidents.values():
            if inc.get("status") in ("OPEN", "ACTIVE"):
                inc["status"]   = "RESOLVED"
                inc["end_time"] = now_ts
                count += 1
        for inc in sniffer.target_incidents.values():
            if inc.get("status") in ("OPEN", "ACTIVE"):
                inc["status"]   = "RESOLVED"
                inc["end_time"] = now_ts
                count += 1
    _ral()
    return jsonify({"ok": True, "resolved": count})


@main_bp.route("/api/capture/soc")
@require_permission("capture", "read")
def api_capture_soc():
    """
    GET /api/capture/soc?since=<epoch>&limit=<n>&filter=<text>&proto=<TCP|UDP|...>&sev=<NORMAL|MEDIUM|HIGH>

    Returns sniffer.packets (SOC-filtered stream) with full detection metadata:
    time, src, dst, src_mac, proto, port, country, rate, confidence, severity.
    These are the same packets the detection engine processes — not raw capture.
    """
    try:
        since_id = int(request.args.get("since_id", -1))
    except (ValueError, TypeError):
        since_id = -1
    try:
        before_id = int(request.args.get("before_id", 0))
    except (ValueError, TypeError):
        before_id = 0
    try:
        limit = min(int(request.args.get("limit", 2000)), 5000)
    except (ValueError, TypeError):
        limit = 2000

    filt      = (request.args.get("filter",  "") or "").strip().lower()
    proto_flt = (request.args.get("proto",   "") or "").strip().upper()
    sev_flt   = (request.args.get("sev",     "") or "").strip().upper()

    snap = list(sniffer.packets)
    _INIT_WINDOW = 150

    def _apply_filters(s):
        if filt:
            s = [p for p in s if
                 filt in (p.get("src") or "").lower() or
                 filt in (p.get("dst") or "").lower() or
                 filt in (p.get("src_mac") or "").lower() or
                 filt in (p.get("country") or "").lower()]
        if proto_flt and proto_flt != "ALL":
            s = [p for p in s if (p.get("proto") or "").upper() == proto_flt]
        if sev_flt and sev_flt != "ALL":
            s = [p for p in s if (p.get("severity") or "NORMAL").upper() == sev_flt]
        return s

    if before_id > 0:
        # Backward lazy-load: frontend scrolled up and wants older history.
        # Return up to `limit` packets with seq_id < before_id, oldest-first,
        # so the client can prepend them in correct temporal order.
        page = _apply_filters([p for p in snap if p.get("seq_id", 0) < before_id])[-limit:]
    elif since_id > 0:
        # Incremental poll: return only packets the client hasn't seen yet.
        snap_new = [p for p in snap if p.get("seq_id", 0) > since_id]
        # Gap detection: cursor is older than the entire deque (long disconnect).
        oldest_seq = snap[0].get("seq_id", 0) if snap else 0
        if oldest_seq > since_id:
            snap_new = snap[-_INIT_WINDOW:]
        page = _apply_filters(snap_new)[:limit]
    else:
        # Initial load or filter reset: jump straight to the latest window.
        # 150 rows render in < 5 ms — no visible replay scroll on reconnect.
        page = _apply_filters(snap[-_INIT_WINDOW:])

    active_incs  = [inc for inc in sniffer.incidents.values()
                    if inc.get("status") in ("OPEN", "ACTIVE")]
    # Also count victim-side (target) incidents — rand-source SYN floods hit these
    active_target_incs = [inc for inc in sniffer.target_incidents.values()
                          if inc.get("status") in ("OPEN", "ACTIVE")]
    latch_active = (_time.time() - get_last_attack_epoch()) < sniffer.ATTACK_LATCH_SECONDS
    return jsonify({
        "packets":      page,
        "total_seen":   sniffer.network_stats["total_packets"],
        "under_attack": len(active_incs) > 0 or len(active_target_incs) > 0 or latch_active,
        "timestamp":    datetime.now().strftime("%I:%M:%S %p"),
    })


@main_bp.route("/api/capture/stream")
@require_permission("capture", "read")
def api_capture_stream():
    """
    GET /api/capture/stream?since=<epoch>&limit=<n>&filter=<text>

    Returns raw_packets entries newer than `since` (unix epoch float).
    `filter` is a case-insensitive substring match against src, dst, proto, info.
    Maximum 500 rows per call.
    """
    try:
        since = float(request.args.get("since", 0))
    except (ValueError, TypeError):
        since = 0.0

    try:
        limit = min(int(request.args.get("limit", 200)), 500)
    except (ValueError, TypeError):
        limit = 200

    filt = (request.args.get("filter", "") or "").strip().lower()

    # raw_packets is a deque — snapshot then filter.
    snap = list(sniffer.raw_packets)
    if since > 0:
        snap = [p for p in snap if p.get("epoch", 0) > since]

    if filt:
        snap = [
            p for p in snap
            if (filt in p.get("src", "").lower()
                or filt in p.get("dst", "").lower()
                or filt in p.get("proto", "").lower()
                or filt in p.get("info", "").lower())
        ]

    # Return latest `limit` entries.
    snap = snap[-limit:]

    return jsonify({
        "packets":     snap,
        "count":       len(snap),
        "total_seen":  sniffer._raw_pkt_seq,
        "proto_colors": sniffer.PROTO_COLORS,
        "timestamp":   datetime.now().strftime("%I:%M:%S %p"),
    })


# ── Dashboard API ──

@main_bp.route("/api/dashboard")
@login_required
def api_dashboard():
    pkts = list(sniffer.packets)
    alrts = list(sniffer.alerts)
    graph = list(sniffer.traffic_history)
    stats = dict(sniffer.protocol_stats)

    active_incidents = [
        inc for inc in sniffer.incidents.values()
        if inc.get("status") in ("OPEN", "ACTIVE")
    ]
    # Also count victim-side (target) incidents — rand-source SYN floods hit these
    active_target_incidents = [
        inc for inc in sniffer.target_incidents.values()
        if inc.get("status") in ("OPEN", "ACTIVE")
    ]
    all_active = active_incidents + active_target_incidents

    # under_attack: true while incidents are active OR within the latch window
    # after the last confirmed attack packet — prevents flicker when a flood
    # briefly dips below the per-IP threshold between bursts.
    latch_active = (_time.time() - get_last_attack_epoch()) < sniffer.ATTACK_LATCH_SECONDS
    under_attack = len(all_active) > 0 or latch_active

    return jsonify({
        "packets": pkts,
        "alerts": alrts[-30:],
        "graph": graph,
        "stats": stats,
        "capture": sniffer.capture_status,
        "traffic": dash_data.live_traffic_metrics(),
        "under_attack": under_attack,
        "active_attack_count": len(all_active),
        "active_incidents": len(all_active),
        "baseline": detection.get_baseline_stats(),
        "timestamp": datetime.now().strftime("%I:%M:%S %p"),
    })


# ── Kept for backwards compatibility with old dashboard JS ──
@main_bp.route("/api/soc")
@login_required
def api_soc():
    return api_dashboard()


# ── Network Overview API ──

@main_bp.route("/api/network")
@login_required
def api_network():
    ns = sniffer.network_stats
    stats = dict(sniffer.protocol_stats)
    pps = dash_data.live_traffic_metrics()

    return jsonify({
        "total_packets": ns["total_packets"],
        "active_connections": len(ns["active_connections"]),
        "suspicious_ips": len(ns["suspicious_ips"]),
        "top_protocols": stats,
        "capture": sniffer.capture_status,
        "traffic_rate": round(sniffer.current_pps(), 1),
        "traffic": pps,
        "traffic_history": list(sniffer.traffic_history),
    })


# ── Network Device Discovery API ──

@main_bp.route("/api/network/devices")
@login_required
def api_network_devices():
    """
    GET /api/network/devices — all discovered LAN devices.

    Sources combined:
      • Passive ARP (sniffer captures ARP replies from switch broadcasts)
      • Windows ARP cache (`arp -a`, refreshed every 30 s, no admin needed)
      • Active ARP scan (Scapy who-has to local /24, refreshed every 60 s)

    NOTE: on a switched network, packet-level traffic of OTHER devices is
    physically invisible without a managed switch port mirror or Wi-Fi monitor
    mode.  This endpoint shows devices that EXIST on the LAN, not their traffic.
    """
    devices = sniffer.get_network_devices()
    return jsonify({
        "devices": devices,
        "count":   len(devices),
        "note":    (
            "Switched network: only traffic TO/FROM this host is captured. "
            "Device list uses ARP discovery (passive + active scan)."
        ),
        "timestamp": datetime.now().strftime("%I:%M:%S %p"),
    })


# ── Public spec endpoints ──

@main_bp.route("/stats")
@login_required
def api_stats():
    """GET /stats — traffic stats per the IDS/IPS spec."""
    ns = sniffer.network_stats
    stats = dict(sniffer.protocol_stats)
    history = list(sniffer.traffic_history)
    live = dash_data.live_traffic_metrics()
    current_rate = live["pps_1s"]

    top_ips = dash_data.top_talker_rows(10)

    return jsonify({
        "total_packets":      ns["total_packets"],
        "active_connections": len(ns["active_connections"]),
        "suspicious_ips":     len(ns["suspicious_ips"]),
        "blocked_ips":        fw.blocked_count(),
        "current_pps":        current_rate,
        "protocols":          stats,
        "traffic_history":    history,
        "traffic":            live,
        "top_ips":            top_ips,
        "baseline":           detection.get_baseline_stats(),
        "capture":            sniffer.capture_status,
        "timestamp":          datetime.now().strftime("%I:%M:%S %p"),
    })


@main_bp.route("/alerts")
@login_required
def api_alerts():
    """GET /alerts — recent suspicious / attack events."""
    severity_filter = request.args.get("severity", "ALL").upper()
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except (ValueError, TypeError):
        limit = 50

    alerts = list(sniffer.alerts)
    if severity_filter != "ALL":
        alerts = [a for a in alerts if (a.get("severity") or "").upper() == severity_filter]

    active_incidents = [
        inc for inc in sniffer.incidents.values()
        if inc.get("status") in ("OPEN", "ACTIVE")
    ]

    return jsonify({
        "alerts":          list(reversed(alerts))[:limit],
        "total":           len(alerts),
        "active_incidents": len(active_incidents),
        "timestamp":       datetime.now().strftime("%I:%M:%S %p"),
    })


@main_bp.route("/block", methods=["POST"])
@require_permission("firewall", "write")
def api_block():
    """POST /block — manually block an IP."""
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    reason = (data.get("reason") or "Manual block").strip()
    duration = data.get("duration")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    kwargs = {"reason": reason, "auto": False}
    if duration is not None:
        kwargs["duration"] = int(duration)
    return jsonify(fw.block_ip(ip, **kwargs))


@main_bp.route("/unblock", methods=["POST"])
@require_permission("firewall", "write")
def api_unblock():
    """POST /unblock — remove a block."""
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    return jsonify(fw.unblock_ip(ip))


# ── Advanced Dashboard API ────────────────────────────────────────────────────

_SERVICE_MAP = {
    20: "FTP-Data", 21: "FTP",    22: "SSH",    23: "Telnet",
    25: "SMTP",     53: "DNS",    67: "DHCP",   68: "DHCP",
    80: "HTTP",    110: "POP3",  143: "IMAP",  161: "SNMP",
   443: "HTTPS",  445: "SMB",   465: "SMTPS", 587: "SMTP",
   993: "IMAPS",  995: "POP3S",1433: "MSSQL",1521: "Oracle",
  3306: "MySQL", 3389: "RDP",  5432: "PgSQL", 5900: "VNC",
  6379: "Redis", 8080: "HTTP+",8443: "HTTPS+",27017: "Mongo",
}


@main_bp.route("/api/advanced")
@login_required
def api_advanced():
    """Comprehensive data endpoint for the advanced SOC dashboard panels."""
    # ── ARP & scan events ────────────────────────────────────────────────
    _now = _time.time()
    arp_evts  = [e for e in reversed(list(sniffer.arp_events))
                 if _now - e.get("_epoch", _now) <= 60][:30]
    scan_evts = list(reversed(list(sniffer.scan_events)))[:30]

    # ── Port heatmap ─────────────────────────────────────────────────────
    port_data  = dict(sniffer.port_stats)
    top_ports  = sorted(port_data.items(), key=lambda x: x[1], reverse=True)[:20]
    port_total = max(sum(port_data.values()), 1)
    port_heatmap = [
        {
            "port":    p,
            "service": _SERVICE_MAP.get(p, f"Port {p}"),
            "count":   c,
            "percent": round(c / port_total * 100, 1),
        }
        for p, c in top_ports
    ]

    # ── Hourly heatmap (24 values, index = hour) ─────────────────────────
    hourly = [sniffer.hourly_stats.get(h, 0) for h in range(24)]

    # ── Country stats — primary: top_attackers (all IPs, every packet) ──────
    # top_attackers is populated for EVERY packet regardless of severity,
    # so distributed flood IPs (below per-IP threshold) are counted here.
    country_counts: dict = {}
    country_attacker_counts: dict = {}
    for a in list(sniffer.top_attackers.values()):
        c = a.get("country") or ""
        if c and c not in ("Local", "Multicast", "Unknown"):
            country_counts[c] = country_counts.get(c, 0) + a.get("packet_count", 1)
            country_attacker_counts[c] = country_attacker_counts.get(c, 0) + 1

    # Also include geolocated packets from live packet_streamer events
    for ev in list(sniffer.attack_map_events):
        c = ev.get("src_country") or ""
        if c and c not in ("Local", "Multicast", "Unknown"):
            country_counts[c] = country_counts.get(c, 0) + 1
            country_attacker_counts[c] = country_attacker_counts.get(c, 0) + 1

    top_countries  = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    country_total  = max(sum(country_counts.values()), 1)

    # ── Threat prediction (rule-based) ───────────────────────────────────
    bl          = detection.get_baseline_stats()
    deviation   = bl.get("deviation", 0)
    active_incs = [
        i for i in list(sniffer.incidents.values())
        if i.get("status") in ("OPEN", "ACTIVE")
    ]

    risk_score = min(100, int(
        deviation   * 10
        + len(active_incs)  * 15
        + len(arp_evts)     * 8
        + len(scan_evts)    * 6
    ))

    if   risk_score >= 80: risk_level = "IMMINENT"
    elif risk_score >= 60: risk_level = "HIGH"
    elif risk_score >= 30: risk_level = "ELEVATED"
    else:                  risk_level = "LOW"

    bl_samples = bl.get("samples", 0)
    ai_conf    = min(95, 50 + bl_samples)

    threat_prediction = {
        "risk_level":             risk_level,
        "risk_score":             risk_score,
        "ddos_probability":       min(100, int(deviation * 15 + len(active_incs) * 10)),
        "escalation_probability": min(100, int(len(active_incs) * 20 + deviation * 8)),
        "burst_probability":      min(100, int(deviation * 12)),
        "repeat_probability":     min(100, len(sniffer.top_attackers) * 4),
        "ai_confidence":          ai_conf,
        "baseline_deviation":     deviation,
    }

    # ── System status ─────────────────────────────────────────────────────
    system_status = dash_data.system_status_block()

    # ── Public IP attack events ───────────────────────────────────────────
    pub_ip_attacks = []
    for _p in reversed(list(sniffer.packets)):
        if _is_public_ip(_p.get("dst", "")) and _p.get("severity") in ("HIGH", "MEDIUM"):
            pub_ip_attacks.append({
                "time":        _p.get("time", ""),
                "src_ip":      _p.get("src", ""),
                "src_country": _p.get("country", ""),
                "dst_ip":      _p.get("dst", ""),
                "attack_type": _p.get("proto", "Unknown"),
                "severity":    _p.get("severity", ""),
                "confidence":  _p.get("confidence", 0),
            })
            if len(pub_ip_attacks) >= 30:
                break

    # ── Active incidents list ─────────────────────────────────────────────
    incidents_list = [
        {
            "id":          iid,
            "src_ip":      inc.get("source_ip", ""),
            "attack_type": inc.get("attack_type", "Unknown"),
            "severity":    inc.get("severity", "MEDIUM"),
            "confidence":  inc.get("confidence", 0),
            "packets":     inc.get("packet_count", 0),
            "start_time":  inc.get("start_time", ""),
            "start_epoch": inc.get("start_epoch", 0),
            "status":      inc.get("status", "OPEN"),
            "country":     inc.get("country", ""),
        }
        for iid, inc in sorted(
            sniffer.incidents.items(),
            key=lambda x: x[1].get("start_epoch", 0),
            reverse=True
        )
        if inc.get("status") in ("OPEN", "ACTIVE")
    ][:15]

    # ── Kill chain stages per attacker ────────────────────────────────────
    _scan_ips = {s.get("src_ip", "") for s in list(sniffer.scan_events)[-100:]}
    try:
        from core.firewall import get_blocked_list as _gb
        _blocked_ips = {b["ip"] for b in _gb()}
    except Exception:
        _blocked_ips = set()
    kill_chain = []
    for _ip, _atk in sorted(
        sniffer.top_attackers.items(),
        key=lambda x: x[1].get("severity_score", 0), reverse=True
    )[:10]:
        _sc = _atk.get("severity_score", 0)
        if _sc < 5:
            continue
        _stages = []
        if _ip in _scan_ips:
            _stages.append("recon")
        if _sc >= 10:
            _stages.append("probe")
        if _sc >= 40:
            _stages.append("attack")
        if _ip in _blocked_ips:
            _stages.append("blocked")
        if _stages:
            kill_chain.append({
                "ip":          _ip,
                "country":     _atk.get("country", ""),
                "attack_type": _atk.get("attack_type", "Unknown"),
                "severity":    "HIGH" if _sc > 60 else "MEDIUM",
                "confidence":  int(min(_sc, 99)),
                "stages":      _stages,
                "active_stage": _stages[-1],
            })

    # ── Network topology data ─────────────────────────────────────────────
    import socket as _sock
    try:
        _local_ip = _sock.gethostbyname(_sock.gethostname())
    except Exception:
        _local_ip = "127.0.0.1"
    topo_nodes = [{"id": "host", "ip": _local_ip, "type": "host", "label": "This Host"}]
    topo_edges = []

    # Only show attackers that are currently active — remove them when attack ends
    _topo_now = _time.time()
    _active_attacker_ips = {
        inc.get("source_ip", "")
        for inc in sniffer.incidents.values()
        if inc.get("status") in ("OPEN", "ACTIVE")
    }

    for _ip, _atk in sorted(
        sniffer.top_attackers.items(),
        key=lambda x: x[1].get("severity_score", 0), reverse=True
    )[:8]:
        _sc = _atk.get("severity_score", 0)
        if _sc < 5:
            continue
        # Skip if attack resolved and last seen > 30 seconds ago
        _last_seen = _atk.get("last_seen_epoch", 0)
        if _ip not in _active_attacker_ips and (_topo_now - _last_seen) > 30:
            continue
        _sev = "HIGH" if _sc > 60 else "MEDIUM"
        topo_nodes.append({
            "id": _ip, "ip": _ip, "type": "attacker",
            "label": _ip, "severity": _sev,
            "name": _atk.get("country", "") or _atk.get("attack_type", ""),
            "attack_type": _atk.get("attack_type", ""),
            "packets": _atk.get("packet_count", 0),
        })
        topo_edges.append({"from": _ip, "to": "host", "severity": _sev})
    for _ip, _dev in list(sniffer.discovered_devices.items())[:16]:
        if any(n["id"] == _ip for n in topo_nodes):
            continue
        # Skip multicast (224-239.x.x.x), link-local (169.254.x.x), broadcast
        try:
            _first = int(_ip.split(".")[0])
            if 224 <= _first <= 239: continue
            if _first == 255: continue
            if _ip.startswith("169.254."): continue
        except Exception:
            continue
        _hn  = _dev.get("hostname", "")
        _ven = _dev.get("vendor", "")
        _lbl = (
            _hn  if _hn  and _hn  != _ip and _hn  not in ("Unknown", "unknown") else
            _ven if _ven and _ven not in ("Unknown", "unknown", "") else
            ""
        )[:18]
        topo_nodes.append({
            "id":     _ip, "ip": _ip, "type": "device",
            "label":  _lbl or _ip,
            "name":   _lbl,          # empty = no resolved name yet
            "vendor": _ven if _ven not in ("Unknown", "unknown", "", None) else "",
            "mac":    _dev.get("mac", ""),
        })
        topo_edges.append({"from": "host", "to": _ip, "severity": "NORMAL"})

    return jsonify({
        "arp_events":        arp_evts,
        "scan_events":       scan_evts,
        "port_heatmap":      port_heatmap,
        "hourly_heatmap":    hourly,
        "country_stats":     [
            {"country": c, "count": n, "percent": round(n / country_total * 100, 1),
             "attackers": country_attacker_counts.get(c, 0)}
            for c, n in top_countries
        ],
        "attack_map_events": list(reversed(list(sniffer.attack_map_events)))[:60],
        "public_ip_attacks": pub_ip_attacks,
        "threat_prediction": threat_prediction,
        "system_status":     system_status,
        "incidents_list":    incidents_list,
        "kill_chain":        kill_chain,
        "topology":          {"nodes": topo_nodes, "edges": topo_edges},
        "timestamp":         datetime.now().strftime("%I:%M:%S %p"),
    })


# ── Enhancement Layers API ────────────────────────────────────────────────────

@main_bp.route("/api/layers/visibility")
@login_required
def api_layers_visibility():
    """GET /api/layers/visibility — interface health and capture coverage status."""
    return jsonify(layers.get_visibility())


@main_bp.route("/api/layers/flows")
@login_required
def api_layers_flows():
    """GET /api/layers/flows?limit=<n> — top flows sorted by packet count."""
    try:
        limit = min(int(request.args.get("limit", 50)), 500)
    except (ValueError, TypeError):
        limit = 50
    return jsonify({
        "flows":     layers.get_flow_stats(limit),
        "timestamp": datetime.now().strftime("%I:%M:%S %p"),
    })


@main_bp.route("/api/layers/session")
@login_required
def api_layers_session():
    """GET /api/layers/session — live capture session stats (Wireshark-style)."""
    return jsonify(layers.get_session())


@main_bp.route("/api/layers/risk/<ip>")
@login_required
def api_layers_risk(ip: str):
    """GET /api/layers/risk/<ip> — per-IP flow data from the enhancement layer."""
    return jsonify({
        "ip":        ip,
        "flows":     layers.get_src_flows(ip),
        "timestamp": datetime.now().strftime("%I:%M:%S %p"),
    })


# ── Network Sensor / Visibility API ──────────────────────────────────────────

@main_bp.route("/api/sensor/status")
@login_required
def api_sensor_status():
    """
    GET /api/sensor/status — full visibility status.

    Returns topology assessment (is this host a gateway? SPAN detected?),
    remote agent list, receiver port, and visibility score (0-100).
    """
    return jsonify(network_sensor.get_full_status())


@main_bp.route("/api/sensor/topology")
@login_required
def api_sensor_topology():
    """
    GET /api/sensor/topology — current network topology assessment.

    Explains why traffic may not be visible and what the current capture
    mode is (HOST_IDS / PARTIAL_IDS / NETWORK_IDS).
    """
    return jsonify(network_sensor.assess_topology())


@main_bp.route("/api/sensor/guidance")
@login_required
def api_sensor_guidance():
    """
    GET /api/sensor/guidance — prioritised, topology-aware guidance.

    Returns ordered list of solutions (SPAN port, ICS gateway, bridge mode,
    distributed agents, TAP) with step-by-step instructions for each,
    filtered and annotated based on this machine's current topology.
    """
    return jsonify(network_sensor.get_guidance())


@main_bp.route("/api/sensor/span")
@login_required
def api_sensor_span():
    """
    GET /api/sensor/span?refresh=1 — SPAN/mirror port detection result.

    Checks whether this NIC is receiving frames for other MAC addresses,
    which indicates an active switch mirror/SPAN port.
    Add ?refresh=1 to trigger a fresh 2-second background probe.
    """
    force = request.args.get("refresh", "0") == "1"
    return jsonify(network_sensor.get_span_status(force=force))


@main_bp.route("/api/sensor/passive-map")
@login_required
def api_sensor_passive_map():
    """
    GET /api/sensor/passive-map — all devices seen via broadcast traffic.

    ARP, DHCP, mDNS broadcasts are flooded to all switch ports and are
    always visible regardless of SPAN configuration. This map shows every
    device that has sent a broadcast frame since the sniffer started.
    """
    devices = network_sensor.get_passive_map()
    return jsonify({
        "devices":   devices,
        "count":     len(devices),
        "note":      (
            "Devices discovered via broadcast traffic (ARP/DHCP/mDNS). "
            "These are visible on ALL switched networks without SPAN or gateway mode."
        ),
        "timestamp": datetime.now().strftime("%I:%M:%S %p"),
    })


@main_bp.route("/api/sensor/agents")
@login_required
def api_sensor_agents():
    """
    GET /api/sensor/agents — connected remote sensor agents.

    Shows all machines running remote_agent.py and reporting to this SOC.
    Status ACTIVE = reported within last 30 s; STALE = silent longer.
    """
    return jsonify({
        "agents":    network_sensor.get_agent_status(),
        "receiver_port": network_sensor.RECEIVER_PORT,
        "deploy_cmd": (
            f"python remote_agent.py "
            f"--soc-ip <THIS_IP> --soc-port {network_sensor.RECEIVER_PORT}"
        ),
        "timestamp": datetime.now().strftime("%I:%M:%S %p"),
    })


@main_bp.route("/api/targets")
@login_required
def api_targets():
    """
    GET /api/targets — devices on the network that are (or have been) under attack.

    Each entry is a victim IP that detection.record_dst_packet() has flagged as
    receiving flood, DDoS, or port-scan traffic.  Populated only when traffic to
    that destination is physically visible to this sensor (requires SPAN port,
    gateway mode, or bridge mode for other-device traffic).

    Fields per entry:
      ip, country, attack_type, severity_score, packet_count,
      attacker_count, last_seen
    """
    def _clean(t: dict) -> dict:
        return {k: v for k, v in t.items() if not k.startswith("_")}

    targets = sorted(
        sniffer.attacked_targets.values(),
        key=lambda t: t.get("severity_score", 0),
        reverse=True,
    )
    active_target_ips = {
        inc["target_ip"]
        for inc in sniffer.target_incidents.values()
        if inc.get("status") in ("OPEN", "ACTIVE")
    }
    return jsonify({
        "targets":         [_clean(t) for t in targets],
        "count":           len(targets),
        "active_count":    len(active_target_ips),
        "active_ips":      sorted(active_target_ips),
        "timestamp":       datetime.now().strftime("%I:%M:%S %p"),
    })


@main_bp.route("/api/target-incidents")
@login_required
def api_target_incidents():
    """
    GET /api/target-incidents — incidents where a network device is the victim.

    Complements /alerts (which is attacker-keyed).  These incidents are keyed
    by the destination IP so the dashboard can answer "who is being attacked?"
    rather than only "who is attacking?".

    Supports ?status=OPEN|ACTIVE|RESOLVED for filtering.
    """
    status_filter = (request.args.get("status") or "").strip().upper()
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except (ValueError, TypeError):
        limit = 100

    incs = list(sniffer.target_incidents.values())
    if status_filter in ("OPEN", "ACTIVE", "RESOLVED"):
        incs = [i for i in incs if i.get("status") == status_filter]

    incs_sorted = sorted(incs, key=lambda i: i.get("start_epoch", 0), reverse=True)[:limit]
    active = sum(1 for i in sniffer.target_incidents.values()
                 if i.get("status") in ("OPEN", "ACTIVE"))
    return jsonify({
        "incidents":    incs_sorted,
        "count":        len(incs_sorted),
        "total":        len(sniffer.target_incidents),
        "active":       active,
        "timestamp":    datetime.now().strftime("%I:%M:%S %p"),
    })


@main_bp.route("/api/sensor/remote-events")
@login_required
def api_sensor_remote_events():
    """
    GET /api/sensor/remote-events?limit=<n> — recent events from remote agents.

    Each entry is a full agent report: packet counts, protocol breakdown,
    and per-IP severity alerts using the same thresholds as the central SOC.
    """
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except (ValueError, TypeError):
        limit = 100
    events = network_sensor.get_remote_events(limit)
    return jsonify({
        "events":    events,
        "count":     len(events),
        "timestamp": datetime.now().strftime("%I:%M:%S %p"),
    })
