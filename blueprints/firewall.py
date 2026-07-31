"""
firewall_bp.py — Firewall Management Blueprint

Existing routes preserved exactly; new routes added below the originals.
"""
from flask import Blueprint, render_template, jsonify, request, abort
from flask_login import login_required, current_user
from rbac import require_permission
from core import firewall
from core import protection_settings

firewall_bp = Blueprint("firewall", __name__)


# ── Existing routes (unchanged) ───────────────────────────────────────────────

@firewall_bp.route("/firewall")
@login_required
def firewall_page():
    if not current_user.can('firewall', 'read'):
        abort(403)
    return render_template("firewall.html")


@firewall_bp.route("/api/firewall", methods=["GET"])
@login_required
@require_permission('firewall', 'read')
def api_firewall_get():
    return jsonify({
        "blocked": firewall.get_blocked_list(),
        "history": firewall.get_block_history(50),
        "blocked_count": firewall.blocked_count(),
    })


@firewall_bp.route("/api/firewall/block", methods=["POST"])
@login_required
@require_permission('firewall', 'write')
def api_block():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    reason = (data.get("reason") or "Manual block").strip()
    duration = data.get("duration")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    kwargs = {"reason": reason, "auto": False}
    if duration is not None:
        try:
            kwargs["duration"] = int(duration)
        except (ValueError, TypeError):
            pass
    result = firewall.block_ip(ip, **kwargs)
    # Immediately resolve all incidents for the blocked IP so the dashboard
    # returns to SECURE without waiting for the latch/timeout to expire.
    try:
        from detection import sniffer as _sniffer
        _sniffer.resolve_incidents_for_ip(ip)
    except Exception:
        pass
    return jsonify(result)


@firewall_bp.route("/api/firewall/unblock", methods=["POST"])
@login_required
@require_permission('firewall', 'write')
def api_unblock():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    return jsonify(firewall.unblock_ip(ip))


@firewall_bp.route("/api/firewall/force-unblock", methods=["POST"])
@login_required
@require_permission('firewall', 'write')
def api_force_unblock():
    """Unblock an IP even if it has no in-memory record (e.g. blocked before restart)."""
    data = request.get_json(silent=True) or {}
    ip   = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    return jsonify(firewall.force_unblock(ip))


@firewall_bp.route("/api/firewall/distributed-ips")
@login_required
@require_permission('firewall', 'read')
def api_distributed_ips():
    """
    Return flood-only IPs from the distributed detection window.
    Filters: public IPs only, sent 3+ packets (normal servers send 1-2).
    """
    from detection import detection as _det
    data = _det.get_distributed_flood_ips(min_packets=3)
    return jsonify({
        "ips":         data["ips"],
        "count":       data["flood_count"],   # flood IPs only
        "total_seen":  data["all_count"],     # all unique IPs in window
        "ip_counts":   data["ip_counts"],
    })


@firewall_bp.route("/api/firewall/block-distributed", methods=["POST"])
@login_required
@require_permission('firewall', 'write')
def api_block_distributed():
    """
    Block genuine flood IPs — public IPs that sent 3+ packets in the flood window.
    Private IPs, gateway, whitelist are automatically excluded.
    """
    from detection import detection as _det
    from detection import sniffer as _sniffer
    data    = _det.get_distributed_flood_ips(min_packets=3)
    ips     = data["ips"]
    blocked = []
    skipped = []
    for ip in ips:
        result = firewall.block_ip(ip, reason="Distributed flood — auto block", auto=True)
        if result.get("status") == "blocked":
            blocked.append(ip)
            try:
                _sniffer.resolve_incidents_for_ip(ip)
            except Exception:
                pass
        else:
            skipped.append(ip)
    return jsonify({
        "blocked":    len(blocked),
        "skipped":    len(skipped),
        "total":      len(ips),
        "total_seen": data["all_count"],
    })


@firewall_bp.route("/api/firewall/whitelist", methods=["GET"])
@login_required
@require_permission('firewall', 'read')
def api_whitelist_get():
    return jsonify({"whitelist": firewall.get_whitelist()})


@firewall_bp.route("/api/firewall/whitelist/add", methods=["POST"])
@login_required
@require_permission('firewall', 'write')
def api_whitelist_add():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    firewall.add_whitelist(ip)
    return jsonify({"status": "added", "ip": ip})


@firewall_bp.route("/api/firewall/whitelist/remove", methods=["POST"])
@login_required
@require_permission('firewall', 'write')
def api_whitelist_remove():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    firewall.remove_whitelist(ip)
    return jsonify({"status": "removed", "ip": ip})


# ── New routes ─────────────────────────────────────────────────────────────────

@firewall_bp.route("/api/firewall/suspicious", methods=["GET"])
@login_required
@require_permission('firewall', 'read')
def api_suspicious():
    """Return the list of IPs currently marked as suspicious / attacking."""
    ips = firewall.get_suspicious_ips()
    return jsonify({"suspicious": ips, "count": len(ips)})


@firewall_bp.route("/api/firewall/block-suspicious", methods=["POST"])
@login_required
@require_permission('firewall', 'write')
def api_block_suspicious():
    """Block all currently suspicious IPs in one click."""
    data = request.get_json(silent=True) or {}
    duration = data.get("duration")
    kwargs = {}
    if duration is not None:
        try:
            kwargs["duration"] = int(duration)
        except (ValueError, TypeError):
            pass
    result = firewall.block_all_suspicious(**kwargs)
    return jsonify(result)


@firewall_bp.route("/api/firewall/arp-events", methods=["GET"])
@login_required
@require_permission('firewall', 'read')
def api_arp_events():
    """Return recent ARP spoofing / MITM detection events."""
    try:
        from detection import sniffer
        events = list(sniffer.arp_events)
    except Exception:
        events = []
    return jsonify({"arp_events": events, "count": len(events)})


@firewall_bp.route("/api/firewall/protection-settings", methods=["GET"])
@login_required
@require_permission('firewall', 'read')
def api_protection_settings_get():
    return jsonify({"settings": protection_settings.get_settings()})


@firewall_bp.route("/api/firewall/protection-settings", methods=["POST"])
@login_required
@require_permission('firewall', 'manage')
def api_protection_settings_post():
    data = request.get_json(silent=True) or {}
    updated = protection_settings.update_settings(data)
    return jsonify({"status": "ok", "settings": updated})


@firewall_bp.route("/api/firewall/stats", methods=["GET"])
@login_required
@require_permission('firewall', 'read')
def api_firewall_stats():
    """
    Comprehensive stats for the enhanced firewall dashboard:
    blocked count, suspicious count, ARP event count, flood alerts,
    protection settings.
    """
    try:
        from detection import sniffer
        susp_count = len(firewall.get_suspicious_ips())
        arp_count = len(sniffer.arp_events)
        pps = sniffer.network_stats.get("pps", 0)
        active_conns = len(sniffer.network_stats.get("active_connections", set()))
    except Exception:
        susp_count = arp_count = pps = active_conns = 0

    history = firewall.get_block_history(200)
    auto_blocked = sum(1 for h in history if h.get("auto") and h.get("action") == "BLOCKED")

    return jsonify({
        "blocked_count": firewall.blocked_count(),
        "suspicious_count": susp_count,
        "arp_event_count": arp_count,
        "auto_blocked": auto_blocked,
        "active_connections": active_conns,
        "pps": round(pps, 1),
        "settings": protection_settings.get_settings(),
    })
