"""
analytics_bp.py — Analytics Blueprint: Logs & Top Attackers
"""
from flask import Blueprint, render_template, jsonify, request, abort
from flask_login import login_required, current_user
from detection import sniffer
from core import firewall as fw
from core.database import (get_logs, get_trash, soft_delete_log, restore_log,
                      permanent_delete_log, trash_count)
from rbac import require_permission
from core import soc_logger

analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/attackers")
@login_required
def top_attackers_page():
    if not current_user.can('logs', 'read'):
        abort(403)
    return render_template("top_attackers.html")


@analytics_bp.route("/logs")
@login_required
def logs_page():
    if not current_user.can('logs', 'read'):
        abort(403)
    return render_template("logs.html")


@analytics_bp.route("/logs/trash")
@login_required
def logs_trash_page():
    if not current_user.can('logs', 'read'):
        abort(403)
    return render_template("logs_trash.html")


@analytics_bp.route("/api/top-attackers")
@login_required
@require_permission('logs', 'read')
def api_top_attackers():
    attackers = [dict(a) for a in sniffer.top_attackers.values()]
    for a in attackers:
        a["blocked"] = fw.is_blocked(a["ip"])
    attackers.sort(key=lambda x: x.get("severity_score", 0), reverse=True)
    return jsonify({"attackers": attackers[:10]})


@analytics_bp.route("/api/logs")
@login_required
@require_permission('logs', 'read')
def api_logs():
    severity   = request.args.get("severity", "ALL").upper()
    ip_filter  = request.args.get("ip", "").strip()
    event_type = request.args.get("type", "ALL").upper()

    logs = get_logs()

    if severity != "ALL":
        logs = [l for l in logs if (l.get("severity") or "").upper() == severity]
    if ip_filter:
        logs = [l for l in logs if ip_filter in (l.get("ip") or "")]
    if event_type != "ALL":
        logs = [l for l in logs if (l.get("type") or "ALERT").upper() == event_type]

    logs = list(reversed(logs))
    return jsonify({"logs": logs[:300], "total": len(logs), "trash_count": trash_count()})


# ── Log soft-delete ───────────────────────────────────────────────────────────

@analytics_bp.route("/api/logs/<log_id>", methods=["DELETE"])
@login_required
@require_permission('logs', 'delete')
def api_delete_log(log_id):
    if soft_delete_log(log_id):
        return jsonify({"ok": True})
    return jsonify({"error": "Log entry not found"}), 404


# ── Trash endpoints ───────────────────────────────────────────────────────────

@analytics_bp.route("/api/logs/trash", methods=["GET"])
@login_required
@require_permission('logs', 'read')
def api_logs_trash():
    return jsonify({"logs": get_trash()})


@analytics_bp.route("/api/logs/trash/<log_id>/restore", methods=["POST"])
@login_required
@require_permission('logs', 'write')
def api_restore_log(log_id):
    if restore_log(log_id):
        return jsonify({"ok": True})
    return jsonify({"error": "Log entry not found in trash"}), 404


@analytics_bp.route("/api/logs/trash/<log_id>", methods=["DELETE"])
@login_required
@require_permission('logs', 'delete')
def api_permanent_delete_log(log_id):
    if permanent_delete_log(log_id):
        return jsonify({"ok": True})
    return jsonify({"error": "Log entry not found in trash"}), 404


@analytics_bp.route("/api/soc-log-feed")
@login_required
@require_permission('logs', 'read')
def api_soc_log_feed():
    """Return last N entries from the SOC platform's internal logger (soc_logger)."""
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except (ValueError, TypeError):
        limit = 50
    return jsonify({"logs": soc_logger.get_recent(limit)})
