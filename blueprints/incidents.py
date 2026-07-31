"""
incidents_bp.py — Incident Management Blueprint
"""
from flask import Blueprint, render_template, jsonify, abort
from flask_login import login_required, current_user
from rbac import require_permission
from detection import sniffer

incidents_bp = Blueprint("incidents", __name__)


@incidents_bp.route("/incidents")
@login_required
def incidents_page():
    if not current_user.can('incidents', 'read'):
        abort(403)
    return render_template("incidents.html")


@incidents_bp.route("/api/incidents")
@login_required
@require_permission('incidents', 'read')
def api_incidents():
    inc_list = list(sniffer.incidents.values())
    inc_list.sort(key=lambda x: x.get("severity_score", 0), reverse=True)
    open_count = sum(1 for i in inc_list if i["status"] in ("OPEN", "ACTIVE"))
    resolved_count = sum(1 for i in inc_list if i["status"] == "RESOLVED")
    return jsonify({
        "incidents": inc_list,
        "open_count": open_count,
        "resolved_count": resolved_count,
        "total": len(inc_list),
    })
