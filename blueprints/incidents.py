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
    all_incs = list(sniffer.incidents.values())
    seen_ids = {i.get("id") for i in all_incs if i.get("id")}
    for tinc in sniffer.target_incidents.values():
        if tinc.get("id") not in seen_ids:
            all_incs.append(tinc)
            if tinc.get("id"):
                seen_ids.add(tinc.get("id"))

    all_incs.sort(key=lambda x: x.get("severity_score", 0), reverse=True)
    open_count = sum(1 for i in all_incs if i.get("status") in ("OPEN", "ACTIVE"))
    resolved_count = sum(1 for i in all_incs if i.get("status") == "RESOLVED")
    return jsonify({
        "incidents": all_incs,
        "open_count": open_count,
        "resolved_count": resolved_count,
        "total": len(all_incs),
    })
