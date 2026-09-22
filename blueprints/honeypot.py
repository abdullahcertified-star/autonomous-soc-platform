"""
honeypot_bp.py — Honeypot API for the SOC platform

The honeypot trap runs as a standalone server (honeypot_server.py, port 5001).
This blueprint only exposes the read API so the SOC reports page can display hits.

  GET /api/honeypot-log  →  last 500 HONEYPOT events from shared logs.json
"""
from flask import Blueprint, jsonify
from rbac import require_permission

from core.database import get_logs

honeypot_bp = Blueprint("honeypot", __name__)


@honeypot_bp.route("/api/honeypot-log")
@require_permission("honeypot", "read")
def api_honeypot_log():
    all_logs = get_logs()
    honeypot = [e for e in all_logs if e.get("type") == "HONEYPOT"]
    honeypot.reverse()          # newest first
    return jsonify({"log": honeypot[:500], "total": len(honeypot)})
