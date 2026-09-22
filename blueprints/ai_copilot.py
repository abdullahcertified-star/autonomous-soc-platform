"""
blueprints/ai_copilot.py — AI SOC Analyst Copilot REST API

Routes:
  POST /api/ai/chat            — Interactive analyst chat with autonomous tool calling
  GET  /api/ai/status          — Agent health, model (Gemini 2.5 vs Heuristic), tools
  GET  /api/ai/investigations  — Recent autonomous alert investigations
  POST /api/ai/investigate     — Quick one-click automated investigation for an IP
"""
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from core import ai_agent
from rbac import audit

ai_copilot_bp = Blueprint('ai_copilot', __name__)


@ai_copilot_bp.route('/api/ai/status', methods=['GET'])
@login_required
def get_status():
    """Returns AI Agent status, active model, and tool capability list."""
    try:
        status = ai_agent.get_agent_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@ai_copilot_bp.route('/api/ai/chat', methods=['POST'])
@login_required
def chat():
    """Primary conversational endpoint with function/tool execution."""
    data = request.get_json(silent=True) or {}
    prompt = (data.get("prompt") or "").strip()
    history = data.get("history") or []

    if not prompt:
        return jsonify({"ok": False, "error": "Prompt cannot be empty"}), 400

    try:
        result = ai_agent.chat(prompt, history=history)
        audit("ai_copilot_query", current_user.username, prompt[:80])
        return jsonify({
            "ok": True,
            "response": result.get("response", ""),
            "tool_calls": result.get("tool_calls", []),
            "model": result.get("model", "unknown"),
            "warning": result.get("warning")
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@ai_copilot_bp.route('/api/ai/investigations', methods=['GET'])
@login_required
def get_investigations():
    """Returns recent autonomous correlation & attack investigations."""
    try:
        limit = int(request.args.get('limit', 20))
        investigations = ai_agent.get_recent_investigations(limit=limit)
        return jsonify({"ok": True, "investigations": investigations})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@ai_copilot_bp.route('/api/ai/investigate', methods=['POST'])
@login_required
def investigate_ip():
    """One-click autonomous investigation of a target IP."""
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "IP is required"}), 400

    try:
        prompt = f"Run a comprehensive security investigation on IP {ip}. Check threat intelligence, packet volume, incidents, and firewall status."
        result = ai_agent.chat(prompt)
        return jsonify({
            "ok": True,
            "ip": ip,
            "response": result.get("response", ""),
            "tool_calls": result.get("tool_calls", []),
            "model": result.get("model", "unknown")
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
