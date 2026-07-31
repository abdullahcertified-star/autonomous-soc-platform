"""
threat_intel_bp.py — Threat Intelligence API Blueprint

Routes:
  GET /threat-intel              — UI page
  GET /api/threat-intel/stats    — engine stats
  GET /api/threat-intel/check    — IP lookup (?ip=...)
  POST /api/threat-intel/ioc     — add IOC
  GET /api/threat-intel/iocs     — list DB IOCs
"""
from flask import Blueprint, jsonify, request, render_template, abort
from flask_login import login_required, current_user

from rbac import require_permission, audit

threat_intel_bp = Blueprint('threat_intel', __name__)


@threat_intel_bp.route('/threat-intel')
@login_required
def threat_intel_page():
    if not current_user.can('threat_intel', 'read'):
        abort(403)
    return render_template('threat_intel.html')


@threat_intel_bp.route('/api/threat-intel/stats')
@login_required
@require_permission('threat_intel', 'read')
def ti_stats():
    try:
        from reporting import threat_intel
        return jsonify(threat_intel.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_intel_bp.route('/api/threat-intel/check')
@login_required
@require_permission('threat_intel', 'read')
def ti_check():
    ip = (request.args.get('ip') or '').strip()
    if not ip:
        return jsonify({'error': 'ip parameter required'}), 400
    try:
        from reporting import threat_intel
        result = threat_intel.check_ip(ip)
        return jsonify({'ip': ip, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_intel_bp.route('/api/threat-intel/ioc', methods=['POST'])
@login_required
@require_permission('threat_intel', 'write')
def add_ioc():
    data = request.get_json(silent=True) or {}
    ioc_type    = data.get('ioc_type', 'ip')
    value       = (data.get('value') or '').strip()
    if not value:
        return jsonify({'error': 'value is required'}), 400
    try:
        from reporting import threat_intel
        ok = threat_intel.add_ioc(
            ioc_type    = ioc_type,
            value       = value,
            source      = data.get('source', 'manual'),
            confidence  = int(data.get('confidence', 80)),
            threat_type = data.get('threat_type', ''),
            description = data.get('description', ''),
        )
        audit('add_ioc', value, ioc_type)
        return jsonify({'ok': ok, 'value': value})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_intel_bp.route('/api/threat-intel/iocs')
@login_required
@require_permission('threat_intel', 'read')
def list_iocs():
    try:
        from models import IOCEntry
        entries = IOCEntry.query.filter_by(active=True)\
                                .order_by(IOCEntry.last_seen.desc())\
                                .limit(500).all()
        return jsonify([e.to_dict() for e in entries])
    except Exception as e:
        return jsonify({'error': str(e)}), 500
