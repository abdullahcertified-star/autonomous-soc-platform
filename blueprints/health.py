"""
health_bp.py — Health Check & Metrics Endpoints

Routes:
  GET /health          — liveness probe (no auth required)
  GET /api/metrics     — system metrics (requires login)
  GET /api/status      — quick status dict for nav badges
"""
import time
import platform
from datetime import datetime

from flask import Blueprint, jsonify
from flask_login import login_required

health_bp = Blueprint('health', __name__)

_START_TIME = time.time()


@health_bp.route('/health')
def health_check():
    """Liveness probe — returns 200 if the app is running."""
    return jsonify({
        'status':    'ok',
        'timestamp': datetime.utcnow().isoformat(),
        'uptime_s':  round(time.time() - _START_TIME),
    })


@health_bp.route('/api/metrics')
@login_required
def metrics():
    """Aggregated platform metrics for dashboards."""
    try:
        from detection import sniffer
        sniffer_stats = {
            'total_packets':   sniffer.network_stats.get('total_packets', 0),
            'active_conns':    len(sniffer.network_stats.get('active_connections', set())),
            'alerts_count':    len(sniffer.alerts),
            'incidents_count': len(sniffer.incidents),
            'pps':             sniffer.network_stats.get('pps', 0),
        }
    except Exception:
        sniffer_stats = {}

    try:
        from detection import beaconing
        beaconing_stats = beaconing.get_summary()
    except Exception:
        beaconing_stats = {}

    try:
        from reporting import threat_intel
        ti_stats = threat_intel.get_stats()
    except Exception:
        ti_stats = {}

    try:
        from models import Case, CorrelationRule, IOCEntry
        db_stats = {
            'cases_total':   Case.query.count(),
            'cases_open':    Case.query.filter_by(status='OPEN').count(),
            'rules_enabled': CorrelationRule.query.filter_by(enabled=True).count(),
            'iocs_total':    IOCEntry.query.filter_by(active=True).count(),
        }
    except Exception:
        db_stats = {}

    return jsonify({
        'uptime_s':   round(time.time() - _START_TIME),
        'platform':   platform.system(),
        'python':     platform.python_version(),
        'sniffer':    sniffer_stats,
        'beaconing':  beaconing_stats,
        'threat_intel': ti_stats,
        'database':   db_stats,
        'timestamp':  datetime.utcnow().isoformat(),
    })


@health_bp.route('/api/status')
@login_required
def quick_status():
    """Lightweight status for nav badges — called frequently."""
    try:
        from models import Case
        open_cases = Case.query.filter_by(status='OPEN').count()
        breached   = sum(1 for c in Case.query.filter(
                         Case.status.notin_(['RESOLVED', 'CLOSED'])).all()
                         if c.sla_breached)
    except Exception:
        open_cases = 0
        breached   = 0

    try:
        from detection import sniffer
        active_incidents = [
            inc for inc in list(sniffer.incidents.values()) + list(getattr(sniffer, "target_incidents", {}).values())
            if inc.get("status") in ("OPEN", "ACTIVE")
        ]
        under_attack = len(active_incidents) > 0 or bool(getattr(sniffer, 'network_stats', {}).get('under_attack'))
        incidents    = len(active_incidents)
    except Exception:
        under_attack = False
        incidents    = 0

    return jsonify({
        'open_cases':   open_cases,
        'sla_breached': breached,
        'under_attack': under_attack,
        'incidents':    incidents,
    })
