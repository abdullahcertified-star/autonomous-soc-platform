"""
mitre_bp.py — MITRE ATT&CK Mapping API Blueprint

Routes:
  GET /mitre                   — UI page
  GET /api/mitre/summary       — tactic/technique counts from live alerts + rules
  GET /api/mitre/rules         — list CorrelationRule rows
  PATCH /api/mitre/rules/<id>  — enable/disable a rule
"""
from collections import defaultdict

from flask import Blueprint, jsonify, request, render_template, abort
from flask_login import login_required, current_user

from rbac import require_permission, audit

mitre_bp = Blueprint('mitre', __name__)


@mitre_bp.route('/mitre')
@login_required
def mitre_page():
    if not current_user.can('mitre', 'read'):
        abort(403)
    return render_template('mitre.html')


@mitre_bp.route('/api/mitre/summary')
@login_required
@require_permission('mitre', 'read')
def mitre_summary():
    tactic_map = defaultdict(lambda: defaultdict(int))

    try:
        from detection import sniffer
        from detection.correlation import map_mitre
        for alert in list(sniffer.alerts):
            atype = alert.get('attack_type') or alert.get('type', '')
            m = map_mitre(atype)
            if m['mitre_tactic']:
                key = (m['mitre_technique'], m['mitre_tech_name'])
                tactic_map[m['mitre_tactic']][key] += 1
    except Exception:
        pass

    try:
        from detection import beaconing
        from detection.correlation import map_mitre
        for ev in list(beaconing.beaconing_events):
            m = map_mitre(ev.get('attack_type', ''))
            if m['mitre_tactic']:
                key = (m['mitre_technique'], m['mitre_tech_name'])
                tactic_map[m['mitre_tactic']][key] += 1
        for ev in list(beaconing.lateral_events):
            m = map_mitre(ev.get('attack_type', ''))
            if m['mitre_tactic']:
                key = (m['mitre_technique'], m['mitre_tech_name'])
                tactic_map[m['mitre_tactic']][key] += 1
    except Exception:
        pass

    tactics = []
    for tactic, tech_dict in sorted(tactic_map.items()):
        techniques = [
            {'id': tid, 'name': tname, 'count': cnt}
            for (tid, tname), cnt in sorted(tech_dict.items(), key=lambda x: -x[1])
        ]
        tactics.append({'tactic': tactic, 'techniques': techniques})

    fired_rules = []
    try:
        from models import CorrelationRule
        rules = CorrelationRule.query.filter(CorrelationRule.fire_count > 0)\
                                     .order_by(CorrelationRule.last_fired.desc())\
                                     .limit(10).all()
        fired_rules = [r.to_dict() for r in rules]
    except Exception:
        pass

    return jsonify({'tactics': tactics, 'fired_rules': fired_rules})


@mitre_bp.route('/api/mitre/rules')
@login_required
@require_permission('mitre', 'read')
def list_rules():
    try:
        from models import CorrelationRule
        rules = CorrelationRule.query.order_by(CorrelationRule.created_at.asc()).all()
        return jsonify([r.to_dict() for r in rules])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@mitre_bp.route('/api/mitre/rules/<int:rule_id>', methods=['PATCH'])
@login_required
@require_permission('mitre', 'write')
def update_rule(rule_id):
    try:
        from models import CorrelationRule
        from extensions import db
        rule = CorrelationRule.query.get_or_404(rule_id)
        data = request.get_json(silent=True) or {}
        if 'enabled' in data:
            rule.enabled = bool(data['enabled'])
        db.session.commit()
        audit('toggle_rule', rule.name, str(rule.enabled))
        return jsonify(rule.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500
