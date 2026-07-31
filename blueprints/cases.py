"""
cases_bp.py — SOC Case Management Blueprint

Routes:
  GET  /cases                       — case list UI
  GET  /cases/trash                 — recycle bin UI
  GET  /api/cases                   — JSON list (filters: status, severity, assigned_to)
  POST /api/cases                   — create new case
  GET  /api/cases/<id>              — single case detail + notes
  PATCH /api/cases/<id>             — update status/severity/assignment/fields
  DELETE /api/cases/<id>            — soft-delete → recycle bin
  GET  /api/cases/trash             — list soft-deleted cases
  POST /api/cases/<id>/restore      — restore from recycle bin
  DELETE /api/cases/<id>/permanent  — permanently delete from recycle bin
  POST /api/cases/<id>/notes        — add note
  GET  /api/cases/stats             — summary counters
"""
import uuid
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request, render_template, abort
from flask_login import login_required, current_user

from extensions import db
from models import Case, CaseNote, User
from rbac import require_permission, audit

cases_bp = Blueprint('cases', __name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _new_case_id() -> str:
    return f"CASE-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"


def _default_sla(severity: str) -> datetime:
    hours = {'CRITICAL': 1, 'HIGH': 4, 'MEDIUM': 24, 'LOW': 72}.get(severity, 24)
    return datetime.utcnow() + timedelta(hours=hours)


# ── UI Routes ─────────────────────────────────────────────────────────────────

@cases_bp.route('/cases')
@login_required
def cases_page():
    if not current_user.can('cases', 'read'):
        abort(403)
    analysts = User.query.filter(User.role.in_(['analyst', 'admin'])).all()
    return render_template('cases.html', analysts=analysts)


@cases_bp.route('/cases/trash')
@login_required
def trash_page():
    if not current_user.can('cases', 'read'):
        abort(403)
    return render_template('trash.html')


# ── API: list / create ────────────────────────────────────────────────────────

@cases_bp.route('/api/cases', methods=['GET'])
@login_required
@require_permission('cases', 'read')
def list_cases():
    q = Case.query.filter(Case.deleted != True)
    if s := request.args.get('status'):
        q = q.filter_by(status=s.upper())
    if sev := request.args.get('severity'):
        q = q.filter_by(severity=sev.upper())
    if asgn := request.args.get('assigned_to'):
        u = User.query.filter_by(username=asgn).first()
        q = q.filter_by(assigned_to_id=u.id if u else -1)
    limit  = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    cases  = q.order_by(Case.created_at.desc()).offset(offset).limit(limit).all()
    return jsonify([c.to_dict() for c in cases])


@cases_bp.route('/api/cases', methods=['POST'])
@login_required
@require_permission('cases', 'write')
def create_case():
    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title is required'}), 400

    severity = (data.get('severity') or 'MEDIUM').upper()
    assigned_to_id = None
    if asgn := data.get('assigned_to'):
        u = User.query.filter_by(username=asgn).first()
        if u:
            assigned_to_id = u.id

    case = Case(
        case_id        = _new_case_id(),
        title          = title,
        description    = data.get('description', ''),
        severity       = severity,
        status         = 'OPEN',
        source         = data.get('source', 'manual'),
        incident_ref   = data.get('incident_ref'),
        src_ip         = data.get('src_ip'),
        attack_type    = data.get('attack_type'),
        mitre_tactic   = data.get('mitre_tactic'),
        mitre_technique= data.get('mitre_technique'),
        created_by_id  = current_user.id,
        assigned_to_id = assigned_to_id,
        sla_deadline   = _default_sla(severity),
    )
    db.session.add(case)
    db.session.commit()
    audit('create_case', case.case_id, title)
    return jsonify(case.to_dict()), 201


# ── API: single case ──────────────────────────────────────────────────────────

@cases_bp.route('/api/cases/<int:case_db_id>', methods=['GET'])
@login_required
@require_permission('cases', 'read')
def get_case(case_db_id):
    case = Case.query.get_or_404(case_db_id)
    data = case.to_dict()
    data['notes'] = [n.to_dict() for n in case.notes.order_by(CaseNote.created_at.asc()).all()]
    return jsonify(data)


@cases_bp.route('/api/cases/<int:case_db_id>', methods=['PATCH'])
@login_required
@require_permission('cases', 'write')
def update_case(case_db_id):
    case = Case.query.get_or_404(case_db_id)
    data = request.get_json(silent=True) or {}

    if 'status' in data:
        new_status = data['status'].upper()
        if new_status not in ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'):
            return jsonify({'error': 'invalid status'}), 400
        if new_status in ('RESOLVED', 'CLOSED') and not case.resolved_at:
            case.resolved_at = datetime.utcnow()
        case.status = new_status

    if 'severity' in data:
        case.severity = data['severity'].upper()

    if 'title' in data:
        case.title = data['title'].strip() or case.title

    if 'description' in data:
        case.description = data['description']

    if 'assigned_to' in data:
        if data['assigned_to']:
            u = User.query.filter_by(username=data['assigned_to']).first()
            case.assigned_to_id = u.id if u else case.assigned_to_id
        else:
            case.assigned_to_id = None

    case.updated_at = datetime.utcnow()
    db.session.commit()
    audit('update_case', case.case_id, str(data))
    return jsonify(case.to_dict())


@cases_bp.route('/api/cases/<int:case_db_id>', methods=['DELETE'])
@login_required
@require_permission('cases', 'delete')
def delete_case(case_db_id):
    case = Case.query.get_or_404(case_db_id)
    if case.deleted:
        return jsonify({'error': 'Case is already in the recycle bin'}), 400
    cid = case.case_id
    case.deleted    = True
    case.deleted_at = datetime.utcnow()
    case.deleted_by = current_user.username
    db.session.commit()
    audit('soft_delete_case', cid)
    return jsonify({'ok': True, 'moved_to_trash': cid})


# ── API: recycle bin ──────────────────────────────────────────────────────────

@cases_bp.route('/api/cases/trash', methods=['GET'])
@login_required
@require_permission('cases', 'read')
def list_trash():
    cases = Case.query.filter(Case.deleted == True).order_by(Case.deleted_at.desc()).all()
    return jsonify([c.to_dict() for c in cases])


@cases_bp.route('/api/cases/<int:case_db_id>/restore', methods=['POST'])
@login_required
@require_permission('cases', 'write')
def restore_case(case_db_id):
    case = Case.query.get_or_404(case_db_id)
    if not case.deleted:
        return jsonify({'error': 'Case is not in the recycle bin'}), 400
    case.deleted    = False
    case.deleted_at = None
    case.deleted_by = None
    case.updated_at = datetime.utcnow()
    db.session.commit()
    audit('restore_case', case.case_id)
    return jsonify({'ok': True, 'restored': case.case_id})


@cases_bp.route('/api/cases/<int:case_db_id>/permanent', methods=['DELETE'])
@login_required
@require_permission('cases', 'delete')
def permanent_delete(case_db_id):
    case = Case.query.get_or_404(case_db_id)
    cid  = case.case_id
    db.session.delete(case)
    db.session.commit()
    audit('permanent_delete_case', cid)
    return jsonify({'ok': True, 'permanently_deleted': cid})


# ── API: notes ────────────────────────────────────────────────────────────────

@cases_bp.route('/api/cases/<int:case_db_id>/notes', methods=['POST'])
@login_required
@require_permission('cases', 'write')
def add_note(case_db_id):
    case = Case.query.get_or_404(case_db_id)
    data = request.get_json(silent=True) or {}
    body = (data.get('body') or '').strip()
    if not body:
        return jsonify({'error': 'body is required'}), 400

    note_type = data.get('note_type', 'comment')
    if note_type not in ('comment', 'action', 'escalation', 'resolution'):
        note_type = 'comment'

    note = CaseNote(
        case_id   = case.id,
        author_id = current_user.id,
        body      = body,
        note_type = note_type,
    )
    db.session.add(note)

    # Auto-progress status
    if case.status == 'OPEN':
        case.status = 'IN_PROGRESS'
        case.updated_at = datetime.utcnow()

    db.session.commit()
    return jsonify(note.to_dict()), 201


# ── API: stats ────────────────────────────────────────────────────────────────

@cases_bp.route('/api/cases/stats')
@login_required
@require_permission('cases', 'read')
def case_stats():
    live     = Case.query.filter(Case.deleted != True)
    total    = live.count()
    open_    = live.filter_by(status='OPEN').count()
    inprog   = live.filter_by(status='IN_PROGRESS').count()
    resolved = live.filter_by(status='RESOLVED').count()
    closed   = live.filter_by(status='CLOSED').count()
    critical = live.filter_by(severity='CRITICAL').filter(
                   Case.status.notin_(['RESOLVED', 'CLOSED'])).count()
    breached = sum(1 for c in Case.query.filter(Case.deleted != True).filter(
                   Case.status.notin_(['RESOLVED', 'CLOSED'])).all()
                   if c.sla_breached)
    trashed  = Case.query.filter(Case.deleted == True).count()
    return jsonify({
        'total': total, 'open': open_, 'in_progress': inprog,
        'resolved': resolved, 'closed': closed,
        'critical_active': critical, 'sla_breached': breached,
        'trashed': trashed,
    })
