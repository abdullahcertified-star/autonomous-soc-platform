"""
settings_bp.py — Settings & Configuration Blueprint
"""
from flask import Blueprint, render_template, jsonify, request, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from rbac import require_permission
import json
import os
import random
import threading
import time
from detection import detection
from core import sim
from detection import sniffer
from core import firewall as fw
from detection import incident_manager
from core.database import clear_log
from utils import ts

settings_bp = Blueprint("settings", __name__)

_DETECTION_CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "detection", "detection_config.json")

_INT_FIELDS = [
    "time_window", "baseline_window", "confidence_threshold",
    "sustained_seconds", "cooldown_seconds",
    "low_threshold", "medium_threshold", "high_threshold",
]
_BOOL_FIELDS = ["enabled", "sim_mode"]


def _load_detection_config() -> None:
    try:
        with open(_DETECTION_CONFIG_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
        for field in _INT_FIELDS:
            if field in saved:
                try:
                    detection.config[field] = int(saved[field])
                except (ValueError, TypeError):
                    pass
        for field in _BOOL_FIELDS:
            if field in saved:
                detection.config[field] = bool(saved[field])
    except (FileNotFoundError, json.JSONDecodeError):
        pass


def _save_detection_config() -> None:
    to_save = {}
    for field in _INT_FIELDS:
        if field in detection.config:
            to_save[field] = detection.config[field]
    for field in _BOOL_FIELDS:
        if field in detection.config:
            to_save[field] = detection.config[field]
    with open(_DETECTION_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(to_save, f, indent=2)


# Load persisted settings immediately on import
_load_detection_config()


@settings_bp.route("/settings")
@login_required
def settings_page():
    if not current_user.can('settings', 'read'):
        abort(403)
    return render_template("settings.html")


@settings_bp.route("/api/settings", methods=["GET"])
@login_required
@require_permission('settings', 'read')
def api_settings_get():
    return jsonify({"config": dict(detection.config)})


@settings_bp.route("/api/settings", methods=["POST"])
@login_required
@require_permission('settings', 'write')
def api_settings_post():
    data = request.get_json(silent=True) or {}

    for f in _INT_FIELDS:
        if f in data:
            try:
                detection.config[f] = int(data[f])
            except (ValueError, TypeError):
                pass

    for f in _BOOL_FIELDS:
        if f in data:
            detection.config[f] = bool(data[f])

    _save_detection_config()
    return jsonify({"status": "ok", "config": dict(detection.config)})


@settings_bp.route("/api/reset", methods=["POST"])
@login_required
@require_permission('settings', 'write')
def api_reset():
    detection.reset_all()
    fw.reset_firewall()
    incident_manager.reset_all()
    sniffer.reset_state()
    clear_log()
    return jsonify({"status": "reset_ok"})


# ═════════════════════════════════════════════════════════════════════════════
# PRESENTATION DEMO MODE — injects fake attack data directly into sniffer state
# No Scapy / admin required. All detection, dashboard, incidents update live.
# ═════════════════════════════════════════════════════════════════════════════

_demo: dict = {"running": False, "end_time": 0.0, "thread": None}

_FAKE_ATTACKERS = [
    ("45.33.32.156",   "US"), ("198.20.69.74",  "CN"), ("66.240.205.34", "RU"),
    ("80.82.77.139",   "DE"), ("185.220.101.5", "NL"), ("91.108.4.1",    "GB"),
    ("103.25.206.4",   "IN"), ("194.165.16.75", "TR"),
]
_ATTACK_TYPES = ["SYN Flood", "UDP Flood", "ICMP Flood", "DDoS", "Port Scan"]


def _run_demo(duration: int, local_ip: str) -> None:
    sim.enable()          # suppress real OS firewall rules during demo
    start_f    = time.time()
    _inc_start = ts()

    # Pre-create incidents for each attacker
    for i, (ip, _) in enumerate(_FAKE_ATTACKERS):
        inc_id = f"DEMO-{i}"
        sniffer.incidents[inc_id] = {
            "incident_id":       inc_id,
            "source_ip":         ip,
            "start_time":        _inc_start,
            "end_time":          _inc_start,
            "start_epoch":       start_f,
            "last_update_epoch": start_f,
            "duration_seconds":  0,
            "duration":          "0s",
            "status":            "ACTIVE",
            "severity_score":    random.randint(80, 98),
            "attack_type":       _ATTACK_TYPES[i % len(_ATTACK_TYPES)],
            "packet_count":      0,
            "confidence":        random.randint(80, 95),
        }

    while _demo["running"] and time.time() - start_f < duration:
        now_ts = ts()
        now_f  = time.time()

        for i, (ip, country) in enumerate(_FAKE_ATTACKERS):
            rate       = random.randint(3000, 9000)
            severity   = "HIGH" if rate > 5900 else "MEDIUM"
            confidence = min(99, 60 + int(rate / 150))
            atype      = _ATTACK_TYPES[i % len(_ATTACK_TYPES)]
            sport      = random.randint(1024, 65535)
            dport      = random.choice([80, 443, 22, 3389, 53, 8080, 25])

            # Packet record
            sniffer.packets.append({
                "seq_id":     random.randint(10000, 99999),
                "time":       now_ts,
                "epoch":      now_f,
                "src":        ip,
                "dst":        local_ip,
                "src_mac":    "aa:bb:cc:dd:ee:ff",
                "proto":      atype.split()[0] if atype != "Port Scan" else "TCP",
                "src_port":   sport,
                "port":       dport,
                "tcp_flags":  "S" if "SYN" in atype else "",
                "rate":       rate,
                "severity":   severity,
                "confidence": confidence,
                "packets_5s": rate,
                "country":    country,
                "outbound":   False,
                "enhanced":   {},
            })

            # Alert
            sniffer.alerts.append({
                "time":       now_ts,
                "ip":         ip,
                "dst":        local_ip,
                "severity":   severity,
                "confidence": confidence,
                "msg":        f"{severity} {atype} — {rate} pkt/5s from {ip}",
            })

            # Update incident
            inc_id = f"DEMO-{i}"
            if inc_id in sniffer.incidents:
                inc = sniffer.incidents[inc_id]
                elapsed = int(now_f - inc["start_epoch"])
                inc["end_time"]          = now_ts
                inc["last_update_epoch"] = now_f
                inc["duration_seconds"]  = elapsed
                inc["duration"]          = f"{elapsed}s"
                inc["packet_count"]      = inc["packet_count"] + rate
                inc["severity_score"]    = max(inc["severity_score"], confidence)

            # Attack map (globe)
            sniffer.attack_map_events.append({
                "time":        now_ts,
                "epoch":       now_f,
                "src_ip":      ip,
                "dst_ip":      local_ip,
                "src_mac":     "aa:bb:cc:dd:ee:ff",
                "src_country": country,
                "dst_country": "PK",
                "attack_type": atype,
                "severity":    severity,
                "rate":        rate,
                "confidence":  confidence,
            })

            # Top attackers
            sniffer.top_attackers[ip] = {
                "ip":          ip,
                "country":     country,
                "rate":        rate,
                "confidence":  confidence,
                "attack_type": atype,
                "severity":    severity,
                "last_seen":   now_ts,
                "total_pkts":  sniffer.top_attackers.get(ip, {}).get("total_pkts", 0) + rate,
            }

        # Port scan events (every 5s)
        if int(now_f - start_f) % 5 == 0:
            scanner_ip = "66.240.205.34"
            sniffer.scan_events.append({
                "time":        now_ts,
                "_epoch":      now_f,
                "src_ip":      scanner_ip,
                "src_country": "RU",
                "scan_type":   "SYN Scan",
                "port_count":  random.randint(80, 200),
                "ports":       list(range(1, 101)),
                "risk_score":  90,
                "severity":    "HIGH",
                "msg":         f"Port scan from {scanner_ip}",
            })

        # ARP / MITM event (first 10s of demo)
        if now_f - start_f < 10:
            sniffer.arp_events.append({
                "time":        now_ts,
                "_epoch":      now_f,
                "src_ip":      "192.168.1.50",
                "src_mac":     "aa:bb:cc:dd:ee:ff",
                "attack_type": "ARP Poisoning",
                "severity":    "HIGH",
                "msg":         "IP 192.168.1.1 now claims MAC aa:bb:cc:dd:ee:ff (DEMO)",
            })

        time.sleep(1)

    # Clean up demo incidents when done
    for i in range(len(_FAKE_ATTACKERS)):
        inc_id = f"DEMO-{i}"
        if inc_id in sniffer.incidents:
            sniffer.incidents[inc_id]["status"] = "RESOLVED"
    sim.disable()
    _demo["running"] = False


@settings_bp.route("/api/sim/demo-start", methods=["POST"])
@login_required
@require_permission('settings', 'write')
def api_demo_start():
    if _demo["running"]:
        remaining = max(0, int(_demo["end_time"] - time.time()))
        return jsonify({"status": "already_running", "remaining": remaining})
    data     = request.get_json(silent=True) or {}
    duration = min(int(data.get("duration", 60)), 120)
    local_ip = sniffer._get_default_ip() or "192.168.1.1"
    _demo["running"]  = True
    _demo["end_time"] = time.time() + duration
    t = threading.Thread(target=_run_demo, args=(duration, local_ip), daemon=True)
    _demo["thread"] = t
    t.start()
    return jsonify({"status": "started", "duration": duration, "local_ip": local_ip})


@settings_bp.route("/api/sim/demo-stop", methods=["POST"])
@login_required
@require_permission('settings', 'write')
def api_demo_stop():
    _demo["running"] = False
    return jsonify({"status": "stopped"})


@settings_bp.route("/api/sim/demo-status", methods=["GET"])
@login_required
def api_demo_status():
    remaining = max(0, int(_demo["end_time"] - time.time())) if _demo["running"] else 0
    return jsonify({"running": _demo["running"], "remaining": remaining})


# ── Simulation Mode API ───────────────────────────────────────────────────────

@settings_bp.route("/api/sim/status", methods=["GET"])
@login_required
def api_sim_status():
    return jsonify({
        "active": sim.is_sim(),
        "stats":  sim.get_stats(),
    })


@settings_bp.route("/api/sim/events", methods=["GET"])
@login_required
@require_permission('settings', 'read')
def api_sim_events():
    limit         = min(int(request.args.get("limit", 100)), 500)
    action_filter = request.args.get("action", "")
    return jsonify({
        "active": sim.is_sim(),
        "events": sim.get_events(limit=limit, action_filter=action_filter),
        "stats":  sim.get_stats(),
    })


@settings_bp.route("/api/sim/events", methods=["DELETE"])
@login_required
@require_permission('settings', 'write')
def api_sim_events_clear():
    n = sim.clear_events()
    return jsonify({"cleared": n})


# ── Admin: user management panel ─────────────────────────────────────────────

_ROLE_MAP   = {'super_user': 'admin', 'power_user': 'analyst', 'standard_user': 'viewer'}
_LABEL_MAP  = {'admin': 'super_user', 'analyst': 'power_user', 'viewer': 'standard_user'}


@settings_bp.route("/admin/users/create", methods=["POST"])
@login_required
def admin_create_user():
    """Admin creates a user directly — auto-approved."""
    if current_user.role != 'admin':
        abort(403)
    from extensions import db
    from models import User
    from blueprints.auth import _assign_role, validate_password
    import html as _html, re as _re

    username   = _html.escape(request.form.get('username', '').strip())
    email      = _html.escape(request.form.get('email', '').strip().lower())
    password   = request.form.get('password', '')
    role_label = request.form.get('role', 'standard_user')
    internal   = _ROLE_MAP.get(role_label, 'viewer')

    errors = []
    if not username or not email or not password:
        errors.append('All fields are required.')
    if username and not _re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        errors.append('Username: 3–30 chars, letters/digits/underscore only.')
    if username and User.query.filter_by(username=username).first():
        errors.append(f'Username "{username}" is already taken.')
    if email and User.query.filter_by(email=email).first():
        errors.append(f'Email "{email}" is already registered.')
    errors.extend(validate_password(password))

    for e in errors:
        flash(e, 'error')
    if not errors:
        user = User(username=username, email=email, role=internal,
                    is_approved=True, requested_role=role_label)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        _assign_role(user, internal, assigned_by=current_user)
        flash(f'User "{username}" created as {role_label.replace("_", " ").title()}.', 'success')
    return redirect(url_for('settings.admin_pending_users'))


@settings_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
def admin_delete_user(user_id):
    """Permanently delete an approved user account."""
    if current_user.role != 'admin':
        abort(403)
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('settings.admin_pending_users'))
    from extensions import db
    from models import User
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('settings.admin_pending_users'))
    if user.username == 'seed_admin':
        flash('The seed_admin account is protected and cannot be deleted.', 'error')
        return redirect(url_for('settings.admin_pending_users'))
    name = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{name}" has been permanently deleted.', 'info')
    return redirect(url_for('settings.admin_pending_users'))


@settings_bp.route("/admin/permissions")
@login_required
def admin_permissions():
    """Permissions matrix — shows all resource:action rows per role."""
    if current_user.role != 'admin':
        abort(403)
    from models import Role, Permission
    from collections import defaultdict
    roles = Role.query.order_by(Role.level.asc()).all()
    perms = Permission.query.order_by(Permission.resource.asc(), Permission.action.asc()).all()
    role_perm_map = {r.id: {p.id for p in r.permissions} for r in roles}
    _order = {'read': 0, 'write': 1, 'delete': 2, 'manage': 3}
    by_resource: dict = defaultdict(list)
    for p in perms:
        by_resource[p.resource].append(p)
    for res in by_resource:
        by_resource[res].sort(key=lambda p: _order.get(p.action, 9))
    _display = {'viewer': 'Standard User', 'analyst': 'Power User', 'admin': 'Super User'}
    return render_template('admin_permissions.html',
                           roles=roles,
                           by_resource=dict(sorted(by_resource.items())),
                           role_perm_map=role_perm_map,
                           role_display=_display)


@settings_bp.route("/admin/permissions/toggle", methods=["POST"])
@login_required
def admin_permissions_toggle():
    """AJAX endpoint — grant or revoke a permission from a role."""
    if current_user.role != 'admin':
        abort(403)
    from extensions import db
    from models import Role, Permission
    data    = request.get_json(silent=True) or {}
    role_id = data.get('role_id')
    perm_id = data.get('perm_id')
    grant   = bool(data.get('grant', True))
    role = db.session.get(Role, role_id)
    perm = db.session.get(Permission, perm_id)
    if not role or not perm:
        return jsonify({'error': 'Not found'}), 404
    if grant:
        if perm not in role.permissions:
            role.permissions.append(perm)
    else:
        if perm in role.permissions:
            role.permissions.remove(perm)
    db.session.commit()
    return jsonify({'ok': True, 'role': role.name, 'perm': perm.name, 'granted': grant})


@settings_bp.route("/admin/users/pending-count")
@login_required
def admin_pending_count():
    if current_user.role != 'admin':
        return jsonify({'count': 0})
    from models import User
    return jsonify({'count': User.query.filter_by(is_approved=False).count()})


@settings_bp.route("/admin/users/pending")
@login_required
def admin_pending_users():
    """User management: pending approvals + active user roster."""
    if current_user.role != 'admin':
        abort(403)
    from models import User
    pending = User.query.filter_by(is_approved=False).order_by(User.created_at.asc()).all()
    active  = User.query.filter_by(is_approved=True).order_by(User.created_at.asc()).all()
    return render_template("admin_pending_users.html",
                           pending=pending, active=active, label_map=_LABEL_MAP)


@settings_bp.route("/admin/users/<int:user_id>/approve", methods=["POST"])
@login_required
def admin_approve_user(user_id):
    """Approve a pending user and assign their requested role."""
    if current_user.role != 'admin':
        abort(403)
    from extensions import db
    from models import User, UserRole
    from blueprints.auth import _assign_role

    user = db.session.get(User, user_id)
    if not user or user.is_approved:
        flash('User not found or already approved.', 'error')
        return redirect(url_for('settings.admin_pending_users'))

    chosen_label  = request.form.get('role', user.requested_role or 'standard_user')
    internal_role = _ROLE_MAP.get(chosen_label, 'viewer')

    user.role        = internal_role
    user.is_approved = True
    db.session.commit()

    _assign_role(user, internal_role, assigned_by=current_user)
    flash(f'"{user.username}" approved as {chosen_label.replace("_", " ").title()}.', 'success')
    return redirect(url_for('settings.admin_pending_users'))


@settings_bp.route("/admin/users/<int:user_id>/reject", methods=["POST"])
@login_required
def admin_reject_user(user_id):
    """Permanently delete a rejected registration."""
    if current_user.role != 'admin':
        abort(403)
    from extensions import db
    from models import User

    user = db.session.get(User, user_id)
    if not user or user.is_approved:
        flash('User not found or already approved.', 'error')
        return redirect(url_for('settings.admin_pending_users'))

    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'Access request from "{username}" has been rejected and removed.', 'info')
    return redirect(url_for('settings.admin_pending_users'))


@settings_bp.route("/admin/users/<int:user_id>/change-role", methods=["POST"])
@login_required
def admin_change_role(user_id):
    """Change the access level of an already-approved user."""
    if current_user.role != 'admin':
        abort(403)
    if user_id == current_user.id:
        flash('You cannot change your own access level.', 'error')
        return redirect(url_for('settings.admin_pending_users'))

    from extensions import db
    from models import User, Role, UserRole

    user = db.session.get(User, user_id)
    if not user or not user.is_approved:
        flash('User not found.', 'error')
        return redirect(url_for('settings.admin_pending_users'))

    chosen_label  = request.form.get('role', 'standard_user')
    internal_role = _ROLE_MAP.get(chosen_label, 'viewer')
    old_label     = _LABEL_MAP.get(user.role, 'standard_user')

    if internal_role == user.role:
        flash(f'"{user.username}" already has that access level.', 'info')
        return redirect(url_for('settings.admin_pending_users'))

    # Update role column
    user.role = internal_role

    # Deactivate all current active role assignments
    UserRole.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
    db.session.flush()

    # Add or re-activate the new role
    role_obj = Role.query.filter_by(name=internal_role).first()
    if role_obj:
        existing = UserRole.query.filter_by(user_id=user.id, role_id=role_obj.id).first()
        if existing:
            existing.is_active      = True
            existing.assigned_by_id = current_user.id
            existing.assigned_at    = __import__('datetime').datetime.utcnow()
        else:
            db.session.add(UserRole(
                user_id        = user.id,
                role_id        = role_obj.id,
                assigned_by_id = current_user.id,
                is_active      = True,
            ))

    db.session.commit()
    flash(
        f'"{user.username}" changed from {old_label.replace("_"," ").title()} '
        f'to {chosen_label.replace("_"," ").title()}.',
        'success'
    )
    return redirect(url_for('settings.admin_pending_users'))
