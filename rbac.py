"""
rbac.py — Role-Based Access Control

Schema (SSMS-style, defined in models.py)
──────────────────────────────────────────
  roles            → named privilege tiers
  permissions      → atomic resource:action pairs
  role_permissions → which permissions each role grants
  user_roles       → which roles each user holds
  login_history    → every login attempt (success + failure)

Built-in roles (seeded on startup)
────────────────────────────────────
  viewer   (level 0) — read-only: dashboards, logs, incidents
  analyst  (level 1) — SOC operations: cases, blocks, alerts, reports
  admin    (level 2) — full access: settings, users, roles

Decorators
──────────────────────────────────────────
  @require_role('admin')               — exact role name match
  @require_role('admin', 'analyst')    — any of the listed roles
  @require_min_role('analyst')         — role level ≥ min_role
  @require_permission('firewall','write') — explicit permission check

Helper
  audit(action, target, detail)        — writes AuditLog row
"""
from functools import wraps
from flask import jsonify, request
from flask_login import current_user
from datetime import datetime


# ── Role hierarchy ─────────────────────────────────────────────────────────────

ROLES = ('viewer', 'analyst', 'admin')
ROLE_LEVEL = {r: i for i, r in enumerate(ROLES)}

# Full permission matrix — consumed by _seed_rbac() in app.py
# Format: {role_name: [(resource, action, description), ...]}
ROLE_PERMISSIONS: dict[str, list[tuple[str, str, str]]] = {
    'viewer': [
        ('dashboard',   'read',   'View main dashboard'),
        ('network',     'read',   'View network overview'),
        ('alerts',      'read',   'View alerts feed'),
        ('cases',       'read',   'View cases'),
        ('incidents',   'read',   'View incidents'),
        ('logs',        'read',   'View event logs'),
        ('threat_intel','read',   'View threat intelligence'),
        ('mitre',       'read',   'View MITRE ATT&CK mapping'),
        ('capture',     'read',   'View packet capture stream'),
    ],
    'analyst': [
        # Inherits viewer permissions (added during seed)
        ('reports',     'read',   'View and export reports'),
        ('firewall',    'read',   'View firewall rules'),
        ('firewall',    'write',  'Add/remove firewall blocks'),
        ('honeypot',    'read',   'View honeypot events'),
        ('honeypot',    'write',  'Configure honeypot'),
        ('cases',       'write',  'Create and update cases'),
        ('cases',       'delete', 'Delete / archive cases'),
        ('incidents',   'write',  'Update incident status'),
        ('alerts',      'write',  'Acknowledge / close alerts'),
        ('threat_intel','write',  'Add / update IOCs'),
        ('logs',        'write',  'Restore logs from trash'),
        ('logs',        'delete', 'Delete / move logs to trash'),
        ('mitre',       'write',  'Enable / disable correlation rules'),
    ],
    'admin': [
        # Inherits analyst + viewer permissions (added during seed)
        ('settings',    'read',   'View platform settings'),
        ('settings',    'write',  'Change platform settings'),
        ('users',       'read',   'View user list'),
        ('users',       'write',  'Create and edit users'),
        ('users',       'delete', 'Deactivate / delete users'),
        ('roles',       'manage', 'Assign and revoke roles'),
        ('firewall',    'manage', 'Manage firewall policy'),
        ('audit',       'read',   'View full audit trail'),
    ],
}


def _level(role: str) -> int:
    return ROLE_LEVEL.get(role, 0)


# ── Route decorators ───────────────────────────────────────────────────────────

def require_role(*roles):
    """
    Reject with 403 if the logged-in user's role is not in *roles*.
    Checks User.role column (fast, no DB query).
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            if current_user.role not in roles:
                return jsonify({'error': f"Requires role: {' or '.join(roles)}"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_min_role(min_role: str):
    """
    Reject if user's role level is below *min_role*.
    Checks User.role column (fast, no DB query).
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            if _level(current_user.role) < _level(min_role):
                return jsonify({'error': f'Requires at least {min_role} role'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_permission(resource: str, action: str):
    """
    Reject with 403 if none of the user's active roles grant resource:action.
    Reads user_roles → role_permissions (one DB round-trip; cached by SQLAlchemy
    identity map within the same request).
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            if not current_user.can(resource, action):
                return jsonify({'error': f'Permission denied: requires {resource}:{action}'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ── Convenience check (use in templates / view logic) ─────────────────────────

def has_permission(resource: str, action: str) -> bool:
    """
    Return True if current_user holds the resource:action permission.
    Safe to call from Jinja2 templates via `{{ has_permission('cases','write') }}`.
    """
    if not current_user.is_authenticated:
        return False
    return current_user.can(resource, action)


# ── Audit helper ───────────────────────────────────────────────────────────────

def audit(action: str, target: str = None, detail: str = None) -> None:
    """Write an AuditLog row for the current authenticated request. Silently no-ops on error."""
    try:
        from extensions import db
        from models import AuditLog
        entry = AuditLog(
            user_id    = current_user.id if current_user.is_authenticated else None,
            action     = action,
            target     = target,
            detail     = detail,
            ip_address = request.remote_addr,
            timestamp  = datetime.utcnow(),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        pass
