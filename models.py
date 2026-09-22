"""
Database Models — SOC Enterprise Platform
"""
from extensions import db, login_manager
from flask_login import UserMixin
from datetime import datetime
import bcrypt
import secrets


# ── User ──────────────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):
    """User model with all auth fields."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Account security fields
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    # Enterprise: role-based access (admin / analyst / viewer)
    role = db.Column(db.String(20), default='analyst', nullable=False)

    # Enterprise: TOTP 2FA
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)

    # Approval workflow
    is_approved    = db.Column(db.Boolean, default=False, nullable=False, server_default='0')
    requested_role = db.Column(db.String(20), nullable=True)   # role label chosen at registration

    # Relationships
    cases_created  = db.relationship('Case', foreign_keys='Case.created_by_id',  backref='creator',  lazy='dynamic')
    cases_assigned = db.relationship('Case', foreign_keys='Case.assigned_to_id', backref='assignee', lazy='dynamic')
    audit_logs     = db.relationship('AuditLog', backref='user', lazy='dynamic')
    api_keys       = db.relationship('APIKey', backref='owner', lazy='dynamic')

    def set_password(self, password: str):
        pw_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(pw_bytes, salt).decode('utf-8')

    def check_password(self, password: str) -> bool:
        if not password or not self.password_hash:
            return False
        pw_bytes = password.encode('utf-8')
        if len(pw_bytes) > 72:
            return False
        try:
            return bcrypt.checkpw(pw_bytes, self.password_hash.encode('utf-8'))
        except Exception:
            return False

    def is_locked(self) -> bool:
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False

    # RBAC relationships (defined after the RBAC model classes below)
    assigned_roles = db.relationship(
        'UserRole', foreign_keys='UserRole.user_id',
        back_populates='user', lazy='dynamic', cascade='all,delete-orphan',
    )
    login_logs = db.relationship(
        'LoginHistory', foreign_keys='LoginHistory.user_id',
        back_populates='user', lazy='dynamic',
    )

    # ── Role / permission helpers ─────────────────────────────────────────

    def get_active_role(self) -> str:
        """Highest-level non-expired role from user_roles; falls back to User.role column."""
        try:
            best = None
            for ur in self.assigned_roles.filter_by(is_active=True).all():
                if ur.is_expired:
                    continue
                r = ur.role
                if r and (best is None or r.level > best.level):
                    best = r
            if best:
                return best.name
        except Exception:
            pass
        return self.role  # backward-compat fallback

    def get_permissions(self) -> set:
        """Set of 'resource:action' strings granted by all active roles."""
        perms: set = set()
        try:
            for ur in self.assigned_roles.filter_by(is_active=True).all():
                if ur.is_expired:
                    continue
                if ur.role:
                    for p in ur.role.permissions:
                        perms.add(p.name)
        except Exception:
            pass
        return perms

    def can(self, resource: str, action: str) -> bool:
        """True if any active role grants resource:action."""
        return f'{resource}:{action}' in self.get_permissions()

    def has_role(self, *roles) -> bool:
        """True if user's primary role (column) is in the supplied set."""
        return self.role in roles

    def __repr__(self):
        return f'<User {self.username} [{self.role}]>'


@login_manager.user_loader
def load_user(user_id: str):
    user = User.query.get(int(user_id))
    if user and not user.is_approved:
        return None
    return user


# ── Case Management ───────────────────────────────────────────────────────────

class Case(db.Model):
    """SOC Case / Ticket — tracks investigation lifecycle."""
    __tablename__ = 'cases'

    id             = db.Column(db.Integer, primary_key=True)
    case_id        = db.Column(db.String(20), unique=True, nullable=False, index=True)
    title          = db.Column(db.String(200), nullable=False)
    description    = db.Column(db.Text, nullable=True)
    severity       = db.Column(db.String(20), default='MEDIUM')   # LOW/MEDIUM/HIGH/CRITICAL
    status         = db.Column(db.String(20), default='OPEN')     # OPEN/IN_PROGRESS/RESOLVED/CLOSED
    source         = db.Column(db.String(50), default='manual')   # manual/detection/threat_intel/syslog
    incident_ref   = db.Column(db.String(30), nullable=True)      # sniffer incident ID
    src_ip         = db.Column(db.String(45), nullable=True)
    attack_type    = db.Column(db.String(80), nullable=True)
    mitre_tactic   = db.Column(db.String(100), nullable=True)
    mitre_technique= db.Column(db.String(100), nullable=True)

    created_by_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at     = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at    = db.Column(db.DateTime, nullable=True)
    sla_deadline   = db.Column(db.DateTime, nullable=True)

    notes      = db.relationship('CaseNote', backref='case', lazy='dynamic', cascade='all,delete-orphan')

    # Soft-delete (recycle bin)
    deleted    = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by = db.Column(db.String(80), nullable=True)

    @property
    def sla_breached(self) -> bool:
        if self.sla_deadline and self.status not in ('RESOLVED', 'CLOSED'):
            return datetime.utcnow() > self.sla_deadline
        return False

    @property
    def age_hours(self) -> float:
        return (datetime.utcnow() - self.created_at).total_seconds() / 3600

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'case_id': self.case_id, 'title': self.title,
            'severity': self.severity, 'status': self.status, 'source': self.source,
            'incident_ref': self.incident_ref, 'src_ip': self.src_ip,
            'attack_type': self.attack_type, 'mitre_tactic': self.mitre_tactic,
            'mitre_technique': self.mitre_technique,
            'created_by': self.creator.username if self.creator else None,
            'assigned_to': self.assignee.username if self.assignee else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'sla_breached': self.sla_breached,
            'age_hours': round(self.age_hours, 1),
            'note_count': self.notes.count(),
            'deleted': self.deleted,
            'deleted_at': self.deleted_at.isoformat() if self.deleted_at else None,
            'deleted_by': self.deleted_by,
        }

    def __repr__(self):
        return f'<Case {self.case_id} [{self.severity}/{self.status}]>'


class CaseNote(db.Model):
    """Analyst notes / timeline entries for a case."""
    __tablename__ = 'case_notes'

    id         = db.Column(db.Integer, primary_key=True)
    case_id    = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    author_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    body       = db.Column(db.Text, nullable=False)
    note_type  = db.Column(db.String(20), default='comment')  # comment/action/escalation/resolution
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    author = db.relationship('User', backref='case_notes')

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'body': self.body, 'note_type': self.note_type,
            'author': self.author.username if self.author else 'System',
            'created_at': self.created_at.isoformat(),
        }


# ── API Keys ──────────────────────────────────────────────────────────────────

class APIKey(db.Model):
    """REST API authentication keys."""
    __tablename__ = 'api_keys'

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(80), nullable=False)
    key_hash    = db.Column(db.String(128), unique=True, nullable=False, index=True)
    prefix      = db.Column(db.String(12), nullable=False)   # first 8 chars for display
    owner_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    scopes      = db.Column(db.String(200), default='read')  # comma-separated: read,write,admin
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    last_used   = db.Column(db.DateTime, nullable=True)
    expires_at  = db.Column(db.DateTime, nullable=True)
    active      = db.Column(db.Boolean, default=True)

    @property
    def is_expired(self) -> bool:
        return bool(self.expires_at and datetime.utcnow() > self.expires_at)

    def has_scope(self, scope: str) -> bool:
        target = (scope or '').strip().lower()
        if not target:
            return False
        user_scopes = [s.strip().lower() for s in (self.scopes or '').split(',') if s.strip()]
        return target in user_scopes or 'admin' in user_scopes

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'name': self.name, 'prefix': self.prefix,
            'owner': self.owner.username if self.owner else None,
            'scopes': self.scopes, 'active': self.active,
            'created_at': self.created_at.isoformat(),
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_expired': self.is_expired,
        }


# ── Correlation Rules ─────────────────────────────────────────────────────────

class CorrelationRule(db.Model):
    """Custom SIEM correlation rules."""
    __tablename__ = 'correlation_rules'

    id           = db.Column(db.Integer, primary_key=True)
    name         = db.Column(db.String(120), nullable=False)
    description  = db.Column(db.Text, nullable=True)
    rule_type    = db.Column(db.String(30), default='threshold')  # threshold/sequence/frequency
    conditions   = db.Column(db.Text, nullable=False)   # JSON-encoded condition dict
    severity     = db.Column(db.String(20), default='MEDIUM')
    mitre_tactic = db.Column(db.String(100), nullable=True)
    mitre_tech   = db.Column(db.String(100), nullable=True)
    enabled      = db.Column(db.Boolean, default=True)
    fire_count   = db.Column(db.Integer, default=0)
    last_fired   = db.Column(db.DateTime, nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id= db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'name': self.name, 'description': self.description,
            'rule_type': self.rule_type, 'conditions': self.conditions,
            'severity': self.severity, 'mitre_tactic': self.mitre_tactic,
            'mitre_tech': self.mitre_tech, 'enabled': self.enabled,
            'fire_count': self.fire_count,
            'last_fired': self.last_fired.isoformat() if self.last_fired else None,
        }


# ── Audit Log ─────────────────────────────────────────────────────────────────

class AuditLog(db.Model):
    """Immutable audit trail for all user actions."""
    __tablename__ = 'audit_logs'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action     = db.Column(db.String(80), nullable=False)   # e.g. 'block_ip', 'close_case'
    target     = db.Column(db.String(200), nullable=True)   # what was acted on
    detail     = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'user': self.user.username if self.user else 'System',
            'action': self.action, 'target': self.target,
            'detail': self.detail, 'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat(),
        }


# ── IOC Cache ─────────────────────────────────────────────────────────────────

class IOCEntry(db.Model):
    """Persistent IOC (Indicator of Compromise) store."""
    __tablename__ = 'ioc_entries'

    id          = db.Column(db.Integer, primary_key=True)
    ioc_type    = db.Column(db.String(20), nullable=False, index=True)  # ip/domain/hash/url
    value       = db.Column(db.String(512), nullable=False, index=True)
    source      = db.Column(db.String(80), default='manual')   # manual/abuseipdb/threatfox/feed
    confidence  = db.Column(db.Integer, default=50)            # 0–100
    threat_type = db.Column(db.String(80), nullable=True)
    description = db.Column(db.Text, nullable=True)
    last_seen   = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at  = db.Column(db.DateTime, nullable=True)
    active      = db.Column(db.Boolean, default=True)

    __table_args__ = (db.UniqueConstraint('ioc_type', 'value', name='uq_ioc_type_value'),)

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'ioc_type': self.ioc_type, 'value': self.value,
            'source': self.source, 'confidence': self.confidence,
            'threat_type': self.threat_type, 'description': self.description,
            'last_seen': self.last_seen.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
        }


# ── Notification Config ───────────────────────────────────────────────────────

class NotificationConfig(db.Model):
    """Webhook / alert destination settings."""
    __tablename__ = 'notification_configs'

    id           = db.Column(db.Integer, primary_key=True)
    name         = db.Column(db.String(80), nullable=False)
    channel      = db.Column(db.String(20), nullable=False)  # slack/discord/email/webhook
    destination  = db.Column(db.String(512), nullable=False) # URL or email address
    min_severity = db.Column(db.String(20), default='HIGH')  # minimum severity to notify
    enabled      = db.Column(db.Boolean, default=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'name': self.name, 'channel': self.channel,
            'destination': self.destination[:30] + '...' if len(self.destination) > 30 else self.destination,
            'min_severity': self.min_severity, 'enabled': self.enabled,
        }


# ── Web-Layer Security Events ─────────────────────────────────────────────────

class SecurityEvent(db.Model):
    """Persistent record of web-layer attacks detected by the web IDS."""
    __tablename__ = 'security_events'

    id          = db.Column(db.Integer, primary_key=True)
    ip_address  = db.Column(db.String(45), nullable=False, index=True)
    attack_type = db.Column(db.String(50), nullable=False)   # sql_injection / xss / command_injection / ldap_injection
    severity    = db.Column(db.String(20), default='HIGH')   # MEDIUM / HIGH / CRITICAL
    path        = db.Column(db.String(500), nullable=True)   # request path
    user_agent  = db.Column(db.String(500), nullable=True)
    blocked     = db.Column(db.Boolean, default=False)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self) -> dict:
        return {
            'id':          self.id,
            'ip':          self.ip_address,
            'attack_type': self.attack_type,
            'severity':    self.severity,
            'path':        self.path,
            'blocked':     self.blocked,
            'timestamp':   self.timestamp.isoformat(),
        }


# ── IP Risk Scores ────────────────────────────────────────────────────────────

class RiskScore(db.Model):
    """Historical risk scores calculated for attacking IP addresses."""
    __tablename__ = 'risk_scores'

    id            = db.Column(db.Integer, primary_key=True)
    ip_address    = db.Column(db.String(45), nullable=False, index=True)
    score         = db.Column(db.Float, nullable=False)       # 0.0–100.0
    level         = db.Column(db.String(20), nullable=False)  # LOW/MEDIUM/HIGH/CRITICAL
    attack_type   = db.Column(db.String(80), nullable=True)
    packet_count  = db.Column(db.Integer, default=0)
    calculated_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self) -> dict:
        return {
            'id':           self.id,
            'ip':           self.ip_address,
            'score':        self.score,
            'level':        self.level,
            'attack_type':  self.attack_type,
            'packet_count': self.packet_count,
            'timestamp':    self.calculated_at.isoformat(),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# RBAC — Roles · Permissions · UserRoles · LoginHistory
#
# Schema mirrors a typical SSMS authorization design:
#
#   roles            — named privilege tiers (viewer / analyst / admin)
#   permissions      — atomic capabilities (resource:action pairs)
#   role_permissions — many-to-many join: which permissions each role grants
#   user_roles       — many-to-many join: which roles each user holds, with
#                      audit metadata (who assigned, when, optional expiry)
#   login_history    — immutable record of every login attempt
# ═══════════════════════════════════════════════════════════════════════════════

# Many-to-many association table: roles ↔ permissions
_role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id',       db.Integer, db.ForeignKey('roles.id',       ondelete='CASCADE'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True),
)


class Role(db.Model):
    """
    Named role with an ordered privilege level.

    level hierarchy (ascending):
        0  viewer   — read-only dashboards and logs
        1  analyst  — SOC operations (cases, blocks, alerts)
        2  admin    — full access including user and settings management
    """
    __tablename__ = 'roles'

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(50),  unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    level       = db.Column(db.Integer, nullable=False, default=0)
    is_system   = db.Column(db.Boolean, nullable=False, default=False)  # system roles cannot be deleted
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    permissions = db.relationship(
        'Permission', secondary=_role_permissions,
        backref=db.backref('roles', lazy='dynamic'), lazy='subquery',
    )

    def to_dict(self) -> dict:
        active_users = UserRole.query.filter_by(role_id=self.id, is_active=True).count()
        return {
            'id':          self.id,
            'name':        self.name,
            'description': self.description,
            'level':       self.level,
            'is_system':   self.is_system,
            'permissions': [p.name for p in self.permissions],
            'user_count':  active_users,
        }

    def __repr__(self):
        return f'<Role {self.name} [L{self.level}]>'


class Permission(db.Model):
    """
    Atomic capability expressed as resource:action, e.g. 'firewall:write'.

    Resources  : dashboard, network, alerts, cases, incidents, logs,
                 firewall, honeypot, threat_intel, reports, mitre,
                 capture, settings, users, roles, audit
    Actions    : read, write, delete, manage
    """
    __tablename__ = 'permissions'

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), unique=True, nullable=False)   # 'firewall:write'
    resource    = db.Column(db.String(50),  nullable=False)                 # 'firewall'
    action      = db.Column(db.String(50),  nullable=False)                 # 'write'
    description = db.Column(db.String(200), nullable=True)

    __table_args__ = (
        db.UniqueConstraint('resource', 'action', name='uq_perm_resource_action'),
    )

    def to_dict(self) -> dict:
        return {
            'id':          self.id,
            'name':        self.name,
            'resource':    self.resource,
            'action':      self.action,
            'description': self.description,
        }

    def __repr__(self):
        return f'<Permission {self.name}>'


class UserRole(db.Model):
    """
    Assignment of a Role to a User, with audit metadata and optional expiry.

    Columns
    -------
    user_id        — the user receiving the role
    role_id        — the role being granted
    assigned_by_id — admin who made the assignment (NULL = seeded by system)
    assigned_at    — when the assignment was created
    expires_at     — NULL = permanent; set to auto-expire temporary elevations
    is_active      — soft-delete: False = role removed without losing history
    """
    __tablename__ = 'user_roles'

    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),   nullable=False, index=True)
    role_id        = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'),   nullable=False, index=True)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'),  nullable=True)
    assigned_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at     = db.Column(db.DateTime, nullable=True)
    is_active      = db.Column(db.Boolean,  default=True, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'role_id', name='uq_user_role'),
    )

    # Relationships
    user        = db.relationship('User', foreign_keys='UserRole.user_id',
                                  back_populates='assigned_roles')
    role        = db.relationship('Role', backref=db.backref('user_roles', lazy='dynamic'))
    assigned_by = db.relationship('User', foreign_keys='UserRole.assigned_by_id',
                                  backref=db.backref('roles_granted', lazy='dynamic'))

    @property
    def is_expired(self) -> bool:
        return bool(self.expires_at and datetime.utcnow() > self.expires_at)

    def to_dict(self) -> dict:
        return {
            'id':          self.id,
            'user':        self.user.username if self.user else str(self.user_id),
            'role':        self.role.name     if self.role else None,
            'role_level':  self.role.level    if self.role else 0,
            'assigned_by': self.assigned_by.username if self.assigned_by else 'system',
            'assigned_at': self.assigned_at.isoformat(),
            'expires_at':  self.expires_at.isoformat() if self.expires_at else None,
            'is_active':   self.is_active and not self.is_expired,
        }

    def __repr__(self):
        return f'<UserRole user={self.user_id} role={self.role_id}>'


class LoginHistory(db.Model):
    """
    Immutable audit trail of every login attempt — success and failure.

    failure_reason values
    ---------------------
    wrong_password  — credentials did not match
    not_found       — no user with that identifier exists
    account_locked  — user.locked_until is in the future
    rate_limited    — IP exceeded MAX_ATTEMPTS within LOCKOUT_WINDOW
    """
    __tablename__ = 'login_history'

    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    username       = db.Column(db.String(80),  nullable=False)
    ip_address     = db.Column(db.String(45),  nullable=False, index=True)
    user_agent     = db.Column(db.String(500), nullable=True)
    success        = db.Column(db.Boolean,     nullable=False)
    failure_reason = db.Column(db.String(100), nullable=True)
    role_snapshot  = db.Column(db.String(50),  nullable=True)   # role name at login time
    login_at       = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    logout_at      = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', foreign_keys='LoginHistory.user_id',
                           back_populates='login_logs')

    @property
    def session_minutes(self) -> float | None:
        if self.logout_at and self.login_at:
            return round((self.logout_at - self.login_at).total_seconds() / 60, 1)
        return None

    def to_dict(self) -> dict:
        return {
            'id':              self.id,
            'username':        self.username,
            'ip_address':      self.ip_address,
            'success':         self.success,
            'failure_reason':  self.failure_reason,
            'role':            self.role_snapshot,
            'login_at':        self.login_at.isoformat(),
            'logout_at':       self.logout_at.isoformat() if self.logout_at else None,
            'session_minutes': self.session_minutes,
        }

    def __repr__(self):
        status = 'OK' if self.success else f'FAIL({self.failure_reason})'
        return f'<LoginHistory {self.username} {status} {self.login_at}>'
