"""
Flask SOC Application — Main Entry Point
"""
import os
import threading
import urllib.parse

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, abort
from flask_wtf.csrf import CSRFProtect

from extensions import db, login_manager, socketio, limiter
from blueprints.auth import auth_bp
from blueprints.main import main_bp
from blueprints.incidents import incidents_bp
from blueprints.analytics import analytics_bp
from blueprints.settings import settings_bp
from blueprints.firewall import firewall_bp
from blueprints.honeypot import honeypot_bp
from blueprints.cases import cases_bp
from blueprints.health import health_bp
from blueprints.threat_intel import threat_intel_bp
from blueprints.mitre import mitre_bp
from blueprints.api_keys import api_keys_bp
from blueprints.report import report_bp
from blueprints.portscan import portscan_bp
from detection import sniffer
from core import firewall as fw
from detection import web_ids
from core import soc_logger as log
from core import sim

# ── Paths exempt from web-IDS and rate-limiting ────────────────────────────────
_EXEMPT_PREFIXES = ("/static/", "/socket.io/")


def _seed_rbac() -> None:
    """
    Idempotent RBAC seed — runs inside an app context after db.create_all().

    Creates (if absent):
      • 3 system roles   : viewer (L0) · analyst (L1) · admin (L2)
      • All permissions  : one row per resource:action pair
      • role_permissions : full permission matrix per role (cumulative)
      • user_roles       : migrates every existing user who has no UserRole row
                           to the role stored in their User.role column
    """
    from models import Role, Permission, UserRole
    from rbac import ROLE_PERMISSIONS

    # ── 1. Roles ──────────────────────────────────────────────────────────────
    role_defs = [
        ('viewer',  'Read-only access: dashboards and logs',               0),
        ('analyst', 'SOC operations: cases, blocks, firewall, alerts',     1),
        ('admin',   'Full access: settings, users, roles, audit trail',    2),
    ]
    role_map: dict = {}
    for name, desc, level in role_defs:
        r = Role.query.filter_by(name=name).first()
        if not r:
            # pyrefly: ignore
            r = Role(name=name, description=desc, level=level, is_system=True)
            db.session.add(r)
            db.session.flush()
        role_map[name] = r

    # ── 2. Permissions + role_permissions ─────────────────────────────────────
    # Build cumulative permission sets (each role inherits all lower-level ones)
    from models import Permission as _Perm
    viewer_perms  = set(ROLE_PERMISSIONS['viewer'])
    analyst_perms = viewer_perms  | set(ROLE_PERMISSIONS['analyst'])
    admin_perms   = analyst_perms | set(ROLE_PERMISSIONS['admin'])

    tier_perms = {
        'viewer':  viewer_perms,
        'analyst': analyst_perms,
        'admin':   admin_perms,
    }

    # ── Pass 1: ensure Permission objects exist in the table ─────────────────
    perm_cache: dict = {}
    all_perm_sets = list(tier_perms.values())
    for perm_set in all_perm_sets:
        for resource, action, description in perm_set:
            key = (resource, action)
            if key not in perm_cache:
                p = _Perm.query.filter_by(resource=resource, action=action).first()
                if not p:
                    # pyrefly: ignore
                    p = _Perm(
                        name        = f'{resource}:{action}',
                        resource    = resource,
                        action      = action,
                        description = description,
                    )
                    db.session.add(p)
                    db.session.flush()
                perm_cache[key] = p
    db.session.flush()

    # ── Pass 2: assign permissions to roles — additive only ──────────────────
    # Only adds permissions not yet assigned to a role; never removes existing
    # ones. This means new permissions added to ROLE_PERMISSIONS are picked up
    # on restart without wiping admin customisations for permissions that are
    # already present in the role.
    for role_name, perm_set in tier_perms.items():
        role = role_map[role_name]
        existing_ids = {p.id for p in role.permissions}
        for resource, action, _ in perm_set:
            perm = perm_cache.get((resource, action))
            if perm and perm.id not in existing_ids:
                role.permissions.append(perm)
                existing_ids.add(perm.id)

    db.session.commit()

    # ── 3. Migrate existing users to user_roles ───────────────────────────────
    from models import User as _User
    for user in _User.query.all():
        already = UserRole.query.filter_by(user_id=user.id).first()
        if already:
            continue
        role_name = user.role if user.role in role_map else 'analyst'
        # pyrefly: ignore
        ur = UserRole(
            user_id   = user.id,
            role_id   = role_map[role_name].id,
            is_active = True,
        )
        db.session.add(ur)

    db.session.commit()


def _seed_admin() -> None:
    """
    Create the built-in seed_admin superuser if not already present.
    Credentials are read from environment variables (set in .env).
    Change the password immediately after first login.
    """
    username = os.environ.get('SEED_ADMIN_USERNAME', 'seed_admin')
    email    = os.environ.get('SEED_ADMIN_EMAIL',    'admin@soc.local')
    password = os.environ.get('SEED_ADMIN_PASSWORD', 'Admin@SOC2024!')

    from models import User, UserRole, Role
    if User.query.filter_by(username=username).first():
        return
    # pyrefly: ignore
    admin = User(
        username       = username,
        email          = email,
        role           = 'admin',
        is_approved    = True,
        requested_role = 'super_user',
    )
    admin.set_password(password)
    db.session.add(admin)
    db.session.flush()
    admin_role = Role.query.filter_by(name='admin').first()
    if admin_role:
        # pyrefly: ignore
        db.session.add(UserRole(user_id=admin.id, role_id=admin_role.id, is_active=True))
    db.session.commit()


def create_app():
    app = Flask(__name__)

    # ── Core config ────────────────────────────────────────────────────────────
    app.config["SECRET_KEY"] = os.environ.get(
        "SECRET_KEY", "dev-secret-key-change-in-production-!@#"
    )
    _odbc = urllib.parse.quote_plus(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=ABDULLAH\\SQLEXPRESS;"
        "DATABASE=SOC_Platform;"
        "Trusted_Connection=yes;"
        "TrustServerCertificate=yes;"
    )
    app.config["SQLALCHEMY_DATABASE_URI"] = f"mssql+pyodbc:///?odbc_connect={_odbc}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Session hardening
    app.config["PERMANENT_SESSION_LIFETIME"]  = 86400 * 7   # 7 days (was 30)
    app.config["SESSION_COOKIE_HTTPONLY"]     = True
    app.config["SESSION_COOKIE_SAMESITE"]     = "Lax"
    app.config["SESSION_COOKIE_SECURE"]       = (
        os.environ.get("FLASK_ENV", "development") == "production"
    )
    app.config["SESSION_COOKIE_NAME"]         = "soc_session"

    # CSRF
    app.config["WTF_CSRF_TIME_LIMIT"] = 3600

    # Flask-Limiter — disable for testing if needed
    app.config["RATELIMIT_ENABLED"] = True

    # ── Extension init ─────────────────────────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    CSRFProtect(app)
    limiter.init_app(app)
    socketio.init_app(app)

    login_manager.login_view = "auth.login"

    # ── Blueprint registration ─────────────────────────────────────────────────
    app.register_blueprint(auth_bp,        url_prefix="/auth")
    app.register_blueprint(main_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(firewall_bp)
    app.register_blueprint(honeypot_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(threat_intel_bp)
    app.register_blueprint(mitre_bp)
    app.register_blueprint(api_keys_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(portscan_bp)

    with app.app_context():
        db.create_all()
        # SQL Server migration: add approval columns if not yet present
        from sqlalchemy import text as _text
        _approval_cols = [
            "ALTER TABLE users ADD is_approved BIT NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD requested_role NVARCHAR(20) NULL",
        ]
        with db.engine.connect() as _conn:
            for _sql in _approval_cols:
                try:
                    _conn.execute(_text(_sql))
                    _conn.commit()
                except Exception:
                    pass

        _seed_rbac()          # idempotent — safe to run on every startup
        _seed_admin()         # creates seed_admin superuser if absent

    # ── Custom error pages ────────────────────────────────────────────────────
    @app.errorhandler(403)
    def forbidden(_e):
        from flask import render_template as _rt
        return _rt('403.html'), 403

    @app.errorhandler(404)
    def not_found(_e):
        from flask import render_template as _rt
        return _rt('404.html'), 404

    # ── Security: firewall enforcement ─────────────────────────────────────────
    @app.before_request
    def enforce_firewall():
        ip = request.remote_addr or ""
        if ip and fw.is_blocked(ip):
            abort(403, description=f"Access denied — {ip} is blocked by the SOC firewall.")

    # ── Security: web-layer IDS (SQLi / XSS / command injection) ──────────────
    @app.before_request
    def web_layer_ids():
        """Inspect every non-static request for web-layer attacks."""
        path = request.path
        if any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return
        ip = request.remote_addr or ""
        if not ip:
            return

        body = ""
        ct = request.content_type or ""
        if "application/json" not in ct and request.content_length:
            try:
                body = request.get_data(as_text=True)[:16_384]
            except Exception:
                pass

        detections = web_ids.inspect_request(
            ip=ip,
            path=path,
            args=request.args.to_dict(flat=False),
            form=request.form.to_dict(flat=False),
            body=body,
        )

        if detections:
            severities = {d["severity"] for d in detections}
            types      = [d["attack_type"] for d in detections]
            log.warning("web_ids",
                        f"Web attack detected: {', '.join(types)}",
                        {"ip": ip, "path": path, "types": types})
            # Auto-block on command injection (critical severity)
            if "CRITICAL" in severities and ip:
                if sim.is_sim():
                    sim.record(sim.WEBIDS_SUPPRESSED,
                               f"Web IDS auto-block suppressed for {ip} — {', '.join(types)}",
                               ip=ip, extra={"types": types})
                    log.warning("web_ids", f"[SIM] Would have auto-blocked {ip} — {', '.join(types)}")
                else:
                    result = fw.block_ip(ip, reason=f"Web IDS: {', '.join(types)}", auto=True,
                                         duration=3600)
                    if result.get("status") == "blocked":
                        log.critical("web_ids", f"Auto-blocked {ip} — command injection attempt")

    # ── Security: HTTP security headers ───────────────────────────────────────
    @app.after_request
    def security_headers(response):
        h = response.headers
        h["X-Content-Type-Options"]    = "nosniff"
        h["X-Frame-Options"]           = "DENY"
        h["X-XSS-Protection"]          = "1; mode=block"
        h["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        h["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
        # Cache-Control for API endpoints
        if request.path.startswith("/api/"):
            h["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        return response

    # ── Background threads ─────────────────────────────────────────────────────
    threading.Thread(target=sniffer.start_sniffer, daemon=True).start()

    try:
        from detection.correlation import start_correlation_engine
        start_correlation_engine(app)
    except Exception:
        pass

    try:
        from core.syslog_ingester import start_syslog_ingester
        start_syslog_ingester(app)
    except Exception:
        pass

    # Flask-SocketIO real-time event emitter (Phase 6)
    try:
        from core.websocket_events import start_event_emitter
        start_event_emitter(app)
        log.info("app", "SocketIO event emitter started")
    except Exception as e:
        log.error("app", f"SocketIO emitter failed to start: {e}")

    log.info("app", "SOC platform started", {
        "env": os.environ.get("FLASK_ENV", "development"),
        "debug": False,
    })

    return app


if __name__ == "__main__":
    app = create_app()
    # Use socketio.run() so WebSocket clients can connect alongside HTTP polling
    socketio.run(app, host="0.0.0.0", port=5000, debug=False,
                 allow_unsafe_werkzeug=True)
