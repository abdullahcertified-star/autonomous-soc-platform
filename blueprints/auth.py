"""
Authentication Blueprint
Handles: register, login, logout, password reset, rate limiting
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db, limiter
from models import User, Role, UserRole, LoginHistory
from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import urlparse
import re
import secrets
import html

auth_bp = Blueprint('auth', __name__)

# Maps the registration form value → internal role name
_ROLE_MAP = {
    'super_user':    'admin',
    'power_user':    'analyst',
    'standard_user': 'viewer',
}

# --- In-memory rate limiter (per IP, resets on server restart) ---
login_attempts = defaultdict(list)  # {ip: [timestamp, ...]}
MAX_ATTEMPTS = 5
LOCKOUT_WINDOW = 300  # 5 minutes in seconds


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def is_safe_redirect_url(target: str | None) -> bool:
    """Ensure redirect target is a safe local relative path to prevent Open Redirect (CWE-601)."""
    if not target or not isinstance(target, str):
        return False
    # Must start with single forward slash, not protocol-relative //, no backslashes
    if not target.startswith('/') or target.startswith('//') or '\\' in target:
        return False
    try:
        parsed = urlparse(target)
        return parsed.netloc == '' and parsed.scheme == ''
    except Exception:
        return False


def sanitize(value: str) -> str:
    """Strip leading/trailing whitespace and escape HTML."""
    return html.escape(value.strip()) if value else ''


def validate_password(password: str) -> list[str]:
    """
    Return list of validation error messages.
    Empty list = password is valid.
    """
    errors = []
    if len(password) < 8:
        errors.append('Password must be at least 8 characters.')
    if len(password.encode('utf-8')) > 72:
        errors.append('Password must not exceed 72 bytes.')
    if not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least one uppercase letter.')
    if not re.search(r'[a-z]', password):
        errors.append('Password must contain at least one lowercase letter.')
    if not re.search(r'\d', password):
        errors.append('Password must contain at least one digit.')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-]', password):
        errors.append('Password must contain at least one special character.')
    return errors


def is_rate_limited(ip: str) -> bool:
    """Return True if this IP has exceeded the allowed login attempts."""
    now = datetime.utcnow().timestamp()
    # Keep only recent attempts within the window
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < LOCKOUT_WINDOW]
    return len(login_attempts[ip]) >= MAX_ATTEMPTS


def record_attempt(ip: str):
    """Record a failed login attempt for the given IP."""
    login_attempts[ip].append(datetime.utcnow().timestamp())


def remaining_lockout(ip: str) -> int:
    """Return seconds remaining in IP lockout (0 if not locked)."""
    now = datetime.utcnow().timestamp()
    attempts = [t for t in login_attempts[ip] if now - t < LOCKOUT_WINDOW]
    if len(attempts) >= MAX_ATTEMPTS and attempts:
        oldest = min(attempts)
        remaining = int(LOCKOUT_WINDOW - (now - oldest))
        return max(0, remaining)
    return 0


def _record_login(user: User | None, identifier: str, success: bool,
                  failure_reason: str | None = None) -> int | None:
    """
    Persist a LoginHistory row for this attempt.
    Returns the row's primary key so the session can track it for logout.
    """
    try:
        ua = (request.user_agent.string or '')[:500]
        entry = LoginHistory(
            user_id        = user.id if user else None,
            username       = user.username if user else identifier,
            ip_address     = request.remote_addr or '',
            user_agent     = ua,
            success        = success,
            failure_reason = failure_reason,
            role_snapshot  = user.role if user else None,
        )
        db.session.add(entry)
        db.session.commit()
        return entry.id
    except Exception:
        db.session.rollback()
        return None


def _assign_role(user: User, role_name: str, assigned_by: User | None = None) -> None:
    """
    Create a UserRole row linking *user* to *role_name*.
    No-ops if the role doesn't exist in the DB or the assignment already exists.
    """
    try:
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return
        existing = UserRole.query.filter_by(user_id=user.id, role_id=role.id).first()
        if existing:
            existing.is_active = True
            db.session.commit()
            return
        ur = UserRole(
            user_id        = user.id,
            role_id        = role.id,
            assigned_by_id = assigned_by.id if assigned_by else None,
            is_active      = True,
        )
        db.session.add(ur)
        db.session.commit()
    except Exception:
        db.session.rollback()


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("10/minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = sanitize(request.form.get('username', ''))
        email = sanitize(request.form.get('email', '').lower())
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        errors = []

        # Basic field presence
        if not username or not email or not password or not confirm:
            errors.append('All fields are required.')

        # Username rules
        if username and (len(username) < 3 or len(username) > 30):
            errors.append('Username must be 3–30 characters.')
        if username and not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append('Username may only contain letters, digits, and underscores.')

        # Email format
        if email and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            errors.append('Enter a valid email address.')

        # Password strength
        errors.extend(validate_password(password))

        # Password match
        if password and confirm and password != confirm:
            errors.append('Passwords do not match.')

        # Duplicate check
        if not errors:
            if User.query.filter_by(email=email).first():
                errors.append('An account with that email already exists.')
            if User.query.filter_by(username=username).first():
                errors.append('That username is already taken.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('register.html', username=username, email=email,
                                   requested_role=request.form.get('requested_role', 'standard_user'))

        # Map the requested access level to an internal role
        raw_role     = request.form.get('requested_role', 'standard_user')
        internal_role = _ROLE_MAP.get(raw_role, 'viewer')

        # Create user — pending admin approval
        user = User(
            username       = username,
            email          = email,
            role           = internal_role,
            is_approved    = False,
            requested_role = raw_role,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Access request submitted. You can log in once an admin approves your account.', 'info')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        ip = request.remote_addr

        # IP-level rate limiting
        if is_rate_limited(ip):
            secs = remaining_lockout(ip)
            _record_login(None, request.form.get('identifier', ''), False, 'rate_limited')
            flash(f'Too many failed attempts. Try again in {secs} seconds.', 'error')
            return render_template('login.html')

        identifier = sanitize(request.form.get('identifier', '').lower())
        password   = request.form.get('password', '')
        remember   = request.form.get('remember_me') == 'on'

        if not identifier or not password:
            flash('Please enter your email/username and password.', 'error')
            return render_template('login.html')

        # Find user by email or username (case-insensitive)
        user = User.query.filter(
            (db.func.lower(User.email) == identifier) | (db.func.lower(User.username) == identifier)
        ).first()

        # Approval gate — account exists but admin hasn't approved yet
        if user and not user.is_approved:
            _record_login(user, identifier, False, 'pending_approval')
            flash('Invalid email/username or password.', 'error')
            return render_template('login.html')

        # Account-level lockout
        if user and user.is_locked():
            _record_login(user, identifier, False, 'account_locked')
            flash('Invalid email/username or password.', 'error')
            return render_template('login.html')

        # If previous lockout window has expired, reset counter
        if user and not user.is_locked() and user.locked_until:
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()

        if user and user.check_password(password):
            # Successful login — reset counters
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()

            # Show last successful login before this one
            prev = (LoginHistory.query
                    .filter_by(user_id=user.id, success=True)
                    .order_by(LoginHistory.login_at.desc())
                    .offset(1).first())
            if prev:
                flash(f'Previous login: {prev.login_at.strftime("%d %b %Y %H:%M")} '
                      f'from {prev.ip_address}', 'info')

            # Record this login and store its ID for logout tracking
            hist_id = _record_login(user, identifier, True)
            session['_login_history_id'] = hist_id
            session['_session_version'] = getattr(user, 'session_version', 1) or 1

            login_user(user, remember=remember)
            session.permanent = True

            next_page = request.args.get('next') or request.form.get('next')
            if not is_safe_redirect_url(next_page):
                next_page = None
            flash(f'Welcome back, {user.username}! Role: {user.role.capitalize()}', 'success')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            # Failed login
            record_attempt(ip)

            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    _record_login(user, identifier, False, 'account_locked')
                else:
                    _record_login(user, identifier, False, 'wrong_password')
                db.session.commit()
            else:
                _record_login(None, identifier, False, 'not_found')
            flash('Invalid email/username or password.', 'error')

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    # Stamp logout time on the LoginHistory row created at login
    hist_id = session.get('_login_history_id')
    if hist_id:
        try:
            hist = db.session.get(LoginHistory, hist_id)
            if hist and not hist.logout_at:
                hist.logout_at = datetime.utcnow()
                db.session.commit()
        except Exception:
            db.session.rollback()

    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


# ─────────────────────────────────────────────
# Password Reset
# ─────────────────────────────────────────────

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("10/minute")
def forgot_password():
    if request.method == 'POST':
        email = sanitize(request.form.get('email', '').lower())
        user  = User.query.filter_by(email=email).first()

        # Always show the same message to prevent email enumeration
        flash('If an account with that email exists, a reset link has been sent.', 'info')

        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

            # In production, email the link. Log event safely without leaking the token or reset URL.
            import logging
            logging.getLogger(__name__).info("[AUTH] Password reset requested for %s", email)

        return redirect(url_for('auth.login'))

    return render_template('forgot_password.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user or not user.reset_token_expiry or datetime.utcnow() > user.reset_token_expiry:
        flash('This reset link is invalid or has expired.', 'error')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        errors   = validate_password(password)

        if password != confirm:
            errors.append('Passwords do not match.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('reset_password.html', token=token)

        user.set_password(password)
        user.reset_token = None
        user.reset_token_expiry = None
        user.failed_login_attempts = 0
        user.locked_until = None
        user.session_version = (getattr(user, 'session_version', 1) or 1) + 1
        db.session.commit()

        flash('Password updated successfully. Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=token)
