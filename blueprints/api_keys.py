"""
api_keys.py — REST API Key Management

Provides:
  • key generation (prefix + SHA-256 hashed secret)
  • verify_api_key(key_string) → APIKey | None
  • Flask decorator @require_api_key(scope)
  • Blueprint with CRUD routes under /api/keys

Keys look like: soc_<random_40_hex_chars>
Only the SHA-256 hash is stored; raw key is shown once at creation.
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from extensions import db
from models import APIKey, User
from rbac import require_permission, audit

api_keys_bp = Blueprint('api_keys', __name__)

_PREFIX = 'soc_'


# ── Key utilities ─────────────────────────────────────────────────────────────

def _generate_raw() -> str:
    return _PREFIX + secrets.token_hex(20)


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def verify_api_key(raw: str):
    """Return the APIKey row if valid and active, else None."""
    if not raw or not raw.startswith(_PREFIX):
        return None
    hashed = _hash_key(raw)
    key = APIKey.query.filter_by(key_hash=hashed, active=True).first()
    if not key:
        return None
    if key.is_expired:
        return None
    key.last_used = datetime.utcnow()
    try:
        db.session.commit()
    except Exception:
        pass
    return key


# ── Auth decorator ────────────────────────────────────────────────────────────

def require_api_key(scope: str = 'read'):
    """
    Decorator for API-key-protected routes.
    Checks Authorization: Bearer soc_... header.
    Falls back to session auth so browser users still work.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer soc_'):
                raw = auth_header[7:]
                key = verify_api_key(raw)
                if not key:
                    return jsonify({'error': 'Invalid or expired API key'}), 401
                if not key.has_scope(scope):
                    return jsonify({'error': f'API key missing scope: {scope}'}), 403
                return fn(*args, **kwargs)
            # Fall back to session
            from flask_login import current_user
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ── CRUD routes ───────────────────────────────────────────────────────────────

@api_keys_bp.route('/api/keys', methods=['GET'])
@login_required
def list_keys():
    if current_user.role == 'admin':
        keys = APIKey.query.order_by(APIKey.created_at.desc()).all()
    else:
        keys = APIKey.query.filter_by(owner_id=current_user.id)\
                           .order_by(APIKey.created_at.desc()).all()
    return jsonify([k.to_dict() for k in keys])


@api_keys_bp.route('/api/keys', methods=['POST'])
@login_required
@require_permission('settings', 'write')
def create_key():
    data    = request.get_json(silent=True) or {}
    name    = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400

    scopes  = data.get('scopes', 'read')
    expires_days = data.get('expires_days')
    expires_at = (datetime.utcnow() + timedelta(days=int(expires_days))
                  if expires_days else None)

    raw     = _generate_raw()
    hashed  = _hash_key(raw)

    key = APIKey(
        name       = name,
        key_hash   = hashed,
        prefix     = raw[:12],
        owner_id   = current_user.id,
        scopes     = scopes,
        expires_at = expires_at,
    )
    db.session.add(key)
    db.session.commit()
    audit('create_api_key', name, scopes)

    result = key.to_dict()
    result['raw_key'] = raw   # shown once — never stored
    return jsonify(result), 201


@api_keys_bp.route('/api/keys/<int:key_id>', methods=['DELETE'])
@login_required
def revoke_key(key_id):
    key = APIKey.query.get_or_404(key_id)
    if key.owner_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    key.active = False
    db.session.commit()
    audit('revoke_api_key', key.name)
    return jsonify({'ok': True, 'revoked': key.name})
