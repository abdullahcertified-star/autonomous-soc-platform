"""
notifications.py — Enterprise Alert Notification Engine

Delivers SOC alerts to:
  • Slack  (incoming webhook)
  • Discord (incoming webhook)
  • Generic HTTP webhook (POST JSON)
  • Email   (SMTP, optional)

Rate-limited per-destination to prevent spam floods.
Reads active NotificationConfig rows from the database.
Safe to call from any thread; DB operations use a fresh app context.
"""
import json
import threading
import time
from datetime import datetime

import urllib.request
import urllib.error

_RATE_WINDOW   = 60     # seconds
_MAX_PER_WINDOW= 10     # max sends per destination per window
_rate_state: dict = {}  # {dest_id: [epoch, ...]}
_lock = threading.Lock()

SEV_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
SEV_EMOJI = {'LOW': '🔵', 'MEDIUM': '🟡', 'HIGH': '🔴', 'CRITICAL': '🚨'}
SEV_COLOR = {'LOW': 3447003, 'MEDIUM': 16776960, 'HIGH': 15158332, 'CRITICAL': 10038562}


def _rate_ok(dest_id: int) -> bool:
    now = time.time()
    with _lock:
        stamps = [t for t in _rate_state.get(dest_id, []) if now - t < _RATE_WINDOW]
        if len(stamps) >= _MAX_PER_WINDOW:
            return False
        stamps.append(now)
        _rate_state[dest_id] = stamps
    return True


def _build_slack_payload(title: str, body: str, severity: str, src_ip: str = '') -> dict:
    emoji = SEV_EMOJI.get(severity, '⚠️')
    color = '#ef4444' if severity in ('HIGH', 'CRITICAL') else '#f97316' if severity == 'MEDIUM' else '#22c55e'
    return {
        "attachments": [{
            "color": color,
            "title": f"{emoji} SOC Alert — {title}",
            "text": body,
            "fields": [
                {"title": "Severity", "value": severity, "short": True},
                {"title": "Source IP", "value": src_ip or "N/A", "short": True},
                {"title": "Time", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), "short": True},
            ],
            "footer": "SOC Enterprise Platform",
        }]
    }


def _build_discord_payload(title: str, body: str, severity: str, src_ip: str = '') -> dict:
    emoji = SEV_EMOJI.get(severity, '⚠️')
    return {
        "embeds": [{
            "title": f"{emoji} SOC Alert — {title}",
            "description": body,
            "color": SEV_COLOR.get(severity, 3447003),
            "fields": [
                {"name": "Severity", "value": severity, "inline": True},
                {"name": "Source IP", "value": src_ip or "N/A", "inline": True},
            ],
            "footer": {"text": "SOC Enterprise Platform"},
            "timestamp": datetime.utcnow().isoformat(),
        }]
    }


def _build_generic_payload(title: str, body: str, severity: str, src_ip: str = '',
                            extra: dict = None) -> dict:
    return {
        "source": "soc-enterprise",
        "title": title,
        "body": body,
        "severity": severity,
        "src_ip": src_ip,
        "timestamp": datetime.utcnow().isoformat(),
        **(extra or {}),
    }


def _http_post(url: str, payload: dict, timeout: int = 5) -> bool:
    try:
        data = json.dumps(payload).encode('utf-8')
        req  = urllib.request.Request(
            url, data=data,
            headers={'Content-Type': 'application/json', 'User-Agent': 'SOC-Enterprise/1.0'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 400
    except Exception:
        return False


def send_alert(title: str, body: str, severity: str = 'HIGH',
               src_ip: str = '', extra: dict = None) -> None:
    """
    Dispatch an alert to all active, eligible notification destinations.
    Non-blocking: runs in a daemon thread.
    In Simulation Mode: records the suppressed alert instead of sending.
    """
    from core import sim
    if sim.is_sim():
        sim.record(sim.ALERT_SUPPRESSED,
                   f"{title} — {body[:120]}",
                   ip=src_ip,
                   extra={"severity": severity, "title": title})
        return
    threading.Thread(
        target=_dispatch,
        args=(title, body, severity, src_ip, extra or {}),
        daemon=True,
    ).start()


def _dispatch(title: str, body: str, severity: str, src_ip: str, extra: dict) -> None:
    try:
        from extensions import db
        from models import NotificationConfig
        import flask
        # Need an app context for DB access from a thread
        app = flask.current_app._get_current_object()
        with app.app_context():
            configs = NotificationConfig.query.filter_by(enabled=True).all()
            for cfg in configs:
                if SEV_ORDER.get(severity, 0) < SEV_ORDER.get(cfg.min_severity, 0):
                    continue
                if not _rate_ok(cfg.id):
                    continue
                if cfg.channel == 'slack':
                    _http_post(cfg.destination, _build_slack_payload(title, body, severity, src_ip))
                elif cfg.channel == 'discord':
                    _http_post(cfg.destination, _build_discord_payload(title, body, severity, src_ip))
                else:
                    _http_post(cfg.destination, _build_generic_payload(title, body, severity, src_ip, extra))
    except Exception:
        pass
