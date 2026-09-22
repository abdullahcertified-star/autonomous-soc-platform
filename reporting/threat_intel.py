"""
threat_intel.py — Threat Intelligence Engine

Features:
  • In-memory + DB-backed IOC store (IPs, domains, hashes)
  • AbuseIPDB API integration for live IP reputation scoring
  • Bundled static blocklist of known-bad infrastructure IPs
  • check_ip(ip) — fast IOC lookup, returns threat context or None
  • Configurable via protection_settings (api keys stored there)
  • Results cached with TTL to reduce API calls
  • Auto-loads IOCs from DB on startup

The module never modifies detection.py or sniffer.py state.
"""
import threading
import time
import json
import urllib.request
import urllib.error
from collections import OrderedDict
from datetime import datetime, timedelta

from core import protection_settings
from core.database import log_event
from utils import ts

# ── Cache ─────────────────────────────────────────────────────────────────────
_CACHE_TTL    = 3600      # seconds before re-querying AbuseIPDB for same IP
_CACHE_SIZE   = 2000
_cache: OrderedDict = OrderedDict()   # {ip: (epoch, result_dict|None)}
_lock = threading.Lock()

# ── Known bad IPs (seed list — expanded via DB IOCEntry) ─────────────────────
# A minimal static seed. In production you'd load Feodo, Spamhaus, etc.
_STATIC_BAD: dict = {
    # Feodo Tracker samples (public threat intel, illustrative)
    "185.220.101.1":  {"threat": "TOR Exit Node",     "confidence": 80},
    "185.220.101.2":  {"threat": "TOR Exit Node",     "confidence": 80},
    "198.98.56.1":    {"threat": "Botnet C2",         "confidence": 90},
    "194.165.16.1":   {"threat": "Malware C2",        "confidence": 85},
    "45.33.32.156":   {"threat": "Scanner",           "confidence": 70},
    "89.248.167.131": {"threat": "Shodan Scanner",    "confidence": 65},
    "71.6.135.131":   {"threat": "Shodan Scanner",    "confidence": 65},
    "80.82.77.139":   {"threat": "Shodan Scanner",    "confidence": 65},
}

# Loaded from DB at startup + refreshed periodically
_db_iocs: dict = {}   # {ip_value: ioc_dict}
_db_loaded = False
_app_instance = None


def init_threat_intel(app) -> None:
    """Store app reference and perform initial IOC load."""
    global _app_instance
    _app_instance = app
    _load_db_iocs()


def _load_db_iocs() -> None:
    global _db_iocs, _db_loaded
    try:
        from models import IOCEntry
        from extensions import db
        app = _app_instance
        if not app:
            try:
                import flask
                app = flask.current_app._get_current_object()
            except Exception:
                app = None
        if app:
            with app.app_context():
                entries = IOCEntry.query.filter_by(ioc_type='ip', active=True).all()
                _db_iocs = {e.value: e.to_dict() for e in entries}
                _db_loaded = True
    except Exception:
        pass


def _start_refresh_thread(app=None) -> None:
    global _app_instance
    if app:
        _app_instance = app
    def _loop():
        while True:
            time.sleep(300)
            _load_db_iocs()
    threading.Thread(target=_loop, daemon=True).start()



# ── AbuseIPDB lookup ──────────────────────────────────────────────────────────

def _query_abuseipdb(ip: str) -> dict | None:
    api_key = protection_settings.get('abuseipdb_key') or ''
    if not api_key:
        return None
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=30"
        req = urllib.request.Request(
            url,
            headers={"Key": api_key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        d = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        if score < 10:
            return None
        return {
            "source":     "abuseipdb",
            "confidence": score,
            "threat":     d.get("usageType", "Unknown"),
            "isp":        d.get("isp", ""),
            "country":    d.get("countryCode", ""),
            "reports":    d.get("totalReports", 0),
        }
    except Exception:
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def check_ip(ip: str) -> dict | None:
    """
    Look up an IP against all IOC sources.

    Returns a dict with threat context if the IP is malicious, else None.
    Result is cached for _CACHE_TTL seconds.
    """
    if not ip or ip.startswith('127.') or ip.startswith('0.'):
        return None

    now = time.time()

    with _lock:
        if ip in _cache:
            epoch, result = _cache[ip]
            if now - epoch < _CACHE_TTL:
                _cache.move_to_end(ip)
                return result
        # Evict oldest if full
        while len(_cache) >= _CACHE_SIZE:
            _cache.popitem(last=False)

    # Check static list
    if ip in _STATIC_BAD:
        result = {**_STATIC_BAD[ip], "source": "static_feed", "ip": ip}
        _cache_set(ip, result, now)
        return result

    # Check DB IOCs (loaded at startup)
    if not _db_loaded:
        _load_db_iocs()
    if ip in _db_iocs:
        entry = _db_iocs[ip]
        result = {
            "source":     entry.get("source", "db"),
            "confidence": entry.get("confidence", 50),
            "threat":     entry.get("threat_type", "IOC Match"),
            "ip":         ip,
        }
        _cache_set(ip, result, now)
        return result

    # Live AbuseIPDB query (if API key configured)
    result = _query_abuseipdb(ip)
    _cache_set(ip, result, now)

    if result:
        log_event({
            "type":     "THREAT_INTEL",
            "ip":       ip,
            "severity": "HIGH" if result["confidence"] >= 75 else "MEDIUM",
            "msg":      f"IOC match: {ip} - {result.get('threat')} (score {result['confidence']})",
            "time":     ts(),
        })
    else:
        # Autonomous Agentic AI background enrichment for uncatalogued external IP
        try:
            from core import ai_agent
            ai_agent.enrich_ip(ip)
        except Exception:
            pass

    return result


def _cache_set(ip: str, result, now: float) -> None:
    with _lock:
        _cache[ip] = (now, result)


def add_ioc(ioc_type: str, value: str, source: str = 'manual',
            confidence: int = 80, threat_type: str = '', description: str = '') -> bool:
    """Persist an IOC to the database."""
    try:
        from models import IOCEntry
        from extensions import db
        entry = IOCEntry.query.filter_by(ioc_type=ioc_type, value=value).first()
        if entry:
            entry.confidence  = confidence
            entry.threat_type = threat_type
            entry.last_seen   = datetime.utcnow()
        else:
            entry = IOCEntry(
                ioc_type=ioc_type, value=value, source=source,
                confidence=confidence, threat_type=threat_type,
                description=description,
            )
            db.session.add(entry)
        db.session.commit()
        # Invalidate cache for this IP
        with _lock:
            _cache.pop(value, None)
            if ioc_type == 'ip':
                _db_iocs[value] = entry.to_dict()
        return True
    except Exception:
        return False


def get_stats() -> dict:
    return {
        "cache_size":    len(_cache),
        "static_iocs":  len(_STATIC_BAD),
        "db_iocs":      len(_db_iocs),
        "abuseipdb_configured": bool(protection_settings.get('abuseipdb_key')),
    }


# Kick off DB refresh thread on import
_start_refresh_thread()
