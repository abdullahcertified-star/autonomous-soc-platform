"""
incident_manager.py — Thread-safe incident lifecycle and attacker registry.

Merges repeated detections into OPEN→ACTIVE→RESOLVED lifecycles instead of
spawning duplicate incident rows for every packet.
"""
from __future__ import annotations

import threading
import time
import urllib.request
import json as _json
import ipaddress
from collections import deque

from utils import ts

# ── Exported state (Flask blueprints import these via sniffer facade) ────────
incidents: dict = {}
top_attackers: dict = {}

_incident_lock = threading.Lock()
_attacker_lock = threading.Lock()
_incident_counter = 0
_incident_ctr_lock = threading.Lock()

_last_attack_epoch: float = 0.0
_latch_lock = threading.Lock()

# GeoIP async worker
_geoip_cache: dict = {}
_geoip_queue: deque = deque()
_geoip_lock = threading.Lock()

DIST_KEY = "INC-DIST"


def _new_incident_id() -> str:
    global _incident_counter
    with _incident_ctr_lock:
        _incident_counter += 1
        return f"INC-{_incident_counter:04d}"


def _fmt_duration(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    return f"{m}m {s:02d}s"


def _apply_elapsed(inc: dict, now: float) -> None:
    elapsed = now - inc["start_epoch"]
    inc["duration_seconds"] = elapsed
    inc["duration"] = _fmt_duration(elapsed)


def severity_score(confidence: int, rate_metric: float) -> int:
    """Map confidence and an observed rate scalar to 0-100."""
    r = min(float(rate_metric), 5000.0)
    return min(100, int(confidence * 0.5 + r * 0.01))


def correlation_key(src: str, proto: str, attack_kind: str) -> str:
    """Stable merge key — separate floods from scans from arp, etc."""
    pb = proto if proto in ("TCP", "UDP", "ICMP", "DNS") else "OTHER"
    return f"{src}|{pb}|{attack_kind}"


def touch_attack_latch(now: float | None = None) -> None:
    try:
        from detection import network_profiler
        if not network_profiler.is_ready():
            return
    except Exception:
        pass
    global _last_attack_epoch
    t = now if now is not None else time.time()
    with _latch_lock:
        _last_attack_epoch = t


def get_last_attack_epoch() -> float:
    with _latch_lock:
        return _last_attack_epoch


def reset_attack_latch() -> None:
    """Zero the attack latch so the dashboard returns to SECURE immediately."""
    global _last_attack_epoch
    with _latch_lock:
        _last_attack_epoch = 0.0


def register_incident(
    *,
    src: str,
    proto: str,
    attack_kind: str,
    severity: str,
    confidence: int,
    rate_metric: float,
    attack_type: str,
) -> None:
    """Create or update an incident for sustained HIGH/MEDIUM severity."""
    if severity not in ("HIGH", "MEDIUM"):
        return

    now = time.time()
    now_ts = ts()
    touch_attack_latch(now)

    score = severity_score(confidence, rate_metric)
    ckey = correlation_key(src, proto, attack_kind)

    with _incident_lock:
        existing = None
        for inc in incidents.values():
            if inc.get("_corr_key") == ckey and inc["status"] in ("OPEN", "ACTIVE"):
                existing = inc
                break

        if existing:
            _apply_elapsed(existing, now)
            existing["status"] = "ACTIVE"
            existing["end_time"] = now_ts
            existing["last_update_epoch"] = now
            existing["severity_score"] = max(int(existing.get("severity_score", 0)), score)
            existing["attack_type"] = attack_type
            existing["packet_count"] = int(existing.get("packet_count", 0)) + 1
        else:
            inc_id = _new_incident_id()
            incidents[inc_id] = {
                "incident_id": inc_id,
                "_corr_key": ckey,
                "source_ip": src,
                "protocol": proto,
                "attack_kind": attack_kind,
                "start_time": now_ts,
                "end_time": now_ts,
                "start_epoch": now,
                "last_update_epoch": now,
                "duration_seconds": 0,
                "duration": "0s",
                "status": "OPEN",
                "severity_score": score,
                "attack_type": attack_type,
                "packet_count": 1,
                "confidence": confidence,
            }


def update_attacker(src: str, **fields: object) -> None:
    with _attacker_lock:
        if src not in top_attackers:
            top_attackers[src] = {
                "ip": src,
                "packet_count": 0,
                "severity_score": 0,
                "last_seen": "",
                "last_seen_epoch": 0.0,
                "attack_type": "Normal",
                "country": str(fields.get("country", "Unknown")),
                "direction": str(fields.get("direction", "UNKNOWN")),
            }
            with _geoip_lock:
                if src not in _geoip_cache:
                    _geoip_queue.append(src)
        ta = top_attackers[src]
        ta["packet_count"] = int(ta.get("packet_count", 0)) + 1
        ta["last_seen"] = ts()
        ta["last_seen_epoch"] = time.time()
        for k in ("direction", "attack_type", "country"):
            if k in fields and fields[k] is not None:
                ta[k] = fields[k]
        if "severity_score" in fields and fields["severity_score"] is not None:
            ta["severity_score"] = max(
                int(ta.get("severity_score", 0)),
                int(fields["severity_score"]),
            )


def merge_distributed_incident(dist_pb: str, total_pkts: int, unique_srcs: int, label: str) -> None:
    now = time.time()
    now_ts = ts()
    touch_attack_latch(now)
    score = min(100, 40 + unique_srcs * 2)
    with _incident_lock:
        key = DIST_KEY
        if key in incidents and incidents[key]["status"] in ("OPEN", "ACTIVE"):
            inc = incidents[key]
            _apply_elapsed(inc, now)
            inc["status"] = "ACTIVE"
            inc["end_time"] = now_ts
            inc["last_update_epoch"] = now
            inc["packet_count"] = total_pkts
            inc["severity_score"] = max(inc.get("severity_score", 0), score)
            inc["attack_type"] = label
        else:
            incidents[key] = {
                "incident_id": key,
                "_corr_key": "DISTRIBUTED|" + dist_pb,
                "source_ip": "DISTRIBUTED",
                "protocol": "MIXED",
                "attack_kind": "distributed",
                "start_time": now_ts,
                "end_time": now_ts,
                "start_epoch": now,
                "last_update_epoch": now,
                "duration_seconds": 0,
                "duration": "0s",
                "status": "OPEN",
                "severity_score": score,
                "attack_type": label,
                "packet_count": total_pkts,
                "confidence": 85,
            }


def resolve_stale_incidents() -> None:
    """Background: mark incidents RESOLVED after silence."""
    while True:
        time.sleep(10)
        now = time.time()
        now_ts = ts()
        with _incident_lock:
            for inc in incidents.values():
                if inc["status"] not in ("OPEN", "ACTIVE"):
                    continue
                last_t = inc.get("last_update_epoch", inc.get("start_epoch", now))
                if now - last_t >= 30:
                    _apply_elapsed(inc, now)
                    inc["status"] = "RESOLVED"
                    inc["end_time"] = now_ts


def _is_private_or_local(ip: str) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved
    except ValueError:
        return False


def _geoip_worker() -> None:
    while True:
        ip = None
        with _geoip_lock:
            if _geoip_queue:
                ip = _geoip_queue.popleft()
        if ip is None:
            time.sleep(2)
            continue
        with _geoip_lock:
            cached = _geoip_cache.get(ip)
        if cached:
            with _attacker_lock:
                if ip in top_attackers:
                    top_attackers[ip]["country"] = cached
            continue

        if _is_private_or_local(ip):
            with _geoip_lock:
                _geoip_cache[ip] = "LAN"
            with _attacker_lock:
                if ip in top_attackers:
                    top_attackers[ip]["country"] = "LAN"
            continue

        try:
            url = f"http://ip-api.com/json/{ip}?fields=countryCode"
            req = urllib.request.Request(url, headers={"User-Agent": "SOC/2.0"})
            with urllib.request.urlopen(req, timeout=4) as r:
                data = _json.loads(r.read())
            code = data.get("countryCode", "").strip()
            if code:
                with _geoip_lock:
                    _geoip_cache[ip] = code
                with _attacker_lock:
                    if ip in top_attackers:
                        top_attackers[ip]["country"] = code
        except Exception:
            pass
        time.sleep(1.5)


_services_started = False
_services_lock = threading.Lock()


def lookup_country(ip: str) -> str:
    """Non-blocking: return cached GeoIP country code, or queue lookup and return ''."""
    if not ip or not isinstance(ip, str):
        return ""
    if _is_private_or_local(ip):
        with _geoip_lock:
            _geoip_cache[ip] = "LAN"
        return "LAN"
    with _geoip_lock:
        if ip in _geoip_cache:
            return _geoip_cache[ip]
        if ip not in _geoip_queue:
            _geoip_queue.append(ip)
    return ""


def start_incident_services() -> None:
    """Idempotent: start GeoIP worker and incident resolver (call from sniffer)."""
    global _services_started
    with _services_lock:
        if _services_started:
            return
        _services_started = True
        threading.Thread(target=_geoip_worker, daemon=True, name="geoip-worker").start()
        threading.Thread(target=resolve_stale_incidents, daemon=True, name="incident-resolver").start()


def reset_all() -> None:
    with _incident_lock:
        incidents.clear()
    with _attacker_lock:
        top_attackers.clear()
    with _geoip_lock:
        _geoip_cache.clear()
        _geoip_queue.clear()
