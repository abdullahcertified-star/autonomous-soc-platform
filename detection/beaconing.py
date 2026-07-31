"""
beaconing.py — C2 Beaconing & Lateral Movement Detection

Detects two attack patterns without touching the existing detection pipeline:

1. BEACONING (C2 callback detection)
   • Tracks connection intervals for each (src_ip, dst_ip) pair
   • Flags flows where the inter-arrival time is suspiciously regular
   • Low jitter (coefficient of variation < 0.15) + sufficient sample size
   • Typical C2 implants beacon every 30–300 seconds with low randomness

2. LATERAL MOVEMENT
   • Tracks how many unique internal hosts each internal source contacts
   • Flags sources that rapidly fan out to many internal destinations
   • Separate from port-scan detection — focuses on breadth of host reach

Both detectors are passive observers; they append to module-level deques
that the API layer reads. They never modify sniffer or detection state.
"""
import threading
import time
import math
from collections import defaultdict, deque
from utils import ts

# ── State ─────────────────────────────────────────────────────────────────────
beaconing_events  = deque(maxlen=200)
lateral_events    = deque(maxlen=200)
_lock             = threading.Lock()

# {(src, dst): [epoch_float, ...]}  — ring of last N connection timestamps
_flow_times: dict  = defaultdict(lambda: deque(maxlen=60))

# {src_ip: set(dst_ips)}  — lateral movement: internal→internal fan-out
_lateral_map: dict = defaultdict(set)

# Rate-limit: don't re-alert the same flow within this window
_last_beacon_alert: dict = {}   # {(src,dst): epoch}
_last_lateral_alert: dict= {}   # {src: epoch}
_ALERT_COOLDOWN = 120.0         # seconds


# ── Tuning constants ──────────────────────────────────────────────────────────
MIN_SAMPLES         = 8         # minimum observations before evaluating
MAX_CV              = 0.20      # coefficient of variation threshold (lower = more regular)
MIN_INTERVAL        = 5.0       # ignore sub-5s intervals (not C2 beaconing)
MAX_INTERVAL        = 600.0     # ignore >10-min gaps (session timeouts, not beacons)
LATERAL_THRESHOLD   = 6         # unique internal hosts before flagging lateral movement
LATERAL_WINDOW      = 120.0     # seconds to consider for lateral movement fan-out


# ── Internal IP check ─────────────────────────────────────────────────────────
import ipaddress as _ipa
_PRIVATE = [
    _ipa.ip_network('10.0.0.0/8'),
    _ipa.ip_network('172.16.0.0/12'),
    _ipa.ip_network('192.168.0.0/16'),
]

def _is_private(ip: str) -> bool:
    try:
        a = _ipa.ip_address(ip)
        return any(a in n for n in _PRIVATE)
    except ValueError:
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def observe(src_ip: str, dst_ip: str, now: float = None) -> None:
    """
    Called once per accepted packet from the sniffer pipeline.
    Lightweight: just records timestamps and updates fan-out map.
    """
    if now is None:
        now = time.time()

    key = (src_ip, dst_ip)
    with _lock:
        _flow_times[key].append(now)
        if _is_private(src_ip) and _is_private(dst_ip):
            _lateral_map[src_ip].add(dst_ip)

    _check_beaconing(src_ip, dst_ip, now)
    _check_lateral(src_ip, now)


def _check_beaconing(src: str, dst: str, now: float) -> None:
    key = (src, dst)
    times = list(_flow_times[key])
    if len(times) < MIN_SAMPLES:
        return

    # Compute inter-arrival intervals
    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
    intervals = [iv for iv in intervals if MIN_INTERVAL <= iv <= MAX_INTERVAL]
    if len(intervals) < MIN_SAMPLES - 1:
        return

    mean = sum(intervals) / len(intervals)
    if mean < MIN_INTERVAL:
        return

    std  = math.sqrt(sum((x - mean) ** 2 for x in intervals) / len(intervals))
    cv   = std / mean if mean > 0 else 1.0

    if cv > MAX_CV:
        return

    # Rate-limit alerts
    if now - _last_beacon_alert.get(key, 0) < _ALERT_COOLDOWN:
        return
    _last_beacon_alert[key] = now

    confidence = max(30, min(95, int((1 - cv / MAX_CV) * 80 + 15)))
    event = {
        "time":        ts(),
        "src_ip":      src,
        "dst_ip":      dst,
        "attack_type": "C2 Beaconing",
        "severity":    "HIGH" if confidence >= 70 else "MEDIUM",
        "confidence":  confidence,
        "interval_mean": round(mean, 1),
        "interval_cv":   round(cv, 3),
        "sample_count":  len(intervals),
        "msg": (f"Beacon detected: {src} → {dst} | "
                f"avg interval {mean:.1f}s ± {std:.1f}s (CV={cv:.3f})"),
    }
    beaconing_events.appendleft(event)

    try:
        from core.database import log_event
        log_event({"type": "BEACONING", "ip": src, "dst": dst,
                   "severity": event["severity"], "confidence": confidence,
                   "msg": event["msg"]})
    except Exception:
        pass

    try:
        from reporting import notifications
        notifications.send_alert(
            "C2 Beaconing Detected", event["msg"],
            severity=event["severity"], src_ip=src,
        )
    except Exception:
        pass


def _check_lateral(src: str, now: float) -> None:
    if not _is_private(src):
        return

    dsts = _lateral_map.get(src, set())
    if len(dsts) < LATERAL_THRESHOLD:
        return

    if now - _last_lateral_alert.get(src, 0) < _ALERT_COOLDOWN:
        return
    _last_lateral_alert[src] = now

    event = {
        "time":        ts(),
        "src_ip":      src,
        "attack_type": "Lateral Movement",
        "severity":    "HIGH",
        "unique_targets": len(dsts),
        "targets_sample": list(dsts)[:10],
        "msg": f"Lateral movement: {src} contacted {len(dsts)} internal hosts",
    }
    lateral_events.appendleft(event)

    try:
        from core.database import log_event
        log_event({"type": "LATERAL_MOVEMENT", "ip": src,
                   "severity": "HIGH", "msg": event["msg"]})
    except Exception:
        pass

    try:
        from reporting import notifications
        notifications.send_alert("Lateral Movement Detected", event["msg"],
                                 severity="HIGH", src_ip=src)
    except Exception:
        pass


def reset_state() -> None:
    with _lock:
        beaconing_events.clear()
        lateral_events.clear()
        _flow_times.clear()
        _lateral_map.clear()
        _last_beacon_alert.clear()
        _last_lateral_alert.clear()


def get_summary() -> dict:
    return {
        "beaconing_count": len(beaconing_events),
        "lateral_count":   len(lateral_events),
        "tracked_flows":   len(_flow_times),
        "beaconing":       list(beaconing_events)[:20],
        "lateral":         list(lateral_events)[:20],
    }
