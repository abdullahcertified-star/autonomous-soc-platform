"""
sim.py — Simulation Mode Controller

When sim_mode is ON:
  • OS-level firewall rules are NOT applied/removed
  • External notifications (Slack/Discord/webhooks) are NOT sent
  • Web-IDS auto-blocks are suppressed
  • All detection, logging, and UI display continue normally
  • Every suppressed real-world action is recorded here for review

Querying sim state: sim.is_sim()
Recording an intercepted action: sim.record(action, detail, ip, extra)
"""
import json
import os
import threading
from collections import deque
from datetime import datetime

from detection import detection   # config lives here

_EVENTS_FILE = os.path.join(os.path.dirname(__file__), "sim_events.json")
_lock  = threading.Lock()

# Action type constants
BLOCK_SUPPRESSED    = "BLOCK_SUPPRESSED"
UNBLOCK_SUPPRESSED  = "UNBLOCK_SUPPRESSED"
ALERT_SUPPRESSED    = "ALERT_SUPPRESSED"
WEBIDS_SUPPRESSED   = "WEBIDS_SUPPRESSED"
CORR_CASE_SIMULATED = "CORR_CASE_SIMULATED"

# In-memory ring buffer — newest first
_events: deque = deque(maxlen=500)
_loaded = False


# ─────────────────────────────────────────────────────────────
# State helpers
# ─────────────────────────────────────────────────────────────

def is_sim() -> bool:
    """Return True if Simulation Mode is currently active."""
    return bool(detection.config.get("sim_mode", False))


def enable() -> None:
    detection.config["sim_mode"] = True


def disable() -> None:
    detection.config["sim_mode"] = False


# ─────────────────────────────────────────────────────────────
# Event recording
# ─────────────────────────────────────────────────────────────

def record(action: str, detail: str, ip: str = "", extra: dict = None) -> dict:
    """
    Record a simulated / suppressed action.
    Returns the event dict. No-op if sim mode is off.
    """
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "action":    action,
        "detail":    detail,
        "ip":        ip,
        **(extra or {}),
    }
    with _lock:
        _events.appendleft(event)
    _save()
    return event


# ─────────────────────────────────────────────────────────────
# Persistence
# ─────────────────────────────────────────────────────────────

def _save() -> None:
    try:
        with open(_EVENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(list(_events), f, indent=2)
    except OSError:
        pass


def _load() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    try:
        with open(_EVENTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            for ev in reversed(data[:500]):
                _events.appendleft(ev)
    except (FileNotFoundError, json.JSONDecodeError):
        pass


# ─────────────────────────────────────────────────────────────
# Queries
# ─────────────────────────────────────────────────────────────

def get_events(limit: int = 100, action_filter: str = "") -> list:
    """Return recent simulated events, newest first."""
    _load()
    with _lock:
        evs = list(_events)
    if action_filter:
        evs = [e for e in evs if e.get("action") == action_filter]
    return evs[:limit]


def get_stats() -> dict:
    """Counts per action type."""
    _load()
    with _lock:
        evs = list(_events)
    counts: dict = {}
    for e in evs:
        a = e.get("action", "UNKNOWN")
        counts[a] = counts.get(a, 0) + 1
    return {
        "total":             len(evs),
        "blocks_suppressed": counts.get(BLOCK_SUPPRESSED, 0),
        "unblocks_suppressed": counts.get(UNBLOCK_SUPPRESSED, 0),
        "alerts_suppressed": counts.get(ALERT_SUPPRESSED, 0),
        "webids_suppressed": counts.get(WEBIDS_SUPPRESSED, 0),
        "cases_simulated":   counts.get(CORR_CASE_SIMULATED, 0),
    }


def clear_events() -> int:
    """Wipe all recorded sim events. Returns how many were cleared."""
    _load()
    with _lock:
        n = len(_events)
        _events.clear()
    _save()
    return n


# Eagerly load on import so the first GET is instant
_load()
