"""
soc_logger.py — Centralized SOC Structured Logging

Features:
  • Structured JSON log entries with source tagging
  • In-memory ring buffer (1 000 entries) for live dashboard queries
  • File-based persistent log at logs/soc.log
  • Severity levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

Usage:
    from core import soc_logger as log
    log.info("detection", "SYN flood confirmed", {"ip": "1.2.3.4", "rate": 8000})
    log.critical("firewall", "Block applied", {"ip": "5.6.7.8"})
"""
import logging
from logging.handlers import RotatingFileHandler
import json
import threading
import time
import os
from collections import deque
from datetime import datetime

# ── File setup ────────────────────────────────────────────────────────────────

_LOG_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "soc.log")
os.makedirs(_LOG_DIR, exist_ok=True)

# ── In-memory ring buffer ─────────────────────────────────────────────────────

_recent: deque = deque(maxlen=1000)
_lock = threading.Lock()
_seq  = 0

# ── File logger ───────────────────────────────────────────────────────────────

_fh = RotatingFileHandler(_LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
_lg = logging.getLogger("soc_platform")
_lg.setLevel(logging.DEBUG)
_lg.addHandler(_fh)
_lg.propagate = False


# ── Internal emit ─────────────────────────────────────────────────────────────

def _emit(level: str, source: str, message: str, data: dict = None):
    global _seq
    with _lock:
        _seq += 1
        entry = {
            "seq":     _seq,
            "time":    datetime.utcnow().isoformat(),
            "epoch":   time.time(),
            "level":   level,
            "source":  source,
            "message": message,
            "data":    data or {},
        }
        _recent.appendleft(entry)

    payload = json.dumps({"src": source, "msg": message, **(data or {})})
    getattr(_lg, level.lower(), _lg.info)(payload)


# ── Public logging API ────────────────────────────────────────────────────────

def debug(source: str, message: str, data: dict = None):
    _emit("DEBUG", source, message, data)

def info(source: str, message: str, data: dict = None):
    _emit("INFO", source, message, data)

def warning(source: str, message: str, data: dict = None):
    _emit("WARNING", source, message, data)

def error(source: str, message: str, data: dict = None):
    _emit("ERROR", source, message, data)

def critical(source: str, message: str, data: dict = None):
    _emit("CRITICAL", source, message, data)


# ── Query helpers ─────────────────────────────────────────────────────────────

def get_recent(limit: int = 200, level: str = None, source: str = None) -> list:
    """Return recent log entries with optional level/source filters."""
    with _lock:
        logs = list(_recent)
    if level:
        logs = [l for l in logs if l["level"] == level.upper()]
    if source:
        logs = [l for l in logs if source.lower() in l["source"].lower()]
    return logs[:limit]


def get_stats() -> dict:
    with _lock:
        logs = list(_recent)
    counts: dict = {}
    for entry in logs:
        counts[entry["level"]] = counts.get(entry["level"], 0) + 1
    return {
        "total":    len(logs),
        "by_level": counts,
        "log_file": _LOG_FILE,
    }
