"""
web_ids.py — Web-Layer Intrusion Detection System

Detects common web attacks in HTTP request parameters:
  • SQL Injection
  • Cross-Site Scripting (XSS)
  • OS Command / Shell Injection
  • Path Traversal
  • LDAP Injection

Results are stored in a ring buffer for dashboard queries and optionally
trigger IP blocks via the firewall module.
"""
import re
import time
import threading
from collections import defaultdict, deque
from datetime import datetime

# ── Compiled attack signatures ────────────────────────────────────────────────

_SQLI = [
    re.compile(r"\b(union\s+select|select\s+\S+\s+from|insert\s+into|update\s+\S+\s+set|delete\s+from|drop\s+table|create\s+table|alter\s+table)\b", re.I),
    re.compile(r"(--|#|\/\*[\s\S]*?\*\/)", re.I),
    re.compile(r"\b(or|and)\b\s+\d+\s*=\s*\d+", re.I),
    re.compile(r"(sleep\s*\(\s*\d+|benchmark\s*\(|waitfor\s+delay\b)", re.I),
    re.compile(r"\b(xp_cmdshell|information_schema|sysobjects|syscolumns|sys\.tables)\b", re.I),
    re.compile(r"('|\")\s*;\s*(drop|alter|create|insert|delete)\b", re.I),
    re.compile(r"(\bchar\s*\(|\bcast\s*\(|\bconvert\s*\().*\bfrom\b", re.I),
]

_XSS = [
    re.compile(r"<\s*script[^>]*>", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"\bon(load|error|click|mouseover|focus|blur|keyup|keydown|input|change)\s*=", re.I),
    re.compile(r"<\s*iframe[^>]*>", re.I),
    re.compile(r"document\s*\.\s*(cookie|write|location|domain|referrer)", re.I),
    re.compile(r"window\s*\.\s*(location|open|navigate|eval)", re.I),
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\bexpression\s*\(", re.I),
    re.compile(r"<\s*(img|svg|body|input)[^>]+\bon\w+\s*=", re.I),
]

_CMD = [
    re.compile(r"[;&|`]\s*(cat|ls|dir|whoami|id|uname|hostname|pwd|echo|rm\s|cp\s|mv\s|wget|curl|nc\s|ncat|python|perl|ruby|php)\b", re.I),
    re.compile(r"\$\([^)]{0,100}\)", re.I),
    re.compile(r"`[^`]{0,100}`", re.I),
    re.compile(r"(\.\.[\\/]){2,}", re.I),
    re.compile(r"\b(etc\/passwd|etc\/shadow|proc\/self|windows\/system32\/cmd\.exe)\b", re.I),
    re.compile(r"\b(cmd\.exe|\/bin\/(sh|bash|dash)|powershell(\.exe)?)\b", re.I),
]

_LDAP = [
    re.compile(r"\(\s*\|", re.I),
    re.compile(r"\(\s*&", re.I),
    re.compile(r"\*\s*\)", re.I),
    re.compile(r"[)(|&*]{3,}", re.I),
]

# ── Detection metadata ────────────────────────────────────────────────────────

_SIGNATURE_MAP = [
    ("sql_injection",     "HIGH",     _SQLI),
    ("xss",               "HIGH",     _XSS),
    ("command_injection", "CRITICAL", _CMD),
    ("ldap_injection",    "MEDIUM",   _LDAP),
]

# ── Thread-safe event store ───────────────────────────────────────────────────

web_events: deque = deque(maxlen=500)
ip_attack_counts: dict = defaultdict(int)
_lock = threading.Lock()


# ── Core detection function ───────────────────────────────────────────────────

def _check_value(value: str) -> list:
    """Return list of (attack_type, severity) for each signature match."""
    hits = []
    for attack_type, severity, patterns in _SIGNATURE_MAP:
        for pat in patterns:
            if pat.search(value):
                hits.append((attack_type, severity))
                break  # one match per category is enough
    return hits


def inspect_request(ip: str, path: str, args: dict, form: dict, body: str = "") -> list:
    """
    Inspect an HTTP request for web-layer attacks.

    Returns a list of detection dicts (empty list = request is clean).
    Side-effect: appends to web_events and increments ip_attack_counts.
    """
    candidates = []

    for param_dict in (args, form):
        for key, val in param_dict.items():
            if isinstance(val, (list, tuple)):
                val = " ".join(str(v) for v in val)
            candidates.append(f"{key} {val}")

    if body:
        candidates.append(body[:8192])  # inspect first 8 KB of body

    detections = []
    seen_types = set()
    for candidate in candidates:
        for attack_type, severity in _check_value(candidate):
            if attack_type not in seen_types:
                seen_types.add(attack_type)
                detections.append({"attack_type": attack_type, "severity": severity})

    if detections:
        with _lock:
            for det in detections:
                ip_attack_counts[ip] += 1
                web_events.appendleft({
                    "time":        datetime.now().strftime("%H:%M:%S"),
                    "epoch":       time.time(),
                    "ip":          ip,
                    "path":        path[:200],
                    "attack_type": det["attack_type"],
                    "severity":    det["severity"],
                })

    return detections


# ── Query helpers ─────────────────────────────────────────────────────────────

def get_events(limit: int = 100) -> list:
    with _lock:
        return list(web_events)[:limit]


def get_stats() -> dict:
    with _lock:
        top = sorted(
            [{"ip": ip, "count": c} for ip, c in ip_attack_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]
        return {
            "total_events":        len(web_events),
            "unique_attacker_ips": len(ip_attack_counts),
            "top_attackers":       top,
        }
