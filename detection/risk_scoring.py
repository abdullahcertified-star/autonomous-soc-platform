"""
risk_scoring.py — Formal Risk Scoring Engine

Formula:
    Risk Score = attack_weight × frequency_factor × asset_value × reputation_factor × confidence × 100

Ranges:
    LOW (0–29) | MEDIUM (30–59) | HIGH (60–79) | CRITICAL (80–100)

Components:
    attack_weight      — 0.0–1.0, danger level of the attack type
    frequency_factor   — normalized packet rate, 0.0–1.0  (caps at 10 000 pps)
    asset_value        — importance of the targeted asset  (default 1.0)
    reputation_factor  — 0.5 (unknown) → 1.5 (confirmed malicious IP)
    confidence         — 0.0–1.0 from the detection engine's confidence %
"""
import threading
from typing import Optional

# ── Attack type weights ───────────────────────────────────────────────────────

ATTACK_WEIGHTS: dict = {
    "ddos":               0.90,
    "syn_flood":          0.85,
    "udp_flood":          0.80,
    "icmp_flood":         0.70,
    "port_scan":          0.60,
    "stealth_scan":       0.65,
    "brute_force":        0.80,
    "credential_stuff":   0.85,
    "sql_injection":      0.95,
    "xss":                0.70,
    "command_injection":  1.00,
    "ldap_injection":     0.65,
    "path_traversal":     0.75,
    "arp_spoofing":       0.85,
    "mitm":               0.90,
    "c2_beacon":          0.95,
    "data_exfil":         0.95,
    "unknown":            0.30,
}

# ── IP reputation cache  {ip: int 0–100, higher = more malicious} ─────────────

_rep: dict = {}
_rep_lock = threading.Lock()


# ── Public helpers ────────────────────────────────────────────────────────────

def get_weight(attack_type: str) -> float:
    """Return danger weight for an attack type string."""
    key = (attack_type or "unknown").lower().replace(" ", "_").replace("-", "_")
    return ATTACK_WEIGHTS.get(key, ATTACK_WEIGHTS["unknown"])


def get_reputation_factor(ip: str) -> float:
    """Map reputation score 0–100 → multiplier 1.0–1.5 (neutral default = 1.0)."""
    with _rep_lock:
        score = _rep.get(ip, 0)
    return 1.0 + (max(0, min(100, score)) / 200.0)


def update_reputation(ip: str, delta: int) -> int:
    """
    Adjust IP reputation score by delta (positive = more malicious).
    Clamped to [0, 100].  Returns the new score.
    """
    with _rep_lock:
        current = _rep.get(ip, 0)
        new_score = max(0, min(100, current + delta))
        _rep[ip] = new_score
    return new_score


def set_reputation(ip: str, score: int):
    """Directly set IP reputation score."""
    with _rep_lock:
        _rep[ip] = max(0, min(100, score))


# ── Core scoring function ─────────────────────────────────────────────────────

def calculate(
    attack_type: str,
    packet_count: int,
    ip: str = "",
    asset_value: float = 1.0,
    window_sec: int = 5,
    confidence: float = 1.0,
) -> dict:
    """
    Compute a normalised risk score for an event.

    Returns:
        {
            "score":      float 0–100,
            "level":      "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "components": { ... }
        }
    """
    w = get_weight(attack_type)
    pps = packet_count / max(window_sec, 1)

    atype_lower = (attack_type or "").lower()
    is_volumetric = any(k in atype_lower for k in ("flood", "ddos"))

    if is_volumetric:
        # Scale 0 to 1200+ pps with a baseline 0.35 for confirmed flood alerts
        freq = min(1.0, max(0.35, pps / 1200.0))
    else:
        # Signature/exploit/scan attacks are severe even at low packet volume
        freq = min(1.0, 0.75 + min(0.25, (packet_count / 50.0) * 0.25))

    rep = get_reputation_factor(ip) if ip else 1.0
    conf = max(0.0, min(1.0, confidence))

    raw = w * freq * asset_value * rep * conf
    score = min(100.0, round(raw * 100, 1))

    if   score >= 80: level = "CRITICAL"
    elif score >= 60: level = "HIGH"
    elif score >= 30: level = "MEDIUM"
    else:             level = "LOW"

    return {
        "score": score,
        "level": level,
        "components": {
            "attack_weight":     w,
            "frequency_factor":  round(freq, 4),
            "reputation_factor": round(rep, 2),
            "asset_value":       asset_value,
            "confidence":        round(conf, 2),
        },
    }


def score_incident(incident: dict) -> dict:
    """Convenience wrapper — derive score from a sniffer incident dict."""
    return calculate(
        attack_type  = incident.get("attack_type") or "unknown",
        packet_count = incident.get("packet_count") or incident.get("rate") or 0,
        ip           = incident.get("ip") or incident.get("src_ip") or "",
        confidence   = (incident.get("confidence") or 50) / 100.0,
    )


# ── Query helpers ─────────────────────────────────────────────────────────────

def get_all_reputations() -> list:
    """Return all cached IP reputations, sorted highest first."""
    with _rep_lock:
        return sorted(
            [{"ip": ip, "score": s} for ip, s in _rep.items()],
            key=lambda x: x["score"],
            reverse=True,
        )


def level_color(level: str) -> str:
    """Return a CSS hex color for a risk level string."""
    return {
        "CRITICAL": "#dc2626",
        "HIGH":     "#ef4444",
        "MEDIUM":   "#f97316",
        "LOW":      "#22c55e",
    }.get(level, "#7a96b8")
