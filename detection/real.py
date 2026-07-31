"""
real.py — Intelligent Port Scan Risk Scoring Engine

Replaces the flat "risk = min(100, 30 + port_count)" formula with a
weighted, multi-factor model that behaves like a real IDS:

  • Slow scan ≠ critical by default
  • Burst scan → high / critical
  • Repeated scans increase risk gradually
  • Large target spread drives the score up

Scoring model (four factors, weighted sum):

  Factor          Weight   What it measures
  ─────────────── ──────   ────────────────────────────────────────────────────
  Port Score       35 %    How many unique ports were probed
  Speed Score      25 %    Time gap between scan trigger events (same source)
  Target Score     20 %    Number of distinct destination hosts targeted
  Repetition Score 20 %    How many times this source has triggered scan alerts

Final risk clamped to [0, 100].  Severity thresholds:
  0–30  → LOW
  31–60 → MEDIUM
  61–85 → HIGH
  86–100 → CRITICAL

Public API:
  calculate_port_scan_risk(ports, targets, time_gap, repeat_count) → dict
  port_score(n)       → int
  speed_score(secs)   → int
  target_score(n)     → int
  repetition_score(n) → int
  risk_to_severity(r) → str
"""

from __future__ import annotations


# ──────────────────────────────────────────────────────────────
# Individual factor scores (each returns 0–100)
# ──────────────────────────────────────────────────────────────

def port_score(ports: int) -> int:
    """
    Score based on number of unique destination ports probed.

    1–10    →  5   (reconnaissance / service discovery)
    11–30   → 20   (light scan — likely automated service probe)
    31–60   → 50   (moderate scan)
    61–100  → 80   (aggressive scan)
    100+    → 100  (full-range / masscan-style sweep)
    """
    if ports <= 10:   return 5
    if ports <= 30:   return 20
    if ports <= 60:   return 50
    if ports <= 100:  return 80
    return 100


def speed_score(time_gap: float) -> int:
    """
    Score based on elapsed time since scan tracking began for this source.

    time_gap is the total seconds from first packet to scan-event trigger.
    Short gaps mean fast/burst scanning; long gaps mean slow stealth scans.

    > 10 s   →   5   (slow, stealth scan — low urgency)
    5–10 s   →  20   (moderate speed)
    1–5  s   →  60   (fast scan)
    < 1  s   → 100   (burst / hping3-style sweep)
    """
    if time_gap > 10:  return 5
    if time_gap >= 5:  return 20
    if time_gap >= 1:  return 60
    return 100


def target_score(targets: int) -> int:
    """
    Score based on number of distinct destination hosts targeted.

    1        →   5   (single-host probe)
    2–5      →  30   (small subnet sweep)
    6–20     →  70   (subnet sweep)
    20+      → 100   (network-wide sweep)
    """
    if targets <= 1:   return 5
    if targets <= 5:   return 30
    if targets <= 20:  return 70
    return 100


def repetition_score(repeat_count: int) -> int:
    """
    Score based on how many scan-alert triggers this source has generated.
    Each trigger fires every 5 new unique ports (see sniffer.py threshold).

    1–2   →  10   (first detection — could be benign)
    3–5   →  40   (repeated — intentional scanning)
    6–10  →  80   (persistent scanner)
    10+   → 100   (relentless / automated attack)
    """
    if repeat_count <= 2:   return 10
    if repeat_count <= 5:   return 40
    if repeat_count <= 10:  return 80
    return 100


# ──────────────────────────────────────────────────────────────
# Severity mapping
# ──────────────────────────────────────────────────────────────

def risk_to_severity(risk: int) -> str:
    """Map a 0–100 risk score to a 4-tier severity label."""
    if risk <= 30:  return "LOW"
    if risk <= 60:  return "MEDIUM"
    if risk <= 85:  return "HIGH"
    return "CRITICAL"


# ──────────────────────────────────────────────────────────────
# Main public function
# ──────────────────────────────────────────────────────────────

def calculate_port_scan_risk(
    ports:        int,
    targets:      int,
    time_gap:     float,
    repeat_count: int,
) -> dict:
    """
    Compute weighted risk score and severity for a port scan event.

    Parameters
    ----------
    ports        : number of unique destination ports probed so far
    targets      : number of unique destination hosts targeted so far
    time_gap     : seconds elapsed since scanning began (from first packet)
    repeat_count : how many scan-alert triggers this source has already fired

    Returns
    -------
    dict with keys:
      risk_score     (int, 0–100)
      severity       (str: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL")
      port_score     (int, component score)
      speed_score    (int, component score)
      target_score   (int, component score)
      repeat_score   (int, component score)
    """
    ps = port_score(ports)
    ss = speed_score(time_gap)
    ts = target_score(targets)
    rs = repetition_score(repeat_count)

    # Weighted sum — coefficients sum to 1.00
    raw = ps * 0.35 + ss * 0.25 + ts * 0.20 + rs * 0.20
    risk = max(0, min(100, round(raw)))

    return {
        "risk_score":   risk,
        "severity":     risk_to_severity(risk),
        "port_score":   ps,
        "speed_score":  ss,
        "target_score": ts,
        "repeat_score": rs,
    }
