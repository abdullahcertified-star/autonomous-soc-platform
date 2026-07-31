"""
firewall.py — SOC Firewall / IP Blocking Module

Safety rules (default — never blocked unless override flag is set):
  • RFC-1918 private ranges: 10/8, 172.16/12, 192.168/16
  • Loopback: 127/8
  • Link-local: 169.254/16
  • User-defined whitelist

Private-IP blocking:
  • Controlled by protection_settings.block_private_ips.
  • When False (default): private IPs are refused — existing behaviour.
  • When True: private IPs CAN be blocked but are still logged separately.
  • Loopback (127/8) is ALWAYS protected regardless of the flag.

Block expiry:
  • Every block carries an optional expires_at epoch.
  • A background thread auto-unblocks expired entries every 30 s.
  • Default duration is configurable via DEFAULT_BLOCK_DURATION (seconds).
    Set to 0 for a permanent block.

OS-level enforcement:
  • Linux  : iptables -I INPUT -s <ip> -j DROP
  • Windows: netsh advfirewall firewall add rule ...
  Both are best-effort; the in-memory block remains active even if the OS
  command fails (e.g. no root/admin privileges).
"""
import ipaddress
import json
import os
import platform
import subprocess
import threading
import time
from collections import deque

from core.database import log_event
from utils import ts
from core import protection_settings
from core import sim

# ── Constants ──
AUTO_BLOCK_SCORE = 90
DEFAULT_BLOCK_DURATION = 300   # seconds; 0 = permanent

# ── Persistence file — survives restarts ──────────────────────────────────────
_STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall_state.json")

# ── Always-protected ranges (cannot be blocked even with the toggle ON) ──
_ALWAYS_PROTECTED = [
    ipaddress.ip_network("127.0.0.0/8"),    # loopback
    ipaddress.ip_network("::1/128"),         # IPv6 loopback
]

# ── Private / RFC-1918 ranges (blocked only when toggle is OFF) ──
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("fc00::/7"),         # IPv6 ULA
]

# Legacy alias kept for any external callers
_PROTECTED_NETS = _ALWAYS_PROTECTED + _PRIVATE_NETS

# ── State ──
_blocked: set       = set()
_blocked_meta: dict = {}          # {ip: entry_dict}
_block_log: deque   = deque(maxlen=500)
_whitelist: set     = set()
_lock               = threading.Lock()


# ── Persistence ───────────────────────────────────────────────────────────────

def _save_state() -> None:
    """Write current block state + history to disk (called after every change)."""
    try:
        state = {
            "blocked_meta": {ip: dict(e) for ip, e in _blocked_meta.items()},
            "block_log":    list(_block_log)[:200],   # last 200 entries
        }
        with open(_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, default=str)
    except Exception:
        pass


def _load_state() -> None:
    """Load persisted block state on startup and re-apply OS rules."""
    global _blocked, _blocked_meta
    if not os.path.exists(_STATE_FILE):
        return
    try:
        with open(_STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
        meta  = state.get("blocked_meta", {})
        hist  = state.get("block_log", [])
        now   = time.time()
        with _lock:
            for ip, entry in meta.items():
                exp = entry.get("expires_at")
                if exp and float(exp) < now:
                    continue           # expired — skip, don't re-apply
                _blocked.add(ip)
                _blocked_meta[ip] = entry
                _apply_os_block(ip) # re-apply OS rule (idempotent)
            for entry in hist:
                _block_log.append(entry)
    except Exception:
        pass


# Load persisted state immediately at import time
_load_state()


# ──────────────────────────────────────────────
# Safety predicates
# ──────────────────────────────────────────────

def is_loopback(ip: str) -> bool:
    """Return True if the IP is always protected (loopback)."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _ALWAYS_PROTECTED)
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Return True if the IP is in a private/RFC-1918 range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def is_protected(ip: str) -> bool:
    """
    Return True if the IP should be refused for blocking.

    Loopback is always refused.
    Private IPs are refused only when the block_private_ips toggle is OFF.
    """
    if is_loopback(ip):
        return True
    if is_private_ip(ip) and not protection_settings.get("block_private_ips"):
        return True
    return False


def is_whitelisted(ip: str) -> bool:
    return ip in _whitelist


def add_whitelist(ip: str) -> None:
    _whitelist.add(ip)


def remove_whitelist(ip: str) -> None:
    _whitelist.discard(ip)


def get_whitelist() -> list:
    return list(_whitelist)


# ──────────────────────────────────────────────
# OS-level firewall helpers
# ──────────────────────────────────────────────

def _apply_os_block(ip: str) -> None:
    """Push an OS-level drop rule. Errors are silently ignored."""
    try:
        if platform.system() == "Windows":
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=SOC_BLOCK_{ip}",
                    "dir=in", "action=block",
                    f"remoteip={ip}",
                ],
                capture_output=True, timeout=5,
            )
        else:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5,
            )
    except Exception:
        pass


def _remove_os_block(ip: str) -> None:
    """Remove the OS-level drop rule. Errors are silently ignored."""
    try:
        if platform.system() == "Windows":
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=SOC_BLOCK_{ip}",
                ],
                capture_output=True, timeout=5,
            )
        else:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5,
            )
    except Exception:
        pass


# ──────────────────────────────────────────────
# Core API
# ──────────────────────────────────────────────

def is_blocked(ip: str) -> bool:
    return ip in _blocked


def blocked_count() -> int:
    with _lock:
        return len(_blocked)


def _record(ip: str, action: str, reason: str, auto: bool) -> dict:
    entry = {"ip": ip, "action": action, "blocked_at": ts(), "reason": reason, "auto": auto}
    _block_log.appendleft(entry)
    return entry


def block_ip(ip: str, reason: str = "Manual", auto: bool = False,
             duration: int = None) -> dict:
    """
    Block an IP.

    Returns a result dict with status:
      'blocked'         — newly blocked
      'already_blocked' — already in the block list
      'refused_private' — IP is in a protected range
      'refused_whitelist' — IP is in the user whitelist
    """
    if is_protected(ip):
        reason_tag = "refused_loopback" if is_loopback(ip) else "refused_private"
        return {"status": reason_tag, "ip": ip}
    if is_whitelisted(ip):
        return {"status": "refused_whitelist", "ip": ip}

    if duration is None:
        duration = DEFAULT_BLOCK_DURATION
    expires_at = (time.time() + duration) if duration > 0 else None

    with _lock:
        already = ip in _blocked
        _blocked.add(ip)
        entry = _record(ip, "BLOCKED", reason, auto)
        entry["expires_at"] = expires_at
        entry["duration"] = duration
        _blocked_meta[ip] = entry
        if not already:
            if sim.is_sim():
                sim.record(sim.BLOCK_SUPPRESSED,
                           f"{'AUTO-' if auto else ''}BLOCK suppressed for {ip} — {reason}",
                           ip=ip, extra={"auto": auto, "duration": duration})
            else:
                _apply_os_block(ip)
            log_event({
                "type": "FIREWALL",
                "ip": ip,
                "time": entry["blocked_at"],
                "severity": "HIGH" if auto else "MEDIUM",
                "msg": f"[SIM] {'AUTO-' if auto else ''}BLOCKED: {ip} — {reason}" if sim.is_sim()
                       else f"{'AUTO-' if auto else ''}BLOCKED: {ip} — {reason}",
                **({"sim": True} if sim.is_sim() else {}),
            })
        result = {"status": "blocked" if not already else "already_blocked", "ip": ip}
    _save_state()
    return result


def unblock_ip(ip: str, reason: str = "Manual unblock") -> dict:
    with _lock:
        if ip not in _blocked:
            return {"status": "not_blocked", "ip": ip}
        _blocked.discard(ip)
        _blocked_meta.pop(ip, None)
        if sim.is_sim():
            sim.record(sim.UNBLOCK_SUPPRESSED,
                       f"UNBLOCK suppressed for {ip} — {reason}", ip=ip)
        else:
            _remove_os_block(ip)
        entry = _record(ip, "UNBLOCKED", reason, False)
        log_event({
            "type": "FIREWALL",
            "ip": ip,
            "time": entry["blocked_at"],
            "severity": "LOW",
            "msg": f"UNBLOCKED: {ip} — {reason}",
        })
        result = {"status": "unblocked", "ip": ip}
    _save_state()
    return result


def force_unblock(ip: str, reason: str = "Force unblock") -> dict:
    """
    Unblock an IP even if it has no in-memory record (e.g. blocked before a restart).
    Removes the OS firewall rule and updates state.
    """
    with _lock:
        _blocked.discard(ip)
        _blocked_meta.pop(ip, None)
    _remove_os_block(ip)
    entry = _record(ip, "FORCE_UNBLOCKED", reason, False)
    log_event({
        "type": "FIREWALL", "ip": ip,
        "time": entry["blocked_at"], "severity": "LOW",
        "msg": f"FORCE UNBLOCKED: {ip} — {reason}",
    })
    _save_state()
    return {"status": "unblocked", "ip": ip}


def get_blocked_list() -> list:
    now = time.time()
    with _lock:
        result = []
        for entry in _blocked_meta.values():
            e = dict(entry)
            exp = e.get("expires_at")
            e["expires_in"] = max(0, int(exp - now)) if exp else None
            result.append(e)
        return result


def get_block_history(limit: int = 100) -> list:
    with _lock:
        return [dict(e) for e in list(_block_log)[:limit]]


def reset_firewall() -> None:
    with _lock:
        for ip in list(_blocked):
            _remove_os_block(ip)
        _blocked.clear()
        _blocked_meta.clear()
        _block_log.clear()


# ──────────────────────────────────────────────
# Background expiry thread
# ──────────────────────────────────────────────

def _expiry_loop() -> None:
    """Auto-unblock IPs whose duration has elapsed (runs every 30 s)."""
    while True:
        time.sleep(30)
        now = time.time()
        with _lock:
            expired = [
                ip for ip, meta in _blocked_meta.items()
                if meta.get("expires_at") and now >= meta["expires_at"]
            ]
        for ip in expired:
            unblock_ip(ip, reason="Auto-expired block")


_expiry_thread = threading.Thread(target=_expiry_loop, daemon=True)
_expiry_thread.start()


# ──────────────────────────────────────────────
# Suspicious-IP helpers (read from sniffer state)
# ──────────────────────────────────────────────

def get_suspicious_ips() -> list:
    """
    Return a merged list of suspicious IPs from the sniffer.

    Pulls from:
      • sniffer.network_stats["suspicious_ips"]  — IPs tagged SUSPICIOUS by detection
      • sniffer.top_attackers                     — IPs with HIGH severity score

    Host IPs (this machine's own addresses) are always excluded to prevent the
    local machine from appearing as an attacker in the firewall page.
    """
    try:
        from detection import sniffer as _sniffer
        result = {}

        # Resolve host IPs to exclude them from the suspicious list
        host_ips = _sniffer._get_host_ips()

        # From the suspicious_ips set (IPs currently in SUSPICIOUS state)
        for ip in list(_sniffer.network_stats.get("suspicious_ips", set())):
            if ip in host_ips:
                continue   # never flag this machine as suspicious
            result[ip] = result.get(ip, {"ip": ip, "source": "detection", "severity": "SUSPICIOUS", "packets": 0})

        # From top_attackers (IPs with attack/suspicious classification)
        for ip, info in list(_sniffer.top_attackers.items()):
            if ip in host_ips:
                continue   # never flag this machine as an attacker
            sev = info.get("severity", "NORMAL")
            score = info.get("severity_score", 0)
            # top_attackers stores severity_score (int), not a severity string.
            # Derive severity from score: >=60 → HIGH, >=30 → MEDIUM/ATTACK.
            if sev not in ("SUSPICIOUS", "HIGH", "ATTACK"):
                if score >= 60:
                    sev = "HIGH"
                elif score >= 30:
                    sev = "ATTACK"
                else:
                    sev = info.get("attack_type", "NORMAL")
            if sev in ("SUSPICIOUS", "HIGH", "ATTACK", "SYN Flood", "UDP Flood", "DDoS Flood", "Port Scan"):
                if ip not in result:
                    result[ip] = {
                        "ip": ip,
                        "source": "top_attackers",
                        "severity": sev,
                        "packets": info.get("packet_count", 0),
                        "attack_type": info.get("attack_type", ""),
                        "country": info.get("country", ""),
                        "last_seen": info.get("last_seen", ""),
                    }
                else:
                    result[ip]["packets"] = info.get("packet_count", 0)
                    result[ip]["severity"] = sev

        # Exclude already-blocked IPs
        with _lock:
            blocked = set(_blocked)
        return [v for k, v in result.items() if k not in blocked]

    except Exception:
        return []


def block_all_suspicious(duration: int = None) -> dict:
    """Block every IP currently in the suspicious list. Returns summary."""
    ips = get_suspicious_ips()
    blocked_ok, skipped = [], []
    for entry in ips:
        ip = entry["ip"]
        r = block_ip(ip, reason=f"Flood/Attack — {entry.get('attack_type', 'Suspicious')}", auto=True, duration=duration)
        if r["status"] in ("blocked",):
            blocked_ok.append(ip)
        else:
            skipped.append({"ip": ip, "status": r["status"]})
    return {"blocked": blocked_ok, "skipped": skipped, "total": len(ips)}
