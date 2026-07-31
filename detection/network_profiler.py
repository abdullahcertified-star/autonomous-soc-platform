"""
network_profiler.py — Automatic Network Profile Detection & Dynamic Threshold Tuning

Runs once at startup after a 60-second baseline measurement window.
Detects the environment (Home / University / Corporate / Server / Public / Unknown)
then adjusts detection.config thresholds so false positives don't fire on busy
networks and real attacks aren't missed on high-traffic ones.

How it works:
  1. 60-second silent learning phase — measures actual pkt/5s baseline
  2. Collects network signals — subnet size, host count, gateway vendor
  3. Classifies profile using combined signals
  4. Computes final thresholds:
       normal/suspicious = max(dynamic, profile_default)  -> fewer false positives
       attack            = min(dynamic, profile_floor)    -> never miss real attacks
  5. Writes to detection.config — existing engine reads those values as-is

Nothing else in the system changes. Detection logic, sniffer, firewall all untouched.
"""

import re
import socket
import subprocess
import threading
import time

from detection import detection  # only writes to detection.config dict — no other coupling

# ── Profile threshold table ──────────────────────────────────────────────────
# abs_normal_rate    : pkt/5s below which traffic is NORMAL
# abs_suspicious_rate: pkt/5s below which traffic is SUSPICIOUS (above = ATTACK)
# attack_floor       : hard cap — ATTACK threshold never rises above this value

PROFILES: dict[str, dict] = {
    #                          rate thresholds (pkt/5s)               scan
    #                          normal    suspicious   attack_floor    threshold
    "HOME":       {"abs_normal_rate": 2400,  "abs_suspicious_rate": 5000,  "attack_floor":  6000, "scan_threshold":  60},
    "UNIVERSITY": {"abs_normal_rate": 5000,  "abs_suspicious_rate": 8000,  "attack_floor": 10000, "scan_threshold": 100},
    "CORPORATE":  {"abs_normal_rate": 4000,  "abs_suspicious_rate": 7000,  "attack_floor":  9000, "scan_threshold":  80},
    "SERVER":     {"abs_normal_rate": 8000,  "abs_suspicious_rate": 12000, "attack_floor": 15000, "scan_threshold": 120},
    "PUBLIC":     {"abs_normal_rate": 1500,  "abs_suspicious_rate": 3500,  "attack_floor":  5000, "scan_threshold":  50},
    "UNKNOWN":    {"abs_normal_rate": 2400,  "abs_suspicious_rate": 5900,  "attack_floor":  5900, "scan_threshold":  60},
}

# Gateway MAC vendor substrings → network type hint
_ENTERPRISE = ("cisco", "juniper", "hp ", "hewlett", "fortinet", "palo alto",
               "dell", "extreme", "aruba", "ubiquiti", "meraki", "mikrotik",
               "ruckus", "brocade", "f5 ")
_HOME_ROUTER = ("tp-link", "tplink", "netgear", "d-link", "dlink", "asus",
                "linksys", "belkin", "zyxel", "fritz", "tenda", "archer",
                "huawei", "xiaomi", "openwrt")

# ── Public state ─────────────────────────────────────────────────────────────
_lock = threading.Lock()
_state: dict = {
    "profile":       "UNKNOWN",
    "status":        "pending",   # pending | learning | detecting | applied
    "baseline_avg":  0.0,
    "host_count":    0,
    "subnet_prefix": 24,
    "gw_vendor":     "unknown",
    "thresholds":    dict(PROFILES["UNKNOWN"]),
    "learning_pct":  0,           # 0–100 progress bar during learning phase
}


def get_state() -> dict:
    with _lock:
        return dict(_state)


def _upd(key, value) -> None:
    with _lock:
        _state[key] = value


# ── Network signal helpers ───────────────────────────────────────────────────

def _get_subnet_prefix() -> int:
    """Return /prefix of the default outbound interface (e.g. 24 for 192.168.x.x/24)."""
    try:
        import ipaddress
        out = subprocess.check_output("ipconfig", text=True,
                                      stderr=subprocess.DEVNULL, timeout=6)
        # Find our outbound IP first
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        lines = out.splitlines()
        for i, line in enumerate(lines):
            if local_ip in line:
                for j in range(max(0, i - 6), min(len(lines), i + 6)):
                    m = re.search(r'Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', lines[j])
                    if m:
                        mask = m.group(1)
                        return ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
    except Exception:
        pass
    return 24


def _get_gateway_info() -> tuple[str, str]:
    """Return (gateway_ip, lowercase_vendor_string)."""
    try:
        out = subprocess.check_output("ipconfig", text=True,
                                      stderr=subprocess.DEVNULL, timeout=6)
        gw_ip = None
        for line in out.splitlines():
            if "Default Gateway" in line:
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    gw_ip = m.group(1)
                    break
        if not gw_ip:
            return ("", "unknown")

        arp_out = subprocess.check_output(
            f"arp -a {gw_ip}", text=True, stderr=subprocess.DEVNULL, timeout=5
        )
        mac_m = re.search(r'([0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2})',
                          arp_out, re.IGNORECASE)
        if not mac_m:
            return (gw_ip, "unknown")

        mac = mac_m.group(1).replace("-", ":").lower()

        # Use sniffer's OUI table (lazy import to avoid circular at module level)
        try:
            from detection import sniffer as _s
            vendor = _s._mac_vendor(mac).lower()
        except Exception:
            vendor = "unknown"

        return (gw_ip, vendor)
    except Exception:
        return ("", "unknown")


def _measure_baseline(seconds: int = 60) -> float:
    """
    Sample sniffer.network_stats["total_packets"] every 5 seconds for `seconds`
    seconds. Returns the median pkt/5s window observed.
    Does NOT block the caller — runs in the profiler background thread.
    """
    from detection import sniffer as _s

    samples: list[float] = []
    prev = _s.network_stats.get("total_packets", 0)
    start = time.time()
    sample_interval = 5  # seconds between samples

    while time.time() - start < seconds:
        elapsed = time.time() - start
        _upd("learning_pct", int(min(99, elapsed / seconds * 100)))
        time.sleep(sample_interval)
        curr = _s.network_stats.get("total_packets", 0)
        delta = max(0, curr - prev)
        samples.append(float(delta))
        prev = curr

    _upd("learning_pct", 100)
    if not samples:
        return 0.0
    samples.sort()
    return float(samples[len(samples) // 2])  # median


# ── Classification ────────────────────────────────────────────────────────────

def _classify(subnet_prefix: int, host_count: int,
              gw_vendor: str, baseline_avg: float) -> str:
    v = gw_vendor.lower()
    is_enterprise  = any(e in v for e in _ENTERPRISE)
    is_home_router = any(h in v for h in _HOME_ROUTER)

    # SERVER: very high sustained baseline — must be a datacenter / VPS
    if baseline_avg > 5000:
        return "SERVER"

    # UNIVERSITY / CAMPUS: large subnet or huge device count
    if subnet_prefix <= 16 or host_count > 80:
        return "UNIVERSITY"

    # CORPORATE: enterprise hardware + reasonable host count
    if is_enterprise and 10 < host_count <= 80:
        return "CORPORATE"

    # UNIVERSITY: enterprise hardware + very many devices
    if is_enterprise and host_count > 80:
        return "UNIVERSITY"

    # PUBLIC: unknown/untrusted gateway, many unknown devices
    if not is_home_router and not is_enterprise and host_count > 20:
        return "PUBLIC"

    # HOME: few devices, consumer hardware or small subnet
    if subnet_prefix >= 24 and host_count <= 25:
        return "HOME"

    return "UNKNOWN"


# ── Threshold computation & application ──────────────────────────────────────

def _apply(profile: str, baseline_avg: float) -> None:
    """Compute final thresholds and write into detection.config."""
    p = PROFILES.get(profile, PROFILES["UNKNOWN"])

    if baseline_avg > 100:
        # Dynamic thresholds derived from measured baseline
        dyn_normal     = baseline_avg * 1.5
        dyn_suspicious = baseline_avg * 2.5
        dyn_attack     = baseline_avg * 4.0

        # Normal/Suspicious: MAX of dynamic vs profile default → fewer false positives
        fn = max(dyn_normal,     p["abs_normal_rate"])
        fs = max(dyn_suspicious, p["abs_suspicious_rate"])
        # Attack: MIN of dynamic vs profile floor → never miss real attacks
        fa = min(dyn_attack, p["attack_floor"])

        # Enforce ordering with small gaps
        fn = min(fn, fs - 200)
        fs = min(fs, fa - 200)
    else:
        # Not enough traffic to measure — fall back to profile defaults
        fn = p["abs_normal_rate"]
        fs = p["abs_suspicious_rate"]
        fa = p["attack_floor"]

    fn = int(max(500,  fn))
    fs = int(max(1000, fs))
    fa = int(max(2000, fa))

    # Write into detection engine config (engine already reads these on every check)
    detection.config["abs_normal_rate"]     = fn
    detection.config["abs_suspicious_rate"] = fs

    thresholds = {"abs_normal_rate": fn, "abs_suspicious_rate": fs, "attack_floor": fa}
    with _lock:
        _state["thresholds"] = thresholds

    # Update scan threshold based on profile
    try:
        from detection import sniffer as _s
        _s.set_scan_threshold(p["scan_threshold"])
    except Exception:
        pass

    print(f"[Profiler] {profile} thresholds applied — "
          f"NORMAL≤{fn}  SUSPICIOUS≤{fs}  ATTACK>{fa}  pkt/5s  "
          f"scan≥{p['scan_threshold']} ports")


# ── Background runner ─────────────────────────────────────────────────────────

def _run() -> None:
    _upd("status", "learning")
    print("[Profiler] 60-second baseline measurement started ...")

    baseline_avg = _measure_baseline(60)
    _upd("baseline_avg", round(baseline_avg, 1))
    print(f"[Profiler] Baseline: {baseline_avg:.0f} pkt/5s (median over 60 s)")

    _upd("status", "detecting")

    subnet_prefix         = _get_subnet_prefix()
    gw_ip, gw_vendor      = _get_gateway_info()

    # Lazy sniffer import for discovered_devices count
    try:
        from detection import sniffer as _s
        host_count = len(_s.discovered_devices)
    except Exception:
        host_count = 0

    _upd("subnet_prefix", subnet_prefix)
    _upd("gw_vendor",     gw_vendor)
    _upd("host_count",    host_count)

    print(f"[Profiler] subnet=/{subnet_prefix}  hosts={host_count}  "
          f"gw={gw_ip}  vendor={gw_vendor}")

    profile = _classify(subnet_prefix, host_count, gw_vendor, baseline_avg)
    _upd("profile", profile)
    print(f"[Profiler] Network profile: {profile}")

    _apply(profile, baseline_avg)
    _upd("status", "applied")


def start() -> None:
    """Call once from sniffer.start_sniffer() after capture threads are running."""
    threading.Thread(target=_run, daemon=True, name="net-profiler").start()
