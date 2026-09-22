"""
detection.py — SOC Detection Engine

Decision logic (primary: absolute per-IP rate):
  ip_rate ≤ 2400              → NORMAL
  2401 ≤ ip_rate ≤ 5900       → SUSPICIOUS  (behavioral signals can escalate → ATTACK)
  ip_rate > 5900              → ATTACK

Behavioral escalation (within suspicious range → ATTACK):
  • One IP dominates >70 % of all traffic
  • >50 % of traffic from one IP targets same (dst, port)
  • Sudden spike ×3 within 1–2 s

SYN flood checked independently of rate (high pure-SYN:ACK ratio).
SYN+ACK flood checked via synack_count fraction of total traffic.
"""
import time
import math
import threading
from collections import defaultdict, deque

# ── Live-editable config (settings blueprint writes here) ──
config = {
    "enabled": True,

    # Rate measurement
    "rate_window": 5,               # seconds: per-IP rate window

    # Baseline window + z-score thresholds (primary classification when ready)
    "baseline_window": 300,
    "min_baseline_samples": 15,
    "normal_deviation": 2.0,        # z < 2  → NORMAL
    "suspicious_deviation": 5.0,    # z ≥ 5  → ATTACK  (2 ≤ z < 5 → SUSPICIOUS)

    # ── Absolute rate fallback (used only before baseline is ready) ──
    "abs_normal_rate": 2400,        # ≤ this → NORMAL
    "abs_suspicious_rate": 5900,    # ≤ this → SUSPICIOUS; above → ATTACK

    # DDoS: multiple source IPs targeting the same destination
    "ddos_min_sources": 5,          # unique IPs targeting same dst in window
    "ddos_rate_threshold": 50,      # min packets to that dst in window

    # Behavioral thresholds (escalate SUSPICIOUS → ATTACK)
    "syn_ack_ratio_suspicious": 3.0,
    "syn_ack_ratio_attack": 10.0,
    "min_syn_count": 80,             # minimum SYN packets before ratio check fires
    "min_synack_count": 20,          # minimum SYN+ACK packets before SYN-ACK flood fires
    "synack_attack_ratio": 0.5,      # SYN+ACK fraction of total traffic → attack
    "ip_concentration": 0.70,           # src IP > 70 % of all traffic
    "same_target_concentration": 0.50,  # > 50 % of src traffic to one (dst, port)
    "spike_factor": 3.0,                # rate multiplies ×3 within 1–2 s

    # ── Destination-side (victim) thresholds ──────────────────────────────
    # Total packets/5s arriving AT a destination IP (from all sources combined).
    # Separate from abs_normal/suspicious_rate which are per-SOURCE thresholds.
    "dst_normal_rate":  2400,   # ≤ this → NORMAL   (≈ 480 pps combined)
    "dst_attack_rate":  6500,   # > this → HIGH      (≈ 1300 pps combined)
    # Multi-source DDoS: unique sources + combined packet count to one destination.
    "ddos_dst_min_sources":   5,    # unique source IPs targeting same dst
    "ddos_dst_pkt_threshold": 2400, # combined packets to that dst in rate_window

    # Confirmation + cooldown
    "sustained_seconds": 3,
    "cooldown_seconds": 30,

    # Distributed flood (many unique external IPs in a short window)
    # Raised thresholds: 15 unique IPs in 10s is normal browsing (CDNs, DNS).
    # A real DDoS involves hundreds of IPs sending hundreds of packets each.
    "distributed_src_window":    10,   # seconds to look back
    "distributed_src_threshold": 80,   # unique external IPs required
    "distributed_pkt_threshold": 300,  # total packets in window required
    "distributed_cooldown":      30,   # seconds between repeated alerts

    # Private-IP distributed flood — VM farms, infected LAN devices, multi-VM
    # scenarios (Windows host + multiple Kali/attack VMs).
    # Uses higher thresholds than the public-IP check to avoid false positives
    # on normal busy LANs.  The existing external-IP logic is unchanged.
    "distributed_private_src_threshold": 8,    # unique private IPs required
    "distributed_private_pkt_threshold": 150,  # total packets in window required

    # Short-window burst flood (single-source rapid burst, e.g. hping3 -i u10)
    # 600 pps threshold: normal downloads peak at ~500 pps; real flood tools do 10k+
    "burst_window":    1,    # seconds for burst rate measurement
    "abs_burst_rate":  600,  # pps in burst_window from one source → immediate MEDIUM

    "sim_mode": False,
}

# ── Per-IP tracking ──
_src_ts: dict    = defaultdict(deque)   # {src: packet timestamps}
_syn_ts: dict    = defaultdict(deque)   # {src: pure-SYN (no ACK) timestamps}
_synack_ts: dict = defaultdict(deque)   # {src: SYN+ACK timestamps}
_ack_ts: dict    = defaultdict(deque)   # {src: all ACK-containing packet timestamps}
_flow_ts: dict   = defaultdict(lambda: defaultdict(deque))  # {src: {(dst,port): timestamps}}
_rate_snap: dict = {}                   # {src: (epoch, rate)} — last rate snapshot
_unique_ports: dict = defaultdict(set)  # {src: set of dst_ports seen}

# ── Per-destination DDoS tracking ──
_dst_ts: dict   = defaultdict(lambda: deque(maxlen=500))   # {dst: packet timestamps}
_dst_srcs: dict = defaultdict(lambda: deque(maxlen=500))   # {dst: [(t, src), ...]}

# ── Global tracking ──
_global_ts: deque       = deque()      # all packet timestamps (rate_window)
_baseline_samples: deque = deque()     # (epoch, global_rate) sampled 1/s
_last_sample_t: float   = 0.0

# ── Attack state ──
_attack_start: dict     = {}           # {src: epoch first threshold crossed}
_cooldown_until: dict   = {}           # {src: epoch cooldown expires}
_confidence_scores: dict = {}          # {src: last confidence 0-100}

# ── Distributed flood tracking ──
_global_src_window: deque = deque(maxlen=2000)  # (timestamp, src_ip) per packet
_dist_cooldown_until: float = 0.0               # epoch until next dist alert allowed

# ── Short-window burst tracking (1-second window, per source IP) ──
_burst_ts: dict = defaultdict(deque)

# ── Per-destination victim tracking ──
# Tracks attack load ON a destination IP so we can detect when any device
# on the network is being targeted, not just when a source is attacking.
_dst_rate_ts: dict   = defaultdict(deque)                        # {dst: timestamps in rate_window}
_dst_src_dq: dict    = defaultdict(lambda: defaultdict(lambda: deque(maxlen=200)))  # {dst: {src: timestamps}}
_dst_syn_ts: dict    = defaultdict(deque)                        # {dst: SYN timestamps}
_dst_port_scan: dict = defaultdict(lambda: defaultdict(set))     # {dst: {src: set(ports)}}
_dst_attack_start: dict = {}
_dst_cooldown: dict     = {}
_dst_confidence: dict   = {}


def _profiler_ready() -> bool:
    """Check if network profiler has finished baseline calibration."""
    try:
        from detection import network_profiler
        return network_profiler.is_ready()
    except Exception:
        return True


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _prune(dq: deque, cutoff: float) -> None:
    while dq and dq[0] < cutoff:
        dq.popleft()


def _mean_std(values) -> tuple:
    n = len(values)
    if n < 2:
        return (values[0] if n == 1 else 0.0), 0.0
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return mean, math.sqrt(variance)


def _sample_global_rate(now: float) -> None:
    """Take a global rate snapshot once per second."""
    global _last_sample_t
    if now - _last_sample_t < 1.0:
        return
    _last_sample_t = now
    rate = len(_global_ts)                  # already pruned by caller
    cutoff = now - config["baseline_window"]
    while _baseline_samples and _baseline_samples[0][0] < cutoff:
        _baseline_samples.popleft()
    _baseline_samples.append((now, rate))


def _get_baseline() -> tuple:
    """Return (mean, std_dev) using only the lower half of rate samples.

    Sorting and taking the bottom 50 % keeps attack-period spikes out of the
    baseline estimate as long as the attack occupies less than half the
    5-minute rolling window (~2.5 min).  This stops the mean from drifting
    toward the attack rate and the deviation ratio from collapsing to ×1.
    """
    if len(_baseline_samples) < config["min_baseline_samples"]:
        return 0.0, 0.0
    rates = sorted(s[1] for s in _baseline_samples)
    half = max(config["min_baseline_samples"], len(rates) // 2)
    return _mean_std(rates[:half])


# ──────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────

def record_packet(src_ip: str, dst_ip: str,
                  is_syn: bool = False, is_ack: bool = False,
                  dst_port: int = 0):
    """
    Record one packet arrival.

    Returns (severity, confidence, ip_rate):
      severity   — None | 'MEDIUM' | 'HIGH'
      confidence — int 0-100
      ip_rate    — packets from src_ip in the last rate_window seconds
    """
    if not config["enabled"]:
        return None, 0, 0

    now = time.time()
    w   = config["rate_window"]

    # ── Record timestamps ──
    _src_ts[src_ip].append(now)
    _global_ts.append(now)
    _burst_ts[src_ip].append(now)
    if is_syn and not is_ack:   # pure SYN — SYN flood indicator
        _syn_ts[src_ip].append(now)
    if is_syn and is_ack:       # SYN+ACK — SYN-ACK flood indicator
        _synack_ts[src_ip].append(now)
    if is_ack:
        _ack_ts[src_ip].append(now)  # all ACK-containing (denominator for SYN ratio)
    flow_key = (dst_ip, dst_port)
    # Cap unique flows per source to avoid O(n²) on random-destination floods.
    if len(_flow_ts[src_ip]) < 500 or flow_key in _flow_ts[src_ip]:
        _flow_ts[src_ip][flow_key].append(now)
        _prune(_flow_ts[src_ip][flow_key], now - w)

    # ── Unique destination ports per source IP ──
    if dst_port:
        _unique_ports[src_ip].add(dst_port)

    # ── DDoS destination tracking (multiple sources → same dst) ──
    _dst_ts[dst_ip].append(now)
    _dst_srcs[dst_ip].append((now, src_ip))
    cutoff = now - w
    while _dst_srcs[dst_ip] and _dst_srcs[dst_ip][0][0] < cutoff:
        _dst_srcs[dst_ip].popleft()

    # ── Prune stale ──
    _prune(_src_ts[src_ip],   now - w)
    _prune(_global_ts,        now - w)
    _prune(_syn_ts[src_ip],   now - w)
    _prune(_synack_ts[src_ip],now - w)
    _prune(_ack_ts[src_ip],   now - w)
    _prune(_burst_ts[src_ip], now - config["burst_window"])

    # ── Sample global rate for baseline display (1/s) ──
    _sample_global_rate(now)

    ip_rate       = len(_src_ts[src_ip])
    global_rate   = len(_global_ts)
    burst_rate_1s = len(_burst_ts[src_ip])

    # ── Profiler Calibration Guard ──
    # Hold attack detection while the network profiler is learning normal baseline
    if not _profiler_ready():
        return None, 0, ip_rate

    # ── Cooldown guard ──
    # Only honour cooldown when traffic is genuinely calm — both the 5-second
    # rate AND the 1-second burst rate must be below their respective thresholds.
    # A high burst_rate_1s means a new attack has started; re-engage immediately.
    if src_ip in _cooldown_until and now < _cooldown_until[src_ip]:
        if (ip_rate <= config["abs_normal_rate"]
                and burst_rate_1s <= config["abs_burst_rate"]):
            _confidence_scores[src_ip] = 0
            return None, 0, ip_rate
        del _cooldown_until[src_ip]   # rate or burst is elevated — re-engage

    # ── SYN / ACK ratio (per IP) — pure SYN only, so SYN+ACK floods don't mask it ──
    syn_count = len(_syn_ts[src_ip])
    ack_count = len(_ack_ts[src_ip])
    syn_ack_ratio = syn_count / max(ack_count, 1) if syn_count > 0 else 0.0

    # ── SYN+ACK flood: high fraction of total traffic is SYN+ACK ──
    synack_count = len(_synack_ts[src_ip])
    synack_flood = (
        synack_count >= config["min_synack_count"] and
        ip_rate > 0 and
        synack_count / ip_rate >= config["synack_attack_ratio"]
    )

    # ── IP concentration: this src's share of all traffic ──
    ip_concentration  = ip_rate / global_rate if global_rate > 0 else 0.0
    high_concentration = ip_concentration >= config["ip_concentration"]

    # ── Same-target concentration: fraction of this src's traffic to one (dst,port) ──
    top_flow = max((len(dq) for dq in _flow_ts[src_ip].values()), default=0)
    same_target = (top_flow / ip_rate >= config["same_target_concentration"]) if ip_rate > 0 else False

    # ── Sudden spike: rate ×spike_factor within 1–2 s ──
    spike_detected = False
    prev = _rate_snap.get(src_ip)
    if prev:
        prev_epoch, prev_rate = prev
        elapsed = now - prev_epoch
        if 1.0 <= elapsed <= 2.5 and prev_rate > 0:
            if ip_rate / prev_rate >= config["spike_factor"]:
                spike_detected = True
    if not prev or (now - prev[0]) >= 1.0:
        _rate_snap[src_ip] = (now, ip_rate)

    SYN_SUSP = config["syn_ack_ratio_suspicious"]
    SYN_ATK  = config["syn_ack_ratio_attack"]
    ABS_NORM = config["abs_normal_rate"]   # 2400 — upper bound of NORMAL
    ABS_SUSP = config["abs_suspicious_rate"]  # 5900 — upper bound of SUSPICIOUS

    # ── DDoS: multiple unique sources targeting the same destination ──
    dst_pkt_count   = len(_dst_srcs[dst_ip])
    unique_dst_srcs = len(set(e[1] for e in _dst_srcs[dst_ip]))
    ddos_detected   = (
        unique_dst_srcs >= config["ddos_min_sources"] and
        dst_pkt_count  >= config["ddos_rate_threshold"]
    )

    # Behavioral escalation signals (can push SUSPICIOUS → ATTACK)
    behavioral_attack = (
        syn_ack_ratio >= SYN_ATK
        or synack_flood
        or ddos_detected
        or (high_concentration and (spike_detected or same_target))
        or (same_target and spike_detected)
    )

    # ──────────────────────────────────────────────────────────────────────
    # Classification — ABSOLUTE PPS RATE (primary, always active)
    #
    #   ip_rate 0 – 2400        → NORMAL
    #   ip_rate 2401 – 5900     → SUSPICIOUS  (behavioral signals → ATTACK)
    #   ip_rate 5901 +          → ATTACK
    #
    # SYN flood is independent of rate and always checked first.
    # ──────────────────────────────────────────────────────────────────────

    MIN_SYN = config["min_syn_count"]

    if syn_count >= MIN_SYN and syn_ack_ratio >= SYN_ATK:    # pure SYN flood — ATTACK
        raw_sev = "HIGH"
    elif syn_count >= MIN_SYN and syn_ack_ratio >= SYN_SUSP: # pure SYN flood — SUSPICIOUS
        raw_sev = "MEDIUM"
    elif synack_flood:                                        # SYN+ACK flood — ATTACK
        raw_sev = "HIGH"
    elif ip_rate > ABS_SUSP:                  # > 5900 → ATTACK
        raw_sev = "HIGH"
    elif ip_rate > ABS_NORM:                  # 2401–5900 → SUSPICIOUS
        # Behavioral signals escalate SUSPICIOUS → ATTACK within this range
        raw_sev = "HIGH" if behavioral_attack else "MEDIUM"
    else:                                     # 0–2400 → NORMAL
        raw_sev = None

    # ── Confidence scoring (0-100) ──
    confidence = 0
    if raw_sev:
        # Component 1: rate position within thresholds (0-40 pts)
        if ip_rate > ABS_SUSP:
            rate_score = 20 + min(20, int((ip_rate - ABS_SUSP) / ABS_SUSP * 20))
        elif ip_rate > ABS_NORM:
            rate_score = min(20, int((ip_rate - ABS_NORM) / (ABS_SUSP - ABS_NORM) * 20))
        else:
            rate_score = 0
        rate_score = min(40, rate_score)

        # Component 2: behavioral signals (0-40 pts)
        beh = 0
        if syn_ack_ratio >= SYN_ATK:
            beh += 30
        elif syn_ack_ratio >= SYN_SUSP:
            beh += 15
        if synack_flood:
            beh += 30
        if high_concentration:
            beh += 15
        if same_target:
            beh += 15
        if spike_detected:
            beh += 10
        beh_score = min(40, beh)

        # Component 3: sustained duration (0-20 pts, full at 5 s)
        if src_ip not in _attack_start:
            _attack_start[src_ip] = now
        sustained = now - _attack_start[src_ip]
        sus_score = min(20, int(sustained * 4))

        confidence = rate_score + beh_score + sus_score

    else:
        if src_ip in _attack_start:
            del _attack_start[src_ip]
            _cooldown_until[src_ip] = now + config["cooldown_seconds"]
        confidence = 0

    _confidence_scores[src_ip] = confidence

    # ── Short-window burst flood — bypasses sustained_seconds ──
    # Handles two cases that the rate+sustained engine misses:
    #   (a) Short bursts below NORMAL threshold (ip_rate < 2400) — raw_sev is None.
    #   (b) ICMP/OTHER floods where _attack_start is set ~240 ms later than SYN floods
    #       (SYN path fires at packet 20, rate path fires when ip_rate > 2400), causing
    #       ICMP to miss the sustained_seconds=3 window even at identical packet rates.
    # Fires unconditionally when burst rate is high and traffic is concentrated.
    _burst_thresh = config["abs_burst_rate"]
    if burst_rate_1s > _burst_thresh and same_target:
        if src_ip not in _attack_start:
            _attack_start[src_ip] = now
        _burst_conf = min(90, 30 + min(60, (burst_rate_1s - _burst_thresh) // 4))
        _confidence_scores[src_ip] = max(_confidence_scores.get(src_ip, 0), _burst_conf)
        # Escalate to HIGH when behavior confirms attack regardless of absolute rate:
        # concentrated burst (same_target) + dominates traffic (high_concentration)
        # or sudden spike — a 400-pps focused flood is as dangerous as a 5000-pps one.
        _burst_sev = raw_sev or (
            "HIGH" if (high_concentration or spike_detected) else "MEDIUM"
        )
        return _burst_sev, _burst_conf, ip_rate

    # ── Require sustained threshold + minimum confidence ──
    confirmed_sev = None
    if raw_sev and confidence >= 30 and src_ip in _attack_start:
        if (now - _attack_start[src_ip]) >= config["sustained_seconds"]:
            confirmed_sev = raw_sev

    return confirmed_sev, confidence, ip_rate


# ──────────────────────────────────────────────
# Victim-side detection
# ──────────────────────────────────────────────

def record_dst_packet(dst_ip: str, src_ip: str, dst_port: int = 0,
                      is_syn: bool = False):
    """
    Track attack load ON a destination IP.

    Called from sniffer.process_packet() for every packet whose destination is
    NOT this host, so we detect attacks targeting any device on the network.

    Returns (severity, confidence, dst_rate, attack_type).
    Severity is None for NORMAL traffic, 'MEDIUM' or 'HIGH' for attacks.
    """
    if not config["enabled"]:
        return None, 0, 0, "Normal"

    now = time.time()
    w   = config["rate_window"]

    # Record packet arriving at this destination
    _dst_rate_ts[dst_ip].append(now)
    _prune(_dst_rate_ts[dst_ip], now - w)

    # Track which sources are hitting this destination
    _dst_src_dq[dst_ip][src_ip].append(now)

    if is_syn:
        _dst_syn_ts[dst_ip].append(now)
        _prune(_dst_syn_ts[dst_ip], now - w)

    # Port scan tracking: one source probing many ports on this specific target
    if dst_port > 0 and len(_dst_port_scan[dst_ip][src_ip]) < 500:
        _dst_port_scan[dst_ip][src_ip].add(dst_port)

    # Cooldown: don't re-fire alerts immediately after a resolved attack
    if dst_ip in _dst_cooldown and now < _dst_cooldown[dst_ip]:
        return None, 0, len(_dst_rate_ts[dst_ip]), "Normal"

    dst_rate = len(_dst_rate_ts[dst_ip])
    cutoff   = now - w

    # ── Profiler Calibration Guard ──
    if not _profiler_ready():
        return None, 0, dst_rate, "Normal"

    # Unique source IPs that have sent packets to this dst in the last rate_window
    unique_srcs = sum(
        1 for src_dq in _dst_src_dq[dst_ip].values()
        if src_dq and src_dq[-1] >= cutoff
    )
    syn_count    = len(_dst_syn_ts[dst_ip])
    # Highest port count from any single source → indicates a targeted port scan
    max_scan_pts = max(
        (len(ports) for ports in _dst_port_scan[dst_ip].values()), default=0
    )

    # Destination-side thresholds (total packets TO this dst from all sources).
    DST_NORM    = config["dst_normal_rate"]        # 2400 pkt/5s → MEDIUM
    DST_ATK     = config["dst_attack_rate"]        # 6500 pkt/5s → HIGH
    DDOS_SRCS   = config["ddos_dst_min_sources"]   # 5 unique sources
    DDOS_PKTS   = config["ddos_dst_pkt_threshold"] # 2400 combined pkt/5s
    MIN_SYN     = config["min_syn_count"]
    SYN_ATK     = config["syn_ack_ratio_attack"]
    _SCAN_THRESH = 8   # ports from one src to this specific dst before flagging

    raw_sev    = None
    attack_type = "Normal"
    confidence  = 0

    # ── SYN flood targeting this destination ──
    if syn_count >= MIN_SYN:
        syn_per_src = syn_count / max(unique_srcs, 1)
        if syn_count >= int(MIN_SYN * SYN_ATK) or syn_per_src >= 15:
            raw_sev    = "HIGH"
            attack_type = "SYN Flood"
            confidence  = min(90, 40 + min(50, syn_count // 2))

    # ── Multi-source DDoS (≥5 unique IPs sending ≥2400 combined pkt/5s) ──
    if not raw_sev and unique_srcs >= DDOS_SRCS and dst_rate >= DDOS_PKTS:
        raw_sev    = "HIGH"
        attack_type = f"DDoS ({unique_srcs} sources)"
        confidence  = min(90, 50 + unique_srcs * 2)

    # ── Rate flood to this destination ──
    if not raw_sev:
        if dst_rate > DST_ATK:                                 # > 6500 pkt/5s → HIGH
            raw_sev    = "HIGH"
            attack_type = "Flood"
            confidence  = min(80, 40 + (dst_rate - DST_ATK) // 200)
        elif dst_rate > DST_NORM:                              # > 2400 pkt/5s → MEDIUM
            raw_sev    = "MEDIUM"
            attack_type = "High Traffic"
            confidence  = min(60, 20 + (dst_rate - DST_NORM) // 100)

    # ── Port scan against this target ──
    if not raw_sev and max_scan_pts >= _SCAN_THRESH:
        raw_sev    = "MEDIUM"
        attack_type = "Port Scan"
        confidence  = min(80, 30 + max_scan_pts * 2)

    if raw_sev:
        if dst_ip not in _dst_attack_start:
            _dst_attack_start[dst_ip] = now
        # Require 2-second sustained before confirming (avoids single-packet spikes)
        if now - _dst_attack_start[dst_ip] < 2.0:
            return None, confidence, dst_rate, attack_type
    else:
        if dst_ip in _dst_attack_start:
            del _dst_attack_start[dst_ip]
            _dst_cooldown[dst_ip] = now + config["cooldown_seconds"]
        _dst_confidence[dst_ip] = 0
        return None, 0, dst_rate, "Normal"

    _dst_confidence[dst_ip] = confidence
    return raw_sev, confidence, dst_rate, attack_type


# ──────────────────────────────────────────────
# Query helpers
# ──────────────────────────────────────────────

def get_src_rate(src_ip: str) -> int:
    _prune(_src_ts[src_ip], time.time() - config["rate_window"])
    return len(_src_ts[src_ip])


def get_global_rate() -> int:
    _prune(_global_ts, time.time() - config["rate_window"])
    return len(_global_ts)


def get_confidence(ip: str) -> int:
    return _confidence_scores.get(ip, 0)


def get_all_ip_scores() -> dict:
    return dict(_confidence_scores)


def get_attack_duration(ip: str) -> float:
    if ip in _attack_start:
        return time.time() - _attack_start[ip]
    return 0.0


def get_baseline_stats() -> dict:
    """Return current baseline health for dashboard display.

    deviation = current_rate / baseline_mean  (ratio, network-size-independent)
      < 2.0        → NORMAL
      2.0 – 5.0   → SUSPICIOUS
      ≥ 5.0        → ATTACK

    Example with baseline = 700 PPS:
      current = 2400  → deviation ≈ 3.43  (but per-IP rate ≤ 2400, classified NORMAL by engine)
      current = 2401  → deviation ≈ 3.43  → display SUSPICIOUS
      current = 5901  → deviation ≈ 8.43  → display ATTACK
    """
    mean, std = _get_baseline()
    curr = get_global_rate()
    profiler_ok = _profiler_ready()
    ready = len(_baseline_samples) >= config["min_baseline_samples"] and profiler_ok

    # Deviation: ratio of current global rate to baseline mean
    deviation = round(curr / mean, 2) if (ready and mean > 0) else 0.0

    # Z-score: kept as reference / secondary display value
    z_score = round((curr - mean) / std, 2) if (ready and std > 0) else 0.0

    # Adaptive upper boundary: mean + 5σ  (display only)
    adaptive_upper = round(mean + config["suspicious_deviation"] * std, 1) if ready else 0.0

    # Status based on deviation ratio thresholds AND absolute rate floor.
    # While profiler is calibrating, status is CALIBRATING.
    if not profiler_ok:
        status = "CALIBRATING"
    elif curr <= config["abs_normal_rate"] or curr < 200:
        status = "NORMAL"
    elif deviation < config["normal_deviation"]:       # ratio < 2.0 → NORMAL
        status = "NORMAL"
    elif deviation < config["suspicious_deviation"]: # 2.0 ≤ ratio < 5.0 → SUSPICIOUS
        status = "SUSPICIOUS"
    else:                                            # ratio ≥ 5.0 and curr > abs_normal_rate → ATTACK
        status = "ATTACK"

    return {
        "baseline_mean":    round(mean, 1),
        "baseline_std":     round(std, 1),
        "adaptive_upper":   adaptive_upper,
        "current_rate":     curr,
        "deviation":        deviation,   # ratio: current / mean  (used by dashboard bar)
        "z_score":          z_score,     # (current − mean) / std  (reference)
        "status":           status,
        "samples":          len(_baseline_samples),
        "ready":            ready,
    }


def get_unique_ports(src_ip: str) -> int:
    return len(_unique_ports.get(src_ip, set()))


def get_distributed_flood_ips(min_packets: int = 3) -> dict:
    """
    Return IPs that are genuine flood contributors — not normal network traffic.

    Filters applied:
      1. Public IPs only  — private/RFC-1918 are never returned
      2. min_packets      — IPs that sent only 1-2 packets are normal servers
                            responding to your requests; flood sources repeat
      3. Packet count     — returned so caller can show per-IP packet counts

    Returns {"ips": [...], "all_count": N, "flood_count": M}
    """
    now    = time.time()
    cutoff = now - config["distributed_src_window"]

    # Count packets per IP in the current window
    ip_counts: dict = {}
    for ts, ip in _global_src_window:
        if ts >= cutoff:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    all_count = len(ip_counts)

    # Keep only public IPs with at least min_packets
    flood_ips = {
        ip: cnt for ip, cnt in ip_counts.items()
        if cnt >= min_packets and not _is_private(ip)
    }

    return {
        "ips":         sorted(flood_ips.keys()),
        "ip_counts":   flood_ips,
        "all_count":   all_count,       # total unique IPs in window
        "flood_count": len(flood_ips),  # genuine flood IPs only
    }


def clear_src_state(src_ip: str) -> None:
    """
    Wipe all per-IP detection state for an attacker whose incident was resolved.
    Prevents residual _attack_start / rate data from re-triggering HIGH on the
    next stray packet after the attack ends.
    """
    _src_ts.pop(src_ip, None)
    _syn_ts.pop(src_ip, None)
    _synack_ts.pop(src_ip, None)
    _ack_ts.pop(src_ip, None)
    _burst_ts.pop(src_ip, None)
    _flow_ts.pop(src_ip, None)
    _rate_snap.pop(src_ip, None)
    _unique_ports.pop(src_ip, None)
    _attack_start.pop(src_ip, None)
    _confidence_scores.pop(src_ip, None)
    _cooldown_until.pop(src_ip, None)  # clear cooldown — don't blind re-detection


def get_ddos_info(dst_ip: str) -> dict:
    """Return DDoS indicators for a destination IP."""
    entries = list(_dst_srcs.get(dst_ip, []))
    unique_srcs = len(set(e[1] for e in entries))
    return {"dst": dst_ip, "unique_sources": unique_srcs, "packet_count": len(entries)}


# backward-compat alias
def get_flow_rate(src_ip: str, dst_ip: str) -> int:
    return get_src_rate(src_ip)


def _is_private(ip: str) -> bool:
    """Return True for RFC-1918 / loopback / link-local addresses."""
    try:
        parts = ip.split('.')
        a = int(parts[0])
        b = int(parts[1]) if len(parts) > 1 else 0
        return (
            a == 10 or a == 127
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or (a == 169 and b == 254)
        )
    except (ValueError, IndexError):
        return False


def check_global_flood(src_ip: str) -> tuple:
    """
    Detect a distributed flood: many unique external source IPs sending packets
    in a short rolling window — separate from per-IP rate detection.

    Returns (is_flood: bool, unique_external_srcs: int, total_pkts: int).
    Has its own cooldown; safe to call on every packet.
    """
    global _dist_cooldown_until
    now = time.time()
    win = config["distributed_src_window"]

    _global_src_window.append((now, src_ip))
    cutoff = now - win
    while _global_src_window and _global_src_window[0][0] < cutoff:
        _global_src_window.popleft()

    total_pkts = len(_global_src_window)

    # ── External-IP distributed flood (original logic, unchanged) ────────────
    # Counts only non-private sources so a busy LAN doesn't trigger false alerts.
    unique_ext_srcs = len(set(ip for _, ip in _global_src_window
                              if not _is_private(ip)))

    # ── Private-IP distributed flood (new — VM / LAN attack extension) ───────
    # Counts only private-address sources separately with higher thresholds.
    # This catches scenarios where multiple VMs (e.g. Kali + other VMs on the
    # same hypervisor) or infected LAN devices jointly flood a target, but each
    # individual rate stays below the per-IP ATTACK threshold.
    # The public-IP path above is completely unaffected.
    unique_pvt_srcs = len(set(ip for _, ip in _global_src_window
                               if _is_private(ip)))

    # Combined unique-source count for the return value (informational).
    unique_srcs = max(unique_ext_srcs, unique_pvt_srcs)

    # ── Profiler Calibration Guard ──
    if not _profiler_ready():
        return False, unique_srcs, total_pkts

    if now < _dist_cooldown_until:
        return False, unique_srcs, total_pkts

    is_ext_flood = (
        unique_ext_srcs >= config["distributed_src_threshold"]
        and total_pkts  >= config["distributed_pkt_threshold"]
    )
    is_pvt_flood = (
        unique_pvt_srcs >= config["distributed_private_src_threshold"]
        and total_pkts  >= config["distributed_private_pkt_threshold"]
    )
    is_flood = is_ext_flood or is_pvt_flood
    if is_flood:
        _dist_cooldown_until = now + config["distributed_cooldown"]

    return is_flood, unique_srcs, total_pkts


def reset_all() -> None:
    global _last_sample_t, _dist_cooldown_until
    _src_ts.clear()
    _syn_ts.clear()
    _synack_ts.clear()
    _ack_ts.clear()
    _flow_ts.clear()
    _burst_ts.clear()
    _dst_ts.clear()
    _dst_srcs.clear()
    _unique_ports.clear()
    _global_ts.clear()
    _baseline_samples.clear()
    _rate_snap.clear()
    _attack_start.clear()
    _cooldown_until.clear()
    _confidence_scores.clear()
    _global_src_window.clear()
    _last_sample_t = 0.0
    _dist_cooldown_until = 0.0
    # Victim-side state
    _dst_rate_ts.clear()
    _dst_src_dq.clear()
    _dst_syn_ts.clear()
    _dst_port_scan.clear()
    _dst_attack_start.clear()
    _dst_cooldown.clear()
    _dst_confidence.clear()


# ──────────────────────────────────────────────
# Background state pruner
# ──────────────────────────────────────────────

def _background_pruner() -> None:
    """Prune stale queues every second.

    Without this, _global_ts and per-IP deques only get pruned when a new
    packet arrives.  If the attack stops completely, stale timestamps linger
    and get_baseline_stats() / get_src_rate() keep reporting inflated rates,
    making the dashboard stay in ATTACK state indefinitely.

    Also clears _attack_start for IPs that have gone silent so the next
    packet from them is classified fresh instead of inheriting old state.
    """
    while True:
        time.sleep(1)
        now    = time.time()
        w      = config["rate_window"]
        cutoff = now - w

        # Always prune global queue so baseline stats reflect reality
        _prune(_global_ts, cutoff)
        _sample_global_rate(now)

        # Reset attack state for IPs that have been silent > rate_window
        for src_ip, dq in list(_src_ts.items()):
            _prune(dq, cutoff)
            if src_ip in _burst_ts:
                _prune(_burst_ts[src_ip], now - config["burst_window"])
            if dq:
                continue   # still has recent packets
            if src_ip in _attack_start:
                del _attack_start[src_ip]
                _cooldown_until[src_ip] = now + config["cooldown_seconds"]
            _confidence_scores[src_ip] = 0

        # Prune destination-side queues
        for dst_ip, dq in list(_dst_rate_ts.items()):
            _prune(dq, cutoff)
            if dst_ip in _dst_syn_ts:
                _prune(_dst_syn_ts[dst_ip], cutoff)
            if not dq and dst_ip in _dst_attack_start:
                del _dst_attack_start[dst_ip]
                _dst_cooldown[dst_ip] = now + config["cooldown_seconds"]
                _dst_confidence[dst_ip] = 0


_pruner_thread = threading.Thread(target=_background_pruner, daemon=True)
_pruner_thread.start()
