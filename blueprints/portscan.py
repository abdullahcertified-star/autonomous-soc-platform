"""
portscan_bp.py — Built-in Port Scanner
TCP Connect scan using Python socket — no nmap, no admin required.
"""

import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

portscan_bp = Blueprint("portscan", __name__)

# ── Service name lookup ───────────────────────────────────────────────────────
_SERVICES: dict = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP",
    123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 179: "BGP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "Submission", 631: "IPP", 636: "LDAPS", 873: "rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS5", 1194: "OpenVPN",
    1433: "MS-SQL", 1521: "Oracle-DB", 1723: "PPTP", 2049: "NFS",
    2375: "Docker", 2376: "Docker-TLS", 2379: "etcd", 3000: "HTTP-Dev",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4444: "Metasploit",
    5000: "HTTP-Dev", 5432: "PostgreSQL", 5672: "RabbitMQ",
    5900: "VNC", 5901: "VNC-1", 6379: "Redis", 6443: "Kubernetes",
    7001: "WebLogic", 8000: "HTTP-Dev", 8008: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9000: "PHP-FPM", 9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
    10250: "Kubelet", 11211: "Memcached", 27017: "MongoDB",
    27018: "MongoDB-Shard", 50070: "Hadoop-HDFS",
}

# ── Port profiles ─────────────────────────────────────────────────────────────
_QUICK_PORTS = sorted({
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 27017,
})

_COMMON_PORTS = sorted(set(range(1, 1025)) | {
    1433, 1521, 1723, 2049, 2375, 2376, 2379, 3000, 3306, 3389, 3690,
    4444, 5000, 5432, 5672, 5900, 5901, 6379, 6443, 7001, 8000, 8008,
    8080, 8443, 8888, 9000, 9200, 9300, 10250, 11211, 27017, 27018,
})

TIMEOUT = 0.6
WORKERS = 150

# ── Scan store ────────────────────────────────────────────────────────────────
_scans:      dict = {}
_scans_lock  = threading.Lock()
_history:    list = []


# ── Helpers ───────────────────────────────────────────────────────────────────

def _banner(ip: str, port: int) -> str:
    """Grab first line of service banner. Returns '' on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((ip, port))
        if port in (80, 8080, 8000, 8008, 8443):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 21:
            pass  # FTP sends banner on connect
        raw = s.recv(256)
        s.close()
        line = raw.decode("utf-8", errors="ignore").split("\n")[0].strip()
        return line[:80]
    except Exception:
        return ""


def _scan_port(ip: str, port: int) -> tuple:
    """Returns (port, is_open, banner)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            return port, True, _banner(ip, port)
        return port, False, ""
    except Exception:
        return port, False, ""


def _parse_ports(spec: str) -> list:
    """Parse '22,80,443,8000-8100' → sorted list of ints."""
    ports: set = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                for p in range(int(lo.strip()), int(hi.strip()) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except Exception:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except Exception:
                pass
    return sorted(ports)


def _run_scan(scan_id: str, ip: str, ports: list, stop_ev: threading.Event) -> None:
    """Background scanner thread."""
    total = len(ports)
    done  = 0
    open_count = 0

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(_scan_port, ip, p): p for p in ports}
        for fut in as_completed(futures):
            if stop_ev.is_set():
                ex.shutdown(wait=False, cancel_futures=True)
                break
            port, is_open, banner = fut.result()
            done += 1
            if is_open:
                open_count += 1
                with _scans_lock:
                    _scans[scan_id]["results"].append({
                        "port":    port,
                        "state":   "open",
                        "service": _SERVICES.get(port, "Unknown"),
                        "banner":  banner,
                    })
            with _scans_lock:
                _scans[scan_id]["ports_done"] = done
                _scans[scan_id]["progress"]   = round(done / total * 100, 1)

    elapsed = round(time.time() - _scans[scan_id]["start"], 1)
    status  = "stopped" if stop_ev.is_set() else "done"

    with _scans_lock:
        sc = _scans[scan_id]
        sc["status"]     = status
        sc["elapsed"]    = elapsed
        sc["open_count"] = open_count
        sc["results"].sort(key=lambda r: r["port"])

    with _scans_lock:
        _history.insert(0, {
            "scan_id":     scan_id,
            "target":      ip,
            "hostname":    _scans[scan_id].get("hostname", ip),
            "open_count":  open_count,
            "ports_total": total,
            "elapsed":     elapsed,
            "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status":      status,
        })
        if len(_history) > 20:
            _history.pop()


# ── Routes ────────────────────────────────────────────────────────────────────

@portscan_bp.route("/scanner")
@login_required
def scanner_page():
    return render_template("scanner.html", user=current_user)


@portscan_bp.route("/api/scan/start", methods=["POST"])
@login_required
def api_scan_start():
    data   = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    mode   = data.get("mode", "quick")
    custom = (data.get("custom") or "").strip()

    if not target:
        return jsonify({"error": "Target is required"}), 400

    try:
        ip = socket.gethostbyname(target)
    except Exception:
        return jsonify({"error": f"Cannot resolve hostname: {target}"}), 400

    if mode == "quick":
        ports = _QUICK_PORTS
    elif mode == "common":
        ports = _COMMON_PORTS
    elif mode == "full":
        ports = list(range(1, 65536))
    elif mode == "custom":
        ports = _parse_ports(custom)
        if not ports:
            return jsonify({"error": "No valid ports in custom range"}), 400
    else:
        ports = _QUICK_PORTS

    scan_id  = uuid.uuid4().hex[:12]
    stop_ev  = threading.Event()

    with _scans_lock:
        _scans[scan_id] = {
            "status":      "running",
            "target":      ip,
            "hostname":    target,
            "mode":        mode,
            "ports_total": len(ports),
            "ports_done":  0,
            "progress":    0.0,
            "results":     [],
            "open_count":  0,
            "start":       time.time(),
            "elapsed":     0,
            "stop_event":  stop_ev,
        }

    threading.Thread(
        target=_run_scan, args=(scan_id, ip, ports, stop_ev),
        daemon=True, name=f"scan-{scan_id}"
    ).start()

    return jsonify({"scan_id": scan_id, "target": ip, "total": len(ports)})


@portscan_bp.route("/api/scan/<scan_id>/status")
@login_required
def api_scan_status(scan_id):
    with _scans_lock:
        sc = _scans.get(scan_id)
    if not sc:
        return jsonify({"error": "Scan not found"}), 404
    elapsed = (round(time.time() - sc["start"], 1)
               if sc["status"] == "running" else sc.get("elapsed", 0))
    return jsonify({
        "status":      sc["status"],
        "target":      sc["target"],
        "hostname":    sc.get("hostname", sc["target"]),
        "mode":        sc.get("mode", ""),
        "ports_total": sc["ports_total"],
        "ports_done":  sc["ports_done"],
        "progress":    sc["progress"],
        "open_count":  sc.get("open_count", len([r for r in sc["results"] if r["state"] == "open"])),
        "elapsed":     elapsed,
        "results":     sc["results"],
    })


@portscan_bp.route("/api/scan/<scan_id>/stop", methods=["POST"])
@login_required
def api_scan_stop(scan_id):
    with _scans_lock:
        sc = _scans.get(scan_id)
    if sc:
        sc["stop_event"].set()
    return jsonify({"ok": True})


@portscan_bp.route("/api/scan/history")
@login_required
def api_scan_history():
    with _scans_lock:
        return jsonify({"history": list(_history)})
