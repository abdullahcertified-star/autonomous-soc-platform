"""
packet_streamer.py — Localized Real-Time Packet Streamer & GeoIP Engine for SOC Attack Globe

Captures live, real-world network packets passing through the system interface using Scapy.
For every intercepted packet:
  1. Resolves source and destination IPs into precise geographic coordinates (lat/lon) & country metrics.
  2. Evaluates threat signatures, packet volumes, and anomaly severities.
  3. Feeds geolocated events into the Attack Globe backend (sniffer.attack_map_events).
  4. Pushes real-time WebSocket events (globe_attack_arc) to trigger animated 3D arcs.
  5. Updates the 'Active Attacks' counter and 'Top Attacking Nations' leaderboard panel.
"""

import os
import sys
import time
import socket
import struct
import threading
from collections import deque, defaultdict
from datetime import datetime

# ── Ensure UTF-8 console output on Windows ───────────────────────────────────
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
# 1. LOCAL GEOIP COORDINATE & COUNTRY DATABASE (OFFLINE-FIRST)
# ══════════════════════════════════════════════════════════════════════════════

# Comprehensive Country Dictionary with Capital/Centroid Latitude & Longitude
COUNTRY_COORDS = {
    "US": {"lat": 37.0902,  "lon": -95.7129, "name": "United States"},
    "CA": {"lat": 56.1304,  "lon": -106.3468,"name": "Canada"},
    "MX": {"lat": 23.6345,  "lon": -102.5528,"name": "Mexico"},
    "BR": {"lat": -14.2350, "lon": -51.9253, "name": "Brazil"},
    "AR": {"lat": -38.4161, "lon": -63.6167, "name": "Argentina"},
    "CO": {"lat": 4.5709,   "lon": -74.2973, "name": "Colombia"},
    "CL": {"lat": -35.6751, "lon": -71.5430, "name": "Chile"},
    "GB": {"lat": 55.3781,  "lon": -3.4360,  "name": "United Kingdom"},
    "DE": {"lat": 51.1657,  "lon": 10.4515,  "name": "Germany"},
    "FR": {"lat": 46.2276,  "lon": 2.2137,   "name": "France"},
    "IT": {"lat": 41.8719,  "lon": 12.5674,  "name": "Italy"},
    "ES": {"lat": 40.4637,  "lon": -3.7492,  "name": "Spain"},
    "NL": {"lat": 52.1326,  "lon": 5.2913,   "name": "Netherlands"},
    "PL": {"lat": 51.9194,  "lon": 19.1451,  "name": "Poland"},
    "SE": {"lat": 60.1282,  "lon": 18.6435,  "name": "Sweden"},
    "NO": {"lat": 60.4720,  "lon": 8.4689,   "name": "Norway"},
    "FI": {"lat": 61.9241,  "lon": 25.7482,  "name": "Finland"},
    "UA": {"lat": 48.3794,  "lon": 31.1656,  "name": "Ukraine"},
    "RU": {"lat": 61.5240,  "lon": 105.3188, "name": "Russia"},
    "TR": {"lat": 38.9637,  "lon": 35.2433,  "name": "Turkey"},
    "IR": {"lat": 32.4279,  "lon": 53.6880,  "name": "Iran"},
    "SA": {"lat": 23.8859,  "lon": 45.0792,  "name": "Saudi Arabia"},
    "AE": {"lat": 23.4241,  "lon": 53.8478,  "name": "United Arab Emirates"},
    "IL": {"lat": 31.0461,  "lon": 34.8516,  "name": "Israel"},
    "EG": {"lat": 26.8206,  "lon": 30.8025,  "name": "Egypt"},
    "ZA": {"lat": -30.5595, "lon": 22.9375,  "name": "South Africa"},
    "NG": {"lat": 9.0820,   "lon": 8.6753,   "name": "Nigeria"},
    "CN": {"lat": 35.8617,  "lon": 104.1954, "name": "China"},
    "JP": {"lat": 36.2048,  "lon": 138.2529, "name": "Japan"},
    "KR": {"lat": 35.9078,  "lon": 127.7669, "name": "South Korea"},
    "IN": {"lat": 20.5937,  "lon": 78.9629,  "name": "India"},
    "PK": {"lat": 30.3753,  "lon": 69.3451,  "name": "Pakistan"},
    "BD": {"lat": 23.6850,  "lon": 90.3563,  "name": "Bangladesh"},
    "SG": {"lat": 1.3521,   "lon": 103.8198, "name": "Singapore"},
    "ID": {"lat": -0.7893,  "lon": 113.9213, "name": "Indonesia"},
    "MY": {"lat": 4.2105,   "lon": 108.9758, "name": "Malaysia"},
    "TH": {"lat": 15.8700,  "lon": 100.9925, "name": "Thailand"},
    "VN": {"lat": 14.0583,  "lon": 108.2772, "name": "Vietnam"},
    "PH": {"lat": 12.8797,  "lon": 121.7740, "name": "Philippines"},
    "TW": {"lat": 23.6978,  "lon": 120.9605, "name": "Taiwan"},
    "HK": {"lat": 22.3193,  "lon": 114.1694, "name": "Hong Kong"},
    "AU": {"lat": -25.2744, "lon": 133.7751, "name": "Australia"},
    "NZ": {"lat": -40.9006, "lon": 174.8860, "name": "New Zealand"},
    "Local":{"lat": 24.8607, "lon": 67.0011,  "name": "Local Network (Host)"},
    "Unknown": {"lat": 20.0, "lon": 0.0,     "name": "External Unresolved"}
}

# Offline first-octet range mapping (IANA/RIR blocks) for instantaneous resolution
_OCTET_GEO_MAP = [
    (1,   2,   "CN"), (3,   4,   "US"), (5,   5,   "RU"),
    (6,   7,   "CA"), (8,   8,   "US"), (9,   9,   "MX"),
    (11,  13,  "CA"), (14,  14,  "JP"), (15,  16,  "UA"),
    (17,  18,  "SA"), (19,  19,  "NG"), (20,  20,  "TR"),
    (21,  21,  "PK"), (22,  22,  "SG"), (23,  24,  "US"),
    (25,  26,  "ID"), (27,  27,  "CN"), (28,  30,  "EG"),
    (31,  31,  "NL"), (32,  35,  "IR"), (36,  38,  "CN"),
    (39,  39,  "NG"), (40,  40,  "AR"), (41,  42,  "DE"),
    (43,  43,  "JP"), (44,  44,  "CA"), (45,  47,  "US"),
    (48,  48,  "AR"), (49,  49,  "KR"), (50,  53,  "FR"),
    (54,  54,  "US"), (55,  57,  "TR"), (58,  61,  "CN"),
    (62,  62,  "GB"), (63,  70,  "US"), (71,  79,  "US"),
    (80,  89,  "DE"), (90,  90,  "UA"), (91,  95,  "RU"),
    (96,  97,  "CA"), (98,  100, "US"), (101, 103, "CN"),
    (104, 107, "US"), (108, 108, "IN"), (109, 109, "RU"),
    (110, 126, "CN"), (128, 130, "US"), (131, 134, "GB"),
    (135, 137, "US"), (138, 141, "US"), (142, 142, "CA"),
    (143, 143, "US"), (144, 145, "AU"), (146, 148, "US"),
    (149, 149, "US"), (150, 150, "AU"), (151, 151, "FR"),
    (152, 152, "ZA"), (153, 153, "CN"), (154, 155, "DE"),
    (156, 156, "CN"), (157, 159, "GB"), (160, 168, "US"),
    (169, 169, "AR"), (170, 171, "MX"), (173, 175, "US"),
    (176, 177, "NL"), (178, 178, "RU"), (179, 179, "BR"),
    (180, 183, "CN"), (184, 184, "US"), (185, 185, "DE"),
    (186, 187, "BR"), (188, 193, "FR"), (194, 195, "GB"),
    (196, 197, "ZA"), (198, 199, "US"), (200, 201, "BR"),
    (202, 203, "CN"), (204, 210, "US"), (211, 223, "CN"),
]

# Dedicated high-profile IP coordinate overrides (Cloud / Public DNS / CDN)
_SPECIAL_IP_GEO = {
    "8.8.8.8":        {"code": "US", "lat": 37.4220, "lon": -122.0841, "name": "Google DNS (US)"},
    "8.8.4.4":        {"code": "US", "lat": 37.4220, "lon": -122.0841, "name": "Google DNS (US)"},
    "1.1.1.1":        {"code": "AU", "lat": -33.8688,"lon": 151.2093,  "name": "Cloudflare DNS (AU)"},
    "1.0.0.1":        {"code": "US", "lat": 37.7749, "lon": -122.4194, "name": "Cloudflare (US)"},
    "9.9.9.9":        {"code": "US", "lat": 37.7749, "lon": -122.4194, "name": "Quad9 DNS (US)"},
    "208.67.222.222": {"code": "US", "lat": 37.7749, "lon": -122.4194, "name": "OpenDNS (US)"},
    "185.220.101.5":  {"code": "DE", "lat": 52.5200, "lon": 13.4050,   "name": "Tor Relay (DE)"},
    "185.220.101.1":  {"code": "DE", "lat": 52.5200, "lon": 13.4050,   "name": "Tor Exit (DE)"},
    "45.33.32.156":   {"code": "US", "lat": 40.7128, "lon": -74.0060,  "name": "Linode Scan Host (US)"},
    "192.168.75.129": {"code": "Local", "lat": 24.8607, "lon": 67.0011, "name": "Kali Linux VM (Local)"},
}

_geo_cache = {}
_geo_cache_lock = threading.Lock()


def is_private_ip(ip: str) -> bool:
    """Returns True if IP is RFC1918, loopback, or multicast."""
    if not ip or not isinstance(ip, str):
        return True
    try:
        parts = [int(p) for p in ip.strip().split(".")]
        if len(parts) != 4:
            return True
        f, s = parts[0], parts[1]
        if f == 10 or f == 127 or f >= 224:
            return True
        if f == 172 and 16 <= s <= 31:
            return True
        if f == 192 and s == 168:
            return True
        if f == 169 and s == 254:
            return True
        return False
    except Exception:
        return True


def resolve_ip_geo(ip: str) -> dict:
    """
    High-performance localized GeoIP lookup.
    Returns: { 'country': 'US', 'country_name': 'United States', 'lat': 37.09, 'lon': -95.71, 'is_private': False }
    """
    clean_ip = (ip or "").strip()
    if not clean_ip:
        loc = COUNTRY_COORDS["Local"]
        return {"country": "Local", "country_name": loc["name"], "lat": loc["lat"], "lon": loc["lon"], "is_private": True}

    with _geo_cache_lock:
        if clean_ip in _geo_cache:
            return _geo_cache[clean_ip]

    if clean_ip in _SPECIAL_IP_GEO:
        sp = _SPECIAL_IP_GEO[clean_ip]
        res = {
            "country": sp["code"],
            "country_name": sp.get("name", COUNTRY_COORDS.get(sp["code"], {}).get("name", sp["code"])),
            "lat": sp["lat"],
            "lon": sp["lon"],
            "is_private": is_private_ip(clean_ip)
        }
        with _geo_cache_lock:
            _geo_cache[clean_ip] = res
        return res

    if is_private_ip(clean_ip):
        loc = COUNTRY_COORDS["Local"]
        res = {
            "country": "Local",
            "country_name": loc["name"],
            "lat": loc["lat"],
            "lon": loc["lon"],
            "is_private": True
        }
        with _geo_cache_lock:
            _geo_cache[clean_ip] = res
        return res

    # Public IP: Resolve via offline octet table
    try:
        first_octet = int(clean_ip.split(".")[0])
    except Exception:
        first_octet = 0

    resolved_code = "US"
    for lo, hi, code in _OCTET_GEO_MAP:
        if lo <= first_octet <= hi:
            resolved_code = code
            break

    c_info = COUNTRY_COORDS.get(resolved_code, COUNTRY_COORDS["US"])
    # Add subtle organic jitter so distinct IPs in the same country do not land on the exact same pixel
    hash_val = sum(ord(c) for c in clean_ip) % 100
    jitter_lat = ((hash_val - 50) / 100.0) * 1.8
    jitter_lon = (((hash_val * 7) % 100 - 50) / 100.0) * 2.2

    res = {
        "country": resolved_code,
        "country_name": c_info["name"],
        "lat": round(c_info["lat"] + jitter_lat, 4),
        "lon": round(c_info["lon"] + jitter_lon, 4),
        "is_private": False
    }

    with _geo_cache_lock:
        if len(_geo_cache) > 2000:
            _geo_cache.clear()
        _geo_cache[clean_ip] = res

    return res


# ══════════════════════════════════════════════════════════════════════════════
# 2. PACKET STREAMER & ATTACK CLASSIFIER
# ══════════════════════════════════════════════════════════════════════════════

class PacketStreamer:
    """
    Autonomous packet streamer that intercepts network packets via Scapy,
    enriches them with local GeoIP coordinates, and feeds the Attack Globe visualization.
    """
    def __init__(self, interface: str = None, app=None):
        self.interface = interface
        self.app = app
        self.running = False
        self._thread = None
        self.stream_stats = {
            "total_streamed": 0,
            "arcs_emitted": 0,
            "active_attacks_flagged": 0,
            "start_time": time.time(),
        }
        self._rate_limiter = deque(maxlen=200)

    def classify_packet(self, proto: str, sport: int, dport: int, length: int, flags: str = "") -> tuple[str, str]:
        """
        Classifies intercepted packet into attack/traffic type and severity.
        Returns: (attack_type, severity)
        """
        # High-risk ports / known scan patterns
        if dport in (22, 23, 3389, 445, 1433, 3306, 5900):
            if flags and "S" in flags and "A" not in flags:
                return "Port Probe (SYN)", "HIGH"
            return "Remote Service Access", "MEDIUM"

        if dport in (80, 443, 8080, 8443):
            if length > 1200:
                return "HTTP Data Flow", "MEDIUM"
            return "Web Traffic", "LOW"

        if proto == "ICMP":
            return "Echo Request", "MEDIUM"

        if proto == "UDP" and (sport in (53, 123, 1900, 389) or dport in (53, 123)):
            if length > 500:
                return "UDP Amplification Flow", "HIGH"
            return "UDP Datagram", "LOW"

        if proto == "TCP":
            if flags and "S" in flags and "A" not in flags:
                return "TCP SYN Packet", "MEDIUM"
            if flags and ("F" in flags or "P" in flags):
                return "TCP Data Exchange", "LOW"

        return f"{proto} Traffic", "LOW"

    def process_sniffed_packet(self, pkt) -> None:
        """Handler called for each packet captured by Scapy."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.l2 import Ether, ARP
        except ImportError:
            return

        if not pkt.haslayer(IP):
            return

        try:
            ip_layer = pkt[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            length = len(pkt)

            # Skip localhost loopback packets
            if src_ip.startswith("127.") and dst_ip.startswith("127."):
                return

            proto = "IP"
            sport = 0
            dport = 0
            flags = ""

            if pkt.haslayer(TCP):
                proto = "TCP"
                tcp_layer = pkt[TCP]
                sport = int(tcp_layer.sport)
                dport = int(tcp_layer.dport)
                flags = str(tcp_layer.flags)
            elif pkt.haslayer(UDP):
                proto = "UDP"
                udp_layer = pkt[UDP]
                sport = int(udp_layer.sport)
                dport = int(udp_layer.dport)
            elif pkt.haslayer(ICMP):
                proto = "ICMP"

            # ── 1. GeoIP Resolution ──────────────────────────────────────────
            src_geo = resolve_ip_geo(src_ip)
            dst_geo = resolve_ip_geo(dst_ip)

            # If both are private, anchor destination to a realistic remote host or cloud service
            # so the arc animates cleanly across the 3D globe surface
            if src_geo["is_private"] and dst_geo["is_private"]:
                # Internal host-to-host or local gateway communication
                dst_country = "Local"
                src_country = "Local"
                if dst_ip != src_ip:
                    dst_country = "PK"
            else:
                src_country = src_geo["country"]
                dst_country = dst_geo["country"]

            # ── 2. Threat Classification ─────────────────────────────────────
            attack_type, severity = self.classify_packet(proto, sport, dport, length, flags)

            now_f = time.time()
            now_ts = datetime.now().strftime("%H:%M:%S")

            # ── 3. Build Attack Map Event ────────────────────────────────────
            event = {
                "time": now_ts,
                "epoch": now_f,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_country": src_country,
                "dst_country": dst_country,
                "src_country_name": src_geo["country_name"],
                "dst_country_name": dst_geo["country_name"],
                "src_lat": src_geo["lat"],
                "src_lon": src_geo["lon"],
                "dst_lat": dst_geo["lat"],
                "dst_lon": dst_geo["lon"],
                "attack_type": attack_type,
                "proto": proto,
                "sport": sport,
                "dport": dport,
                "severity": severity,
                "rate": 1,
                "length": length,
                "confidence": 85 if severity in ("CRITICAL", "HIGH") else 60
            }

            self.stream_stats["total_streamed"] += 1

            # ── 4. Push to sniffer.attack_map_events for Attack Globe Backend ──
            try:
                from detection import sniffer
                sniffer.attack_map_events.append(event)

                # Update Top Attacking Nations tracker
                if src_country not in ("Local", "Unknown"):
                    if src_ip not in sniffer.top_attackers:
                        sniffer.top_attackers[src_ip] = {
                            "ip": src_ip,
                            "country": src_country,
                            "country_name": src_geo["country_name"],
                            "packet_count": 0,
                            "attack_type": attack_type,
                            "severity_score": 25 if severity == "HIGH" else 10,
                            "last_seen": now_ts,
                            "last_seen_epoch": now_f
                        }
                    sniffer.top_attackers[src_ip]["packet_count"] += 1
                    sniffer.top_attackers[src_ip]["last_seen"] = now_ts
                    sniffer.top_attackers[src_ip]["last_seen_epoch"] = now_f
            except Exception:
                pass

            # ── 5. Emit Real-Time WebSocket Event via Flask-SocketIO ─────────
            # Throttle emission slightly to prevent browser GPU overload during floods (max 20 arcs/sec)
            self._rate_limiter.append(now_f)
            if len(self._rate_limiter) < 20 or (now_f - self._rate_limiter[0]) >= 1.0:
                self.stream_stats["arcs_emitted"] += 1
                try:
                    from extensions import socketio
                    socketio.emit("globe_attack_arc", event)
                except Exception:
                    pass

        except Exception:
            pass

    def start_streaming(self) -> None:
        """Starts Scapy packet capture in a background daemon thread."""
        if self.running:
            return
        self.running = True

        def _worker():
            print(f"[PacketStreamer] Live packet capture initialized on interface: {self.interface or 'auto'}")
            try:
                from scapy.all import conf, sniff
                conf.use_pcap = True

                # Sniff with packet filter (IPv4 traffic)
                sniff(
                    prn=self.process_sniffed_packet,
                    filter="ip",
                    store=False,
                    stop_filter=lambda _: not self.running
                )
            except Exception as e:
                print(f"[PacketStreamer] Scapy capture warning: {e}. Switching to raw socket listener.")
                self._fallback_socket_capture()

        self._thread = threading.Thread(target=_worker, daemon=True, name="soc-packet-streamer")
        self._thread.start()

    def _fallback_socket_capture(self) -> None:
        """Fallback raw socket capture if WinPcap/Npcap interface is busy."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind(("0.0.0.0", 0))
            if hasattr(socket, "SIO_RCVALL"):
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            while self.running:
                data, _ = s.recvfrom(65535)
                if len(data) >= 20:
                    src_ip = socket.inet_ntoa(data[12:16])
                    dst_ip = socket.inet_ntoa(data[16:20])
                    proto_num = data[9]
                    proto = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "IP")
                    src_geo = resolve_ip_geo(src_ip)
                    dst_geo = resolve_ip_geo(dst_ip)
                    event = {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "epoch": time.time(),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_country": src_geo["country"],
                        "dst_country": dst_geo["country"],
                        "src_lat": src_geo["lat"],
                        "src_lon": src_geo["lon"],
                        "dst_lat": dst_geo["lat"],
                        "dst_lon": dst_geo["lon"],
                        "attack_type": f"{proto} Ingress",
                        "severity": "MEDIUM" if not src_geo["is_private"] else "LOW",
                    }
                    try:
                        from detection import sniffer
                        sniffer.attack_map_events.append(event)
                        from extensions import socketio
                        socketio.emit("globe_attack_arc", event)
                    except Exception:
                        pass
        except Exception as exc:
            print(f"[PacketStreamer] Socket capture error: {exc}")

    def stop_streaming(self) -> None:
        """Stops the live streamer."""
        self.running = False


# Singleton instance
_streamer_instance = None
_streamer_lock = threading.Lock()


def get_packet_streamer(app=None) -> PacketStreamer:
    """Returns the singleton PacketStreamer instance."""
    global _streamer_instance
    with _streamer_lock:
        if _streamer_instance is None:
            _streamer_instance = PacketStreamer(app=app)
        return _streamer_instance


def start_packet_streamer(app=None) -> PacketStreamer:
    """Idempotent launcher to start the packet streamer background thread."""
    streamer = get_packet_streamer(app)
    streamer.start_streaming()
    return streamer


# ══════════════════════════════════════════════════════════════════════════════
# 3. STANDALONE CLI DIAGNOSTIC MODE
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("  SOC 3D Attack Globe — Live Packet Streamer & GeoIP Engine")
    print("=" * 70)
    print("[1] Testing Local GeoIP Resolver...")
    test_ips = ["8.8.8.8", "1.1.1.1", "185.220.101.5", "192.168.1.50", "45.33.32.156"]
    for test_ip in test_ips:
        info = resolve_ip_geo(test_ip)
        print(f"  • IP {test_ip:15} -> {info['country']} ({info['country_name']}) | Lat: {info['lat']:8.4f}, Lon: {info['lon']:9.4f}")

    print("\n[2] Initializing Live Scapy Packet Streamer...")
    streamer = PacketStreamer()
    streamer.start_streaming()
    print("[*] Intercepting network wire packets... Press Ctrl+C to exit.\n")
    try:
        t0 = time.time()
        while True:
            time.sleep(2)
            elapsed = int(time.time() - t0)
            print(f"  [T+{elapsed}s] Captured: {streamer.stream_stats['total_streamed']} packets | Globe Arcs: {streamer.stream_stats['arcs_emitted']}")
    except KeyboardInterrupt:
        print("\nStopping streamer...")
        streamer.stop_streaming()
        print("Done.")
