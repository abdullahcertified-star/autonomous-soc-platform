"""
utils/network.py — Dynamic host discovery and traffic classification.

Resolves local IPs/interfaces at runtime so VM ↔ host, NAT, bridged, and
host-only traffic is classified correctly instead of being dropped or mis-labeled.
"""
from __future__ import annotations

import ipaddress
import socket as pysocket
import threading
import time
from typing import Any, Optional

from scapy.interfaces import get_working_ifaces

# ── RFC-style buckets for dashboards and stats ───────────────────────────────
DIR_INBOUND = "INBOUND"       # remote → this host
DIR_OUTBOUND = "OUTBOUND"     # this host → remote (non-loopback)
DIR_LATERAL = "LATERAL"       # private↔private on LAN/VM segment
DIR_LOOPBACK = "LOOPBACK"     # 127.x / ::1 or host↔same-host
DIR_BROADCAST = "BROADCAST"   # L2 broadcast / global broadcast IP
DIR_MULTICAST = "MULTICAST"  # IP multicast destination
DIR_EXTERNAL = "EXTERNAL"     # neither endpoint local (promiscuous witness)

_REFRESH_INTERVAL = 30.0

# Adapter name/description keywords
_VM_KEYWORDS = (
    "vmware", "vmnet", "vmxnet", "vboxnet", "virtualbox",
    "hyper-v", "hyperv", "vethernet", "ndisbridge",
    "host-only", "nat adapter", "internal network",
)
_SKIP_KEYWORDS = (
    "bluetooth", "wan miniport", "teredo", "isatap",
    "6to4", "gameloop", "pseudo",
)
_LOOPBACK_KEYWORDS = ("loopback", "npcap loopback")


class HostIdentity:
    """Thread-safe cache of this machine's addresses and subnet membership."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._host_ips: set[str] = {"127.0.0.1"}
        self._networks: list[Any] = []
        self._last_refresh = 0.0

    def refresh(self, force: bool = False) -> None:
        now = time.monotonic()
        with self._lock:
            if not force and (now - self._last_refresh) < _REFRESH_INTERVAL:
                return
            self._last_refresh = now
            ips: set[str] = {"127.0.0.1", "::1"}
            nets: list[Any] = []

            # default-route address (often correct for primary NIC)
            dg = _default_route_ipv4()
            if dg:
                ips.add(dg)

            try:
                hn = pysocket.gethostname()
                for info in pysocket.getaddrinfo(hn, None):
                    addr = info[4][0]
                    if isinstance(addr, str) and ":" not in addr:
                        ips.add(addr)
            except Exception:
                pass

            try:
                for iface in get_working_ifaces():
                    if not iface.ip:
                        continue
                    s = str(iface.ip)
                    ips.add(s)
                    # infer /24-ish if no netmask (best-effort)
                    try:
                        if getattr(iface, "netmask", None) and str(iface.netmask) != "0.0.0.0":
                            ip_obj = ipaddress.ip_interface(
                                f"{s}/{iface.netmask}"
                            ).network
                            nets.append(ip_obj)
                        else:
                            parts = s.split(".")
                            if len(parts) == 4:
                                nets.append(ipaddress.ip_network(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", strict=False))
                    except Exception:
                        pass
            except Exception:
                pass

            # de-duplicate networks
            merged: list[Any] = []
            for n in nets:
                try:
                    merged.append(n)
                except Exception:
                    pass

            self._host_ips = ips
            self._networks = merged

    @property
    def host_ips(self) -> set[str]:
        self.refresh()
        with self._lock:
            return set(self._host_ips)

    def is_local_ip(self, ip: str) -> bool:
        self.refresh()
        with self._lock:
            if ip in self._host_ips:
                return True
            try:
                a = ipaddress.ip_address(ip)
                for n in self._networks:
                    if a in n:
                        return True
            except ValueError:
                pass
            return False


def _default_route_ipv4() -> Optional[str]:
    try:
        s = pysocket.socket(pysocket.AF_INET, pysocket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return ip.startswith("127.") or ip == "::1"


def is_multicast_dst(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False


def is_global_broadcast(ip: str) -> bool:
    return ip in ("255.255.255.255", "0.0.0.0")


def classify_direction(src: str, dst: str, host: HostIdentity) -> str:
    """
    Classify observed IPv4 direction for statistics (not Ethernet-level in/out).
    """
    if is_loopback(src) or is_loopback(dst):
        return DIR_LOOPBACK
    if is_global_broadcast(dst) or dst.endswith(".255"):
        return DIR_BROADCAST
    if is_multicast_dst(dst):
        return DIR_MULTICAST

    hs = host.is_local_ip(src)
    hd = host.is_local_ip(dst)
    src_priv = is_private(src)
    dst_priv = is_private(dst)

    if hs and hd:
        return DIR_LOOPBACK
    if hs and not hd:
        return DIR_OUTBOUND
    if hd and not hs:
        return DIR_INBOUND
    if src_priv and dst_priv:
        return DIR_LATERAL
    return DIR_EXTERNAL


def is_noise_service_port(dport: int, sport: int) -> bool:
    """mDNS / SSDP / DHCP-like — used to suppress scan false positives."""
    if dport in (67, 68) or sport in (67, 68):
        return True
    if dport in (53, 5353) and sport == 5353:
        return True
    if dport == 5353 or sport == 5353:
        return True
    if dport == 1900 or sport == 1900:
        return True
    return False


def discover_interfaces(include_loopback: bool = True) -> list[str]:
    """
    Return capture-ready interface names for all active adapters Scapy reports.

    Includes VirtualBox, VMware, Hyper-V, Ethernet, Wi-Fi, and Npcap loopback.
    """
    out: list[str] = []
    seen: set[str] = set()
    try:
        ifaces = list(get_working_ifaces())
    except Exception:
        ifaces = []

    for iface in ifaces:
        name = iface.name or ""
        if not name:
            continue
        desc = (getattr(iface, "description", "") or "").lower()
        nl = name.lower()
        combined = f"{nl} {desc}"

        if any(k in combined for k in _SKIP_KEYWORDS):
            continue
        if not include_loopback and any(k in combined for k in _LOOPBACK_KEYWORDS):
            continue

        if name not in seen:
            seen.add(name)
            out.append(name)

    # Do not merge get_if_list() on Windows: it duplicates adapters as raw GUID
    # strings that often fail pcap open ("syntax is incorrect") while the same
    # NIC is already listed above with a friendly name.

    # Prefer physical + VM adapters first, loopback last (stable ordering)
    def sort_key(n: str) -> tuple[int, str]:
        low = n.lower()
        if "loopback" in low:
            return (2, n)
        if any(k in low for k in _VM_KEYWORDS):
            return (0, n)
        return (1, n)

    out.sort(key=sort_key)
    return out


def default_bpf_filter() -> str:
    """Optional BPF: IPv4 plus ARP. Tweak if you need only specific hosts."""
    return "ip or arp"
