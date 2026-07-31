"""
capture.py — Stable SOC capture engine (no missing imports)
"""
from __future__ import annotations

import ctypes
import os
import platform
import queue
import threading

from scapy.all import conf
from scapy.sendrecv import AsyncSniffer

from utils.network import default_bpf_filter


# ─────────────────────────────────────────────
# ADMIN CHECK
# ─────────────────────────────────────────────

def _is_admin() -> bool:
    """Check Windows/Linux admin/root privileges"""
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ─────────────────────────────────────────────
# LOOPBACK RESOLUTION
# ─────────────────────────────────────────────

def resolve_loopback_iface() -> str:
    """Return loopback interface for Scapy (Windows/Linux safe)"""
    try:
        from scapy.arch import get_working_ifaces

        for iface in get_working_ifaces():
            name = (iface.name or "").lower()
            desc = (getattr(iface, "description", "") or "").lower()

            if "loopback" in name or "loopback" in desc:
                return iface.name

    except Exception:
        pass

    return r"\Device\NPF_Loopback"


# ─────────────────────────────────────────────
# LOOPBACK SNIFER (MISSING FIX)
# ─────────────────────────────────────────────

def start_loopback_sniffer(callback, iface_name: str):
    """
    Dedicated loopback capture (Npcap / VM localhost traffic)
    """
    try:
        def _wrap(pkt):
            callback(pkt, iface=iface_name)

        sniffer = AsyncSniffer(
            iface=iface_name,
            prn=_wrap,
            store=False,
            filter="ip",
        )

        sniffer.start()
        print(f"[SOC] Loopback capture active: {iface_name}")
        return sniffer

    except Exception as e:
        print(f"[SOC] Loopback sniffer error: {e}")
        return None


# ─────────────────────────────────────────────
# CAPTURE ENGINE
# ─────────────────────────────────────────────

class CaptureEngine:
    def __init__(
        self,
        packet_callback,
        *,
        bpf_filter: str | None = None,
        use_queue: bool = True,
        queue_size: int = 75000,
        workers: int = 3,
    ):
        self.cb = packet_callback
        self.bpf = bpf_filter or default_bpf_filter()

        self.use_queue = use_queue
        self.q = queue.Queue(maxsize=queue_size) if use_queue else None

        self.workers = workers
        self.stop_event = threading.Event()

        self.sniffers = []
        self.threads = []

        self.dropped = 0
        self.status = None

    # ─────────────────────────────────────────────

    def set_status_dict(self, d: dict):
        self.status = d

    # ─────────────────────────────────────────────

    def _worker(self):
        while not self.stop_event.is_set():
            try:
                iface, pkt = self.q.get(timeout=0.5)
                self.cb(pkt, iface=iface)
                self.q.task_done()
            except queue.Empty:
                continue
            except Exception:
                pass

    # ─────────────────────────────────────────────

    def _push(self, pkt, iface: str):
        if not self.q:
            self.cb(pkt, iface=iface)
            return

        try:
            self.q.put_nowait((iface, pkt))
        except queue.Full:
            self.dropped += 1
            if self.status:
                self.status["dropped_packets"] = self.dropped

    # ─────────────────────────────────────────────

    def start(self, ifaces: list[str], *, promisc: bool = True):
        conf.sniff_promisc = promisc

        # workers
        for _ in range(self.workers if self.use_queue else 0):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self.threads.append(t)

        # sniffers
        for iface in ifaces:
            try:
                sniffer = AsyncSniffer(
                    iface=iface,
                    prn=lambda p, i=iface: self._push(p, i),
                    store=False,
                    filter=self.bpf,
                )
                sniffer.start()
                self.sniffers.append(sniffer)
                print(f"[SOC] Capturing on {iface}")
            except Exception as e:
                print(f"[SOC] Failed on {iface}: {e}")

    # ─────────────────────────────────────────────

    def stop(self):
        self.stop_event.set()

        for s in self.sniffers:
            try:
                s.stop()
            except Exception:
                pass