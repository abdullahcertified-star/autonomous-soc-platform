"""
utils/stats.py — Timestamp-based sliding-window traffic statistics (accurate PPS/BPS).

Replaces naive counters: rates are derived from (monotonic_timestamp, byte_len)
events pruned by window age — not from mis-labeled 5-second raw counts.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any

from utils.network import DIR_BROADCAST, DIR_LOOPBACK, DIR_MULTICAST


WIN_1S = 1.0
WIN_10S = 10.0


def _mono() -> float:
    return time.perf_counter()


class _DirectionWindows:
    """Byte + packet counters per direction bucket for a single window length."""

    __slots__ = ("packets", "bytes", "lock")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.packets: deque[tuple[float, int]] = deque()
        self.bytes: deque[tuple[float, int]] = deque()

    def add(self, t_mono: float, nbytes: int) -> None:
        with self.lock:
            self.packets.append((t_mono, 1))
            self.bytes.append((t_mono, nbytes))

    def prune(self, t_mono: float, window: float) -> None:
        cutoff = t_mono - window
        with self.lock:
            while self.packets and self.packets[0][0] < cutoff:
                self.packets.popleft()
            while self.bytes and self.bytes[0][0] < cutoff:
                self.bytes.popleft()

    def count_packets(self) -> int:
        with self.lock:
            return len(self.packets)

    def sum_bytes(self) -> int:
        with self.lock:
            return sum(b for _, b in self.bytes)


class TrafficStatistics:
    """
    Thread-safe global traffic accounting with 1 s and 10 s sliding windows.

    - Global PPS: packet count in the last 1 s wall in monotonic space.
    - 10 s average PPS: total packets in last 10 s / 10.
    - Bandwidth: sum(bytes) in 1 s / 1 (separate inbound/outbound where known).
    """

    def __init__(self, graph_depth: int = 60) -> None:
        self._lock = threading.Lock()
        self._events: deque[tuple[float, int, str, str]] = deque()
        # (t, nbytes, proto, direction)

        self._dir_1s: dict[str, _DirectionWindows] = defaultdict(_DirectionWindows)
        self.graph_samples: deque[float] = deque(maxlen=graph_depth)
        self.drop_count = 0

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self.graph_samples.clear()
            self._dir_1s.clear()
            self.drop_count = 0

    def record(self, *, nbytes: int, proto: str, direction: str, t_mono: float | None = None) -> None:
        """Record one counted packet after deduplication."""
        t = t_mono if t_mono is not None else _mono()
        with self._lock:
            self._events.append((t, max(0, nbytes), proto, direction))
            self._dir_1s[direction].add(t, max(0, nbytes))
            self._prune_locked(t)

    def _prune_locked(self, t_mono: float) -> None:
        cutoff = t_mono - WIN_10S
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        for dw in self._dir_1s.values():
            dw.prune(t_mono, WIN_10S)

    def prune_external(self) -> None:
        """Call from a maintenance thread so rates decay when traffic stops."""
        t = _mono()
        with self._lock:
            self._prune_locked(t)

    # ── Queries (must hold lock or copy quickly) ───────────────────────────

    def pps_1s(self) -> float:
        t = _mono()
        with self._lock:
            self._prune_locked(t)
            c = 0
            c10 = 0
            cutoff1 = t - WIN_1S
            cutoff10 = t - WIN_10S
            for ev in self._events:
                if ev[0] >= cutoff1:
                    c += 1
                if ev[0] >= cutoff10:
                    c10 += 1
            return float(c)

    def pps_10s_avg(self) -> float:
        t = _mono()
        with self._lock:
            self._prune_locked(t)
            cutoff10 = t - WIN_10S
            c10 = sum(1 for ev in self._events if ev[0] >= cutoff10)
            return c10 / WIN_10S

    def bytes_per_sec_1s(self, direction: str | None = None) -> float:
        """Layer-3 aggregate bytes per second (1 s window)."""
        t = _mono()
        cutoff1 = t - WIN_1S
        with self._lock:
            self._prune_locked(t)
            if direction is None:
                b = sum(sz for ts, sz, _, d in self._events if ts >= cutoff1)
                return float(b) / WIN_1S
            b = 0
            for ts, sz, _, d in self._events:
                if ts >= cutoff1 and d == direction:
                    b += sz
            return float(b) / WIN_1S

    def protocol_counts_1s(self) -> dict[str, int]:
        """Packets per protocol in the last 1 second (for live distribution)."""
        t = _mono()
        cutoff1 = t - WIN_1S
        out: dict[str, int] = defaultdict(int)
        with self._lock:
            self._prune_locked(t)
            for ts, _, proto, _ in self._events:
                if ts >= cutoff1:
                    out[proto] += 1
        return dict(out)

    def snapshot_talkers_1s(self, limit: int = 10) -> list[tuple[str, int]]:
        """Top source IPs by packet count in the last 1 s (requires optional IP tracking)."""
        # Populated via TopTalkerTracker; placeholder returns [] if unused
        return []

    def append_graph_sample(self, value: float) -> None:
        with self._lock:
            self.graph_samples.append(value)

    def get_traffic_history(self) -> list[float]:
        with self._lock:
            return list(self.graph_samples)


class TopTalkerTracker:
    """Rolling 1 s source-IP histogram for dashboard 'top talkers'."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._dq: deque[tuple[float, str]] = deque()

    def record(self, src_ip: str, t_mono: float | None = None) -> None:
        t = t_mono if t_mono is not None else _mono()
        with self._lock:
            self._dq.append((t, src_ip))
            c = t - WIN_1S
            while self._dq and self._dq[0][0] < c:
                self._dq.popleft()

    def top(self, n: int = 10) -> list[tuple[str, int]]:
        t = _mono()
        cutoff = t - WIN_1S
        cnt: dict[str, int] = defaultdict(int)
        with self._lock:
            while self._dq and self._dq[0][0] < cutoff:
                self._dq.popleft()
            for ts, ip in self._dq:
                if ts >= cutoff:
                    cnt[ip] += 1
        return sorted(cnt.items(), key=lambda x: x[1], reverse=True)[:n]

    def clear(self) -> None:
        with self._lock:
            self._dq.clear()


def estimate_packet_size_layers(pkt: Any) -> int:
    """Safe wire size; fall back to len(bytes)."""
    try:
        return len(bytes(pkt))
    except Exception:
        return 0


def direction_for_stats(direction: str) -> str:
    """Map fine-grained direction into IN / OUT / OTHER for byte split."""
    if direction == DIR_LOOPBACK:
        return DIR_LOOPBACK
    if direction in (DIR_BROADCAST, DIR_MULTICAST):
        return direction
    from utils.network import DIR_INBOUND, DIR_OUTBOUND, DIR_LATERAL, DIR_EXTERNAL

    if direction == DIR_INBOUND:
        return DIR_INBOUND
    if direction == DIR_OUTBOUND:
        return DIR_OUTBOUND
    if direction == DIR_LATERAL:
        return DIR_LATERAL
    return DIR_EXTERNAL


# Singletons wired by sniffer / analyzer
traffic_stats = TrafficStatistics(graph_depth=60)
top_talkers = TopTalkerTracker()
