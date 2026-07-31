"""
normalizer.py — IP-agnostic traffic normalization for the SOC detection pipeline.

This module is a thin compatibility shim inserted between packet capture and
the detection engine.  It does NOT change detection thresholds, firewall rules,
incident lifecycle, the packet capture path, or any SOC pipeline logic.

──────────────────────────────────────────────────────────────────────────────
WHY THIS EXISTS — two concrete blind spots fixed here
──────────────────────────────────────────────────────────────────────────────

BLIND SPOT 1: sniffer._should_drop_packet() condition 4
  Original logic: drop if (src in host_ips) AND (dst in host_ips).
  Intent: suppress Windows self-traffic (Defender, WSL, Docker loopback).
  Side-effect: when VMware / VirtualBox NAT forwards a VM attack to the host,
  the post-NAT packet arrives with:
      src = host's VMnet adapter IP   (e.g. 192.168.75.1)
      dst = host's physical NIC IP    (e.g. 192.168.1.100)
  Both endpoints are host IPs → original check drops the packet → the entire
  attack stream from Kali (or any VM on NAT mode) is silently discarded before
  it ever reaches detection.record_packet().

  Fix (should_drop_same_machine):
    Narrow the drop to cases where the two IPs share the same /24 subnet
    (genuine intra-interface self-traffic) or are identical (loopback alias).
    Cross-subnet host-to-host flows — the signature of hypervisor NAT — are
    passed through to the detection engine unchanged.

BLIND SPOT 2: detection.check_global_flood() private-IP exclusion
  Original: unique_srcs counts only non-private sources.
  Side-effect: VM-originated distributed attacks (multiple Kali VMs, or many
  infected LAN hosts) never accumulate enough unique_srcs to fire the
  distributed flood alert, even if each individual rate is below the per-IP
  ATTACK threshold.

  Fix (in detection.py): add a parallel private-IP distributed flood check
  with its own (higher) thresholds so the existing public-IP behaviour is
  preserved while private-IP distributed attacks are also detected.

──────────────────────────────────────────────────────────────────────────────
DESIGN CONSTRAINTS
──────────────────────────────────────────────────────────────────────────────
  • No changes to detection thresholds or severity classifications.
  • No changes to firewall, incident lifecycle, or database layers.
  • No changes to frontend or capture logic.
  • classify_src() is for attribution / display only; it never gates detection.
"""
from __future__ import annotations
from typing import FrozenSet


# ──────────────────────────────────────────────────────────────────────────────
# Public API — used by sniffer.py
# ──────────────────────────────────────────────────────────────────────────────

def should_drop_same_machine(src: str, dst: str,
                              host_ips: FrozenSet[str]) -> bool:
    """
    Subnet-aware replacement for sniffer._should_drop_packet() condition 4.

    Returns True  → packet is genuine self-traffic, discard it (same as before).
    Returns False → packet has at least one external endpoint OR is cross-subnet
                    host-to-host (NATed VM traffic) → pass to detection engine.

    Drop conditions (both must be host IPs, AND one of):
      a) src == dst              — pure loopback / IP alias reflection
      b) src and dst share /24  — intra-interface self-traffic (Windows apps,
                                   Defender, WSL on same subnet)

    Pass conditions (either causes a False return):
      • src or dst is NOT a host IP  → external traffic, never filter
      • both host IPs but different  → cross-subnet NATed VM attack traffic
        /24 subnets                    (e.g. VMnet 192.168.75.1 → physical
                                        192.168.1.100) — pass to detection
    """
    # Fast path: at least one external endpoint → never filter.
    if src not in host_ips or dst not in host_ips:
        return False

    # Pure loopback alias / same-IP reflection → drop.
    if src == dst:
        return True

    # Same /24 → intra-interface self-traffic → drop.
    try:
        if src.rsplit(".", 1)[0] == dst.rsplit(".", 1)[0]:
            return True
    except Exception:
        # Malformed IP string — conservative: drop.
        return True

    # Both are host IPs but on different /24 subnets.
    # This is the VMware / VirtualBox NAT fingerprint:
    #   src = VMnet adapter (192.168.75.1), dst = physical NIC (192.168.1.100)
    # The packet represents a real VM attack forwarded by the hypervisor NAT.
    # Pass it through to the detection engine.
    return False


def classify_src(ip: str, host_ips: FrozenSet[str]) -> str:
    """
    Return an attribution label for a source IP.

    Used exclusively for log / event metadata enrichment.
    This function NEVER gates detection — it has no side effects on severity,
    confidence, rate counting, or any other detection decision.

    Returns one of: 'loopback' | 'host' | 'private' | 'external'
    """
    if ip.startswith("127.") or ip in ("::1",):
        return "loopback"
    if ip in host_ips:
        return "host"
    try:
        parts  = ip.split(".")
        first  = int(parts[0])
        second = int(parts[1]) if len(parts) > 1 else 0
        private = (
            first == 10
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
            or (first == 169 and second == 254)
        )
        return "private" if private else "external"
    except (ValueError, IndexError):
        return "external"
