"""
websocket_events.py — Flask-SocketIO Real-Time Event Emitter

Runs a daemon thread that pushes live SOC data to all connected
WebSocket clients every 2 seconds, enabling true real-time dashboards
without polling.

Events emitted:
    status_update  — system health metrics (always, every 2 s)
    new_alert      — each newly registered attack alert (up to 3 per tick)
    attack_start   — fires once when the system transitions to under-attack
    attack_clear   — fires once when the attack subsides
"""
import threading
import time

from detection import sniffer
from detection import incident_manager
from core import firewall as fw
from detection import detection
from core import soc_logger as log
from extensions import socketio

_last_alert_seq = 0
_was_under_attack = False


def _build_status() -> dict:
    """Gather lightweight status snapshot for the status_update event."""
    all_active = [
        inc for inc in sniffer.incidents.values()
        if inc.get("status") in ("OPEN", "ACTIVE")
    ]
    seen_ids = {i.get("id") for i in all_active if i.get("id")}
    for inc in sniffer.target_incidents.values():
        if inc.get("status") in ("OPEN", "ACTIVE") and inc.get("id") not in seen_ids:
            all_active.append(inc)

    now = time.time()
    latch_sec = getattr(sniffer, "ATTACK_LATCH_SECONDS", 30)
    latch_active = (now - incident_manager.get_last_attack_epoch()) < latch_sec
    under_attack = (len(all_active) > 0) or latch_active

    ns = sniffer.network_stats
    return {
        "under_attack":   under_attack,
        "active_attacks": len(all_active),
        "total_packets":  ns.get("total_packets", 0),
        "blocked_ips":    fw.blocked_count(),
        "pps":            ns.get("pps", 0),
        "arp_alerts":     len(list(sniffer.arp_events)),
        "scan_alerts":    len(list(sniffer.scan_events)),
        "suspicious_ips": len(ns.get("suspicious_ips", [])),
    }


def _emitter_loop(app):
    global _last_alert_seq, _was_under_attack

    with app.app_context():
        log.info("websocket", "SocketIO event emitter started")

        while True:
            time.sleep(2)
            try:
                status = _build_status()
                socketio.emit("status_update", status)

                # ── Push new alerts ───────────────────────────────────────────
                alerts_snap = list(sniffer.alerts)
                if _last_alert_seq == 0 and alerts_snap:
                    # Initialize baseline sequence on first tick so we don't burst flood stale alerts
                    _last_alert_seq = max((a.get("seq", 0) for a in alerts_snap), default=0)
                else:
                    new_alerts = [a for a in alerts_snap if a.get("seq", 0) > _last_alert_seq]
                    if new_alerts:
                        for alert in new_alerts[-3:]:  # cap at 3 per tick
                            socketio.emit("new_alert", alert)
                        _last_alert_seq = max(a.get("seq", 0) for a in alerts_snap)

                # ── Attack state transitions ──────────────────────────────────
                now_attacking = status["under_attack"]
                if now_attacking and not _was_under_attack:
                    socketio.emit("attack_start", {
                        "active_attacks": status["active_attacks"],
                        "time": time.strftime("%H:%M:%S"),
                    })
                    log.warning("websocket", "Attack started — emitting attack_start",
                                {"attacks": status["active_attacks"]})
                elif not now_attacking and _was_under_attack:
                    socketio.emit("attack_clear", {"time": time.strftime("%H:%M:%S")})
                    log.info("websocket", "Attack cleared — emitting attack_clear")
                _was_under_attack = now_attacking

            except Exception as exc:
                log.error("websocket", f"Emitter error: {exc}")


def start_event_emitter(app):
    """Launch the background SocketIO emitter thread.  Call once from create_app()."""
    t = threading.Thread(target=_emitter_loop, args=(app,), daemon=True)
    t.name = "soc_socketio_emitter"
    t.start()
