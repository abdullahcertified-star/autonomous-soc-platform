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
from core import firewall as fw
from detection import detection
from core import soc_logger as log
from extensions import socketio

_last_alert_len = 0
_was_under_attack = False


def _build_status() -> dict:
    """Gather lightweight status snapshot for the status_update event."""
    active = [
        inc for inc in sniffer.incidents.values()
        if inc.get("status") in ("OPEN", "ACTIVE")
    ]
    ns = sniffer.network_stats
    return {
        "under_attack":   len(active) > 0,
        "active_attacks": len(active),
        "total_packets":  ns.get("total_packets", 0),
        "blocked_ips":    fw.blocked_count(),
        "pps":            ns.get("pps_1s", 0),
        "arp_alerts":     len(list(sniffer.arp_events)),
        "scan_alerts":    len(list(sniffer.scan_events)),
        "suspicious_ips": len(ns.get("suspicious_ips", [])),
    }


def _emitter_loop(app):
    global _last_alert_len, _was_under_attack

    with app.app_context():
        log.info("websocket", "SocketIO event emitter started")

        while True:
            time.sleep(2)
            try:
                status = _build_status()
                socketio.emit("status_update", status)

                # ── Push new alerts ───────────────────────────────────────────
                alerts_snap = list(sniffer.alerts)
                current_len = len(alerts_snap)
                if current_len > _last_alert_len:
                    new_alerts = alerts_snap[_last_alert_len:]
                    for alert in new_alerts[-3:]:  # cap at 3 per tick
                        socketio.emit("new_alert", alert)
                _last_alert_len = current_len

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
