"""
honeypot_server.py — Standalone Honeypot Server (port 5001)

Run separately from the main SOC platform:
    python honeypot_server.py

Every visit and login attempt is written to the shared logs.json so
it appears automatically in the SOC log feed, reports page, and incidents.
"""
import os
import sys

# Ensure we can import from the SOC project directory
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _PROJECT_ROOT)

from flask import Flask, render_template, request
from collections import deque

# Shared log writer — writes to the same logs.json as the SOC platform
from core.database import log_event
from utils import ts

app = Flask(
    __name__,
    template_folder=os.path.join(_PROJECT_ROOT, "templates"),
    static_folder=os.path.join(_PROJECT_ROOT, "static"),
)
app.secret_key = os.urandom(24)

# In-memory log (last 500 hits — queried by SOC /api/honeypot-log)
_honeypot_log: deque = deque(maxlen=500)


@app.route("/", methods=["GET", "POST"])
@app.route("/admin-login", methods=["GET", "POST"])
@app.route("/admin", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def admin_login():
    ip  = request.remote_addr or "unknown"
    ua  = request.headers.get("User-Agent", "")[:200]
    now = ts()
    triggered = False

    if request.method == "POST":
        username = request.form.get("username", "")[:64]
        password = request.form.get("password", "")[:64]

        entry = {
            "type":     "HONEYPOT",
            "ip":       ip,
            "dst":      "honeypot:5001",
            "username": username,
            "password": password,
            "time":     now,
            "severity": "HIGH",
            "msg": (
                f"HONEYPOT TRIGGERED — {ip} submitted login "
                f"as '{username}' on fake admin panel (port 5001)"
            ),
        }
        triggered = True

    else:
        entry = {
            "type":     "HONEYPOT",
            "ip":       ip,
            "dst":      "honeypot:5001",
            "time":     now,
            "severity": "MEDIUM",
            "user_agent": ua,
            "msg": (
                f"HONEYPOT VISIT — {ip} accessed fake admin panel "
                f"(port 5001) | UA: {ua[:100]}"
            ),
        }

    _honeypot_log.appendleft(entry)
    # Write to shared logs.json — visible in SOC log feed + reports instantly
    log_event(entry)

    return render_template("honeypot.html", triggered=triggered, ip=ip, time=now)


@app.route("/api/honeypot-log")
def api_honeypot_log():
    """Internal API — queried by SOC platform's /api/honeypot-log proxy."""
    return {"log": list(_honeypot_log), "total": len(_honeypot_log)}


if __name__ == "__main__":
    print("=" * 55)
    print("  HONEYPOT SERVER  —  http://0.0.0.0:5001")
    print("  Logs forwarded to SOC platform via shared logs.json")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5001, debug=False)
