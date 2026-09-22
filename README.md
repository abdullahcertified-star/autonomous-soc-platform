# 🛡️ Autonomous SOC Platform & 3D Threat Globe

> **A real-time Security Operations Center (SOC) platform featuring an interactive 3D Attack Globe, Scapy packet streaming, automated firewall containment, and SOCO — an autonomous agentic AI cybersecurity analyst.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Backend-Flask%20%7C%20Socket.IO-black.svg)](https://flask.palletsprojects.com/)
[![Three.js](https://img.shields.io/badge/Frontend-Three.js%20Globe-brightgreen.svg)](https://threejs.org/)
[![AI Engine](https://img.shields.io/badge/AI%20Copilot-SOCO%20%7C%20Gemini-orange.svg)](https://deepmind.google/technologies/gemini/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

An enterprise-ready, self-hosted Security Operations Center built with Python, Flask, Three.js, and Scapy — combining live packet capture, multi-layer intrusion detection, automated firewall response, case management, and SOCO AI analyst capabilities.

> **Authorized use only.** This platform captures traffic, port-scans hosts, and blocks IPs on the
> machine it runs on. Only point it at networks and systems you own or are explicitly permitted to test.

---

## Features

### Detection
| Capability | Details |
|---|---|
| Live packet capture | Scapy + Npcap/libpcap; sliding-window flow statistics |
| Flood detection | SYN / UDP / ICMP flood, per-IP packet-rate thresholds with confidence scoring |
| Port scan detection | Fan-out and fan-in scan recognition across the capture stream |
| Web-layer IDS | Every non-static request inspected for SQLi, XSS, and command injection |
| MITM / ARP spoofing | ARP cache anomaly detection with event history |
| Beaconing analysis | Periodic-callback detection for C2-style traffic patterns |
| Correlation engine | Background thread that groups related alerts into incidents |
| Risk scoring | Per-IP composite risk score fed from detection signals |
| Network profiling | Passive asset discovery and topology mapping |
| Syslog ingestion | UDP syslog receiver normalizes external device logs into the pipeline |
| Threat intel | IOC store with lookup API |
| MITRE ATT&CK | Detection rules mapped to techniques, with per-rule enable/disable |

### Response
| Capability | Details |
|---|---|
| Firewall control | Block / unblock / force-unblock, timed blocks, whitelist |
| Auto-block | Critical web-IDS detections (command injection) block the source for 1 hour |
| Distributed blocking | Bulk-block a set of coordinated sources |
| Honeypot | Listener service that logs interaction attempts |
| Simulation mode | Replays attack scenarios with all real blocking suppressed — safe for demos |

### Operations
| Capability | Details |
|---|---|
| Dashboards | Live SOC dashboard, network view, 3D attack globe, capture stream, top attackers |
| Case management | Cases with severity, SLA timers, notes, soft-delete trash and restore |
| Log management | Searchable log feed, soft-delete trash, restore, permanent delete |
| Reporting | On-demand PDF incident reports (ReportLab) plus JSON report APIs |
| Real-time push | Flask-SocketIO emits live events; HTTP polling fallback |
| Port scanner | Built-in scanner with banner grabbing and scan history |
| Health / metrics | `/health`, `/api/metrics`, `/api/status` endpoints |
| API keys | Scoped, hashed API keys for programmatic access |

### Access Control
| Capability | Details |
|---|---|
| Authentication | Flask-Login sessions, bcrypt (cost 12) password hashing |
| RBAC | Three system roles — `viewer` (L0), `analyst` (L1), `admin` (L2) — with a cumulative permission matrix seeded idempotently on startup |
| Registration approval | New accounts land in a pending queue until an admin approves them |
| CSRF protection | Flask-WTF on every POST form, 1-hour token lifetime |
| Rate limiting | Flask-Limiter per IP, plus per-account lockout after repeated login failures |
| Audit trail | Login attempts recorded with success/failure reason |
| Security headers | `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, no-store on `/api/` |
| Password reset | Token-based flow with 1-hour expiry |

---

## Project Structure

```
soc_auths/
├── app.py                    # App factory, blueprint registration, RBAC/admin seeding,
│                             #   before/after-request security hooks, background threads
├── extensions.py             # db, login_manager, socketio, limiter (avoids circular imports)
├── models.py                 # SQLAlchemy models: users, roles, permissions, cases, IOCs, …
├── rbac.py                   # ROLE_PERMISSIONS matrix + permission decorators
├── requirements.txt          # Pinned dependencies + system prerequisites
├── SOC_Platfrom Database.sql # SQL Server schema (DDL only)
│
├── blueprints/               # HTTP layer — 14 blueprints
│   ├── auth.py               #   register / login / logout / password reset
│   ├── main.py               #   dashboards, capture stream, sensor & layer APIs
│   ├── settings.py           #   detection tuning, user admin, permissions, simulation
│   ├── firewall.py           #   block / unblock / whitelist / ARP events
│   ├── cases.py              #   case CRUD, notes, trash, stats
│   ├── analytics.py          #   logs, log trash, top attackers
│   ├── report.py             #   PDF + JSON reports
│   ├── portscan.py           #   scanner UI and scan lifecycle APIs
│   ├── incidents.py · mitre.py · threat_intel.py · honeypot.py
│   └── health.py · api_keys.py
│
├── detection/                # Detection engines
│   ├── sniffer.py            #   capture loop and per-packet dispatch
│   ├── detection.py          #   threshold/flood/scan logic + tunable config
│   ├── network_sensor.py     #   passive topology & asset sensing
│   ├── correlation.py        #   alert → incident correlation thread
│   ├── web_ids.py            #   SQLi / XSS / command-injection request inspection
│   ├── beaconing.py · risk_scoring.py · network_profiler.py
│   └── analyzer.py · capture.py · normalizer.py · incident_manager.py · real.py
│
├── core/                     # Platform services
│   ├── firewall.py           #   OS firewall integration and block state
│   ├── layers.py             #   L2–L7 flow/session tracking
│   ├── syslog_ingester.py    #   UDP syslog receiver
│   ├── websocket_events.py   #   SocketIO event emitter
│   ├── honeypot_server.py · remote_agent.py · soc_logger.py
│   └── database.py · sim.py · protection_settings.py
│
├── reporting/                # Report generation, notifications, threat-intel feeds
├── utils/                    # Network helpers and sliding-window statistics
├── scripts/                  # Attack simulators (SYN / UDP / ICMP flood, port scan) + benchmark
├── templates/                # 28 Jinja2 templates
└── static/                   # soc.css, hacker.css, style.css, three.js (globe view)
```

---

## Quick Start

Full step-by-step instructions live in **[INSTALL.md](INSTALL.md)** (cross-platform) and
**[SETUP.md](SETUP.md)** (Windows walkthrough). The short version:

### 1. System prerequisites

- **Python 3.10+**
- **Npcap** (Windows, tick *WinPcap API-compatible mode*) or **libpcap** (Linux) — required for capture
- **ODBC Driver 18 for SQL Server** and a **SQL Server** instance with a `SOC_Platform` database

### 2. Virtual environment + dependencies

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure environment

Think of `.env` as your private local settings file (which is git-ignored and never committed to GitHub), while `.env.example` is the public template.

**A. Create your `.env` file from the template:**
```bash
cp .env.example .env          # Windows PowerShell: copy .env.example .env
```
*(Alternatively in VS Code / File Explorer: Right-click `.env.example` → Copy → Paste → Rename to `.env`)*

**B. Open `.env` and set your values:**

1. **Pick your Admin Password:**  
   Change `your-strong-password-here` to the password you want to use when logging into the platform:
   ```ini
   SEED_ADMIN_USERNAME=seed_admin
   SEED_ADMIN_EMAIL=admin@soc.local
   SEED_ADMIN_PASSWORD=YourPassword123!
   ```
   *(Note: If left blank or unset, the platform will auto-generate a secure 16-character password and display it in your console on startup).*

2. **Generate your Flask Secret Key:**  
   Run this one-liner to generate a secure random scramble-code for session cookies:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
   Copy the output and paste it after `SECRET_KEY=`:
   ```ini
   SECRET_KEY=d83f2a1b9c4e7f0a12847291a0b3c5e7...
   ```

3. **Choose your Database:**  
   * **Local SQLite (Zero Setup — Recommended for testing):** Keep `SQLALCHEMY_DATABASE_URI` commented out (default). The platform will automatically create and manage a local database with zero configuration.
   * **PostgreSQL / Neon / RDS:** Uncomment and set your connection URI (`postgresql://user:pass@host/dbname?sslmode=require`).

4. **AI Copilot (Optional):**  
   * Add your `GEMINI_API_KEY` from [Google AI Studio](https://aistudio.google.com/) for Gemini 2.5 Flash reasoning (falls back to the built-in heuristic analyst if left blank).

> **Never commit `.env`** — it is listed in `.gitignore` and holds your local secrets.

### 4. Run

```bash
python app.py
```

The server starts at **http://127.0.0.1:5000**. On first run, the app creates the database schema, seeds the
RBAC roles and permissions, and registers the initial `seed_admin` superuser from your `.env` configuration.

> Packet capture needs elevated privileges. Run as Administrator on Windows, or on Linux grant the
> capability once: `sudo setcap cap_net_raw+eip $(which python3)`. Without it the sniffer starts but
> sees no traffic.

---

## Key Routes

| URL | Description |
|---|---|
| `/auth/register` · `/auth/login` · `/auth/logout` | Account lifecycle |
| `/auth/forgot-password` · `/auth/reset-password/<token>` | Password reset |
| `/dashboard` | Main SOC dashboard |
| `/network` · `/globe` · `/capture` · `/mitm` | Network, 3D globe, live capture, MITM views |
| `/incidents` · `/cases` · `/cases/trash` | Incident and case management |
| `/logs` · `/logs/trash` · `/attackers` | Log feed, trash, top attackers |
| `/firewall` | Block list, whitelist, ARP events |
| `/scanner` | Port scanner |
| `/threat-intel` · `/mitre` | IOC store, ATT&CK coverage |
| `/reports` | Report builder → `GET /api/reports/pdf` |
| `/settings` · `/admin/permissions` · `/admin/users/pending` | Tuning, RBAC matrix, approvals |
| `/health` · `/api/metrics` · `/api/status` | Health and metrics endpoints |

JSON APIs mirror the pages under `/api/…` and are CSRF- and permission-guarded.

---

## Configuration

All runtime configuration is read from `.env` — see **[.env.example](.env.example)** for the full
annotated list. Highlights:

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Session and CSRF signing key — required |
| `FLASK_ENV` | `production` enables HTTPS-only cookies |
| `SEED_ADMIN_USERNAME` / `_EMAIL` / `_PASSWORD` | First-run superuser |
| `CAPTURE_INTERFACE` | Override auto-detected capture NIC |
| `SYSLOG_PORT` / `SYSLOG_HOST` | Syslog receiver binding |
| `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` | Critical-alert notifications |

Detection thresholds are tuned live from `/settings` and persisted to
`detection/detection_config.json`; firewall behaviour is persisted to
`core/protection_settings.json`. Both fall back to in-code defaults when the files are absent, and
both are gitignored as runtime state.

---

## Simulation Mode

Enable simulation from `/settings` to replay attack scenarios end-to-end without touching the real
firewall. Blocks that *would* have fired are recorded as suppressed events instead. The standalone
simulators in [scripts/](scripts/) generate real traffic against a target you control:

```bash
python scripts/sim_syn_flood.py
python scripts/sim_port_scan.py
python scripts/sim_udp_flood.py
python scripts/sim_icmp_flood.py
```

---

## Production Notes

1. Generate a strong `SECRET_KEY` and set `FLASK_ENV=production` (enables `SESSION_COOKIE_SECURE`).
2. Terminate TLS in front of the app — session cookies are secure-only in production mode.
3. Run under a real WSGI server:
   - **Linux:** `pip install gunicorn eventlet` (full WebSocket support)
   - **Windows:** `pip install waitress` (HTTP polling fallback; waitress has no WebSocket support)
4. The SQL Server connection string in [app.py](app.py) is currently hardcoded to a local
   `SQLEXPRESS` instance — point it at your own server before deploying.
5. Password reset currently flashes the reset link instead of emailing it; wire up Flask-Mail or
   SendGrid before exposing the app.
6. Put the syslog receiver and dashboard on a management network, not the internet.

---

## Password Requirements

Minimum 8 characters, with at least one uppercase letter, one lowercase letter, one digit, and one
special character.
