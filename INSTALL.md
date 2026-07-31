# SOC / SIEM Platform — Installation Guide

> **Python 3.10 or higher is required.**  
> Validated on **Python 3.14.4**, **Windows 11**, and **Ubuntu 22.04 LTS**.

---

## Table of Contents

1. [System Prerequisites](#1-system-prerequisites)
2. [Clone / Extract the Project](#2-clone--extract-the-project)
3. [Virtual Environment Setup](#3-virtual-environment-setup)
4. [Install Python Dependencies](#4-install-python-dependencies)
5. [Environment Variables (.env)](#5-environment-variables-env)
6. [Database Initialization](#6-database-initialization)
7. [Run — Development Server](#7-run--development-server)
8. [Run — Production Server](#8-run--production-server)
9. [First-Time Admin Account](#9-first-time-admin-account)
10. [Verify the Installation](#10-verify-the-installation)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. System Prerequisites

### All Platforms

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | ≥ 3.10 | 3.12+ recommended |
| pip | ≥ 23.0 | Ships with Python 3.10+ |
| Git | any | For cloning only |

```bash
# Check versions
python --version        # Windows: py --version
python -m pip --version
```

---

### Windows — Npcap (packet capture driver)

Scapy requires the Npcap driver for packet capture on Windows.

1. Download from **https://npcap.com/#download**
2. Run the installer
3. During installation, **check** `WinPcap API-compatible mode`
4. Reboot if prompted

> Without Npcap, the sniffer will start but capture zero packets.  
> The rest of the platform (dashboard, auth, firewall, reports) works without it.

---

### Linux — libpcap + capabilities

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install -y libpcap-dev python3-dev build-essential

# RHEL / CentOS / Fedora
sudo dnf install -y libpcap-devel python3-devel gcc

# Allow non-root packet capture (replaces sudo)
sudo setcap cap_net_raw+eip $(which python3)
```

---

### Linux — Production server dependencies (optional)

```bash
# Only needed for production deployment (Section 8)
sudo apt install -y gunicorn
```

---

## 2. Clone / Extract the Project

```bash
# Option A — Git
git clone <repository-url> soc_auths
cd soc_auths

# Option B — ZIP / folder copy
# Place the project folder anywhere and cd into it
cd path/to/soc_auths
```

---

## 3. Virtual Environment Setup

A virtual environment keeps the SOC dependencies isolated from system Python.

```bash
# Create the virtual environment (run once)
python -m venv .venv          # Windows
python3 -m venv .venv         # Linux / macOS

# Activate the virtual environment
# ─ Windows (PowerShell) ─
.\.venv\Scripts\Activate.ps1

# ─ Windows (CMD) ─
.venv\Scripts\activate.bat

# ─ Linux / macOS ─
source .venv/bin/activate
```

> Your prompt should show `(.venv)` after activation.  
> Run `deactivate` to exit the virtual environment.

---

## 4. Install Python Dependencies

```bash
# Upgrade pip first (prevents resolver issues on older installs)
pip install --upgrade pip

# Install all platform dependencies
pip install -r requirements.txt
```

### Linux Production — add WebSocket workers

For WebSocket support in production (gunicorn), also install:

```bash
pip install gunicorn eventlet
```

### Windows Production — add WSGI server

```bash
pip install waitress
```

> **Note:** Waitress does not support native WebSocket.  
> The dashboard falls back to HTTP long-polling automatically — all features work.

---

## 5. Environment Variables (.env)

Create a `.env` file in the project root. Never commit this file to version control.

```bash
# Windows PowerShell
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```

Edit `.env` with your values:

```ini
# ─────────────────────────────────────────────────────────
#  SOC Platform — Environment Configuration
#  Copy to .env and fill in your values
# ─────────────────────────────────────────────────────────

# REQUIRED — Flask secret key (generate with: python -c "import secrets; print(secrets.token_hex(32))")
SECRET_KEY=change-me-to-a-long-random-string-before-deploy

# ENVIRONMENT — 'development' or 'production'
# production: enables SESSION_COOKIE_SECURE (requires HTTPS)
FLASK_ENV=development

# DATABASE — SQLite is the default. Uncomment one of the alternatives below.
# SQLALCHEMY_DATABASE_URI=sqlite:///users.db
# SQLALCHEMY_DATABASE_URI=postgresql://user:password@localhost/soc_db
# SQLALCHEMY_DATABASE_URI=mssql+pyodbc://user:pass@server/soc_db?driver=ODBC+Driver+17+for+SQL+Server

# SYSLOG INGESTER (optional) — UDP port to receive syslog messages
# SYSLOG_PORT=514

# RATE LIMITING — Override default 300/min if needed
# RATELIMIT_DEFAULT=500 per minute
```

The application reads `.env` automatically via `python-dotenv`.

---

## 6. Database Initialization

The database is created automatically on first run. No migration tool is needed.

```bash
# Optional: manually verify/initialize (useful for debugging)
python -c "
from app import create_app
from extensions import db
app = create_app()
with app.app_context():
    db.create_all()
    print('Database tables created successfully')
"
```

This creates `instance/users.db` with all 10 tables:

| Table | Purpose |
|-------|---------|
| `users` | User accounts (bcrypt passwords, TOTP, roles) |
| `cases` | SOC tickets / investigation lifecycle |
| `case_notes` | Analyst timeline notes per case |
| `api_keys` | REST API credentials |
| `correlation_rules` | Custom SIEM alert rules |
| `audit_logs` | Immutable user action trail |
| `ioc_entries` | Indicators of Compromise |
| `notification_configs` | Slack/Discord/email/webhook channels |
| `security_events` | Web-layer attack records (SQLi, XSS, etc.) |
| `risk_scores` | Historical IP risk scores |

---

## 7. Run — Development Server

```bash
# Activate venv first (see Section 3)

# Windows
py app.py

# Linux / macOS
python app.py
```

The server starts at **http://0.0.0.0:5000**. Open **http://localhost:5000** in a browser.

```
[SOC] INFO  app started  env=development
 * Running on http://0.0.0.0:5000
 * WebSocket ready (threading mode)
```

> `debug=False` is set in `app.py` by default.  
> For auto-reload during development, set `debug=True` in `app.py` temporarily.  
> **Never run with `debug=True` in production.**

---

## 8. Run — Production Server

### Linux — Gunicorn + Eventlet (recommended)

Eventlet provides proper async WebSocket support alongside HTTP polling.

```bash
# Single-worker (required for SocketIO — shared state)
gunicorn \
  --worker-class eventlet \
  --workers 1 \
  --bind 0.0.0.0:5000 \
  --timeout 120 \
  --keep-alive 5 \
  --log-level info \
  "app:create_app()"
```

**With systemd service** (`/etc/systemd/system/soc.service`):

```ini
[Unit]
Description=SOC SIEM Platform
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/soc_auths
ExecStart=/opt/soc_auths/.venv/bin/gunicorn \
    --worker-class eventlet \
    --workers 1 \
    --bind 0.0.0.0:5000 \
    --timeout 120 \
    "app:create_app()"
Restart=always
RestartSec=5
EnvironmentFile=/opt/soc_auths/.env

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable soc
sudo systemctl start soc
sudo systemctl status soc
```

---

### Linux — Nginx Reverse Proxy (optional)

If running behind Nginx, add WebSocket upgrade support:

```nginx
# /etc/nginx/sites-available/soc
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade    $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host       $host;
        proxy_set_header   X-Real-IP  $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/soc /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

### Windows — Waitress

```bash
# Install waitress once
pip install waitress

# Run (HTTP polling — all dashboard features work)
waitress-serve \
  --host=0.0.0.0 \
  --port=5000 \
  --threads=4 \
  "app:create_app()"
```

> Waitress does not support native WebSocket.  
> The SocketIO client falls back to long-polling automatically.  
> All real-time dashboard panels continue to work via HTTP polling.

**Windows Service with NSSM** (optional, for always-on):

```powershell
# Download NSSM from https://nssm.cc/download
# Then:
nssm install SOC-Platform "C:\path\to\.venv\Scripts\waitress-serve.exe" `
  "--host=0.0.0.0 --port=5000 app:create_app()"
nssm set SOC-Platform AppDirectory "C:\path\to\soc_auths"
nssm start SOC-Platform
```

---

## 9. First-Time Admin Account

Navigate to **http://localhost:5000/auth/register** and create your first account.

Then promote it to **admin** via the SQLite shell:

```bash
# Windows
py -c "
from app import create_app
from extensions import db
from models import User
app = create_app()
with app.app_context():
    u = User.query.filter_by(username='YOUR_USERNAME').first()
    u.role = 'admin'
    db.session.commit()
    print(f'Promoted {u.username} to admin')
"

# Linux
python -c "
from app import create_app
from extensions import db
from models import User
app = create_app()
with app.app_context():
    u = User.query.filter_by(username='YOUR_USERNAME').first()
    u.role = 'admin'
    db.session.commit()
    print(f'Promoted {u.username} to admin')
"
```

**Roles:**

| Role | Access |
|------|--------|
| `admin` | Full access: user management, all settings, all data |
| `analyst` | Dashboard, cases, incidents, firewall (no user management) |
| `viewer` | Read-only dashboard and reports |

---

## 10. Verify the Installation

```bash
# Quick smoke test — checks all modules load cleanly
py -c "
import sys
mods = ['web_ids', 'risk_scoring', 'soc_logger', 'extensions', 'models', 'report_bp']
for m in mods:
    try:
        __import__(m)
        print(f'  OK  {m}')
    except Exception as e:
        print(f'  ERR {m}: {e}')
        sys.exit(1)
print('All modules loaded successfully')
"
```

Expected output:

```
  OK  web_ids
  OK  risk_scoring
  OK  soc_logger
  OK  extensions
  OK  models
  OK  report_bp
All modules loaded successfully
```

**Browser checklist:**

| URL | Expected |
|-----|---------|
| `http://localhost:5000/` | Redirect to login |
| `http://localhost:5000/dashboard` | Live SOC dashboard |
| `http://localhost:5000/api/dashboard` | JSON status response |
| `http://localhost:5000/reports` | Reports page |
| `http://localhost:5000/api/reports/pdf?hours=24` | PDF download |
| `http://localhost:5000/api/reports/web-ids` | Web IDS events JSON |
| `http://localhost:5000/health` | `{"status": "ok"}` |

---

## 11. Troubleshooting

### `ModuleNotFoundError: No module named 'scapy'`
```bash
pip install scapy==2.5.0
```

### `ModuleNotFoundError: No module named 'flask_socketio'`
```bash
pip install flask-socketio==5.6.1 simple-websocket==1.1.0
```

### Scapy captures 0 packets (Windows)
- Verify Npcap is installed: open **Services** and check for `npcap` service running
- Re-run the Npcap installer with **"WinPcap API-compatible mode"** checked
- Run the SOC server **as Administrator** once to confirm Npcap is working

### Scapy captures 0 packets (Linux)
```bash
# Non-root packet capture capability
sudo setcap cap_net_raw+eip $(which python3)
# Or run with sudo (development only)
sudo python app.py
```

### `CSRF token missing or incorrect`
- Clear browser cookies and log in again
- Ensure `WTF_CSRF_TIME_LIMIT` in `app.py` matches your session duration
- Do not run the server behind a proxy without setting `PREFERRED_URL_SCHEME`

### PDF reports return `503 Service Unavailable`
```bash
pip install reportlab==4.5.1 pillow
```

### WebSocket not connecting (browser console shows polling fallback)
- Check that `Flask-SocketIO` and `simple-websocket` are installed
- The system falls back to HTTP polling automatically — dashboard still works
- For production WebSocket: use gunicorn + eventlet on Linux (see Section 8)

### `Address already in use` on port 5000
```bash
# Windows — find and kill the process on port 5000
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux
sudo fuser -k 5000/tcp
```

### `PermissionError` on Windows for port 514 (syslog)
- Ports below 1024 require Administrator on Windows
- Either run as Administrator or change the syslog port in the `.env`

### SQLite `database is locked`
- Only one process should access the SQLite database at a time
- For multi-process production, migrate to PostgreSQL (see `.env` section)

---

## Directory Structure (Post-Install)

```
soc_auths/
├── .env                    ← your environment config (not in git)
├── .venv/                  ← virtual environment (not in git)
├── instance/
│   └── users.db            ← SQLite database (auto-created)
├── logs/
│   └── soc.log             ← structured SOC log (auto-created)
├── static/                 ← CSS, JS, icons
├── templates/              ← Jinja2 HTML templates
├── app.py                  ← Flask app factory + entry point
├── extensions.py           ← Shared extensions (db, login, socketio, limiter)
├── models.py               ← SQLAlchemy models
├── requirements.txt        ← Python dependencies
├── INSTALL.md              ← This file
├── web_ids.py              ← Web-layer attack detection
├── risk_scoring.py         ← IP risk scoring engine
├── soc_logger.py           ← Structured logging
├── websocket_events.py     ← SocketIO real-time emitter
├── report_bp.py            ← PDF/JSON report generator
└── ...                     ← Detection, firewall, sniffer, blueprints
```

---

## Quick Reference — Common Commands

```bash
# Start development server
py app.py                                   # Windows
python app.py                               # Linux

# Start production (Linux — WebSocket enabled)
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 "app:create_app()"

# Start production (Windows — HTTP polling)
waitress-serve --host=0.0.0.0 --port=5000 "app:create_app()"

# Install / update all dependencies
pip install -r requirements.txt

# Generate a new SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Reset the database (WARNING: deletes all data)
del instance\users.db      # Windows
rm instance/users.db       # Linux
py app.py                  # re-creates tables on startup

# View structured SOC log
type logs\soc.log          # Windows
tail -f logs/soc.log       # Linux
```
