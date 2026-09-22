# SOC Platform v3.0 — Complete Setup Guide

## System Requirements

| Component | Minimum |
|---|---|
| OS | Windows 10 / 11 (64-bit) |
| RAM | 4 GB (8 GB recommended) |
| Disk | 2 GB free |
| Python | 3.10 or newer |
| Browser | Chrome 110+, Edge 110+, Firefox 110+ |
| Network | One active network adapter |

---

## Step 1 — Install Python

1. Go to **https://www.python.org/downloads/**
2. Download **Python 3.10 or newer** (3.14 recommended)
3. Run the installer
4. **IMPORTANT** — on the first screen tick **"Add Python to PATH"** before clicking Install Now
5. After install, open a Command Prompt and verify:

```
python --version
```

Expected output: `Python 3.14.x` (or whichever version you installed)

If `python` is not recognised, use `py` instead — the Python Launcher ships with all Windows installs.

---

## Step 2 — Install Npcap (Packet Capture Driver)

Npcap is required for the live packet capture engine (Scapy). Without it the sniffer will not start.

1. Go to **https://npcap.com/#download**
2. Download the latest **Npcap installer** (e.g. `npcap-1.80.exe`)
3. Run the installer
4. On the options screen **tick "WinPcap API-compatible Mode"** — this is required
5. Complete the install and **restart your PC** if prompted

---

## Step 3 — Install SQL Server Express

The platform stores all users, cases, incidents, and logs in Microsoft SQL Server.

1. Go to **https://www.microsoft.com/en-us/sql-server/sql-server-downloads**
2. Scroll down and download **SQL Server Express** (free edition)
3. Run the installer and choose **Basic** installation type
4. Wait for the install to complete — note the server name shown at the end (usually `PCNAME\SQLEXPRESS`)
5. Optionally install **SQL Server Management Studio (SSMS)** from the same page — useful for managing the database

### Create the database

After SQL Server is installed, open **Command Prompt as Administrator** and run:

```
sqlcmd -S .\SQLEXPRESS -Q "CREATE DATABASE SOC_Platform"
```

Or open SSMS, connect to `.\SQLEXPRESS`, open a New Query window and run:

```sql
CREATE DATABASE SOC_Platform;
```

---

## Step 4 — Install ODBC Driver 18

Python connects to SQL Server through the ODBC driver. This must be installed separately.

1. Go to **https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server**
2. Download **ODBC Driver 18 for SQL Server** (Windows x64)
3. Run the `.msi` installer and complete with default settings

Verify it is installed:

```
odbcconf /Q
```

You should see `ODBC Driver 18 for SQL Server` in the list.

---

## Step 5 — Copy the Project Files

Copy the entire project folder to the target machine. The folder structure must look like this:

```
soc_auths/
├── app.py
├── sniffer.py
├── main.py
├── models.py
├── firewall.py
├── detection.py
├── requirements.txt
├── .env
├── templates/
├── static/
├── logs/
└── instance/
```

If the `logs/` folder does not exist, create it manually:

```
mkdir logs
```

---

## Step 6 — Configure the Database Connection

Open `app.py` in a text editor and find this block around line 169:

```python
_odbc = urllib.parse.quote_plus(
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=ABDULLAH\\SQLEXPRESS;"
    "DATABASE=SOC_Platform;"
    "Trusted_Connection=yes;"
    "TrustServerCertificate=yes;"
)
```

Change `ABDULLAH\\SQLEXPRESS` to match your own PC name:

```python
    "SERVER=YOURPCNAME\\SQLEXPRESS;"
```

To find your PC name, open Command Prompt and run:

```
hostname
```

Example: if `hostname` returns `LAPTOP-XYZ`, change the line to:

```python
    "SERVER=LAPTOP-XYZ\\SQLEXPRESS;"
```

Save the file.

---

## Step 7 — Configure the .env File

The project root contains a `.env` template that holds the admin credentials and security keys.
Copy `.env.example` to `.env` and set your preferred values:

```ini
SEED_ADMIN_USERNAME=seed_admin
SEED_ADMIN_EMAIL=admin@soc.local
SEED_ADMIN_PASSWORD=your-secure-password-here
SECRET_KEY=any-long-random-string-here
FLASK_ENV=development
```

* Choose a strong password for `SEED_ADMIN_PASSWORD`. If left blank, the system will auto-generate a secure random 16-character password and display it on first launch.
* Generate a strong `SECRET_KEY` using: `python -c "import secrets; print(secrets.token_hex(32))"`

---

## Step 8 — Install Python Dependencies

Open Command Prompt **inside the project folder** and run:

```
pip install -r requirements.txt
```

Or if `pip` is not recognised:

```
py -3 -m pip install -r requirements.txt
```

This will install Flask, Scapy, SQLAlchemy, Flask-SocketIO, bcrypt, and all other required packages. It may take 1–2 minutes.

Verify the install completed without errors. Common errors and fixes:

| Error | Fix |
|---|---|
| `Microsoft Visual C++ 14.0 is required` | Install "Build Tools for Visual Studio" from https://visualstudio.microsoft.com/visual-cpp-build-tools/ |
| `No module named pip` | Run `py -3 -m ensurepip --upgrade` |
| `pyodbc install failed` | Make sure ODBC Driver 18 is installed first (Step 4) |

---

## Step 9 — Run the Application

Open Command Prompt in the project folder and run:

```
python app.py
```

Or:

```
py -3 app.py
```

**You must run this as Administrator** for full packet capture capability. Right-click Command Prompt → "Run as Administrator", then navigate to the project folder.

On first run you will see output similar to:

```
 * Starting sniffer on interface: Ethernet
 * Seeding RBAC roles and permissions...
 * Creating seed_admin superuser...
 * Running on http://0.0.0.0:5000
```

Leave this window open — closing it stops the server.

---

## Step 10 — Access the Dashboard

Open your browser and go to:

```
http://localhost:5000
```

Or from another device on the same network:

```
http://<YOUR-PC-IP-ADDRESS>:5000
```

To find your IP address, run `ipconfig` in Command Prompt and look for `IPv4 Address`.

---

## Step 11 — First Login

| Field | Value |
|---|---|
| Username | `seed_admin` |
| Password | `Admin@SOC2024!` (or whatever you set in `.env`) |

After logging in you will be on the main SOC Dashboard.

---

## Troubleshooting

### "No module named scapy" or sniffer errors on startup

Scapy is installed but Npcap is missing or installed without WinPcap mode.
Reinstall Npcap (Step 2) making sure to tick **"WinPcap API-compatible Mode"**, then restart.

### "Login failed for user" / database connection error

- Confirm SQL Server Express is running: open Services (`services.msc`) and check that **SQL Server (SQLEXPRESS)** is Started
- Confirm the PC name in `app.py` matches your actual hostname (`hostname` command)
- Confirm the `SOC_Platform` database exists (Step 3)

### Page loads but shows no live traffic

The sniffer requires the app to run **as Administrator**. Close the current terminal and reopen Command Prompt with "Run as Administrator", then start the app again.

### "Address already in use" on port 5000

Another process is using port 5000. Either stop that process or change the port in the last line of `app.py`:

```python
socketio.run(app, host="0.0.0.0", port=5001, ...)
```

Then access the dashboard at `http://localhost:5001`.

### CSRF / 400 Bad Request on login

Clear your browser cookies for `localhost` and try again.

---

## Resetting to a Clean State (for demo or presentation)

Delete these files from the project folder:

```
logs.json
logs_trash.json
sim_events.json
logs\soc.log
instance\users.db
```

Then in SSMS: right-click `SOC_Platform` database → Delete → tick "Close existing connections" → OK.

Restart the app. All tables are recreated fresh and the default `seed_admin` account is restored automatically.

---

## Quick Reference

| Action | Command |
|---|---|
| Start the app | `py -3 app.py` |
| Install dependencies | `py -3 -m pip install -r requirements.txt` |
| Find your PC name | `hostname` |
| Find your IP address | `ipconfig` |
| Create the database | `sqlcmd -S .\SQLEXPRESS -Q "CREATE DATABASE SOC_Platform"` |
| Default login | `seed_admin` / `Admin@SOC2024!` |
| Dashboard URL | `http://localhost:5000` |
