"""
core/db_manager.py — Dynamic Database Manager

Provides utility functions to:
  - Construct compliant database connection URIs (PostgreSQL, MSSQL, MySQL, SQLite, Custom).
  - Mask sensitive credentials in URIs for safe presentation/logging.
  - Test candidate database connections with strict timeouts and diagnostics.
  - Safely update .env configuration file in-place without corrupting other variables.
  - Dynamically rebind the active SQLAlchemy engine at runtime without restarting the process.
  - Seed or migrate existing accounts/cases to newly initialized databases.
"""

import os
import re
import time
import urllib.parse
from typing import Dict, Any, Optional, Tuple
from sqlalchemy import create_engine, text, inspect
from extensions import db


# Root directory for .env
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(BASE_DIR, ".env")


def mask_uri(uri: str) -> str:
    """
    Mask passwords in database connection URIs so they can be safely displayed in the UI.
    Handles standard URIs (postgresql://, mysql://) and ODBC connection strings
    (both raw PWD=secret; and URL-encoded PWD%3Dsecret%3B).
    """
    if not uri:
        return ""

    masked = uri
    # Check for ODBC connection strings: PWD=secret; or URL-encoded PWD%3D...%3B
    if "odbc_connect=" in masked:
        masked = re.sub(r"PWD=[^;]+;", "PWD=******;", masked, flags=re.IGNORECASE)
        masked = re.sub(r"PWD%3D[^%&;]+(%3B|;)?", "PWD%3D******%3B", masked, flags=re.IGNORECASE)
        return masked

    # Standard URL pattern: scheme://user:password@host:port/dbname
    pattern = r"://([^:]+):([^@]+)@"
    return re.sub(pattern, r"://\1:******@", masked)


def build_connection_uri(
    provider: str,
    host: str = "",
    port: Optional[int] = None,
    database: str = "",
    username: str = "",
    password: str = "",
    sqlite_path: str = "",
    custom_uri: str = "",
    extra_options: Optional[Dict[str, Any]] = None
) -> str:
    """
    Constructs a standardized SQLAlchemy connection URI based on provider type.
    """
    provider = (provider or "").strip().lower()
    extra_options = extra_options or {}

    # If the user pasted a complete URI into the host field or custom_uri
    if "://" in host:
        raw = host.strip()
        if raw.startswith("postgres://"):
            raw = "postgresql://" + raw[len("postgres://"):]
        return raw

    if provider == "custom":
        raw = custom_uri.strip()
        if raw.startswith("postgres://"):
            raw = "postgresql://" + raw[len("postgres://"):]
        return raw

    if provider == "sqlite":
        path = sqlite_path.strip() if sqlite_path else "soc.db"
        if not path.startswith("/") and not (len(path) > 1 and path[1] == ":") and not path.startswith("instance/"):
            return f"sqlite:///{path}"
        return f"sqlite:///{path}"

    # Encode username and password safely
    enc_user = urllib.parse.quote_plus(username.strip())
    enc_pass = urllib.parse.quote_plus(password.strip())
    host = host.strip() or "localhost"
    database = database.strip()

    if provider in ("postgres", "postgresql"):
        p = port or 5432
        sslmode = extra_options.get("sslmode")
        base = f"postgresql://{enc_user}:{enc_pass}@{host}:{p}/{database}"
        if sslmode:
            base += f"?sslmode={sslmode}"
        return base

    elif provider in ("mysql", "mariadb"):
        p = port or 3306
        charset = extra_options.get("charset", "utf8mb4")
        return f"mysql+pymysql://{enc_user}:{enc_pass}@{host}:{p}/{database}?charset={charset}"

    elif provider in ("mssql", "sqlserver"):
        use_trusted = extra_options.get("trusted_connection", False)
        server_spec = f"{host},{port}" if port else host
        odbc_driver = extra_options.get("driver", "ODBC Driver 18 for SQL Server")
        trust_cert = "yes" if extra_options.get("trust_server_certificate", True) else "no"

        if use_trusted:
            odbc_params = (
                f"DRIVER={{{odbc_driver}}};"
                f"SERVER={server_spec};"
                f"DATABASE={database};"
                "Trusted_Connection=yes;"
                f"TrustServerCertificate={trust_cert};"
            )
        else:
            odbc_params = (
                f"DRIVER={{{odbc_driver}}};"
                f"SERVER={server_spec};"
                f"DATABASE={database};"
                f"UID={username.strip()};"
                f"PWD={password.strip()};"
                f"TrustServerCertificate={trust_cert};"
            )
        encoded_odbc = urllib.parse.quote_plus(odbc_params)
        return f"mssql+pyodbc:///?odbc_connect={encoded_odbc}"

    raise ValueError(f"Unsupported database provider: {provider}")


def test_db_connection(uri: str, timeout_sec: int = 12) -> Dict[str, Any]:
    """
    Tests connectivity to a given SQLAlchemy database URI using an isolated, temporary engine.
    Returns status, latency in milliseconds, dialect, server version, and any error message.
    """
    if not uri:
        return {"ok": False, "error": "Connection URI cannot be empty."}

    connect_args = {}
    uri_lower = uri.lower()

    if "sqlite" in uri_lower:
        connect_args = {"timeout": timeout_sec}
    elif "postgresql" in uri_lower:
        connect_args = {"connect_timeout": timeout_sec}
    elif "mysql" in uri_lower:
        connect_args = {"connect_timeout": timeout_sec}
    elif "mssql" in uri_lower:
        connect_args = {"timeout": timeout_sec}

    t0 = time.time()
    temp_engine = None
    try:
        temp_engine = create_engine(
            uri,
            connect_args=connect_args,
            pool_pre_ping=False,
            echo=False
        )
        with temp_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            latency_ms = round((time.time() - t0) * 1000, 2)
            dialect_name = temp_engine.dialect.name

            server_version = "Unknown"
            try:
                version_info = getattr(temp_engine.dialect, "server_version_info", None)
                if version_info:
                    server_version = ".".join(str(x) for x in version_info)
            except Exception:
                pass

            return {
                "ok": True,
                "latency_ms": latency_ms,
                "dialect": dialect_name,
                "version": server_version,
                "message": f"Successfully connected to {dialect_name.upper()} ({latency_ms} ms)"
            }
    except Exception as exc:
        latency_ms = round((time.time() - t0) * 1000, 2)
        err_msg = str(exc)
        if "@" in err_msg and "://" in err_msg:
            err_msg = mask_uri(err_msg)
        return {
            "ok": False,
            "latency_ms": latency_ms,
            "error": err_msg,
            "message": f"Connection failed: {err_msg}"
        }
    finally:
        if temp_engine:
            try:
                temp_engine.dispose()
            except Exception:
                pass


def update_env_file(key: str, value: str, env_path: Optional[str] = None) -> bool:
    """
    Safely updates or appends a key=value pair in .env without overwriting other entries.
    Also updates os.environ in the current process.
    """
    path = env_path or ENV_PATH
    os.environ[key] = value

    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{key}={value}\n")
        return True

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    updated = False
    new_lines = []
    key_prefix = f"{key}="

    for line in lines:
        stripped = line.strip()
        if stripped.startswith(key_prefix):
            new_lines.append(f"{key}={value}\n")
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        new_lines.append(f"{key}={value}\n")

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    return True


def get_active_database_info(app) -> Dict[str, Any]:
    """
    Returns telemetry and health status of the currently active application database.
    """
    active_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    masked_uri = mask_uri(active_uri)
    dialect_name = "Unknown"
    latency_ms = -1
    is_healthy = False
    table_count = 0
    tables = []
    user_count = 0
    case_count = 0

    try:
        engine = db.engine
        dialect_name = engine.dialect.name
        
        t0 = time.time()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            latency_ms = round((time.time() - t0) * 1000, 2)
            is_healthy = True

        insp = inspect(engine)
        tables = insp.get_table_names()
        table_count = len(tables)

        if "users" in tables:
            from models import User
            user_count = User.query.count()
        if "cases" in tables:
            from models import Case
            case_count = Case.query.count()

    except Exception:
        is_healthy = False

    return {
        "uri_masked": masked_uri,
        "dialect": dialect_name,
        "is_healthy": is_healthy,
        "latency_ms": latency_ms,
        "table_count": table_count,
        "tables": tables,
        "user_count": user_count,
        "case_count": case_count,
    }


def switch_database(app, new_uri: str, clone_data: bool = False) -> Dict[str, Any]:
    """
    Dynamically switches the active Flask-SQLAlchemy database engine at runtime:
      1. Tests connectivity to new_uri.
      2. Initializes schema/tables via db.metadata.create_all(bind=target_engine).
      3. Optionally copies existing users & cases from the current DB to the new DB.
      4. Seeds default roles and admin account if fresh.
      5. Disposes current engine and replaces app.extensions['sqlalchemy'].engines[None].
      6. Updates .env for persistence across process restarts.
    """
    probe = test_db_connection(new_uri)
    if not probe["ok"]:
        return {
            "ok": False,
            "error": f"Failed to connect to target database: {probe.get('error')}"
        }

    users_to_clone = []
    cases_to_clone = []
    
    if clone_data:
        try:
            from models import User, Case
            users_to_clone = [
                {
                    "username": u.username,
                    "email": u.email,
                    "password_hash": u.password_hash,
                    "role": u.role,
                    "is_approved": u.is_approved,
                    "requested_role": u.requested_role,
                    "created_at": u.created_at,
                }
                for u in User.query.all()
            ]
            cases_to_clone = [
                {
                    "title": c.title,
                    "description": c.description,
                    "severity": c.severity,
                    "status": c.status,
                    "source_ip": c.source_ip,
                    "created_at": c.created_at,
                }
                for c in Case.query.all()
            ]
        except Exception:
            pass

    target_engine = create_engine(new_uri, pool_pre_ping=True)
    try:
        db.metadata.create_all(bind=target_engine)
    except Exception as exc:
        target_engine.dispose()
        return {
            "ok": False,
            "error": f"Failed to initialize schema tables on target database: {str(exc)}"
        }

    old_engine = app.extensions.get("sqlalchemy", {}).engines.get(None)
    if old_engine:
        try:
            old_engine.dispose()
        except Exception:
            pass

    app.config["SQLALCHEMY_DATABASE_URI"] = new_uri
    app.extensions["sqlalchemy"].engines[None] = target_engine
    db.session.remove()

    try:
        from app import _seed_rbac, _seed_admin
        _seed_rbac()
        _seed_admin()

        if clone_data and users_to_clone:
            from models import User, Case
            for udata in users_to_clone:
                if not User.query.filter_by(username=udata["username"]).first():
                    u = User(**udata)
                    db.session.add(u)
            for cdata in cases_to_clone:
                c = Case(**cdata)
                db.session.add(c)
            db.session.commit()
    except Exception:
        pass

    update_env_file("SQLALCHEMY_DATABASE_URI", new_uri)

    return {
        "ok": True,
        "message": f"Successfully switched database to {target_engine.dialect.name.upper()}!",
        "uri_masked": mask_uri(new_uri),
        "dialect": target_engine.dialect.name
    }
