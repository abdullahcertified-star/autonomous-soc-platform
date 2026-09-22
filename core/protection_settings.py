"""
protection_settings.py — Persistent protection/firewall configuration

Stored in protection_settings.json alongside the app.
Thread-safe; all reads and writes go through this module.
"""
import json
import os
import threading

_SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "protection_settings.json")
_lock = threading.Lock()

_DEFAULTS = {
    "block_private_ips": False,        # allow blocking RFC-1918 / private ranges
    "flood_req_threshold": 100,        # requests per minute per IP before flagged
    "flood_block_auto": False,         # auto-block IPs that exceed flood threshold
    "mitm_detection": True,            # enable MITM / ARP spoofing detection
    "ddos_alert_threshold": 5,         # unique sources before DDoS alert
}

_settings: dict = {}


def _load() -> None:
    global _settings
    try:
        with open(_SETTINGS_FILE, "r") as f:
            _settings = {**_DEFAULTS, **json.load(f)}
    except (FileNotFoundError, json.JSONDecodeError):
        _settings = dict(_DEFAULTS)


def _save() -> None:
    tmp = _SETTINGS_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_settings, f, indent=2)
        os.replace(tmp, _SETTINGS_FILE)
    except Exception:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass
        raise


def get_settings() -> dict:
    with _lock:
        if not _settings:
            _load()
        return dict(_settings)


def update_settings(updates: dict) -> dict:
    with _lock:
        if not _settings:
            _load()
        for k, v in updates.items():
            if k in _DEFAULTS:
                default_val = _DEFAULTS[k]
                if isinstance(default_val, bool):
                    if isinstance(v, str):
                        _settings[k] = v.strip().lower() in ("true", "1", "yes", "on")
                    else:
                        _settings[k] = bool(v)
                elif isinstance(default_val, int):
                    try:
                        _settings[k] = int(v)
                    except (ValueError, TypeError):
                        pass
                else:
                    _settings[k] = type(default_val)(v)
        _save()
        return dict(_settings)


def get(key: str):
    return get_settings().get(key, _DEFAULTS.get(key))


# Eagerly load on import
_load()
