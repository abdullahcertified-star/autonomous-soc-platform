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
    with open(_SETTINGS_FILE, "w") as f:
        json.dump(_settings, f, indent=2)


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
                _settings[k] = type(_DEFAULTS[k])(v)
        _save()
        return dict(_settings)


def get(key: str):
    return get_settings().get(key, _DEFAULTS.get(key))


# Eagerly load on import
_load()
