"""
database.py — SOC Event Logger (JSONL append-only)
Each log_event() is O(1): one appended line, no full-file rewrite.
Soft-delete moves entries to logs_trash.json; permanent delete removes them entirely.
"""
import json
import os
import uuid
import hashlib
from datetime import datetime

LOG_FILE   = "logs.json"
TRASH_FILE = "logs_trash.json"


def _entry_id(entry: dict) -> str:
    """Return existing _id or derive a stable one from content hash."""
    if '_id' in entry:
        return entry['_id']
    key = json.dumps({k: v for k, v in entry.items() if k != '_id'}, sort_keys=True)
    return 'log-' + hashlib.md5(key.encode()).hexdigest()[:16]


def _read_file(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        entries = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        entry = json.loads(line)
                        if '_id' not in entry:
                            entry['_id'] = _entry_id(entry)
                        entries.append(entry)
                    except json.JSONDecodeError:
                        pass
        return entries
    except OSError:
        return []


def _write_file(path: str, entries: list) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def log_event(event: dict) -> None:
    event = {**event, "timestamp": datetime.now().isoformat(), "_id": str(uuid.uuid4())}
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def _read_all() -> list:
    return _read_file(LOG_FILE)


def get_logs() -> list:
    return _read_all()


def get_recent(n: int = 50) -> list:
    """Return last n entries, newest first."""
    if not os.path.exists(LOG_FILE):
        return []
    try:
        from collections import deque
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            tail = deque(f, maxlen=n)
        entries = []
        for line in reversed(list(tail)):
            if line.strip():
                try:
                    entry = json.loads(line)
                    if '_id' not in entry:
                        entry['_id'] = _entry_id(entry)
                    entries.append(entry)
                except json.JSONDecodeError:
                    pass
        return entries
    except (json.JSONDecodeError, OSError):
        return []


def clear_log() -> None:
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        pass


# ── Soft-delete (Recycle Bin) ─────────────────────────────────────────────────

def get_trash() -> list:
    """Return trashed log entries, newest-deleted first."""
    return list(reversed(_read_file(TRASH_FILE)))


def soft_delete_log(log_id: str) -> bool:
    """Move log entry to trash. Returns True if found and moved."""
    all_logs = _read_all()
    entry = next((l for l in all_logs if l.get('_id') == log_id), None)
    if not entry:
        return False
    remaining = [l for l in all_logs if l.get('_id') != log_id]
    _write_file(LOG_FILE, remaining)
    entry['_deleted_at'] = datetime.now().isoformat()
    with open(TRASH_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return True


def restore_log(log_id: str) -> bool:
    """Restore a log entry from trash back to main log."""
    trash = _read_file(TRASH_FILE)
    entry = next((l for l in trash if l.get('_id') == log_id), None)
    if not entry:
        return False
    remaining_trash = [l for l in trash if l.get('_id') != log_id]
    _write_file(TRASH_FILE, remaining_trash)
    restored = {k: v for k, v in entry.items() if k != '_deleted_at'}
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(restored) + "\n")
    return True


def permanent_delete_log(log_id: str) -> bool:
    """Permanently remove a log entry from trash."""
    trash = _read_file(TRASH_FILE)
    entry = next((l for l in trash if l.get('_id') == log_id), None)
    if not entry:
        return False
    remaining = [l for l in trash if l.get('_id') != log_id]
    _write_file(TRASH_FILE, remaining)
    return True


def trash_count() -> int:
    return len(_read_file(TRASH_FILE))
