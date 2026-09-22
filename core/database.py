"""
database.py — SOC Event Logger (JSONL append-only)
Each log_event() is O(1): one appended line, no full-file rewrite.
Soft-delete moves entries to logs_trash.json; permanent delete removes them entirely.
Uses cross-process file locking to prevent multi-process log corruption (SEC-08).
"""
import contextlib
import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime

_BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE    = os.path.join(_BASE_DIR, "logs.json")
TRASH_FILE  = os.path.join(_BASE_DIR, "logs_trash.json")

_thread_lock = threading.Lock()


@contextlib.contextmanager
def _file_lock():
    """Combined thread and process-level file lock (SEC-08)."""
    with _thread_lock:
        lock_file = None
        try:
            lock_path = LOG_FILE + ".lock"
            lock_file = open(lock_path, "a+")
            if os.name == "nt":
                import msvcrt
                for _ in range(30):
                    try:
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        time.sleep(0.01)
                else:
                    try:
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                    except Exception:
                        pass
            else:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            if lock_file:
                try:
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
                try:
                    lock_file.close()
                except Exception:
                    pass


def _entry_id(entry: dict) -> str:
    """Return existing _id or derive a stable one from content hash."""
    if '_id' in entry:
        return entry['_id']
    key = json.dumps({k: v for k, v in entry.items() if k != '_id'}, sort_keys=True)
    return 'log-' + hashlib.sha256(key.encode()).hexdigest()[:16]


def _read_file_unlocked(path: str) -> list:
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


def _write_file_unlocked(path: str, entries: list) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def log_event(event: dict) -> None:
    event = {**event, "timestamp": datetime.now().isoformat(), "_id": str(uuid.uuid4())}
    with _file_lock():
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")


def _read_all() -> list:
    with _file_lock():
        return _read_file_unlocked(LOG_FILE)


def get_logs() -> list:
    return _read_all()


def get_recent(n: int = 50) -> list:
    """Return last n entries, newest first."""
    with _file_lock():
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
    with _file_lock():
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            pass


# ── Soft-delete (Recycle Bin) ─────────────────────────────────────────────────

def get_trash() -> list:
    """Return trashed log entries, newest-deleted first."""
    with _file_lock():
        return list(reversed(_read_file_unlocked(TRASH_FILE)))


def soft_delete_log(log_id: str) -> bool:
    """Move log entry to trash. Returns True if found and moved."""
    with _file_lock():
        all_logs = _read_file_unlocked(LOG_FILE)
        entry = next((l for l in all_logs if l.get('_id') == log_id), None)
        if not entry:
            return False
        remaining = [l for l in all_logs if l.get('_id') != log_id]
        _write_file_unlocked(LOG_FILE, remaining)
        entry['_deleted_at'] = datetime.now().isoformat()
        with open(TRASH_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return True


def restore_log(log_id: str) -> bool:
    """Restore a log entry from trash back to main log."""
    with _file_lock():
        trash = _read_file_unlocked(TRASH_FILE)
        entry = next((l for l in trash if l.get('_id') == log_id), None)
        if not entry:
            return False
        remaining_trash = [l for l in trash if l.get('_id') != log_id]
        _write_file_unlocked(TRASH_FILE, remaining_trash)
        restored = {k: v for k, v in entry.items() if k != '_deleted_at'}
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(restored) + "\n")
        return True


def permanent_delete_log(log_id: str) -> bool:
    """Permanently remove a log entry from trash."""
    with _file_lock():
        trash = _read_file_unlocked(TRASH_FILE)
        entry = next((l for l in trash if l.get('_id') == log_id), None)
        if not entry:
            return False
        remaining = [l for l in trash if l.get('_id') != log_id]
        _write_file_unlocked(TRASH_FILE, remaining)
        return True


def trash_count() -> int:
    with _file_lock():
        return len(_read_file_unlocked(TRASH_FILE))
