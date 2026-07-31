"""
syslog_ingester.py — UDP Syslog Listener (RFC 3164 / RFC 5424)

Listens on UDP port 514 (configurable) and ingests syslog messages.
Parsed events are:
  • Written to the existing log_event() pipeline
  • Checked against threat intel (src IP)
  • Can trigger correlation rule sources (source = "syslog_events")

Never modifies sniffer.py or detection.py state.

Usage:
  from core.syslog_ingester import start_syslog_ingester
  start_syslog_ingester(app)
"""
import re
import socket
import threading
import time
from collections import deque
from datetime import datetime

from core.database import log_event

# ── In-memory ring buffer ─────────────────────────────────────────────────────
syslog_events: deque = deque(maxlen=1000)
_lock = threading.Lock()

SYSLOG_PORT    = 514
SYSLOG_BIND    = '0.0.0.0'
MAX_MSG_BYTES  = 4096

# RFC 3164 month abbreviations
_MONTHS = {m: i+1 for i, m in enumerate(
    ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'])}

# Regex patterns
_RE_RFC3164 = re.compile(
    r'^<(\d+)>'                             # PRI
    r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # TIMESTAMP
    r'(\S+)\s+'                             # HOSTNAME
    r'([^:]+):\s*'                          # TAG
    r'(.*)',                                # MSG
    re.DOTALL,
)
_RE_RFC5424 = re.compile(
    r'^<(\d+)>(\d+)\s+'                    # PRI VERSION
    r'(\S+)\s+'                             # TIMESTAMP
    r'(\S+)\s+'                             # HOSTNAME
    r'(\S+)\s+'                             # APP-NAME
    r'(\S+)\s+'                             # PROCID
    r'(\S+)\s+'                             # MSGID
    r'(\S+)\s*'                             # STRUCTURED-DATA
    r'(.*)',                                 # MSG
    re.DOTALL,
)


def _parse_pri(pri: int) -> tuple:
    """Return (facility_name, severity_name, sev_int) from PRI value."""
    facility_int = pri >> 3
    severity_int = pri & 0x07
    facilities = {
        0: 'kern', 1: 'user', 2: 'mail', 3: 'daemon', 4: 'auth',
        5: 'syslog', 6: 'lpr', 7: 'news', 8: 'uucp', 9: 'cron',
        16: 'local0', 17: 'local1', 18: 'local2', 19: 'local3',
        20: 'local4', 21: 'local5', 22: 'local6', 23: 'local7',
    }
    severities = {
        0: 'EMERGENCY', 1: 'ALERT', 2: 'CRITICAL', 3: 'ERROR',
        4: 'WARNING', 5: 'NOTICE', 6: 'INFO', 7: 'DEBUG',
    }
    sev_map = {
        0: 'CRITICAL', 1: 'CRITICAL', 2: 'CRITICAL', 3: 'HIGH',
        4: 'MEDIUM', 5: 'LOW', 6: 'LOW', 7: 'LOW',
    }
    return (
        facilities.get(facility_int, f'fac{facility_int}'),
        severities.get(severity_int, 'UNKNOWN'),
        sev_map.get(severity_int, 'LOW'),
    )


def _parse_syslog(raw: str, src_ip: str) -> dict:
    """Parse a syslog message string into a structured dict."""
    base = {
        'time':    datetime.utcnow().isoformat(),
        'src_ip':  src_ip,
        'raw':     raw[:500],
        'source':  'syslog',
    }

    m = _RE_RFC5424.match(raw)
    if m and m.group(2) == '1':
        pri, _, ts, host, app, pid, msgid, _, msg = m.groups()
        fac, sev_name, sev = _parse_pri(int(pri))
        return {**base, 'pri': int(pri), 'facility': fac,
                'syslog_severity': sev_name, 'severity': sev,
                'hostname': host, 'app': app, 'pid': pid,
                'msg': msg.strip()}

    m = _RE_RFC3164.match(raw)
    if m:
        pri, ts, host, tag, msg = m.groups()
        fac, sev_name, sev = _parse_pri(int(pri))
        return {**base, 'pri': int(pri), 'facility': fac,
                'syslog_severity': sev_name, 'severity': sev,
                'hostname': host, 'app': tag.strip(), 'msg': msg.strip()}

    # Fallback — unparsed
    return {**base, 'severity': 'LOW', 'msg': raw[:200]}


def _process(raw: str, src_ip: str, app_ctx) -> None:
    event = _parse_syslog(raw, src_ip)

    with _lock:
        syslog_events.appendleft(event)

    # Check threat intel on source IP
    try:
        from reporting import threat_intel
        hit = threat_intel.check_ip(src_ip)
        if hit:
            event['threat_intel'] = hit
            event['severity'] = 'HIGH'
    except Exception:
        pass

    # Log to event pipeline
    try:
        log_event({
            'type':     'SYSLOG',
            'ip':       src_ip,
            'severity': event.get('severity', 'LOW'),
            'msg':      event.get('msg', '')[:200],
            'time':     event['time'],
        })
    except Exception:
        pass


def _listen(port: int, app) -> None:
    """UDP listener thread."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2.0)
        sock.bind((SYSLOG_BIND, port))
    except OSError:
        # Port 514 requires admin on most systems — fail silently
        return

    while True:
        try:
            data, addr = sock.recvfrom(MAX_MSG_BYTES)
            src_ip = addr[0]
            raw    = data.decode('utf-8', errors='replace').strip()
            if raw:
                with app.app_context():
                    _process(raw, src_ip, app)
        except socket.timeout:
            continue
        except Exception:
            time.sleep(1)


def start_syslog_ingester(app, port: int = SYSLOG_PORT) -> None:
    """Start the syslog UDP listener in a daemon thread."""
    threading.Thread(target=_listen, args=(port, app), daemon=True).start()


def get_recent(limit: int = 100) -> list:
    with _lock:
        return list(syslog_events)[:limit]
