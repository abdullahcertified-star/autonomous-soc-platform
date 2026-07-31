"""
correlation.py — MITRE ATT&CK Mapping + Correlation Rules Engine

Two responsibilities:

1. MITRE ATT&CK MAPPING
   Translates existing sniffer alert types → ATT&CK Tactic + Technique IDs.
   Used by the UI and case manager to annotate incidents.

2. CORRELATION ENGINE
   Evaluates user-defined CorrelationRule rows against the live alert stream.
   Each rule fires at most once per cooldown window.
   When a rule fires it creates a Case automatically.
   Runs in a background thread (10-second evaluation loop).
"""
import json
import threading
import time
from datetime import datetime, timedelta
from utils import ts

# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────
# {alert_type_keyword (lower): (tactic, technique_id, technique_name)}
MITRE_MAP: dict[str, tuple] = {
    "syn flood":           ("Impact",             "T1498",    "Network Denial of Service"),
    "udp flood":           ("Impact",             "T1498.002","Reflection Amplification"),
    "ddos":                ("Impact",             "T1498",    "Network Denial of Service"),
    "distributed flood":   ("Impact",             "T1498",    "Network Denial of Service"),
    "port scan":           ("Discovery",          "T1046",    "Network Service Discovery"),
    "syn scan":            ("Discovery",          "T1046",    "Network Service Discovery"),
    "null scan":           ("Discovery",          "T1046",    "Network Service Discovery"),
    "xmas scan":           ("Discovery",          "T1046",    "Network Service Discovery"),
    "fin scan":            ("Discovery",          "T1046",    "Network Service Discovery"),
    "arp poisoning":       ("Credential Access",  "T1557.002","ARP Cache Poisoning"),
    "arp spoof":           ("Credential Access",  "T1557.002","ARP Cache Poisoning"),
    "mac spreading":       ("Credential Access",  "T1557",    "Adversary-in-the-Middle"),
    "mitm":                ("Credential Access",  "T1557",    "Adversary-in-the-Middle"),
    "c2 beaconing":        ("Command and Control","T1071",    "Application Layer Protocol"),
    "beaconing":           ("Command and Control","T1071",    "Application Layer Protocol"),
    "lateral movement":    ("Lateral Movement",   "T1021",    "Remote Services"),
    "brute force":         ("Credential Access",  "T1110",    "Brute Force"),
    "credential stuffing": ("Credential Access",  "T1110.004","Credential Stuffing"),
    "exfiltration":        ("Exfiltration",       "T1041",    "Exfiltration Over C2 Channel"),
    "dns tunnel":          ("Command and Control","T1071.004","DNS"),
    "flood":               ("Impact",             "T1498",    "Network Denial of Service"),
}


def map_mitre(attack_type: str) -> dict:
    """Return MITRE ATT&CK metadata for a given attack type string."""
    key = (attack_type or '').lower()
    for kw, (tactic, tech_id, tech_name) in MITRE_MAP.items():
        if kw in key:
            return {
                "mitre_tactic":     tactic,
                "mitre_technique":  tech_id,
                "mitre_tech_name":  tech_name,
                "mitre_url":        f"https://attack.mitre.org/techniques/{tech_id.replace('.','/')}/",
            }
    return {"mitre_tactic": None, "mitre_technique": None, "mitre_tech_name": None, "mitre_url": None}


# ── Default built-in rules (seeded into DB on first run) ─────────────────────
DEFAULT_RULES = [
    {
        "name":        "Mass Port Scan — Critical",
        "description": "Single source scanned >500 ports",
        "rule_type":   "threshold",
        "conditions":  json.dumps({"field": "ports_scanned", "op": "gt", "value": 500,
                                   "source": "scan_events"}),
        "severity":    "CRITICAL",
        "mitre_tactic":"Discovery",
        "mitre_tech":  "T1046",
    },
    {
        "name":        "Repeated ARP Spoofing",
        "description": "Same source generated 3+ ARP anomalies",
        "rule_type":   "frequency",
        "conditions":  json.dumps({"source": "arp_events", "group_by": "src_ip",
                                   "count": 3, "window_seconds": 300}),
        "severity":    "HIGH",
        "mitre_tactic":"Credential Access",
        "mitre_tech":  "T1557.002",
    },
    {
        "name":        "C2 Beaconing Detected",
        "description": "Regular-interval callback pattern observed",
        "rule_type":   "threshold",
        "conditions":  json.dumps({"source": "beaconing_events", "any": True}),
        "severity":    "HIGH",
        "mitre_tactic":"Command and Control",
        "mitre_tech":  "T1071",
    },
    {
        "name":        "Lateral Movement — Internal Fan-Out",
        "description": "Internal host reached 6+ other internal hosts",
        "rule_type":   "threshold",
        "conditions":  json.dumps({"source": "lateral_events", "any": True}),
        "severity":    "CRITICAL",
        "mitre_tactic":"Lateral Movement",
        "mitre_tech":  "T1021",
    },
    {
        "name":        "High-Volume Attack — Multiple Incidents",
        "description": "3 or more ACTIVE incidents simultaneously",
        "rule_type":   "frequency",
        "conditions":  json.dumps({"source": "incidents", "status": "ACTIVE", "count": 3}),
        "severity":    "CRITICAL",
        "mitre_tactic":"Impact",
        "mitre_tech":  "T1498",
    },
]

_rule_last_fired: dict = {}   # {rule_id: epoch}
_RULE_COOLDOWN = 300.0


def seed_default_rules(app) -> None:
    """Insert built-in rules if no rules exist yet, and patch outdated thresholds."""
    with app.app_context():
        try:
            from models import CorrelationRule
            from extensions import db
            if CorrelationRule.query.count() == 0:
                for r in DEFAULT_RULES:
                    db.session.add(CorrelationRule(**r))
                db.session.commit()
            else:
                # Patch the Mass Port Scan rule if it still has the old threshold (100).
                # The old value caused constant false positives on localhost/Windows.
                scan_rule = CorrelationRule.query.filter_by(name="Mass Port Scan — Critical").first()
                if scan_rule:
                    try:
                        cond = json.loads(scan_rule.conditions)
                        if cond.get("value", 0) < 500:
                            cond["value"] = 500
                            scan_rule.conditions   = json.dumps(cond)
                            scan_rule.description  = "Single source scanned >500 ports"
                            db.session.commit()
                    except Exception:
                        pass
        except Exception:
            pass


# ── Rule evaluation ───────────────────────────────────────────────────────────

def _eval_rule(rule, app) -> bool:
    """Evaluate one rule against live sniffer state. Returns True if it fires."""
    try:
        cond = json.loads(rule.conditions)
    except (json.JSONDecodeError, TypeError):
        return False

    source = cond.get("source", "")

    try:
        from detection import sniffer
        from detection import beaconing

        if source == "scan_events":
            events = list(sniffer.scan_events)
            field  = cond.get("field", "ports_scanned")
            op     = cond.get("op", "gt")
            val    = cond.get("value", 0)
            for e in events:
                ev_val = e.get(field, 0)
                if op == "gt"  and ev_val > val:  return True
                if op == "gte" and ev_val >= val: return True
                if op == "eq"  and ev_val == val: return True

        elif source == "arp_events":
            events  = list(sniffer.arp_events)
            by_ip   = {}
            win_sec = cond.get("window_seconds", 300)
            cutoff  = time.time() - win_sec
            for e in events:
                ip = e.get("src_ip", "")
                by_ip[ip] = by_ip.get(ip, 0) + 1
            threshold = cond.get("count", 3)
            return any(v >= threshold for v in by_ip.values())

        elif source == "beaconing_events":
            return bool(beaconing.beaconing_events)

        elif source == "lateral_events":
            return bool(beaconing.lateral_events)

        elif source == "incidents":
            status    = cond.get("status", "ACTIVE")
            threshold = cond.get("count", 3)
            active    = sum(1 for inc in sniffer.incidents.values()
                           if inc.get("status") == status)
            return active >= threshold

    except Exception:
        pass
    return False


def _auto_create_case(rule, app) -> None:
    """Create a Case record when a correlation rule fires."""
    with app.app_context():
        try:
            from models import Case
            from extensions import db
            import uuid
            mitre = map_mitre(rule.mitre_tech or rule.name)
            case_id = f"CASE-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
            case = Case(
                case_id       = case_id,
                title         = f"[AUTO] {rule.name}",
                description   = rule.description,
                severity      = rule.severity,
                status        = 'OPEN',
                source        = 'correlation',
                attack_type   = rule.name,
                mitre_tactic  = rule.mitre_tactic or mitre["mitre_tactic"],
                mitre_technique=rule.mitre_tech or mitre["mitre_technique"],
                sla_deadline  = datetime.utcnow() + timedelta(hours=4),
            )
            db.session.add(case)
            rule.fire_count += 1
            rule.last_fired  = datetime.utcnow()
            db.session.commit()
        except Exception:
            pass


def _eval_loop(app) -> None:
    """Background thread: evaluate all enabled rules every 10 seconds."""
    # Give the app time to fully start
    time.sleep(15)
    seed_default_rules(app)

    while True:
        time.sleep(10)
        now = time.time()
        try:
            with app.app_context():
                from models import CorrelationRule
                rules = CorrelationRule.query.filter_by(enabled=True).all()
                for rule in rules:
                    if now - _rule_last_fired.get(rule.id, 0) < _RULE_COOLDOWN:
                        continue
                    if _eval_rule(rule, app):
                        _rule_last_fired[rule.id] = now
                        _auto_create_case(rule, app)
                        try:
                            from reporting import notifications
                            notifications.send_alert(
                                f"Correlation Rule Fired: {rule.name}",
                                rule.description or rule.name,
                                severity=rule.severity,
                            )
                        except Exception:
                            pass
        except Exception:
            pass


def start_correlation_engine(app) -> None:
    threading.Thread(target=_eval_loop, args=(app,), daemon=True).start()
