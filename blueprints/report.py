"""
report_bp.py — SOC Report Generator Blueprint

Endpoints:
    GET  /reports              — Reports page (HTML)
    GET  /api/reports/data     — JSON report data  (?hours=24)
    GET  /api/reports/pdf      — Download PDF report (?hours=24)
    GET  /api/reports/web-ids  — Web-layer attack events + stats
    GET  /api/reports/risk     — IP risk scores
"""
import io
import time
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request, send_file, render_template, abort
from flask_login import login_required, current_user
from rbac import require_permission

from detection import sniffer
from core import firewall as fw
from detection import detection
from detection import web_ids
from detection import risk_scoring
from core import soc_logger as log
from core.database import get_logs as _get_logs

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import inch
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table,
        TableStyle, HRFlowable,
    )
    _PDF_OK = True
except ImportError:
    _PDF_OK = False

report_bp = Blueprint("report", __name__)


# ── Data gathering ────────────────────────────────────────────────────────────

def _gather(hours: int = 24) -> dict:
    cutoff = time.time() - hours * 3600

    incidents = [
        inc for inc in sniffer.incidents.values()
        if inc.get("start_epoch", 0) >= cutoff
    ]
    alerts = [
        a for a in sniffer.alerts
        if a.get("epoch", 0) >= cutoff
    ]
    top_attackers = sorted(
        sniffer.top_attackers.values(),
        key=lambda x: x.get("packet_count", 0),
        reverse=True,
    )[:20]

    scan_events = [e for e in sniffer.scan_events if e.get("epoch", 0) >= cutoff]
    arp_events  = [e for e in sniffer.arp_events  if e.get("epoch", 0) >= cutoff]

    # Honeypot hits — read from shared logs.json, filter by type and time window
    cutoff_dt = datetime.utcnow() - timedelta(hours=hours)
    honeypot_hits = []
    for entry in _get_logs():
        if entry.get("type") != "HONEYPOT":
            continue
        try:
            ts = datetime.fromisoformat(entry.get("timestamp", ""))
            if ts < cutoff_dt:
                continue
        except Exception:
            pass
        honeypot_hits.append(entry)
    honeypot_hits.reverse()  # newest first

    bl = detection.get_baseline_stats()

    # Enrich top attackers with risk scores
    enriched = []
    for a in top_attackers:
        rs = risk_scoring.score_incident(a)
        enriched.append({**a, "risk_score": rs["score"], "risk_level": rs["level"]})

    return {
        "generated_at":  datetime.utcnow().isoformat() + "Z",
        "period_hours":  hours,
        "incidents":     incidents,
        "alerts":        alerts,
        "top_attackers": enriched,
        "scan_events":   scan_events,
        "arp_events":    arp_events,
        "honeypot_hits": honeypot_hits[:100],
        "honeypot_total": len(honeypot_hits),
        "blocked_ips":   fw.get_blocked_list(),
        "baseline":      bl,
        "protocol_stats": dict(sniffer.protocol_stats),
        "total_packets": sniffer.network_stats.get("total_packets", 0),
        "attack_counts": {
            "incidents":      len(incidents),
            "alerts":         len(alerts),
            "port_scans":     len(scan_events),
            "arp_attacks":    len(arp_events),
            "blocked_ips":    fw.blocked_count(),
            "honeypot_probes": len(honeypot_hits),
        },
    }


def _recommendations(data: dict) -> list:
    c = data["attack_counts"]
    recs = []
    if c["incidents"] > 10:
        recs.append("HIGH incident volume — review triage SLA and consider adding analyst capacity.")
    if c["port_scans"] > 5:
        recs.append("Elevated port-scan activity. Enforce ingress filtering and review ACLs.")
    if c["arp_attacks"] > 0:
        recs.append("ARP/MITM events detected. Enable Dynamic ARP Inspection on managed switches.")
    if c["blocked_ips"] < c["incidents"] // 2:
        recs.append("Many incident sources remain unblocked. Review 'Block Suspicious' automation.")
    bl = data.get("baseline", {})
    if bl.get("status") == "ATTACK":
        recs.append("Traffic baseline is in ATTACK state — investigate active flood sources now.")
    ws = web_ids.get_stats()
    if ws["total_events"] > 0:
        recs.append(
            f"Web-layer attacks detected ({ws['total_events']} events). "
            "Review WAF rules and sanitise all user input."
        )
    if c.get("honeypot_probes", 0) > 0:
        recs.append(
            f"{c['honeypot_probes']} honeypot probe(s) detected. "
            "Review source IPs in the Honeypot Probe Log and consider blocking them."
        )
    if not recs:
        recs.append("No critical issues in this reporting period. Continue standard monitoring.")
    recs.append("Ensure all open cases are assigned and progressing within SLA deadlines.")
    recs.append("Regularly tune correlation rules to reduce false-positive fatigue.")
    return recs


# ── PDF generator ─────────────────────────────────────────────────────────────

def _make_pdf(data: dict) -> io.BytesIO:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        rightMargin=0.75 * inch, leftMargin=0.75 * inch,
        topMargin=0.75 * inch,  bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()

    H1 = ParagraphStyle("H1", parent=styles["Title"],
                        textColor=HexColor("#ef4444"), fontSize=22, spaceAfter=4)
    H2 = ParagraphStyle("H2", parent=styles["Heading2"],
                        textColor=HexColor("#38bdf8"), fontSize=13,
                        spaceBefore=14, spaceAfter=6)
    BODY = ParagraphStyle("BODY", parent=styles["Normal"],
                          fontSize=9, spaceAfter=3, textColor=HexColor("#c9d6e8"))

    BG_DARK  = HexColor("#060b14")
    BG_MED   = HexColor("#0a1628")
    BORDER   = HexColor("#1f2f4d")
    ACCENT   = HexColor("#38bdf8")
    FG       = HexColor("#c9d6e8")

    def _table(rows, col_widths):
        t = Table(rows, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0),  BG_MED),
            ("TEXTCOLOR",    (0, 0), (-1, 0),  ACCENT),
            ("FONTSIZE",     (0, 0), (-1, 0),  9),
            ("FONTSIZE",     (0, 1), (-1, -1), 8),
            ("GRID",         (0, 0), (-1, -1), 0.5, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_DARK, BG_MED]),
            ("TEXTCOLOR",    (0, 1), (-1, -1), FG),
            ("ALIGN",        (1, 1), (-1, -1), "CENTER"),
        ]))
        return t

    story = []
    c = data["attack_counts"]

    # ── Cover ─────────────────────────────────────────────────────────────────
    story.append(Paragraph("SOC Security Report", H1))
    story.append(Paragraph(
        f"Generated: {data['generated_at']} | Period: last {data['period_hours']}h",
        BODY,
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    story.append(Spacer(1, 10))

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", H2))
    summary_rows = [
        ["Metric", "Value", "Assessment"],
        ["Total Incidents",       str(c["incidents"]),
         "ELEVATED" if c["incidents"] > 5 else "NORMAL"],
        ["Total Alerts",          str(c["alerts"]),   ""],
        ["Port Scan Events",      str(c["port_scans"]), ""],
        ["ARP / MITM Events",     str(c["arp_attacks"]),
         "ACTION REQUIRED" if c["arp_attacks"] else "CLEAN"],
        ["Blocked IPs",           str(c["blocked_ips"]), ""],
        ["Total Packets Captured",str(data["total_packets"]), ""],
        ["Web-Layer Attacks",
         str(web_ids.get_stats()["total_events"]),
         "REVIEW" if web_ids.get_stats()["total_events"] else "CLEAN"],
        ["Honeypot Probes",
         str(data.get("honeypot_total", 0)),
         "INVESTIGATE" if data.get("honeypot_total", 0) else "CLEAN"],
    ]
    story.append(_table(summary_rows, [3.2 * inch, 1.8 * inch, 2.2 * inch]))
    story.append(Spacer(1, 10))

    # ── Top Attackers ─────────────────────────────────────────────────────────
    if data["top_attackers"]:
        story.append(Paragraph("Top Attacking Sources", H2))
        atk_rows = [["IP", "Country", "Packets", "Attack Type", "Risk"]]
        for a in data["top_attackers"][:15]:
            atk_rows.append([
                a.get("ip", "--"),
                a.get("country", "--"),
                str(a.get("packet_count", 0)),
                a.get("attack_type", "--"),
                f"{a.get('risk_score', 0)} {a.get('risk_level', '')}",
            ])
        story.append(_table(atk_rows,
                            [1.8 * inch, 1.2 * inch, 1.0 * inch, 1.8 * inch, 1.4 * inch]))
        story.append(Spacer(1, 10))

    # ── Protocol Distribution ─────────────────────────────────────────────────
    ps = data.get("protocol_stats", {})
    if ps:
        story.append(Paragraph("Protocol Distribution", H2))
        total = max(sum(ps.values()), 1)
        proto_rows = [["Protocol", "Packets", "Share"]]
        for proto, cnt in sorted(ps.items(), key=lambda x: x[1], reverse=True):
            proto_rows.append([proto, str(cnt), f"{cnt / total * 100:.1f}%"])
        story.append(_table(proto_rows, [2.5 * inch, 2.0 * inch, 2.7 * inch]))
        story.append(Spacer(1, 10))

    # ── Web-layer IDS ─────────────────────────────────────────────────────────
    wevents = web_ids.get_events(20)
    if wevents:
        story.append(Paragraph("Web-Layer Attack Events", H2))
        w_rows = [["Time", "IP", "Path", "Attack Type", "Severity"]]
        for ev in wevents:
            w_rows.append([
                ev.get("time", "--"),
                ev.get("ip", "--"),
                (ev.get("path", "--") or "--")[:40],
                ev.get("attack_type", "--"),
                ev.get("severity", "--"),
            ])
        story.append(_table(w_rows,
                            [0.9 * inch, 1.4 * inch, 2.0 * inch, 1.6 * inch, 1.3 * inch]))
        story.append(Spacer(1, 10))

    # ── Honeypot Probe Log ────────────────────────────────────────────────────
    hp_hits = data.get("honeypot_hits", [])
    if hp_hits:
        story.append(Paragraph("Honeypot Probe Log", H2))
        hp_rows = [["Timestamp", "IP Address", "Severity", "Username Tried", "Details"]]
        for h in hp_hits[:30]:
            hp_rows.append([
                (h.get("timestamp") or h.get("time") or "--")[:19],
                h.get("ip", "--"),
                h.get("severity", "--"),
                h.get("username", "—") or "—",
                (h.get("msg") or "")[:60],
            ])
        story.append(_table(hp_rows,
                            [1.4 * inch, 1.3 * inch, 0.9 * inch, 1.2 * inch, 2.4 * inch]))
        story.append(Spacer(1, 10))

    # ── Recommendations ───────────────────────────────────────────────────────
    story.append(Paragraph("Security Recommendations", H2))
    for i, rec in enumerate(_recommendations(data), 1):
        story.append(Paragraph(f"{i}. {rec}", BODY))

    doc.build(story)
    buf.seek(0)
    return buf


# ── Routes ────────────────────────────────────────────────────────────────────

@report_bp.route("/reports")
@login_required
def reports_page():
    if not current_user.can('reports', 'read'):
        abort(403)
    return render_template("reports.html", user=current_user)


@report_bp.route("/api/reports/data")
@login_required
@require_permission('reports', 'read')
def api_report_data():
    """GET /api/reports/data?hours=<n> — JSON report data."""
    try:
        hours = min(int(request.args.get("hours", 24)), 168)
    except (ValueError, TypeError):
        hours = 24
    data = _gather(hours)
    data["recommendations"] = _recommendations(data)
    log.info("report", f"JSON report generated", {"hours": hours, "user": current_user.username})
    return jsonify(data)


@report_bp.route("/api/reports/pdf")
@login_required
@require_permission('reports', 'read')
def api_report_pdf():
    """GET /api/reports/pdf?hours=<n> — Download PDF security report."""
    if not _PDF_OK:
        return jsonify({
            "error": "PDF generation unavailable. Install: pip install reportlab"
        }), 503

    try:
        hours = min(int(request.args.get("hours", 24)), 168)
    except (ValueError, TypeError):
        hours = 24

    data = _gather(hours)
    pdf  = _make_pdf(data)
    fname = f"soc_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"
    log.info("report", f"PDF report generated", {"hours": hours, "user": current_user.username})
    return send_file(pdf, mimetype="application/pdf",
                     as_attachment=True, download_name=fname)


@report_bp.route("/api/reports/web-ids")
@login_required
@require_permission('reports', 'read')
def api_web_ids():
    """GET /api/reports/web-ids — Web-layer attack events and statistics."""
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except (ValueError, TypeError):
        limit = 100
    return jsonify({
        "events": web_ids.get_events(limit),
        "stats":  web_ids.get_stats(),
    })


@report_bp.route("/api/reports/risk")
@login_required
@require_permission('reports', 'read')
def api_risk_scores():
    """GET /api/reports/risk — IP reputation scores and risk level distribution."""
    reputations = risk_scoring.get_all_reputations()
    levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    scored = []
    for a in sniffer.top_attackers.values():
        rs = risk_scoring.score_incident(a)
        levels[rs["level"]] = levels.get(rs["level"], 0) + 1
        scored.append({
            "ip":         a.get("ip", "--"),
            "country":    a.get("country", "--"),
            "risk_score": rs["score"],
            "risk_level": rs["level"],
            "attack_type":a.get("attack_type", "--"),
        })
    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    return jsonify({
        "risk_scores":    scored[:50],
        "level_dist":     levels,
        "ip_reputations": reputations[:20],
    })
