"""
Générateur de rapports PDF — Smart SIEM Module DATA, Semaine 3.

Importable par le Backend :
    from app.reports.pdf_generator import generate_pdf_report
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(_BASE_DIR / ".env")
sys.path.insert(0, str(_BASE_DIR))

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.db.aggregations import (
    count_by_log_type,
    count_by_severity,
    top_source_ips,
)
from app.db.elasticsearch_client import get_client
from app.db.search import get_timeline, search_logs

_INDEX      = os.getenv("ES_INDEX", "logs-siem")
_ALERTS_IDX = os.getenv("ALERTS_INDEX", "siem-alerts")
_RET_DAYS   = int(os.getenv("RETENTION_DAYS", "30"))
_REPORTS_DIR = Path(os.getenv("REPORTS_DIR", str(_BASE_DIR / "reports")))

# ── Couleurs maison ──────────────────────────────────────────────────────────
_NAVY   = colors.HexColor("#0d2035")
_BLUE   = colors.HexColor("#1f6feb")
_STEEL  = colors.HexColor("#21262d")
_GREY   = colors.HexColor("#8b949e")
_WHITE  = colors.white
_RED    = colors.HexColor("#ff7b7b")
_ORANGE = colors.HexColor("#ffa657")
_GREEN  = colors.HexColor("#56d364")
_LIGHT  = colors.HexColor("#f0f6fc")


# ── Collecte des données ─────────────────────────────────────────────────────

def _fetch_alerts(date_from, date_to):
    """Interroge l'index siem-alerts et retourne (total, {statut: count})."""
    try:
        client = get_client()
        rc = {}
        if date_from:
            rc["gte"] = date_from
        if date_to:
            rc["lte"] = date_to
        query = (
            {"bool": {"filter": [{"range": {"timestamp": rc}}]}}
            if rc
            else {"match_all": {}}
        )
        resp = client.search(
            index=_ALERTS_IDX,
            query=query,
            size=0,
            aggs={"by_status": {"terms": {"field": "status", "size": 20}}},
        )
        total = resp["hits"]["total"]["value"]
        by_status = {
            b["key"]: b["doc_count"]
            for b in resp["aggregations"]["by_status"]["buckets"]
        }
        return total, by_status
    except Exception:
        return 0, {}


def _fetch_top_hosts(n=5, date_from=None, date_to=None):
    """Agrégation terms sur le champ host, tri par doc_count décroissant."""
    try:
        client = get_client()
        rc = {}
        if date_from:
            rc["gte"] = date_from
        if date_to:
            rc["lte"] = date_to
        query = (
            {"bool": {"filter": [{"range": {"timestamp": rc}}]}}
            if rc
            else {"match_all": {}}
        )
        resp = client.search(
            index=_INDEX,
            query=query,
            size=0,
            aggs={
                "top_hosts": {
                    "terms": {
                        "field": "host",
                        "size": n,
                        "order": {"_count": "desc"},
                    }
                }
            },
        )
        return [
            {"host": b["key"], "count": b["doc_count"]}
            for b in resp["aggregations"]["top_hosts"]["buckets"]
        ]
    except Exception:
        return []


def _fetch_report_data(date_from, date_to):
    """Collecte toutes les données nécessaires au rapport depuis ES."""
    severity_counts  = count_by_severity(date_from, date_to)
    type_counts      = count_by_log_type(date_from, date_to)
    total_logs       = sum(severity_counts.values())
    top_ips          = top_source_ips(n=10, date_from=date_from, date_to=date_to)
    top_hosts        = _fetch_top_hosts(n=5, date_from=date_from, date_to=date_to)
    critical_logs    = search_logs(
        severity="critical",
        date_from=date_from,
        date_to=date_to,
        page=1,
        page_size=20,
    )["results"]
    timeline_events  = get_timeline(
        date_from=date_from,
        date_to=date_to,
        log_types=["auth", "réseau", "système", "application"],
        max_events=200,
    )["events"]
    # Filtre les critiques pour la timeline des incidents
    critical_events  = [e for e in timeline_events if e.get("severity") == "critical"]
    alert_total, alert_by_status = _fetch_alerts(date_from, date_to)

    return {
        "severity_counts":  severity_counts,
        "type_counts":      type_counts,
        "total_logs":       total_logs,
        "top_ips":          top_ips,
        "top_hosts":        top_hosts,
        "critical_logs":    critical_logs,
        "critical_events":  critical_events,
        "alert_total":      alert_total,
        "alert_by_status":  alert_by_status,
    }


# ── Helpers ReportLab ────────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()
    defs = {
        "Title":     ParagraphStyle("Title",     fontSize=26, textColor=_LIGHT,  alignment=TA_CENTER, spaceAfter=8,  fontName="Helvetica-Bold"),
        "Subtitle":  ParagraphStyle("Subtitle",  fontSize=13, textColor=_GREY,   alignment=TA_CENTER, spaceAfter=4,  fontName="Helvetica"),
        "H1":        ParagraphStyle("H1",        fontSize=14, textColor=_BLUE,   spaceBefore=18, spaceAfter=6, fontName="Helvetica-Bold"),
        "H2":        ParagraphStyle("H2",        fontSize=11, textColor=_LIGHT,  spaceBefore=10, spaceAfter=4, fontName="Helvetica-Bold"),
        "Body":      ParagraphStyle("Body",      fontSize=9,  textColor=_LIGHT,  spaceAfter=3,  fontName="Helvetica", leading=13),
        "Small":     ParagraphStyle("Small",     fontSize=7,  textColor=_GREY,   spaceAfter=2,  fontName="Helvetica"),
        "Hash":      ParagraphStyle("Hash",      fontSize=7,  textColor=_GREY,   alignment=TA_CENTER, fontName="Courier"),
        "CoverHash": ParagraphStyle("CoverHash", fontSize=8,  textColor=_GREY,   alignment=TA_CENTER, spaceAfter=0, fontName="Courier"),
    }
    return defs


_TABLE_HEADER = TableStyle([
    ("BACKGROUND",  (0, 0), (-1, 0), _NAVY),
    ("TEXTCOLOR",   (0, 0), (-1, 0), _BLUE),
    ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE",    (0, 0), (-1, 0), 8),
    ("FONTSIZE",    (0, 1), (-1, -1), 8),
    ("FONTNAME",    (0, 1), (-1, -1), "Helvetica"),
    ("TEXTCOLOR",   (0, 1), (-1, -1), _LIGHT),
    ("BACKGROUND",  (0, 1), (-1, -1), _STEEL),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_STEEL, colors.HexColor("#161b22")]),
    ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#30363d")),
    ("TOPPADDING",  (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ("RIGHTPADDING",(0, 0), (-1, -1), 6),
    ("VALIGN",      (0, 0), (-1, -1), "TOP"),
])


def _table(data, col_widths=None):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(_TABLE_HEADER)
    return t


def _hr():
    return HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d"), spaceAfter=6, spaceBefore=6)


def _fmt_ts(ts):
    if not ts:
        return "—"
    try:
        return ts.replace("T", " ").replace("Z", " UTC")
    except Exception:
        return str(ts)


# ── Construction des sections ────────────────────────────────────────────────

def _cover_page(s, date_from, date_to, generated_at, content_hash):
    story = []
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("Smart SIEM", s["Title"]))
    story.append(Paragraph("Rapport de sécurité", s["Title"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(_hr())
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(f"Période couverte : {_fmt_ts(date_from)}  →  {_fmt_ts(date_to)}", s["Subtitle"]))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(f"Généré le : {generated_at}", s["Subtitle"]))
    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph("Rapport produit automatiquement par le module DATA — Smart SIEM.", s["Body"]))
    story.append(Paragraph("Ce document est confidentiel. Ne pas diffuser sans autorisation.", s["Small"]))
    story.append(Spacer(1, 3 * cm))
    story.append(_hr())
    story.append(Paragraph("Hash SHA-256 du contenu de ce rapport :", s["Small"]))
    story.append(Paragraph(content_hash, s["CoverHash"]))
    story.append(PageBreak())
    return story


def _section_executive_summary(s, data):
    story = []
    story.append(Paragraph("1. Résumé exécutif", s["H1"]))
    story.append(_hr())

    sev   = data["severity_counts"]
    types = data["type_counts"]
    total = data["total_logs"]
    alerts_total  = data["alert_total"]
    alerts_status = data["alert_by_status"]

    story.append(Paragraph(f"Total de logs collectés sur la période : <b>{total:,}</b>", s["Body"]))
    story.append(Spacer(1, 0.3 * cm))

    # Tableau sévérités
    story.append(Paragraph("Répartition par sévérité", s["H2"]))
    sev_data = [["Sévérité", "Nombre", "% du total"]]
    for key, label in [("critical", "Critique"), ("warning", "Avertissement"), ("info", "Info")]:
        n = sev.get(key, 0)
        pct = f"{n / total * 100:.1f} %" if total else "—"
        sev_data.append([label, f"{n:,}", pct])
    sev_data.append(["TOTAL", f"{total:,}", "100 %"])
    story.append(_table(sev_data, col_widths=[8 * cm, 4 * cm, 4 * cm]))
    story.append(Spacer(1, 0.4 * cm))

    # Tableau types
    story.append(Paragraph("Répartition par type de log", s["H2"]))
    type_data = [["Type", "Nombre", "% du total"]]
    for key in ["auth", "réseau", "système", "application"]:
        n = types.get(key, 0)
        pct = f"{n / total * 100:.1f} %" if total else "—"
        type_data.append([key.capitalize(), f"{n:,}", pct])
    story.append(_table(type_data, col_widths=[8 * cm, 4 * cm, 4 * cm]))
    story.append(Spacer(1, 0.4 * cm))

    # Alertes
    story.append(Paragraph("Alertes générées", s["H2"]))
    story.append(Paragraph(f"Nombre total d'alertes : <b>{alerts_total:,}</b>", s["Body"]))
    if alerts_by_status := alerts_status:
        alt_data = [["Statut", "Nombre"]]
        for status, cnt in sorted(alerts_by_status.items()):
            alt_data.append([status, f"{cnt:,}"])
        story.append(_table(alt_data, col_widths=[8 * cm, 4 * cm]))
    else:
        story.append(Paragraph("Aucune donnée d'alerte disponible pour la période.", s["Small"]))

    story.append(PageBreak())
    return story


def _section_top_threats(s, data):
    story = []
    story.append(Paragraph("2. Top menaces", s["H1"]))
    story.append(_hr())

    # Top 10 IPs
    story.append(Paragraph("Top 10 IP sources les plus actives", s["H2"]))
    if data["top_ips"]:
        ip_data = [["#", "Adresse IP", "Nombre de logs"]]
        for i, entry in enumerate(data["top_ips"], 1):
            ip_data.append([str(i), entry["ip"], f"{entry['count']:,}"])
        story.append(_table(ip_data, col_widths=[1 * cm, 9 * cm, 6 * cm]))
    else:
        story.append(Paragraph("Aucune IP source disponible.", s["Small"]))
    story.append(Spacer(1, 0.4 * cm))

    # Top 5 hôtes
    story.append(Paragraph("Top 5 hôtes les plus touchés", s["H2"]))
    if data["top_hosts"]:
        host_data = [["#", "Hôte", "Nombre de logs"]]
        for i, entry in enumerate(data["top_hosts"], 1):
            host_data.append([str(i), entry["host"], f"{entry['count']:,}"])
        story.append(_table(host_data, col_widths=[1 * cm, 9 * cm, 6 * cm]))
    else:
        story.append(Paragraph("Aucune donnée d'hôte disponible.", s["Small"]))
    story.append(Spacer(1, 0.4 * cm))

    # 20 logs critiques récents
    story.append(Paragraph("Logs critiques les plus récents (max 20)", s["H2"]))
    if data["critical_logs"]:
        crit_data = [["Horodatage", "IP source", "Hôte", "Message"]]
        for log in data["critical_logs"][:20]:
            msg = (log.get("raw_message") or "")[:80]
            if len(log.get("raw_message") or "") > 80:
                msg += "…"
            crit_data.append([
                _fmt_ts(log.get("timestamp")),
                log.get("source_ip", "—"),
                log.get("host", "—"),
                msg,
            ])
        story.append(_table(crit_data, col_widths=[4 * cm, 3 * cm, 3 * cm, 6 * cm]))
    else:
        story.append(Paragraph("Aucun log critique sur la période.", s["Small"]))

    story.append(PageBreak())
    return story


def _section_timeline(s, data):
    story = []
    story.append(Paragraph("3. Timeline des incidents critiques", s["H1"]))
    story.append(_hr())
    story.append(Paragraph(
        "Événements critiques triés chronologiquement (du plus ancien au plus récent).",
        s["Body"],
    ))
    story.append(Spacer(1, 0.2 * cm))

    events = data["critical_events"]
    if events:
        tl_data = [["Horodatage", "IP source", "Hôte", "Message"]]
        for ev in events:
            msg = (ev.get("raw_message") or "")[:90]
            if len(ev.get("raw_message") or "") > 90:
                msg += "…"
            tl_data.append([
                _fmt_ts(ev.get("timestamp")),
                ev.get("source_ip", "—"),
                ev.get("host", "—"),
                msg,
            ])
        story.append(_table(tl_data, col_widths=[4 * cm, 3 * cm, 3 * cm, 6 * cm]))
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph(f"{len(events)} événement(s) affiché(s).", s["Small"]))
    else:
        story.append(Paragraph("Aucun événement critique sur la période.", s["Small"]))

    story.append(PageBreak())
    return story


def _section_compliance(s, date_from, date_to, content_hash):
    story = []
    story.append(Paragraph("4. Conformité", s["H1"]))
    story.append(_hr())

    story.append(Paragraph("Politique de rétention", s["H2"]))
    story.append(Paragraph(
        f"Durée de conservation configurée : <b>{_RET_DAYS} jours</b>.", s["Body"]
    ))
    story.append(Paragraph(
        "Les logs plus anciens que cette durée sont supprimés automatiquement "
        "par la politique ILM Elasticsearch.", s["Body"]
    ))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("Période couverte par ce rapport", s["H2"]))
    story.append(Paragraph(f"Début : <b>{_fmt_ts(date_from)}</b>", s["Body"]))
    story.append(Paragraph(f"Fin :   <b>{_fmt_ts(date_to)}</b>", s["Body"]))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("Intégrité des données", s["H2"]))
    story.append(Paragraph(
        "Le hash SHA-256 ci-dessous est calculé sur l'ensemble des données "
        "collectées depuis Elasticsearch pour la période de ce rapport.",
        s["Body"],
    ))
    story.append(Paragraph(f"Hash SHA-256 du contenu : {content_hash}", s["Hash"]))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("Mentions RGPD", s["H2"]))
    story.append(Paragraph(
        f"Conformément au RGPD (Art. 5 §1 e), les données à caractère personnel "
        f"présentes dans les logs sont conservées pour une durée maximale de "
        f"<b>{_RET_DAYS} jours</b> à compter de leur collecte. "
        "Au-delà de cette période, elles sont automatiquement purgées de l'index "
        "Elasticsearch via la politique ILM et, si nécessaire, manuellement via "
        "la fonction <i>purge_expired_logs()</i> du module de conformité.",
        s["Body"],
    ))
    story.append(Paragraph(
        "Les données ne sont pas transférées hors de l'Union Européenne. "
        "Elles sont accessibles uniquement aux personnels habilités via le "
        "contrôle d'accès basé sur les rôles (RBAC).",
        s["Body"],
    ))
    return story


# ── Point d'entrée public ────────────────────────────────────────────────────

def generate_pdf_report(date_from, date_to, output_path=None):
    """
    Génère un rapport PDF de sécurité Smart SIEM pour la période donnée.

    Le rapport contient dans l'ordre :
    1. Page de couverture (titre, période, horodatage, hash SHA-256 du contenu)
    2. Résumé exécutif (totaux logs, répartitions sévérité/type, alertes)
    3. Top menaces (Top 10 IPs, Top 5 hôtes, 20 logs critiques récents)
    4. Timeline des incidents critiques (ordre chronologique)
    5. Conformité (rétention configurée, hash, mentions RGPD)

    Les données sont issues de search_logs(), get_timeline(),
    count_by_severity(), count_by_log_type(), top_source_ips().

    Paramètres
    ----------
    date_from   : str — Début de période (ISO 8601, ex: "2026-06-01T00:00:00Z").
    date_to     : str — Fin de période   (ISO 8601, ex: "2026-06-07T23:59:59Z").
    output_path : str | Path, optionnel — Chemin de sortie.
                  Par défaut : reports/siem_report_{date_from}_{date_to}.pdf

    Retour
    ------
    dict :
        {
            "path"         : str — chemin absolu du PDF généré,
            "sha256"       : str — hash SHA-256 du fichier PDF,
            "generated_at" : str — horodatage ISO 8601 de génération
        }

    Exemple
    -------
    >>> result = generate_pdf_report("2026-06-01T00:00:00Z", "2026-06-07T23:59:59Z")
    >>> print(result["path"])
    /…/reports/siem_report_2026-06-01T00:00:00Z_2026-06-07T23:59:59Z.pdf
    """
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Résolution du chemin de sortie
    if output_path is None:
        safe_from = date_from.replace(":", "-")
        safe_to   = date_to.replace(":", "-")
        _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        output_path = _REPORTS_DIR / f"siem_report_{safe_from}_{safe_to}.pdf"
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Collecte des données
    data = _fetch_report_data(date_from, date_to)

    # Hash SHA-256 du contenu (sérialisé, reproductible)
    content_hash = hashlib.sha256(
        json.dumps(data, sort_keys=True, default=str, ensure_ascii=False).encode()
    ).hexdigest()

    # Construction du PDF
    s = _styles()
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="Smart SIEM — Rapport de sécurité",
        author="Smart SIEM DATA module",
    )

    story = []
    story += _cover_page(s, date_from, date_to, generated_at, content_hash)
    story += _section_executive_summary(s, data)
    story += _section_top_threats(s, data)
    story += _section_timeline(s, data)
    story += _section_compliance(s, date_from, date_to, content_hash)

    doc.build(story)

    # Hash SHA-256 du fichier PDF généré
    file_hash = hashlib.sha256(output_path.read_bytes()).hexdigest()

    return {
        "path":         str(output_path.resolve()),
        "sha256":       file_hash,
        "generated_at": generated_at,
    }
