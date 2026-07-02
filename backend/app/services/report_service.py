# backend/app/services/report_service.py
#
# Service de génération de rapports de sécurité hebdomadaires.
# Sources de données :
#   - Elasticsearch : logs bruts (volume, criticité, type, top IPs)
#   - SQL           : alertes, audit logs, scores UEBA
# Sortie :
#   - dict de données aggrégées (JSON summary)
#   - bytes PDF généré par reportlab

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone, timedelta
from io import BytesIO

from elasticsearch import AsyncElasticsearch
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.ueba_risk_score import UEBARiskScore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Agrégation des données
# ---------------------------------------------------------------------------

async def aggregate_report_data(
    db: AsyncSession,
    es: AsyncElasticsearch,
    days: int | None = None,
) -> dict:
    """
    Agrège toutes les données nécessaires au rapport sur la période `days` jours.
    Retourne un dict prêt à être consommé par le générateur PDF.
    """
    period = days or settings.reports_default_days
    since = datetime.now(timezone.utc) - timedelta(days=period)
    since_str = since.isoformat()

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_days": period,
        "period_start": since.strftime("%d/%m/%Y"),
        "period_end": datetime.now(timezone.utc).strftime("%d/%m/%Y"),
        "logs": await _aggregate_logs(es, since_str),
        "alerts": await _aggregate_alerts(db, since),
        "audit": await _aggregate_audit(db, since),
        "ueba": await _aggregate_ueba(db, since),
    }
    return report


async def _aggregate_logs(es: AsyncElasticsearch, since_str: str) -> dict:
    """Volume, répartition criticité, répartition type, top IPs depuis ES."""
    try:
        resp = await es.search(
            index=settings.es_logs_index_name,
            body={
                "query": {
                    "bool": {
                        "should": [
                            {"range": {"received_at": {"gte": since_str}}},
                            {"range": {"timestamp":   {"gte": since_str}}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "size": 10000,
                "_source": ["severity", "log_type", "source_ip"],
            },
        )
        hits = resp.get("hits", {}).get("hits", [])
    except Exception as exc:
        logger.warning("[Report] Impossible de lire ES: %s", exc)
        hits = []

    total = len(hits)
    severity_counter: Counter = Counter()
    log_type_counter: Counter = Counter()
    ip_counter: Counter = Counter()

    for hit in hits:
        src = hit.get("_source", {})
        sev = str(src.get("severity") or "unknown").lower()
        lt = str(src.get("log_type") or "unknown").lower()
        ip = str(src.get("source_ip") or "")
        severity_counter[sev] += 1
        log_type_counter[lt] += 1
        if ip:
            ip_counter[ip] += 1

    return {
        "total": total,
        "by_severity": dict(severity_counter.most_common()),
        "by_type": dict(log_type_counter.most_common(10)),
        "top_source_ips": dict(ip_counter.most_common(10)),
    }


async def _aggregate_alerts(db: AsyncSession, since: datetime) -> dict:
    """Alertes SQL : total, par sévérité, par statut, top règles, alertes critiques."""
    result = await db.execute(
        select(Alert).where(Alert.detected_at >= since).order_by(Alert.detected_at.desc())
    )
    alerts = result.scalars().all()

    total = len(alerts)
    severity_counter: Counter = Counter()
    status_counter: Counter = Counter()
    rule_counter: Counter = Counter()
    critical_list = []

    for a in alerts:
        severity_counter[a.severity] += 1
        status_counter[a.status] += 1
        rule_counter[a.rule_name] += 1
        if a.severity in ("CRITICAL", "HIGH"):
            critical_list.append({
                "id": a.id,
                "rule": a.rule_name,
                "severity": a.severity,
                "status": a.status,
                "detected_at": a.detected_at.strftime("%d/%m/%Y %H:%M") if a.detected_at else "",
                "source_ip": a.source_ip or "",
                "host": a.host or "",
            })

    return {
        "total": total,
        "by_severity": dict(severity_counter),
        "by_status": dict(status_counter),
        "top_rules": dict(rule_counter.most_common(5)),
        "critical_and_high": critical_list[:20],
    }


async def _aggregate_audit(db: AsyncSession, since: datetime) -> dict:
    """Audit SQL : total actions, par type d'action, par résultat."""
    result = await db.execute(
        select(AuditLog).where(AuditLog.timestamp >= since)
    )
    entries = result.scalars().all()

    action_counter: Counter = Counter()
    result_counter: Counter = Counter()
    for e in entries:
        action_counter[e.action] += 1
        result_counter[e.result] += 1

    return {
        "total": len(entries),
        "by_action": dict(action_counter.most_common(10)),
        "by_result": dict(result_counter),
    }


async def _aggregate_ueba(db: AsyncSession, since: datetime) -> dict:
    """Scores UEBA SQL : entités à risque élevé/critique."""
    result = await db.execute(
        select(UEBARiskScore)
        .where(UEBARiskScore.computed_at >= since)
        .where(UEBARiskScore.risk_level.in_(["high", "critical"]))
        .order_by(UEBARiskScore.score.desc())
        .limit(10)
    )
    rows = result.scalars().all()
    return {
        "high_risk_entities": [
            {
                "entity": f"{r.entity_type}/{r.entity_id}",
                "score": r.score,
                "level": r.risk_level,
                "anomalies": r.anomaly_count,
            }
            for r in rows
        ]
    }


# ---------------------------------------------------------------------------
# Génération PDF
# ---------------------------------------------------------------------------

def generate_pdf_report(data: dict) -> bytes:
    """
    Génère un rapport PDF professionnel à partir des données agrégées.
    Retourne les bytes du PDF.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SIEMTitle",
        parent=styles["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=6,
    )
    h2_style = ParagraphStyle(
        "SIEMH2",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#16213e"),
        spaceBefore=14,
        spaceAfter=4,
    )
    body_style = styles["Normal"]
    body_style.fontSize = 9

    elements = []

    # ── En-tête ───────────────────────────────────────────
    elements.append(Paragraph("Smart SIEM — Rapport de Sécurité Hebdomadaire", title_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#e94560")))
    elements.append(Spacer(1, 0.3 * cm))

    meta = [
        ["Période couverte", f"{data['period_start']} → {data['period_end']}"],
        ["Durée", f"{data['period_days']} jours"],
        ["Rapport généré le", _fmt_dt(data['generated_at'])],
    ]
    elements.append(_simple_table(meta, col_widths=[5 * cm, 12 * cm]))
    elements.append(Spacer(1, 0.5 * cm))

    # ── Section 1 : Logs ──────────────────────────────────
    logs = data["logs"]
    elements.append(Paragraph("1. Volume de logs ingérés", h2_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    elements.append(Spacer(1, 0.2 * cm))

    kpi_data = [["Métrique", "Valeur"]]
    kpi_data.append(["Total de logs reçus", str(logs["total"])])
    for sev, cnt in sorted(logs["by_severity"].items()):
        kpi_data.append([f"  • {sev}", str(cnt)])
    elements.append(_data_table(kpi_data))
    elements.append(Spacer(1, 0.3 * cm))

    if logs["by_type"]:
        elements.append(Paragraph("Répartition par type de log :", body_style))
        type_data = [["Type", "Nombre"]] + [[k, str(v)] for k, v in logs["by_type"].items()]
        elements.append(_data_table(type_data))
        elements.append(Spacer(1, 0.3 * cm))

    if logs["top_source_ips"]:
        elements.append(Paragraph("Top 10 IPs sources :", body_style))
        ip_data = [["IP Source", "Occurrences"]] + [[k, str(v)] for k, v in logs["top_source_ips"].items()]
        elements.append(_data_table(ip_data))

    elements.append(Spacer(1, 0.4 * cm))

    # ── Section 2 : Alertes ───────────────────────────────
    alerts = data["alerts"]
    elements.append(Paragraph("2. Alertes de sécurité", h2_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    elements.append(Spacer(1, 0.2 * cm))

    alert_kpi = [["Métrique", "Valeur"], ["Total d'alertes", str(alerts["total"])]]
    for sev, cnt in alerts["by_severity"].items():
        alert_kpi.append([f"  • {sev}", str(cnt)])
    for st, cnt in alerts["by_status"].items():
        alert_kpi.append([f"  Statut {st}", str(cnt)])
    elements.append(_data_table(alert_kpi))
    elements.append(Spacer(1, 0.3 * cm))

    if alerts["critical_and_high"]:
        elements.append(Paragraph("Alertes HIGH et CRITICAL :", body_style))
        crit_data = [["Date", "Règle", "Sévérité", "Statut", "Source IP"]]
        for a in alerts["critical_and_high"]:
            crit_data.append([
                a["detected_at"], a["rule"][:30], a["severity"], a["status"], a["source_ip"] or a["host"]
            ])
        elements.append(_data_table(crit_data, col_widths=[3.5*cm, 6*cm, 2.2*cm, 2.2*cm, 3.1*cm]))

    elements.append(Spacer(1, 0.4 * cm))

    # ── Section 3 : Audit ─────────────────────────────────
    audit = data["audit"]
    elements.append(Paragraph("3. Traçabilité et audit", h2_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    elements.append(Spacer(1, 0.2 * cm))

    audit_kpi = [["Métrique", "Valeur"], ["Total d'actions auditées", str(audit["total"])]]
    for res, cnt in audit["by_result"].items():
        audit_kpi.append([f"  Résultat {res}", str(cnt)])
    elements.append(_data_table(audit_kpi))

    if audit["by_action"]:
        elements.append(Spacer(1, 0.2 * cm))
        elements.append(Paragraph("Top actions auditées :", body_style))
        act_data = [["Action", "Occurrences"]] + [[k, str(v)] for k, v in audit["by_action"].items()]
        elements.append(_data_table(act_data))

    elements.append(Spacer(1, 0.4 * cm))

    # ── Section 4 : UEBA ──────────────────────────────────
    ueba = data["ueba"]
    elements.append(Paragraph("4. Analyse comportementale (UEBA)", h2_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    elements.append(Spacer(1, 0.2 * cm))

    if ueba["high_risk_entities"]:
        ueba_data = [["Entité", "Score", "Niveau", "Anomalies"]]
        for e in ueba["high_risk_entities"]:
            ueba_data.append([e["entity"], str(e["score"]), e["level"].upper(), str(e["anomalies"])])
        elements.append(_data_table(ueba_data))
    else:
        elements.append(Paragraph("Aucune entité à risque élevé détectée sur la période.", body_style))

    elements.append(Spacer(1, 0.5 * cm))

    # ── Section 5 : Résumé opérationnel ──────────────────
    elements.append(Paragraph("5. Résumé opérationnel", h2_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    elements.append(Spacer(1, 0.2 * cm))

    total_critical = alerts["by_severity"].get("CRITICAL", 0)
    total_high = alerts["by_severity"].get("HIGH", 0)
    open_alerts = alerts["by_status"].get("open", 0)
    ueba_count = len(ueba["high_risk_entities"])

    if total_critical > 0 or ueba_count > 0:
        level_text = "ATTENTION REQUISE"
        level_color = colors.HexColor("#e94560")
    elif total_high > 5 or open_alerts > 10:
        level_text = "SURVEILLANCE ACCRUE"
        level_color = colors.HexColor("#f5a623")
    else:
        level_text = "SITUATION NOMINALE"
        level_color = colors.HexColor("#2ecc71")

    summary_lines = [
        f"<b>Niveau de risque global :</b> {level_text}",
        f"Logs analysés : <b>{logs['total']}</b> sur {data['period_days']} jours.",
        f"Alertes déclenchées : <b>{alerts['total']}</b> dont <b>{total_critical}</b> CRITICAL et <b>{total_high}</b> HIGH.",
        f"Alertes encore ouvertes : <b>{open_alerts}</b>.",
        f"Entités à risque UEBA : <b>{ueba_count}</b>.",
    ]
    for line in summary_lines:
        elements.append(Paragraph(line, body_style))
        elements.append(Spacer(1, 0.15 * cm))

    elements.append(Spacer(1, 0.5 * cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    elements.append(Paragraph(
        f"<i>Rapport généré automatiquement par Smart SIEM — {_fmt_dt(data['generated_at'])}</i>",
        ParagraphStyle("footer", parent=styles["Normal"], fontSize=7, textColor=colors.grey)
    ))

    doc.build(elements)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Helpers PDF
# ---------------------------------------------------------------------------

def _simple_table(data: list[list], col_widths: list | None = None) -> Table:
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#16213e")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _data_table(data: list[list], col_widths: list | None = None) -> Table:
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ])
    t.setStyle(style)
    return t


def _fmt_dt(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y à %H:%M UTC")
    except Exception:
        return iso_str


def _color_hex(color) -> str:
    """Extrait le hex sans '#' d'un objet reportlab color."""
    try:
        return color.hexval()[1:]
    except Exception:
        return "000000"
