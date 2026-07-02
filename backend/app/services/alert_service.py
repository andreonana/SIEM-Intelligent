# backend/app/services/alert_service.py
#
# Couche service pour la gestion des alertes de sécurité.
# V3 : déduplication sur fenêtre 5 minutes (spec), confidence_score, soar_status.

import json
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.rule import CorrelationRule


# ---------------------------------------------------------------------------
# Déduplication — fenêtre 5 minutes (V3 spec)
# ---------------------------------------------------------------------------

DEDUPE_WINDOW_MINUTES = 5  # V3 exige 5 minutes


async def check_dedupe(db: AsyncSession, dedupe_key: str, minutes: int = DEDUPE_WINDOW_MINUTES) -> bool:
    """
    Retourne True si une alerte avec cette clé existe dans les `minutes` dernières minutes.
    Fenêtre : 5 minutes par défaut (spec V3).
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    result = await db.execute(
        select(Alert).where(
            Alert.dedupe_key == dedupe_key,
            Alert.detected_at >= since,
        ).limit(1)
    )
    return result.scalar_one_or_none() is not None


def _dedupe_key_5min(rule_id: str, source_ip: str) -> str:
    """
    Clé de déduplication sur fenêtre 5 minutes.
    Basée sur rule_id + source_ip + tranche de 5 minutes UTC.
    """
    now = datetime.now(timezone.utc)
    # Tranche de 5 minutes : arrondit à la tranche inférieure
    slot = (now.hour * 60 + now.minute) // 5
    day = now.strftime("%Y-%m-%d")
    return f"{rule_id}:{source_ip or 'any'}:{day}:slot{slot}"


# ---------------------------------------------------------------------------
# Création d'alerte
# ---------------------------------------------------------------------------

async def create_alert(
    db: AsyncSession,
    rule_id: str,
    rule_name: str,
    severity: str,
    description: str,
    source_ip: str | None = None,
    host: str | None = None,
    related_log_ids: list | None = None,
    mitre_tactic: str | None = None,
    mitre_technique: str | None = None,
    dedupe_key: str | None = None,
    confidence_score: float = 80.0,
    soar_status: str = "manual",
) -> Alert:
    alert = Alert(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        description=description,
        status="open",
        source_ip=source_ip,
        host=host,
        related_log_ids=json.dumps(related_log_ids) if related_log_ids else None,
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_technique,
        dedupe_key=dedupe_key,
        confidence_score=confidence_score,
        soar_status=soar_status,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert


async def get_alert(db: AsyncSession, alert_id: int) -> Alert | None:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    return result.scalar_one_or_none()


async def list_alerts(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    severity_filter: str | None = None,
    status_filter: str | None = None,
) -> dict:
    query = select(Alert).order_by(desc(Alert.detected_at))
    if severity_filter:
        query = query.where(Alert.severity == severity_filter)
    if status_filter:
        query = query.where(Alert.status == status_filter)

    offset = (page - 1) * page_size
    result = await db.execute(query.offset(offset).limit(page_size))
    alerts = result.scalars().all()

    count_q = select(func.count()).select_from(Alert)
    if severity_filter:
        count_q = count_q.where(Alert.severity == severity_filter)
    if status_filter:
        count_q = count_q.where(Alert.status == status_filter)
    total = (await db.execute(count_q)).scalar_one()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "alerts": [a.to_dict() for a in alerts],
    }


async def acknowledge_alert(db: AsyncSession, alert_id: int, username: str) -> Alert:
    alert = await get_alert(db, alert_id)
    if alert is None:
        raise ValueError(f"Alerte {alert_id} introuvable.")
    alert.acknowledged_by = username
    alert.acknowledged_at = datetime.now(timezone.utc)
    if alert.status == "open":
        alert.status = "in_progress"
    await db.commit()
    await db.refresh(alert)
    return alert


async def resolve_alert(db: AsyncSession, alert_id: int, username: str, note: str | None = None) -> Alert:
    alert = await get_alert(db, alert_id)
    if alert is None:
        raise ValueError(f"Alerte {alert_id} introuvable.")
    alert.status = "resolved"
    alert.resolved_at = datetime.now(timezone.utc)
    alert.resolution_note = note
    if alert.acknowledged_by is None:
        alert.acknowledged_by = username
        alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(alert)
    return alert


async def assign_alert(db: AsyncSession, alert_id: int, username: str) -> Alert:
    alert = await get_alert(db, alert_id)
    if alert is None:
        raise ValueError(f"Alerte {alert_id} introuvable.")
    alert.assigned_to = username
    if alert.status == "open":
        alert.status = "in_progress"
    await db.commit()
    await db.refresh(alert)
    return alert


# ---------------------------------------------------------------------------
# Seed des règles de corrélation au démarrage
# V3 : confidence_score, soar_mode, confirm_delay_seconds
# ---------------------------------------------------------------------------

_DEFAULT_RULES = [
    {
        "rule_id":               "RULE_001",
        "name":                  "Brute Force SSH/Auth",
        "description":           "Détection de tentatives d'authentification répétées en échec (brute force).",
        "rule_type":             "threshold",
        "threshold":             5,
        "window_minutes":        10,
        "severity":              "HIGH",
        "mitre_tactic":          "Credential Access",
        "mitre_technique":       "T1110",
        "soar_action":           "block_ip",
        "confidence_score":      90.0,
        "soar_mode":             "AUTO",
        "confirm_delay_seconds": 60,
    },
    {
        "rule_id":               "RULE_002",
        "name":                  "Connexion hors horaires",
        "description":           "Connexion réussie en dehors des heures ouvrées (avant 6h ou après 22h UTC).",
        "rule_type":             "pattern",
        "threshold":             None,
        "window_minutes":        10,
        "severity":              "WARNING",
        "mitre_tactic":          "Initial Access",
        "mitre_technique":       "T1078",
        "soar_action":           None,
        "confidence_score":      70.0,
        "soar_mode":             "MANUAL",
        "confirm_delay_seconds": 60,
    },
    {
        "rule_id":               "RULE_003",
        "name":                  "Élévation de privilèges / modification de rôle non autorisée",
        "description":           "Détection de commandes sudo, d'élévation de privilèges ou de modifications de rôle.",
        "rule_type":             "pattern",
        "threshold":             None,
        "window_minutes":        10,
        "severity":              "HIGH",
        "mitre_tactic":          "Privilege Escalation",
        "mitre_technique":       "T1548",
        "soar_action":           "escalate_admin",
        "confidence_score":      85.0,
        "soar_mode":             "CONFIRM",
        "confirm_delay_seconds": 60,
    },
    {
        "rule_id":               "RULE_004",
        "name":                  "Communication avec IP suspecte / exfiltration",
        "description":           "Trafic réseau sortant suspect ou même source_ip sur plus de 3 hôtes distincts.",
        "rule_type":             "pattern",
        "threshold":             None,
        "window_minutes":        10,
        "severity":              "CRITICAL",
        "mitre_tactic":          "Exfiltration",
        "mitre_technique":       "T1041",
        "soar_action":           "block_ip",
        "confidence_score":      95.0,
        "soar_mode":             "AUTO",
        "confirm_delay_seconds": 60,
    },
    {
        "rule_id":               "RULE_005",
        "name":                  "Arrêt du service de logs / dissimulation",
        "description":           "Détection d'arrêt ou de désactivation du service de journalisation.",
        "rule_type":             "pattern",
        "threshold":             None,
        "window_minutes":        10,
        "severity":              "CRITICAL",
        "mitre_tactic":          "Defense Evasion",
        "mitre_technique":       "T1562",
        "soar_action":           "escalate_admin",
        "confidence_score":      92.0,
        "soar_mode":             "AUTO",
        "confirm_delay_seconds": 60,
    },
]


async def seed_correlation_rules(db: AsyncSession) -> None:
    """
    Insère les règles de corrélation par défaut si absentes.
    Met à jour les champs V3 (confidence_score, soar_mode) si la règle existe déjà.
    """
    now = datetime.now(timezone.utc)
    for rule_data in _DEFAULT_RULES:
        existing = await db.execute(
            select(CorrelationRule).where(CorrelationRule.rule_id == rule_data["rule_id"])
        )
        rule = existing.scalar_one_or_none()
        if rule is None:
            db.add(CorrelationRule(
                rule_id=rule_data["rule_id"],
                name=rule_data["name"],
                description=rule_data["description"],
                rule_type=rule_data["rule_type"],
                enabled=True,
                threshold=rule_data.get("threshold"),
                window_minutes=rule_data.get("window_minutes", 10),
                severity=rule_data["severity"],
                mitre_tactic=rule_data.get("mitre_tactic"),
                mitre_technique=rule_data.get("mitre_technique"),
                soar_action=rule_data.get("soar_action"),
                confidence_score=rule_data.get("confidence_score", 80.0),
                soar_mode=rule_data.get("soar_mode", "MANUAL"),
                confirm_delay_seconds=rule_data.get("confirm_delay_seconds", 60),
                created_at=now,
                updated_at=now,
            ))
        else:
            # Mise à jour des champs V3 uniquement
            rule.confidence_score = rule_data.get("confidence_score", rule.confidence_score)
            rule.soar_mode = rule_data.get("soar_mode", rule.soar_mode)
            rule.confirm_delay_seconds = rule_data.get("confirm_delay_seconds", rule.confirm_delay_seconds)
    await db.commit()
