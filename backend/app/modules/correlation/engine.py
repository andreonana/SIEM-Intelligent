# backend/app/modules/correlation/engine.py
#
# Moteur de corrélation S3 — analyse les logs ES et crée des alertes SQL.
# V3 :
#   - Confidence score propagé de la règle vers l'alerte
#   - Déduplication sur fenêtre 5 minutes (spec V3)
#   - Auto-déclenchement SOAR selon soar_mode (AUTO/CONFIRM/MANUAL)

import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from elasticsearch import AsyncElasticsearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.rule import CorrelationRule
from app.modules.correlation.rules import HARDCODED_RULES, RULES_BY_ID, Rule
from app.services.alert_service import create_alert, check_dedupe, _dedupe_key_5min
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _message(hit: dict) -> str:
    # Le pipeline de normalisation stocke le contenu du log sous "raw_message"
    # (voir app/modules/normalisation/service.py). "message" n'existe pas dans
    # le mapping Elasticsearch réel — utiliser ce champ ferait échouer
    # silencieusement toute règle basée sur le contenu du message (ex: RULE_001).
    src = hit.get("_source", {})
    return (src.get("raw_message") or src.get("message") or src.get("log", {}).get("message") or "").lower()


def _field(hit: dict, field: str) -> str:
    src = hit.get("_source", {})
    return str(src.get(field) or "").lower()


def _log_type(hit: dict) -> str:
    return _field(hit, "log_type")


def _source_ip(hit: dict) -> str:
    src = hit.get("_source", {})
    return str(src.get("source_ip") or src.get("src_ip") or "")


def _host(hit: dict) -> str:
    src = hit.get("_source", {})
    return str(src.get("host") or src.get("hostname") or "")


def _timestamp_hour(hit: dict) -> int | None:
    src = hit.get("_source", {})
    ts_raw = src.get("@timestamp") or src.get("timestamp")
    if not ts_raw:
        return None
    try:
        dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        return dt.hour
    except Exception:
        return None


async def _fetch_logs(es: AsyncElasticsearch, index: str, window_minutes: int) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    try:
        resp = await es.search(
            index=index,
            body={
                "query": {
                    "bool": {
                        "should": [
                            {"range": {"received_at":  {"gte": since.isoformat()}}},
                            {"range": {"timestamp":    {"gte": since.isoformat()}}},
                            {"range": {"@timestamp":   {"gte": since.isoformat()}}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "size": 10000,
                "_source": True,
            },
        )
        return resp.get("hits", {}).get("hits", [])
    except Exception as exc:
        logger.warning("Impossible de lire ES (%s): %s", index, exc)
        return []


# ---------------------------------------------------------------------------
# Évaluation des règles — chaque handler retourne (n_created, list[Alert])
# ---------------------------------------------------------------------------

async def _eval_rule_001(hits, rule: Rule, db: AsyncSession, confidence: float):
    counts: dict[str, list[str]] = defaultdict(list)
    for hit in hits:
        lt = _log_type(hit)
        msg = _message(hit)
        if lt != "auth" and "auth" not in lt:
            continue
        if not any(k in msg for k in ("failed", "failure", "invalid")):
            continue
        ip = _source_ip(hit)
        counts[ip].append(hit.get("_id", ""))

    alerts = []
    threshold = rule.threshold or 5
    for ip, log_ids in counts.items():
        if len(log_ids) < threshold:
            continue
        dk = _dedupe_key_5min(rule.rule_id, ip)
        if await check_dedupe(db, dk):
            continue
        alert = await create_alert(
            db=db, rule_id=rule.rule_id, rule_name=rule.name,
            severity=rule.severity,
            description=f"Brute force détecté depuis {ip} — {len(log_ids)} tentatives en échec.",
            source_ip=ip, related_log_ids=log_ids[:50],
            mitre_tactic=rule.mitre_tactic, mitre_technique=rule.mitre_technique,
            dedupe_key=dk, confidence_score=confidence,
        )
        alerts.append(alert)
    return alerts


async def _eval_rule_002(hits, rule: Rule, db: AsyncSession, confidence: float):
    alerts = []
    for hit in hits:
        lt = _log_type(hit)
        if lt != "auth" and "auth" not in lt:
            continue
        hour = _timestamp_hour(hit)
        if hour is None:
            continue
        if 6 <= hour < 22:
            continue
        ip = _source_ip(hit)
        dk = _dedupe_key_5min(rule.rule_id, ip)
        if await check_dedupe(db, dk):
            continue
        alert = await create_alert(
            db=db, rule_id=rule.rule_id, rule_name=rule.name,
            severity=rule.severity,
            description=f"Connexion détectée hors horaires (heure UTC: {hour}h) depuis {ip or 'inconnu'}.",
            source_ip=ip or None, host=_host(hit) or None,
            related_log_ids=[hit.get("_id", "")],
            mitre_tactic=rule.mitre_tactic, mitre_technique=rule.mitre_technique,
            dedupe_key=dk, confidence_score=confidence,
        )
        alerts.append(alert)
    return alerts


async def _eval_rule_003(hits, rule: Rule, db: AsyncSession, db_audit_logs, confidence: float):
    alerts = []
    candidates = []

    for hit in hits:
        lt = _log_type(hit)
        msg = _message(hit)
        if lt in ("audit", "system") or any(k in msg for k in ("sudo", "privilege", "role_update", "su ", "setuid", "setgid")):
            candidates.append(("es", _source_ip(hit), _host(hit), hit.get("_id", "")))

    for entry in db_audit_logs:
        action = entry.get("action", "")
        detail = (entry.get("detail") or "").lower()
        if action in ("role_update", "create_user", "disable_user") or "sudo" in detail or "privilege" in detail:
            candidates.append(("sql", "", "", str(entry.get("id", ""))))

    for src, ip, host, log_id in candidates:
        dk = _dedupe_key_5min(rule.rule_id, ip or "sql")
        if await check_dedupe(db, dk):
            continue
        alert = await create_alert(
            db=db, rule_id=rule.rule_id, rule_name=rule.name,
            severity=rule.severity,
            description=f"Tentative d'élévation de privilèges détectée (source: {src}).",
            source_ip=ip or None, host=host or None,
            related_log_ids=[log_id],
            mitre_tactic=rule.mitre_tactic, mitre_technique=rule.mitre_technique,
            dedupe_key=dk, confidence_score=confidence,
        )
        alerts.append(alert)
    return alerts


async def _eval_rule_004(hits, rule: Rule, db: AsyncSession, confidence: float):
    alerts = []

    for hit in hits:
        lt = _log_type(hit)
        msg = _message(hit)
        if lt in ("network", "firewall") and any(k in msg for k in ("outbound", "data transfer", "exfil")):
            ip = _source_ip(hit)
            dk = _dedupe_key_5min(rule.rule_id, ip)
            if await check_dedupe(db, dk):
                continue
            alert = await create_alert(
                db=db, rule_id=rule.rule_id, rule_name=rule.name,
                severity=rule.severity,
                description=f"Trafic réseau sortant suspect détecté depuis {ip or 'inconnu'}.",
                source_ip=ip or None, host=_host(hit) or None,
                related_log_ids=[hit.get("_id", "")],
                mitre_tactic=rule.mitre_tactic, mitre_technique=rule.mitre_technique,
                dedupe_key=dk, confidence_score=confidence,
            )
            alerts.append(alert)

    ip_hosts: dict[str, set[str]] = defaultdict(set)
    for hit in hits:
        ip = _source_ip(hit)
        host = _host(hit)
        if ip and host:
            ip_hosts[ip].add(host)

    for ip, hosts in ip_hosts.items():
        if len(hosts) <= 3:
            continue
        dk = _dedupe_key_5min("RULE_004_MULTI", ip)
        if await check_dedupe(db, dk):
            continue
        alert = await create_alert(
            db=db, rule_id=rule.rule_id, rule_name=rule.name,
            severity=rule.severity,
            description=f"IP {ip} détectée sur {len(hosts)} hôtes distincts (possible mouvement latéral/exfil).",
            source_ip=ip, related_log_ids=[],
            mitre_tactic=rule.mitre_tactic, mitre_technique=rule.mitre_technique,
            dedupe_key=dk, confidence_score=confidence,
        )
        alerts.append(alert)
    return alerts


async def _eval_rule_005(hits, rule: Rule, db: AsyncSession, confidence: float):
    alerts = []
    for hit in hits:
        msg = _message(hit)
        if not any(k in msg for k in ("service stopped", "log rotation", "auditd", "syslog", "logging disabled")):
            continue
        ip = _source_ip(hit)
        host = _host(hit)
        dk = _dedupe_key_5min(rule.rule_id, ip or host or "any")
        if await check_dedupe(db, dk):
            continue
        alert = await create_alert(
            db=db, rule_id=rule.rule_id, rule_name=rule.name,
            severity=rule.severity,
            description=f"Arrêt ou désactivation d'un service de journalisation détecté sur {host or 'hôte inconnu'}.",
            source_ip=ip or None, host=host or None,
            related_log_ids=[hit.get("_id", "")],
            mitre_tactic=rule.mitre_tactic, mitre_technique=rule.mitre_technique,
            dedupe_key=dk, confidence_score=confidence,
        )
        alerts.append(alert)
    return alerts


# ---------------------------------------------------------------------------
# Fonction principale
# ---------------------------------------------------------------------------

async def run_correlation(
    db: AsyncSession,
    es_client: AsyncElasticsearch,
    window_minutes: int = 30,
) -> dict:
    from app.core.config import settings
    from app.modules.soar.dispatcher import dispatch_soar

    # Charger les règles actives depuis DB avec leurs paramètres V3
    db_rules_result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.enabled == True)
    )
    active_rules: dict[str, CorrelationRule] = {r.rule_id: r for r in db_rules_result.scalars().all()}

    hits = await _fetch_logs(es_client, settings.es_logs_index_name, window_minutes)

    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    audit_result = await db.execute(
        select(AuditLog).where(AuditLog.timestamp >= since)
    )
    db_audit_logs = [
        {"id": e.id, "action": e.action, "detail": e.detail, "username": e.username}
        for e in audit_result.scalars().all()
    ]

    rules_evaluated = 0
    alerts_created = 0
    soar_dispatched = 0

    for rule in HARDCODED_RULES:
        if rule.rule_id not in active_rules:
            continue

        db_rule = active_rules[rule.rule_id]
        confidence = db_rule.confidence_score
        soar_mode = db_rule.soar_mode
        confirm_delay = db_rule.confirm_delay_seconds

        rules_evaluated += 1
        created_alerts = []

        try:
            if rule.rule_id == "RULE_001":
                created_alerts = await _eval_rule_001(hits, rule, db, confidence)
            elif rule.rule_id == "RULE_002":
                created_alerts = await _eval_rule_002(hits, rule, db, confidence)
            elif rule.rule_id == "RULE_003":
                created_alerts = await _eval_rule_003(hits, rule, db, db_audit_logs, confidence)
            elif rule.rule_id == "RULE_004":
                created_alerts = await _eval_rule_004(hits, rule, db, confidence)
            elif rule.rule_id == "RULE_005":
                created_alerts = await _eval_rule_005(hits, rule, db, confidence)
        except Exception as exc:
            logger.error("Erreur évaluation %s: %s", rule.rule_id, exc)
            continue

        alerts_created += len(created_alerts)

        # Déclenchement SOAR si un soar_action est défini et mode != MANUAL
        if rule.soar_action and soar_mode != "MANUAL" and created_alerts:
            for alert in created_alerts:
                try:
                    await dispatch_soar(
                        db=db,
                        alert=alert,
                        soar_action=rule.soar_action,
                        soar_mode=soar_mode,
                        confirm_delay_seconds=confirm_delay,
                        confidence_score=confidence,
                    )
                    soar_dispatched += 1
                except Exception as exc:
                    logger.error("[SOAR] Erreur dispatch alert_id=%s: %s", alert.id, exc)

    await log_action(
        db=db,
        username="system",
        action="correlation_run",
        detail=(
            f"rules_evaluated={rules_evaluated}, alerts_created={alerts_created}, "
            f"soar_dispatched={soar_dispatched}, window_minutes={window_minutes}"
        ),
    )

    return {
        "rules_evaluated":  rules_evaluated,
        "alerts_created":   alerts_created,
        "soar_dispatched":  soar_dispatched,
        "logs_analyzed":    len(hits),
        "window_minutes":   window_minutes,
    }
