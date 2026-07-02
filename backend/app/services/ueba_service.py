# backend/app/services/ueba_service.py
#
# Orchestrateur du pipeline UEBA : baseline -> behavior -> anomalies -> scoring -> persistance.
# Point d'entrée unique pour le routeur et les tâches planifiées.

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from elasticsearch import AsyncElasticsearch
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.ueba_anomaly import UEBAAnomaly
from app.models.ueba_risk_score import UEBARiskScore
from app.modules.ueba.baseline import compute_baseline, baseline_to_dict, EntityBaseline
from app.modules.ueba.behavior_analyzer import analyze_recent_behavior
from app.modules.ueba.anomaly_detector import detect_anomalies, anomaly_to_dict
from app.modules.ueba.risk_scorer import compute_risk_score, risk_score_to_dict
from app.services.alert_service import create_alert, check_dedupe
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline principal
# ---------------------------------------------------------------------------

async def run_ueba_analysis(
    db: AsyncSession,
    es: AsyncElasticsearch,
    entity_type: str = "source_ip",
    entity_id: str | None = None,
    baseline_days: int | None = None,
    window_minutes: int | None = None,
    triggered_by: str = "system",
) -> dict:
    """
    Lance le pipeline UEBA complet :
      1. Calcul de la baseline comportementale (baseline_days).
      2. Analyse du comportement récent (window_minutes).
      3. Détection d'anomalies par comparaison.
      4. Calcul du score de risque.
      5. Persistance SQL des anomalies et des scores.
      6. Création d'alertes pour les entités high/critical.
      7. Entrée d'audit.

    Retourne un résumé de l'analyse.
    """
    days = baseline_days or settings.ueba_baseline_days
    window = window_minutes or settings.ueba_analysis_window_minutes

    # 1. Baseline
    baselines = await compute_baseline(es, entity_type=entity_type, entity_id=entity_id, baseline_days=days)

    if not baselines:
        logger.info("[UEBA] Aucune baseline disponible pour entity_type=%s", entity_type)
        return {"entities_analyzed": 0, "anomalies_detected": 0, "alerts_created": 0}

    # 2. Comportement récent
    summaries = await analyze_recent_behavior(
        es, entity_type=entity_type, entity_id=entity_id, window_minutes=window
    )

    total_anomalies = 0
    total_alerts = 0
    entities_analyzed = 0

    for eid, baseline in baselines.items():
        summary = summaries.get(eid)
        if summary is None:
            # Entité sans activité récente — pas d'anomalie
            continue

        entities_analyzed += 1

        # 3. Anomalies
        anomalies = detect_anomalies(baseline, summary)

        # 4. Score de risque
        risk = compute_risk_score(entity_type, eid, anomalies)

        # 5. Persistance
        await _persist_anomalies(db, anomalies)
        await _persist_risk_score(db, risk)

        total_anomalies += len(anomalies)

        # 6. Alertes pour high/critical
        if risk.risk_level in ("high", "critical"):
            created = await _create_ueba_alert(db, risk, anomalies)
            total_alerts += created

    # 7. Audit
    await log_action(
        db=db,
        username=triggered_by,
        action="ueba_analysis",
        detail=(
            f"entity_type={entity_type}, entities={entities_analyzed}, "
            f"anomalies={total_anomalies}, alerts={total_alerts}, "
            f"baseline_days={days}, window_min={window}"
        ),
    )

    return {
        "entity_type": entity_type,
        "entities_analyzed": entities_analyzed,
        "anomalies_detected": total_anomalies,
        "alerts_created": total_alerts,
        "baseline_days": days,
        "window_minutes": window,
    }


# ---------------------------------------------------------------------------
# Persistance
# ---------------------------------------------------------------------------

async def _persist_anomalies(db: AsyncSession, anomalies: list) -> None:
    for a in anomalies:
        record = UEBAAnomaly(
            entity_type=a.entity_type,
            entity_id=a.entity_id,
            anomaly_type=a.anomaly_type,
            severity=a.severity,
            weight=a.weight,
            description=a.description,
            evidence=a.evidence,
            detected_at=a.detected_at,
        )
        db.add(record)
    if anomalies:
        await db.commit()


async def _persist_risk_score(db: AsyncSession, risk) -> None:
    record = UEBARiskScore(
        entity_type=risk.entity_type,
        entity_id=risk.entity_id,
        score=risk.score,
        risk_level=risk.risk_level,
        anomaly_count=risk.anomaly_count,
        contributing_types=json.dumps(risk.contributing_types),
        justification=risk.justification,
        computed_at=risk.computed_at,
    )
    db.add(record)
    await db.commit()


async def _create_ueba_alert(db: AsyncSession, risk, anomalies: list) -> int:
    """Crée une alerte de corrélation pour une entité à risque élevé."""
    rule_id = "UEBA_HIGH_RISK"
    severity = "CRITICAL" if risk.risk_level == "critical" else "HIGH"
    dedupe_key = f"ueba:{risk.entity_type}:{risk.entity_id}:{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"

    if await check_dedupe(db, dedupe_key):
        return 0

    types_str = ", ".join(risk.contributing_types)
    description = (
        f"[UEBA] Score de risque {risk.risk_level.upper()} ({risk.score}/100) "
        f"pour {risk.entity_type} '{risk.entity_id}'. "
        f"Anomalies : {types_str}."
    )

    alert = await create_alert(
        db=db,
        rule_id=rule_id,
        rule_name="UEBA — Comportement à risque élevé",
        severity=severity,
        description=description,
        source_ip=risk.entity_id if risk.entity_type == "source_ip" else None,
        host=risk.entity_id if risk.entity_type == "host" else None,
        mitre_tactic="Behavioral Analysis",
        dedupe_key=dedupe_key,
    )
    return 1 if alert else 0


# ---------------------------------------------------------------------------
# Lectures SQL
# ---------------------------------------------------------------------------

async def list_anomalies(
    db: AsyncSession,
    entity_type: str | None = None,
    entity_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    query = select(UEBAAnomaly).order_by(desc(UEBAAnomaly.detected_at))
    count_q = select(func.count()).select_from(UEBAAnomaly)

    if entity_type:
        query = query.where(UEBAAnomaly.entity_type == entity_type)
        count_q = count_q.where(UEBAAnomaly.entity_type == entity_type)
    if entity_id:
        query = query.where(UEBAAnomaly.entity_id == entity_id)
        count_q = count_q.where(UEBAAnomaly.entity_id == entity_id)

    offset = (page - 1) * page_size
    result = await db.execute(query.offset(offset).limit(page_size))
    rows = result.scalars().all()
    total = (await db.execute(count_q)).scalar_one()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "anomalies": [r.to_dict() for r in rows],
    }


async def list_risk_scores(
    db: AsyncSession,
    entity_type: str | None = None,
    min_level: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    query = select(UEBARiskScore).order_by(desc(UEBARiskScore.computed_at))
    count_q = select(func.count()).select_from(UEBARiskScore)

    if entity_type:
        query = query.where(UEBARiskScore.entity_type == entity_type)
        count_q = count_q.where(UEBARiskScore.entity_type == entity_type)
    if min_level:
        level_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_val = level_order.get(min_level, 0)
        allowed = [k for k, v in level_order.items() if v >= min_val]
        query = query.where(UEBARiskScore.risk_level.in_(allowed))
        count_q = count_q.where(UEBARiskScore.risk_level.in_(allowed))

    offset = (page - 1) * page_size
    result = await db.execute(query.offset(offset).limit(page_size))
    rows = result.scalars().all()
    total = (await db.execute(count_q)).scalar_one()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "risk_scores": [r.to_dict() for r in rows],
    }


async def get_entity_risk(
    db: AsyncSession,
    entity_type: str,
    entity_id: str,
) -> dict | None:
    """Retourne le score de risque le plus récent pour une entité."""
    result = await db.execute(
        select(UEBARiskScore)
        .where(UEBARiskScore.entity_type == entity_type)
        .where(UEBARiskScore.entity_id == entity_id)
        .order_by(desc(UEBARiskScore.computed_at))
        .limit(1)
    )
    row = result.scalar_one_or_none()
    return row.to_dict() if row else None
