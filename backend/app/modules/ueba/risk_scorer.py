# backend/app/modules/ueba/risk_scorer.py
#
# Calcul du score de risque UEBA à partir des anomalies détectées.
#
# Règles de scoring :
#   Le score est la somme des weights des anomalies détectées, plafonné à 100.
#   Les seuils de niveau sont configurables via settings :
#     0  <= score < ueba_risk_medium_threshold   -> low
#     20 <= score < ueba_risk_high_threshold     -> medium
#     45 <= score < ueba_risk_critical_threshold -> high
#     70 <= score                                -> critical

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.config import settings
from app.modules.ueba.anomaly_detector import Anomaly

logger = logging.getLogger(__name__)


@dataclass
class RiskScore:
    entity_type: str
    entity_id: str
    score: float                       # 0 à 100
    risk_level: str                    # low | medium | high | critical
    anomaly_count: int
    contributing_types: list[str]      # Types d'anomalies qui contribuent
    justification: str
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def compute_risk_score(
    entity_type: str,
    entity_id: str,
    anomalies: list[Anomaly],
) -> RiskScore:
    """
    Calcule le score de risque global pour une entité à partir de ses anomalies.

    Chaque anomalie contribue selon son weight (défini dans anomaly_detector.py).
    Le score brut est plafonné à 100.
    """
    if not anomalies:
        return RiskScore(
            entity_type=entity_type,
            entity_id=entity_id,
            score=0.0,
            risk_level="low",
            anomaly_count=0,
            contributing_types=[],
            justification="Aucune anomalie détectée.",
        )

    raw_score = sum(a.weight for a in anomalies)
    score = min(raw_score, 100.0)

    risk_level = _level_from_score(score)

    contributing_types = sorted({a.anomaly_type for a in anomalies})

    justification_parts = [
        f"Score brut : {raw_score:.1f} → normalisé à {score:.1f}/100.",
        f"Niveau de risque : {risk_level.upper()}.",
        "Anomalies contribuant au score :",
    ]
    for a in sorted(anomalies, key=lambda x: -x.weight):
        justification_parts.append(
            f"  [{a.anomaly_type}] +{a.weight:.0f} ({a.severity}) — {a.description}"
        )

    return RiskScore(
        entity_type=entity_type,
        entity_id=entity_id,
        score=round(score, 1),
        risk_level=risk_level,
        anomaly_count=len(anomalies),
        contributing_types=contributing_types,
        justification="\n".join(justification_parts),
    )


def _level_from_score(score: float) -> str:
    if score >= settings.ueba_risk_critical_threshold:
        return "critical"
    if score >= settings.ueba_risk_high_threshold:
        return "high"
    if score >= settings.ueba_risk_medium_threshold:
        return "medium"
    return "low"


def risk_score_to_dict(rs: RiskScore) -> dict:
    return {
        "entity_type":       rs.entity_type,
        "entity_id":         rs.entity_id,
        "score":             rs.score,
        "risk_level":        rs.risk_level,
        "anomaly_count":     rs.anomaly_count,
        "contributing_types": rs.contributing_types,
        "justification":     rs.justification,
        "computed_at":       rs.computed_at.isoformat(),
    }
