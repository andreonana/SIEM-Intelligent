# backend/app/modules/ueba/anomaly_detector.py
#
# Détection d'anomalies comportementales par comparaison baseline / comportement récent.
#
# Logique : heuristique déterministe et explicable.
# Chaque anomalie a un type, une sévérité et un weight (contribution au score de risque).
# Pas de ML : les seuils sont explicites et défendables.
#
# Tableau des poids utilisés dans le scoring :
#   unusual_login_hour      : +10  (heure inhabituelle)
#   unseen_source_ip        : +20  (IP jamais vue)
#   unseen_host             : +15  (hôte jamais vu)
#   abnormal_activity_volume: +20  (volume 3x la moyenne)
#   auth_failure_spike      : +25  (pic d'échecs auth)
#   abnormal_host_spread    : +20  (dispersion multi-hôtes)
#   anomalous_log_mix       : +10  (type de log inhabituel)
#   sensitive_action_spike  : +20  (actions sensibles inhabituelles)

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.modules.ueba.baseline import EntityBaseline
from app.modules.ueba.behavior_analyzer import BehaviorSummary

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Seuils de détection
# ---------------------------------------------------------------------------

# Facteur multiplicatif sur avg_daily_events (normalisé sur la fenêtre d'analyse)
# pour déclarer un pic d'activité.
ACTIVITY_SPIKE_FACTOR = 3.0

# Facteur multiplicatif sur avg_daily_auth_failures pour déclarer un pic d'échecs.
AUTH_FAILURE_SPIKE_FACTOR = 3.0

# Nombre d'hôtes distincts au-delà duquel on déclare une dispersion anormale.
HOST_SPREAD_THRESHOLD = 3

# Nombre minimal d'actions sensibles pour déclarer une anomalie (si baseline = 0).
SENSITIVE_ACTIONS_ABSOLUTE_THRESHOLD = 3

# ---------------------------------------------------------------------------
# Modèle d'anomalie
# ---------------------------------------------------------------------------

@dataclass
class Anomaly:
    anomaly_type: str
    entity_type: str
    entity_id: str
    severity: str               # INFO | WARNING | HIGH | CRITICAL
    weight: float               # Contribution au score de risque (0-100)
    description: str
    evidence: str
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _anomaly_to_dict(a: Anomaly) -> dict:
    return {
        "anomaly_type": a.anomaly_type,
        "entity_type":  a.entity_type,
        "entity_id":    a.entity_id,
        "severity":     a.severity,
        "weight":       a.weight,
        "description":  a.description,
        "evidence":     a.evidence,
        "detected_at":  a.detected_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Détecteurs individuels
# ---------------------------------------------------------------------------

def _detect_unusual_hour(
    baseline: EntityBaseline,
    summary: BehaviorSummary,
) -> list[Anomaly]:
    """Heure d'activité hors de la plage habituelle."""
    if not baseline.usual_hours:
        return []
    anomalies = []
    unusual = [h for h in summary.observed_hours if h not in baseline.usual_hours]
    if unusual:
        anomalies.append(Anomaly(
            anomaly_type="unusual_login_hour",
            entity_type=summary.entity_type,
            entity_id=summary.entity_id,
            severity="WARNING",
            weight=10.0,
            description=(
                f"Activité détectée à des heures inhabituelles : {unusual}. "
                f"Heures habituelles : {baseline.usual_hours}."
            ),
            evidence=f"unusual_hours={unusual}",
        ))
    return anomalies


def _detect_unseen_source_ip(
    baseline: EntityBaseline,
    summary: BehaviorSummary,
) -> list[Anomaly]:
    """IP source jamais vue dans la baseline."""
    if not baseline.usual_source_ips:
        return []
    anomalies = []
    known_ips = set(baseline.usual_source_ips)
    new_ips = [ip for ip in summary.observed_source_ips if ip not in known_ips]
    for ip in new_ips:
        anomalies.append(Anomaly(
            anomaly_type="unseen_source_ip",
            entity_type=summary.entity_type,
            entity_id=summary.entity_id,
            severity="HIGH",
            weight=20.0,
            description=f"Activité depuis une IP source inconnue : {ip}.",
            evidence=f"new_ip={ip}, known_ips={list(known_ips)[:5]}",
        ))
    return anomalies


def _detect_unseen_host(
    baseline: EntityBaseline,
    summary: BehaviorSummary,
) -> list[Anomaly]:
    """Hôte jamais vu dans la baseline."""
    if not baseline.usual_hosts:
        return []
    anomalies = []
    known_hosts = set(baseline.usual_hosts)
    new_hosts = [h for h in summary.observed_hosts if h not in known_hosts]
    for host in new_hosts:
        anomalies.append(Anomaly(
            anomaly_type="unseen_host",
            entity_type=summary.entity_type,
            entity_id=summary.entity_id,
            severity="HIGH",
            weight=15.0,
            description=f"Activité depuis un hôte inconnu : {host}.",
            evidence=f"new_host={host}, known_hosts={list(known_hosts)[:5]}",
        ))
    return anomalies


def _detect_activity_spike(
    baseline: EntityBaseline,
    summary: BehaviorSummary,
) -> list[Anomaly]:
    """Volume d'activité anormalement élevé."""
    if baseline.avg_daily_events <= 0:
        return []
    # Normalise le volume récent à une journée pour comparer à avg_daily_events
    minutes_in_day = 1440.0
    events_per_day_equivalent = summary.total_events * (minutes_in_day / summary.window_minutes)
    if events_per_day_equivalent >= baseline.avg_daily_events * ACTIVITY_SPIKE_FACTOR:
        ratio = round(events_per_day_equivalent / baseline.avg_daily_events, 1)
        return [Anomaly(
            anomaly_type="abnormal_activity_volume",
            entity_type=summary.entity_type,
            entity_id=summary.entity_id,
            severity="HIGH" if ratio < 10 else "CRITICAL",
            weight=20.0,
            description=(
                f"Volume d'activité {ratio}x supérieur à la normale "
                f"({summary.total_events} événements en {summary.window_minutes} min, "
                f"moyenne journalière habituelle : {baseline.avg_daily_events})."
            ),
            evidence=f"events={summary.total_events}, window_min={summary.window_minutes}, "
                     f"equiv_daily={round(events_per_day_equivalent,1)}, baseline_daily={baseline.avg_daily_events}",
        )]
    return []


def _detect_auth_failure_spike(
    baseline: EntityBaseline,
    summary: BehaviorSummary,
) -> list[Anomaly]:
    """Pic d'échecs d'authentification."""
    if summary.auth_failure_count == 0:
        return []

    minutes_in_day = 1440.0
    failures_per_day_equiv = summary.auth_failure_count * (minutes_in_day / summary.window_minutes)
    baseline_daily = baseline.avg_daily_auth_failures

    if baseline_daily > 0 and failures_per_day_equiv >= baseline_daily * AUTH_FAILURE_SPIKE_FACTOR:
        ratio = round(failures_per_day_equiv / baseline_daily, 1)
        return [Anomaly(
            anomaly_type="auth_failure_spike",
            entity_type=summary.entity_type,
            entity_id=summary.entity_id,
            severity="CRITICAL",
            weight=25.0,
            description=(
                f"Pic d'échecs d'authentification : {summary.auth_failure_count} échecs en "
                f"{summary.window_minutes} min ({ratio}x la moyenne habituelle)."
            ),
            evidence=f"auth_failures={summary.auth_failure_count}, "
                     f"equiv_daily={round(failures_per_day_equiv,1)}, "
                     f"baseline_daily={baseline_daily}",
        )]
    elif baseline_daily == 0 and summary.auth_failure_count >= 5:
        # Aucun échec dans la baseline → toute activité d'échec est suspecte
        return [Anomaly(
            anomaly_type="auth_failure_spike",
            entity_type=summary.entity_type,
            entity_id=summary.entity_id,
            severity="HIGH",
            weight=25.0,
            description=(
                f"{summary.auth_failure_count} échecs d'authentification détectés "
                f"alors qu'aucun n'est habituel pour cette entité."
            ),
            evidence=f"auth_failures={summary.auth_failure_count}, baseline_daily=0",
        )]
    return []


def _detect_host_spread(
    baseline: EntityBaseline,
    summary: BehaviorSummary,
) -> list[Anomaly]:
    """Dispersion inhabituelle sur plusieurs hôtes (possible mouvement latéral)."""
    # Comparer au nombre d'hôtes habituels
    usual_host_count = len(baseline.usual_hosts)
    if summary.host_spread > max(HOST_SPREAD_THRESHOLD, usual_host_count * 2):
        return [Anomaly(
            anomaly_type="abnormal_host_spread",
            entity_type=summary.entity_type,
            entity_id=summary.entity_id,
            severity="HIGH",
            weight=20.0,
            description=(
                f"Activité détectée sur {summary.host_spread} hôtes distincts "
                f"(habituel : {usual_host_count}). Possible mouvement latéral."
            ),
            evidence=f"host_spread={summary.host_spread}, usual_hosts={usual_host_count}, "
                     f"observed_hosts={summary.observed_hosts[:5]}",
        )]
    return []


def _detect_unusual_log_type(
    baseline: EntityBaseline,
    summary: BehaviorSummary,
) -> list[Anomaly]:
    """Type de log non observé dans la baseline."""
    if not baseline.dominant_log_types:
        return []
    known = set(baseline.dominant_log_types)
    new_types = [lt for lt in summary.observed_log_types if lt not in known]
    if new_types:
        return [Anomaly(
            anomaly_type="anomalous_log_mix",
            entity_type=summary.entity_type,
            entity_id=summary.entity_id,
            severity="WARNING",
            weight=10.0,
            description=f"Types de logs inhabituels observés : {new_types}.",
            evidence=f"new_types={new_types}, known_types={list(known)}",
        )]
    return []


def _detect_sensitive_action_spike(
    baseline: EntityBaseline,
    summary: BehaviorSummary,
) -> list[Anomaly]:
    """Actions sensibles anormalement élevées."""
    if summary.sensitive_action_count == 0:
        return []

    minutes_in_day = 1440.0
    sensitive_per_day = summary.sensitive_action_count * (minutes_in_day / summary.window_minutes)
    baseline_daily = baseline.sensitive_action_count / max(baseline.period_days, 1)

    if baseline_daily > 0 and sensitive_per_day >= baseline_daily * 3:
        ratio = round(sensitive_per_day / baseline_daily, 1)
        return [Anomaly(
            anomaly_type="sensitive_action_spike",
            entity_type=summary.entity_type,
            entity_id=summary.entity_id,
            severity="HIGH",
            weight=20.0,
            description=(
                f"Pic d'actions sensibles : {summary.sensitive_action_count} en "
                f"{summary.window_minutes} min ({ratio}x la normale)."
            ),
            evidence=f"sensitive={summary.sensitive_action_count}, "
                     f"equiv_daily={round(sensitive_per_day,1)}, baseline_daily={round(baseline_daily,2)}",
        )]
    elif baseline_daily == 0 and summary.sensitive_action_count >= SENSITIVE_ACTIONS_ABSOLUTE_THRESHOLD:
        return [Anomaly(
            anomaly_type="sensitive_action_spike",
            entity_type=summary.entity_type,
            entity_id=summary.entity_id,
            severity="HIGH",
            weight=20.0,
            description=(
                f"{summary.sensitive_action_count} actions sensibles détectées "
                f"alors qu'aucune n'est habituelle pour cette entité."
            ),
            evidence=f"sensitive={summary.sensitive_action_count}, baseline_daily=0",
        )]
    return []


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------

DETECTORS = [
    _detect_unusual_hour,
    _detect_unseen_source_ip,
    _detect_unseen_host,
    _detect_activity_spike,
    _detect_auth_failure_spike,
    _detect_host_spread,
    _detect_unusual_log_type,
    _detect_sensitive_action_spike,
]


def detect_anomalies(
    baseline: EntityBaseline,
    summary: BehaviorSummary,
) -> list[Anomaly]:
    """
    Compare le comportement récent à la baseline et retourne la liste des anomalies détectées.

    La baseline doit correspondre à la même entité que le summary.
    Si la baseline n'est pas fiable (trop peu d'événements), les détecteurs fonctionnent
    en mode dégradé (seuils absolus uniquement, comparaisons relatives désactivées).
    """
    if baseline.entity_id != summary.entity_id or baseline.entity_type != summary.entity_type:
        raise ValueError(
            f"Mismatch entité : baseline={baseline.entity_type}/{baseline.entity_id}, "
            f"summary={summary.entity_type}/{summary.entity_id}"
        )

    anomalies: list[Anomaly] = []
    for detector in DETECTORS:
        try:
            found = detector(baseline, summary)
            anomalies.extend(found)
        except Exception as exc:
            logger.warning("[UEBA/detector] Erreur dans %s: %s", detector.__name__, exc)

    if anomalies:
        logger.info(
            "[UEBA/detector] %d anomalie(s) pour %s/%s",
            len(anomalies), summary.entity_type, summary.entity_id,
        )

    return anomalies


def anomaly_to_dict(a: Anomaly) -> dict:
    return _anomaly_to_dict(a)
