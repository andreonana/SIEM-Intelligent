# backend/app/modules/ueba/behavior_analyzer.py
#
# Analyse du comportement récent d'une entité depuis ES.
# Produit un BehaviorSummary comparable à une EntityBaseline.

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.modules.ueba.baseline import (
    _extract_user,
    _extract_source_ip,
    _extract_host,
    _extract_log_type,
    _extract_hour,
    _is_auth_failure,
    _is_auth_success,
    _is_sensitive_action,
)

logger = logging.getLogger(__name__)


@dataclass
class BehaviorSummary:
    """Résumé comportemental observé sur une fenêtre récente."""
    entity_type: str
    entity_id: str
    window_minutes: int
    total_events: int
    observed_hours: list[int]
    observed_source_ips: list[str]
    observed_hosts: list[str]
    observed_log_types: list[str]
    auth_failure_count: int
    auth_success_count: int
    sensitive_action_count: int
    host_spread: int          # Nombre d'hôtes distincts
    ip_spread: int            # Nombre d'IPs sources distinctes
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Fetch ES — fenêtre récente
# ---------------------------------------------------------------------------

async def _fetch_recent_logs(
    es: AsyncElasticsearch,
    index: str,
    window_minutes: int,
) -> list[dict]:
    # On utilise received_at (date d'arrivée au SIEM) pour la fenêtre récente —
    # plus fiable que timestamp (date de l'événement côté source) qui peut être
    # mal parsé (mois en français, timezone incorrecte, etc.).
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    try:
        resp = await es.search(
            index=index,
            body={
                "query": {
                    "bool": {
                        "should": [
                            {"range": {"received_at":  {"gte": since.isoformat()}}},
                            {"range": {"@timestamp":   {"gte": since.isoformat()}}},
                            {"range": {"timestamp":    {"gte": since.isoformat()}}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "size": 10000,
                "_source": True,
            },
        )
        hits = resp.get("hits", {}).get("hits", [])
        logger.debug("[UEBA/behavior] %d logs récents récupérés (window=%dm)", len(hits), window_minutes)
        return hits
    except Exception as exc:
        logger.warning("[UEBA/behavior] Impossible de lire ES: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Construction des résumés comportementaux
# ---------------------------------------------------------------------------

def build_behavior_summaries_from_hits(
    hits: list[dict],
    entity_type: str,
    window_minutes: int,
) -> dict[str, BehaviorSummary]:
    """Construit les résumés de comportement récent par entité."""
    entity_hits: dict[str, list[dict]] = defaultdict(list)

    for hit in hits:
        src = hit.get("_source", {})
        if entity_type == "user":
            eid = _extract_user(src)
        elif entity_type == "source_ip":
            eid = _extract_source_ip(src)
        elif entity_type == "host":
            eid = _extract_host(src)
        else:
            continue
        if not eid:
            continue
        entity_hits[eid].append(src)

    summaries: dict[str, BehaviorSummary] = {}

    for eid, srcs in entity_hits.items():
        hours: set[int] = set()
        source_ips: set[str] = set()
        hosts: set[str] = set()
        log_types: Counter = Counter()
        auth_failures = 0
        auth_successes = 0
        sensitive = 0

        for src in srcs:
            hour = _extract_hour(src)
            if hour is not None:
                hours.add(hour)

            ip = _extract_source_ip(src)
            if ip:
                source_ips.add(ip)

            host = _extract_host(src)
            if host:
                hosts.add(host)

            lt = _extract_log_type(src)
            if lt:
                log_types[lt] += 1

            if _is_auth_failure(src):
                auth_failures += 1
            if _is_auth_success(src):
                auth_successes += 1
            if _is_sensitive_action(src):
                sensitive += 1

        summaries[eid] = BehaviorSummary(
            entity_type=entity_type,
            entity_id=eid,
            window_minutes=window_minutes,
            total_events=len(srcs),
            observed_hours=sorted(hours),
            observed_source_ips=list(source_ips),
            observed_hosts=list(hosts),
            observed_log_types=list(log_types.keys()),
            auth_failure_count=auth_failures,
            auth_success_count=auth_successes,
            sensitive_action_count=sensitive,
            host_spread=len(hosts),
            ip_spread=len(source_ips),
        )

    return summaries


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------

async def analyze_recent_behavior(
    es: AsyncElasticsearch,
    entity_type: str = "source_ip",
    entity_id: str | None = None,
    window_minutes: int | None = None,
) -> dict[str, BehaviorSummary]:
    """
    Extrait et retourne le résumé comportemental récent de chaque entité.

    Args:
        es:             Client Elasticsearch async.
        entity_type:    "user" | "source_ip" | "host"
        entity_id:      Si fourni, filtre sur une seule entité.
        window_minutes: Fenêtre d'observation (défaut : settings.ueba_analysis_window_minutes).

    Returns:
        Dict {entity_id -> BehaviorSummary}
    """
    if entity_type not in ("user", "source_ip", "host"):
        raise ValueError(f"entity_type invalide: {entity_type!r}")

    window = window_minutes or settings.ueba_analysis_window_minutes
    hits = await _fetch_recent_logs(es, settings.es_logs_index_name, window)
    summaries = build_behavior_summaries_from_hits(hits, entity_type, window)

    if entity_id:
        return {entity_id: summaries[entity_id]} if entity_id in summaries else {}

    return summaries


def summary_to_dict(s: BehaviorSummary) -> dict:
    return {
        "entity_type":          s.entity_type,
        "entity_id":            s.entity_id,
        "window_minutes":       s.window_minutes,
        "total_events":         s.total_events,
        "observed_hours":       s.observed_hours,
        "observed_source_ips":  s.observed_source_ips,
        "observed_hosts":       s.observed_hosts,
        "observed_log_types":   s.observed_log_types,
        "auth_failure_count":   s.auth_failure_count,
        "auth_success_count":   s.auth_success_count,
        "sensitive_action_count": s.sensitive_action_count,
        "host_spread":          s.host_spread,
        "ip_spread":            s.ip_spread,
        "observed_at":          s.observed_at.isoformat(),
    }
