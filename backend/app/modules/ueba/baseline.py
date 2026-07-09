# backend/app/modules/ueba/baseline.py
#
# Calcul de la baseline comportementale à partir des logs Elasticsearch.
#
# Stratégie :
#   - La baseline est calculée à la volée depuis ES sur une fenêtre configurable (défaut 30 jours).
#   - Elle est calculée par entité : "user", "source_ip" ou "host".
#   - Une baseline synthétise : heures habituelles, IPs habituelles, hôtes habituels,
#     volume moyen quotidien, taux d'échecs auth, types de logs dominants.
#   - Pas de persistance SQL : ES est la source de vérité.

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from elasticsearch import AsyncElasticsearch

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class EntityBaseline:
    """Résumé comportemental d'une entité sur la fenêtre de baseline."""
    entity_type: str
    entity_id: str
    period_days: int
    total_events: int
    avg_daily_events: float
    usual_hours: list[int]          # Heures UTC (top 85 % de l'activité)
    usual_source_ips: list[str]
    usual_hosts: list[str]
    dominant_log_types: list[str]
    auth_failure_count: int
    auth_success_count: int
    avg_daily_auth_failures: float
    sensitive_action_count: int
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_reliable: bool = True        # False si total_events < ueba_min_events_for_baseline


# ---------------------------------------------------------------------------
# Helpers d'extraction de champs
# ---------------------------------------------------------------------------

def _extract_user(src: dict) -> str:
    return str(src.get("user") or src.get("username") or "").strip()


def _extract_source_ip(src: dict) -> str:
    return str(src.get("source_ip") or src.get("src_ip") or "").strip()


def _extract_host(src: dict) -> str:
    return str(src.get("host") or src.get("hostname") or "").strip()


def _extract_log_type(src: dict) -> str:
    return str(src.get("log_type") or "").strip().lower()


def _extract_hour(src: dict) -> int | None:
    ts_raw = src.get("@timestamp") or src.get("timestamp")
    if not ts_raw:
        return None
    try:
        dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        return dt.hour
    except Exception:
        return None


def _extract_date(src: dict) -> str | None:
    ts_raw = src.get("@timestamp") or src.get("timestamp")
    if not ts_raw:
        return None
    try:
        dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return None


def _is_auth_failure(src: dict) -> bool:
    msg = (src.get("message") or "").lower()
    log_type = _extract_log_type(src)
    return log_type == "auth" and any(
        k in msg for k in ("failed", "failure", "invalid", "denied", "error")
    )


def _is_auth_success(src: dict) -> bool:
    msg = (src.get("message") or "").lower()
    log_type = _extract_log_type(src)
    return log_type == "auth" and any(
        k in msg for k in ("accepted", "success", "opened session", "logged in")
    )


def _is_sensitive_action(src: dict) -> bool:
    msg = (src.get("message") or "").lower()
    return any(
        k in msg
        for k in ("sudo", "privilege", "role_update", "su ", "setuid", "chmod", "useradd", "passwd")
    )


def _top_n_keys(counter: Counter, n: int = 10, coverage: float = 0.85) -> list:
    """Retourne les clés couvrant `coverage` des occurrences, au maximum n."""
    total = sum(counter.values())
    if total == 0:
        return []
    cumulative = 0
    result = []
    for key, count in counter.most_common(n):
        result.append(key)
        cumulative += count
        if cumulative / total >= coverage:
            break
    return result


# ---------------------------------------------------------------------------
# Fetch ES
# ---------------------------------------------------------------------------

async def _fetch_baseline_logs(
    es: AsyncElasticsearch,
    index: str,
    baseline_days: int,
) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(days=baseline_days)
    try:
        resp = await es.search(
            index=index,
            body={
                "query": {
                    "bool": {
                        "should": [
                            {"range": {"@timestamp": {"gte": since.isoformat()}}},
                            {"range": {"timestamp":  {"gte": since.isoformat()}}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "size": 10000,
                "_source": True,
            },
        )
        hits = resp.get("hits", {}).get("hits", [])
        logger.info("[UEBA/baseline] %d logs récupérés sur %d jours", len(hits), baseline_days)
        return hits
    except Exception as exc:
        logger.warning("[UEBA/baseline] Impossible de lire ES: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Construction des baselines
# ---------------------------------------------------------------------------

def build_baselines_from_hits(
    hits: list[dict],
    entity_type: str,
    baseline_days: int,
    min_events: int,
) -> dict[str, EntityBaseline]:
    """Construit les baselines pour toutes les entités observées dans les hits."""
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

    baselines: dict[str, EntityBaseline] = {}

    for eid, srcs in entity_hits.items():
        hour_counter: Counter = Counter()
        ip_counter: Counter = Counter()
        host_counter: Counter = Counter()
        log_type_counter: Counter = Counter()
        auth_failures = 0
        auth_successes = 0
        sensitive_actions = 0

        for src in srcs:
            hour = _extract_hour(src)
            if hour is not None:
                hour_counter[hour] += 1

            ip = _extract_source_ip(src)
            if ip:
                ip_counter[ip] += 1

            host = _extract_host(src)
            if host:
                host_counter[host] += 1

            lt = _extract_log_type(src)
            if lt:
                log_type_counter[lt] += 1

            if _is_auth_failure(src):
                auth_failures += 1
            if _is_auth_success(src):
                auth_successes += 1
            if _is_sensitive_action(src):
                sensitive_actions += 1

        total = len(srcs)
        baselines[eid] = EntityBaseline(
            entity_type=entity_type,
            entity_id=eid,
            period_days=baseline_days,
            total_events=total,
            avg_daily_events=round(total / baseline_days, 2),
            usual_hours=_top_n_keys(hour_counter, n=24, coverage=0.85),
            usual_source_ips=list(ip_counter.keys()),
            usual_hosts=list(host_counter.keys()),
            dominant_log_types=_top_n_keys(log_type_counter, n=5, coverage=0.90),
            auth_failure_count=auth_failures,
            auth_success_count=auth_successes,
            avg_daily_auth_failures=round(auth_failures / baseline_days, 3),
            sensitive_action_count=sensitive_actions,
            is_reliable=(total >= min_events),
        )

    return baselines


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------

async def compute_baseline(
    es: AsyncElasticsearch,
    entity_type: str = "source_ip",
    entity_id: str | None = None,
    baseline_days: int | None = None,
) -> dict[str, EntityBaseline]:
    """
    Calcule et retourne les baselines comportementales.

    Args:
        es:            Client Elasticsearch async.
        entity_type:   "user" | "source_ip" | "host"
        entity_id:     Si fourni, filtre sur une seule entité.
        baseline_days: Fenêtre d'observation (défaut : settings.ueba_baseline_days).

    Returns:
        Dict {entity_id -> EntityBaseline}
    """
    if entity_type not in ("user", "source_ip", "host"):
        raise ValueError(f"entity_type invalide: {entity_type!r}")

    days = baseline_days or settings.ueba_baseline_days
    min_events = settings.ueba_min_events_for_baseline

    hits = await _fetch_baseline_logs(es, settings.es_logs_index_name, days)
    baselines = build_baselines_from_hits(hits, entity_type, days, min_events)

    if entity_id:
        return {entity_id: baselines[entity_id]} if entity_id in baselines else {}

    return baselines


def baseline_to_dict(b: EntityBaseline) -> dict:
    return {
        "entity_type":             b.entity_type,
        "entity_id":               b.entity_id,
        "period_days":             b.period_days,
        "total_events":            b.total_events,
        "avg_daily_events":        b.avg_daily_events,
        "usual_hours":             b.usual_hours,
        "usual_source_ips":        b.usual_source_ips,
        "usual_hosts":             b.usual_hosts,
        "dominant_log_types":      b.dominant_log_types,
        "auth_failure_count":      b.auth_failure_count,
        "auth_success_count":      b.auth_success_count,
        "avg_daily_auth_failures": b.avg_daily_auth_failures,
        "sensitive_action_count":  b.sensitive_action_count,
        "is_reliable":             b.is_reliable,
        "computed_at":             b.computed_at.isoformat(),
    }
