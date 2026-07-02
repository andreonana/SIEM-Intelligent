# backend/app/api/v1/routers/dashboard.py
#
# Endpoint de synthèse pour le tableau de bord principal.
# Agrège des données réelles depuis Elasticsearch (volume de logs, top IP sources)
# et la base relationnelle (alertes actives, top alertes par sévérité).

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.elasticsearch_client import get_es_client
from app.core.config import settings
from app.models.alert import Alert
from app.modules.rbac.roles import require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("")
async def get_dashboard(
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """
    Retourne les données de synthèse réelles pour le tableau de bord principal :
    volume de logs par heure (24h), top alertes actives, top adresses IP sources.
    Rôle requis: reader ou plus.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)

    total_logs = 0
    logs_per_hour = []
    source_map = []

    try:
        es_client = get_es_client()
        index = settings.es_logs_index_name

        count_resp = await es_client.count(index=index)
        total_logs = count_resp.get("count", 0)

        hourly_resp = await es_client.search(
            index=index,
            size=0,
            query={"range": {"received_at": {"gte": since.isoformat()}}},
            aggs={
                "per_hour": {
                    "date_histogram": {
                        "field": "received_at",
                        "fixed_interval": "1h",
                        "min_doc_count": 0,
                    }
                },
                "top_sources": {
                    "terms": {"field": "source_ip.keyword", "size": 10},
                },
            },
        )
        for bucket in hourly_resp["aggregations"]["per_hour"]["buckets"]:
            logs_per_hour.append({"hour": bucket["key_as_string"], "count": bucket["doc_count"]})
        for bucket in hourly_resp["aggregations"]["top_sources"]["buckets"]:
            source_map.append({"source_ip": bucket["key"], "count": bucket["doc_count"]})
    except Exception as exc:
        logger.warning("[Dashboard] Elasticsearch indisponible ou index vide: %s", exc)

    result = await db.execute(
        select(Alert).where(Alert.status != "resolved").order_by(Alert.detected_at.desc()).limit(10)
    )
    active_alerts = result.scalars().all()

    count_result = await db.execute(select(Alert).where(Alert.status != "resolved"))
    total_alerts_active = len(count_result.scalars().all())

    top_alerts = [
        {
            "id": a.id,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "description": a.description,
            "status": a.status,
            "detected_at": a.detected_at.isoformat() if a.detected_at else None,
        }
        for a in active_alerts
    ]

    return {
        "total_logs": total_logs,
        "total_alerts_active": total_alerts_active,
        "logs_per_hour": logs_per_hour,
        "top_alerts": top_alerts,
        "source_map": source_map,
    }
