#   backend/app/api/v1/routers/dashboard.py
#
#   Ce fichier définit l"endpoint de synthèse pour le tableau de bord.
#
#   *** STATUT: SQUELETTE FONCTIONNEL   ***
#   Ce module agrégera les statistiques réelles depuis Elasticsearch: volume de logs / heure, 
#    top alertes, carte des sources n'est pas encore implémenté. Cet endpoint retourne une
#    structure de données minimale mais cohérente avec ce que le frontend affiche, pour 
#    permettre son intégration dès maintenant.

from fastapi import APIRouter, Depends, HTTPException, status
from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

@router.get("", summary="Données de synthèse du tableau de bord")

async def get_dashboard(es_client: AsyncElasticsearch = Depends(get_es_client), user: dict = Depends(require_role("reader"))):
    """
    Retourne les données de synthèse pour le tableau de bord principal.
    Rôle requis: reader ou plus
    *** SQUELETTE   ***: Retourne des valeurs à 0 en attendant l'implémentation du module dashboard (week 3)
    """
    try:
        count_logs_resp = await es_client.count(index=settings.es_logs_index_name)
        total_logs      = count_logs_resp["count"]

        count_alerts_resp   = await es_client.count(index=settings.es_alerts_index_name, query={"term": {"status": "ouvert"}},)
        total_alerts_active = count_alerts_resp["count"]

        agg_resp        = await settings.es_client.search(
            index=settings.es_logs_index_name,
            size=0,
            query={"range": {"timestamp": {"gte": "now-24h"}}},
            aggs={
                "logs_per_hour": {
                    "date_histogram": {
                        "field":                "timestamp",
                        "calendar_interval":    "hour",
                        "min_doc_count":        0,
                        "extended_bounds": {
                            "min":  "now-24/h",
                            "max":  "now/h",
                        },
                    }
                },
                "by_severity": {"terms": {"field": "severity", "size": 10}},
                "top_ips": {
                    "terms": {
                        "field":    "source_ip",
                        "size":     10,
                        "order":    {"_count": "desc"},
                    }
                },
            },
        )

        aggs = agg_resp.get("aggregations", {})

        logs_per_hour = [
            {"hour": bucket["key_as_string"], "count": bucket["doc_count"],}
            for bucket in aggs.get("logs_per_hour", {}).get("buckets", [])
        ]

        severity_distribution = {b["key"]: b["doc_count"] for b in aggs.get("logs_per_hour", {}).get("buckets", [])}

        top_source_ips = [
            {"ip": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_ips", {}).get("buckets", [])
        ]

        recent_alerts_resp = await es_client.search(
            index=settings.es_alerts_index_name,
            size=5,
            query={
                "bool": {
                    "filter": [
                        {"term": {"status": "ouvert"}},
                        {"term": {"severity": "critical"}},
                    ]
                }
            },
            sort=[{"detected_at": {"order": "desc"}}],
        )
        top_alerts = [{"id": h["_id"], **h["_source"]} for h in recent_alerts_resp["hits"]["hits"]]
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Elasticsearch indisponible: {exc}",
        ) from exc

    return {
        "total_logs":               total_logs,
        "total_alerts_active":      total_alerts_active,
        "logs_per_hour":            logs_per_hour,
        "severity_distribution":    severity_distribution,
        "top_source_ips":           top_source_ips,
        "top_alerts":               top_alerts,
    }