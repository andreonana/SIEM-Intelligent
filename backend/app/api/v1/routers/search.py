# backend/app/api/v1/routers/search.py
#
# Endpoint de recherche multi-critère dans les logs (Elasticsearch) et
# export CSV/Excel des résultats filtrés.

from fastapi import APIRouter, Depends, HTTPException, Query, status
from elasticsearch import AsyncElasticsearch
from fastapi.responses import Response
from pydantic import BaseModel

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role
from app.services.export_service import to_csv_bytes, to_xlsx_bytes

router = APIRouter(prefix="/api/search", tags=["search"])


class SearchRequest(BaseModel):
    """
    Corps de la requête de recherche multi-critère.
    Tous les champs sont optionnels (seuls ceux fournis par l'appelant sont utilisés).
    """

    source_ip:      str | None = None
    host:           str | None = None
    log_type:       str | None = None
    severity:       str | None = None
    username:       str | None = None
    start_date:     str | None = None  # ISO 8601
    end_date:       str | None = None  # ISO 8601
    page:           int = 1
    page_size:      int = 50


def _build_query(search: SearchRequest) -> dict:
    # Remarque : le pipeline de normalisation ne produit pas de champ "destination_ip"
    # aujourd'hui (seul `host` — la machine destinataire — est disponible). Aucun filtre
    # sur une IP de destination n'est donc exposé pour éviter un filtre toujours vide.
    filters = []
    if search.source_ip:
        filters.append({"term": {"source_ip.keyword": search.source_ip}})
    if search.host:
        filters.append({"term": {"host.keyword": search.host}})
    if search.log_type:
        filters.append({"term": {"log_type.keyword": search.log_type}})
    if search.severity:
        filters.append({"term": {"severity.keyword": search.severity}})
    if search.username:
        filters.append({"match": {"raw_message": search.username}})
    if search.start_date or search.end_date:
        date_range = {}
        if search.start_date:
            date_range["gte"] = search.start_date
        if search.end_date:
            date_range["lte"] = search.end_date
        filters.append({"range": {"received_at": date_range}})

    return {"bool": {"filter": filters}} if filters else {"match_all": {}}


@router.post("")
async def search_logs(
    search: SearchRequest,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user: dict = Depends(require_role("reader")),
):
    """
    Recherche des logs selon plusieurs critères combinables : IP source/destination,
    host, type, sévérité, plage horaire, mot-clé (utilisateur/texte libre).
    Rôle requis: reader ou plus.
    """
    query = _build_query(search)
    from_offset = (search.page - 1) * search.page_size

    try:
        response = await es_client.search(
            index=settings.es_logs_index_name,
            query=query,
            from_=from_offset,
            size=search.page_size,
            sort=[{"received_at": {"order": "desc"}}],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Erreur de communication avec Elasticsearch: {exc}",
        ) from exc

    hits = response["hits"]["hits"]
    total = response["hits"]["total"]["value"]
    results = [{"id": hit["_id"], **hit["_source"]} for hit in hits]

    return {
        "total": total,
        "page": search.page,
        "page_size": search.page_size,
        "results": results,
        "logs": results,
    }


_EXPORT_COLUMNS = ["id", "timestamp", "received_at", "source_ip", "host", "log_type", "severity", "raw_message"]


async def _fetch_logs_for_export(search: SearchRequest, es_client: AsyncElasticsearch) -> list[dict]:
    query = _build_query(search)
    try:
        response = await es_client.search(
            index=settings.es_logs_index_name,
            query=query,
            size=min(search.page_size or 5000, 5000),
            sort=[{"received_at": {"order": "desc"}}],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Erreur de communication avec Elasticsearch: {exc}",
        ) from exc
    return [{"id": hit["_id"], **hit["_source"]} for hit in response["hits"]["hits"]]


@router.post("/export.csv")
async def export_logs_csv(
    search: SearchRequest,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user: dict = Depends(require_role("reader")),
):
    """Exporte les logs filtrés au format CSV. Rôle requis : reader ou plus."""
    search.page_size = search.page_size or 5000
    rows = await _fetch_logs_for_export(search, es_client)
    content = to_csv_bytes(rows, _EXPORT_COLUMNS)
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="smart-siem-logs-export.csv"'},
    )


@router.post("/export.xlsx")
async def export_logs_xlsx(
    search: SearchRequest,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user: dict = Depends(require_role("reader")),
):
    """Exporte les logs filtrés au format Excel (.xlsx). Rôle requis : reader ou plus."""
    search.page_size = search.page_size or 5000
    rows = await _fetch_logs_for_export(search, es_client)
    content = to_xlsx_bytes(rows, _EXPORT_COLUMNS, sheet_title="Logs")
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="smart-siem-logs-export.xlsx"'},
    )
