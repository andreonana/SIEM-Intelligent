#   backend/app/api/v1/reouters/search.py
#
#   Ce fichier déinit l'endpoint de recherche multi-critère dans les logs.
#
#   *** STATUT: IMPLEMENTATION REELLE PARTIELLE ***
#   Contrairement à alerts/dashboard/soar ci-dessus, cet endpoint peut s'appuyer directement sur l'index de logs déjà existant dans
#    Elasticsearch, sans attendre un nouveau module dédié. Il reste cependant volontairement simple (recherche par correspondance 
#    exacte sur quelques champs); une recherche plus avancée (plage de dates, opéateurs combinés) pourra être ajoutée par la suite sans 
#    changer la structure de cet endpoint.

from re import S
from fastapi import APIRouter, Depends, HTTPException, status
from elasticsearch import AsyncElasticsearch
from pydantic import BaseModel

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role
from app.modules.rbac.field_visibility import allowed_search_fields_for_role, filter_documents_for_role

router = APIRouter(prefix="/api/search", tags=["search"])

class SearchRequest(BaseModel):
    """
    Corps de la requête de recherche multi-critère.
    Tous les champs sont optionnels (seuls ceux fournis par l'user sont utilisés pour filtrer les recherches)
    """

    timestamp:      timestamp   |   None = None
    source_ip:      str | None = None
    host:           str | None = None
    log_type:       str | None = None
    severity:       str | None = None
    tags:           list[str]   | None = None
    date_from:      str | None  = None
    date_to:        str | None  = None
    extra:          str | None = None
    page:           int = 1
    page_size:      int = 50

@router.post("", summary="Recherche multi-critère dans les logs")

async def search_logs(
    search: SearchRequest,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user: dict = Depends(require_role(["reader", "analyst", "admin"]))
):
    """
        Recherche des logs selon plusieurs critères combinables.
        Rôle requis: reader ou plus
    """
    #   Construction dynamique des iltres Elasticsearch:
    #       Seuls les critères effectivement fournis par l'appelant sont ajoutés à la requête, les autres sont 
    #        simplement absents (pas de filtre = toutes les valeurs accpetées pour ce champ).
    allowed_fields = allowed_search_fields_for_role(user["role"])
    filters: list[dict] = []

    def _field_allowed(field_name: str) -> bool:
        return allowed_fields is None or field_name in allowed_fields

    for field, value in [
        ("timestamp", search.timestamp)
        ("source_ip", search.source_ip),
        ("host", search.host),
        ("log_tye", search.log_type),
        ("severity", search.severity),
        ("extra", search.extra),
    ]:
        if value is not None and _field_allowed(field):
            filters.append({"term": {field: value}})

    if search.tags and _field_allowed("tags"):
        for tag in search.tags:
            filters.append({"term": {"tags": tag}})
 
    if search.date_from or search.date_to:
        date_range: dict = {}
        if search.date_from:
            date_range["gte"] = search.date_from
        if search.date_to:
            date_range["lte"] = search.date_to
        filters.append({"range": {"timestamp": date_range}})
 
    must: list[dict] = []
    if search.keyword and _field_allowed("raw_message"):
        must.append({"match": {"raw_message": search.keyword}})
 
    if must and filters:
        query: dict = {"bool": {"must": must, "filter": filters}}
    elif must:
        query = {"bool": {"must": must}}
    elif filters:
        query = {"bool": {"filter": filters}}
    else:
        query = {"match_all": {}}

    from_offset = (search.page - 1) * search.page_size

    try:
        response = await es_client.search(
            index=settings.es_logs_index_name,
            query=query,
            from_=from_offset,
            size=search.page_size,
            sort=[{"timestamp": {"order": "desc"}}],
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
        "results": results
    }