#   backend/app/api/v1/routers/audit.py
#
#   Ce fichier définit l'endpoint de consolidation du jeu définit d'audit (Qui a fait quoi et quand dans le système).
#   *** STATUT: PARTIELLEMENT FONCTIONNEL   ***
#   Le fichier retention.py, écrit dèjà des entrées d'audit dans un index Elasticsearch dédié (settings.es_audit_index_name)
#    à chaque exécutiondu nettoyage de retention.
#   Cet endpoint expose la lecture de ces entrées déjà produites. La journalisation des autres actions utilisateurs (connexion,
#    déconnexion, consultation déalerte...) n'est pas encore implémentée

from fastapi import APIRouter, Depends, HTTPException, Query, status
from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/audit", tags=["audit"])

@router.get("", summary="Journal d'audit système")

async def get_audit_log(
    page:       int = Query(1, ge=1),
    page_size:  int = Query(50, ge=1, le=200),
    action:     str = Query(
        None,
        description=("Filtrer par type d'action: retention_cleanup | rule_config_update | retention_trigger | manual_retention_trigger | entity_unlock | tag_severity_update | ..."),
    ),
    es_client:  AsyncElasticsearch = Depends(get_es_client),
    user:       dict = Depends(require_role("administrator")),
):
    """
        Retourne le journal d'audit des actions effectuées dans le système, du plus récent au plus ancien.
        Rôle requis: administrator
    """
    from_offset = (page - 1)*page_size

    filters: list[dict] = []
    if action:
        filters.append({"term": {"action": action}})
    
    query = {"bool": {"filter": filters}} if filters else {"match_all": {}}

    try:
        response = await es_client.search(
            index=settings.es_audit_index_name,
            query={"match_all": {}},
            from_=from_offset,
            size=page_size,
            sort=[{"timestamp": {"order": "desc"}}],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Erreur de communication avec Elasticsearch: {exc}",
        ) from exc

    hits    = response["hits"]["hits"]
    total   = response["hits"]["total"]["value"]
    entries = [{"id": hit["_id"], **hit["_source"]} for hit in hits]

    return {
        "total":        total, 
        "page":         page, 
        "page_size":    page_size, 
        "entries":      entries,
    }