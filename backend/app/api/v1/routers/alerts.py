#   backend/app/api/v1/routers/alerts.py
#
#   Ce fichier définit les endpoints liés aux alertes de sécurité.
#
#   *** STATUT: SQUELETTE FONCTIONNEL   ***
#   Les endpoints d'ici permet au frontend de commencer son intégration dès maintenant, sans attendre 
#    que le module d'alerting soit terminé.
#
#   A COMPLETER LORS DU DEBUT DE SEMAINE 3

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

_VALID_STATUSES = {"ouvert", "acquité", "fermé"}

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

@router.get("", summary="Liste des alertes")

async def get_all_alerts(
    page:       int = Query(1, ge=1),
    page_size:  int = Query(50, ge=1, le=200),
    statut:     str = Query(None, description="Filtrer par défaut: ouvert | acquité |fermé"),
    severity:   str = Query(None, description="Filtrer par severity: CRITICAL | WARNING | INFO"),
    es_client:  AsyncElasticsearch = Depends(get_es_client),
    user: dict = Depends(require_role("reader")),
):
    """
        Retourne la liste des alertes actives.
        Rôle requis: reader ou plus.
        Filtres optionnels: statut, severity.
    """
    filters: list[dict] = []
    if statut:
        filters.append({"term": {"status": statut}})
    if severity:
        filters.append({"term": {"severity": severity.upper()}})

    query   = {"bool": {"filter": filters}} if filters else {"match_all": {}}
    offset  = (page - 1)*page_size
    
    try:
        response = await es_client.search(
            index=settings.es_alerts_index_name,
            query=query,
            from_=offset,
            size=page_size,
            sort=[{"detected_at": {"order": "desc"}}],
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Elasticsearch indisponible: {exc}") from exc

    total   = response["hits"]["total"]["value"]
    alerts  = [{"id": hit["_id"], **hit["_source"]} for hit in response["hits"]["hits"]]

    return {"total": total, "page": page, "page_size": page_size, "alerts": alerts}

@router.get("/{alert_id}", summary="Détail d'une alerte")

async def get_alert(alert_id: str, es_client: AsyncElasticsearch = Depends(get_es_client) ,user: dict = Depends(require_role("reader"))):
    """
        Retourne une alerte précise par son identifiant.
        Rôle requis: reader ou plus
    """
    try:
        resp = await es_client.get(index=settings.es_alerts_index_name, id=alert_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(f"Aucune alerte trouvéd avec l'identifiant '{alert_id}'."),
        )

    return {"id": resp["_id"], **resp["_source"]}

async def _update_alert_status(
    es_client:  AsyncElasticsearch,
    alert_id:   str,
    new_status: str,
    updated_by: str,
) -> dict:
    """
        Met à jour le statut d'une alerte et retourne le document mis à jour.
    """
    try:
        await es_client.update(
            index=settings.es_alerts_index_name,
            id=alert_id,
            doc={
                "status":       new_status,
                "updated_by":   updated_by,
                "updated_at":   _now(),
            },
        )
        resp = await es_client.get(index=settings.es_alerts_index_name, id=alert_id)
        return {"id": resp["_id"], **resp["_source"]}
    except Exception:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alerte `{alert_id}` introuvable.")


@router.post("/{alert_id}/acknowledge", summary="Acquitter une alerte")

async def acknowledge_alert(
    alert_id:   str, 
    es_client:  AsyncElasticsearch = Depends(get_es_client),
    user:       dict = Depends(require_role("analyst"))
):
    """
        Marque une alerte comme prise en compte (acquité) par un analyste.
        Rôle requis: Analyst ou plus
    """
    return await _update_alert_status(es_client, alert_id, "acquité", user["username"])


@router.post("/{alert_id}/close", summary="Fermer une alerte")

async def close_alert(
    alert_id:   str,
    es_client:  AsyncElasticsearch = Depends(get_es_client),
    user:       dict = Depends(require_role("analyst"))
):
    """
        Ferme une alerte (investigation terminée, faux positif, résolu).
        Rôle requis: analyst ou plus.
    """
    return await _update_alert_status(es_client, alert_id, "fermé", user["username"])


@router.post("/{alert_id}/reopen", summary="Réouvrir une laerte fermée.")

async def reopen_alert(
    alert_id:   str,
    es_client:  AsyncElasticsearch = Depends(get_es_client),
    user:       dict = Depends(require_role("analyst")),
):
    """
        Remet une alerte fermée ou acquittée en statut "ouvert".
        Rôle requis:    analyst ou plus.
    """
    return await _update_alert_status(es_client, alert_id, "ouvert", user["username"])