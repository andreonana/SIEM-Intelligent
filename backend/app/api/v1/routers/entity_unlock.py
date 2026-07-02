#   backend/app/api/v1/routers/entity_unlock.py
#
#   Endpoints de gestion des entités en quarantaine (lockout SOAR).
#
#   La quarantaine est déclenchée automatiquement par certaines règles de corrélation
#   (BruteForceRule, BusinessHoursRule, UnauthorizedPrivilegesRule) via lockout_service.
#   Seul un administrateur peut lever manuellement une quarantaine.
#
#   *** RÈGLE MÉTIER ***
#   - Consulter la liste / l'historique des entités bloquées : analyst ou plus.
#   - Libérer une entité de quarantaine : administrator uniquement.
#     La levée est tracée dans l'index d'audit (qui l'a fait et quand).
#
#   Deux types d'entités gérées :
#       - "source_ip" : adresse IP source bloquée.
#       - "host"      : machine ou compte visé bloqué.

from datetime import datetime, timezone

from elasticsearch import AsyncElasticsearch
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client
from app.modules.correlation.lockout_service import (
    is_entity_locked,
    list_all_lockout_history,
    list_locked_entities,
    unlock_entity,
)
from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/lockouts", tags=["lockouts"])

_VALID_ENTITY_TYPES: frozenset[str] = frozenset({"source_ip", "host"})


# ─────────────────────────────────────────────────────────────────────────────
#   Consultation
# ─────────────────────────────────────────────────────────────────────────────

@router.get("", summary="Entités actuellement en quarantaine")
async def get_locked_entities(
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user:      dict = Depends(require_role("analyst")),
):
    """
    Retourne la liste de toutes les entités actuellement bloquées (locked=True).
    Rôle requis : analyst ou plus.
    """
    entities = await list_locked_entities(es_client)
    return {"total": len(entities), "entities": entities}


@router.get("/history", summary="Historique complet des quarantaines")
async def get_lockout_history(
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user:      dict = Depends(require_role("analyst")),
):
    """
    Retourne l'historique complet des quarantaines (actives et levées).
    Utile pour l'audit post-incident.
    Rôle requis : analyst ou plus.
    """
    history = await list_all_lockout_history(es_client)
    return {"total": len(history), "history": history}


@router.get("/{entity_type}/{entity_value}", summary="Statut de quarantaine d'une entité")
async def get_entity_lockout_status(
    entity_type:  str,
    entity_value: str,
    es_client:    AsyncElasticsearch = Depends(get_es_client),
    user:         dict = Depends(require_role("analyst")),
):
    """
    Indique si une entité précise est actuellement en quarantaine.
    Rôle requis : analyst ou plus.

    Paramètres :
        entity_type  : "source_ip" ou "host".
        entity_value : valeur de l'entité (ex. "192.168.1.50" ou "srv-web-01").
    """
    if entity_type not in _VALID_ENTITY_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Type d'entité invalide : '{entity_type}'. Valeurs acceptées : {sorted(_VALID_ENTITY_TYPES)}.",
        )

    locked = await is_entity_locked(es_client, entity_type, entity_value)
    return {
        "entity_type":  entity_type,
        "entity_value": entity_value,
        "locked":       locked,
    }


# ─────────────────────────────────────────────────────────────────────────────
#   Libération de quarantaine (administrator uniquement)
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/{entity_type}/{entity_value}/unlock",
    summary="Libérer une entité de quarantaine",
)
async def unlock_locked_entity(
    entity_type:  str,
    entity_value: str,
    es_client:    AsyncElasticsearch = Depends(get_es_client),
    user:         dict = Depends(require_role("administrator")),
):
    """
    Lève la quarantaine d'une entité (IP source ou machine/compte).
    Cette action est irréversible côté API — si une nouvelle détection se produit,
    l'entité sera re-bloquée automatiquement.
    Rôle requis : administrator.

    L'action est tracée dans l'index d'audit (administrateur + horodatage).

    Paramètres :
        entity_type  : "source_ip" ou "host".
        entity_value : valeur exacte de l'entité.
    """
    if entity_type not in _VALID_ENTITY_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Type d'entité invalide : '{entity_type}'. Valeurs acceptées : {sorted(_VALID_ENTITY_TYPES)}.",
        )

    # Vérification préalable : l'entité est-elle réellement bloquée ?
    currently_locked = await is_entity_locked(es_client, entity_type, entity_value)
    if not currently_locked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"L'entité {entity_type}='{entity_value}' n'est pas en quarantaine "
                f"ou n'a jamais été bloquée."
            ),
        )

    success = await unlock_entity(
        es_client,
        entity_type=entity_type,
        entity_value=entity_value,
        unlocked_by=user["username"],
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Impossible de mettre à jour Elasticsearch. Réessayez.",
        )

    now = datetime.now(timezone.utc).isoformat()

    # Trace dans l'index d'audit
    try:
        await es_client.index(
            index=settings.es_audit_index_name,
            document={
                "action":       "entity_unlock",
                "entity_type":  entity_type,
                "entity_value": entity_value,
                "unlocked_by":  user["username"],
                "timestamp":    now,
            },
        )
    except Exception:
        pass  # L'audit est best-effort — ne pas bloquer la réponse si ES est lent

    return {
        "message":      f"Entité {entity_type}='{entity_value}' libérée de quarantaine.",
        "entity_type":  entity_type,
        "entity_value": entity_value,
        "unlocked_by":  user["username"],
        "unlocked_at":  now,
    }