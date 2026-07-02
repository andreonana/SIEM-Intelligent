#   backend/app/api/v1/routers/retention.py
#
#   Endpoints de gestion de la politique de rétention des logs.
#
#   La rétention automatique est assurée par le scheduler APScheduler (nuit à 02:00 UTC)
#   déclenché dans le lifespan de main.py via start_retention_scheduler().
#   Ces endpoints permettent à un administrateur de :
#       - Consulter la configuration de rétention actuelle.
#       - Déclencher manuellement un nettoyage (démonstration, intervention urgente).
#
#   Rôle requis : administrator pour toutes les actions.

from datetime import datetime, timezone

from elasticsearch import AsyncElasticsearch
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.retention import run_retention_cleanup
from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/admin/retention", tags=["rétention"])


@router.get("", summary="Configuration de rétention actuelle")
async def get_retention_config(
    user: dict = Depends(require_role("administrator")),
):
    """
    Retourne la configuration de rétention configurée dans les variables d'environnement.
    Rôle requis : administrator.
    """
    return {
        "retention_days":       settings.retention_days,
        "logs_index":           settings.es_logs_index_name,
        "audit_index":          settings.es_audit_index_name,
        "scheduled_cleanup":    "02:00 UTC (quotidien)",
        "description": (
            f"Les logs plus anciens que {settings.retention_days} jours sont supprimés "
            f"automatiquement chaque nuit à 02:00 UTC. "
            f"Cet endpoint permet de déclencher ce nettoyage manuellement."
        ),
    }


@router.post("/run", summary="Déclencher manuellement la rétention des logs")
async def trigger_retention_manually(
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user:      dict = Depends(require_role("administrator")),
):
    """
    Déclenche immédiatement la suppression des logs antérieurs à settings.retention_days.
    N'attend pas le job nocturne automatique.
    Rôle requis : administrator.

    L'opération est tracée dans l'index d'audit avec le username de l'administrateur.
    """
    try:
        result = await run_retention_cleanup(es_client=es_client)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Erreur lors du nettoyage : {exc}",
        ) from exc

    now = datetime.now(timezone.utc).isoformat()

    # Trace supplémentaire dans l'audit pour identifier l'administrateur déclencheur.
    # (run_retention_cleanup écrit déjà un audit "system" — on ajoute la trace humaine)
    try:
        await es_client.index(
            index=settings.es_audit_index_name,
            document={
                "action":          "manual_retention_trigger",
                "triggered_by":    user["username"],
                "timestamp":       now,
                "deleted":         result["deleted"],
                "cutoff":          result["cutoff"],
                "retention_days":  result["retention_days"],
            },
        )
    except Exception:
        pass  # Audit best-effort

    return {
        "status":           "nettoyage terminé",
        "triggered_by":     user["username"],
        "triggered_at":     now,
        "deleted":          result["deleted"],
        "cutoff":           result["cutoff"],
        "retention_days":   result["retention_days"],
    }