# backend/app/modules/rbac/retention.py
#
# Politique de rétention des logs — purge ES + audit SQL.
# La durée de rétention est lue depuis settings (RETENTION_DAYS dans .env).
# L'audit de chaque purge est écrit en base SQL (audit_logs) ET signalé dans les logs applicatifs.
# Contrôlable via ENABLE_RETENTION_SCHEDULER=false pour les tests.

import asyncio
import logging
from datetime import datetime, timezone, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from elasticsearch import Elasticsearch, NotFoundError
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.modules.rbac.roles import require_role
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)

router = APIRouter()

INDEX_LOGS = settings.es_logs_index_name
RETENTION_DAYS = settings.retention_days

# Client Elasticsearch synchrone (APScheduler ne supporte pas l'async natif)
_es_kwargs: dict = {"hosts": [settings.elasticsearch_url]}
if settings.elasticsearch_username and settings.elasticsearch_password:
    _es_kwargs["basic_auth"] = (settings.elasticsearch_username, settings.elasticsearch_password)
if settings.elasticsearch_ca_cert_path:
    _es_kwargs["ca_certs"] = settings.elasticsearch_ca_cert_path
    _es_kwargs["verify_certs"] = True
else:
    _es_kwargs["verify_certs"] = False

_es_client: Elasticsearch | None = None


def _get_es() -> Elasticsearch:
    global _es_client
    if _es_client is None:
        _es_client = Elasticsearch(**_es_kwargs)
    return _es_client


def run_retention_cleanup(triggered_by: str = "system") -> dict:
    """
    Supprime dans Elasticsearch les logs antérieurs à RETENTION_DAYS jours.
    Écrit l'entrée d'audit en base SQL (via une boucle asyncio dédiée).
    Retourne un résumé de l'opération.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    deleted = 0
    error: str | None = None

    try:
        es = _get_es()
        response = es.delete_by_query(
            index=INDEX_LOGS,
            body={"query": {"range": {"timestamp": {"lt": cutoff.isoformat()}}}},
        )
        deleted = response.get("deleted", 0)
        logger.info("[retention] Purge terminée : %d documents supprimés (cutoff=%s)", deleted, cutoff.isoformat())
    except NotFoundError:
        logger.warning("[retention] Index '%s' introuvable — aucun log à purger.", INDEX_LOGS)
    except Exception as exc:
        error = str(exc)
        logger.error("[retention] Échec de la purge ES : %s", error)

    # Audit SQL — persisté indépendamment de l'état d'Elasticsearch
    detail = f"cutoff={cutoff.date().isoformat()}, retention={RETENTION_DAYS}j, supprimés={deleted}"
    if error:
        detail += f", erreur={error}"

    async def _write_audit() -> None:
        async with AsyncSessionLocal() as db:
            await log_action(
                db,
                username=triggered_by,
                action="retention_cleanup",
                target=INDEX_LOGS,
                detail=detail,
                result="failure" if error else "success",
            )

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_write_audit())
    finally:
        loop.close()

    return {
        "deleted": deleted,
        "cutoff": cutoff.isoformat(),
        "retention_days": RETENTION_DAYS,
        "error": error,
    }


def start_retention_scheduler() -> None:
    """
    Démarre le job APScheduler de purge quotidienne à 02h00.
    Désactivable via ENABLE_RETENTION_SCHEDULER=false dans .env (utile pour les tests).
    """
    if not settings.enable_retention_scheduler:
        logger.info("[retention] Scheduler désactivé (ENABLE_RETENTION_SCHEDULER=false).")
        return

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_retention_cleanup,
        trigger="cron",
        hour=2,
        minute=0,
        id="daily_retention_cleanup",
        kwargs={"triggered_by": "system"},
    )
    scheduler.start()
    logger.info("[retention] Scheduler démarré — purge quotidienne à 02:00 UTC.")


@router.post(
    "/api/admin/retention/run",
    tags=["Security"],
    summary="Déclenche manuellement la purge de rétention des logs",
)
async def trigger_retention_manually(
    request: Request,
    user: dict = Depends(require_role("administrator")),
    db: AsyncSession = Depends(lambda: None),  # injection db pour l'audit direct
):
    """
    Déclenche la purge de rétention immédiatement.
    Réservé aux administrators. L'action est auditée en base SQL.
    """
    result = run_retention_cleanup(triggered_by=user["username"])
    return {
        "status": "purge terminée" if not result["error"] else "purge échouée",
        "triggered_by": user["username"],
        **result,
    }
