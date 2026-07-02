# backend/app/modules/soar/dispatcher.py
#
# Dispatcher SOAR — gère les modes AUTO, CONFIRM et MANUAL.
#
# AUTO   : exécute le playbook immédiatement après création de l'alerte.
# CONFIRM: planifie l'exécution via APScheduler après confirm_delay_seconds (défaut 60s).
#          L'exécution peut être annulée via DELETE /api/soar/scheduled/{execution_id}.
# MANUAL : aucun déclenchement automatique (comportement historique).
#
# Ce module est appelé par le moteur de corrélation (engine.py) après create_alert().
# Il ne crash jamais la création d'alerte : toute erreur SOAR est loguée et absorbée.

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.playbook_execution import PlaybookExecution
from app.modules.soar.playbooks import run_playbook
from app.services.audit_service import log_action

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Référence globale au scheduler APScheduler (injecté depuis main.py au démarrage)
_scheduler = None


def set_scheduler(scheduler) -> None:
    """Injecte le scheduler APScheduler depuis main.py."""
    global _scheduler
    _scheduler = scheduler


def get_scheduler():
    return _scheduler


# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------

async def dispatch_soar(
    db: AsyncSession,
    alert: Alert,
    soar_action: str,
    soar_mode: str,
    confirm_delay_seconds: int,
    confidence_score: float,
) -> None:
    """
    Déclenche ou planifie le playbook associé à l'alerte selon le mode SOAR.

    Args:
        db:                     Session SQLAlchemy async.
        alert:                  Alerte nouvellement créée.
        soar_action:            Identifiant du playbook (block_ip, escalate_admin, etc.).
        soar_mode:              AUTO | CONFIRM | MANUAL.
        confirm_delay_seconds:  Délai avant exécution en mode CONFIRM.
        confidence_score:       Score de confiance de la règle (0-100).
    """
    if soar_mode == "MANUAL":
        logger.debug("[SOAR] Mode MANUAL — pas de déclenchement automatique (alert_id=%s)", alert.id)
        return

    params = {
        "alert_id":         alert.id,
        "ip":               alert.source_ip or "",
        "reason":           alert.description[:200],
        "severity":         alert.severity,
        "confidence_score": confidence_score,
    }

    try:
        if soar_mode == "AUTO":
            await _execute_auto(db, alert, soar_action, params)
        elif soar_mode == "CONFIRM":
            await _schedule_confirm(db, alert, soar_action, params, confirm_delay_seconds)
        else:
            logger.warning("[SOAR] Mode inconnu '%s' pour alert_id=%s — ignoré", soar_mode, alert.id)
    except Exception as exc:
        # Ne jamais faire crasher la création d'alerte si SOAR échoue
        logger.error("[SOAR] Erreur dispatch pour alert_id=%s: %s", alert.id, exc, exc_info=True)


# ---------------------------------------------------------------------------
# Mode AUTO : exécution immédiate
# ---------------------------------------------------------------------------

async def _execute_auto(
    db: AsyncSession,
    alert: Alert,
    playbook_id: str,
    params: dict,
) -> None:
    logger.info("[SOAR/AUTO] Déclenchement immédiat: playbook=%s alert_id=%s", playbook_id, alert.id)

    # Marquer l'alerte comme "en cours d'exécution"
    alert.soar_status = "executing"
    await db.commit()

    result = await run_playbook(
        playbook_id=playbook_id,
        params=params,
        triggered_by="system_auto",
        db=db,
    )

    alert.soar_status = "executed"
    await db.commit()

    await log_action(
        db=db,
        username="system_auto",
        action="soar_auto_executed",
        target=f"alert/{alert.id}",
        detail=json.dumps({"playbook": playbook_id, "result": result}),
    )
    logger.info("[SOAR/AUTO] Exécution terminée: playbook=%s alert_id=%s result=%s", playbook_id, alert.id, result)


# ---------------------------------------------------------------------------
# Mode CONFIRM : exécution différée via APScheduler
# ---------------------------------------------------------------------------

async def _schedule_confirm(
    db: AsyncSession,
    alert: Alert,
    playbook_id: str,
    params: dict,
    delay_seconds: int,
) -> None:
    run_at = datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)

    # Créer un enregistrement PlaybookExecution avec status="scheduled"
    execution = PlaybookExecution(
        playbook_id=playbook_id,
        alert_id=alert.id,
        triggered_by="system_confirm",
        params=json.dumps(params),
        result=None,
        status="scheduled",
        soar_mode="CONFIRM",
        scheduled_at=run_at,
        executed_at=datetime.now(timezone.utc),
    )
    db.add(execution)
    await db.commit()
    await db.refresh(execution)

    execution_id = execution.id

    alert.soar_status = "scheduled"
    await db.commit()

    await log_action(
        db=db,
        username="system_confirm",
        action="soar_confirm_scheduled",
        target=f"alert/{alert.id}",
        detail=json.dumps({
            "playbook": playbook_id,
            "execution_id": execution_id,
            "scheduled_at": run_at.isoformat(),
            "delay_seconds": delay_seconds,
        }),
    )

    logger.info(
        "[SOAR/CONFIRM] Planifié: playbook=%s alert_id=%s execution_id=%s run_at=%s",
        playbook_id, alert.id, execution_id, run_at.isoformat(),
    )

    # Planifier via APScheduler si disponible, sinon asyncio.ensure_future
    if _scheduler is not None:
        _scheduler.add_job(
            _run_scheduled_execution,
            "date",
            run_date=run_at,
            args=[execution_id, playbook_id, params],
            id=f"soar_confirm_{execution_id}",
            replace_existing=True,
        )
    else:
        # Fallback asyncio si scheduler non disponible (ex: tests)
        asyncio.ensure_future(_async_delayed_execution(
            execution_id, playbook_id, params, delay_seconds
        ))


def _run_scheduled_execution(execution_id: int, playbook_id: str, params: dict) -> None:
    """
    Callback APScheduler (synchrone) — crée une session DB et lance le playbook.
    APScheduler 3.x ne supporte pas les coroutines nativement avec BackgroundScheduler.
    """
    import asyncio
    from app.db.database import AsyncSessionLocal

    async def _inner():
        async with AsyncSessionLocal() as db:
            await _finalize_confirm_execution(db, execution_id, playbook_id, params)

    # Exécuter dans un event loop
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(_inner())
        else:
            loop.run_until_complete(_inner())
    except RuntimeError:
        asyncio.run(_inner())


async def _async_delayed_execution(
    execution_id: int, playbook_id: str, params: dict, delay_seconds: int
) -> None:
    """Fallback asyncio pour exécution différée sans APScheduler."""
    await asyncio.sleep(delay_seconds)
    from app.db.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        await _finalize_confirm_execution(db, execution_id, playbook_id, params)


async def _finalize_confirm_execution(
    db: AsyncSession,
    execution_id: int,
    playbook_id: str,
    params: dict,
) -> None:
    """Exécute réellement le playbook pour une exécution CONFIRM planifiée."""
    from sqlalchemy import select
    from app.models.alert import Alert as AlertModel

    # Récupérer l'exécution planifiée
    exec_result = await db.execute(
        select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
    )
    execution = exec_result.scalar_one_or_none()

    if execution is None:
        logger.error("[SOAR/CONFIRM] execution_id=%s introuvable", execution_id)
        return

    if execution.status == "cancelled":
        logger.info("[SOAR/CONFIRM] execution_id=%s annulée — pas d'exécution", execution_id)
        return

    logger.info("[SOAR/CONFIRM] Exécution différée: execution_id=%s playbook=%s", execution_id, playbook_id)

    try:
        result = await run_playbook(
            playbook_id=playbook_id,
            params=params,
            triggered_by="system_confirm",
            db=db,
        )
        execution.status = "success"
        execution.result = json.dumps(result)
    except Exception as exc:
        logger.error("[SOAR/CONFIRM] Erreur exécution: %s", exc)
        execution.status = "failure"
        execution.result = json.dumps({"error": str(exc)})

    execution.executed_at = datetime.now(timezone.utc)
    await db.commit()

    # Mettre à jour le soar_status de l'alerte
    if params.get("alert_id"):
        alert_result = await db.execute(
            select(AlertModel).where(AlertModel.id == params["alert_id"])
        )
        alert = alert_result.scalar_one_or_none()
        if alert:
            alert.soar_status = "executed" if execution.status == "success" else "failed"
            await db.commit()

    await log_action(
        db=db,
        username="system_confirm",
        action="soar_confirm_executed",
        target=f"execution/{execution_id}",
        detail=json.dumps({"playbook": playbook_id, "status": execution.status}),
    )


# ---------------------------------------------------------------------------
# Annulation d'une exécution planifiée
# ---------------------------------------------------------------------------

async def cancel_scheduled_execution(db: AsyncSession, execution_id: int) -> dict:
    """
    Annule une exécution CONFIRM planifiée.
    Retourne dict avec le résultat de l'annulation.
    """
    from sqlalchemy import select

    exec_result = await db.execute(
        select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
    )
    execution = exec_result.scalar_one_or_none()

    if execution is None:
        return {"success": False, "error": f"execution_id={execution_id} introuvable"}

    if execution.status != "scheduled":
        return {"success": False, "error": f"L'exécution est en statut '{execution.status}', non annulable."}

    execution.status = "cancelled"
    await db.commit()

    # Retirer du scheduler APScheduler si possible
    if _scheduler is not None:
        job_id = f"soar_confirm_{execution_id}"
        try:
            _scheduler.remove_job(job_id)
        except Exception:
            pass  # Le job peut déjà s'être exécuté

    # Mettre à jour l'alerte associée
    if execution.alert_id:
        alert_result = await db.execute(
            select(Alert).where(Alert.id == execution.alert_id)
        )
        alert = alert_result.scalar_one_or_none()
        if alert and alert.soar_status == "scheduled":
            alert.soar_status = "cancelled"
            await db.commit()

    await log_action(
        db=db,
        username="system",
        action="soar_confirm_cancelled",
        target=f"execution/{execution_id}",
    )

    return {"success": True, "execution_id": execution_id, "status": "cancelled"}
