# backend/app/api/v1/routers/soar.py
#
# Endpoints SOAR V3 :
#   GET  /api/soar/playbooks                         — liste des playbooks disponibles
#   POST /api/soar/playbooks/{playbook_id}/run       — déclenchement manuel
#   GET  /api/soar/scheduled                         — exécutions CONFIRM planifiées
#   DELETE /api/soar/scheduled/{execution_id}        — annulation d'une exécution CONFIRM

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.playbook_execution import PlaybookExecution
from app.modules.rbac.roles import require_role
from app.modules.soar.dispatcher import cancel_scheduled_execution
from app.modules.soar.playbooks import PLAYBOOKS, run_playbook
from app.services.audit_service import log_action

router = APIRouter(prefix="/api/soar", tags=["soar"])


class RunPlaybookBody(BaseModel):
    alert_id: int | None = None
    params: dict = {}


@router.get("/playbooks")
async def get_playbooks(user: dict = Depends(require_role("analyst"))):
    """Liste les playbooks SOAR disponibles."""
    return {"total": len(PLAYBOOKS), "playbooks": list(PLAYBOOKS.values())}


@router.post("/playbooks/{playbook_id}/run")
async def run_playbook_endpoint(
    playbook_id: str,
    body: RunPlaybookBody = RunPlaybookBody(),
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Déclenche manuellement l'exécution d'un playbook (mode MANUAL)."""
    if playbook_id not in PLAYBOOKS:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' introuvable.")

    params = dict(body.params)
    if body.alert_id is not None:
        params["alert_id"] = body.alert_id

    try:
        result = await run_playbook(
            playbook_id=playbook_id,
            params=params,
            triggered_by=user["username"],
            db=db,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        await log_action(db, user["username"], "playbook_run", target=playbook_id, result="failure", detail=str(e), role=user.get("role"))
        raise HTTPException(status_code=500, detail=f"Erreur playbook: {e}")

    return {"playbook_id": playbook_id, "triggered_by": user["username"], "result": result}


@router.get("/scheduled")
async def list_scheduled_executions(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Liste les exécutions de playbooks planifiées en mode CONFIRM.
    Inclut : status=scheduled | success | failure | cancelled.
    """
    offset = (page - 1) * page_size
    result = await db.execute(
        select(PlaybookExecution)
        .where(PlaybookExecution.soar_mode == "CONFIRM")
        .order_by(desc(PlaybookExecution.scheduled_at))
        .offset(offset)
        .limit(page_size)
    )
    executions = result.scalars().all()
    return {
        "page": page,
        "page_size": page_size,
        "executions": [e.to_dict() for e in executions],
    }


@router.delete("/scheduled/{execution_id}")
async def cancel_execution(
    execution_id: int,
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Annule une exécution CONFIRM planifiée avant qu'elle ne s'exécute.
    Retourne une erreur si l'exécution n'est pas en statut 'scheduled'.
    """
    result = await cancel_scheduled_execution(db, execution_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Annulation impossible."))
    await log_action(
        db, user["username"], "soar_cancel",
        target=f"execution/{execution_id}",
        detail="Annulé manuellement via API",
        role=user.get("role"),
    )
    return result
