# backend/app/api/v1/routers/correlation.py
#
# Endpoint de déclenchement manuel du moteur de corrélation.

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role
from app.modules.correlation.engine import run_correlation
from app.services.audit_service import log_action

router = APIRouter(prefix="/api/correlation", tags=["correlation"])


class CorrelationRunBody(BaseModel):
    window_minutes: int = 30


@router.post("/run")
async def run_correlation_endpoint(
    body: CorrelationRunBody = CorrelationRunBody(),
    user: dict = Depends(require_role("administrator")),
    db: AsyncSession = Depends(get_db),
):
    """Déclenche manuellement un scan de corrélation sur la fenêtre temporelle indiquée."""
    es = get_es_client()
    summary = await run_correlation(db, es, window_minutes=body.window_minutes)
    await log_action(
        db=db,
        username=user["username"],
        role=user.get("role"),
        action="correlation_run",
        detail=f"window_minutes={body.window_minutes}, result={summary}",
    )
    return {"triggered_by": user["username"], **summary}
