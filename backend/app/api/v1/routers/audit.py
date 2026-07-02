# backend/app/api/v1/routers/audit.py
#
# Lecture du journal d'audit.
# Source principale : table SQL audit_logs (actions utilisateurs).
# Accès réservé aux administrators.

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.modules.rbac.roles import require_role
from app.services.audit_service import get_audit_logs

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
async def get_audit_log(
    page:            int            = Query(1, ge=1),
    page_size:       int            = Query(50, ge=1, le=500),
    username_filter: str | None     = Query(None),
    action_filter:   str | None     = Query(None),
    user:            dict           = Depends(require_role("administrator")),
    db:              AsyncSession   = Depends(get_db),
):
    """
    Retourne le journal d'audit des actions utilisateurs (du plus récent au plus ancien).
    Filtrable par username et par action.
    Rôle requis : administrator.
    """
    return await get_audit_logs(
        db,
        page=page,
        page_size=page_size,
        username_filter=username_filter,
        action_filter=action_filter,
    )
