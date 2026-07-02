# backend/app/api/v1/routers/integrity.py
#
# Endpoints de chaîne de custody SHA-256.
# GET  /api/integrity/batches             — liste des batches
# GET  /api/integrity/batches/{batch_id}  — détail d'un batch
# POST /api/integrity/verify/{batch_id}   — vérification d'intégrité

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.modules.rbac.roles import require_role
from app.services.integrity_service import list_batches, get_batch, verify_batch

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/integrity", tags=["integrity"])


class VerifyRequest(BaseModel):
    logs: list[dict]  # Liste des logs originaux à re-hasher


@router.get("/batches")
async def get_batches(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Liste paginée des batches de logs avec leur hash SHA-256."""
    return await list_batches(db, page=page, page_size=page_size)


@router.get("/batches/{batch_id}")
async def get_batch_detail(
    batch_id: str,
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Détail d'un batch : hash SHA-256, parent, source, log_count."""
    batch = await get_batch(db, batch_id)
    if batch is None:
        raise HTTPException(status_code=404, detail=f"Batch '{batch_id}' introuvable.")
    return batch.to_dict()


@router.post("/verify/{batch_id}")
async def verify_batch_integrity(
    batch_id: str,
    body: VerifyRequest,
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Vérifie l'intégrité d'un batch en recalculant son SHA-256 à partir des logs fournis.
    Retourne {valid, hash_valid, chain_valid, stored_sha256, computed_sha256}.
    """
    result = await verify_batch(db, batch_id, body.logs)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result
