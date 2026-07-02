# backend/app/services/integrity_service.py
#
# Service de chaîne de custody SHA-256.
# Chaque batch d'ingestion est haché, chainé au précédent et stocké en SQL.

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.log_batch import LogBatch

logger = logging.getLogger(__name__)

# Hash vide : parent du premier batch
_GENESIS_HASH = "0" * 64


async def _get_last_sha256(db: AsyncSession) -> str:
    """Retourne le SHA-256 du dernier batch enregistré, ou le hash genesis."""
    result = await db.execute(
        select(LogBatch).order_by(desc(LogBatch.id)).limit(1)
    )
    last = result.scalar_one_or_none()
    return last.sha256 if last else _GENESIS_HASH


def _compute_sha256(logs: list[dict], batch_id: str, parent_sha256: str) -> str:
    """
    Calcule le SHA-256 du batch.
    Contenu haché : JSON canonique (trié, sans espaces) de
    {batch_id, parent_sha256, logs} — déterministe et reproductible.
    """
    payload = {
        "batch_id":     batch_id,
        "parent_sha256": parent_sha256,
        "logs":         logs,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def record_batch(
    db: AsyncSession,
    logs: list[dict],
    source: str = "ingestion_api",
) -> LogBatch:
    """
    Enregistre un batch de logs dans la chaîne de custody.
    Retourne l'enregistrement LogBatch créé.
    """
    batch_id = str(uuid.uuid4())
    parent_sha256 = await _get_last_sha256(db)
    sha256 = _compute_sha256(logs, batch_id, parent_sha256)

    # Preview du payload (tronqué à 4096 chars) pour audit sans stocker tout le batch
    preview = json.dumps(logs[:3], default=str)[:4096]

    batch = LogBatch(
        batch_id=batch_id,
        sha256=sha256,
        parent_sha256=parent_sha256,
        log_count=len(logs),
        source=source,
        payload_preview=preview,
        created_at=datetime.now(timezone.utc),
    )
    db.add(batch)
    await db.commit()
    await db.refresh(batch)
    logger.info("[Integrity] Batch %s enregistré: %d logs, sha256=%s...", batch_id, len(logs), sha256[:12])
    return batch


async def verify_batch(db: AsyncSession, batch_id: str, logs: list[dict]) -> dict:
    """
    Vérifie l'intégrité d'un batch en recalculant son SHA-256.
    Retourne {valid, batch_id, stored_sha256, computed_sha256, chain_valid}.
    """
    result = await db.execute(
        select(LogBatch).where(LogBatch.batch_id == batch_id)
    )
    batch = result.scalar_one_or_none()
    if batch is None:
        return {"valid": False, "error": f"Batch {batch_id!r} introuvable."}

    computed = _compute_sha256(logs, batch_id, batch.parent_sha256)
    hash_valid = computed == batch.sha256

    # Vérification de la chaîne : le parent_sha256 doit correspondre au sha256 du batch précédent
    prev_result = await db.execute(
        select(LogBatch).where(LogBatch.sha256 == batch.parent_sha256)
    )
    prev_batch = prev_result.scalar_one_or_none()
    chain_valid = (batch.parent_sha256 == _GENESIS_HASH) or (prev_batch is not None)

    return {
        "valid":          hash_valid and chain_valid,
        "batch_id":       batch_id,
        "stored_sha256":  batch.sha256,
        "computed_sha256": computed,
        "hash_valid":     hash_valid,
        "chain_valid":    chain_valid,
        "parent_sha256":  batch.parent_sha256,
        "log_count":      batch.log_count,
        "source":         batch.source,
        "created_at":     batch.created_at.isoformat() if batch.created_at else None,
    }


async def list_batches(db: AsyncSession, page: int = 1, page_size: int = 50) -> dict:
    offset = (page - 1) * page_size
    result = await db.execute(
        select(LogBatch).order_by(desc(LogBatch.id)).offset(offset).limit(page_size)
    )
    batches = result.scalars().all()
    total_r = await db.execute(select(func.count()).select_from(LogBatch))
    total = total_r.scalar_one()
    return {
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "batches":   [b.to_dict() for b in batches],
    }


async def get_batch(db: AsyncSession, batch_id: str) -> LogBatch | None:
    result = await db.execute(
        select(LogBatch).where(LogBatch.batch_id == batch_id)
    )
    return result.scalar_one_or_none()
