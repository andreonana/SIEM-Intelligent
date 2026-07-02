# backend/app/api/v1/routers/investigation.py
#
# Endpoints d'investigation forensique : reconstruction de chronologie réelle
# depuis Elasticsearch pour une entité (IP source ou host), et marquage
# persistant d'entités suspectes pour investigation croisée entre analystes.

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import get_db
from app.db.elasticsearch_client import get_es_client
from app.models.investigation_flag import InvestigationFlag
from app.modules.rbac.roles import require_role
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/investigation", tags=["investigation"])


class FlagRequest(BaseModel):
    note: str | None = None


@router.get("/{entity_id}")
async def get_investigation(
    entity_id: str,
    user: dict = Depends(require_role("analyst")),
):
    """
    Retourne la chronologie réelle des événements liés à une entité (IP source
    ou host), reconstituée depuis Elasticsearch, triée chronologiquement.
    Rôle requis: analyst ou plus.
    """
    timeline = []
    try:
        es_client = get_es_client()
        resp = await es_client.search(
            index=settings.es_logs_index_name,
            size=200,
            sort=[{"received_at": "asc"}],
            query={
                "bool": {
                    "should": [
                        {"term": {"source_ip.keyword": entity_id}},
                        {"term": {"host.keyword": entity_id}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        )
        for hit in resp["hits"]["hits"]:
            src = hit["_source"]
            timeline.append({
                "id": hit["_id"],
                "timestamp": src.get("timestamp") or src.get("received_at"),
                "source_ip": src.get("source_ip"),
                "host": src.get("host"),
                "log_type": src.get("log_type"),
                "severity": src.get("severity"),
                "raw_message": src.get("raw_message"),
            })
    except Exception as exc:
        logger.warning("[Investigation] Elasticsearch indisponible: %s", exc)

    return {"entity_id": entity_id, "timeline": timeline}


@router.post("/{entity_id}/flag")
async def flag_investigation(
    entity_id: str,
    body: FlagRequest,
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Marque une entité comme suspecte, persisté durablement en base pour
    investigation croisée entre analystes.
    Rôle requis: analyst ou plus.
    """
    flag = InvestigationFlag(entity_id=entity_id, flagged_by=user["username"], note=body.note)
    db.add(flag)
    await db.commit()
    await db.refresh(flag)

    await log_action(db, user["username"], "investigation_flag", target=entity_id, detail=body.note or "", role=user.get("role"))

    return {
        "entity_id": entity_id,
        "flagged_by": user["username"],
        "status": "flagged",
        "flag_id": flag.id,
    }


@router.get("/{entity_id}/flags")
async def list_flags(
    entity_id: str,
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Liste les marquages existants pour une entité donnée."""
    result = await db.execute(
        select(InvestigationFlag)
        .where(InvestigationFlag.entity_id == entity_id)
        .order_by(InvestigationFlag.flagged_at.desc())
    )
    flags = result.scalars().all()
    return {"entity_id": entity_id, "flags": [f.to_dict() for f in flags]}
