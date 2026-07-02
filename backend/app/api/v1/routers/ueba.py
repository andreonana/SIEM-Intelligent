# backend/app/api/v1/routers/ueba.py
#
# Endpoints UEBA — Analyse comportementale, anomalies, scores de risque.
#
# RBAC :
#   reader        : lecture (baselines, anomalies, scores)
#   analyst       : lecture + lancement d'analyse
#   administrator : tout

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role
from app.modules.ueba.baseline import compute_baseline, baseline_to_dict
from app.services.ueba_service import (
    run_ueba_analysis,
    list_anomalies,
    list_risk_scores,
    get_entity_risk,
)

router = APIRouter(prefix="/api/ueba", tags=["ueba"])


# ---------------------------------------------------------------------------
# Schémas de requête
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    entity_type: str = Field(
        default="source_ip",
        description="Type d'entité à analyser : 'user', 'source_ip' ou 'host'.",
    )
    entity_id: str | None = Field(
        default=None,
        description="Si fourni, analyse uniquement cette entité.",
    )
    baseline_days: int | None = Field(
        default=None,
        ge=1,
        le=365,
        description="Fenêtre de baseline en jours (défaut : 30).",
    )
    window_minutes: int | None = Field(
        default=None,
        ge=5,
        le=1440,
        description="Fenêtre d'analyse récente en minutes (défaut : 60).",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/baseline")
async def get_baselines(
    entity_type: str = Query(default="source_ip", description="'user', 'source_ip' ou 'host'"),
    baseline_days: int = Query(default=30, ge=1, le=365),
    user: dict = Depends(require_role("reader")),
):
    """
    Calcule et retourne la baseline comportementale globale.
    Fenêtre par défaut : 30 jours.
    """
    if entity_type not in ("user", "source_ip", "host"):
        raise HTTPException(status_code=400, detail="entity_type invalide (user | source_ip | host).")

    es = get_es_client()
    baselines = await compute_baseline(es, entity_type=entity_type, baseline_days=baseline_days)
    return {
        "entity_type": entity_type,
        "baseline_days": baseline_days,
        "total": len(baselines),
        "baselines": [baseline_to_dict(b) for b in baselines.values()],
    }


@router.get("/baseline/{entity_type}/{entity_id}")
async def get_entity_baseline(
    entity_type: str,
    entity_id: str,
    baseline_days: int = Query(default=30, ge=1, le=365),
    user: dict = Depends(require_role("reader")),
):
    """Retourne la baseline comportementale d'une entité précise."""
    if entity_type not in ("user", "source_ip", "host"):
        raise HTTPException(status_code=400, detail="entity_type invalide (user | source_ip | host).")

    es = get_es_client()
    baselines = await compute_baseline(
        es, entity_type=entity_type, entity_id=entity_id, baseline_days=baseline_days
    )

    if not baselines:
        raise HTTPException(
            status_code=404,
            detail=f"Aucune baseline disponible pour {entity_type}/{entity_id}.",
        )

    return baseline_to_dict(baselines[entity_id])


@router.post("/analyze")
async def trigger_analysis(
    body: AnalyzeRequest = AnalyzeRequest(),
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Lance une analyse UEBA complète :
    baseline → comportement récent → anomalies → scoring → persistance → alertes.

    Rôle requis : analyst ou administrator.
    """
    if body.entity_type not in ("user", "source_ip", "host"):
        raise HTTPException(status_code=400, detail="entity_type invalide (user | source_ip | host).")

    es = get_es_client()
    result = await run_ueba_analysis(
        db=db,
        es=es,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        baseline_days=body.baseline_days,
        window_minutes=body.window_minutes,
        triggered_by=user["username"],
    )
    return result


@router.get("/anomalies")
async def get_anomalies(
    entity_type: str | None = Query(default=None),
    entity_id: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """
    Liste les anomalies comportementales persistées.
    Filtrables par entity_type et entity_id.
    """
    return await list_anomalies(
        db, entity_type=entity_type, entity_id=entity_id, page=page, page_size=page_size
    )


@router.get("/risk-scores")
async def get_risk_scores(
    entity_type: str | None = Query(default=None),
    min_level: str | None = Query(
        default=None,
        description="Niveau minimal : low | medium | high | critical",
    ),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """
    Liste les scores de risque calculés par UEBA.
    Filtrables par entity_type et niveau minimal.
    """
    if min_level and min_level not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail="min_level invalide (low | medium | high | critical).")

    return await list_risk_scores(
        db, entity_type=entity_type, min_level=min_level, page=page, page_size=page_size
    )


@router.get("/entities/{entity_type}/{entity_id}/risk")
async def get_entity_risk_score(
    entity_type: str,
    entity_id: str,
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """Retourne le score de risque le plus récent pour une entité précise."""
    if entity_type not in ("user", "source_ip", "host"):
        raise HTTPException(status_code=400, detail="entity_type invalide (user | source_ip | host).")

    score = await get_entity_risk(db, entity_type=entity_type, entity_id=entity_id)
    if score is None:
        raise HTTPException(
            status_code=404,
            detail=f"Aucun score de risque disponible pour {entity_type}/{entity_id}.",
        )
    return score
