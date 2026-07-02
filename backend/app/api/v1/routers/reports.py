# backend/app/api/v1/routers/reports.py
#
# Endpoints de génération et de téléchargement des rapports de sécurité.
#
# GET  /api/reports/weekly/summary  → JSON des données agrégées sur 7 jours
# GET  /api/reports/weekly          → Téléchargement du PDF rapport hebdomadaire
# POST /api/reports/weekly/generate → Déclenche la génération (même résultat que GET)

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role
from app.services.report_service import aggregate_report_data, generate_pdf_report

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/weekly/summary")
async def weekly_summary(
    days: int = Query(default=7, ge=1, le=90, description="Nombre de jours couverts par le rapport."),
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Retourne le résumé JSON des données de sécurité sur les N derniers jours.
    Rôle requis : analyst ou plus.
    """
    try:
        es_client = get_es_client()
        data = await aggregate_report_data(db, es_client, days=days)
        return {
            "status": "ok",
            "requested_by": user["username"],
            "data": data,
        }
    except Exception as exc:
        logger.error("[Reports] Erreur génération summary: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'agrégation: {exc}")


@router.get("/weekly")
async def download_weekly_pdf(
    days: int = Query(default=7, ge=1, le=90, description="Nombre de jours couverts par le rapport."),
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Génère et retourne le rapport PDF hebdomadaire (téléchargement direct).
    Rôle requis : analyst ou plus.
    """
    try:
        es_client = get_es_client()
        data = await aggregate_report_data(db, es_client, days=days)
        pdf_bytes = generate_pdf_report(data)

        filename = (
            f"siem-rapport-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
            f"-{days}j.pdf"
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as exc:
        logger.error("[Reports] Erreur génération PDF: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erreur lors de la génération du PDF: {exc}")


@router.post("/weekly/generate", status_code=200)
async def generate_weekly_report(
    days: int = Query(default=7, ge=1, le=90),
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Génère le rapport hebdomadaire et retourne un lien de téléchargement.
    Rôle requis : analyst ou plus.
    """
    try:
        es_client = get_es_client()
        data = await aggregate_report_data(db, es_client, days=days)
        return {
            "status": "rapport généré",
            "requested_by": user["username"],
            "period_days": days,
            "generated_at": data["generated_at"],
            "download_url": f"/api/reports/weekly?days={days}",
            "summary": {
                "total_logs": data["logs"]["total"],
                "total_alerts": data["alerts"]["total"],
                "critical_alerts": data["alerts"]["by_severity"].get("CRITICAL", 0),
                "high_risk_entities": len(data["ueba"]["high_risk_entities"]),
            },
        }
    except Exception as exc:
        logger.error("[Reports] Erreur génération: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erreur: {exc}")
