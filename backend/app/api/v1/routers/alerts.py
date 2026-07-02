# backend/app/api/v1/routers/alerts.py
#
# Endpoints de gestion des alertes de sécurité.

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.alert import Alert
from app.modules.rbac.roles import require_role
from app.services.alert_service import (
    get_alert,
    list_alerts,
    acknowledge_alert,
    resolve_alert,
    assign_alert,
)
from app.services.audit_service import log_action
from app.services.export_service import to_csv_bytes, to_xlsx_bytes

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class ResolveBody(BaseModel):
    note: str | None = None


class AssignBody(BaseModel):
    username: str


@router.get("")
async def get_all_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """Liste paginée des alertes. Filtres optionnels: severity, status."""
    return await list_alerts(db, page=page, page_size=page_size, severity_filter=severity, status_filter=status)


_ALERT_EXPORT_COLUMNS = [
    "id", "rule_id", "rule_name", "severity", "description", "status",
    "source_ip", "host", "detected_at", "mitre_tactic", "mitre_technique",
    "confidence_score", "soar_status", "assigned_to", "resolved_at", "resolution_note",
]


async def _fetch_alerts_for_export(
    db: AsyncSession,
    severity: str | None,
    status_filter: str | None,
    start_date: str | None,
    end_date: str | None,
) -> list[dict]:
    query = select(Alert).order_by(Alert.detected_at.desc())
    if severity:
        query = query.where(Alert.severity == severity)
    if status_filter:
        query = query.where(Alert.status == status_filter)
    if start_date:
        query = query.where(Alert.detected_at >= start_date)
    if end_date:
        query = query.where(Alert.detected_at <= end_date)
    result = await db.execute(query.limit(5000))
    return [a.to_dict() for a in result.scalars().all()]


@router.get("/export.csv")
async def export_alerts_csv(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    start_date: str | None = Query(None, description="ISO 8601"),
    end_date: str | None = Query(None, description="ISO 8601"),
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """Exporte les alertes filtrées (gravité/statut/période) au format CSV."""
    rows = await _fetch_alerts_for_export(db, severity, status, start_date, end_date)
    content = to_csv_bytes(rows, _ALERT_EXPORT_COLUMNS)
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="smart-siem-alerts-export.csv"'},
    )


@router.get("/export.xlsx")
async def export_alerts_xlsx(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    start_date: str | None = Query(None, description="ISO 8601"),
    end_date: str | None = Query(None, description="ISO 8601"),
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """Exporte les alertes filtrées (gravité/statut/période) au format Excel (.xlsx)."""
    rows = await _fetch_alerts_for_export(db, severity, status, start_date, end_date)
    content = to_xlsx_bytes(rows, _ALERT_EXPORT_COLUMNS, sheet_title="Alertes")
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="smart-siem-alerts-export.xlsx"'},
    )


@router.get("/{alert_id}")
async def get_alert_detail(
    alert_id: int,
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """Détail d'une alerte par son ID."""
    alert = await get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alerte {alert_id} introuvable.")
    await log_action(db, user["username"], "alert_view", target=str(alert_id), role=user.get("role"))
    return alert.to_dict()


@router.post("/{alert_id}/acknowledge")
async def ack_alert(
    alert_id: int,
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Marque une alerte comme prise en compte par l'analyste."""
    try:
        alert = await acknowledge_alert(db, alert_id, user["username"])
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    await log_action(db, user["username"], "alert_acknowledge", target=str(alert_id), role=user.get("role"))
    return alert.to_dict()


@router.post("/{alert_id}/resolve")
async def resolve_alert_endpoint(
    alert_id: int,
    body: ResolveBody = ResolveBody(),
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Résout une alerte avec une note optionnelle."""
    try:
        alert = await resolve_alert(db, alert_id, user["username"], note=body.note)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    await log_action(db, user["username"], "alert_resolve", target=str(alert_id), detail=body.note, role=user.get("role"))
    return alert.to_dict()


@router.post("/{alert_id}/assign")
async def assign_alert_endpoint(
    alert_id: int,
    body: AssignBody,
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Assigne une alerte à un utilisateur."""
    try:
        alert = await assign_alert(db, alert_id, body.username)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    await log_action(db, user["username"], "alert_assign", target=str(alert_id), detail=f"assigned_to={body.username}", role=user.get("role"))
    return alert.to_dict()
