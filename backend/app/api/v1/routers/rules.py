# backend/app/api/v1/routers/rules.py
#
# Endpoints de gestion des règles de corrélation.

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.rule import CorrelationRule
from app.modules.rbac.roles import require_role
from app.services.audit_service import log_action

router = APIRouter(prefix="/api/rules", tags=["rules"])


class RuleCreate(BaseModel):
    rule_id:         str
    name:            str
    description:     str = ""
    rule_type:       str              # threshold | pattern
    enabled:         bool = True
    threshold:       int | None = None
    window_minutes:  int = 10
    severity:        str = "HIGH"
    mitre_tactic:    str | None = None
    mitre_technique: str | None = None
    soar_action:     str | None = None


class RuleUpdate(BaseModel):
    name:            str | None = None
    description:     str | None = None
    rule_type:       str | None = None
    enabled:         bool | None = None
    threshold:       int | None = None
    window_minutes:  int | None = None
    severity:        str | None = None
    mitre_tactic:    str | None = None
    mitre_technique: str | None = None
    soar_action:     str | None = None


@router.get("")
async def get_all_rules(
    user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Liste toutes les règles de corrélation."""
    result = await db.execute(select(CorrelationRule).order_by(CorrelationRule.rule_id))
    rules = result.scalars().all()
    return {"total": len(rules), "rules": [r.to_dict() for r in rules]}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: RuleCreate,
    user: dict = Depends(require_role("administrator")),
    db: AsyncSession = Depends(get_db),
):
    """Crée une nouvelle règle de corrélation."""
    existing = await db.execute(select(CorrelationRule).where(CorrelationRule.rule_id == body.rule_id))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail=f"Règle '{body.rule_id}' existe déjà.")
    now = datetime.now(timezone.utc)
    rule = CorrelationRule(
        rule_id=body.rule_id,
        name=body.name,
        description=body.description,
        rule_type=body.rule_type,
        enabled=body.enabled,
        threshold=body.threshold,
        window_minutes=body.window_minutes,
        severity=body.severity,
        mitre_tactic=body.mitre_tactic,
        mitre_technique=body.mitre_technique,
        soar_action=body.soar_action,
        created_at=now,
        updated_at=now,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    await log_action(db, user["username"], "rule_create", target=body.rule_id, role=user.get("role"))
    return rule.to_dict()


@router.put("/{rule_id}")
async def update_rule(
    rule_id: str,
    body: RuleUpdate,
    user: dict = Depends(require_role("administrator")),
    db: AsyncSession = Depends(get_db),
):
    """Modifie une règle de corrélation existante."""
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.rule_id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Règle '{rule_id}' introuvable.")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)
    rule.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(rule)
    await log_action(db, user["username"], "rule_update", target=rule_id, role=user.get("role"))
    return rule.to_dict()


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: str,
    user: dict = Depends(require_role("administrator")),
    db: AsyncSession = Depends(get_db),
):
    """Supprime une règle de corrélation."""
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.rule_id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Règle '{rule_id}' introuvable.")
    await db.delete(rule)
    await db.commit()
    await log_action(db, user["username"], "rule_delete", target=rule_id, role=user.get("role"))
