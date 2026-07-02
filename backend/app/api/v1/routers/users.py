# backend/app/api/v1/routers/users.py
#
# Gestion des utilisateurs — CRUD complet sur la base persistante.
# Toutes les actions sensibles sont journalisées (CDC — traçabilité).

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.modules.rbac.roles import require_role
from app.services import user_service
from app.services.audit_service import log_action

router = APIRouter(prefix="/api/users", tags=["users"])

VALID_ROLES = {"reader", "analyst", "administrator"}


class UserCreate(BaseModel):
    username:    str
    password:    str
    role:        str
    team:        str | None = None
    service:     str | None = None
    subsidiary:  str | None = None
    environment: str | None = None


class UserUpdate(BaseModel):
    role:        str | None  = None
    password:    str | None  = None
    is_active:   bool | None = None
    team:        str | None  = None
    service:     str | None  = None
    subsidiary:  str | None  = None
    environment: str | None  = None


@router.get("")
async def get_all_users(
    user: dict         = Depends(require_role("administrator")),
    db:   AsyncSession = Depends(get_db),
):
    """Liste tous les utilisateurs. Rôle requis : administrator."""
    users = await user_service.list_all_users(db)
    return {"total": len(users), "users": [u.to_dict() for u in users]}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_user(
    new_user: UserCreate,
    request:  Request,
    user:     dict         = Depends(require_role("administrator")),
    db:       AsyncSession = Depends(get_db),
):
    """Crée un nouvel utilisateur. Rôle requis : administrator."""
    if new_user.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Rôle invalide '{new_user.role}'. Valeurs acceptées: {sorted(VALID_ROLES)}",
        )
    try:
        created = await user_service.create_user(
            db,
            username=new_user.username,
            plain_password=new_user.password,
            role=new_user.role,
            team=new_user.team,
            service=new_user.service,
            subsidiary=new_user.subsidiary,
            environment=new_user.environment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    ip = request.client.host if request.client else None
    await log_action(
        db,
        username=user["username"],
        role=user.get("role"),
        action="create_user",
        target=new_user.username,
        detail=f"role={new_user.role}",
        ip_address=ip,
    )
    return {**created.to_dict(), "created_by": user["username"]}


@router.put("/{user_id}")
async def update_user(
    user_id:  int,
    update:   UserUpdate,
    request:  Request,
    user:     dict         = Depends(require_role("administrator")),
    db:       AsyncSession = Depends(get_db),
):
    """Modifie un utilisateur (rôle, mot de passe, activation, périmètre). Rôle requis : administrator."""
    target_user = await user_service.get_user_by_id(db, user_id)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Aucun utilisateur avec l'id '{user_id}'.",
        )

    old_role = target_user.role
    try:
        updated = await user_service.update_user(
            db,
            user=target_user,
            role=update.role,
            plain_password=update.password,
            is_active=update.is_active,
            team=update.team,
            service=update.service,
            subsidiary=update.subsidiary,
            environment=update.environment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    ip = request.client.host if request.client else None
    if update.role and update.role != old_role:
        await log_action(
            db,
            username=user["username"],
            role=user.get("role"),
            action="role_update",
            target=target_user.username,
            detail=f"{old_role} → {update.role}",
            ip_address=ip,
        )

    return updated.to_dict()


@router.delete("/{user_id}", status_code=status.HTTP_200_OK)
async def delete_user(
    user_id: int,
    request: Request,
    user:    dict         = Depends(require_role("administrator")),
    db:      AsyncSession = Depends(get_db),
):
    """
    Désactive un utilisateur (soft delete — préserve la traçabilité d'audit).
    Rôle requis : administrator.
    """
    target_user = await user_service.get_user_by_id(db, user_id)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Aucun utilisateur avec l'id '{user_id}'.",
        )
    await user_service.delete_user(db, target_user)

    ip = request.client.host if request.client else None
    await log_action(
        db,
        username=user["username"],
        role=user.get("role"),
        action="disable_user",
        target=target_user.username,
        detail="soft delete — compte désactivé, données conservées pour l'audit",
        ip_address=ip,
    )
    return {"status": "désactivé", "username": target_user.username}
