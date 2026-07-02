# backend/app/services/user_service.py
#
# Couche service pour la gestion des utilisateurs — CRUD complet sur la DB.
# Point d'entrée unique pour toute logique métier liée aux comptes.

import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.modules.rbac.auth import hash_password, verify_password

VALID_ROLES = {"reader", "analyst", "administrator"}

# Politique de complexité : 8+ caractères, au moins 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial.
_PASSWORD_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]).{8,}$')


def _validate_password(plain_password: str) -> None:
    if not _PASSWORD_RE.match(plain_password):
        raise ValueError(
            "Le mot de passe doit contenir au moins 8 caractères, "
            "une majuscule, une minuscule, un chiffre et un caractère spécial."
        )

# Comptes de démonstration créés au premier démarrage si la table est vide
_DEMO_ACCOUNTS = [
    {
        "username":    "admin",
        "password":    "Admin1234!",
        "role":        "administrator",
        "team":        "soc",
        "service":     "securite",
        "subsidiary":  "HQ",
        "environment": "prod",
    },
    {
        "username":    "analyst",
        "password":    "Analyst1234!",
        "role":        "analyst",
        "team":        "soc",
        "service":     "securite",
        "subsidiary":  "HQ",
        "environment": "prod",
    },
    {
        "username":    "reader",
        "password":    "Reader1234!",
        "role":        "reader",
        "team":        "ops",
        "service":     "exploitation",
        "subsidiary":  "HQ",
        "environment": "prod",
    },
]


async def seed_demo_users(db: AsyncSession) -> None:
    """Insère les comptes de démo s'ils n'existent pas encore."""
    for account in _DEMO_ACCOUNTS:
        result = await db.execute(select(User).where(User.username == account["username"]))
        if result.scalar_one_or_none() is None:
            db.add(User(
                username=account["username"],
                hashed_password=hash_password(account["password"]),
                role=account["role"],
                team=account.get("team"),
                service=account.get("service"),
                subsidiary=account.get("subsidiary"),
                environment=account.get("environment"),
            ))
    await db.commit()


async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: int) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def authenticate(db: AsyncSession, username: str, plain_password: str) -> User | None:
    user = await get_user_by_username(db, username)
    if user is None or not user.is_active:
        return None
    if not verify_password(plain_password, user.hashed_password):
        return None
    return user


async def list_all_users(db: AsyncSession) -> list[User]:
    result = await db.execute(select(User).order_by(User.id))
    return list(result.scalars().all())


async def create_user(
    db: AsyncSession,
    username: str,
    plain_password: str,
    role: str,
    team: str | None = None,
    service: str | None = None,
    subsidiary: str | None = None,
    environment: str | None = None,
) -> User:
    if role not in VALID_ROLES:
        raise ValueError(f"Rôle invalide '{role}'. Valeurs acceptées: {VALID_ROLES}")
    _validate_password(plain_password)
    existing = await get_user_by_username(db, username)
    if existing is not None:
        raise ValueError(f"Utilisateur '{username}' existe déjà.")
    user = User(
        username=username,
        hashed_password=hash_password(plain_password),
        role=role,
        team=team,
        service=service,
        subsidiary=subsidiary,
        environment=environment,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def update_user(
    db: AsyncSession,
    user: User,
    role: str | None = None,
    plain_password: str | None = None,
    is_active: bool | None = None,
    team: str | None = None,
    service: str | None = None,
    subsidiary: str | None = None,
    environment: str | None = None,
) -> User:
    if role is not None:
        if role not in VALID_ROLES:
            raise ValueError(f"Rôle invalide '{role}'.")
        user.role = role
    if plain_password is not None:
        _validate_password(plain_password)
        user.hashed_password = hash_password(plain_password)
    if is_active is not None:
        user.is_active = is_active
    if team is not None:
        user.team = team
    if service is not None:
        user.service = service
    if subsidiary is not None:
        user.subsidiary = subsidiary
    if environment is not None:
        user.environment = environment
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)
    return user


async def delete_user(db: AsyncSession, user: User) -> None:
    """Désactivation logique (soft delete) — préserve la traçabilité d'audit."""
    user.is_active = False
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
