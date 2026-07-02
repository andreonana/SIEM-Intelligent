# backend/app/api/v1/routers/auth.py
#
# Endpoints d'authentification, incluant le flux MFA TOTP RFC 6238.
#
# Flux sans MFA :
#   POST /api/auth/login  → JWT complet
#
# Flux avec MFA activé :
#   POST /api/auth/login  → {mfa_required: true, mfa_token: "<token 5min>"}
#   POST /api/auth/mfa/verify  → JWT complet
#
# Activation MFA :
#   POST /api/auth/mfa/setup         → secret + provisioning URI
#   POST /api/auth/mfa/verify-setup  → active MFA après validation du premier code
#   GET  /api/auth/mfa/status        → état MFA de l'utilisateur courant
#   POST /api/auth/mfa/disable       → désactive MFA

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.modules.rbac.auth import create_access_token
from app.modules.rbac.mfa import (
    generate_totp_secret,
    get_provisioning_uri,
    verify_totp_code,
    create_mfa_pending_token,
    decode_mfa_pending_token,
)
from app.modules.rbac.roles import require_role, get_current_user
from app.services.user_service import authenticate, get_user_by_username, get_user_by_id
from app.services.audit_service import log_action

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Schémas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_token: str | None = None


class MFAVerifyRequest(BaseModel):
    mfa_token: str = Field(description="Token intermédiaire reçu lors du login.")
    code: str = Field(description="Code TOTP à 6 chiffres.")


class MFASetupVerifyRequest(BaseModel):
    code: str = Field(description="Premier code TOTP pour confirmer l'activation.")


class MFADisableRequest(BaseModel):
    code: str = Field(description="Code TOTP courant pour confirmer la désactivation.")
    password: str = Field(description="Mot de passe actuel pour confirmer.")


# ---------------------------------------------------------------------------
# Login (avec prise en charge MFA)
# ---------------------------------------------------------------------------

@router.post("/login", response_model=LoginResponse)
async def login(
    credentials: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Authentifie un utilisateur.
    - Si MFA désactivé : retourne directement le JWT complet.
    - Si MFA activé : retourne mfa_required=true + mfa_token temporaire (5 min).
      Le client doit ensuite appeler POST /api/auth/mfa/verify avec le code TOTP.
    """
    ip = request.client.host if request.client else None
    user = await authenticate(db, credentials.username, credentials.password)

    if user is None:
        await log_action(db, username=credentials.username, action="login",
                         ip_address=ip, result="failure",
                         detail="Identifiant ou mot de passe incorrect")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Identifiant ou mot de passe incorrect.",
                            headers={"WWW-Authenticate": "Bearer"})

    # MFA activé → flux en deux étapes
    if user.mfa_enabled and user.mfa_secret:
        mfa_token = create_mfa_pending_token(str(user.id), user.username)
        await log_action(db, username=user.username, role=user.role, action="login_mfa_required",
                         ip_address=ip, result="success",
                         detail="MFA requis — code TOTP attendu")
        return LoginResponse(mfa_required=True, mfa_token=mfa_token, access_token="")

    # Pas de MFA → JWT immédiat
    await log_action(db, username=user.username, role=user.role, action="login", ip_address=ip, result="success")
    token = create_access_token(user_id=str(user.id), username=user.username, role=user.role)
    return LoginResponse(access_token=token)


@router.post("/logout")
async def logout(
    request: Request,
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """Confirme la déconnexion côté serveur. Le JWT reste valide jusqu'à son expiration."""
    ip = request.client.host if request.client else None
    await log_action(db, username=user["username"], role=user.get("role"), action="logout", ip_address=ip)
    return {"status": "déconnecté", "username": user["username"]}


# ---------------------------------------------------------------------------
# MFA — Seconde étape du login
# ---------------------------------------------------------------------------

@router.post("/mfa/verify")
async def mfa_verify(
    body: MFAVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Seconde étape du login MFA.
    Consomme le mfa_token intermédiaire + le code TOTP.
    Retourne le JWT complet si le code est valide.
    """
    ip = request.client.host if request.client else None

    try:
        payload = decode_mfa_pending_token(body.mfa_token)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))

    username = payload.get("username", "")
    user = await get_user_by_username(db, username)

    if user is None or not user.is_active or not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Session MFA invalide.")

    if not verify_totp_code(user.mfa_secret, body.code):
        await log_action(db, username=username, action="mfa_verify_failure",
                         ip_address=ip, result="failure",
                         detail=f"Code TOTP invalide")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Code TOTP invalide ou expiré.")

    # Mise à jour last_used
    user.mfa_last_used_at = datetime.now(timezone.utc)
    await db.commit()

    await log_action(db, username=username, role=user.role, action="mfa_verify_success",
                     ip_address=ip, result="success")

    token = create_access_token(user_id=str(user.id), username=user.username, role=user.role)
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# MFA — Setup (génération du secret)
# ---------------------------------------------------------------------------

@router.post("/mfa/setup")
async def mfa_setup(
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """
    Génère un secret TOTP pour l'utilisateur courant.
    Retourne l'URI otpauth:// à scanner dans un authenticator.
    Le MFA n'est PAS encore activé — il le sera après verify-setup.
    """
    db_user = await get_user_by_username(db, user["username"])
    if db_user is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    if db_user.mfa_enabled:
        raise HTTPException(status_code=400,
                            detail="MFA déjà activé. Désactivez-le d'abord.")

    secret = generate_totp_secret()
    db_user.mfa_secret = secret
    await db.commit()

    uri = get_provisioning_uri(secret, db_user.username)

    await log_action(db, username=user["username"], role=user.get("role"), action="mfa_setup_started",
                     result="success", detail="Secret TOTP généré")

    return {
        "provisioning_uri": uri,
        "secret": secret,
        "message": "Scannez l'URI dans votre authenticator puis appelez /mfa/verify-setup avec le premier code.",
    }


# ---------------------------------------------------------------------------
# MFA — Activation (verify-setup)
# ---------------------------------------------------------------------------

@router.post("/mfa/verify-setup")
async def mfa_verify_setup(
    body: MFASetupVerifyRequest,
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """
    Valide le premier code TOTP et active le MFA.
    Doit être appelé après /mfa/setup, avec le code affiché par l'authenticator.
    """
    db_user = await get_user_by_username(db, user["username"])
    if db_user is None or not db_user.mfa_secret:
        raise HTTPException(status_code=400,
                            detail="Aucun setup MFA en cours. Appelez d'abord /mfa/setup.")

    if db_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA déjà activé.")

    if not verify_totp_code(db_user.mfa_secret, body.code):
        await log_action(db, username=user["username"], action="mfa_verify_failure",
                         result="failure", detail="Code de vérification setup invalide")
        raise HTTPException(status_code=400,
                            detail="Code TOTP invalide. Vérifiez l'heure de votre appareil.")

    db_user.mfa_enabled = True
    db_user.mfa_enabled_at = datetime.now(timezone.utc)
    await db.commit()

    await log_action(db, username=user["username"], role=user.get("role"), action="mfa_enabled",
                     result="success", detail="MFA TOTP activé avec succès")

    return {"mfa_enabled": True, "message": "MFA activé. Le prochain login exigera un code TOTP."}


# ---------------------------------------------------------------------------
# MFA — Statut
# ---------------------------------------------------------------------------

@router.get("/mfa/status")
async def mfa_status(
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """Retourne l'état MFA de l'utilisateur courant."""
    db_user = await get_user_by_username(db, user["username"])
    if db_user is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
    return {
        "username": db_user.username,
        "mfa_enabled": db_user.mfa_enabled,
        "mfa_enabled_at": db_user.mfa_enabled_at.isoformat() if db_user.mfa_enabled_at else None,
        "mfa_last_used_at": db_user.mfa_last_used_at.isoformat() if db_user.mfa_last_used_at else None,
    }


# ---------------------------------------------------------------------------
# MFA — Désactivation
# ---------------------------------------------------------------------------

@router.post("/mfa/disable")
async def mfa_disable(
    body: MFADisableRequest,
    request: Request,
    user: dict = Depends(require_role("reader")),
    db: AsyncSession = Depends(get_db),
):
    """
    Désactive le MFA de l'utilisateur courant.
    Exige le mot de passe ET le code TOTP courant pour prévenir la désactivation forcée.
    """
    from app.modules.rbac.auth import verify_password
    ip = request.client.host if request.client else None

    db_user = await get_user_by_username(db, user["username"])
    if db_user is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    if not db_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA non activé.")

    if not verify_password(body.password, db_user.hashed_password):
        await log_action(db, username=user["username"], action="mfa_disabled",
                         ip_address=ip, result="failure", detail="Mot de passe incorrect")
        raise HTTPException(status_code=401, detail="Mot de passe incorrect.")

    if not verify_totp_code(db_user.mfa_secret, body.code):
        await log_action(db, username=user["username"], action="mfa_disabled",
                         ip_address=ip, result="failure", detail="Code TOTP invalide")
        raise HTTPException(status_code=401, detail="Code TOTP invalide.")

    db_user.mfa_enabled = False
    db_user.mfa_secret = None
    db_user.mfa_enabled_at = None
    await db.commit()

    await log_action(db, username=user["username"], role=user.get("role"), action="mfa_disabled",
                     ip_address=ip, result="success", detail="MFA désactivé")

    return {"mfa_enabled": False, "message": "MFA désactivé."}
