# backend/app/modules/rbac/mfa.py
#
# Module MFA TOTP conforme RFC 6238 (Time-based One-Time Password).
# Utilise pyotp pour la génération et la vérification des codes TOTP.
#
# Flux d'activation :
#   1. POST /api/auth/mfa/setup  → génère un secret + URI de provisioning
#   2. L'utilisateur configure son authenticator (Google, Authy, Microsoft...)
#   3. POST /api/auth/mfa/verify-setup  → valide le premier code TOTP → active MFA
#
# Flux de login avec MFA :
#   1. POST /api/auth/login  → si MFA activé, retourne mfa_required=true + mfa_token temporaire
#   2. POST /api/auth/mfa/verify  → valide le code TOTP → retourne le JWT final

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pyotp

from app.core.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Génération de secret
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Génère un secret TOTP Base32 aléatoire (160 bits, conforme RFC 6238)."""
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, username: str) -> str:
    """
    Retourne l'URI de provisioning otpauth:// compatible avec tous les authenticators.
    Format : otpauth://totp/<issuer>:<username>?secret=<secret>&issuer=<issuer>
    """
    totp = pyotp.TOTP(
        secret,
        interval=settings.mfa_time_step,
    )
    return totp.provisioning_uri(
        name=username,
        issuer_name=settings.mfa_issuer_name,
    )


# ---------------------------------------------------------------------------
# Vérification TOTP
# ---------------------------------------------------------------------------

def verify_totp_code(secret: str, code: str) -> bool:
    """
    Vérifie un code TOTP RFC 6238.
    Fenêtre de tolérance : ±mfa_allowed_drift intervalles (défaut ±1 = ±30s).
    Retourne True si le code est valide, False sinon.
    """
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    try:
        totp = pyotp.TOTP(secret, interval=settings.mfa_time_step)
        return totp.verify(code, valid_window=settings.mfa_allowed_drift)
    except Exception as exc:
        logger.warning("[MFA] Erreur vérification TOTP: %s", exc)
        return False


# ---------------------------------------------------------------------------
# JWT temporaire MFA (pre-auth token)
# ---------------------------------------------------------------------------
# Stratégie : après login username/password réussi (quand MFA est activé),
# on émet un "mfa_token" signé avec le même SECRET_KEY mais une durée courte
# (5 min) et un claim spécial "mfa_pending=true".
# Ce token n'est pas un accès complet — il ne contient pas le rôle utilisable.
# L'endpoint /mfa/verify le consomme et émet le JWT complet.

from datetime import timedelta
from jose import JWTError, jwt as jose_jwt
import os

_SECRET = os.getenv("JWT_SECRET") or "dev-jwt-secret-must-be-min-32-chars-long"
_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
_MFA_TOKEN_EXPIRY_MINUTES = 5


def create_mfa_pending_token(user_id: str, username: str) -> str:
    """
    Crée un token signé à durée de vie courte indiquant que l'étape MFA est requise.
    NE contient PAS le rôle — ne donne pas accès aux endpoints protégés.
    """
    payload = {
        "sub": str(user_id),
        "username": username,
        "mfa_pending": True,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=_MFA_TOKEN_EXPIRY_MINUTES),
    }
    return jose_jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def decode_mfa_pending_token(token: str) -> dict:
    """
    Décode et valide un mfa_pending token.
    Lève ValueError si le token est invalide, expiré ou ne contient pas mfa_pending=True.
    """
    try:
        payload = jose_jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
    except JWTError as exc:
        raise ValueError(f"Token MFA invalide ou expiré: {exc}") from exc

    if not payload.get("mfa_pending"):
        raise ValueError("Ce token n'est pas un token MFA intermédiaire.")
    return payload
