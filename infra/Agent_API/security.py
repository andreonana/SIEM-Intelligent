"""
Authentification et contrôle d'accès de l'AgentAPI.

Deux couches indépendantes, toutes deux obligatoires :
1. Token secret partagé (header X-API-Key) — comparaison en temps constant.
2. Whitelist de l'IP source de la requête — le SIEM backend uniquement.

Ne jamais exposer cette API sur une interface publique. Elle est prévue
pour tourner sur un réseau de management isolé, avec ces deux contrôles
et un accès restreint.
"""
import hmac

from fastapi import Header, HTTPException, Request, status

try:
    from . import config
except ImportError:  # pragma: no cover - fallback for direct execution
    import config


def verify_token(x_api_key: str = Header(default="")) -> None:
    if not x_api_key or not hmac.compare_digest(x_api_key, config.API_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou manquant",
        )


def verify_caller_ip(request: Request) -> None:
    client_ip = request.client.host if request.client else None
    if client_ip not in config.ALLOWED_CALLERS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Appelant non autorisé: {client_ip}",
        )


def enforce_security(request: Request, x_api_key: str = Header(default="")) -> None:
    """Combine les deux contrôles. À utiliser comme dependency unique sur chaque route sensible."""
    verify_caller_ip(request)
    verify_token(x_api_key)
