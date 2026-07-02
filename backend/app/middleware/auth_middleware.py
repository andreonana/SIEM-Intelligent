# backend/app/middleware/auth_middleware.py
#
# Middleware d'authentification — décode le JWT de chaque requête entrante
# et injecte le contexte utilisateur dans request.state.
#
# Ce middleware ne remplace pas les dépendances FastAPI require_role() —
# il les COMPLÈTE en rendant le contexte utilisateur disponible dans les
# middlewares suivants (notamment l'audit logger) sans duplication de logique.
#
# Les routes publiques (/health, /api/auth/login, /docs) ne nécessitent
# pas de JWT et ne sont pas rejetées ici.

from __future__ import annotations

import logging
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Routes publiques — pas de JWT requis à ce niveau
_PUBLIC_PATHS = (
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/auth/login",
    "/api/auth/mfa/verify",
)


class AuthContextMiddleware(BaseHTTPMiddleware):
    """
    Décode le JWT Bearer sans rejet (les rejets restent dans require_role).
    Remplit request.state.user_id, request.state.username, request.state.role
    si le token est valide ; None sinon.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Valeurs par défaut
        request.state.user_id = None
        request.state.username = None
        request.state.role = None

        path = request.url.path
        if any(path.startswith(p) for p in _PUBLIC_PATHS):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                from app.modules.rbac.auth import decode_access_token
                payload = decode_access_token(token)
                request.state.user_id = payload.get("sub")
                request.state.username = payload.get("username")
                request.state.role = payload.get("role")
            except Exception:
                # Token invalide — ne pas rejeter ici, require_role le fera
                pass

        return await call_next(request)
