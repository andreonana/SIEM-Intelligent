# backend/app/middleware/audit_logger.py
#
# Middleware d'audit HTTP — journalise les requêtes mutantes (POST/PUT/PATCH/DELETE)
# et les accès aux endpoints sensibles dans la table audit_logs SQL.
#
# Distincton :
#   - Audit métier (login, alert_ack, playbook_run) : géré par audit_service.py
#   - Audit technique HTTP (toutes requêtes mutantes) : ce middleware
#
# Filtrages pour éviter le flood :
#   - Ignoré : GET, HEAD, OPTIONS sur des routes non sensibles
#   - Ignoré : /health, /docs, /openapi.json
#   - Toujours audité : POST /api/auth/login, /api/auth/mfa/* et les routes mutantes

from __future__ import annotations

import logging
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Routes jamais auditées
_NEVER_AUDIT = ("/health", "/docs", "/redoc", "/openapi.json")

# Routes GET qui méritent un audit (accès à des ressources sensibles)
_AUDIT_READS = (
    "/api/reports/",
    "/api/audit",
    "/api/users",
    "/api/integrity/",
)

# Méthodes mutantes : toujours auditées
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class AuditLoggerMiddleware(BaseHTTPMiddleware):
    """
    Journalise les accès HTTP pertinents dans audit_logs SQL.
    Utilise request.state.username si AuthContextMiddleware est branché avant.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path
        method = request.method

        # Toujours ignorer les routes monitoring/docs
        if any(path.startswith(p) for p in _NEVER_AUDIT):
            return await call_next(request)

        # Décider si on audite cette requête
        should_audit = (
            method in _MUTATING_METHODS
            or any(path.startswith(p) for p in _AUDIT_READS)
        )

        if not should_audit:
            return await call_next(request)

        start = time.monotonic()
        response = await call_next(request)
        duration_ms = int((time.monotonic() - start) * 1000)

        # Récupérer le contexte utilisateur depuis AuthContextMiddleware
        username = getattr(request.state, "username", None) or "anonymous"
        role = getattr(request.state, "role", None)
        ip = _get_ip(request)
        status_code = response.status_code

        # Journalisation asynchrone en base SQL (fire-and-forget pour ne pas bloquer)
        import asyncio
        asyncio.ensure_future(_write_audit(
            username=username,
            role=role,
            method=method,
            path=path,
            status_code=status_code,
            ip=ip,
            duration_ms=duration_ms,
        ))

        return response


def _get_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _write_audit(
    username: str,
    role: str | None,
    method: str,
    path: str,
    status_code: int,
    ip: str,
    duration_ms: int,
) -> None:
    """Écrit une entrée d'audit HTTP en base SQL."""
    try:
        from app.db.database import AsyncSessionLocal
        from app.services.audit_service import log_action
        async with AsyncSessionLocal() as db:
            await log_action(
                db=db,
                username=username,
                role=role,
                action=f"http_{method.lower()}",
                ip_address=ip,
                target=path,
                result="success" if status_code < 400 else "failure",
                detail=f"status={status_code} duration_ms={duration_ms}",
            )
    except Exception as exc:
        # Ne jamais crasher sur un échec d'audit technique
        logger.warning("[AuditMiddleware] Écriture audit échouée: %s", exc)
