# backend/app/middleware/rate_limiter.py
#
# Rate limiter en mémoire (sliding window) — sans dépendance Redis.
# Respecte settings.rate_limit_max_requests par settings.rate_limit_window_seconds.
#
# Appliqué via app.add_middleware(RateLimiterMiddleware) dans main.py.
# Retourne HTTP 429 avec Retry-After si la limite est dépassée.
#
# Protège surtout les endpoints d'ingestion et d'auth.
# Les routes /health, /docs, /openapi.json sont exclues.

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings

# Routes exclues du rate limiting (monitoring, docs)
_EXCLUDED_PREFIXES = ("/health", "/docs", "/openapi.json", "/redoc")

# Endpoints soumis à une limite plus stricte (10x moins)
_STRICT_PREFIXES = ("/api/auth/login",)


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    Middleware de rate limiting par IP, fenêtre glissante en mémoire.
    Utilise une deque par (ip, endpoint_bucket) pour compter les requêtes.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._buckets: dict[str, deque] = defaultdict(deque)
        self._max_req = settings.rate_limit_max_requests
        self._window = settings.rate_limit_window_seconds
        # Limite stricte pour auth : max_requests // 10, min 5
        self._strict_max = max(5, self._max_req // 10)

    def _get_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _is_strict(self, path: str) -> bool:
        return any(path.startswith(p) for p in _STRICT_PREFIXES)

    def _bucket_key(self, ip: str, path: str) -> str:
        # Groupe les sous-chemins en famille pour éviter l'explosion de clés
        if path.startswith("/api/ingest") or path.startswith("/api/logs"):
            bucket = "ingest"
        elif path.startswith("/api/auth"):
            bucket = "auth"
        else:
            bucket = "api"
        return f"{ip}:{bucket}"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Exclure routes monitoring et docs
        if any(path.startswith(p) for p in _EXCLUDED_PREFIXES):
            return await call_next(request)

        ip = self._get_ip(request)
        key = self._bucket_key(ip, path)
        now = time.monotonic()
        window = self._window
        max_req = self._strict_max if self._is_strict(path) else self._max_req

        bucket = self._buckets[key]

        # Purger les timestamps hors fenêtre
        while bucket and bucket[0] < now - window:
            bucket.popleft()

        if len(bucket) >= max_req:
            retry_after = int(window - (now - bucket[0])) + 1
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Trop de requêtes. Réessayez dans {retry_after} secondes.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        bucket.append(now)
        return await call_next(request)
