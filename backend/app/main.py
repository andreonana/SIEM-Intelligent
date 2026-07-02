#   backend/app/main.py
#
#   Point d'entrée FastAPI — V3.
#   Branche les middlewares (rate limiter, auth context, audit HTTP),
#   les routeurs, le scheduler APScheduler pour SOAR CONFIRM,
#   et gère le cycle de vie complet.

from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SHARED_ENV_FILE = _PROJECT_ROOT / ".env"

load_dotenv(dotenv_path=_SHARED_ENV_FILE)

from fastapi import FastAPI

from app.db.elasticsearch_client import close_es_client
from app.db.database import init_db, AsyncSessionLocal
from app.services.user_service import seed_demo_users
from app.services.alert_service import seed_correlation_rules

from app.api.v1.routers.logs import router as logs_router
from app.api.v1.routers.auth import router as auth_router
from app.api.v1.routers.health import router as health_router
from app.api.v1.routers.alerts import router as alerts_router
from app.api.v1.routers.dashboard import router as dashboard_router
from app.api.v1.routers.search import router as search_router
from app.api.v1.routers.investigation import router as investigation_router
from app.api.v1.routers.soar import router as soar_router
from app.api.v1.routers.rules import router as rules_router
from app.api.v1.routers.reports import router as reports_router
from app.api.v1.routers.users import router as users_router
from app.api.v1.routers.audit import router as audit_router
from app.api.v1.routers.correlation import router as correlation_router
from app.api.v1.routers.ueba import router as ueba_router
from app.api.v1.routers.integrity import router as integrity_router
from app.api.v1.routers.system import router as system_router
from app.modules.rbac.retention import router as retention_router, start_retention_scheduler

# Middlewares V3
from app.middleware.rate_limiter import RateLimiterMiddleware
from app.middleware.auth_middleware import AuthContextMiddleware
from app.middleware.audit_logger import AuditLoggerMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialisation SQL et seeds
    await init_db()
    async with AsyncSessionLocal() as db:
        await seed_demo_users(db)
        await seed_correlation_rules(db)

    # Scheduler de rétention (logs ES)
    start_retention_scheduler()

    # Scheduler APScheduler pour SOAR CONFIRM
    from apscheduler.schedulers.background import BackgroundScheduler
    from app.modules.soar.dispatcher import set_scheduler
    soar_scheduler = BackgroundScheduler()
    soar_scheduler.start()
    set_scheduler(soar_scheduler)

    yield

    # Arrêt propre
    soar_scheduler.shutdown(wait=False)
    await close_es_client()


app = FastAPI(
    title="Smart SIEM API",
    version="3.0.0",
    description="API SIEM — corrélation, SOAR auto, UEBA, chaîne de custody SHA-256",
    lifespan=lifespan,
)

# ── Middlewares (ordre : dernier ajouté = premier exécuté) ────────────────
# 1. Rate limiter — rejet 429 avant tout traitement
app.add_middleware(RateLimiterMiddleware)
# 2. Auth context — décode JWT, peuple request.state.username
app.add_middleware(AuthContextMiddleware)
# 3. Audit HTTP — journalise les requêtes mutantes
app.add_middleware(AuditLoggerMiddleware)

# ── Routeurs ──────────────────────────────────────────────────────────────
app.include_router(logs_router)
app.include_router(auth_router)
app.include_router(health_router)
app.include_router(alerts_router)
app.include_router(dashboard_router)
app.include_router(search_router)
app.include_router(investigation_router)
app.include_router(soar_router)
app.include_router(rules_router)
app.include_router(reports_router)
app.include_router(users_router)
app.include_router(audit_router)
app.include_router(correlation_router)
app.include_router(ueba_router)
app.include_router(integrity_router)
app.include_router(system_router)
app.include_router(retention_router)


@app.get("/health")
async def health_check():
    return {"status": "ok"}
