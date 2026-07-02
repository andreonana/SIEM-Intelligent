#   backend/app/main.py
#
#   Ce fichier est le point d'entrée de l'application FastAPI;
#   Il assemblel'application, branche les divers routeurs HTTP, gère le cycle de vie 
#    de la connexion à Elasticsearch, et définit l'endpointde santé exigé.
#
#   Application servie avec Uvicorn (serveur ASGI), de la façon suivante, depuis le dossier backend/ :
#       uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
#
#   Le nom du module à indiquer à Uvicorn est "app.main", et l'objet FastAPI exposé dans ce fichier s'appelle "app"

from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SHARED_ENV_FILE = _PROJECT_ROOT / ".env"

load_dotenv(dotenv_path=_SHARED_ENV_FILE)

# from backend.app.api.v1 import routers
from fastapi import FastAPI

from app.db.elasticsearch_client    import close_es_client

from app.api.v1.routers.logs            import router as logs_router
from app.api.v1.routers.logs_stream     import router as logs_stream_router
from app.api.v1.routers.retention       import router as retention_router
from app.api.v1.routers.business_hours  import router as business_hours_router
from app.api.v1.routers.entity_unlock   import router as entity_unlock_router
from app.api.v1.routers.auth            import router as auth_router
from app.api.v1.routers.health          import router as health_router
from app.api.v1.routers.alerts          import router as alerts_router
from app.api.v1.routers.dashboard       import router as dashboard_router
from app.api.v1.routers.search          import router as search_router
from app.api.v1.routers.investigation   import router as investigation_router
from app.api.v1.routers.soar            import router as soar_router
from app.api.v1.routers.rules           import router as rules_router
from app.api.v1.routers.reports         import router as reports_router
from app.api.v1.routers.users           import router as users_router
from app.api.v1.routers.audit           import router as audit_router

from app.modules.rbac.retention         import start_retention_scheduler
from app.modules.correlation.service    import start_correlation_scheduler
from app.modules.correlation.lifecycle_service  import log_service_startup, log_service_shutdown
from app.db.elasticsearch_client        import get_es_client

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
        Gère les actions à exécuter au démarrage et à l'arrêt du serveur.
        Tout ce qui se trouve avant l'instruction "yield" s'exécute une seule fois, au démarrage du serveur, avant que la
         première requête ne soit acceptée. Tout ce qui se trouve après "yield" s'exécute une seule fois, à l'arrêt du serveur.
        Séquence de démarrage (avant yield) :
        1. Démarrage du scheduler de rétention (nettoyage quotidien à 02:00 UTC).
        2. Démarrage du scheduler de corrélation (scan périodique).
        3. Log de démarrage du service (lifecycle_service — tag "log hidden").
    Séquence d'arrêt (après yield) :
        4. Log d'arrêt du service (lifecycle_service — tag "log hidden").
        5. Fermeture propre de la connexion Elasticsearch.
    """
    start_retention_scheduler()
    start_correlation_scheduler()

    es=get_es_client()
    await log_service_shutdown(es)

    yield

    await log_service_shutdown(es)
    await close_es_client()

app = FastAPI(
    title="Smart SIEM API",
    version="0.1.0",
    description="API d'ingestion, normalisation et corrélation de logs de sécurité",
    lifespan=lifespan,
)


#   Branchement de tous mles routeurs  de l'API. Chaque routeur définit lui-même son préfixe de chemin.
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(logs_router)
app.include_router(logs_stream_router)
app.include_router(search_router)
app.include_router(alerts_router)
app.include_router(dashboard_router)
app.include_router(users_router)
app.include_router(audit_router)
app.include_router(rules_router)
app.include_router(soar_router)
app.include_router(investigation_router)
app.include_router(reports_router)
app.include_router(retention_router)
app.include_router(business_hours_router)
app.include_router(entity_unlock_router)


@app.get("/health")
async def health_check():
    """
    Endpoint de santé demandé.
    Il reste volontairement indépendant d'Elasticsearch; répond même si le cluster Elasticsearch est 
     temporariement indisponible, ce qui permet à un sustème de supervision de distinguer "l'API tourne"
     de "l'API et sa base de données tournent tous les deux".
    """
    return {"status": "ok"}