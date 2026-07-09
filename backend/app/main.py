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

from app.db.elasticsearch_client import close_es_client

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

from app.modules.rbac.retention import router as retention_router, start_retention_scheduler

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gère les actions à exécuter au démarrage et à l'arrêt du serveur.
    Tout ce qui se trouve avant l'instruction "yield" s'exécute une seule fois, au démarrage du serveur, avant que la
     première requête ne soit acceptée. Tout ce qui se trouve après "yield" s'exécute une seule fois, à l'arrêt du serveur.
    """
    start_retention_scheduler()
    #   Aucune action n'est nécessaire au démarrage à ce jour:
    #   La connexion au cluster Elasticsearch est créée automatiqeument, de façon différée, au premier appel réel à
    #    get_es_client() (db/elasticsearch_client). Il n'y a donc rien à initialiser explicitement ici.
    yield

    #   A l'arrêt du serveur, on ferme proprement la connexion ouverte vers Elasticsearch, pour éviter de laisser des connexions
    #    réseau inutilement ouvertes après l'arrêt de l'application.
    await close_es_client()

app = FastAPI(
    title="Smart SIEM API",
    version="0.1.0",
    description="API d'ingestion, normalisation et corrélation de logs de sécurité",
    lifespan=lifespan,
)

#   Branchement du routeur de logs (endpoints d'ingestion) défini dans backend/app/api/v1/routers/logs.py
app.include_router(logs_router)

#   *** ENDPOINT LOGIN START    ***
#
#   Aucun routeur d'authentification n'est branché ici à ce jour.
#
#   Le fichier auth.py gère le login, hachage de passwords et création de tokes JWT.
#   Une fois le fichier reçu, il devra suivre le même schéma pour logs_router:
#
#   from app.modules.rbac.auth import router as auth_router
#   app.include_router(auth_router)
#
#   Nom exact du routeur doit être update à la réception.
#
#   *** ENDPOINT LOGIN END  ***

#   *** MODULE RETENTION START  ***
#
#   Aucune tâche de rétention/nettoyage automatique n'est branchée ici à
#    ce jour.
#
#   Le fichier retention.py, à recevoir de l'équipe sécurité, expose un
#    routeur et une fonction de démarrage de planification, à brancher
#    exactement de la façon suivante une fois ce fichier reçu et placé
#    dans le projet :
#
#   from retention import router as retention_router, start_retention_scheduler
#
#   app.include_router(retention_router)
#
#   @app.on_event("startup")
#   def on_startup():
#       start_retention_scheduler()
#
#   Remarque : la syntaxe @app.on_event("startup") est celle indiquée
#    par l'équipe sécurité pour ce fichier précis. Elle coexiste sans
#    conflit avec le gestionnaire "lifespan" défini plus haut dans ce
#    fichier, qui gère par ailleurs la fermeture de la connexion
#    Elasticsearch — FastAPI accepte les deux mécanismes en parallèle.
#
#   *** MODULE RETENTION END    ***

#   Beanchement de tous mles routeurs  de l'API. Chaque routeur définit lui-même son préfixe de chemin.
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

#   *** MODULE RETENTION START  ***
#
#   Branche l'nedpoint POST /api/admin/retnetion/run, défini directement dnas backend/retention.py protégé
#    par require_role("administrateur")
app.include_router(retention_router)
#   *** MODULE RETENTION END    ***

@app.get("/health")
async def health_check():
    """
    Endpoint de santé demandé.
    Il reste volontairement indépendant d'Elasticsearch; répond même si le cluster Elasticsearch est 
     temporariement indisponible, ce qui permet à un sustème de supervision de distinguer "l'API tourne"
     de "l'API et sa base de données tournent tous les deux".
    """
    return {"status": "ok"}