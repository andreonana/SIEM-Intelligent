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

from backend.app.api.v1 import routers
from fastapi import FastAPI

from app.api.v1.routers.logs import router as logs_routers
from app.db.elasticsearch_client import close_es_client

@asynccontextmanager
async def lifespace(app: FastAPI):
    """
    Gère les actions à exécuter au démarrage et à l'arrêt du serveur.
    Tout ce qui se trouve avant l'instruction "yield" s'exécute une seule fois, au démarrage du serveur, avant que la
     première requête ne soit acceptée. Tout ce qui se trouve après "yield" s'exécute une seule fois, à l'arrêt du serveur.
    """
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
    description="API d'ingestion, normalisation et corrélation de logs de sécurité"
)

#   Branchement du routeur de logs (endpoints d'ingestion) défini dans backend/app/api/v1/routers/logs.py
app.include_router(logs_routers)

#   *** ENDPOINT LOGIN START    ***
#
#   Aucun routeur d'authentification n'est branché ici à ce jour.
#
#   Le fichier auth.py gère le login, hachage de passwords et création de tokes JWT.
#   Une fois le fichier reçu, il devra suivre le même schéma pour logs_router:
#
#   from auth import router as auth_router
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

@app.get("/health")
async def health_check():
    """
    Endpoint de santé
    """
    return {"status": "ok"}