#   backend/app/modules/rbac/local_protection.py
#
#   Ce fichier contient une sécurité LOCALE et BASIQUE qui protège uniquement les fonctions de CE MODULE (ingestion de logs) contre
#    un usage direct abusif.
# 
#   Elle est strictement complémentaire au système de sécurité global (auth, gestion des rôles) 
#    fournies sous forme de fichiers à importer.
#
#   Périmètre exact de ce fichier (A NE PAS FAIRE PAR LUI):
#       - Ne pas remplacer auth.py (login, hachage passwords, créations tokens JWT).
#       - Ne pas remplacer rbac.py (fonction require_role() protégeant l'endpoint selon user' role)
#        - Fournir seulement 2 protections complémentaires et purement techniques, utiles avant même que l'auth complète ne soit branchée:
#           1. Une clé API statique de secours, utilisable en tout début de développement;
#           2. Une limitation de débit (rate limiting) protégeant spécifiquement l'endpoint d'ingestion contre un flot de requêtes excessif,
#               qui satureraut Elasticsearch ou l'API elle-même. Une préoccupation purement technique, sans rapport avec la notion de user role

import os
import time
from collections import defaultdict

from fastapi import Header, HTTPException, Request, status

#   ********    DEPENDANCE EXTERNE  ********
#   Variable: INGEST_API_KEY attendue dans le fichier .env racine du projet
#   Clé statique utilisée pour une protection minimale de l'endpointd'ingestion, en attendant le branchement complet du système d'authentification.
#
#   Une valeur de secours est fournie par défaut ("dev-only-change-me") pour ne jamais bloquer le démarrage de l'application avant que .env ne soit disponible.
#   Cette valeur est explicitement nommée pour qu'elle ne puisse jamais être cnfondue avec une vraie clé de production en cas de subsistance par erreur.
INGEST_API_KEY = os.getenv("INGEST_API_KEY", "dev-only-change-me")

def verify_simple_api_key(x_api_key: str = Header(...)) -> None:
    """
    Vérifie la présence et la validité d'une clé API statique transmise dans l'en-tête HTTP "X-API-KEY".
    Header(...) signifie que cet en-tête est obligatoire. Si l'appelant ne la fournit pas, 
     FastAPI renvoie automatiquement une erreur avant même l'exécution de cette fonction.
     Lève une HTTPException 401 si la clé fournie ne corespond pas à celle attendue.
    """
    if x_api_key != INGEST_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Clé API invalide ou manquante.",
        )

#   --------    Limitation de débit (ate limiting)  --------
#
#   Implémentation en mémoire (dictionnaire Python), donc valable uniquement pour une seule instance de serveur en cours d'exécution.
#   Si l'application devait un jour tourner sur plusieurs instances en parallèle, cette protection devrait un jour être déplacée vers 
#    un système de stockage partagé entre instances. Pas nécessaire pour le périmètre actuel du projet.
_request_timestamps: dict[str, list[float]] = defaultdict(list)

_RATE_LIMIT_MAX_REQUESTS = 100
#   Nombre maximal de requêtes autorisées par fenêtre de temps glissante.

_RATE_LIMIT_WINDOW_SECONDS = 60
#   Duée de la fenêtre gilssante, en secondes.

def enforce_rate_limit(request: Request) -> None:
    """
    Limite le nombre de requêtes acceptées par adresse IP appelante, sur une fenêtre glissante de _RATE_LIMIT_WINDOW_SECONDS secondes.
    La limitation se fait par adesse IP cliente plutôt que par clé API, car plusieurs sources de logs différentes (agents, récepteur Syslog)
     pourraient partager la même clé API simple:
        Limiter par IP protège chaque source indépendamment, sans qu'une source défaillante n'affecte les autres.
    Lève une HTTPException 429 ("Too Many Requests") si la limite est dépassée.
    """
    client_ip = request.client.host if request.client else "unknown"

    #   time.monotonic() est utilisé plutîot que time.time() car il ne peut jamais "reculer" contrairement ) l'horloge système resynchronisable;
    #    efficace pour un calcul fiable de fenêtre glissante.
    now = time.monotonic()

    timestamps = _request_timestamps[client_ip]

    #   Retrait des hordatages trop anciens (hors de la fenêtre) avant de compter les requêtes restantes.
    #   Sans cette purge, le dictionnaire accumulerait indéfiniment des entrées obsolètes en mémoire sur un serveur qui tourne longtemps
    cutoff = now - _RATE_LIMIT_WINDOW_SECONDS
    while timestamps and timestamps[0] < cutoff:
        timestamps.pop(0)

    if len(timestamps) >= _RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Limite de {_RATE_LIMIT_MAX_REQUESTS} requêtes par "
                f"{_RATE_LIMIT_WINDOW_SECONDS} secondes dépassées pour cette source"
            ),
        )

    timestamps.append(now)