#   backend/app/api/v1/routers/logs_stream.py
#
#   Ce fichier expose le flux de logs en temps réel, via Server-Sent Events (SSE).
#   Le cleint ouvre une connexion qui reste ouverte et reçoit chaque nouveau log au fur et à mesure de son ingestion, sans besoin de
#    rafraîchir ou re-interroger périodiquement lui-même; Le serveur pousse lui-même les nouveaux logs aux clients.
#
#   *** REGLE METIER CONFIRMEE  ***
#   Tous les logs doivent apparaître dans le flux au fil du temps (pas seulement à la demande); et les logs de severity "critical"
#    doivent être explicitement mis en avant pour attirer l'attention; ce fichier a aussi le champ "highlight" (pour les logs critiques)
#    , que le front peut utiliser pour afficher différemment (couleur)
#
#   *** IMPLEMENTATION PAR POLLING COURT, PAS PAR ABONNEMENT NATIF  ***
#   Elasticsearch n'a pas de mécanisme natif de "push" vers un client HTTP. Ce flux fonctionne donc par un polling très court (toutes les
#    1 secondes) côté serveur. A chaque itération, recherche de logs avec pour received_at celle postérieur au dernier log déjà envoyé au
#    client.
#   Du point de vue du client, l'expérience reste celle d'un flux continu: le polling est un détail d'implémentation invisible depuis l'extérieur.

import asyncio 
import json

from fastapi import APIRouter, Depends, Request
from fastapi.sse import EventSourceResponse
from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role
from app.modules.rbac.field_visibility import filter_document_for_role

router = APIRouter(prefix="/api/v1/logs", tags=["logs"])

_POLL_INTERNAL_SECONDS = 1

async def _log_event_generator(
    request: Request,
    es_client: AsyncElasticsearch,
    role: str
):
    """
    Générateur esynchrone qui produit un évènement SSE pour chaque nouveau log détecté, dans l'ordre chronologique d'arrivée.
    Paramètres:
        request: Objet de requête FastAPI, utilisé pour détecter si le client a fermé la connexion pour stopper le polling
        es_client: Client Elasticsearch
        role:   Rôle de l'utilisateur connecté, pour appliqué le filtrage de visibilité des champs sur chaque log envoyé.
    """
    last_received_at:       str |   None = None
    
    while True:
        #   Si le client a fermé la connexion (logout), arrête le polling au lieu de continuer à interroger Elasticsearch pour un 
        #    client qui n'écoute plus
        if await request.is_disconnected():
            break

        query_filter = []
        if last_received_at:
            query_filter.append({"range": {"received_at": {"gt": last_received_at}}})

        query = {"bool": {"filter": query_filter}} if query_filter else {"match_all": {}}

        try:
            response = await es_client.search(
                index=settings.es_logs_index_name,
                query=query,
                sort=[{"received_at": {"order": "asc"}}],
                size=100,                                                                   #   Nombre max de logs attrapé en un seul cycle de polling; largement suffisant pour ce cycle
            )
            hits = response["hits"]["hits"]
        except Exception:
            #   Si elasticsearch est temporairement indisponible, ne pas casser le flux SSE. Patiente du prochain cycle.
            hits = []

        for hit in hits:
            document = {"id": hit["_id"], **hit["_source"]}
            last_received_at = document.get("received_at", last_received_at)
            #   Filtrage de visibilité par rôles, cohérent avec les autres endpoints
            visible_document = filter_document_for_role(document, role)

            #   *** MISE EN AVANT DES LOGS CRITIQUES    ***
            #   Champs ajouté automatiquement dans la représentation envoyée au client SSE (jamais persisté dans Elasticsearch)
            #    (simple indicateur pour le frontend)
            visible_document["highlight"] = document.get("severity") == "critical"

            yield {"event": "log", "data": json.dumps(visible_document, default=str)}

        await asyncio.sleep(_POLL_INTERNAL_SECONDS)

    @rputer.get("/stream")
    async def stream_logs(request: Request, 
        es_client: AsyncElasticsearch = Depends(get_es_client), 
        #   Accessible aux 3 rôles: Canal de lecture en temps réel
        user: dict = Depends(require_role("reader")),
        ):
        """
        Flux de logs en temps réel, via Server-Sent Events.
        Rôle requis: reader ou plus
        Le client se connecte une seule fois et reçoit chaque nouveau log au fil de son ingestion, sans avoir à réinterroger l'endpoint.
        Les logs de severity "critical" portent un champ "hightligh": true pour signaler au frontend qu'ils doivent être mis en avant.
        """
        return EventSourceResponse(_log_event_generator(request, es_client, user["role"]))