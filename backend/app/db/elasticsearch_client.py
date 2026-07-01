#   backend/app/db/elasticsearch.py

#   Rôle:
#       Seul fichier sachant comment se connecter physiquement au cluster ElasticSearch.

#   Toutes les valeurs de connexion sont lues via os.getenv(), jamais écrites en dur ici.
#   Toutes valeurs attendues du .env sera commentée.

import os

from app.core.config import settings
from elasticsearch import AsyncElasticsearch
#   FastAPI est asynchrone donc pas "Elasticsearch synchrone":
#       Une connexion bloquante gèlerait l'event loop de tout le serveur pendant chaque requête vers Elasticsearch.

def _build_client() -> AsyncElasticsearch:
    """
    Construit et retourne une instance du client ES configurée à partir du setting centralisé.
    Fonction privée (préfixe _): Le reste de l'application ne l'appelle jamais directement, seul get_es_client()
        ci-dessous peut être appelé
    """

    #   Construction du dictionnaire de paramètres pour éviter d'appeler AsyncElasticsearch() directement avec tous
    #    les arguments, car certains paramètres sont optionnels et ne doivent être transmis que ce qui existe.
    client_kwargs: dict = {
        "hosts": [settings.elasticsearch_url],
    }

    if settings.elasticsearch_api_key:
        client_kwargs["api_key"] = settings.elasticsearch_api_key
    elif settings.elasticsearch_username and settings.elasticsearch_password:
        client_kwargs["basic_auth"] = (settings.elasticsearch_username, settings.elasticsearch_password)
    else:
        #   Aucune méthode d'autehtnification
        print("[WARNING] Aucune configuration Elasticsearch configurée. Acceptable uniquement sur un cluster local sans protection.")
    
    if settings.elasticsearch_ca_cert_path:
        client_kwargs["ca_certs"] = settings.elasticsearch_ca_cert_path
        client_kwargs["verify_certs"] = True
    else:
        client_kwargs["verify_certs"] = False
        print("[WARNING] ELASTIC_CA_CERT_PATH n'est pas configuré. "
              "La connexion à Elastisearch se fait donc sans vérification du certificat TLS.")
        
    return AsyncElasticsearch(**client_kwargs)

#   Variable globale contenant l'unique instance du client une fois crée (None => Client non construit)
_es_client: AsyncElasticsearch | None = None

def get_es_client() -> AsyncElasticsearch:
    """
    Retourne l'instance partagée du client Elasticsearch.
    Cette fonction est conçue pour être utilisée comme dépendance FastAPI, via Depends(get_es_client),
     dans n'importe que endpoint ayant besoin de lier ou écrire dans Elasticsearch
    Le client n'est créé qu'une seule fois, au premier appel (if _es_client is None), puis réutilisé pour 
     toutes les requêtes suivantes: Ouvrir une nouvelle connexion à chaque requête HTTP serait très coûteux en performance.
    """
    global _es_client
    if _es_client is None:
        _es_client = _build_client()
    return _es_client

async def close_es_client() -> None:
    """
    Ferme proprement la connexion auu cluster Elasticsearch lors de l'arrêt du serveur pour éviter de laisser des 
     connexions ouvertes inutilement après arrêt de l'application.
    """
    global _es_client
    if _es_client is not None:
        await _es_client.close()
        _es_client = None
