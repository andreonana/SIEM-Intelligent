#   backend/app/db/elasticsearch.py

#   Rôle:
#       Seul fichier sachant comment se connecter physiquement au cluster ElasticSearch.

#   Toutes les valeurs de connexion sont lues via os.getenv(), jamais écrites en dur ici.
#   Toutes valeurs attendues du .env sera commentée.

import os

from elasticsearch import AsyncElasticsearch
#   FastAPI est asynchrone donc pas "Elasticsearch synchrone":
#       Une connexion bloquante gèlerait l'event loop de tout le serveur pendant chaque requête vers Elasticsearch.

def _build_client() -> AsyncElasticsearch:
    """
    Construit le client ES à partir des variables d'environnement.
    Fonction privée (préfixe _): Le reste de l'application ne l'appelle jamais directement, seul get_es_client()
        ci-dessous peut être appelé
    """

    #   --------    Variable attendue dans le .env  ----------
    #   ##  ELASTICSEARCH_URL est attendu dans .env racinde du projet fourni par l'infra.
    #       C'est l'adresse réseau du cluster Elasticsearch, permettant de diriger où envoyer les logs.
    es_url = os.getenv("ELASTICSEARCH_URL")
    if not es_url:
        raise RuntimeError(
            "ELASTICSEARCH_URL manquante dans l'environnement. "
            "Cette variable doit être fournie dans le .env partagé du projet."
            "Sans elle, impossible de savoir à quel ElasticSearch se connecter."
        )

    #   --------    Authentification    --------
    #   Element à fournir dans le .env racine du projet par la sécurité pour clé d'authentification auprès du
    #        cluster d'Elasticsearch.
    #       Optionnelle si ELASTIC_USERNAME et ELASTIC_PASSWORD sont fournis à la place 
    #   Cas 1: Avec clé d'API fournie par la sécurité pour gérer l'authentification au cluster ES dans son périmètre.
    api_key = os.getenv("ELASTIC_API_KEY")

    #   Cas 2:  Authentification basique sans clé API dont les données sont toujours fournies par la sécurité
    es_username = os.getenv("ELASTIC_USERNAME")
    es_password = os.getenv("ELASTIC_PASSWORD")

    #   --------    TLS:    Certificats générés par la sécurité --------
    #   Variable attendue dans .env racine du projet de la part de la sécurité comme le chemin 
    #    local vers le certificat présent dans git.ignore, donc à recevoir en direct.
    ca_cert_path = os.getenv("ELASTIC_CA_CERT_PATH")

    #   Construction du dictionnaire de paramètres pour éviter d'appeler AsyncElasticsearch() directement avec tous
    #    les arguments, car certains paramètres sont optionnels et ne doivent être transmis que ce qui existe.
    client_kwargs: dict = {
        "hosts": [es_url],
    }

    if api_key:
        client_kwargs["api_key"] = api_key
    elif es_username and es_password:
        client_kwargs["basic_auth"] = (es_username, es_password)
    else:
        #   Aucune méthode d'autehtnification
        print("[WARNING] Aucune configuration Elasticsearch configurée. Acceptable uniquement sur un cluster local sans protection.")
    
    if ca_cert_path:
        client_kwargs["ca_certs"] = ca_cert_path
        client_kwargs["verify_ccerts"] = True
    else:
        client_kwargs["verify_ccerts"] = False
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
