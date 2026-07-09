"""
Client Elasticsearch réutilisable pour le module DATA de Smart SIEM.
Usage : from app.db.elasticsearch_client import get_client
"""

import os
from pathlib import Path
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

# Charge le .env depuis le répertoire dataset/
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(_BASE_DIR / ".env")

ES_HOST = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")


def get_client() -> Elasticsearch:
    """Retourne un client Elasticsearch connecté et vérifié."""
    try:
        client = Elasticsearch(hosts=[ES_HOST], request_timeout=30)
        if not client.ping():
            raise ConnectionError(
                f"Elasticsearch ne répond pas sur {ES_HOST}. "
                "Vérifiez que le service est démarré."
            )
        return client
    except ConnectionError:
        raise
    except Exception as exc:
        raise ConnectionError(
            f"Impossible de se connecter à Elasticsearch ({ES_HOST}) : {exc}"
        ) from exc
