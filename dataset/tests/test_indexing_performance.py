"""
Test de performance d'indexation : insère 10 000 logs et mesure
le temps d'une recherche filtrée. Échoue si > 3 secondes.

Lancement : pytest dataset/tests/test_indexing_performance.py -v
"""

import random
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from elasticsearch import helpers

from app.db.elasticsearch_client import get_client

INDEX = "logs-siem"
VOLUME = 10_000
MAX_RESPONSE_TIME_S = 3.0

LOG_TYPES = ["auth", "réseau", "système", "application"]
SEVERITIES = ["info", "warning", "critical"]


def _make_log(base_time: datetime) -> dict:
    offset = timedelta(hours=random.uniform(0, 168))
    return {
        "timestamp":   (base_time - offset).isoformat(),
        "source_ip":   f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "host":        random.choice(["web-01", "db-01", "auth-srv", "proxy"]),
        "log_type":    random.choice(LOG_TYPES),
        "severity":    random.choices(SEVERITIES, weights=[0.6, 0.3, 0.1])[0],
        "raw_message": f"perf-test-{uuid.uuid4()}",
        "tags":        ["perf-test"],
    }


@pytest.fixture(scope="module")
def es_client():
    return get_client()


@pytest.fixture(scope="module", autouse=True)
def bulk_insert_logs(es_client):
    """Insère 10 000 logs avant les tests, nettoie après."""
    base_time = datetime.now(timezone.utc)
    actions = [
        {"_index": INDEX, "_source": _make_log(base_time)}
        for _ in range(VOLUME)
    ]
    helpers.bulk(es_client, actions)
    es_client.indices.refresh(index=INDEX)
    yield
    # Nettoyage : supprime uniquement les docs du test de perf
    es_client.delete_by_query(
        index=INDEX,
        query={"term": {"tags": "perf-test"}},
        refresh=True,
    )


def test_bulk_insert_volume(es_client):
    """Vérifie que des documents ont bien été indexés."""
    resp = es_client.count(index=INDEX, query={"term": {"tags": "perf-test"}})
    assert resp["count"] >= VOLUME, (
        f"Attendu ≥ {VOLUME} docs, trouvé {resp['count']}"
    )


def test_filtered_search_under_3_seconds(es_client):
    """Une recherche filtrée (plage horaire + severity) doit répondre en < 3s."""
    start = time.perf_counter()
    resp = es_client.search(
        index=INDEX,
        size=100,
        query={
            "bool": {
                "filter": [
                    {"term": {"severity": "warning"}},
                    {"range": {"timestamp": {"gte": "now-7d/d", "lte": "now"}}},
                ]
            }
        },
    )
    elapsed = time.perf_counter() - start

    print(f"\n  Résultats : {resp['hits']['total']['value']} docs")
    print(f"  Temps     : {elapsed:.3f}s (limite : {MAX_RESPONSE_TIME_S}s)")

    assert elapsed < MAX_RESPONSE_TIME_S, (
        f"Recherche trop lente : {elapsed:.3f}s > {MAX_RESPONSE_TIME_S}s"
    )
