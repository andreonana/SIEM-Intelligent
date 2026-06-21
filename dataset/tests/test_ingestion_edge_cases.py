"""
Tests des cas limites d'ingestion :
- Document malformé (champ obligatoire manquant) → erreur catchée proprement
- 1000 documents en un seul bulk → tous présents sans perte
- Deux documents identiques → indexés séparément (doublons autorisés en SIEM)

Lancement : pytest dataset/tests/test_ingestion_edge_cases.py -v
"""

import time
import uuid
from datetime import datetime, timezone

import pytest
from elasticsearch import helpers
from elasticsearch.exceptions import RequestError

from app.db.elasticsearch_client import get_client

INDEX = "logs-siem"

_VALID_LOG = {
    "timestamp":   "2024-01-15T10:30:00+00:00",
    "source_ip":   "192.168.1.100",
    "host":        "test-host",
    "log_type":    "auth",
    "severity":    "warning",
    "raw_message": "test message",
    "tags":        ["edge-case-test"],
}


@pytest.fixture(scope="module")
def es_client():
    return get_client()


@pytest.fixture(autouse=True)
def cleanup(es_client):
    """Nettoie les documents de test après chaque test."""
    yield
    es_client.delete_by_query(
        index=INDEX,
        query={"term": {"tags": "edge-case-test"}},
        refresh=True,
    )


# ── Test 1 : document malformé ────────────────────────────────────────────────

def test_malformed_document_fails_gracefully(es_client):
    """
    Un document avec source_ip invalide doit provoquer une erreur ES
    catchée proprement — aucun plantage non géré.
    """
    malformed = {
        "timestamp":   "2024-01-15T10:30:00+00:00",
        "source_ip":   "NOT_AN_IP",   # type ip → rejette les valeurs non-IP
        "host":        "test-host",
        "log_type":    "auth",
        "severity":    "info",
        "raw_message": "malformed doc",
        "tags":        ["edge-case-test"],
    }

    caught_error = None
    try:
        es_client.index(index=INDEX, document=malformed, refresh=True)
    except Exception as exc:
        caught_error = exc

    # Le client doit lever une exception (pas de succès silencieux)
    assert caught_error is not None, (
        "Un document avec source_ip invalide aurait dû lever une exception"
    )
    # Et ce doit être une erreur ES de type 400 (mapper_parsing_exception)
    assert isinstance(caught_error, RequestError), (
        f"Exception inattendue : {type(caught_error).__name__}: {caught_error}"
    )


# ── Test 2 : bulk de 1000 documents ──────────────────────────────────────────

def test_bulk_1000_documents_no_loss(es_client):
    """1000 documents insérés en une seule opération bulk → tous présents."""
    batch_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    actions = [
        {
            "_index": INDEX,
            "_source": {
                **_VALID_LOG,
                "timestamp":   now,
                "raw_message": f"bulk-test-{i}-{batch_id}",
                "tags":        ["edge-case-test", batch_id],
            },
        }
        for i in range(1000)
    ]

    success, errors = helpers.bulk(es_client, actions, raise_on_error=False)
    es_client.indices.refresh(index=INDEX)

    assert not errors, f"{len(errors)} erreurs lors du bulk : {errors[:3]}"

    resp = es_client.count(index=INDEX, query={"term": {"tags": batch_id}})
    assert resp["count"] == 1000, (
        f"Perte de données : attendu 1000, trouvé {resp['count']}"
    )


# ── Test 3 : doublons autorisés ───────────────────────────────────────────────

def test_duplicate_documents_both_indexed(es_client):
    """
    Deux documents strictement identiques doivent être indexés séparément.
    En SIEM, les doublons sont intentionnels (même événement reçu deux fois).
    """
    duplicate_id = str(uuid.uuid4())
    doc = {
        **_VALID_LOG,
        "raw_message": f"duplicate-{duplicate_id}",
        "tags":        ["edge-case-test", duplicate_id],
    }

    # Insertion sans _id explicite → ES génère des IDs distincts
    es_client.index(index=INDEX, document=doc)
    es_client.index(index=INDEX, document=doc)
    es_client.indices.refresh(index=INDEX)

    resp = es_client.count(
        index=INDEX,
        query={"term": {"tags": duplicate_id}},
    )
    assert resp["count"] == 2, (
        f"Attendu 2 documents (doublons), trouvé {resp['count']}"
    )
