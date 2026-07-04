# tests/unit/s2/test_search_investigation.py
#
# Tests de la recherche multi-critères (S2 Data) et de l'investigation
# forensique : construction de la requête ES, contrat des endpoints,
# ordre chronologique de la timeline, marquage suspect, RBAC.

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# _build_query — construction de la requête Elasticsearch (fonction pure)
# ---------------------------------------------------------------------------

def test_build_query_no_criteria_is_match_all():
    from app.api.v1.routers.search import _build_query, SearchRequest
    query = _build_query(SearchRequest())
    assert query == {"match_all": {}}


def test_build_query_source_ip():
    from app.api.v1.routers.search import _build_query, SearchRequest
    query = _build_query(SearchRequest(source_ip="198.51.100.77"))
    assert {"term": {"source_ip.keyword": "198.51.100.77"}} in query["bool"]["filter"]


def test_build_query_username_matches_raw_message():
    """Le champ 'username' du CDC (recherche par utilisateur) est traduit en
    recherche plein texte sur raw_message, faute de champ 'username' structuré
    dans le pipeline de normalisation actuel."""
    from app.api.v1.routers.search import _build_query, SearchRequest
    query = _build_query(SearchRequest(username="root"))
    assert {"match": {"raw_message": "root"}} in query["bool"]["filter"]


def test_build_query_severity_and_log_type():
    from app.api.v1.routers.search import _build_query, SearchRequest
    query = _build_query(SearchRequest(severity="critical", log_type="auth"))
    assert {"term": {"severity.keyword": "critical"}} in query["bool"]["filter"]
    assert {"term": {"log_type.keyword": "auth"}} in query["bool"]["filter"]


def test_build_query_date_range_both_bounds():
    from app.api.v1.routers.search import _build_query, SearchRequest
    query = _build_query(SearchRequest(start_date="2026-01-01", end_date="2026-01-31"))
    assert {"range": {"received_at": {"gte": "2026-01-01", "lte": "2026-01-31"}}} in query["bool"]["filter"]


def test_build_query_date_range_start_only():
    from app.api.v1.routers.search import _build_query, SearchRequest
    query = _build_query(SearchRequest(start_date="2026-01-01"))
    assert {"range": {"received_at": {"gte": "2026-01-01"}}} in query["bool"]["filter"]


def test_build_query_combines_all_criteria():
    from app.api.v1.routers.search import _build_query, SearchRequest
    query = _build_query(SearchRequest(
        source_ip="10.0.0.5", host="web-srv", log_type="auth",
        severity="critical", username="admin",
        start_date="2026-01-01", end_date="2026-01-02",
    ))
    assert len(query["bool"]["filter"]) == 6


# ---------------------------------------------------------------------------
# POST /api/search — endpoint (client ES simulé)
# ---------------------------------------------------------------------------

def _fake_es_hit(hit_id, source_ip="198.51.100.77", severity="critical"):
    return {
        "_id": hit_id,
        "_source": {
            "timestamp": "2026-07-01T10:00:00+00:00",
            "source_ip": source_ip,
            "host": "web-srv",
            "log_type": "auth",
            "severity": severity,
            "raw_message": "Failed password for root",
        },
    }


@pytest.mark.asyncio
async def test_search_endpoint_passes_criteria_to_es_and_returns_envelope():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.v1.routers.search import router
    from app.db.elasticsearch_client import get_es_client
    from app.modules.rbac.roles import get_current_user

    mock_es = AsyncMock()
    mock_es.search = AsyncMock(return_value={
        "hits": {"total": {"value": 1}, "hits": [_fake_es_hit("log-1")]},
    })

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_es_client] = lambda: mock_es
    app.dependency_overrides[get_current_user] = lambda: {"username": "admin", "role": "administrator"}

    client = TestClient(app)
    resp = client.post("/api/search", json={
        "source_ip": "198.51.100.77", "severity": "critical", "log_type": "auth",
        "page": 1, "page_size": 25,
    })

    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["page"] == 1
    assert body["page_size"] == 25
    assert body["results"][0]["source_ip"] == "198.51.100.77"
    assert body["results"][0]["severity"] == "critical"

    # Vérifie que les critères sont bien transmis à Elasticsearch (pas un filtre local).
    called_query = mock_es.search.call_args.kwargs["query"]
    assert {"term": {"source_ip.keyword": "198.51.100.77"}} in called_query["bool"]["filter"]
    assert {"term": {"severity.keyword": "critical"}} in called_query["bool"]["filter"]
    assert {"term": {"log_type.keyword": "auth"}} in called_query["bool"]["filter"]


@pytest.mark.asyncio
async def test_search_endpoint_es_failure_returns_503():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.v1.routers.search import router
    from app.db.elasticsearch_client import get_es_client
    from app.modules.rbac.roles import get_current_user

    mock_es = AsyncMock()
    mock_es.search = AsyncMock(side_effect=ConnectionError("ES down"))

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_es_client] = lambda: mock_es
    app.dependency_overrides[get_current_user] = lambda: {"username": "admin", "role": "administrator"}

    client = TestClient(app)
    resp = client.post("/api/search", json={})
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# GET /api/investigation/{entity_id} — timeline chronologique
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_investigation_endpoint_returns_ordered_timeline():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.v1.routers.investigation import router

    mock_es = AsyncMock()
    mock_es.search = AsyncMock(return_value={
        "hits": {"hits": [
            _fake_es_hit("e1", severity="warning"),
            _fake_es_hit("e2", severity="critical"),
        ]},
    })

    app = FastAPI()
    app.include_router(router)

    from app.modules.rbac.roles import get_current_user
    app.dependency_overrides[get_current_user] = lambda: {"username": "admin", "role": "administrator"}

    with patch("app.api.v1.routers.investigation.get_es_client", return_value=mock_es):
        client = TestClient(app)
        resp = client.get("/api/investigation/198.51.100.77")

    assert resp.status_code == 200
    body = resp.json()
    assert body["entity_id"] == "198.51.100.77"
    assert len(body["timeline"]) == 2
    # Champs minimums requis par le CDC pour la timeline horodatée
    for field in ("timestamp", "source_ip", "host", "log_type", "severity", "raw_message"):
        assert field in body["timeline"][0]

    called_query = mock_es.search.call_args.kwargs["query"]
    assert {"term": {"source_ip.keyword": "198.51.100.77"}} in called_query["bool"]["should"]
    assert {"term": {"host.keyword": "198.51.100.77"}} in called_query["bool"]["should"]
    assert mock_es.search.call_args.kwargs["sort"] == [{"received_at": "asc"}]


@pytest.mark.asyncio
async def test_investigation_endpoint_es_down_returns_empty_timeline_not_crash():
    """Comportement honnête : si Elasticsearch est indisponible, la timeline
    est vide plutôt que de faire planter l'investigation (dégradation propre)."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.v1.routers.investigation import router
    from app.modules.rbac.roles import get_current_user

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: {"username": "admin", "role": "administrator"}

    with patch("app.api.v1.routers.investigation.get_es_client", side_effect=ConnectionError("ES down")):
        client = TestClient(app)
        resp = client.get("/api/investigation/198.51.100.77")

    assert resp.status_code == 200
    assert resp.json()["timeline"] == []


def test_rbac_reader_cannot_access_investigation():
    """L'investigation exige le rôle analyst ou plus — un reader est bloqué."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.v1.routers.investigation import router

    app = FastAPI()
    app.include_router(router)
    reader_payload = {"sub": "1", "username": "reader_user", "role": "reader"}

    with patch("app.modules.rbac.roles.decode_access_token", return_value=reader_payload):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/investigation/198.51.100.77",
            headers={"Authorization": "Bearer fake_reader_token"},
        )

    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/investigation/{entity_id}/flag — marquage suspect
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_flag_investigation_persists_and_logs_audit():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.v1.routers.investigation import router
    from app.db.database import get_db
    from app.modules.rbac.roles import get_current_user

    mock_flag = MagicMock()
    mock_flag.id = 7

    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()

    async def _refresh(obj):
        obj.id = 7
    db.refresh = AsyncMock(side_effect=_refresh)

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: {"username": "analyst_user", "role": "analyst"}
    app.dependency_overrides[get_db] = lambda: db

    with patch("app.api.v1.routers.investigation.log_action", new=AsyncMock()) as mock_log:
        client = TestClient(app)
        resp = client.post("/api/investigation/198.51.100.77/flag", json={"note": "Comportement suspect"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["entity_id"] == "198.51.100.77"
    assert body["flagged_by"] == "analyst_user"
    assert body["status"] == "flagged"
    db.add.assert_called_once()
    db.commit.assert_called_once()
    mock_log.assert_called_once()
