# tests/test_s1.py — Tests de conformité S1
#
# Stratégie :
#  - Base SQL   : SQLite en mémoire via dependency_overrides (pas de fichier sur disque)
#  - Elasticsearch : AsyncMock via dependency_overrides
#  - Scheduler APScheduler : désactivé en test via mock
#  - Tous les tests sont indépendants et ne partagent pas d'état DB

import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.database import Base, get_db
from app.db.elasticsearch_client import get_es_client
from app.main import app
from app.modules.rbac.auth import create_access_token
from app.models.user import User
from app.models.audit_log import AuditLog
from app.services import user_service
from app.modules.normalisation.service import normalize, normalize_json
from app.modules.normalisation.parsers.json_parser import JSONLogParser


# ─── DB SQLite en mémoire pour les tests ──────────────────────────────────────

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

_test_engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
_TestSessionLocal = async_sessionmaker(_test_engine, class_=AsyncSession, expire_on_commit=False)


async def _init_test_db():
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Seed comptes de démo
    async with _TestSessionLocal() as db:
        await user_service.seed_demo_users(db)


async def _get_test_db():
    async with _TestSessionLocal() as session:
        yield session


# Initialise la DB de test une seule fois au chargement du module
asyncio.get_event_loop().run_until_complete(_init_test_db())


# ─── Mock Elasticsearch ────────────────────────────────────────────────────────

def make_mock_es_index(doc_id: str = "abc123"):
    mock = AsyncMock()
    mock.index = AsyncMock(return_value={"_id": doc_id})
    return mock


def make_mock_es_search(hits: list, total: int):
    mock = AsyncMock()
    mock.search = AsyncMock(return_value={
        "hits": {"hits": hits, "total": {"value": total}}
    })
    return mock


# ─── Helper tokens ────────────────────────────────────────────────────────────

def token(role: str, username: str = "testuser") -> str:
    return create_access_token(user_id="99", username=username, role=role)


def auth(role: str) -> dict:
    return {"Authorization": f"Bearer {token(role)}"}


# ─── Fixture client avec DB de test et ES mocké ───────────────────────────────

@pytest.fixture
def client():
    mock_es = AsyncMock()
    app.dependency_overrides[get_db] = _get_test_db
    app.dependency_overrides[get_es_client] = lambda: mock_es
    # Désactive le scheduler APScheduler au démarrage du TestClient
    with patch("app.modules.rbac.retention.BackgroundScheduler") as mock_sched:
        mock_sched.return_value = MagicMock()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c
    app.dependency_overrides.clear()


@pytest.fixture
def client_with_es(request):
    """Fixture qui injecte un mock ES paramétrable."""
    mock_es = getattr(request, "param", AsyncMock())
    app.dependency_overrides[get_db] = _get_test_db
    app.dependency_overrides[get_es_client] = lambda: mock_es
    with patch("app.modules.rbac.retention.BackgroundScheduler") as mock_sched:
        mock_sched.return_value = MagicMock()
        with TestClient(app) as c:
            yield c, mock_es
    app.dependency_overrides.clear()


# ══════════════════════════════════════════════════════════════════════════════
#   1. DÉMARRAGE ET SANTÉ
# ══════════════════════════════════════════════════════════════════════════════

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_openapi_accessible(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200
    assert "paths" in r.json()


# ══════════════════════════════════════════════════════════════════════════════
#   2. AUTHENTIFICATION LOCALE
# ══════════════════════════════════════════════════════════════════════════════

def test_login_success(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Admin1234!"})
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


def test_login_wrong_password(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_login_unknown_user(client):
    r = client.post("/api/auth/login", json={"username": "nobody", "password": "x"})
    assert r.status_code == 401


def test_logout_no_token(client):
    r = client.post("/api/auth/logout")
    assert r.status_code in (401, 403)


def test_logout_with_token(client):
    # Obtenir un vrai token depuis la DB
    r = client.post("/api/auth/login", json={"username": "reader", "password": "Reader1234!"})
    token_val = r.json()["access_token"]
    r2 = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token_val}"})
    assert r2.status_code == 200
    assert r2.json()["username"] == "reader"


def test_login_creates_audit_entry(client):
    """Vérifier que le login écrit bien dans l'audit."""
    client.post("/api/auth/login", json={"username": "analyst", "password": "Analyst1234!"})
    r = client.get("/api/audit", headers=auth("administrator"))
    assert r.status_code == 200
    entries = r.json()["entries"]
    actions = [e["action"] for e in entries]
    assert "login" in actions


# ══════════════════════════════════════════════════════════════════════════════
#   3. RBAC
# ══════════════════════════════════════════════════════════════════════════════

def test_rbac_reader_cannot_access_users(client):
    r = client.get("/api/users", headers=auth("reader"))
    assert r.status_code == 403


def test_rbac_analyst_cannot_access_users(client):
    r = client.get("/api/users", headers=auth("analyst"))
    assert r.status_code == 403


def test_rbac_administrator_can_access_users(client):
    r = client.get("/api/users", headers=auth("administrator"))
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 3
    assert "users" in body


def test_rbac_hierarchy_analyst_gte_reader(client):
    """analyst satisfait un endpoint qui exige reader."""
    mock_es = make_mock_es_search([], 0)
    app.dependency_overrides[get_es_client] = lambda: mock_es
    r = client.get("/api/v1/logs", headers=auth("analyst"))
    assert r.status_code not in (403,)


# ══════════════════════════════════════════════════════════════════════════════
#   4. GESTION DES UTILISATEURS (CRUD persistant)
# ══════════════════════════════════════════════════════════════════════════════

def test_list_users_returns_demo_accounts(client):
    r = client.get("/api/users", headers=auth("administrator"))
    body = r.json()
    usernames = {u["username"] for u in body["users"]}
    assert {"admin", "analyst", "reader"} <= usernames


def test_user_has_org_scope_fields(client):
    r = client.get("/api/users", headers=auth("administrator"))
    user = next(u for u in r.json()["users"] if u["username"] == "admin")
    assert "team" in user
    assert "service" in user
    assert "subsidiary" in user
    assert "environment" in user


def test_create_user(client):
    payload = {
        "username":    "testcreate",
        "password":    "Test1234!",
        "role":        "reader",
        "team":        "infra",
        "service":     "reseau",
        "subsidiary":  "FR",
        "environment": "staging",
    }
    r = client.post("/api/users", json=payload, headers=auth("administrator"))
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "testcreate"
    assert body["role"] == "reader"
    assert body["team"] == "infra"


def test_create_user_invalid_role(client):
    r = client.post(
        "/api/users",
        json={"username": "u2", "password": "pass", "role": "superadmin"},
        headers=auth("administrator"),
    )
    assert r.status_code == 422


def test_create_duplicate_user(client):
    client.post(
        "/api/users",
        json={"username": "dupuser", "password": "x", "role": "reader"},
        headers=auth("administrator"),
    )
    r = client.post(
        "/api/users",
        json={"username": "dupuser", "password": "y", "role": "reader"},
        headers=auth("administrator"),
    )
    assert r.status_code == 409


def test_update_user_role(client):
    # Créer un utilisateur
    r = client.post(
        "/api/users",
        json={"username": "updateme", "password": "Pass1!", "role": "reader"},
        headers=auth("administrator"),
    )
    user_id = r.json()["id"]

    r2 = client.put(
        f"/api/users/{user_id}",
        json={"role": "analyst"},
        headers=auth("administrator"),
    )
    assert r2.status_code == 200
    assert r2.json()["role"] == "analyst"


def test_update_user_role_writes_audit(client):
    r = client.post(
        "/api/users",
        json={"username": "audituser", "password": "P1!", "role": "reader"},
        headers=auth("administrator"),
    )
    user_id = r.json()["id"]
    client.put(f"/api/users/{user_id}", json={"role": "analyst"}, headers=auth("administrator"))

    audit = client.get("/api/audit", headers=auth("administrator")).json()
    assert any(e["action"] == "role_update" for e in audit["entries"])


def test_delete_user(client):
    r = client.post(
        "/api/users",
        json={"username": "deleteme", "password": "D1!", "role": "reader"},
        headers=auth("administrator"),
    )
    user_id = r.json()["id"]

    r2 = client.delete(f"/api/users/{user_id}", headers=auth("administrator"))
    assert r2.status_code == 200
    assert r2.json()["status"] == "désactivé"


def test_delete_nonexistent_user(client):
    r = client.delete("/api/users/99999", headers=auth("administrator"))
    assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
#   5. NORMALISATION
# ══════════════════════════════════════════════════════════════════════════════

def test_normalize_syslog_required_fields():
    raw = "<34>Jun 30 14:20:00 webserver sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2"
    result = normalize(raw, source="syslog")
    assert result.timestamp is not None
    assert result.host
    assert result.log_type
    assert result.severity
    assert result.raw_message == raw
    assert isinstance(result.tags, list)


def test_normalize_syslog_critical_auth():
    raw = "<34>Jun 30 14:20:00 webserver sshd[1234]: Failed password for root from 10.0.0.1 port 22"
    result = normalize(raw, source="syslog")
    assert result.severity == "critical"
    assert result.log_type == "auth"


def test_normalize_syslog_info_system():
    raw = "<30>Jun 30 14:20:00 webserver kernel: disk I/O scheduled"
    result = normalize(raw, source="syslog")
    assert result.severity == "info"
    assert result.log_type == "système"


def test_normalize_json_required_fields():
    data = {
        "timestamp": "2026-06-30T12:00:00",
        "source_ip": "10.0.0.1",
        "host":      "srv01",
        "raw_message": "test login event",
    }
    result = normalize_json(data)
    assert result.timestamp is not None
    assert result.source_ip == "10.0.0.1"
    assert result.host == "srv01"
    assert result.log_type
    assert result.severity


def test_normalize_json_missing_timestamp():
    with pytest.raises(ValueError, match="timestamp"):
        normalize_json({"source_ip": "1.2.3.4"})


def test_json_parser_parse_dict():
    parser = JSONLogParser()
    result = parser.parse_dict({"timestamp": "2026-06-30T10:00:00", "source_ip": "1.2.3.4", "host": "h"})
    assert result.source_ip == "1.2.3.4"
    assert result.host == "h"


def test_json_parser_parse_string():
    import json
    parser = JSONLogParser()
    data = {"timestamp": "2026-06-30T10:00:00", "source_ip": "5.6.7.8", "host": "h1"}
    result = parser.parse(json.dumps(data))
    assert result.source_ip == "5.6.7.8"


# ══════════════════════════════════════════════════════════════════════════════
#   6. INGESTION (ES mocké via dependency_overrides)
# ══════════════════════════════════════════════════════════════════════════════

INGEST_HEADERS = {"X-API-Key": "dev-only-change-me"}


def test_ingest_syslog(client):
    app.dependency_overrides[get_es_client] = lambda: make_mock_es_index("id1")
    r = client.post(
        "/api/v1/logs/ingest",
        json={"raw_message": "<34>Jun 30 14:20:00 webserver sshd[1234]: Failed password for root from 10.0.0.1 port 22", "source": "syslog"},
        headers=INGEST_HEADERS,
    )
    assert r.status_code == 201
    body = r.json()
    assert body["severity"] == "critical"
    assert body["log_type"] == "auth"
    assert body["id"] == "id1"


def test_ingest_json_endpoint(client):
    app.dependency_overrides[get_es_client] = lambda: make_mock_es_index("id2")
    r = client.post(
        "/api/v1/logs/ingest/json",
        json={"raw_json": {
            "timestamp":   "2026-06-30T12:00:00",
            "source_ip":   "10.0.0.5",
            "host":        "appserver",
            "raw_message": "authentication failure detected",
        }},
        headers=INGEST_HEADERS,
    )
    assert r.status_code == 201
    assert r.json()["id"] == "id2"
    assert r.json()["severity"] == "critical"


def test_ingest_bulk(client):
    app.dependency_overrides[get_es_client] = lambda: make_mock_es_index("idbulk")
    logs = [
        {"raw_message": f"<30>Jun 30 12:0{i}:00 host kernel: event {i}", "source": "syslog"}
        for i in range(5)
    ]
    r = client.post("/api/v1/logs/ingest/bulk", json=logs, headers=INGEST_HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_received"] == 5
    assert body["total_inserted"] == 5
    assert body["total_failed"] == 0


def test_ingest_requires_api_key(client):
    r = client.post(
        "/api/v1/logs/ingest",
        json={"raw_message": "test", "source": "syslog"},
    )
    assert r.status_code == 422  # Header obligatoire manquant


def test_ingest_invalid_source(client):
    r = client.post(
        "/api/v1/logs/ingest",
        json={"raw_message": "some log", "source": "unknown_source"},
        headers=INGEST_HEADERS,
    )
    assert r.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
#   7. LECTURE DES LOGS (ES mocké)
# ══════════════════════════════════════════════════════════════════════════════

def test_get_logs_no_token(client):
    r = client.get("/api/v1/logs")
    assert r.status_code in (401, 403)


def test_get_logs_with_reader(client):
    fake_hits = [{"_id": "1", "_source": {
        "timestamp": "2026-06-30T10:00:00", "severity": "info",
        "log_type":  "auth", "source_ip": "1.1.1.1",
        "host":      "h", "raw_message": "msg", "tags": [],
    }}]
    app.dependency_overrides[get_es_client] = lambda: make_mock_es_search(fake_hits, 1)
    r = client.get("/api/v1/logs", headers=auth("reader"))
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["logs"][0]["id"] == "1"


def test_get_log_by_id_not_found(client):
    mock_es = AsyncMock()
    mock_es.get = AsyncMock(side_effect=Exception("NotFound"))
    app.dependency_overrides[get_es_client] = lambda: mock_es
    r = client.get("/api/v1/logs/nonexistent", headers=auth("reader"))
    assert r.status_code == 404


def test_get_log_by_id_found(client):
    mock_es = AsyncMock()
    mock_es.get = AsyncMock(return_value={
        "_id": "abc",
        "_source": {
            "timestamp": "2026-06-30T10:00:00", "severity": "info",
            "log_type":  "auth", "source_ip": "1.1.1.1",
            "host":      "h", "raw_message": "msg", "tags": [],
        },
    })
    app.dependency_overrides[get_es_client] = lambda: mock_es
    r = client.get("/api/v1/logs/abc", headers=auth("reader"))
    assert r.status_code == 200
    assert r.json()["id"] == "abc"


# ══════════════════════════════════════════════════════════════════════════════
#   8. AUDIT
# ══════════════════════════════════════════════════════════════════════════════

def test_audit_requires_administrator(client):
    r = client.get("/api/audit", headers=auth("reader"))
    assert r.status_code == 403


def test_audit_accessible_by_admin(client):
    r = client.get("/api/audit", headers=auth("administrator"))
    assert r.status_code == 200
    body = r.json()
    assert "entries" in body
    assert "total" in body
