# tests/unit/s2/test_alerts.py
#
# Tests unitaires du service d'alertes SQL.

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch


def _make_mock_alert(alert_id: int = 1, status: str = "open") -> MagicMock:
    alert = MagicMock()
    alert.id = alert_id
    alert.rule_id = "RULE_001"
    alert.rule_name = "Brute Force SSH/Auth"
    alert.severity = "HIGH"
    alert.description = "Test alert"
    alert.status = status
    alert.source_ip = "1.2.3.4"
    alert.acknowledged_by = None
    alert.acknowledged_at = None
    alert.resolved_at = None
    alert.resolution_note = None
    alert.dedupe_key = "RULE_001:1.2.3.4:2024-01-01"
    alert.detected_at = datetime.now(timezone.utc)
    alert.to_dict = lambda: {"id": alert.id, "status": alert.status}
    return alert


# ---------------------------------------------------------------------------
# create_alert
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_alert_persists():
    """create_alert doit ajouter l'alerte et retourner l'objet."""
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    mock_alert = _make_mock_alert()

    with patch("app.services.alert_service.Alert", return_value=mock_alert):
        from app.services.alert_service import create_alert
        result = await create_alert(
            db=db,
            rule_id="RULE_001",
            rule_name="Brute Force",
            severity="HIGH",
            description="Test",
            source_ip="1.2.3.4",
        )

    db.add.assert_called_once()
    db.commit.assert_called_once()
    assert result.id == 1


# ---------------------------------------------------------------------------
# get_alert
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_alert_found():
    """get_alert retourne l'alerte si elle existe."""
    mock_alert = _make_mock_alert(alert_id=42)
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_alert
    db.execute = AsyncMock(return_value=mock_result)

    from app.services.alert_service import get_alert
    result = await get_alert(db, 42)
    assert result.id == 42


@pytest.mark.asyncio
async def test_get_alert_not_found():
    """get_alert retourne None si l'alerte n'existe pas."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=mock_result)

    from app.services.alert_service import get_alert
    result = await get_alert(db, 999)
    assert result is None


# ---------------------------------------------------------------------------
# acknowledge_alert
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_acknowledge_alert_updates_status():
    """acknowledge_alert passe le statut à in_progress et enregistre l'utilisateur."""
    mock_alert = _make_mock_alert(alert_id=1, status="open")
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_alert
    db.execute = AsyncMock(return_value=mock_result)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    from app.services.alert_service import acknowledge_alert
    result = await acknowledge_alert(db, 1, "analyst_user")

    assert result.acknowledged_by == "analyst_user"
    assert result.status == "in_progress"


@pytest.mark.asyncio
async def test_acknowledge_alert_not_found():
    """acknowledge_alert lève ValueError si alerte introuvable."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=mock_result)

    from app.services.alert_service import acknowledge_alert
    with pytest.raises(ValueError, match="introuvable"):
        await acknowledge_alert(db, 999, "analyst_user")


# ---------------------------------------------------------------------------
# resolve_alert
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_alert_sets_resolved():
    """resolve_alert passe le statut à resolved."""
    mock_alert = _make_mock_alert(alert_id=1, status="in_progress")
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_alert
    db.execute = AsyncMock(return_value=mock_result)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    from app.services.alert_service import resolve_alert
    result = await resolve_alert(db, 1, "analyst_user", note="False positive")

    assert result.status == "resolved"
    assert result.resolution_note == "False positive"


# ---------------------------------------------------------------------------
# check_dedupe
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_check_dedupe_returns_true_when_exists():
    """check_dedupe retourne True si une alerte récente avec cette clé existe."""
    mock_alert = _make_mock_alert()
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_alert
    db.execute = AsyncMock(return_value=mock_result)

    from app.services.alert_service import check_dedupe
    result = await check_dedupe(db, "RULE_001:1.2.3.4:2024-01-01")
    assert result is True


@pytest.mark.asyncio
async def test_check_dedupe_returns_false_when_absent():
    """check_dedupe retourne False si aucune alerte récente."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=mock_result)

    from app.services.alert_service import check_dedupe
    result = await check_dedupe(db, "RULE_001:9.9.9.9:2099-01-01")
    assert result is False


# ---------------------------------------------------------------------------
# RBAC — reader ne peut pas acknowledge
# ---------------------------------------------------------------------------

def test_rbac_reader_cannot_acknowledge():
    """
    Vérifie que require_role("analyst") bloque un reader.
    On patch decode_access_token pour retourner un payload reader.
    """
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from unittest.mock import patch as _patch
    from app.api.v1.routers.alerts import router

    app = FastAPI()
    app.include_router(router)

    reader_payload = {"sub": "1", "username": "reader_user", "role": "reader"}

    # decode_access_token est importé dans roles.py — on patch la référence locale
    with _patch("app.modules.rbac.roles.decode_access_token", return_value=reader_payload):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/alerts/1/acknowledge", headers={"Authorization": "Bearer fake_reader_token"})

    assert resp.status_code == 403
