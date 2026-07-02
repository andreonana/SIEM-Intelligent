# tests/unit/s2/test_soar.py
#
# Tests unitaires des playbooks SOAR.

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# block_ip — aucune simulation : échec explicite si FIREWALL_API_URL est absent
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_block_ip_fails_explicitly_when_no_firewall_url():
    """Sans FIREWALL_API_URL, block_ip doit honnêtement retourner status=failure
    avec un message d'erreur clair — jamais un faux succès simulé."""
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    mock_execution = MagicMock()
    mock_execution.id = 1

    with patch("app.modules.soar.playbooks._persist_execution", AsyncMock(return_value=mock_execution)) as mock_persist, \
         patch("app.modules.soar.playbooks.log_action", AsyncMock()) as mock_log, \
         patch("app.core.config.settings") as mock_settings:

        mock_settings.firewall_api_url = None

        from app.modules.soar.playbooks import _run_block_ip
        result = await _run_block_ip(
            params={"ip": "10.0.0.1", "reason": "brute force", "alert_id": 1},
            triggered_by="analyst",
            db=db,
        )

    assert result["status"] == "failure"
    assert result["ip"] == "10.0.0.1"
    assert "FIREWALL_API_URL" in result["error"]
    # Persisté et journalisé avec un statut honnête, jamais "success"
    mock_persist.assert_awaited_once()
    assert mock_persist.call_args[0][5] == "failure"
    mock_log.assert_awaited_once()
    assert mock_log.call_args.kwargs.get("result") == "failure"


@pytest.mark.asyncio
async def test_block_ip_calls_firewall_api_and_returns_blocked_on_success():
    """Avec FIREWALL_API_URL configuré, block_ip appelle POST /block et retourne
    status=blocked seulement si le corps de réponse réel le confirme."""
    db = AsyncMock()
    mock_execution = MagicMock(id=1)

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value={"status": "blocked", "ip": "192.168.1.5"})

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("app.modules.soar.playbooks._persist_execution", AsyncMock(return_value=mock_execution)), \
         patch("app.modules.soar.playbooks.log_action", AsyncMock()), \
         patch("app.core.config.settings") as mock_settings, \
         patch("httpx.AsyncClient", return_value=mock_client):

        mock_settings.firewall_api_url = "http://firewall-controller:8080"

        from app.modules.soar.playbooks import _run_block_ip
        result = await _run_block_ip(
            params={"ip": "192.168.1.5", "reason": "suspicious", "alert_id": 2},
            triggered_by="admin",
            db=db,
        )

    mock_client.post.assert_awaited_once_with(
        "http://firewall-controller:8080/block",
        json={"ip": "192.168.1.5", "reason": "suspicious"},
    )
    assert result["status"] == "blocked"
    assert result["ip"] == "192.168.1.5"


@pytest.mark.asyncio
async def test_block_ip_returns_failure_when_firewall_body_says_failure():
    """Régression critique : un HTTP 200 ne doit jamais être interprété comme un
    succès si le corps JSON du firewall indique status=failure (le code ne doit
    plus faire confiance aveuglément au code HTTP de transport)."""
    db = AsyncMock()
    mock_execution = MagicMock(id=1)

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value={
        "status": "failure", "ip": "10.0.0.9", "error": "iptables: Permission denied",
    })

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("app.modules.soar.playbooks._persist_execution", AsyncMock(return_value=mock_execution)) as mock_persist, \
         patch("app.modules.soar.playbooks.log_action", AsyncMock()), \
         patch("app.core.config.settings") as mock_settings, \
         patch("httpx.AsyncClient", return_value=mock_client):

        mock_settings.firewall_api_url = "http://firewall-controller:8080"

        from app.modules.soar.playbooks import _run_block_ip
        result = await _run_block_ip(
            params={"ip": "10.0.0.9", "reason": "test", "alert_id": 3},
            triggered_by="admin",
            db=db,
        )

    assert result["status"] == "failure"
    assert "Permission denied" in result["error"]
    assert mock_persist.call_args[0][5] == "failure"


@pytest.mark.asyncio
async def test_block_ip_returns_failure_on_network_error():
    """Le firewall injoignable (timeout, connexion refusée...) doit produire
    status=failure avec le détail de l'erreur de transport."""
    db = AsyncMock()
    mock_execution = MagicMock(id=1)

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=ConnectionError("Connection refused"))

    with patch("app.modules.soar.playbooks._persist_execution", AsyncMock(return_value=mock_execution)) as mock_persist, \
         patch("app.modules.soar.playbooks.log_action", AsyncMock()), \
         patch("app.core.config.settings") as mock_settings, \
         patch("httpx.AsyncClient", return_value=mock_client):

        mock_settings.firewall_api_url = "http://firewall-controller:8080"

        from app.modules.soar.playbooks import _run_block_ip
        result = await _run_block_ip(
            params={"ip": "10.0.0.9", "reason": "test", "alert_id": 4},
            triggered_by="admin",
            db=db,
        )

    assert result["status"] == "failure"
    assert "Connection refused" in result["error"]
    assert mock_persist.call_args[0][5] == "failure"


# ---------------------------------------------------------------------------
# disable_account
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disable_account_existing_user():
    """Un utilisateur existant doit être désactivé."""
    mock_user = MagicMock()
    mock_user.is_active = True
    db = AsyncMock()
    db.commit = AsyncMock()

    mock_execution = MagicMock(id=1)

    with patch("app.modules.soar.playbooks.get_user_by_username", AsyncMock(return_value=mock_user)), \
         patch("app.modules.soar.playbooks._persist_execution", AsyncMock(return_value=mock_execution)), \
         patch("app.modules.soar.playbooks.log_action", AsyncMock()):

        from app.modules.soar.playbooks import _run_disable_account
        result = await _run_disable_account(
            params={"username": "bad_actor", "reason": "compromise", "alert_id": 5},
            triggered_by="admin",
            db=db,
        )

    assert result["status"] == "disabled"
    assert result["username"] == "bad_actor"
    assert mock_user.is_active is False


@pytest.mark.asyncio
async def test_disable_account_user_not_found():
    """Un utilisateur inexistant → status=user_not_found."""
    db = AsyncMock()
    mock_execution = MagicMock(id=1)

    with patch("app.modules.soar.playbooks.get_user_by_username", AsyncMock(return_value=None)), \
         patch("app.modules.soar.playbooks._persist_execution", AsyncMock(return_value=mock_execution)), \
         patch("app.modules.soar.playbooks.log_action", AsyncMock()):

        from app.modules.soar.playbooks import _run_disable_account
        result = await _run_disable_account(
            params={"username": "ghost_user", "reason": "test", "alert_id": None},
            triggered_by="admin",
            db=db,
        )

    assert result["status"] == "user_not_found"
    assert result["username"] == "ghost_user"


# ---------------------------------------------------------------------------
# escalate_admin
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_escalate_admin_no_channels_configured():
    """Sans canaux configurés, escalate_admin retourne une liste vide."""
    db = AsyncMock()
    mock_execution = MagicMock(id=1)

    with patch("app.modules.soar.playbooks._persist_execution", AsyncMock(return_value=mock_execution)), \
         patch("app.modules.soar.playbooks.log_action", AsyncMock()), \
         patch("app.core.config.settings") as mock_settings:

        mock_settings.slack_webhook_url = None
        mock_settings.teams_webhook_url = None
        mock_settings.alert_email_to = None

        from app.modules.soar.playbooks import _run_escalate_admin
        result = await _run_escalate_admin(
            params={"reason": "Critical incident", "alert_id": 10, "severity": "CRITICAL"},
            triggered_by="system",
            db=db,
        )

    assert result["status"] == "escalated"
    assert result["channels_notified"] == []


@pytest.mark.asyncio
async def test_escalate_admin_slack_channel():
    """Avec SLACK_WEBHOOK_URL configuré, escalate_admin notifie Slack."""
    db = AsyncMock()
    mock_execution = MagicMock(id=1)

    with patch("app.modules.soar.playbooks._persist_execution", AsyncMock(return_value=mock_execution)), \
         patch("app.modules.soar.playbooks.log_action", AsyncMock()), \
         patch("app.modules.soar.playbooks.send_webhook", AsyncMock(return_value=True)), \
         patch("app.core.config.settings") as mock_settings:

        mock_settings.slack_webhook_url = "https://hooks.slack.com/test"
        mock_settings.teams_webhook_url = None
        mock_settings.alert_email_to = None

        from app.modules.soar.playbooks import _run_escalate_admin
        result = await _run_escalate_admin(
            params={"reason": "Escalation test", "alert_id": 99, "severity": "HIGH"},
            triggered_by="analyst",
            db=db,
        )

    assert result["status"] == "escalated"
    assert "slack" in result["channels_notified"]


# ---------------------------------------------------------------------------
# run_playbook dispatcher
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_playbook_unknown_raises_value_error():
    """Un playbook inconnu doit lever ValueError."""
    from app.modules.soar.playbooks import run_playbook
    db = AsyncMock()

    with pytest.raises(ValueError, match="inconnu"):
        await run_playbook("unknown_playbook", {}, "admin", db)


@pytest.mark.asyncio
async def test_run_playbook_dispatches_block_ip():
    """run_playbook('block_ip', ...) dispatche vers le handler block_ip."""
    db = AsyncMock()
    mock_handler = AsyncMock(return_value={"status": "simulated", "ip": "1.1.1.1"})

    import app.modules.soar.playbooks as pb
    original = pb._HANDLERS["block_ip"]
    pb._HANDLERS["block_ip"] = mock_handler
    try:
        result = await pb.run_playbook("block_ip", {"ip": "1.1.1.1"}, "admin", db)
    finally:
        pb._HANDLERS["block_ip"] = original

    assert result["status"] == "simulated"
    mock_handler.assert_called_once()
