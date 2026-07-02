# tests/unit/s2/test_correlation.py
#
# Tests unitaires du moteur de corrélation S2.
# Les appels Elasticsearch et SQLAlchemy sont mockés — aucun docker requis.

import json
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers — générateurs de logs synthétiques
# ---------------------------------------------------------------------------

def _make_log(log_type: str, message: str, source_ip: str = "1.2.3.4", host: str = "srv1", hour: int = 14) -> dict:
    ts = datetime.now(timezone.utc).replace(hour=hour, minute=0, second=0, microsecond=0)
    return {
        "_id": f"id_{message[:8]}",
        "_source": {
            "log_type": log_type,
            "message": message,
            "source_ip": source_ip,
            "hostname": host,
            "@timestamp": ts.isoformat(),
        },
    }


def _make_auth_fail(source_ip: str = "1.2.3.4", n: int = 1) -> list[dict]:
    return [_make_log("auth", f"failed password attempt {i}", source_ip=source_ip) for i in range(n)]


# ---------------------------------------------------------------------------
# RULE_001 — Brute Force
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rule_001_triggers_above_threshold():
    """5 échecs d'auth depuis la même IP → 1 alerte créée."""
    from app.modules.correlation.rules import RULES_BY_ID

    rule = RULES_BY_ID["RULE_001"]
    hits = _make_auth_fail("10.0.0.1", n=6)

    created_alerts = []

    async def fake_check_dedupe(db, dedupe_key, hours=6):
        return False

    async def fake_create_alert(db, rule_id, rule_name, severity, description,
                                 source_ip=None, host=None, related_log_ids=None,
                                 mitre_tactic=None, mitre_technique=None, dedupe_key=None,
                                 confidence_score=None, soar_status=None):
        created_alerts.append({"rule_id": rule_id, "source_ip": source_ip})
        mock = MagicMock()
        mock.id = len(created_alerts)
        return mock

    with patch("app.modules.correlation.engine.check_dedupe", fake_check_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create_alert):
        from app.modules.correlation import engine
        db = AsyncMock()
        n = await engine._eval_rule_001(hits, rule, db, confidence=90.0)

    assert len(n) == 1
    assert created_alerts[0]["source_ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_rule_001_no_trigger_below_threshold():
    """4 échecs d'auth → pas d'alerte (threshold = 5)."""
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_001"]
    hits = _make_auth_fail("10.0.0.2", n=4)

    async def fake_check_dedupe(db, dedupe_key, hours=6):
        return False

    async def fake_create_alert(**kwargs):
        raise AssertionError("create_alert ne doit pas être appelé")

    with patch("app.modules.correlation.engine.check_dedupe", fake_check_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create_alert):
        db = AsyncMock()
        n = await engine._eval_rule_001(hits, rule, db, confidence=90.0)

    assert len(n) == 0


# ---------------------------------------------------------------------------
# RULE_002 — Connexion hors horaires
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rule_002_triggers_off_hours():
    """Connexion à 3h UTC → alerte WARNING."""
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_002"]
    hits = [_make_log("auth", "login accepted", source_ip="5.6.7.8", hour=3)]

    created_alerts = []

    async def fake_check_dedupe(db, dedupe_key, hours=6):
        return False

    async def fake_create_alert(db, rule_id, rule_name, severity, **kwargs):
        created_alerts.append({"rule_id": rule_id, "severity": severity})
        return MagicMock(id=1)

    with patch("app.modules.correlation.engine.check_dedupe", fake_check_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create_alert):
        db = AsyncMock()
        n = await engine._eval_rule_002(hits, rule, db, confidence=70.0)

    assert len(n) == 1
    assert created_alerts[0]["severity"] == "WARNING"


@pytest.mark.asyncio
async def test_rule_002_no_trigger_business_hours():
    """Connexion à 10h UTC → pas d'alerte."""
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_002"]
    hits = [_make_log("auth", "login accepted", source_ip="5.6.7.8", hour=10)]

    async def fake_check_dedupe(db, dedupe_key, hours=6):
        return False

    with patch("app.modules.correlation.engine.check_dedupe", fake_check_dedupe), \
         patch("app.modules.correlation.engine.create_alert", AsyncMock(side_effect=AssertionError)):
        db = AsyncMock()
        n = await engine._eval_rule_002(hits, rule, db, confidence=70.0)

    assert len(n) == 0


# ---------------------------------------------------------------------------
# RULE_003 — Élévation de privilèges (multi-source)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rule_003_triggers_from_es_log():
    """Log système avec 'sudo' → alerte HIGH."""
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_003"]
    hits = [_make_log("system", "sudo command executed", source_ip="192.168.1.1")]

    created_alerts = []

    async def fake_check_dedupe(db, dedupe_key, hours=6):
        return False

    async def fake_create_alert(db, rule_id, severity, **kwargs):
        created_alerts.append({"rule_id": rule_id, "severity": severity})
        return MagicMock(id=1)

    with patch("app.modules.correlation.engine.check_dedupe", fake_check_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create_alert):
        db = AsyncMock()
        n = await engine._eval_rule_003(hits, rule, db, db_audit_logs=[], confidence=85.0)

    assert len(n) >= 1
    assert created_alerts[0]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_rule_003_triggers_from_sql_audit():
    """Audit SQL avec action role_update → alerte (multi-source)."""
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_003"]
    db_audit_logs = [{"id": 42, "action": "role_update", "detail": "", "username": "admin"}]

    created_alerts = []

    async def fake_check_dedupe(db, dedupe_key, hours=6):
        return False

    async def fake_create_alert(db, rule_id, severity, **kwargs):
        created_alerts.append({"rule_id": rule_id})
        return MagicMock(id=1)

    with patch("app.modules.correlation.engine.check_dedupe", fake_check_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create_alert):
        db = AsyncMock()
        n = await engine._eval_rule_003([], rule, db, db_audit_logs=db_audit_logs, confidence=85.0)

    assert len(n) >= 1


# ---------------------------------------------------------------------------
# RULE_004 — Exfiltration (multi-host)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rule_004_triggers_multi_host():
    """Même IP sur 4 hôtes → alerte CRITICAL."""
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_004"]
    hits = [
        _make_log("network", "normal traffic", source_ip="10.1.1.1", host=f"host{i}")
        for i in range(4)
    ]

    created_alerts = []

    async def fake_check_dedupe(db, dedupe_key, hours=6):
        return False

    async def fake_create_alert(db, rule_id, severity, **kwargs):
        created_alerts.append({"rule_id": rule_id, "severity": severity})
        return MagicMock(id=1)

    with patch("app.modules.correlation.engine.check_dedupe", fake_check_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create_alert):
        db = AsyncMock()
        n = await engine._eval_rule_004(hits, rule, db, confidence=95.0)

    assert len(n) >= 1
    assert any(a["severity"] == "CRITICAL" for a in created_alerts)


@pytest.mark.asyncio
async def test_rule_004_triggers_exfil_keyword():
    """Log réseau avec 'outbound' → alerte CRITICAL."""
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_004"]
    hits = [_make_log("network", "outbound data transfer detected", source_ip="172.16.0.1")]

    created_alerts = []

    async def fake_check_dedupe(db, dedupe_key, hours=6):
        return False

    async def fake_create_alert(db, rule_id, severity, **kwargs):
        created_alerts.append({"severity": severity})
        return MagicMock(id=1)

    with patch("app.modules.correlation.engine.check_dedupe", fake_check_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create_alert):
        db = AsyncMock()
        n = await engine._eval_rule_004(hits, rule, db, confidence=95.0)

    assert len(n) >= 1
    assert created_alerts[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# RULE_005 — Arrêt service de logs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rule_005_triggers_on_auditd_stop():
    """Message 'auditd stopped' → alerte CRITICAL."""
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_005"]
    hits = [_make_log("system", "auditd service stopped unexpectedly")]

    created_alerts = []

    async def fake_check_dedupe(db, dedupe_key, hours=6):
        return False

    async def fake_create_alert(db, rule_id, severity, **kwargs):
        created_alerts.append({"severity": severity})
        return MagicMock(id=1)

    with patch("app.modules.correlation.engine.check_dedupe", fake_check_dedupe), \
         patch("app.modules.correlation.engine.create_alert", fake_create_alert):
        db = AsyncMock()
        n = await engine._eval_rule_005(hits, rule, db, confidence=92.0)

    assert len(n) == 1
    assert created_alerts[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Déduplication
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_deduplication_blocks_second_alert():
    """check_dedupe renvoie True → aucune alerte créée."""
    from app.modules.correlation.rules import RULES_BY_ID
    from app.modules.correlation import engine

    rule = RULES_BY_ID["RULE_001"]
    hits = _make_auth_fail("10.0.0.5", n=10)

    async def fake_check_dedupe(db, dedupe_key, hours=6):
        return True  # alerte déjà existante

    with patch("app.modules.correlation.engine.check_dedupe", fake_check_dedupe), \
         patch("app.modules.correlation.engine.create_alert", AsyncMock(side_effect=AssertionError)):
        db = AsyncMock()
        n = await engine._eval_rule_001(hits, rule, db, confidence=90.0)

    assert len(n) == 0
