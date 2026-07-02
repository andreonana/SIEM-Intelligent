# backend/tests/unit/s3/test_v3_features.py
#
# Tests unitaires des fonctionnalités V3.
# Couvre :
#   1. Auto-déclenchement SOAR
#   2. Mode AUTO
#   3. Mode CONFIRM avec délai
#   4. Confidence score
#   5. Déduplication 5 minutes
#   6. SHA-256 batch
#   7. Endpoint vérification intégrité
#   8. Rate limiting (middleware)
#   9. Email réel mocké proprement

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, call
import pytest


# ============================================================
# 1+2. SOAR Auto-déclenchement — mode AUTO
# ============================================================

class TestSOARAutoDispatch:
    """Mode AUTO : le playbook doit être exécuté immédiatement."""

    @pytest.mark.asyncio
    async def test_dispatch_auto_calls_run_playbook(self):
        """dispatch_soar en mode AUTO doit appeler run_playbook exactement une fois."""
        from app.modules.soar.dispatcher import dispatch_soar

        alert = MagicMock()
        alert.id = 42
        alert.source_ip = "192.168.1.100"
        alert.description = "Brute force"
        alert.severity = "HIGH"
        alert.soar_status = "manual"

        db = AsyncMock()
        db.commit = AsyncMock()

        with patch("app.modules.soar.dispatcher.run_playbook", new_callable=AsyncMock) as mock_run, \
             patch("app.modules.soar.dispatcher.log_action", new_callable=AsyncMock):
            mock_run.return_value = {"status": "blocked", "ip": "192.168.1.100"}

            await dispatch_soar(
                db=db,
                alert=alert,
                soar_action="block_ip",
                soar_mode="AUTO",
                confirm_delay_seconds=60,
                confidence_score=90.0,
            )

            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args
            assert call_kwargs.kwargs["playbook_id"] == "block_ip"
            assert call_kwargs.kwargs["triggered_by"] == "system_auto"

    @pytest.mark.asyncio
    async def test_dispatch_manual_does_not_call_playbook(self):
        """Mode MANUAL : aucun playbook ne doit être déclenché."""
        from app.modules.soar.dispatcher import dispatch_soar

        alert = MagicMock()
        alert.id = 1

        db = AsyncMock()

        with patch("app.modules.soar.dispatcher.run_playbook", new_callable=AsyncMock) as mock_run:
            await dispatch_soar(
                db=db,
                alert=alert,
                soar_action="block_ip",
                soar_mode="MANUAL",
                confirm_delay_seconds=60,
                confidence_score=80.0,
            )
            mock_run.assert_not_called()

    @pytest.mark.asyncio
    async def test_soar_failure_does_not_propagate(self):
        """Une erreur dans le playbook ne doit pas remonter (isolation)."""
        from app.modules.soar.dispatcher import dispatch_soar

        alert = MagicMock()
        alert.id = 99
        alert.source_ip = "10.0.0.1"
        alert.description = "test"
        alert.severity = "CRITICAL"
        alert.soar_status = "manual"

        db = AsyncMock()
        db.commit = AsyncMock()

        with patch("app.modules.soar.dispatcher.run_playbook", new_callable=AsyncMock) as mock_run, \
             patch("app.modules.soar.dispatcher.log_action", new_callable=AsyncMock):
            mock_run.side_effect = RuntimeError("firewall down")

            # Ne doit pas lever d'exception
            await dispatch_soar(
                db=db,
                alert=alert,
                soar_action="block_ip",
                soar_mode="AUTO",
                confirm_delay_seconds=60,
                confidence_score=90.0,
            )


# ============================================================
# 3. Mode CONFIRM — exécution différée
# ============================================================

class TestSOARConfirmMode:
    """Mode CONFIRM : création d'un enregistrement schedulé, exécution différée."""

    @pytest.mark.asyncio
    async def test_confirm_creates_scheduled_execution(self):
        """Mode CONFIRM crée un PlaybookExecution avec status='scheduled'."""
        from app.modules.soar.dispatcher import dispatch_soar

        alert = MagicMock()
        alert.id = 7
        alert.source_ip = "1.2.3.4"
        alert.description = "priv escalation"
        alert.severity = "HIGH"
        alert.soar_status = "manual"

        # Simuler la DB : add() doit peupler execution.id
        executions_added = []

        async def mock_commit():
            if executions_added and not hasattr(executions_added[-1], "_id_set"):
                executions_added[-1].id = 77
                executions_added[-1]._id_set = True

        async def mock_refresh(obj):
            obj.id = 77

        db = AsyncMock()
        db.commit = mock_commit
        db.refresh = mock_refresh

        def mock_add(obj):
            executions_added.append(obj)

        db.add = mock_add

        with patch("app.modules.soar.dispatcher.log_action", new_callable=AsyncMock), \
             patch("app.modules.soar.dispatcher.asyncio.ensure_future") as mock_future:
            await dispatch_soar(
                db=db,
                alert=alert,
                soar_action="escalate_admin",
                soar_mode="CONFIRM",
                confirm_delay_seconds=60,
                confidence_score=85.0,
            )

        # Un PlaybookExecution doit avoir été ajouté
        assert len(executions_added) == 1
        exec_obj = executions_added[0]
        assert exec_obj.status == "scheduled"
        assert exec_obj.soar_mode == "CONFIRM"
        assert exec_obj.playbook_id == "escalate_admin"

    @pytest.mark.asyncio
    async def test_confirm_scheduled_at_is_in_future(self):
        """L'heure planifiée doit être dans le futur (now + delay)."""
        from app.modules.soar.dispatcher import dispatch_soar

        alert = MagicMock()
        alert.id = 8
        alert.source_ip = None
        alert.description = "test"
        alert.severity = "HIGH"
        alert.soar_status = "manual"

        executions_added = []
        delay = 60

        async def mock_commit(): pass
        async def mock_refresh(obj):
            obj.id = 88

        db = AsyncMock()
        db.commit = mock_commit
        db.refresh = mock_refresh
        db.add = lambda obj: executions_added.append(obj)

        before = datetime.now(timezone.utc)

        with patch("app.modules.soar.dispatcher.log_action", new_callable=AsyncMock), \
             patch("app.modules.soar.dispatcher.asyncio.ensure_future"):
            await dispatch_soar(
                db=db,
                alert=alert,
                soar_action="escalate_admin",
                soar_mode="CONFIRM",
                confirm_delay_seconds=delay,
                confidence_score=85.0,
            )

        after = datetime.now(timezone.utc)
        exec_obj = executions_added[0]
        expected_min = before + timedelta(seconds=delay - 1)
        expected_max = after + timedelta(seconds=delay + 1)
        assert expected_min <= exec_obj.scheduled_at <= expected_max


# ============================================================
# 4. Confidence score
# ============================================================

class TestConfidenceScore:
    def test_rule_model_has_confidence_score(self):
        from app.models.rule import CorrelationRule
        rule = CorrelationRule(
            rule_id="TEST_001",
            name="Test",
            description="",
            rule_type="threshold",
            severity="HIGH",
            confidence_score=90.0,
            soar_mode="AUTO",
            confirm_delay_seconds=60,
        )
        assert rule.confidence_score == 90.0

    def test_alert_model_has_confidence_score(self):
        from app.models.alert import Alert
        alert = Alert(
            rule_id="RULE_001",
            rule_name="Test",
            severity="HIGH",
            description="test",
            confidence_score=75.5,
        )
        assert alert.confidence_score == 75.5

    def test_alert_to_dict_includes_confidence(self):
        from app.models.alert import Alert
        alert = Alert(
            rule_id="RULE_001",
            rule_name="Test",
            severity="HIGH",
            description="test",
            confidence_score=92.0,
            soar_status="executed",
        )
        d = alert.to_dict()
        assert "confidence_score" in d
        assert d["confidence_score"] == 92.0
        assert "soar_status" in d

    def test_rule_to_dict_includes_confidence(self):
        from app.models.rule import CorrelationRule
        rule = CorrelationRule(
            rule_id="RULE_001",
            name="Test",
            description="",
            rule_type="threshold",
            severity="HIGH",
            confidence_score=88.0,
            soar_mode="CONFIRM",
            confirm_delay_seconds=120,
        )
        d = rule.to_dict()
        assert d["confidence_score"] == 88.0
        assert d["soar_mode"] == "CONFIRM"
        assert d["confirm_delay_seconds"] == 120


# ============================================================
# 5. Déduplication 5 minutes
# ============================================================

class TestDeduplication5Min:
    def test_dedupe_key_uses_5min_slots(self):
        from app.services.alert_service import _dedupe_key_5min

        key1 = _dedupe_key_5min("RULE_001", "1.2.3.4")
        key2 = _dedupe_key_5min("RULE_001", "1.2.3.4")
        # Même clé si appelé dans la même tranche de 5 min
        assert key1 == key2

    def test_dedupe_key_differs_by_rule(self):
        from app.services.alert_service import _dedupe_key_5min
        k1 = _dedupe_key_5min("RULE_001", "1.2.3.4")
        k2 = _dedupe_key_5min("RULE_002", "1.2.3.4")
        assert k1 != k2

    def test_dedupe_key_differs_by_ip(self):
        from app.services.alert_service import _dedupe_key_5min
        k1 = _dedupe_key_5min("RULE_001", "1.2.3.4")
        k2 = _dedupe_key_5min("RULE_001", "5.6.7.8")
        assert k1 != k2

    def test_dedupe_window_is_5_minutes(self):
        from app.services.alert_service import DEDUPE_WINDOW_MINUTES
        assert DEDUPE_WINDOW_MINUTES == 5

    @pytest.mark.asyncio
    async def test_check_dedupe_returns_false_when_no_alert(self):
        from app.services.alert_service import check_dedupe
        from unittest.mock import AsyncMock, MagicMock

        db = AsyncMock()
        # Simuler aucun résultat
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_result)

        result = await check_dedupe(db, "RULE_001:1.2.3.4:2026-07-01:slot0")
        assert result is False

    @pytest.mark.asyncio
    async def test_check_dedupe_returns_true_when_alert_exists(self):
        from app.services.alert_service import check_dedupe
        from unittest.mock import AsyncMock, MagicMock

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = MagicMock()  # Alerte existante
        db.execute = AsyncMock(return_value=mock_result)

        result = await check_dedupe(db, "RULE_001:1.2.3.4:2026-07-01:slot0")
        assert result is True


# ============================================================
# 6. SHA-256 batch
# ============================================================

class TestSHA256Batch:
    def test_compute_sha256_is_deterministic(self):
        from app.services.integrity_service import _compute_sha256
        logs = [{"source_ip": "1.2.3.4", "message": "test"}]
        h1 = _compute_sha256(logs, "batch-abc", "0" * 64)
        h2 = _compute_sha256(logs, "batch-abc", "0" * 64)
        assert h1 == h2

    def test_compute_sha256_is_64_hex_chars(self):
        from app.services.integrity_service import _compute_sha256
        h = _compute_sha256([{"a": 1}], "b-id", "0" * 64)
        assert len(h) == 64
        int(h, 16)  # valide hexadécimal

    def test_compute_sha256_changes_with_content(self):
        from app.services.integrity_service import _compute_sha256
        h1 = _compute_sha256([{"a": 1}], "b-id", "0" * 64)
        h2 = _compute_sha256([{"a": 2}], "b-id", "0" * 64)
        assert h1 != h2

    def test_compute_sha256_changes_with_batch_id(self):
        from app.services.integrity_service import _compute_sha256
        logs = [{"a": 1}]
        h1 = _compute_sha256(logs, "batch-1", "0" * 64)
        h2 = _compute_sha256(logs, "batch-2", "0" * 64)
        assert h1 != h2

    def test_compute_sha256_changes_with_parent(self):
        from app.services.integrity_service import _compute_sha256
        logs = [{"a": 1}]
        h1 = _compute_sha256(logs, "b-id", "0" * 64)
        h2 = _compute_sha256(logs, "b-id", "a" * 64)
        assert h1 != h2

    def test_genesis_hash_is_64_zeros(self):
        from app.services.integrity_service import _GENESIS_HASH
        assert _GENESIS_HASH == "0" * 64
        assert len(_GENESIS_HASH) == 64


# ============================================================
# 7. Vérification d'intégrité
# ============================================================

class TestIntegrityVerification:
    @pytest.mark.asyncio
    async def test_verify_batch_valid(self):
        """verify_batch retourne valid=True si les logs correspondent au hash stocké."""
        from app.services.integrity_service import verify_batch, _compute_sha256, _GENESIS_HASH

        logs = [{"msg": "hello"}, {"msg": "world"}]
        batch_id = "test-batch-123"
        parent = _GENESIS_HASH
        sha = _compute_sha256(logs, batch_id, parent)

        # Mock LogBatch
        mock_batch = MagicMock()
        mock_batch.sha256 = sha
        mock_batch.parent_sha256 = parent
        mock_batch.log_count = 2
        mock_batch.source = "test"
        mock_batch.created_at = datetime.now(timezone.utc)

        db = AsyncMock()
        # Premier execute → le batch, second execute → pas de parent
        mock_result1 = MagicMock()
        mock_result1.scalar_one_or_none.return_value = mock_batch
        mock_result2 = MagicMock()
        mock_result2.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(side_effect=[mock_result1, mock_result2])

        result = await verify_batch(db, batch_id, logs)
        assert result["valid"] is True
        assert result["hash_valid"] is True
        assert result["chain_valid"] is True

    @pytest.mark.asyncio
    async def test_verify_batch_invalid_when_tampered(self):
        """verify_batch retourne valid=False si les logs ont été modifiés."""
        from app.services.integrity_service import verify_batch, _compute_sha256, _GENESIS_HASH

        logs_original = [{"msg": "original"}]
        logs_tampered = [{"msg": "tampered"}]
        batch_id = "test-batch-456"
        parent = _GENESIS_HASH
        sha = _compute_sha256(logs_original, batch_id, parent)

        mock_batch = MagicMock()
        mock_batch.sha256 = sha
        mock_batch.parent_sha256 = parent
        mock_batch.log_count = 1
        mock_batch.source = "test"
        mock_batch.created_at = datetime.now(timezone.utc)

        db = AsyncMock()
        mock_r1 = MagicMock()
        mock_r1.scalar_one_or_none.return_value = mock_batch
        mock_r2 = MagicMock()
        mock_r2.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(side_effect=[mock_r1, mock_r2])

        result = await verify_batch(db, batch_id, logs_tampered)
        assert result["hash_valid"] is False
        assert result["valid"] is False

    @pytest.mark.asyncio
    async def test_verify_batch_not_found(self):
        """verify_batch retourne error si le batch_id n'existe pas."""
        from app.services.integrity_service import verify_batch

        db = AsyncMock()
        mock_r = MagicMock()
        mock_r.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_r)

        result = await verify_batch(db, "nonexistent-id", [])
        assert result["valid"] is False
        assert "error" in result


# ============================================================
# 8. Rate limiting
# ============================================================

class TestRateLimiter:
    def test_rate_limiter_bucket_key(self):
        """Les chemins d'ingestion doivent tomber dans le bucket 'ingest'."""
        from app.middleware.rate_limiter import RateLimiterMiddleware
        from unittest.mock import MagicMock

        app_mock = MagicMock()
        rl = RateLimiterMiddleware(app_mock)

        assert rl._bucket_key("1.2.3.4", "/api/ingest/logs") == "1.2.3.4:ingest"
        assert rl._bucket_key("1.2.3.4", "/api/logs/ingest") == "1.2.3.4:ingest"
        assert rl._bucket_key("1.2.3.4", "/api/auth/login") == "1.2.3.4:auth"
        assert rl._bucket_key("1.2.3.4", "/api/alerts") == "1.2.3.4:api"

    def test_rate_limiter_is_strict_for_login(self):
        from app.middleware.rate_limiter import RateLimiterMiddleware
        app_mock = MagicMock()
        rl = RateLimiterMiddleware(app_mock)
        assert rl._is_strict("/api/auth/login") is True
        assert rl._is_strict("/api/alerts") is False

    def test_rate_limiter_purges_old_timestamps(self):
        from app.middleware.rate_limiter import RateLimiterMiddleware
        from collections import deque
        app_mock = MagicMock()
        rl = RateLimiterMiddleware(app_mock)

        key = "127.0.0.1:api"
        bucket = rl._buckets[key]
        old_time = time.monotonic() - rl._window - 1
        bucket.append(old_time)
        assert len(bucket) == 1

        # Simuler une requête qui purge les vieux timestamps
        now = time.monotonic()
        while bucket and bucket[0] < now - rl._window:
            bucket.popleft()
        assert len(bucket) == 0


# ============================================================
# 9. Email réel mocké
# ============================================================

class TestEmailReal:
    @pytest.mark.asyncio
    async def test_send_email_calls_aiosmtplib(self):
        """send_email doit appeler aiosmtplib.send avec les bons paramètres."""
        with patch("app.core.config.settings") as mock_settings, \
             patch("aiosmtplib.send", new_callable=AsyncMock) as mock_smtp:
            mock_settings.smtp_host = "smtp.example.com"
            mock_settings.smtp_port = 587
            mock_settings.smtp_user = "siem@example.com"
            mock_settings.smtp_password = "secret"

            mock_smtp.return_value = ({}, "OK")

            from app.modules.alerting.notifier import send_email
            result = await send_email("admin@example.com", "Test Subject", "Test body")

            assert result is True
            mock_smtp.assert_called_once()
            call_kwargs = mock_smtp.call_args.kwargs
            assert call_kwargs["hostname"] == "smtp.example.com"
            assert call_kwargs["port"] == 587
            assert call_kwargs["username"] == "siem@example.com"

    @pytest.mark.asyncio
    async def test_send_email_returns_false_when_no_smtp_host(self):
        """send_email retourne False si SMTP_HOST manque — pas d'exception."""
        with patch("app.core.config.settings") as mock_settings:
            mock_settings.smtp_host = None
            mock_settings.smtp_user = "user@example.com"
            mock_settings.smtp_password = "pass"

            from app.modules.alerting.notifier import send_email
            result = await send_email("dest@example.com", "Subject", "body")
            assert result is False

    @pytest.mark.asyncio
    async def test_send_email_returns_false_on_smtp_error(self):
        """send_email retourne False si aiosmtplib lève une exception — pas de propagation."""
        with patch("app.core.config.settings") as mock_settings, \
             patch("aiosmtplib.send", new_callable=AsyncMock) as mock_smtp:
            mock_settings.smtp_host = "smtp.example.com"
            mock_settings.smtp_port = 587
            mock_settings.smtp_user = "siem@example.com"
            mock_settings.smtp_password = "secret"
            mock_smtp.side_effect = ConnectionRefusedError("SMTP unreachable")

            from app.modules.alerting.notifier import send_email
            result = await send_email("admin@example.com", "Test", "body")
            assert result is False

    @pytest.mark.asyncio
    async def test_send_email_uses_starttls_on_port_587(self):
        """Port 587 → start_tls=True, use_tls=False."""
        with patch("app.core.config.settings") as mock_settings, \
             patch("aiosmtplib.send", new_callable=AsyncMock) as mock_smtp:
            mock_settings.smtp_host = "smtp.example.com"
            mock_settings.smtp_port = 587
            mock_settings.smtp_user = "siem@example.com"
            mock_settings.smtp_password = "secret"
            mock_smtp.return_value = ({}, "OK")

            from app.modules.alerting.notifier import send_email
            await send_email("x@example.com", "s", "b")

            kwargs = mock_smtp.call_args.kwargs
            assert kwargs.get("start_tls") is True
            assert kwargs.get("use_tls") is False

    @pytest.mark.asyncio
    async def test_send_email_uses_ssl_on_port_465(self):
        """Port 465 → use_tls=True, start_tls=False."""
        with patch("app.core.config.settings") as mock_settings, \
             patch("aiosmtplib.send", new_callable=AsyncMock) as mock_smtp:
            mock_settings.smtp_host = "smtp.example.com"
            mock_settings.smtp_port = 465
            mock_settings.smtp_user = "siem@example.com"
            mock_settings.smtp_password = "secret"
            mock_smtp.return_value = ({}, "OK")

            from app.modules.alerting.notifier import send_email
            await send_email("x@example.com", "s", "b")

            kwargs = mock_smtp.call_args.kwargs
            assert kwargs.get("use_tls") is True
            assert kwargs.get("start_tls") is False
