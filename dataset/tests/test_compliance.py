"""
Tests du module de conformité RGPD/ISO — Smart SIEM DATA S3.

Prérequis : Elasticsearch actif avec des données dans logs-siem.
Lancement  : pytest tests/test_compliance.py -v
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.reports.compliance import (
    generate_compliance_report,
    generate_retention_report,
    verify_log_integrity,
)

_DATE_FROM = "2026-01-01T00:00:00Z"
_DATE_TO   = "2026-12-31T23:59:59Z"


# ── verify_log_integrity ──────────────────────────────────────────────────────

class TestVerifyLogIntegrity:
    @pytest.fixture(scope="class")
    def integrity(self):
        return verify_log_integrity(_DATE_FROM, _DATE_TO)

    def test_returns_required_keys(self, integrity):
        assert set(integrity.keys()) >= {"period", "log_count", "sha256", "verified_at"}

    def test_period_contains_bounds(self, integrity):
        assert integrity["period"]["from"] == _DATE_FROM
        assert integrity["period"]["to"]   == _DATE_TO

    def test_log_count_is_non_negative_int(self, integrity):
        assert isinstance(integrity["log_count"], int)
        assert integrity["log_count"] >= 0

    def test_sha256_is_valid_hex(self, integrity):
        sha = integrity["sha256"]
        assert isinstance(sha, str)
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_hash_is_stable_across_two_calls(self):
        """Deux appels successifs sur la même période retournent le même hash."""
        r1 = verify_log_integrity(_DATE_FROM, _DATE_TO)
        r2 = verify_log_integrity(_DATE_FROM, _DATE_TO)
        assert r1["sha256"] == r2["sha256"], (
            f"Hash instable : {r1['sha256'][:12]}… ≠ {r2['sha256'][:12]}…"
        )
        assert r1["log_count"] == r2["log_count"]

    def test_verified_at_is_iso8601(self, integrity):
        from datetime import datetime, timezone
        dt = datetime.strptime(integrity["verified_at"], "%Y-%m-%dT%H:%M:%SZ")
        assert dt is not None

    def test_empty_period_returns_zero_count(self):
        """Une période sans données retourne log_count = 0 et un hash SHA-256 valide."""
        r = verify_log_integrity("1970-01-01T00:00:00Z", "1970-01-02T00:00:00Z")
        assert r["log_count"] == 0
        # hash de la chaîne vide (aucun document → payload = b"")
        import hashlib
        assert r["sha256"] == hashlib.sha256(b"").hexdigest()


# ── generate_retention_report ─────────────────────────────────────────────────

class TestGenerateRetentionReport:
    @pytest.fixture(scope="class")
    def retention(self):
        return generate_retention_report()

    def test_returns_required_keys(self, retention):
        assert set(retention.keys()) >= {
            "retention_days", "oldest_log", "newest_log", "total_logs", "ilm_policy"
        }

    def test_retention_days_matches_env(self, retention):
        import os
        expected = int(os.getenv("RETENTION_DAYS", "30"))
        assert retention["retention_days"] == expected

    def test_total_logs_is_non_negative(self, retention):
        assert isinstance(retention["total_logs"], int)
        assert retention["total_logs"] >= 0

    def test_oldest_before_newest(self, retention):
        """Le log le plus ancien est antérieur ou égal au plus récent."""
        if retention["oldest_log"] and retention["newest_log"]:
            assert retention["oldest_log"] <= retention["newest_log"], (
                f"oldest ({retention['oldest_log']}) > newest ({retention['newest_log']})"
            )

    def test_ilm_policy_is_string(self, retention):
        assert isinstance(retention["ilm_policy"], str)
        assert len(retention["ilm_policy"]) > 0


# ── generate_compliance_report ────────────────────────────────────────────────

class TestGenerateComplianceReport:
    @pytest.fixture(scope="class")
    def compliance(self, tmp_path_factory):
        out = tmp_path_factory.mktemp("compliance") / "compliance_test.json"
        return generate_compliance_report(output_path=str(out))

    def test_returns_dict(self, compliance):
        assert isinstance(compliance, dict)

    def test_required_top_level_keys(self, compliance):
        assert set(compliance.keys()) >= {
            "generated_at", "integrity_check", "retention_report",
            "purges", "report_sha256"
        }

    def test_report_sha256_valid(self, compliance):
        sha = compliance["report_sha256"]
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_report_sha256_reproducible(self, compliance):
        """Le hash est calculé à partir des données sans lui-même (pas de récursion)."""
        import hashlib, json
        report_copy = {k: v for k, v in compliance.items() if k != "report_sha256"}
        expected = hashlib.sha256(
            json.dumps(report_copy, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        assert compliance["report_sha256"] == expected

    def test_file_is_valid_json(self, tmp_path):
        out = tmp_path / "compliance_check.json"
        generate_compliance_report(output_path=str(out))
        with out.open(encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, dict)
