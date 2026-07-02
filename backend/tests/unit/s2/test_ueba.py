# tests/unit/s2/test_ueba.py
#
# Tests unitaires du module UEBA : baseline, behavior_analyzer, anomaly_detector, risk_scorer.
# Toutes les dépendances externes (ES, DB) sont mockées.

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.modules.ueba.baseline import (
    EntityBaseline,
    build_baselines_from_hits,
    baseline_to_dict,
    _top_n_keys,
)
from app.modules.ueba.behavior_analyzer import (
    BehaviorSummary,
    build_behavior_summaries_from_hits,
    summary_to_dict,
)
from app.modules.ueba.anomaly_detector import (
    Anomaly,
    detect_anomalies,
    _detect_unusual_hour,
    _detect_unseen_source_ip,
    _detect_unseen_host,
    _detect_activity_spike,
    _detect_auth_failure_spike,
    _detect_host_spread,
)
from app.modules.ueba.risk_scorer import (
    RiskScore,
    compute_risk_score,
    risk_score_to_dict,
)
from collections import Counter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_hit(
    source_ip: str = "10.0.0.1",
    host: str = "server01",
    log_type: str = "auth",
    message: str = "accepted publickey",
    hour_utc: int = 10,
    user: str = "",
) -> dict:
    ts = datetime(2026, 1, 15, hour_utc, 0, 0, tzinfo=timezone.utc).isoformat()
    return {
        "_source": {
            "source_ip": source_ip,
            "host": host,
            "log_type": log_type,
            "message": message,
            "timestamp": ts,
            "user": user,
        }
    }


def _make_baseline(
    entity_type: str = "source_ip",
    entity_id: str = "10.0.0.1",
    usual_hours: list = None,
    usual_ips: list = None,
    usual_hosts: list = None,
    avg_daily: float = 10.0,
    auth_failures: int = 0,
    avg_daily_failures: float = 0.0,
    dominant_log_types: list = None,
    sensitive_count: int = 0,
) -> EntityBaseline:
    return EntityBaseline(
        entity_type=entity_type,
        entity_id=entity_id,
        period_days=30,
        total_events=300,
        avg_daily_events=avg_daily,
        usual_hours=usual_hours or [8, 9, 10, 11, 14, 15, 16],
        usual_source_ips=usual_ips or ["10.0.0.1"],
        usual_hosts=usual_hosts or ["server01"],
        dominant_log_types=dominant_log_types or ["auth"],
        auth_failure_count=auth_failures,
        auth_success_count=290,
        avg_daily_auth_failures=avg_daily_failures,
        sensitive_action_count=sensitive_count,
        is_reliable=True,
    )


def _make_summary(
    entity_type: str = "source_ip",
    entity_id: str = "10.0.0.1",
    total_events: int = 5,
    observed_hours: list = None,
    observed_ips: list = None,
    observed_hosts: list = None,
    observed_log_types: list = None,
    auth_failures: int = 0,
    host_spread: int = 1,
    sensitive: int = 0,
) -> BehaviorSummary:
    return BehaviorSummary(
        entity_type=entity_type,
        entity_id=entity_id,
        window_minutes=60,
        total_events=total_events,
        observed_hours=observed_hours or [10],
        observed_source_ips=observed_ips or ["10.0.0.1"],
        observed_hosts=observed_hosts or ["server01"],
        observed_log_types=observed_log_types or ["auth"],
        auth_failure_count=auth_failures,
        auth_success_count=total_events - auth_failures,
        sensitive_action_count=sensitive,
        host_spread=host_spread,
        ip_spread=len(observed_ips or ["10.0.0.1"]),
    )


# ===========================================================================
# Tests : baseline
# ===========================================================================

class TestBaseline:

    def test_build_baseline_basic(self):
        hits = [_make_hit(source_ip="10.0.0.1", hour_utc=10) for _ in range(20)]
        baselines = build_baselines_from_hits(hits, "source_ip", baseline_days=30, min_events=5)
        assert "10.0.0.1" in baselines
        b = baselines["10.0.0.1"]
        assert b.total_events == 20
        assert b.avg_daily_events == round(20 / 30, 2)
        assert 10 in b.usual_hours
        assert "server01" in b.usual_hosts
        assert b.is_reliable is True

    def test_baseline_unreliable_below_min(self):
        hits = [_make_hit(source_ip="10.0.0.2", hour_utc=10)]
        baselines = build_baselines_from_hits(hits, "source_ip", baseline_days=30, min_events=5)
        assert baselines["10.0.0.2"].is_reliable is False

    def test_baseline_auth_failures_counted(self):
        hits = (
            [_make_hit(log_type="auth", message="failed password") for _ in range(5)]
            + [_make_hit(log_type="auth", message="accepted publickey") for _ in range(10)]
        )
        baselines = build_baselines_from_hits(hits, "source_ip", baseline_days=30, min_events=5)
        b = baselines["10.0.0.1"]
        assert b.auth_failure_count == 5
        assert b.auth_success_count == 10

    def test_baseline_by_host(self):
        hits = [_make_hit(host="webserver", source_ip="192.168.1.1") for _ in range(10)]
        baselines = build_baselines_from_hits(hits, "host", baseline_days=30, min_events=5)
        assert "webserver" in baselines

    def test_baseline_to_dict_keys(self):
        b = _make_baseline()
        d = baseline_to_dict(b)
        for key in ("entity_type", "entity_id", "avg_daily_events", "usual_hours",
                    "usual_source_ips", "usual_hosts", "dominant_log_types", "is_reliable"):
            assert key in d

    def test_top_n_keys_coverage(self):
        c = Counter({"a": 80, "b": 10, "c": 10})
        result = _top_n_keys(c, n=5, coverage=0.85)
        assert "a" in result

    @pytest.mark.asyncio
    async def test_compute_baseline_calls_es(self):
        mock_es = AsyncMock()
        mock_es.search = AsyncMock(return_value={
            "hits": {"hits": [_make_hit() for _ in range(10)]}
        })
        with patch("app.modules.ueba.baseline.settings") as mock_settings:
            mock_settings.ueba_baseline_days = 30
            mock_settings.ueba_min_events_for_baseline = 5
            mock_settings.es_logs_index_name = "test-index"
            from app.modules.ueba.baseline import compute_baseline
            result = await compute_baseline(mock_es, entity_type="source_ip", baseline_days=30)
        assert isinstance(result, dict)
        mock_es.search.assert_called_once()


# ===========================================================================
# Tests : behavior_analyzer
# ===========================================================================

class TestBehaviorAnalyzer:

    def test_build_summaries_basic(self):
        hits = [_make_hit(source_ip="10.0.0.1", hour_utc=10) for _ in range(5)]
        summaries = build_behavior_summaries_from_hits(hits, "source_ip", window_minutes=60)
        assert "10.0.0.1" in summaries
        s = summaries["10.0.0.1"]
        assert s.total_events == 5
        assert 10 in s.observed_hours
        assert "server01" in s.observed_hosts

    def test_build_summaries_auth_failures(self):
        hits = [_make_hit(log_type="auth", message="failed password") for _ in range(3)]
        summaries = build_behavior_summaries_from_hits(hits, "source_ip", window_minutes=60)
        assert summaries["10.0.0.1"].auth_failure_count == 3

    def test_host_spread_counted(self):
        hits = [
            _make_hit(source_ip="10.0.0.1", host=f"server{i}") for i in range(5)
        ]
        summaries = build_behavior_summaries_from_hits(hits, "source_ip", window_minutes=60)
        assert summaries["10.0.0.1"].host_spread == 5

    def test_summary_to_dict_keys(self):
        s = _make_summary()
        d = summary_to_dict(s)
        for key in ("entity_type", "entity_id", "total_events", "observed_hours",
                    "auth_failure_count", "host_spread"):
            assert key in d


# ===========================================================================
# Tests : anomaly_detector
# ===========================================================================

class TestAnomalyDetector:

    def test_no_anomaly_normal_behavior(self):
        baseline = _make_baseline(usual_hours=[10], usual_ips=["10.0.0.1"], usual_hosts=["server01"])
        summary = _make_summary(observed_hours=[10], observed_ips=["10.0.0.1"], observed_hosts=["server01"])
        anomalies = detect_anomalies(baseline, summary)
        types = [a.anomaly_type for a in anomalies]
        assert "unusual_login_hour" not in types
        assert "unseen_source_ip" not in types
        assert "unseen_host" not in types

    def test_unusual_hour_detected(self):
        baseline = _make_baseline(usual_hours=[8, 9, 10])
        summary = _make_summary(observed_hours=[3])  # 3h UTC = hors plage
        anomalies = _detect_unusual_hour(baseline, summary)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "unusual_login_hour"
        assert anomalies[0].weight == 10.0

    def test_no_unusual_hour_in_range(self):
        baseline = _make_baseline(usual_hours=[8, 9, 10])
        summary = _make_summary(observed_hours=[9])
        anomalies = _detect_unusual_hour(baseline, summary)
        assert anomalies == []

    def test_unseen_ip_detected(self):
        baseline = _make_baseline(usual_ips=["10.0.0.1"])
        summary = _make_summary(observed_ips=["192.168.99.99"])
        anomalies = _detect_unseen_source_ip(baseline, summary)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "unseen_source_ip"
        assert anomalies[0].weight == 20.0

    def test_known_ip_no_anomaly(self):
        baseline = _make_baseline(usual_ips=["10.0.0.1"])
        summary = _make_summary(observed_ips=["10.0.0.1"])
        anomalies = _detect_unseen_source_ip(baseline, summary)
        assert anomalies == []

    def test_unseen_host_detected(self):
        baseline = _make_baseline(usual_hosts=["server01"])
        summary = _make_summary(observed_hosts=["rogue-host"])
        anomalies = _detect_unseen_host(baseline, summary)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "unseen_host"
        assert anomalies[0].weight == 15.0

    def test_activity_spike_detected(self):
        # avg_daily = 10, donc en 60 min, équivalent journée = 240
        # SPIKE_FACTOR = 3, seuil = 30 → spike déclenché
        baseline = _make_baseline(avg_daily=10.0)
        summary = _make_summary(total_events=20, observed_hours=[10])  # 20 en 60 min = 480/jour equiv
        anomalies = _detect_activity_spike(baseline, summary)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "abnormal_activity_volume"

    def test_no_activity_spike_normal_volume(self):
        baseline = _make_baseline(avg_daily=10.0)
        # 0.5 events en 60 min = 12/jour -> à peine au-dessus de la moyenne (non spike)
        summary = _make_summary(total_events=1, observed_hours=[10])
        anomalies = _detect_activity_spike(baseline, summary)
        assert anomalies == []

    def test_auth_failure_spike_detected(self):
        baseline = _make_baseline(auth_failures=10, avg_daily_failures=0.33)
        # 5 failures en 60 min = 5*24=120/jour, soit 120/0.33 = 364x la normale
        summary = _make_summary(auth_failures=5)
        anomalies = _detect_auth_failure_spike(baseline, summary)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "auth_failure_spike"
        assert anomalies[0].weight == 25.0

    def test_auth_failure_spike_zero_baseline(self):
        baseline = _make_baseline(auth_failures=0, avg_daily_failures=0.0)
        summary = _make_summary(auth_failures=6)
        from app.modules.ueba.anomaly_detector import _detect_auth_failure_spike
        anomalies = _detect_auth_failure_spike(baseline, summary)
        assert len(anomalies) == 1
        assert anomalies[0].severity == "HIGH"

    def test_host_spread_detected(self):
        baseline = _make_baseline(usual_hosts=["server01"])
        summary = _make_summary(
            observed_hosts=["s1", "s2", "s3", "s4", "s5"],
            host_spread=5,
        )
        anomalies = _detect_host_spread(baseline, summary)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "abnormal_host_spread"

    def test_entity_mismatch_raises(self):
        baseline = _make_baseline(entity_type="source_ip", entity_id="10.0.0.1")
        summary = _make_summary(entity_type="source_ip", entity_id="10.0.0.2")
        with pytest.raises(ValueError, match="Mismatch entité"):
            detect_anomalies(baseline, summary)

    def test_cumulative_anomalies(self):
        """Une entité avec plusieurs signaux doit retourner plusieurs anomalies."""
        baseline = _make_baseline(
            usual_hours=[9, 10],
            usual_ips=["10.0.0.1"],
            usual_hosts=["server01"],
            avg_daily=5.0,
        )
        summary = _make_summary(
            observed_hours=[3],           # heure inhabituelle
            observed_ips=["99.99.99.99"], # IP inconnue
            observed_hosts=["rogue"],     # hôte inconnu
            total_events=50,              # pic d'activité
        )
        anomalies = detect_anomalies(baseline, summary)
        types = {a.anomaly_type for a in anomalies}
        assert "unusual_login_hour" in types
        assert "unseen_source_ip" in types
        assert "unseen_host" in types
        assert "abnormal_activity_volume" in types


# ===========================================================================
# Tests : risk_scorer
# ===========================================================================

class TestRiskScorer:

    def test_no_anomaly_score_zero(self):
        rs = compute_risk_score("source_ip", "10.0.0.1", [])
        assert rs.score == 0.0
        assert rs.risk_level == "low"
        assert rs.anomaly_count == 0

    def test_score_sum_of_weights(self):
        anomalies = [
            Anomaly("unusual_login_hour", "source_ip", "10.0.0.1", "WARNING", 10.0, "desc", "ev"),
            Anomaly("unseen_source_ip",   "source_ip", "10.0.0.1", "HIGH",    20.0, "desc", "ev"),
        ]
        rs = compute_risk_score("source_ip", "10.0.0.1", anomalies)
        assert rs.score == 30.0
        assert rs.risk_level == "medium"

    def test_score_capped_at_100(self):
        anomalies = [
            Anomaly(f"type_{i}", "source_ip", "10.0.0.1", "CRITICAL", 30.0, "desc", "ev")
            for i in range(10)
        ]
        rs = compute_risk_score("source_ip", "10.0.0.1", anomalies)
        assert rs.score == 100.0

    def test_risk_level_critical(self):
        anomalies = [
            Anomaly("auth_failure_spike", "source_ip", "10.0.0.1", "CRITICAL", 25.0, "d", "e"),
            Anomaly("unseen_source_ip",   "source_ip", "10.0.0.1", "HIGH",     20.0, "d", "e"),
            Anomaly("unseen_host",        "source_ip", "10.0.0.1", "HIGH",     15.0, "d", "e"),
            Anomaly("abnormal_activity",  "source_ip", "10.0.0.1", "HIGH",     20.0, "d", "e"),
        ]
        rs = compute_risk_score("source_ip", "10.0.0.1", anomalies)
        assert rs.score == 80.0
        assert rs.risk_level == "critical"

    def test_risk_level_high(self):
        anomalies = [
            Anomaly("unseen_source_ip", "source_ip", "10.0.0.1", "HIGH", 20.0, "d", "e"),
            Anomaly("unseen_host",      "source_ip", "10.0.0.1", "HIGH", 15.0, "d", "e"),
            Anomaly("unusual_hour",     "source_ip", "10.0.0.1", "WARN", 10.0, "d", "e"),
        ]
        rs = compute_risk_score("source_ip", "10.0.0.1", anomalies)
        assert rs.score == 45.0
        assert rs.risk_level == "high"

    def test_contributing_types_listed(self):
        anomalies = [
            Anomaly("unusual_login_hour", "source_ip", "10.0.0.1", "WARNING", 10.0, "d", "e"),
            Anomaly("unseen_source_ip",   "source_ip", "10.0.0.1", "HIGH",    20.0, "d", "e"),
        ]
        rs = compute_risk_score("source_ip", "10.0.0.1", anomalies)
        assert "unusual_login_hour" in rs.contributing_types
        assert "unseen_source_ip" in rs.contributing_types

    def test_justification_contains_score(self):
        anomalies = [Anomaly("test_type", "source_ip", "ip", "HIGH", 20.0, "desc", "ev")]
        rs = compute_risk_score("source_ip", "ip", anomalies)
        assert "20" in rs.justification

    def test_risk_score_to_dict_keys(self):
        rs = compute_risk_score("source_ip", "10.0.0.1", [])
        d = risk_score_to_dict(rs)
        for key in ("entity_type", "entity_id", "score", "risk_level",
                    "anomaly_count", "contributing_types", "justification", "computed_at"):
            assert key in d


# ===========================================================================
# Tests : service UEBA (orchestrateur)
# ===========================================================================

class TestUEBAService:

    @pytest.mark.asyncio
    async def test_run_ueba_no_baseline(self):
        """Si ES ne retourne rien, pas d'analyse."""
        mock_es = AsyncMock()
        mock_es.search = AsyncMock(return_value={"hits": {"hits": []}})
        mock_db = AsyncMock()

        with patch("app.services.ueba_service.compute_baseline", new_callable=AsyncMock) as mock_bl, \
             patch("app.services.ueba_service.analyze_recent_behavior", new_callable=AsyncMock) as mock_beh, \
             patch("app.services.ueba_service.log_action", new_callable=AsyncMock):
            mock_bl.return_value = {}
            mock_beh.return_value = {}

            from app.services.ueba_service import run_ueba_analysis
            result = await run_ueba_analysis(mock_db, mock_es, entity_type="source_ip")

        assert result["entities_analyzed"] == 0
        assert result["anomalies_detected"] == 0

    @pytest.mark.asyncio
    async def test_run_ueba_with_anomalies(self):
        """Vérifie que le pipeline complet produit des anomalies et un score."""
        baseline = _make_baseline(
            usual_hours=[9, 10],
            usual_ips=["10.0.0.1"],
            usual_hosts=["server01"],
        )
        summary = _make_summary(
            observed_hours=[3],
            observed_ips=["99.99.99.99"],
            observed_hosts=["rogue"],
        )

        with patch("app.services.ueba_service.compute_baseline", new_callable=AsyncMock) as mock_bl, \
             patch("app.services.ueba_service.analyze_recent_behavior", new_callable=AsyncMock) as mock_beh, \
             patch("app.services.ueba_service._persist_anomalies", new_callable=AsyncMock), \
             patch("app.services.ueba_service._persist_risk_score", new_callable=AsyncMock), \
             patch("app.services.ueba_service._create_ueba_alert", new_callable=AsyncMock, return_value=0), \
             patch("app.services.ueba_service.log_action", new_callable=AsyncMock):

            mock_bl.return_value = {"10.0.0.1": baseline}
            mock_beh.return_value = {"10.0.0.1": summary}

            from app.services.ueba_service import run_ueba_analysis
            mock_db = AsyncMock()
            mock_es = AsyncMock()
            result = await run_ueba_analysis(mock_db, mock_es, entity_type="source_ip")

        assert result["entities_analyzed"] == 1
        assert result["anomalies_detected"] > 0
