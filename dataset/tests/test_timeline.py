"""
Tests de la timeline horodatée — get_timeline().

Données requises : index logs-siem avec 1000 logs ingérés (S1).
Lancement      : python tests/test_timeline.py
                 pytest tests/test_timeline.py -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.search import get_timeline


@pytest.fixture(scope="module", autouse=True)
def require_elasticsearch():
    try:
        from app.db.elasticsearch_client import get_client
        if not get_client().ping():
            pytest.skip("Elasticsearch non disponible sur localhost:9200")
    except Exception:
        pytest.skip("Elasticsearch non disponible sur localhost:9200")


# ── Ordre chronologique ───────────────────────────────────────────────────────

class TestTimelineOrder:
    def test_events_sorted_chronologically(self):
        result = get_timeline(max_events=100)
        assert result["total"] > 0
        timestamps = [e["timestamp"] for e in result["events"]]
        assert timestamps == sorted(timestamps), (
            "La timeline doit être triée par timestamp croissant"
        )

    def test_oldest_event_before_newest(self):
        result = get_timeline(max_events=50)
        events = result["events"]
        if len(events) >= 2:
            assert events[0]["timestamp"] <= events[-1]["timestamp"], (
                f"Premier événement ({events[0]['timestamp']}) "
                f"doit être antérieur au dernier ({events[-1]['timestamp']})"
            )

    def test_total_consistent_with_events(self):
        result = get_timeline(max_events=10)
        assert result["total"] >= len(result["events"])


# ── Filtre par host ───────────────────────────────────────────────────────────

class TestTimelineByHost:
    def test_filter_by_host_db_master(self):
        result = get_timeline(host="db-master", max_events=200)
        assert result["total"] > 0, "Aucun événement pour db-master"
        for event in result["events"]:
            assert event["host"] == "db-master", (
                f"Événement d'un autre host : {event['host']}"
            )

    def test_filter_by_host_proxy_01(self):
        result = get_timeline(host="proxy-01", max_events=200)
        assert result["total"] > 0
        for event in result["events"]:
            assert event["host"] == "proxy-01"

    def test_nonexistent_host_returns_empty(self):
        result = get_timeline(host="machine-inexistante-xyz-42")
        assert result["total"] == 0
        assert result["events"] == []


# ── Filtre par log_types ──────────────────────────────────────────────────────

class TestTimelineByLogTypes:
    def test_single_type_auth(self):
        result = get_timeline(log_types=["auth"], max_events=300)
        assert result["total"] > 0, "Aucun log auth dans la timeline"
        for event in result["events"]:
            assert event["log_type"] == "auth", (
                f"log_type inattendu : {event['log_type']}"
            )

    def test_single_type_reseau(self):
        result = get_timeline(log_types=["réseau"], max_events=300)
        assert result["total"] > 0
        for event in result["events"]:
            assert event["log_type"] == "réseau"

    def test_multiple_types_auth_and_reseau(self):
        result = get_timeline(log_types=["auth", "réseau"], max_events=500)
        assert result["total"] > 0
        for event in result["events"]:
            assert event["log_type"] in ("auth", "réseau"), (
                f"log_type hors sélection : {event['log_type']}"
            )

    def test_all_types_combined(self):
        all_types = ["auth", "réseau", "système", "application"]
        result_all = get_timeline(log_types=all_types, max_events=1)
        result_none = get_timeline(max_events=1)
        assert result_all["total"] == result_none["total"], (
            "Tous les types combinés doit être équivalent à aucun filtre"
        )


# ── Filtre par plage temporelle ───────────────────────────────────────────────

class TestTimelineByDateRange:
    def test_events_within_window(self):
        date_from = "2026-06-14T00:00:00Z"
        date_to = "2026-06-15T23:59:59Z"
        result = get_timeline(date_from=date_from, date_to=date_to)
        assert result["total"] > 0
        assert result["date_from"] == date_from
        assert result["date_to"] == date_to
        for event in result["events"]:
            assert event["timestamp"] >= "2026-06-14", (
                f"Événement avant date_from : {event['timestamp']}"
            )
            assert event["timestamp"] <= "2026-06-16", (
                f"Événement après date_to : {event['timestamp']}"
            )

    def test_empty_future_window(self):
        result = get_timeline(
            date_from="2030-01-01T00:00:00Z",
            date_to="2030-12-31T23:59:59Z",
        )
        assert result["total"] == 0
        assert result["events"] == []

    def test_date_bounds_in_response(self):
        date_from = "2026-06-15T00:00:00Z"
        date_to = "2026-06-16T23:59:59Z"
        result = get_timeline(date_from=date_from, date_to=date_to)
        assert result["date_from"] == date_from
        assert result["date_to"] == date_to


# ── Champs retournés ──────────────────────────────────────────────────────────

class TestTimelineFields:
    EXPECTED_FIELDS = {"timestamp", "source_ip", "host", "log_type", "severity", "raw_message"}

    def test_only_expected_fields_returned(self):
        result = get_timeline(max_events=10)
        for event in result["events"]:
            extra = set(event.keys()) - self.EXPECTED_FIELDS
            missing = self.EXPECTED_FIELDS - set(event.keys())
            assert not extra, f"Champs non attendus : {extra}"
            assert not missing, f"Champs manquants : {missing}"

    def test_max_events_respected(self):
        result = get_timeline(max_events=15)
        assert len(result["events"]) <= 15

    def test_no_filter_returns_many_events(self):
        result = get_timeline(max_events=500)
        assert result["total"] >= 1000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
