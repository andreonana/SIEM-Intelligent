"""
Tests du moteur de recherche multi-critères — search_logs().

Données requises : index logs-siem avec 1000 logs ingérés (S1).
Lancement      : python tests/test_search.py
                 pytest tests/test_search.py -v
"""

import sys
import ipaddress
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.search import search_logs


@pytest.fixture(scope="module", autouse=True)
def require_elasticsearch():
    try:
        from app.db.elasticsearch_client import get_client
        if not get_client().ping():
            pytest.skip("Elasticsearch non disponible sur localhost:9200")
    except Exception:
        pytest.skip("Elasticsearch non disponible sur localhost:9200")


# ── Filtre par severity ───────────────────────────────────────────────────────

class TestSearchBySeverity:
    def test_only_critical_results(self):
        result = search_logs(severity="critical", page_size=100)
        assert result["total"] > 0, "Aucun log critical dans l'index"
        for doc in result["results"]:
            assert doc["severity"] == "critical"

    def test_only_warning_results(self):
        result = search_logs(severity="warning", page_size=100)
        assert result["total"] > 0
        for doc in result["results"]:
            assert doc["severity"] == "warning"

    def test_only_info_results(self):
        result = search_logs(severity="info", page_size=100)
        assert result["total"] > 0
        for doc in result["results"]:
            assert doc["severity"] == "info"


# ── Filtre par plage horaire ──────────────────────────────────────────────────

class TestSearchByDateRange:
    def test_results_within_range(self):
        result = search_logs(
            date_from="2026-06-14T00:00:00Z",
            date_to="2026-06-15T23:59:59Z",
            page_size=100,
        )
        assert result["total"] > 0
        for doc in result["results"]:
            ts = doc["timestamp"]
            assert ts >= "2026-06-14", f"Timestamp avant date_from : {ts}"
            assert ts <= "2026-06-16", f"Timestamp après date_to : {ts}"

    def test_empty_future_range(self):
        result = search_logs(
            date_from="2030-01-01T00:00:00Z",
            date_to="2030-12-31T23:59:59Z",
        )
        assert result["total"] == 0

    def test_date_from_only(self):
        result = search_logs(date_from="2026-06-20T00:00:00Z", page_size=50)
        assert result["total"] > 0
        for doc in result["results"]:
            assert doc["timestamp"] >= "2026-06-20"


# ── Filtre par source_ip ──────────────────────────────────────────────────────

class TestSearchBySourceIP:
    def test_exact_ip_returns_correct_ip(self):
        # 10.89.72.118 est présente dans les données de test (S1)
        result = search_logs(source_ip="10.89.72.118", page_size=10)
        for doc in result["results"]:
            assert doc["source_ip"] == "10.89.72.118"

    def test_cidr_range_10_0_0_0_8(self):
        # 5 IPs en 10.x.x.x sont dans les données de test
        result = search_logs(source_ip="10.0.0.0/8", page_size=100)
        assert result["total"] == 5, (
            f"Attendu 5 IPs dans 10.0.0.0/8, obtenu {result['total']}"
        )
        net = ipaddress.ip_network("10.0.0.0/8")
        for doc in result["results"]:
            assert ipaddress.ip_address(doc["source_ip"]) in net, (
                f"IP hors CIDR : {doc['source_ip']}"
            )

    def test_cidr_no_match_returns_empty(self):
        # 192.168.0.0/16 — aucune IP dans les données de test
        result = search_logs(source_ip="192.168.0.0/16")
        assert result["total"] == 0


# ── Filtres combinés (AND cumulatif) ─────────────────────────────────────────

class TestSearchCombined:
    def test_severity_and_log_type(self):
        result = search_logs(severity="critical", log_type="auth", page_size=50)
        for doc in result["results"]:
            assert doc["severity"] == "critical"
            assert doc["log_type"] == "auth"

    def test_severity_type_and_date_from(self):
        result = search_logs(
            severity="warning",
            log_type="système",
            date_from="2026-06-14T00:00:00Z",
            page_size=50,
        )
        for doc in result["results"]:
            assert doc["severity"] == "warning"
            assert doc["log_type"] == "système"
            assert doc["timestamp"] >= "2026-06-14"

    def test_combined_reduces_results(self):
        total_critical = search_logs(severity="critical", page_size=1)["total"]
        total_combined = search_logs(
            severity="critical", log_type="auth", page_size=1
        )["total"]
        assert total_combined <= total_critical


# ── Recherche full-text (keyword) ─────────────────────────────────────────────

class TestSearchByKeyword:
    def test_keyword_timeout_in_message(self):
        result = search_logs(keyword="timeout", page_size=50)
        assert result["total"] > 0, "Aucun résultat pour 'timeout'"
        for doc in result["results"]:
            assert "timeout" in doc["raw_message"].lower()

    def test_keyword_connection(self):
        result = search_logs(keyword="connection", page_size=20)
        assert result["total"] > 0
        for doc in result["results"]:
            assert "connection" in doc["raw_message"].lower()

    def test_unknown_keyword_returns_empty(self):
        result = search_logs(keyword="xyzzy_nonexistent_token_42")
        assert result["total"] == 0


# ── Pagination ────────────────────────────────────────────────────────────────

class TestPagination:
    def test_page1_different_from_page2(self):
        page1 = search_logs(page=1, page_size=10)
        page2 = search_logs(page=2, page_size=10)
        assert page1["total"] == page2["total"], "Le total doit être identique quelle que soit la page"
        keys1 = [f"{d['timestamp']}{d.get('source_ip', '')}" for d in page1["results"]]
        keys2 = [f"{d['timestamp']}{d.get('source_ip', '')}" for d in page2["results"]]
        assert keys1 != keys2, "Page 1 et page 2 ne doivent pas retourner les mêmes résultats"

    def test_total_at_least_1000(self):
        result = search_logs(page=1, page_size=1)
        assert result["total"] >= 1000, f"Attendu ≥1000 logs, obtenu {result['total']}"

    def test_page_size_respected(self):
        result = search_logs(page=1, page_size=25)
        assert len(result["results"]) == 25

    def test_metadata_in_response(self):
        result = search_logs(page=3, page_size=15)
        assert result["page"] == 3
        assert result["page_size"] == 15
        assert "total" in result
        assert "results" in result


# ── Sans filtre ───────────────────────────────────────────────────────────────

class TestNoFilter:
    def test_returns_all_logs_when_no_filter(self):
        result = search_logs(page_size=1)
        assert result["total"] >= 1000

    def test_sorted_desc_by_timestamp(self):
        result = search_logs(page_size=20)
        timestamps = [doc["timestamp"] for doc in result["results"]]
        assert timestamps == sorted(timestamps, reverse=True), (
            "Les résultats doivent être triés par timestamp décroissant"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
