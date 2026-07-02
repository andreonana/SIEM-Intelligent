# backend/tests/unit/s3/test_exports_dashboard_health.py
#
# Tests des fonctionnalités V3 finalisées : exports CSV/Excel, agrégation
# dashboard réelle, endpoint de santé infra, timeline d'investigation.

import pytest

from app.services.export_service import to_csv_bytes, to_xlsx_bytes


class TestExportService:
    def test_to_csv_bytes_contains_header_and_rows(self):
        rows = [{"id": 1, "name": "alpha"}, {"id": 2, "name": "beta"}]
        content = to_csv_bytes(rows, ["id", "name"])
        text = content.decode("utf-8-sig")
        assert "id,name" in text
        assert "1,alpha" in text
        assert "2,beta" in text

    def test_to_csv_bytes_missing_column_is_blank(self):
        rows = [{"id": 1}]
        content = to_csv_bytes(rows, ["id", "name"])
        text = content.decode("utf-8-sig")
        assert "1," in text

    def test_to_xlsx_bytes_produces_valid_zip_magic_bytes(self):
        rows = [{"id": 1, "name": "alpha"}]
        content = to_xlsx_bytes(rows, ["id", "name"])
        # Un fichier .xlsx est un zip : commence par "PK"
        assert content[:2] == b"PK"

    def test_to_xlsx_bytes_empty_rows_still_has_header(self):
        content = to_xlsx_bytes([], ["id", "name"], sheet_title="Test")
        assert content[:2] == b"PK"
        assert len(content) > 0


class TestSearchQueryBuilder:
    def test_build_query_uses_keyword_subfield_for_exact_terms(self):
        from app.api.v1.routers.search import _build_query, SearchRequest

        search = SearchRequest(source_ip="1.2.3.4", severity="critical")
        query = _build_query(search)
        filters = query["bool"]["filter"]
        assert {"term": {"source_ip.keyword": "1.2.3.4"}} in filters
        assert {"term": {"severity.keyword": "critical"}} in filters

    def test_build_query_no_destination_ip_field(self):
        """Le champ destination_ip n'existe pas dans le pipeline de normalisation :
        SearchRequest ne doit pas exposer ce filtre pour éviter un filtre toujours vide."""
        from app.api.v1.routers.search import SearchRequest

        assert "destination_ip" not in SearchRequest.model_fields

    def test_build_query_date_range(self):
        from app.api.v1.routers.search import _build_query, SearchRequest

        search = SearchRequest(start_date="2026-01-01", end_date="2026-01-31")
        query = _build_query(search)
        filters = query["bool"]["filter"]
        assert any("range" in f for f in filters)

    def test_build_query_match_all_when_no_filters(self):
        from app.api.v1.routers.search import _build_query, SearchRequest

        search = SearchRequest()
        query = _build_query(search)
        assert query == {"match_all": {}}


class TestCorrelationMessageField:
    def test_message_helper_reads_raw_message_field(self):
        """Régression : le pipeline de normalisation stocke le contenu du log sous
        'raw_message', pas 'message'. Sans ce correctif, RULE_001 (brute-force) et
        RULE_003 ne détectent jamais rien car _message() retournait toujours ''."""
        from app.modules.correlation.engine import _message

        hit = {"_source": {"raw_message": "Failed password for root from 1.2.3.4"}}
        assert _message(hit) == "failed password for root from 1.2.3.4"

    def test_message_helper_falls_back_to_message_field(self):
        from app.modules.correlation.engine import _message

        hit = {"_source": {"message": "Some Legacy Message"}}
        assert _message(hit) == "some legacy message"

    def test_message_helper_empty_when_no_field(self):
        from app.modules.correlation.engine import _message

        assert _message({"_source": {}}) == ""


class TestBlockIpParamsAlignment:
    def test_block_ip_params_declared_are_ip_reason_alert_id(self):
        """Vérifie que le playbook block_ip attend bien 'ip' (pas 'source_ip') pour
        rester cohérent avec ce que le frontend envoie réellement."""
        from app.modules.soar.playbooks import PLAYBOOKS

        assert PLAYBOOKS["block_ip"]["params"] == ["ip", "reason", "alert_id"]


@pytest.mark.asyncio
class TestSystemHealthEndpoint:
    async def test_tcp_probe_returns_false_on_closed_port(self):
        """Port local fermé : refus de connexion garanti et déterministe,
        contrairement à une IP externe dont le comportement réseau dépend de
        l'environnement d'exécution (sandbox, proxy, etc.)."""
        import socket
        from app.api.v1.routers.system import _tcp_probe

        # Trouve un port local libre (donc fermé/refusé) de façon fiable
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]

        reachable = await _tcp_probe("127.0.0.1", free_port, timeout=1.0)
        assert reachable is False

    async def test_tcp_probe_returns_true_when_listening(self):
        import socket
        from app.api.v1.routers.system import _tcp_probe

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            reachable = await _tcp_probe("127.0.0.1", port, timeout=1.0)
            assert reachable is True
        finally:
            server.close()

    async def test_check_tcp_service_reports_unavailable_when_closed(self):
        import socket
        from app.api.v1.routers.system import _check_tcp_service

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]

        result = await _check_tcp_service("dummy", "127.0.0.1", free_port)
        assert result["status"] == "unavailable"
        assert result["name"] == "dummy"
