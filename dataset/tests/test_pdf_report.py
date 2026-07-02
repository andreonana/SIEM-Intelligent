"""
Tests du générateur de rapports PDF — Smart SIEM DATA S3.

Prérequis : Elasticsearch actif avec des données dans logs-siem.
Lancement  : pytest tests/test_pdf_report.py -v
"""

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.reports.pdf_generator import generate_pdf_report

# Période couverte par les données de test (ajuster si besoin)
_DATE_FROM = "2026-01-01T00:00:00Z"
_DATE_TO   = "2026-12-31T23:59:59Z"


@pytest.fixture(scope="module")
def report_result(tmp_path_factory):
    """Génère un rapport PDF une seule fois pour tous les tests du module."""
    out = tmp_path_factory.mktemp("pdf") / "test_report.pdf"
    return generate_pdf_report(_DATE_FROM, _DATE_TO, output_path=str(out))


class TestGeneratePdfReport:
    def test_returns_dict_with_required_keys(self, report_result):
        """La fonction retourne un dict avec path, sha256 et generated_at."""
        assert isinstance(report_result, dict)
        assert "path" in report_result
        assert "sha256" in report_result
        assert "generated_at" in report_result

    def test_pdf_file_created(self, report_result):
        """Le fichier PDF est effectivement créé sur le disque."""
        path = Path(report_result["path"])
        assert path.exists(), f"Fichier PDF introuvable : {path}"

    def test_pdf_file_not_empty(self, report_result):
        """Le fichier PDF n'est pas vide (taille > 1 ko)."""
        path = Path(report_result["path"])
        size = path.stat().st_size
        assert size > 1024, f"PDF trop petit ({size} octets) — génération probablement incomplète."

    def test_pdf_starts_with_pdf_magic(self, report_result):
        """Le fichier commence par la signature PDF (%PDF-)."""
        path = Path(report_result["path"])
        with path.open("rb") as f:
            header = f.read(5)
        assert header == b"%PDF-", f"Signature PDF invalide : {header!r}"

    def test_sha256_matches_file(self, report_result):
        """Le hash SHA-256 retourné correspond exactement au fichier généré."""
        path = Path(report_result["path"])
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        assert report_result["sha256"] == file_hash, (
            f"Hash retourné ({report_result['sha256'][:12]}…) "
            f"≠ hash du fichier ({file_hash[:12]}…)"
        )

    def test_sha256_is_hex_string_64_chars(self, report_result):
        """Le hash SHA-256 est une chaîne hexadécimale de 64 caractères."""
        sha = report_result["sha256"]
        assert isinstance(sha, str)
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_generated_at_is_iso8601(self, report_result):
        """generated_at est une chaîne ISO 8601 UTC valide."""
        from datetime import datetime, timezone
        ts = report_result["generated_at"]
        # Format attendu : 2026-06-23T14:05:00Z
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        assert dt is not None

    def test_default_output_path_uses_dates(self, tmp_path):
        """Sans output_path, le fichier se nomme siem_report_{from}_{to}.pdf."""
        import os
        # Redirige REPORTS_DIR vers tmp_path pour éviter de polluer le projet
        orig = os.environ.get("REPORTS_DIR")
        os.environ["REPORTS_DIR"] = str(tmp_path)
        try:
            result = generate_pdf_report(_DATE_FROM, _DATE_TO)
            assert Path(result["path"]).exists()
            assert "siem_report" in Path(result["path"]).name
        finally:
            if orig is None:
                os.environ.pop("REPORTS_DIR", None)
            else:
                os.environ["REPORTS_DIR"] = orig
