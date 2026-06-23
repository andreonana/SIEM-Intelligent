"""
Valide que les logs ingérés dans Elasticsearch sont complets et bien formés.
Affiche un rapport succès/échec.

Lancement : python dataset/scripts/validate_ingestion.py
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.elasticsearch_client import get_client

INDEX = "logs-siem"
DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "test_logs.json"

REQUIRED_FIELDS = ["timestamp", "source_ip", "host", "log_type", "severity", "raw_message", "tags"]
VALID_LOG_TYPES = {"auth", "réseau", "système", "application"}
VALID_SEVERITIES = {"info", "warning", "critical"}


def get_expected_count() -> int:
    if not DATA_FILE.exists():
        return 0
    with DATA_FILE.open(encoding="utf-8") as f:
        return len(json.load(f))


def validate_document(doc: dict) -> list[str]:
    """Retourne la liste des problèmes trouvés sur un document."""
    issues = []
    src = doc.get("_source", {})

    for field in REQUIRED_FIELDS:
        if field not in src or src[field] is None:
            issues.append(f"champ absent ou null : '{field}'")

    if src.get("log_type") not in VALID_LOG_TYPES:
        issues.append(f"log_type invalide : '{src.get('log_type')}'")

    if src.get("severity") not in VALID_SEVERITIES:
        issues.append(f"severity invalide : '{src.get('severity')}'")

    if not isinstance(src.get("tags"), list):
        issues.append("tags n'est pas un tableau")

    return issues


def main() -> None:
    print("\n=== Rapport de validation — Smart SIEM logs-siem ===\n")

    client = get_client()
    expected = get_expected_count()

    # ── Comptage ──────────────────────────────────────────────────────────────
    count_resp = client.count(index=INDEX)
    actual = count_resp["count"]

    print(f"Logs attendus  : {expected}")
    print(f"Logs en base   : {actual}")

    count_ok = actual >= expected > 0
    print(f"Comptage       : {'✓ OK' if count_ok else '✗ ÉCHEC'}")

    # ── Échantillon : vérification des champs ─────────────────────────────────
    start = time.perf_counter()
    sample_resp = client.search(
        index=INDEX,
        size=50,
        query={"match_all": {}},
    )
    elapsed = time.perf_counter() - start
    hits = sample_resp["hits"]["hits"]

    issues_found = []
    for doc in hits:
        doc_issues = validate_document(doc)
        if doc_issues:
            issues_found.append({"id": doc["_id"], "issues": doc_issues})

    print(f"\nÉchantillon vérifié : {len(hits)} documents")
    print(f"Temps de requête    : {elapsed:.3f}s")
    print(f"Problèmes trouvés   : {len(issues_found)}")

    if issues_found:
        print("\nDétail des problèmes :")
        for item in issues_found[:5]:
            print(f"  [{item['id']}] {', '.join(item['issues'])}")

    # ── Recherche filtrée (simulation requête métier) ──────────────────────────
    start2 = time.perf_counter()
    filter_resp = client.search(
        index=INDEX,
        size=10,
        query={
            "bool": {
                "filter": [
                    {"term": {"severity": "critical"}},
                    {"range": {"timestamp": {"gte": "now-7d/d", "lte": "now"}}},
                ]
            }
        },
    )
    elapsed2 = time.perf_counter() - start2
    critical_count = filter_resp["hits"]["total"]["value"]

    print(f"\nRecherche filtrée (critical, 7 derniers jours) :")
    print(f"  Résultats    : {critical_count} logs")
    print(f"  Temps        : {elapsed2:.3f}s")

    # ── Résumé ────────────────────────────────────────────────────────────────
    success = count_ok and len(issues_found) == 0
    print(f"\n{'='*50}")
    print(f"RÉSULTAT GLOBAL : {'✓ SUCCÈS' if success else '✗ ÉCHEC'}")
    print(f"{'='*50}\n")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
