"""
Lit data/test_logs.json et insère les logs directement dans Elasticsearch
via bulk insert (sans passer par aucune API HTTP intermédiaire).

Lancement : python dataset/scripts/ingest_test_logs.py
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from elasticsearch import helpers
from app.db.elasticsearch_client import get_client

INDEX = "logs-siem"
DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "test_logs.json"


def load_logs() -> list[dict]:
    if not DATA_FILE.exists():
        print(f"✗ Fichier introuvable : {DATA_FILE}")
        print("  Lancez d'abord : python dataset/scripts/generate_test_logs.py")
        sys.exit(1)

    with DATA_FILE.open(encoding="utf-8") as f:
        return json.load(f)


def build_actions(logs: list[dict]) -> list[dict]:
    return [{"_index": INDEX, "_source": log} for log in logs]


def main() -> None:
    print(f"\n=== Ingestion des logs dans '{INDEX}' ===\n")

    logs = load_logs()
    print(f"→ {len(logs)} logs chargés depuis {DATA_FILE.name}")

    client = get_client()
    actions = build_actions(logs)

    start = time.perf_counter()
    success, errors = helpers.bulk(client, actions, raise_on_error=False)
    elapsed = time.perf_counter() - start

    # Forcer le rafraîchissement pour que les docs soient immédiatement requêtables
    client.indices.refresh(index=INDEX)

    print(f"✓ {success} documents indexés en {elapsed:.2f}s")
    if errors:
        print(f"✗ {len(errors)} erreurs :")
        for err in errors[:5]:
            print(f"   {err}")


if __name__ == "__main__":
    main()
