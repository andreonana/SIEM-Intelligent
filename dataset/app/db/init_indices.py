"""
Crée les index Elasticsearch du Smart SIEM avec leurs mappings et la politique ILM.
Idempotent : peut être relancé sans erreur si les index existent déjà.

Lancement : python dataset/app/db/init_indices.py
"""

import os
import sys
from pathlib import Path

# Rend le package dataset/ importable depuis la racine du projet
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dotenv import load_dotenv
from elasticsearch import NotFoundError

load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")

from app.db.elasticsearch_client import get_client, ES_HOST

RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))
ILM_POLICY_NAME = "logs-siem-policy"

# ── Mappings ──────────────────────────────────────────────────────────────────

INDEX_CONFIGS = {
    "logs-siem": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.lifecycle.name": ILM_POLICY_NAME,
        },
        "mappings": {
            "properties": {
                "timestamp":    {"type": "date"},
                "source_ip":    {"type": "ip"},
                "host":         {"type": "keyword"},
                "log_type":     {"type": "keyword"},   # auth | réseau | système | application
                "severity":     {"type": "keyword"},   # info | warning | critical
                "raw_message":  {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword", "ignore_above": 1024}
                    },
                },
                "tags":         {"type": "keyword"},   # array implicite en ES
            }
        },
    },
    "siem-users": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "username":      {"type": "keyword"},
                "password_hash": {"type": "keyword"},
                "role":          {"type": "keyword"},
                "created_at":    {"type": "date"},
            }
        },
    },
    "siem-rules": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "rule_id":    {"type": "keyword"},
                "name":       {"type": "text"},
                "type":       {"type": "keyword"},
                "active":     {"type": "boolean"},
                "created_at": {"type": "date"},
            }
        },
    },
    "siem-alerts": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "alert_id":     {"type": "keyword"},
                "severity":     {"type": "keyword"},
                "status":       {"type": "keyword"},
                "related_logs": {"type": "keyword"},   # array d'IDs de logs
                "created_at":   {"type": "date"},
            }
        },
    },
}


def create_ilm_policy(client) -> None:
    """Crée ou met à jour la politique ILM de rétention pour logs-siem."""
    min_age = f"{RETENTION_DAYS}d"
    policy = {
        "phases": {
            "delete": {
                "min_age": min_age,
                "actions": {"delete": {}},
            }
        }
    }
    client.ilm.put_lifecycle(name=ILM_POLICY_NAME, policy=policy)
    print(f"  [ILM] Politique '{ILM_POLICY_NAME}' configurée (rétention : {min_age})")


def create_index(client, index_name: str, config: dict) -> None:
    """Crée un index s'il n'existe pas encore."""
    if client.indices.exists(index=index_name):
        print(f"  [SKIP] Index '{index_name}' existe déjà")
        return

    client.indices.create(
        index=index_name,
        settings=config["settings"],
        mappings=config["mappings"],
        wait_for_active_shards=0,
    )
    print(f"  [OK]   Index '{index_name}' créé")


def main() -> None:
    print(f"\n=== Initialisation des index Smart SIEM ({ES_HOST}) ===\n")

    client = get_client()

    print("→ Création de la politique ILM ...")
    create_ilm_policy(client)

    print("\n→ Création des index ...")
    for index_name, config in INDEX_CONFIGS.items():
        create_index(client, index_name, config)

    print("\n✓ Initialisation terminée avec succès.\n")


if __name__ == "__main__":
    main()
