#!/usr/bin/env python3
"""
Smart SIEM — Forwarder Agent S1
================================
Surveille un répertoire de logs (LOG_DIR), lit les nouvelles lignes au fil de l'eau
et les envoie au backend d'ingestion en lots (bulk).

Flux : fichier log Linux → forwarder → POST /api/v1/logs/ingest (bulk) → Elasticsearch

Lancement local :
    LOG_DIR=infra/log_test BACKEND_URL=http://localhost:8000 python3 agents/forwarder.py

En Docker : géré par docker-compose.yml (service forwarder).
"""

import json
import os
import time
from pathlib import Path

import urllib.request
import urllib.error

# ── Configuration depuis l'environnement ─────────────────────────────────────
BACKEND_URL   = os.getenv("BACKEND_URL",   "http://localhost:8000")
INGEST_API_KEY = os.getenv("INGEST_API_KEY", "dev-only-change-me")
LOG_DIR       = os.getenv("LOG_DIR",       "infra/log_test")
BATCH_SIZE    = int(os.getenv("BATCH_SIZE",    "50"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "2"))

INGEST_ENDPOINT = f"{BACKEND_URL}/api/v1/logs/ingest"
BULK_ENDPOINT   = f"{BACKEND_URL}/api/v1/logs/ingest/bulk"
HEALTH_ENDPOINT = f"{BACKEND_URL}/health"

# ── État de lecture (position par fichier) ────────────────────────────────────
_file_positions: dict[str, int] = {}


def wait_for_backend(max_wait: int = 120) -> None:
    """Attend que le backend soit disponible avant de commencer."""
    print(f"[forwarder] En attente du backend {BACKEND_URL} ...")
    for _ in range(max_wait):
        try:
            req = urllib.request.Request(HEALTH_ENDPOINT)
            with urllib.request.urlopen(req, timeout=3) as r:
                if r.status == 200:
                    print("[forwarder] Backend prêt.")
                    return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError(f"Backend inaccessible après {max_wait}s")


def send_bulk(logs: list[dict]) -> dict:
    """Envoie un lot de logs au backend via /api/v1/logs/ingest/bulk."""
    payload = json.dumps(logs).encode("utf-8")
    req = urllib.request.Request(
        BULK_ENDPOINT,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": INGEST_API_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            result = json.loads(r.read())
            return result
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"[forwarder] HTTP {e.code} sur bulk: {body[:200]}")
        return {"total_inserted": 0, "total_failed": len(logs)}


def read_new_lines(log_path: Path) -> list[str]:
    """Lit les nouvelles lignes d'un fichier depuis la dernière position connue."""
    pos = _file_positions.get(str(log_path), 0)
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(pos)
            lines = f.readlines()
            _file_positions[str(log_path)] = f.tell()
        return [l.rstrip("\n") for l in lines if l.strip()]
    except Exception as exc:
        print(f"[forwarder] Erreur lecture {log_path}: {exc}")
        return []


def collect_from_directory(log_dir: Path) -> list[str]:
    """Collecte toutes les nouvelles lignes de tous les fichiers .log du répertoire."""
    lines = []
    for log_file in sorted(log_dir.glob("*.log")):
        new_lines = read_new_lines(log_file)
        if new_lines:
            print(f"[forwarder] {log_file.name}: +{len(new_lines)} lignes")
        lines.extend(new_lines)
    return lines


def lines_to_payloads(lines: list[str]) -> list[dict]:
    """Convertit des lignes brutes en payloads d'ingestion (format syslog)."""
    return [{"raw_message": line, "source": "syslog"} for line in lines if line.strip()]


def run() -> None:
    log_dir = Path(LOG_DIR)
    if not log_dir.exists():
        print(f"[forwarder] Création du répertoire de logs : {log_dir}")
        log_dir.mkdir(parents=True, exist_ok=True)

    wait_for_backend()
    print(f"[forwarder] Surveillance de {log_dir} — intervalle {POLL_INTERVAL}s")

    total_sent = 0
    while True:
        lines = collect_from_directory(log_dir)
        payloads = lines_to_payloads(lines)

        # Envoi par lots
        for i in range(0, len(payloads), BATCH_SIZE):
            batch = payloads[i : i + BATCH_SIZE]
            result = send_bulk(batch)
            inserted = result.get("total_inserted", 0)
            failed   = result.get("total_failed", 0)
            total_sent += inserted
            if inserted or failed:
                print(f"[forwarder] Lot envoyé : {inserted} OK, {failed} erreurs — total cumulé : {total_sent}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
