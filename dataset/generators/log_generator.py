#!/usr/bin/env python3
"""
dataset/generators/log_generator.py

Générateur du dataset de test "30 jours + 3 attaques cachées" exigé par le
cahier des charges V3 (section UEBA / bootstrapping de la baseline).

Produit 30 jours de trafic syslog "normal" (bruit de fond réaliste sur
plusieurs hôtes) et y injecte 3 scénarios d'attaque réels et détectables :

  1. Brute-force SSH       — rafale d'échecs d'authentification depuis une
                              IP externe contre un hôte, en quelques minutes.
  2. Mouvement latéral      — un compte compromis s'authentifie avec succès
                              sur plusieurs hôtes internes en séquence rapide.
  3. Exfiltration lente     — volume de transfert sortant croissant sur les
                              derniers jours depuis un hôte compromis,
                              délibérément "low and slow" pour rester sous
                              les seuils de détection naïfs.

Usage :
    python3 log_generator.py                     # écrit dataset/exports/30day_dataset.jsonl
    python3 log_generator.py --ingest             # + envoie tout au backend via /api/v1/logs/ingest/bulk
    python3 log_generator.py --backend-url http://localhost:8000 --api-key <clé>

Ce script est un OUTIL DE TEST volontairement identifié comme tel : il ne
doit jamais être exécuté automatiquement par le backend en production, et
son usage est distinct des mocks d'interface (voir README, section
"Dataset 30 jours + attaques cachées").
"""

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration du dataset
# ---------------------------------------------------------------------------

DAYS = 30
BASELINE_HOSTS = ["web-srv-01", "db-srv-01", "file-srv-01", "app-srv-02", "auth-srv-01"]
INTERNAL_SUBNET = "10.0.4."
NORMAL_USERS = ["jdupont", "mmartin", "abernard", "svelasquez", "operator"]

random.seed(42)  # dataset reproductible


def _syslog_line(ts: datetime, host: str, process: str, pid: int, message: str) -> str:
    """Formate une ligne syslog RFC3164 minimale, compatible avec le parser existant."""
    ts_str = ts.strftime("%b %d %H:%M:%S")
    return f"<34>{ts_str} {host} {process}[{pid}]: {message}"


def _emit(entries: list, ts: datetime, host: str, process: str, pid: int, message: str, scenario: str = "baseline"):
    entries.append({
        "raw_message": _syslog_line(ts, host, process, pid, message),
        "source": "syslog",
        "_scenario": scenario,       # métadonnée de traçabilité (retirée avant ingestion réelle)
        "_timestamp": ts.isoformat(),
    })


# ---------------------------------------------------------------------------
# 1. Bruit de fond (baseline comportementale sur 30 jours)
# ---------------------------------------------------------------------------

def generate_baseline(entries: list, start: datetime):
    for day in range(DAYS):
        day_start = start + timedelta(days=day)
        # ~40 événements normaux par jour, répartis aléatoirement sur les heures ouvrées
        for _ in range(40):
            hour = random.choices(
                population=range(24),
                weights=[1, 1, 1, 1, 1, 1, 2, 4, 6, 8, 8, 7, 6, 7, 8, 8, 7, 6, 4, 3, 2, 2, 1, 1],
            )[0]
            ts = day_start.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
            host = random.choice(BASELINE_HOSTS)
            user = random.choice(NORMAL_USERS)
            kind = random.choice(["login_ok", "logout", "file_access", "service_check"])
            if kind == "login_ok":
                _emit(entries, ts, host, "sshd", 1000, f"Accepted password for {user} from {INTERNAL_SUBNET}{random.randint(10,250)} port 22 ssh2")
            elif kind == "logout":
                _emit(entries, ts, host, "sshd", 1000, f"pam_unix(sshd:session): session closed for user {user}")
            elif kind == "file_access":
                _emit(entries, ts, host, "audit", 1001, f"user={user} action=read file=/data/reports/daily.csv result=success")
            else:
                _emit(entries, ts, host, "systemd", 1, "Started daily backup verification service.")


# ---------------------------------------------------------------------------
# 2. Attaque cachée #1 — Brute-force SSH
# ---------------------------------------------------------------------------

def inject_brute_force_ssh(entries: list, start: datetime):
    """Jour 12 : ~60 échecs d'authentification SSH depuis une IP externe en 3 minutes,
    puis un succès final (compromission)."""
    day = start + timedelta(days=12)
    attack_start = day.replace(hour=3, minute=10, second=0)
    attacker_ip = "203.0.113.77"
    target_host = "auth-srv-01"

    for i in range(60):
        ts = attack_start + timedelta(seconds=i * 3)
        _emit(
            entries, ts, target_host, "sshd", 2000,
            f"Failed password for root from {attacker_ip} port {40000 + i} ssh2",
            scenario="brute_force_ssh",
        )

    # Succès final : la compromission qui alimente le scénario de mouvement latéral
    success_ts = attack_start + timedelta(seconds=61 * 3)
    _emit(
        entries, success_ts, target_host, "sshd", 2000,
        f"Accepted password for root from {attacker_ip} port 40999 ssh2",
        scenario="brute_force_ssh",
    )
    return success_ts, target_host


# ---------------------------------------------------------------------------
# 3. Attaque cachée #2 — Mouvement latéral
# ---------------------------------------------------------------------------

def inject_lateral_movement(entries: list, compromise_ts: datetime, compromised_host: str):
    """Dans les 30 minutes suivant la compromission initiale, le compte 'root'
    s'authentifie avec succès sur 4 hôtes internes différents en séquence rapide."""
    targets = ["web-srv-01", "db-srv-01", "file-srv-01", "app-srv-02"]
    ts = compromise_ts
    for i, host in enumerate(targets):
        ts = ts + timedelta(minutes=random.randint(4, 8))
        _emit(
            entries, ts, host, "sshd", 3000 + i,
            f"Accepted publickey for root from {INTERNAL_SUBNET}{200 + i} port 22 ssh2",
            scenario="lateral_movement",
        )
        _emit(
            entries, ts + timedelta(seconds=5), host, "audit", 3001 + i,
            "user=root action=priv_escalation target=/etc/shadow result=success",
            scenario="lateral_movement",
        )


# ---------------------------------------------------------------------------
# 4. Attaque cachée #3 — Exfiltration lente (Nina Myers pattern)
# ---------------------------------------------------------------------------

def inject_slow_exfiltration(entries: list, start: datetime):
    """Sur les 5 derniers jours du dataset, volume de transfert sortant croissant
    depuis file-srv-01, délibérément fractionné pour rester sous des seuils naïfs."""
    host = "file-srv-01"
    base_day = start + timedelta(days=DAYS - 5)
    volume_mb = 40  # démarre discret, augmente chaque jour

    for day_offset in range(5):
        day = base_day + timedelta(days=day_offset)
        transfers_today = 3 + day_offset  # de plus en plus fractionné/fréquent
        for t in range(transfers_today):
            ts = day.replace(hour=random.randint(1, 4), minute=random.randint(0, 59), second=random.randint(0, 59))
            chunk_mb = volume_mb // transfers_today
            _emit(
                entries, ts, host, "netflow", 4000 + day_offset * 10 + t,
                f"Outbound transfer dest=198.51.100.23 port=443 bytes={chunk_mb * 1024 * 1024} proto=HTTPS user=svc-backup",
                scenario="slow_exfiltration",
            )
        volume_mb = int(volume_mb * 1.8)  # croissance progressive du volume total quotidien


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def build_dataset() -> list:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=DAYS)

    entries: list = []
    generate_baseline(entries, start)
    compromise_ts, compromised_host = inject_brute_force_ssh(entries, start)
    inject_lateral_movement(entries, compromise_ts, compromised_host)
    inject_slow_exfiltration(entries, start)

    entries.sort(key=lambda e: e["_timestamp"])
    return entries


def write_jsonl(entries: list, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def ingest_to_backend(entries: list, backend_url: str, api_key: str, batch_size: int = 200):
    import httpx

    payloads = [{"raw_message": e["raw_message"], "source": e["source"]} for e in entries]
    total_ok, total_fail = 0, 0

    with httpx.Client(timeout=30.0) as client:
        for i in range(0, len(payloads), batch_size):
            batch = payloads[i:i + batch_size]
            resp = client.post(
                f"{backend_url}/api/v1/logs/ingest/bulk",
                json=batch,
                headers={"X-API-Key": api_key},
            )
            if resp.status_code == 200:
                result = resp.json()
                total_ok += result.get("total_inserted", len(batch))
                total_fail += result.get("total_failed", 0)
            else:
                print(f"[ERREUR] batch {i}: HTTP {resp.status_code} — {resp.text[:200]}", file=sys.stderr)
                total_fail += len(batch)

    print(f"Ingestion terminée : {total_ok} logs indexés, {total_fail} échecs.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", default="dataset/exports/30day_dataset.jsonl", help="Fichier JSONL de sortie")
    parser.add_argument("--ingest", action="store_true", help="Envoie le dataset au backend via /api/v1/logs/ingest/bulk")
    parser.add_argument("--backend-url", default="http://localhost:8000")
    parser.add_argument("--api-key", default=None, help="Valeur de INGEST_API_KEY (sinon lue depuis l'env)")
    args = parser.parse_args()

    entries = build_dataset()

    scenario_counts = {}
    for e in entries:
        scenario_counts[e["_scenario"]] = scenario_counts.get(e["_scenario"], 0) + 1

    print(f"Dataset généré : {len(entries)} logs sur {DAYS} jours.")
    for scenario, count in scenario_counts.items():
        print(f"  - {scenario}: {count} log(s)")

    output_path = Path(args.output)
    write_jsonl(entries, output_path)
    print(f"Écrit dans {output_path}")

    if args.ingest:
        import os
        api_key = args.api_key or os.environ.get("INGEST_API_KEY")
        if not api_key:
            print("[ERREUR] --ingest requiert --api-key ou la variable d'environnement INGEST_API_KEY", file=sys.stderr)
            sys.exit(1)
        ingest_to_backend(entries, args.backend_url, api_key)


if __name__ == "__main__":
    main()
