#!/usr/bin/env python3
"""
Smart SIEM — Injection de logs de test S1
==========================================
Génère des logs réalistes et les injecte directement dans le backend via l'API bulk.

Usage :
    python3 scripts/seed/inject_logs.py --count 100
    python3 scripts/seed/inject_logs.py --count 1000 --url http://localhost:8000
    python3 scripts/seed/inject_logs.py --syslog   # écrit dans infra/log_test/ (pour le forwarder)

Ce script ne nécessite pas de dépendance externe (stdlib Python uniquement).
"""

import argparse
import json
import os
import random
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────
BACKEND_URL    = os.getenv("BACKEND_URL",    "http://localhost:8000")
INGEST_API_KEY = os.getenv("INGEST_API_KEY", "dev-only-change-me")
BULK_ENDPOINT  = f"{BACKEND_URL}/api/v1/logs/ingest/bulk"
BATCH_SIZE     = 50

# ── Templates de logs réalistes ───────────────────────────────────────────────
HOSTS = ["web-srv-01", "web-srv-02", "db-master", "auth-srv", "proxy-01", "vpn-gw"]
IPS   = [f"192.168.1.{i}" for i in range(10, 100)] + [f"10.0.0.{i}" for i in range(1, 50)]

SYSLOG_TEMPLATES = [
    # Auth — critique
    "<34>{date} {host} sshd[{pid}]: Failed password for root from {ip} port {port} ssh2",
    "<34>{date} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2",
    "<34>{date} {host} sshd[{pid}]: Invalid user admin from {ip} port {port}",
    "<34>{date} {host} sudo[{pid}]: {user} : command not allowed ; COMMAND=/bin/bash",
    # Auth — info
    "<30>{date} {host} sshd[{pid}]: Accepted publickey for {user} from {ip} port {port}",
    "<30>{date} {host} sshd[{pid}]: session opened for user {user} by (uid=0)",
    # Réseau
    "<28>{date} {host} kernel: DROP IN=eth0 SRC={ip} DST=10.0.0.1 PROTO=TCP DPT=22",
    "<30>{date} {host} nginx[{pid}]: {ip} - - \"GET /admin HTTP/1.1\" 403 512",
    "<30>{date} {host} nginx[{pid}]: {ip} - - \"POST /login HTTP/1.1\" 401 128",
    # Système
    "<28>{date} {host} kernel: Out of memory: Kill process {pid} (postgres)",
    "<30>{date} {host} systemd[1]: nginx.service start request repeated too quickly",
    # Application
    "<30>{date} {host} app[{pid}]: authentication failure for user {user}@{ip}",
    "<30>{date} {host} app[{pid}]: Database query timeout after 30s",
]

USERS = ["root", "admin", "deploy", "svc-backup", "monitoring", "jenkins"]


def _random_date(base: datetime) -> str:
    offset = timedelta(hours=random.uniform(0, 168))
    dt = base - offset
    return dt.strftime("%b %d %H:%M:%S")


def generate_syslog_line(base_time: datetime) -> str:
    template = random.choice(SYSLOG_TEMPLATES)
    return template.format(
        date=_random_date(base_time),
        host=random.choice(HOSTS),
        ip=random.choice(IPS),
        port=random.randint(1024, 65535),
        pid=random.randint(100, 99999),
        user=random.choice(USERS),
    )


def generate_json_log(base_time: datetime) -> dict:
    offset = timedelta(hours=random.uniform(0, 168))
    ts = base_time - offset
    log_types = ["auth", "réseau", "système", "application"]
    log_type = random.choice(log_types)
    severities = random.choices(["info", "warning", "critical"], weights=[0.6, 0.3, 0.1])[0]
    messages = {
        "auth":        f"authentication failure; user={random.choice(USERS)} from={random.choice(IPS)}",
        "réseau":      f"DROP SRC={random.choice(IPS)} PROTO=TCP DPT={random.choice([22, 80, 443, 3306])}",
        "système":     f"kernel: EXT4-fs error on device sda1",
        "application": f"Unhandled exception in worker {random.randint(100,999)}: NullPointerException",
    }
    return {
        "timestamp": ts.isoformat(),
        "source_ip": random.choice(IPS),
        "host":      random.choice(HOSTS),
        "log_type":  log_type,
        "severity":  severities,
        "raw_message": messages[log_type],
        "tags":      [],
    }


def send_bulk(payloads: list[dict]) -> dict:
    data = json.dumps(payloads).encode("utf-8")
    req = urllib.request.Request(
        BULK_ENDPOINT,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key":    INGEST_API_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"  ✗ HTTP {e.code}: {body[:300]}")
        return {"total_inserted": 0, "total_failed": len(payloads)}
    except Exception as exc:
        print(f"  ✗ Erreur réseau: {exc}")
        return {"total_inserted": 0, "total_failed": len(payloads)}


def inject_via_api(count: int, mode: str = "syslog") -> None:
    """Injecte count logs via l'endpoint bulk du backend."""
    base_time = datetime.now(timezone.utc)
    total_ok = total_err = 0

    print(f"[inject] Injection de {count} logs ({mode}) → {BULK_ENDPOINT}")

    all_payloads = []
    for _ in range(count):
        if mode == "json":
            log = generate_json_log(base_time)
            # Pour l'endpoint bulk, on a besoin du format RawLogIngest
            # On sérialise le JSON en raw_message pour le syslog parser
            # OU on utilise l'endpoint /ingest/json — ici on utilise bulk avec source=rest
            payload = {"raw_message": json.dumps(log), "source": "rest"}
        else:
            payload = {"raw_message": generate_syslog_line(base_time), "source": "syslog"}
        all_payloads.append(payload)

    for i in range(0, count, BATCH_SIZE):
        batch = all_payloads[i : i + BATCH_SIZE]
        result = send_bulk(batch)
        ok  = result.get("total_inserted", 0)
        err = result.get("total_failed", 0)
        total_ok  += ok
        total_err += err
        print(f"  Lot {i//BATCH_SIZE + 1}: {ok} OK, {err} erreurs")

    print(f"\n[inject] Terminé : {total_ok} logs indexés, {total_err} erreurs")


def write_to_file(count: int, output_dir: Path) -> None:
    """Écrit les logs dans des fichiers .log surveillés par le forwarder."""
    output_dir.mkdir(parents=True, exist_ok=True)
    log_file = output_dir / "generated.log"
    base_time = datetime.now(timezone.utc)

    print(f"[inject] Écriture de {count} lignes syslog → {log_file}")
    with log_file.open("a", encoding="utf-8") as f:
        for _ in range(count):
            f.write(generate_syslog_line(base_time) + "\n")
    print(f"[inject] {count} lignes écrites. Le forwarder les ingérera automatiquement.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Smart SIEM — Injection de logs de test S1")
    parser.add_argument("--count",   type=int, default=100,                help="Nombre de logs à injecter")
    parser.add_argument("--url",     type=str, default=None,               help="URL backend (défaut: $BACKEND_URL)")
    parser.add_argument("--syslog",  action="store_true",                  help="Écrire dans infra/log_test/ (pour forwarder)")
    parser.add_argument("--json",    action="store_true",                  help="Format JSON natif (mode rest)")
    parser.add_argument("--dir",     type=str, default="infra/log_test",   help="Répertoire de logs (--syslog uniquement)")
    args = parser.parse_args()

    global BACKEND_URL, BULK_ENDPOINT
    if args.url:
        BACKEND_URL   = args.url
        BULK_ENDPOINT = f"{BACKEND_URL}/api/v1/logs/ingest/bulk"

    if args.syslog:
        write_to_file(args.count, Path(args.dir))
    else:
        mode = "json" if args.json else "syslog"
        inject_via_api(args.count, mode=mode)


if __name__ == "__main__":
    main()
