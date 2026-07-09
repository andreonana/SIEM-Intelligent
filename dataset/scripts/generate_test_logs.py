"""
Génère des logs de test réalistes au format normalisé Smart SIEM et les sauvegarde
dans data/test_logs.json. Ce fichier simule ce que le pipeline Backend transmettrait.

Lancement : python dataset/scripts/generate_test_logs.py --count 1000
"""

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from faker import Faker

fake = Faker()

LOG_TYPES = ["auth", "réseau", "système", "application"]
SEVERITIES = ["info", "warning", "critical"]
SEVERITY_WEIGHTS = [0.60, 0.30, 0.10]

HOSTS = [
    "web-srv-01", "web-srv-02", "db-master", "db-replica",
    "auth-srv", "proxy-01", "monitor", "vpn-gw",
]

RAW_MESSAGES = {
    "auth": [
        "Failed password for {user} from {ip} port {port} ssh2",
        "Accepted publickey for {user} from {ip} port {port}",
        "Invalid user {user} from {ip}",
        "pam_unix(sshd:auth): authentication failure; user={user}",
    ],
    "réseau": [
        "Connection from {ip}:{port} to {dst}:{dport} ESTABLISHED",
        "DROP IN=eth0 OUT= SRC={ip} DST={dst} PROTO=TCP DPT={dport}",
        "New connection accepted from {ip}",
        "TLS handshake timeout from {ip}",
    ],
    "système": [
        "Out of memory: Kill process {pid} ({proc})",
        "kernel: EXT4-fs error on device sda1",
        "systemd: {proc}.service start request repeated too quickly",
        "CPU temperature above threshold: {temp}°C",
    ],
    "application": [
        'GET /api/v1/users HTTP/1.1 200 {size}ms from {ip}',
        'POST /login HTTP/1.1 401 from {ip} — invalid credentials',
        "Database query timeout after 30s: SELECT * FROM events",
        "Unhandled exception in worker {pid}: NullPointerException",
    ],
}

TAGS_BY_TYPE = {
    "auth":        [["ssh", "login"], ["ssh", "brute-force"], ["auth", "sudo"]],
    "réseau":      [["firewall", "drop"], ["tcp", "established"], ["tls", "error"]],
    "système":     [["kernel", "oom"], ["disk", "error"], ["cpu", "temp"]],
    "application": [["http", "api"], ["http", "auth"], ["db", "timeout"]],
}


def _render_message(template: str) -> str:
    return template.format(
        user=fake.user_name(),
        ip=fake.ipv4(),
        dst=fake.ipv4_private(),
        port=random.randint(1024, 65535),
        dport=random.choice([22, 80, 443, 3306, 5432, 6379]),
        pid=random.randint(100, 99999),
        proc=random.choice(["nginx", "postgres", "redis", "sshd", "systemd"]),
        temp=random.randint(80, 105),
        size=random.randint(10, 5000),
    )


def generate_log(base_time: datetime) -> dict:
    log_type = random.choice(LOG_TYPES)
    severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS)[0]
    offset_hours = random.uniform(0, 168)  # répartis sur 7 jours
    ts = base_time - timedelta(hours=offset_hours)

    template = random.choice(RAW_MESSAGES[log_type])
    tags = random.choice(TAGS_BY_TYPE[log_type])

    return {
        "timestamp": ts.isoformat(),
        "source_ip": fake.ipv4(),
        "host":      random.choice(HOSTS),
        "log_type":  log_type,
        "severity":  severity,
        "raw_message": _render_message(template),
        "tags":      tags,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Génère des logs de test Smart SIEM")
    parser.add_argument("--count", type=int, default=1000, help="Nombre de logs à générer")
    args = parser.parse_args()

    output_path = Path(__file__).resolve().parent.parent / "data" / "test_logs.json"
    output_path.parent.mkdir(exist_ok=True)

    base_time = datetime.now(timezone.utc)
    logs = [generate_log(base_time) for _ in range(args.count)]

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(logs, f, ensure_ascii=False, indent=2)

    print(f"✓ {args.count} logs générés → {output_path}")
    counts = {}
    for log in logs:
        counts[log["severity"]] = counts.get(log["severity"], 0) + 1
    for sev, n in sorted(counts.items()):
        print(f"  {sev:10s}: {n}")


if __name__ == "__main__":
    main()
