#!/usr/bin/env python3
"""
Smart SIEM — Test de charge S2
===============================
Injecte N logs via les 3 sources, mesure le débit et la latence,
puis vérifie l'indexation dans Elasticsearch.

Usage :
  python3 scripts/seed/load_test.py --count 1000
  python3 scripts/seed/load_test.py --count 5000 --workers 10
  python3 scripts/seed/load_test.py --source syslog --count 2000
  python3 scripts/seed/load_test.py --source file   --count 500
  python3 scripts/seed/load_test.py --source all    --count 1000

Pas de dépendances externes — stdlib Python uniquement.
"""

import argparse
import json
import os
import random
import socket
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────────────────
BACKEND_URL    = os.getenv("BACKEND_URL",    "http://localhost:8000")
INGEST_API_KEY = os.getenv("INGEST_API_KEY", "dev-only-change-me")
SYSLOG_HOST    = os.getenv("SYSLOG_HOST",    "localhost")
SYSLOG_PORT    = int(os.getenv("SYSLOG_PORT", "5140"))
LOG_TEST_DIR   = Path(os.getenv("LOG_TEST_DIR", "infra/log_test"))
BATCH_SIZE     = int(os.getenv("BATCH_SIZE", "100"))
BULK_ENDPOINT  = f"{BACKEND_URL}/api/v1/logs/ingest/bulk"
ES_URL         = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ES_INDEX       = os.getenv("ES_LOGS_INDEX_NAME", "smart-siem-logs")

# ── Données de test réalistes ──────────────────────────────────────────────────
HOSTS = ["web-01", "web-02", "db-master", "auth-srv", "proxy-01", "vpn-gw", "bastion"]
IPS   = [f"192.168.{a}.{b}" for a in range(1, 5) for b in range(1, 50)]
USERS = ["root", "admin", "deploy", "svc-backup", "monitoring", "jenkins", "operator"]

SYSLOG_TEMPLATES = [
    "<34>{date} {host} sshd[{pid}]: Failed password for root from {ip} port {port} ssh2",
    "<34>{date} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2",
    "<34>{date} {host} sudo[{pid}]: {user} : command not allowed ; COMMAND=/bin/bash",
    "<30>{date} {host} sshd[{pid}]: Accepted publickey for {user} from {ip} port {port}",
    "<28>{date} {host} kernel: DROP IN=eth0 SRC={ip} DST=10.0.0.1 PROTO=TCP DPT=22",
    "<30>{date} {host} nginx[{pid}]: {ip} - - \"GET /admin HTTP/1.1\" 403 512",
    "<30>{date} {host} nginx[{pid}]: {ip} - - \"POST /login HTTP/1.1\" 401 128",
    "<28>{date} {host} kernel: Out of memory: Kill process {pid} (postgres)",
    "<30>{date} {host} systemd[1]: nginx.service start request repeated too quickly",
    "<30>{date} {host} app[{pid}]: authentication failure for user {user}@{ip}",
    "<34>{date} {host} sshd[{pid}]: Invalid user admin from {ip} port {port}",
    "<28>{date} {host} auditd: USER_AUTH pid={pid} uid=0 subj=unconfined_u auid=0 res=failed",
]


def _rnd_syslog() -> str:
    t = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 3600))
    return random.choice(SYSLOG_TEMPLATES).format(
        date=t.strftime("%b %d %H:%M:%S"),
        host=random.choice(HOSTS),
        ip=random.choice(IPS),
        port=random.randint(1024, 65535),
        pid=random.randint(100, 99999),
        user=random.choice(USERS),
    )


def _rnd_json_log() -> dict:
    t = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 3600))
    return {
        "timestamp":   t.isoformat(),
        "source_ip":   random.choice(IPS),
        "host":        random.choice(HOSTS),
        "log_type":    random.choice(["auth", "network", "system", "application"]),
        "severity":    random.choices(["info", "warning", "critical"], weights=[6, 3, 1])[0],
        "raw_message": _rnd_syslog(),
        "tags":        [],
    }


# ── Source 1 : API bulk directe ────────────────────────────────────────────────

def _post_bulk(payloads: list[dict]) -> tuple[int, int, float]:
    """Envoie un lot, retourne (ok, err, latence_ms)."""
    data = json.dumps(payloads).encode("utf-8")
    req = urllib.request.Request(
        BULK_ENDPOINT, data=data, method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": INGEST_API_KEY},
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            result = json.loads(r.read())
        elapsed = (time.perf_counter() - t0) * 1000
        return result.get("total_inserted", 0), result.get("total_failed", 0), elapsed
    except urllib.error.HTTPError as exc:
        elapsed = (time.perf_counter() - t0) * 1000
        body = exc.read().decode("utf-8", errors="replace")[:200]
        print(f"  ✗ HTTP {exc.code}: {body}")
        return 0, len(payloads), elapsed
    except Exception as exc:
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"  ✗ {exc}")
        return 0, len(payloads), elapsed


def load_test_api(count: int, workers: int = 1, source: str = "syslog") -> dict:
    """Source 1 (JSON API) et Source 2 (syslog via API bulk)."""
    print(f"\n{'='*60}")
    print(f"[load-test] Source API bulk — {count} logs, {workers} worker(s), format={source}")
    print(f"{'='*60}")

    if source == "json":
        payloads = [{"raw_message": json.dumps(_rnd_json_log()), "source": "rest"} for _ in range(count)]
    else:
        payloads = [{"raw_message": _rnd_syslog(), "source": "syslog"} for _ in range(count)]

    batches = [payloads[i:i + BATCH_SIZE] for i in range(0, len(payloads), BATCH_SIZE)]
    latencies: list[float] = []
    total_ok = total_err = 0
    t_start = time.perf_counter()

    if workers <= 1:
        for i, batch in enumerate(batches):
            ok, err, lat = _post_bulk(batch)
            total_ok  += ok
            total_err += err
            latencies.append(lat)
            print(f"  lot {i+1:03d}/{len(batches)}: {ok:4d} OK, {err:3d} err — {lat:.0f} ms")
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_post_bulk, b): b for b in batches}
            for i, fut in enumerate(as_completed(futures)):
                ok, err, lat = fut.result()
                total_ok  += ok
                total_err += err
                latencies.append(lat)
                print(f"  lot {i+1:03d}/{len(batches)}: {ok:4d} OK, {err:3d} err — {lat:.0f} ms")

    elapsed = time.perf_counter() - t_start
    return _summary("api", count, total_ok, total_err, elapsed, latencies)


# ── Source 2 : Syslog UDP ──────────────────────────────────────────────────────

def load_test_syslog_udp(count: int) -> dict:
    """Envoie des messages syslog bruts via UDP au syslog-receiver."""
    print(f"\n{'='*60}")
    print(f"[load-test] Source Syslog UDP — {count} messages → {SYSLOG_HOST}:{SYSLOG_PORT}")
    print(f"{'='*60}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    errors = 0
    t_start = time.perf_counter()

    for i in range(count):
        msg = _rnd_syslog().encode("utf-8")
        try:
            sock.sendto(msg, (SYSLOG_HOST, SYSLOG_PORT))
            sent += 1
        except Exception as exc:
            errors += 1
            if errors <= 3:
                print(f"  ✗ UDP sendto: {exc}")

    sock.close()
    elapsed = time.perf_counter() - t_start
    throughput = sent / elapsed if elapsed > 0 else 0
    print(f"  Envoyé: {sent} datagrams UDP en {elapsed:.2f}s ({throughput:.0f} msg/s)")
    print(f"  Erreurs: {errors}")
    print(f"  Note: l'indexation dans ES se fait avec le délai de flush du receiver ({2}s)")
    return {
        "source": "syslog-udp", "total_sent": count, "ok": sent, "errors": errors,
        "elapsed_s": round(elapsed, 2), "throughput_per_s": round(throughput, 1),
    }


# ── Source 3 : File (forwarder) ────────────────────────────────────────────────

def load_test_file(count: int) -> dict:
    """Écrit des logs dans infra/log_test/ pour que le forwarder les ingère."""
    print(f"\n{'='*60}")
    print(f"[load-test] Source Fichier — {count} lignes → {LOG_TEST_DIR}")
    print(f"{'='*60}")

    LOG_TEST_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_TEST_DIR / "load_test.log"

    t_start = time.perf_counter()
    with log_file.open("a", encoding="utf-8") as f:
        for _ in range(count):
            f.write(_rnd_syslog() + "\n")
    elapsed = time.perf_counter() - t_start

    print(f"  {count} lignes écrites dans {log_file} en {elapsed:.2f}s")
    print(f"  Débit écriture: {count/elapsed:.0f} lignes/s")
    print(f"  Le forwarder ingérera ces logs dans les prochaines secondes (POLL_INTERVAL=2s).")
    return {
        "source": "file", "total_written": count, "elapsed_s": round(elapsed, 2),
        "write_rate_per_s": round(count / elapsed, 1), "file": str(log_file),
    }


# ── ES count vérification ──────────────────────────────────────────────────────

def _count_es_docs(before: int) -> int:
    """Retourne le nombre de documents dans l'index ES."""
    url = f"{ES_URL}/{ES_INDEX}/_count"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        return data.get("count", 0)
    except Exception as exc:
        print(f"  [ES count] Erreur: {exc}")
        return before


# ── Résumé ─────────────────────────────────────────────────────────────────────

def _summary(source: str, count: int, ok: int, err: int, elapsed: float, latencies: list[float]) -> dict:
    throughput = ok / elapsed if elapsed > 0 else 0
    lat_avg = statistics.mean(latencies) if latencies else 0
    lat_p95 = sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0
    lat_max = max(latencies) if latencies else 0

    print(f"\n── Résultats ({source}) ──")
    print(f"  Total logs :   {count}")
    print(f"  Indexés    :   {ok}")
    print(f"  Erreurs    :   {err}")
    print(f"  Durée      :   {elapsed:.2f}s")
    print(f"  Débit      :   {throughput:.1f} logs/s")
    print(f"  Latence avg:   {lat_avg:.0f} ms")
    print(f"  Latence p95:   {lat_p95:.0f} ms")
    print(f"  Latence max:   {lat_max:.0f} ms")

    return {
        "source": source, "total": count, "ok": ok, "errors": err,
        "elapsed_s": round(elapsed, 2), "throughput_per_s": round(throughput, 1),
        "latency_avg_ms": round(lat_avg, 1), "latency_p95_ms": round(lat_p95, 1),
        "latency_max_ms": round(lat_max, 1),
    }


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Smart SIEM — Test de charge S2")
    parser.add_argument("--count",   type=int, default=1000,  help="Nombre de logs à injecter")
    parser.add_argument("--workers", type=int, default=1,     help="Threads parallèles pour l'API bulk")
    parser.add_argument("--source",  choices=["api", "syslog", "file", "all"], default="api",
                        help="Source d'injection (défaut: api)")
    parser.add_argument("--url",     type=str, default=None,  help="URL backend")
    parser.add_argument("--format",  choices=["syslog", "json"], default="syslog",
                        help="Format des logs API (défaut: syslog)")
    args = parser.parse_args()

    global BACKEND_URL, BULK_ENDPOINT
    if args.url:
        BACKEND_URL  = args.url
        BULK_ENDPOINT = f"{BACKEND_URL}/api/v1/logs/ingest/bulk"

    print(f"\n{'='*60}")
    print(f"  Smart SIEM — Test de charge S2")
    print(f"  Backend : {BACKEND_URL}")
    print(f"  Source  : {args.source}  |  Count : {args.count}  |  Workers : {args.workers}")
    print(f"  Date    : {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}")

    es_before = _count_es_docs(0)
    print(f"\n[ES] Documents avant test : {es_before}")

    results = []

    if args.source in ("api", "all"):
        r = load_test_api(args.count, workers=args.workers, source=args.format)
        results.append(r)

    if args.source in ("syslog", "all"):
        r = load_test_syslog_udp(args.count)
        results.append(r)

    if args.source in ("file", "all"):
        r = load_test_file(args.count)
        results.append(r)

    if args.source in ("syslog", "file", "all"):
        print(f"\n[ES] Attente de {5}s pour flush du receiver/forwarder...")
        time.sleep(5)

    es_after = _count_es_docs(es_before)
    delta = es_after - es_before
    print(f"\n[ES] Documents après test  : {es_after}")
    print(f"[ES] Delta (nouveaux docs) : {delta}")

    print(f"\n{'='*60}")
    print("  SYNTHÈSE FINALE")
    print(f"{'='*60}")
    for r in results:
        src = r.get("source", "?")
        ok  = r.get("ok",           r.get("total_written", r.get("total_sent", "?")))
        thr = r.get("throughput_per_s", r.get("write_rate_per_s", "n/a"))
        print(f"  {src:15s} : {ok} logs, {thr} /s")
    print(f"  ES indexés totaux  : +{delta}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
