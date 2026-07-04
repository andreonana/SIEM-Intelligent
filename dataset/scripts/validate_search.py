#!/usr/bin/env python3
"""
Validation des requêtes Elasticsearch — Smart SIEM Module DATA Semaine 2.

Lance une série de requêtes sur les données réelles de l'index logs-siem
et génère un rapport : critère testé | nombre de résultats | temps | statut.

Échoue (exit code 1) si :
  - une assertion est fausse
  - une requête dépasse 3 secondes

Lancement : python scripts/validate_search.py
"""

import sys
import time
import ipaddress
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MAX_RESPONSE_TIME_S = 3.0

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

COL_LABEL = 54
COL_N     = 10
COL_TIME  = 9
COL_STATUS = 6


def ok(msg):  return f"{GREEN}{msg}{RESET}"
def err(msg): return f"{RED}{msg}{RESET}"
def warn(msg): return f"{YELLOW}{msg}{RESET}"


def run(fn, *args, **kwargs):
    """Exécute fn(*args, **kwargs), retourne (success, elapsed_s, result_or_error)."""
    start = time.perf_counter()
    try:
        result = fn(*args, **kwargs)
        return True, time.perf_counter() - start, result
    except Exception as exc:
        return False, time.perf_counter() - start, str(exc)


def n_results(result):
    if isinstance(result, dict) and "total" in result:
        return str(result["total"])
    if isinstance(result, list):
        return str(len(result))
    return "—"


def header():
    line = (
        f"{BOLD}{'Critère testé':<{COL_LABEL}}"
        f"{'Résultats':>{COL_N}}"
        f"{'Temps':>{COL_TIME}}"
        f"{'Statut':>{COL_STATUS}}{RESET}"
    )
    sep = "─" * (COL_LABEL + COL_N + COL_TIME + COL_STATUS + 3)
    print(line)
    print(sep)


def row(label, n, elapsed, status_ok, time_ok):
    time_str = f"{elapsed:.3f}s"
    if not time_ok:
        time_str = warn(time_str)
    status_str = ok("PASS") if (status_ok and time_ok) else err("FAIL")
    print(
        f"{label:<{COL_LABEL}}"
        f"{n:>{COL_N}}"
        f"{time_str:>{COL_TIME + 10}}"   # +10 pour les codes ANSI
        f"{status_str:>{COL_STATUS + 10}}"
    )


def check(label, fn, assertion, failures, slow, *args, **kwargs):
    success, elapsed, result = run(fn, *args, **kwargs)
    if not success:
        n = err("ERREUR")
        status_ok = False
    else:
        n = n_results(result)
        try:
            status_ok = bool(assertion(result))
        except Exception:
            status_ok = False

    time_ok = elapsed < MAX_RESPONSE_TIME_S
    row(label, n, elapsed, status_ok, time_ok)

    if not status_ok:
        failures.append(label)
    if not time_ok:
        slow.append(label)


def main():
    print(f"\n{BOLD}=== Validation Elasticsearch — Smart SIEM S2 ==={RESET}\n")

    # Vérification de la connexion
    try:
        from app.db.elasticsearch_client import get_client
        client = get_client()
        if not client.ping():
            print(err("✗ Elasticsearch non disponible sur localhost:9200"))
            sys.exit(1)
        print(ok("✓ Elasticsearch connecté\n"))
    except Exception as e:
        print(err(f"✗ Connexion impossible : {e}"))
        sys.exit(1)

    from app.db.search import search_logs, get_timeline
    from app.db.aggregations import (
        count_by_severity,
        count_by_log_type,
        top_source_ips,
        logs_per_hour,
    )

    failures = []
    slow = []

    header()

    # ── search_logs ───────────────────────────────────────────────────────────

    check(
        "Sans filtre — tous les logs",
        search_logs, lambda r: r["total"] >= 1000,
        failures, slow,
        page_size=1,
    )
    check(
        "Filtre severity=critical",
        search_logs,
        lambda r: r["total"] > 0 and all(d["severity"] == "critical" for d in r["results"]),
        failures, slow,
        severity="critical", page_size=50,
    )
    check(
        "Filtre severity=warning",
        search_logs,
        lambda r: r["total"] > 0 and all(d["severity"] == "warning" for d in r["results"]),
        failures, slow,
        severity="warning", page_size=50,
    )
    check(
        "Filtre log_type=auth",
        search_logs,
        lambda r: r["total"] > 0 and all(d["log_type"] == "auth" for d in r["results"]),
        failures, slow,
        log_type="auth", page_size=50,
    )
    check(
        "Filtre log_type=réseau",
        search_logs,
        lambda r: r["total"] > 0 and all(d["log_type"] == "réseau" for d in r["results"]),
        failures, slow,
        log_type="réseau", page_size=50,
    )
    check(
        "Filtre log_type=système",
        search_logs,
        lambda r: r["total"] > 0 and all(d["log_type"] == "système" for d in r["results"]),
        failures, slow,
        log_type="système", page_size=50,
    )
    check(
        "Filtre host=db-master",
        search_logs,
        lambda r: r["total"] > 0 and all(d["host"] == "db-master" for d in r["results"]),
        failures, slow,
        host="db-master", page_size=50,
    )
    check(
        "IP exacte 10.89.72.118",
        search_logs,
        lambda r: all(d["source_ip"] == "10.89.72.118" for d in r["results"]),
        failures, slow,
        source_ip="10.89.72.118",
    )
    check(
        "CIDR 10.0.0.0/8 → 5 résultats",
        search_logs,
        lambda r: r["total"] == 5 and all(
            ipaddress.ip_address(d["source_ip"]) in ipaddress.ip_network("10.0.0.0/8")
            for d in r["results"]
        ),
        failures, slow,
        source_ip="10.0.0.0/8", page_size=100,
    )
    check(
        "Plage 14–15 juin 2026",
        search_logs,
        lambda r: r["total"] > 0,
        failures, slow,
        date_from="2026-06-14T00:00:00Z", date_to="2026-06-15T23:59:59Z", page_size=1,
    )
    check(
        "Plage future → 0 résultat",
        search_logs,
        lambda r: r["total"] == 0,
        failures, slow,
        date_from="2030-01-01T00:00:00Z", date_to="2030-12-31T23:59:59Z",
    )
    check(
        "Keyword 'timeout'",
        search_logs,
        lambda r: r["total"] > 0 and all("timeout" in d["raw_message"].lower() for d in r["results"]),
        failures, slow,
        keyword="timeout", page_size=50,
    )
    check(
        "Keyword 'connection'",
        search_logs,
        lambda r: r["total"] > 0 and all("connection" in d["raw_message"].lower() for d in r["results"]),
        failures, slow,
        keyword="connection", page_size=50,
    )
    check(
        "Combiné severity=critical + log_type=auth",
        search_logs,
        lambda r: all(
            d["severity"] == "critical" and d["log_type"] == "auth"
            for d in r["results"]
        ),
        failures, slow,
        severity="critical", log_type="auth", page_size=50,
    )
    check(
        "Pagination — page 1 ≠ page 2",
        lambda: (search_logs(page=1, page_size=10), search_logs(page=2, page_size=10)),
        lambda r: r[0]["total"] == r[1]["total"] and r[0]["results"] != r[1]["results"],
        failures, slow,
    )
    check(
        "Tri — timestamp décroissant",
        search_logs,
        lambda r: [d["timestamp"] for d in r["results"]] == sorted(
            [d["timestamp"] for d in r["results"]], reverse=True
        ),
        failures, slow,
        page_size=20,
    )

    # ── get_timeline ──────────────────────────────────────────────────────────

    check(
        "Timeline — ordre chronologique",
        get_timeline,
        lambda r: r["total"] > 0 and r["events"] == sorted(r["events"], key=lambda e: e["timestamp"]),
        failures, slow,
        max_events=100,
    )
    check(
        "Timeline — filtre host=db-master",
        get_timeline,
        lambda r: r["total"] > 0 and all(e["host"] == "db-master" for e in r["events"]),
        failures, slow,
        host="db-master", max_events=200,
    )
    check(
        "Timeline — log_types=['auth']",
        get_timeline,
        lambda r: r["total"] > 0 and all(e["log_type"] == "auth" for e in r["events"]),
        failures, slow,
        log_types=["auth"], max_events=300,
    )
    check(
        "Timeline — log_types=['auth','réseau']",
        get_timeline,
        lambda r: r["total"] > 0 and all(e["log_type"] in ("auth", "réseau") for e in r["events"]),
        failures, slow,
        log_types=["auth", "réseau"], max_events=500,
    )
    check(
        "Timeline — fenêtre 14–15 juin",
        get_timeline,
        lambda r: r["total"] > 0 and all(e["timestamp"] >= "2026-06-14" for e in r["events"]),
        failures, slow,
        date_from="2026-06-14T00:00:00Z", date_to="2026-06-15T23:59:59Z",
    )
    check(
        "Timeline — champs uniquement attendus",
        get_timeline,
        lambda r: all(
            set(e.keys()) == {"timestamp", "source_ip", "host", "log_type", "severity", "raw_message"}
            for e in r["events"]
        ),
        failures, slow,
        max_events=10,
    )

    # ── aggregations ──────────────────────────────────────────────────────────

    check(
        "Agrég. count_by_severity",
        count_by_severity,
        lambda r: set(r.keys()) == {"info", "warning", "critical"} and sum(r.values()) >= 1000,
        failures, slow,
    )
    check(
        "Agrég. count_by_log_type",
        count_by_log_type,
        lambda r: set(r.keys()) == {"auth", "réseau", "système", "application"} and sum(r.values()) >= 1000,
        failures, slow,
    )
    check(
        "Agrég. top_source_ips(n=10)",
        top_source_ips,
        lambda r: len(r) <= 10 and all("ip" in x and "count" in x for x in r),
        failures, slow,
        n=10,
    )
    check(
        "Agrég. logs_per_hour — 14 juin",
        logs_per_hour,
        lambda r: isinstance(r, list) and len(r) > 0 and all("hour" in x and "count" in x for x in r),
        failures, slow,
        date_from="2026-06-14T00:00:00Z", date_to="2026-06-14T23:59:59Z",
    )

    # ── Résumé ────────────────────────────────────────────────────────────────

    total = len(failures) + len(slow)
    print()

    if not total:
        print(ok(f"{BOLD}✓ Toutes les requêtes passent en moins de {MAX_RESPONSE_TIME_S}s{RESET}"))
        sys.exit(0)

    if failures:
        print(err(f"✗ Assertions échouées ({len(failures)}) :"))
        for f in failures:
            print(f"  · {f}")
    if slow:
        print(warn(f"⚠ Requêtes trop lentes (>{MAX_RESPONSE_TIME_S}s) ({len(slow)}) :"))
        for s in slow:
            print(f"  · {s}")

    sys.exit(1)


if __name__ == "__main__":
    main()
