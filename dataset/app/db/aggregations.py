"""
Agrégations Elasticsearch pour le dashboard Smart SIEM.
Module DATA — Semaine 2.

Importable par le Backend :
    from app.db.aggregations import count_by_severity, top_source_ips
"""

import os
from pathlib import Path

from dotenv import load_dotenv

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(_BASE_DIR / ".env")

from app.db.elasticsearch_client import get_client  # noqa: E402

INDEX = os.getenv("ES_INDEX", "logs-siem")


def _date_query(date_from=None, date_to=None):
    """Construit la query de filtre temporel. Retourne match_all si aucune borne."""
    if not date_from and not date_to:
        return {"match_all": {}}
    range_clause = {}
    if date_from:
        range_clause["gte"] = date_from
    if date_to:
        range_clause["lte"] = date_to
    return {"bool": {"filter": [{"range": {"timestamp": range_clause}}]}}


def count_by_severity(date_from=None, date_to=None):
    """
    Compte les logs par niveau de sévérité sur la période donnée.

    Utilise une terms aggregation sur le champ keyword `severity`.
    `size=0` évite de remonter des documents inutiles.

    Paramètres
    ----------
    date_from : str, optionnel — borne inférieure ISO 8601.
    date_to   : str, optionnel — borne supérieure ISO 8601.

    Retour
    ------
    dict : {"info": int, "warning": int, "critical": int}

    Exemple
    -------
    >>> count_by_severity()
    {"info": 580, "warning": 315, "critical": 105}

    >>> count_by_severity(date_from="2026-06-14T00:00:00Z", date_to="2026-06-15T23:59:59Z")
    {"info": 72, "warning": 41, "critical": 13}
    """
    client = get_client()
    response = client.search(
        index=INDEX,
        query=_date_query(date_from, date_to),
        size=0,
        aggs={"by_severity": {"terms": {"field": "severity", "size": 10}}},
    )
    buckets = {
        b["key"]: b["doc_count"]
        for b in response["aggregations"]["by_severity"]["buckets"]
    }
    return {
        "info": buckets.get("info", 0),
        "warning": buckets.get("warning", 0),
        "critical": buckets.get("critical", 0),
    }


def count_by_log_type(date_from=None, date_to=None):
    """
    Compte les logs par type sur la période donnée.

    Paramètres
    ----------
    date_from : str, optionnel.
    date_to   : str, optionnel.

    Retour
    ------
    dict : {"auth": int, "réseau": int, "système": int, "application": int}

    Exemple
    -------
    >>> count_by_log_type()
    {"auth": 236, "réseau": 243, "système": 275, "application": 246}
    """
    client = get_client()
    response = client.search(
        index=INDEX,
        query=_date_query(date_from, date_to),
        size=0,
        aggs={"by_type": {"terms": {"field": "log_type", "size": 10}}},
    )
    buckets = {
        b["key"]: b["doc_count"]
        for b in response["aggregations"]["by_type"]["buckets"]
    }
    return {
        "auth": buckets.get("auth", 0),
        "réseau": buckets.get("réseau", 0),
        "système": buckets.get("système", 0),
        "application": buckets.get("application", 0),
    }


def top_source_ips(n=10, date_from=None, date_to=None):
    """
    Retourne les N adresses IP sources les plus fréquentes.

    Utilise une terms aggregation sur le champ `source_ip` (type ip),
    triée par doc_count décroissant.

    Paramètres
    ----------
    n         : int — nombre d'IPs à retourner. Défaut : 10.
    date_from : str, optionnel.
    date_to   : str, optionnel.

    Retour
    ------
    list[dict] : [{"ip": str, "count": int}, ...] trié par count décroissant.

    Exemple
    -------
    >>> top_source_ips(n=3)
    [{"ip": "79.2.29.234", "count": 3}, {"ip": "10.89.72.118", "count": 1}, ...]
    """
    client = get_client()
    response = client.search(
        index=INDEX,
        query=_date_query(date_from, date_to),
        size=0,
        aggs={
            "top_ips": {
                "terms": {
                    "field": "source_ip",
                    "size": n,
                    "order": {"_count": "desc"},
                }
            }
        },
    )
    return [
        {"ip": b["key"], "count": b["doc_count"]}
        for b in response["aggregations"]["top_ips"]["buckets"]
    ]


def logs_per_hour(date_from=None, date_to=None):
    """
    Agrège le nombre de logs par heure (histogramme temporel).

    Utilise date_histogram avec `fixed_interval: 1h`.
    `min_doc_count: 1` exclut les heures sans activité du résultat.

    Paramètres
    ----------
    date_from : str, optionnel.
    date_to   : str, optionnel.

    Retour
    ------
    list[dict] : [{"hour": str (ISO 8601), "count": int}, ...] ordre chronologique.

    Exemple
    -------
    >>> logs_per_hour(date_from="2026-06-14T00:00:00Z", date_to="2026-06-14T23:59:59Z")
    [{"hour": "2026-06-14T00:00:00+0000", "count": 18}, ...]
    """
    client = get_client()
    response = client.search(
        index=INDEX,
        query=_date_query(date_from, date_to),
        size=0,
        aggs={
            "per_hour": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h",
                    "format": "yyyy-MM-dd'T'HH:mm:ssZ",
                    "min_doc_count": 1,
                }
            }
        },
    )
    return [
        {"hour": b["key_as_string"], "count": b["doc_count"]}
        for b in response["aggregations"]["per_hour"]["buckets"]
    ]
