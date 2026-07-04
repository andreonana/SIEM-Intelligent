"""
Requêtes Elasticsearch — Moteur de recherche multi-critères et timeline horodatée.
Module DATA Smart SIEM — Semaine 2.

Importable par le Backend :
    from app.db.search import search_logs, get_timeline
"""

import os
from pathlib import Path

from dotenv import load_dotenv

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(_BASE_DIR / ".env")

from app.db.elasticsearch_client import get_client  # noqa: E402

INDEX = os.getenv("ES_INDEX", "logs-siem")


def search_logs(
    source_ip=None,
    host=None,
    log_type=None,
    severity=None,
    date_from=None,
    date_to=None,
    keyword=None,
    page=1,
    page_size=50,
):
    """
    Recherche multi-critères dans l'index logs-siem.

    Tous les paramètres sont optionnels. Plusieurs paramètres combinés
    produisent un filtre cumulatif (AND). Sans paramètre, retourne tous les logs.

    Paramètres
    ----------
    source_ip : str, optionnel
        IP exacte (ex: "1.2.3.4") ou notation CIDR (ex: "10.0.0.0/8").
        Le type 'ip' d'Elasticsearch supporte CIDR nativement via term query.
    host : str, optionnel
        Nom de la machine (correspondance exacte, keyword field).
    log_type : str, optionnel
        Type de log : auth | réseau | système | application.
    severity : str, optionnel
        Niveau de sévérité : info | warning | critical.
    date_from : str, optionnel
        Borne inférieure de la plage temporelle (ISO 8601, ex: "2026-06-14T00:00:00Z").
    date_to : str, optionnel
        Borne supérieure de la plage temporelle (ISO 8601).
    keyword : str, optionnel
        Mot ou phrase recherché(e) dans raw_message (full-text, analysé).
        Placé dans `must` car le match analyzer est incompatible avec `filter`.
    page : int
        Numéro de page (commence à 1). Défaut : 1.
    page_size : int
        Nombre de résultats par page. Défaut : 50.

    Retour
    ------
    dict
        {
            "total": int,       — nombre total de résultats (toutes pages)
            "page": int,        — page actuelle
            "page_size": int,   — taille de page appliquée
            "results": list     — documents de la page courante
        }

    Exemple
    -------
    >>> search_logs(severity="critical", page=1, page_size=10)
    {"total": 105, "page": 1, "page_size": 10, "results": [...]}

    >>> search_logs(source_ip="10.0.0.0/8", keyword="timeout")
    {"total": 2, "page": 1, "page_size": 50, "results": [...]}
    """
    client = get_client()

    filters = []
    must = []

    if source_ip:
        # Le type 'ip' ES accepte CIDR nativement (ex: "10.0.0.0/8")
        filters.append({"term": {"source_ip": source_ip}})
    if host:
        filters.append({"term": {"host": host}})
    if log_type:
        filters.append({"term": {"log_type": log_type}})
    if severity:
        filters.append({"term": {"severity": severity}})

    range_clause = {}
    if date_from:
        range_clause["gte"] = date_from
    if date_to:
        range_clause["lte"] = date_to
    if range_clause:
        filters.append({"range": {"timestamp": range_clause}})

    if keyword:
        must.append({"match": {"raw_message": keyword}})

    if filters or must:
        bool_body = {}
        if filters:
            bool_body["filter"] = filters
        if must:
            bool_body["must"] = must
        query = {"bool": bool_body}
    else:
        query = {"match_all": {}}

    from_ = (page - 1) * page_size

    response = client.search(
        index=INDEX,
        query=query,
        sort=[{"timestamp": {"order": "desc"}}],
        from_=from_,
        size=page_size,
    )

    return {
        "total": response["hits"]["total"]["value"],
        "page": page,
        "page_size": page_size,
        "results": [hit["_source"] for hit in response["hits"]["hits"]],
    }


def get_timeline(
    source_ip=None,
    host=None,
    date_from=None,
    date_to=None,
    log_types=None,
    max_events=500,
):
    """
    Retourne les événements triés chronologiquement pour construire une timeline.

    Tous les paramètres sont optionnels. La timeline est triée par timestamp
    croissant (plus ancien en premier) pour refléter l'ordre réel des événements.

    Paramètres
    ----------
    source_ip : str, optionnel
        IP exacte ou CIDR.
    host : str, optionnel
        Nom de la machine.
    date_from : str, optionnel
        Début de la fenêtre temporelle (ISO 8601).
    date_to : str, optionnel
        Fin de la fenêtre temporelle (ISO 8601).
    log_types : list[str], optionnel
        Liste de types (ex: ["auth", "réseau"]) — terms query, OR entre les valeurs.
    max_events : int
        Nombre maximum d'événements retournés. Défaut : 500.

    Retour
    ------
    dict
        {
            "total": int,       — total de correspondances (peut dépasser max_events)
            "date_from": str,   — borne utilisée (None si non fournie)
            "date_to": str,     — borne utilisée (None si non fournie)
            "events": list      — événements triés chronologiquement,
                                  champs : timestamp, source_ip, host,
                                           log_type, severity, raw_message
        }

    Exemple
    -------
    >>> get_timeline(log_types=["auth"], max_events=100)
    {"total": 236, "date_from": None, "date_to": None, "events": [...]}
    """
    client = get_client()

    filters = []

    if source_ip:
        filters.append({"term": {"source_ip": source_ip}})
    if host:
        filters.append({"term": {"host": host}})
    if log_types:
        # terms query : OR entre les valeurs de la liste
        filters.append({"terms": {"log_type": log_types}})

    range_clause = {}
    if date_from:
        range_clause["gte"] = date_from
    if date_to:
        range_clause["lte"] = date_to
    if range_clause:
        filters.append({"range": {"timestamp": range_clause}})

    query = {"bool": {"filter": filters}} if filters else {"match_all": {}}

    response = client.search(
        index=INDEX,
        query=query,
        sort=[{"timestamp": {"order": "asc"}}],
        size=max_events,
        source=["timestamp", "source_ip", "host", "log_type", "severity", "raw_message"],
    )

    return {
        "total": response["hits"]["total"]["value"],
        "date_from": date_from,
        "date_to": date_to,
        "events": [hit["_source"] for hit in response["hits"]["hits"]],
    }
