"""
Module de conformité RGPD/ISO — Smart SIEM Module DATA, Semaine 3.

Importable par le Backend :
    from app.reports.compliance import (
        verify_log_integrity,
        generate_retention_report,
        purge_expired_logs,
        generate_compliance_report,
    )
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(_BASE_DIR / ".env")
sys.path.insert(0, str(_BASE_DIR))

from app.db.elasticsearch_client import get_client

_INDEX       = os.getenv("ES_INDEX", "logs-siem")
_RET_DAYS    = int(os.getenv("RETENTION_DAYS", "30"))
_REPORTS_DIR = Path(os.getenv("REPORTS_DIR", str(_BASE_DIR / "reports")))
_ILM_POLICY  = os.getenv("ILM_POLICY", "siem-logs-policy")

_PAGE_SIZE = 1000   # taille de page pour les requêtes scroll-like


def _utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scroll_all_source_docs(date_from, date_to):
    """
    Récupère les champs source de tous les logs sur la période via search_after.

    Utilise `_doc` comme tiebreaker (supporté nativement par ES sans fielddata)
    pour une pagination efficace. Le hash final est calculé sur les valeurs
    source triées en Python, ce qui le rend reproductible quelle que soit
    l'ordre de stockage interne d'Elasticsearch.
    """
    client = get_client()

    rc = {}
    if date_from:
        rc["gte"] = date_from
    if date_to:
        rc["lte"] = date_to
    query = (
        {"bool": {"filter": [{"range": {"timestamp": rc}}]}}
        if rc
        else {"match_all": {}}
    )

    _SOURCE_FIELDS = ["timestamp", "source_ip", "host", "log_type", "severity", "raw_message"]

    docs = []
    search_after = None

    while True:
        kwargs = dict(
            index=_INDEX,
            query=query,
            size=_PAGE_SIZE,
            # _doc : tiebreaker interne ES — ne nécessite pas de fielddata
            sort=[{"timestamp": {"order": "asc"}}, {"_doc": {"order": "asc"}}],
            source=_SOURCE_FIELDS,
        )
        if search_after:
            kwargs["search_after"] = search_after

        resp = client.search(**kwargs)
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for hit in hits:
            docs.append(hit["_source"])
        search_after = hits[-1]["sort"]

    return docs


# ── Fonctions publiques ───────────────────────────────────────────────────────

def verify_log_integrity(date_from, date_to):
    """
    Calcule le hash SHA-256 de tous les logs de la période.

    Les logs sont récupérés via search_after, triés par (timestamp, _id),
    puis concaténés sous la forme "id|timestamp\\n" avant hachage.
    Ce hash est reproductible : deux appels successifs sur la même période
    retournent le même résultat si les données n'ont pas changé.

    Paramètres
    ----------
    date_from : str — Borne inférieure ISO 8601 (ex: "2026-06-01T00:00:00Z").
    date_to   : str — Borne supérieure ISO 8601 (ex: "2026-06-30T23:59:59Z").

    Retour
    ------
    dict :
        {
            "period"     : {"from": str, "to": str},
            "log_count"  : int,
            "sha256"     : str,
            "verified_at": str   — horodatage ISO 8601 UTC
        }

    Exemple
    -------
    >>> r = verify_log_integrity("2026-06-01T00:00:00Z", "2026-06-30T23:59:59Z")
    >>> print(r["sha256"])
    a3f1…
    """
    docs = _scroll_all_source_docs(date_from, date_to)

    # Tri déterministe sur les champs source (indépendant de l'ordre ES interne)
    _SORT_KEY = ("timestamp", "source_ip", "host", "log_type", "severity", "raw_message")
    docs.sort(key=lambda d: tuple(str(d.get(f, "") or "") for f in _SORT_KEY))

    # Sérialisation reproductible : une ligne JSON par document, trié
    payload = "\n".join(
        json.dumps({f: d.get(f, "") for f in _SORT_KEY}, sort_keys=True, ensure_ascii=False)
        for d in docs
    ).encode("utf-8")
    sha256  = hashlib.sha256(payload).hexdigest()

    return {
        "period":      {"from": date_from, "to": date_to},
        "log_count":   len(docs),
        "sha256":      sha256,
        "verified_at": _utcnow(),
    }


def generate_retention_report():
    """
    Retourne les informations sur la politique de rétention active.

    Interroge l'index pour trouver le log le plus ancien et le plus récent,
    puis consulte l'ILM Elasticsearch si disponible.

    Retour
    ------
    dict :
        {
            "retention_days": int,
            "oldest_log"    : str (timestamp ISO 8601 ou None),
            "newest_log"    : str (timestamp ISO 8601 ou None),
            "total_logs"    : int,
            "ilm_policy"    : str
        }

    Exemple
    -------
    >>> r = generate_retention_report()
    >>> print(r["oldest_log"])
    2026-05-24T08:14:22.000Z
    """
    client = get_client()

    # Total
    count_resp = client.count(index=_INDEX)
    total = count_resp["count"]

    # Log le plus ancien
    oldest_resp = client.search(
        index=_INDEX,
        query={"match_all": {}},
        sort=[{"timestamp": {"order": "asc"}}],
        size=1,
        source=["timestamp"],
    )
    oldest = (
        oldest_resp["hits"]["hits"][0]["_source"].get("timestamp")
        if oldest_resp["hits"]["hits"]
        else None
    )

    # Log le plus récent
    newest_resp = client.search(
        index=_INDEX,
        query={"match_all": {}},
        sort=[{"timestamp": {"order": "desc"}}],
        size=1,
        source=["timestamp"],
    )
    newest = (
        newest_resp["hits"]["hits"][0]["_source"].get("timestamp")
        if newest_resp["hits"]["hits"]
        else None
    )

    # Politique ILM (best-effort)
    ilm_policy = _ILM_POLICY
    try:
        ilm = client.ilm.get_lifecycle(name=_ILM_POLICY)
        if ilm:
            ilm_policy = f"{_ILM_POLICY} (trouvée dans ILM)"
    except Exception:
        ilm_policy = f"{_ILM_POLICY} (non trouvée dans ILM — rétention appliquée manuellement)"

    return {
        "retention_days": _RET_DAYS,
        "oldest_log":     oldest,
        "newest_log":     newest,
        "total_logs":     total,
        "ilm_policy":     ilm_policy,
    }


def purge_expired_logs():
    """
    Supprime manuellement les logs plus anciens que RETENTION_DAYS.

    Complète l'ILM automatique dans les cas où elle n'est pas configurée
    ou pour une purge forcée à la demande.

    Utilise l'API delete_by_query d'Elasticsearch.

    Retour
    ------
    dict :
        {
            "deleted"    : int   — nombre de documents supprimés,
            "purged_at"  : str   — horodatage ISO 8601 UTC de la purge,
            "cutoff_date": str   — date limite appliquée (ISO 8601 UTC)
        }

    Exemple
    -------
    >>> r = purge_expired_logs()
    >>> print(r["deleted"])
    142
    """
    client  = get_client()
    cutoff  = datetime.now(timezone.utc) - timedelta(days=_RET_DAYS)
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    resp = client.delete_by_query(
        index=_INDEX,
        query={"range": {"timestamp": {"lt": cutoff_iso}}},
        conflicts="proceed",
        refresh=True,
    )

    deleted = resp.get("deleted", 0)
    purged_at = _utcnow()

    return {
        "deleted":     deleted,
        "purged_at":   purged_at,
        "cutoff_date": cutoff_iso,
    }


def generate_compliance_report(output_path=None):
    """
    Génère un fichier JSON horodaté de conformité RGPD/ISO.

    Le rapport contient :
    - verify_log_integrity() sur les 30 derniers jours
    - generate_retention_report()
    - Liste des purges effectuées durant cette session
    - Timestamp de génération
    - Hash SHA-256 du rapport lui-même (pour chaîne de confiance)

    Paramètres
    ----------
    output_path : str | Path, optionnel — chemin de sortie.
                  Par défaut : reports/compliance_{timestamp}.json

    Retour
    ------
    dict — contenu complet du rapport, tel que sauvegardé dans le fichier JSON.
           Le champ "report_sha256" contient le hash du fichier.

    Exemple
    -------
    >>> r = generate_compliance_report()
    >>> print(r["report_sha256"])
    e9d4…
    """
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if output_path is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_path = _REPORTS_DIR / f"compliance_{ts}.json"
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Fenêtre des 30 derniers jours
    now  = datetime.now(timezone.utc)
    from_ = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    to_   = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    integrity     = verify_log_integrity(from_, to_)
    retention     = generate_retention_report()
    generated_at  = _utcnow()

    report = {
        "generated_at":     generated_at,
        "integrity_check":  integrity,
        "retention_report": retention,
        "purges":           [],   # rempli par le Backend si nécessaire
        "report_sha256":    "",   # calculé ci-dessous
    }

    # Hash du rapport (sans le champ report_sha256 lui-même)
    report_copy = {k: v for k, v in report.items() if k != "report_sha256"}
    report["report_sha256"] = hashlib.sha256(
        json.dumps(report_copy, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)

    return report
