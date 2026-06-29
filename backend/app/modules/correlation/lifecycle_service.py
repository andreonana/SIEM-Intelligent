#   backend/app/modules/correlation/lifecycle_service.py
#
#   Ce fichier gère les logs de cycle de vie du SIEM lui-même. Un log généré automatiquement à l'ARRÊT du serveur, et un autre généré automatiquement
#    au PROCHAIN DEMARRAGE, qui calcule et signale la durée exacte d'indisponibilité entre les deux.
#
#   *** REGLE METIER CONFIRMEE - IMMUABILITE    ***
#   Ces logs sont générés automatiquement et ne sont jamais modifiables, même par un administrateur; contrairement aux autres logs du système. C'est
#    la preuve d'intégrité du système de journalisation lui-même; si ce log pouvait être modifié, un attaquant pourrait coupé la journalisation pour
#    aussi effacer la trace de cette coupure.
#   Le tag "log hidden" désigne le fait que les logs réels du sytème sont restées "cachés" / absents pendant toute la durée de l'arrêt; severity -> critical
#    car l'arrêt de la journalisation est l'une des situations les plus graves pour un SIEM car toutes compromission survenue dans cette période serait invisible.
#
#   *** ABSENCE DE LOG DE FERMETURE EN CAS DE CRASH BRUTAL  ***
#   Cette mécanique respose sur le bon déroulement de la séquence d'arrêt de FastAPI. Si le processus est brutalement tué (coupure de courant, crash d'OS), 
#    le log d'ARRÊT ne sera jamais généré; seul celui de relancement le sera, avec unen durée calculée depuis le DERNIER log de service connu, pas 
#    nécessairement depuis un log d'arrêt explicite. C'est une limite structurelle honnête à connaître: Aucun système ne peut garantir qu'un processus tué 
#    brutalement ait le temps d'écrie quoi que ce soit avant de s'arrêter.

from ast import expr_context
from datetime import datetime, timezone

from elasticsearch import AsyncElasticsearch

from app.core.config import settings

SERVICE_LIFECYCLE_TAG = "log hidden"

async def log_service_shutdown(es_client: AsyncElasticsearch) -> None:
    """
        Génère un log immuaable d'arrêt du servicen, au moment où le serveur FastAPI s'arrête.
    """
    now = datetime.now(timezone.utc)

    document = {
        "timestamp": now.isoformat(),
        "source_ip": "system",
        "host": "smart-siem-backend",
        "log_type": "système",
        "severity": "critical",
        "raw_message":  (f"Arrêt du service de journalisation Smart SIEM à {now.isoformat()}. Aucun log ne sera collecté jusqu'au prochain démarrage."),
        "tags": [SERVICE_LIFECYCLE_TAG],
        "received_at": now.isoformat(), 
    }

    try:
        await es_client.index(index=settings.es_logs_index_name, document=document)
    except Exception as exc:
        print(f"[AVERTISSEMENT] Impossible d'enregistrer le log d'arrêt du service dans Elasticsearch: {exc}")

async def log_service_startup(es_client: AsyncElasticsearch) -> None:
    """
        Génère un log immuable de démarrage du service, au moment où le serveur FastAPI démarre.
        Recherche le dernier log de cycle de vie connu (démarrage ou arrêt précédent) pour calculer
         la durée exacte d'indisponibilité, et l'inclut dans le message de ce nouveau log.
    """
    now = datetime.now(timezone.utc)

    last_timestamp = await _find_last_lifecycle_timestamp(es_client)
    last_timestamp_log = await _find_last_log_timestamp(es_client)

    if last_timestamp is not None:
        downtime_seconds = (now - last_timestamp).total_seconds()
        downtime_message = (f"Durée d'indisponibilité depuis le dernier évènement de cycle de vie connu ({last_timestamp.isoformat()}): {downtime_seconds:.0f} secondes.")
    elif last_timestamp_log is not None:
        downtime_seconds = (now - last_timestamp_log)
        downtime_message = (f"Durée d'indisponibilité depuis le dernier évènement du cycle de vie connu ({last_timestamp_log.isoformat()}): {downtime_seconds:.0f} secondes.")
    else:
        downtime_message = ("Aucun évènement de cycle de vie extérieur trouvé. Probablement le premier démarrage du système.")

    document = {
        "timestamp": now.isoformat(),
        "source_ip": "system",
        "host": "smart-siem-backend",
        "log_type": "système",
        "severity": "critical",
        "raw_message": (f"Démarrage du service de journalisation Smart SIEM à {now.isoformat()}. {downtime_message}."),
        "tags": [SERVICE_LIFECYCLE_TAG],
        "received_at": now.isoformat(),
    }

    try:
        await es_client.index(index=settings.es_logs_index_name, document=document)
    except Exception as exc:
        print(
            f"[AVERTISSEMENT] Impossible d'enregistrer le log de démarrage du service dans Elasticsearch: {exc}."
        )

async def _find_last_lifecycle_timestamp(es_client: AsyncElasticsearch) -> datetime | None:
    """
        Recherche le timestamp du dernier cycle de vie de Smart SIEM, pour servir de référence au calcule de durée d'indisponibilité.
        Retourne None si aucun log de ce type n'existe encore (premier démarrage du système).
    """
    try:
        response = await es_client.search(
            index=settings.es_logs_index_name,
            query={"term": {"tags": SERVICE_LIFECYCLE_TAG}},
            sort=[{"timestamp": {"order": "desc"}}],
            size=1,
        )
    except Exception:
        return None

    hits = response["hits"]["hits"]
    if not hits:
        return None

    return datetime.fromisoformat(hits[0]["_source"]["timestamp"])

async def _find_last_log_timestamp(es_client: AsyncElasticsearch) -> datetime | None:
    """
        Recherche le timestamp du dernier log de Smart SIEM, pour servir de référence au calcule de durée d'indisponibilité.
        Retourne None si aucun log de ce type n'existe encore (premier démarrage du système).
    """
    try:
        response = await es_client.search(
            index=settings.es_logs_index_name,
            sort=[{"timestamp": {"order": "desc"}}],
            size=1,
        )
    except Exception:
        return None

    hits = response["hits"]["hits"]
    if not hits:
        return None

    return datetime.fromisoformat(hits[0]["_source"]["timestamp"])