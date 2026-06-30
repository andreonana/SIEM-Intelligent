#   backend/app/modules/correlation/service.py
#
#   Ce fichier orchestre le cycle complet de corrélation en récupérant les logs depuis Elasticsearch (sur une fenêtre de temps), les fournissant 
#    à chaque règle active, indexant les alertes produites, indexant les éventuels logs de détection générés par une règle, et déclenchant le
#    blocage des entités concernées le cas échéant.
#
#   Ce fichier est la façade publique du module de corrélation, tout comme normalize() pour celui de normalisation.
#   
#   *** PROPAGATION TEMPS REEL VERS LE FRONTEND ***
#   Le log de détection généré par une règle est indexé dans le même index que toutes les autres logs (settings.es_logs_index_name); il apparaît
#    donc automatiquement, san saucun mécanisme supplémentaire, dans le flux temps réel exposé par la route de logs_stream, qui interroge déjà en 
#    continu cet index. Indexer ce log dans Elasticsearch et le rendre visible au frontend ne sont donc qu'une seule écriture suivie par le polling.

from datetime import datetime, timedelta, timezone

from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.modules.correlation.rules.base import CorrelationAlert, LogWindow
from app.modules.correlation.rules.registry import get_active_rules
from app.modules.correlation.lockout_service import lock_entity
from app.modules.correlation.business_hours_service import get_business_hours_config

async def _fetch_recent_logs(
    es_client:      AsyncElasticsearch,
    window_seconds: int,
    source_ip:      str |   None = None,
    host:           str |   None = None,
) -> LogWindow:
    """
        Récupère les logs des "indow_seconds" dernières secondes depuis Elasticsearch, et les enveloppe dans LogWindow.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)

    filters = [{"range": {"timestamp": {"gte": window_start.isoformat()}}}]
    if source_ip:
        filters.append({"term": {"source_ip": source_ip}})
    if host:
        filters.append({"term": {"host": host}})

    response = await es_client.search(
        index=settings.es_logs_index_name,
        query={"bool": {"filter": filters}},
        size=10000,
    )

    hits = response["hits"]["hits"]
    logs = [{"id": hit["_id"], **hit["_source"]} for hit in hits]

    return LogWindow(logs=logs, window_start=window_start, window_end=now)

async def _index_alert(alert: CorrelationAlert, es_client: AsyncElasticsearch) -> None:
    """
        Indexe une alerte produite par une règle dans l'index Elasticsearch dédié aux alertes (settings.es_alerts_index_name)
    """
    document = {
        "rule_name":        alert.rule_name,
        "severity":         alert.severity,
        "description":      alert.description,
        "source_ip":        alert.source_ip,
        "host":             alert.host,
        "relanted_log_ids": alert.related_log_ids,
        "detected_at":      alert.detected_at.isoformat(),
        "status":           "ouvert",
    }

    await es_client.index(index=settings.es_alerts_index_name, document=document)

async def _index_generated_log(alert: CorrelationAlert, es_client: AsyncElasticsearch) -> None:
    """
        Indexe le log de détection généré par une règle (CorrelationAlert.generated_log_severity), dans l'index des logs lui-même; différent des logs
         individuels qui ont déclenché la détection.
        Appelé qui si alert.generated_log_severity n'est pas None car toutes les règles ne génèret pas nécessairement un type de log supplémentaire. 
    """
    document = {
        "timestamp":        alert.detected_at.isoformat(),
        "source_ip":        alert.source_ip,
        "host":             alert.host,
        "log_type":         "système",
        "severity":         alert.generated_log_severity,
        "raw_message":      alert.description,
        "tags":             alert.generated_log_tags,
        "received_at":      alert.detect_at.isoformat(),
    }

    await es_client.index(index=settings.es_logs_index_name, document=document)

async def _trigger_lockout_if_needed(alert: CorrelationAlert, es_client: AsyncElasticsearch) -> None:
    """
        Déclenche le blocage simulé des entités concernées par une alerte comme brute-force
        N'est appelé que pour les alertes issues d'une règle exigeant ce playbook de blocage (bruteforce_threshold, business_hours_violation, etc)
    """
    if alert.rule_name not in {"bruteforce_threshold", "business_hours_violation"}:
        return

    if alert.source_ip:
        await lock_entity(
            es_client,
            entity_type="source_ip",
            entity_value=alert.source_ip,
            reason=alert.description,
        )
    if alert.host:
        await lock_entity(
            es_client,
            entity_type="host",
            entity_value=alert.host,
            reason=alert.description,
        )

async def _process_alerts(alerts: list[CorrelationAlert], es_client: AsyncElasticsearch) -> None:
    """
        Traite une liste d'alertes produites par les règles: Indexe chaque alerte, indexe le log de détection associé si la règle en a généré un, et
         déclenche le blocage si applicable.
        fonction privée par run_correlation_scan() et evaluate_for_source() pour ne dupliquer aucune de ces 3 étapes entre les deux chemins d'exécution.
    """
    for alert in alerts:
        await _index_alert(alert, es_client)

        if alert.generated_log_severity is not None:
            await _index_generated_log(alert, es_client)
        
        await _trigger_lockout_if_needed(alert, es_client)

async def run_correlation_scan(es_client: AsyncElasticsearch, source_ip: str | None = None, host: str | None = None) -> list[CorrelationAlert]:
    """
        Exécute un cycle complet de corrélation sur la fenêtre de temps générale en récupérant les logs récents, appliquant toutes les règles actives, indexant
         les alertes et logs de détection produits, déclenchant les blocages applicables.

        C'est la fonction que le job périodique appelle touutes les settings.correlation_scan_interval_secondes.
    """
    window = await _fetch_recent_logs(
        es_client,
        window_seconds=settings.correlation_brute_force_window_seconds,
        source_ip=source_ip,
        host=host,
    )

    business_hours_config = get_business_hours_config(es_client)

    all_alerts: list[CorrelationAlert] = []
    for rule in get_active_rules(business_hours_config):
        all_alerts.extend(rule.evaluate(window))
    
    await _process_alerts(all_alerts, es_client)

    return all_alerts

async def evaluate_for_source(es_client: AsyncElasticsearch, source_ip: str | None, host: str | None) -> list[CorrelationAlert]:
    """
        Exécute un scan de corrélation ciblé et immédiat pour une source précise (IP et/ou host), sans attendre l eprochain job périodique.
        Appelée par le service d'ingestion juste après l'indexation d'un log dont le type, la criticité et/ou les tags correspondent au conditions de déclenchement
         immédiat
    """
    window = await _fetch_recent_logs(
        es_client,
        window_seconds=settings.correlation_brute_force_window_seconds,
        source_ip=source_ip,
        host=host,
    )

    get_business_hours_config = await get_business_hours_config(es_client)

    all_alerts: list[CorrelationAlert] = []
    for rule in get_active_rules(get_business_hours_config):
        all_alerts.etend(rule.evaluate(window))

    await _process_alerts(all_alerts, es_client)

    return all_alerts

def should_trigger_immediate_scan(log_type: str, severity: str, tags: list[str]) -> bool:
    """
        Détermine si un log qui vient d'être ingéré doit déclencher un scan de corrélation immédiat.
        Un nouveau paramètre log_type a été ajouté. Tout log de type "auth" déclenche toujours un scan immédiat, indépendamment de sa severity individuelle (nécessaire
         pour les règles comme brute force).
        Retourne True si:
            - log_type == "auth";
            - severity du log correspond à settings.correlation_immediate_trigger_severity;
            - au moins un des tags du log fait partie de settings.correlation_immediate_trigger_tags.
    """
    if log_type == "auth":
        return True

    if severity == settings.correlation_immediate_trigger_severity:
        return True
    
    trigger_tags = set(settings.correlation_immediate_trigger_tags)
    if trigger_tags.intersection(tags):
        return True

    return False