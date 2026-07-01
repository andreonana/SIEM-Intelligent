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

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.modules.correlation.rules.base import CorrelationAlert, LogWindow
from app.modules.correlation.rules.registry import get_active_rules
from app.modules.correlation.lockout_service import lock_entity
from app.modules.correlation.business_hours_service import get_business_hours_config
from app.modules.correlation.network_inventory_service import get_network_inventory
from app.modules.correlation.rule_config_service import get_rule_configs
from app.modules.correlation.mitre import get_mitre

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

    filters: list[dict] = [{"range": {"timestamp": {"gte": window_start.isoformat()}}}]
    if source_ip:
        filters.append({"term": {"source_ip": source_ip}})
    if host:
        filters.append({"term": {"host": host}})

    try:
        response = await es_client.search(
            index=settings.es_logs_index_name,
            query={"bool": {"filter": filters}},
            size=10_000,
            sort=[{"timestamp": {"order": "asc"}}],
        )
    except Exception as exc:
        print(f"[Corrélation] Impossible de récupérer les logs depuis ES: {exc}")
        return LogWindow(logs=[], cindow_start=window_startt, window_end=now)

    logs = [{"id": hit["_id"], **hit["_source"]} for hit in response["hits"]["hits"]]

    return LogWindow(logs=logs, window_start=window_start, window_end=now)

async def _index_alert(alert: CorrelationAlert, es_client: AsyncElasticsearch) -> None:
    """
        Indexe une alerte produite par une règle dans l'index Elasticsearch dédié aux alertes (settings.es_alerts_index_name)
    """

    mitre = get_mitre(alert.rule_name)

    document = {
        "rule_name":        alert.rule_name,
        "severity":         alert.severity,
        "description":      alert.description,
        "source_ip":        alert.source_ip,
        "host":             alert.host,
        "related_log_ids":  alert.related_log_ids,
        "detected_at":      alert.detected_at.isoformat(),
        "status":           "ouvert",
        #   MITRES ATTAQUES A AJOUTER
        "mitre_tactic_id":      mitre.get("tactic_id", ""),
        "mitre_tactic_name":    mitre.get("tactic_name", ""),
        "mitre_technique_id":   mitre.get("technique_id", ""),
        "mitre_technique_name": mitre.get("technique_name", ""),
    }

    try:
        await es_client.index(index=settings.es_alerts_index_name, document=document)
    except Exception as exc:
        print(f"[Correlation] Impossible d'indexer l'alerte `{alert.rule_name}`: {exc}.")

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
        "received_at":      alert.detected_at.isoformat(),
    }

    try:
        await es_client.index(index=settings.es_logs_index_name, document=document)
    except Exception as exc:
        print(f"[Correlation] Impossible d'indexer le log de détection `{alert.rule_name}`: {exc}.")

async def _trigger_lockout_if_needed(alert: CorrelationAlert, es_client: AsyncElasticsearch) -> None:
    """
        Déclenche le blocage simulé des entités concernées par une alerte comme brute-force
        N'est appelé que pour les alertes issues d'une règle exigeant ce playbook de blocage (bruteforce_threshold, business_hours_violation, etc)
    """
    if not alert.rule_name:
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

async def _load_scan_context(es_client: AsyncElasticsearch) -> dict:
    """
        Charge depuis E, en parallèle conceptuelle (séquentielle ici pour siplicité), les 3 sources de contexte nécessaire aux règles:
            -   Configuration des horaires de travail (BusinessHoursRule);
            -   Inventaire réseau connu (UnknownNetworkRule);
            -   Configurations d'acitivation des règles.
    """
    business_hours_config   = await get_business_hours_config(es_client)
    network_inventory       = await get_network_inventory(es_client)
    rule_configs            = await get_rule_configs(es_client)

    return {
        "business_hours_config":    business_hours_config,
        "network_inventory":        network_inventory,
        "rule_configs":             rule_configs,
    }

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

    context = await _load_scan_context(es_client)

    active_rules = get_active_rules(
        business_hours_config=context["business_hours_config"],
        network_inventory=context["network_inventory"],
        es_client=es_client,
        rule_configs=context["rule_configs"],
    )

    all_alerts: list[CorrelationAlert] = []
    for rule in active_rules:
        try:
            rule_alerts = await rule.evaluate(window)
            all_alerts.extend(rule.alerts)
        except Exception as exc:
            print(f"[Corrélation] Erreur lors de l'évaluation de la règle `{rule.name}`: {exc}.")
    
    await _process_alerts(all_alerts, es_client)

    return all_alerts

async def evaluate_for_source(es_client: AsyncElasticsearch, source_ip: str | None, host: str | None) -> list[CorrelationAlert]:
    """
        Exécute un scan de corrélation ciblé et immédiat pour une source précise (IP et/ou host), sans attendre l eprochain job périodique.
        Appelée par le service d'ingestion juste après l'indexation d'un log dont le type, la criticité et/ou les tags correspondent au conditions de déclenchement
         immédiat
    """
    return run_correlation_scan(
        es_client=es_client,
        source_ip=source_ip,
        host=host,
    )

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

    if severity in settings.correlation_immediate_trigger_severity:
        return True
    
    trigger_tags = set(settings.correlation_immediate_trigger_tags)
    if trigger_tags & set(tags):
        return True

    return False

async def _periodic_scan_job() -> None:
    """
        Tâche planifiée par APIScheduler: exécute run_correlation_scan() sur l'ensemble des logs récents, sans filtre de source.
        Le client Elasticsearch est récupéré via get_es_client() et aucune connexion supplémentaire n'est ouverte à chaque exécution.
    """
    es_client = get_es_client()
    try:
        alerts = await run_correlation_scan(es_client)
        if alerts:
            print(f"[Corrélation][Périodique] {len(alerts)} alerte(s) détectée(s).")
    except Exception as exc:
        print(f"[Corrélation][éPériodique] Erreur lors du scan: {exc}.")

def start_correlation_scheduler() -> None:
    """
        Démarre le scheduler APScheduler (AsyncIOScheduler) qui exécute le scan de corrélation périodique toutes les settings.correlation_scan_interval_seconds.
        AsyncIOScheduler s'intègre dans la boucle asynchrio de FastAPI et peut awaiter des coroutines (_periodic_scan_job) sans bloquer le serveur.
        Il est appelé une seule fois depuis le lifespan de main.py, avant le yield et après start_retention_scheduler().
    """
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        _periodic_scan_job,
        trigger="interval",
        seconds=settings.correlation_scan_interval_seconds,
        id="periodic_correlation_scan",
        replace_existing=True,
    )
    scheduler.start()
    print(f"[Corrélation] Scheduler démarré. Scan toutes les {settings.correlation_scan_intervla_seconds} secondes.")