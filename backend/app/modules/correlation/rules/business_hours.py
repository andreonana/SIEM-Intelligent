#   backend/app/modules/correlation/rules/business_hours.py
#
#   Cette règle détecte les connexions qui se produisent hors les horaires de travail configurées, un signal fort de "machine zombie" ou de compte
#    compromis utilisé  en dehors des heures normales.
#
#   *** REGLE METIER CONFIRMEE  ***
#   -   Toute connexion hors-horaire génère un log CRITICAL et envoie automatiquement la machine concernée (host) en quarantaine (tout comme brute
#        force).
#   -   Si plusieurs hosts différents sont concernés par la même source_ip (un seul point d'origine agissant sur plusieurs machines hors-horaire), 
#        c'est un signal encore plus grave: En plus de mettre chaque host en quarantaine, la source_ip elle même est bloquée du réseau.

from collections import defaultdict
from datetime import datetime

from app.modules.correlation.rules.base import CorrelationAlert, CorrelationRule, LogWindow
from app.modules.correlation.business_hours_service import is_within_business_hours

BUSINESS_HOURS_VIOLATION_TAG = "outside hours"

class BusinessHoursRule(CorrelationRule):
    """
        Règle qui détecte les logs de connexion (type "auth") survenant hors des horaires de travail configurés.
        Contrairement aux autres règles de ce module, celle-ci a besoin de la configuration horaires de travail au moment de son évaluation; elle est
         donc injectée via le constructeur plutôt que rechargée à chaque appel à evaluate(), pour permettre au moteur d'orchestration de charger cette
         configuration 1 seule fois par cycle de scan au lieu d'une fois par règle.
    """

    def __init__(self, business_hours_config):
        self._config = business_hours_config

    @property
    def name(self) -> str:
        return "business_hours_violation"

    def evaluate(self, window: LogWindow) -> list[CorrelationAlert]:
        #   Si la configuration des horaires n'est pas activée (aucun admin ne l'a encore définie), cette règle ne produit pas d'alerte
        if not self._config.get("enabled", False):
            return []

        violations = [
            log
            for log in window.logs
            if log.get("log_type") == "auth"
             and log.get("timestamp")
             and not is_within_business_hours(datetime.fromisoformat(log["timestamp"]), self._config)
        ]

        if not violations:
            return []

        alerts: list[CorrelationAlert] = []

        #   Regroupement par host: Un même host peut apparaître plusieurs fois dans la fenêtre, mais une seule alerte par host suffit
        violations_by_host: dict[str, list[str]] = defaultdict(list)
        for log in violations:
            host = log.get("host")
            if host:
                violations_by_host[host].append(log)

        for host, logs in violations_by_host.items():
            distinct_ips = {log.get("source_ip") for log in logs if log.get("source_ip")}
            description = (f"Connexion hors horaire de travail détectée sur la machine {host}, depuis {len(distinct_ips)} source(s): {', '.join(sorted(distinct_ips))}.")

            alerts.append(
                CorrelationAlert(
                    rule_name=self.name,
                    severity="CRITICAL",
                    description=description,
                    host=host,
                    related_logs_ids=[log["id"] for log in logs if log.get["id"]],
                    generated_log_severity="critical",
                    generated_log_tags=[BUSINESS_HOURS_VIOLATION_TAG],
                    triggers_lockout=True,
                )
            )

        #   *** ESCALADE:   Même source_ip sur plusieurs hosts différents   ***
        #   Détection indépendante du regroupement par host ci-dessus; Si une seule source_ip est à l'origine de connexions hors-horaire 
        #    sur pluqieurs machines distinctes, c'est un signal de gravité supérieure (accès centralisé compromis, mouvement latéral potentiel)
        #    justifiant de bloquer la source elle-même, pas seulement les machines visées.
        hosts_by_ip: dict[str, set[str]] = defaultdict(set)
        for log in violations:
            source_ip = log.get("source_ip")
            host = log.get("host")
            if source_ip and host:
                hosts_by_ip[source_ip].add(host)

        for source_ip, hosts in hosts_by_ip.items():
            if len(hosts) > 1:
                related_ids = [
                    log["id"]
                    for log in violations
                    if log.get("source_ip") == source_ip and log.get("id")
                ]
                alerts.append(
                    CorrelationAlert(
                        rule_name=self.name,
                        severity="CRITICAL",
                        description=(f"La source '{source_ip}' a établi des connexions hors horaire de travail sur {len(hosts)} machines distinctes ({', '.join(sorted(hosts))}). Sourece bloquée du réseau."),
                        source_ip=source_ip,
                        related_logs_ids=related_ids,
                        generated_log_severity="critical",
                        generated_log_tags=[BUSINESS_HOURS_VIOLATION_TAG],
                        triggers_lockout=True,
                    )
                )

        return alerts