#   backend/app/modules/correlation/rules/port_scan.py
#
#   Cette règle détecte un scan de ports: une m^me source qui contacte un grand nombre de ports distincts sur la fenêtre de corrélation;
#    signature classique d'une reconnaissance réseau interne.
#
#   *** Dependances de donnees  ***
#   Cette règle nécessite que les logs de type "réseau" portent un champ "destination_port" dans leur "extra", un agent de surveillance
#    réseau (firewall, sonde) doit envoyer ce champ explicitement dans son JSON. Sans cette donnée, cette règle ne peut produire aucune
#    détection (elle ignore silencieusement les logs qui n'ont pas ce champ au lieu de lever une erreur).

from collections import defaultdict

from app.core.config import settings
from app.modules.correlation.rules.base import CorrelationAlert, CorrelationRule, LogWindow

PORT_SCAN_TAG = "port scan"

class PortScanRule(CorrelationRule):
    """
        Règle de seuil qui détecte une source qui contacte un nombre de ports distincts dépassant settings.correlation_port_scan_threshold
         sur la fenêtre de logs fournie.
    """

    @property
    def name(self) -> str:
        return "port_scan"

    def evaluate(self, window: LogWindow) -> list[CorrelationAlert]:
        network_logs = [
            log
            for log in window.logs
            if log.get("log_type") == "réseau"
             and log.get("source_ip")
             and log.get("extra", {}).get("destination") is not None
        ]

        if not network_logs:
            return []

        ports_by_ip: dict[str, str] = defaultdict(set)
        logs_by_ip: dict[str, list[dict]] = defaultdict(list)
        for log in network_logs:
            source_ip = log["source_ip"]
            ports_by_ip[source_ip].add(log["extra"]["destination_port"])
            logs_by_ip[source_ip].append(log)
        
        alerts: list[CorrelationAlert] = []
        for source_ip, ports in ports_by_ip.items():
            if len(ports) >= settings.correlation_port_scan_threshold:
                logs = logs_by_ip[source_ip]
                alerts.append(
                    CorrelationAlert(
                        rule_name=self.name,
                        severity="HIGH",
                        description=(f"Scan de ports détecté depuis {source_ip}: {len(ports)} ports distincts contactés en moins de {settings.correlation_port_scan_threshold} secondes."),
                        source_ip=source_ip,
                        related_logs_ids=[log["id"] for log in logs],
                        generated_log_severity="warning",
                        generated_log_tags=[PORT_SCAN_TAG],
                        triggers_lockout=False,
                    )
                )

        return alerts