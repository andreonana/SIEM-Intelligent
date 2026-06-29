#   backend/app/modules/correlation/rules/unknown_network.py
#
#   Cette règle détecte les connexions provenant d'une source absente de l'inventaire réseau connue de l'entreprise.

from collections import defaultdict

from app.modules.correlation.rules.base import CorrelationAlert, CorrelationRule, LogWindow
from app.modules.correlation.network_inventory_service import is_known_source

UNKNOWN_NETWORK_TAG = "unknown network"

class UnknownNetworkRule(CorrelationRule):
    """
        Règle qui détecte les logs de connexions (type "auth") provenant d'une source absente de l'inventaire réseau connu.
        Reçoit l'inventaire réseau déjà chargé via le constructeur, tout comme BusinessHoursRule reçoit sa configuration.
        Le moteur d'orchestration charge cette donnée une seule fois par cycle de scan, pas une fois par règle.
    """

    def __init__(self, network_inventory: dict):
        self._inventory = network_inventory

    @property
    def name(self) -> str:
        return "unknown network"

    def evaluate(self, window: LogWindow) -> list[CorrelationAlert]:
        if not self._inventory.get("enabled", False):
            return []

        unknown_logs = [
            log
            for log in window.logs
            if log.get("log_type") == "auth"
             and log.get("source_ip")
             and log.get("host")
             and not is_known_source(log["source_ip"], log["host"], self._inventory)
        ]

        if not unknown_logs:
            return []

        #   Regroupement par couple (source_ip, host): Une seule alert distincte par couple distinct détecté dnas la fenêtre,
        #    et non une alerte par log individuel
        grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for log in unknown_logs:
            grouped[(log["source_ip"], log["host"])].append(log)

            alerts: list[CorrelationAlert] = []
            for (source_ip, host), logs in grouped.items():
                alerts.append(
                    CorrelationAlert(
                        rule_name=self.name,
                        severity="WARNING",
                        description=(f"Connexion détectée depuis une source absente de l'inventaire réseau connu: {source_ip} -> {host}."),
                        source_ip=source_ip,
                        host=host,
                        related_log_ids=[log["id"] for log in logs],
                        generated_log_severity="warning",
                        generated_log_tags=[UNKNOWN_NETWORK_TAG],
                        triggers_lockout=False,
                    )
                )

        return alerts