#   backend/app/modules/correlation/rules/communication_banned.py
#
#   Cette règle détecte une tentative de communication (log réseau ou auth) avec une entité déjà placée en quarantaine par lockout_service. Il s'agit de nos propres entités
#    déjà bloquées, pas d'une liste de réputation externe séparée.

from app.modules.correlation.rules.base import CorrelationAlert, CorrelationRule, LogWindow
from app.modules.correlation.lockout_service import is_entity_locked

COMMUNICATION_BANNED_TAG = "communication banned"

class CommunicationBannedRule(CorrelationRule):
    """
        Règle asynchrone qui nécessite d'interroger Elasticsearch pour connaître le statut de quarantaine de chaque destination recontrée dans la fenêtre des logs. 
    """

    def __init__(self, es_client):
        self._es_client = es_client

    @property
    def name(self) -> str:
        return "communication_banned"

    def evaluate(self, window: LogWindow) -> list[CorrelationAlert]:
        alerts: list[CorrelationAlert] = []

        for log in window.logs:
            source_ip = log.get("source_ip")
            host = log.get("host")

            if not source_ip and not host:
                continue

            #   Vérification asynchrone de la quarantaine pour la source et la destination
            is_source_locked = False
            is_host_locked = False

            if source_ip:
                is_source_locked = await is_entity_locked(self._es_client, entity_type="source_ip", entity_value=source_ip)

            if host:
                is_host_locked = await is_entity_locked(self._es_client, entity_type="host", entity_value=host)

            if is_source_locked or is_host_locked:
                locked_entity = source_ip if is_source_locked else host
                direction = "depuis" if is_source_locked else "vers"

                alerts.append(
                    CorrelationAlert(
                        rule_name=self.name,
                        severity="WARNING",
                        decription=(f"Tentative de communication détectée vers une source bannie ({locked_entity})")
                    )
                )
