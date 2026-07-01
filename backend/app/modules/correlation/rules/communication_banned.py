#   backend/app/modules/correlation/rules/communication_banned.py
#
#   Cette règle détecte une tentative de communication (log réseau ou auth) avec une entité déjà placée en quarantaine par lockout_service. Il s'agit de nos propres entités
#    déjà bloquées, pas d'une liste de réputation externe séparée.
#
#   *** REGLE METIER CONFIRMEE  ***
#   -   "Communication banned" s'applique à NOS PROPRES entités déjà bloquées, et non à une liste de réputatiion externe.
#   -   Toute activité réseau ou d'authentification depuis ou vers une entité bloquée est suspecte: une entité légitimement bloquée ne devrait plus communiquer.
#   -   Severity WARNING car la communication peut être résiduelle ou automatique (daemon tente de se reconnecter) et l'analyste juge.

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

    async def evaluate(self, window: LogWindow) -> list[CorrelationAlert]:
        """
            Pour chaque log de la fenêtre, vérifie si la source_ip ou le host est bloqué.
            Un log suffit pour déclenchner l'alerte.
        """
        alerts: list[CorrelationAlert] = []

        already_alerted: set[tuple[str | None, str | None]] = set()

        for log in window.logs:
            source_ip   = log.get("source_ip")
            host        = log.get("host")

            if not source_ip and not host:
                continue

            pair = (source_ip, host)
            if pair in already_alerted:
                continue

            #   Vérification asynchrone de la quarantaine pour la source et la destination
            is_source_locked = False
            is_host_locked  = False

            if source_ip:
                is_source_locked = await is_entity_locked(self._es_client, entity_type="source_ip", entity_value=source_ip)

            if host:
                is_host_locked = await is_entity_locked(self._es_client, entity_type="host", entity_value=host)

            if not is_source_locked and is_host_locked:
                continue

            #   Construction de l'alerte
            alerady_alerted.add(pair)

            if is_dource_locked and is_host_locked:
                detail = (f"La source bannie `{source_ip}` tente de communiquer avec l'host banni `{host}`.")
            elif is_source_locked:
                detail = (f"La source bannie `{source_ip}` tente de communiquer avec `{host}`.")
            else:
                detail = (f"Tentative de communication vers l'host banni '{host}' depuis `{source_ip}`.")

            alerts.append(
                CorrelationAlert(
                    rule_name=self.name,
                    severity="WARNING",
                    description=detail,
                    source_ip=source_ip,
                    host=host,
                    related_logs_ids=[log["id"]] if log.get("id") else [],
                    generated_log_severity="warning",
                    generated_log_tags=[COMMUNICATION_BANNED_TAG],
                    triggers_lockout=False,
                )
            )
        
        return alerts
