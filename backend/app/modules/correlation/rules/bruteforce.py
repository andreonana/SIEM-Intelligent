#   backend/app/modules/correlation/rules/bruteforce.py
#
#   Cette règle détecte un schéma d'échecs d'authentification répétés, et distingue 2 scénarios selon le temps écoulé entre
#    le premier et le cinqueième échec d'une même tranche:
#           - 5 échecs en 60 secondes ou moins: signature d'un script automatisé (vitesse non-humaine) => severité "critical".
#           - 5 échecs en plsu de 60 secondes: Plus probablement une personne qui se trompe répétitivement => severité "warning".
#           - Mons de 5 échecs: Pas d'anomalie
#
#   *** REGLE METIER CONFIRMEE  ***
#   Le comptage se fait séparément par IP source ("source_ip") et par hôte ("host") visé:
#    Une IP qui échoue 5 fois sue le même host en 5 secondes déclenche cette alerte
#    un host qui reçoit 5 échecs en 5 secondes déclenche cette alerte (et un signal d'attaque combiné sur une même cible).

from collections import defaultdict
from datetime import datetime

from app.core.config import settings
from app.modules.correlation.rules.base import CorrelationAlert, CorrelationRule, LogWindow

#   Tag attribué au log de détection généré par cette règle. Volontairement distinct et immunisé de "update log severity" 
#    (audit de la table tag -> severity elle même), qui sont 2 types de logs automatiqeument générés pour diverses raisons
BRUTEFORCE_DETECTION_TAG = "brute force"

def _seconds_between(logs: list[dict]) -> float:
    """
    Calcule le nombre de secondes écoulées entre le premier et le dernier log d'une liste, en se basant sur leur champ "timestamp"
    """
    timestamps = sorted(
        datetime.fromisoformat(log["timestamp"]) for log in logs if log.get("timestamp")
    )
    if len(timestamps) < 2:
        return 0.0
    return (timestamps[-1] - timestamps[0]).total_seconds()

class BruteForceRule(CorrelationRule):
    """
    Règle de seuil (threshold): Détecte un nombre d'échecs d'authentification dépassant settings.correlation_bruteforce_threshold, compté
     séparément par IP source et par host, sur la fenêtre de logs fournié par le moteur d'orchestration dans une limite de temps jugée
     humainement impossible.
    """

    @property
    def name(self) -> str:
        return "bruteforce_threshold"

    def _build_tranches(self, logs: list[dict]) -> list[list[dict]]:
        """
        Découpe une liste de logs (déjà triée par ordre chronologique) en tranches successives de exactement settings.correlation_brute_force_threshold
         éléments.
        Une tranche incomplète (moins d'échecs que le seuil) en fin de liste n'est jamais retourné: Elle ne constitue pas encore une détection, elle pourra
         le devenir lors du prochain cycle si d'autres échecs s'ajoutent.
        """
        threshold = settings.correlation_brute_force_threshold
        sorted_logs = sorted(logs, key=lambda log:log.get("timestamp", ""))

        tranches = []
        for start in range(0, len(sorted_logs) - threshold + 1, threshold):
            tranches.append(sorted_logs[start : start + threshold])
        return tranches

    def _evaluate_group(self, grouped_logs: dict[str, list[dict]], group_field: str) -> list[CorrelationAlert]:
        """
        Applique la détection à un regroupement de logs (soit par source_ip, soit par host, qui appelle cette méthodes 2 fois indépendamment).
        Paramètre group_filed: "source_ip ou "host utilisé uniquement pour savoir quel champ renseigner dans CorrelationAlert (source_ip= ou host=)
        """
        alerts: list[CorrelationAlert] = []

        for group_value, logs in grouped_logs.items():
            for tranche in self._build_tranches(logs):
                elapsed_seconds = _seconds_between(tranche)
                if elapsed_seconds <= settings.correlation_brute_force_window_seconds:
                    #   Scénario "script automatisé": 5 échecs dans la fenêtre de temps configurée (60 secondes par défaut), non-humain
                    log_severity = "critical"
                    description = (f"{len(tranche)} échecs d'authentifications détectées depuis {group_field}={group_value} en seulement {elapsed_seconds:.0f} secondes. Signature d'un script automatisé.")
                else:
                    #   Scénario "erreurs humaines répétées": 5 échecs, mais étalées sur plus de temps que la fenêtre configurée. Plus
                    #    probablement un humain qui se trompe de champ d'autehntification plusieurs fois.
                    log_severity = "warning"
                    description = (
                        f"{len(tranche)} échecs d'authentification détectées depuis {group_field}={group_value} en {elapsed_seconds:.0f} secondes. Probablement des erreurs répétées ayant atteint le seul de blocage." 
                    )

                alert_kwargs = {
                    "rule_name": self.name,
                    "severity": "CRITICAL" if log_severity == "critical" else "WARNING",
                    "description": description,
                    "related_logs_ids": [log["id"] for log in tranche],
                    "generated_log_severity": log_severity,
                    "generate_log_tags": [BRUTEFORCE_DETECTION_TAG],
                    "triggers_lockout": True,
                }
                alert_kwargs[group_field] = group_value
                alerts.append(CorrelationAlert(**alert_kwargs))

        return alerts

    def evaluate(self, window: LogWindow) -> list[CorrelationAlert]:
        #   On ne s'interesse qu'aux logs de type "auth": Même un échec classé "info" par la table tag->severity doit être compté ici,
        #    comme c'est précisement la répétition de logs individuellement bénins qui constitue le signal recherché par cette règle.
        auth_failures = [log for log in window.logs if log.get("log_type") == "auth"]

        alerts: list[CorrelationAlert] = []

        #   --------    Comptage par IP source  --------
        failures_by_ip: dict[str, list[dict]] = defaultdict(list)
        for log in auth_failures:
            source_ip = log.get("source_ip")
            if source_ip:
                failures_by_ip[source_ip].append(log)
        alerts.extends(self._evaluate_group(failures_by_ip, "source_ip"))

        #   --------    Comptage par host visé (indépendamment du comptage par IP)  --------
        #   Détecte une attaque distribuée: Plusieurs IP différentes ciblant la même machine, qui ne déclencherait jamais le comptage IP d'avant
        failures_by_host: dict[str, list[dict]] = defaultdict(list)
        for log in auth_failures:
            host = log.get("host")
            if host:
                failures_by_host[host].append(log)
        alerts.extends(self._evaluate_group(failures_by_host), "host")

        return alerts
