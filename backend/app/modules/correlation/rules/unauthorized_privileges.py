#   backend/app/modules/correlation/rules/unauthorized_privileges.py
#
#   Cette règle détecte un changement de RÔLE d'un utilisateur entre deux authentifications réussies successives, sans qu'aucun log d'autorisation légitime ("update role") 
#    n'ait été émis par un administrateur dans l'intervalle entre ces deux authentifications.
#
#   *** RÈGLE MÉTIER CONFIRMÉE ***
#   1. À chaque authentification réussie, on compare le rôle courant de l'utilisateur au rôle qu'il avait lors de sa DERNIÈRE authentification réussie connue.
#   2. Si le rôle a changé, on cherche dans l'intervalle de temps EXACT entre ces deux authentifications un log avec le tag "update role", où source_ip = l'IP d'un administrateur 
#    et host = l'utilisateur concerné — la preuve qu'un administrateur a légitimement effectué ce changement.
#   3. Si aucun log "update role" correspondant n'est trouvé dans cet intervalle, le changement de rôle est considéré comme NON AUTORISÉ : alerte critique, tag "unauthorised privileges".
#
#   *** HYPOTHÈSES NON CONFIRMÉES — à valider ***
#   Le contenu structuré nécessaire à cette règle (nom d'utilisateur, résultat de l'authentification, rôle courant) n'a pas été confirmé avec précision. Cette implémentation adopte les hypothèses
#    suivantes, les plus robustes disponibles, à ajuster si la convention réelle diffère :
#   - Le champ "host" du log d'authentification représente l'identifiant de l'utilisateur (cohérent avec la convention déjà confirmée pour les logs "update role").
#   - Un log d'authentification est un SUCCÈS s'il porte extra["auth_result"] == "success" (et non un échec, lesquels restent gérés exclusivement par BruteForceRule). Si ce champ est
#      absent, le log est ignoré par cette règle (ni succès ni échec confirmé).
#   - Le rôle courant de l'utilisateur au moment de l'authentification est lu dans extra["role"].
#   - Le log "update role" légitime porte directement source_ip pour identifier l'administrateur à l'origine du changement, cohérent avec la règle confirmée ("l'IP de l'admin est la source_ip,
#      l'user est l'host").

from datetime import datetime

from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.modules.correlation.rules.base import CorrelationAlert, CorrelationRule, LogWindow

UNAUTHORIZED_PRIVILEGES_TAG = "unauthorised privileges"
UPDATE_ROLE_TAG             = "update role"

_AUTH_FAILURE_TAGS: frozenset[str] = frozenset({
    "failed password",
    "authentication error",
    "authentication failure",
    "invalid user",
    "invalid credentials",
    "login failed",
    "logon failure",
    "access denied",
    "permission denied",
})

def _is_successful_auth_response(log: dict) -> bool:
    """
        Détermine si un log est la réponse d'un serveur à une authentification réussie.
        Critères:
            1. log_type == "auth"
            2. severity == "info"   -> Aucun échec, tagging n'a rien modifié et severity est restée "info" par défaut
            3. host renseigné       ->  host = username dans la réponse du serveur
            4. timestamp renseigné
            5. Aucun tag d'échec explicite dans la liste des tags indexés.
    """
    if log.get("log_type") != "auth":
        return False
    if not log.get("host") or not log.get("timestamp"):
        return False
    if log.get("severity") != "info":
        return False
    if set(log.get("tags", [])) & _AUTH_FAILURE_TAGS:
        return False
    return True

class UnauthorizedPrivilegesRule(CorrelationRule):
    """
        Règle asynchrone : nécessite d'interroger Elasticsearch pour retrouver la dernière authentification réussie de chaque
         utilisateur (potentiellement antérieure à la fenêtre de corrélation standard) et pour rechercher un éventuel log
         "update role" dans l'intervalle exact entre les deux authentifications.
    """

    def __init__(self, es_client) -> None:
        self._es_client = es_client

    @property
    def name(self) -> str:
        return "unauthorized_privileges"

    def evaluate(self, window: LogWindow) -> list[CorrelationAlert]:
        raise NotImplementedError(
            "UnauthorizedPrivilegesRule nécessite un appel asynchrone : "
            "utiliser evaluate_async(), jamais evaluate()."
        )

    async def evaluate_async(self, window: LogWindow) -> list[CorrelationAlert]:
        #   On ne s'intéresse qu'aux authentifications RÉUSSIES de la fenêtre courante, portant un rôle explicite.
        successful_auths = [
            log
            for log in window.logs
            if _is_successful_auth_response(log)
             and log.get("extra", {}).get("role") is not None
        ]

        alerts: list[CorrelationAlert] = []

        for current_auth in successful_auths:
            username            = current_auth["host"]
            current_role        = current_auth["extra"]["role"]
            current_timestamp   = datetime.fromisoformat(current_auth["timestamp"])

            previous_auth = await self._find_previous_successful_auth(
                username, before=current_timestamp
            )

            if previous_auth is None:
                #   Aucune authentification antérieure connue pour cet utilisateur : impossible de détecter un changement
                #    (rien à comparer), pas une anomalie en soi — c'est peut-être sa toute première authentification connue du système.
                continue

            previous_role = previous_auth.get("extra", {}).get("role")
            if previous_role is None or previous_role == current_role:
                #   Rôle inchangé : rien à signaler.
                continue

            previous_timestamp = datetime.fromisoformat(previous_auth["timestamp"])

            authorized = await self._has_legitimate_role_update(
                username, after=previous_timestamp, before=current_timestamp
            )

            if not authorized:
                alerts.append(
                    CorrelationAlert(
                        rule_name=self.name,
                        severity="CRITICAL",
                        description=(f"Changement de rôle non autorisé détecté pour l'utilisateur '{username}' : rôle passé de '{previous_role}' à '{current_role}' entre "
                            f"{previous_timestamp.isoformat()} et {current_timestamp.isoformat()}, sans log d'autorisation administrateur correspondant dans cet intervalle."
                        ),
                        host=username,
                        related_logs_ids=[previous_auth["id"], current_auth["id"]],
                        generated_log_severity="critical",
                        generated_log_tags=[UNAUTHORIZED_PRIVILEGES_TAG],
                        triggers_lockout=True,
                        #   Quarantaine automatique du compte concerné : un changement de privilège non autorisé est une des situations les plus graves possibles
                        #    (élévation de privilèges confirmée), cohérent avec la gravité "critique" de cette règle.
                    )
                )

        return alerts

    async def _find_previous_successful_auth(
        self, username: str, before: datetime
    ) -> dict | None:
        """
            Recherche la dernière authentification réussie connue d'un utilisateur, strictement antérieure à l'horodatage fourni.
            Cette recherche n'est PAS limitée à la fenêtre de corrélation standard (settings.correlation_bruteforce_window_seconds) :
             l'authentification précédente peut être arbitrairement ancienne (un utilisateur peut ne se connecter qu'une fois par semaine), donc cette règle interroge
             l'index complet des logs sans restriction de fenêtre temporelle, en ne gardant que le document le plus récent avant "before".
        """
        try:
            response = await self._es_client.search(
                index=settings.es_logs_index_name,
                query={
                    "bool": {
                        "filter": [
                            {"term": {"host":       username}},
                            {"term": {"log_type":   "auth"}},
                            {"term": {"severity":   "info"}},
                            {"range": {"timestamp": {"lt": before.isoformat()}}},
                        ],
                    "must_not": [{"terms": {"tags": list(_AUTH_FAILURE_TAGS)}}],
                    }
                },
                sort=[{"timestamp": {"order": "desc"}}],
                size=1,
            )
        except Exception:
            return None

        hits = response["hits"]["hits"]
        if not hits:
            return None

        return {"id": hits[0]["_id"], **hits[0]["_source"]}

    async def _has_legitimate_role_update(
        self, username: str, after: datetime, before: datetime
    ) -> bool:
        """
            Vérifie si un log "update role" légitime existe pour cet utilisateur, strictement dans l'intervalle (after, before)
             exclusif des deux bornes — c'est-à-dire entre la précédente authentification et l'authentification courante.
        """
        try:
            response = await self._es_client.search(
                index=settings.es_logs_index_name,
                query={
                    "bool": {
                        "filter": [
                            {"term": {"host": username}},
                            {"term": {"tags": UPDATE_ROLE_TAG}},
                            {
                                "range": {
                                    "timestamp": {
                                        "gt": after.isoformat(),
                                        "lt": before.isoformat(),
                                    }
                                }
                            },
                        ]
                    }
                },
                size=1,
            )
        except Exception:
            #   En cas d'erreur de communication avec Elasticsearch, on ne peut pas confirmer la légitimité du changement; par prudence sécuritaire, 
            #    on considère le changement comme NON autorisé plutôt que de risquer de laisser passer une élévation de privilèges illégitime à cause d'une panne
            #    technique. C'est l'inverse du principe appliqué ailleurs; ici, le doute doit profiter à la sécurité, pas à la disponibilité.
            return False

        return len(response["hits"]["hits"]) > 0