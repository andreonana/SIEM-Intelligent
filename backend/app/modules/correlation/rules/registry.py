#   backend/app/modules/correlation/rules/registry
#
#   Ce fichier centralise la liste des règles de corrélation actives.
#   Pour ajouter une nouvelle règle, il suffira de l'ajouter à la liste wci-dessous sans besoin de le faire dans le moteur d'orchestration

from elasticsearch import AsyncElasticsearch

from app.modules.correlation.rules.base import CorrelationRule
from app.modules.correlation.rules.bruteforce import BruteForceRule
from app.modules.correlation.rules.business_hours import BusinessHoursRule
from app.modules.correlation.rules.unknown_network import UnknownNetworkRule
from app.modules.correlation.rules.communication_banned import CommunicationBannedRule
from app.modules.correlation.rules.unauthorized_privileges import UnauthorizedPrivilegesRule
from app.modules.correlation.rule_config_service import is_rule_enabled

def get_active_rules(business_hours_config: dict, network_inventory: dict, es_client: AsyncElasticsearch, rule_configs: dict[str, dict],) -> list[CorrelationRule]:
    """
        Retourne la liste des règles de corrélation actives.
        Paramètre business_hours_config:    Configuration des horaires de travail déjà chargée par l'appelant, nécessaire à BusinessHoursRule.
         Si non fournie, BusinessHoursRule reçoit une configuration désactivée par défaut (cohérent avec le comportement de business_hours_service.get_business_hours_config()
         quand aucune configuration n'existe encore).
        Une nouvelle instence de chaque règle est crée à chaque appel plutôt que réutilisée comme singleton: LEs règles de corrélation sont sans état entre deux évaluations
         (BusinessHoursRule reçoit sa configuration en paramètre à chaque fois au lieu de la conserver durablement), donc le coût de création est négligeable et évite tout 
         risque de pollution d'état entre deux scans successifs.
        
            Règles et leur mode d'évaluation :
        ┌──────────────────────────────────┬───────────┬──────────────────┐
        │ Règle                            │ async ES? │ Quarantaine auto │
        ├──────────────────────────────────┼───────────┼──────────────────┤
        │ BruteForceRule                   │ Non       │ Oui              │
        │ BusinessHoursRule                │ Non       │ Oui              │
        │ UnknownNetworkRule               │ Non       │ Non              │
        │ CommunicationBannedRule          │ Oui       │ Non (déjà banni) │
        │ UnauthorizedPrivilegesRule       │ Oui       │ Oui              │
        └──────────────────────────────────┴───────────┴──────────────────┘
    """
    rules: list[CorrelationRule] = []

    if is_rule_enabled(rule_configs, "bruteforce_threshold"):
        rules.append(BruteForceRule())
    if is_rule_enabled(rule_configs, "business_hours_violation"):
        rules.append(BusinessHoursRule(business_hours_config))
    if is_rule_enabled(rule_configs, "unknown_network"):
        rules.append(UnknownNetworkRule(network_inventory))
    if is_rule_enabled(rule_configs, "communication_banned"):
        rules.append(CommunicationBannedRule(es_client))
    if is_rule_enabled(rule_configs, "unauthorized_privileges"):
        rules.append(UnauthorizedPrivilegesRule(es_client))

    return rules