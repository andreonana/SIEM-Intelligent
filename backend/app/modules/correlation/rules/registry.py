#   backend/app/modules/correlation/rules/registry
#
#   Ce fichier centralise la liste des règles de corrélation actives.
#   Pour ajouter une nouvelle règle, il suffira de l'ajouter à la liste wci-dessous sans besoin de le faire dans le moteur d'orchestration

from app.modules.correlation.rules.base import CorrelationAlert, CorrelationRule
from app.modules.correlation.rules.bruteforce import BruteForceRule
from app.modules.correlation.rules.business_hours import BusinessHoursRule

def get_active_rules(business_hours_config: dict | None = None) -> list[CorrelationAlert]:
    """
        Retourne la liste des règles de corrélation actives.
        Paramètre business_hours_config:    Configuration des horaires de travail déjà chargée par l'appelant, nécessaire à BusinessHoursRule.
         Si non fournie, BusinessHoursRule reçoit une configuration désactivée par défaut (cohérent avec le comportement de business_hours_service.get_business_hours_config()
         quand aucune configuration n'existe encore).
        Une nouvelle insatence de chaque règle est crée à chaque appel plutôt que réutilisée comme singleton: LEs règles de corrélation sont sans état entre deux évaluations
         (BusinessHoursRule reçoit sa configuration en paramètrenà chaque fois au lieu de la conserver durablement), donc le coût de création est négligeable et évite tout 
         risque de pollution d'état entre deux scans successifs.
    """
    return [
        BruteForceRule(),
        BusinessHoursRule(business_hours_config or {"enabled": False}),
    ]