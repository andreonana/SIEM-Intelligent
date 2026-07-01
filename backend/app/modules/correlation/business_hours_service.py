#   backend/app/modules/correlation/business_hours_service.py
#
#   Ce fichier gère la configuration des horaires de travail de l'entreprise et détermine su un log d'authentification arrive hors de ces horaires; 
#    un signal fort de machine pottentiellement compormise ou de contrôle distant non autorisé.
#
#   *** REGLES METIER CONFIRMEES    ***
#   -   Les horaires de travail (jours ouverts, heures d'ouverture, heure de fermeture) sont définis globalement par un administrateur, pas par machine.
#        Aucune machine n'est exemptée par défaut, toute machine active hors horaire est par nature suspecte.
#   -   Un administrateur peut ajouer des exceptions ponctuelles (heures supplémentaires) pour une date précise, pouvant aussi bien réduire qu'étendre la plage 
#        déjà ouverte (ex. "aujourd'hui, jusqu'à 22h au lieu de 19h"), ou même ouvrir totalement ou partiellement un jour normalement fermé.
#        Une exception redéfinit librement l'heure d'ouverture et celle de efrmeture pour la date concernée; la décision appartient entièrement à l'admin, ce 
#        fichier ne lui impose aucune contrainte de cohérence avec l'horaire normal de la semaine.

from datetime import datetime, time
from zoneinfo import ZoneInfo

from elasticsearch import AsyncElasticsearch

from app.core.config import settings

_CONFIG_DOCUMENT_ID = "global_config"

async def get_business_hours_config(es_client: AsyncElasticsearch) -> dict:
    """
        Récupère la configuration actuelle des horaires de travail.
        Si aucune configuration n'a encore été définie par un admin, retourne une configuration par défaut désactivée (enabled=False), tant qu'aucun horaire
         n'a été explicitement configuré, la règle de détection hors-horaire ne doit jamais se déclencher par erreur sur une configuration absente ou par défaut
         involontaire.
    """
    default_config = {
        "enabled": False,
        "working_days": [],                                                             #   0 = lundi ... 6 = dimanche
        "opening_time": None,
        "closing_time": None,
        "exceptions": {},
    }

    try:
        response = await es_client.get(
            index=settings.es_business_hours_index_name, id=_CONFIG_DOCUMENT_ID
        )
        return response["_source"]
    except Exception:
        return default_config

async def update_business_hours_config(
    es_client:      AsyncElasticsearch,
    working_days:   list[int],
    opening_time:   str,
    closing_time:   str,
) -> dict:
    """
        Met à jour la configuration globale des horaires de travail.
        Réservé à un admin; vérification du rôle faite au niveau du routeur HTTP.
    """
    if time.fromisoformat(closing_time) <= time.fromisoformat(opening_time):
        raise ValueError(f"L'heure de fermeture ({closing_time}) doit être postérieure/supérieurs ) celle d'ouverture ({opening_time}).")

    config = await get_business_hours_config(es_client)
    config.update(
        {
            "enabled": True,
            "working_days": working_days,
            "opening_time": opening_time,
            "closing_time": closing_time,
        }
    )

    await es_client.index(
        index=settings.es_business_hours_index_name,
        id=_CONFIG_DOCUMENT_ID,
        document=config,
    )
    return config

async def add_exception(
    es_client: AsyncElasticsearch, 
    exception_date: str, 
    opening_time: str,
    closing_time: str
) -> dict:
    """
        Ajoute une exception ponctuelle (heure sup) pour une date précise.
        Paramètres:
            exception_date   : date au format "YYYY-MM-DD".
            opening_time     : Nouvelle heure d'ouverture pour cette date, ormat "HH:MM", ou None pour ouvert depuis
             le début de la journée.  
            closing_time     : nouvelle heure de fermeture pour cette date précise, au format "HH:MM".
                Doit être postérieure à opening_time.
    """
    if opening_time is not None and closing_time is not None:
        if time.fromisoformat(closing_time) <= time.fromisoformat(opening_time):
            raise ValueError(f"L'heure de fermeture ({closing_time}) doit être supérieure à celle d'ouverture ({opening_time}) pour cette exception.")

    config = await get_business_hours_config(es_client)

    exceptions = config.get("exceptions", {})
    exceptions[exception_date] = {
        "opening_time": opening_time,
        "closing_time": closing_time,
    }       
    config["exceptions"] = exceptions

    await es_client.index(
        index=settings.es_business_hours_index_name,
        id=_CONFIG_DOCUMENT_ID,
        document=config,
    )
    return config

async def remove_exception(es_client: asyncElasticsearch, exception_date: str,) -> dict:
    """
        Supprime une exception ponctuelle pour une date précise.
        Rôle: admin ou plus
    """
    config = await get_business_hourd_config(es_client)
    exceptions = config.get("exceptions", {})
    exceptions.pop(exception_date, None)
    config["exceptions"] = exceptions

    await es_client.index(
        index=settings.es_business_hours_index_name,
        id=_CONFIG_DOCUMENT_ID,
        document=config,
    )
    return config

def is_within_business_hours(log_timestamp: datetime, config: dict) -> bool:
    """
        Détermine si un horodatage de log se situe dans les horaires de travail configurés, en tenant compte des exceptions
         ponctuelles éventuelles.
        Si la configuration est désactivée (enable=False), retourne toujours True car il n'y a pas de configuration horaires.
    """
    if not config.get("enabled", False):
        return True

    tz = ZoneInfo(settings.business_hours_timezone)
    local_time = log_timestamp.astimezone(tz)
    date_str   = local_time.date().isoformat()
    current_time = local_time.time()

    exceptions = config.get("exceptions", {})

    if date_str in exceptions:
        #   Une exception existe pour cette date précise: Elle remplace entièrement la logique normale de jour ouvert / horaire
        #    normale ci-dessous; y compris pour un jour qui ne serait normalement pas dans working_days.
        exception = exceptions[date_str]
        opening_str = exception.get("opening_time")
        closing_str = exception.get("closing_time")

        opening = time.fromisoformat(opening_str) if opening_str else time.min
        closing = time.fromisoformat(closing_str) if closing_str else time.max

        return opening <= current_time <= closing

    #   Aucune exception pour cette date: On applique l'horaire normal de la semaine. weekday() de Python retourne 0 pour lundi 
    #    et 6 pour dimanche; exactement la convention utilisée dans working_days
    if local_time.weekday() not in config.get("working_days", []):
        return False

    opening_str = config.get("opening_time")
    closing_str = config.get("closing_time")

    if opening_str is None or closing_str is None:
        #   Aucun horaire normal n'a été défini pour les jours ouvrés déclarés (cas incohérent, coniguration incomplète): par prudence,
        #    on considère qu'aucune restriction horaire ne s'applique plutôt que de risquer un comportement imprévisible.
        return True
    
    opening = time.fromisoformat(opening_str) if opening_str else time.min
    closing = time.fromisoformat(closing_str) if closing_str else time.max

    return opening <= current_time <= closing