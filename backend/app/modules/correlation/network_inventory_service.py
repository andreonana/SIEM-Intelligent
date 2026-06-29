#   backend/app/modules/correlation/network_inventory_service.py
#
#   Ce fichier gère l'inventaire des machines (host, IP, MAC) connues du réseau de l'entreprise. Toute connexion depuis un élément absent de cet inventaire
#    est considérée comme suspecte; c'est la traduction opérationnelle de la règle ("Connexion depuis une source inhabituelle").
#
#   Géré par un administrateur global, au même titre que la configuration des horaires de travail; pas de propostition/validation de la part d'un analyste ici,
#    car il s'agit d'une déclaration d'inventaire matériel, pas d'une classification de contenu comme la table tag->severity.

from elasticsearch import AsyncElasticsearch

from app.core.config import  settings

_INVENTORY_DOCUMENT_ID = "global_inventory"

async def get_network_inventory(es_client: AsyncElasticsearch) -> dict:
    """
        Récupère l'inventaire réseau actuel.
        Retourne une structure désactivée par défaut (enabled=False) si aucun inventaire n'a encore été déclaré; cohérent avec le même principe que 
         business_hours_service.get_business_hours_config().
    """
    default_inventory = {"enabled": False, "know_hosts": [], "kwonw_ips": []}

    try:
        response = await es_client.get(
            index=settings.es_network_inventory_index_name,
            id=_INVENTORY_DOCUMENT_ID,
        )
        return response["_source"]
    except Exception:
        return default_inventory

async def update_network_inventory(
    es_client: AsyncElasticsearch, known_hosts: list[str],
    known_ips: list[str]
) -> dict:
    """
        Mise à jour de l'inventaire réseau complet (remplace la liste existante par celle fournie).
        Réservé à un admin; vérification du rôle au nbiveau du routeur HTTP.
    """
    inventory = {
        "enabled": True,
        "known_hosts": known_hosts,
        "known_ips": known_ips,
    }

    await es_client.index(
        index=settings.es_network_inventory_index_name,
        id=_INVENTORY_DOCUMENT_ID,
        document=inventory,
    )
    return inventory

def is_known_source(source_ip: str, host: str, inventory: dict) -> bool:
    """
        Détermine si une source (IP et host) fait partie de l'inventaire réseau connu.
        Si l'inventaiere n'est pas activé (enabled=False), retourne toujours True; tant qu'aucun inventaire
         n'a été explicitement déclaré, aucune source ne doit être considérée comme inconnue par erreur sur 
         une configuration absente.
         Une source est considérée comme connue si son IP ou son host figure dnas l'inventaire; une machine 
         peut être identifiée par l'un ou l'autre selon ce que la source du log a fourni.
    """
    if not inventory.get("enabled", False):
        return True

    return source_ip in inventory.get("known_ips", []) or host in inventory.get("known_hosts", [])