# backend/app/modules/correlation/lockout_service.py
#
#   Ce fichier implémente le PLAYBOOK SOAR de blocage, déclenché après des évènements comme les
#    tranches d'échecs d'authentification détectée par BruteForceRule.
#
#   *** RÈGLE MÉTIER CONFIRMÉE ***
#   Après chaque tranche de settings.correlation_bruteforce_threshold échecs (peu importe le scénario rapide/lent),
#    DEUX entités sont bloquées simultanément et indépendamment :
#   - le COMPTE visé (host, dans le vocabulaire de ce projet), pour le cas où l'attaque viendrait de l'extérieur ;
#   - la MACHINE SOURCE (source_ip), même en l'absence d'attaque réelle confirmée — une pénalité pour l'utilisateur légitime qui
#      se trompe trop souvent, qui le force à passer par "mot de passe oublié" plutôt que de continuer à essayer indéfiniment.
#
#   Ce blocage est SIMULÉ, cohérent avec le reste du module SOAR: il ne pilote aucun système d'authentification externe réel,
#    mais marque l'entité comme bloquée dans un index Elasticsearch dédié, que le frontend peut consulter pour refléter ce statut,
#    et qu'un administrateur peut lever manuellement (cf. unlock_entity ci-dessous).

from datetime import datetime, timezone

from elasticsearch import AsyncElasticsearch

from app.core.config import settings

#   Nom de l'index de quarntaine
def _lockout_index_name() -> str:
    return f"{settings.es_logs_index_name}-lockouts"


async def lock_entity(
    es_client: AsyncElasticsearch, entity_type: str, entity_value: str, reason: str
) -> None:
    """
    Marque une entité (un host/compte, ou une IP source) comme
    bloquée.

    Paramètres :
        entity_type : "host" ou "source_ip" — indique quel type
            d'entité est concerné.
        entity_value : la valeur exacte de l'entité (le nom du host,
            ou l'adresse IP).
        reason : description de la raison du blocage, pour
            traçabilité.

    Utilise l'entity_type et l'entity_value combinés comme identifiant
    du document (plutôt qu'un identifiant généré aléatoirement) : ainsi,
    bloquer une entité déjà bloquée écrase simplement l'entrée
    existante (mise à jour de la raison et de l'horodatage), sans créer
    de doublons.
    """
    document_id = f"{entity_type}:{entity_value}"

    await es_client.index(
        index=_lockout_index_name(),
        id=document_id,
        document={
            "entity_type": entity_type,
            "entity_value": entity_value,
            "locked": True,
            "reason": reason,
            "locked_at": datetime.now(timezone.utc).isoformat(),
            "unlocked_by": None,
            "unlocked_at": None,
        },
    )


async def unlock_entity(
    es_client: AsyncElasticsearch, entity_type: str, entity_value: str, unlocked_by: str
) -> None:
    """
    Lève le blocage d'une entité.

    Réservé aux administrateurs — la vérification du rôle se fait au
    niveau du routeur HTTP (cf. principe déjà appliqué partout dans ce
    projet : le RBAC reste une responsabilité de la couche API).
    """
    document_id = f"{entity_type}:{entity_value}"

    try:
        await es_client.update(
            index=_lockout_index_name(),
            id=document_id,
            doc={
                "locked": False,
                "unlocked_by": unlocked_by,
                "unlocked_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return True,
    except Exception:
        return False

#   Vé&rification de statut
async def is_entity_locked(
    es_client: AsyncElasticsearch, entity_type: str, entity_value: str
) -> bool:
    """
    Vérifie si une entité est actuellement bloquée.

    Retourne False si l'entité n'a jamais été bloquée (aucun document
    correspondant), plutôt que de lever une exception.
    """
    document_id = f"{entity_type}:{entity_value}"

    try:
        response = await es_client.get(index=_lockout_index_name(), id=document_id)
    except Exception:
        return False

    return response["_source"].get("locked", False)


async def list_locked_entities(es_client: AsyncElasticsearch) -> list[dict]:
    """
    Liste toutes les entités actuellement bloquées.
    """
    try:
        response = await es_client.search(
            index=_lockout_index_name(),
            query={"term": {"locked": True}},
            size=1000,
            sort=[{"locked_at": {"order": "desc"}}],
        )
    except Exception:
        return []

    return [{"id": hit["_id"], **hit["_source"]} for hit in response["hits"]["hits"]]

async def list_all_lockout_history(es_client:AsyncElasticsearch) -> list[dict]:
    """
        Retourne l'historique complet des blocages (actifs et levés).
        Utile pour l'audit et l'investigation post-incident.
    """
    try:
        response = await es_client.search(
            index=_lockout_index(),
            query={"match_all": {}},
            size=100,
            sort=[{"locked_at": {"order": "desc"}}],
        )
    except Exception:
        return []

    retrun [{"id": hit["_id"], **hit["_source"]} for hit in response["hits"]["hits"]]