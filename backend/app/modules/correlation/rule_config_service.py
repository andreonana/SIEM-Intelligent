#   backend/app/modules/correlation/rule_config_service.py
#
#   Gère la configuration d'activation/désactivation de chaque règle de corrélation stockée dans Elasticsearch pour permettre un changement
#    à chaud sans redémarrage ou "mise à jour" du SIEM.
#
#   *** REGLE METIER    ***
#   Seul un administrateur peut activer ou désactiver une règle de corrélation.
#   La vérificatiob du rôle est faite au niveau du routeur, lors de l'authentification pour la connexion.

from datetime import datetime, timezone

from elasticsearch import AsyncElasticsearch

from app.core.config import settings

#   LISTE DES NOMS DES REGLES CONNUS DU SYSTEME
KNOWN_RULE_NAMES:   frozenset[str] = frozenset({
    "brutefore_threshold",
    "business_hours_violation",
    "unknown_network",
    "communication_banned",
    "unauthorized_privileges",
})

#   Valeur par défaut si aucun document de configuration n'existe pour une règle
_DEFAULT_ENABLED = True

async def get_rules_config(es_client: AsyncElasticsearch) -> dict[str, dict]:
    """
        Retourne la configuration de toutes les règles connues.
        Format de retour:
            {
                "bruteforce_threshold":         {"enabled": True, "update_at": "...", "updated_by": "..."},
                "business_hours_violation":     {"enabled": True, ...}
                "unknown_network":              {"enabled": False, ...},
                ...
            }
        Si aucun document n'existe pour une règle (jamais configurée), elle est retournée avec enabled=True (activée par défaut).
    """
    #   Initialise toutes les règles avec la valeur par défaut:
    configs: dict[str, dict]    = {
        name: {"enabled": _DEFAULT_ENABLED, "rule_name": name}
        for name in KNOWN_RULE_NAMES
    }

    try:
        response = await es_client.search(
            index=settings.es_rule_configs_index_name,
            query={"match_all": {}},
            size=len(KNOWN_RULE_NAMES) + 10                     #   marge de sécurité
        )
    except Exception:
        #   Index absent ou cluster indisponible -> retour des valeurs par défaut.
        #   Toutes les règles restent actives: ne jamais désactiver silencieusement.
        return configs

    for hit in response["hits"]["hits"]:
        doc     = hit["_source"]
        name    = doc.get("rule_name")
        if name in configs:
            configs[name] = doc

    return configs

async def get_rule_config(es_client: AsyncElasticsearch, rule_name: str,) -> dict:
    """
        Retourne la configuration d'une règle précise.
        Retourne {"enabled": True, "rule_name"}
    """
    try:
        response = await es_client.get(
            index=settings.es_rule_configs_index_name,
            id=rule_name,
        )
        return response["_source"]
    except Exception:
        return {"enabled": _DEFAULT_ENABLED, "rule_name": rule_name}

async def set_rule_enabled(es_client: AsyncElasticsearch, rule_name: str, enabled: bool, updated_by: str,) -> dict:
    """
        Active ou désactive une règle de corrélation dont l'état peut changer.
        Rôle requis: admin ou plus
        Paramètres:
            rule_name   : Nom de la règle (doit être dans KNOWN_RULE_NAMES).
            enabled     : True pour activer, False pour désactiver.
            updated_by  : username de l'admin effectuant la modification.
        Lève ValueError si rule_name n'est pas reconnu.
    """
    if rule_name not in KNOWN_RULE_NAMES:
        raise ValueError(f"Règle inconnue: `{rule_name}`. Règles disponibles et modifiables: {sorted(KNOWN_RULE_NAMES)}.")

    now         = datetime.now(timezone.utc)
    document    = {
        "rule_name":    rule_name,
        "enabled":      enabled,
        "updated_by":   updated_by,
        "updated_at":   now.isoformat(),
    }

    await es_client.index(
        index=settings.es_rule_configs_index_name,
        id=rule_name,
        document=document,
    )

    #   Traçe l'index d'audit
    await es_client.index(
        index=settings.es_audit_index_name,
        document={
            "action":       "rule_config_update",
            "rule_name":    rule_name,
            "enabled":      enabled,
            "updated_by":   updated_by,
            "timestamp":    now.isoformat(),
        },
    )

    return document

def is_rule_enabled(configs: dict[str, dict], rule_name: str) -> bool:
    """
        Vérifie si une règle est activée dans la configuration chargée.
        Synchrone car utilisable directement dans registry.get_active_rules().
        Retourne True si la règle est absente de la config (active par défaut).
    """
    return configs.get(rule_name, {}).get("enabled", _DEFAULT_ENABLED)