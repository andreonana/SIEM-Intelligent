#   backend/app/api/v1/routers/rules.py
#
#   Ce fichier définit les endpoints de gestion des règles de corrélation (consultationpar les analystes, 
#    création/modification/suppression réservé aux administrateurs).
#
#   *** STATUT: SQUELETTE FONCTIONNEL    ***
#   Le module modules/correlation responsable de ces règles contre les logs entrants n'est pas encore implémenté.
#   Ces endpoints de gestion (CRUD) sont en place avec leur RBAC actif, en atendant cette implémentation.

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client
from app.modules.correlation.rule_config_service import KNOWN_RULE_NAMES, get_rule_config, get_rules_config, set_rule_enabled
from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/rules", tags=["rules"])

_PROTECTED_RULE_NAMES:  frozenset[str] = frozenset({
    "log_hidden",
    "lifecycle_service",
    "lifecycle",
})

#class RuleCreate(BaseModel):
 #   """
#  Corps de la requête de création d'une règle de corrélation.
 #   """
  #  name:           str
   # description:    str = ""
    #rule_type:      str                                 #   "threshold" ou "pattern"

def _guard_protected(rule_name: str) -> None:
    """
        Lève HTTP 403 si le nom de règle correspond au service de cycle de vie protégé. 
    """
    if rule_name in _PROTECTED_RULE_NAMES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(f"La règle `{rule_name}` est liée au service de cycle de vie du SIEM (tag'log hidden'). Elle garantit la traçabilité des arrêts et redémarrage du système et ne peut pas être désactivée."),
        )


@router.get("", summary="Liste des règles de corrélation et leur état")

async def get_all_rules(es_client: AsyncElasticsearch = Depends(get_es_client), user: dict = Depends(require_role("analyst"))):
    """
        Retourne la liste des règles de corrélation configurées.
        Rôle requis: analyst ou plus.
        *** SQUELETTE   ***
            Retourne une liste vide en manque de données dans le module de corrélation.
    """
    configs = await get_rules_config(es_client)

    rules = []
    descriptions = {
        "bruteforce_threshold":     "Détecte les attaques par force brute (N échecs d'authenification en fenêtre de temps).",
        "business_hours_violation": "Détecte les connexions hors horaires de travail configurés.",
        "unknown_netword":          "Détecte les connexions depuis une source absente de l'inventaire du réseau.",
        "communication_banned":     "Détecte toutes tentatives de communication impliquant une entité en quarantaine.",
        "unauthorized_privileges":  "Détecte les changements de rôle non autorisés entre deux sessions.",
    }

    for rule_name in sorted(KNOWN_RULE_NAMES):
        cfg = configs.get(rule_name, {})
        rules.append({
            "rule_name":        rule_name,
            "enabled":          cfg.get("enabled", True),
            "description":      descriptions.get(rule_name, ""),
            "updated_by":       cfg.get("updated_by"),
            "updated_at":       cfg.get("updated_at"),
        })

    return {"total": len(rules), "rules": rules}


@router.get("/{rule_name}", summary="État d'une règle de corrélation")
async def get_rule(
    rule_name: str,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user:      dict = Depends(require_role("analyst")),
):
    """
    Retourne l'état actuel (activée / désactivée) d'une règle précise.
    Rôle requis : analyst ou plus.
    """
    _guard_protected(rule_name)
 
    if rule_name not in KNOWN_RULE_NAMES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Règle inconnue : '{rule_name}'. Règles disponibles : {sorted(KNOWN_RULE_NAMES)}.",
        )
 
    cfg = await get_rule_config(es_client, rule_name)
    return cfg
 
 
# ─────────────────────────────────────────────────────────────────────────────
#   Activation / Désactivation  (administrator uniquement)
# ─────────────────────────────────────────────────────────────────────────────
 
@router.put(
    "/{rule_name}/activate",
    summary="Activer une règle de corrélation",
)
async def activate_rule(
    rule_name: str,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user:      dict = Depends(require_role("administrator")),
):
    """
    Active une règle de corrélation.
    L'activation prend effet immédiatement au prochain cycle de scan (sans redémarrage).
    Rôle requis : administrator.
 
    Règle protégée : le service lifecycle ('log hidden') ne peut pas être activé /
    désactivé via cet endpoint — il est toujours actif par conception.
    """
    _guard_protected(rule_name)
 
    try:
        result = await set_rule_enabled(
            es_client,
            rule_name=rule_name,
            enabled=True,
            updated_by=user["username"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
 
    return {
        "message":    f"Règle '{rule_name}' activée.",
        "rule_name":  result["rule_name"],
        "enabled":    result["enabled"],
        "updated_by": result["updated_by"],
        "updated_at": result["updated_at"],
    }
 
 
@router.put(
    "/{rule_name}/deactivate",
    summary="Désactiver une règle de corrélation",
)
async def deactivate_rule(
    rule_name: str,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user:      dict = Depends(require_role("administrator")),
):
    """
    Désactive une règle de corrélation.
    La règle cesse de produire des alertes dès le prochain cycle de scan.
    Rôle requis : administrator.
 
    Règle protégée : le service lifecycle ('log hidden') EST GARANTI ACTIF en permanence
    et ne peut pas être désactivé — c'est une mesure d'intégrité du SIEM.
    """
    _guard_protected(rule_name)
 
    try:
        result = await set_rule_enabled(
            es_client,
            rule_name=rule_name,
            enabled=False,
            updated_by=user["username"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
 
    # Trace supplémentaire dans l'audit pour les désactivations
    # (déjà écrite par set_rule_enabled, mais on confirme ici dans la réponse)
    return {
        "message":    f"Règle '{rule_name}' désactivée.",
        "rule_name":  result["rule_name"],
        "enabled":    result["enabled"],
        "updated_by": result["updated_by"],
        "updated_at": result["updated_at"],
    }
 