#   backend/app/api/v1/routers/rules.py
#
#   Ce fichier définit les endpoints de gestion des règles de corrélation (consultationpar les analystes, 
#    création/modification/suppression réservé aux administrateurs).
#   *** STATUT: SQUELETTE ONCTIONNEL    ***
#   Le module modules/correlation responsable de ces règles contre les logs entrants n'est pas encore implémenté.
#   Ces endpoints de gestion (CRUD) sont en place avec leur RBAC actif, en atendant cette implémentation.

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/rules", tags=["rules"])

class RuleCreate(BaseModel):
    """
    Corps de la requête de création d'une règle de corrélation.
    """
    name:           str
    description:    str = ""
    rule_type:      str                                 #   "threshold" ou "pattern"

@router.get("")

async def get_all_rules(user: dict = Depends(require_role("analyst"))):
    """
    Retourne la liste des règles de corrélation configurées.
    Rôle requis: analyst ou plus.
    *** SQUELETTE   ***
        Retourne un eliste vide en manque de données dans le module de corrélation.
    """
    return {"total": 0, "rules": []}


@router.post("", status_code=status.HTTP_201_CREATED)

async def create_rule(
    rule: RuleCreate,
    user: dict = Depends(require_role("administrator"))
):
    """
    Crée une nouvelle règle de corrélation.
    Rôle requis: administrator
    *** SQUELETTE   ***
        Confirme la réception sans encore persister la règle durablement.
    """
    return {
        "status": "règle créée (persistance à venir)",
        "name": rule.name,
        "rule_type": rule.rule_type,
        "created_by": user["username"],
    }


@router.post("/{rule_id}")

async def update_rule(
    rule_id:        str,
    rule:           RuleCreate,
    user:           dict = Depends(require_role("administrator")),
):
    """
    Modifie une règle de corrélation existante.
    Rôle requis: administrator
    *** SQUELETTE   ***
        Retourne une erreur 404, si aucune règle réelle n'existe encore dans le système.
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=(f"Aucune règle trouvée avec l'identifiant '{rule_id}'."),
    )


@router.delete("/{rule_id}")

async def delete_rule(
    rule_id:    str,
    user:       dict = Depends(require_role("administrator"))
):
    """
    Supprime une règle de corrélation.
    Rôle requis:    administrator
    *** SQUELETTE   ***
        Retourne uen erreur 404, pour la même raiseon que update_rule() ci-haut.
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=(f"Aucune règle trouvée avec l'identifiant '{rule_id}'."),
    )