#   backend/app/api/v1/routers/investigation.py
#
#   Ce fichier définit les endpoints d'investigation forensique (reconstruction de chronologie, marquage d'évènement suspects).
#
#   *** STATUT: SQUELETTE FONCTIONNEL   ***
#   La timeline interactive et le marquage croisé multiè-analystes nécessitent une modélisation dédiée qui n'existe pas encore.
#    Ces endpoints sont en place avec leur RBAC actif.

from fastapi import APIRouter, Depends, HTTPException, status

from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/investigation", tags=["investigation"])

@router.get("/{entity_id}")

async def get_investigation(
    entity_id: str,
    user: dict = Depends(require_role("analyst"))
):
    """
        Retourne la chronologie des évènements liés à une entité donnée (machine ou adresse IP par exemple), pour reconstitution forensique.
        Rôle requis: analyst ou plus.
        *** SQUELETTE   ***:    Retourne une structure vide en attendant l'implémentation de la timeline interactive
    """
    return {"entity_id": entity_id, "timeline": []}

@router.post("/{entity_id}/flag")

async def flag_investigation(
    entity_id: str,
    user: dict = Depends(require_role("analyst"))
):
    """
        Retourne un évènement ou une entité comme suspect, pour investigation croisée entre plusieurs analystes.
        Rôle requis: analyst
        *** SQUELETTE   ***
            Confirme la réception de la demande de marquage, sans encore la persister durablement.
    """
    return {
        "entity_id": entity_id,
        "flagget_by": user["username"],
        "status": "marqué (onctionnalité de persistance à venir)", 
    }