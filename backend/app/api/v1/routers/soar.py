#   backend/app/api/v1/routers/soar.py
#
#   Ce fichier définit les endpoints liés aux playbooks d'automatisation de réponse aux incidents (SOAR).
#
#   *** STATUT: SQUELETTE FONCTIONNEL   ***
#   Le module modules/soar/ (qui implémentera les actions réelles: blocage d'IP, désactivation de compte, 
#    isolation de machine) n'est pas encore développé;
#   Il est planifié pour la semaine 2 du projet, une fois le moteur de corrélation cpapble de détecter 
#    les menaces déclenchant ces playbooks.

from fastapi import APIRouter, Depends, HTTPException, status

from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/soar", tags=["soar"])

@router.get("/playbooks")

async def get_playbooks(user: dict = Depends(require_role("analyst"))):
    """
    Retourne la liste des playbooks d'automatisation disponibles.
    Rôle requis: analyst ou plus
    *** SQUELETTE   ***
        Retourne une liste vide en attendant l'implémentation du module modules/soar/.
    """
    return {"total": 0, "playbooks": []}


@router.post("/playbooks/{playbook_id}/run")

async def run_playbook(
    playbook_id: str,
    user: dict = Depends(require_role("analyst"))
):
    """
    Déclenche manuellement l'exécution d'un playbook précis.
    Rôle requis: analyst ou plus
    *** SQUELETTE   ***
        Retourne une erreur 404, puisqu'aucun playbook réel n'existe encore dans le système?
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=(f"Aucun playbook trouvé avec l'identifiant '{playbook_id}'."),
    )