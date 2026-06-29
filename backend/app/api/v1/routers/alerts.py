#   backend/app/api/v1/routers/alerts.py
#
#   Ce fichier définit les endpoints liés aux alertes de sécurité.
#
#   *** STATUT: SQUELETTE FONCTIONNEL   ***
#   Les endpoints d'ici permet au frontend de commencer son intégration dès maintenant, sans attendre 
#    que le module d'alerting soit terminé.
#
#   A COMPLETER LORS DU DEBUT DE SEMAINE 3

from fastapi import APIRouter, Depends, HTTPException, status

from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

@router.get("")

async def get_all_alerts(user: dict = Depends(require_role("reader"))):
    """
    Retourne la liste des alertes actives.
    Rôle requis: reader ou plus.
    """
    return {"total": 0, "alerts": []}

@router.get("/{alert_id}")

async def get_alert(alert_id: str, user: dict = Depends(require_role("reader"))):
    """
    Retourne une alerte précise par son identifiant.
    Rôle requis: reader ou plus
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=(f"Aucune alerte trouvéd avec l'identifiant '{alert_id}'."),
    )

@router.post("/{alert_id}/acknowledge")

async def acknowledge_alert(
    alert_id: str, user: dict = Depends(require_role("analyst"))
):
    """
    Marque une alerte comme prise en compte (acquité) par un analyste.
    Rôle requis: Analyst ou plus
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=(
            f"Aucune alerte trouvée avec l'identifiant '{alert_id}'."
        ),
    )