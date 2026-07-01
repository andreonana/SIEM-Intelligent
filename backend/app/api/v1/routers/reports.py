#   backend/app/api/v1/routers/report.py
#
#   Ce fichier définit les endpoints liés aux rapports de sécurité (consultation des rapports existants, génération à 
#    la demande).
#
#   *** STATUT: SQUELETTE FONCTIONNEL   ***
#   Le génératieur de rapports PDF/Excel automatique est pour la semaine 3

from fastapi import APIRouter, Depends

from app.core.config import settings

from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/reports", tags=["reports"])

@router.get("")

async def get_all_reports(user: dict = Depends(require_role("analyst"))):
    """
    Retourne la lsite des rapports déjà générés.
    Rôle requis: analyst ou plus
    *** SQUELETTE   ***
        Retourne une liste vide en attendant le générateur de rapports automatique.
    """
    return {"total": 0, "reports": []}


@router.post("/generate", status_code=202)

async def generate_report(user: dict = Depends(require_role("administrator"))):
    """
    Déclenche la génération d'un nouveau rapport de sécurité.
    Rôle requis: administrator
    *** SQUELETTE   ***
        Confirme la prise en compte de la demande, sans encore générer de rapport réel.
        Le code 202 (Accepted) indique que la demande est acceptée, mais traitée de façon asynchrone
         (cohérent avec la nature potentiellement longue de la génération d'un rapport PDF complet une
         fois implémentée).
    """
    return {
        "status": "génération en file d'attente (fonctionnalité à venir)",
        "request_by": user["username"],
    }