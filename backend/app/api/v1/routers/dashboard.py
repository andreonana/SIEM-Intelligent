#   backend/app/api/v1/routers/dashboard.py
#
#   Ce fichier définit l"endpoint de synthèse pour le tableau de bord.
#
#   *** STATUT: SQUELETTE FONCTIONNEL   ***
#   Ce module agrégera les statistiques réelles depuis Elasticsearch: volume de logs / heure, 
#    top alertes, carte des sources n'est pas encore implémenté. Cet endpoint retourne une
#    structure de données minimale mais cohérente avec ce que le frontend affiche, pour 
#    permettre son intégration dès maintenant.

from fastapi import APIRouter, Depends

from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

@router.get("")

async def get_dashboard(user: dict = Depends(require_role("reader"))):
    """
    Retourne les données de synthèse pour le tableau de bord principal.
    Rôle requis: reader ou plus
    *** SQUELETTE   ***: Retourne des valeurs à 0 en attendant l'implémentation du module dashboard (week 3)
    """
    return {
        "total_logs": 0,
        "total_alerts_active": 0,
        "logs_per_hour": [],
        "top_alerts": [],
        "source_map": []
    }