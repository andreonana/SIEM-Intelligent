#   backend/app/api/v1/routers/health.py
#
#   Ce fichier expose l'endpoint de santé au chemin exact attendu par la spécification reçue de l'équipe: GET /api/health.
#  
#   Remarque:   Ce projet possède déjà un endpoint GET /health (sans le préfixe "/api"), défini directement dans main.py 
#            et exigé pour les ondes de supervision interne.
#   Cet endpoint (/api/health) est un allias public destiné au frontend et aux autres services, conformément à la rable 
#    d'endpoints reçue. Les deux coexistent sans conflit, à des chemins différents.

from fastapi import APIRouter

router = APIRouter(prefix="/api", tags=["health"])

@router.get("/health")
async def api_health_check():
    """
        Endpoint de santé public, accessible sans authentification.
        Rôle requis: `public` (aucun `depends()` de protection).
    """
    return {"status": "ok"}