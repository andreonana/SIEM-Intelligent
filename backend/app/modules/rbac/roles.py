# ============================================================
# rbac.py — Role-Based Access Control
# Handles: who can access what endpoint
# Used by: backend dev adds Depends(require_role(...)) 
#          to any endpoint they want to protect
# ============================================================

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from typing import Optional

from app.modules.rbac.auth import decode_access_token, bearer_scheme

# ── Role Hierarchy ────────────────────────────────────────
# Higher number = more permissions
# An administrator (3) can do everything a reader (1) can do
ROLE_LEVELS = {
    "reader": 1,
    "analyst": 2,
    "administrator": 3
}

# ── Current User Extractor ────────────────────────────────
def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
) -> dict:
    """
    FastAPI calls this automatically when an endpoint uses it.
    Extracts the JWT from the request header and returns the user info.

    Returns a dict like:
    {
        "user_id": "42",
        "username": "chloe",
        "role": "analyst"
    }

    Raises HTTP 401 if the token is absent or invalid.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token d'authentification manquant.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials  # The raw JWT string
    payload = decode_access_token(token)
    
    return {
        "user_id": payload["sub"],
        "username": payload["username"],
        "role": payload["role"]
    }

# ── Role Enforcement ──────────────────────────────────────
def require_role(minimum_role: str):
    """
    Protects an endpoint by requiring a minimum role level.
    
    HOW THE BACKEND DEV USES THIS:
    
        from rbac import require_role
        
        # Any logged-in user can view logs
        @app.get("/api/logs")
        def get_logs(user=Depends(require_role("reader"))):
            return {"logs": [...]}
        
        # Only analysts and admins can manage alerts  
        @app.post("/api/alerts/{id}/acknowledge")
        def ack_alert(id: str, user=Depends(require_role("analyst"))):
            return {"status": "acknowledged"}
        
        # Only admins can create users
        @app.post("/api/users")
        def create_user(user=Depends(require_role("administrator"))):
            return {"status": "created"}
    
    The 'user' variable always contains the current user's info,
    which the backend dev can use for audit logging.
    """
    def check_role(user: dict = Depends(get_current_user)):
        user_role = user["role"]

        if isinstance(minimum_role, list):
            # Mode liste explicite : le rôle doit apparaître tel quel dans la liste fournie,
            # sans logique de hiérarchie.
            if user_role not in minimum_role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Accès refusé. Rôles requis : {minimum_role}. Votre rôle : '{user_role}'.",
                )
            return user

        # Mode hiérarchique : le niveau du rôle utilisateur doit atteindre le niveau requis.
        user_level = ROLE_LEVELS.get(user_role, 0)
        required_level = ROLE_LEVELS.get(minimum_role, 99)

        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Accès refusé. Rôle requis : '{minimum_role}' ou supérieur. "
                       f"Votre rôle : '{user_role}'.",
            )
        return user

    return check_role