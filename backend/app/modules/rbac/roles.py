# ============================================================
# rbac.py — Role-Based Access Control
# Handles: who can access what endpoint
# Used by: backend dev adds Depends(require_role(...)) 
#          to any endpoint they want to protect
# ============================================================

from fastapi import Depends, HTTPException, status
# from fastapi.security import HTTPAuthorizationCredentials

from app.modules.rbac.auth import decode_access_token, bearer_scheme

# ── Role Hierarchy ────────────────────────────────────────
# Higher number = more permissions
# An administrator (3) can do everything a reader (1) can do
ROLE_LEVELS: dict[str, int] = {
    "reader":           1,
    "analyst":          2,
    "administrator":    3,
}

# ── Current User Extractor ────────────────────────────────
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)
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
    """
    token = credentials.credentials  # The raw JWT string
    payload = decode_access_token(token)
    
    return {
        "user_id":  payload["sub"],
        "username": payload["username"],
        "role":     payload["role"]
    }

# ── Role Enforcement ──────────────────────────────────────
def require_role(minimum_role: str | list[str]):
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
    def check_role(user: dict = Depends(get_current_user)) -> dict:
        user_role:  str = user["role"]

        if isinstance(minimum_role, list):
            #   *** Mode liste explicite (extension backend dev)    ***
            #   Comparaison directe: Le rôle de l'utilisateur doit apparaître tel quel dans la liste fourni,
            #    sans raisonnement de hiérarchie
            if user_role not in minimum_role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(f"Access denied. Requires one of {minimum_role}. "
                    f"Your role: '{user_role}'."),
                )
            #   *** Mode hiérarchique original inchangé.

        user_level =        ROLE_LEVELS.get(user["role"], 0)
        required_level =    ROLE_LEVELS.get(minimum_role, 99)
        
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires '{minimum_role}' role or higher. "
                       f"Your role: '{user_role}'"
            )
        return user  # Pass user info to the endpoint function
    
    return check_role