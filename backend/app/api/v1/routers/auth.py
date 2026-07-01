#   backend/app/api/v1/routers/auth.py
#
#   Ce fichier définit les deux endpoints d'authentification attendus par le frontend: La connexion (login, public)
#    et la déconnexion (logout, qui nécessite d'être déjà connecté).
#
#   Ce fichier ne réimplémente AUCUNE logique d'authentification : Toute la mécanique (vérification du password, 
#    génération du token JWT) vit dans auth.py, reçu de l'éqiipe de sécurité et placé à la racine de backend/ .
#   Ce routeur ne fait que l'exposer comme endpoint HTTP.

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.modules.rbac.auth import create_access_token, verify_password
from app.modules.rbac.roles import require_role, get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])

class LoginRequest(BaseModel):
    """
    Corps de la requête de connexion: identifiant et mot de passe en clair, envoyés une seule fois pour obtenir un token JWT.
    """
    username:   str
    password:   str

class LoginResponse(BaseModel):
    """
    Réponse renvoyée après une connexion réussie: Le token JWT à utiliser dans l'en-tête 
     "Authorization: Bearer <token>" de toutes les requêtes suivantes.
    """
    access_token:   str
    token_type:     str = "bearer"

#   *** ENDPOINT LOGIN START    ***
#
#   Endpoint:   POST /api/auth/login
#   Rôle requis:    Public (aucun Depends() de protection)
#
#   *** HYPOTHESE NON CONFIRMEE à valider avec l'équipe sécurité    ***
#   Le fichier auth.py reçu fournit hash_password(), verify_password(), create_access_token() et decode_access_token(), mais ne 
#    contient lui-même aucun mécanisme de stockage ou de recherche des utilisateurs existants (pas de fonction "find_user_by_username" 
#    par exemple).
#   Ce backend a donc besoib de savoir, lors de la connexion, où aller chercher l'user correspondant à "username" pour récupérer son 
#    mot de passe haché et son rôle, avant de pouvoir appeler verify_password() puis create_access_token().
@router.post(
    "/login",
    response_model=LoginResponse
)

async def login(credentials: LoginRequest):
    """
    Authentiie un utilisateur et retourne un token JWT.
    Endpoint public: Aucune protection par rôle n'est nécessaire ici, puisqu'il permet d'obtenir un token pour s'authentifier sur les
     autres endpoints protégés.
    """
    #   *** SQUELETTE (à compléter une ois la source des utilisateurs conirmée) ***
    #
    #   La logiqeu attendue, une ois cette source confirmée, ressemble à:
    #   user_record = find_user_by_username(credentials.username)
    #   if user_record is None or not verify_password(
    #                                           cerdentials.password, user_record["hashed_password"]
    #                                       ):
    #     raise HTTPException(
    #           statusçcode=HTTP_401_UNAUTHORIZED,
    #           detail="Identifiant ou mot de pase incorrect.",
    #       )
    #   token = create_access_token(
    #       user_id=user_record["id"],
    #       username=user_record["username"],
    #       role=user_record["role"],
    #   )
    #   return LoginResponse(access_token=token)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "Connexion non encore branchée: La source de vérité des utilisateurs (où chercher username/password haché/rôle) doit être "
            "confirmée avant de compléter cet endpoint."
        ),
    )
#   *** ENDPOINT LOGIN END  ***

@router.post("/logout")
async def logout(user: dict = Depends(require_role("reader"))):
    """
    Déconnecte l'utilisateur courant.
    Rôle requis:    reader (tout utilisateur connecté, quel que soit son rôle précis, peut se déconnecter).
    Remarque technique: Les tokens JWT, par nature, restent valides jusqu'à leur expiration même après un "logout". Il n'existe pas de
     mécanisme nati de révocation côté serveur dans le ichier auth.py reçu. Ct endpoint confirme donc la déconnexion côté client (qui doit 
     supprimer le token stocké de son côté), mais ne invalide pas le token côté serveur.
    """
    return {"status": "déconnecté", "username": user["username"]}