#   backend/app/modules/rbac/auth.py
#
#   Rôle: authentification et gestion des tokens JWT.
#   Gère le hachage des passwords, la création et la vérification des tokens JWT.
#
#   Utilisé par:
#       - roles.py pour le décodage de token sur chaque requête protégée
#       - routeur de login

# ============================================================
# auth.py — Authentication & JWT Token Management
# Handles: password hashing, token creation, token decoding
# Used by: rbac.py, and the backend dev's login endpoint
# ============================================================

from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from elasticsearch import AsyncElasticsearch

from app.core.config import settings

# Safety check: if JWT_SECRET is missing, crash immediately
# Better to know now than to have silent security failures
if not settings.jwt_secret:
    raise RuntimeError("JWT_SECRET is not set in .env file!")

# ── Password Hashing ──────────────────────────────────────
# bcrypt is the industry standard for hashing passwords
# NEVER store plain passwords — always store the hash
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain_password: str) -> str:
    """
    Converts a plain password into a secure hash.
    Example: "mypassword123" → "$2b$12$abc123..."
    
    Use this when CREATING a user.
    """
    return _pwd_context.hash(plain_password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Checks if a plain password matches a stored hash.
    Returns True if they match, False otherwise.
    
    Use this when a user LOGS IN.
    """
    return _pwd_context.verify(plain_password, hashed_password)

# ── JWT Token Creation ────────────────────────────────────
def create_access_token(user_id: str, username: str, role: str) -> str:
    """
    Creates a signed JWT token containing the user's identity and role.
    This token is what the frontend sends with every request.
    
    The token contains:
    - sub: the user's ID (standard JWT field)
    - username: their login name
    - role: reader | analyst | administrator
    - exp: expiry time (automatically checked on decode)
    
    Example output:
    "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoi..."
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat" : now,
        "exp": now + timedelta(minutes=settings.jwt_expiry_minutes)
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

# ── JWT Token Decoding ────────────────────────────────────
def decode_access_token(token: str) -> dict:
    """
    Reads and verifies a JWT token.
    
    Returns the payload dict if valid:
    {"sub": "1", "username": "chloe", "role": "analyst", "exp": ...}
    
    Raises HTTP 401 if:
    - Token is expired
    - Token signature is invalid (tampered with)
    - Token is malformed
    """
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm],)
        
        # Make sure the token actually has a user ID
        if payload.get("sub") is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is missing user identity",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid or has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ── Bearer Token Extractor ────────────────────────────────
# This tells FastAPI to look for the token in the
# "Authorization: Bearer <token>" header of every request
bearer_scheme = HTTPBearer()


# ── Recherche utilisateur ──────────────────────────────────
async def find_user_by_username(es_client: AsyncElasticsearch, username: str) -> dict | None:
    """
    Recherche un utilisateur par son username dans l'index Elasticsearch dédié.
 
    Retourne None si aucun utilisateur ne correspond à ce username, plutôt que de lever une
     exception — c'est le même principe que get_log_by_id() dans le module d'ingestion:
     l'absence d'un enregistrement n'est pas une erreur technique, c'est un résultat de recherche
     valide que l'appelant (login() ci-dessous) doit pouvoir distinguer d'une vraie panne.
 
    Retourne un dictionnaire {"username": ..., "hashed_password": ..., "role": ...} si trouvé.
    """
    try:
        response = await es_client.get(
            index=settings.es_index_users,
            id=username,
        )
    except Exception:
        #   Le client elasticsearch lève une exception (NotFoundError) quand le document
        #    demandé n'existe pas dans l'index — username inconnu, ou index pas encore créé
        #    (aucun utilisateur déclaré à ce jour). Les deux cas se traduisent de la même façon
        #    pour l'appelant: "aucun utilisateur correspondant".
        return None
 
    return response["_source"]
 
# ── Connexion (login) ──────────────────────────────────────
async def login(username: str, password: str, es_client: AsyncElasticsearch) -> str:
    """
    Authentifie un utilisateur à partir de son username et de son mot de passe en clair.
 
    Déroulement:
        1. Recherche l'utilisateur correspondant au username dans Elasticsearch.
        2. Si aucun utilisateur ne correspond, OU si le mot de passe fourni ne correspond pas
           au hash stocké, lève une HTTPException 401 — le même message générique est utilisé
           dans les deux cas ("Identifiant ou mot de passe incorrect"), pour ne jamais révéler
           à un attaquant si c'est le username ou le password qui est en cause.
        3. Si tout est valide, construit et retourne un token JWT signé pour cet utilisateur.
 
    Paramètres:
        username:  Identifiant fourni par l'appelant (formulaire de connexion).
        password:  Mot de passe en clair fourni par l'appelant, jamais stocké tel quel.
        es_client: Client Elasticsearch asynchrone partagé, injecté par l'appelant (typiquement
                   via Depends(get_es_client) au niveau du routeur HTTP), jamais construit ici —
                   cohérent avec le reste du projet où aucune fonction de service ne connaît la
                   connexion Elasticsearch elle-même.
 
    Retourne le token JWT signé (string), prêt à être renvoyé tel quel dans la réponse HTTP.
 
    Lève une HTTPException 401 si l'authentification échoue (utilisateur inconnu ou mot de passe
     incorrect).
    """
    user_record = await find_user_by_username(es_client, username)
 
    if user_record is None or not verify_password(password, user_record["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiant ou mot de passe incorrect.",
            headers={"WWW-Authenticate": "Bearer"},
        )
 
    #   Le username sert lui-même d'identifiant unique (_id du document ES), donc de "user_id"
    #    du token — cohérent avec la structure de document décrite en en-tête de ce fichier.
    return create_access_token(
        user_id=username,
        username=user_record["username"],
        role=user_record["role"],
    )