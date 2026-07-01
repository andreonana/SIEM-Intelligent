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

from elasticsearch import Elasticsearch

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

def login(es_client: Elasticsearch, username: str, password: str):
    response = es_client.search(
        index="users",
        body={
            "query": {
                "term": {"username.keyword": username}
            }
        }
    )

    hits = response["hits"]["hits"]

    if not hits:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    token = create_access_token(
        user_id=hits[0]["id"],
        username=hits[0]["username"],
        role=hits[0]["role"],
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": hits[0]["id"],
            "username": hits[0]["username"],
            "role": hits[0]["role"],
        }
    }

# ── Bearer Token Extractor ────────────────────────────────
# This tells FastAPI to look for the token in the
# "Authorization: Bearer <token>" header of every request
bearer_scheme = HTTPBearer()