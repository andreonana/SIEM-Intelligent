# ============================================================
# auth.py — Authentication & JWT Token Management
# Handles: password hashing, token creation, token decoding
# Used by: rbac.py, and the backend dev's login endpoint
# ============================================================

import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Load variables from the .env file
# This reads JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_MINUTES
load_dotenv()

# ── Configuration ─────────────────────────────────────────
# These come from .env — never hardcoded
SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))

# Safety check: if JWT_SECRET is missing, crash immediately
# Better to know now than to have silent security failures
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET is not set in .env file!")

# ── Password Hashing ──────────────────────────────────────
# bcrypt is the industry standard for hashing passwords
# NEVER store plain passwords — always store the hash
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain_password: str) -> str:
    """
    Converts a plain password into a secure hash.
    Example: "mypassword123" → "$2b$12$abc123..."
    
    Use this when CREATING a user.
    """
    return pwd_context.hash(plain_password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Checks if a plain password matches a stored hash.
    Returns True if they match, False otherwise.
    
    Use this when a user LOGS IN.
    """
    return pwd_context.verify(plain_password, hashed_password)

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
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=EXPIRY_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

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
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
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