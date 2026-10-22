"""
Authentication utilities for password hashing and JWT token management.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Security scheme for bearer token
security = HTTPBearer()

from ..security import passwords

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-please-use-strong-secret")
_DEFAULT_SECRET = "change-me-in-production-please-use-strong-secret"
if SECRET_KEY == _DEFAULT_SECRET:
    if os.getenv("ENVIRONMENT", "development").lower() == "production":
        raise RuntimeError(
            "SECRET_KEY is still the public default. Anyone could forge login "
            "tokens. Set SECRET_KEY to a random value (see .env.example)."
        )
    logger.critical(
        "SECRET_KEY is the public default - tokens can be forged. "
        "Never run like this outside local development."
    )
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
)  # 1 hour default


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against an Argon2id or legacy bcrypt hash."""
    return passwords.verify_password(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password with Argon2id."""
    return passwords.hash_password(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.

    Args:
        data: Data to encode in token
        expires_delta: Optional custom expiration time

    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """
    Decode and validate a JWT access token.

    Args:
        token: JWT token string

    Returns:
        Decoded token data

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        logger.warning(f"JWT decode error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def validate_token_data(payload: dict) -> dict:
    """
    Validate required fields in token payload.

    Args:
        payload: Decoded JWT payload

    Returns:
        Validated payload

    Raises:
        HTTPException: If required fields are missing
    """
    # Tokens that only allow finishing the 2FA step are not login tokens
    if payload.get("purpose"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    required_fields = ["user_id", "username", "email", "role"]

    for field in required_fields:
        if field not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: missing {field}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return payload


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Get current user from JWT token.
    
    Args:
        credentials: Bearer token from request header
        
    Returns:
        User object
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    from ..database import get_db
    from ..models import User
    
    token = credentials.credentials
    
    try:
        # Decode token
        payload = decode_access_token(token)
        user_id: int = payload.get("user_id")
        
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user from database - use generator
    db = next(get_db())
    user = db.query(User).filter(User.id == user_id).first()
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


async def get_current_active_user(
    current_user = Depends(get_current_user)
):
    """
    Get current active user (must be active and verified).
    
    Args:
        current_user: User from get_current_user dependency
        
    Returns:
        Active user object
        
    Raises:
        HTTPException: If user is not active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    return current_user


async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
):
    """
    Get current user if authenticated, otherwise return None.
    Used for endpoints that work both authenticated and unauthenticated.
    
    Args:
        credentials: Optional bearer token
        
    Returns:
        User object or None
    """
    if credentials is None:
        return None
    
    try:
        from ..database import get_db
        from ..models import User
        
        token = credentials.credentials
        payload = decode_access_token(token)
        user_id: int = payload.get("user_id")
        
        if user_id is None:
            return None
        
        # Get user from database
        db = next(get_db())
        user = db.query(User).filter(User.id == user_id).first()
        return user
    except Exception as e:
        logger.warning(f"Optional auth failed: {e}")
        return None
