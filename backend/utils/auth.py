"""
Authentication utilities for password hashing and JWT token management.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
import jwt
from jwt import PyJWTError

logger = logging.getLogger(__name__)

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


def decode_access_token(token: str, purpose: Optional[str] = None) -> dict:
    """
    Decode and validate a JWT.

    ``purpose`` names the kind of token the caller accepts. Normal login
    tokens carry no purpose; the short-lived token of the 2FA step carries
    ``"mfa"``. A token of the wrong kind is rejected here, centrally, so an
    ``mfa`` token (issued after the password step only) can never be used as
    a login token on any endpoint.

    Raises:
        HTTPException: If token is invalid, expired or of the wrong kind
    """
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["exp"]},  # a token without expiry is never valid
        )
    except PyJWTError as e:
        logger.warning(f"JWT decode error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if payload.get("purpose") != purpose:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


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
