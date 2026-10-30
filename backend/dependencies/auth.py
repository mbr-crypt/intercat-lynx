"""
FastAPI dependencies for authentication and authorization.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, UserRole
from ..utils.auth import decode_access_token, validate_token_data

logger = logging.getLogger(__name__)

# HTTP Bearer token scheme
security = HTTPBearer()


# While an admin-chosen password is still active, only these calls work
_ALLOWED_WHILE_PASSWORD_CHANGE_PENDING = ("/auth/me", "/auth/change-password")


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """
    Get current authenticated user from JWT token.

    Args:
        credentials: HTTP Bearer token
        db: Database session

    Returns:
        Current user object

    Raises:
        HTTPException: If authentication fails
    """
    token = credentials.credentials

    # Decode and validate token
    payload = decode_access_token(token)
    payload = validate_token_data(payload)

    user_id = payload.get("user_id")

    # Get user from database
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user is active
    if not user.is_active:
        logger.warning(f"Inactive user attempted access: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive"
        )

    # Tokens issued before a password change / "sign out everywhere" are dead.
    # (Tokens from before this feature have no "tv" claim and count as version 0.)
    if int(payload.get("tv", 0)) != user.token_version:
        logger.info(f"Revoked session used: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is no longer valid. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if account is locked
    if user.locked_until and _as_utc(user.locked_until) > datetime.now(timezone.utc):
        logger.warning(f"Locked user attempted access: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is locked until {user.locked_until.isoformat()}",
        )

    if user.must_change_password and not request.url.path.endswith(
        _ALLOWED_WHILE_PASSWORD_CHANGE_PENDING
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required",
        )

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Get current active user (alias for get_current_user).

    Args:
        current_user: Current user from get_current_user

    Returns:
        Current active user
    """
    return current_user


async def require_login(current_user: User = Depends(get_current_user)) -> User:
    """
    Guard for a whole router: the site is for signed-in users only.

    Only login, registration, the setup assistant, the branding (the login page
    needs it) and the health checks stay open (see tests/test_login_required.py,
    which fails when a new route is left open by accident).
    """
    return current_user


def require_role(required_role: UserRole):
    """
    Dependency factory to require specific user role.

    Usage:
        @router.get("/admin-only", dependencies=[Depends(require_role(UserRole.ADMIN))])

    Args:
        required_role: Required user role

    Returns:
        Dependency function
    """

    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        """Check if user has required role."""
        # Role hierarchy: ADMIN > ANALYST > VIEWER
        role_hierarchy = {UserRole.VIEWER: 0, UserRole.ANALYST: 1, UserRole.ADMIN: 2}

        user_level = role_hierarchy.get(current_user.role, 0)
        required_level = role_hierarchy.get(required_role, 0)

        if user_level < required_level:
            logger.warning(
                f"Insufficient permissions: {current_user.username} "
                f"(role: {current_user.role}) tried to access {required_role} resource"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {required_role.value}",
            )

        return current_user

    return role_checker


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """
    Require admin role.

    Args:
        current_user: Current user

    Returns:
        Current user if admin

    Raises:
        HTTPException: If user is not admin
    """
    if current_user.role != UserRole.ADMIN:
        logger.warning(
            f"Non-admin user attempted admin action: {current_user.username}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )

    return current_user


def optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        HTTPBearer(auto_error=False)
    ),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """
    Get current user if authenticated, otherwise None.

    Useful for endpoints that work both authenticated and unauthenticated.

    Args:
        credentials: Optional HTTP Bearer token
        db: Database session

    Returns:
        User if authenticated, None otherwise
    """
    if not credentials:
        return None

    try:
        token = credentials.credentials
        payload = decode_access_token(token)
        payload = validate_token_data(payload)

        user_id = payload.get("user_id")
        user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
        if user and int(payload.get("tv", 0)) != user.token_version:
            return None

        return user
    except Exception as e:
        logger.debug(f"Optional auth failed: {e}")
        return None
