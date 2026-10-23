"""Authentication with a read-only API token (for machines such as Zabbix)."""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..services import api_token_service

_bearer = HTTPBearer(auto_error=False)


async def get_token_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """
    Accept ``Authorization: Bearer lynx_...``. Login tokens (JWT) are not
    accepted here and API tokens are not accepted anywhere else, so a leaked
    monitoring token can only read the product summary.
    """
    user = (
        api_token_service.find_user(db, credentials.credentials) if credentials else None
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
