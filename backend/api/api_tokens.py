"""
Manage the caller's own API tokens (read-only tokens for monitoring).

The token is returned once when it is created; afterwards only a prefix is
visible. Everything is scoped to the signed-in user.
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import get_current_user
from ..models import ApiToken, User
from ..services import api_token_service as tokens

router = APIRouter()


class TokenOut(BaseModel):
    id: int
    name: str
    prefix: str
    created_at: datetime
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class TokenCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    expires_in_days: Optional[int] = Field(None, ge=1, le=3650)


class TokenCreated(BaseModel):
    token: str  # shown only here
    info: TokenOut


def _out(row: ApiToken) -> TokenOut:
    return TokenOut(
        id=row.id,
        name=row.name,
        prefix=row.prefix,
        created_at=row.created_at,
        last_used_at=row.last_used_at,
        expires_at=row.expires_at,
    )


def _mine(db: Session, user: User):
    return db.query(ApiToken).filter(ApiToken.user_id == user.id)


@router.get("", response_model=List[TokenOut])
async def list_tokens(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return [_out(r) for r in _mine(db, user).order_by(ApiToken.created_at.desc()).all()]


@router.post("", response_model=TokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    data: TokenCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    if not data.name.strip():
        raise HTTPException(status_code=422, detail="Name is required")
    if _mine(db, user).count() >= tokens.MAX_TOKENS_PER_USER:
        raise HTTPException(
            status_code=400,
            detail=f"At most {tokens.MAX_TOKENS_PER_USER} tokens per user. Delete one you no longer use.",
        )
    row, token = tokens.create_token(db, user, data.name, data.expires_in_days)
    return TokenCreated(token=token, info=_out(row))


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_token(
    token_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    row = _mine(db, user).filter(ApiToken.id == token_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(row)
    db.commit()
