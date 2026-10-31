"""Create and check read-only API tokens."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from ..models import ApiToken, User

TOKEN_PREFIX = "lynx_"
MAX_TOKENS_PER_USER = 10
# Updating "last used" on every poll would write to the database every minute
LAST_USED_RESOLUTION = timedelta(minutes=5)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(
    db: Session, user: User, name: str, expires_in_days: Optional[int] = None
) -> Tuple[ApiToken, str]:
    """Returns the stored row and the plain token (never retrievable again)."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(
        user_id=user.id,
        name=name.strip(),
        token_hash=hash_token(token),
        prefix=token[:12],
        expires_at=(
            datetime.now(timezone.utc) + timedelta(days=expires_in_days)
            if expires_in_days
            else None
        ),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, token


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def revoke_all(db: Session, user: User) -> int:
    """
    Delete every API token of the user (no commit; the caller commits).

    Used wherever "sign out everywhere" happens (password change or reset,
    admin revoke, 2FA reset). A machine token is a credential like any other:
    if it survived those events, an attacker who had stolen it would keep
    access after the owner "changed everything".
    """
    return db.query(ApiToken).filter(ApiToken.user_id == user.id).delete(
        synchronize_session=False
    )


def find_user(db: Session, token: str) -> Optional[User]:
    """The active user the token belongs to, or None (unknown, expired, user disabled)."""
    if not token.startswith(TOKEN_PREFIX):
        return None
    row = db.query(ApiToken).filter(ApiToken.token_hash == hash_token(token)).first()
    if row is None:
        return None
    now = datetime.now(timezone.utc)
    if row.expires_at is not None and _utc(row.expires_at) <= now:
        return None
    user = db.query(User).filter(User.id == row.user_id).first()
    if user is None or not user.is_active:
        return None
    # An account with a pending forced password change (temporary password after
    # an admin reset) is not fully usable yet, for tokens either.
    if user.must_change_password:
        return None
    if row.last_used_at is None or now - _utc(row.last_used_at) > LAST_USED_RESOLUTION:
        row.last_used_at = now
        db.commit()
    return user
