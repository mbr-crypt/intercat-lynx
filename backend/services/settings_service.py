"""
Runtime settings stored in the database (table ``app_settings``).

The setup assistant writes here (SMTP server, NVD API key, setup state).
Lookup order for runtime values: database first, then the environment
variable, then the default - so Docker/.env based installations keep working.

Values flagged ``secret`` (passwords, API keys) are encrypted with
``backend.security.crypto`` and are never returned by the API.
"""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from ..models import AppSetting
from ..security import crypto

logger = logging.getLogger(__name__)


def get(db: Session, key: str, default: Optional[str] = None) -> Optional[str]:
    row = db.get(AppSetting, key)
    if row is None or row.value is None:
        return default
    if row.is_secret:
        try:
            return crypto.decrypt_secret(row.value)
        except ValueError:
            logger.error("Setting %s cannot be decrypted (key changed?)", key)
            return default
    return row.value


def set_value(db: Session, key: str, value: Optional[str], secret: bool = False) -> None:
    stored = value
    if value is not None and secret:
        stored = crypto.encrypt_secret(value)
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=stored, is_secret=secret))
    else:
        row.value = stored
        row.is_secret = secret
    db.commit()


def delete(db: Session, key: str) -> None:
    row = db.get(AppSetting, key)
    if row is not None:
        db.delete(row)
        db.commit()


def is_set(db: Session, key: str) -> bool:
    row = db.get(AppSetting, key)
    return row is not None and bool(row.value)


def registration_allowed(db: Session) -> bool:
    """
    Self-registration is closed until the setup assistant is finished (so that
    nobody can register before the root user exists) and afterwards follows
    the choice made in the assistant (default for upgraded installs: open).
    """
    if get(db, "setup.completed") != "true":
        return False
    return get(db, "registration.enabled", "true") != "false"


def runtime(key: str, env_name: str, default: Optional[str] = None) -> Optional[str]:
    """
    Effective value for code that has no request session (Celery tasks, the
    e-mail service): database > environment > default. Never raises - a
    database problem must not break sending mail or fetching data.
    """
    import os

    try:
        from ..database import SessionLocal

        db = SessionLocal()
        try:
            value = get(db, key)
        finally:
            db.close()
        if value not in (None, ""):
            return value
    except Exception as e:
        logger.debug("Runtime setting %s not read from database: %s", key, e)
    return os.getenv(env_name, default)
