"""
Audit log for security-relevant actions (user management).

One row per action: who (actor), what (action), whom (target), details.
Never put passwords, tokens or other secrets into ``detail``.
"""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from ..models import AuditEvent, User

logger = logging.getLogger(__name__)

# Action names (stable, shown in the admin UI)
USER_CREATED = "user.created"
USER_UPDATED = "user.updated"
USER_ROLE_CHANGED = "user.role_changed"
USER_ACTIVATED = "user.activated"
USER_DEACTIVATED = "user.deactivated"
USER_UNLOCKED = "user.unlocked"
USER_DELETED = "user.deleted"
USER_PASSWORD_RESET = "user.password_reset"
USER_2FA_RESET = "user.2fa_reset"
USER_SESSIONS_REVOKED = "user.sessions_revoked"
SETTING_REGISTRATION = "setting.registration"
IMPORT_STARTED = "import.started"
SETTING_SMTP = "setting.smtp"
SETTING_SMTP_TEST = "setting.smtp_test"
SETTING_NVD_KEY = "setting.nvd_key"
SETTING_PUBLIC_URL = "setting.public_url"
SETTING_BRANDING = "setting.branding"


def record(
    db: Session,
    actor: Optional[User],
    action: str,
    target: Optional[User] = None,
    detail: Optional[str] = None,
    commit: bool = True,
) -> AuditEvent:
    event = AuditEvent(
        actor_id=actor.id if actor else None,
        actor_username=actor.username if actor else None,
        action=action,
        target_id=target.id if target else None,
        target_username=target.username if target else None,
        detail=detail,
    )
    db.add(event)
    if commit:
        db.commit()
    logger.info(
        "AUDIT %s actor=%s target=%s %s",
        action,
        event.actor_username,
        event.target_username,
        detail or "",
    )
    return event
