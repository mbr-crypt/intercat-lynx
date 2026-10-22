"""
Two-factor authentication logic (database side).

Kept separate from the HTTP layer so the login endpoint, the 2FA management
endpoints and the setup assistant share one implementation.
"""

import hmac
import logging
from typing import List, Optional

from sqlalchemy.orm import Session

from . import crypto, totp

logger = logging.getLogger(__name__)


def _is_totp_code(code: str) -> bool:
    c = (code or "").strip().replace(" ", "")
    return len(c) == totp.DIGITS and c.isdigit()


def begin_setup(user, db: Session) -> str:
    """Create a new (not yet active) secret and store it encrypted."""
    secret = totp.generate_secret()
    user.totp_secret_enc = crypto.encrypt_secret(secret)
    user.totp_enabled = False
    user.totp_last_counter = None
    db.commit()
    return secret


def pending_secret(user) -> Optional[str]:
    if not user.totp_secret_enc:
        return None
    return crypto.decrypt_secret(user.totp_secret_enc)


def confirm_setup(user, code: str, db: Session) -> Optional[List[str]]:
    """
    Activate 2FA once the user proves the app works. Returns the recovery
    codes (shown exactly once) or None if the code was wrong.
    """
    secret = pending_secret(user)
    if not secret or user.totp_enabled:
        return None
    counter = totp.verify_code(secret, code)
    if counter is None:
        return None
    codes = crypto.generate_recovery_codes()
    user.recovery_codes = [crypto.hash_recovery_code(c) for c in codes]
    user.totp_enabled = True
    user.totp_last_counter = counter
    db.commit()
    return codes


def check_second_factor(user, code: str, db: Session) -> bool:
    """Verify a TOTP code (once per time step) or consume a recovery code."""
    if not user.totp_enabled or not user.totp_secret_enc:
        return False

    if _is_totp_code(code):
        counter = totp.verify_code(
            crypto.decrypt_secret(user.totp_secret_enc),
            code,
            last_used_counter=user.totp_last_counter,
        )
        if counter is None:
            return False
        user.totp_last_counter = counter
        db.commit()
        return True

    # Recovery code: single use
    candidate = crypto.hash_recovery_code(code)
    remaining = list(user.recovery_codes or [])
    match = None
    for stored in remaining:
        if hmac.compare_digest(stored, candidate):
            match = stored
    if match is None:
        return False
    remaining.remove(match)
    user.recovery_codes = remaining
    db.commit()
    logger.warning(
        "Recovery code used by %s, %d left", user.username, len(remaining)
    )
    return True


def regenerate_recovery_codes(user, db: Session) -> List[str]:
    codes = crypto.generate_recovery_codes()
    user.recovery_codes = [crypto.hash_recovery_code(c) for c in codes]
    db.commit()
    return codes


def disable(user, db: Session) -> None:
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_last_counter = None
    user.recovery_codes = None
    db.commit()
