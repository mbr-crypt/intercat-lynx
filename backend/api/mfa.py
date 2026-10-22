"""
Endpoints to manage two-factor authentication (TOTP) of the logged-in user.

Every sensitive step asks for the password again ("re-authentication"), so a
stolen session cannot silently weaken the account.
"""

import io
import logging

import segno
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import get_current_user, require_admin
from ..models import User
from ..schemas.auth import (
    RecoveryCodesResponse,
    TwoFactorConfirm,
    TwoFactorEnable,
    TwoFactorSetupResponse,
    TwoFactorStart,
)
from ..security import mfa, totp
from ..utils.auth import verify_password

logger = logging.getLogger(__name__)

router = APIRouter()


def _require_password(user: User, password: str) -> None:
    if not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Incorrect password"
        )


def qr_svg(uri: str) -> str:
    """QR code as inline SVG (generated on the server, nothing leaves it)."""
    buf = io.BytesIO()
    segno.make(uri, error="m").save(buf, kind="svg", scale=5, border=2, xmldecl=False)
    return buf.getvalue().decode("utf-8")


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_two_factor(
    data: TwoFactorStart,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Step 1: generate a secret and QR code. 2FA is not active until confirmed."""
    if user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is already enabled",
        )
    _require_password(user, data.password)
    secret = mfa.begin_setup(user, db)
    uri = totp.provisioning_uri(secret, user.email)
    return {"secret": secret, "otpauth_uri": uri, "qr_svg": qr_svg(uri)}


@router.post("/2fa/enable", response_model=RecoveryCodesResponse)
async def enable_two_factor(
    data: TwoFactorEnable,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Step 2: confirm with a code from the app. Returns the recovery codes once."""
    codes = mfa.confirm_setup(user, data.code, db)
    if codes is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid code or no setup in progress",
        )
    logger.info(f"2FA enabled: {user.username}")
    return {"recovery_codes": codes}


@router.post("/2fa/disable")
async def disable_two_factor(
    data: TwoFactorConfirm,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Turn 2FA off. Needs the password and a valid code."""
    _require_password(user, data.password)
    if not mfa.check_second_factor(user, data.code, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid verification code"
        )
    mfa.disable(user, db)
    logger.warning(f"2FA disabled: {user.username}")
    return {"message": "Two-factor authentication disabled"}


@router.post("/2fa/recovery-codes", response_model=RecoveryCodesResponse)
async def regenerate_recovery_codes(
    data: TwoFactorConfirm,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Replace all recovery codes by a fresh set (old ones stop working)."""
    if not user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is not enabled",
        )
    _require_password(user, data.password)
    if not mfa.check_second_factor(user, data.code, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid verification code"
        )
    return {"recovery_codes": mfa.regenerate_recovery_codes(user, db)}


@router.put("/users/{user_id}/reset-2fa", dependencies=[Depends(require_admin)])
async def admin_reset_two_factor(user_id: int, db: Session = Depends(get_db)):
    """Admin: remove 2FA from an account whose owner lost phone and recovery codes."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    mfa.disable(target, db)
    logger.warning(f"2FA reset by admin for: {target.username}")
    return {"message": "Two-factor authentication reset"}
