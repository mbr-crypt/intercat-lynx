"""
How the signed-in user wants to be told about CVEs for the products they follow.

Everything is scoped to the caller. The webhook secret is shown once (when it is
created or renewed) and stored encrypted; the settings never return it again.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import get_current_user
from ..models import NotificationSetting, User
from ..schemas.notification_settings import (
    NotificationSettingsOut,
    NotificationSettingsUpdate,
    SecretOut,
    TestResult,
)
from ..security.crypto import encrypt_secret
from ..services import product_alert_service as alerts
from ..services import watchlist_service as wl
from ..services.email_service import email_service

logger = logging.getLogger(__name__)

router = APIRouter()


def _out(user: User, s: NotificationSetting, new_secret: str = None) -> NotificationSettingsOut:
    return NotificationSettingsOut(
        in_app_enabled=s.in_app_enabled,
        email_enabled=s.email_enabled,
        email_address=user.email,
        smtp_configured=email_service.smtp_enabled,
        webhook_enabled=s.webhook_enabled,
        webhook_url=s.webhook_url,
        webhook_has_secret=bool(s.webhook_secret_encrypted),
        min_severity=s.min_severity,
        always_exploited=s.always_exploited,
        last_email_ok_at=s.last_email_ok_at,
        last_email_error=s.last_email_error,
        last_webhook_ok_at=s.last_webhook_ok_at,
        last_webhook_error=s.last_webhook_error,
        new_webhook_secret=new_secret,
    )


@router.get("", response_model=NotificationSettingsOut)
async def read_settings(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _out(user, alerts.get_or_create_settings(db, user))


@router.put("", response_model=NotificationSettingsOut)
async def update_settings(
    data: NotificationSettingsUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    setting = alerts.get_or_create_settings(db, user)
    changes = data.model_dump(exclude_unset=True)

    if "min_severity" in changes:
        value = (changes["min_severity"] or "").upper()
        if value not in wl.SEVERITIES:
            raise HTTPException(
                status_code=422, detail="min_severity must be low, medium, high or critical"
            )
        changes["min_severity"] = value

    if "webhook_url" in changes:
        url = (changes["webhook_url"] or "").strip()
        if url:
            try:
                alerts.validate_webhook_url(url)
            except ValueError as e:
                raise HTTPException(status_code=422, detail=str(e))
        changes["webhook_url"] = url or None

    for key, value in changes.items():
        if value is not None or key == "webhook_url":
            setattr(setting, key, value)

    new_secret = None
    if setting.webhook_enabled:
        if not setting.webhook_url:
            raise HTTPException(status_code=422, detail="Für den Webhook fehlt die Adresse.")
        if not setting.webhook_secret_encrypted:
            new_secret = alerts.new_webhook_secret()
            setting.webhook_secret_encrypted = encrypt_secret(new_secret)

    db.commit()
    db.refresh(setting)
    return _out(user, setting, new_secret)


@router.post("/webhook/secret", response_model=SecretOut)
async def renew_webhook_secret(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """New signing secret. The old one stops working at once; shown only here."""
    setting = alerts.get_or_create_settings(db, user)
    secret = alerts.new_webhook_secret()
    setting.webhook_secret_encrypted = encrypt_secret(secret)
    db.commit()
    return SecretOut(secret=secret)


@router.post("/test/{channel}", response_model=TestResult)
async def send_test(
    channel: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Send one sample message over the channel so the user can check the setup."""
    if channel not in ("email", "webhook"):
        raise HTTPException(status_code=404, detail="Unknown channel")
    setting = alerts.get_or_create_settings(db, user)
    ok, error = alerts.send_test(db, user, setting, channel)
    return TestResult(ok=ok, error=error)
