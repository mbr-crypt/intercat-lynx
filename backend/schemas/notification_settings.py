"""Schemas for the per-user alert settings."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class NotificationSettingsOut(BaseModel):
    in_app_enabled: bool
    email_enabled: bool
    email_address: str
    smtp_configured: bool
    webhook_enabled: bool
    webhook_url: Optional[str] = None
    webhook_has_secret: bool
    min_severity: str
    always_exploited: bool
    last_email_ok_at: Optional[datetime] = None
    last_email_error: Optional[str] = None
    last_webhook_ok_at: Optional[datetime] = None
    last_webhook_error: Optional[str] = None
    # Shown exactly once, when the secret was created or renewed
    new_webhook_secret: Optional[str] = None


class NotificationSettingsUpdate(BaseModel):
    """Only the given fields are changed."""

    in_app_enabled: Optional[bool] = None
    email_enabled: Optional[bool] = None
    webhook_enabled: Optional[bool] = None
    webhook_url: Optional[str] = Field(None, max_length=1000)
    min_severity: Optional[str] = None
    always_exploited: Optional[bool] = None


class TestResult(BaseModel):
    ok: bool
    error: Optional[str] = None


class SecretOut(BaseModel):
    secret: str
