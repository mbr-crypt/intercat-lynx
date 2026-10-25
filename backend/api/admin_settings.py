"""
"Einstellungen" page of the administration (Admin only).

Takes over what only the setup assistant could change before: mail server
(SMTP) with a test mail, NVD API key, self-registration, the public address of
the installation and the branding (name, colour, footer text, logos).

Lookup order for every value stays: database, then environment variable, then
default. The page shows where the effective value comes from (``source``), so
an administrator can see why a change in ``.env`` has no effect.

Secrets (SMTP password, NVD key) are stored encrypted and are never sent back,
only whether one is set. Nothing secret goes into the audit log.
"""

import os
from typing import Optional, Tuple
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import require_admin
from ..models import User
from ..services import audit_service, branding_service, settings_service
from ..services.email_service import email_service
from .setup import SmtpSettings

router = APIRouter()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _effective(db: Session, key: str, env_name: str, default: str = "") -> Tuple[str, str]:
    """(value, source) with source "db", "env" or "default"."""
    value = settings_service.get(db, key)
    if value not in (None, ""):
        return value, "db"
    env = os.getenv(env_name)
    if env not in (None, ""):
        return env, "env"
    return default, "default"


def _is_true(value: str) -> bool:
    return str(value).lower() == "true"


def _public_url(value: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or " " in value:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Die öffentliche Adresse muss mit http:// oder https:// beginnen",
        )
    return value


def _view(db: Session) -> dict:
    smtp_enabled, smtp_enabled_src = _effective(db, "smtp.enabled", "SMTP_ENABLED", "false")
    host, host_src = _effective(db, "smtp.host", "SMTP_HOST")
    port, _ = _effective(db, "smtp.port", "SMTP_PORT", "587")
    security, _ = _effective(db, "smtp.security", "SMTP_SECURITY", "starttls")
    username, _ = _effective(db, "smtp.username", "SMTP_USERNAME")
    from_email, _ = _effective(db, "smtp.from_email", "SMTP_FROM_EMAIL")
    from_name, _ = _effective(db, "smtp.from_name", "SMTP_FROM_NAME", "InterCat Lynx")
    password_set = settings_service.is_set(db, "smtp.password") or bool(os.getenv("SMTP_PASSWORD"))
    nvd_set_db = settings_service.is_set(db, "nvd.api_key")
    nvd_set = nvd_set_db or bool(os.getenv("NVD_API_KEY"))
    public_url, public_url_src = _effective(db, "app.public_url", "PUBLIC_URL")

    branding = branding_service.get_branding(db)
    return {
        "smtp": {
            "enabled": _is_true(smtp_enabled),
            "host": host,
            "port": int(port) if str(port).isdigit() else 587,
            "security": security if security in ("starttls", "ssl", "none") else "starttls",
            "username": username,
            "password_set": password_set,
            "from_email": from_email,
            "from_name": from_name,
            "source": host_src if host else smtp_enabled_src,
        },
        "nvd": {"api_key_set": nvd_set, "source": "db" if nvd_set_db else ("env" if nvd_set else "default")},
        "registration_enabled": settings_service.get(db, "registration.enabled", "true") != "false",
        "public_url": public_url,
        "public_url_source": public_url_src,
        "branding": {
            "name": branding["name"],
            "name_is_default": not settings_service.is_set(db, branding_service.NAME_KEY),
            "accent": branding["accent"] or "",
            "footer_text": branding["footer_text"] or "",
            "url": branding["url"] or "",
            "has_logo_light": settings_service.is_set(db, branding_service.LOGO_KEYS["light"]),
            "has_logo_dark": settings_service.is_set(db, branding_service.LOGO_KEYS["dark"]),
            "logo_light": branding["logo_light"],
            "logo_dark": branding["logo_dark"],
            "default_name": branding_service.DEFAULT_NAME,
        },
    }


# --------------------------------------------------------------------------
# schemas
# --------------------------------------------------------------------------


class BrandingUpdate(BaseModel):
    """Every field: None = unchanged, empty text = back to the default."""

    name: Optional[str] = Field(default=None, max_length=200)
    accent: Optional[str] = Field(default=None, max_length=20)
    footer_text: Optional[str] = Field(default=None, max_length=1000)
    url: Optional[str] = Field(default=None, max_length=1000)


class SettingsUpdate(BaseModel):
    smtp: Optional[SmtpSettings] = None
    # "" removes the stored key; None leaves it as it is
    nvd_api_key: Optional[str] = Field(default=None, max_length=100)
    clear_smtp_password: bool = False
    registration_enabled: Optional[bool] = None
    public_url: Optional[str] = Field(default=None, max_length=255)
    branding: Optional[BrandingUpdate] = None


class SmtpTest(BaseModel):
    to: EmailStr


# --------------------------------------------------------------------------
# endpoints
# --------------------------------------------------------------------------


@router.get("")
async def get_settings(
    current_user: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """Effective settings (secrets only as "set / not set")."""
    return _view(db)


@router.put("")
async def update_settings(
    data: SettingsUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Save the changed parts. Everything is checked before anything is written."""
    # --- check first
    branding_changes = {}
    if data.branding is not None:
        b = data.branding
        try:
            if b.name is not None:
                branding_changes[branding_service.NAME_KEY] = (
                    branding_service.clean_name(b.name) if b.name.strip() else ""
                )
            if b.accent is not None:
                branding_changes[branding_service.ACCENT_KEY] = (
                    branding_service.clean_accent(b.accent) if b.accent.strip() else ""
                )
            if b.footer_text is not None:
                branding_changes[branding_service.FOOTER_KEY] = branding_service.clean_footer(b.footer_text)
            if b.url is not None:
                branding_changes[branding_service.URL_KEY] = (
                    branding_service.clean_url(b.url) if b.url.strip() else ""
                )
        except branding_service.BrandingError as e:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    public_url = None
    if data.public_url is not None:
        public_url = _public_url(data.public_url) if data.public_url.strip() else ""

    # --- then write
    if data.smtp is not None:
        s = data.smtp
        settings_service.set_value(db, "smtp.enabled", "true" if s.enabled else "false")
        settings_service.set_value(db, "smtp.host", s.host.strip())
        settings_service.set_value(db, "smtp.port", str(s.port))
        settings_service.set_value(db, "smtp.security", s.security)
        settings_service.set_value(db, "smtp.username", (s.username or "").strip())
        settings_service.set_value(db, "smtp.from_email", str(s.from_email))
        settings_service.set_value(db, "smtp.from_name", s.from_name.strip() or "InterCat Lynx")
        password_note = "unchanged"
        if s.password:
            settings_service.set_value(db, "smtp.password", s.password, secret=True)
            password_note = "changed"
        elif data.clear_smtp_password:
            settings_service.delete(db, "smtp.password")
            password_note = "removed"
        audit_service.record(
            db,
            current_user,
            audit_service.SETTING_SMTP,
            detail=f"host={s.host.strip()} port={s.port} security={s.security} "
            f"enabled={'yes' if s.enabled else 'no'} password={password_note}",
        )

    if data.nvd_api_key is not None:
        key = data.nvd_api_key.strip()
        if key:
            settings_service.set_value(db, "nvd.api_key", key, secret=True)
        else:
            settings_service.delete(db, "nvd.api_key")
        audit_service.record(
            db, current_user, audit_service.SETTING_NVD_KEY, detail="set" if key else "removed"
        )

    if data.registration_enabled is not None:
        settings_service.set_value(
            db, "registration.enabled", "true" if data.registration_enabled else "false"
        )
        audit_service.record(
            db,
            current_user,
            audit_service.SETTING_REGISTRATION,
            detail="open" if data.registration_enabled else "closed",
        )

    if public_url is not None:
        branding_service.set_text(db, "app.public_url", public_url)
        audit_service.record(
            db,
            current_user,
            audit_service.SETTING_PUBLIC_URL,
            detail=public_url or "removed",
        )

    if branding_changes:
        for key, value in branding_changes.items():
            branding_service.set_text(db, key, value)
        branding_service.touch(db)
        names = {
            branding_service.NAME_KEY: "name",
            branding_service.ACCENT_KEY: "accent",
            branding_service.FOOTER_KEY: "footer",
            branding_service.URL_KEY: "url",
        }
        audit_service.record(
            db,
            current_user,
            audit_service.SETTING_BRANDING,
            detail="changed: " + ", ".join(names[k] for k in branding_changes),
        )

    return _view(db)


@router.post("/smtp-test")
async def smtp_test(
    data: SmtpTest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Send a real test mail with the saved settings."""
    ok, error = await email_service.send_test_email(str(data.to))
    audit_service.record(
        db, current_user, audit_service.SETTING_SMTP_TEST, detail="ok" if ok else "failed"
    )
    return {"ok": ok, "error": error}


@router.put("/branding/logo/{variant}")
async def upload_logo(
    variant: str,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Upload a logo as the raw request body (PNG, JPEG or WebP, at most 512 KB).
    ``variant`` is ``light`` (for the light scheme) or ``dark`` (for the dark scheme).
    """
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > branding_service.MAX_LOGO_BYTES + 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Das Logo darf höchstens {branding_service.MAX_LOGO_BYTES // 1024} KB groß sein",
        )
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > branding_service.MAX_LOGO_BYTES + 1024:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Das Logo darf höchstens {branding_service.MAX_LOGO_BYTES // 1024} KB groß sein",
            )
    try:
        branding_service.set_logo(db, variant, body)
    except branding_service.BrandingError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    branding_service.touch(db)
    audit_service.record(
        db, current_user, audit_service.SETTING_BRANDING, detail=f"logo_{variant}: uploaded"
    )
    return _view(db)


@router.delete("/branding/logo/{variant}")
async def remove_logo(
    variant: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        branding_service.delete_logo(db, variant)
    except branding_service.BrandingError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    branding_service.touch(db)
    audit_service.record(
        db, current_user, audit_service.SETTING_BRANDING, detail=f"logo_{variant}: removed"
    )
    return _view(db)
