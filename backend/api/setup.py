"""
Setup assistant API - first start of a fresh installation.

Flow (see docs in the vault, "InterCat Lynx - Setup-Assistent"):
  1. status        public, tells the frontend whether the wizard must be shown
  2. checks        system check (database, keys, Redis, internet)
  3. admin         create the root user (Argon2id password)
  4. 2FA           uses the normal /auth/2fa/* endpoints with the returned token
  5. settings      SMTP server, NVD API key, self-registration
  6. import        fill the database with CVE data (background job + progress)
  7. complete      closes the assistant for good

Protection against a stranger finishing the setup first: every step except
``status`` needs the **setup token** (header ``X-Setup-Token``). It is printed
to the server log at start-up (``docker compose logs backend``) or taken from
the environment variable ``SETUP_TOKEN``. After ``complete`` the whole router
answers 404.
"""

import hmac
import logging
import os
import secrets
import socket
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import SessionLocal, get_db
from ..models import AppSetting, User, UserRole
from ..security import attempt_limit, crypto
from ..services import import_job, settings_service
from ..services.email_service import email_service
from ..utils.auth import get_password_hash
from .auth import issue_access_token

logger = logging.getLogger(__name__)

router = APIRouter()

COMPLETED = "setup.completed"
TOKEN_KEY = "setup.token"
ADMIN_MARKER = "setup.admin_created"

COMMON_PASSWORDS = {
    "passwort1234",
    "password1234",
    "123456789012",
    "qwertzuiop12",
    "administrator",
    "changeme1234",
}


# --------------------------------------------------------------------------
# state and token
# --------------------------------------------------------------------------


def is_completed(db: Session) -> bool:
    return settings_service.get(db, COMPLETED) == "true"


def admin_exists(db: Session) -> bool:
    return db.query(User).filter(User.role == UserRole.ADMIN).first() is not None


def ensure_token(db: Session) -> str:
    """
    Setup token from the environment, or a generated one kept in the database.

    The backend runs as several processes (replicas x uvicorn workers) and all
    of them start at the same moment on a fresh installation. Each would
    generate its own token and the last write would win, so the token printed
    in one log would not match the stored one. The table key is unique, so
    exactly one INSERT succeeds; the others roll back and read that winner.
    """
    env_token = os.getenv("SETUP_TOKEN")
    if env_token:
        return env_token
    token = settings_service.get(db, TOKEN_KEY)
    if token:
        return token
    candidate = secrets.token_urlsafe(32)
    try:
        db.add(
            AppSetting(
                key=TOKEN_KEY, value=crypto.encrypt_secret(candidate), is_secret=True
            )
        )
        db.commit()
        return candidate
    except IntegrityError:
        db.rollback()
        winner = settings_service.get(db, TOKEN_KEY)
        if not winner:
            raise
        return winner


def announce_setup_token() -> None:
    """
    Called at start-up. Prints the setup token while the setup is open, and
    closes the assistant automatically on installations that already have an
    admin (upgrade from the original project).
    """
    db = SessionLocal()
    try:
        if is_completed(db):
            return
        if admin_exists(db):
            settings_service.set_value(db, COMPLETED, "true")
            logger.info("Existing admin found - setup assistant not needed")
            return
        token = ensure_token(db)
        # 2 replicas x 2 workers all run this; one message in the log is enough
        if not attempt_limit.claim_once("setup-token-announced", 60):
            return
        logger.warning(
            "\n" + "=" * 64 + "\n"
            "  InterCat Lynx is not set up yet.\n"
            "  Open the web interface and enter this setup token:\n\n"
            f"      {token}\n\n"
            "  (also valid: environment variable SETUP_TOKEN)\n" + "=" * 64
        )
    except Exception as e:
        logger.error("Could not prepare setup token: %s", e)
    finally:
        db.close()


def require_setup(
    x_setup_token: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> Session:
    """Dependency: setup must be open and the caller must know the token."""
    if is_completed(db):
        # Same answer as for a route that does not exist
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    expected = ensure_token(db)
    if not x_setup_token or not hmac.compare_digest(
        x_setup_token.encode(), expected.encode()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid setup token"
        )
    return db


# --------------------------------------------------------------------------
# schemas
# --------------------------------------------------------------------------


class AdminCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100, pattern="^[a-zA-Z0-9_-]+$")
    email: EmailStr
    full_name: Optional[str] = Field(default=None, max_length=255)
    # Length matters more than complexity rules (NIST SP 800-63B)
    password: str = Field(..., min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def not_trivial(cls, v: str) -> str:
        if v.lower() in COMMON_PASSWORDS or len(set(v)) < 5:
            raise ValueError("Password is too easy to guess")
        return v


class SmtpSettings(BaseModel):
    enabled: bool = True
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(default=587, ge=1, le=65535)
    security: str = Field(default="starttls", pattern="^(starttls|ssl|none)$")
    username: Optional[str] = Field(default=None, max_length=255)
    password: Optional[str] = Field(default=None, max_length=512)
    from_email: EmailStr
    from_name: str = Field(default="InterCat Lynx", max_length=100)


class SetupSettings(BaseModel):
    smtp: Optional[SmtpSettings] = None
    nvd_api_key: Optional[str] = Field(default=None, max_length=100)
    registration_enabled: bool = False


class SmtpTest(BaseModel):
    to: EmailStr


class ImportStart(BaseModel):
    mode: str = Field(..., pattern="^(recent|full|skip)$")
    days: int = Field(default=30, ge=1, le=120)


class CompleteRequest(BaseModel):
    # Explicit acknowledgement if the admin runs without a second factor
    acknowledge_no_2fa: bool = False


# --------------------------------------------------------------------------
# endpoints
# --------------------------------------------------------------------------


@router.get("/status")
async def setup_status(db: Session = Depends(get_db)):
    """Public. Tells the frontend whether to show the assistant."""
    completed = is_completed(db)
    return {"setup_required": not completed, "admin_exists": admin_exists(db) if not completed else True}


@router.post("/verify-token")
async def verify_token(db: Session = Depends(require_setup)):
    return {"valid": True, "admin_exists": admin_exists(db)}


def _check(name: str, ok: bool, detail: str, required: bool = True) -> dict:
    return {
        "name": name,
        "ok": ok,
        "required": required,
        "detail": detail,
    }


@router.get("/checks")
async def system_checks(db: Session = Depends(require_setup)):
    """System check shown as the first step."""
    checks = []

    try:
        db.execute(text("SELECT 1"))
        checks.append(_check("Datenbank", True, "Verbindung funktioniert"))
    except Exception as e:
        checks.append(_check("Datenbank", False, f"Nicht erreichbar: {type(e).__name__}"))

    key = os.getenv("SECRET_KEY", "")
    key_ok = len(key) >= 32 and not key.startswith("change-me")
    checks.append(
        _check(
            "Geheimer Schlüssel (SECRET_KEY)",
            key_ok,
            "Zufälliger Schlüssel gesetzt"
            if key_ok
            else "Fehlt oder zu kurz. In .env einen zufälligen Wert mit mindestens 32 Zeichen setzen "
            "und das Backend neu starten",
        )
    )

    try:
        crypto.decrypt_secret(crypto.encrypt_secret("probe"))
        checks.append(_check("Verschlüsselung gespeicherter Geheimnisse", True, "Funktioniert"))
    except Exception as e:
        checks.append(_check("Verschlüsselung gespeicherter Geheimnisse", False, str(e)))

    try:
        from ..api.stats import redis_client

        redis_client.ping()
        checks.append(_check("Redis (Zwischenspeicher)", True, "Erreichbar", required=False))
    except Exception:
        checks.append(
            _check(
                "Redis (Zwischenspeicher)",
                False,
                "Nicht erreichbar. Die Seite läuft trotzdem, nur ohne Zwischenspeicher "
                "und ohne Begrenzung der Anfragen",
                required=False,
            )
        )

    try:
        socket.create_connection(("services.nvd.nist.gov", 443), timeout=5).close()
        checks.append(_check("Internetzugang zur NVD", True, "Erreichbar", required=False))
    except Exception:
        checks.append(
            _check(
                "Internetzugang zur NVD",
                False,
                "Nicht erreichbar. Ohne ihn kann der Datenimport nicht laufen "
                "(Firewall/Proxy prüfen)",
                required=False,
            )
        )

    return {
        "checks": checks,
        "can_continue": all(c["ok"] for c in checks if c["required"]),
    }


@router.post("/admin", status_code=status.HTTP_201_CREATED)
async def create_admin(data: AdminCreate, db: Session = Depends(require_setup)):
    """Create the root user. Possible exactly once."""
    if admin_exists(db):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Admin already exists")

    pwd_l = data.password.lower()
    if data.username.lower() in pwd_l or data.email.split("@")[0].lower() in pwd_l:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must not contain the username or e-mail name",
        )

    try:
        # The marker is a primary key: of two simultaneous requests only one
        # can insert it, the other fails -> no two root users by a race.
        db.add(AppSetting(key=ADMIN_MARKER, value=datetime.now(timezone.utc).isoformat()))
        db.flush()
        user = User(
            email=data.email,
            username=data.username,
            full_name=data.full_name,
            hashed_password=get_password_hash(data.password),
            role=UserRole.ADMIN,
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Admin already exists")

    db.refresh(user)
    logger.info("Setup: root user created: %s", user.username)
    return {"user_id": user.id, "username": user.username, **issue_access_token(user)}


@router.put("/settings")
async def save_settings(data: SetupSettings, db: Session = Depends(require_setup)):
    """SMTP, NVD API key and registration policy. Secrets are stored encrypted."""
    if data.smtp:
        s = data.smtp
        settings_service.set_value(db, "smtp.enabled", "true" if s.enabled else "false")
        settings_service.set_value(db, "smtp.host", s.host)
        settings_service.set_value(db, "smtp.port", str(s.port))
        settings_service.set_value(db, "smtp.security", s.security)
        settings_service.set_value(db, "smtp.username", s.username or "")
        if s.password:
            settings_service.set_value(db, "smtp.password", s.password, secret=True)
        settings_service.set_value(db, "smtp.from_email", s.from_email)
        settings_service.set_value(db, "smtp.from_name", s.from_name)
    if data.nvd_api_key:
        settings_service.set_value(db, "nvd.api_key", data.nvd_api_key.strip(), secret=True)
    settings_service.set_value(
        db, "registration.enabled", "true" if data.registration_enabled else "false"
    )
    return {
        "smtp_configured": settings_service.is_set(db, "smtp.host"),
        "nvd_api_key_set": settings_service.is_set(db, "nvd.api_key"),
        "registration_enabled": data.registration_enabled,
    }


@router.post("/smtp-test")
async def smtp_test(data: SmtpTest, db: Session = Depends(require_setup)):
    ok, error = await email_service.send_test_email(data.to)
    return {"ok": ok, "error": error}


@router.post("/import")
async def start_import(data: ImportStart, db: Session = Depends(require_setup)):
    if data.mode == "skip":
        return {"started": False, "skipped": True}
    started = import_job.start_in_background(SessionLocal, data.mode, data.days)
    if not started:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Import already running")
    return {"started": True}


@router.get("/import/status")
async def import_status(db: Session = Depends(require_setup)):
    return import_job.read_status(db)


@router.post("/complete")
async def complete_setup(data: CompleteRequest, db: Session = Depends(require_setup)):
    """Close the assistant. Requires an admin; a second factor unless acknowledged."""
    admin = db.query(User).filter(User.role == UserRole.ADMIN).first()
    if not admin:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Create the root user first")
    if not admin.totp_enabled and not data.acknowledge_no_2fa:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enable two-factor authentication for the root user, "
            "or explicitly confirm to continue without it",
        )
    settings_service.set_value(db, COMPLETED, "true")
    settings_service.delete(db, TOKEN_KEY)
    logger.info("Setup completed")
    return {"completed": True}
