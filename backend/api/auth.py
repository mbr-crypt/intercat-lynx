"""
Authentication endpoints for user registration, login, and management.
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import get_current_user
from ..models import EmailVerification, User, UserRole
from ..schemas.auth import (
    LoginResponse,
    PasswordChange,
    TwoFactorLogin,
    Token,
    UserCreate,
    UserLogin,
    UserResponse,
    UserUpdate,
)
from ..schemas.email_verification import (
    EmailChangeConfirm,
    EmailChangeRequest,
    EmailVerificationConfirm,
    EmailVerificationRequest,
    VerificationResponse,
)
from ..security import attempt_limit, login_throttle, mfa, passwords
from ..services import settings_service, user_service
from ..services.email_service import email_service
from ..utils.client_ip import get_client_ip
from ..utils.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    decode_access_token,
    get_password_hash,
    verify_password,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user account.

    **Requirements:**
    - Unique email and username
    - Strong password (8+ chars, uppercase, lowercase, digit)

    **Default role:** VIEWER

    **Returns:**
    - User profile information
    """
    if not settings_service.registration_allowed(db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is currently closed. Ask an administrator for an account.",
        )

    # Check if email already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken"
        )

    # Check if email was verified
    email_verified = (
        db.query(EmailVerification)
        .filter(
            EmailVerification.email == user_data.email,
            EmailVerification.verification_type == "registration",
            EmailVerification.is_used == True,
        )
        .first()
    )

    # Create new user
    hashed_password = get_password_hash(user_data.password)

    new_user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hashed_password,
        role=UserRole.VIEWER,  # Default role
        is_active=True,
        is_verified=bool(email_verified),  # Set to True if email was verified
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    logger.info(f"New user registered: {new_user.username} ({new_user.email})")

    return new_user


MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 30
MFA_TOKEN_MINUTES = 5


def _register_failure(user: User, db: Session) -> None:
    """Count a failed password/2FA attempt and lock the account after 5."""
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCK_MINUTES)
        logger.warning(f"Account locked due to failed attempts: {user.username}")
    db.commit()


def _is_known_address(user: User, ip: str) -> bool:
    """The address of the user's last completed login."""
    return bool(ip) and ip != "unknown" and user.last_login_ip == ip


def _raise_if_locked(user: User, ip: str) -> None:
    """
    The lockout stops password guessing from strangers. It does NOT apply to
    the address the user last logged in from: otherwise anyone who knows a
    username could lock that person (or the administrator) out at will.
    """
    locked = user.locked_until
    if locked is not None and locked.tzinfo is None:
        locked = locked.replace(tzinfo=timezone.utc)
    if locked and locked > datetime.now(timezone.utc) and not _is_known_address(user, ip):
        logger.warning(f"Login attempt on locked account: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is temporarily locked after too many failed attempts.",
        )


def issue_access_token(user: User) -> dict:
    token = create_access_token(
        {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "tv": user.token_version,
        }
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


def _complete_login(user: User, db: Session, ip: str) -> dict:
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_ip = ip[:45] if ip and ip != "unknown" else None
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    logger.info(f"User logged in: {user.username}")
    return {**issue_access_token(user), "must_change_password": user.must_change_password}


@router.post("/login", response_model=LoginResponse)
async def login(request: Request, credentials: UserLogin, db: Session = Depends(get_db)):
    """
    Login step 1: username and password.

    If the account has two-factor authentication enabled the response contains
    ``mfa_required: true`` and a short-lived ``mfa_token``; finish with
    ``POST /login/2fa``. Otherwise the access token is returned directly.

    **Security:**
    - Passwords are verified against Argon2id (legacy bcrypt hashes are
      accepted and upgraded to Argon2id on success)
    - Unknown users cost the same time as wrong passwords (no user enumeration
      through timing)
    - Account lockout after 5 failed attempts (30 minutes), except for the
      address of the user's last login (so it cannot be used to lock someone out)
    - At most 20 failed attempts per client address in 15 minutes
    """
    ip = get_client_ip(request)
    login_throttle.check(ip)
    user = db.query(User).filter(User.username == credentials.username).first()

    if not user:
        login_throttle.record_failure(ip)
        passwords.burn_password_check(credentials.password)
        logger.warning("Login attempt with non-existent username")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    _raise_if_locked(user, ip)

    if not verify_password(credentials.password, user.hashed_password):
        _register_failure(user, db)
        login_throttle.record_failure(ip)
        logger.warning(f"Failed login attempt for user: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not user.is_active:
        logger.warning(f"Login attempt on inactive account: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Please contact administrator.",
        )

    # Silent upgrade of legacy bcrypt hashes to Argon2id
    if passwords.needs_rehash(user.hashed_password):
        user.hashed_password = get_password_hash(credentials.password)
        db.commit()

    if user.totp_enabled:
        mfa_token = create_access_token(
            {"user_id": user.id, "purpose": "mfa"},
            expires_delta=timedelta(minutes=MFA_TOKEN_MINUTES),
        )
        return {"mfa_required": True, "mfa_token": mfa_token}

    return _complete_login(user, db, ip)


@router.post("/login/2fa", response_model=LoginResponse)
async def login_second_factor(
    request: Request, data: TwoFactorLogin, db: Session = Depends(get_db)
):
    """
    Login step 2: six-digit code from the authenticator app, or a one-time
    recovery code. Failed codes count towards the same lockout as passwords,
    so the 1-in-a-million guess cannot be brute-forced.
    """
    ip = get_client_ip(request)
    login_throttle.check(ip)
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired verification",
    )
    try:
        payload = decode_access_token(data.mfa_token, purpose="mfa")
    except HTTPException:
        raise invalid
    if "user_id" not in payload:
        raise invalid

    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user or not user.is_active or not user.totp_enabled:
        raise invalid

    _raise_if_locked(user, ip)

    if not mfa.check_second_factor(user, data.code, db):
        _register_failure(user, db)
        login_throttle.record_failure(ip)
        logger.warning(f"Failed 2FA attempt for user: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code",
        )

    return _complete_login(user, db, ip)


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """
    Get current user profile.

    **Requires:** Valid JWT token

    **Returns:**
    - User profile information
    """
    return current_user


@router.put("/me", response_model=UserResponse)
async def update_profile(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Update current user profile.

    **Requires:** Valid JWT token

    **Updatable fields:**
    - email (must be unique)

    **Returns:**
    - Updated user profile
    """
    # Update email if provided
    if user_update.email and user_update.email != current_user.email:
        # Check if new email already exists
        existing_user = db.query(User).filter(User.email == user_update.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use"
            )
        current_user.email = user_update.email
        current_user.is_verified = False  # Re-verify email

    current_user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(current_user)

    logger.info(f"User profile updated: {current_user.username}")

    return current_user


@router.post("/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Change user password.

    **Requires:** Valid JWT token

    **Requirements:**
    - Correct old password
    - Strong new password (8+ chars, uppercase, lowercase, digit)

    **Returns:**
    - Success message
    """
    # Verify old password
    if not verify_password(password_data.old_password, current_user.hashed_password):
        logger.warning(f"Failed password change attempt: {current_user.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password"
        )

    if password_data.old_password == password_data.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The new password must differ from the current one",
        )

    # Update password. All other sessions of this account end; this one continues
    # with the fresh token returned below.
    current_user.hashed_password = get_password_hash(password_data.new_password)
    current_user.must_change_password = False
    current_user.token_version += 1
    db.commit()

    logger.info(f"Password changed successfully: {current_user.username}")

    return {
        "message": "Password changed successfully",
        **issue_access_token(current_user),
    }


@router.delete("/me")
async def delete_account(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Delete own user account.

    **Requires:** Valid JWT token

    **Warning:** This action is permanent and cannot be undone!

    **Returns:**
    - Success message
    """
    username = current_user.username

    if current_user.role == UserRole.ADMIN and not (
        db.query(User)
        .filter(User.role == UserRole.ADMIN, User.is_active == True, User.id != current_user.id)
        .count()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You are the last administrator. Make someone else an administrator first.",
        )

    # Delete user account
    user_service.delete_user_and_data(db, current_user)
    db.commit()

    logger.info(f"User account deleted: {username}")

    return {"message": "Account deleted successfully"}


# Admin endpoints for user management live in backend/api/users.py


# ============================================================================
# EMAIL VERIFICATION ENDPOINTS
# ============================================================================


@router.post("/send-verification-code", response_model=VerificationResponse)
async def send_verification_code(
    http_request: Request,
    request: EmailVerificationRequest,
    db: Session = Depends(get_db),
):
    """
    Send verification code to email for registration.

    **Public endpoint** - No authentication required.

    **Use case:** Before registration, verify email ownership.

    **Returns:**
    - Confirmation message
    - Email address
    - Expiry time (15 minutes)
    """
    # Each call sends a mail to an address the caller names, so the number of
    # mails per address and per client has to be limited.
    ip = get_client_ip(http_request)
    attempt_limit.code_sends_by_email.check(request.email)
    attempt_limit.code_sends_by_ip.check(ip)

    # Check if email is already registered
    existing_user = db.query(User).filter(User.email == request.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    attempt_limit.code_sends_by_email.record(request.email)
    attempt_limit.code_sends_by_ip.record(ip)

    # Generate verification code
    code = EmailVerification.generate_code()
    expires_at = EmailVerification.get_expiry_time()

    # Store verification code
    verification = EmailVerification(
        user_id=None,  # No user yet
        email=request.email,
        code=code,
        verification_type="registration",
        expires_at=expires_at,
    )

    db.add(verification)
    db.commit()

    # Send email
    await email_service.send_verification_code(
        email=request.email, code=code, verification_type="registration"
    )

    logger.info(f"Verification code sent to {request.email}")

    return VerificationResponse(
        message="Verification code sent successfully",
        email=request.email,
        expires_in_minutes=15,
    )


@router.post("/verify-email", response_model=dict)
async def verify_email(
    http_request: Request,
    request: EmailVerificationConfirm,
    db: Session = Depends(get_db),
):
    """
    Verify email with code (used during registration).

    **Public endpoint** - No authentication required.

    **Returns:**
    - Success message
    - Verification token (to be used in registration)
    """
    ip = get_client_ip(http_request)
    attempt_limit.code_failures_by_email.check(request.email)
    attempt_limit.code_failures_by_ip.check(ip)

    # Find verification code
    verification = (
        db.query(EmailVerification)
        .filter(
            EmailVerification.email == request.email,
            EmailVerification.code == request.code,
            EmailVerification.verification_type == "registration",
            EmailVerification.is_used == False,
        )
        .order_by(EmailVerification.created_at.desc())
        .first()
    )

    if not verification:
        attempt_limit.code_failures_by_email.record(request.email)
        attempt_limit.code_failures_by_ip.record(ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification code",
        )

    if verification.is_expired():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has expired",
        )

    # Mark as used
    verification.is_used = True
    verification.verified_at = datetime.now(timezone.utc)
    db.commit()

    logger.info(f"Email verified: {request.email}")

    return {
        "message": "Email verified successfully",
        "email": request.email,
        "verified": True,
    }


@router.post("/request-email-change", response_model=VerificationResponse)
async def request_email_change(
    http_request: Request,
    request: EmailChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Request email change - sends verification code to NEW email.

    **Requires:** Authentication

    **Returns:**
    - Confirmation message
    - New email address
    - Expiry time (15 minutes)
    """
    # Check if new email is already in use
    existing_user = (
        db.query(User)
        .filter(User.email == request.new_email, User.id != current_user.id)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use"
        )

    ip = get_client_ip(http_request)
    attempt_limit.code_sends_by_email.check(request.new_email)
    attempt_limit.code_sends_by_ip.check(ip)
    attempt_limit.code_sends_by_email.record(request.new_email)
    attempt_limit.code_sends_by_ip.record(ip)

    # Generate verification code
    code = EmailVerification.generate_code()
    expires_at = EmailVerification.get_expiry_time()

    # Store verification code
    verification = EmailVerification(
        user_id=current_user.id,
        email=request.new_email,
        code=code,
        verification_type="email_change",
        expires_at=expires_at,
    )

    db.add(verification)
    db.commit()

    # Send email to NEW address
    await email_service.send_verification_code(
        email=request.new_email, code=code, verification_type="email_change"
    )

    logger.info(
        f"Email change requested by user {current_user.username}: {request.new_email}"
    )

    return VerificationResponse(
        message="Verification code sent to new email address",
        email=request.new_email,
        expires_in_minutes=15,
    )


@router.post("/confirm-email-change", response_model=dict)
async def confirm_email_change(
    http_request: Request,
    request: EmailChangeConfirm,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Confirm email change with verification code.

    **Requires:** Authentication

    **Returns:**
    - Success message
    - New email address
    """
    ip = get_client_ip(http_request)
    attempt_limit.code_failures_by_email.check(request.new_email)
    attempt_limit.code_failures_by_ip.check(ip)

    # Find verification code
    verification = (
        db.query(EmailVerification)
        .filter(
            EmailVerification.user_id == current_user.id,
            EmailVerification.email == request.new_email,
            EmailVerification.code == request.code,
            EmailVerification.verification_type == "email_change",
            EmailVerification.is_used == False,
        )
        .order_by(EmailVerification.created_at.desc())
        .first()
    )

    if not verification:
        attempt_limit.code_failures_by_email.record(request.new_email)
        attempt_limit.code_failures_by_ip.record(ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification code",
        )

    if verification.is_expired():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has expired",
        )

    # Someone else may have taken the address since the code was sent
    taken = (
        db.query(User)
        .filter(User.email == request.new_email, User.id != current_user.id)
        .first()
    )
    if taken:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use"
        )

    # Update user email
    current_user.email = request.new_email
    current_user.is_verified = True
    current_user.updated_at = datetime.now(timezone.utc)

    # Mark verification as used
    verification.is_used = True
    verification.verified_at = datetime.now(timezone.utc)

    db.commit()

    logger.info(f"Email changed for user {current_user.username}: {request.new_email}")

    return {"message": "Email changed successfully", "new_email": request.new_email}
