"""
Pydantic schemas for authentication and authorization.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, validator

from ..models import UserRole


# User Registration
class UserCreate(BaseModel):
    """Schema for user registration."""

    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100, pattern="^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=8, max_length=100)

    @validator("password")
    def validate_password(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


# User Login
class UserLogin(BaseModel):
    """Schema for user login."""

    username: str
    password: str


# Token Response
class Token(BaseModel):
    """JWT token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class LoginResponse(BaseModel):
    """Login result: either a token, or a request for the second factor."""

    access_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    mfa_required: bool = False
    # Short-lived token that only allows completing the 2FA step
    mfa_token: Optional[str] = None


class TwoFactorLogin(BaseModel):
    """Second step of login."""

    mfa_token: str
    code: str = Field(..., min_length=6, max_length=20)


class TwoFactorSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_svg: str


class TwoFactorEnable(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)


class TwoFactorConfirm(BaseModel):
    """Re-authentication for sensitive 2FA changes."""

    password: str
    code: str = Field(..., min_length=6, max_length=20)


class TwoFactorStart(BaseModel):
    password: str


class RecoveryCodesResponse(BaseModel):
    recovery_codes: list


class TokenData(BaseModel):
    """Data stored in JWT token."""

    user_id: int
    username: str
    email: str
    role: UserRole


# User Response
class UserResponse(BaseModel):
    """Public user information."""

    id: int
    email: str
    username: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login_at: Optional[datetime]
    totp_enabled: bool = False

    class Config:
        from_attributes = True


# User Update
class UserUpdate(BaseModel):
    """Schema for updating user profile."""

    email: Optional[EmailStr] = None


# Password Change
class PasswordChange(BaseModel):
    """Schema for changing password."""

    old_password: str
    new_password: str = Field(..., min_length=8, max_length=100)

    @validator("new_password")
    def validate_password(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


# Admin: Update user role
class UserRoleUpdate(BaseModel):
    """Schema for admin to update user role."""

    role: UserRole
