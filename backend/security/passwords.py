"""
Password hashing with Argon2id.

Argon2id is the current OWASP recommendation. It is deliberately slow *and*
memory-hungry, which makes GPU/ASIC brute-force attacks expensive.

Existing accounts of the original project use bcrypt. Those hashes stay valid
and are upgraded to Argon2id transparently on the next successful login
(see ``needs_rehash``), so no password reset is needed.
"""

import logging

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

# argon2-cffi defaults follow RFC 9106 (low-memory profile): Argon2id,
# 64 MiB memory, 3 passes, 4 lanes.
_hasher = PasswordHasher()

# Read-only support for legacy hashes of the upstream project.
_legacy = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Upper bound against denial of service through huge inputs.
MAX_PASSWORD_LENGTH = 1024


def hash_password(password: str) -> str:
    """Hash a password with Argon2id (salt is generated and embedded)."""
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError("Password too long")
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify against an Argon2id hash or a legacy bcrypt hash."""
    if not password or not hashed or len(password) > MAX_PASSWORD_LENGTH:
        return False
    try:
        if hashed.startswith("$argon2"):
            return _hasher.verify(hashed, password)
        return _legacy.verify(password, hashed)
    except (VerificationError, InvalidHashError):
        return False
    except Exception as e:  # malformed legacy hash etc.
        logger.error("Password verification error: %s", type(e).__name__)
        return False


def needs_rehash(hashed: str) -> bool:
    """True for legacy bcrypt hashes and Argon2 hashes with outdated parameters."""
    if not hashed.startswith("$argon2"):
        return True
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        return True


# Verifying against this hash for unknown usernames keeps the response time
# the same as for a wrong password, so login timing does not reveal which
# usernames exist.
DUMMY_HASH = _hasher.hash("lynx-dummy-password-for-timing")


def burn_password_check(password: str) -> None:
    """Spend the same time as a real verification (for unknown users)."""
    verify_password(password, DUMMY_HASH)
