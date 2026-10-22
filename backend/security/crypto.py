"""
Encryption of secrets stored in the database (e.g. the TOTP secret, SMTP
password, NVD API key).

A TOTP secret must be recoverable (the server needs it to compute codes), so
it cannot be hashed like a password. It is encrypted instead (Fernet =
AES-128-CBC + HMAC-SHA256), so a stolen database dump alone does not reveal
it. The key comes from the environment, not from the database.
"""

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_DEFAULT_SECRET = "change-me-in-production-please-use-strong-secret"


def _master_key() -> bytes:
    key = os.getenv("ENCRYPTION_KEY") or os.getenv("SECRET_KEY") or ""
    if not key or key == _DEFAULT_SECRET:
        raise RuntimeError(
            "ENCRYPTION_KEY (or SECRET_KEY) must be set to a random value; "
            "run the setup assistant or `python -c \"import secrets;"
            "print(secrets.token_urlsafe(48))\"`"
        )
    return key.encode("utf-8")


def _derive(purpose: bytes) -> bytes:
    """Separate keys per purpose from one master key (HKDF-SHA256)."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"lynx:" + purpose
    ).derive(_master_key())


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(_derive(b"secrets-at-rest")))


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as e:
        raise ValueError("Stored secret cannot be decrypted (wrong key?)") from e


# --- recovery codes -------------------------------------------------------

_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o/1/l/i to avoid misreading


def generate_recovery_codes(count: int = 10) -> list:
    """One-time codes for the case that the phone is lost, e.g. ``k7m2q-x9d4f``."""
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def hash_recovery_code(code: str) -> str:
    """Keyed hash (HMAC-SHA256): fast, and useless without the server key."""
    normalized = code.strip().lower().replace(" ", "")
    return hmac.new(
        _derive(b"recovery-codes"), normalized.encode("utf-8"), hashlib.sha256
    ).hexdigest()
