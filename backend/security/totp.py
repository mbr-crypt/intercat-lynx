"""
Time-based one-time passwords (TOTP, RFC 6238) - second login factor.

Implemented with the standard library only (HMAC-SHA1 as in RFC 4226), the
same approach as the time tracking project (Zeiterfassung v3.1). It is
compatible with Google Authenticator, Microsoft Authenticator, Aegis, 2FAS,
Bitwarden and similar apps.

Explained for non-specialists: the server and the phone app share a secret.
Both compute a 6-digit number from the secret and the current time (a new one
every 30 seconds). Knowing the password alone is therefore not enough to log in.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Optional
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6
SECRET_BYTES = 20  # 160 bit, the size recommended by RFC 4226


def generate_secret() -> str:
    """New random shared secret, Base32 encoded (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii")


def _hotp(secret_b32: str, counter: int, digits: int = DIGITS) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def code_at(secret_b32: str, for_time: Optional[float] = None) -> str:
    """The valid code for a given moment (used by tests and for verification)."""
    t = time.time() if for_time is None else for_time
    return _hotp(secret_b32, int(t // STEP_SECONDS))


def verify_code(
    secret_b32: str,
    code: str,
    now: Optional[float] = None,
    window: int = 1,
    last_used_counter: Optional[int] = None,
) -> Optional[int]:
    """
    Check a code. Returns the matched time-step counter, or None if invalid.

    ``window=1`` accepts one step before and after to tolerate clock drift.
    A counter that is not newer than ``last_used_counter`` is rejected, so a
    code that was observed (shoulder surfing, phishing proxy) cannot be reused.
    """
    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    t = time.time() if now is None else now
    current = int(t // STEP_SECONDS)
    matched: Optional[int] = None
    for counter in range(current - window, current + window + 1):
        # compare every candidate (no early exit) to keep timing uniform
        if hmac.compare_digest(_hotp(secret_b32, counter), code) and matched is None:
            matched = counter
    if matched is None:
        return None
    if last_used_counter is not None and matched <= last_used_counter:
        return None
    return matched


def provisioning_uri(secret_b32: str, account: str, issuer: str = "InterCat Lynx") -> str:
    """``otpauth://`` link that authenticator apps read from the QR code."""
    label = quote(f"{issuer}:{account}")
    return (
        f"otpauth://totp/{label}?secret={secret_b32}"
        f"&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
