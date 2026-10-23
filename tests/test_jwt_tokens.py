"""
Login tokens: the library was replaced (python-jose has no fixed release for
its known vulnerability, PyJWT is maintained). These tests pin down the
behaviour that matters.
"""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException

from backend.utils.auth import ALGORITHM, SECRET_KEY, create_access_token, decode_access_token


def test_round_trip():
    token = create_access_token({"sub": "alice"})
    assert decode_access_token(token)["sub"] == "alice"


def test_token_without_expiry_is_rejected():
    token = jwt.encode({"sub": "alice"}, SECRET_KEY, algorithm=ALGORITHM)
    with pytest.raises(HTTPException) as e:
        decode_access_token(token)
    assert e.value.status_code == 401


def test_expired_token_is_rejected():
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    token = jwt.encode({"sub": "alice", "exp": past}, SECRET_KEY, algorithm=ALGORITHM)
    with pytest.raises(HTTPException):
        decode_access_token(token)


def test_token_signed_with_another_key_is_rejected():
    future = datetime.now(timezone.utc) + timedelta(minutes=5)
    token = jwt.encode({"sub": "alice", "exp": future}, "x" * 40, algorithm=ALGORITHM)
    with pytest.raises(HTTPException):
        decode_access_token(token)


def test_unsigned_token_is_rejected():
    future = datetime.now(timezone.utc) + timedelta(minutes=5)
    token = jwt.encode({"sub": "alice", "exp": future}, None, algorithm="none")
    with pytest.raises(HTTPException):
        decode_access_token(token)


def test_wrong_purpose_is_rejected():
    token = create_access_token({"sub": "alice", "purpose": "mfa"})
    with pytest.raises(HTTPException):
        decode_access_token(token)  # a login endpoint must not take an mfa token
    assert decode_access_token(token, purpose="mfa")["sub"] == "alice"
