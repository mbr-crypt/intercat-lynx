"""Tests for Argon2id hashing, TOTP (RFC 6238) and secret encryption."""

import base64

import pytest
from passlib.hash import bcrypt

from backend.security import crypto, passwords, totp


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "unit-test-key-" + "x" * 40)
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)


# --- passwords -------------------------------------------------------------


def test_new_hashes_are_argon2id():
    h = passwords.hash_password("Correct-Horse-9")
    assert h.startswith("$argon2id$")
    assert passwords.verify_password("Correct-Horse-9", h)
    assert not passwords.verify_password("wrong", h)


def test_hashes_are_salted():
    assert passwords.hash_password("same") != passwords.hash_password("same")


def test_legacy_bcrypt_still_verifies_and_is_flagged_for_upgrade():
    legacy = bcrypt.hash("Old-Password-1")
    assert passwords.verify_password("Old-Password-1", legacy)
    assert not passwords.verify_password("nope", legacy)
    assert passwords.needs_rehash(legacy)
    assert not passwords.needs_rehash(passwords.hash_password("x"))


def test_garbage_and_oversized_input_is_rejected_not_raised():
    assert not passwords.verify_password("a", "not-a-hash")
    assert not passwords.verify_password("a" * 5000, passwords.hash_password("a"))
    with pytest.raises(ValueError):
        passwords.hash_password("a" * 5000)


# --- TOTP: official RFC 6238 test vectors (SHA-1, 8 digits) ------------------

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


@pytest.mark.parametrize(
    "t,expected",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_rfc6238_vectors(t, expected):
    assert totp._hotp(RFC_SECRET, int(t // 30), digits=8) == expected


def test_verify_accepts_current_and_adjacent_step_only():
    s = totp.generate_secret()
    now = 1_700_000_000
    assert totp.verify_code(s, totp.code_at(s, now), now=now) is not None
    assert totp.verify_code(s, totp.code_at(s, now - 30), now=now) is not None
    assert totp.verify_code(s, totp.code_at(s, now - 120), now=now) is None


def test_verify_rejects_malformed_codes():
    s = totp.generate_secret()
    for bad in ["", "12345", "1234567", "abcdef", None]:
        assert totp.verify_code(s, bad) is None


def test_code_cannot_be_replayed():
    s = totp.generate_secret()
    now = 1_700_000_000
    counter = totp.verify_code(s, totp.code_at(s, now), now=now)
    assert counter is not None
    assert totp.verify_code(s, totp.code_at(s, now), now=now, last_used_counter=counter) is None


def test_provisioning_uri_contains_issuer_and_secret():
    uri = totp.provisioning_uri("ABCDEFGH", "moritz", "InterCat Lynx")
    assert uri.startswith("otpauth://totp/InterCat%20Lynx%3Amoritz?secret=ABCDEFGH")
    assert "issuer=InterCat%20Lynx" in uri


# --- crypto -----------------------------------------------------------------


def test_secret_roundtrip_and_ciphertext_differs():
    token = crypto.encrypt_secret("JBSWY3DPEHPK3PXP")
    assert "JBSWY3DP" not in token
    assert crypto.decrypt_secret(token) == "JBSWY3DPEHPK3PXP"


def test_wrong_key_cannot_decrypt(monkeypatch):
    token = crypto.encrypt_secret("secret")
    monkeypatch.setenv("SECRET_KEY", "another-key-" + "y" * 40)
    with pytest.raises(ValueError):
        crypto.decrypt_secret(token)


def test_default_or_missing_key_is_refused(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "change-me-in-production-please-use-strong-secret")
    with pytest.raises(RuntimeError):
        crypto.encrypt_secret("x")
    monkeypatch.delenv("SECRET_KEY")
    with pytest.raises(RuntimeError):
        crypto.encrypt_secret("x")


def test_recovery_codes_are_unique_and_hash_is_normalised():
    codes = crypto.generate_recovery_codes()
    assert len(set(codes)) == 10 and all(len(c) == 11 and c[5] == "-" for c in codes)
    assert crypto.hash_recovery_code(codes[0]) == crypto.hash_recovery_code(
        " " + codes[0].upper() + " "
    )
    assert crypto.hash_recovery_code(codes[0]) != crypto.hash_recovery_code(codes[1])
