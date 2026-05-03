"""
Tests for drf_jwt_2fa.totp_encryption.
"""

from drf_jwt_2fa.totp import generate_totp_secret
from drf_jwt_2fa.totp_encryption import (
    decrypt_totp_secret,
    encrypt_totp_secret,
)


def test_encrypt_decrypt_roundtrip():
    secret = generate_totp_secret()
    ciphertext = encrypt_totp_secret(secret)
    assert ciphertext != secret
    assert decrypt_totp_secret(ciphertext) == secret


def test_encrypt_produces_different_ciphertext_each_time():
    """Fernet uses a random IV so the same plaintext encrypts differently."""
    secret = generate_totp_secret()
    assert encrypt_totp_secret(secret) != encrypt_totp_secret(secret)


def test_decrypt_returns_empty_string_for_empty_string():
    assert decrypt_totp_secret("") == ""


def test_decrypt_returns_empty_string_for_invalid_ciphertext():
    assert decrypt_totp_secret("not-valid-fernet-token") == ""
