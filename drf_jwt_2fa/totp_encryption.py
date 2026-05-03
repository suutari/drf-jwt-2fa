"""
Fernet-based encryption helpers for TOTP secrets.
"""

import base64

from cryptography.fernet import Fernet, InvalidToken

from .settings import api_settings


def encrypt_totp_secret(secret: str) -> str:
    """
    Encrypt a TOTP secret for storage.

    Encrypt given secret using Fernet symmetric encryption with the key
    from ``TOTP_ENCRYPTION_KEY`` and return the resulting ciphertext as
    a URL-safe base64 string suitable for storing in a ``CharField``.

    Use :func:`decrypt_totp_secret` to reverse the operation.
    """
    fernet = _get_fernet()
    return fernet.encrypt(secret.encode()).decode()


def decrypt_totp_secret(ciphertext: str) -> str:
    """
    Decrypt a TOTP secret retrieved from storage.

    Return the decrypted secret value or empty string if ciphertext is
    empty, invalid, or was encrypted with a different key.
    """
    if not ciphertext:
        return ""
    try:
        fernet = _get_fernet()
        return fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        return ""


def _get_fernet() -> Fernet:
    raw_key: bytes = api_settings.TOTP_ENCRYPTION_KEY
    key = base64.urlsafe_b64encode(raw_key)
    return Fernet(key)
