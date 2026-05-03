"""
TOTP (Time-based One-Time Password) utilities.
"""

import re

import pyotp
from django.contrib.auth.base_user import AbstractBaseUser

from .settings import api_settings


def make_sure_is_valid_totp_secret(secret: str, /) -> None:
    """
    Raise ValueError if given value is not a valid TOTP secret.
    """
    if not _TOTP_SECRET_RE.match(secret):
        raise ValueError("Invalid TOTP secret")


_TOTP_SECRET_RE = re.compile(r"^[A-Z2-7]{32}$")


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp_code(secret: str, code: str, valid_window: int = 1) -> bool:
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=valid_window)
    except ValueError:
        return False


def get_totp_provisioning_uri(secret: str, user: AbstractBaseUser) -> str:
    """
    Return a provisioning URI for the given user and TOTP secret.

    The URI can be converted to a QR code and scanned by authenticator
    apps.

    :type secret: str
    :type user: django.contrib.auth.models.AbstractBaseUser
    :rtype: str
    """
    issuer = api_settings.TOTP_ISSUER_NAME
    account_name = user.get_username()
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=account_name, issuer_name=issuer)
