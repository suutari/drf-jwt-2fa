"""
TOTP (Time-based One-Time Password) utilities.
"""

import pyotp
from django.contrib.auth.models import AbstractBaseUser

from .models import TwoFactorAuthMethod, UserTwoFactorAuthData
from .settings import api_settings


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


def get_totp_secret_for_user(user: AbstractBaseUser) -> str | None:
    """
    Return the active TOTP secret for the given user, or ``None``.

    Look up UserTwoFactorAuthData for the user and return the
    totp_secret field only when preferred_2fa_auth is "totp".
    """
    d = UserTwoFactorAuthData.objects.filter(user=user).first()  # type: ignore
    if not d or d.preferred_2fa_auth != TwoFactorAuthMethod.TOTP:
        return None
    return d.totp_secret


def get_preferred_2fa_method_for_user(user: AbstractBaseUser) -> str:
    """
    Return the preferred 2FA method for the given user.

    Look up UserTwoFactorAuthData for the user and return the
    preferred_2fa_auth field value.  If no record exists, or the stored
    value is "" (NOT_CONFIGURED), fall back to DEFAULT_2FA_AUTH_METHOD.

    Note: "no-2fa" (NO_2FA) is returned as-is; the login flow treats
    both "" and "no-2fa" the same way, controlled by NO_2FA_BEHAVIOR.
    """
    d = UserTwoFactorAuthData.objects.filter(user=user).first()  # type: ignore
    if not d or not d.preferred_2fa_auth:
        return api_settings.DEFAULT_2FA_AUTH_METHOD
    return d.preferred_2fa_auth
