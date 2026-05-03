"""
Getter functions used by the default settings.
"""

from django.contrib.auth.base_user import AbstractBaseUser

from .models import UserTwoFactorAuthData


def get_totp_secret_of_user(user: AbstractBaseUser) -> str | None:
    """
    Get active TOTP secret of user.
    """
    return UserTwoFactorAuthData.get_totp_secret_of_user(user)


def get_preferred_2fa_method_of_user(user: AbstractBaseUser) -> str:
    """
    Get preferred 2FA method of user.
    """
    return UserTwoFactorAuthData.get_preferred_2fa_method_of_user(user)
