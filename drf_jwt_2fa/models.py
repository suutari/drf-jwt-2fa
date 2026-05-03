from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.utils.translation import gettext_lazy as _

from .settings import api_settings
from .totp import make_sure_is_valid_totp_secret
from .totp_encryption import decrypt_totp_secret, encrypt_totp_secret


class TwoFactorAuthMethod(models.TextChoices):
    NOT_CONFIGURED = "", _("Not configured")
    NO_2FA = "no-2fa", _("No 2FA in use")
    CODE_SENDER = "code-sender", _("Code via sender (e.g. e-mail or SMS)")
    TOTP = "totp", _("TOTP (Time-based One-Time Password)")


class UserTwoFactorAuthData(models.Model):
    """
    Stores 2FA preferences and TOTP secrets for a user.

    This model is optional: the PREFERRED_2FA_METHOD_GETTER and
    TOTP_SECRET_GETTER settings can be configured with custom callables
    that do not use this model at all.  When those settings are left at
    their defaults, this model is used.

    The preferred_2fa_auth field controls which 2FA method is used for
    the user at login time:

      * NOT_CONFIGURED: No 2FA configured for the user.
      * NO_2FA: 2FA explicitly disabled by the user.
      * CODE_SENDER: Send a one-time code via the configured CODE_SENDER
        callable (uses e-mail by default).
      * TOTP: Verify a TOTP code.

    During TOTP enrollment the new secret is initially stored in
    encrypted_totp_secret_pending field.  Only after the user has
    successfully confirmed the first code, it is moved to
    encrypted_totp_secret and preferred_2fa_auth is set to TOTP.

    Use :meth:`get_totp_secret`, :meth:`set_totp_secret`,
    :meth:`get_pending_totp_secret`, and :meth:`set_pending_totp_secret`
    to read and write the secrets; they handle encryption and decryption
    transparently.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="two_factor_auth_data",
        verbose_name=_("user"),
    )
    preferred_2fa_auth = models.CharField(
        max_length=16,
        choices=TwoFactorAuthMethod.choices,
        default=TwoFactorAuthMethod.NOT_CONFIGURED,
        verbose_name=_("preferred 2FA method"),
    )
    encrypted_totp_secret = models.CharField(
        max_length=200,
        blank=True,
        default="",
        verbose_name=_("TOTP secret"),
    )
    encrypted_totp_secret_pending = models.CharField(
        max_length=200,
        blank=True,
        default="",
        verbose_name=_("TOTP secret (pending enrollment)"),
    )

    class Meta:
        verbose_name = _("user two-factor authentication data")
        verbose_name_plural = _("user two-factor authentication data")

    def __str__(self):
        return f"{self.user} ({self.preferred_2fa_auth or '2FA unconfigured'})"

    @classmethod
    def get_totp_secret_of_user(cls, user: AbstractBaseUser) -> str | None:
        """
        Get the active TOTP secret of user.

        Return None if the user has no record or their preferred 2FA
        method is not TOTP.
        """
        d = cls.objects.filter(user=user).first()
        if not d or d.preferred_2fa_auth != TwoFactorAuthMethod.TOTP:
            return None
        return d.get_totp_secret()

    @classmethod
    def get_preferred_2fa_method_of_user(
        cls, user: AbstractBaseUser
    ) -> TwoFactorAuthMethod:
        """
        Get the preferred 2FA method of user.

        Return the preferred_2fa_auth field value.  Return the value
        configured to DEFAULT_2FA_AUTH_METHOD, if no record exists for
        the user or the stored value is still "" (NOT_CONFIGURED).
        """
        d = cls.objects.filter(user=user).first()
        if not d or not d.preferred_2fa_auth:
            return TwoFactorAuthMethod(api_settings.DEFAULT_2FA_AUTH_METHOD)
        return TwoFactorAuthMethod(d.preferred_2fa_auth)

    def get_totp_secret(self) -> str:
        """
        Return the decrypted TOTP secret.
        """
        return decrypt_totp_secret(self.encrypted_totp_secret)

    def set_totp_secret(self, val: str, /) -> None:
        """
        Encrypt TOTP secret and store it to encrypted_totp_secret.
        """
        if val:
            make_sure_is_valid_totp_secret(val)
        self.encrypted_totp_secret = encrypt_totp_secret(val) if val else ""

    def get_pending_totp_secret(self) -> str:
        """
        Return the decrypted pending TOTP secret.
        """
        return decrypt_totp_secret(self.encrypted_totp_secret_pending)

    def set_pending_totp_secret(self, val: str, /) -> None:
        """
        Encrypt TOTP secret and store it to encrypted_totp_secret_pending.
        """
        if val:
            make_sure_is_valid_totp_secret(val)
        encrypted = encrypt_totp_secret(val) if val else ""
        self.encrypted_totp_secret_pending = encrypted
