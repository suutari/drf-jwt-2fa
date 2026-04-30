from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


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
    totp_secret_pending field. Only after the user has successfully
    confirmed the first code, it is moved to totp_secret and
    preferred_2fa_auth is set to TOTP.
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
    totp_secret = models.CharField(
        max_length=200,
        blank=True,
        default="",
        verbose_name=_("TOTP secret"),
    )
    totp_secret_pending = models.CharField(
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
