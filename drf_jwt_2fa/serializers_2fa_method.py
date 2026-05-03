"""
Serializer for the set-2fa-method endpoint.
"""

from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers

from .models import TwoFactorAuthMethod, UserTwoFactorAuthData
from .settings import api_settings


class Set2faMethodSerializer(serializers.Serializer):
    """
    Allows an authenticated user to change their preferred 2FA method.
    The ``method`` field accepts ``"code-sender"``, ``"totp"``, or
    ``"no-2fa"``.

    Constraints:

    * ``"no-2fa"`` is only accepted when the ``NO_2FA_BEHAVIOR`` setting
      is ``"allow"``; otherwise a ``PermissionDenied`` error is raised.
    * ``"totp"`` is only accepted when the user already has an active
      TOTP secret enrolled (i.e. :meth:`~.models.UserTwoFactorAuthData.\
get_totp_secret` returns a non-empty value); otherwise a
      ``PermissionDenied`` error is raised.

    Call ``save()`` to persist the new preferred method.
    """

    method = serializers.ChoiceField(
        choices=[(x.value, x.label) for x in TwoFactorAuthMethod if x.value],
        help_text=_("Preferred 2FA method"),
    )

    def validate(self, attrs):
        method = attrs["method"]
        user = self.context["request"].user

        can_2fa_be_disabled = api_settings.NO_2FA_BEHAVIOR == "allow"
        if method == TwoFactorAuthMethod.NO_2FA and not can_2fa_be_disabled:
            raise exceptions.PermissionDenied(
                _("Disabling 2FA is not allowed.")
            )

        if method == TwoFactorAuthMethod.TOTP:
            data = UserTwoFactorAuthData.objects.filter(user=user).first()
            if not (data and data.get_totp_secret()):
                raise exceptions.PermissionDenied(
                    _("No active TOTP secret. Complete TOTP enrollment first.")
                )

        return attrs

    def save(self, **kwargs):
        user = self.context["request"].user
        method = self.validated_data["method"]
        UserTwoFactorAuthData.objects.update_or_create(
            user=user,
            defaults={"preferred_2fa_auth": method},
        )
        return {}
