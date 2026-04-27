"""
Serializers for TOTP enrollment (setup and confirm).
"""

from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers

from .models import TwoFactorAuthMethod, UserTwoFactorAuthData
from .settings import api_settings
from .totp import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    get_totp_provisioning_uri,
    verify_totp_code,
)


class SetupTotpSerializer(serializers.Serializer):
    """
    Serializer for the TOTP setup endpoint.

    Generates a new pending TOTP secret for the authenticated user and
    returns the provisioning URI (suitable for converting to a QR code)
    and the raw base32 secret (for manual entry in authenticator apps).

    Call ``save()`` to persist the pending secret and obtain the result
    dict with ``secret`` and ``provisioning_uri`` keys.
    """

    def validate(self, attrs):
        return attrs

    def save(self, **kwargs):
        user = self.context["request"].user
        secret = generate_totp_secret()
        data, _created = UserTwoFactorAuthData.objects.get_or_create(user=user)
        data.totp_secret_pending = encrypt_totp_secret(secret)
        data.save(update_fields=["totp_secret_pending"])
        provisioning_uri = get_totp_provisioning_uri(secret, user)
        return {
            "secret": secret,
            "provisioning_uri": provisioning_uri,
        }


class ConfirmTotpSerializer(serializers.Serializer):
    """
    Serializer for the TOTP confirm endpoint.

    Verifies the first TOTP code against the pending secret and, on
    success, activates TOTP as the user's preferred 2FA method.

    ``validate()`` checks the code and raises on failure.  Call
    ``save()`` to commit the activation to the database.
    """

    code = serializers.CharField(
        write_only=True,
        required=True,
        help_text=_("TOTP code from your authenticator app"),
    )

    def validate(self, attrs):
        user = self.context["request"].user
        data = UserTwoFactorAuthData.objects.filter(user=user).first()
        pending_ciphertext = data.totp_secret_pending if data else None
        pending_secret = decrypt_totp_secret(pending_ciphertext or "")
        if not pending_secret:
            raise exceptions.PermissionDenied(
                _("No pending TOTP setup. Call the setup endpoint first.")
            )

        valid_window = api_settings.TOTP_VALID_WINDOW
        if not verify_totp_code(pending_secret, attrs["code"], valid_window):
            raise exceptions.AuthenticationFailed(_("Invalid TOTP code."))

        # Stash for save(); avoids a second DB query.
        attrs["_data"] = data
        attrs["_pending_secret"] = pending_secret
        return attrs

    def save(self, **kwargs):
        data = self.validated_data["_data"]
        pending_secret = self.validated_data["_pending_secret"]
        data.totp_secret = encrypt_totp_secret(pending_secret)
        data.totp_secret_pending = ""
        data.preferred_2fa_auth = TwoFactorAuthMethod.TOTP
        data.save(
            update_fields=[
                "totp_secret",
                "totp_secret_pending",
                "preferred_2fa_auth",
            ]
        )
        return {}
