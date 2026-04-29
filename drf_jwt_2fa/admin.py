from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .models import UserTwoFactorAuthData


@admin.register(UserTwoFactorAuthData)
class UserTwoFactorAuthDataAdmin(admin.ModelAdmin):
    """
    Admin interface for UserTwoFactorAuthData.

    The TOTP secret fields contain Fernet-encrypted ciphertext and are
    therefore read-only to prevent accidental corruption of the stored
    secrets.
    """

    list_display = ("user", "preferred_2fa_auth", "has_totp_secret")
    list_filter = ("preferred_2fa_auth",)
    search_fields = ("user__username", "user__email")
    readonly_fields = ("user", "totp_secret", "totp_secret_pending")

    @admin.display(boolean=True, description=_("TOTP configured"))
    def has_totp_secret(self, obj):
        return bool(obj.totp_secret)
