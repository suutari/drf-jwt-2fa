from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class DrfJwt2faConfig(AppConfig):
    name = "drf_jwt_2fa"
    verbose_name = _("Django Rest Framework JWT 2FA")
    default_auto_field = "django.db.models.BigAutoField"
