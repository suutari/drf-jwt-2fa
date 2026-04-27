import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="UserTwoFactorAuthData",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "preferred_2fa_auth",
                    models.CharField(
                        choices=[
                            ("", "Not configured"),
                            ("no-2fa", "No 2FA in use"),
                            (
                                "code-sender",
                                "Code via sender (e.g. e-mail or SMS)",
                            ),
                            (
                                "totp",
                                "TOTP (Time-based One-Time Password)",
                            ),
                        ],
                        default="",
                        max_length=16,
                        verbose_name="preferred 2FA method",
                    ),
                ),
                (
                    "totp_secret",
                    models.CharField(
                        blank=True,
                        default="",
                        max_length=200,
                        verbose_name="TOTP secret",
                    ),
                ),
                (
                    "totp_secret_pending",
                    models.CharField(
                        blank=True,
                        default="",
                        max_length=200,
                        verbose_name="TOTP secret (pending enrollment)",
                    ),
                ),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="two_factor_auth_data",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="user",
                    ),
                ),
            ],
            options={
                "verbose_name": "user two-factor authentication data",
                "verbose_name_plural": "user two-factor authentication data",
            },
        ),
    ]
