import pytest
from django.contrib.auth.models import User

from drf_jwt_2fa.models import TwoFactorAuthMethod, UserTwoFactorAuthData


@pytest.mark.parametrize(
    "preferred, totp_secret, expected",
    [
        (TwoFactorAuthMethod.NOT_CONFIGURED, "", "jane (2FA unconfigured)"),
        (TwoFactorAuthMethod.NO_2FA, "", "jane (no-2fa)"),
        (TwoFactorAuthMethod.CODE_SENDER, "", "jane (code-sender)"),
        (TwoFactorAuthMethod.TOTP, "fake totp secret", "jane (totp)"),
    ],
)
def test_user_two_factor_auth_data_str(preferred, totp_secret, expected):
    user = User(username="jane")
    data = UserTwoFactorAuthData(
        user=user,
        preferred_2fa_auth=preferred,
        totp_secret=totp_secret,
    )
    assert str(data) == expected
