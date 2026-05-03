import pytest
from django.contrib.auth.models import User

from drf_jwt_2fa.models import TwoFactorAuthMethod, UserTwoFactorAuthData
from drf_jwt_2fa.totp import generate_totp_secret


@pytest.mark.parametrize(
    "preferred, encrypted_totp_secret, expected",
    [
        (TwoFactorAuthMethod.NOT_CONFIGURED, "", "jane (2FA unconfigured)"),
        (TwoFactorAuthMethod.NO_2FA, "", "jane (no-2fa)"),
        (TwoFactorAuthMethod.CODE_SENDER, "", "jane (code-sender)"),
        (TwoFactorAuthMethod.TOTP, "fake totp secret", "jane (totp)"),
    ],
)
def test_user_two_factor_auth_data_str(
    preferred, encrypted_totp_secret, expected
):
    user = User(username="jane")
    data = UserTwoFactorAuthData(
        user=user,
        preferred_2fa_auth=preferred,
        encrypted_totp_secret=encrypted_totp_secret,
    )
    assert str(data) == expected


def test_get_totp_secret_returns_empty_string_when_not_set():
    data = UserTwoFactorAuthData()
    assert data.get_totp_secret() == ""


def test_set_totp_secret_encrypts_and_get_decrypts():
    secret = generate_totp_secret()
    data = UserTwoFactorAuthData()
    data.set_totp_secret(secret)
    assert data.get_totp_secret() == secret
    # The stored value must be ciphertext, not the plaintext secret.
    assert secret not in data.encrypted_totp_secret
    assert data.encrypted_totp_secret != ""


def test_get_pending_totp_secret_returns_empty_string_when_not_set():
    data = UserTwoFactorAuthData()
    assert data.get_pending_totp_secret() == ""


def test_set_pending_totp_secret_encrypts_and_get_decrypts():
    secret = generate_totp_secret()
    data = UserTwoFactorAuthData()
    data.set_pending_totp_secret(secret)
    assert data.get_pending_totp_secret() == secret
    assert secret not in data.encrypted_totp_secret_pending
    assert data.encrypted_totp_secret_pending != ""


def test_set_totp_secret_clears_when_empty_string():
    data = UserTwoFactorAuthData()
    data.set_totp_secret(generate_totp_secret())
    assert data.encrypted_totp_secret != ""
    data.set_totp_secret("")
    assert data.encrypted_totp_secret == ""
    assert data.get_totp_secret() == ""


def test_set_and_get_are_independent_for_active_and_pending():
    active = generate_totp_secret()
    pending = generate_totp_secret()
    assert active != pending
    data = UserTwoFactorAuthData()
    data.set_totp_secret(active)
    data.set_pending_totp_secret(pending)
    assert data.get_totp_secret() == active
    assert data.get_pending_totp_secret() == pending
