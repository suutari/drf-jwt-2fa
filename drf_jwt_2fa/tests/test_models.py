import pytest
from django.contrib.auth.models import User

from drf_jwt_2fa.models import TwoFactorAuthMethod, UserTwoFactorAuthData
from drf_jwt_2fa.totp import generate_totp_secret

from .factories import get_user
from .utils import OverrideJwt2faSettings


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


@pytest.mark.django_db
def test_get_totp_secret_of_user_returns_none_when_no_record():
    user = get_user()
    assert UserTwoFactorAuthData.get_totp_secret_of_user(user) is None


@pytest.mark.django_db
def test_get_totp_secret_of_user_returns_none_when_method_is_not_totp():
    user = get_user()
    secret = generate_totp_secret()
    d = UserTwoFactorAuthData(
        user=user,
        preferred_2fa_auth=TwoFactorAuthMethod.CODE_SENDER,
    )
    d.set_totp_secret(secret)
    d.save()
    assert UserTwoFactorAuthData.get_totp_secret_of_user(user) is None


@pytest.mark.django_db
def test_get_totp_secret_of_user_returns_secret_when_method_is_totp():
    user = get_user()
    secret = generate_totp_secret()
    d = UserTwoFactorAuthData(
        user=user,
        preferred_2fa_auth=TwoFactorAuthMethod.TOTP,
    )
    d.set_totp_secret(secret)
    d.save()
    assert UserTwoFactorAuthData.get_totp_secret_of_user(user) == secret


@pytest.mark.django_db
@pytest.mark.parametrize("default", ["", "no-2fa", "code-sender"])
def test_get_preferred_2fa_method_of_user_returns_default_when_no_record(
    default,
):
    with OverrideJwt2faSettings(DEFAULT_2FA_AUTH_METHOD=default):
        user = get_user()
        result = UserTwoFactorAuthData.get_preferred_2fa_method_of_user(user)
        assert result == default


@pytest.mark.django_db
@pytest.mark.parametrize("default", ["", "no-2fa", "code-sender"])
def test_get_preferred_2fa_method_of_user_returns_default_when_not_configured(
    default,
):
    with OverrideJwt2faSettings(DEFAULT_2FA_AUTH_METHOD=default):
        user = get_user()
        UserTwoFactorAuthData.objects.create(
            user=user,
            preferred_2fa_auth=TwoFactorAuthMethod.NOT_CONFIGURED,
        )
        result = UserTwoFactorAuthData.get_preferred_2fa_method_of_user(user)
        assert result == default


@pytest.mark.django_db
def test_get_preferred_2fa_method_of_user_returns_code_sender():
    user = get_user()
    UserTwoFactorAuthData.objects.create(
        user=user,
        preferred_2fa_auth=TwoFactorAuthMethod.CODE_SENDER,
    )
    result = UserTwoFactorAuthData.get_preferred_2fa_method_of_user(user)
    assert result == "code-sender"


@pytest.mark.django_db
def test_get_preferred_2fa_method_of_user_returns_totp():
    user = get_user()
    d = UserTwoFactorAuthData(
        user=user,
        preferred_2fa_auth=TwoFactorAuthMethod.TOTP,
    )
    d.set_totp_secret(generate_totp_secret())
    d.save()
    result = UserTwoFactorAuthData.get_preferred_2fa_method_of_user(user)
    assert result == "totp"
