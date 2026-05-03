from unittest.mock import Mock

import pyotp
import pytest

from drf_jwt_2fa.models import TwoFactorAuthMethod, UserTwoFactorAuthData
from drf_jwt_2fa.totp import (
    generate_totp_secret,
    get_preferred_2fa_method_for_user,
    get_totp_provisioning_uri,
    get_totp_secret_for_user,
    verify_totp_code,
)

from .factories import get_user
from .utils import OverrideJwt2faSettings


def test_generate_totp_secret_returns_32_char_base32():
    secret = generate_totp_secret()
    assert isinstance(secret, str)
    assert len(secret) == 32
    # Must be accepted by pyotp, i.e. valid base32 string
    pyotp.TOTP(secret)


def test_generate_totp_secret_is_random():
    secrets = {generate_totp_secret() for _ in range(5)}
    assert len(secrets) == 5


def test_verify_totp_code_with_valid_code():
    secret = generate_totp_secret()
    code = pyotp.TOTP(secret).now()
    assert verify_totp_code(secret, code) is True


def test_verify_totp_code_with_wrong_code():
    secret = generate_totp_secret()
    code = pyotp.TOTP(secret).now()
    wrong_code = "000000" if code != "000000" else "111111"
    assert verify_totp_code(secret, wrong_code) is False


def test_verify_totp_code_with_invalid_secret():
    assert verify_totp_code("not-valid-base32!!!", "000000") is False


def test_get_totp_provisioning_uri_contains_secret():
    secret = generate_totp_secret()
    user = Mock()
    user.get_username.return_value = "alice"
    uri = get_totp_provisioning_uri(secret, user)
    assert uri.startswith("otpauth://totp/")
    assert secret in uri


def test_get_totp_provisioning_uri_uses_user_username_and_issuer():
    secret = generate_totp_secret()
    user = Mock()
    user.get_username.return_value = "alice"
    with OverrideJwt2faSettings(TOTP_ISSUER_NAME="Foobar Inc."):
        uri = get_totp_provisioning_uri(secret, user)
    assert "Foobar%20Inc.:alice" in uri


def test_get_totp_provisioning_uri_full_value():
    secret = generate_totp_secret()
    user = Mock()
    user.get_username.return_value = "john@example.com"
    with OverrideJwt2faSettings(TOTP_ISSUER_NAME="Example Org."):
        uri = get_totp_provisioning_uri(secret, user)

    issuer = "Example%20Org."
    account = "john%40example.com"
    assert uri == (
        f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}"
    )


@pytest.mark.django_db
def test_get_totp_secret_for_user_returns_none_when_no_record():
    user = get_user()
    assert get_totp_secret_for_user(user) is None


@pytest.mark.django_db
def test_get_totp_secret_for_user_returns_none_when_method_is_code_sender():
    user = get_user()
    secret = generate_totp_secret()
    d = UserTwoFactorAuthData(
        user=user,
        preferred_2fa_auth=TwoFactorAuthMethod.CODE_SENDER,
    )
    d.set_totp_secret(secret)
    d.save()
    assert get_totp_secret_for_user(user) is None


@pytest.mark.django_db
def test_get_totp_secret_for_user_returns_secret_when_method_is_totp():
    user = get_user()
    secret = generate_totp_secret()
    d = UserTwoFactorAuthData(
        user=user,
        preferred_2fa_auth=TwoFactorAuthMethod.TOTP,
    )
    d.set_totp_secret(secret)
    d.save()
    assert get_totp_secret_for_user(user) == secret


@pytest.mark.django_db
@pytest.mark.parametrize("default", ["", "no-2fa", "code-sender"])
def test_get_preferred_2fa_method_returns_default_when_no_record(default):
    with OverrideJwt2faSettings(DEFAULT_2FA_AUTH_METHOD=default):
        user = get_user()
        assert get_preferred_2fa_method_for_user(user) == default


@pytest.mark.django_db
@pytest.mark.parametrize("default", ["", "no-2fa", "code-sender"])
def test_get_preferred_2fa_method_returns_default_when_not_configured(default):
    with OverrideJwt2faSettings(DEFAULT_2FA_AUTH_METHOD=default):
        user = get_user()
        UserTwoFactorAuthData.objects.create(
            user=user,
            preferred_2fa_auth=TwoFactorAuthMethod.NOT_CONFIGURED,
        )
        assert get_preferred_2fa_method_for_user(user) == default


@pytest.mark.django_db
def test_get_preferred_2fa_method_returns_code_sender():
    user = get_user()
    UserTwoFactorAuthData.objects.create(
        user=user,
        preferred_2fa_auth=TwoFactorAuthMethod.CODE_SENDER,
    )
    assert get_preferred_2fa_method_for_user(user) == "code-sender"


@pytest.mark.django_db
def test_get_preferred_2fa_method_returns_totp():
    user = get_user()
    d = UserTwoFactorAuthData(
        user=user,
        preferred_2fa_auth=TwoFactorAuthMethod.TOTP,
    )
    d.set_totp_secret(generate_totp_secret())
    d.save()
    assert get_preferred_2fa_method_for_user(user) == "totp"
