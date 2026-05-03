from unittest.mock import Mock

import pyotp
import pytest

from drf_jwt_2fa.totp import (
    generate_totp_secret,
    get_totp_provisioning_uri,
    make_sure_is_valid_totp_secret,
    verify_totp_code,
)

from .utils import OverrideJwt2faSettings


def test_generate_totp_secret_returns_32_char_base32():
    secret = generate_totp_secret()
    assert isinstance(secret, str)
    assert len(secret) == 32
    # Must be accepted by pyotp, i.e. valid base32 string
    pyotp.TOTP(secret)


def test_make_sure_is_valid_totp_secret_accepts_valid_secret():
    make_sure_is_valid_totp_secret(generate_totp_secret())


def test_make_sure_is_valid_totp_secret_raises_on_too_short():
    with pytest.raises(ValueError):
        make_sure_is_valid_totp_secret("AAAAAAAAAAAAAAAA")  # 16 chars


def test_make_sure_is_valid_totp_secret_raises_on_too_long():
    with pytest.raises(ValueError):
        make_sure_is_valid_totp_secret("A" * 33)


def test_make_sure_is_valid_totp_secret_raises_on_invalid_chars():
    with pytest.raises(ValueError):
        make_sure_is_valid_totp_secret("!" * 32)


def test_make_sure_is_valid_totp_secret_raises_on_lowercase():
    with pytest.raises(ValueError):
        # Lowercase is not valid Base32 in this context
        make_sure_is_valid_totp_secret("a" * 32)


def test_make_sure_is_valid_totp_secret_raises_on_empty_string():
    with pytest.raises(ValueError):
        make_sure_is_valid_totp_secret("")


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
