import pytest

from drf_jwt_2fa.settings import api_settings

from .utils import OverrideJwt2faSettings


def test_code_sender_can_be_overridden_with_a_callable():
    """CODE_SENDER accepts a callable."""
    from drf_jwt_2fa.sending import send_verification_code_via_email

    with OverrideJwt2faSettings(CODE_SENDER=send_verification_code_via_email):
        assert api_settings.CODE_SENDER is send_verification_code_via_email


def fake_code_sender(user, code):
    pass  # pragma: no cover


def test_code_sender_can_be_overridden_with_a_string():
    """CODE_SENDER accepts an import path string."""
    with OverrideJwt2faSettings(
        CODE_SENDER="drf_jwt_2fa.tests.test_settings.fake_code_sender"
    ):
        assert api_settings.CODE_SENDER is fake_code_sender


@OverrideJwt2faSettings(CODE_LENGTH="not-an-int")
def test_wrong_int_setting_type_raises_type_error():
    with pytest.raises(TypeError) as exc:
        _ = api_settings.CODE_LENGTH
    assert exc.value.args[0] == (
        "JWT2FA_AUTH setting 'CODE_LENGTH' must be an instance of int"
    )


@OverrideJwt2faSettings(CODE_SENDER=1234)
def test_wrong_func_setting_type_raises_type_error():
    with pytest.raises(TypeError) as exc:
        _ = api_settings.CODE_SENDER
    assert exc.value.args[0] == (
        "JWT2FA_AUTH setting 'CODE_SENDER' must be an instance of CodeSender"
    )


@OverrideJwt2faSettings(EMAIL_SENDER_BODY_OVERRIDE=1234)
def test_wrong_str_or_none_setting_type_raises_type_error():
    with pytest.raises(TypeError) as exc:
        _ = api_settings.EMAIL_SENDER_BODY_OVERRIDE
    assert exc.value.args[0] == (
        "JWT2FA_AUTH setting 'EMAIL_SENDER_BODY_OVERRIDE' "
        "must be an instance of str | None"
    )


@OverrideJwt2faSettings(CODE_EXPIRATION_TIME=5)
def test_wrong_timedelta_setting_type_raises_type_error():
    with pytest.raises(TypeError) as exc:
        _ = api_settings.CODE_EXPIRATION_TIME
    assert exc.value.args[0] == (
        "JWT2FA_AUTH setting 'CODE_EXPIRATION_TIME' "
        "must be an instance of timedelta"
    )


def test_unknown_setting_is_ignored():
    """An unrecognised key in JWT2FA_AUTH is silently ignored."""
    with OverrideJwt2faSettings(NONEXISTENT_SETTING=True):
        assert api_settings.CODE_LENGTH == 7
