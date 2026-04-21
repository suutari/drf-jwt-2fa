import datetime
import time
from unittest.mock import patch

import freezegun
import pytest
from django.core import mail
from django.core.cache import cache
from rest_framework import exceptions, status

from drf_jwt_2fa.exceptions import (
    TooManyAuthAttemptsError,
    TooManyCodeTokensError,
    VerificationCodeSendingError,
)
from drf_jwt_2fa.sending import CodeSendingError
from drf_jwt_2fa.token_manager import CodeTokenManager

from .factories import get_user
from .utils import (
    OverrideJwt2faSettings,
    check_code_token,
    decode_jwt_part,
    encode_jwt_part,
    get_verification_code_from_mailbox,
)


@pytest.mark.django_db
def test_create_code_token():
    manager = CodeTokenManager()

    mail_outbox_size_before = len(mail.outbox)

    token = manager.create_code_token(get_user())

    # Check sent mails
    assert len(mail.outbox) == mail_outbox_size_before + 1
    assert mail.outbox[-1].subject.endswith(": Your verification code")
    assert mail.outbox[-1].from_email == "webmaster@localhost"
    assert mail.outbox[-1].to == ["testuser@localhost"]

    # Check the generated token
    check_code_token(token)


@pytest.mark.django_db
@OverrideJwt2faSettings(EMAIL_SENDER_FROM_ADDRESS="no-reply@example.com")
def test_create_code_token_uses_configured_from_address():
    manager = CodeTokenManager()

    mail_outbox_size_before = len(mail.outbox)

    manager.create_code_token(get_user())

    assert len(mail.outbox) == mail_outbox_size_before + 1
    assert mail.outbox[-1].from_email == "no-reply@example.com"


@pytest.mark.django_db
def test_create_code_token_with_no_email():
    manager = CodeTokenManager()

    mail_outbox_size_before = len(mail.outbox)

    with pytest.raises(VerificationCodeSendingError) as exc_info:
        manager.create_code_token(get_user(username="no-email", email=""))
    assert str(exc_info.value) == (
        "Verification code sending failed: No e-mail address known"
    )
    assert exc_info.value.status_code == status.HTTP_501_NOT_IMPLEMENTED

    # Check sent mails
    assert len(mail.outbox) == mail_outbox_size_before


@pytest.mark.django_db
@patch("drf_jwt_2fa.sending.send_mail", return_value=0)
def test_create_code_token_with_email_send_error(mocked_send_mail):
    manager = CodeTokenManager()

    with pytest.raises(VerificationCodeSendingError) as exc_info:
        manager.create_code_token(get_user())
    assert str(exc_info.value) == (
        "Verification code sending failed: Unable to send e-mail"
    )
    assert exc_info.value.status_code == status.HTTP_501_NOT_IMPLEMENTED

    assert mocked_send_mail.call_count == 1


@pytest.mark.django_db
def test_create_code_token_with_custom_sender_raising_unknown_error(caplog):
    def failing_code_sender(user, code):
        raise ValueError("Custom error")

    with OverrideJwt2faSettings(CODE_SENDER=failing_code_sender):
        manager = CodeTokenManager()
        with (
            caplog.at_level("ERROR", logger="drf_jwt_2fa.sending"),
            pytest.raises(VerificationCodeSendingError) as exc_info,
        ):
            manager.create_code_token(get_user())

    error = exc_info.value
    assert str(error) == "Verification code sending failed: Unknown error"
    assert error.status_code == status.HTTP_501_NOT_IMPLEMENTED

    logged = caplog.records[0]
    assert logged.message == "Verification code sending failed"
    assert logged.exc_text.splitlines()[0].startswith("Traceback")
    assert "in failing_code_sender" in logged.exc_text
    assert logged.exc_text.splitlines()[-1] == "ValueError: Custom error"


@pytest.mark.django_db
def test_create_code_token_with_custom_sender_raising_code_sending_error():
    def failing_code_sender(user, code):
        raise CodeSendingError("Custom code sending error")

    with OverrideJwt2faSettings(CODE_SENDER=failing_code_sender):
        manager = CodeTokenManager()
        with pytest.raises(VerificationCodeSendingError) as exc_info:
            manager.create_code_token(get_user())
        assert "Custom code sending error" in str(exc_info.value)
        assert exc_info.value.status_code == status.HTTP_501_NOT_IMPLEMENTED


@pytest.mark.django_db
def test_check_code_token_and_code_success():
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    code = get_verification_code_from_mailbox()
    username = manager.check_code_token_and_code(token, code)
    assert username == "testuser"


@pytest.mark.django_db
def test_check_code_token_and_code_with_invalid_token():
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    code = get_verification_code_from_mailbox()
    (header, payload_before, signature) = token.split(".")
    payload = decode_jwt_part(payload_before)
    payload["usr"] = "somebody-else"
    new_token = header + "." + encode_jwt_part(payload) + "." + signature
    check_code_token(new_token, username="somebody-else", verify=False)
    with pytest.raises(Exception) as exc_info:
        manager.check_code_token_and_code(new_token, code)
    assert str(exc_info.value) == "Incorrect authentication credentials."
    assert isinstance(exc_info.value, exceptions.AuthenticationFailed)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_check_code_token_and_code_with_invalid_code():
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    correct_code = get_verification_code_from_mailbox()
    assert len(correct_code) == 7
    invalid_code = "1234567" if correct_code != "1234567" else "7654321"
    with pytest.raises(exceptions.AuthenticationFailed) as exc_info:
        manager.check_code_token_and_code(token, invalid_code)
    assert str(exc_info.value) == "Incorrect authentication credentials."
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
@OverrideJwt2faSettings(CODE_EXPIRATION_TIME=datetime.timedelta(seconds=-1))
def test_check_code_token_and_code_with_expired_token():
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    assert decode_jwt_part(token.split(".")[1])["exp"] < time.time()
    code = get_verification_code_from_mailbox()
    with pytest.raises(exceptions.PermissionDenied) as exc_info:
        manager.check_code_token_and_code(token, code)
    assert str(exc_info.value) == "Signature has expired."
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
@OverrideJwt2faSettings(MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN=3)
def test_check_code_token_and_code_blocks_after_max_failed_attempts():
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    correct_code = get_verification_code_from_mailbox()
    wrong_code = "0000000" if correct_code != "0000000" else "1111111"

    # MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN failures are allowed
    for _ in range(3):
        with pytest.raises(exceptions.AuthenticationFailed):
            manager.check_code_token_and_code(token, wrong_code)

    # Next attempt (4th) should be blocked regardless of code
    with pytest.raises(TooManyAuthAttemptsError) as exc_info:
        manager.check_code_token_and_code(token, correct_code)
    assert str(exc_info.value) == "Too many failed authentication attempts."
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
@OverrideJwt2faSettings(MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN=3)
def test_check_code_token_and_code_succeeds_within_attempt_limit():
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    correct_code = get_verification_code_from_mailbox()
    wrong_code = "0000000" if correct_code != "0000000" else "1111111"

    # Two failures followed by a success should work fine
    for _ in range(2):
        with pytest.raises(exceptions.AuthenticationFailed):
            manager.check_code_token_and_code(token, wrong_code)

    username = manager.check_code_token_and_code(token, correct_code)
    assert username == "testuser"


@pytest.mark.django_db
@OverrideJwt2faSettings(MAX_ACTIVE_CODE_TOKENS_PER_USER=2)
def test_create_code_token_blocks_when_active_token_limit_reached():
    manager = CodeTokenManager()
    user = get_user()

    # Create up to the limit
    manager.create_code_token(user)
    manager.create_code_token(user)

    # Next one should be rejected
    with pytest.raises(TooManyCodeTokensError) as exc_info:
        manager.create_code_token(user)
    assert str(exc_info.value) == (
        "Too many active code tokens. Please wait for existing ones to expire."
    )
    assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.django_db
@OverrideJwt2faSettings(
    MAX_ACTIVE_CODE_TOKENS_PER_USER=2,
    CODE_EXPIRATION_TIME=datetime.timedelta(seconds=1),
)
def test_create_code_token_allows_new_token_after_previous_ones_expire():
    manager = CodeTokenManager()
    user = get_user()

    manager.create_code_token(user)
    manager.create_code_token(user)

    # After tokens expire, a new one should be allowed
    with freezegun.freeze_time(
        datetime.datetime.now(tz=datetime.timezone.utc)
        + datetime.timedelta(seconds=2)
    ):
        token = manager.create_code_token(user)
    assert token


@pytest.mark.django_db
@OverrideJwt2faSettings(MAX_ACTIVE_CODE_TOKENS_PER_USER=2)
def test_create_code_token_limit_is_per_user():
    manager = CodeTokenManager()
    user1 = get_user(username="user1")
    user2 = get_user(username="user2")

    # Fill up the limit for user1
    manager.create_code_token(user1)
    manager.create_code_token(user1)

    # user2 should still be able to get a token
    token = manager.create_code_token(user2)
    assert token


@pytest.mark.django_db
@OverrideJwt2faSettings(MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN=3)
def test_failed_auth_attempt_counter_uses_add_on_first_attempt():
    """First failed attempt recorded via cache.add (key absent)."""
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    correct_code = get_verification_code_from_mailbox()
    wrong_code = "0000000" if correct_code != "0000000" else "1111111"

    with (
        patch("django.core.cache.cache.add", wraps=cache.add) as mock_add,
        pytest.raises(exceptions.AuthenticationFailed),
    ):
        manager.check_code_token_and_code(token, wrong_code)

    # cache.add must have been called once; since the key did not yet exist
    # the real implementation will have returned True and the key is now set.
    assert mock_add.call_count == 1


@pytest.mark.django_db
@OverrideJwt2faSettings(MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN=3)
def test_failed_auth_attempt_counter_uses_atomic_add_and_incr():
    """Failed attempt recording uses cache.add + cache.incr for atomicity.

    When cache.add returns False (key already exists, as happens when a
    concurrent request set it first), cache.incr is used instead of a
    non-atomic read-then-write, ensuring each failed attempt is counted
    exactly once even under concurrent load.
    """
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    correct_code = get_verification_code_from_mailbox()
    wrong_code = "0000000" if correct_code != "0000000" else "1111111"

    # First wrong attempt: seeds the cache key via cache.add (returns True).
    with pytest.raises(exceptions.AuthenticationFailed):
        manager.check_code_token_and_code(token, wrong_code)

    # Second wrong attempt: cache.add returns False because key now exists,
    # so the implementation must fall back to cache.incr.
    with (
        patch("django.core.cache.cache.incr", wraps=cache.incr) as mock_incr,
        pytest.raises(exceptions.AuthenticationFailed),
    ):
        manager.check_code_token_and_code(token, wrong_code)

    # incr must have been called to record the failed attempt atomically
    assert mock_incr.call_count == 1


@pytest.mark.django_db
@OverrideJwt2faSettings(MAX_ACTIVE_CODE_TOKENS_PER_USER=None)
def test_create_code_token_no_limit_when_max_active_tokens_is_none():
    """No active-token limit is enforced when MAX_ACTIVE_CODE_TOKENS_PER_USER
    is None."""
    manager = CodeTokenManager()
    user = get_user()
    for _ in range(10):
        token = manager.create_code_token(user)
    assert token


@pytest.mark.django_db
@OverrideJwt2faSettings(MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN=None)
def test_check_code_token_and_code_no_attempt_limit_when_setting_is_none():
    """No attempt limit is enforced when MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN
    is None."""
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    correct_code = get_verification_code_from_mailbox()
    wrong_code = "0000000" if correct_code != "0000000" else "1111111"

    for _ in range(20):
        with pytest.raises(exceptions.AuthenticationFailed):
            manager.check_code_token_and_code(token, wrong_code)

    # With the setting disabled the correct code must still be accepted
    user_id = manager.check_code_token_and_code(token, correct_code)
    assert user_id is not None


@pytest.mark.django_db
@OverrideJwt2faSettings(MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN=None)
def test_record_failed_auth_attempt_skipped_when_setting_is_none():
    """_record_failed_auth_attempt does nothing when
    MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN is None."""
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    correct_code = get_verification_code_from_mailbox()
    wrong_code = "0000000" if correct_code != "0000000" else "1111111"

    with (
        patch("django.core.cache.cache.set") as mock_set,
        patch("django.core.cache.cache.add") as mock_add,
        pytest.raises(exceptions.AuthenticationFailed),
    ):
        manager.check_code_token_and_code(token, wrong_code)

    mock_set.assert_not_called()
    mock_add.assert_not_called()
