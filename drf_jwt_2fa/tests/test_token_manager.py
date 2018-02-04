import datetime
import time

import pytest
from django.conf import settings
from django.core import mail
from django.test import override_settings
from mock import patch
from rest_framework import serializers

from drf_jwt_2fa.settings import api_settings
from drf_jwt_2fa.token_manager import CodeTokenManager

from .factories import get_user
from .utils import (
    check_code_token, decode_jwt_part, encode_jwt_part,
    get_verification_code_from_mailbox)


@pytest.mark.django_db
def test_create_code_token():
    manager = CodeTokenManager()

    mail_outbox_size_before = len(mail.outbox)

    token = manager.create_code_token(get_user())

    # Check sent mails
    assert len(mail.outbox) == mail_outbox_size_before + 1
    assert mail.outbox[-1].subject.endswith(': Your verification code')
    assert mail.outbox[-1].from_email == 'webmaster@localhost'
    assert mail.outbox[-1].to == ['testuser@localhost']

    # Check the generated token
    check_code_token(token)


@pytest.mark.django_db
def test_create_code_token_with_no_email():
    manager = CodeTokenManager()

    mail_outbox_size_before = len(mail.outbox)

    with pytest.raises(serializers.ValidationError) as exc_info:
        manager.create_code_token(get_user(username='no-email', email=''))
    assert str(exc_info.value) == repr(
        [u'Verification code sending failed: No e-mail address known'])

    # Check sent mails
    assert len(mail.outbox) == mail_outbox_size_before


@pytest.mark.django_db
@patch('drf_jwt_2fa.sending.send_mail', return_value=0)
def test_create_code_token_with_email_send_error(mocked_send_mail):
    manager = CodeTokenManager()

    with pytest.raises(serializers.ValidationError) as exc_info:
        manager.create_code_token(get_user())
    assert str(exc_info.value) == repr(
        [u'Verification code sending failed: Unable to send e-mail'])

    assert mocked_send_mail.called_once()


@pytest.mark.django_db
def test_check_code_token_and_code_success():
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    code = get_verification_code_from_mailbox()
    username = manager.check_code_token_and_code(token, code)
    assert username == 'testuser'


@pytest.mark.django_db
def test_check_code_token_and_code_with_invalid_token():
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    code = get_verification_code_from_mailbox()
    (header, payload_before, signature) = token.split('.')
    payload = decode_jwt_part(payload_before)
    payload['usr'] = 'somebody-else'
    new_token = header + '.' + encode_jwt_part(payload) + '.' + signature
    check_code_token(new_token, username='somebody-else', verify=False)
    with pytest.raises(serializers.ValidationError) as exc_info:
        manager.check_code_token_and_code(new_token, code)
    assert str(exc_info.value) == repr([u'Verification failed'])


@pytest.mark.django_db
def test_check_code_token_and_code_with_invalid_code():
    manager = CodeTokenManager()
    token = manager.create_code_token(get_user())
    correct_code = get_verification_code_from_mailbox()
    assert len(correct_code) == 6
    invalid_code = '123456' if correct_code != '123456' else '654321'
    with pytest.raises(serializers.ValidationError) as exc_info:
        manager.check_code_token_and_code(token, invalid_code)
    assert str(exc_info.value) == repr([u'Verification failed'])


@pytest.mark.django_db
@override_settings(JWT2FA_AUTH={
    'CODE_EXPIRATION_TIME': datetime.timedelta(seconds=-1),
})
def test_check_code_token_and_code_with_expired_token():
    old_user_settings = api_settings._user_settings
    api_settings.reload()
    api_settings._user_settings = settings.JWT2FA_AUTH
    try:
        manager = CodeTokenManager()
        token = manager.create_code_token(get_user())
        assert decode_jwt_part(token.split('.')[1])['exp'] < time.time()
        code = get_verification_code_from_mailbox()
        with pytest.raises(serializers.ValidationError) as exc_info:
            manager.check_code_token_and_code(token, code)
        assert str(exc_info.value) == repr([u'Signature has expired.'])
    finally:
        api_settings.reload()
        api_settings._user_settings = old_user_settings
