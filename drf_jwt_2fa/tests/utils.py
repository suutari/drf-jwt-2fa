import base64
import json
import time

import jwt
import six
from django.conf import settings
from django.core import mail
from django.test import override_settings
from django.test.utils import TestContextDecorator
from rest_framework.test import APIClient
from rest_framework_jwt.settings import api_settings as jwt_settings

from drf_jwt_2fa.settings import api_settings

str = six.text_type  # Make str be unicode on Python 2 too


def get_api_client():
    api_client = APIClient()
    api_client.default_format = 'json'
    return api_client


def check_auth_token(token, username='testuser', email='testuser@localhost'):
    payload = check_token_basics_and_get_payload(token)
    assert sorted(payload.keys()) == ['email', 'exp', 'user_id', 'username']
    assert isinstance(payload['user_id'], int)
    assert isinstance(payload['username'], str)
    assert isinstance(payload['email'], str)
    assert isinstance(payload['exp'], int)
    assert payload['exp'] > time.time()
    assert payload['username'] == username
    assert payload['email'] == email
    key = jwt_settings.JWT_SECRET_KEY
    jwt.decode(token, key, algorithms=['HS256'])


def check_code_token(token, username='testuser', verify=True):
    payload = check_token_basics_and_get_payload(token)
    assert sorted(payload.keys()) == ['exp', 'iat', 'usr', 'vch', 'vcn']
    assert isinstance(payload['exp'], int)
    assert isinstance(payload['iat'], int)
    assert isinstance(payload['usr'], str)
    assert isinstance(payload['vch'], str)
    assert isinstance(payload['vcn'], str)
    assert payload['exp'] > time.time()
    assert payload['iat'] <= time.time()
    assert payload['usr'] == username
    assert payload['vch'].startswith('pbkdf2_sha256$')
    assert len(payload['vcn']) == 10
    if verify:
        key = api_settings.CODE_TOKEN_SECRET_KEY
        jwt.decode(token, key, algorithms=['HS256'])


def check_token_basics_and_get_payload(token):
    assert token
    assert len(token.split('.')) == 3
    (header_part, payload_part, signature_part) = token.split('.')
    assert decode_jwt_part(header_part) == {'alg': 'HS256', 'typ': 'JWT'}
    return decode_jwt_part(payload_part)


def get_verification_code_from_mailbox():
    return mail.outbox[-1].subject.split(':')[0]


def decode_jwt_part(part):
    return json.loads(b64decode(part).decode('utf-8'))


def b64decode(encoded):
    padding = (4 - len(encoded) % 4) * '='
    return base64.b64decode(encoded + padding)


def encode_jwt_part(data):
    json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')
    return base64.b64encode(json_data).decode('ascii').strip('=')


class OverrideJwt2faSettings(TestContextDecorator):
    def __init__(self, values):
        super(OverrideJwt2faSettings, self).__init__()
        self.override_settings = override_settings(JWT2FA_AUTH=values)

    def enable(self):
        self.override_settings.enable()
        api_settings.reload()
        api_settings._user_settings = settings.JWT2FA_AUTH

    def disable(self):
        self.override_settings.disable()
        api_settings.reload()
