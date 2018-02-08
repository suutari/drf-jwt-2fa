from __future__ import unicode_literals

import datetime
import math
import pickle
import time

import pytest
from django.core.cache.backends.locmem import LocMemCache
from django.test.client import RequestFactory
from django.urls import reverse
from freezegun import freeze_time
from mock import patch
from rest_framework import status

from drf_jwt_2fa.throttling import CodeTokenThrottler

from .test_endpoints import get_code_token
from .utils import (
    OverrideJwt2faSettings, get_api_client, get_verification_code_from_mailbox)


@pytest.mark.parametrize('num', [None, 1, 42, 938383])
@pytest.mark.parametrize('duration_str, duration_seconds', [
    ('s', 1), ('7s', 7), ('m', 60), ('10m', 600), ('h', 3600), ('d', 86400)])
def test_code_token_throttler_parse_rate(num, duration_str, duration_seconds):
    rate_string = str(num) + '/' + duration_str if num else None
    expected_result = (num, duration_seconds) if num else (None, None)
    throttler = CodeTokenThrottler()
    throttler.parse_rate(rate_string) == expected_result


def get_code_token_throttler(cache):
    throttler = CodeTokenThrottler()
    throttler.timer = time.time
    throttler.cache = cache
    return throttler


@OverrideJwt2faSettings({'CODE_TOKEN_THROTTLE_RATE': '2/10s'})
def test_code_token_throttler():
    with patch('drf_jwt_2fa.throttling.sha1_string') as mocked_sha1_string:
        mocked_sha1_string.side_effect = lambda x: 'SHA1({})'.format(x)
        check_code_token_throttler(RequestFactory())


def check_code_token_throttler(rf):
    with freeze_time('2020-01-02 13:00:00') as frozen_datetime:
        cache = LocMemCache('test_cache', {})
        cache.clear()
        throttler = get_code_token_throttler(cache)
        request = rf.get('/')

        assert inspect_cache(cache) == {}

        # First two requests should be allowed
        assert throttler.allow_request(request, None) is True
        assert inspect_cache(cache) == {
            ':1:drf_jwt_2fa-tc-SHA1(127.0.0.1)': [1577970000.0],
        }

        frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
        throttler = get_code_token_throttler(cache)
        assert throttler.allow_request(request, None) is True
        assert inspect_cache(cache) == {
            ':1:drf_jwt_2fa-tc-SHA1(127.0.0.1)': [1577970001.0, 1577970000.0],
        }

        # Third request should be throttled
        throttler = get_code_token_throttler(cache)
        frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
        assert throttler.allow_request(request, None) is False
        assert inspect_cache(cache) == {
            ':1:drf_jwt_2fa-tc-SHA1(127.0.0.1)': [1577970001.0, 1577970000.0],
        }

        # After 8s more, total 11s have passed and a new request should
        # be allowed
        throttler = get_code_token_throttler(cache)
        frozen_datetime.tick(delta=datetime.timedelta(seconds=8))
        assert throttler.allow_request(request, None) is True
        assert inspect_cache(cache) == {
            ':1:drf_jwt_2fa-tc-SHA1(127.0.0.1)': [1577970010.0, 1577970001.0],
        }


def inspect_cache(cache):
    return {
        key: pickle.loads(pickled_value)
        for (key, pickled_value) in cache._cache.items()}


@pytest.mark.django_db
def test_code_token_throttling():
    with freeze_time('2020-01-02 13:00:00') as frozen_datetime:
        assert time.time() == 1577970000.0

        code_token1 = get_code_token()
        code1 = get_verification_code_from_mailbox()

        code_token2 = get_code_token()
        code2 = get_verification_code_from_mailbox()

        incorrect_codes = [
            code for code in [
                '1234567', '2345678', '3456789', '4567890', '5678901',
                '6789012', '7890123', '8901234', '9012345', '0123456']
            if code not in {code1, code2}]
        client = get_api_client()

        def attempt(code_token, code):
            return client.post(
                reverse('auth'),
                data={'code_token': code_token, 'code': code})

        # Note: Default throttle wait time is 2 seconds

        # Try 1 on code_token1
        frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
        assert time.time() == 1577970001.0
        result0 = attempt(code_token1, incorrect_codes[0])
        assert result0.data == {
            'detail': 'Incorrect authentication credentials.'}
        assert result0.status_code == status.HTTP_403_FORBIDDEN

        # Try 2 on code_token1, after 0.5s.  Should be throttled
        frozen_datetime.tick(delta=datetime.timedelta(seconds=0.5))
        assert time.time() == 1577970001.5
        result1 = attempt(code_token1, incorrect_codes[1])
        assert result1.data == {
            'detail': (
                'Request was throttled. Expected available in {} seconds.'
                .format(math.ceil(2)))
        }
        assert result1.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Try 3 on code_token1, after 1.75s.  Should NOT be throttled,
        # since 2.25s have passed since the last non-throttled (Try 1)
        frozen_datetime.tick(delta=datetime.timedelta(seconds=1.75))
        assert time.time() == 1577970003.25
        result2 = attempt(code_token1, incorrect_codes[2])
        assert result2.data == {
            'detail': 'Incorrect authentication credentials.'}
        assert result2.status_code == status.HTTP_403_FORBIDDEN

        # Try 4 on code_token1, after 0.75s.  Should be throttled.
        frozen_datetime.tick(delta=datetime.timedelta(seconds=0.75))
        assert time.time() == 1577970004.0
        result3 = attempt(code_token1, incorrect_codes[3])
        assert result3.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Try with a different code token.  Should NOT be throttled.
        assert time.time() == 1577970004.0
        result4 = attempt(code_token2, incorrect_codes[4])
        assert result4.data == {
            'detail': 'Incorrect authentication credentials.'}
        assert result4.status_code == status.HTTP_403_FORBIDDEN

        # Try without a code token.  Should NOT be throttled.
        assert time.time() == 1577970004.0
        result4 = attempt('', 'abc')
        assert result4.data == {'code_token': ['This field may not be blank.']}
        assert result4.status_code == status.HTTP_400_BAD_REQUEST

        # Try 5 on code_token1, after 1.5s.  Should NOT be throttled
        # since 2.25s have passed since the last non-throttled (Try 3)
        frozen_datetime.tick(delta=datetime.timedelta(seconds=1.5))
        assert time.time() == 1577970005.5
        result5 = attempt(code_token1, incorrect_codes[5])
        assert result5.data == {
            'detail': 'Incorrect authentication credentials.'}
        assert result5.status_code == status.HTTP_403_FORBIDDEN
