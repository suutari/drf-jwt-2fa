import datetime
import math
import pickle
import time
from unittest.mock import Mock, patch

import pytest
from django.core.cache.backends.locmem import LocMemCache
from django.test.client import RequestFactory
from django.urls import reverse
from freezegun import freeze_time
from rest_framework import status

from drf_jwt_2fa.throttling import AuthTokenThrottler, CodeTokenThrottler
from drf_jwt_2fa.utils import get_code_token_hash

from .factories import get_code_token
from .utils import OverrideJwt2faSettings, get_api_client


@pytest.mark.parametrize("num", [None, 1, 42, 938383])
@pytest.mark.parametrize(
    "duration_str, duration_seconds",
    [("s", 1), ("7s", 7), ("m", 60), ("10m", 600), ("h", 3600), ("d", 86400)],
)
def test_code_token_throttler_parse_rate(num, duration_str, duration_seconds):
    rate_string = str(num) + "/" + duration_str if num else None
    expected_result = (num, duration_seconds) if num else (None, None)
    throttler = CodeTokenThrottler()
    assert throttler.parse_rate(rate_string) == expected_result


def get_code_token_throttler(cache):
    throttler = CodeTokenThrottler()
    throttler.timer = time.time
    throttler.cache = cache
    return throttler


@OverrideJwt2faSettings(CODE_TOKEN_THROTTLE_RATE="2/10s")
def test_code_token_throttler():
    def fake_hasher(initial):
        hasher = Mock()
        hasher.hexdigest.return_value = f"HASH({initial.decode()})"
        return hasher

    with patch("drf_jwt_2fa.throttling.ident_hasher", side_effect=fake_hasher):
        check_code_token_throttler(RequestFactory())


def check_code_token_throttler(rf):
    with freeze_time("2020-01-02 13:00:00") as frozen_datetime:
        cache = LocMemCache("test_cache", {})
        cache.clear()
        throttler = get_code_token_throttler(cache)
        request = rf.get("/")

        assert inspect_cache(cache) == {}

        # First two requests should be allowed
        assert throttler.allow_request(request, None) is True
        assert inspect_cache(cache) == {
            ":1:drf_jwt_2fa-tc-HASH(127.0.0.1)": [1577970000.0],
        }

        frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
        throttler = get_code_token_throttler(cache)
        assert throttler.allow_request(request, None) is True
        assert inspect_cache(cache) == {
            ":1:drf_jwt_2fa-tc-HASH(127.0.0.1)": [1577970001.0, 1577970000.0],
        }

        # Third request should be throttled
        throttler = get_code_token_throttler(cache)
        frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
        assert throttler.allow_request(request, None) is False
        assert inspect_cache(cache) == {
            ":1:drf_jwt_2fa-tc-HASH(127.0.0.1)": [1577970001.0, 1577970000.0],
        }

        # After 8s more, total 11s have passed and a new request should
        # be allowed
        throttler = get_code_token_throttler(cache)
        frozen_datetime.tick(delta=datetime.timedelta(seconds=8))
        assert throttler.allow_request(request, None) is True
        assert inspect_cache(cache) == {
            ":1:drf_jwt_2fa-tc-HASH(127.0.0.1)": [1577970010.0, 1577970001.0],
        }


def inspect_cache(cache):
    return {
        key: pickle.loads(pickled_value)
        for (key, pickled_value) in cache._cache.items()
    }


def test_code_token_throttling():
    with freeze_time("2020-01-02 13:00:00") as frozen_datetime:
        assert time.time() == 1577970000.0

        code1 = "1111111"
        code_token1 = get_code_token(verification_code=code1)

        code2 = "2222222"
        code_token2 = get_code_token(verification_code=code2)

        incorrect_codes = ["1234", "2345", "3456", "4567", "5678", "6789"]
        client = get_api_client()

        def attempt(code_token, code):
            return client.post(
                reverse("auth"), data={"code_token": code_token, "code": code}
            )

        # Note: Default throttle wait time is 2 seconds

        # Try 1 on code_token1
        frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
        assert time.time() == 1577970001.0
        result0 = attempt(code_token1, incorrect_codes[0])
        assert result0.data == {
            "detail": "Incorrect authentication credentials."
        }
        assert result0.status_code == status.HTTP_401_UNAUTHORIZED

        # Try 2 on code_token1, after 0.5s.  Should be throttled
        frozen_datetime.tick(delta=datetime.timedelta(seconds=0.5))
        assert time.time() == 1577970001.5
        result1 = attempt(code_token1, incorrect_codes[1])
        expected_detail = (
            f"Request was throttled. Expected available in "
            f"{math.ceil(2)} seconds."
        )
        assert result1.data == {
            "detail": expected_detail,
        }
        assert result1.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Try 3 on code_token1, after 1.75s.  Should NOT be throttled,
        # since 2.25s have passed since the last non-throttled (Try 1)
        frozen_datetime.tick(delta=datetime.timedelta(seconds=1.75))
        assert time.time() == 1577970003.25
        result2 = attempt(code_token1, incorrect_codes[2])
        assert result2.data == {
            "detail": "Incorrect authentication credentials."
        }
        assert result2.status_code == status.HTTP_401_UNAUTHORIZED

        # Try 4 on code_token1, after 0.75s.  Should be throttled.
        frozen_datetime.tick(delta=datetime.timedelta(seconds=0.75))
        assert time.time() == 1577970004.0
        result3 = attempt(code_token1, incorrect_codes[3])
        assert result3.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Try with a different code token.  Should NOT be throttled.
        assert time.time() == 1577970004.0
        result4 = attempt(code_token2, incorrect_codes[4])
        assert result4.data == {
            "detail": "Incorrect authentication credentials."
        }
        assert result4.status_code == status.HTTP_401_UNAUTHORIZED

        # Try without a code token.  Should NOT be throttled.
        assert time.time() == 1577970004.0
        result4 = attempt("", "abc")
        assert result4.data == {"code_token": ["This field may not be blank."]}
        assert result4.status_code == status.HTTP_400_BAD_REQUEST

        # Try 5 on code_token1, after 1.5s.  Should NOT be throttled
        # since 2.25s have passed since the last non-throttled (Try 3)
        frozen_datetime.tick(delta=datetime.timedelta(seconds=1.5))
        assert time.time() == 1577970005.5
        result5 = attempt(code_token1, incorrect_codes[5])
        assert result5.data == {
            "detail": "Incorrect authentication credentials."
        }
        assert result5.status_code == status.HTTP_401_UNAUTHORIZED


def test_auth_token_throttler_cache_key_no_token():
    """AuthTokenThrottler returns None cache key when no code_token."""
    rf = RequestFactory()
    request = rf.post("/", data={}, content_type="application/json")
    request.data = {}
    throttler = AuthTokenThrottler()
    assert throttler.get_cache_key(request, None) is None


def test_auth_token_throttler_cache_key_uses_get_code_token_hash():
    """AuthTokenThrottler cache key is based on get_code_token_hash."""
    rf = RequestFactory()
    token = get_code_token()
    request = rf.post("/")
    request.data = {"code_token": token}
    throttler = AuthTokenThrottler()

    key = throttler.get_cache_key(request, None)

    expected_key = f"drf_jwt_2fa-ta-{get_code_token_hash(token)}"
    assert key == expected_key


def test_auth_token_throttler_cache_key_differs_per_token():
    """Different code tokens produce different cache keys."""
    rf = RequestFactory()
    token_a = get_code_token()
    token_b = get_code_token()
    throttler = AuthTokenThrottler()

    def make_request(token):
        request = rf.post("/")
        request.data = {"code_token": token}
        return request

    key_a = throttler.get_cache_key(make_request(token_a), None)
    key_b = throttler.get_cache_key(make_request(token_b), None)

    assert key_a != key_b


@freeze_time("2020-01-02 13:00:00")
def test_auth_token_throttler_cache_key_stored_in_cache():
    """The key stored in cache matches get_code_token_hash of the token."""
    rf = RequestFactory()
    token = get_code_token()
    request = rf.post("/")
    request.data = {"code_token": token}
    token_hash = get_code_token_hash(token)

    cache = LocMemCache("test_auth_cache", {})
    cache.clear()
    throttler = AuthTokenThrottler()
    throttler.cache = cache

    throttler.allow_request(request, None)

    assert inspect_cache(cache) == {
        # Note: 1577970002.0 = unix time of now + 2 seconds (retry wait time)
        f":1:drf_jwt_2fa-ta-{token_hash}": 1577970002.0,
    }
