import time

from django.core.cache import cache as default_cache
from rest_framework import throttling

from .settings import api_settings
from .utils import sha1_string


class CodeTokenThrottler(throttling.SimpleRateThrottle):
    cache_key_template = 'drf_jwt_2fa-tc-{ident_hash}'

    @property
    def rate(self):
        return api_settings.CODE_TOKEN_THROTTLE_RATE

    def parse_rate(self, rate):
        if not rate:
            return (None, None)
        (num_requests_str, period_str) = rate.split('/')
        period_num = int(period_str[:-1] or '1')
        period_unit = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[period_str[-1]]
        return (int(num_requests_str), period_num * period_unit)

    def get_cache_key(self, request, view):
        return self.cache_key_template.format(
            ident_hash=sha1_string(self.get_ident(request)))


class AuthTokenThrottler(throttling.BaseThrottle):
    cache = default_cache
    cache_key_template = 'drf_jwt_2fa-ta-{code_token_hash}'

    def allow_request(self, request, view):
        key = self.get_cache_key(request, view)
        if not key:
            return True
        now = time.time()
        next_allowed = self.cache.get(key)
        if next_allowed and next_allowed > now:
            self.wait_time = next_allowed - now
            return False
        self.cache.set(key, now + self.retry_wait_seconds)
        return True

    def wait(self):
        return self.wait_time

    def get_cache_key(self, request, view):
        code_token = request.data.get('code_token')
        return self.cache_key_template.format(
            code_token_hash=sha1_string(code_token)) if code_token else None

    @property
    def retry_wait_seconds(self):
        return api_settings.AUTH_TOKEN_RETRY_WAIT_TIME.total_seconds()
