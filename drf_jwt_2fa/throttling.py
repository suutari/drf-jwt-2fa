import time
from hashlib import sha256 as ident_hasher

from django.core.cache import cache as default_cache
from rest_framework import throttling
from rest_framework.request import Request
from rest_framework.views import APIView

from .settings import api_settings
from .utils import get_code_token_hash


class CodeTokenThrottler(throttling.SimpleRateThrottle):
    cache_key_template = "drf_jwt_2fa:throttle:code:{ident_hash}"

    def get_rate(self) -> str:
        return api_settings.CODE_TOKEN_THROTTLE_RATE

    def parse_rate(self, rate: str | None) -> tuple[int | None, int | None]:
        if not rate:
            return (None, None)
        (num_requests_str, period_str) = rate.split("/")
        period_num = int(period_str[:-1] or "1")
        period_unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[period_str[-1]]
        return (int(num_requests_str), period_num * period_unit)

    def get_cache_key(self, request: Request, view: APIView) -> str:
        ident_bytes = self.get_ident(request).encode("utf-8")
        ident_hash = ident_hasher(ident_bytes).hexdigest()[:20]
        return self.cache_key_template.format(ident_hash=ident_hash)


class AuthTokenThrottler(throttling.BaseThrottle):
    cache = default_cache
    cache_key_template = "drf_jwt_2fa:throttle:auth:{code_token_hash}"

    def allow_request(self, request: Request, view: APIView) -> bool:
        key = self.get_cache_key(request, view)
        if not key:
            return True
        now = time.time()
        next_allowed = self.cache.get(key)
        if next_allowed and next_allowed > now:
            self.wait_time = next_allowed - now
            return False
        next_allowed = now + self.retry_wait_seconds
        self.cache.set(key, next_allowed, timeout=self.retry_wait_seconds)
        return True

    def wait(self) -> float:
        return self.wait_time

    def get_cache_key(self, request: Request, view: APIView) -> str | None:
        token = request.data.get("code_token")
        if not token:
            return None
        token_hash = get_code_token_hash(token)
        return self.cache_key_template.format(code_token_hash=token_hash)

    @property
    def retry_wait_seconds(self) -> float:
        return api_settings.AUTH_TOKEN_RETRY_WAIT_TIME.total_seconds()
