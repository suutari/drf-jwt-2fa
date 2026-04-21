import time

import jwt
from django.contrib.auth import hashers as django_hashers
from django.core.cache import cache
from django.utils.crypto import get_random_string
from django.utils.translation import gettext as _
from rest_framework import exceptions

from .exceptions import (
    TooManyAuthAttemptsError,
    TooManyCodeTokensError,
    VerificationCodeSendingError,
)
from .sending import CodeSendingError, send_verification_code
from .settings import api_settings
from .utils import sha1_string


class CodeTokenManager:
    jwt_algorithm = "HS256"
    _auth_attempts_cache_key_template = (
        "drf_jwt_2fa:auth_attempts:{token_hash}"
    )
    _active_tokens_cache_key_template = "drf_jwt_2fa:active_tokens:{user_id}"

    @property
    def code_length(self):
        return api_settings.CODE_LENGTH

    @property
    def code_chars(self):
        return api_settings.CODE_CHARACTERS

    def create_code_token(self, user):
        """
        Create a code token and send a new verification code.

        Create a new code token for given user with a new randomly
        generated verification code.  The code token is returned and the
        verification code is sent via another channel (e.g. e-mail).

        Raises TooManyCodeTokensError if the user already has
        MAX_ACTIVE_CODE_TOKENS_PER_USER unexpired code tokens.

        :type user: django.contrib.auth.models.AbstractBaseUser
        :rtype: str
        """
        code = self.generate_verification_code()
        payload = self.get_token_payload(user, code)
        self._check_and_register_active_token(user.pk, payload["exp"])
        try:
            self.send_verification_code(user, code)
        except CodeSendingError as error:
            raise VerificationCodeSendingError(error) from error
        return self.encode_token(payload)

    def check_code_token_and_code(self, token, code):
        """
        Check code token and related verification code.

        Check integrity of the given code token and check that the
        verification code is correct for the given token.  Return
        username of the verified user, if both are OK, or raise a
        validation error otherwise.

        Raises TooManyAuthAttemptsError if the token has already
        exceeded MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN failed attempts.

        :type token: str
        :param token: Code token to check
        :type code: str
        :param code: Verification code to check against the token
        :rtype: str
        :return: Username of the verified user
        """
        payload = self.decode_token(token)
        self._check_auth_attempts_not_exceeded(token, payload)
        hashed_code = payload.get("vch")
        nonce = payload.get("vcn")
        if not self.is_verification_code_ok(code, nonce, hashed_code):
            self._record_failed_auth_attempt(token, payload)
            raise exceptions.AuthenticationFailed()
        return payload.get("usr")

    def _check_and_register_active_token(self, user_id, expiry):
        """
        Check if user is under the active token limit and register new token.

        :raises TooManyCodeTokensError: if limit is reached
        """
        max_tokens = api_settings.MAX_ACTIVE_CODE_TOKENS_PER_USER
        if max_tokens is None:
            return
        key = self._active_tokens_cache_key_template.format(user_id=user_id)
        now = time.time()
        active_expiries = [exp for exp in (cache.get(key) or []) if exp > now]
        if len(active_expiries) >= max_tokens:
            raise TooManyCodeTokensError()
        active_expiries.append(expiry)
        ttl = int(max(exp - now for exp in active_expiries)) + 1
        cache.set(key, active_expiries, timeout=ttl)

    def _auth_attempts_cache_key(self, token):
        return self._auth_attempts_cache_key_template.format(
            token_hash=sha1_string(token)
        )

    def _check_auth_attempts_not_exceeded(self, token, payload):
        max_attempts = api_settings.MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN
        if max_attempts is None:
            return
        attempts = cache.get(self._auth_attempts_cache_key(token)) or 0
        if attempts >= max_attempts:
            raise TooManyAuthAttemptsError()

    def _record_failed_auth_attempt(self, token, payload):
        max_attempts = api_settings.MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN
        if max_attempts is None:
            return
        key = self._auth_attempts_cache_key(token)
        ttl = max(int(payload.get("exp", time.time()) - time.time()), 1)
        if not cache.add(key, 1, timeout=ttl):
            cache.incr(key)

    def generate_verification_code(self):
        return get_random_string(self.code_length, self.code_chars)

    def get_token_payload(self, user, code):
        """
        Get code token for given user and verification code.

        :type user: django.contrib.auth.models.AbstractBaseUser
        :type code: str
        :rtype: dict[str, str|int]
        """
        now = int(time.time())
        expiration_time = api_settings.CODE_EXPIRATION_TIME
        expiration_seconds = int(expiration_time.total_seconds())
        (hashed_code, nonce) = self.hash_verification_code(code)
        return {
            "usr": user.get_username(),
            "vch": hashed_code,  # Verification Code Hash
            "vcn": nonce,  # Verification Code Nonce
            "iat": now,
            "exp": now + expiration_seconds,
        }

    def send_verification_code(self, user, code):
        send_verification_code(user, code)

    def encode_token(self, payload):
        key = api_settings.CODE_TOKEN_SECRET_KEY
        jwt_data = jwt.encode(payload, key, self.jwt_algorithm)
        return jwt_data

    def decode_token(self, token):
        try:
            return jwt.decode(
                jwt=token,
                key=api_settings.CODE_TOKEN_SECRET_KEY,
                verify=True,
                algorithms=[self.jwt_algorithm],
            )
        except jwt.ExpiredSignatureError:
            raise exceptions.PermissionDenied(
                _("Signature has expired.")
            ) from None
        except jwt.DecodeError:
            raise exceptions.AuthenticationFailed() from None

    def hash_verification_code(self, code):
        nonce = get_random_string(length=10)
        extended_code = self.extend_code(code, nonce)
        hashed_code = django_hashers.make_password(extended_code)
        return (hashed_code, nonce)

    def is_verification_code_ok(self, code, nonce, hashed_code):
        extended_code = self.extend_code(code, nonce)
        return django_hashers.check_password(extended_code, hashed_code)

    def extend_code(self, code, nonce):
        extension = api_settings.CODE_EXTENSION_SECRET
        return code + nonce + extension
