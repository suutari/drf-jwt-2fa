import logging
import secrets
import time
from typing import NotRequired, TypedDict

import jwt
from django.contrib.auth import get_user_model
from django.contrib.auth import hashers as django_hashers
from django.contrib.auth.models import AbstractBaseUser
from django.core.cache import cache
from django.utils.crypto import get_random_string
from django.utils.translation import gettext as _
from rest_framework import exceptions

from .exceptions import (
    TokenAlreadyUsedError,
    TooManyAuthAttemptsError,
    TooManyCodeTokensError,
    TwoFactorAuthNotConfiguredError,
    VerificationCodeSendingError,
)
from .models import TwoFactorAuthMethod
from .sending import CodeSendingError
from .settings import api_settings
from .totp import verify_totp_code
from .utils import get_code_token_hash


class CodeTokenPayload(TypedDict):
    jti: str  # JWT ID
    uid: str  # User ID
    iat: int  # Issued at
    exp: int  # Expires at
    typ: NotRequired[str]  # Token type (code-sender or totp)
    vch: NotRequired[str]  # Verification Code Hash
    vcn: NotRequired[str]  # Verification Code Nonce


LOG = logging.getLogger(__name__)


class CodeTokenManager:
    jwt_algorithm = "HS256"
    _auth_attempts_cache_key_template = (
        "drf_jwt_2fa:auth_attempts:{token_hash}"
    )
    _active_tokens_cache_key_template = "drf_jwt_2fa:active_tokens:{user_id}"
    _used_tokens_cache_key_template = "drf_jwt_2fa:used_token:{jti}"

    @property
    def code_length(self) -> int:
        return api_settings.CODE_LENGTH

    @property
    def code_chars(self) -> str:
        return api_settings.CODE_CHARACTERS

    def create_code_token(self, user: AbstractBaseUser) -> str | None:
        """
        Create a code token and, when applicable, send a verification code.

        The behaviour depends on the user's preferred 2FA method:

          * "totp": Build a TOTP code token; no code is sent because the
            user generates it themselves via an authenticator app.

          * "code-sender": Generate a random code, send it via the
            configured CODE_SENDER, and return a code-sender token.

          * "" or "no-2fa": The action is controlled by NO_2FA_BEHAVIOR:

            * "error": Raise TwoFactorAuthNotConfiguredError
            * "allow": Return None

        Raises TooManyCodeTokensError if the user already has
        MAX_ACTIVE_CODE_TOKENS_PER_USER unexpired code tokens.
        """
        method = api_settings.PREFERRED_2FA_METHOD_GETTER(user)

        if not method or method == TwoFactorAuthMethod.NO_2FA:
            if api_settings.NO_2FA_BEHAVIOR == "allow":
                return None
            raise TwoFactorAuthNotConfiguredError()

        if method == TwoFactorAuthMethod.TOTP:
            return self._create_totp_code_token(user)

        return self._create_code_sender_token(user)

    def _create_code_sender_token(self, user: AbstractBaseUser) -> str:
        code = self.generate_verification_code()
        payload = self.get_code_sender_token_payload(user, code)
        self._check_and_register_active_token(str(user.pk), payload["exp"])
        try:
            self.send_verification_code(user, code)
        except CodeSendingError as error:
            raise VerificationCodeSendingError(error) from error
        return self.encode_token(payload)

    def _create_totp_code_token(self, user: AbstractBaseUser) -> str:
        payload = self.get_totp_token_payload(user)
        self._check_and_register_active_token(str(user.pk), payload["exp"])
        return self.encode_token(payload)

    def check_code_token_and_code(self, token: str, code: str) -> str:
        """
        Check code token and related verification code.

        Check integrity of the given code token and check that the
        verification code is correct for the given token.  Return
        primary key of the verified user, if both are OK, or raise a
        validation error otherwise.

        Raises TooManyAuthAttemptsError if the token has already
        exceeded MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN failed attempts.

        :param token: Code token to check
        :param code: Verification code to check against the token
        :return: Primary key of the verified user (as string)
        """
        payload = self.decode_token(token)
        self._check_auth_attempts_not_exceeded(token, payload)
        token_type = payload.get("typ", TwoFactorAuthMethod.CODE_SENDER)

        if token_type == TwoFactorAuthMethod.TOTP:
            code_ok = self._verify_totp_code(payload, code)
        else:
            hashed_code = payload["vch"]
            nonce = payload["vcn"]
            code_ok = self.is_verification_code_ok(code, nonce, hashed_code)

        if not code_ok:
            self._record_failed_auth_attempt(token, payload)
            raise exceptions.AuthenticationFailed()
        self._reserve_token(payload)
        return payload.get("uid")

    def _verify_totp_code(self, payload: CodeTokenPayload, code: str) -> bool:
        user_id = payload.get("uid")
        user_model = get_user_model()
        try:
            user = user_model.objects.get(pk=user_id)
        except user_model.DoesNotExist:
            return False
        secret = api_settings.TOTP_SECRET_GETTER(user)
        if not secret:
            return False
        valid_window = api_settings.TOTP_VALID_WINDOW
        return verify_totp_code(secret, code, valid_window=valid_window)

    def _check_and_register_active_token(
        self, user_id: str, expiry: int
    ) -> None:
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

    def _check_auth_attempts_not_exceeded(
        self, token: str, payload: CodeTokenPayload
    ) -> None:
        max_attempts = api_settings.MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN
        if max_attempts is None:
            return
        attempts = cache.get(self._auth_attempts_cache_key(token)) or 0
        if attempts >= max_attempts:
            raise TooManyAuthAttemptsError()

    def _auth_attempts_cache_key(self, token: str) -> str:
        return self._auth_attempts_cache_key_template.format(
            token_hash=get_code_token_hash(token)
        )

    def _record_failed_auth_attempt(
        self, token: str, payload: CodeTokenPayload
    ) -> None:
        max_attempts = api_settings.MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN
        if max_attempts is None:
            return
        key = self._auth_attempts_cache_key(token)
        ttl = max(int(payload.get("exp", time.time()) - time.time()), 1)
        if not cache.add(key, 1, timeout=ttl):
            cache.incr(key)

    def _reserve_token(self, payload: CodeTokenPayload) -> None:
        key = self._used_tokens_cache_key(payload)
        ttl = max(int(payload.get("exp", time.time()) - time.time()), 1)
        if not cache.add(key, True, timeout=ttl):
            raise TokenAlreadyUsedError()

    def _used_tokens_cache_key(self, payload: CodeTokenPayload) -> str:
        jti = payload.get("jti", "")
        return self._used_tokens_cache_key_template.format(jti=jti)

    def generate_verification_code(self) -> str:
        return get_random_string(self.code_length, self.code_chars)

    def get_code_sender_token_payload(
        self, user: AbstractBaseUser, code: str
    ) -> CodeTokenPayload:
        now = int(time.time())
        expiration_time = api_settings.CODE_EXPIRATION_TIME
        expiration_seconds = int(expiration_time.total_seconds())
        (hashed_code, nonce) = self.hash_verification_code(code)
        return {
            "jti": secrets.token_urlsafe(api_settings.CODE_TOKEN_JTI_BYTES),
            "typ": str(TwoFactorAuthMethod.CODE_SENDER),
            "uid": str(user.pk),
            "vch": hashed_code,  # Verification Code Hash
            "vcn": nonce,  # Verification Code Nonce
            "iat": now,
            "exp": now + expiration_seconds,
        }

    def get_totp_token_payload(
        self, user: AbstractBaseUser
    ) -> CodeTokenPayload:
        now = int(time.time())
        expiration_time = api_settings.CODE_EXPIRATION_TIME
        expiration_seconds = int(expiration_time.total_seconds())
        return {
            "jti": secrets.token_urlsafe(api_settings.CODE_TOKEN_JTI_BYTES),
            "typ": str(TwoFactorAuthMethod.TOTP),
            "uid": str(user.pk),
            "iat": now,
            "exp": now + expiration_seconds,
        }

    def send_verification_code(
        self, user: AbstractBaseUser, code: str
    ) -> None:
        try:
            api_settings.CODE_SENDER(user, code)
        except CodeSendingError:
            raise
        except Exception as error:
            LOG.exception("Verification code sending failed")
            raise CodeSendingError(_("Unknown error")) from error

    def encode_token(self, payload: CodeTokenPayload) -> str:
        key = api_settings.CODE_TOKEN_SECRET_KEY
        jwt_data = jwt.encode(payload, key, self.jwt_algorithm)  # type: ignore
        return jwt_data

    def decode_token(self, token: str) -> CodeTokenPayload:
        try:
            payload = jwt.decode(
                jwt=token,
                key=api_settings.CODE_TOKEN_SECRET_KEY,
                verify=True,
                algorithms=[self.jwt_algorithm],
            )
        except jwt.ExpiredSignatureError:
            raise exceptions.PermissionDenied(_("Token has expired")) from None
        except jwt.DecodeError:
            raise exceptions.AuthenticationFailed() from None
        return payload  # type: ignore

    def hash_verification_code(self, code: str) -> tuple[str, str]:
        nonce = get_random_string(length=10)
        extended_code = self.extend_code(code, nonce)
        hashed_code = django_hashers.make_password(extended_code)
        return (hashed_code, nonce)

    def is_verification_code_ok(
        self, code: str, nonce: str, hashed_code: str
    ) -> bool:
        extended_code = self.extend_code(code, nonce)
        return django_hashers.check_password(extended_code, hashed_code)

    def extend_code(self, code: str, nonce: str) -> str:
        extension = api_settings.CODE_EXTENSION_SECRET
        return code + nonce + extension
