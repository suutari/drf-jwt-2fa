import datetime
from typing import Protocol, get_type_hints, runtime_checkable

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
from django.utils.module_loading import import_string

from .utils import derive_key


@runtime_checkable
class CodeSender(Protocol):
    def __call__(self, user: AbstractBaseUser, code: str) -> None: ...


@runtime_checkable
class TotpSecretGetter(Protocol):
    def __call__(self, user: AbstractBaseUser) -> str | None: ...


@runtime_checkable
class PreferredTwoFactorMethodGetter(Protocol):
    def __call__(self, user: AbstractBaseUser) -> str: ...


def _get_default_settings() -> dict[str, object]:
    return {
        "CODE_LENGTH": 7,
        "CODE_CHARACTERS": "0123456789",
        "CODE_TOKEN_SECRET_KEY": derive_key("2fa-code", settings.SECRET_KEY),
        "CODE_EXTENSION_SECRET": derive_key("2fa-ext", settings.SECRET_KEY),
        "CODE_EXPIRATION_TIME": datetime.timedelta(minutes=5),
        "CODE_TOKEN_JTI_BYTES": 16,
        "CODE_TOKEN_THROTTLE_RATE": "12/3h",
        "AUTH_TOKEN_RETRY_WAIT_TIME": datetime.timedelta(seconds=2),
        "MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN": 5,
        "MAX_ACTIVE_CODE_TOKENS_PER_USER": 3,
        "AUTH_RESULT_ACCESS_TOKEN_KEY": "access",
        "AUTH_RESULT_REFRESH_TOKEN_KEY": "refresh",
        "AUTH_RESULT_OTHER_TOKEN_KEY": "token",
        "CODE_SENDER": "drf_jwt_2fa.sending.send_verification_code_via_email",
        "EMAIL_SENDER_FROM_ADDRESS": settings.DEFAULT_FROM_EMAIL,
        "EMAIL_SENDER_SUBJECT_OVERRIDE": None,
        "EMAIL_SENDER_BODY_OVERRIDE": None,
        # Callable (user) -> str | None that returns the active TOTP secret
        # for a user, or None if the user does not use TOTP.
        "TOTP_SECRET_GETTER": "drf_jwt_2fa.totp.get_totp_secret_for_user",
        # Callable (user) -> str that returns the user's preferred 2FA
        # method.  Should return one of the TwoFactorAuthMethod values:
        # "" (none), "code-sender", or "totp".
        "PREFERRED_2FA_METHOD_GETTER": (
            "drf_jwt_2fa.totp.get_preferred_2fa_method_for_user"
        ),
        # Default 2FA method to use when a user has no preference.
        "DEFAULT_2FA_AUTH_METHOD": "code-sender",
        # Behaviour when a user's preferred_2fa_auth is "" or "no-2fa":
        # "error" (default) raises a PermissionDenied error;
        # "allow" issues auth tokens directly without a second factor.
        "NO_2FA_BEHAVIOR": "error",
        # Issuer name shown in authenticator apps during TOTP enrollment
        "TOTP_ISSUER_NAME": "drf-jwt-2fa",
        # How many 30-second time steps around the current time to accept
        # when verifying a TOTP code (to compensate for clock skew)
        "TOTP_VALID_WINDOW": 1,
    }


_IMPORT_STRINGS = {
    "CODE_SENDER",
    "TOTP_SECRET_GETTER",
    "PREFERRED_2FA_METHOD_GETTER",
}


class ApiSettings:
    CODE_LENGTH: int
    CODE_CHARACTERS: str
    CODE_TOKEN_SECRET_KEY: str
    CODE_EXTENSION_SECRET: str
    CODE_EXPIRATION_TIME: datetime.timedelta
    CODE_TOKEN_JTI_BYTES: int
    CODE_TOKEN_THROTTLE_RATE: str
    AUTH_TOKEN_RETRY_WAIT_TIME: datetime.timedelta
    MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN: int | None
    MAX_ACTIVE_CODE_TOKENS_PER_USER: int | None
    AUTH_RESULT_ACCESS_TOKEN_KEY: str
    AUTH_RESULT_REFRESH_TOKEN_KEY: str
    AUTH_RESULT_OTHER_TOKEN_KEY: str
    CODE_SENDER: CodeSender
    EMAIL_SENDER_FROM_ADDRESS: str
    EMAIL_SENDER_SUBJECT_OVERRIDE: str | None
    EMAIL_SENDER_BODY_OVERRIDE: str | None
    TOTP_SECRET_GETTER: TotpSecretGetter
    PREFERRED_2FA_METHOD_GETTER: PreferredTwoFactorMethodGetter
    DEFAULT_2FA_AUTH_METHOD: str
    NO_2FA_BEHAVIOR: str
    TOTP_ISSUER_NAME: str
    TOTP_VALID_WINDOW: int

    def __getattr__(self, name: str) -> object:
        if name not in type(self).__annotations__:
            raise AttributeError(name)
        user_settings: dict = getattr(settings, "JWT2FA_AUTH", None) or {}
        values = {**_get_default_settings(), **user_settings}
        self._resolve_imports(values)
        self._check_setting_types(values)
        self.__dict__.update(values)
        return self.__dict__[name]

    def _resolve_imports(self, values: dict[str, object]) -> None:
        for key in _IMPORT_STRINGS:
            value = values.get(key)
            if isinstance(value, str):
                values[key] = import_string(value)

    def _check_setting_types(self, values: dict[str, object]) -> None:
        for key, tp in get_type_hints(type(self)).items():
            value = values.get(key)
            if not isinstance(value, tp):
                tp_name = tp.__name__ if isinstance(tp, type) else str(tp)
                raise TypeError(
                    f"JWT2FA_AUTH setting {key!r} must be "
                    f"an instance of {tp_name}"
                )

    def reload(self) -> None:
        self.__dict__.clear()


api_settings = ApiSettings()
