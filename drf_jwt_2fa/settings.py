import datetime
from typing import Protocol, get_type_hints, runtime_checkable

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
from django.utils.module_loading import import_string

from .utils import derive_key


@runtime_checkable
class CodeSender(Protocol):
    def __call__(self, user: AbstractBaseUser, code: str) -> None: ...


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
    }


_IMPORT_STRINGS = {"CODE_SENDER"}


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
