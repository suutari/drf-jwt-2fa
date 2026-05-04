from typing import Any, NamedTuple

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.signals import user_logged_in
from django.utils.module_loading import import_string
from rest_framework import exceptions, serializers
from rest_framework_simplejwt import settings as jwt_settings
from rest_framework_simplejwt.serializers import PasswordField

from .enrollment_token import EnrollmentToken
from .settings import api_settings
from .token_manager import CodeTokenManager, CodeVerificationResult
from .utils import check_user_validity


class UserData(NamedTuple):
    user: AbstractBaseUser
    trusted: bool | None


class Jwt2faSerializer(serializers.Serializer):
    token_manager_class = CodeTokenManager

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.token_manager = self.token_manager_class()

    def validate(self, attrs: dict[str, object]) -> dict[str, str]:
        validated_attrs = super().validate(attrs)
        user_data = self._authenticate(validated_attrs)
        return self._create_tokens(user_data)

    def _authenticate(
        self, attrs: dict[str, object]
    ) -> UserData:  # pragma: no cover
        raise NotImplementedError

    def _create_tokens(
        self, user_data: UserData
    ) -> dict[str, str]:  # pragma: no cover
        raise NotImplementedError


class CodeTokenSerializer(Jwt2faSerializer):
    username = serializers.CharField(required=True)
    password = PasswordField(write_only=True, required=True)

    def _authenticate(self, attrs: dict[str, object]) -> UserData:
        credentials = {
            "username": attrs["username"],
            "password": attrs["password"],
        }
        request = self.context.get("request")
        user = authenticate(request=request, **credentials)
        if not user:
            raise exceptions.AuthenticationFailed()
        check_user_validity(user)
        return UserData(user=user, trusted=None)

    def _create_tokens(self, user_data: UserData) -> dict[str, str]:
        user = user_data.user
        code_token = self.token_manager.create_code_token(user)
        if code_token is None:
            # Method is in TRUSTED_2FA_METHODS but requires no challenge
            # (e.g. "no-2fa"): skip second factor and issue auth tokens.
            return _create_auth_tokens_for_user(user, self.context)
        return {
            "token": code_token,
        }


class AuthTokenSerializer(Jwt2faSerializer):
    code_token = serializers.CharField(required=True)
    code = PasswordField(write_only=True, required=True)

    def _authenticate(self, attrs: dict[str, object]) -> UserData:
        code_token: str = attrs["code_token"]  # type: ignore
        code: str = attrs["code"]  # type: ignore
        check_result = self._check_code_token_and_code(code_token, code)
        user = self._get_user(check_result.user_id)
        return UserData(user=user, trusted=check_result.trusted)

    def _check_code_token_and_code(
        self, code_token: str, code: str
    ) -> CodeVerificationResult:
        return self.token_manager.check_code_token_and_code(code_token, code)

    def _get_user(self, user_id: str) -> AbstractBaseUser:
        user_model = get_user_model()
        try:
            user = user_model.objects.get(pk=user_id)
        except user_model.DoesNotExist:
            raise exceptions.AuthenticationFailed() from None
        check_user_validity(user)
        return user

    def _create_tokens(self, user_data: UserData) -> dict[str, str]:
        user = user_data.user
        if not user_data.trusted:
            return self._create_enrollment_token_for_user(user)
        return _create_auth_tokens_for_user(user, self.context)

    @classmethod
    def _create_enrollment_token_for_user(
        cls, user: AbstractBaseUser
    ) -> dict[str, str]:
        token = EnrollmentToken.for_user(user)
        return {api_settings.AUTH_RESULT_ENROLLMENT_TOKEN_KEY: str(token)}


def _create_auth_tokens_for_user(
    user: AbstractBaseUser, context: dict[str, Any]
) -> dict[str, str]:
    token = _get_token_class().for_user(user)
    drf_request = context.get("request")
    request = drf_request._request if drf_request else None
    user_logged_in.send(sender=type(user), request=request, user=user)
    if hasattr(token, "access_token"):
        # The keys are 'access' and 'refresh' by default
        access_key = api_settings.AUTH_RESULT_ACCESS_TOKEN_KEY
        refresh_key = api_settings.AUTH_RESULT_REFRESH_TOKEN_KEY
        return {
            access_key: str(token.access_token),
            refresh_key: str(token),
        }
    token_key = api_settings.AUTH_RESULT_OTHER_TOKEN_KEY
    return {token_key: str(token)}


def _get_token_class():
    serializer_name = jwt_settings.api_settings.TOKEN_OBTAIN_SERIALIZER
    token_serializer = import_string(serializer_name)
    return token_serializer.token_class
