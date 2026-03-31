from django.contrib.auth import authenticate, get_user_model
from django.utils.module_loading import import_string
from rest_framework import exceptions, serializers
from rest_framework_simplejwt.settings import api_settings as jwt_settings

from .settings import api_settings
from .token_manager import CodeTokenManager
from .utils import check_user_validity


class PasswordField(serializers.CharField):
    def __init__(self, *args, **kwargs):
        if 'style' not in kwargs:
            kwargs['style'] = {'input_type': 'password'}
        else:
            kwargs['style']['input_type'] = 'password'
        super(PasswordField, self).__init__(*args, **kwargs)


class Jwt2faSerializer(serializers.Serializer):
    token_manager_class = CodeTokenManager

    def __init__(self, *args, **kwargs):
        super(Jwt2faSerializer, self).__init__(*args, **kwargs)
        self.token_manager = self.token_manager_class()

    def validate(self, attrs):
        validated_attrs = super(Jwt2faSerializer, self).validate(attrs)
        user = self._authenticate(validated_attrs)
        return self._create_tokens(user)


class CodeTokenSerializer(Jwt2faSerializer):
    username = serializers.CharField(required=True)
    password = PasswordField(write_only=True, required=True)

    def _authenticate(self, attrs):
        credentials = {
            'username': attrs.get('username'),
            'password': attrs.get('password'),
        }
        user = authenticate(**credentials)
        if not user:
            raise exceptions.AuthenticationFailed()
        check_user_validity(user)
        return user

    def _create_tokens(self, user):
        return {
            'token': self.token_manager.create_code_token(user),
        }


class AuthTokenSerializer(Jwt2faSerializer):
    code_token = serializers.CharField(required=True)
    code = PasswordField(write_only=True, required=True)

    def _authenticate(self, attrs):
        code_token = attrs.get('code_token')
        code = attrs.get('code')
        username = self._check_code_token_and_code(code_token, code)
        user = self._get_user(username)
        return user

    def _check_code_token_and_code(self, code_token, code):
        return self.token_manager.check_code_token_and_code(code_token, code)

    def _get_user(self, username):
        user_model = get_user_model()
        try:
            user = user_model.objects.get_by_natural_key(username)
        except user_model.DoesNotExist:
            raise exceptions.AuthenticationFailed()
        check_user_validity(user)
        return user

    def _create_tokens(self, user):
        token = self.get_token_class().for_user(user)
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

    @classmethod
    def get_token_class(cls):
        token_serializer = import_string(jwt_settings.TOKEN_OBTAIN_SERIALIZER)
        return token_serializer.token_class
