from django.contrib.auth import authenticate, get_user_model
from rest_framework import exceptions, serializers
from rest_framework_jwt.compat import Serializer as JwtSerializer
from rest_framework_jwt.serializers import PasswordField
from rest_framework_jwt.settings import api_settings as jwt_settings

from .token_manager import CodeTokenManager
from .utils import check_user_validity

jwt_encode_handler = jwt_settings.JWT_ENCODE_HANDLER
jwt_payload_handler = jwt_settings.JWT_PAYLOAD_HANDLER


class Jwt2faSerializer(JwtSerializer):
    token_manager_class = CodeTokenManager

    def __init__(self, *args, **kwargs):
        super(Jwt2faSerializer, self).__init__(*args, **kwargs)
        self.token_manager = self.token_manager_class()

    def validate(self, attrs):
        validated_attrs = super(Jwt2faSerializer, self).validate(attrs)
        user = self._authenticate(validated_attrs)
        return {
            'token': self._create_token(user),
            'user': user,
        }


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

    def _create_token(self, user):
        return self.token_manager.create_code_token(user)


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

    def _create_token(self, user):
        payload = jwt_payload_handler(user)
        return jwt_encode_handler(payload)
