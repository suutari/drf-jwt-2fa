from unittest.mock import Mock

from django.contrib.auth.models import User

from drf_jwt_2fa.token_manager import CodeTokenManager

from .utils import check_code_token


def get_user(username="testuser", password="a42", email="testuser@localhost"):
    user = User.objects.get_or_create(username=username)[0]
    user.set_password(password)
    user.email = email
    user.is_active = True
    user.save()
    return user


def get_code_token_and_its_jti():
    (token, payload) = get_code_token_and_its_payload()
    return (token, payload["jti"])


def get_code_token_and_its_payload():
    token = get_code_token()
    return (token, check_code_token(token))


def get_code_token(verification_code="1234567"):
    manager = CodeTokenManager()
    manager.generate_verification_code = lambda: verification_code
    user = Mock()
    user.pk = 9876
    user.username = "testuser"
    user.email = "testuser@localhost"
    return manager.create_code_token(user)
