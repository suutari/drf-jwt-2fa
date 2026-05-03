from unittest.mock import Mock, patch

from django.contrib.auth.models import User

from drf_jwt_2fa.models import TwoFactorAuthMethod, UserTwoFactorAuthData
from drf_jwt_2fa.token_manager import CodeTokenManager

from .utils import check_code_token


def get_user(username="testuser", password="a42", email="testuser@localhost"):
    user = User.objects.get_or_create(username=username)[0]
    user.set_password(password)
    user.email = email
    user.is_active = True
    user.save()
    return user


def get_user_with_2fa_method(
    method,
    username="testuser",
    password="a42",
    email="testuser@localhost",
    totp_secret="",
):
    """
    Create (or fetch) a user and set their preferred 2FA method.
    """

    user = get_user(username=username, password=password, email=email)
    data, _created = UserTwoFactorAuthData.objects.update_or_create(
        user=user,
        defaults={"preferred_2fa_auth": method},
    )
    data.set_totp_secret(totp_secret)
    data.save(update_fields=["encrypted_totp_secret"])
    return user


def get_user_with_code_sender_2fa(**kwargs):
    return get_user_with_2fa_method(TwoFactorAuthMethod.CODE_SENDER, **kwargs)


def get_user_with_totp_2fa(totp_secret, **kwargs):
    return get_user_with_2fa_method(
        TwoFactorAuthMethod.TOTP, totp_secret=totp_secret, **kwargs
    )


def get_code_token_and_its_jti():
    (token, payload) = get_code_token_and_its_payload()
    return (token, payload["jti"])


def get_code_token_and_its_payload():
    token = get_code_token()
    return (token, check_code_token(token))


def get_code_token(verification_code="1234567"):
    """
    Create a code-sender code token for a mock user, bypassing the
    preferred-2FA-method lookup (which requires a database).
    """
    manager = CodeTokenManager()
    manager.generate_verification_code = lambda: verification_code
    user = Mock()
    user.pk = 9876
    user.username = "testuser"
    user.email = "testuser@localhost"
    # Bypass PREFERRED_2FA_METHOD_GETTER; call the internal method directly.
    with patch.object(manager, "send_verification_code", lambda u, c: None):
        return manager._create_code_sender_token(user)
