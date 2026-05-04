import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken

from drf_jwt_2fa.models import TwoFactorAuthMethod, UserTwoFactorAuthData

from .factories import get_user, get_user_with_totp_2fa
from .utils import OverrideJwt2faSettings, get_api_client


def _auth_client(user):
    """Return an APIClient authenticated with a fresh JWT access token."""
    token = AccessToken.for_user(user)
    client = get_api_client()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


@pytest.mark.django_db
def test_set_2fa_method_requires_authentication():
    client = get_api_client()
    result = client.post(reverse("set-2fa-method"), data={"method": "totp"})
    assert result.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_set_2fa_method_to_code_sender():
    user = get_user()
    client = _auth_client(user)
    result = client.post(
        reverse("set-2fa-method"), data={"method": "code-sender"}
    )
    assert result.status_code == status.HTTP_200_OK
    data = UserTwoFactorAuthData.objects.get(user=user)
    assert data.preferred_2fa_auth == TwoFactorAuthMethod.CODE_SENDER


@pytest.mark.django_db
def test_set_2fa_method_to_no_2fa_when_allowed():
    user = get_user()
    client = _auth_client(user)
    with OverrideJwt2faSettings(
        TRUSTED_2FA_METHODS=["code-sender", "totp", "no-2fa"]
    ):
        result = client.post(
            reverse("set-2fa-method"), data={"method": "no-2fa"}
        )
    assert result.status_code == status.HTTP_200_OK
    data = UserTwoFactorAuthData.objects.get(user=user)
    assert data.preferred_2fa_auth == TwoFactorAuthMethod.NO_2FA


@pytest.mark.django_db
def test_set_2fa_method_to_totp_with_enrolled_secret():
    totp_secret = "74GGLFFJJLNWGN4NHUQGQBHDQVVZR75J"
    user = get_user_with_totp_2fa(totp_secret)
    # Switch away from TOTP first so we can test switching back to it
    UserTwoFactorAuthData.objects.filter(user=user).update(
        preferred_2fa_auth=TwoFactorAuthMethod.CODE_SENDER
    )
    client = _auth_client(user)
    result = client.post(reverse("set-2fa-method"), data={"method": "totp"})
    assert result.status_code == status.HTTP_200_OK
    data = UserTwoFactorAuthData.objects.get(user=user)
    assert data.preferred_2fa_auth == TwoFactorAuthMethod.TOTP


@pytest.mark.django_db
@pytest.mark.parametrize("method", ["no-2fa", "totp"])
def test_set_2fa_method_forbidden_by_default(method):
    user = get_user()
    client = _auth_client(user)
    result = client.post(reverse("set-2fa-method"), data={"method": method})
    assert result.status_code == status.HTTP_403_FORBIDDEN
    assert not UserTwoFactorAuthData.objects.filter(user=user).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("method", ["", "invalid", "not-configured"])
def test_set_2fa_method_invalid_method(method):
    user = get_user()
    client = _auth_client(user)
    result = client.post(reverse("set-2fa-method"), data={"method": method})
    assert result.status_code == status.HTTP_400_BAD_REQUEST
