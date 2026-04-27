import pyotp
import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken

from drf_jwt_2fa.models import TwoFactorAuthMethod, UserTwoFactorAuthData
from drf_jwt_2fa.totp import decrypt_totp_secret

from .factories import get_user
from .utils import check_auth_token, get_api_client


def _auth_client(user):
    """Return an APIClient authenticated with a fresh JWT access token."""
    token = AccessToken.for_user(user)
    client = get_api_client()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


# ---------------------------------------------------------------------------
# Setup endpoint
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_totp_setup_requires_authentication():
    client = get_api_client()
    result = client.post(reverse("totp-setup"))
    assert result.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_totp_setup_returns_secret_and_uri():
    user = get_user()
    client = _auth_client(user)
    result = client.post(reverse("totp-setup"))
    assert result.status_code == status.HTTP_200_OK
    assert "secret" in result.data
    assert "provisioning_uri" in result.data
    secret = result.data["secret"]
    assert len(secret) == 32
    # Secret must be valid base32
    pyotp.TOTP(secret)
    uri = result.data["provisioning_uri"]
    assert uri.startswith("otpauth://totp/")
    assert secret in uri


@pytest.mark.django_db
def test_totp_setup_stores_pending_secret():
    user = get_user()
    client = _auth_client(user)
    result = client.post(reverse("totp-setup"))
    assert result.status_code == status.HTTP_200_OK
    data = UserTwoFactorAuthData.objects.get(user=user)
    assert (
        decrypt_totp_secret(data.totp_secret_pending) == result.data["secret"]
    )
    # Preferred method must not yet be changed
    assert data.preferred_2fa_auth != TwoFactorAuthMethod.TOTP


@pytest.mark.django_db
def test_totp_setup_overwrites_previous_pending_secret():
    user = get_user()
    client = _auth_client(user)
    result1 = client.post(reverse("totp-setup"))
    result2 = client.post(reverse("totp-setup"))
    assert result1.status_code == status.HTTP_200_OK
    assert result2.status_code == status.HTTP_200_OK
    # The two calls must produce different secrets
    assert result1.data["secret"] != result2.data["secret"]
    data = UserTwoFactorAuthData.objects.get(user=user)
    assert (
        decrypt_totp_secret(data.totp_secret_pending) == result2.data["secret"]
    )


# ---------------------------------------------------------------------------
# Confirm endpoint
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_totp_confirm_requires_authentication():
    client = get_api_client()
    result = client.post(reverse("totp-confirm"), data={"code": "000000"})
    assert result.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_totp_confirm_succeeds_with_correct_code():
    user = get_user()
    client = _auth_client(user)
    # Start setup
    setup_result = client.post(reverse("totp-setup"))
    secret = setup_result.data["secret"]
    # Confirm with a valid code
    code = pyotp.TOTP(secret).now()
    result = client.post(reverse("totp-confirm"), data={"code": code})
    assert result.status_code == status.HTTP_200_OK


@pytest.mark.django_db
def test_totp_confirm_activates_totp_for_user():
    user = get_user()
    client = _auth_client(user)
    setup_result = client.post(reverse("totp-setup"))
    secret = setup_result.data["secret"]
    code = pyotp.TOTP(secret).now()
    client.post(reverse("totp-confirm"), data={"code": code})

    data = UserTwoFactorAuthData.objects.get(user=user)
    assert data.preferred_2fa_auth == TwoFactorAuthMethod.TOTP
    assert decrypt_totp_secret(data.totp_secret) == secret
    assert data.totp_secret_pending == ""


@pytest.mark.django_db
def test_totp_confirm_fails_with_wrong_code():
    user = get_user()
    client = _auth_client(user)
    setup_result = client.post(reverse("totp-setup"))
    secret = setup_result.data["secret"]
    correct_code = pyotp.TOTP(secret).now()
    wrong_code = "000000" if correct_code != "000000" else "111111"
    result = client.post(reverse("totp-confirm"), data={"code": wrong_code})
    assert result.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_totp_confirm_fails_without_setup():
    user = get_user()
    client = _auth_client(user)
    result = client.post(reverse("totp-confirm"), data={"code": "000000"})
    assert result.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_totp_confirm_fails_when_pending_secret_is_empty():
    user = get_user()
    # Create record but leave pending empty
    UserTwoFactorAuthData.objects.create(user=user, totp_secret_pending="")
    client = _auth_client(user)
    result = client.post(reverse("totp-confirm"), data={"code": "000000"})
    assert result.status_code == status.HTTP_403_FORBIDDEN


# ---------------------------------------------------------------------------
# Full enrollment + login round-trip
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_full_totp_enrollment_and_login():
    """Enrol via setup+confirm, then log in using the TOTP flow."""
    user = get_user()
    client = _auth_client(user)

    # Step 1: setup
    setup_result = client.post(reverse("totp-setup"))
    assert setup_result.status_code == status.HTTP_200_OK
    secret = setup_result.data["secret"]

    # Step 2: confirm
    code = pyotp.TOTP(secret).now()
    confirm_result = client.post(reverse("totp-confirm"), data={"code": code})
    assert confirm_result.status_code == status.HTTP_200_OK

    # Step 3: login with TOTP
    anon_client = get_api_client()
    code_token_result = anon_client.post(
        reverse("get-code"),
        data={"username": "testuser", "password": "a42"},
    )
    assert code_token_result.status_code == status.HTTP_200_OK
    code_token = code_token_result.data["token"]

    totp_code = pyotp.TOTP(secret).now()
    auth_result = anon_client.post(
        reverse("auth"),
        data={"code_token": code_token, "code": totp_code},
    )
    assert auth_result.status_code == status.HTTP_200_OK
    assert "access" in auth_result.data
    check_auth_token(auth_result.data["access"])
