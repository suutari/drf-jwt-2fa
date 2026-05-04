"""
Tests for the enrollment token feature.
"""

import pyotp
import pytest
from django.contrib.auth.signals import user_logged_in
from django.test import RequestFactory
from django.urls import reverse
from rest_framework import status
from rest_framework.request import Request
from rest_framework_simplejwt.tokens import AccessToken

from drf_jwt_2fa.enrollment_token import (
    EnrollmentToken,
    EnrollmentTokenAuthentication,
)
from drf_jwt_2fa.models import UserTwoFactorAuthData
from drf_jwt_2fa.totp import generate_totp_secret

from .factories import get_user
from .utils import (
    OverrideJwt2faSettings,
    check_auth_token,
    get_api_client,
    get_verification_code_from_mailbox,
)

# ---------------------------------------------------------------------------
# EnrollmentToken unit tests
# ---------------------------------------------------------------------------


def test_enrollment_token_type():
    """EnrollmentToken has token_type 'enrollment'."""
    assert EnrollmentToken.token_type == "enrollment"


def test_enrollment_token_authentication_class_exists():
    """EnrollmentTokenAuthentication can be instantiated."""
    EnrollmentTokenAuthentication()


@pytest.mark.django_db
def test_enrollment_token_authentication_ignores_non_bearer_auth_value():
    auth = EnrollmentTokenAuthentication()
    http_request = RequestFactory().get("/")
    http_request.META["HTTP_AUTHORIZATION"] = "Token sometoken"
    request = Request(http_request)
    result = auth.authenticate(request)

    assert result is None


# ---------------------------------------------------------------------------
# POST /auth/ returns enrollment token when 2FA method not trusted
# ---------------------------------------------------------------------------


@pytest.mark.django_db
@OverrideJwt2faSettings(
    TRUSTED_2FA_METHODS=["code-sender", "totp"],
    FALLBACK_2FA_METHOD="code-sender",
)
def test_auth_endpoint_returns_auth_token_on_trusted_method():
    """
    A user whose 2FA method IS in TRUSTED_2FA_METHODS gets full auth tokens
    (not an enrollment token) from POST /auth/.
    """
    get_user("testuser", "pw")
    client = get_api_client()
    get_code_result = client.post(
        reverse("get-code"),
        data={"username": "testuser", "password": "pw"},
    )
    assert get_code_result.status_code == status.HTTP_200_OK
    code_token = get_code_result.data["token"]
    code = get_verification_code_from_mailbox()

    result = client.post(
        reverse("auth"),
        data={"code_token": code_token, "code": code},
    )

    assert result.status_code == status.HTTP_200_OK
    assert "access" in result.data
    assert "enrollment_token" not in result.data


@pytest.mark.django_db
@OverrideJwt2faSettings(
    TRUSTED_2FA_METHODS=["totp"],  # code-sender not trusted
    FALLBACK_2FA_METHOD="code-sender",
)
def test_auth_returns_enrollment_token_if_code_sender_not_trusted():
    """
    A brand-new user logging in with FALLBACK_2FA_METHOD not in
    TRUSTED_2FA_METHODS, returns an enrollment token.
    """
    client = get_api_client()
    (code_token, code) = _get_code_token_and_code(client)

    # Submit auth; code-sender not trusted -> enrollment token
    result = client.post(
        reverse("auth"),
        data={"code_token": code_token, "code": code},
    )

    assert result.status_code == status.HTTP_200_OK
    assert "enrollment_token" in result.data
    assert "access" not in result.data
    assert "refresh" not in result.data


def _get_code_token_and_code(client):
    get_user(username="newuser", password="pass123")
    get_code_result = client.post(
        reverse("get-code"),
        data={"username": "newuser", "password": "pass123"},
    )
    assert get_code_result.status_code == status.HTTP_200_OK
    code_token = get_code_result.data["token"]
    code = get_verification_code_from_mailbox()
    return (code_token, code)


@pytest.mark.django_db
@OverrideJwt2faSettings(
    TRUSTED_2FA_METHODS=["totp"],
    FALLBACK_2FA_METHOD="code-sender",
    AUTH_RESULT_ENROLLMENT_TOKEN_KEY="custom_enroll_key",
)
def test_auth_returns_enrollment_token_with_custom_key():
    """AUTH_RESULT_ENROLLMENT_TOKEN_KEY controls the response key name."""
    client = get_api_client()
    (code_token, code) = _get_code_token_and_code(client)

    result = client.post(
        reverse("auth"),
        data={"code_token": code_token, "code": code},
    )

    assert result.status_code == status.HTTP_200_OK
    assert "custom_enroll_key" in result.data
    assert "enrollment_token" not in result.data


@pytest.mark.django_db
@OverrideJwt2faSettings(
    TRUSTED_2FA_METHODS=["totp"],
    FALLBACK_2FA_METHOD="code-sender",
)
def test_enrollment_token_does_not_fire_user_logged_in_signal():
    """user_logged_in is NOT fired when an enrollment token is returned."""
    signal_calls = []
    user_logged_in.connect(
        lambda **kw: signal_calls.append(kw),
        dispatch_uid="test_enrollment_token_signal",
    )

    try:
        client = get_api_client()
        (code_token, code) = _get_code_token_and_code(client)

        result = client.post(
            reverse("auth"),
            data={"code_token": code_token, "code": code},
        )
    finally:
        user_logged_in.disconnect(dispatch_uid="test_enrollment_token_signal")

    assert result.status_code == status.HTTP_200_OK
    assert "enrollment_token" in result.data
    assert signal_calls == []


# ---------------------------------------------------------------------------
# TOTP setup/confirm endpoints accept enrollment token
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_totp_setup_accepts_enrollment_token():
    """POST /totp/setup/ works with a valid enrollment token."""
    user = get_user()
    token = EnrollmentToken.for_user(user)
    client = get_api_client()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    result = client.post(reverse("totp-setup"))
    assert result.status_code == status.HTTP_200_OK
    assert "secret" in result.data


@pytest.mark.django_db
def test_totp_confirm_accepts_enrollment_token():
    """POST /totp/confirm/ works with a valid enrollment token."""
    user = get_user()
    secret = generate_totp_secret()
    data, _ = UserTwoFactorAuthData.objects.get_or_create(user=user)
    data.set_pending_totp_secret(secret)
    data.save(update_fields=["encrypted_totp_secret_pending"])

    token = EnrollmentToken.for_user(user)
    client = get_api_client()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    code = pyotp.TOTP(secret).now()
    result = client.post(reverse("totp-confirm"), data={"code": code})
    assert result.status_code == status.HTTP_200_OK


@pytest.mark.django_db
def test_totp_setup_rejects_invalid_enrollment_token():
    """POST /totp/setup/ rejects a tampered/invalid enrollment token."""
    client = get_api_client()
    client.credentials(HTTP_AUTHORIZATION="Bearer not.a.valid.token")
    result = client.post(reverse("totp-setup"))
    assert result.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_totp_setup_allows_access_token():
    """A regular access token is still accepted by SetupTotpView."""
    user = get_user()
    access_token = AccessToken.for_user(user)
    client = get_api_client()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    result = client.post(reverse("totp-setup"))
    assert result.status_code == status.HTTP_200_OK


# ----------------------------------------------------------------------
# Full bootstrap flow: new user -> enrollment token -> TOTP -> login
# ----------------------------------------------------------------------


@pytest.mark.django_db
@OverrideJwt2faSettings(
    TRUSTED_2FA_METHODS=["totp"],
    FALLBACK_2FA_METHOD="code-sender",
)
def test_full_bootstrap_enrollment_flow():
    """
    A new user with code-sender 2FA can bootstrap TOTP via an enrollment
    token when code-sender is not in TRUSTED_2FA_METHODS.
    """
    client = get_api_client()

    # Step 1: Get code token and code via /get-code/ and POST to /auth/
    (code_token, code) = _get_code_token_and_code(client)
    result = client.post(
        reverse("auth"),
        data={"code_token": code_token, "code": code},
    )
    assert result.status_code == status.HTTP_200_OK
    assert "enrollment_token" in result.data
    enrollment_token = result.data["enrollment_token"]

    # Step 2: Use enrollment token to set up TOTP
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {enrollment_token}")
    result = client.post(reverse("totp-setup"))
    assert result.status_code == status.HTTP_200_OK
    secret = result.data["secret"]

    # Step 3: Confirm TOTP with enrollment token
    totp_code = pyotp.TOTP(secret).now()
    result = client.post(reverse("totp-confirm"), data={"code": totp_code})
    assert result.status_code == status.HTTP_200_OK

    # Step 4: subsequent login uses TOTP (trusted) -> full auth tokens
    client.credentials()  # clear credentials
    result = client.post(
        reverse("get-code"),
        data={"username": "newuser", "password": "pass123"},
    )
    assert result.status_code == status.HTTP_200_OK
    totp_code_token = result.data["token"]

    totp_code = pyotp.TOTP(secret).now()
    result = client.post(
        reverse("auth"),
        data={"code_token": totp_code_token, "code": totp_code},
    )
    assert result.status_code == status.HTTP_200_OK
    assert "access" in result.data
    assert "refresh" in result.data
    check_auth_token(result.data["access"])
