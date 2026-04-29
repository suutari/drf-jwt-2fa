import pytest
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import update_last_login
from django.contrib.auth.signals import user_logged_in
from django.test import override_settings
from django.urls import reverse
from rest_framework import status

from .factories import get_user
from .utils import (
    check_auth_token,
    check_code_token,
    get_api_client,
    get_verification_code_from_mailbox,
)


@pytest.mark.django_db
def test_get_code_token_success():
    token = get_code_token()
    check_code_token(token)


def get_code_token():
    get_user(username="testuser", password="a42")
    client = get_api_client()
    result = client.post(
        reverse("get-code"), data={"username": "testuser", "password": "a42"}
    )
    assert "token" in result.data
    assert isinstance(result.data, dict)
    assert result.status_code == status.HTTP_200_OK
    return result.data["token"]


def test_code_token_missing_fields():
    client = get_api_client()
    # Post without username field
    result = client.post(reverse("get-code"), data={"password": "abc"})
    assert sorted(result.data.keys()) == ["username"]
    assert result.status_code == status.HTTP_400_BAD_REQUEST
    assert result.data["username"] == ["This field is required."]


@pytest.mark.django_db
def test_code_token_invalid_password():
    get_user(username="testuser", password="a42")
    client = get_api_client()
    result = client.post(
        reverse("get-code"), data={"username": "testuser", "password": "wrong"}
    )
    assert result.data == {"detail": "Incorrect authentication credentials."}
    assert result.status_code == status.HTTP_401_UNAUTHORIZED


class InactiveAllowingAuthBackend(ModelBackend):
    def user_can_authenticate(self, user):
        return True


@override_settings(
    AUTHENTICATION_BACKENDS=[__name__ + ".InactiveAllowingAuthBackend"]
)
@pytest.mark.django_db
def test_code_token_inactive_user():
    user = get_user(username="testuser", password="a42")
    user.is_active = False
    user.save()
    client = get_api_client()
    result = client.post(
        reverse("get-code"), data={"username": "testuser", "password": "a42"}
    )
    assert result.data == {
        "detail": "You do not have permission to perform this action."
    }
    assert result.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_auth_token_success():
    code_token = get_code_token()
    code = get_verification_code_from_mailbox()
    client = get_api_client()
    result = client.post(
        reverse("auth"), data={"code_token": code_token, "code": code}
    )
    assert "access" in result.data
    assert "refresh" in result.data
    assert result.status_code == status.HTTP_200_OK
    token = result.data["access"]
    check_auth_token(token)


@pytest.mark.django_db
def test_auth_token_invalid_code():
    code_token = get_code_token()
    correct_code = get_verification_code_from_mailbox()
    code = "1234567" if correct_code != "1234567" else "7654321"
    client = get_api_client()
    result = client.post(
        reverse("auth"), data={"code_token": code_token, "code": code}
    )
    assert result.data == {"detail": "Incorrect authentication credentials."}
    assert result.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_auth_token_removed_user():
    code_token = get_code_token()
    code = get_verification_code_from_mailbox()
    user = get_user()
    user.delete()
    client = get_api_client()
    result = client.post(
        reverse("auth"), data={"code_token": code_token, "code": code}
    )
    assert result.data == {"detail": "Incorrect authentication credentials."}
    assert result.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_auth_token_fires_user_logged_in_signal():
    code_token = get_code_token()
    code = get_verification_code_from_mailbox()
    user = get_user()
    received = []

    def receiver(**kwargs):
        received.append(kwargs)

    user_logged_in.connect(receiver)
    try:
        client = get_api_client()
        result = client.post(
            reverse("auth"), data={"code_token": code_token, "code": code}
        )
    finally:
        user_logged_in.disconnect(receiver)
    assert result.status_code == status.HTTP_200_OK
    assert received == [
        {
            "signal": user_logged_in,
            "sender": type(user),
            "request": result.wsgi_request,
            "user": user,
        }
    ]


@pytest.mark.django_db
def test_auth_token_updates_last_login():
    code_token = get_code_token()
    code = get_verification_code_from_mailbox()
    user = get_user()
    assert user.last_login is None
    client = get_api_client()
    result = client.post(
        reverse("auth"), data={"code_token": code_token, "code": code}
    )
    assert result.status_code == status.HTTP_200_OK
    user.refresh_from_db()
    assert user.last_login is not None


@pytest.mark.django_db
def test_that_update_last_login_can_be_disconnected():
    user_logged_in.disconnect(dispatch_uid="update_last_login")
    try:
        code_token = get_code_token()
        code = get_verification_code_from_mailbox()
        user = get_user()
        assert user.last_login is None
        client = get_api_client()
        result = client.post(
            reverse("auth"), data={"code_token": code_token, "code": code}
        )
        assert result.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.last_login is None
    finally:
        user_logged_in.connect(
            update_last_login, dispatch_uid="update_last_login"
        )


@override_settings(
    SIMPLE_JWT={
        "TOKEN_OBTAIN_SERIALIZER": (
            "rest_framework_simplejwt.serializers.TokenRefreshSlidingSerializer"
        ),
    }
)
@pytest.mark.django_db
def test_auth_token_with_custom_obtainer():
    code_token = get_code_token()
    code = get_verification_code_from_mailbox()
    client = get_api_client()
    result = client.post(
        reverse("auth"), data={"code_token": code_token, "code": code}
    )
    assert "token" in result.data
    assert "access" not in result.data
    assert "refresh" not in result.data
    assert result.status_code == status.HTTP_200_OK
    token = result.data["token"]
    check_auth_token(token, token_type="sliding")
