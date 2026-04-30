import pytest
from django.contrib.admin import site as admin_site
from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import User

from drf_jwt_2fa.admin import UserTwoFactorAuthDataAdmin
from drf_jwt_2fa.models import TwoFactorAuthMethod, UserTwoFactorAuthData


@pytest.fixture()
def admin_instance():
    return UserTwoFactorAuthDataAdmin(UserTwoFactorAuthData, AdminSite())


def test_admin_registered():
    assert UserTwoFactorAuthData in admin_site._registry


def test_list_display(admin_instance):
    assert "user" in admin_instance.list_display
    assert "preferred_2fa_auth" in admin_instance.list_display
    assert "has_totp_secret" in admin_instance.list_display


def test_list_filter(admin_instance):
    assert "preferred_2fa_auth" in admin_instance.list_filter


def test_search_fields(admin_instance):
    assert "user__username" in admin_instance.search_fields
    assert "user__email" in admin_instance.search_fields


def test_readonly_fields(admin_instance):
    assert "user" in admin_instance.readonly_fields
    assert "totp_secret" in admin_instance.readonly_fields
    assert "totp_secret_pending" in admin_instance.readonly_fields


@pytest.mark.parametrize(
    "totp_secret, expected",
    [
        ("encryptedsecret", True),
        ("", False),
    ],
)
def test_has_totp_secret(admin_instance, totp_secret, expected):
    user = User(username="jane")
    obj = UserTwoFactorAuthData(
        user=user,
        preferred_2fa_auth=TwoFactorAuthMethod.TOTP,
        totp_secret=totp_secret,
    )
    assert admin_instance.has_totp_secret(obj) is expected
