from django.urls import path

from . import views

urlpatterns = [
    path("get-code/", views.obtain_code_token, name="get-code"),
    path("auth/", views.obtain_auth_token, name="auth"),
    path("refresh/", views.refresh_auth_token, name="refresh"),
    path("verify/", views.verify_auth_token, name="verify"),
    path("totp/setup/", views.setup_totp, name="totp-setup"),
    path("totp/confirm/", views.confirm_totp, name="totp-confirm"),
    path("2fa-method/", views.set_2fa_method, name="set-2fa-method"),
]
