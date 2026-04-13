from django.urls import path

from . import views

urlpatterns = [
    path("get-code/", views.obtain_code_token, name="get-code"),
    path("auth/", views.obtain_auth_token, name="auth"),
    path("refresh/", views.refresh_auth_token, name="refresh"),
    path("verify/", views.verify_auth_token, name="verify"),
]
