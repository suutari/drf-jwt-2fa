from test_settings import *  # noqa: F403
from test_settings import PASSWORD_HASHERS

DEBUG = False
ALLOWED_HOSTS = ["*"]

del PASSWORD_HASHERS  # Don't use PASSWORD_HASHERS from test_settings

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_SSL_REDIRECT = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
