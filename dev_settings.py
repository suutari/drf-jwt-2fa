import os

DEBUG = True
SECRET_KEY = "not-so-secret-but-long-enough-to-avoid-Warning-12"  # noqa: S105
DATABASES = {
    "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": "db.sqlite3"},
}

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_jwt_2fa",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

EMAIL_FILE_PATH = os.getenv("EMAIL_FILE_PATH")
EMAIL_BACKEND = (
    "django.core.mail.backends.filebased.EmailBackend"
    if EMAIL_FILE_PATH
    else "django.core.mail.backends.console.EmailBackend"
)

STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(os.path.dirname(__file__), "static")
ROOT_URLCONF = "dev_urls"
