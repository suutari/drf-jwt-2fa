DEBUG = True
SECRET_KEY = "not-so-secret-but-long-enough-to-avoid-Warnings-123"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3"}}

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.messages",
    "django.contrib.sessions",
    "drf_jwt_2fa",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
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

ROOT_URLCONF = "drf_jwt_2fa.urls"

# Use a fast hasher in tests to avoid slow PBKDF2 iterations.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
