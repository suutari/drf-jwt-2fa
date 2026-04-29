DEBUG = True
SECRET_KEY = "not-so-secret-but-long-enough-to-avoid-Warnings-123"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3"}}

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
]

ROOT_URLCONF = "drf_jwt_2fa.urls"

# Use a fast hasher in tests to avoid slow PBKDF2 iterations.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
