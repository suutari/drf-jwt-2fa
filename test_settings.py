SECRET_KEY = 'not-so-secret'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
    },
}

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
]

ROOT_URLCONF = 'drf_jwt_2fa.urls'
