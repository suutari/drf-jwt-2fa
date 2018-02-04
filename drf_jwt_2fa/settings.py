import datetime

from django.conf import settings
from rest_framework.settings import APISettings

from .utils import hash_string

USER_SETTINGS = getattr(settings, 'JWT2FA_AUTH', None)

DEFAULTS = {
    # Secret key to use for signing the Code Tokens
    'CODE_TOKEN_SECRET_KEY': hash_string('2fa-code-' + settings.SECRET_KEY),

    # Secret string to extend the verification code with
    'CODE_EXTENSION_SECRET': hash_string('2fa-ext-' + settings.SECRET_KEY),

    # How long the code is valid
    'CODE_EXPIRATION_TIME': datetime.timedelta(minutes=5),

    # Function that sends the verification code to the user
    'CODE_SENDER': 'drf_jwt_2fa.sending.send_verification_code_via_email',

    # From Address used by the e-mail sender
    'EMAIL_SENDER_FROM_ADDRESS': settings.DEFAULT_FROM_EMAIL,

    # Set to this to a (translated) string to override the default
    # message subject of the e-mail sender
    'EMAIL_SENDER_SUBJECT_OVERRIDE': None,

    # Set to this to a (translated) string to override the default
    # message body of the e-mail sender
    'EMAIL_SENDER_BODY_OVERRIDE': None,
}

IMPORT_STRINGS = [
    'CODE_SENDER',
]

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
