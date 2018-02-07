import datetime

from django.conf import settings
from rest_framework.settings import APISettings

from .utils import hash_string

USER_SETTINGS = getattr(settings, 'JWT2FA_AUTH', None)

DEFAULTS = {
    # Length of the verification code (digits)
    'CODE_LENGTH': 7,

    # Characters used in the verification code
    'CODE_CHARACTERS': '0123456789',

    # Secret key to use for signing the Code Tokens
    'CODE_TOKEN_SECRET_KEY': hash_string('2fa-code-' + settings.SECRET_KEY),

    # Secret string to extend the verification code with
    'CODE_EXTENSION_SECRET': hash_string('2fa-ext-' + settings.SECRET_KEY),

    # How long the code token is valid
    'CODE_EXPIRATION_TIME': datetime.timedelta(minutes=5),

    # Throttle limit for code token requests from same IP
    'CODE_TOKEN_THROTTLE_RATE': '12/3h',

    # How much time must pass between verification attempts, i.e. to
    # request authentication token with a with the same code token and a
    # verification code
    'AUTH_TOKEN_RETRY_WAIT_TIME': datetime.timedelta(seconds=2),

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
