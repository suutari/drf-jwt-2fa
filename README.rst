Django Rest Framework JWT 2FA
=============================

This package provides a Two Factor Authentication for Django Rest
Framework using JSON Web Tokens.  The implementation is based on another
DRF authentication library called `Simple JWT <simplejwt_>`_.

.. _simplejwt: https://github.com/jazzband/djangorestframework-simplejwt

|PyPI| |Coverage|

.. |PyPI| image::
   https://img.shields.io/pypi/v/drf-jwt-2fa.svg
   :target: https://pypi.python.org/pypi/drf-jwt-2fa/

.. |Coverage| image::
   https://img.shields.io/codecov/c/github/suutari/drf-jwt-2fa.svg
   :target: https://codecov.io/gh/suutari/drf-jwt-2fa

Overview
--------

The authentication flow uses two JWT tokens and a verification code.
Two second-factor methods are supported:

**Code-sender (e-mail by default)**

* First a token called Code Token is requested by providing username and
  password.  If the username and the password are correct, a random
  (7 digit) verification code is generated and sent by e-mail to the
  user's e-mail address.  This verification code is hashed with the
  Django's password hasher and the hash is included to the Code Token.

* After the verification code is received a second token called
  Authentication Token can be requested.  The request is done by
  sending the Code Token and the verification code to another endpoint.
  If the token and the code are correct, an authentication token is
  returned.

**TOTP (Time-based One-Time Password)**

Users who have enrolled a TOTP authenticator app can use TOTP codes
instead of e-mail codes:

* The Code Token request works the same way: The user submits username
  and password to ``POST /get-code/``.  The returned Code Token carries
  a ``typ: "totp"`` claim; no e-mail is sent.

* The user opens their authenticator app, reads the 6-digit code, and
  sends it together with the Code Token to ``POST /auth/``.  If both
  are correct an Authentication Token is returned.

TOTP enrollment is handled via dedicated endpoints (see `TOTP
Enrollment`_ below).

The Authentication Token is in the same format as the JWT tokens of
`Simple JWT <simplejwt_>`_.  With default configuration it is an access
token accompanied by a refresh token.

Requirements
------------

* Python 3.12 or newer
* Django 3.2 or newer
* Django Rest Framework
* Simple JWT
* pyotp 2.6 or newer

Installation
------------

Install the package from PyPI with::

  pip install drf-jwt-2fa

Add ``drf_jwt_2fa`` to ``INSTALLED_APPS`` and run migrations so the
``UserTwoFactorAuthData`` model table is created::

  INSTALLED_APPS = [
      ...
      'drf_jwt_2fa',
  ]

Then run::

  python manage.py migrate

Configuration
-------------

Configure Django Rest Framework to use the provided authentication class
by adding something like this to the settings::

  REST_FRAMEWORK = {
      'DEFAULT_AUTHENTICATION_CLASSES': [
          'drf_jwt_2fa.authentication.Jwt2faAuthentication',
      ]
      'DEFAULT_PERMISSION_CLASSES': [
          'rest_framework.permissions.IsAuthenticated',
      ],
  }


Note: Authentication token endpoint can return different kind of tokens
based on ``token_class`` property of the class configured as the
``TOKEN_OBTAIN_SERIALIZER`` for `Simple JWT <simplejwt_>`_.

The URLs for the authentication API endpoints can be configured with
something like this in an `urls.py`::

  import drf_jwt_2fa.urls
  from django.urls import include, path

  urlpatterns = [
      path("auth/", include(drf_jwt_2fa.urls)),
  ]

or by configuring each view individually::

  from django.urls import include, path
  from drf_jwt_2fa.views import obtain_auth_token, obtain_code_token

  urlpatterns = [
      path('get-code-token/', obtain_code_token),
      path('get-auth-token/', obtain_auth_token),
  ]

Per-User 2FA Method
-------------------

Each user has a ``preferred_2fa_auth`` field stored in the
``UserTwoFactorAuthData`` model (or via a custom getter).  Possible
values are:

* ``""`` -- 2FA still unconfigured.
* ``"no-2fa"`` -- 2FA explicitly disabled for the user.
* ``"code-sender"`` -- Send a verification code via ``CODE_SENDER``
  (e-mail by default).
* ``"totp"`` -- Require a TOTP code from an authenticator app.

For the ``""`` and ``"no-2fa"`` values the ``NO_2FA_BEHAVIOR`` setting
controls what happens: ``"error"`` (default) rejects the login;
``"allow"`` issues auth tokens directly without a second factor.

The 2FA method is looked up via the ``PREFERRED_2FA_METHOD_GETTER``
setting (a callable that receives a user and returns a string).  The
default implementation reads from ``UserTwoFactorAuthData``.

TOTP Enrollment
---------------

Users enroll a TOTP authenticator app using two endpoints that require
a valid JWT access token (``Authorization: Bearer <token>``):

``POST /totp/setup/``
  Returns a ``secret`` (base32 string) and a ``provisioning_uri``
  (``otpauth://`` URL).  Display the URI as a QR code for the user to
  scan with their authenticator app.  Calling this endpoint again
  generates a new pending secret.

``POST /totp/confirm/``
  Body: ``{"code": "<6-digit code from app>"}``

  Verifies the first code against the pending secret.  On success,
  activates TOTP as the user's preferred 2FA method and returns
  ``HTTP 200``.

Example enrollment flow::

  # 1. Obtain an access token via the normal login flow
  POST /get-code/ {"username": "alice", "password": "..."}  -> code_token
  POST /auth/     {"code_token": "...", "code": "..."}      -> access token

  # 2. Start TOTP setup (requires access token)
  POST /totp/setup/
  -> {"secret": "BASE32...", "provisioning_uri": "otpauth://totp/..."}

  # 3. Scan the QR code in the authenticator app, then confirm
  POST /totp/confirm/ {"code": "123456"}
  -> {}   (HTTP 200 = success)

  # 4. Subsequent logins use TOTP
  POST /get-code/ {"username": "alice", "password": "..."} -> totp_code_token
  POST /auth/     {"code_token": "...", "code": "654321"}  -> access token

Changing the Preferred 2FA Method
----------------------------------

Authenticated users can change their preferred 2FA method via:

``POST /2fa-method/``
  Body: ``{"method": "<method>"}``

  Sets the user's preferred 2FA method.  Accepted values:

  * ``"code-sender"`` -- receive a one-time code via the configured sender
    (e.g. e-mail).
  * ``"totp"`` -- use a TOTP authenticator app.  Requires an active TOTP
    secret to already be enrolled via the setup and confirm endpoints.
  * ``"no-2fa"`` -- disable the second factor entirely.  Only permitted
    when ``NO_2FA_BEHAVIOR`` is set to ``"allow"``; returns
    ``HTTP 403`` otherwise.

  Returns ``HTTP 200 {}`` on success.

Custom TOTP Storage
-------------------

If you store TOTP secrets in your own model instead of
``UserTwoFactorAuthData``, point the two getter settings at your own
callables::

  JWT2FA_AUTH = {
      'TOTP_SECRET_GETTER': 'myapp.totp.get_totp_secret',
      'PREFERRED_2FA_METHOD_GETTER': 'myapp.totp.get_preferred_method',
  }

Each callable receives a user instance and must return:

* ``TOTP_SECRET_GETTER(user)`` -> ``str | None`` -- the active TOTP
  secret (base32), or ``None`` if the user is not using TOTP.
* ``PREFERRED_2FA_METHOD_GETTER(user)`` -> ``str`` -- one of ``""``,
  ``"no-2fa"``, ``"code-sender"``, or ``"totp"``.

Additional Settings
-------------------

There are some additional settings that you can override.  Here are all the
available settings with their default values::

  JWT2FA_AUTH = {
      # Length of the verification code (digits)
      'CODE_LENGTH': 7,

      # Characters used in the verification code
      'CODE_CHARACTERS': '0123456789',

      # Secret key to use for signing the Code Tokens
      'CODE_TOKEN_SECRET_KEY': derive_key('2fa-code', settings.SECRET_KEY),

      # Secret string to extend the verification code with
      'CODE_EXTENSION_SECRET': derive_key('2fa-ext', settings.SECRET_KEY),

      # How long the code token is valid
      'CODE_EXPIRATION_TIME': datetime.timedelta(minutes=5),

      # Number of bytes to use for the code token JTI (JWT ID)
      'CODE_TOKEN_JTI_BYTES': 16,  # 16 bytes = 128 bits

      # Throttle limit for code token requests from same IP
      'CODE_TOKEN_THROTTLE_RATE': '12/3h',

      # How much time must pass between verification attempts, i.e. to
      # request authentication token with a with the same code token and a
      # verification code
      'AUTH_TOKEN_RETRY_WAIT_TIME': datetime.timedelta(seconds=2),

      # Maximum number of failed verification attempts allowed per code
      # token before the token is invalidated and further attempts are
      # rejected with HTTP 403.  Set to None to disable the limit.
      'MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN': 5,

      # Maximum number of unexpired code tokens a user may have at a time.
      # Requesting a new code token when the limit is reached returns
      # HTTP 429.  Set to None to disable the limit.
      'MAX_ACTIVE_CODE_TOKENS_PER_USER': 3,

      # Name of the keys for the token values in the dictionary returned
      # by the ObtainAuthToken view
      'AUTH_RESULT_ACCESS_TOKEN_KEY': 'access',
      'AUTH_RESULT_REFRESH_TOKEN_KEY': 'refresh',
      'AUTH_RESULT_OTHER_TOKEN_KEY': 'token',

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

      # Callable (user) -> str | None returning the active TOTP secret
      # for a user, or None if the user is not using TOTP.
      'TOTP_SECRET_GETTER': 'drf_jwt_2fa.getters.get_totp_secret_of_user',

      # Callable (user) -> str returning the user's preferred 2FA method
      # ("", "no-2fa", "code-sender", or "totp").
      'PREFERRED_2FA_METHOD_GETTER': (
          'drf_jwt_2fa.getters.get_preferred_2fa_method_of_user'
      ),

      # Fallback method returned by the default PREFERRED_2FA_METHOD_GETTER
      # when a user has no UserTwoFactorAuthData record or their method is
      # "" (NOT_CONFIGURED).  Defaults to "code-sender".
      'DEFAULT_2FA_AUTH_METHOD': 'code-sender',

      # What to do when a user's preferred method is "" or "no-2fa":
      # "error" raises a PermissionDenied (HTTP 403, default);
      # "allow" issues auth tokens directly without a second factor.
      'NO_2FA_BEHAVIOR': 'error',

      # Issuer name shown in authenticator apps during TOTP enrollment
      'TOTP_ISSUER_NAME': 'drf-jwt-2fa',

      # How many 30-second time steps around the current time are accepted
      # when verifying a TOTP code (to compensate for clock skew)
      'TOTP_VALID_WINDOW': 1,

      # 32-byte key used to encrypt TOTP secrets at rest.  Defaults to a
      # key derived from SECRET_KEY.  Set this explicitly to rotate the
      # encryption key independently of SECRET_KEY.
      'TOTP_ENCRYPTION_KEY': derive_key_bytes('2fa-totp-enc', SECRET_KEY),
  }

Login Signal
------------

The ``user_logged_in`` signal is fired on successful authentication
(i.e.  after the second step of the 2FA flow).  Django's built-in
``update_last_login`` receiver is connected to this signal by default,
so user's ``last_login`` field will be updated automatically.  If you
want to prevent such updates, you can disconnect the receiver from the
signal in your ``AppConfig.ready()``::

  from django.contrib.auth.signals import user_logged_in

  user_logged_in.disconnect(dispatch_uid="update_last_login")
