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

Configuration Examples
----------------------

Email Code with Optional TOTP (Default)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

====================================  =====================================
Effect                                Behaviour
====================================  =====================================
Before user has 2FA configured        Uses email code 2FA for login
``POST /get-code/``                   Returns Code Token
``POST /auth/`` with email code       Returns Auth Token
``POST /auth/`` with TOTP code        Returns Auth Token
TOTP enrollment                       Available, needs Auth Token
Switchable via ``POST /2fa-method/``  ``code-sender``, ``totp``
====================================  =====================================

This is the out-of-the-box behaviour.  No settings changes are needed;
the block below shows the relevant defaults explicitly for clarity::

  JWT2FA_AUTH = {
      'TRUSTED_2FA_METHODS': ['code-sender', 'totp'],
      'FALLBACK_2FA_METHOD': 'code-sender',
  }

All users authenticate with an email-delivered verification code by
default.  Users who want to use a TOTP authenticator app can self-enroll
at any time (see `TOTP Enrollment`_); enrolling automatically switches
their preferred method to TOTP.  If they later want to go back to email
codes they can do so via ``POST /2fa-method/``::

  POST /2fa-method/ {"method": "code-sender"}

Both methods coexist; each user independently chooses which one to use.

TOTP Required
~~~~~~~~~~~~~

====================================  =========================================
Effect                                Behaviour
====================================  =========================================
Before user has 2FA configured        Uses email code 2FA for TOTP enrollment
``POST /get-code/``                   Returns Code Token
``POST /auth/`` with email code       Returns Enrollment Token
``POST /auth/`` with TOTP code        Returns Auth Token
TOTP enrollment                       Mandatory, needs Enrollment or Auth Token
Switchable via ``POST /2fa-method/``  ``totp`` only
====================================  =========================================

TOTP is the only accepted second factor.  Users who have not yet
enrolled a TOTP authenticator app are bootstrapped via an
email-delivered code: ``POST /auth/`` succeeds but returns an
**Enrollment Token** (``enrollment_token`` key) rather than a full Auth
Token (``access`` and ``refresh`` keys).  The Enrollment Token is
accepted only by the TOTP enrollment endpoints (``POST /totp/setup/``
and ``POST /totp/confirm/``); it is rejected everywhere else::

  JWT2FA_AUTH = {
      'TRUSTED_2FA_METHODS': ['totp'],
      'FALLBACK_2FA_METHOD': 'code-sender',
  }

First-time setup (TOTP not yet enrolled)::

  # Step 1: Obtain a code token (email sent)
  POST /get-code/  {"username": "alice", "password": "..."}
  -> {"token": "<code_token>"}

  # Step 2: Verify email code
  POST /auth/  {"code_token": "...", "code": "1234567"}
  -> {"enrollment_token": "<enrollment_token>"}

  # Step 3: Enroll TOTP using the Enrollment Token
  POST /totp/setup/   (Authorization: Bearer <enrollment_token>)
  -> {"secret": "BASE32...", "provisioning_uri": "otpauth://totp/..."}

  # Step 4: Confirm TOTP enrollment
  POST /totp/confirm/  {"code": "123456"}
  -> {}  (HTTP 200)

Logins after TOTP is enrolled::

  # Step 1: Obtain a code token (no email sent; typ: "totp")
  POST /get-code/  {"username": "alice", "password": "..."}
  -> {"token": "<code_token>"}

  # Step 2: Verify TOTP code
  POST /auth/  {"code_token": "...", "code": "654321"}
  -> {"access": "...", "refresh": "..."}

Note: ``POST /2fa-method/`` rejects switching to any method not in
``TRUSTED_2FA_METHODS``, so users cannot downgrade to email code or
disable 2FA entirely in this configuration.

No 2FA by Default
~~~~~~~~~~~~~~~~~

====================================  =============================================
Effect                                Behaviour
====================================  =============================================
Before user has 2FA configured        Auth Token issued directly
``POST /get-code/`` for no-2fa users  Returns Auth Token directly
``POST /get-code/`` for others        Returns Code Token
``POST /auth/`` with email code       Returns Auth Token
``POST /auth/`` with TOTP code        Returns Auth Token
TOTP enrollment                       Available, needs Auth Token
Switchable via ``POST /2fa-method/``  ``code-sender``, ``totp``, ``no-2fa``
====================================  =============================================

Users without a ``UserTwoFactorAuthData`` record skip 2FA entirely:
``POST /get-code/`` returns a full Auth Token directly without a second
step.  Users who have enrolled TOTP or set ``code-sender`` continue to
use those methods and go through the normal two-step flow.  All three
methods (including ``no-2fa``) are available via ``POST /2fa-method/``,
so users can opt in to a second factor or opt back out at will::

  JWT2FA_AUTH = {
      'TRUSTED_2FA_METHODS': ['code-sender', 'totp', 'no-2fa'],
      'FALLBACK_2FA_METHOD': 'no-2fa',
  }

Per-User 2FA Method
-------------------

Each user has a ``preferred_2fa_auth`` field stored in the
``UserTwoFactorAuthData`` model (or via a custom getter).  Possible
values are:

* ``""`` -- 2FA still unconfigured.  (Will be treated as "code-sender"
  by default, but this can be changed with the ``FALLBACK_2FA_METHOD``
  setting.)
* ``"no-2fa"`` -- 2FA explicitly disabled for the user.
* ``"code-sender"`` -- Send a verification code via ``CODE_SENDER``
  (e-mail by default).
* ``"totp"`` -- Require a TOTP code from an authenticator app.

Whether a given method results in a full Auth Token or an Enrollment
Token (or an error) is controlled by the ``TRUSTED_2FA_METHODS``
setting.  Methods not listed there are not accepted as a completed
second factor.

The 2FA method is looked up via the ``PREFERRED_2FA_METHOD_GETTER``
setting (a callable that receives a user and returns a string).  The
default implementation reads from ``UserTwoFactorAuthData``.

TOTP Enrollment
---------------

Users enroll a TOTP authenticator app using two endpoints that require
a valid JWT access token **or** an enrollment token (see
`Enrollment Token (Bootstrap Flow)`_ below):

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

Enrollment Token (Bootstrap Flow)
---------------------------------

When ``"code-sender"`` is not in ``TRUSTED_2FA_METHODS`` (for example,
because you want to require TOTP for everyone), a user who has not yet
enrolled a TOTP authenticator cannot complete a full login.  To allow
such users to set up TOTP without a chicken-and-egg problem, the
``POST /auth/`` endpoint returns an *enrollment token* instead of full
auth tokens when the user's 2FA method is not trusted.

The enrollment token is short-lived (default: 15 minutes) and grants
access only to the TOTP setup and confirm endpoints.  The
``user_logged_in`` signal is **not** fired when an enrollment token is
issued, because the user has not completed the full authentication flow
yet.

Changing the Preferred 2FA Method
---------------------------------

Authenticated users can change their preferred 2FA method via:

``POST /2fa-method/``
  Body: ``{"method": "<method>"}``

  Sets the user's preferred 2FA method.  Accepted values are determined
  by the TRUSTED_2FA_METHODS setting.

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
* ``PREFERRED_2FA_METHOD_GETTER(user)`` -> ``str`` -- one of
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
      # when user has no UserTwoFactorAuthData record or their method is
      # not yet configured.  Defaults to "code-sender".
      'FALLBACK_2FA_METHOD': 'code-sender',

      # Which 2FA methods are accepted as a completed second factor at
      # POST /auth/ and allowed to be set via POST /2fa-method/.  Methods
      # not in this list yield an Enrollment Token rather than a full Auth
      # Token.  Include "no-2fa" to allow users to skip the second factor
      # entirely.
      'TRUSTED_2FA_METHODS': ['code-sender', 'totp'],

      # Key used for the enrollment token in the POST /auth/ response
      # when the user's 2FA method is not in TRUSTED_2FA_METHODS.
      'AUTH_RESULT_ENROLLMENT_TOKEN_KEY': 'enrollment_token',

      # How long an enrollment token remains valid.
      'ENROLLMENT_TOKEN_EXPIRATION_TIME': datetime.timedelta(minutes=15),

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

Customising the Auth Token
--------------------------

The format of the Auth Token returned by the authentication endpoint can
be customised by setting the `TOKEN_OBTAIN_SERIALIZER`_ in
``SIMPLE_JWT`` settings to point to your own serializer class.  The
token type is determined by the ``token_class`` property of that
serializer.  For example, to return a sliding token instead of an access
token, you can set::

  SIMPLE_JWT = {
      'TOKEN_OBTAIN_SERIALIZER': (
          'rest_framework_simplejwt.serializers.TokenObtainSlidingSerializer'
      ),
  }

.. _TOKEN_OBTAIN_SERIALIZER:
   https://django-rest-framework-simplejwt.readthedocs.io/en/latest/settings.html#token-obtain-serializer

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
