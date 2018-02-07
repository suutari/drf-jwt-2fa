Django Rest Framework JWT 2FA
=============================

This package provides a Two Factor Authentication for Django Rest
Framework using JSON Web Tokens.  The implementation is based on another
DRF authentication library called `REST framework JWT Auth <drf-jwt_>`_.

.. _drf-jwt: https://github.com/GetBlimp/django-rest-framework-jwt

|PyPI| |Test Status| |Coverage|

.. |PyPI| image::
   https://img.shields.io/pypi/v/drf-jwt-2fa.svg
   :target: https://pypi.python.org/pypi/drf-jwt-2fa/

.. |Test Status| image::
   https://img.shields.io/travis/suutari/drf-jwt-2fa.svg
   :target: https://travis-ci.org/suutari/drf-jwt-2fa

.. |Coverage| image::
   https://img.shields.io/codecov/c/github/suutari/drf-jwt-2fa.svg
   :target: https://codecov.io/gh/suutari/drf-jwt-2fa

Overview
--------

The authentication flow uses two JWT tokens and a verification code:

* First a token called Code Token is requested by providing username and
  password.  If the username and the password are correct, a random
  (7 digit) verification code is generated and sent by e-mail to the
  user's e-mail address.  This verification code is hashed with the
  Django's password hasher and the hash is included to the Code Token.

* After the verification code is received a second token called
  Authentication Token can be requested.  The request is done by
  sending the Code Token and the verification code to another endpoint.
  If the token and the code are correct, an authentication token is
  returned.  This authentication token can be used to authenticate the
  following API requests.  It is in the same format as the JWT tokens
  of the `REST framework JWT Auth <drf-jwt_>`_.

Requirements
------------

* Python 2.7, 3.4, 3.5, or 3.6
* Django 1.11 or 2.0
* Django Rest Framework

Installation
------------

Install the package from PyPI with::

  pip install drf-jwt-2fa

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


Note: Authentication token options can be configured with the
``JWT_AUTH`` configuration item as documented in `REST framework JWT
Auth <drf-jwt_>`_.


The URLs for the authentication API endpoints can be configured with
something like this in an `urls.py`::

  import drf_jwt_2fa.urls
  from django.conf.urls import include, url

  urlpatterns = [
      url(r'^auth/', include(drf_jwt_2fa.urls), namespace='auth'),
  ]

or by configuring each view individually::

  from django.conf.urls import include, url
  from drf_jwt_2fa.views import obtain_auth_token, obtain_code_token

  urlpatterns = [
      url(r'^get-code-token/', obtain_code_token),
      url(r'^get-auth-token/', obtain_auth_token),
  ]

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
