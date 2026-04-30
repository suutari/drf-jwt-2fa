Django Rest Framework JWT 2FA Change Log
========================================

Unreleased
----------

* Add TOTP (Time-based One-Time Password) support

* Add endpoint for changing the preferred 2FA method

* Fire ``user_logged_in`` signal on successful authentication

  * Note: This updates ``user.last_login`` by default

* Drop support for Python 3.10, 3.11 and Django 2.2

* Add type annotations to all public and private methods

* Pass ``request`` to ``authenticate()`` in ``CodeTokenSerializer`` to
  support authentication backends that require the request object

* Normalize user primary key to string in code token payload

1.0.0 (Released 2026-04-24 19:54 +0200)
---------------------------------------

* Invalidate code token after successful authentication to prevent reuse

* Use ``:`` as delimiter in all cache keys

* Replace SHA-1 with more secure hashing for cache keys:

  * Throttle ident keys now use SHA-256 (truncated to 20 hex chars)
  * Code token cache keys now just use the jti part of the token

* Generate unique "jti" (JWT ID) for each code token

* Use user id (``user.pk``) instead of username in code tokens

* Allow only 5 authentication attempts per code token by default
  (configurable via ``MAX_AUTH_ATTEMPTS_PER_CODE_TOKEN`` setting)

* Allow only 3 active code tokens per user at a time by default
  (configurable via ``MAX_ACTIVE_CODE_TOKENS_PER_USER`` setting)

* Fix ``EMAIL_SENDER_FROM_ADDRESS`` setting being ignored when sending
  verification e-mails

* Wrap unexpected exceptions from a custom ``CODE_SENDER`` function in
  ``CodeSendingError`` and log them with a traceback, instead of letting
  them propagate unhandled

* Rename ``CodeSendingFailed`` to ``CodeSendingError`` and
  ``VerificationCodeSendingFailed`` to ``VerificationCodeSendingError``

* Tooling and Test Changes:

  * Replace flake8/isort with Ruff for linting and code formatting
  * Add Mypy for static type checking (code still unannotated though)
  * Separate ``lint`` and ``style`` Tox environments in CI
  * Remove dependency on the ``six`` library from tests
  * Replace ``mock`` usage with ``unittest.mock`` from stdlib

0.5.0 (Released 2026-04-01 13:37 +0300)
---------------------------------------

* Switch to DRF Simple JWT from drf-jwt
* Support for Django 6.0

0.4.0 (Released 2026-03-26 18:15 +0200)
---------------------------------------

* Support for Django versions from 2.2 to 5.2
* Support for Python 3.10 to 3.14
* Drop support for Django 1.x
* Drop support for Python 3.9 or older

0.3.0 (Released 2018-02-08 3:30 +0200)
--------------------------------------

* Change HTTP status codes of failure responses

0.2.0 (Released 2018-02-07 12:30 +0200)
---------------------------------------

* Implement throttling to the token views
* Increase default verification code length to 7 digits

0.1.0 (Released 2018-02-05 09:20 +0200)
---------------------------------------

First release.
