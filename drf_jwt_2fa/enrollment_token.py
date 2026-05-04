"""
Enrollment token for TOTP setup after an untrusted 2FA method.

When a user completes the first factor (username + password) but their
preferred 2FA method is not in ``TRUSTED_2FA_METHODS`` (e.g. they have
not yet enrolled any second factor), the auth endpoint returns an
*enrollment token* instead of full auth tokens.  The enrollment token
can only be used to call the TOTP setup and confirm endpoints, allowing
the user to complete TOTP enrollment before getting full access.
"""

from rest_framework.request import Request
from rest_framework_simplejwt.authentication import AuthUser, JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import Token

from .settings import api_settings


class EnrollmentToken(Token):
    """A token granting access only to TOTP enrollment endpoints."""

    token_type = "enrollment"  # noqa: S105
    lifetime = api_settings.ENROLLMENT_TOKEN_EXPIRATION_TIME


class EnrollmentTokenAuthentication(JWTAuthentication):
    """
    JWT authentication that only accepts enrollment tokens.

    Used by the TOTP setup and confirm endpoints to allow a user who has
    completed the first factor (but whose 2FA method is not yet trusted)
    to enroll a TOTP authenticator.

    Returns ``None`` (instead of raising) when the provided token is not
    an enrollment token, so that a subsequent authenticator in
    ``authentication_classes`` can handle regular access tokens.
    """

    def authenticate(
        self, request: Request
    ) -> tuple[AuthUser, EnrollmentToken] | None:
        header = self.get_header(request)
        if header is None:
            return None
        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None
        try:
            validated_token = EnrollmentToken(raw_token)  # type: ignore
        except TokenError:
            # Not enrollment token: let another authenticator handle it
            return None
        user: AuthUser = self.get_user(validated_token)  # type: ignore
        return (user, validated_token)
