from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt import views as jwt_views

from . import serializers, totp_serializers
from .authentication import Jwt2faAuthentication
from .serializers_2fa_method import Set2faMethodSerializer
from .throttling import AuthTokenThrottler, CodeTokenThrottler


class ObtainCodeToken(jwt_views.TokenObtainPairView):
    serializer_class = serializers.CodeTokenSerializer
    throttle_classes = (CodeTokenThrottler,)


class ObtainAuthToken(jwt_views.TokenObtainPairView):
    serializer_class = serializers.AuthTokenSerializer
    throttle_classes = (AuthTokenThrottler,)


class RefreshAuthToken(jwt_views.TokenRefreshView):
    pass


class VerifyAuthToken(jwt_views.TokenVerifyView):
    pass


class SetupTotpView(APIView):
    """
    Start TOTP enrollment for the authenticated user.

    Generates a new pending TOTP secret and returns the base32 secret
    and an ``otpauth://`` provisioning URI that can be displayed as a
    QR code for scanning by an authenticator app.

    Requires a valid JWT access token (``Authorization: Bearer <token>``).

    After scanning the QR code, call ``POST /totp/confirm/`` with the
    first code shown by the authenticator app to activate TOTP.
    """

    authentication_classes = (Jwt2faAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = totp_serializers.SetupTotpSerializer(
            data={}, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(serializer.save(), status=status.HTTP_200_OK)


class ConfirmTotpView(APIView):
    """
    Confirm TOTP enrollment for the authenticated user.

    Verifies the first TOTP ``code`` from the authenticator app against
    the pending secret created by ``POST /totp/setup/``.  On success,
    the pending secret becomes the active TOTP secret and the user's
    preferred 2FA method is switched to ``"totp"``.

    Requires a valid JWT access token (``Authorization: Bearer <token>``).
    """

    authentication_classes = (Jwt2faAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = totp_serializers.ConfirmTotpSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({}, status=status.HTTP_200_OK)


class Set2faMethodView(APIView):
    """
    Set the preferred 2FA method for the authenticated user.

    Accepts a ``method`` field with one of the following values:

    * ``"code-sender"`` -- receive a one-time code via the configured
      sender (e.g. e-mail).
    * ``"totp"`` -- use a TOTP authenticator app.  Requires an active
      TOTP secret to already be enrolled via ``POST /totp/setup/`` and
      ``POST /totp/confirm/``.
    * ``"no-2fa"`` -- disable the second factor entirely.  Only allowed
      when the ``NO_2FA_BEHAVIOR`` setting is ``"allow"``.

    Requires a valid JWT access token (``Authorization: Bearer <token>``).
    """

    authentication_classes = (Jwt2faAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = Set2faMethodSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({}, status=status.HTTP_200_OK)


obtain_code_token = ObtainCodeToken.as_view()
obtain_auth_token = ObtainAuthToken.as_view()
refresh_auth_token = RefreshAuthToken.as_view()
verify_auth_token = VerifyAuthToken.as_view()
setup_totp = SetupTotpView.as_view()
confirm_totp = ConfirmTotpView.as_view()
set_2fa_method = Set2faMethodView.as_view()
