from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, status


class TooManyAuthAttemptsError(exceptions.PermissionDenied):
    default_code = "too_many_auth_attempts"
    default_detail = _("Too many failed authentication attempts.")


class TooManyCodeTokensError(exceptions.Throttled):
    default_code = "too_many_code_tokens"
    default_detail = _(
        "Too many active code tokens. Please wait for existing ones to expire."
    )


class TokenAlreadyUsedError(exceptions.AuthenticationFailed):
    default_code = "token_already_used"
    default_detail = _(
        "This code token has already been used. If this wasn't you, "
        "your account may be compromised."
    )


class VerificationCodeSendingError(exceptions.APIException):
    status_code = status.HTTP_501_NOT_IMPLEMENTED
    default_code = "verification_code_sending_failed"
    default_detail = _("Verification code sending failed: {reason}")

    def __init__(
        self,
        reason: str | Exception,
        detail: str | None = None,
        code: str | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(
            detail=(detail or self.default_detail.format(reason=reason)),
            code=code,
            **kwargs,
        )


class TwoFactorAuthNotConfiguredError(exceptions.PermissionDenied):
    default_code = "2fa_not_configured"
    default_detail = _(
        "Two-factor authentication is not configured for this account."
    )


class Unknown2faMethodError(KeyError):
    pass
