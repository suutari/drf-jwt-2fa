from django.utils.translation import ugettext_lazy as _
from rest_framework import exceptions, status


class VerificationCodeSendingFailed(exceptions.APIException):
    status_code = status.HTTP_501_NOT_IMPLEMENTED
    default_code = 'verification_code_sending_failed'
    default_detail = _("Verification code sending failed: {reason}")

    def __init__(self, reason, detail=None, code=None, *args, **kwargs):
        super(VerificationCodeSendingFailed, self).__init__(
            detail=(detail or self.default_detail.format(reason=reason)),
            code=code, *args, **kwargs)
