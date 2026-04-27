import logging

from django.contrib.auth.models import AbstractBaseUser
from django.core.mail import send_mail
from django.utils.translation import gettext as _

from .settings import api_settings

LOG = logging.getLogger(__name__)


class CodeSendingError(Exception):
    pass


def send_verification_code(user: AbstractBaseUser, code: str) -> None:
    sender = api_settings.CODE_SENDER
    try:
        sender(user, code)
    except CodeSendingError:
        raise
    except Exception as error:
        LOG.exception("Verification code sending failed")
        raise CodeSendingError(_("Unknown error")) from error


def send_verification_code_via_email(
    user: AbstractBaseUser, code: str
) -> None:
    user_email_address = getattr(user, "email", None)

    if not user_email_address:
        raise CodeSendingError(_("No e-mail address known"))

    subject_template = _(
        api_settings.EMAIL_SENDER_SUBJECT_OVERRIDE
        or _("{code}: Your verification code")
    )
    body_template = api_settings.EMAIL_SENDER_BODY_OVERRIDE or _(
        "{code} is the verification code needed for the login."
    )

    messages_sent = send_mail(
        subject=subject_template.format(code=code),
        message=body_template.format(code=code),
        from_email=api_settings.EMAIL_SENDER_FROM_ADDRESS,
        recipient_list=[user_email_address],
        fail_silently=True,
    )

    if not messages_sent:
        raise CodeSendingError(_("Unable to send e-mail"))
