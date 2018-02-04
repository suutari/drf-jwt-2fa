import hashlib

from django.utils.translation import ugettext as _
from rest_framework import serializers


def check_user_validity(user):
    """
    Check validity of given user.

    :type user: django.contrib.auth.models.AbstractBaseUser
    :rtype: None
    """
    if not user.is_active:
        raise serializers.ValidationError(_("Deactivated user"))


def hash_string(string, hasher=hashlib.sha256):
    return hasher(string.encode('utf-8')).hexdigest()
