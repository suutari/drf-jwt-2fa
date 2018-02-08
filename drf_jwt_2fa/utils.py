import base64
import hashlib

from rest_framework import exceptions


def check_user_validity(user):
    """
    Check validity of given user.

    :type user: django.contrib.auth.models.AbstractBaseUser
    :rtype: None
    """
    if not user.is_active:
        raise exceptions.PermissionDenied()


def _unpadded_encode(data, encoder=base64.b64encode):
    return encoder(data).rstrip(b'=').decode('ascii')


def hash_string(string, hasher=hashlib.sha256, formatter=_unpadded_encode):
    """
    Calculate a hash of given string encoded to UTF-8.

    The hasher is SHA-256 is by default, but it can be changed with an
    argument.  T binary hash returned by the hasher is converted to a
    string with the given formatter; the default formatter returns the
    hash as unpadded base 64 string.

    :type string: str
    :type hasher: Callable[[bytes], bytes]
    :type formatter: Callable[[bytes], str]
    :rtype: str
    """
    return formatter(hasher(string.encode('utf-8')).digest())


def sha1_string(string, formatter=_unpadded_encode):
    return hash_string(string, hasher=hashlib.sha1, formatter=formatter)
