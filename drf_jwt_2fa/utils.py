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
    return encoder(data).rstrip(b"=").decode("ascii")


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
    return formatter(hasher(string.encode("utf-8")).digest())


def get_code_token_hash(token, prefix_len=81):
    """
    Return a short hash-like identifier for a code token.

    Exploits the fact that a jti values up to 22 characters are fully
    contained within the first 81 bytes of the token, and the payload
    part (after the dot) begins with 8 constant bytes from the value of
    '{"jti"' encoded to base64.

    The return value ``token[:prefix_len].split(".", 1)[-1][8:]`` yields
    the base64-encoded payload fragment that includes the jti value,
    which is unique per token and safe to use as a cache key
    discriminator.

    Note: Even if a longer jti value is configured, the first 22
    characters should be enough for "hashing" purposes.

    :type token: str
    :rtype: str
    """
    return token[:prefix_len].split(".", 1)[-1][8:]
