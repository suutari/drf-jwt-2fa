import base64
import hashlib

from django.contrib.auth.models import AbstractBaseUser
from rest_framework import exceptions


def check_user_validity(user: AbstractBaseUser) -> None:
    """
    Check validity of given user.
    """
    if not user.is_active:
        raise exceptions.PermissionDenied()


def hash_string(string: str) -> str:
    """
    Calculate a SHA-256 hash of given string encoded to UTF-8.

    The resulting hash is returned as a base64-encoded string without
    padding characters.
    """
    hash_bytes = hashlib.sha256(string.encode("utf-8")).digest()
    return base64.b64encode(hash_bytes).rstrip(b"=").decode("ascii")


def get_code_token_hash(token: str, prefix_len: int = 81) -> str:
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
    """
    return token[:prefix_len].split(".", 1)[-1][8:]
