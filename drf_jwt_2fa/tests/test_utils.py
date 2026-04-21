from drf_jwt_2fa.settings import api_settings
from drf_jwt_2fa.utils import get_code_token_hash

from .factories import get_code_token, get_code_token_and_its_jti
from .utils import b64decode


def test_get_token_hash_contains_16byte_jti():
    """The jti value must be present in the get_token_hash return value"""
    (token, jti) = get_code_token_and_its_jti()

    assert api_settings.CODE_TOKEN_JTI_BYTES == 16
    assert len(jti) == 22  # 16 bytes, base64 encoded without padding

    token_hash = get_code_token_hash(token)

    token_hash_decoded = b64decode(token_hash)
    assert jti.encode() in token_hash_decoded


def test_get_token_hash_is_short():
    token = get_code_token()

    token_hash = get_code_token_hash(token)

    assert len(token_hash) == 36
