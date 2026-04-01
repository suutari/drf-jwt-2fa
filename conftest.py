import os
import sys

import pytest

pytest.register_assert_rewrite("drf_jwt_2fa.tests.utils")


def pytest_report_header(config, start_path):
    tox_env_info = ensure_tox_env_is_correct()
    return tox_env_info or None


def ensure_tox_env_is_correct():
    """
    Check that the test environment is correctly set up with Tox.

    When running under Tox, check that Python and Django versions are
    actually those that Tox is supposed to be running with.

    Returns None if no Tox env is detected to be active and otherwise a
    string with the Tox env name and the actual Python and Django
    versions, which have been checked to match the expected versions.

    This makes sure that we're actually testing the intended Python and
    Django versions when running under Tox.
    """
    tox_env = os.environ.get("TOX_ENV_NAME", None)
    if not tox_env:
        return None

    infos = []
    for part in tox_env.split("-"):
        if part.startswith("py"):
            python_ver = parse_ver_str(part.removeprefix("py"))
            infos.append(check_python_version(python_ver))
        elif part.startswith("django"):
            django_ver = parse_ver_str(part.removeprefix("django"))
            infos.append(check_django_version(django_ver))
        else:
            raise ValueError(f"Unknown part in Tox environment name: {part}")

    return f"TOXENV: {tox_env} = {' / '.join(infos)}"


def parse_ver_str(ver_str):
    major = ver_str[0]
    minor = ver_str[1:] if len(ver_str) > 1 else "0"
    return (int(major), int(minor))


def check_python_version(expected):
    actual_ver = sys.version_info[:2]
    assert actual_ver == expected, (
        f"Expected Python version {expected}, but found {sys.version}"
    )
    return f"Python {sys.version}"


def check_django_version(expected):
    import django

    actual_ver = django.VERSION[:2]
    assert actual_ver == expected, (
        f"Expected Django version {expected}, but found {django.get_version()}"
    )
    return f"Django {django.get_version()}"
