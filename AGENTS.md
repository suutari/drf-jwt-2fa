# Development

## Test Commands

```bash
pytest                       # Run tests directly without Tox
pytest drf_jwt_2fa/TESTFILE  # Run tests from specified test file
tox                          # Run all tests with coverage (Python/Django matrix)
tox -e py314-django60        # Run tests with Python 3.14 and Django 6.0
tox -e lint                  # Run Ruff linting
tox -e style                 # Run Ruff style checks
tox -e uvlock                # Check uv.lock is up to date
```

## Supported Versions

- Python: 3.10, 3.12, 3.14
- Django: 2.2, 3.2, 4.2, 5.2, 6.0

## Code Style

- ruff with line-length=79, max-complexity=10

## Key Files

- `pyproject.toml` - ruff settings
- `pyproject.toml` - pytest runs with `--doctest-modules` on the package

## Testing Notes

- Test only with Pytest without Tox unless explicitly asked for full test matrix
- Check code style and linting with `tox -e style,lint`
- Tests use pytest-django with SQLite
