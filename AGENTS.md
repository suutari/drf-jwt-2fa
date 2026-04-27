# Development

## Test Commands

```bash
./check-and-test             # Run all checks and pytest (PREFERRED)
./lint                       # Run very quick code style and lint check
pytest                       # Run tests directly without Tox
pytest drf_jwt_2fa/TESTFILE  # Run tests from specified test file
tox                          # Run full test matrix (Python/Django) and checks
tox -e py314-django60        # Run tests with Python 3.14 and Django 6.0
```

## Supported Versions

- Python: 3.12, 3.14
- Django: 3.2, 4.2, 5.2, 6.0

## Code Style

- ruff with line-length=79, max-complexity=10

## Key Files

- `pyproject.toml` - ruff settings
- `pyproject.toml` - pytest runs with `--doctest-modules` on the package

## Testing Notes

- Run full test suite and checks with `./check-and-test` script
- Run tests from a single test file with `pytest PATH/TO/TESTFILE`
- Don't run the full test matrix with Tox if not explicitly asked to
- Check code style and linting only with `./lint` script
- Check code style, linting and other issues with `tox -m check`
- Tests use pytest-django with SQLite

## Commits

- Before each commit, run `./check-and-test` to ensure code quality and
  passing tests.
- Make sure ChangeLog is also updated when relevant.
- Use descriptive commit messages that explain the changes made
- Use short summary lines (preferably 50 characters or less, but no
  longer than 72 characters) followed by a blank line and then a
  detailed description (if necessary).
- Commit subject MAY be prefixed with a context (e.g. filename,
  directory name, or component) followed by a colon and a space. For
  example: `AuthTokenSerializer: Add support for custom user models`
- Commit message body should be wrapped at 72 characters and should
  provide more context about the changes made, including the motivation
  behind the change and any relevant details that may not be obvious
  from the code itself.
- Use the imperative mood in commit messages (e.g. "Add feature" instead
  of "Added feature" or "Adds feature").  Use imperative mood even in
  the body of the commit message.  Don't use phrase like "This commit
  adds..." or "This change fixes...".  Instead, just describe what the
  commit does directly (e.g. "Add support for custom user models"
  instead).
