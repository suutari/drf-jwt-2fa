# Development

## Test Commands

```bash
./check-and-test             # Run all checks and pytest (PREFERRED)
./lint                       # Run very quick code style and lint check
pytest                       # Run tests directly without Tox
pytest drf_jwt_2fa/TESTFILE  # Run tests from specified test file
tox                          # Run full test matrix (Python/Django) and checks
tox -e py314-django60        # Run tests with Python 3.14 and Django 6.0
tox -e docrendering          # Check rendering of README.rst and ChangeLog.rst
tox -e docrendering -- FILE  # Check a specific file (ReST or Markdown)
```

## Supported Versions

- Python: 3.12, 3.14
- Django: 3.2, 4.2, 5.2, 6.0

## Code Style

- ruff with line-length=79, max-complexity=10
- Use two spaces after a period in docstrings.

## Key Files

- `pyproject.toml` - ruff settings

## Dependency Management

- This project uses `uv` for dependency management and virtual
  environments
- Run commands in the project environment with `uv run <command>`

## Testing Notes

- Run `./check-and-test` immediately after writing code, before doing
  anything else (committing, updating docs, etc.)
- Run tests from a single test file with `pytest PATH/TO/TESTFILE`
- Don't run the full test matrix with Tox if not explicitly asked to
- Check code style and linting only with `./lint` script
- Check README.rst and ChangeLog.rst with `tox -e docrendering`
- Check a specific file (ReST or MD) with `tox -e docrendering -- FILENAME`
- Tests use pytest-django with SQLite
- Don't ignore modules in pytest config to work around collection
  errors, but fix the test environment instead.
- Prefer writing tests over ignoring files from code coverage report.
- pytest runs with `--doctest-modules`; docstrings in the package that
  contain `>>>` examples must be valid and passing doctests

## Code Organisation

- When adding a class or module that belongs to a distinct feature, create
  a new module rather than appending to an existing one that already has a
  clear, narrower purpose.

## ChangeLog

- Make sure ChangeLog is also updated when relevant.
- ChangeLog entries should be brief (one line or a short bullet point).
  Detailed documentation of behaviour, constraints, and examples belongs
  in the README, not the ChangeLog.

## Commits

- Before each commit, run `./check-and-test` to ensure code quality and
  passing tests.
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
- Use two spaces after a period in commit message bodies.
