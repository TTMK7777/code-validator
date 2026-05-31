# Contributing to code-validator

Thanks for your interest in contributing! code-validator is an open-source,
MIT-licensed static security scanner for AI-generated code. Contributions of all
kinds — bug reports, feature requests, documentation, and code — are welcome.

## Reporting Issues

Please file bugs and feature requests via
[GitHub Issues](https://github.com/TTMK7777/code-validator/issues). A good report
includes:

- **Steps to reproduce** (a minimal code snippet or command is ideal)
- **Environment**: OS and Python version (`python --version`)
- **Expected vs. actual behavior**, including the full command you ran and any
  console / report output

For security-sensitive findings, please follow [SECURITY.md](SECURITY.md) instead
of opening a public issue.

## Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/TTMK7777/code-validator.git
cd code-validator

# 2. Install dependencies (only pydantic is required at runtime)
pip install -r requirements.txt

# 3. Install test/dev tooling (used by the test suite and linters)
pip install pytest

# 4. Run the validator against a project
python validator.py --path .

# 5. Run the test suite
pytest
```

Python 3.9 or later is required. Optional extras: `pip install pip-audit` enables
Python dependency CVE auditing.

## Pull Request Workflow

- Branch off `main`. Do **not** push directly to `main`.
- Keep PRs focused on a single concern; smaller PRs are easier to review.
- Open a PR with a clear description of *what* changed and *why*.
- Make sure `pytest` passes before requesting review.

## Coding Conventions

- Follow **PEP 8** and prefer type hints, consistent with the existing code in
  `validator.py`.
- Match the style of surrounding code. The project references `black` and
  `flake8` (listed as optional dev tools in `requirements.txt`); running them
  before submitting helps keep the diff clean.
- Add or update tests under `tests/` for any behavior change.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).

## Code of Conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By participating,
you are expected to uphold it.
