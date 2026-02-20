# code-validator

**Security Scanner for AI-Generated Code**

A lightweight, zero-dependency static analysis tool that scans AI-generated code for security vulnerabilities, code quality issues, and dependency risks. Designed to act as a quality gate in CI/CD pipelines where AI assistants (e.g., Claude, ChatGPT, Copilot) produce code that should be validated before merging.

---

## Features

### Security Scanning
- Hardcoded credentials: API keys (OpenAI, Anthropic, Google, GitHub tokens), passwords, database URLs, and secret keys
- Dangerous CORS configurations: wildcard origins combined with `allow_credentials=True`
- SQL injection patterns: string-concatenated query construction
- Missing security headers: `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection` (FastAPI apps)

### Code Quality Checks
- Lines exceeding the configured maximum length (default: 120 characters)
- Unused import detection (heuristic-based; full analysis via flake8)
- Function complexity stub (extensible for cyclomatic complexity tools)

### Dependency Auditing
- Python: delegates to `pip-audit` when available
- Node.js: delegates to `npm audit` when available

### Reporting
- **HTML**: human-readable browser report with color-coded severity cards
- **JSON**: machine-readable output for CI/CD integration
- **Console**: summary printed to stdout with per-severity counts

### Git Integration
- `--git-diff` mode: scans only files changed since `HEAD`, keeping CI runs fast

---

## Tech Stack

| Component | Detail |
|-----------|--------|
| Language | Python 3.9+ |
| Core dependency | `pydantic >= 2.0.0` |
| Optional | `pip-audit >= 2.6.0` (Python dep auditing) |
| CI | GitHub Actions |

No external API calls. Runs fully offline.

---

## Setup

```bash
# Clone or copy the repository
git clone https://github.com/TTMK7777/code-validator.git
cd code-validator

# Install dependencies (only pydantic is required)
pip install -r requirements.txt

# Optional: enable Python dependency auditing
pip install pip-audit
```

Python 3.9 or later is required.

---

## Usage

### Scan a directory

```bash
python validator.py --path /path/to/project
```

### Scan only files changed in the latest commit (recommended for CI)

```bash
python validator.py --git-diff
```

### Scan a specific commit range

```bash
python validator.py --git-diff --from HEAD~3 --to HEAD
```

### Generate an HTML report

```bash
python validator.py --path . --output report.html --format html
```

### Generate a JSON report

```bash
python validator.py --path . --output report.json --format json
```

### Use a custom configuration file

```bash
python validator.py --path . --config config/validator_config.json
```

### CLI reference

```
usage: validator.py [-h] [--path PATH] [--git-diff] [--output OUTPUT]
                    [--format {html,json,markdown}] [--config CONFIG]

optional arguments:
  --path PATH      Project path to scan (default: current directory)
  --git-diff       Scan only files changed since HEAD
  --output OUTPUT  Output file path for the report
  --format         Report format: html | json | markdown (default: html)
  --config CONFIG  Path to a custom JSON configuration file
```

**Exit codes:** `0` = no critical/high issues found, `1` = at least one critical or high issue detected (useful for blocking CI pipelines).

---

## Configuration

Edit `config/validator_config.json` to customize behavior:

```json
{
  "exclude_patterns": [
    "**/node_modules/**",
    "**/venv/**",
    "**/__pycache__/**",
    "**/.git/**"
  ],
  "file_extensions": [".py", ".js", ".ts", ".tsx", ".json", ".yaml", ".yml"],
  "security_rules": {
    "check_credentials": true,
    "check_cors": true,
    "check_sql_injection": true,
    "check_security_headers": true
  },
  "quality_rules": {
    "max_line_length": 120,
    "check_unused_imports": true,
    "check_complex_functions": true
  },
  "dependency_rules": {
    "check_python": true,
    "check_node": true
  }
}
```

---

## CI/CD Integration

### GitHub Actions

Add the following workflow to your repository (`.github/workflows/code-validation.yml`):

```yaml
name: Code Validation

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  validate:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2  # required for --git-diff

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pip-audit || echo "pip-audit not available"

      - name: Run Code Validator
        run: python validator.py --git-diff --output validation-report.json --format json

      - name: Upload validation report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: validation-report
          path: validation-report.json
```

The validator exits with code `1` when critical or high severity issues are found, which automatically blocks the CI job.

### GitLab CI

```yaml
code-validation:
  image: python:3.11-slim
  script:
    - pip install -r requirements.txt
    - pip install pip-audit || true
    - python validator.py --git-diff --output validation-report.json --format json
  artifacts:
    paths:
      - validation-report.json
    when: always
```

---

## Detection Rules

| Rule ID | Severity | Category | Description |
|---------|----------|----------|-------------|
| SEC001 | Critical | Security | Hardcoded API key detected |
| SEC002 | Critical | Security | Hardcoded password detected |
| SEC003 | Critical | Security | Hardcoded database credentials detected |
| SEC004 | Critical | Security | CORS wildcard origins + credentials enabled |
| SEC005 | High | Security | CORS wildcard origins (production risk) |
| SEC006 | High | Security | Potential SQL injection via string concatenation |
| SEC007 | Medium | Security | Missing security header in FastAPI app |
| QUAL001 | Low | Quality | Line exceeds maximum length |
| DEP001 | Info | Dependencies | pip-audit not installed |
| DEP002 | High | Dependencies | Python package with known CVE |
| DEP003 | Variable | Dependencies | Node.js package with known CVE |

---

## Example Output

```
============================================================
Validation Summary
============================================================
Project: /home/user/my-project
Files scanned: 42
Execution time: 0.83s

Issues by severity:
  Critical : 0
  High     : 1
  Medium   : 2
  Low      : 5
  Info     : 1
============================================================
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
