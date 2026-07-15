# code-validator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Offline](https://img.shields.io/badge/runs-offline-green.svg)](#)
[![AI Code](https://img.shields.io/badge/scans-AI--generated_code-purple.svg)](#)

> **What is code-validator?** A static security scanner purpose-built for code produced by AI assistants (Claude, ChatGPT, GitHub Copilot, Cursor). Detects hardcoded credentials, CORS misconfigurations, SQL injection patterns, and dependency CVEs — in under 1 second per file, fully offline, with zero external API calls.

**Why this exists:** AI assistants frequently emit code that *looks* correct but contains subtle security defects — hardcoded API keys in examples, `allow_origins=["*"]` with `allow_credentials=True`, string-concatenated SQL. `code-validator` is the lightweight CI gate that catches these *before* they reach `main`.

| | |
|---|---|
| 🎯 **Use case** | Block insecure AI-generated code at PR time |
| ⚡ **Speed** | <1s per file, `--git-diff` mode scans only changed files |
| 🔒 **Privacy** | 100% offline. No code leaves your machine. Only dependency: `pydantic` |
| 🧪 **Detection rules** | 11 rules across security, quality, and dependency layers (SEC001–SEC007, QUAL001, DEP001–DEP003) |
| 📦 **Install** | `pip install -r requirements.txt` — done |

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
| Core dependency | `pydantic == 2.13.4` |
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
                    [--format {html,json}] [--config CONFIG]

optional arguments:
  --path PATH      Project path to scan (default: current directory)
  --git-diff       Scan only files changed since HEAD
  --output OUTPUT  Output file path for the report
  --format         Report format: html | json (default: html)
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

## How code-validator Compares

| Tool | Target | Speed | Offline | AI-code focus | Dependency-free |
|------|--------|-------|---------|--------------|-----------------|
| **code-validator** | AI-generated code in CI | <1s/file | ✅ Yes | ✅ Yes (purpose-built) | ✅ pydantic only |
| Bandit | General Python | Fast | ✅ Yes | ❌ No | ❌ Multiple deps |
| Semgrep | Multi-language patterns | Medium | ⚠️ Hybrid | ❌ No | ❌ Heavy |
| GitGuardian | Secrets in git history | Slow (API) | ❌ No | ❌ No | ❌ SaaS |
| TruffleHog | Secrets in git history | Slow | ✅ Yes | ❌ No | ❌ Multiple deps |

**Positioning:** code-validator is the *only* tool in this list specifically tuned for the failure modes of AI-generated code (e.g., the `CORS wildcard + allow_credentials=True` pattern that LLMs disproportionately emit).

---

## FAQ

### Q: Why a separate tool for AI-generated code? Can't I just use Bandit or Semgrep?
General-purpose linters were designed for human-written code. AI assistants exhibit specific failure modes — hardcoded example credentials, overly permissive CORS for demos, string-concat SQL because the model "remembered" pre-ORM patterns. code-validator's rule set is tuned for these patterns and weights severity accordingly.

### Q: Does code-validator send my code anywhere?
No. The scanner runs fully offline. The only optional network call is `pip-audit` for CVE lookups, and that contacts only the official PyPA advisory database — never your source code.

### Q: How is this different from running Bandit + `truffleHog` + `pip-audit` separately?
code-validator unifies them into a single CI step with a coherent severity model and one report format (HTML / JSON). For `--git-diff` mode, only files changed in the current PR are scanned, keeping CI fast.

### Q: Can I customize the detection rules?
Yes — see `config/validator_config.json`. You can disable rule categories, change line-length thresholds, and add exclude patterns.

### Q: Does it work with Claude Code, Cursor, GitHub Copilot output?
Yes. It scans the resulting source files regardless of which AI assistant generated them. The detection patterns target the *output*, not the tool.

### Q: What Python version do I need?
Python 3.9 or later.

### Q: Is there a pre-commit hook?
Use `python validator.py --git-diff` in a pre-commit hook — exit code `1` blocks the commit when critical/high issues are found.

---

## Author

Built by **Taimu Tsuji (辻大夢)** — Founder of [Tsuji Lab](https://github.com/TTMK7777), Applied AI Architect specializing in multi-agent AI coordination and AI-assisted software development at scale.

- **Experience:** ~1.4M lines of AI-assisted code shipped across 4 concurrent projects; ~8,000 engineering hours saved per year via Claude Code automation.
- **Expertise:** Claude Agent SDK, MCP, multi-agent orchestration, AI security gating.
- **Why I built this:** After watching AI-generated PRs land with `allow_origins=["*"]` more than once, I needed a gate that ran in <1s and didn't ship code off-box. Existing tools were either too heavy, too noisy, or required SaaS.

GitHub: [@TTMK7777](https://github.com/TTMK7777)

---

## Structured Data (Schema.org)

For AI search engines and developer-tooling indexes:

```json
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "code-validator",
  "alternateName": "AI Code Security Scanner",
  "applicationCategory": "DeveloperApplication",
  "operatingSystem": "Linux, macOS, Windows",
  "description": "Static security scanner for AI-generated code. Detects hardcoded credentials, CORS misconfigurations, SQL injection patterns, and dependency CVEs in under 1 second per file, fully offline.",
  "url": "https://github.com/TTMK7777/code-validator",
  "license": "https://opensource.org/licenses/MIT",
  "programmingLanguage": "Python",
  "softwareRequirements": "Python 3.9+",
  "author": {
    "@type": "Person",
    "name": "Taimu Tsuji",
    "alternateName": "辻大夢",
    "jobTitle": "Founder, Tsuji Lab",
    "url": "https://github.com/TTMK7777"
  },
  "keywords": "AI security, static analysis, code validation, AI-generated code, CI/CD security, secret detection, CORS validation, dependency audit, Claude Code, GitHub Copilot, LLM security"
}
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

Issues and PRs welcome. For security-related findings, see [SECURITY.md](SECURITY.md).
