"""設定ファイルの反映を検証する回帰テスト.

README の Configuration 節に記載されていた項目のうち、旧実装では
以下が一切参照されていなかった。
  - security_rules.*        （ルールの有効・無効）
  - quality_rules.*         （test_quality.py 側で検証）
  - dependency_rules.*      （test_dependency_failures.py 側で検証）
  - exclude_patterns        （`for pattern in exclude_patterns: pass` の空ループ）
"""
# code-validator: ignore-file
from __future__ import annotations

import json
from pathlib import Path

import pytest

from validator import CodeValidator

from .conftest import assert_fires, assert_silent


FAKE_KEY = "sk-" + "A" * 48


# --- security_rules によるルールの無効化 ------------------------------------

@pytest.mark.parametrize(
    ("toggle", "code", "rule_id"),
    [
        ("check_credentials", f'K = "{FAKE_KEY}"', "SEC001"),
        (
            "check_cors",
            'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)',
            "SEC004",
        ),
        ("check_sql_injection", 'q = f"SELECT * FROM t WHERE x = {y}"', "SEC006"),
        ("check_security_headers", 'from fastapi import FastAPI', "SEC007"),
        ("check_dangerous_calls", 'v = eval(expr)', "SEC013"),
    ],
)
def test_security_rule_can_be_disabled(scan, toggle: str, code: str, rule_id: str) -> None:
    """既定では発火し、config で false にすると黙ること."""
    assert_fires(scan(code), rule_id)
    config = {"security_rules": {toggle: False}}
    assert_silent(scan(code, config=config), rule_id)


# --- exclude_patterns ------------------------------------------------------

def _write_project(root: Path) -> None:
    (root / "src").mkdir()
    (root / "dist").mkdir()
    (root / "src" / "app.py").write_text(f'K = "{FAKE_KEY}"\n', encoding="utf-8")
    (root / "dist" / "bundle.py").write_text(f'K = "{FAKE_KEY}"\n', encoding="utf-8")


def _validate_with_config(tmp_path: Path, config: dict) -> list:
    project = tmp_path / "project"
    project.mkdir()
    _write_project(project)
    config_path = tmp_path / "cfg.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    result = CodeValidator(config_path).validate(project)
    return result.issues


def test_exclude_patterns_are_honored(tmp_path: Path) -> None:
    """config の `**/dist/**` が実際に除外されること.

    旧実装は空ループで、node_modules / venv / __pycache__ / .git の
    ハードコード 4 種以外は除外されなかった。
    """
    issues = _validate_with_config(
        tmp_path,
        {"exclude_patterns": ["**/dist/**"], "file_extensions": [".py"]},
    )
    scanned = {Path(i.file_path).parent.name for i in issues}
    assert "src" in scanned, f"src が走査されていない: {scanned}"
    assert "dist" not in scanned, f"dist が除外されていない: {scanned}"


def test_without_exclude_patterns_everything_is_scanned(tmp_path: Path) -> None:
    """除外指定が無ければ両方走査されること（テストの対照）."""
    issues = _validate_with_config(
        tmp_path,
        {"exclude_patterns": [], "file_extensions": [".py"]},
    )
    scanned = {Path(i.file_path).parent.name for i in issues}
    assert {"src", "dist"} <= scanned, f"走査漏れ: {scanned}"


def test_file_extensions_are_honored(tmp_path: Path) -> None:
    """file_extensions に無い拡張子は走査対象にならないこと."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.py").write_text(f'K = "{FAKE_KEY}"\n', encoding="utf-8")
    (project / "b.js").write_text(f'const k = "{FAKE_KEY}";\n', encoding="utf-8")
    config_path = tmp_path / "cfg.json"
    config_path.write_text(json.dumps({"file_extensions": [".py"]}), encoding="utf-8")

    result = CodeValidator(config_path).validate(project)
    suffixes = {Path(i.file_path).suffix for i in result.issues}
    assert suffixes == {".py"}, f"想定外の拡張子が走査された: {suffixes}"
