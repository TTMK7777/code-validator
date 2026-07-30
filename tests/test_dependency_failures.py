"""依存関係チェックの「検査できなかった」経路 (DEP001/DEP005/DEP006) の回帰テスト.

旧実装の問題:
  - pip-audit の実行失敗をすべて DEP001「インストールされていません」と報告して
    いたため、実際には入っていて依存解決に失敗しただけのケースを誤診した。
  - しかも severity が INFO のため CI は緑のまま通り、「0 件」と「見ていない」が
    区別できなかった（偽グリーン）。
  - npm audit の異常終了は logger.warning のみで Issue を作らず、完全に無言だった。

外部コマンドは呼ばず subprocess.run をモックして経路を検証する。
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from validator import DependencyChecker, Severity

from .conftest import assert_fires, assert_silent


class _FakeCompleted:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def py_project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("pydantic\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def node_project(tmp_path: Path) -> Path:
    (tmp_path / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    return tmp_path


# --- pip-audit ------------------------------------------------------------

def test_dep005_on_resolution_failure(monkeypatch, py_project: Path) -> None:
    """依存解決に失敗したら DEP005 (HIGH) を出し、原因を残すこと."""
    stderr = (
        "ERROR: Cannot install -r requirements.txt (line 1) and urllib3==1.24.1 "
        "because these package versions have conflicting dependencies.\n"
        "ERROR: ResolutionImpossible: for help visit https://pip.pypa.io/\n"
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _FakeCompleted(1, stdout="", stderr=stderr)
    )
    issues = DependencyChecker().check_dependencies(py_project)

    hits = assert_fires(issues, "DEP005")
    assert hits[0].severity == Severity.HIGH, "検査できなかったことが CI を落とさない"
    assert "依存関係の衝突により解決不能" in hits[0].message
    # 「未インストール」と誤診していないこと
    assert_silent(issues, "DEP001")


def test_dep001_only_when_binary_missing(monkeypatch, py_project: Path) -> None:
    """本当に pip-audit が無いときだけ DEP001 を出すこと."""
    def _raise(*args, **kwargs):
        raise FileNotFoundError("pip-audit")

    monkeypatch.setattr(subprocess, "run", _raise)
    issues = DependencyChecker().check_dependencies(py_project)

    hits = assert_fires(issues, "DEP001")
    assert hits[0].severity == Severity.INFO
    assert_silent(issues, "DEP005")


def test_dep005_on_timeout(monkeypatch, py_project: Path) -> None:
    """タイムアウトも「検査できなかった」として HIGH で報告すること."""
    def _timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="pip-audit", timeout=60)

    monkeypatch.setattr(subprocess, "run", _timeout)
    issues = DependencyChecker().check_dependencies(py_project)

    assert assert_fires(issues, "DEP005")[0].severity == Severity.HIGH


def test_dep002_reported_when_audit_succeeds(monkeypatch, py_project: Path) -> None:
    """脆弱性が返ってきたら DEP002 として報告し、DEP005 は出さないこと.

    pip-audit は脆弱性を見つけると returncode=1 を返すため、
    returncode だけで失敗判定してはならない。
    """
    stdout = (
        '{"dependencies": [{"name": "jinja2", "vulns": '
        '[{"id": "PYSEC-2021-66", "fix_versions": ["2.11.3"]}]}]}'
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _FakeCompleted(1, stdout=stdout, stderr="")
    )
    issues = DependencyChecker().check_dependencies(py_project)

    hits = assert_fires(issues, "DEP002")
    assert "jinja2" in hits[0].message and "PYSEC-2021-66" in hits[0].message
    assert hits[0].suggestion == "2.11.3"
    assert_silent(issues, "DEP005")


def test_python_check_can_be_disabled(monkeypatch, py_project: Path) -> None:
    def _fail(*args, **kwargs):
        raise AssertionError("check_python=False なのに pip-audit が呼ばれた")

    monkeypatch.setattr(subprocess, "run", _fail)
    checker = DependencyChecker({"dependency_rules": {"check_python": False}})
    assert checker.check_dependencies(py_project) == []


# --- npm audit ------------------------------------------------------------

def test_dep006_on_npm_failure(monkeypatch, node_project: Path) -> None:
    """npm audit が異常終了したら DEP006 (HIGH) を出すこと（旧実装は無言）."""
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: _FakeCompleted(2, stdout="", stderr="npm ERR! network timeout"),
    )
    issues = DependencyChecker().check_dependencies(node_project)

    hits = assert_fires(issues, "DEP006")
    assert hits[0].severity == Severity.HIGH
    assert "network" in hits[0].message


def test_dep003_reported_when_npm_finds_vulns(monkeypatch, node_project: Path) -> None:
    """npm audit が脆弱性を返したら DEP003 を重大度付きで報告すること."""
    stdout = '{"vulnerabilities": {"lodash": {"severity": "high"}}}'
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _FakeCompleted(1, stdout=stdout, stderr="")
    )
    issues = DependencyChecker().check_dependencies(node_project)

    hits = assert_fires(issues, "DEP003")
    assert hits[0].severity == Severity.HIGH
    assert "lodash" in hits[0].message
    assert_silent(issues, "DEP006")


def test_dep004_when_npm_missing(monkeypatch, node_project: Path) -> None:
    def _raise(*args, **kwargs):
        raise FileNotFoundError("npm")

    monkeypatch.setattr(subprocess, "run", _raise)
    issues = DependencyChecker().check_dependencies(node_project)

    assert assert_fires(issues, "DEP004")[0].severity == Severity.INFO


def test_node_check_can_be_disabled(monkeypatch, node_project: Path) -> None:
    def _fail(*args, **kwargs):
        raise AssertionError("check_node=False なのに npm audit が呼ばれた")

    monkeypatch.setattr(subprocess, "run", _fail)
    checker = DependencyChecker({"dependency_rules": {"check_node": False}})
    assert checker.check_dependencies(node_project) == []
