"""テスト共通のヘルパー。

テストは「一時ファイルに書いてスキャンする」形を基本とする。
実装の内部関数ではなく公開経路 (`scan_file` / `check_file`) を通すことで、
配線漏れ（パターンは定義されているのに呼ばれていない、という過去の
SEC008 / QUAL002 の欠陥）も検出できるようにする。
"""
from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from validator import CodeQualityChecker, Issue, SecurityScanner


@pytest.fixture
def scan(tmp_path: Path):
    """コードを一時 .py に書き出してセキュリティスキャンを実行する。"""

    def _scan(code: str, filename: str = "target.py", config: dict | None = None) -> List[Issue]:
        target = tmp_path / filename
        target.write_text(code, encoding="utf-8")
        return SecurityScanner(config).scan_file(target)

    return _scan


@pytest.fixture
def quality(tmp_path: Path):
    """コードを一時 .py に書き出して品質チェックを実行する。"""

    def _quality(code: str, filename: str = "target.py", config: dict | None = None) -> List[Issue]:
        target = tmp_path / filename
        target.write_text(code, encoding="utf-8")
        return CodeQualityChecker(config).check_file(target)

    return _quality


def rule_ids(issues: List[Issue]) -> List[str]:
    """検出された rule_id の一覧（アサーション失敗時に読みやすくするため）。"""
    return [i.rule_id for i in issues]


def assert_fires(issues: List[Issue], rule_id: str) -> List[Issue]:
    """指定ルールが発火していることを検証し、該当 Issue を返す。"""
    hits = [i for i in issues if i.rule_id == rule_id]
    assert hits, f"{rule_id} が発火しませんでした。検出: {rule_ids(issues)}"
    return hits


def assert_silent(issues: List[Issue], rule_id: str) -> None:
    """指定ルールが発火していないことを検証する（誤検知の防止）。"""
    hits = [i for i in issues if i.rule_id == rule_id]
    assert not hits, (
        f"{rule_id} が誤検知しました: {[(i.line_number, i.code_snippet) for i in hits]}"
    )
