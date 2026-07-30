"""抑制コメント (`# code-validator: ignore` 系) の回帰テスト.

スキャナ自身のテストのように意図的に脆弱なコードを含むファイルを
CI で通すために必要な機構。効きすぎ（全部黙る）と効かなすぎ（黙らない）の
両方を守る。
"""
# code-validator: ignore-file
from __future__ import annotations

from pathlib import Path

from validator import CodeQualityChecker

from .conftest import assert_fires, assert_silent, rule_ids


FAKE_KEY = "sk-" + "A" * 48


def test_line_ignore_suppresses_all_rules_on_that_line(scan) -> None:
    code = f'K = "{FAKE_KEY}"  # code-validator: ignore\n'
    assert scan(code) == [], f"抑制されていない: {rule_ids(scan(code))}"


def test_line_ignore_with_rule_id_suppresses_only_that_rule(scan) -> None:
    code = f'K = "{FAKE_KEY}"  # code-validator: ignore[SEC001]\n'
    assert_silent(scan(code), "SEC001")


def test_line_ignore_with_other_rule_id_does_not_suppress(scan) -> None:
    """別ルールを指定した抑制では黙らないこと（効きすぎの防止）."""
    code = f'K = "{FAKE_KEY}"  # code-validator: ignore[SEC999]\n'
    assert_fires(scan(code), "SEC001")


def test_line_ignore_does_not_leak_to_other_lines(scan) -> None:
    """抑制はその行だけに効くこと."""
    code = (
        f'K1 = "{FAKE_KEY}"  # code-validator: ignore\n'
        f'K2 = "sk-{"B" * 48}"\n'
    )
    hits = assert_fires(scan(code), "SEC001")
    assert [h.line_number for h in hits] == [2]


def test_file_ignore_suppresses_everything(scan) -> None:
    code = (
        '# code-validator: ignore-file\n'
        f'K = "{FAKE_KEY}"\n'
        'query = f"SELECT * FROM t WHERE x = {y}"\n'
        'result = eval(expr)\n'
    )
    assert scan(code) == []


def test_file_ignore_with_rule_ids_suppresses_only_those(scan) -> None:
    """ファイル単位でもルールを絞れること（line_number を持たないルール向け）."""
    code = (
        '# code-validator: ignore-file[SEC004,SEC005,SEC007]\n'
        'from fastapi import FastAPI\n'
        'from fastapi.middleware.cors import CORSMiddleware\n'
        'app = FastAPI()\n'
        'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n'
        f'K = "{FAKE_KEY}"\n'
    )
    issues = scan(code)
    for suppressed in ("SEC004", "SEC005", "SEC007"):
        assert_silent(issues, suppressed)
    # 指定外のルールは生きている
    assert_fires(issues, "SEC001")


def test_suppression_applies_to_quality_rules(tmp_path: Path) -> None:
    """品質ルール側にも同じ抑制が効くこと."""
    target = tmp_path / "q.py"
    target.write_text('import json  # code-validator: ignore[QUAL002]\nprint(1)\n', encoding="utf-8")
    assert_silent(CodeQualityChecker().check_file(target), "QUAL002")


def test_ignore_file_marker_is_not_mistaken_for_line_ignore(scan) -> None:
    """`ignore-file` が行単位の `ignore` として誤解釈されないこと.

    正規表現の先読みが壊れると、ignore-file を書いた行だけが抑制され、
    ファイル全体には効かなくなる。
    """
    code = (
        'from fastapi import FastAPI\n'
        '# code-validator: ignore-file\n'
        f'K = "{FAKE_KEY}"\n'
    )
    assert scan(code) == []
