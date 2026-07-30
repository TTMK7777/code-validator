"""コード品質ルール (QUAL001 行長 / QUAL002 未使用インポート) の回帰テスト.

QUAL002 は旧実装が「名前を集めるだけで常に空リストを返す」空実装であり、
README には機能として記載されていたのに 1 件も報告されなかった。
配線漏れの再発を防ぐことが主目的。
"""
from __future__ import annotations

from pathlib import Path

import pytest

from validator import CodeQualityChecker, Severity

from .conftest import assert_fires, assert_silent


# --- QUAL001: 行長 ----------------------------------------------------------

def test_qual001_detects_long_line(quality) -> None:
    code = 'X = "' + 'a' * 200 + '"\n'
    hits = assert_fires(quality(code), "QUAL001")
    assert hits[0].severity == Severity.LOW


def test_qual001_respects_config_max_line_length(quality) -> None:
    """config の quality_rules.max_line_length が反映されること.

    旧実装はメソッド内の定数 120 で固定されており、README に記載された
    設定項目が効かなかった。
    """
    code = 'X = "' + 'a' * 60 + '"\n'   # 約 67 文字
    assert_silent(quality(code), "QUAL001")          # 既定 120 では出ない
    config = {"quality_rules": {"max_line_length": 40}}
    assert_fires(quality(code, config=config), "QUAL001")


def test_qual001_skips_urls_and_comments(quality) -> None:
    """URL を含む行とコメント行は対象外であること（既存の仕様）."""
    long_url = '# https://example.com/' + 'a' * 200 + '\n'
    assert_silent(quality(long_url), "QUAL001")


# --- QUAL002: 未使用インポート ----------------------------------------------

def test_qual002_detects_unused_imports(quality) -> None:
    code = (
        'import os\n'
        'import json\n'
        'import hashlib\n'
        '\n'
        'print(os.getcwd())\n'
    )
    hits = assert_fires(quality(code), "QUAL002")
    names = sorted(h.message.split(': ')[-1] for h in hits)
    assert names == ["hashlib", "json"], f"想定外の検出: {names}"
    assert all(h.severity == Severity.LOW for h in hits)


@pytest.mark.parametrize(
    "code",
    [
        # 属性アクセスで使用
        'import os\nprint(os.getcwd())\n',
        # from import で使用
        'from pathlib import Path\np = Path(".")\n',
        # as 別名で使用
        'import numpy as np\nprint(np.pi)\n',
        # ドット付き import は根の名前で使用
        'import os.path\nprint(os.path.join("a", "b"))\n',
        # 型注釈の文字列内で使用（AST では追えないがテキストで救う）
        'from typing import List\ndef f() -> "List[int]":\n    return []\n',
        # __all__ 経由の再エクスポート
        'from mod import thing\n__all__ = ["thing"]\n',
        # __future__ は動作に必要なので対象外
        'from __future__ import annotations\n',
        # noqa 付きは意図的な未使用として尊重
        'import json  # noqa\n',
        # ワイルドカードがあると追跡不能なので判定放棄
        'from mod import *\nimport json\n',
    ],
)
def test_qual002_no_false_positive(quality, code: str) -> None:
    assert_silent(quality(code), "QUAL002")


def test_qual002_skips_init_py(tmp_path: Path) -> None:
    """__init__.py は再エクスポート目的の import が正当なため対象外."""
    target = tmp_path / "__init__.py"
    target.write_text('import json\n', encoding="utf-8")
    issues = CodeQualityChecker().check_file(target)
    assert_silent(issues, "QUAL002")


def test_qual002_survives_syntax_error(quality) -> None:
    """構文エラーのファイルでは例外を出さず静かにスキップすること."""
    issues = quality('import json\ndef broken(:\n')
    assert_silent(issues, "QUAL002")


def test_qual002_comment_mentioning_name_is_not_usage(quality) -> None:
    """コメント内の言及を「使用」と誤判定しないこと.

    テキストゲートがコメントを含んでいると、
    「# json は未使用」という記述自体で検出が無効化されてしまう。
    """
    code = (
        'import json\n'
        '\n'
        '# json はここでは使っていない\n'
        'print(1)\n'
    )
    assert_fires(quality(code), "QUAL002")


def test_qual002_can_be_disabled_by_config(quality) -> None:
    code = 'import json\nprint(1)\n'
    assert_fires(quality(code), "QUAL002")
    config = {"quality_rules": {"check_unused_imports": False}}
    assert_silent(quality(code, config=config), "QUAL002")
