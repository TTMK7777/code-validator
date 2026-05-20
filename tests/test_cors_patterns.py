"""CORS-REGEX-001 回帰テスト (#13/#14).

修正前は `CORS_PATTERNS['wildcard_with_credentials']` のリスト閉じ括弧 `\\]` が欠落しており、
実際の FastAPI CORSMiddleware 設定 (`allow_origins=["*"]`) には永遠にマッチしなかった。
このテストはその欠陥が再発しないよう、典型的な FastAPI コードパターンに対する検出を保証する。
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from validator import SecurityScanner, Severity


WILDCARD_WITH_CREDS = SecurityScanner.CORS_PATTERNS["wildcard_with_credentials"]
WILDCARD_ORIGINS = SecurityScanner.CORS_PATTERNS["wildcard_origins"]


# --- 直接の正規表現マッチング ---------------------------------------------

@pytest.mark.parametrize(
    "code",
    [
        # 典型的な FastAPI add_middleware 呼び出し（複数行・kwargs順序通り）
        '''app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
)''',
        # 1行記法
        'add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)',
        # シングルクォート
        "add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)",
        # kwargs 順序が逆 (credentials が先)
        '''add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
)''',
        # リスト内に他のオリジンが混在しつつワイルドカードを含む
        'add_middleware(CORSMiddleware, allow_origins=["https://x.com", "*"], allow_credentials=True)',
        # 間に他の kwargs を挟む
        '''add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
    allow_credentials=True,
)''',
    ],
)
def test_wildcard_with_credentials_matches(code: str) -> None:
    """ワイルドカード origins と allow_credentials=True の共存を検出できること."""
    assert re.search(WILDCARD_WITH_CREDS, code, re.MULTILINE) is not None, (
        f"CORS-REGEX-001 regression: pattern failed to match:\n{code}"
    )


@pytest.mark.parametrize(
    "code",
    [
        # credentials が False なら CRITICAL ではない（HIGH 側で検出）
        'add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False)',
        # credentials 指定なし
        'add_middleware(CORSMiddleware, allow_origins=["*"])',
        # origins が具体的なホスト名
        'add_middleware(CORSMiddleware, allow_origins=["https://example.com"], allow_credentials=True)',
        # 無関係なコード
        'def foo(): return "*"',
    ],
)
def test_wildcard_with_credentials_no_false_positive(code: str) -> None:
    """credentials=True を伴わないワイルドカードや無関係コードでは誤検出しないこと."""
    assert re.search(WILDCARD_WITH_CREDS, code, re.MULTILINE) is None, (
        f"CORS-REGEX-001 false positive on:\n{code}"
    )


def test_wildcard_origins_matches_realistic_list() -> None:
    """`wildcard_origins` パターンが現実的な `["*"]` 表記にマッチすること."""
    assert re.search(WILDCARD_ORIGINS, 'allow_origins=["*"]') is not None
    assert re.search(WILDCARD_ORIGINS, "allow_origins = ['*']") is not None


# --- スキャナ統合テスト ----------------------------------------------------

def _write_and_scan(tmp_path: Path, content: str) -> list:
    target = tmp_path / "app.py"
    target.write_text(content, encoding="utf-8")
    scanner = SecurityScanner()
    return scanner.scan_file(target)


def test_scan_detects_sec004_on_real_fastapi_snippet(tmp_path: Path) -> None:
    """実 FastAPI コード断片で SEC004 (CRITICAL) が発火すること."""
    code = '''from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
'''
    issues = _write_and_scan(tmp_path, code)
    sec004 = [i for i in issues if i.rule_id == "SEC004"]
    assert sec004, f"SEC004 was not raised. Issues: {[(i.rule_id, i.message) for i in issues]}"
    assert sec004[0].severity == Severity.CRITICAL


def test_scan_skips_safe_cors_config(tmp_path: Path) -> None:
    """安全な CORS 設定では SEC004 が発火しないこと."""
    code = '''app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],
    allow_credentials=True,
)
'''
    issues = _write_and_scan(tmp_path, code)
    assert not [i for i in issues if i.rule_id == "SEC004"]
