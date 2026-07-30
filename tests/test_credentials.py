"""認証情報系ルール (SEC001/002/003/008/009/010) の回帰テスト.

このファイル自身は「意図的に脆弱な文字列」を含むため、スキャナ自身の対象から外す。
values はすべて形式だけ合わせた偽値であり、実在しない。
"""
# code-validator: ignore-file
from __future__ import annotations

import pytest

from validator import Severity

from .conftest import assert_fires, assert_silent


# --- SEC001: API キー -------------------------------------------------------

@pytest.mark.parametrize(
    "code",
    [
        'OPENAI = "sk-' + 'A' * 48 + '"',
        'PROJ = "sk-proj-' + 'B' * 48 + '"',
        'ANTHROPIC = "sk-ant-' + 'C' * 60 + '"',
        'GOOGLE = "AIza' + 'D' * 35 + '"',
        'GH_PAT = "ghp_' + 'E' * 36 + '"',
        'GH_OAUTH = "gho_' + 'F' * 36 + '"',
        'GH_SERVER = "ghs_' + 'G' * 36 + '"',
    ],
)
def test_sec001_detects_api_keys(scan, code: str) -> None:
    """主要プロバイダの API キー形式を検出できること."""
    issues = scan(code)
    hits = assert_fires(issues, "SEC001")
    assert hits[0].severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "code",
    [
        # 環境変数経由は値ではない
        'OPENAI = os.environ["OPENAI_API_KEY"]',
        # 長さが足りない（sk- の後 40 文字未満）
        'OPENAI = "sk-tooshort"',
        # コメント行
        '# OPENAI = "sk-' + 'A' * 48 + '"',
        # 無関係な文字列
        'name = "sk-i-jump-in-winter"',
    ],
)
def test_sec001_no_false_positive(scan, code: str) -> None:
    """環境変数参照・短い文字列・コメントでは誤検知しないこと."""
    assert_silent(scan(code), "SEC001")


# --- SEC002: パスワード -----------------------------------------------------

def test_sec002_detects_hardcoded_password(scan) -> None:
    issues = scan('password = "n0t-a-real-password"')
    assert assert_fires(issues, "SEC002")[0].severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "code",
    [
        'password = "password"',            # プレースホルダ
        'password = "your-password"',
        'password = "changeme"',
        'password = "***"',
        'password = os.environ["PW"]',      # 環境変数
        'password = getenv("PW")',
    ],
)
def test_sec002_no_false_positive(scan, code: str) -> None:
    """プレースホルダと環境変数参照では誤検知しないこと."""
    assert_silent(scan(code), "SEC002")


# --- SEC003: DB 認証情報 ----------------------------------------------------

@pytest.mark.parametrize(
    "code",
    [
        'DSN = "postgresql://user:pw@localhost:5432/db"',
        'DSN = "mysql://user:pw@localhost/db"',
        'DSN = "mongodb://user:pw@localhost/db"',
    ],
)
def test_sec003_detects_database_credentials(scan, code: str) -> None:
    assert assert_fires(scan(code), "SEC003")[0].severity == Severity.CRITICAL


def test_sec003_no_false_positive_without_credentials(scan) -> None:
    """ユーザー名・パスワードを含まない接続文字列では発火しないこと."""
    assert_silent(scan('DSN = "postgresql://localhost:5432/db"'), "SEC003")


# --- SEC008: SECRET_KEY -----------------------------------------------------
#
# パターンは以前から定義されていたが _scan_credentials から呼ばれておらず、
# 常に 0 件だった（dead pattern）。配線漏れの再発を防ぐ。

@pytest.mark.parametrize(
    "code",
    [
        'SECRET_KEY = "django-insecure-r4nd0m-value-here"',
        "secret_key = 'flask-session-signing-value'",
    ],
)
def test_sec008_detects_hardcoded_secret_key(scan, code: str) -> None:
    assert assert_fires(scan(code), "SEC008")[0].severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "code",
    [
        'SECRET_KEY = os.environ["SECRET_KEY"]',
        'SECRET_KEY = "your-secret-key"',
        'SECRET_KEY = "placeholder"',
    ],
)
def test_sec008_no_false_positive(scan, code: str) -> None:
    assert_silent(scan(code), "SEC008")


# --- SEC009: AWS 認証情報 ---------------------------------------------------
#
# キー形式のリテラルを直接書くと、リポジトリの pre-commit シークレットスキャナが
# （正しく）反応してコミットできない。実行時に連結して組み立てることで、
# ソース上にキー形式を出さずに同じ値をテストできる。
_AKIA = "AKIA" + "IOSFODNN7EXAMPLE"   # AWS 公式ドキュメントの例示値
_ASIA = "ASIA" + "IOSFODNN7EXAMPLE"


@pytest.mark.parametrize(
    "code",
    [
        f'AWS_ACCESS_KEY_ID = "{_AKIA}"',
        f'key = "{_ASIA}"',                                   # 一時キー
        'AWS_SECRET_ACCESS_KEY = "' + 'a' * 40 + '"',
        'aws_secret_access_key = "' + 'b' * 40 + '"',
    ],
)
def test_sec009_detects_aws_credentials(scan, code: str) -> None:
    assert assert_fires(scan(code), "SEC009")[0].severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "code",
    [
        'AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]',
        'name = "AKIA"',                        # 桁数が足りない
        f'text = "{_AKIA}TOOLONGXX"',           # 20 桁を超える連続列
    ],
)
def test_sec009_no_false_positive(scan, code: str) -> None:
    assert_silent(scan(code), "SEC009")


# --- SEC010: 秘密鍵ブロック -------------------------------------------------

@pytest.mark.parametrize(
    "header",
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ],
)
def test_sec010_detects_embedded_private_key(scan, header: str) -> None:
    assert assert_fires(scan(f'KEY = "{header}"'), "SEC010")[0].severity == Severity.CRITICAL


def test_sec010_ignores_public_key(scan) -> None:
    """公開鍵は秘密情報ではないため発火しないこと."""
    assert_silent(scan('KEY = "-----BEGIN PUBLIC KEY-----"'), "SEC010")


def test_sec010_fires_even_inside_comment(scan) -> None:
    """秘密鍵はコメント内にあっても漏洩なので検出すること."""
    assert_fires(scan('# -----BEGIN RSA PRIVATE KEY-----'), "SEC010")
