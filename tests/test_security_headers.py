"""SEC007 (FastAPI のセキュリティヘッダー欠落) の回帰テスト."""
# code-validator: ignore-file
from __future__ import annotations

from validator import Severity

from .conftest import assert_fires, assert_silent


FASTAPI_APP = '''from fastapi import FastAPI

app = FastAPI()
'''

# FastAPI に言及しているが、アプリを生成していないファイル。
# 実コーパスの計測では、この形（バッジ文字列や型注釈のための import）が
# SEC007 誤検知の最大の発生源だった（72 件中 18 件が README 生成スクリプト）。
FASTAPI_MENTIONED_ONLY = '''BADGES = {
    "FastAPI": "![FastAPI](https://img.shields.io/badge/FastAPI-009688)",
}


def pick(tech_stack):
    return [t for t in tech_stack if t in ["FastAPI", "Flask", "Django"]]
'''

# ルーター側のモジュール。アプリ本体ではないのでヘッダーの責務を持たない。
FASTAPI_ROUTER = '''from fastapi import APIRouter

router = APIRouter()


@router.get("/items")
async def items():
    return []
'''

FASTAPI_WITH_HEADERS = '''from fastapi import FastAPI

app = FastAPI()


@app.middleware("http")
async def add_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response
'''


def test_sec007_reports_missing_headers_once(scan) -> None:
    """アプリ 1 つにつき 1 件にまとめ、欠落ヘッダーを列挙すること.

    旧実装はヘッダーごとに 1 件出していたため、ルーター分割したアプリで
    件数が膨らんだ（実コーパスで 72 件）。
    """
    issues = scan(FASTAPI_APP)
    hits = assert_fires(issues, "SEC007")
    assert len(hits) == 1, f"1 件にまとめる想定だが {len(hits)} 件: {[i.message for i in hits]}"
    assert hits[0].severity == Severity.MEDIUM
    assert "X-Content-Type-Options" in hits[0].message
    assert "X-Frame-Options" in hits[0].message


def test_sec007_does_not_require_deprecated_xss_header(scan) -> None:
    """非推奨の X-XSS-Protection は要求しないこと."""
    hits = assert_fires(scan(FASTAPI_APP), "SEC007")
    assert "X-XSS-Protection" not in hits[0].message


def test_sec007_silent_when_headers_present(scan) -> None:
    """ヘッダーが設定済みなら発火しないこと."""
    assert_silent(scan(FASTAPI_WITH_HEADERS), "SEC007")


def test_sec007_only_applies_to_fastapi(scan) -> None:
    """FastAPI を使っていないファイルには適用しないこと."""
    assert_silent(scan('def main():\n    return 1\n'), "SEC007")


def test_sec007_requires_app_instantiation(scan) -> None:
    """FastAPI に言及しているだけのファイルでは発火しないこと（実コーパス由来）."""
    assert_silent(scan(FASTAPI_MENTIONED_ONLY), "SEC007")


def test_sec007_skips_router_modules(scan) -> None:
    """APIRouter のみのモジュールはアプリ本体ではないので対象外."""
    assert_silent(scan(FASTAPI_ROUTER), "SEC007")
