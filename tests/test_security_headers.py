"""SEC007 (FastAPI のセキュリティヘッダー欠落) の回帰テスト."""
# code-validator: ignore-file
from __future__ import annotations

from validator import Severity

from .conftest import assert_fires, assert_silent


FASTAPI_APP = '''from fastapi import FastAPI

app = FastAPI()
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


def test_sec007_reports_each_missing_header(scan) -> None:
    """3 ヘッダーすべての欠落を個別に指摘すること."""
    issues = scan(FASTAPI_APP)
    hits = assert_fires(issues, "SEC007")
    assert len(hits) == 3, f"3 件の想定だが {len(hits)} 件: {[i.message for i in hits]}"
    assert all(i.severity == Severity.MEDIUM for i in hits)
    joined = " ".join(i.message for i in hits)
    for header in ("X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"):
        assert header in joined


def test_sec007_silent_when_headers_present(scan) -> None:
    """ヘッダーが設定済みなら発火しないこと."""
    assert_silent(scan(FASTAPI_WITH_HEADERS), "SEC007")


def test_sec007_only_applies_to_fastapi(scan) -> None:
    """FastAPI を使っていないファイルには適用しないこと."""
    assert_silent(scan('def main():\n    return 1\n'), "SEC007")
