"""手元の 54 リポに code-validator 自身をかけて見つかった不具合の回帰テスト.

2026-11 に、作者の手元にある実在リポジトリ 54 本（33,727 ファイル）へ
依存検査を切って走らせた。git 管理下のセキュリティ指摘 82 件のうち、
本物の脆弱性は 0 件だった。代わりにツール自身の不具合が見つかった。

  1. 出力先が cp932 のとき、要約の絵文字で UnicodeEncodeError になり
     指摘 0 件でも終了コード 1 を返す（CI では常に赤）
  2. .gitignore を見ないため、git 管理外のファイルの指摘が全体の 87% を占めた
  3. `.venv` が既定の除外に入っていない
  4. 無視された data/ に 200MB 級の JSON があるリポで 10 分を超えて終わらない
  5. SEC006: 固定の部品（列名・テーブル名・WHERE 句の組み立て）だけを
     差し込む f 文字列の SQL を、値の差し込みと区別できない
  6. SEC006: 'update' / "update-index" のような単語を SQL 文の始まりと誤認する
  7. SEC011〜013: 文字列やコメントの中の説明文（"Never use eval()"）に反応する
  8. SEC003: 説明文の `user:pass@host` を実際の認証情報と誤認する

下の「発火しない例」はすべて、そのとき実際に誤検知した行（の形）である。
"""
# code-validator: ignore-file
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from validator import CodeValidator

from .conftest import assert_fires, assert_silent

VALIDATOR = Path(__file__).resolve().parent.parent / "validator.py"
FAKE_KEY = "sk-" + "A" * 48
NO_DEPS = {"dependency_rules": {"check_python": False, "check_node": False}}


def _validate(project: Path, tmp_path: Path, config: dict) -> list:
    config_path = tmp_path / "cfg.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return CodeValidator(config_path).validate(project).issues


# --- 1. 出力の文字コード ----------------------------------------------------

def test_clean_project_exits_zero_when_stdout_is_cp932(tmp_path: Path) -> None:
    """指摘 0 件なら、出力先が cp932 でも終了コード 0 で終わること.

    日本語 Windows でパイプやファイルに出すと stdout は cp932 になる。
    旧実装は要約の絵文字で落ち、例外の終了コード 1 が「指摘あり」の 1 と
    区別できなかった。
    """
    project = tmp_path / "clean"
    project.mkdir()
    (project / "a.py").write_text("x = 1\n", encoding="utf-8")
    config_path = tmp_path / "cfg.json"
    config_path.write_text(json.dumps(NO_DEPS), encoding="utf-8")

    env = {**os.environ, "PYTHONIOENCODING": "cp932"}
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR), "--path", str(project), "--config", str(config_path)],
        capture_output=True, env=env, timeout=120,
    )
    stderr = proc.stderr.decode("cp932", errors="replace")
    assert "UnicodeEncodeError" not in stderr, stderr[-500:]
    assert proc.returncode == 0, stderr[-500:]


# --- 2〜4. 走査対象の選び方 --------------------------------------------------

@pytest.mark.skipif(shutil.which("git") is None, reason="git が無い環境")
def test_gitignored_files_are_skipped_but_new_files_are_scanned(tmp_path: Path) -> None:
    """.gitignore で無視されたファイルは見ず、まだ add していない新規ファイルは見ること."""
    project = tmp_path / "repo"
    (project / "src").mkdir(parents=True)
    (project / "data").mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    (project / ".gitignore").write_text("data/\n", encoding="utf-8")
    (project / "src" / "app.py").write_text(f'K = "{FAKE_KEY}"\n', encoding="utf-8")
    (project / "data" / "dump.py").write_text(f'K = "{FAKE_KEY}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "src/app.py", ".gitignore"], cwd=project, check=True)
    (project / "src" / "new.py").write_text(f'K = "{FAKE_KEY}"\n', encoding="utf-8")

    issues = _validate(project, tmp_path, {**NO_DEPS, "file_extensions": [".py"]})
    names = {Path(i.file_path).name for i in issues}
    assert "app.py" in names, names
    assert "new.py" in names, f"未 add の新規ファイルが走査されていない: {names}"
    assert "dump.py" not in names, f"gitignore の中身が走査された: {names}"


@pytest.mark.skipif(shutil.which("git") is None, reason="git が無い環境")
def test_respect_gitignore_can_be_turned_off(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    (project / "data").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    (project / ".gitignore").write_text("data/\n", encoding="utf-8")
    (project / "data" / "dump.py").write_text(f'K = "{FAKE_KEY}"\n', encoding="utf-8")

    issues = _validate(
        project, tmp_path,
        {**NO_DEPS, "file_extensions": [".py"], "respect_gitignore": False},
    )
    assert "dump.py" in {Path(i.file_path).name for i in issues}


def test_dot_venv_is_excluded_by_default(tmp_path: Path) -> None:
    """git 管理外のフォルダでも、既定の除外で .venv を見ないこと."""
    project = tmp_path / "plain"
    (project / ".venv" / "lib").mkdir(parents=True)
    (project / ".venv" / "lib" / "vendored.py").write_text(f'K = "{FAKE_KEY}"\n', encoding="utf-8")
    (project / "app.py").write_text(f'K = "{FAKE_KEY}"\n', encoding="utf-8")

    issues = _validate(project, tmp_path, {**NO_DEPS, "file_extensions": [".py"]})
    names = {Path(i.file_path).name for i in issues}
    assert "app.py" in names
    assert "vendored.py" not in names, names


def test_oversized_files_are_skipped_with_warning(tmp_path: Path, caplog) -> None:
    """上限を超える大きいファイルは読まず、飛ばしたことを警告に出すこと."""
    project = tmp_path / "plain"
    project.mkdir()
    big = project / "dump.json"
    big.write_text('{"k": "' + FAKE_KEY + '", "pad": "' + "x" * 300_000 + '"}', encoding="utf-8")
    (project / "app.py").write_text(f'K = "{FAKE_KEY}"\n', encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        issues = _validate(project, tmp_path, {**NO_DEPS, "max_file_size_kb": 100})
    names = {Path(i.file_path).name for i in issues}
    assert "app.py" in names
    assert "dump.json" not in names, names
    assert any("dump.json" in r.getMessage() for r in caplog.records), "飛ばしたことが警告に出ていない"


# --- 5〜6. SEC006 -----------------------------------------------------------

@pytest.mark.parametrize(
    "code",
    [
        # 値の位置への差し込み（本物の注入経路）
        'cur.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        'cur.execute(f"SELECT * FROM users WHERE id={user_id}")',
        'cur.execute(f"SELECT * FROM t WHERE name = \'{name}\'")',
        'cur.execute(f"SELECT * FROM t WHERE name LIKE \'%{q}%\'")',
        'cur.execute(f"DELETE FROM t WHERE id IN ({ids})")',
        'cur.execute(f"SELECT * FROM t LIMIT {n}")',
        'sql = f"INSERT INTO t (a) VALUES ({raw})"',
    ],
)
def test_sec006_still_fires_on_value_interpolation(scan, code: str) -> None:
    assert_fires(scan(code), "SEC006")


@pytest.mark.parametrize(
    "code",
    [
        # 固定の部品（句・列名・テーブル名・プレースホルダ列）だけを差し込む形
        'rows = conn.execute(f"SELECT DISTINCT data_source FROM rankings{clause}", params)',
        "row = conn.execute(f\"SELECT 1 FROM rankings WHERE {' AND '.join(where)} LIMIT 1\", params)",
        'row = conn.execute(f"SELECT {counts} FROM rankings").fetchone()',
        'total = conn.execute(f"SELECT COUNT(*) FROM rankings WHERE {where}", params).fetchone()[0]',
        "sql = f\"INSERT INTO rankings ({', '.join(cols)}) VALUES ({placeholders}) \"",
        "sql = f\"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})\"",
        'cur = conn.execute(f"SELECT * FROM {table} LIMIT 0")',
        'conn.execute(f"SELECT pg_advisory_xact_lock({self._LOCK_KEY})")',
        'rows = conn.execute(f"SELECT {cols} FROM rankings WHERE category = ? AND period_type = ?"',
        # IN の中が副問い合わせ（値のリストではない）。Codex 指摘の修正後の再計測で出た行
        'conn.execute(f"DELETE FROM invites WHERE session_id IN (SELECT id FROM sessions WHERE {where})", params)',
        # SQL ではない、単語としての update / select
        "print(f\"    {'update' if cur is not None else 'new':6} {name}\")",
        '_git(cdir, "update-index", "--add", "--cacheinfo", f"160000,{sha},hooks/sub")',
        'assert not any(l.split()[0] in ("new", "update") and l.endswith(f"hooks/{ROUTER}") for l in out)',
    ],
)
def test_sec006_no_false_positive_on_structural_fragments(scan, code: str) -> None:
    assert_silent(scan(code), "SEC006")


# --- 7. SEC011〜013: 文字列・コメント内の説明文 ------------------------------

@pytest.mark.parametrize(
    ("code", "rule_id"),
    [
        ('DESC = "Never use pickle.loads() or eval() on untrusted data"', "SEC012"),
        ('DESC = "Never use pickle.loads() or eval() on untrusted data"', "SEC013"),
        ('x = run(cmd)  # do not eval(x) here', "SEC013"),
        ('def f():\n    """使い方.\n\n    前提: setup.py が先に exec() されていること。\n    """\n', "SEC013"),
        ('HELP = "os.system(" + "cmd)"', "SEC011"),
    ],
)
def test_dangerous_calls_ignore_strings_and_comments(scan, code: str, rule_id: str) -> None:
    assert_silent(scan(code), rule_id)


@pytest.mark.parametrize(
    ("code", "rule_id"),
    [
        ("exec(open('lib.py').read())", "SEC013"),
        ('msg = f"result: {eval(expr)}"', "SEC013"),
        ('x = "a"; obj = pickle.loads(blob)', "SEC012"),
    ],
)
def test_dangerous_calls_still_fire_in_code(scan, code: str, rule_id: str) -> None:
    """文字列の隣や f 文字列の式部分にある実際の呼び出しは拾うこと."""
    assert_fires(scan(code), rule_id)


def test_dangerous_calls_ignore_json_text(scan) -> None:
    """JSON は実行されないので、説明文中の eval() / pickle.loads() に反応しないこと."""
    code = '{"rule": "Never use pickle.loads(), yaml.load() (unsafe), or eval() on untrusted data."}'
    issues = scan(code, filename="policy.json")
    assert_silent(issues, "SEC012")
    assert_silent(issues, "SEC013")


# --- 8. SEC003 --------------------------------------------------------------

@pytest.mark.parametrize(
    "code",
    [
        'def connect(dsn):\n    """接続する.\n\n    例: postgresql://user:pass@host:5432/db\n    """\n',
        'EXAMPLE = "mysql://<user>:<password>@localhost/db"',
        'EXAMPLE = "mongodb://${USER}:${PASSWORD}@localhost/db"',
    ],
)
def test_sec003_no_false_positive_on_placeholders(scan, code: str) -> None:
    assert_silent(scan(code), "SEC003")


def test_sec003_still_fires_on_real_looking_password(scan) -> None:
    assert_fires(scan('DSN = "postgresql://admin:Tr0ub4dor3@db.internal:5432/app"'), "SEC003")


# --- PR #97 への Codex の指摘 -----------------------------------------------
#
# なぜ前段で止まらなかったか: テストは CI の Python 3.12 でしか回しておらず
# （3.11 以前は f 文字列全体が 1 つの文字列トークン）、差分走査・サブモジュール・
# 1 行に複数ある接続文字列・BETWEEN / リストの 2 要素目という経路を
# 「発火する例」に入れていなかった。

def _git(cwd: Path, *args: str) -> None:
    proc = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "protocol.file.allow=always", "-c", "init.defaultBranch=main", *args],
        cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert proc.returncode == 0, f"git {' '.join(args)}: {proc.stderr[-400:]}"


@pytest.mark.parametrize(
    ("code", "rule_id"),
    [
        ('msg = f"result: {eval(expr)}"', "SEC013"),
        ('msg = f"result: {pickle.loads(blob)}"', "SEC012"),
        ("msg = f'{os.system(\"ls \" + path)}'", "SEC011"),
    ],
)
def test_calls_inside_fstring_expressions_fire_on_every_python(scan, code: str, rule_id: str) -> None:
    """f 文字列の式部分にある呼び出しは、Python の版に関係なく拾うこと."""
    assert_fires(scan(code), rule_id)


@pytest.mark.skipif(shutil.which("git") is None, reason="git が無い環境")
def test_size_limit_also_applies_to_git_diff(tmp_path: Path, caplog) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    _git(project, "init", "-q")
    (project / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(project, "add", ".")
    _git(project, "commit", "-q", "-m", "1")
    # 鍵ではなく eval を使う（利用者の pre-commit の秘密検出にコミットを止められないよう）
    (project / "dump.json").write_text('{"pad": "' + "x" * 300_000 + '"}', encoding="utf-8")
    (project / "b.py").write_text("v = eval(expr)\n", encoding="utf-8")
    _git(project, "add", ".")
    _git(project, "commit", "-q", "-m", "2")

    config_path = tmp_path / "cfg.json"
    config_path.write_text(json.dumps({**NO_DEPS, "max_file_size_kb": 100}), encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        issues = CodeValidator(config_path).validate(project, git_diff=True).issues
    names = {Path(i.file_path).name for i in issues}
    assert "b.py" in names, names
    assert "dump.json" not in names, names
    assert any("dump.json" in r.getMessage() for r in caplog.records)


@pytest.mark.skipif(shutil.which("git") is None, reason="git が無い環境")
def test_initialized_submodule_sources_are_scanned(tmp_path: Path) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()
    _git(sub, "init", "-q")
    (sub / "app.py").write_text("v = eval(expr)\n", encoding="utf-8")
    _git(sub, "add", ".")
    _git(sub, "commit", "-q", "-m", "sub")

    project = tmp_path / "repo"
    project.mkdir()
    _git(project, "init", "-q")
    _git(project, "submodule", "add", "-q", str(sub), "vendor/sub")
    _git(project, "commit", "-q", "-m", "add sub")

    issues = _validate(project, tmp_path, {**NO_DEPS, "file_extensions": [".py"]})
    assert "app.py" in {Path(i.file_path).name for i in issues}


@pytest.mark.parametrize(
    "code",
    [
        'cur.execute(f"SELECT * FROM t WHERE id BETWEEN {low} AND {high}")',
        'cur.execute(f"INSERT INTO t (a, b) VALUES (1, {user_input})")',
        'cur.execute(f"DELETE FROM t WHERE id IN (1, {extra})")',
    ],
)
def test_sec006_fires_on_between_and_later_list_items(scan, code: str) -> None:
    assert_fires(scan(code), "SEC006")


def test_sec003_checks_every_url_on_the_line(scan) -> None:
    code = ('CFG = {"example": "postgresql://user:pass@localhost/db", '
            '"production": "postgresql://admin:Tr0ub4dor3@db.internal/app"}')
    assert_fires(scan(code), "SEC003")
