"""インジェクション・危険な API 呼び出し系ルールの回帰テスト.

  SEC006 動的 SQL 構築（f文字列 / 連結 / .format() / % 演算子）
  SEC011 シェル実行（コマンドインジェクション）
  SEC012 危険な逆シリアライズ
  SEC013 動的コード実行 (eval / exec)
"""
# code-validator: ignore-file
from __future__ import annotations

import pytest

from validator import Severity

from .conftest import assert_fires, assert_silent


# --- SEC006: 動的 SQL -------------------------------------------------------
#
# 旧実装は f文字列と `+` 連結のみを見ており、.format() と % 演算子を
# 取りこぼしていた。4 系統すべてを守る。

@pytest.mark.parametrize(
    "code",
    [
        # f文字列補間
        'query = f"SELECT * FROM users WHERE id = {user_id}"',
        # 文字列連結 + %s
        'query = "SELECT * FROM users WHERE id = %s" + str(user_id)',
        # .format() 位置指定
        'query = "SELECT * FROM users WHERE name = \'{}\'".format(name)',
        # .format() 名前指定
        'query = "DELETE FROM users WHERE id = {uid}".format(uid=user_id)',
        # % 演算子
        'query = "DELETE FROM users WHERE id = %s" % user_id',
        # UPDATE / INSERT でも同様
        'sql = f"UPDATE t SET a = {a}"',
        'sql = "INSERT INTO t VALUES (%s)" % v',
    ],
)
def test_sec006_detects_dynamic_sql(scan, code: str) -> None:
    assert assert_fires(scan(code), "SEC006")[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "code",
    [
        # パラメータ化クエリ（安全）
        'cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        'cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        # SQL キーワードを含まない f文字列
        'msg = f"hello {name}"',
        # コメント
        '# query = f"SELECT * FROM users WHERE id = {user_id}"',
    ],
)
def test_sec006_no_false_positive(scan, code: str) -> None:
    assert_silent(scan(code), "SEC006")


# --- SEC011: コマンドインジェクション ---------------------------------------

@pytest.mark.parametrize(
    "code",
    [
        'os.system("echo " + user_input)',
        'os.popen("ls " + path)',
        'subprocess.run("ls " + path, shell=True)',
        'subprocess.call(cmd, shell=True)',
        'subprocess.check_output(cmd, shell=True)',
        'subprocess.Popen(cmd, shell=True)',
    ],
)
def test_sec011_detects_shell_execution(scan, code: str) -> None:
    assert assert_fires(scan(code), "SEC011")[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "code",
    [
        # 引数リスト渡し・shell=False（安全な形）
        'subprocess.run(["ls", path], capture_output=True)',
        'subprocess.run(["git", "status"], shell=False)',
        # コメント
        '# os.system("echo " + user_input)',
    ],
)
def test_sec011_no_false_positive(scan, code: str) -> None:
    assert_silent(scan(code), "SEC011")


# --- SEC012: 危険な逆シリアライズ -------------------------------------------

@pytest.mark.parametrize(
    "code",
    [
        'obj = pickle.loads(blob)',
        'obj = pickle.load(fh)',
        'obj = marshal.loads(blob)',
        'db = shelve.open("cache")',
        'cfg = yaml.load(text)',
    ],
)
def test_sec012_detects_unsafe_deserialization(scan, code: str) -> None:
    assert assert_fires(scan(code), "SEC012")[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "code",
    [
        'cfg = yaml.safe_load(text)',
        'cfg = yaml.load(text, Loader=yaml.SafeLoader)',
        'cfg = yaml.load(text, SafeLoader)',
        'obj = json.loads(blob)',
        '# obj = pickle.loads(blob)',
    ],
)
def test_sec012_no_false_positive(scan, code: str) -> None:
    assert_silent(scan(code), "SEC012")


# --- SEC013: 動的コード実行 -------------------------------------------------

@pytest.mark.parametrize(
    "code",
    [
        'result = eval(expr)',
        'exec(source)',
        'value = eval (expr)',
    ],
)
def test_sec013_detects_dynamic_execution(scan, code: str) -> None:
    assert assert_fires(scan(code), "SEC013")[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "code",
    [
        # literal_eval は安全なので除外されること
        'value = ast.literal_eval(expr)',
        'from ast import literal_eval',
        # 部分一致で拾わないこと
        'do_evaluate(expr)',
        'self.evaluation = 1',
        '# result = eval(expr)',
    ],
)
def test_sec013_no_false_positive(scan, code: str) -> None:
    assert_silent(scan(code), "SEC013")
