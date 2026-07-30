#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClaudeCode自動検証システム
Code Validator for ClaudeCode Output

ClaudeCodeが生成したコードを自動的に検証し、
セキュリティ問題やコード品質の問題を検出します。
"""

import ast
import fnmatch
import io
import os
import sys
import json
import re
import subprocess
import argparse
import html
import tokenize
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import logging

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# --- 抑制コメント ---------------------------------------------------------
#
# スキャナ自身のテストのように「意図的に脆弱なコード」を含むファイルは、
# 検出されるのが正しい一方で CI を赤にしてしまう。実スキャナには必須の
# 逃げ道であり（bandit の `# nosec`、semgrep の `# nosemgrep` に相当）、
# 対象を明示できる形で用意する。
#
#   foo = "sk-..."   # code-validator: ignore            → その行の全ルール
#   foo = "sk-..."   # code-validator: ignore[SEC001]    → その行の SEC001 のみ
#   # code-validator: ignore-file[SEC004,SEC005]         → ファイル全体の指定ルール
#   # code-validator: ignore-file                        → ファイル全体の全ルール
#
# ファイル単位の指定が必要なのは、CORS やセキュリティヘッダーのように
# line_number を持たない（ファイル全体を根拠にする）ルールがあるため。
SUPPRESS_FILE_RE = re.compile(
    r'#\s*code-validator:\s*ignore-file(?:\[([A-Z0-9,\s]+)\])?', re.IGNORECASE
)
# `(?!-file)` は _parse_suppressions がファイル判定を先に行って continue する
# 実装と冗長（どちらか一方でも ignore-file の誤解釈は起きない）。将来の
# リファクタで順序が入れ替わっても壊れないよう、意図的に両方残している。
SUPPRESS_LINE_RE = re.compile(
    r'#\s*code-validator:\s*ignore(?!-file)(?:\[([A-Z0-9,\s]+)\])?', re.IGNORECASE
)

_SUPPRESS_ALL = '__ALL__'


def _parse_suppressions(lines: List[str]) -> Tuple[set, Dict[int, set]]:
    """抑制コメントを解析し、(ファイル単位, 行単位) の抑制対象を返す。

    ルール未指定なら `_SUPPRESS_ALL` を含む集合を返す。
    """
    file_level: set = set()
    line_level: Dict[int, set] = {}

    for line_num, line in enumerate(lines, 1):
        file_match = SUPPRESS_FILE_RE.search(line)
        if file_match:
            file_level |= _split_rule_ids(file_match.group(1))
            continue
        line_match = SUPPRESS_LINE_RE.search(line)
        if line_match:
            line_level[line_num] = _split_rule_ids(line_match.group(1))

    return file_level, line_level


def _split_rule_ids(raw: Optional[str]) -> set:
    """`[SEC001, SEC006]` の中身をルール ID の集合にする。未指定は全ルール。"""
    if not raw:
        return {_SUPPRESS_ALL}
    return {part.strip().upper() for part in raw.split(',') if part.strip()}


def _apply_suppressions(issues: List['Issue'], lines: List[str]) -> List['Issue']:
    """抑制コメントに一致する Issue を除外する。"""
    file_level, line_level = _parse_suppressions(lines)
    if not file_level and not line_level:
        return issues

    kept = []
    for issue in issues:
        if _SUPPRESS_ALL in file_level or issue.rule_id in file_level:
            continue
        suppressed = line_level.get(issue.line_number) if issue.line_number else None
        if suppressed and (_SUPPRESS_ALL in suppressed or issue.rule_id in suppressed):
            continue
        kept.append(issue)

    return kept


class Severity(Enum):
    """問題の重大度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Issue:
    """検出された問題"""
    severity: Severity
    category: str
    file_path: str
    line_number: Optional[int]
    message: str
    rule_id: str
    suggestion: Optional[str] = None
    code_snippet: Optional[str] = None


@dataclass
class ValidationResult:
    """検証結果"""
    timestamp: str
    project_path: str
    total_files: int
    issues: List[Issue]
    summary: Dict[str, int]
    execution_time: float


class SecurityScanner:
    """セキュリティスキャナー"""
    
    # 認証情報のパターン
    CREDENTIAL_PATTERNS = {
        'api_key': [
            r'sk-[a-zA-Z0-9]{40,}',
            r'sk-proj-[a-zA-Z0-9\-_]{40,}',
            r'sk-ant-[a-zA-Z0-9\-_]{50,}',
            r'AIza[0-9A-Za-z\-_]{35}',
            r'ghp_[a-zA-Z0-9]{36}',
            r'gho_[a-zA-Z0-9]{36}',
            r'ghu_[a-zA-Z0-9]{36}',
            r'ghs_[a-zA-Z0-9]{36}',
            r'ghr_[a-zA-Z0-9]{36}',
        ],
        'password': [
            r'password\s*[:=]\s*["\']([^"\']+)["\']',
            r'passwd\s*[:=]\s*["\']([^"\']+)["\']',
            r'pwd\s*[:=]\s*["\']([^"\']+)["\']',
        ],
        'database_url': [
            r'postgresql://[^:]+:[^@]+@',
            r'mysql://[^:]+:[^@]+@',
            r'mongodb://[^:]+:[^@]+@',
        ],
        'secret_key': [
            r'SECRET_KEY\s*=\s*["\']([^"\']+)["\']',
            r'secret_key\s*=\s*["\']([^"\']+)["\']',
        ],
        # AWS アクセスキー ID。AKIA=長期キー / ASIA=一時キー。
        # 末尾 16 桁は大文字英数のみという AWS の仕様に従う。
        'aws_access_key': [
            r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b',
        ],
        # AWS シークレットアクセスキー。値そのものは 40 文字の base64 様文字列で
        # 汎用文字列と区別できないため、代入先の識別子名を手掛かりにする。
        'aws_secret_key': [
            r'aws_secret_access_key\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
            r'AWS_SECRET_ACCESS_KEY\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
        ],
        # ソース中に直接埋め込まれた秘密鍵ブロック。
        # PEM ヘッダは行頭に無い場合（文字列リテラル内 / \n 連結）もあるため行頭固定しない。
        'private_key_block': [
            r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----',
        ],
    }

    # プレースホルダ・サンプル値。検出しても実害がないため除外する。
    PLACEHOLDER_VALUES = {
        'password', 'passwd', 'pwd', 'your-password', 'your_password',
        'changeme', 'change-me', 'example', 'placeholder', 'dummy',
        'xxx', 'xxxx', '***', 'redacted', 'secret', 'todo',
        'your-secret-key', 'your_secret_key', 'replace-me',
    }

    # 危険な動的コード実行。
    #
    # 直前が `.` / 英数字 / 引用符のものは除外する。実コーパスでの計測では、
    # 除外しないと以下が大量に誤検知になった:
    #   model.eval()                  PyTorch の推論モード切替
    #   /re/.exec(str)                JavaScript の正規表現マッチ
    #   child_process.exec(...)       -> コマンド実行なので SEC011 側で扱う
    #   "eval("                       スキャナのパターン定義そのものの文字列
    DANGEROUS_EXEC_PATTERNS = [
        r'(?<![.\w"\'])eval\s*\(',
        r'(?<![.\w"\'])exec\s*\(',
    ]

    # コマンドインジェクション: `shell=True` は「意図的に危険側を選んだ」印であり
    # 引数がリテラルかどうかに関係なく報告する（誤検知が少なく信号が強い）。
    COMMAND_EXEC_ALWAYS_PATTERNS = [
        r'subprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True',
        r'shell\s*:\s*true',  # Node の child_process オプション
    ]

    # 一方 os.system / os.popen は `os.system("clear")` のような定数実行が多く、
    # それ自体は注入経路ではない。動的構築（連結・補間）を伴う場合のみ報告する。
    COMMAND_EXEC_DYNAMIC_PATTERNS = [
        r'os\.system\s*\(',
        r'os\.popen\s*\(',
        r'child_process[\'"\]\)]*\s*\.\s*exec(?:Sync)?\s*\(',
        r'\bexecSync\s*\(',
    ]

    # 文字列が動的に組み立てられている印。
    DYNAMIC_STRING_MARKER = re.compile(r'f["\']|\+|\.\s*format\s*\(|%\s*[\(\w\'"]|\$\{')

    # SQL として実行される文脈。DB API / ORM の実行系メソッドを対象にする。
    # `.update(` や `.insert(` は Streamlit や tkinter にも存在するため含めない。
    SQL_EXEC_CONTEXT = re.compile(
        r'\b(?:execute|executemany|executescript|exec_driver_sql|executescript)\s*\('
        r'|\bcursor\b'
        r'|\braw_sql\b|\btext\s*\(\s*f?["\']'
        r'|\.\s*raw\s*\(',
        re.IGNORECASE,
    )

    # 文字列リテラルが SQL 文そのもので始まっているか。
    # 接頭辞 (f/r/b/u) と三重引用符、先頭の改行・空白を許容する。
    SQL_STRING_START = re.compile(
        r'[rbuf]{0,2}["\']{1,3}\s*'
        r'\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WITH|MERGE|REPLACE\s+INTO|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE)\b',
        re.IGNORECASE,
    )

    # 危険な逆シリアライズ。
    UNSAFE_DESERIALIZE_PATTERNS = [
        r'\bpickle\.loads?\s*\(',
        r'\bcPickle\.loads?\s*\(',
        r'\bmarshal\.loads\s*\(',
        r'\bshelve\.open\s*\(',
        # yaml.load は Loader 指定が無い場合のみ危険（safe_load / SafeLoader は除外）
        r'\byaml\.load\s*\((?![^)]*(?:SafeLoader|CSafeLoader|Loader\s*=\s*yaml\.safe))',
    ]
    
    # CORS設定のパターン
    # 注: FastAPI CORSMiddleware の設定はカンマ・改行・他kwargsを跨いで記述されるため、
    # allow_origins と allow_credentials が同順序かつ隣接している保証はない。
    # ここでは「ワイルドカードを含む allow_origins」と「allow_credentials=True」が
    # 同一ファイル内に共存していることを検出することで実用上のヒット率を確保する。
    # CORS-REGEX-001 (#13/#14) で修正済み: 旧パターンは閉じ `\]` 欠落により本番コードに永遠に
    # マッチしなかったため、両側に `\]?` と DOTALL ベースの近接マッチを導入。
    CORS_PATTERNS = {
        # allow_origins=["*"] のリスト（"*" 単体または他要素混在）を許容
        'wildcard_origins': r'allow_origins\s*=\s*\[[^\]]*["\']\*["\'][^\]]*\]',
        # 同一ファイル内に wildcard origins と allow_credentials=True が共存
        'wildcard_with_credentials': (
            r'allow_origins\s*=\s*\[[^\]]*["\']\*["\'][^\]]*\]'
            r'[\s\S]{0,500}?allow_credentials\s*=\s*True'
            r'|'
            r'allow_credentials\s*=\s*True'
            r'[\s\S]{0,500}?allow_origins\s*=\s*\[[^\]]*["\']\*["\'][^\]]*\]'
        ),
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """設定に応じて個別ルールを有効/無効化する。

        引数なしでも従来どおり全ルール有効で動作する（既存の呼び出しとテストを壊さない）。
        """
        rules = (config or {}).get('security_rules', {})
        self.check_credentials = rules.get('check_credentials', True)
        self.check_cors = rules.get('check_cors', True)
        self.check_sql_injection = rules.get('check_sql_injection', True)
        self.check_security_headers = rules.get('check_security_headers', True)
        self.check_dangerous_calls = rules.get('check_dangerous_calls', True)

    def scan_file(self, file_path: Path) -> List[Issue]:
        """ファイルをスキャンして問題を検出"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            # 認証情報の検出
            if self.check_credentials:
                issues.extend(self._scan_credentials(file_path, lines))

            # CORS設定の検出
            if self.check_cors:
                issues.extend(self._scan_cors(file_path, lines))

            # SQLインジェクションの可能性
            if self.check_sql_injection:
                issues.extend(self._scan_sql_injection(file_path, lines))

            # セキュリティヘッダーの検出
            if self.check_security_headers:
                issues.extend(self._scan_security_headers(file_path, lines))

            # 危険な動的実行・逆シリアライズ・シェル実行
            if self.check_dangerous_calls:
                issues.extend(self._scan_dangerous_calls(file_path, lines))

            # 抑制コメントの適用は必ず最後に行う（全ルールに一律で効かせる）
            issues = _apply_suppressions(issues, lines)

        except Exception as e:
            logger.warning(f"ファイルスキャンエラー {file_path}: {e}")

        return issues
    
    def _scan_credentials(self, file_path: Path, lines: List[str]) -> List[Issue]:
        """認証情報の検出"""
        issues = []
        
        for line_num, line in enumerate(lines, 1):
            # APIキーの検出
            for pattern in self.CREDENTIAL_PATTERNS['api_key']:
                if re.search(pattern, line, re.IGNORECASE):
                    # コメントやドキュメント内は除外
                    if not self._is_comment_or_docstring(line):
                        issues.append(Issue(
                            severity=Severity.CRITICAL,
                            category="security",
                            file_path=str(file_path),
                            line_number=line_num,
                            message=f"APIキーがハードコードされている可能性があります",
                            rule_id="SEC001",
                            suggestion="環境変数を使用してください",
                            code_snippet=line.strip()[:100]
                        ))
            
            # パスワードの検出
            for pattern in self.CREDENTIAL_PATTERNS['password']:
                match = re.search(pattern, line, re.IGNORECASE)
                if match and not self._is_comment_or_docstring(line):
                    password = match.group(1)
                    # サンプルやプレースホルダーは除外
                    if not self._is_placeholder(password):
                        issues.append(Issue(
                            severity=Severity.CRITICAL,
                            category="security",
                            file_path=str(file_path),
                            line_number=line_num,
                            message="パスワードがハードコードされている可能性があります",
                            rule_id="SEC002",
                            suggestion="環境変数またはシークレット管理サービスを使用してください",
                            code_snippet=line.strip()[:100]
                        ))
            
            # データベースURLの検出
            for pattern in self.CREDENTIAL_PATTERNS['database_url']:
                if re.search(pattern, line, re.IGNORECASE) and not self._is_comment_or_docstring(line):
                    issues.append(Issue(
                        severity=Severity.CRITICAL,
                        category="security",
                        file_path=str(file_path),
                        line_number=line_num,
                        message="データベース認証情報がハードコードされている可能性があります",
                        rule_id="SEC003",
                        suggestion="環境変数DATABASE_URLを使用してください",
                        code_snippet=line.strip()[:100]
                    ))

            # SECRET_KEY の検出。パターンは以前から定義されていたが未配線だった
            # ため、Django/Flask の SECRET_KEY 直書きを取りこぼしていた。
            for pattern in self.CREDENTIAL_PATTERNS['secret_key']:
                match = re.search(pattern, line)
                if match and not self._is_comment_or_docstring(line):
                    if not self._is_placeholder(match.group(1)):
                        issues.append(Issue(
                            severity=Severity.CRITICAL,
                            category="security",
                            file_path=str(file_path),
                            line_number=line_num,
                            message="SECRET_KEY がハードコードされている可能性があります",
                            rule_id="SEC008",
                            suggestion="環境変数またはシークレット管理サービスを使用してください",
                            code_snippet=line.strip()[:100]
                        ))

            # AWS 認証情報
            for key in ('aws_access_key', 'aws_secret_key'):
                for pattern in self.CREDENTIAL_PATTERNS[key]:
                    if re.search(pattern, line) and not self._is_comment_or_docstring(line):
                        issues.append(Issue(
                            severity=Severity.CRITICAL,
                            category="security",
                            file_path=str(file_path),
                            line_number=line_num,
                            message="AWS 認証情報がハードコードされている可能性があります",
                            rule_id="SEC009",
                            suggestion="IAM ロールまたは環境変数を使用してください",
                            code_snippet=line.strip()[:100]
                        ))
                        break

            # 秘密鍵ブロックの直接埋め込み。コメント行でも実害があるため
            # _is_comment_or_docstring による除外を行わない。
            for pattern in self.CREDENTIAL_PATTERNS['private_key_block']:
                if re.search(pattern, line):
                    issues.append(Issue(
                        severity=Severity.CRITICAL,
                        category="security",
                        file_path=str(file_path),
                        line_number=line_num,
                        message="秘密鍵がソースコードに埋め込まれています",
                        rule_id="SEC010",
                        suggestion="鍵はリポジトリ外で管理し、パスまたはシークレットストア経由で読み込んでください",
                        code_snippet=line.strip()[:60]
                    ))

        return issues

    def _is_placeholder(self, value: str) -> bool:
        """サンプル・プレースホルダー値かどうかを判定する。

        誤検知を抑えるための除外判定。実値らしさではなく「明らかにダミー」
        であることだけを見る（過度に広げると真の漏洩を見逃すため）。
        """
        normalized = value.strip().lower()
        if normalized in self.PLACEHOLDER_VALUES:
            return True
        # os.environ / process.env 等からの取得は値ではない
        if any(token in value for token in ('os.environ', 'getenv', 'process.env', '${', '{{')):
            return True
        return False
    
    def _scan_cors(self, file_path: Path, lines: List[str]) -> List[Issue]:
        """CORS設定の検出"""
        issues = []
        file_content = '\n'.join(lines)
        
        # allow_origins=["*"]とallow_credentials=Trueの組み合わせ
        if re.search(self.CORS_PATTERNS['wildcard_with_credentials'], file_content, re.MULTILINE):
            issues.append(Issue(
                severity=Severity.CRITICAL,
                category="security",
                file_path=str(file_path),
                line_number=None,
                message="CORS設定: allow_origins=['*']とallow_credentials=Trueの組み合わせは危険です",
                rule_id="SEC004",
                suggestion="allow_originsを具体的なオリジンに制限してください",
            ))
        
        # allow_origins=["*"]のみ
        if re.search(self.CORS_PATTERNS['wildcard_origins'], file_content, re.MULTILINE):
            issues.append(Issue(
                severity=Severity.HIGH,
                category="security",
                file_path=str(file_path),
                line_number=None,
                message="CORS設定: allow_origins=['*']は本番環境では推奨されません",
                rule_id="SEC005",
                suggestion="環境変数で許可オリジンを制御してください",
            ))
        
        return issues
    
    def _scan_sql_injection(self, file_path: Path, lines: List[str]) -> List[Issue]:
        """SQLインジェクションの可能性を検出"""
        issues = []
        
        sql_kw = r'\b(SELECT|INSERT|UPDATE|DELETE)\b'
        for line_num, line in enumerate(lines, 1):
            # SQL キーワードは英単語としてもごく普通に出てくる。実コーパスでの
            # 計測では、キーワードの出現だけを条件にすると以下が大量に誤検知になった:
            #   logger.warning(f"Failed to delete memory {id}")
            #   status.update(label=f"完了 {n}件")
            #   text.insert(tk.END, f"[{ts}] {msg}")
            #   print(f"Build {v} -> UPDATE DETECTED")
            # そこで「SQL として実行される文脈」か「文字列が SQL 文で始まる」ことを
            # 必須条件に加える。
            if not (self.SQL_EXEC_CONTEXT.search(line) or self.SQL_STRING_START.search(line)):
                continue
            # コメントアウトされた SQL は実行されないため対象外。
            # ここで _is_comment_or_docstring を使うと、三重引用符を含む行
            # （複数行 SQL の一般的な書き方）まで除外され取りこぼすため、
            # 行頭コメントだけを見る専用判定を使う。
            if self._is_commented_out(line):
                continue
            has_sql_kw = bool(re.search(sql_kw, line, re.IGNORECASE))
            # パターン1: 文字列連結による動的SQL（+ 演算子 + フォーマット）
            concat_sqli = (
                has_sql_kw
                and re.search(r'.+\+.+', line)
                and ('f"' in line or "f'" in line or '%s' in line or '%d' in line)
            )
            # パターン2: f文字列補間による動的SQL（+ 演算子なし。最も一般的な
            # 現代的パターンで、旧実装は + を必須としていたため全件見逃して
            # いた）。SQL文字列内に引用符が混在する（例 '{tok}'）ため範囲を
            # 厳密に取らず、同一行に f文字列・SQLキーワード・{...} 補間が
            # 揃うことを条件とするヒューリスティック。
            fstring_sqli = (
                has_sql_kw
                and re.search(r'f["\']', line)
                and re.search(r'\{[^}]+\}', line)
            )
            # パターン3: str.format() による動的SQL。
            #   "SELECT ... WHERE name = '{}'".format(name)
            # 旧実装は f文字列と + のみを見ていたため取りこぼしていた。
            format_sqli = (
                has_sql_kw
                and re.search(r'\{\s*\d*\s*\}|\{[a-zA-Z_][a-zA-Z0-9_]*\}', line)
                and re.search(r'\.\s*format\s*\(', line)
            )
            # パターン4: % 演算子による動的SQL。
            #   "DELETE FROM users WHERE id = %s" % user_id
            # プレースホルダを渡す安全な形 (cursor.execute(sql, params)) と区別するため、
            # 文字列リテラル直後に % 演算子が続くことを条件にする。
            percent_sqli = (
                has_sql_kw
                and re.search(r'["\']\s*%\s*[^\s%]', line)
            )
            if concat_sqli or fstring_sqli or format_sqli or percent_sqli:
                issues.append(Issue(
                    severity=Severity.HIGH,
                    category="security",
                    file_path=str(file_path),
                    line_number=line_num,
                    message="SQLインジェクションの可能性: 動的なSQL構築（文字列連結またはf文字列補間）",
                    rule_id="SEC006",
                    suggestion="ORMまたはパラメータ化クエリを使用してください",
                    code_snippet=line.strip()[:100]
                ))
        
        return issues
    
    # FastAPI アプリの生成箇所。`FastAPI` という語の出現ではなく、
    # インスタンス化していることを条件にする。
    #
    # 旧実装は `'FastAPI' in content` で判定していたため、実コーパスでは
    # バッジ文字列に "FastAPI" を含むだけの README 生成スクリプトや、
    # 型注釈のためだけに import しているモジュールで大量に誤検知した。
    FASTAPI_APP_RE = re.compile(r'\bFastAPI\s*\(')

    # セキュリティヘッダーはアプリ全体で一度ミドルウェアに設定するもの。
    # X-XSS-Protection は現在非推奨（設定しないことが推奨）なので要求しない。
    REQUIRED_SECURITY_HEADERS = ('X-Content-Type-Options', 'X-Frame-Options')

    def _scan_security_headers(self, file_path: Path, lines: List[str]) -> List[Issue]:
        """セキュリティヘッダーの検出"""
        issues = []
        file_content = '\n'.join(lines)

        if not self.FASTAPI_APP_RE.search(file_content):
            return issues

        missing = [h for h in self.REQUIRED_SECURITY_HEADERS if h not in file_content]
        if not missing:
            return issues

        # ヘッダーごとに 1 件ずつ出すとルーター分割したアプリで件数が膨らむため、
        # アプリ 1 つにつき 1 件にまとめる。
        issues.append(Issue(
            severity=Severity.MEDIUM,
            category="security",
            file_path=str(file_path),
            line_number=None,
            message=f"セキュリティヘッダーが設定されていません: {', '.join(missing)}",
            rule_id="SEC007",
            suggestion="アプリ生成箇所でセキュリティヘッダーミドルウェアを追加してください",
        ))

        return issues
    
    def _scan_dangerous_calls(self, file_path: Path, lines: List[str]) -> List[Issue]:
        """危険な API 呼び出しを検出する。

        LLM が生成しがちだが既存ルールで拾えていなかった 3 系統を対象にする。
          SEC011 シェル実行（コマンドインジェクション）
          SEC012 危険な逆シリアライズ
          SEC013 動的コード実行 (eval / exec)
        """
        issues = []

        checks = (
            (
                self.COMMAND_EXEC_ALWAYS_PATTERNS,
                "SEC011",
                "shell=True でのコマンド実行は外部入力の混入経路になります",
                "shell=False にし、コマンドと引数はリストで渡してください",
            ),
            (
                self.UNSAFE_DESERIALIZE_PATTERNS,
                "SEC012",
                "信頼できないデータの逆シリアライズは任意コード実行につながります",
                "JSON など安全な形式か、yaml.safe_load を使用してください",
            ),
            (
                self.DANGEROUS_EXEC_PATTERNS,
                "SEC013",
                "eval / exec による動的コード実行は任意コード実行につながります",
                "ast.literal_eval や明示的な分岐に置き換えてください",
            ),
        )

        for line_num, line in enumerate(lines, 1):
            if self._is_commented_out(line):
                continue

            # os.system 等は動的構築を伴う場合のみ。定数実行（`os.system("clear")`）は
            # 注入経路ではないため、実コーパスでは誤検知しか生まなかった。
            if self.DYNAMIC_STRING_MARKER.search(line):
                for pattern in self.COMMAND_EXEC_DYNAMIC_PATTERNS:
                    if re.search(pattern, line):
                        issues.append(Issue(
                            severity=Severity.HIGH,
                            category="security",
                            file_path=str(file_path),
                            line_number=line_num,
                            message="動的に組み立てた文字列をシェルに渡しています（コマンドインジェクション）",
                            rule_id="SEC011",
                            suggestion="subprocess を shell=False で使い、引数はリストで渡してください",
                            code_snippet=line.strip()[:100]
                        ))
                        break

            for patterns, rule_id, message, suggestion in checks:
                for pattern in patterns:
                    if re.search(pattern, line):
                        issues.append(Issue(
                            severity=Severity.HIGH,
                            category="security",
                            file_path=str(file_path),
                            line_number=line_num,
                            message=message,
                            rule_id=rule_id,
                            suggestion=suggestion,
                            code_snippet=line.strip()[:100]
                        ))
                        break

        return issues

    @staticmethod
    def _is_commented_out(line: str) -> bool:
        """行がコメントアウトされたコードかどうかを判定する。

        `_is_comment_or_docstring` は三重引用符を含む行も除外してしまうため、
        「実行されないコード」だけを外したい用途にはこちらを使う。
        """
        stripped = line.strip()
        return stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*')

    def _is_comment_or_docstring(self, line: str) -> bool:
        """コメントまたはドキュメント文字列かどうかを判定"""
        stripped = line.strip()
        return (
            stripped.startswith('#') or
            stripped.startswith('//') or
            stripped.startswith('*') or
            '"""' in stripped or
            "'''" in stripped
        )


class CodeQualityChecker:
    """コード品質チェッカー"""

    DEFAULT_MAX_LINE_LENGTH = 120

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """設定から品質ルールのしきい値と有効/無効を読み込む。

        引数なしでも従来どおりの既定値で動作する。
        """
        rules = (config or {}).get('quality_rules', {})
        self.max_line_length = rules.get('max_line_length', self.DEFAULT_MAX_LINE_LENGTH)
        self.check_unused_imports = rules.get('check_unused_imports', True)
        self.check_complex_functions = rules.get('check_complex_functions', True)

    def check_file(self, file_path: Path) -> List[Issue]:
        """ファイルのコード品質をチェック"""
        issues = []

        # Pythonファイルの場合
        if file_path.suffix == '.py':
            issues.extend(self._check_python_file(file_path))

        return issues

    def _check_python_file(self, file_path: Path) -> List[Issue]:
        """Pythonファイルの品質チェック"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            # 未使用のインポート
            if self.check_unused_imports:
                issues.extend(self._check_unused_imports(file_path, content))

            # 長い行の検出
            issues.extend(self._check_long_lines(file_path, lines))

            # 複雑な関数の検出（簡易チェック）
            if self.check_complex_functions:
                issues.extend(self._check_complex_functions(file_path, lines))

            # セキュリティ側と同じ抑制コメントを品質ルールにも効かせる
            issues = _apply_suppressions(issues, lines)

        except Exception as e:
            logger.warning(f"コード品質チェックエラー {file_path}: {e}")

        return issues

    def _check_unused_imports(self, file_path: Path, content: str) -> List[Issue]:
        """未使用のインポートを検出する。

        旧実装は行を走査して名前を集めるだけで、何も返さない空実装だった
        （README には機能として記載されていたが実際には常に 0 件だった）。

        誤検知ゼロを優先し、2 段のゲートを通ったものだけを報告する。
          1. AST で import が束縛する名前を正確に取得する
          2. その名前が import 文以外の場所にテキストとして出現しないことを確認する

        2 段目は、型注釈の文字列・``__all__``・デコレータなど AST 走査だけでは
        「使用」と判定しにくい箇所を救うための保守的なゲート。取りこぼし
        （false negative）は許容し、誤検知を出さないことを優先する。
        """
        issues = []

        # __init__.py は再エクスポート目的の import が正当なため対象外とする
        if file_path.name == '__init__.py':
            return issues

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            logger.debug(f"AST 解析をスキップ {file_path}: {e}")
            return issues

        # import が束縛する名前と、その行番号を集める
        bindings: Dict[str, int] = {}
        star_import = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    # `import a.b.c` は `a` を束縛する
                    name = alias.asname or alias.name.split('.')[0]
                    bindings[name] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                # `from __future__ import ...` は動作に必要なので対象外
                if node.module == '__future__':
                    continue
                for alias in node.names:
                    if alias.name == '*':
                        star_import = True
                        continue
                    bindings[alias.asname or alias.name] = node.lineno

        # ワイルドカード import があると使用箇所を追跡できないため判定を放棄する
        if star_import:
            return issues

        # AST 上で参照されている名前
        used: set = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                # `a.b.c` の根 `a` を辿る
                root = node
                while isinstance(root, ast.Attribute):
                    root = root.value
                if isinstance(root, ast.Name):
                    used.add(root.id)

        # import 文の行とコメントを除いた本文（2 段目のゲート用）。
        #
        # コメントを残すと「# json と hashlib は未使用」のような記述自体が
        # 「使用されている」と誤判定され、検出が丸ごと無効化される。
        # 文字列リテラルは残す（型注釈の前方参照や __all__ が該当するため）。
        lines = content.split('\n')
        import_lines = set(bindings.values())
        comment_starts = self._comment_start_columns(content)
        body_parts = []
        for idx, line in enumerate(lines, 1):
            if idx in import_lines:
                continue
            col = comment_starts.get(idx)
            body_parts.append(line[:col] if col is not None else line)
        body_text = '\n'.join(body_parts)

        for name, lineno in sorted(bindings.items(), key=lambda kv: kv[1]):
            if name in used:
                continue
            # 2 段目: テキストとしても現れないことを確認する
            if re.search(rf'\b{re.escape(name)}\b', body_text):
                continue
            source_line = lines[lineno - 1] if 0 < lineno <= len(lines) else ''
            # noqa が付いている行は意図的な未使用として尊重する
            if 'noqa' in source_line:
                continue
            issues.append(Issue(
                severity=Severity.LOW,
                category="code_quality",
                file_path=str(file_path),
                line_number=lineno,
                message=f"未使用のインポート: {name}",
                rule_id="QUAL002",
                suggestion="不要なインポートを削除してください",
                code_snippet=source_line.strip()[:100],
            ))

        return issues


    @staticmethod
    def _comment_start_columns(content: str) -> Dict[int, int]:
        """各行のコメント開始桁を返す（行番号 -> 桁）。

        `#` の単純検索では文字列リテラル内の `#` を誤ってコメント扱いするため、
        tokenize で正確に判定する。解析に失敗した場合は空辞書を返し、
        呼び出し側は「コメント除去なし」で保守的に動作する。
        """
        starts: Dict[int, int] = {}
        try:
            for token in tokenize.generate_tokens(io.StringIO(content).readline):
                if token.type == tokenize.COMMENT:
                    lineno, col = token.start
                    starts.setdefault(lineno, col)
        except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
            return {}
        return starts

    def _check_long_lines(self, file_path: Path, lines: List[str]) -> List[Issue]:
        """長い行をチェック"""
        issues = []
        # 旧実装はメソッド内の定数で固定しており、config の
        # quality_rules.max_line_length が README に記載されていたにも関わらず
        # 反映されなかった。
        MAX_LINE_LENGTH = self.max_line_length

        for line_num, line in enumerate(lines, 1):
            if len(line) > MAX_LINE_LENGTH:
                # コメントやURLは除外
                if not line.strip().startswith('#') and 'http' not in line:
                    issues.append(Issue(
                        severity=Severity.LOW,
                        category="code_quality",
                        file_path=str(file_path),
                        line_number=line_num,
                        message=f"行が長すぎます ({len(line)}文字)",
                        rule_id="QUAL001",
                        suggestion=f"行を{MAX_LINE_LENGTH}文字以下に分割してください",
                    ))
        
        return issues
    
    def _check_complex_functions(self, file_path: Path, lines: List[str]) -> List[Issue]:
        """複雑な関数をチェック（簡易版）"""
        issues = []
        # より高度なチェックはcyclomatic complexityツールを使用
        return issues


class DependencyChecker:
    """依存関係チェッカー"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """設定から Python / Node の依存監査の有効・無効を読み込む。"""
        rules = (config or {}).get('dependency_rules', {})
        self.check_python = rules.get('check_python', True)
        self.check_node = rules.get('check_node', True)

    def check_dependencies(self, project_path: Path) -> List[Issue]:
        """依存関係の脆弱性をチェック"""
        issues = []

        # requirements.txtのチェック
        requirements_file = project_path / 'requirements.txt'
        if self.check_python and requirements_file.exists():
            issues.extend(self._check_python_dependencies(requirements_file))

        # package.jsonのチェック
        package_json = project_path / 'package.json'
        if self.check_node and package_json.exists():
            issues.extend(self._check_node_dependencies(package_json))
        
        return issues
    
    def _check_python_dependencies(self, requirements_file: Path) -> List[Issue]:
        """Python依存関係のチェック"""
        issues = []
        
        # pip-auditの実行を試行
        try:
            result = subprocess.run(
                ['pip-audit', '--requirement', str(requirements_file), '--format', 'json'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # pip-audit は脆弱性を検出すると returncode=1 を返すため、
            # returncode で「未インストール / 失敗」を判定してはならない（DEP-LOGIC-002）。
            # stdout に JSON があれば優先的に解析する。
            audit_data = None
            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)
                except json.JSONDecodeError:
                    audit_data = None

            if audit_data is not None:
                # pip-audit の JSON スキーマは
                #   { "dependencies": [ { "name": ..., "vulns": [...] }, ... ] }
                # または旧形式 { "vulnerabilities": [...] } のどちらか。
                vulns = []
                if isinstance(audit_data, dict):
                    if 'vulnerabilities' in audit_data:
                        vulns = audit_data.get('vulnerabilities') or []
                    elif 'dependencies' in audit_data:
                        for dep in audit_data.get('dependencies') or []:
                            for v in dep.get('vulns') or []:
                                vulns.append({
                                    'name': dep.get('name', 'unknown'),
                                    'id': v.get('id', 'unknown'),
                                    'fix_versions': v.get('fix_versions'),
                                })
                for vuln in vulns:
                    fix = vuln.get('fix_versions') or 'パッケージを更新してください'
                    if isinstance(fix, list):
                        fix = ', '.join(fix) if fix else 'パッケージを更新してください'
                    issues.append(Issue(
                        severity=Severity.HIGH,
                        category="dependencies",
                        file_path=str(requirements_file),
                        line_number=None,
                        message=f"脆弱性検出: {vuln.get('name', 'unknown')} - {vuln.get('id', 'unknown')}",
                        rule_id="DEP002",
                        suggestion=fix,
                    ))
            elif result.returncode != 0:
                # JSON が無く非ゼロ終了 = 検査が「実行できなかった」状態。
                # 旧実装はこれを一律 DEP001 (INFO, 未インストール) として報告して
                # いたため、実際には pip-audit が入っていて依存解決に失敗した
                # ケースでも「未インストール」と誤診し、かつ INFO なので CI が
                # 緑のまま通っていた。「0件」と「見ていない」が区別できない
                # 偽グリーンの温床だったため、失敗理由を残して HIGH で報告する。
                detail = self._summarize_process_error(result.stderr)
                issues.append(Issue(
                    severity=Severity.HIGH,
                    category="dependencies",
                    file_path=str(requirements_file),
                    line_number=None,
                    message=f"pip-audit の実行に失敗し、依存関係の脆弱性を検査できませんでした: {detail}",
                    rule_id="DEP005",
                    suggestion=(
                        "requirements.txt の依存衝突を解消するか、"
                        "pip-audit を直接実行して原因を確認してください"
                    ),
                ))

        except FileNotFoundError:
            issues.append(Issue(
                severity=Severity.INFO,
                category="dependencies",
                file_path=str(requirements_file),
                line_number=None,
                message="pip-auditがインストールされていません",
                rule_id="DEP001",
                suggestion="pip install pip-audit を実行してください",
            ))
        except subprocess.TimeoutExpired:
            # タイムアウトも「検査できなかった」ケース。ログだけでは CI が緑になる。
            issues.append(Issue(
                severity=Severity.HIGH,
                category="dependencies",
                file_path=str(requirements_file),
                line_number=None,
                message="pip-audit がタイムアウトし、依存関係の脆弱性を検査できませんでした",
                rule_id="DEP005",
                suggestion="ネットワーク状況を確認するか、依存数を減らして再実行してください",
            ))
        except Exception as e:
            logger.warning(f"依存関係チェックエラー: {e}")

        return issues

    @staticmethod
    def _summarize_process_error(stderr: Optional[str]) -> str:
        """外部プロセスの stderr から原因行を1行に要約する。

        レポートに載るため長さを抑える。ERROR 行があればそれを優先し、
        無ければ最後の非空行を使う。
        """
        if not stderr:
            return "原因不明（stderr が空）"
        lines = [line.strip() for line in stderr.splitlines() if line.strip()]
        if not lines:
            return "原因不明（stderr が空）"
        for line in lines:
            if 'ResolutionImpossible' in line or 'conflicting dependencies' in line:
                return "依存関係の衝突により解決不能"
        for line in lines:
            if line.startswith('ERROR') or 'ERROR:' in line:
                return line[:200]
        return lines[-1][:200]

    def _check_node_dependencies(self, package_json: Path) -> List[Issue]:
        """Node.js依存関係のチェック"""
        issues = []
        
        # npm auditの実行を試行
        try:
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                cwd=package_json.parent,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # npm audit は脆弱性検出時に returncode=1 を返す仕様のため、
            # returncode ではなく stdout の JSON を根拠に脆弱性を判定する (DEP-LOGIC-003)
            # returncode=0: 脆弱性なし / returncode=1: 脆弱性あり
            # returncode>=2: ネットワークエラー・npm未インストール等の実行失敗
            if result.returncode not in (0, 1):
                # 旧実装は logger.warning のみで Issue を作らなかったため、
                # npm audit が失敗しても CI は緑のまま通っていた（pip 側と同じ
                # 偽グリーン）。検査できなかったことを HIGH で明示する。
                logger.warning(
                    "npm audit が異常終了しました (returncode=%d)。"
                    "npm のインストール状況やネットワークを確認してください。",
                    result.returncode,
                )
                issues.append(Issue(
                    severity=Severity.HIGH,
                    category="dependencies",
                    file_path=str(package_json),
                    line_number=None,
                    message=(
                        "npm audit の実行に失敗し、依存関係の脆弱性を検査できませんでした "
                        f"(returncode={result.returncode}): "
                        f"{self._summarize_process_error(result.stderr)}"
                    ),
                    rule_id="DEP006",
                    suggestion="npm ci で依存を解決し、npm audit を直接実行して原因を確認してください",
                ))
            else:
                audit_data = None
                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                    except json.JSONDecodeError:
                        logger.warning(
                            "npm audit の出力が JSON として解析できませんでした。"
                            "npm のバージョンまたは出力形式を確認してください。"
                        )

                if audit_data is not None:
                    vulnerabilities = audit_data.get('vulnerabilities', {})

                    for pkg_name, vuln_info in vulnerabilities.items():
                        severity = vuln_info.get('severity', 'unknown')
                        severity_enum = {
                            'critical': Severity.CRITICAL,
                            'high': Severity.HIGH,
                            'moderate': Severity.MEDIUM,
                            'low': Severity.LOW,
                        }.get(severity, Severity.MEDIUM)

                        issues.append(Issue(
                            severity=severity_enum,
                            category="dependencies",
                            file_path=str(package_json),
                            line_number=None,
                            message=f"脆弱性検出: {pkg_name} ({severity})",
                            rule_id="DEP003",
                            suggestion="npm audit fix を実行してください",
                        ))
                    
        except FileNotFoundError:
            issues.append(Issue(
                severity=Severity.INFO,
                category="dependencies",
                file_path=str(package_json),
                line_number=None,
                message="npmがインストールされていません",
                rule_id="DEP004",
                suggestion="npmをインストールしてください",
            ))
        except subprocess.TimeoutExpired:
            issues.append(Issue(
                severity=Severity.HIGH,
                category="dependencies",
                file_path=str(package_json),
                line_number=None,
                message="npm audit がタイムアウトし、依存関係の脆弱性を検査できませんでした",
                rule_id="DEP006",
                suggestion="ネットワーク状況を確認して再実行してください",
            ))
        except Exception as e:
            logger.warning(f"依存関係チェックエラー: {e}")

        return issues


class CodeValidator:
    """コード検証システムのメインクラス"""
    
    def __init__(self, config_path: Optional[Path] = None):
        # 設定を先に読む。各チェッカーは設定でルールの有効/無効としきい値が
        # 変わるため、生成順を逆にすると config が反映されない。
        self.config = self._load_config(config_path)
        self.security_scanner = SecurityScanner(self.config)
        self.quality_checker = CodeQualityChecker(self.config)
        self.dependency_checker = DependencyChecker(self.config)
    
    def _load_config(self, config_path: Optional[Path]) -> Dict[str, Any]:
        """設定ファイルを読み込む"""
        default_config = {
            'exclude_patterns': [
                '**/node_modules/**',
                '**/venv/**',
                '**/__pycache__/**',
                '**/.git/**',
                '**/dist/**',
                '**/build/**',
            ],
            'file_extensions': ['.py', '.js', '.ts', '.tsx', '.json', '.yaml', '.yml'],
        }
        
        if config_path and config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.warning(f"設定ファイルの読み込みエラー: {e}")
        
        return default_config
    
    def validate(self, project_path: Path, git_diff: bool = False) -> ValidationResult:
        """プロジェクトを検証"""
        start_time = datetime.now()
        issues = []
        
        if git_diff:
            files_to_check = self._get_git_diff_files(project_path)
        else:
            files_to_check = self._get_all_files(project_path)

        self_path = Path(__file__).resolve()
        files_to_check = [f for f in files_to_check if f.resolve() != self_path]

        logger.info(f"検証対象ファイル数: {len(files_to_check)}")
        
        # セキュリティスキャン
        logger.info("セキュリティスキャンを実行中...")
        for file_path in files_to_check:
            if file_path.suffix in ['.py', '.js', '.ts', '.tsx', '.json']:
                issues.extend(self.security_scanner.scan_file(file_path))
        
        # コード品質チェック
        logger.info("コード品質チェックを実行中...")
        for file_path in files_to_check:
            if file_path.suffix == '.py':
                issues.extend(self.quality_checker.check_file(file_path))
        
        # 依存関係チェック
        logger.info("依存関係チェックを実行中...")
        issues.extend(self.dependency_checker.check_dependencies(project_path))
        
        # 結果の集計
        execution_time = (datetime.now() - start_time).total_seconds()
        summary = self._calculate_summary(issues)
        
        return ValidationResult(
            timestamp=datetime.now().isoformat(),
            project_path=str(project_path),
            total_files=len(files_to_check),
            issues=issues,
            summary=summary,
            execution_time=execution_time
        )
    
    def _get_all_files(self, project_path: Path) -> List[Path]:
        """すべての検証対象ファイルを取得"""
        files = []
        exclude_patterns = self.config.get('exclude_patterns', [])
        file_extensions = self.config.get('file_extensions', ['.py'])

        for ext in file_extensions:
            for file_path in project_path.rglob(f'*{ext}'):
                if not self._is_excluded(file_path, project_path, exclude_patterns):
                    files.append(file_path)

        return files

    @staticmethod
    def _is_excluded(file_path: Path, project_path: Path, exclude_patterns: List[str]) -> bool:
        """除外パターンに一致するかを判定する。

        旧実装は exclude_patterns を回すだけの空ループ (`pass`) で、実際には
        node_modules / venv / __pycache__ / .git のハードコード4種しか除外して
        いなかった。config に書いた `**/dist/**` 等が効かない状態だったため、
        fnmatch による実判定に置き換える。
        """
        # POSIX 形式に正規化し、Windows の `\` でもパターンが一致するようにする
        try:
            relative = file_path.relative_to(project_path).as_posix()
        except ValueError:
            relative = file_path.as_posix()
        absolute = file_path.as_posix()

        for pattern in exclude_patterns:
            normalized = pattern.replace('\\', '/')
            if fnmatch.fnmatch(relative, normalized) or fnmatch.fnmatch(absolute, normalized):
                return True
            # `**/node_modules/**` 形式はディレクトリ名の部分一致でも拾う
            bare = normalized.strip('*/')
            if bare and f'/{bare}/' in f'/{relative}/':
                return True

        return False
    
    def _resolve_diff_base(self, project_path: Path) -> Optional[str]:
        """差分の比較ベースを解決する。

        `git diff HEAD` は CI の checkout 直後では作業ツリーに未コミット変更が
        無いため常に空になり、セキュリティゲートが 0 ファイルで素通りしていた
        (CI-BYPASS-001)。PR の実差分を見るには「マージ先からの分岐点」と比較
        する必要がある。優先順位:
          1. origin/<default>...HEAD のマージベース (PR の正しい差分)
          2. HEAD~1 (origin 不在のローカル単発コミット)
        いずれも解決できなければ None を返し、呼び出し側でフォールバックする。
        """
        candidates = []
        try:
            head = subprocess.run(
                ['git', 'symbolic-ref', '--quiet', '--short', 'refs/remotes/origin/HEAD'],
                cwd=project_path, capture_output=True, text=True, timeout=15,
            )
            if head.returncode == 0 and head.stdout.strip():
                candidates.append(head.stdout.strip())  # 例: origin/main
        except (subprocess.SubprocessError, OSError):
            pass
        candidates += ['origin/main', 'origin/master']
        for ref in candidates:
            try:
                mb = subprocess.run(
                    ['git', 'merge-base', ref, 'HEAD'],
                    cwd=project_path, capture_output=True, text=True, timeout=15,
                )
                if mb.returncode == 0 and mb.stdout.strip():
                    return mb.stdout.strip()
            except (subprocess.SubprocessError, OSError):
                continue
        try:
            rev = subprocess.run(
                ['git', 'rev-parse', '--verify', '--quiet', 'HEAD~1'],
                cwd=project_path, capture_output=True, text=True, timeout=15,
            )
            if rev.returncode == 0 and rev.stdout.strip():
                return 'HEAD~1'
        except (subprocess.SubprocessError, OSError):
            pass
        return None

    def _get_git_diff_files(self, project_path: Path) -> List[Path]:
        """Git差分のファイルを取得"""
        files = []
        base = self._resolve_diff_base(project_path)
        # base が解決できた場合は base...HEAD、できなければ最後の砦として
        # 作業ツリー差分 (HEAD) を見る。0 ファイルで黙って成功しないよう、
        # base 解決失敗は警告に出す。
        diff_args = ['git', 'diff', '--name-only',
                     f'{base}...HEAD' if base else 'HEAD']
        if base is None:
            logger.warning(
                "Git差分ベースを解決できず HEAD 比較にフォールバック "
                "(CI では 0 ファイルになり得る — fetch-depth: 0 を確認)"
            )

        project_root = project_path.resolve()
        try:
            result = subprocess.run(
                diff_args,
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=30,  # DOS-001: subprocess に timeout を必須化
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if not line:
                        continue
                    # PATH-TRAV-001: 正規化しプロジェクト配下のみ許可。
                    # 悪意あるコミットの ../../etc/passwd 等を排除する。
                    candidate = (project_path / line).resolve()
                    if candidate == project_root or project_root in candidate.parents:
                        if candidate.exists():
                            files.append(candidate)
                    else:
                        logger.warning(
                            f"プロジェクト外パスをスキップ: {str(line)[:120]!r}"
                        )
        except subprocess.TimeoutExpired:
            logger.warning("Git差分の取得がタイムアウトしました (30s)")
        except Exception as e:
            logger.warning(f"Git差分の取得エラー: {e}")

        return files
    
    def _calculate_summary(self, issues: List[Issue]) -> Dict[str, int]:
        """問題の集計"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        
        for issue in issues:
            severity_key = issue.severity.value
            if severity_key in summary:
                summary[severity_key] += 1
        
        return summary


def generate_html_report(result: ValidationResult, output_path: Path):
    """HTMLレポートを生成"""
    html_template = """
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>コード検証レポート</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .summary-card {{ flex: 1; padding: 15px; border-radius: 4px; }}
        .critical {{ background: #fee; border-left: 4px solid #c00; }}
        .high {{ background: #ffe; border-left: 4px solid #f90; }}
        .medium {{ background: #ffd; border-left: 4px solid #fc0; }}
        .low {{ background: #efe; border-left: 4px solid #0c0; }}
        .info {{ background: #eef; border-left: 4px solid #09f; }}
        .issue {{ margin: 10px 0; padding: 10px; border-left: 3px solid #ccc; background: #fafafa; }}
        .issue.critical {{ border-left-color: #c00; }}
        .issue.high {{ border-left-color: #f90; }}
        .issue.medium {{ border-left-color: #fc0; }}
        .issue.low {{ border-left-color: #0c0; }}
        .issue.info {{ border-left-color: #09f; }}
        .file-path {{ font-weight: bold; color: #0066cc; }}
        .suggestion {{ margin-top: 5px; padding: 5px; background: #e8f4f8; border-radius: 3px; }}
        code {{ background: #f0f0f0; padding: 2px 4px; border-radius: 2px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 コード検証レポート</h1>
        <p><strong>プロジェクト:</strong> {project_path}</p>
        <p><strong>検証日時:</strong> {timestamp}</p>
        <p><strong>検証ファイル数:</strong> {total_files}</p>
        <p><strong>実行時間:</strong> {execution_time:.2f}秒</p>
        
        <div class="summary">
            <div class="summary-card critical">
                <h3>🔴 Critical</h3>
                <p style="font-size: 24px; margin: 0;">{critical}</p>
            </div>
            <div class="summary-card high">
                <h3>🟠 High</h3>
                <p style="font-size: 24px; margin: 0;">{high}</p>
            </div>
            <div class="summary-card medium">
                <h3>🟡 Medium</h3>
                <p style="font-size: 24px; margin: 0;">{medium}</p>
            </div>
            <div class="summary-card low">
                <h3>🟢 Low</h3>
                <p style="font-size: 24px; margin: 0;">{low}</p>
            </div>
            <div class="summary-card info">
                <h3>ℹ️ Info</h3>
                <p style="font-size: 24px; margin: 0;">{info}</p>
            </div>
        </div>
        
        <h2>検出された問題</h2>
        {issues_html}
    </div>
</body>
</html>
    """
    
    # 問題を重大度でソート
    sorted_issues = sorted(result.issues, key=lambda x: {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }[x.severity])
    
    issues_html = ""
    for issue in sorted_issues:
        severity_class = html.escape(issue.severity.value)
        line_info = f" (行 {issue.line_number})" if issue.line_number else ""
        code_snippet = f"<pre><code>{html.escape(issue.code_snippet)}</code></pre>" if issue.code_snippet else ""
        suggestion = f'<div class="suggestion">💡 推奨: {html.escape(issue.suggestion)}</div>' if issue.suggestion else ""

        issues_html += f"""
        <div class="issue {severity_class}">
            <div class="file-path">{html.escape(issue.file_path)}{line_info}</div>
            <div><strong>[{html.escape(issue.rule_id)}]</strong> {html.escape(issue.message)}</div>
            {code_snippet}
            {suggestion}
        </div>
        """
    
    html_content = html_template.format(
        project_path=html.escape(str(result.project_path)),
        timestamp=html.escape(str(result.timestamp)),
        total_files=result.total_files,
        execution_time=result.execution_time,
        critical=result.summary['critical'],
        high=result.summary['high'],
        medium=result.summary['medium'],
        low=result.summary['low'],
        info=result.summary['info'],
        issues_html=issues_html
    )
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info(f"HTMLレポートを生成しました: {output_path}")


def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description='ClaudeCode自動検証システム')
    parser.add_argument('--path', type=str, default='.', help='検証するプロジェクトのパス')
    parser.add_argument('--git-diff', action='store_true', help='Git差分のみを検証')
    parser.add_argument('--output', type=str, help='レポートの出力パス')
    parser.add_argument('--format', choices=['html', 'json', 'markdown'], default='html', help='レポート形式')
    parser.add_argument('--config', type=str, help='設定ファイルのパス')
    
    args = parser.parse_args()
    
    project_path = Path(args.path).resolve()
    if not project_path.exists():
        logger.error(f"パスが存在しません: {project_path}")
        sys.exit(1)
    
    # 検証の実行
    validator = CodeValidator(config_path=Path(args.config) if args.config else None)
    result = validator.validate(project_path, git_diff=args.git_diff)
    
    # レポートの生成
    if args.output:
        output_path = Path(args.output)
        if args.format == 'html':
            generate_html_report(result, output_path)
        elif args.format == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                # Severity Enumを文字列に変換
                issues_dict = []
                for issue in result.issues:
                    issue_dict = asdict(issue)
                    issue_dict['severity'] = issue.severity.value
                    issues_dict.append(issue_dict)
                
                json.dump({
                    'timestamp': result.timestamp,
                    'project_path': result.project_path,
                    'total_files': result.total_files,
                    'summary': result.summary,
                    'execution_time': result.execution_time,
                    'issues': issues_dict,
                }, f, indent=2, ensure_ascii=False)
            logger.info(f"JSONレポートを生成しました: {output_path}")
    
    # 結果の表示
    print("\n" + "="*60)
    print("検証結果サマリー")
    print("="*60)
    print(f"プロジェクト: {result.project_path}")
    print(f"検証ファイル数: {result.total_files}")
    print(f"実行時間: {result.execution_time:.2f}秒")
    print("\n問題の内訳:")
    print(f"  🔴 Critical: {result.summary['critical']}")
    print(f"  🟠 High: {result.summary['high']}")
    print(f"  🟡 Medium: {result.summary['medium']}")
    print(f"  🟢 Low: {result.summary['low']}")
    print(f"  ℹ️  Info: {result.summary['info']}")
    print("="*60)
    
    # 重大な問題がある場合は終了コード1を返す
    if result.summary['critical'] > 0 or result.summary['high'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()

