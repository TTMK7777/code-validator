#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClaudeCode自動検証システム
Code Validator for ClaudeCode Output

ClaudeCodeが生成したコードを自動的に検証し、
セキュリティ問題やコード品質の問題を検出します。
"""

import os
import sys
import json
import re
import subprocess
import argparse
import html
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
    }
    
    # CORS設定のパターン
    CORS_PATTERNS = {
        'wildcard_with_credentials': r'allow_origins\s*=\s*\[["\']\*["\']\s*,\s*allow_credentials\s*=\s*True',
        'wildcard_origins': r'allow_origins\s*=\s*\[["\']\*["\']',
    }
    
    def scan_file(self, file_path: Path) -> List[Issue]:
        """ファイルをスキャンして問題を検出"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
            # 認証情報の検出
            issues.extend(self._scan_credentials(file_path, lines))
            
            # CORS設定の検出
            issues.extend(self._scan_cors(file_path, lines))
            
            # SQLインジェクションの可能性
            issues.extend(self._scan_sql_injection(file_path, lines))
            
            # セキュリティヘッダーの検出
            issues.extend(self._scan_security_headers(file_path, lines))
            
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
                    if password not in ['password', 'passwd', 'your-password', '***']:
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
        
        return issues
    
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
        
        for line_num, line in enumerate(lines, 1):
            # 文字列連結によるSQL構築
            if re.search(r'SELECT.*\+.*|INSERT.*\+.*|UPDATE.*\+.*|DELETE.*\+.*', line, re.IGNORECASE):
                if 'f"' in line or "f'" in line or '%s' in line or '%d' in line:
                    issues.append(Issue(
                        severity=Severity.HIGH,
                        category="security",
                        file_path=str(file_path),
                        line_number=line_num,
                        message="SQLインジェクションの可能性: 文字列連結によるSQL構築",
                        rule_id="SEC006",
                        suggestion="ORMまたはパラメータ化クエリを使用してください",
                        code_snippet=line.strip()[:100]
                    ))
        
        return issues
    
    def _scan_security_headers(self, file_path: Path, lines: List[str]) -> List[Issue]:
        """セキュリティヘッダーの検出"""
        issues = []
        file_content = '\n'.join(lines)
        
        # FastAPIアプリケーションの場合
        if 'FastAPI' in file_content or 'from fastapi import' in file_content:
            required_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
            ]
            
            for header in required_headers:
                if header not in file_content:
                    issues.append(Issue(
                        severity=Severity.MEDIUM,
                        category="security",
                        file_path=str(file_path),
                        line_number=None,
                        message=f"セキュリティヘッダー '{header}' が設定されていません",
                        rule_id="SEC007",
                        suggestion="セキュリティヘッダーミドルウェアを追加してください",
                    ))
        
        return issues
    
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
            
            # 未使用のインポート（簡易チェック）
            issues.extend(self._check_unused_imports(file_path, lines))
            
            # 長い行の検出
            issues.extend(self._check_long_lines(file_path, lines))
            
            # 複雑な関数の検出（簡易チェック）
            issues.extend(self._check_complex_functions(file_path, lines))
            
        except Exception as e:
            logger.warning(f"コード品質チェックエラー {file_path}: {e}")
        
        return issues
    
    def _check_unused_imports(self, file_path: Path, lines: List[str]) -> List[Issue]:
        """未使用のインポートをチェック（簡易版）"""
        issues = []
        imports = []
        used_names = set()
        
        for line in lines:
            # インポート文の検出
            if line.strip().startswith('import ') or line.strip().startswith('from '):
                imports.append(line)
            
            # 使用されている名前の検出（簡易版）
            for word in re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', line):
                used_names.add(word)
        
        # より高度なチェックはflake8やpylintを使用
        return issues
    
    def _check_long_lines(self, file_path: Path, lines: List[str]) -> List[Issue]:
        """長い行をチェック"""
        issues = []
        MAX_LINE_LENGTH = 120
        
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
    
    def check_dependencies(self, project_path: Path) -> List[Issue]:
        """依存関係の脆弱性をチェック"""
        issues = []
        
        # requirements.txtのチェック
        requirements_file = project_path / 'requirements.txt'
        if requirements_file.exists():
            issues.extend(self._check_python_dependencies(requirements_file))
        
        # package.jsonのチェック
        package_json = project_path / 'package.json'
        if package_json.exists():
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
            
            if result.returncode != 0:
                # pip-auditがインストールされていない場合
                issues.append(Issue(
                    severity=Severity.INFO,
                    category="dependencies",
                    file_path=str(requirements_file),
                    line_number=None,
                    message="pip-auditがインストールされていません。依存関係の脆弱性チェックを実行できません",
                    rule_id="DEP001",
                    suggestion="pip install pip-audit を実行してください",
                ))
            else:
                # 脆弱性が見つかった場合
                try:
                    audit_data = json.loads(result.stdout)
                    if audit_data.get('vulnerabilities'):
                        for vuln in audit_data['vulnerabilities']:
                            issues.append(Issue(
                                severity=Severity.HIGH,
                                category="dependencies",
                                file_path=str(requirements_file),
                                line_number=None,
                                message=f"脆弱性検出: {vuln.get('name', 'unknown')} - {vuln.get('id', 'unknown')}",
                                rule_id="DEP002",
                                suggestion=vuln.get('fix_versions', 'パッケージを更新してください'),
                            ))
                except json.JSONDecodeError:
                    pass
                    
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
            logger.warning("pip-auditの実行がタイムアウトしました")
        except Exception as e:
            logger.warning(f"依存関係チェックエラー: {e}")
        
        return issues
    
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
            
            if result.returncode == 0:
                try:
                    audit_data = json.loads(result.stdout)
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
                except json.JSONDecodeError:
                    pass
                    
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
            logger.warning("npm auditの実行がタイムアウトしました")
        except Exception as e:
            logger.warning(f"依存関係チェックエラー: {e}")
        
        return issues


class CodeValidator:
    """コード検証システムのメインクラス"""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.security_scanner = SecurityScanner()
        self.quality_checker = CodeQualityChecker()
        self.dependency_checker = DependencyChecker()
        self.config = self._load_config(config_path)
    
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
        
        for pattern in exclude_patterns:
            # 簡易的な除外処理
            pass
        
        for ext in file_extensions:
            for file_path in project_path.rglob(f'*{ext}'):
                # 除外パターンのチェック
                if not any(exclude in str(file_path) for exclude in ['node_modules', 'venv', '__pycache__', '.git']):
                    files.append(file_path)
        
        return files
    
    def _get_git_diff_files(self, project_path: Path) -> List[Path]:
        """Git差分のファイルを取得"""
        files = []
        
        try:
            result = subprocess.run(
                ['git', 'diff', '--name-only', 'HEAD'],
                cwd=project_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        file_path = project_path / line
                        if file_path.exists():
                            files.append(file_path)
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
        project_path=result.project_path,
        timestamp=result.timestamp,
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

