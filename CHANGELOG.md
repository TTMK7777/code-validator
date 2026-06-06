# Changelog

このプロジェクトの注目すべき変更点はすべてこのファイルに記録します。

フォーマットは [Keep a Changelog 1.1.0](https://keepachangelog.com/ja/1.1.0/) に準拠し、
バージョニングは [セマンティック バージョニング (SemVer)](https://semver.org/lang/ja/) に従います。

## [Unreleased]

### Planned
- Markdown レポート形式の実装（`--format markdown` は CLI で受理されるが現状は HTML / JSON のみ出力）
- サイクロマティック複雑度の完全実装（現状は `_check_complex_functions` のスタブ）
- セキュリティ検出ルールの追加
- テストスイートの拡充（現状は `tests/test_cors_patterns.py` のみ）

## [0.1.0] - 2026-06-06

AI 生成コード向け静的セキュリティスキャナーの初期公開バージョン。完全オフライン動作、
依存は `pydantic` のみ。CI/CD パイプラインの品質ゲートとして利用可能。

### Added
- メインスクリプト `validator.py`（モノリシック CLI、`python validator.py` で実行）。
- セキュリティスキャン `SecurityScanner`:
  - SEC001–SEC003: ハードコードされた認証情報の検出（OpenAI / Anthropic / Google / GitHub トークン、パスワード、DB URL）。
  - SEC004 / SEC005: CORS 設定不備の検出（ワイルドカードオリジン + `allow_credentials=True`、本番リスクのワイルドカード）。
  - SEC006: 文字列連結による SQL インジェクションパターンの検出。
  - SEC007: FastAPI アプリでのセキュリティヘッダー不足の検出。
- コード品質チェック `CodeQualityChecker`:
  - QUAL001: 最大行長（既定 120 文字）超過の検出。
  - 未使用 import のヒューリスティック検出、関数複雑度のスタブ。
- 依存関係監査 `DependencyChecker`:
  - DEP001–DEP003: `pip-audit`（Python）/ `npm audit`（Node.js）への委譲による既知 CVE 検出。
- レポート生成: HTML（`generate_html_report`）、JSON、Console サマリー。
- Git 統合: `--git-diff` モードで変更ファイルのみをスキャン（`--from` / `--to` で範囲指定可）。
- カスタム設定 `config/validator_config.json`（除外パターン、対象拡張子、ルール有効/無効、行長閾値）。
- 終了コード: Critical / High 検出時に `1`、それ以外は `0`（CI ブロック判定用）。
- GitHub Actions / GitLab CI のワークフロー例（README 参照）。

### Changed
- 依存を厳密バージョンに固定（`pydantic==2.13.4`）。

### Fixed
- `wildcard_with_credentials` 向け `CORS_PATTERNS` 正規表現の修正（CORS-REGEX-001）。
- `npm audit` の returncode 取り扱い修正と GitHub Actions の SHA ピン留め対応。

### Security
- CodeQL 解析ワークフローの追加と脆弱性報告ポリシー（`SECURITY.md`）の整備。
- 認証情報を含むファイル（`secrets.json` / `credentials.json` など）の `.gitignore` 追加。

---

なお、本 changelog 以前にも開発履歴があります。詳細は `git log` を参照してください。

[Unreleased]: https://github.com/TTMK7777/code-validator/compare/main...HEAD
[0.1.0]: https://github.com/TTMK7777/code-validator/releases/tag/v0.1.0
