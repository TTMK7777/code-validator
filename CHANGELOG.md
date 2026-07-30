# Changelog

このプロジェクトの注目すべき変更点はすべてこのファイルに記録します。

フォーマットは [Keep a Changelog 1.1.0](https://keepachangelog.com/ja/1.1.0/) に準拠し、
バージョニングは [セマンティック バージョニング (SemVer)](https://semver.org/lang/ja/) に従います。

## [Unreleased]

網羅性の検証で見つかった「README に書いてあるのに実装が無い」「0 件と見ていないが
区別できない」欠陥をまとめて是正した。検出ルールは 11 → 21 に増加。

### Added
- **SEC008**: ハードコードされた `SECRET_KEY` の検出（Django / Flask のセッション署名鍵）。
- **SEC009**: AWS アクセスキー ID (`AKIA` / `ASIA`) とシークレットアクセスキーの検出。
- **SEC010**: ソースに埋め込まれた PEM 秘密鍵ブロックの検出。コメント内でも漏洩なので検出する。
- **SEC011**: シェル実行によるコマンドインジェクションの検出
  （`os.system` / `os.popen` / `subprocess(..., shell=True)`）。
- **SEC012**: 危険な逆シリアライズの検出（`pickle` / `marshal` / `shelve` /
  安全な Loader を指定しない `yaml.load`）。
- **SEC013**: 動的コード実行の検出（`eval` / `exec`。`ast.literal_eval` は除外）。
- **QUAL002**: 未使用 import の検出。`ast` による束縛解析とテキスト出現チェックの 2 段構成。
- **DEP005 / DEP006**: 依存関係監査が**実行できなかった**ことの報告（HIGH）。
- **抑制コメント**: `# code-validator: ignore` / `ignore[SEC001]` /
  `ignore-file` / `ignore-file[SEC004,SEC005]`。意図的に脆弱なコード
  （スキャナ自身のテストフィクスチャなど）を CI で通すために必要。
- **テストスイート**: 各ルールについて「発火する例」と「発火しない例」の両方を追加。
  13 → 136 テスト。ミューテーションテストで、実装を壊すとテストが落ちることを確認済み。

### Fixed
- **`secret_key` パターンが未参照だった**（dead pattern）。定義だけ存在し
  `_scan_credentials` から呼ばれていなかったため、`SECRET_KEY` の直書きを常に見逃していた。
  README には検出対象として記載されていた。
- **`_check_unused_imports` が空実装だった**。名前を収集した後に空リストを返しており、
  常に 0 件。README には機能として記載されていた。
- **`pip-audit` の実行失敗を「未インストール」と誤診していた**。実際には
  インストール済みで依存解決に失敗したケースでも DEP001 (INFO) を返すため、
  CI が緑のまま通っていた。失敗理由を要約して DEP005 (HIGH) で報告するようにした。
- **`npm audit` の異常終了が完全に無言だった**（`logger.warning` のみで Issue なし）。
  DEP006 (HIGH) で報告するようにした。
- **`exclude_patterns` が機能していなかった**。`for pattern in exclude_patterns: pass`
  の空ループで、実際には `node_modules` / `venv` / `__pycache__` / `.git` の
  ハードコード 4 種のみ除外していた。`fnmatch` による実判定に置き換えた。
- **`quality_rules.max_line_length` が反映されなかった**。メソッド内の定数で固定されていた。
- **`security_rules.*` / `dependency_rules.*` が参照されていなかった**。設定で
  ルールの有効・無効を切り替えられるようにした。
- **SEC006 が `.format()` と `%` 演算子を取りこぼしていた**。f文字列と `+` 連結のみ対応していた。
- **SEC006 がコメントアウトされた SQL に誤検知していた**。行頭コメントを除外するようにした
  （三重引用符を含む行を取りこぼさないよう、専用の判定を用いる）。
- `tests/test_cors_patterns.py` が意図的な脆弱コードを含むため、`--git-diff` で
  差分に入ると CI を落とす状態だった。抑制コメントを付与して解消。

### Changed
- README / spec.md / docs/dev/architecture.md / llms.txt のルール一覧と機能記述を実装に一致させた。
  関数複雑度チェックは「スタブであり何も検出しない」ことを明記した。
- データフロー解析（テイント追跡）を行わない旨を README に明記した。

### Planned
- Markdown レポート形式の実装（`--format markdown` は CLI で受理されるが現状は HTML / JSON のみ出力）
- サイクロマティック複雑度の実装（現状は `_check_complex_functions` のスタブ）
- パッケージ化（`pyproject.toml`）と `pipx install` 対応

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
