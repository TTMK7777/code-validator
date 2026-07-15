# code-validator ドキュメント (Documentation Index)

AI 生成コード向けの静的セキュリティスキャナー **code-validator** のドキュメント一覧です。
読者のロール別に入口を用意しています。各ドキュメントは [Diátaxis](https://diataxis.fr/) の
4 分類（Tutorial / How-to / Reference / Explanation）を下表の「種別」列で示す簡易版で運用しており、
`tutorials/` `how-to/` 等の物理ディレクトリは設けず、既存ファイル構成のまま表でマッピングしています。

> このページは `docs/` 配下に置かれています。リンクはこのファイルからの相対パスです。

---

## ロール別エントリーポイント (Entry Points)

### 利用者 (Users) — まず動かしたい
1. [クイックスタートガイド](../QUICKSTART.md) — インストールから初回スキャンまで
2. [README](../README.md) の「Usage」「Configuration」 — CLI オプションと設定

### 運用 (Operators) — CI に組み込みたい
1. [README](../README.md) の「CI/CD Integration」 — GitHub Actions / GitLab CI の組み込み例
2. [config/validator_config.json](../config/validator_config.json) — 除外パターン・対象拡張子・ルール有効化
3. [SECURITY.md](../SECURITY.md) — 脆弱性報告ポリシー

### 開発者 (Developers) — 中身を理解・拡張したい
1. [アーキテクチャ](dev/architecture.md) — モジュール構成とデータフロー
2. [CLAUDE.md](../CLAUDE.md) — 仕様駆動ワークフローとコード規約
3. [spec.md](../spec.md) / [plan.md](../plan.md) — 仕様概要とロードマップ
4. [CONTRIBUTING.md](../CONTRIBUTING.md) — コントリビュート手順

---

## ドキュメント一覧 (All Documents)

| ドキュメント | 種別 (Diátaxis) | 対象読者 | 概要 |
|---|---|---|---|
| [README](../README.md) | Reference / Explanation | 全員 | プロジェクト概要・機能・CLI・検出ルール一覧・FAQ |
| [QUICKSTART.md](../QUICKSTART.md) | Tutorial | 利用者 | インストールと基本的な使用例、トラブルシューティング |
| [アーキテクチャ](dev/architecture.md) | Explanation | 開発者 | コンポーネント構成・データフロー・技術選定理由 |
| [spec.md](../spec.md) | Reference | 開発者 | 機能一覧・非機能要件・用語定義 |
| [plan.md](../plan.md) | Explanation | 開発者 | フェーズ管理・決定事項ログ |
| [CHANGELOG.md](../CHANGELOG.md) | Reference | 全員 | バージョンごとの変更履歴（Keep a Changelog 準拠） |
| [config/validator_config.json](../config/validator_config.json) | Reference | 運用 | 検出ルール・除外パターンの設定ファイル |
| [SECURITY.md](../SECURITY.md) | How-to | 全員 | 脆弱性の報告手順 |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How-to | 開発者 | 開発参加・PR の流れ |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Reference | 全員 | 行動規範 |
| [CLAUDE.md](../CLAUDE.md) | Reference | 開発者 | 仕様駆動ワークフローとコード規約 |
| [specs/README.md](../specs/README.md) | Reference | 開発者 | 個別仕様書の命名規則・テンプレート |
| [llms.txt](llms.txt) | Reference | AI / ツール | AI 検索エンジン向けプロジェクト要約 |

---

## ランディングページ (Landing Page)

[docs/index.html](index.html) は GitHub Pages 用のランディングページです
（Schema.org / FAQPage 構造化データ込み）。ブラウザで開いて閲覧してください。

---

## お問い合わせ (Contact)

質問・バグ報告・機能要望は [GitHub Issues](https://github.com/TTMK7777/code-validator/issues) へお願いします。
セキュリティに関する報告は [SECURITY.md](../SECURITY.md) の手順に従ってください。
