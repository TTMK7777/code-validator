# ClaudeCode自動検証システム
**Code Validator for ClaudeCode Output**

ClaudeCodeが生成したコードを自動的に検証し、セキュリティ問題やコード品質の問題を検出するシステムです。

## 機能

- ✅ **セキュリティスキャン**: 認証情報の漏洩、CORS設定、脆弱性の検出
- ✅ **コード品質チェック**: リンター、フォーマッター、ベストプラクティスの検証
- ✅ **依存関係の脆弱性チェック**: pip-audit、npm auditの自動実行
- ✅ **変更検出**: Git差分から変更されたファイルを自動検出
- ✅ **レポート生成**: HTML/JSON形式の詳細レポート
- ✅ **CI/CD統合**: GitHub Actions、GitLab CI対応

## クイックスタート

```bash
# インストール
cd 01_AI-Agents/code-validator
pip install -r requirements.txt

# 基本的な使用（現在のディレクトリを検証）
python validator.py --path .

# 特定のプロジェクトを検証
python validator.py --path ../my-project

# Git差分を検証（最新のコミット）
python validator.py --git-diff

# 詳細レポート生成
python validator.py --path . --output report.html --format html
```

## 使用方法

### 1. 基本的な検証

```bash
python validator.py --path /path/to/project
```

### 2. Git差分の検証

```bash
# 最新のコミットと比較
python validator.py --git-diff

# 特定のコミット範囲
python validator.py --git-diff --from HEAD~1 --to HEAD
```

### 3. カスタムルールの適用

```bash
# カスタム設定ファイルを使用
python validator.py --path . --config custom_rules.json
```

### 4. CI/CD統合

```yaml
# .github/workflows/code-validation.yml
name: Code Validation
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Code Validator
        run: |
          cd 01_AI-Agents/code-validator
          pip install -r requirements.txt
          python validator.py --git-diff --output validation-report.json
```

## 検証項目

### セキュリティチェック
- [ ] 認証情報のハードコード（APIキー、パスワード、トークン）
- [ ] CORS設定の不備
- [ ] SQLインジェクションの可能性
- [ ] XSS脆弱性
- [ ] セキュリティヘッダーの不足
- [ ] ファイルアップロードの検証不足

### コード品質
- [ ] リンターエラー
- [ ] コードフォーマット
- [ ] 未使用のインポート
- [ ] 複雑度の高い関数
- [ ] ドキュメント不足

### 依存関係
- [ ] 既知の脆弱性
- [ ] 古いパッケージ
- [ ] ライセンス問題

## 設定ファイル

`config/validator_config.json`で検証ルールをカスタマイズできます。

## レポート形式

- **HTML**: ブラウザで閲覧可能な詳細レポート
- **JSON**: CI/CDツールとの統合用
- **Markdown**: ドキュメント形式

## ライセンス

MIT License

