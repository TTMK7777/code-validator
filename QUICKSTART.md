# クイックスタートガイド

## インストール

```bash
cd 01_AI-Agents/code-validator
pip install -r requirements.txt
```

## 基本的な使用

### 1. 現在のプロジェクトを検証

```bash
python validator.py --path .
```

### 2. 特定のプロジェクトを検証

```bash
python validator.py --path ../my-project
```

### 3. Git差分のみを検証（推奨）

```bash
python validator.py --git-diff
```

### 4. HTMLレポートを生成

```bash
python validator.py --path . --output report.html --format html
```

## 使用例

### 例1: セキュリティチェックのみ

```bash
# 現在のディレクトリを検証してHTMLレポートを生成
python validator.py --path . --output security-report.html
```

### 例2: CI/CDでの使用

```bash
# JSON形式でレポートを生成（CI/CDツールとの統合用）
python validator.py --git-diff --output validation-report.json --format json
```

### 例3: カスタム設定を使用

```bash
python validator.py --path . --config config/custom_rules.json
```

## 検出される問題の例

### セキュリティ問題
- APIキーのハードコード
- パスワードのハードコード
- CORS設定の不備
- SQLインジェクションの可能性
- セキュリティヘッダーの不足

### コード品質問題
- 長すぎる行
- 未使用のインポート
- 複雑な関数

### 依存関係の問題
- 既知の脆弱性
- 古いパッケージ

## トラブルシューティング

### pip-auditが見つからない

```bash
pip install pip-audit
```

### npmが見つからない

Node.jsをインストールしてください。

### 権限エラー

```bash
# Windows
python validator.py --path .

# Linux/Mac
python3 validator.py --path .
```

## 次のステップ

- [README.md](README.md) で詳細な機能を確認
- [config/validator_config.json](config/validator_config.json) で設定をカスタマイズ
- GitHub Actionsのワークフローを設定して自動検証を有効化

