# code-validator -- 知見・技術判断

## 技術判断
- pydantic >= 2.0.0 のみを必須依存とし、軽量性を維持
- 外部API呼び出しなし（完全オフライン動作）で安全性を確保
- pip-audit / npm audit はオプション依存として委譲
- 終了コード 0/1 でCI/CDパイプラインとの統合を容易に

## 知見
- --git-diff モードで変更ファイルのみスキャンすると CI が高速化
- fetch-depth: 2 が GitHub Actions での --git-diff に必要
- ハードコードされたクレデンシャルの検出は正規表現ベース
- 未使用importの検出はヒューリスティック（完全な解析は flake8 に委譲）

## 外部リソース
- [pip-audit](https://pypi.org/project/pip-audit/) - Python依存関係監査
- [pydantic](https://docs.pydantic.dev/) - データバリデーション

## FAQ
- Q: 誤検知を減らすには？ A: config/validator_config.json の exclude_patterns で除外パターンを追加
- Q: カスタムルールの追加方法は？ A: validator.py のルール関数を拡張
