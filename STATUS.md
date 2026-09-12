# code-validator — STATUS

> このリポジトリの「現在地」の正本。`todo.md` は `.gitignore` 対象（ローカル限定）のため、共有される現在地はこちらに置く。

## 現在地（2026-09-12 棚卸し）
- 状態: 継続（公開済み・ルール精度の改善が続いている）
- 現在地: security / quality / dependency の 3 層 20 ルール（SEC001–SEC013 のうち SEC007 を除く、QUAL001–QUAL002、DEP001–DEP006）で稼働中。直近のコミットは dependabot / CI 関連が中心で、ルール自体の追加は止まっている。
- 最終作業: 2026-09-02 ci: codeql-action の init と analyze のバージョン不一致を解消 (#71)
- 次の一手: Markdown レポート形式の実装、サイクロマティック複雑度の完全実装、追加セキュリティルールの検討。
- 判断待ち: (1) `src/` ディレクトリへのリファクタリング着手可否 (2) ローカル `todo.md` の「未着手: テストスイートの作成（pytest）」の削除可否（下記のとおり実態と食い違う。`todo.md` は未追跡のため本変更では触っていない）

## テストスイートの実態（2026-09-12 実測）
ローカル `todo.md` の「未着手」欄に「テストスイートの作成（pytest）」が残っているが、**実態と食い違う**。`python -m pytest -q` の実行結果は以下。

```
153 passed in 0.92s
```

内訳（`tests/` 配下・合計 1,040 行）:

| ファイル | 行数 |
|---|---|
| `conftest.py` | 59 |
| `test_config.py` | 103 |
| `test_cors_patterns.py` | 130 |
| `test_credentials.py` | 181 |
| `test_dependency_failures.py` | 164 |
| `test_injection.py` | 192 |
| `test_quality.py` | 120 |
| `test_suppressions.py` | 91 |

つまりテストスイートは **未着手ではなく既に存在し全 153 件が緑**。残っているのは「作成」ではなく「カバレッジの拡充」であり、次の一手を考える際はこちらの記述を正とすること。

## open な Issue / PR
- Issues 0 件 / PR 0 件（2026-09-12 時点）
