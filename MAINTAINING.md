# 保守ガイド

このリポジトリ（code-validator）を、AI を使わずに保守するための案内です。
code-validator は、ソースコードを読んで「危険な書き方」（直書きのパスワード、CORS の全許可など）を探す Python 製の検査ツールです。本体は `validator.py` の 1 ファイルです。

## ファイルの種類

このリポジトリには「普通のコード」「AI への指示書」「設定」「人間向け文書」があります。どれもテキストエディタで直せます。

| 種類 | 例 | 何か | 直すときの注意 |
|---|---|---|---|
| 普通のコード | `validator.py`、`tests/test_quality.py` | 人が書いた Python。AI なしで動く | 直したら下の「直したあとの確認」を回す |
| AI への指示書 | `CLAUDE.md`、`AGENTS.md` | AI のコーディング支援ツールが作業前に読む日本語の手順書。`validator.py` は読まない | 人間の保守には不要。読めば検出ルール追加時の手順（実コードでの誤検知率の測定など）が分かる |
| 設定 | `config/validator_config.json`、`.github/workflows/ci.yml` | 検査の動き方、CI（GitHub 上で自動実行されるテスト）の定義 | 下の逆引き表を参照 |
| 人間向け文書 | `README.md`、`docs/README.md`、`spec.md` | 使い方・仕様・設計 | 下の「文書の正本」を参照 |

## 地図

| 場所 | 中身 | 種類 |
|---|---|---|
| `validator.py` | 実装本体（検出ルール、設定読込、レポート生成、CLI がすべて入っている） | コード |
| `tests/` | テスト（pytest）。発火する例と発火しない例の両方が揃っていないルールもある（例: SEC005 に専用テストは無く、DEP004 は発火側のみ） | コード |
| `src/` | `__init__.py` だけの空き地。実装は入っていない | コード（空） |
| `config/` | `--config` で渡す設定の見本 | 設定 |
| `.github/workflows/` | CI の定義（テスト・自己検査・CodeQL・pip-audit・依存更新の自動マージ） | 設定 |
| `docs/` | 文書一覧、設計メモ、GitHub Pages 用の公開ページ | 文書 |
| `specs/` | 個別仕様書の置き場（現在は命名規則の説明だけ） | 文書 |
| `CLAUDE.md`、`AGENTS.md` | AI 向けの作業指示 | AI への指示書 |

## 文書の正本

- 現在地・次の一手・判断待ち: [STATUS.md](STATUS.md)
- 機能一覧・非機能要件・用語: [spec.md](spec.md)
- 計画・決定事項ログ: [plan.md](plan.md)
- 設計（部品とデータの流れ）: [docs/dev/architecture.md](docs/dev/architecture.md)
- 変更履歴: [CHANGELOG.md](CHANGELOG.md)
- 検出ルール追加時の必須手順: [CLAUDE.md](CLAUDE.md)（「検出ルールを追加・変更するときの必須手順」節）
- 使い方・設定の説明: [README.md](README.md)、[QUICKSTART.md](QUICKSTART.md)

文書同士で食い違っている所（現行はこちらと判断した理由つき）:

| 食い違い | 現行 |
|---|---|
| pydantic の版: CLAUDE.md・README.md・spec.md などは 2.13.4、`requirements.txt` は 2.14.1 | `requirements.txt` が現行（実際に入る版。更新は Dependabot が出す） |
| 計画 [plan.md](plan.md) の Phase 2 に「テストスイート整備」が未着手と書いてある | テストは既にある。[STATUS.md](STATUS.md) が現行 |
| [docs/dev/architecture.md](docs/dev/architecture.md) の「約 946 行」 | 古い数字。`validator.py` はもっと長い |
| README は pydantic を唯一の必須依存と説明するが、`validator.py` は pydantic を読み込んでいない（`git grep -n pydantic validator.py` が 0 件） | 動作に pydantic は使われていない。依存の整理は判断が必要なので、このガイドでは触らない |
| README.md・spec.md は「完全オフライン／外部通信なし」と説明するが、`requirements.txt` か `package.json` がある場所を `--path` で検査すると、`pip-audit` / `npm audit` が入っていれば外部の脆弱性データベースへ問い合わせる（`validator.py` の `DependencyChecker.check_dependencies`。`--git-diff` の有無に関係なく動く） | 通信するのは依存検査だけ。ソースコードは送られない。通信を避けるなら、両ファイルの無いフォルダを指す |
| CLAUDE.md が仕組みとして挙げる todo.md・knowledge.md・memory.md はリポジトリに無い（.gitignore 対象のローカル限定ファイル。STATUS.md にも todo.md はローカル限定とある） | 共有される現在地は [STATUS.md](STATUS.md)。無いファイルを探さなくてよい |

## よくある作業（逆引き）

表中の `git grep ... ':!validator.py'` は bash・PowerShell で打てる書き方です（cmd.exe ではシングルクォートが効かないので、cmd では `":!validator.py"` にします）。触る場所のほかに、**同じ値を手で写している場所**があります。下の `git grep` の出力に出た文書も合わせてください（テストが見ているのは特定の値だけで、文書との一致は見ていません）。

| やりたいこと | 触るファイル | 手で合わせる所・確かめ方 |
|---|---|---|
| 行の長さの上限（既定 120 文字）を変えたい | `validator.py` の `DEFAULT_MAX_LINE_LENGTH`（設定ファイルで渡す場合は `quality_rules.max_line_length`） | `git grep -n "max_line_length" -- README.md config tests` と `git grep -n "120" -- README.md CHANGELOG.md` に出る文書・設定の数字を手で合わせる。`tests/test_quality.py` の `test_qual001_respects_config_max_line_length` が 66 文字の行を使っているので、既定を 65 以下にするとそのテストが落ちる（実測: 50 で落ちた）。逆に上げた場合（150 で実測）は全テストが通るので、上げる変更はテストでは検出されない。最後に全テストを回す |
| 除外するフォルダ・対象にする拡張子を変えたい | 設定ファイルを渡す場合は `config/validator_config.json` の `exclude_patterns` / `file_extensions`。渡さない場合の既定は `validator.py` の `_load_config` の中 | 設定ファイルの `exclude_patterns` は既定の一覧に**足されず置き換わる**（`--config` を渡したとき）。`git grep -n "exclude_patterns" -- README.md config` の所を手で合わせる。`tests/test_config.py` は一時フォルダの設定で `exclude_patterns` / `file_extensions` の動きを見ているが、`config/validator_config.json` の中身は読んでいない（この設定ファイルを直しても、テストでは検出されない）。実際の動きは、`requirements.txt` の無い小さなフォルダに対して `--config` 付きで `python validator.py --path <フォルダ> --config config/validator_config.json` を打って確かめる（ルート直下に向けると pip-audit が通信しうる） |
| 検出ルールを足す・直す | `validator.py` の `SecurityScanner`（SEC）/ `CodeQualityChecker`（QUAL）/ `DependencyChecker`（DEP） | `git grep -n "<ルール ID>" -- . ':!validator.py'` に出る文書（README の検出ルール表、spec.md、llms.txt、docs/llms.txt など）を手で合わせる。`tests/` に「発火する例」と「発火しない例」を足す。実コードでの誤検知率の測定など、必須手順は [CLAUDE.md](CLAUDE.md) |
| 抑制コメント（`# code-validator: ignore`）の書式を変えたい | `validator.py` の `SUPPRESS_FILE_RE` / `SUPPRESS_LINE_RE` | `git grep -n "code-validator: ignore" -- . ':!validator.py'` に出る文書（README の Suppression 節など）と、`tests/test_suppressions.py` を確認する。意図的に脆弱なテストファイルは先頭にこのコメントを置く（置かないと自己検査の CI が落ちる） |
| 依存ライブラリの版を変えたい | `requirements.txt` | 版の数字を本文に書いている文書は手で合わせる: `git grep -n "pydantic" -- . ':!validator.py'`。CI は `.github/workflows/ci.yml` でこのファイルから入れ直すので、全テストが通るか見る |

## 直したあとの確認

1. 依存を入れる（初回だけ）: `pip install -r requirements.txt` と `pip install pytest`
2. `python -m pytest tests/ -q` — 全部 passed なら OK。これは `.github/workflows/ci.yml` の「Run tests」と同じコマンドです（CI は Python 3.12）
3. 動きを目で確かめるとき: 小さなフォルダ（`requirements.txt` が無いこと）を指して `python validator.py --path tests` を打つ。指摘 0 件・終了コード 0 になる。危険な書き方（例: `eval(` を呼ぶ 1 行の `.py`）を置いた別の一時フォルダを指すと、終了コード 1 になる
4. 自分自身を検査する CI（`.github/workflows/validate.yml`）は `python validator.py --git-diff` を使う。ルート直下で打つと `requirements.txt` があるため、`pip-audit`（任意で入れる依存検査ツール）が入っていれば外部の脆弱性データベースへ問い合わせる。通信を避けたい手元の確認では、この手順は打たず上の 3 を使う（このガイドの作成時にも打っていない）

テストが見ていないこと: レポートの見た目（HTML / JSON の出力）、`--git-diff` を含む CLI の引数処理、`.github/workflows/` の内容は、自動テストの対象外です。直したら手で実行して確かめてください。外部サービスにしか分からない変更（CI の挙動、GitHub Pages の表示）は、GitHub 上での確認が必要です。

## 壊れたとき

| 症状 | まず見る所 | よくある原因 |
|---|---|---|
| `--git-diff` が 0 ファイルで通ってしまう | `.github/workflows/validate.yml` の `fetch-depth` | 履歴が浅いと比較元を解決できない（`fetch-depth: 0` が必要。コード側の警告は `validator.py` の `_resolve_diff_base` 付近） |
| CI の自己検査が自分のテストで落ちる | 落ちたテストファイルの先頭 | 意図的に脆弱なコードを含むファイルに `# code-validator: ignore-file` が無い |
| DEP005 / DEP006（High）が出る | 依存検査（`pip-audit` / `npm audit`）の実行ログ | 依存が解決できない、タイムアウト。「検査が走らなかった」ことを失敗として扱う仕様（偽の安全を避けるため） |
| 設定を変えたのに反映されない | `--config` を渡しているか | 設定ファイルは `--config` で明示したときだけ使われる。渡さなければ `validator.py` 内の既定値 |
| `--format markdown` を指定してもレポートが出ない | `validator.py` の `main` | 引数は受け付けるが、Markdown の出力は未実装（HTML と JSON のみ） |

## AI なしでは保守できない所

なし。`validator.py` とテストは普通の Python で、`python -m pytest tests/ -q` だけで確かめられます。`CLAUDE.md` と `AGENTS.md` は AI ツール向けなので、AI を使わない場合は読まなくても構いません（検出ルールを追加するときの手順は人間にも役立つので一読を勧めます）。

## 用語集

| 言葉 | 意味 |
|---|---|
| ルール ID（SEC / QUAL / DEP） | 検出ルールの番号。SEC はセキュリティ、QUAL はコード品質、DEP は依存関係 |
| 抑制コメント | 指摘を意図的に除外する `# code-validator: ignore` 形式のコメント |
| `--git-diff` | マージ先（origin の既定ブランチ）との分岐点以降に変わったファイルだけを検査するモード。比較元を解決できないときは 1 つ前のコミットと比べる |
| CORS | ブラウザが別のサイトからの通信を許すかを決める仕組み。全許可は危険な設定として検出する |
| CI | GitHub 上でテストや検査を自動実行する仕組み。このリポジトリの定義は `.github/workflows/` |
| pip-audit / npm audit | Python / Node.js の依存ライブラリに既知の脆弱性がないか調べる外部ツール。本ツールはこれを呼び出す |
| Dependabot | 依存ライブラリの更新を自動で提案する GitHub の機能 |
| CodeQL | GitHub のコード解析機能。`.github/workflows/codeql.yml` で動く |
| `llms.txt` | AI 検索エンジン向けに書いたプロジェクト要約（ルート直下と `docs/` に同じ内容がある） |
