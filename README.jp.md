# envrcctl

envrcctl は macOS を優先しつつ Linux にも対応可能な CLI ツールで、direnv で使われる `.envrc` を安全かつ構造的に管理します。

着想元:
https://zenn.dev/yottayoshida/articles/llm-key-ring-secure-api-key-management

## 目標

- OS のキーストアに保存されたシークレットを安全に管理
- シークレット以外の環境変数を管理
- 親ディレクトリの継承（`source_up`）をサポート
- CRUD 操作を提供
- 管理ブロック編集のみにより `.envrc` を安全に保つ
- 将来的にプラガブルなシークレットバックエンドで Linux 対応

## アーキテクチャ

### Core（OS 非依存）

担当範囲:

- 管理ブロックの検出・再生成
- シークレット以外の CRUD
- シークレット参照の管理
- 継承の切り替え（source_up の on/off）
- `.envrc` の原子的書き込み
- `inject` コマンド（export 文の生成）
- `eval` コマンド（有効なマージ結果の表示）
- CLI インターフェース

### シークレットバックエンドインターフェース

抽象インターフェース:

    class SecretBackend:
        def get(ref) -> str
        def set(ref, value)
        def delete(ref)
        def list(prefix=None)

初期実装:

- macOS: `/usr/bin/security` CLI を使用する KeychainBackend

将来的な Linux:

- SecretServiceBackend（secret-tool / libsecret）
- pass / keyring ベースのバックエンドの可能性

## 管理ブロック形式

`.envrc` には次の管理セクションが含まれます:

    # >>> envrcctl:begin
    # managed: true

    source_up  # optional (inherit on)

    export BREWFILE="$PWD/Brewfile"

    export ENVRCCTL_SECRET_OPENAI_API_KEY="kc:com.rio.envrcctl:openai:prod"

    eval "$(envrcctl inject)"

    # <<< envrcctl:end

ルール:

- ツールは begin/end の間だけを編集
- それ以外は完全に保持
- 変更時はブロック全体を再生成

## シークレット保管モデル

参照形式:

    kc:<service>:<account>

例:

    kc:com.rio.envrcctl:openai:prod

Keychain での対応:

- service = com.rio.envrcctl
- account = openai:prod
- value = 実際のシークレット

シークレットは `.envrc` に書き込まれません。

## CLI コマンド設計

### init

- `.envrc` がなければ作成
- 管理ブロックを挿入
- 任意: `direnv allow` の案内

### inherit

    envrcctl inherit on
    envrcctl inherit off

管理ブロック内の `source_up` を追加/削除します。

### シークレット以外の CRUD

    envrcctl set VAR value
    envrcctl unset VAR
    envrcctl list
    envrcctl get VAR

管理ブロック内に平文の export として保存します。

### シークレット CRUD

    envrcctl secret set OPENAI_API_KEY --account openai:prod
    envrcctl secret unset OPENAI_API_KEY
    envrcctl secret list
    envrcctl secret rotate OPENAI_API_KEY

シークレット入力モード:

- `--prompt`（デフォルト: getpass 使用）
- `--stdin`（CI 向け）

### inject

すべてのシークレット参照に対して export 文を出力:

    export OPENAI_API_KEY='...'
    export GITHUB_TOKEN='...'

使用例:

    eval "$(envrcctl inject)"

### eval

継承を含む有効な環境を表示します。

シークレットはデフォルトでマスク:

    OPENAI_API_KEY = ****** (from parent, secret)
    GITHUB_TOKEN   = ****** (from current dir, secret)

## セキュリティ原則

- CLI 引数にシークレットを渡さない
- `.envrc` にシークレットを書き込まない
- ファイル更新は原子的に行う
- もし平文出力がある場合は TTY を確認
- `.envrc` が world-writable の場合に警告
- 管理ブロックの隔離

## 実装フェーズ

### Phase 1（MVP）

- init
- set/unset/list（シークレット以外）
- secret set/unset/list
- inject
- inherit on/off
- macOS Keychain backend

### Phase 2

- eval コマンド
- doctor（セキュリティ診断）
- 既存 `.envrc` の migrate
- shell completion

### Phase 3

- Linux SecretService backend
- プラガブルなバックエンド検出
- 参照スキーマの拡張

## パッケージング戦略

- Python 3.10+
- CLI は Typer または Click
- pipx でインストール可能
- 単一パッケージ配布

## 将来的な拡張

- ポリシー強制モード（未管理の export を禁止）
- CI セーフモード
- チーム管理のシークレット名前空間
- 参照の検証とローテーションのワークフロー

## 開発

このプロジェクトは `uv` で管理します。

## ライセンス

`LICENSE` を参照してください。