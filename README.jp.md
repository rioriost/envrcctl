# envrcctl

envrcctl は `.envrc` を安全に管理するための CLI ツールです。シークレットは
ファイルには書かず、OS のキーストア（macOS Keychain / Linux SecretService）
に保存します。

macOS を優先しつつ、Linux でも `secret-tool` を使った運用に対応します。

## 特長

- `.envrc` は管理ブロックのみを安全に編集
- シークレット以外の環境変数を CRUD 管理
- シークレットは Keychain / SecretService に保管
- 継承制御（`source_up` on/off）
- direnv 向けの secret 注入（`eval "$(envrcctl inject)"`）
- 診断・移行コマンド
- シェル補完

## 前提条件

- Python 3.14+
- `direnv`（`.envrc` を使う場合）
- macOS Keychain（標準搭載）または Linux SecretService（`secret-tool`）

## インストール

### pipx（推奨）

    pipx install envrcctl

### uv

    uv tool install envrcctl

### ソースから

    git clone <REPO_URL>
    cd envrcctl
    uv sync
    uv run python -m envrctl.main --help

> Homebrew: `Formula/envrcctl.rb` にテンプレートがあります。
> リリース用の URL/sha256 を置き換えて利用できます。

## クイックスタート

1. `.envrc` に管理ブロックを作成:

    envrcctl init

2. シークレット以外を追加:

    envrcctl set FOO bar
    envrcctl get FOO
    envrcctl list

3. 継承を有効化:

    envrcctl inherit on

4. シークレット登録:

    envrcctl secret set OPENAI_API_KEY --account openai:prod

5. `.envrc` に inject を追加（`init` が付与）:

    eval "$(envrcctl inject)"

6. direnv を許可:

    direnv allow

## コマンド

### シークレット以外

    envrcctl set VAR value
    envrcctl unset VAR
    envrcctl get VAR
    envrcctl list

### シークレット

    envrcctl secret set OPENAI_API_KEY --account openai:prod
    envrcctl secret unset OPENAI_API_KEY
    envrcctl secret list

CI 向け（標準入力）:

    echo -n "$OPENAI_API_KEY" | envrcctl secret set OPENAI_API_KEY --account openai:prod --stdin

### direnv 用 inject

    envrcctl inject

### 有効環境（マスク表示）

    envrcctl eval

### 診断

    envrcctl doctor

### 移行

    envrcctl migrate

## バックエンド選択（macOS/Linux）

バックエンドは自動選択されますが、`ENVRCCTL_BACKEND` で指定できます。

- `kc` — macOS Keychain
- `ss` — SecretService（`secret-tool`）

例:

    ENVRCCTL_BACKEND=ss envrcctl secret set OPENAI_API_KEY --account openai:prod

シークレット参照は次の形式で保存されます:

    <scheme>:<service>:<account>

例:

    kc:com.rio.envrcctl:openai:prod
    ss:com.rio.envrcctl:openai:prod

## シェル補完

    envrcctl --install-completion
    envrcctl --show-completion bash
    envrcctl --show-completion zsh
    envrcctl --show-completion fish

生成済みスクリプトは `completions/` にあります。更新する場合:

    uv run python scripts/generate_completions.py

## セキュリティ

- シークレットは `.envrc` に書き込まれません
- シークレットを CLI 引数で渡しません
- `.envrc` の更新は原子的に行われます
- `.envrc` が world-writable の場合は書き込みを拒否します

## 開発

    uv sync
    .venv/bin/envrcctl --help

## ライセンス

`LICENSE` を参照してください。