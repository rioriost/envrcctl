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
- stdout に出さない exec 注入（`envrcctl exec -- ...`）
- direnv 向けの secret 注入（`eval "$(envrcctl inject)"`, TTY ガード付き）
- secret 種別（runtime/admin）と exec は runtime のみ注入
- secret get はクリップボード優先 + TTY ガード
- 診断・移行コマンド
- シェル補完

## 前提条件

- Python 3.14+
- `direnv`
- macOS Keychain（標準搭載）または Linux SecretService（`secret-tool`）

## インストール

### macOS（Homebrew）

```sh
    brew tap rioriost/envrcctl
    brew install envrcctl
```

direnvのインストールは以下です。

```sh
    brew install direnv
```

### Linux（pipx、推奨）

```sh
    pipx install envrcctl
```

### Linux（uv）

```sh
    uv tool install envrcctl
```

### ソースから（macOS/Linux）

```sh
    git clone <REPO_URL>
    cd envrcctl
    uv sync
    uv run python -m envrcctl.main --help
```

## クイックスタート

1. `.envrc` に管理ブロックを作成:

```sh
    envrcctl init
```

既存の `.envrc` がある場合は確認が求められます。非対話実行では `--yes` でスキップできます。`--inject` で inject 行を明示的に追加できます。

2. シークレット以外を追加:

```sh
    envrcctl set FOO bar
    envrcctl get FOO
    envrcctl list
```

3. 継承を有効化:

```sh
    envrcctl inherit on
```

4. シークレット登録:

```sh
    envrcctl secret set OPENAI_API_KEY --account openai:prod
```

5. inject 行を明示的に追加:

```sh
    envrcctl init --inject
```

管理ブロックに `eval "$(envrcctl inject)"` が追加されます。

6. direnv を許可:

```sh
    direnv allow
```

## コマンド

### シークレット以外

```sh
    envrcctl set VAR value
    envrcctl unset VAR
    envrcctl get VAR
    envrcctl list
```

### シークレット

```sh
    envrcctl secret set OPENAI_API_KEY --account openai:prod --kind runtime
    envrcctl secret set OPENAI_API_KEY --account openai:admin --kind admin
    envrcctl secret unset OPENAI_API_KEY
    envrcctl secret list
    envrcctl secret get OPENAI_API_KEY
    envrcctl secret get OPENAI_API_KEY --plain
```

CI 向け（標準入力）:

```sh
    echo -n "$OPENAI_API_KEY" | envrcctl secret set OPENAI_API_KEY --account openai:prod --stdin
```

### stdout に出さない exec

```sh
    envrcctl exec -- python script.py
    envrcctl exec -k OPENAI_API_KEY -- python script.py
```

exec は runtime のみ注入します。

### direnv 用 inject

```sh
    envrcctl inject
```

非対話実行では `--force` が必要です。

### 有効環境（マスク表示）

```sh
    envrcctl eval
```

### 診断

```sh
    envrcctl doctor
```

### 移行

```sh
    envrcctl migrate
```

未管理の export または secret ref が検出された場合は確認が求められます。非対話実行では `--yes` でスキップできます。

## バックエンド選択（macOS/Linux）

バックエンドは自動選択されますが、`ENVRCCTL_BACKEND` で指定できます。

- `kc` — macOS Keychain
- `ss` — SecretService（`secret-tool`）

例:

```sh
    ENVRCCTL_BACKEND=ss envrcctl secret set OPENAI_API_KEY --account openai:prod
```

シークレット参照は次の形式で保存されます:

    <scheme>:<service>:<account>:<kind>

`kind` は `runtime` または `admin`（既定: `runtime`）です。

例:

    kc:st.rio.envrcctl:openai:prod:runtime
    kc:st.rio.envrcctl:openai:admin:admin

## シェル補完

```sh
    envrcctl --install-completion
    envrcctl --show-completion bash
    envrcctl --show-completion zsh
    envrcctl --show-completion fish
```

生成済みスクリプトは `completions/` にあります。更新する場合:

```sh
    uv run python scripts/generate_completions.py
```

## セキュリティ

- シークレットは `.envrc` に書き込まれません
- シークレットを CLI 引数で渡しません
- `.envrc` の更新は原子的に行われます
- `inject` は非対話環境でブロックされます（`--force` で解除）
- `secret get` はクリップボード優先で、平文出力は TTY ガードされます
- `.envrc` が world-writable の場合は書き込みを拒否します

## 開発

```sh
    uv sync
    .venv/bin/envrcctl --help
```

## 謝辞

下記の記事を参考に、exec等を追加しました。ヒントを与えていただいたことに感謝いたします。  
「[もう.envにAPIキーを平文で置くのはやめた — macOS Keychain管理CLI「LLM Key Ring」](https://zenn.dev/yottayoshida/articles/llm-key-ring-secure-api-key-management)」

## ライセンス

MIT
