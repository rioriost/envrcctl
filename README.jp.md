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
- direnv 向けの secret 注入（`eval "$(envrcctl inject)"`）
- secret 種別（runtime/admin）と exec は runtime のみ注入
- Linux では `secret get` / `inject` / `exec` に TTY ガード
- macOS では `secret get` / `inject` / `exec` に TTY ガード + device owner authentication
- macOS では `inject` / `exec` が複数の runtime secret を 1 回の device owner authentication で一括取得
- tamper-evident なローカル監査ログ
- 診断・移行コマンド
- シェル補完

## 前提条件

- Python 3.14+
- `direnv`
- macOS Keychain（標準搭載）または Linux SecretService（`secret-tool`）
- device owner authentication (TouchID or Apple Watch)

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

### macOS 認証ヘルパーのビルドと配置

macOS で `secret get` / `inject` / `exec` に必要な device owner authentication を使うには、
`envrcctl-macos-auth` ヘルパーをビルドして `envrcctl` から参照できる場所に配置する必要があります。

既定では、`envrcctl` は Python パッケージと同じディレクトリにある
`envrcctl-macos-auth` を探します。別の場所に置く場合は
`ENVRCCTL_MACOS_AUTH_HELPER` 環境変数でパスを指定できます。

例:

```sh
    swiftc -framework LocalAuthentication -framework Security \
      scripts/macos/envrcctl-macos-auth.swift \
      -o src/envrcctl/envrcctl-macos-auth
```

別の場所に出力する場合:

```sh
    swiftc -framework LocalAuthentication -framework Security \
      scripts/macos/envrcctl-macos-auth.swift \
      -o /usr/local/bin/envrcctl-macos-auth
```

その場合は `envrcctl` 実行前に以下を設定します。

```sh
    export ENVRCCTL_MACOS_AUTH_HELPER=/usr/local/bin/envrcctl-macos-auth
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

Linux では、対話式シェルでのみ実行できます。  
macOS では、対話式シェルであることに加えて、Touch ID / Apple Watch を含む macOS の device owner authentication が必要です。  
複数の runtime secret を対象にする場合でも、macOS では 1 回の認証でまとめて取得します。

### direnv 用 inject

```sh
    envrcctl inject
```

Linux では、非対話実行時に `--force` が必要です。  
macOS では、`_is_interactive` 相当の対話判定に加えて、Touch ID / Apple Watch を含む macOS の device owner authentication が必要です。  
複数の runtime secret がある場合も、`inject` は 1 回の認証で対象 secret を一括取得します。

### 有効環境（マスク表示）

```sh
    envrcctl eval
```

### 監査ログ

```sh
    envrcctl audit list
    envrcctl audit show --index 0
    envrcctl audit verify
```

`envrcctl` は以下の操作について、tamper-evident なローカル監査イベントを記録します。

- `secret get`
- `inject`
- `exec`

監査ログには次の性質があります。

- plaintext の secret value は保存しません
- 環境変数名、secret ref metadata、作業ディレクトリ、`exec` の command metadata を保存します
- 各イベントを `prev_hash` と `hash` で連結し、過去イベントの改変や削除を検知可能にします

`envrcctl audit verify` は、この hash chain を検証し、監査ログの改変が疑われる場合に失敗を報告します。

### 診断

```sh
    envrcctl doctor
```

`doctor` は audit の健全性も確認し、以下の場合に警告を出します。

- audit chain の検証に失敗した場合
- audit store の permission が安全でない場合

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
- Linux では `inject` は非対話環境でブロックされます（`--force` で解除）
- Linux では `secret get` はクリップボード優先で、平文出力は TTY ガードされます
- Linux では `exec` も対話式シェルでの利用を前提とします
- macOS では `secret get` / `inject` / `exec` の実行時に、`_is_interactive` 相当の判定に加えて device owner authentication が必要です
- macOS の device owner authentication は、環境によって Touch ID、Apple Watch 承認、または macOS が提供する他の所有者認証方法で満たされます
- macOS では `envrcctl-macos-auth` ヘルパーのビルドと配置が必要です。既定の探索先を使わない場合は `ENVRCCTL_MACOS_AUTH_HELPER` で実行ファイルのパスを指定してください
- secret access 操作は tamper-evident なローカル audit log に記録されます
- audit record に plaintext の secret value は含まれません
- audit integrity は hash chain に基づき、`envrcctl audit verify` で検証できます
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
