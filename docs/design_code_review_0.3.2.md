# envrcctl 0.3.2 設計・コードレビューと修正プラン

> 本書は `db34c07` のレビュー時点の記録です。R01–R21 の対応内容と
> 互換性の変更は [0.4.0 リリースノート](releases/0.4.0.md) を参照してください。
> 以下の行番号と再現結果は修正前の実装を示します。

## 対象と結論

- レビュー日: 2026-09-16
- レビューモデル: GPT-6 Astra
- 対象リビジョン: `db34c07` (`0.3.2`)
- 対象範囲: Python runtime、Swift 認証 helper とその境界、既存テスト、
  Homebrew formula、配布・補完・検証スクリプト、関連設計文書。
- 方針: 設計・実装・利用手順の整合性をレビューし、修正計画を作成する。
  このレビューでは実装を変更しない。

**既存の構成を維持した修正で対応可能だが、通常操作での値の破損、
direnv 連携の不成立、Keychain 書き込み時の平文 argv、
ファイル・secret・監査記録の不整合を優先して修正すべき。**
大規模な書き直しや、単に `cli.py` を分割するリファクタリングを先行させる必要はない。

`ManagedBlock`、secret reference、OS backend、監査イベントの責務分離は妥当である。
secret の一括取得後に出力する構造や、runtime/admin の注入フィルタも維持したい。
Swift helper が一つの `LAContext` を batch 全体で共有し、全件取得が完了するまで
応答を出さない点も維持する。ただし、実際の Keychain ACL による追加プロンプトの有無まで
静的レビューで保証できるものではない。
一方、モジュール間の契約が不足している。特に次の条件を明文化する必要がある。

- render した値を parse しても元の値が変わらない。
- 対話認証の可否と、stdout が pipe であることを区別する。
- 書き込み拒否時には既存ファイルや OS store を変更しない。
- OS store のアイテム識別子と `.envrc` の参照文字列を区別する。
- 同時実行、途中終了、子プロセス起動失敗を含め、監査履歴の整合性を保つ。

優先度は **P1: 次のリリースまでに修正**、**P2: 続く修正で対応** とする。
以下では再現できた不具合と、仕様変更を伴う設計上の改善を区別する。

## 確認済みの指摘

### R01 / P1: 生成される inject 行が TTY ガードと両立しない

**箇所:** `src/envrcctl/managed_block.py:11`、
`src/envrcctl/cli.py:111-112,479-489`

生成行は `eval "$(envrcctl inject)"` だが、コマンド置換内の stdout は必ず pipe
になる。`_is_interactive()` は stdin と stdout の両方に TTY を要求するため、
対話シェルから使っても `inject` は拒否される。Linux の生成行には `--force` がなく、
macOS は `--force` を付けても後段の判定で拒否する。

さらに、取得失敗で出力が空でも `eval ""` は成功するため、呼び出し側へ失敗が伝わらない。
疑似端末を stdin に接続した実際の Bash コマンド置換で、
`inject` の終了コードが 1、空の出力に対する `eval` が 0 になることを確認した。

**修正方針:** stdout の配送先と対話認証ポリシーを分離し、direnv 用の許可条件を
定義する。macOS の device owner authentication を省略する対応にはしない。
生成する shell fragment は inject 自体の終了コードを検査してから評価する。
既存の inject 行の認識・更新、README の両言語版も同時に対応する。

**受け入れ条件:** Bash の実コマンド置換と direnv の実行経路で成功すること。
認証拒否・secret 不在・監査失敗を親へ非ゼロで伝え、export を部分出力しないこと。
TTY のない CI で暗黙に許可されず、Linux の明示的 override と macOS の必須認証を維持すること。

### R02 / P1: 通常の値が parse/render 往復で破損する

**箇所:** `src/envrcctl/managed_block.py:34-36,49-71,109-116`

render は `shlex.quote()` を使用するが、parse は先頭・末尾の引用符を除去するだけである。
例えば `it's valid` は往復すると shell 用の引用符連結が値に混入する。
改行を含む `first\nsecond` は `splitlines()` によって分断され、
取得値が `"'first"` になる。後続の別変数の更新でも壊れた値が再保存される。

**修正方針:** 管理ブロックで受け入れるリテラル文法を定義し、shell を実行せずに
render の逆変換を実装する。複数行の quoted value を論理行として扱うか、
互換性を考慮した可逆な表現へ移行する。`shlex.split()` を物理行ごとに適用するだけでは
改行問題は解決しない。不正な引用やマーカーは黙って捨てず、更新を拒否する。

**受け入れ条件:** 空文字、単引用符、二重引用符、両方の引用符、改行、
backslash、`$`、Unicode の往復一致。`set → get → 別変数の set → get` でも一致し、
生成した shell を読み込んだ値も一致すること。

### R03 / P1: 固定名の一時ファイルによる上書きと権限変更

**箇所:** `src/envrcctl/envrc.py:85-112`

`_atomic_write()` は固定名 `.envrc.tmp` を通常の `open("w")` で開く。
そのパスが symlink の場合はリンク先を上書きし、`os.replace()` 後には
`.envrc` 自体が symlink になる。最終パスの事前検査だけでは防げない。
レビューでは一時ディレクトリ内のダミーファイルだけを使い、この挙動を確認した。

また、元の `.envrc` が `0600` でも、umask `022` で更新すると `0644` になる。
同時更新では一時ファイル名が競合し、単に一時名を固有化しても
read-modify-write の lost update は残る。

**修正方針:** 同一ディレクトリに排他的に作成した固有の一時ファイルを使用し、
既存の安全な mode を維持、新規ファイルの mode を明示する。
通常ファイル・リンク・親ディレクトリの検査を一貫させる。
読み込みから置換までをプロセス間で直列化するか、競合検出して明示的に失敗させる。
一時ファイルの後始末と、必要な file/directory fsync を実施する。

**受け入れ条件:** 一時名や対象が symlink でも別ファイルを変更しないこと。
`0600` を維持すること。同時更新が silent lost update や一時名の競合を起こさず、
途中失敗時に元ファイルを保持すること。

### R04 / P1: .envrc 更新拒否より先に OS store を変更する

**箇所:** `src/envrcctl/cli.py:345-354,376-381`

`secret set` は `.envrc` の読み込み・書き込み検査より先に `backend.set()` を行う。
`secret unset` も `.envrc` を更新する前に backend の値を削除する。
例えば world-writable の `.envrc` に対する unset はエラー終了するが、
OS store の値は既に消え、参照だけが残る。mock store を使って再現した。

**修正方針:** まず読み込み・構文・書き込み先・共有参照を検査し、
R03 の更新制御下で変更内容を準備する。OS store とファイルには共通トランザクションがないため、
単なる処理順変更で原子性を保証できるとは扱わない。
失敗時の補償処理、残存参照・孤立アイテムの通知と復旧手順を定義する。
既存値を破壊する操作と、参照編集だけの操作は分離する。

**受け入れ条件:** 事前に拒否できる操作では backend を呼ばないこと。
backend 失敗・ファイル置換失敗の両方で、既存値の喪失や成功扱いを起こさないこと。
補償できない部分成功は明示的に報告すること。

### R05 / P1: 共有 secret の判定が参照文字列の完全一致になっている

**箇所:** `src/envrcctl/cli.py:370-378`、
`src/envrcctl/secrets.py:61-81`

`kc:svc:account` と `kc:svc:account:runtime` は同じ OS store アイテムを指すが、
共有判定では異なる文字列として扱う。一方を unset すると、残った変数で使う値まで
削除される。kind が異なる参照でも OS store の service/account が同じなら同様である。
互換参照と明示的 runtime 参照を使って再現した。

同一プロジェクト内だけを調べても、別プロジェクトや親の `.envrc` から共有される
アイテムの利用状況は分からない。この点はローカル比較の修正だけでは解決しない。

**修正方針:** canonical な backend identity `(scheme, service, account)` で比較する。
kind は利用ポリシーであり保存先識別子ではないことを明示する。
プロジェクト外の共有については、通常の unset を参照解除とし、
store 自体の削除は明示的な破壊操作とする案を推奨する。
CLI 互換性に影響するため、移行・確認表示・リリースノートを伴う変更とする。

**受け入れ条件:** 旧形式・kind 違い・同一 block 内の alias で誤削除しないこと。
別プロジェクトで共有する値を、通常の参照解除で破壊しないこと。

### R06 / P1: migrate が shell の意味と上書き順序を変える

**箇所:** `src/envrcctl/managed_block.py:18-23`、
`src/envrcctl/envrc.py:46-66`、`src/envrcctl/cli.py:975-987`

`export TARGET="$HOME/bin"` を migrate すると `$HOME/bin` というリテラルへ変わる。
条件分岐内の export もインデントを無視して抽出し、管理ブロックへ移すため
条件付き設定が無条件になる。実際の Bash 読み込みでも確認した。

また、管理ブロックで `VALUE=old`、その後で `export VALUE=new` としている場合、
実際の有効値は `new` だが、`setdefault()` により `old` が残り、
外側の `new` の行は削除される。

**修正方針:** 管理ブロックのリテラル parser と、任意の `.envrc` の移行を別の問題として扱う。
動的式・条件分岐・function・複合文・曖昧な重複は自動で移さず、原文を残して警告する。
トップレベルの安全なリテラルに対象を限定し、重複値の競合は明示的に解決する。
`--yes` は確認省略であって、意味変更の許可とは扱わない。

**受け入れ条件:** 展開式や条件付き export を壊さずに保持すること。
before/block/after の重複を silent に失わないこと。
安全に移行できる入力では、移行前後の shell の有効値が一致すること。

### R07 / P1: 同時の監査追記で hash chain が壊れる

**箇所:** `src/envrcctl/audit.py:133-135,171-183`

`latest_hash` の読み込みから log 追記、sidecar 更新までに排他制御がない。
2 つの呼び出しが同じ tail を読んでから追記すると、両方が同じ `prev_hash` を持ち、
正規の同時利用だけで `audit verify` が失敗する。
読み込みタイミングだけを barrier で同期させた 2 並列の実行で再現した。

log と sidecar は別々に更新され、fsync もないため、
途中終了で片方だけ更新される問題もある。これは静的に確認したクラッシュ耐性の不足であり、
電源断の実機試験を行ったという意味ではない。

**修正方針:** プロセス間 lock の下で tail 検査・追記・durability 確保・sidecar 更新を行う。
sidecar は一時ファイルから原子的に置換する。
log を正とする場合のクラッシュ復旧条件を定義し、整合性不明の状態を
黙って初期化・上書きしない。既存履歴は破棄せず保全する。

**受け入れ条件:** 複数プロセスによる追記で件数・event ID・chain が一致すること。
各 I/O 境界の障害注入でも履歴を失わず、復旧可能な状態と要調査の状態を区別できること。

### R08 / P1: exec の監査が子プロセスの終了後にしか残らない

**箇所:** `src/envrcctl/cli.py:588-610`。
関連する起動エラー境界: `src/envrcctl/command_runner.py:54-65`、
`src/envrcctl/auth.py:59-70`

`subprocess.run()` の完了後に初めて監査を追記する。
そのため長時間動作する子の実行中には記録がなく、親の異常終了ではアクセス履歴が残らない。
監査書き込みが失敗しても、子には既に secret が渡され、処理は実行済みである。
起動時の `FileNotFoundError` なども捕捉対象の `EnvrcctlError` ではないため記録されない。
mock 子プロセスと監査失敗・起動失敗を使って順序と履歴欠落を確認した。

backend/helper の共通起動境界も `CalledProcessError` しか変換せず、
ENOENT・EACCES・ENOEXEC が domain error にならない。
実行前の存在・実行権限チェックだけでは、これらの失敗を網羅できない。

**修正方針:** 子の起動前に durable なアクセス／起動予定イベントを書き、
終了結果を対応する別イベントで記録する。取得、開示、起動、完了の意味を分け、
成功した起動予定イベントを「子が起動した証明」とは扱わない。
既知の OS エラー・中断を構造化し、終了コード・signal の扱いも定義する。
監査エラーを再度同じ監査関数に書こうとして元の原因を隠さない。

**受け入れ条件:** 事前の監査失敗時には子が起動しないこと。
長時間実行中・親の中断・起動失敗にも追跡可能な記録があること。
通常の子の終了コードを保持し、監査失敗との区別ができること。
backend/helper の ENOENT・EACCES・ENOEXEC も安全な診断に変換され、
認証なしの fallback や後続の secret 操作を行わないこと。

### R09 / P2: audit verify が不正な JSON 型でクラッシュし、検査中に権限を修正する

**箇所:** `src/envrcctl/audit.py:103-115,211-220,304-320`

JSON として有効な `[]` や `null` は object 検査を通らず `payload.keys()` に進むため、
`AttributeError` で終了する。`[]` の一行だけを置いた log で再現した。

また、検証は `ensure_audit_files_secure()` を呼び、
file の mode を `0600` へ直してから確認する。
README が説明する不適切な監査ファイル権限の警告より先に状態を変更してしまう。

**修正方針:** JSON の最上位型、schema version、必須フィールドを段階的に検証し、
失敗行と理由を返す。検査と修復を分離し、verify/doctor は原則 read-only にする。
OS エラーも想定されるものだけを明示的に `EnvrcctlError` 等へ変換する。

**受け入れ条件:** `[]`、`null`、不正 schema、権限不足で traceback ではなく
検査結果を返すこと。検査の前後で内容・mode が変わらないこと。

### R10 / P2・設計変更: audit の「平文を保存しない」保証と argv 保存が矛盾する

**箇所:** `src/envrcctl/cli.py:64-65,588-595`、
`src/envrcctl/audit.py:137-149`

`exec` の command 配列と例外文字列をそのまま永続化する。
例えば `exec -- command --token DUMMY_SECRET_DO_NOT_USE` は、
そのダミー値を監査ファイルに平文保存する。mock 子プロセスで確認した。

argv の保存自体は既存の設計文書に記載されているため、
単なる実装漏れではなく「secret plaintext を保存しない」という保証との仕様矛盾である。
shell 展開済みの引数や任意の外部エラーから、すべての secret を判定することはできない。

**修正方針:** 既定の記録を実行ファイル名などの非機密 metadata に限定し、
raw argv を必要とする場合は明示的 opt-in と警告を設ける。
例外も既知の code と安全な message を使用する。
option 名のパターン置換だけで、機密値非保存を保証したとは扱わない。

**受け入れ条件:** token option、URL credentials、header、shell 展開済み引数、
外部エラーにダミー secret を含めても、既定の監査ファイルには残らないこと。

### R11 / P1: Keychain 書き込み時に secret をプロセス引数へ渡している

**箇所:** `src/envrcctl/keychain.py:164-180`、
`src/envrcctl/command_runner.py:62-65`

`security ... -w <value>` として secret 自体を argv に含めている。
同じ値を stdin にも渡しているが、argv から消えるわけではなく、
プロセス引数を観測できる経路に値が露出する。
README と command inventory の「secret は CLI 引数で渡さない」という説明と矛盾する。

さらに、`raise EnvrcctlError(...) from exc` が secret を含む command を持つ
`CalledProcessError` を保持するため、外側の message を redact しても
例外チェーンを整形すると secret が残る。ダミー値と subprocess mock で確認した。
通常の CLI 表示が必ずこの traceback を出すと主張するものではなく、
例外オブジェクト・診断経路に機密値が残る問題である。

**修正方針:** native helper に stdin-fed の Keychain 書き込みを追加し、
Security framework で作成・更新する。`security` の argv から `-w` の値だけを
外せば stdin を安全に読む、と仮定しない。
秘密を含む下位例外・stdout/stderr を domain error に保持しない。
既存アイテムの更新・アクセス制御の意味を維持する。

**受け入れ条件:** ダミー secret が argv、通常エラー、整形済み例外チェーンの
いずれにも残らず、stdin だけで正確に伝わること。
新規作成・既存更新・失敗時の挙動を protocol tests と専用 Keychain item の
opt-in 統合試験で確認すること。

### R12 / P2: backend ごとの改行・空白処理が secret の実値を変える

**箇所:** `src/envrcctl/keychain.py:51-60,148-162`、
`src/envrcctl/secretservice.py:12-38`、
`src/envrcctl/command_runner.py:55-60`、
`scripts/macos/envrcctl-macos-auth.swift:335-336`

Swift の単件取得は framing newline を加えず UTF-8 を書くが、
Python 側は末尾の newline を削除する。
同じ `token\n` が単件では `token`、一括 JSON では `token\n` となる。
`text=True` の universal-newline conversion は CRLF や CR も変えてしまう。

SecretService の set は値に newline を追加する。
pipe から読む `secret-tool store` にとってこれは区切りではなく値の一部であり、
別の SecretService client からは変更された値が見える。
get の `.strip()` はこれを隠す一方、正当な先頭・末尾の空白も削除する。
protocol mock と、改行を出力する無害な Python 子プロセスで確認した。
SecretService の framing は
[upstream の stdin/output 実装](https://github.com/GNOME/libsecret/blob/master/tool/secret-tool.c)
に照らして確認したもので、この環境での実 SecretService 試験ではない。

**修正方針:** 単件取得を既存の JSON batch protocol に寄せるなど、
secret と通信 framing を区別する。SecretService の stdin に newline を追加せず、
受信を UTF-8 として正確に decode する。
`cli.py:342` の stdin 入力末尾処理も含め、入力契約を統一する。
既存の newline 付きアイテムを推測で切り詰めず、明示的な再登録・移行手順を用意する。

**受け入れ条件:** spaces、tabs、改行、CRLF、CR、Unicode について
set/get/single/bulk と別 client の観測値が一致すること。
既存アイテムを読み込んだだけで正規化・変更しないこと。

### R13 / P2: 相対 helper パスは検証したファイルと実行するファイルが一致しない

**箇所:** `src/envrcctl/auth.py:19-26,56-61`、
`src/envrcctl/keychain.py:20-27,51-55`

`ENVRCCTL_MACOS_AUTH_HELPER=./helper` を `Path` にすると、
文字列化時に `helper` となる。
存在確認は作業ディレクトリのファイルを見るが、subprocess の bare name は
PATH 探索となり、起動できないか同名の別ファイルを選ぶ。
既存の実行可能ファイルを使った検査と argv の捕捉で確認した。別 helper は実行していない。

**修正方針:** 選択した filesystem path を絶対化してから検査・実行し、
両方に同じ値を使用する。`shutil.which()` が相対 PATH entry から返す値も対象にする。
auth/keychain の重複する helper 探索・検査処理は、この契約を共有できる範囲で集約する。

**受け入れ条件:** `./helper`、bare relative name、相対サブディレクトリ、
相対 PATH entry、同名 PATH candidate のいずれでも、検証した絶対パスだけが実行対象になること。

### R14 / P1: macOS の backend dispatch と認証 capability が一致していない

**箇所:** `src/envrcctl/cli.py:137-155`、
`src/envrcctl/keychain.py:82-92,118-146`、
`src/envrcctl/secretservice.py:9`、`src/envrcctl/secrets.py:42-51`、
`scripts/macos/envrcctl-macos-auth.swift:42-59,237-248`

`_get_secret_values()` は最初の参照から backend を選び、macOS では全件をその
`get_many_with_auth()` へ送る。`kc` と `ss` が混在しても分割しない。
native protocol は Keychain 専用で scheme を持たず、Python 側の結果キーも
`(service, account)` だけなので、異なる store の同名アイテムを混同する。
Keychain に同名アイテムがあれば SecretService の値の代わりに注入され得る。
dispatcher mock と native request mock の両方で確認した。

SecretService だけを選ぶ場合にも別の問題がある。
`SecretServiceBackend` は `SecretBackend` Protocol を継承し、
認証付き単件・一括 method を override していない。
継承した `...` の method は存在し呼び出せるが、認証も lookup もせず `None` を返す。
macOS の実行経路で、method の存在だけでは対応済みと判断できない。

**修正方針:** cross-backend identity に scheme を含め、backend ごとに dispatch する。
Keychain の入口でも foreign scheme を拒否する。
macOS 上の SecretService に必須認証をどう適用するかは別途決定し、
対応しない構成は backend 選択時に明示的に拒否する。
`hasattr()` や実体のない Protocol method の存在を capability 判定に使わない。

**受け入れ条件:** 同じ／異なる service/account、参照順の逆転、
片方にしか存在しないアイテムで cross-store substitution を起こさないこと。
macOS 上の単独 SecretService も、認証付きの実取得か明示的な非対応エラーとなり、
`None` や空の成功応答にしないこと。
同一 Keychain 内の deduplication と 1 回の認証は維持すること。

### R15 / P1: release target の依存グラフが並列 Make で破綻する

**箇所:** `Makefile:16-27,40-50`

`sync completions dist helper-archive formula` は順序付き pipeline ではなく、
同じ target の独立した prerequisite である。
`make -j release-artifacts` や並列 `MAKEFLAGS` の継承では、
生成途中の artifact の checksum 計算、dist の削除と helper archive 作成が競合する。
formula 側の artifact 不在時の build とも二重実行になり得る。
同じ依存グラフを使う無害な模擬 stage で、後段の先行実行を確認した。

**修正方針:** pipeline の所有者を一つにし、明示的な依存関係または
一つの逐次 orchestrator を使う。formula は完成・検証済み artifact だけを消費する。

**受け入れ条件:** 遅延する mock stage と並列 Make でも必要な順序を維持し、
各 artifact を一度だけ生成すること。途中の失敗時に後段を開始しないこと。

### R16 / P1: helper archive の作成失敗を成功として扱う

**箇所:** `Makefile:43-47`

一つの shell recipe 内で `cp`、`chmod`、`tar` の失敗を検査せず、
最後の cleanup の終了コードが全体の結果になる。
模擬コマンドで各 packaging 操作を失敗させても recipe は 0 を返した。
不完全な archive が残ると、存在確認だけをする後段で再利用され得る。

**修正方針:** 失敗時に直ちに終了し、trap による cleanup でも失敗コードを維持する。
一時 archive の member と実行可能 mode を確認してから最終名に置換する。

**受け入れ条件:** copy、chmod、tar、検証の各失敗で非ゼロ終了し、
formula 生成に進まず、不完全な最終 artifact を残さないこと。

### R17 / P2: 配布前の helper rename が失敗復元と packaging 除外を不安定にする

**箇所:** `Makefile:24-38`、`pyproject.toml:16-32`

build 前に helper を source directory 内の `.bak` へ移動するが、
`uv build` が失敗すると復元 target は実行されない。
通常の helper パスが消えた状態で checkout が残ることを模擬 build で確認した。

また、packaging の除外は元のファイル名だけで、`.bak` は対象外である。
native-free な Python artifact に backup が含まれる余地がある。
この点は設定と Hatch の選択規則に基づく指摘であり、
現在公開中の wheel/sdist に混入していると確認したものではない。

**修正方針:** helper の rename をやめ、明示的な packaging 除外を使う。
過去に残った backup も除外する。

**受け入れ条件:** 元 helper と backup が両方存在しても wheel/sdist に含まれず、
build の成否にかかわらず元 helper のパスと内容が変わらないこと。

### R18 / P2: 配布する全シェル補完が Typer と異なる protocol を使う

**箇所:** `scripts/generate_completions.py:18-26`、`completions/`

Typer の command に対して Click の completion class を使って生成している。
配布スクリプトの `bash_complete`、`zsh_complete`、`fish_complete` は
現在の CLI が `Shell complete not supported.` として拒否する。
locked Click 8.4.2 / Typer 0.26.8 に対する black-box request で確認した。
`complete_bash` は認識されるが、instruction 名だけでなく応答形式も異なる。

**修正方針:** Typer の completion 機構から生成し、3 種の配布物を更新する。
instruction 名だけを文字列置換して済ませない。

**受け入れ条件:** 生成スクリプトを実際の CLI と接続し、
command、option、該当する path の候補を Bash/Zsh/Fish で取得できること。

### R19 / P2: Homebrew formula に helper の最低 macOS version 制約がない

**箇所:** `Formula/envrcctl.rb:10-19`、
`scripts/release_artifacts.py:291-300`

`docs/releases/0.3.2-validation.md:12` は helper の最低 version を macOS 26 と記録するが、
formula は対応する OS version 制約を持たない。
Python 依存を満たす旧 arm64 macOS でもインストール対象になり、
help と helper の存在確認だけでは利用可能性を判定できない。
最低 version は既存の release validation に基づき、今回 binary を実行したものではない。

**修正方針:** 実際の Mach-O deployment target と照合し、
generator に最低 OS version を反映して formula を再生成する。
README の導入条件にも明記する。

**受け入れ条件:** 対応外 OS をインストール前に拒否し、
formula の宣言と配布 helper の metadata が一致すること。

### R20 / P2: 既存 artifact の再利用が現在の lockfile と整合しているか検査しない

**箇所:** `scripts/release_artifacts.py:386-413`

同じ version のファイルが存在すると build を省略する一方、
formula の依存 resource は現在の project/lockfile から作る。
version を上げずに release 準備中の依存やソースを修正すると、
古い app artifact と新しい依存情報を組み合わせる。
artifact 存在を模擬した呼び出しで、build が省略され formula 更新へ進むことを確認した。

**修正方針:** build と formula-only/reuse を明示的に分ける。
再利用するなら source/config/lockfile の fingerprint と artifact hash を記録・照合し、
不一致時には再生成または明示的に拒否する。

**受け入れ条件:** version を維持したまま入力を変更しても古い artifact を
無条件には使わないこと。formula-only は入力由来の不一致を検知できること。

### R21 / P2: 検証スクリプトが標準 macOS Bash で起動できない

**箇所:** `.zed/scripts/verify:1-7`

`mapfile -d` は macOS 標準の Bash 3.2 に存在しない。
新しい Bash が PATH にない環境では、検査に入る前に
`mapfile: command not found`、終了コード 127 となる。
`/bin/bash` と模擬 git 出力で確認した。

**修正方針:** Bash 3.2 互換の NUL-delimited read loop を使うか、
必要な Bash version を明示的に検出・選択し、導入条件として文書化する。

**受け入れ条件:** 標準 `/bin/bash` で clean/変更ありの両方を扱え、
空白を含むファイル名でも意図した検査へ到達すること。

## 設計上の注意と非指摘事項

hash と sidecar が同じ書き込み権限の下にある以上、全履歴の再計算や store 全体の削除を
検出できる保証はない。これは既存の監査設計でも受容している限界であり、
外部署名や remote logging を今回の必須修正とはしない。
ただし、log だけが欠落し sidecar が残る状態を現在は正常な空履歴として扱うため、
完全な未初期化状態と不整合状態を区別する改善は R09 に含めたい。

runtime/admin は注入対象を選ぶ metadata であり、OS store 内の独立したアクセス制御ではない。
この前提を変える場合は別の仕様変更として扱う。

## 修正の実施順序

| 段階 | 対象 | 実施内容と依存関係 |
| --- | --- | --- |
| 0 | 回帰条件の固定 | 以下の隔離テスト環境と各指摘の失敗ケースを先に追加する。 |
| 1 | R02, R03, R11 | 可逆な管理ブロック、安全なファイル更新、argv を使わない Keychain 書き込みを最優先で確立する。 |
| 2 | R04, R05, R06, R12 | 段階 1 の更新制御上で、secret の変更契約・値の忠実性と保守的な migration を実装する。 |
| 3 | R07, R09 | 監査ストレージの直列化・復旧・read-only 検証を整える。 |
| 4 | R08, R10 | 段階 3 に基づき、監査イベントの lifecycle と機密 metadata の扱いを変更する。 |
| 5 | R01, R13, R14 | helper の同一性、backend dispatch、対話認証と stdout を分離し、監査失敗を含む direnv 連携を完成させる。 |
| 並行・配布工程 | R15, R16, R17, R20 | R15/R16 を次の公開までに修正し、続いて非破壊 build と artifact 来歴を保証する。 |
| 並行・導入品質 | R18, R19, R21 | 補完、OS 対応条件、標準 Bash での検証経路を修正する。 |
| 最終 | 文書・互換性 | README 両言語版、threat model、command inventory、release checklist を実装に合わせる。 |

段階は依存関係を示すもので、すべてを一つの巨大な変更にまとめる意図ではない。
特に unset の意味、監査 event schema、生成 shell fragment の変更には
既存ユーザー向けの移行説明が必要である。

## 回帰防止方針

既存テストは CLI の分岐や backend の mock 応答をよくカバーしている一方、
`_is_interactive = True` の差し替えは実際の command substitution を表現しない。
line coverage の向上だけでは、今回の境界条件は保証できない。

`tests/conftest.py` は direnv の検出だけを全体で mock しており、
一部の CLI テストは通常の監査関数を呼ぶ。
まず全テストで HOME と XDG state を隔離し、開発者の監査履歴に触れない構成にする。

追加する回帰層は次のとおり。

- 管理ブロックの可逆性、連続更新、不正入力を扱う table-driven tests。
- ダミーファイルだけを使う権限・symlink・並列更新・途中失敗のテスト。
- OS store の失敗とファイル保存の失敗を別々に注入する secret lifecycle tests。
- mock の TTY 判定に依存しない PTY/Bash/direnv 統合テスト。
- 複数プロセスと I/O 障害注入による audit の整合性・復旧テスト。
- helper の stdin/JSON、例外診断、scheme dispatch の contract tests。
- 専用のテスト用アイテムを使う macOS/Linux backend の opt-in 統合テスト。
- mock stage による並列 Make と失敗伝播、実 artifact の member/provenance、
  install 後の補完と最低 OS version の確認。

レビュー用の再現では実際の keychain、ユーザーの secret、対話式 OS 認証を使用しない。
Linux デスクトップの SecretService、Touch ID / Apple Watch、実機の電源断について
動作保証したものではない。
配布・インストール・公開、native helper の再ビルドも実施していない。
配布設定から推定した inclusion リスクや、既存文書に基づく OS 要件は、
実際の artifact を使った受け入れ確認と区別して記載した。
