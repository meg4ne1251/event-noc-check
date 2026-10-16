# 開発・変更の進め方

まず [README.md](README.md)、[AGENTS.md](AGENTS.md)、[チェック仕様](docs/checks.md) を確認してください。Go製CLIを実装しています。検査条件を変える場合はREADMEとチェック仕様も更新してください。

## 変更の方針

- 現場の具体的な用途と、変更後にどう確認できるようになるかを説明する。
- IPv4・IPv6、DNSの通信経路とレコード種別を混同しない。
- OSごとのコマンドや権限の違いを確認し、確認済みの環境だけを記載する。
- CLIの表示、終了コード、JSONの構造を変えたら、関連する文書を更新する。
- 通常のCIは外部のネットワークや会場固有の環境に依存させない。

## 検証

コード変更では、成功時だけでなく、タイムアウト、IPv6のみ失敗、DNSのUDPのみ失敗、依存ツール不足など変更に関係する分岐を確認してください。実ネットワークでの確認は通常の自動テストと分け、送信先・回数・時間を制限します。

文書のみの変更では、内容の整合性、相対リンク、未実装機能の表示、公開情報の範囲を確認します。

## コミット・公開前の確認

```sh
git status --short
git diff
# 変更内容を確認したファイルだけを git add で指定
git diff --cached --check
git diff --cached
```

- 実測ログ、会場固有設定、パケットキャプチャ、認証情報を含めない。
- `.env.example` やサンプルもダミー値のみとする。
- 新しい出力やローカル専用ファイルには `.gitignore` の除外を追加する。
- 除外が効いているかは `git check-ignore -v <ファイル>` で確認する。
- `.gitignore` では追跡済みファイルや差分内の秘密情報は保護できない。
- ライセンスは未決定。公開前に採用方針を決め、必要なら `LICENSE` を追加する。

PRには変更の目的、挙動、実施した検証、未確認の環境を記載してください。

## ビルドとテスト

```sh
go build -o bin/noc-check ./cmd/noc-check
go test -race -cover ./...
go vet ./...
# 任意のOS実コマンド確認。宛先はループバックのみ
NOC_CHECK_LOCAL_COMMANDS=1 go test ./internal/check -run TestLocalOSCommands -v
```

標準テストは外部ネットワーク不要ですが、ローカルHTTP/TLSサーバーの待受を許可した環境が必要です。設定エラー、DNSの方式別障害、IPv6失敗、証明書不正、期限到達、依存不足、ログ保存の有無、JSON出力を確認します。OS実コマンドテストはmacOSのIPv6断片化禁止が権限不足になる環境でも、正しい `SKIP` を確認します。

`.github/workflows/test.yml` はUbuntu/macOSで同じテストとループバック試験を実行します。公開DNSへの問い合わせはCIに含めません。実通信が必要な場合のみ `bin/noc-check --on-missing skip` を明示実行してください。結果を保存する場合は `results/` か `reports/` とし、コミットしません。
