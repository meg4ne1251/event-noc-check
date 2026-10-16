# 検証方法と対応範囲

初期実装はGo 1.26.3 / macOS 27.0.1 arm64でビルドし、次を実行しています。生の実測ログ、実際の端末アドレス、ネットワーク構成はこの文書やソースに含めません。

- `go test -race -cover ./...`: 公開ネットワーク不要の自動テスト。設定不正、期限到達、片系障害、DNS UDP/TCPの独立性、TLS証明書拒否、リダイレクト非追従、経路固定、AS照会対象外・キャッシュ、依存不足、ログ保存、CLIのJSONを確認。
- `go vet ./...`、gofmt、macOSネイティブビルド、Linux amd64向けクロスビルド。
- `NOC_CHECK_LOCAL_COMMANDS=1 go test ./internal/check -run TestLocalOSCommands -v`: 実ping・断片化禁止・UDP tracerouteをIPv4/IPv6ループバックで確認。
- `bin/noc-check --on-missing skip --format json`: 既定宛先を使う任意の実通信試験。全体期限・試行数を制限し、結果はGitで除外される `results/` にのみ保持。macOS dig互換性修正後には直接DNSとpingを追加確認。

macOSのIPv6断片化禁止は権限不足になり得ます。ループバック試験はこの場合に正しく `SKIP` を返すことも検証します。管理者権限での動作は未検証です。IPv6インターネット到達性や各OSのすべての外部コマンド実装を保証しません。

GitHub Actionsの `Test` ワークフローはUbuntu/macOSで自動テストと実コマンドのループバック試験を実行します。最新の実行状況はGitHub Actionsを参照してください。クロスビルドだけをLinuxでの実行成功とは扱いません。

外部サービスとネットワーク条件による失敗は、ソフトウェアのテスト成功とは別に判断してください。現場での採用前には対象OS、権限、依存コマンド、IPv4/IPv6の利用条件を揃えた再確認が必要です。
