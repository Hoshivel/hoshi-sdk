# hoshi-sdk/go

零相依的 Go 套件。

```sh
go get github.com/hoshivel/hoshi-sdk/go
```

| 套件 | 用途 |
|---|---|
| `kit/logging` | 日誌輪替、保留、敏感欄位遮蔽、執行期層級 |
| `kit/lifecycle` | 啟動、訊號、關機步驟與建置識別 |
| `identity` | OpenID Connect client |

## `kit/logging`

```go
logger, err := logging.New(logging.Options{
    Level:      "info",
    Format:     "json",
    File:       "/var/log/example/example.log",
    MaxSizeMB:  64,
    RetainDays: 30,
    MaxFiles:   14,
})
if err != nil {
    return err
}
defer logger.Close()
```

- 安裝為預設 `slog` logger。
- 同時按檔案大小與 UTC 日期輪替。
- 遮蔽 password、secret、token、authorization、cookie 及常見變體。
- `SetLevel` 可在執行期調整層級。

## `kit/lifecycle`

```go
op := lifecycle.Begin(logger, "load configuration")
cfg, err := load()
if err != nil {
    return op.Fail(err)
}
op.OK("path", cfg.Path)

sd := lifecycle.BeginShutdown(logger, "signal")
sd.Step("drain connections", drain())
sd.Done()
```

正常停止使用 `BeginShutdown`（info）；由錯誤逼停使用 `BeginFailure`（error）：

```go
sd := lifecycle.BeginFailure(logger, "listener failed", err, "addr", addr)
sd.Step("database", db.Close())
sd.Done()
```

訊號：

```go
sigctx, stop := lifecycle.NotifySignals(ctx)
defer stop()
<-sigctx.Done()
lifecycle.BeginShutdown(logger, sigctx.SignalName())
```

`lifecycle.BuildOf()` 讀取 Go build info，可輸出 commit、build time 與 dirty 狀態：

```go
log.Info("starting", append([]any{"addr", addr}, lifecycle.BuildOf().LogAttrs()...)...)
```

值為 `<revision>`、`<revision>+dirty` 或 `unknown`。

## `identity`

```go
client := &identity.Client{
    Issuer:       "https://id.example.com",
    ClientID:     clientID,
    ClientSecret: clientSecret,
}

pkce, err := identity.NewPKCE()
if err != nil {
    return err
}
url, err := client.AuthorizeURL(ctx, identity.AuthorizeRequest{
    RedirectURI: "https://app.example.com/callback",
    Scopes:      []string{identity.ScopeOpenID, identity.ScopeProfile},
    State:       state,
    Nonce:       nonce,
    PKCE:        pkce,
})
```

callback：

```go
tok, err := client.Exchange(ctx, code, redirectURI, pkce.Verifier)
if err != nil {
    return err
}
id, err := client.VerifyIDToken(ctx, tok.IDToken, nonce)
```

- discovery 文件的 issuer 必須相符，且所有端點必須與 issuer 同 origin。
- `VerifyIDToken` 通過前不得使用 claim。
- 授權只檢查呼叫端自己定義的角色，不把供應者管理角色視為等價。

## 驗證

```sh
gofmt -l .
go build ./...
go vet ./...
go test -race ./...
```
