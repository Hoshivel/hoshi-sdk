# hoshi-sdk/go

零相依的 Go 套件。

```sh
go get github.com/hoshivel/hoshi-sdk/go
```

| 套件 | 做什麼 |
|---|---|
| `kit/logging` | 服務的日誌：檔案輪替、保留期、敏感欄位遮蔽、執行期改層級 |
| `kit/lifecycle` | 行程邊界的記錄：啟動、訊號、關機過程與各步驟耗時 |
| `identity` | OpenID Connect 呼叫端 |

`go.mod` 沒有 `require` 區塊，也不會長出一個——見倉庫根的 `README.md`。

## `kit/logging`

一個行程一個 logger，安裝成 `slog` 的預設值，所以任何用 `slog` 的程式庫
寫出來的東西都會落在同一個地方、同一種格式。

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

**輪替同時看大小與日期。** 只看大小的話，一個安靜的服務永遠不會輪替，
於是沒有任何檔案「舊」到該被刪掉——「保留 N 天」會被設定、被逐字遵守，
然後完全沒有效果。

**敏感欄位會被遮蔽**：`password`、`secret`、`token`、`authorization`、
`cookie`、`client_secret`、`id_token` 等等，以及它們的常見變體
（`smtp_password`、`control.secret`）。

層級可以在執行期改（`SetLevel`），不必重啟。

## `kit/lifecycle`

它記錄的是**行程的一生**，不是日誌管線——所以和 `kit/logging` 分開。
它接受任何能寫四個層級的東西，`*slog.Logger` 就滿足：

```go
op := lifecycle.Begin(logger, "load configuration")
cfg, err := load()
if err != nil {
    return op.Fail(err)      // 記錄失敗並把 err 原樣回傳
}
op.OK("path", cfg.Path)

sd := lifecycle.BeginShutdown(logger, "signal")
sd.Step("drain connections", drain())
sd.Done()
```

訊號等待也在這裡：

```go
sigctx, stop := lifecycle.NotifySignals(ctx)
defer stop()
<-sigctx.Done()
lifecycle.BeginShutdown(logger, sigctx.SignalName())
```

## `identity`

OpenID Connect 呼叫端。機器對機器的表面都在這裡：discovery、token、
userinfo、introspection、revocation、`id_token` 的 RS256 驗簽。
瀏覽器流程是呼叫端自己的事——`AuthorizeURL` 給出要導去的位址，
`Exchange` 接住回來的 code。

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

回來之後：

```go
tok, err := client.Exchange(ctx, code, redirectURI, pkce.Verifier)
if err != nil {
    return err
}
id, err := client.VerifyIDToken(ctx, tok.IDToken, nonce)
```

**端點一律來自 discovery**，而 discovery 說的話會先被檢查：文件必須指名
它自己是為哪個 issuer 取來的，而且每個端點都必須落在該 issuer 自己的 origin 上。

**`VerifyIDToken` 之前不要讀 claim。** 持有一個 token 和驗過一個 token
是兩回事；一個回傳未驗證 claim 的 API 會讓這個差別在呼叫端看不見。

檢查角色時，檢查**你自己服務定義的角色**——供應者層級的管理員角色不等於
你這個服務的管理員，把它當成一回事會安靜地放寬誰可以動手。

## 驗證

```sh
gofmt -l .          # 須無輸出
go build ./...
go vet ./...
go test -race ./...
```
