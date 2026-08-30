# hoshi-sdk

零相依的公開 Go 與 JavaScript 套件。

```text
hoshi-sdk/
├── go/   logging、lifecycle、identity
└── js/   identity
```

## 安裝

```sh
go get github.com/hoshivel/hoshi-sdk/go
npm install @hoshivel/hoshi-sdk
```

## 套件

| 套件 | 用途 |
|---|---|
| [`go/kit/logging`](go/kit/logging) | 日誌輪替、保留、遮蔽與執行期層級 |
| [`go/kit/lifecycle`](go/kit/lifecycle) | 啟動、訊號、關機步驟與耗時 |
| [`go/identity`](go/identity) | OIDC discovery、PKCE、token、userinfo、introspection、revocation、RS256 驗簽 |
| [`js/identity`](js/src/identity.js) | JavaScript `OIDCClient` |

identity client 強制從 discovery 取得端點，且只透過驗證 API 回傳 `id_token` claim。

## 收錄條件

內容必須同時符合：

1. 至少兩個獨立使用者實際需要；
2. 不含產品業務規則；
3. 介面穩定、可測試、可版本化；
4. 適合公開承諾。

Go `go.mod` 不得有 `require`；JS package 不得有任何 dependency 欄位。

## 驗證

```sh
cd go && gofmt -l . && go build ./... && go vet ./... && go test -race ./...
cd js && npm test
```

`gofmt -l .` 必須無輸出。JS 使用 Node 內建 test runner，無建置步驟。

## 授權

[Apache License 2.0](LICENSE)
