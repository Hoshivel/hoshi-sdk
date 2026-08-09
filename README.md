# hoshi-sdk

Hoshivel 對外開放的共用實作：**零相依**的 Go 與 JavaScript 套件。

```
hoshi-sdk
├── go/    Go：kit/logging、kit/lifecycle、identity
└── js/    JavaScript：identity
```

三個套件的共同點是**它們與 Hoshivel 無關**——把服務換成任何一個團隊的服務，
它們一樣成立。這是東西能出現在這個倉庫的條件，見〈什麼會進這裡〉。

## 安裝

```sh
go get github.com/hoshivel/hoshi-sdk/go
```

```sh
npm install @hoshivel/hoshi-sdk
```

## 套件

| 套件 | 做什麼 |
|---|---|
| [`go/kit/logging`](go/kit/logging) | 服務的日誌：檔案輪替（按大小**與**日期）、保留期、敏感欄位遮蔽、執行期改層級 |
| [`go/kit/lifecycle`](go/kit/lifecycle) | 行程邊界的記錄：啟動、訊號、關機過程與各步驟耗時 |
| [`go/identity`](go/identity) | OpenID Connect 呼叫端：discovery、PKCE、token、userinfo、introspection、revocation、`id_token` RS256 驗簽 |
| [`js/src/identity.js`](js/src/identity.js) | 同上的 JavaScript 版（`OIDCClient`） |

### 兩件 `identity` 不讓你略過的事

- **端點一律來自 discovery。** 沒有任何 API 讓你寫死 `/oauth/token`。
  寫死的路徑會一直正常，直到部署形狀改變，然後在離原因很遠的地方壞掉。
- **`id_token` 先驗再用。** `VerifyIDToken` 檢查 RS256 簽章、issuer、audience、
  到期與 nonce。**持有一個 token 和驗過一個 token 是兩回事**，
  而一個回傳未驗證 claim 的套件會讓這個差別在呼叫端看不見。

## 零相依

`go/go.mod` 沒有 `require` 區塊，`js/package.json` 沒有 `dependencies`。
**這是硬性條件，不是現況。**

採用其中一個套件的服務**不該連帶繼承一整棵相依樹**——一個只是想要日誌輪替的
專案，不該因此多出十個間接相依與它們的更新節奏。

## 驗證

```sh
cd go && gofmt -l . && go build ./... && go vet ./... && go test -race ./...
cd js && npm test          # Node 內建 test runner，無建置步驟
```

`gofmt -l .` 須無輸出。

## 什麼會進這裡

四個條件，**缺一不可**：

1. 兩個以上獨立的使用者實際需要它；
2. 不含任何一家的業務規則；
3. 介面穩定、可測試、可版本化；
4. **這個介面適合對外承諾。**

第 4 條是這個倉庫與內部共用實作的分界。內部服務之間怎麼互相認證、呼叫、
交換資料，是內部平臺的事——那些東西前三條全過，但沒有 Hoshivel 以外的
消費者，公開只會把內部介面凍結在一個對外的相容承諾底下。

## 授權

[Apache License 2.0](LICENSE)。
