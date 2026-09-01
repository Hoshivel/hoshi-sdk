<!-- hoshivel:agent-rules v1 -> https://github.com/Hoshivel/workspace -->

# AGENTS.md — hoshi-sdk（公開）

> 共通流程以 [workspace](https://github.com/Hoshivel/workspace) 的 `AGENTS.md`
> 為準；本檔只列本倉庫規則。外部貢獻者只需讀 `README.md` 與 §2。

## 0. 開工前

1. 讀 `../workspace/focus.md` 與 `../workspace/AGENTS.md`；缺少時先
   `git clone https://github.com/Hoshivel/workspace.git ../workspace`，
   取不到就停止並說明。
2. 待辦與日誌在 `workspace/todo/hoshi-sdk/`、`workspace/logs/hoshi-sdk/`；
   不得在本倉庫另建副本。

## 1. 入場閱讀順序

1. `README.md`：收錄條件與公開邊界。
2. `go/README.md`、`js/README.md`：各語言 API 與用法。

## 2. 驗證

- Go：`cd go && gofmt -l . && go build ./... && go vet ./... && go test -race ./...`
- JS：`cd js && npm test`

`gofmt -l .` 必須無輸出；JS 無建置步驟。

## 3. 特殊規則

- 公開內容不得暴露私有拓撲、信任邊界、金鑰／簽章組成、內網位址、埠、路徑或
  部署結構，也不得指向私有倉庫內部路徑。
- Go 不得有 `require`；JS 不得有 dependencies、devDependencies 或 peerDependencies。
- 收錄內容必須同時符合：至少兩個獨立使用者、不含產品規則、介面穩定可測試可版本化、
  適合公開承諾。
- 套件、測試與範例不得知道 Hoshivel 服務名、角色名或內部協定路徑。
- 文件用正體中文，程式碼註解用英文。
