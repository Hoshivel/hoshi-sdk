<!-- hoshivel:agent-rules v1 -> https://github.com/Hoshivel/workspace -->

# AGENTS.md — hoshi-sdk（公開）

> **代理執行規範的正本不在這裡**，在
> [workspace](https://github.com/Hoshivel/workspace) 的 `AGENTS.md`：
> 四層記錄（焦點／todo／logs／decisions）、中斷復原流程、跨倉庫協作流程、
> 分支與 PR 規則全在那裡。
> 本檔只補上**這個倉庫自己的**東西。
>
> **本倉庫是公開的。** 外部貢獻者不需要 workspace——讀 `README.md` 與
> 下方 §2 的驗證指令就夠了。§0 是給 Hoshivel 自己的代理看的。

## 0. 開工前

**先取得 workspace，讀它的 `focus.md` 與 `AGENTS.md`。**

```sh
cat ../workspace/focus.md                                          # 本機：就在旁邊
git clone https://github.com/Hoshivel/workspace.git ../workspace   # 雲端：自己補上
```

- 取不到就**停下來告訴使用者**，不要退回在本倉庫自建 `TODO.md` 或工作記錄。
- **本倉庫的待辦在 `workspace/todo/hoshi-sdk/`**，工作日誌在 `workspace/logs/hoshi-sdk/`。
  **不得**自建 `TODO.md`／`logs/`，也不得記錄領取、分支或 `Status: Editing`
  （workspace `AGENTS.md` §4.4、§5）。
- 續接既有任務時**沿用該事項記的分支與 PR**，不要另開新分支
  （workspace `AGENTS.md` §4.3）。

## 1. 入場閱讀順序

1. `README.md` —— 本倉庫的定位，以及**什麼會進這裡**（四個條件）。
2. `go/README.md`／`js/README.md` —— 各語言的套件說明與用法。

## 2. 驗證

改碼後在對應層執行；綠燈再更新該事項的 `Status:`（`Editing` → `待驗證`）：

- **Go（`go/`）**：`gofmt -l .`（須無輸出）、`go build ./...`、`go vet ./...`、
  `go test -race ./...`
- **JS（`js/`）**：`npm test`（Node 內建 test runner，**無建置步驟**）

## 3. 這個倉庫的特殊規則

- **這是公開倉庫。不得放進任何內部的東西。** 判準是 workspace `AGENTS.md`
  §1.10.1 那一句：**這段文字讓讀者更容易攻擊我們嗎？** 具體不得出現——
  內部架構與服務拓撲、資料流與信任邊界、金鑰與簽章的組成方式、主機名稱與
  內網位址、埠與路徑的對應、部署結構、指向私有倉庫內容的路徑。
  **倉庫名稱與連結本身可以**。
- **零相依是硬性條件**：`go/go.mod` 不得有 `require` 區塊，
  `js/package.json` 不得有 `dependencies`／`devDependencies`／`peerDependencies`。
  採用單一套件的專案不該因此繼承一棵相依樹。
- **收東西進來要過四個條件**（見 `README.md`）。第 4 條「這個介面適合對外承諾」
  是本倉庫與內部共用實作的分界：前三條在判斷「能不能被共用」，
  只有第 4 條在判斷「能不能公開」。
- **這裡的套件不得知道 Hoshivel 的存在。** 不得出現自家服務名、自家角色名、
  自家協定的路徑——包含測試夾具。一個綁著某家服務的套件放在這裡，
  對外面的人沒有用，對內部則是把介面凍結在錯的地方。
- 文件與註解沿用倉庫既有風格：**正體中文為主**（程式碼註解英文），
  狀態關鍵字（`Status:` 的那幾個值）保持原樣以利機器辨識。
