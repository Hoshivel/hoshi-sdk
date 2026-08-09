# @hoshivel/hoshi-sdk

零相依的 JavaScript client library。**無建置步驟**——原始碼就是發佈的東西。

```sh
npm install @hoshivel/hoshi-sdk
```

| 匯入 | 內容 |
|---|---|
| `@hoshivel/hoshi-sdk/identity` | `OIDCClient`：discovery、PKCE、token、userinfo、`id_token` 驗簽 |
| `@hoshivel/hoshi-sdk` | 全部再匯出 |

需要 Node 18 以上（用到全域 `fetch` 與 WebCrypto），瀏覽器同樣可用。

## `identity`

```js
import { OIDCClient, createPKCE, createState, SCOPE_OPENID, SCOPE_PROFILE }
  from "@hoshivel/hoshi-sdk/identity";

const client = new OIDCClient({
  issuer: "https://id.example.com",
  clientID,
  clientSecret,          // 不要在瀏覽器裡設定這個
});

const pkce = await createPKCE();
const state = createState();

const url = await client.authorizeURL({
  redirectURI: "https://app.example.com/callback",
  scopes: [SCOPE_OPENID, SCOPE_PROFILE],
  state,
  challenge: pkce,
  nonce,
});
```

回來之後：

```js
const tok = await client.exchange({ code, redirectURI, verifier: pkce.verifier });
const id = await client.verifyIdToken(tok.id_token, nonce);
```

**端點一律來自 discovery。** 沒有任何 API 讓你寫死 `/oauth/token`——
寫死的路徑會一直正常，直到部署形狀改變，然後在離原因很遠的地方壞掉。

**`verifyIdToken` 之前不要讀 claim。** 持有一個 token 和驗過一個 token
是兩回事，而一個回傳未驗證 claim 的 API 會讓這個差別在呼叫端看不見。

### 登出

清掉自己的 cookie 只是半個登出：供應者的工作階段還活著，使用者下次點登入
會**靜默地**成功——看起來像登出從來沒發生過。清掉自己的工作階段之後，
把瀏覽器送到 `endSessionURL()`：

```js
const url = await client.endSessionURL({ idToken: tok.id_token, postLogoutRedirectURI });
```

供應者沒有宣告 `end_session_endpoint` 時它會直接報錯，不猜路徑——
一個猜出來、然後 404 的登出 URL，和一個成功的登出長得一模一樣。

## 驗證

```sh
npm test        # Node 內建 test runner
```
