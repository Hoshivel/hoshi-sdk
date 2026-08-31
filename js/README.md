# @hoshivel/hoshi-sdk

零相依的 JavaScript OIDC client。原始碼即發佈內容，無建置步驟。需要 Node 18+
或支援 `fetch` 與 WebCrypto 的瀏覽器。

```sh
npm install @hoshivel/hoshi-sdk
```

| 匯入 | 內容 |
|---|---|
| `@hoshivel/hoshi-sdk/identity` | `OIDCClient` 與 identity helpers |
| `@hoshivel/hoshi-sdk` | 全部再匯出 |

## 使用

```js
import { OIDCClient, createPKCE, createState, SCOPE_OPENID, SCOPE_PROFILE }
  from "@hoshivel/hoshi-sdk/identity";

const client = new OIDCClient({
  issuer: "https://id.example.com",
  clientID,
  clientSecret, // 瀏覽器不得設定
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

callback：

```js
const tok = await client.exchange({ code, redirectURI, verifier: pkce.verifier });
const id = await client.verifyIdToken(tok.id_token, nonce);
```

端點只從 discovery 取得；`verifyIdToken` 通過前不得使用 claim。

## 登出

先清除本地 session，再導向供應者的 `end_session_endpoint`：

```js
const url = await client.endSessionURL({ idToken: tok.id_token, postLogoutRedirectURI });
```

discovery 未宣告端點時函式直接報錯，不猜測路徑。

## 驗證

```sh
npm test
```
