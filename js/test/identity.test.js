import { strict as assert } from "node:assert";
import { test, describe, before } from "node:test";

import {
  OIDCClient,
  IDTokenError,
  OAuthError,
  SCOPE_EMAIL,
  createPKCE,
  createState,
} from "../src/identity.js";

const ISSUER = "https://id.example.test";
const CLIENT_ID = "test-client";
const CLIENT_SECRET = "test-secret";

const encoder = new TextEncoder();

function base64Url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// 一組真的 RSA 金鑰，只產生一次：2048-bit 產生的成本足以主導整個測試套件。
let keyPair;
let otherKeyPair;
let publicJWK;

before(async () => {
  const params = {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: "SHA-256",
  };
  keyPair = await crypto.subtle.generateKey(params, true, ["sign", "verify"]);
  otherKeyPair = await crypto.subtle.generateKey(params, true, ["sign", "verify"]);
  publicJWK = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
});

/** 用真的金鑰簽出一個真的 JWT。 */
async function signToken(claims, { kid = "key-1", alg = "RS256", key } = {}) {
  const header = base64Url(encoder.encode(JSON.stringify({ alg, kid, typ: "JWT" })));
  const payload = base64Url(encoder.encode(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key ?? keyPair.privateKey,
    encoder.encode(`${header}.${payload}`),
  );
  return `${header}.${payload}.${base64Url(signature)}`;
}

function validClaims(overrides = {}) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    sub: "usr_1",
    aud: CLIENT_ID,
    exp: nowSeconds + 3600,
    iat: nowSeconds - 60,
    nonce: "n-1",
    email: "ann@example.com",
    email_verified: true,
    name: "Ann",
    roles: ["billing.admin"],
    ...overrides,
  };
}

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

/**
 * 一個假的 OIDC 供應者。它送出真的 discovery 文件、真的 JWKS、真的簽章——
 * 走的是實機供應者會走的同一條路，而不是一個「照建構方式必然同意 client」的 mock。
 */
function fakeProvider({ kid = "key-1", overrides = {} } = {}) {
  const hits = { discovery: 0, jwks: 0 };
  let lastForm = null;
  let lastAuth = null;

  const routes = {
    [`GET ${ISSUER}/.well-known/openid-configuration`]: () => {
      hits.discovery += 1;
      return json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/oauth/authorize`,
        token_endpoint: `${ISSUER}/oauth/token`,
        userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
        jwks_uri: `${ISSUER}/oauth/jwks.json`,
        revocation_endpoint: `${ISSUER}/oauth/revoke`,
        introspection_endpoint: `${ISSUER}/oauth/introspect`,
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: ["S256"],
        ...overrides,
      });
    },
    [`GET ${ISSUER}/oauth/jwks.json`]: () => {
      hits.jwks += 1;
      return json({
        keys: [{ kty: "RSA", kid: provider.kid, use: "sig", alg: "RS256", n: publicJWK.n, e: publicJWK.e }],
      });
    },
    [`POST ${ISSUER}/oauth/token`]: (init) => {
      lastForm = new URLSearchParams(init.body);
      lastAuth = init.headers.get("Authorization");
      if (lastForm.get("code") === "bad-code") {
        return json({ error: "invalid_grant" }, 400);
      }
      return json({
        access_token: "at_live",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "rt_live",
        scope: "openid profile email roles",
      });
    },
    [`GET ${ISSUER}/oauth/userinfo`]: (init) => {
      if (init.headers.get("Authorization") !== "Bearer at_live") {
        return json({ error: "invalid_token" }, 401);
      }
      return json({
        sub: "usr_1",
        email: "ann@example.com",
        email_verified: true,
        name: "Ann",
        roles: ["billing.admin"],
      });
    },
    [`POST ${ISSUER}/oauth/introspect`]: (init) => {
      const form = new URLSearchParams(init.body);
      if (form.get("token") !== "at_live") return json({ active: false });
      return json({ active: true, sub: "usr_1", client_id: CLIENT_ID, token_type: "Bearer" });
    },
    [`POST ${ISSUER}/oauth/revoke`]: () => new Response("", { status: 200 }),
  };

  const provider = {
    kid,
    hits,
    get lastForm() {
      return lastForm;
    },
    get lastAuth() {
      return lastAuth;
    },
    fetch: async (url, init = {}) => {
      const handler = routes[`${init.method ?? "GET"} ${url}`];
      if (!handler) return json({ error: "not_found" }, 404);
      return handler(init);
    },
  };
  return provider;
}

function newClient(provider, extra = {}) {
  return new OIDCClient({
    issuer: ISSUER,
    clientID: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    fetch: provider.fetch,
    ...extra,
  });
}

// ---- discovery -------------------------------------------------------------

describe("discovery", () => {
  test("抓一次之後就快取", async () => {
    const provider = fakeProvider();
    const client = newClient(provider);

    const doc = await client.discover();
    assert.equal(doc.token_endpoint, `${ISSUER}/oauth/token`);
    await client.discover();
    assert.equal(provider.hits.discovery, 1);
  });

  test("issuer 不符就拒絕", async () => {
    // 名字不是我們要的那個供應者的文件，不該成為驗證 token 的依據。
    const provider = fakeProvider({ overrides: { issuer: "https://elsewhere.example.test" } });
    const client = newClient(provider);
    await assert.rejects(() => client.discover(), /不符/);
  });

  test("端點指到 issuer 以外的 origin 就拒絕", async () => {
    // 重點是這個形狀：issuer 是對的，被換掉的是端點。一份這樣的文件會把
    // client secret 與授權碼送去別人的主機，而呼叫端看不出任何異狀。
    for (const field of [
      "authorization_endpoint",
      "token_endpoint",
      "userinfo_endpoint",
      "jwks_uri",
      "revocation_endpoint",
      "introspection_endpoint",
      "end_session_endpoint",
    ]) {
      const provider = fakeProvider({
        overrides: { [field]: "https://attacker.example.test/oauth/collect" },
      });
      await assert.rejects(
        () => newClient(provider).discover(),
        new RegExp(`${field}.*origin`),
        `${field} 指到別的 origin 必須被拒絕`,
      );
    }
  });

  test("供應者沒宣告的選用端點不算違規", async () => {
    // 宣告得比較少的供應者不等於被竄改過的供應者：缺的那個端點會在用到它的
    // 那次呼叫失敗，而不是讓整份 discovery 不能用。
    const provider = fakeProvider({ overrides: { end_session_endpoint: undefined } });
    const client = newClient(provider);
    await client.discover();
    await assert.rejects(() => client.endSessionURL({}), /end_session_endpoint/);
  });
});

// ---- PKCE ------------------------------------------------------------------

describe("PKCE", () => {
  test("challenge 是 verifier 的 SHA-256", async () => {
    const pkce = await createPKCE();
    const digest = await crypto.subtle.digest("SHA-256", encoder.encode(pkce.verifier));
    assert.equal(pkce.challenge, base64Url(digest));
    assert.equal(pkce.method, "S256");
    assert.ok(pkce.verifier.length >= 43, "RFC 7636 要求至少 43 字元");
  });

  test("state 每次都不同", () => {
    const seen = new Set();
    for (let i = 0; i < 200; i += 1) seen.add(createState());
    assert.equal(seen.size, 200);
  });
});

// ---- authorize -------------------------------------------------------------

describe("authorizeURL", () => {
  test("帶齊參數，並自動補上 openid", async () => {
    const client = newClient(fakeProvider());
    const pkce = await createPKCE();

    const url = new URL(await client.authorizeURL({
      redirectURI: "https://app.example.test/cb",
      scopes: [SCOPE_EMAIL],
      state: "st-1",
      challenge: pkce,
      nonce: "n-1",
    }));

    assert.equal(url.searchParams.get("response_type"), "code");
    assert.equal(url.searchParams.get("client_id"), CLIENT_ID);
    assert.equal(url.searchParams.get("state"), "st-1");
    assert.equal(url.searchParams.get("nonce"), "n-1");
    assert.equal(url.searchParams.get("code_challenge"), pkce.challenge);
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");

    const scope = url.searchParams.get("scope");
    assert.ok(scope.includes("openid"), "openid 應被自動補上");
    assert.ok(scope.includes("email"));
  });

  test("缺 state 或 challenge 就拒絕", async () => {
    const client = newClient(fakeProvider());
    const pkce = await createPKCE();

    await assert.rejects(
      () => client.authorizeURL({ redirectURI: "https://a.test/cb", challenge: pkce }),
      /state/,
    );
    await assert.rejects(
      () => client.authorizeURL({ redirectURI: "https://a.test/cb", state: "st" }),
      /challenge/,
    );
  });
});

// ---- token -----------------------------------------------------------------

describe("token endpoint", () => {
  test("exchange 送出 PKCE，密鑰走 Basic 而不是 body", async () => {
    const provider = fakeProvider();
    const client = newClient(provider);

    const tokens = await client.exchange({
      code: "ac_1",
      redirectURI: "https://app.example.test/cb",
      verifier: "verifier-1",
    });
    assert.equal(tokens.access_token, "at_live");
    assert.equal(provider.lastForm.get("grant_type"), "authorization_code");
    assert.equal(provider.lastForm.get("code_verifier"), "verifier-1");

    // 密鑰放標頭而不是 body，才不會進到會記錄 post data 的請求日誌裡。
    assert.ok(provider.lastAuth.startsWith("Basic "));
    assert.equal(provider.lastForm.get("client_secret"), null);
  });

  test("把 OAuth 錯誤帶上來", async () => {
    const client = newClient(fakeProvider());
    await assert.rejects(
      () => client.exchange({ code: "bad-code", redirectURI: "https://a.test/cb", verifier: "v" }),
      (err) => {
        assert.ok(err instanceof OAuthError);
        assert.equal(err.code, "invalid_grant");
        return true;
      },
    );
  });

  test("refresh 用 refresh_token grant", async () => {
    const provider = fakeProvider();
    const client = newClient(provider);
    await client.refresh("rt_live");
    assert.equal(provider.lastForm.get("grant_type"), "refresh_token");
    assert.equal(provider.lastForm.get("refresh_token"), "rt_live");
  });
});

// ---- userinfo / introspect / revoke ----------------------------------------

describe("userinfo、introspect、revoke", () => {
  test("userInfo 回傳 claims", async () => {
    const client = newClient(fakeProvider());
    const info = await client.userInfo("at_live");
    assert.equal(info.sub, "usr_1");
    assert.equal(info.email_verified, true);
    assert.ok(info.roles.includes("billing.admin"));
    assert.ok(!info.roles.includes("platform_admin"));
  });

  test("token 無效時丟 invalid_token", async () => {
    const client = newClient(fakeProvider());
    await assert.rejects(
      () => client.userInfo("at_wrong"),
      (err) => err.code === "invalid_token",
    );
  });

  test("未知的 token 是成功的查詢、否定的答案", async () => {
    const client = newClient(fakeProvider());
    const result = await client.introspect("at_unknown");
    assert.equal(result.active, false);
    assert.equal(result.sub, undefined, "inactive 的結果不該洩漏 subject");
  });

  test("revoke 成功", async () => {
    const client = newClient(fakeProvider());
    await client.revoke("at_live");
  });
});

// ---- id_token --------------------------------------------------------------

describe("verifyIdToken", () => {
  test("驗過的 token 回傳 claims", async () => {
    const client = newClient(fakeProvider());
    const claims = await client.verifyIdToken(await signToken(validClaims()), "n-1");
    assert.equal(claims.sub, "usr_1");
    assert.equal(claims.email, "ann@example.com");
  });

  test("aud 是陣列也接受", async () => {
    const client = newClient(fakeProvider());
    const token = await signToken(validClaims({ aud: ["another-client", CLIENT_ID], azp: CLIENT_ID }));
    const claims = await client.verifyIdToken(token, "n-1");
    assert.equal(claims.sub, "usr_1");
  });

  // 每個案例都從一個「會驗過」的 token 出發，只破壞一件事，
  // 所以通過就代表確實是那一項檢查擋下的。
  const rejections = [
    {
      name: "不是三段式 JWT",
      token: async () => "not.a",
      nonce: "n-1",
      want: /三段式/,
    },
    {
      name: "alg 不是 RS256",
      // "none" 與「拿公鑰當 HMAC 密鑰」都以「非預期的 alg」的形式出現。
      token: () => signToken(validClaims(), { alg: "none" }),
      nonce: "n-1",
      want: /alg/,
    },
    {
      name: "由供應者沒公告的金鑰簽出",
      token: () => signToken(validClaims(), { key: undefined, kid: "key-1" }),
      nonce: "n-1",
      useOtherKey: true,
      want: /簽章驗不過/,
    },
    {
      name: "未知的 kid",
      token: () => signToken(validClaims(), { kid: "does-not-exist" }),
      nonce: "n-1",
      want: /未知的金鑰/,
    },
    {
      // spec IDTokenClaims 驗證程序第 6 條。不在早期「iss／aud／exp／nonce」
      // 清單裡，所以重寫實作時特別容易漏掉。
      name: "缺 sub",
      token: () => {
        const c = validClaims();
        delete c.sub;
        return signToken(c);
      },
      nonce: "n-1",
      want: /sub/,
    },
    {
      // 同上，第 7 條。
      name: "缺 iat",
      token: () => {
        const c = validClaims();
        delete c.iat;
        return signToken(c);
      },
      nonce: "n-1",
      want: /iat/,
    },
    {
      name: "iss 是別人",
      token: () => signToken(validClaims({ iss: "https://elsewhere.example.test" })),
      nonce: "n-1",
      want: /iss/,
    },
    {
      name: "aud 是另一個 client",
      token: () => signToken(validClaims({ aud: "someone-else" })),
      nonce: "n-1",
      want: /aud/,
    },
    {
      name: "已過期",
      token: () => signToken(validClaims({ exp: Math.floor(Date.now() / 1000) - 3600 })),
      nonce: "n-1",
      want: /過期/,
    },
    {
      name: "簽發時間在未來",
      token: () => signToken(validClaims({ iat: Math.floor(Date.now() / 1000) + 3600 })),
      nonce: "n-1",
      want: /未來/,
    },
    {
      name: "nonce 屬於另一個登入",
      token: () => signToken(validClaims()),
      nonce: "n-2",
      want: /nonce/,
    },
    {
      name: "沒送 nonce 卻帶了一個回來",
      token: () => signToken(validClaims()),
      nonce: "",
      want: /nonce/,
    },
  ];

  for (const tc of rejections) {
    test(`拒絕：${tc.name}`, async () => {
      const client = newClient(fakeProvider());
      const token = tc.useOtherKey
        ? await signToken(validClaims(), { key: otherKeyPair.privateKey })
        : await tc.token();
      await assert.rejects(
        () => client.verifyIdToken(token, tc.nonce),
        (err) => {
          assert.ok(err instanceof IDTokenError, `應為 IDTokenError，實得 ${err}`);
          assert.match(err.message, tc.want);
          return true;
        },
      );
    });
  }

  test("未知 kid 的重抓有限速", async () => {
    const provider = fakeProvider();
    const client = newClient(provider);

    await client.verifyIdToken(await signToken(validClaims()), "n-1");
    assert.equal(provider.hits.jwks, 1);

    // 一串帶著捏造 kid 的 token 不該變成一串外連請求——那等於把本行程的
    // 流量交到任何能遞出 token 的人手上。
    for (let i = 0; i < 5; i += 1) {
      const forged = await signToken(validClaims(), { kid: "made-up" });
      await assert.rejects(() => client.verifyIdToken(forged, "n-1"));
    }
    assert.equal(provider.hits.jwks, 1, "5 個未知 kid 之後仍應只抓過一次");

    // 過了間隔之後，真正的金鑰輪替要能被接上。
    const realNow = client.now.bind(client);
    client.now = () => realNow() + 5 * 60 * 1000;
    provider.kid = "key-2";

    const rotated = await signToken(validClaims(), { kid: "key-2" });
    const claims = await client.verifyIdToken(rotated, "n-1");
    assert.equal(claims.sub, "usr_1");
    assert.equal(provider.hits.jwks, 2);
  });
});
