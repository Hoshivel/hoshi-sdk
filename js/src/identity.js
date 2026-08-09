/**
 * OpenID Connect 的 JavaScript relying-party client —— 依公開的 OIDC 規範實作，
 * 不綁定任何一家供應者。
 *
 * 涵蓋機器對機器的表面：discovery、token、userinfo、introspection、revocation，
 * 以及 id_token 的 RS256 驗簽。瀏覽器流程本身是呼叫端自己的事：
 * `authorizeURL()` 給出要把瀏覽器導去的位址，`exchange()` 接住回來的 code。
 *
 * ## 兩件這個套件不讓你略過的事
 *
 * **端點一律來自 discovery。** 沒有任何 API 讓你寫死 `/oauth/token`。寫死的路徑
 * 會一路正常，直到部署形狀改變（改掛子路徑、換網域），然後在離原因很遠的地方壞掉。
 *
 * **claims 回傳前先驗簽。** `verifyIdToken()` 檢查 RS256 簽章，然後檢查
 * issuer、audience、過期與 nonce。「持有 token」與「驗過 token」是兩件事，
 * 一個會回傳未驗證 claims 的套件會讓這個差別在呼叫點上看不見。
 *
 * ⚠️ **`clientSecret` 不該進瀏覽器。** 需要 client 認證的端點（token、
 * introspect、revoke）只能在伺服器端呼叫。瀏覽器裡只有 `authorizeURL()`、
 * `userInfo()` 與 `verifyIdToken()` 是安全的。
 *
 * 零相依。
 */

/** OpenID Connect 定義的 scope，外加供應者常用來回傳角色清單的 `roles`。 */
export const SCOPE_OPENID = "openid";
export const SCOPE_PROFILE = "profile";
export const SCOPE_EMAIL = "email";
export const SCOPE_ROLES = "roles";
export const SCOPE_OFFLINE_ACCESS = "offline_access";

/** UserInfo 的 sub 必須與這次登入已驗證的 id_token 相同。 */
export function assertUserInfoSubject(userInfo, idToken) {
  if (!userInfo?.sub || !idToken?.sub || userInfo.sub !== idToken.sub) {
    throw new IDTokenError("userinfo 的 sub 與已驗證的 id_token 不符");
  }
}

/** discovery 文件重抓前的快取時間，毫秒。它只有在部署改變時才會變。 */
const DISCOVERY_TTL_MS = 15 * 60 * 1000;

/**
 * 未知 kid 觸發 JWKS 重抓的最短間隔，毫秒。
 *
 * 遇到未知 kid 就重抓，是讓金鑰輪替變透明的作法。不限速的話，一串帶著捏造 kid
 * 的 token 就會變成一串對供應者的外連請求——等於把本行程的流量交到任何能遞出
 * token 的人手上。兩次重抓之間，未知的 kid 就是拒絕，而那本來就是偽造 token
 * 的正確答案。
 */
const JWKS_REFETCH_INTERVAL_MS = 60 * 1000;

/** exp／iat 檢查容許的時鐘偏移，秒。 */
const CLOCK_SKEW_SECONDS = 120;

const DEFAULT_TIMEOUT_MS = 15_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** OAuth 2.0 錯誤回應（RFC 6749 §5.2）。 */
export class OAuthError extends Error {
  constructor(code, { description, status } = {}) {
    super(description ? `identity: ${code}: ${description}` : `identity: ${code || status}`);
    this.name = "OAuthError";
    this.code = code;
    this.description = description;
    this.status = status;
  }
}

/** id_token 驗證失敗。**永遠不要**在收到這個之後繼續使用該 token 的 claims。 */
export class IDTokenError extends Error {
  constructor(message) {
    super(`identity: ${message}`);
    this.name = "IDTokenError";
  }
}

// ---- base64url ------------------------------------------------------------

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ---- PKCE -----------------------------------------------------------------

/**
 * 產生一組 PKCE（RFC 7636）。
 *
 * `verifier` 留在呼叫端——存在伺服器端的 session 裡，**不要放進 URL**——
 * `challenge` 送去授權端點。少了它，任何攔截到授權 code 的人都能把它換成 token。
 *
 * @returns {Promise<{verifier: string, challenge: string, method: "S256"}>}
 */
export async function createPKCE() {
  // 32 bytes → 43 個 base64url 字元，落在 RFC 7636 的 43–128 範圍內，
  // 且在它建議的熵上限。
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  const verifier = base64UrlEncode(buf);
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(verifier));
  return { verifier, challenge: base64UrlEncode(digest), method: "S256" };
}

/**
 * 產生 `state` 或 `nonce`。兩者都是一次性、不可猜測、且回來時要比對的：
 * state 比對呼叫端存的那個，nonce 比對 id_token 裡的 claim。
 * @returns {string}
 */
export function createState() {
  const buf = new Uint8Array(24);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

// ---- client ---------------------------------------------------------------

/**
 * 對著一個 OIDC 供應者。
 *
 * 這個物件會快取 discovery 與簽章金鑰，所以請留著重複使用，
 * 不要每個請求建一個。
 */
export class OIDCClient {
  /**
   * @param {object} options
   * @param {string} options.issuer 供應者的公開位址，不含尾斜線。
   *   它必須與每個被接受的 id_token 的 `iss` claim 相符。
   * @param {string} [options.clientID]
   * @param {string} [options.clientSecret] **不要在瀏覽器裡設定這個。**
   * @param {typeof fetch} [options.fetch]
   * @param {number} [options.timeoutMs]
   * @param {boolean} [options.allowInsecureHTTP] 只供明確信任的本機 transport
   */
  constructor({ issuer, clientID, clientSecret, fetch: fetchImpl, timeoutMs, allowInsecureHTTP = false } = {}) {
    if (!issuer) throw new Error("identity: 需要 issuer");
    const parsed = new URL(issuer);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && (loopback || allowInsecureHTTP))) {
      throw new Error("identity: 非 loopback 的 HTTP issuer 被禁止，請使用 HTTPS");
    }
    this.issuer = issuer.replace(/\/+$/, "");
    this.clientID = clientID;
    this.clientSecret = clientSecret;
    this.fetch = fetchImpl ?? globalThis.fetch;
    this.timeoutMs = timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  #discovery = null;
  #discoveredAt = 0;
  #keys = null; // {byKid: Map<string, CryptoKey>, fetchedAt: number}

  /** 目前時間，測試可覆寫。 */
  now() {
    return Date.now();
  }

  /**
   * 取得（並快取）供應者的 discovery 文件。
   * 其他所有方法都經過它，這就是路徑不會被寫死在呼叫端的原因。
   */
  async discover() {
    if (this.#discovery && this.now() - this.#discoveredAt < DISCOVERY_TTL_MS) {
      return this.#discovery;
    }
    const doc = await this.#json(
      "GET",
      `${this.issuer}/.well-known/openid-configuration`,
    );
    // 名字不是我們要的那個供應者的文件，不該成為驗證 token 的依據——
    // 不管它為什麼會從這個位址送出來。
    if (doc.issuer !== this.issuer) {
      throw new Error(
        `identity: discovery 的 issuer 是 ${doc.issuer}，與設定的 ${this.issuer} 不符`,
      );
    }
    this.#checkOrigin(doc);
    this.#discovery = doc;
    this.#discoveredAt = this.now();
    return doc;
  }

  /**
   * 每個宣告出來的端點都必須位於 issuer 自己的 origin。
   *
   * 上面的 issuer 比對只證明「這份文件說了對的名字」。一份保留 issuer、
   * 卻把 `token_endpoint` 指去別處的文件，會把 client secret 與授權碼
   * 送到那個主機，而呼叫端看起來一切正常——登入照樣成功，只是別人那邊也成功了。
   */
  #checkOrigin(doc) {
    const origin = new URL(this.issuer).origin;
    for (const field of [
      "authorization_endpoint",
      "token_endpoint",
      "userinfo_endpoint",
      "jwks_uri",
      "revocation_endpoint",
      "introspection_endpoint",
      "end_session_endpoint",
    ]) {
      // 供應者沒宣告的端點不算違規：它會在用到它的那次呼叫失敗，並說明原因。
      const raw = doc[field];
      if (!raw) continue;
      let target;
      try {
        target = new URL(raw);
      } catch {
        throw new Error(`identity: discovery 的 ${field}（${raw}）不是合法網址`);
      }
      if (target.origin !== origin || target.username || target.password || target.hash) {
        throw new Error(
          `identity: discovery 的 ${field}（${raw}）不在 issuer 的 origin ${origin} 上`,
        );
      }
    }
  }

  /**
   * 組出要把瀏覽器導去的登入位址。不會發出請求。
   *
   * @param {object} p
   * @param {string} p.redirectURI 必須與該 client 登錄的其中一個逐字相符
   * @param {string[]} [p.scopes] 缺 `openid` 會自動補上
   * @param {string} p.state 回來時要比對——它是 callback 與 CSRF 之間唯一的東西
   * @param {{challenge: string, method: string}} p.challenge 來自 `createPKCE()`
   * @param {string} [p.nonce] 會寫進 id_token，由 `verifyIdToken()` 比對
   * @param {"none"|"consent"} [p.prompt]
   * @returns {Promise<string>}
   */
  async authorizeURL({ redirectURI, scopes = [], state, challenge, nonce, prompt }) {
    if (!this.clientID) throw new Error("identity: 需要 clientID");
    if (!redirectURI) throw new Error("identity: 需要 redirectURI");
    // 沒有 state，callback 就分不出自己這次重導是不是別人造成的，所以不預設。
    if (!state) throw new Error("identity: 需要 state");
    if (!challenge?.challenge) {
      throw new Error("identity: 需要 challenge（用 createPKCE() 產生）");
    }

    const doc = await this.discover();
    const url = new URL(doc.authorization_endpoint);
    const requested = scopes.includes(SCOPE_OPENID)
      ? scopes
      : [SCOPE_OPENID, ...scopes];

    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.clientID);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("scope", requested.join(" "));
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", challenge.challenge);
    url.searchParams.set("code_challenge_method", challenge.method ?? "S256");
    if (nonce) url.searchParams.set("nonce", nonce);
    if (prompt) url.searchParams.set("prompt", prompt);
    return url.toString();
  }

  /**
   * 建立「結束供應者工作階段」的 URL（OpenID Connect RP-Initiated Logout）。
   *
   * 在共用登入的環境裡，清掉自己的 cookie 只是半個登出：供應者的工作階段還活著，
   * 使用者下次點登入會**靜默地**成功——看起來像登出從來沒發生過。
   * 清掉自己的工作階段之後，把瀏覽器送到這個 URL。
   *
   * 供應者沒有宣告 `end_session_endpoint` 時直接報錯，不猜路徑：
   * 一個猜出來、然後 404 的登出 URL，和一個成功的登出長得一模一樣。
   *
   * @param {object} p
   * @param {string} [p.idToken] 先前發放的 id_token，作為 hint。過期的仍可用；
   *   完全不給則供應者無從驗證 `postLogoutRedirectURI`，因此不會重導。
   * @param {string} [p.postLogoutRedirectURI] 必須與本 client 登錄的其中一個逐字相符
   * @param {string} [p.state] 原樣附加在重導位址上帶回
   * @returns {Promise<string>}
   */
  async endSessionURL({ idToken, postLogoutRedirectURI, state } = {}) {
    const doc = await this.discover();
    if (!doc.end_session_endpoint) {
      throw new Error("identity: 供應者未宣告 end_session_endpoint");
    }
    const url = new URL(doc.end_session_endpoint);
    if (idToken) url.searchParams.set("id_token_hint", idToken);
    if (postLogoutRedirectURI) {
      url.searchParams.set("post_logout_redirect_uri", postLogoutRedirectURI);
    }
    if (state) url.searchParams.set("state", state);
    return url.toString();
  }

  /**
   * 用授權 code 換 token。
   * `redirectURI` 必須與取得 code 那次相同，`verifier` 必須是送出的 challenge 的原文。
   */
  async exchange({ code, redirectURI, verifier }) {
    const doc = await this.discover();
    return this.#form(doc.token_endpoint, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      code_verifier: verifier,
    });
  }

  /**
   * 用 refresh token 換一組新的 token。
   * refresh token 可能被輪替：回應帶了新的就存新的、丟掉舊的。
   */
  async refresh(refreshToken) {
    const doc = await this.discover();
    return this.#form(doc.token_endpoint, {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
  }

  /**
   * 取得 access token 涵蓋的 claims。
   *
   * 只有 `sub` 保證存在；值為空的 claim **直接不出現**，
   * 所以缺欄位代表「沒授權或沒設定」，不會是「授權了但是空字串」。
   */
  async userInfo(accessToken) {
    if (!accessToken) throw new Error("identity: 需要 access token");
    const doc = await this.discover();
    return this.#json("GET", doc.userinfo_endpoint, { bearer: accessToken });
  }

  /**
   * 查詢 token 是否仍然有效。
   *
   * 不是本 client 發的 token 會回 `{active: false}` 而不是錯誤，
   * 所以 `active === false` 只代表「對你無效」，不代表別的。
   */
  async introspect(token) {
    const doc = await this.discover();
    return this.#form(doc.introspection_endpoint, { token });
  }

  /**
   * 撤銷 access 或 refresh token。
   * 撤銷不存在的 token 也成功（RFC 7009）——這個端點不是「token 存在嗎」的預言機。
   */
  async revoke(token) {
    const doc = await this.discover();
    await this.#form(doc.revocation_endpoint, { token }, { expectJSON: false });
  }

  /**
   * 驗證 id_token 的簽章與 claims，回傳它的內容。
   *
   * 檢查順序：JWT 格式 → `alg` 是 RS256 → 簽章金鑰已知 → 簽章驗過 →
   * `iss` 相符 → `aud` 含本 client → 未過期且非未來簽發 → `nonce` 相符。
   *
   * @param {string} idToken
   * @param {string} [nonce] 這次登入送出的 nonce；沒送過才傳空字串
   * @returns {Promise<object>} 驗過的 claims
   */
  async verifyIdToken(idToken, nonce = "") {
    const parts = String(idToken ?? "").split(".");
    if (parts.length !== 3) {
      throw new IDTokenError("id_token 不是三段式 JWT");
    }

    let header;
    try {
      header = JSON.parse(decoder.decode(base64UrlDecode(parts[0])));
    } catch {
      throw new IDTokenError("id_token 的 header 無法解析");
    }
    // 只接受 RS256。照 token 說的演算法走，正是 "alg": "none" 與
    // 「拿公鑰當 HMAC 密鑰」這兩個經典漏洞的入口——演算法是我們的決定，不是它的。
    if (header.alg !== "RS256") {
      throw new IDTokenError(`id_token 的 alg 是 ${header.alg}，應為 RS256`);
    }

    const key = await this.#signingKey(header.kid);
    const signed = encoder.encode(`${parts[0]}.${parts[1]}`);
    const verified = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      base64UrlDecode(parts[2]),
      signed,
    );
    if (!verified) {
      throw new IDTokenError("id_token 的簽章驗不過");
    }

    let claims;
    try {
      claims = JSON.parse(decoder.decode(base64UrlDecode(parts[1])));
    } catch {
      throw new IDTokenError("id_token 的 claims 無法解析");
    }

    if (claims.iss !== this.issuer) {
      throw new IDTokenError(`id_token 的 iss 是 ${claims.iss}，應為 ${this.issuer}`);
    }

    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!claims.sub) {
      throw new IDTokenError("id_token 沒有 sub claim");
    }
    if (!claims.iat) {
      throw new IDTokenError("id_token 沒有 iat claim");
    }
    if (this.clientID && !audience.includes(this.clientID)) {
      throw new IDTokenError(`id_token 的 aud (${audience.join(", ")}) 不含 ${this.clientID}`);
    }
    if (audience.length > 1 && !claims.azp) {
      throw new IDTokenError("多 audience 的 id_token 沒有 azp claim");
    }
    if (claims.azp && this.clientID && claims.azp !== this.clientID) {
      throw new IDTokenError(`id_token 的 azp 是 ${claims.azp}，應為 ${this.clientID}`);
    }

    const nowSeconds = Math.floor(this.now() / 1000);
    if (!claims.exp) {
      throw new IDTokenError("id_token 沒有 exp claim");
    }
    if (nowSeconds > claims.exp + CLOCK_SKEW_SECONDS) {
      throw new IDTokenError("id_token 已過期");
    }
    if (claims.iat && claims.iat > nowSeconds + CLOCK_SKEW_SECONDS) {
      throw new IDTokenError("id_token 的簽發時間在未來");
    }
    // 兩個方向都要管：送了 nonce 卻沒帶回來，代表這個 token 屬於另一個登入；
    // 沒送 nonce 卻帶了一個回來，代表它屬於一個不是我們發起的登入。
    if ((claims.nonce ?? "") !== nonce) {
      throw new IDTokenError("id_token 的 nonce 與送出的不符");
    }
    return claims;
  }

  // ---- 內部 --------------------------------------------------------------

  async #signingKey(kid) {
    if (this.#keys) {
      const cached = this.#keys.byKid.get(kid);
      if (cached) return cached;
      if (this.now() - this.#keys.fetchedAt < JWKS_REFETCH_INTERVAL_MS) {
        throw new IDTokenError(`id_token 由未知的金鑰 ${kid} 簽出`);
      }
    }
    const fetched = await this.#fetchJWKS();
    const key = fetched.byKid.get(kid);
    if (!key) {
      throw new IDTokenError(`id_token 由未知的金鑰 ${kid} 簽出`);
    }
    return key;
  }

  async #fetchJWKS() {
    const doc = await this.discover();
    const raw = await this.#json("GET", doc.jwks_uri);
    const byKid = new Map();

    for (const jwk of raw.keys ?? []) {
      // 不是 RSA 簽章金鑰就跳過，而不是讓整次抓取失敗：供應者可能發布
      // 我們用不到的金鑰，其中一把不該把可用的那些一起拖下水。
      if (jwk.kty !== "RSA" || (jwk.use && jwk.use !== "sig")) continue;
      try {
        const key = await crypto.subtle.importKey(
          "jwk",
          { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
          false,
          ["verify"],
        );
        byKid.set(jwk.kid, key);
      } catch {
        continue;
      }
    }
    if (byKid.size === 0) {
      throw new IDTokenError("jwks 裡沒有可用的 RSA 簽章金鑰");
    }
    this.#keys = { byKid, fetchedAt: this.now() };
    return this.#keys;
  }

  async #json(method, url, { bearer } = {}) {
    if (!url) throw new Error("identity: 此供應者沒有公告這個端點");
    const headers = new Headers({ Accept: "application/json" });
    if (bearer) headers.set("Authorization", `Bearer ${bearer}`);
    return this.#send(method, url, { headers });
  }

  async #form(url, fields, { expectJSON = true } = {}) {
    if (!url) throw new Error("identity: 此供應者沒有公告這個端點");
    if (!this.clientID || !this.clientSecret) {
      throw new Error("identity: 這個端點需要 clientID 與 clientSecret");
    }
    const headers = new Headers({
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      // client_secret_basic：密鑰放標頭而不是 body，才不會進到會記錄
      // post data 的請求日誌裡。
      Authorization: `Basic ${btoa(
        `${encodeURIComponent(this.clientID)}:${encodeURIComponent(this.clientSecret ?? "")}`,
      )}`,
    });
    const body = new URLSearchParams(fields).toString();
    return this.#send("POST", url, { headers, body, expectJSON });
  }

  async #send(method, url, { headers, body, expectJSON = true }) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    try {
      response = await this.fetch(url, {
        method,
        headers,
        body,
        signal: controller.signal,
        redirect: "manual",
      });
    } finally {
      clearTimeout(timer);
    }

    const text = await response.text();
    let parsed;
    try {
      parsed = text ? JSON.parse(text) : undefined;
    } catch {
      parsed = undefined;
    }

    if (!response.ok) {
      // 非 JSON 的錯誤內容（代理丟出來的 HTML 之類）不會被硬凹成一個假的
      // error code：code 留空，訊息退回狀態碼。
      throw new OAuthError(parsed?.error ?? "", {
        description: parsed?.error_description,
        status: response.status,
      });
    }
    return expectJSON ? parsed : undefined;
  }
}
