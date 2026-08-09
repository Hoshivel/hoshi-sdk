import test from "node:test";
import assert from "node:assert/strict";

import { OIDCClient, assertUserInfoSubject } from "../src/identity.js";

test("遠端明文 HTTP 預設被拒絕", () => {
  assert.throws(
    () => new OIDCClient({ issuer: "http://id.example" }),
    /HTTPS/,
  );
});

test("loopback 的明文 HTTP 可以，那是本機開發唯一的出口", () => {
  assert.doesNotThrow(() => new OIDCClient({ issuer: "http://127.0.0.1:8080" }));
  assert.doesNotThrow(() => new OIDCClient({ issuer: "http://localhost:8080" }));
});

test("userinfo subject 必須等於已驗證 id_token", () => {
  // 不比對的話，一個攻擊者可以拿自己的 access token 去換別人的 userinfo，
  // 而呼叫端看到的是一次成功的登入。
  assert.doesNotThrow(() => assertUserInfoSubject({ sub: "usr_1" }, { sub: "usr_1" }));
  assert.throws(() => assertUserInfoSubject({ sub: "usr_2" }, { sub: "usr_1" }), /sub/);
  assert.throws(() => assertUserInfoSubject({}, { sub: "usr_1" }), /sub/);
});
