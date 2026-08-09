/**
 * @hoshivel/hoshi-sdk —— 零相依的 JavaScript client library。
 *
 *     import { OIDCClient } from "@hoshivel/hoshi-sdk/identity";
 *
 * 子路徑匯入只帶進你要的那一個模組；從這裡匯入則拿到全部。
 */

export {
  OIDCClient,
  OAuthError,
  IDTokenError,
  SCOPE_OPENID,
  SCOPE_PROFILE,
  SCOPE_EMAIL,
  SCOPE_ROLES,
  SCOPE_OFFLINE_ACCESS,
  createPKCE,
  createState,
  assertUserInfoSubject,
} from "./identity.js";
