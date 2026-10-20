/**
 * Why a login was refused for want of a session grant. Each surfaces as
 * `?error=<code>` on Better Auth's error page (the callback redirects there),
 * or as the `code` of a 401 on a route that answers JSON.
 */

/** The callback reached the session hook with nothing captured from the account write. */
export const GRANT_NOT_CAPTURED = "grant_not_captured";

/** The grant insert failed; the session was deleted. */
export const GRANT_NOT_CREATED = "grant_not_created";

/** Keycloak's token response carried no ID token. */
export const GRANT_ID_TOKEN_MISSING = "grant_id_token_missing";

/** The ID token has no `sid` or `sub` claim, so back-channel logout could never match it. */
export const GRANT_SID_MISSING = "grant_sid_missing";

/**
 * Keycloak's token response carried no usable `refresh_expires_in` (or
 * `expires_in`), so the session would have no realm bound.
 */
export const GRANT_REFRESH_EXPIRY_MISSING = "grant_refresh_expiry_missing";

/** A session was created by a route other than the Keycloak callback. */
export const GRANT_UNSUPPORTED_LOGIN = "grant_unsupported_login";

export type GrantErrorCode =
  | typeof GRANT_NOT_CAPTURED
  | typeof GRANT_NOT_CREATED
  | typeof GRANT_ID_TOKEN_MISSING
  | typeof GRANT_SID_MISSING
  | typeof GRANT_REFRESH_EXPIRY_MISSING
  | typeof GRANT_UNSUPPORTED_LOGIN;
