/** Keycloak owns user.username; Better Auth migrates the optional column and refreshes
 * mapped user fields on each login, including users created before this field existed. */
import type { BetterAuthOptions } from "better-auth";
import { genericOAuth, keycloak } from "better-auth/plugins/generic-oauth";
import type { Kysely } from "kysely";

import type { CookieNamePolicy, KeycloakAuthConfig } from "./config.js";
import { AUTH_BASE_PATH, COOKIE_PREFIX } from "./constants.js";
import { exposedRoutesFor, exposeRoutes, stripProviderTokens } from "./exposure.js";
import {
  composeAfterHooks,
  composeBeforeHooks,
  recordCallbackStart,
} from "./grants/callback-start.js";
import { grantHooks } from "./grants/grant-hooks.js";
import type { GrantStore } from "./grants/grant-store.js";
import { keycloakAccountSubject, mapKeycloakProfile } from "./keycloak-profile.js";
import { keycloakUserFields } from "./keycloak-user.js";
import type { AuthLogger } from "./logger.js";
import { backchannelLogout } from "./logout/backchannel.js";
import { captureSignOut, finishSignOut } from "./logout/sign-out.js";

/**
 * `openid` is listed even though discovery would add it: when discovery fails
 * at startup the provider runs as plain OAuth and would not request it.
 * Roles, groups, tenants and audiences arrive as the realm's default client
 * scopes, so they are not requested here.
 */
export const KEYCLOAK_SCOPES = ["openid", "profile", "email"];

/** What `createKeycloakAuthOptions` stores sessions, users and accounts in. */
export type AuthDatabase = BetterAuthOptions["database"];

/**
 * Better Auth's built-in Kysely support over the host's pool, the runtime
 * store. `schemaName` qualifies every statement, so the runtime never depends
 * on `search_path`.
 *
 * `transaction` must be set: Better Auth forwards this shape's flag as it is
 * and treats unset as false (a raw `pg.Pool` would get it on by default), and
 * without it `createOAuthUser` commits the `user` row before a failing
 * `account` insert.
 */
export const createPostgresStore = (db: Kysely<unknown>, schemaName: string) =>
  ({ db, type: "postgres", schemaName, transaction: true }) satisfies AuthDatabase;

/**
 * The cookie part of Better Auth's `advanced` options for a cookie-name policy
 * and a cookie prefix (`COOKIE_PREFIX`, `interlock`, unless the host names
 * its own).
 *
 * Better Auth names every cookie through one getter, as
 * `${secureCookiePrefix}${cookiePrefix}.${kind}`, where the secure prefix is
 * `__Secure-` while `useSecureCookies` is on and empty otherwise. The OAuth
 * `state` cookie goes through the same getter, so `cookiePrefix` covers it
 * without listing kinds. A plugin that calls `ctx.setCookie` with a name of
 * its own bypasses this, so audit a plugin's cookies before adding it.
 *
 * - `host`: secure cookies off and `cookiePrefix` `__Host-<prefix>`, so every
 *   name is literally `__Host-<prefix>.<kind>` and browsers enforce `__Host-`.
 * - `secure`: Better Auth's own `__Secure-<prefix>.<kind>`.
 *
 * Both pin `Secure` rather than letting Better Auth infer it from the base
 * URL. An `http` BETTER_AUTH_URL then yields cookies a browser drops, which
 * fails closed instead of issuing an unprefixed, insecure session cookie.
 */
export function cookieSettings(policy: CookieNamePolicy, prefix = COOKIE_PREFIX) {
  return {
    useSecureCookies: policy === "secure",
    cookiePrefix: policy === "host" ? `__Host-${prefix}` : prefix,
    defaultCookieAttributes: { secure: true },
  } satisfies BetterAuthOptions["advanced"];
}

/**
 * The receiver's route under the base path: the host's configuration holds
 * the back-channel logout path under it, so the rest is the route.
 */
export const receiverRouteOf = (config: Pick<KeycloakAuthConfig, "keycloak">) =>
  config.keycloak.backchannelLogoutPath.slice(AUTH_BASE_PATH.length);

/**
 * Better Auth's log calls, as records the host logger can redact. Better
 * Auth's own arguments go under `args` as they are, and can hold tokens.
 */
const betterAuthLog =
  (logger: AuthLogger): NonNullable<BetterAuthOptions["logger"]>["log"] =>
  (level, message, ...args) => {
    // Some of Better Auth's own messages already carry the tag.
    const record = {
      message: `[better-auth] ${message.replace(/^\[better-auth\]\s*/i, "")}`,
      args,
    };
    switch (level) {
      case "error":
        logger.error(record);
        break;
      case "warn":
        logger.warn(record);
        break;
      case "debug":
        logger.debug(record);
        break;
      default:
        logger.log(record);
    }
  };

/** What `createKeycloakAuthOptions` builds on besides the configuration. */
export interface KeycloakAuthOptions {
  /**
   * Where sessions, users and accounts live: `createPostgresStore` at
   * runtime, a memory store in unit tests.
   */
  database: AuthDatabase;
  /** Where the grant hooks write each session's provider tokens. */
  grants: GrantStore;
  /**
   * Where the hooks, the receiver, sign-out and Better Auth itself log. The
   * host's logger redacts; see `AuthLogger`.
   */
  logger: AuthLogger;
  /** The base of every cookie name; `COOKIE_PREFIX` unless given. */
  cookiePrefix?: string;
}

/**
 * Builds the Better Auth options for a Keycloak login with session-scoped
 * grants from validated configuration and the stores, logger and cookie
 * prefix in `options`. Pure: nothing connects until Better Auth initializes.
 */
export function createKeycloakAuthOptions(
  config: KeycloakAuthConfig,
  { database, grants, logger, cookiePrefix = COOKIE_PREFIX }: KeycloakAuthOptions,
): BetterAuthOptions {
  // Without a database Better Auth 1.7 silently switches to its stateless
  // mode, with the session and the provider tokens in encrypted cookies.
  if (!database) {
    throw new Error("Better Auth needs a database; without one it keeps sessions in cookies");
  }
  // Without the grant hooks the account row would keep the provider tokens
  // and no session would have a grant.
  if (!grants) {
    throw new Error("Better Auth needs a grant store; without one the provider tokens are lost");
  }
  // A missing logger would surface as a crash inside a hook, mid-request.
  if (!logger) {
    throw new Error("Better Auth needs a logger; the hooks and the receiver report through it");
  }
  const issuer = config.keycloak.issuer.replace(/\/+$/, "");
  const endpoint = (name: string) => `${issuer}/protocol/openid-connect/${name}`;
  const receiverRoute = receiverRouteOf(config);
  const userFields = keycloakUserFields();

  return {
    baseURL: config.betterAuth.url,
    basePath: AUTH_BASE_PATH,
    // Passed explicitly so Better Auth never parses BETTER_AUTH_SECRETS itself;
    // its parser echoes a malformed entry, secret included. `secret` is left
    // unset: Better Auth takes the first, newest entry of this list.
    secrets: config.betterAuth.secrets,
    trustedOrigins: config.trustedOrigins,
    telemetry: { enabled: false },
    logger: { level: "info", log: betterAuthLog(logger) },
    database,
    // Stated off as well as implied by the database, so the stateless cookie
    // session and the account cookie can never come back. The grant hooks
    // strip the tokens from every account write, so the row is the identity
    // link only and each session's tokens live on its `session_grant` row.
    //
    // The slide is off: the refresher owns `expiresAt` and moves it to the
    // realm's refresh deadline on every refresh, so Better Auth's own slide
    // could only write the clamped value back and reissue the cookie on every
    // `get-session`. The session update hook still clamps any slide.
    session: { cookieCache: { enabled: false }, disableSessionRefresh: true },
    user: userFields.user,
    account: { encryptOAuthTokens: true, storeAccountCookie: false },
    // The exposure hook runs first, so a route outside the allow-list, or an
    // `idToken` sign-in, runs nothing else (`exposure.ts`). The callback's
    // start then anchors the login's deadlines (`callback-start.ts`), and
    // sign-out keeps the grant's ID token before the session goes. After the
    // handler, sign-out establishes the local deletion and ends the Keycloak
    // session from the server (`logout/sign-out.ts`), and provider token
    // fields are stripped from every result.
    hooks: {
      before: composeBeforeHooks([
        exposeRoutes(exposedRoutesFor(receiverRoute)),
        recordCallbackStart(),
        captureSignOut(grants, logger),
      ]),
      after: composeAfterHooks([
        finishSignOut(grants, {
          logger,
          issuer,
          clientId: config.keycloak.clientId,
          // Never followed: Keycloak's redirect to it is the proof of logout.
          // Resolved, not appended, so a trailing slash in BETTER_AUTH_URL
          // cannot make it `//`.
          postLogoutRedirectUri: new URL("/", config.betterAuth.url).href,
        }),
        stripProviderTokens(),
      ]),
    },
    // The limiter is on in production (100 per 10 s per address and path, in
    // each replica's memory). Every logout token comes from Keycloak's one
    // address and Keycloak never retries a refused delivery, so a burst of
    // logouts must never meet a 429; the receiver bounds its own cost (one
    // JWKS fetch per second at most, `logout/backchannel.ts`).
    rateLimit: { customRules: { [receiverRoute]: false } },
    databaseHooks: { ...grantHooks(grants, logger), user: userFields.hooks },
    advanced: {
      ...cookieSettings(config.cookieNamePolicy, cookiePrefix),
      // Better Auth turns both checks off whenever NODE_ENV is `test` or TEST
      // is set. Pinned on so that neither the e2e suite nor a misconfigured
      // deployment runs without origin and callback URL validation.
      disableOriginCheck: false,
      disableCSRFCheck: false,
    },
    plugins: [
      genericOAuth({
        config: [
          {
            ...keycloak({
              clientId: config.keycloak.clientId,
              clientSecret: config.keycloak.clientSecret,
              issuer,
              scopes: KEYCLOAK_SCOPES,
            }),
            // Set beside discovery, which still runs and still supplies the
            // issuer and JWKS. A provider whose discovery fetch fails at
            // startup is otherwise skipped until the process restarts.
            authorizationUrl: endpoint("auth"),
            tokenUrl: endpoint("token"),
            userInfoUrl: endpoint("userinfo"),
            // Better Auth would hand the browser an end-session URL built
            // from the account row; sign-out ends the Keycloak session from
            // the server instead (`logout/sign-out.ts`), so no token or
            // Keycloak URL reaches the browser.
            disableProviderLogout: true,
            overrideUserInfo: true,
            accountSubject: keycloakAccountSubject,
            mapProfileToUser: mapKeycloakProfile,
          },
        ],
      }),
      backchannelLogout(grants, {
        logger,
        route: receiverRoute,
        issuer,
        clientId: config.keycloak.clientId,
      }),
    ],
  };
}
