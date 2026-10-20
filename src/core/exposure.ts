import { APIError, createAuthMiddleware } from "better-auth/api";

import { CALLBACK_ENDPOINT } from "./grants/callback-start.js";
import { TOKEN_FIELDS } from "./grants/grant-hooks.js";
import { BACKCHANNEL_LOGOUT_ROUTE } from "./logout/backchannel.js";
import { isPlainObject } from "./plain-object.js";

/**
 * The Better Auth routes reachable from outside, as `ctx.path` reports them:
 * sign-in, the OAuth callback, sign-out, the error page and `get-session` for
 * the browser, and the back-channel logout receiver for Keycloak. Every
 * other route answers 404. A reverse proxy that repeats this list as a path
 * list must be kept in step with it. `__tests__/helpers/auth-routes.ts` pins
 * the full table the instance serves.
 */
export const EXPOSED_ROUTES: ReadonlySet<string> = new Set([
  "/sign-in/social",
  CALLBACK_ENDPOINT,
  "/sign-out",
  "/error",
  "/get-session",
  BACKCHANNEL_LOGOUT_ROUTE,
]);

/**
 * `EXPOSED_ROUTES` with the receiver at the route configured by
 * `KEYCLOAK_BACKCHANNEL_LOGOUT_PATH`, when that is not the usual one.
 */
export const exposedRoutesFor = (receiverRoute: string): ReadonlySet<string> =>
  receiverRoute === BACKCHANNEL_LOGOUT_ROUTE
    ? EXPOSED_ROUTES
    : new Set(
        [...EXPOSED_ROUTES].map((route) =>
          route === BACKCHANNEL_LOGOUT_ROUTE ? receiverRoute : route,
        ),
      );

/** A Better Auth route outside `EXPOSED_ROUTES` was requested. */
export const ROUTE_NOT_EXPOSED = "route_not_exposed";

/** A `sign-in/social` body carried `idToken`, the client-supplied token sign-in. */
export const ID_TOKEN_FORBIDDEN = "id_token_forbidden";

/**
 * Answers 404 for every Better Auth route but `routes` (`EXPOSED_ROUTES`, or
 * `exposedRoutesFor` a configured receiver route), and 400 for a
 * `sign-in/social` body carrying `idToken`, before any Keycloak or JWKS
 * contact. It runs first in the composed before hooks, so a blocked request
 * runs nothing else.
 *
 * Path only: Better Auth's router runs user hooks only for a matched route
 * and method, so a method a route does not declare (`GET /sign-out`, any
 * `HEAD`) is already a 404 before this runs. It also runs for `auth.api.*`
 * server calls; a path-less endpoint (`setPassword`) reports `/` and is
 * blocked too, which is fail-closed, since nothing calls one.
 *
 * It throws `APIError`, which the router answers as `{ code, message }`. A
 * returned `Response` would be handed silently to an `auth.api.*` caller.
 * Keep the messages free of `column`, `relation`, `table` and `does not
 * exist`: Better Auth's error handler logs any such message at error level.
 *
 * The session hook's `grant_unsupported_login` refusal stays as the inner
 * layer for an ID-token session (`grants/grant-hooks.ts`).
 */
export const exposeRoutes = (routes: ReadonlySet<string> = EXPOSED_ROUTES) =>
  createAuthMiddleware(async (ctx) => {
    if (!routes.has(ctx.path)) {
      throw new APIError("NOT_FOUND", { code: ROUTE_NOT_EXPOSED, message: "Not Found" });
    }
    const body: unknown = ctx.body;
    if (
      ctx.path === "/sign-in/social" &&
      isPlainObject(body) &&
      Object.prototype.hasOwnProperty.call(body, "idToken")
    ) {
      throw new APIError("BAD_REQUEST", {
        code: ID_TOKEN_FORBIDDEN,
        message: "ID-token sign-in is not accepted",
      });
    }
    return Promise.resolve();
  });

/**
 * Deletes every provider token field from a value in place, at any depth.
 * It recurses into arrays and plain objects only, so a `Date`, an `APIError`
 * or a `Response` is left as it is, and it stops at a cycle. A field that
 * cannot be deleted (a frozen or non-configurable property) throws, so the
 * value is never serialized with the token still on it.
 */
export function scrubProviderTokens(value: unknown, seen = new WeakSet<object>()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) {
    return;
  }
  if (Array.isArray(value)) {
    seen.add(value);
    for (const item of value) {
      scrubProviderTokens(item, seen);
    }
    return;
  }
  if (!isPlainObject(value)) {
    return;
  }
  seen.add(value);
  for (const field of TOKEN_FIELDS) {
    if (!Reflect.deleteProperty(value, field)) {
      throw new Error(`Could not strip the provider token field ${field}`);
    }
  }
  for (const item of Object.values(value)) {
    scrubProviderTokens(item, seen);
  }
}

/**
 * Strips the provider token fields from whatever a Better Auth route
 * returned, so `get-session` is sanitized by construction rather than by the
 * account row having no tokens. It edits the result in place, which is what
 * Better Auth serializes, and returns nothing. `session.token` is Better
 * Auth's own session token, not a provider token, and stays.
 */
export const stripProviderTokens = () =>
  createAuthMiddleware(async (ctx) => {
    scrubProviderTokens(ctx.context.returned);
    return Promise.resolve();
  });
