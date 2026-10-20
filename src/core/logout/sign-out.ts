import { APIError, createAuthMiddleware } from "better-auth/api";
import { decryptOAuthToken } from "better-auth/oauth2";

import type { GrantStore } from "../grants/grant-store.js";
import type { AuthLogger } from "../logger.js";
import { isPlainObject } from "../plain-object.js";
import {
  endKeycloakSession,
  type KeycloakLogout,
  type KeycloakLogoutRequest,
  type UnconfirmedReason,
} from "./keycloak-logout.js";

/** Better Auth's native sign-out route, as `ctx.path` reports it. */
export const SIGN_OUT_ENDPOINT = "/sign-out";

/** 503: the cookies were cleared, but the session could not be shown to be deleted. */
export const SIGN_OUT_INCOMPLETE = "sign_out_incomplete";

/** What the `before` hook learned about the session being signed out. */
interface Capture {
  /** The Better Auth session token from the signed session cookie. */
  token: string;
  /** Whether the session row was found; undefined when the lookup failed. */
  found?: boolean;
  sessionId?: string;
  keycloakSid?: string;
  /** The grant's latest ID token, decrypted; in memory for this request only. */
  idTokenHint?: string;
}

/**
 * Each sign-out request's capture, keyed by the request's auth context,
 * which its before hook, handler and after hook share (`callback-start.ts`
 * keys its anchors the same way).
 */
const captures = new WeakMap<object, Capture>();

/**
 * Before Better Auth's sign-out deletes the session (the grant cascades),
 * reads it as the session guard does, with the non-deleting `findSession`,
 * and keeps the grant's latest ID token (the refresher stores every
 * refreshed one) for `finishSignOut`. A failure is logged and sign-out goes
 * on: ending the session matters more than the hint.
 */
export const captureSignOut = (grants: GrantStore, logger: AuthLogger) =>
  createAuthMiddleware(async (ctx) => {
    if (ctx.path !== SIGN_OUT_ENDPOINT) {
      return;
    }
    const token = await ctx.getSignedCookie(
      ctx.context.authCookies.sessionToken.name,
      ctx.context.secret,
    );
    if (!token) {
      return;
    }
    const capture: Capture = { token };
    captures.set(ctx.context, capture);
    try {
      const found = await ctx.context.internalAdapter.findSession(token);
      capture.found = Boolean(found);
      if (!found) {
        return;
      }
      capture.sessionId = found.session.id;
      const grant = await grants.findBySessionId(found.session.id);
      if (grant === undefined) {
        return;
      }
      capture.keycloakSid = grant.keycloakSid;
      capture.idTokenHint = await decryptOAuthToken(grant.idToken, ctx.context);
    } catch {
      logger.warn({
        message:
          "Sign-out could not read the session grant; the Keycloak logout will be unconfirmed",
        sessionId: capture.sessionId,
      });
    }
  });

export type SignOutOptions = Omit<KeycloakLogoutRequest, "idTokenHint"> & {
  /** Where the outcome, and a failed local deletion, are reported. */
  logger: AuthLogger;
};

/**
 * After Better Auth's sign-out has deleted the session and cleared the
 * cookies, which it reports as success even when its delete failed (its
 * adapter swallows a failed lookup), this:
 *
 * 1. Establishes the local deletion with a statement of its own that throws
 *    on failure. If that fails, the answer is 503 `sign_out_incomplete`: the
 *    cookies are still cleared, but sign-out is not reported as successful.
 * 2. Ends the Keycloak session from the server with the grant's ID token
 *    (`keycloak-logout.ts`), so no token and no Keycloak URL reaches the
 *    browser, and the user never sees a Keycloak page.
 * 3. Answers `{ success: true, keycloakLogout }`, with no `url` and no
 *    `Location` (Better Auth's own provider logout is disabled).
 *
 * The local session is gone before Keycloak is called and no lock is held,
 * so Keycloak's back-channel delivery to Interlock, which it makes before it
 * answers, never waits on this request.
 */
export const finishSignOut = (grants: GrantStore, { logger, ...logout }: SignOutOptions) =>
  createAuthMiddleware(async (ctx) => {
    if (ctx.path !== SIGN_OUT_ENDPOINT) {
      return;
    }
    const capture = captures.get(ctx.context);
    captures.delete(ctx.context);
    const returned: unknown = ctx.context.returned;
    // Better Auth refused the request (an APIError) or answered otherwise.
    if (!isPlainObject(returned) || returned.success !== true) {
      return;
    }
    if (capture === undefined) {
      returned.keycloakLogout = "no_session" satisfies KeycloakLogout;
      return;
    }
    const { sessionId, keycloakSid } = capture;

    let localFailed = false;
    try {
      await grants.endSessionByToken(capture.token);
    } catch {
      localFailed = true;
      logger.error({ message: "Sign-out could not end the session in the database", sessionId });
    }

    let keycloakLogout: KeycloakLogout;
    let unconfirmed: { reason: UnconfirmedReason; status?: number } | undefined;
    if (capture.idTokenHint !== undefined) {
      const result = await endKeycloakSession({ ...logout, idTokenHint: capture.idTokenHint });
      keycloakLogout = result.outcome;
      if (result.outcome === "unconfirmed") {
        unconfirmed = { reason: result.reason, status: result.status };
      }
    } else if (capture.found === false) {
      keycloakLogout = "no_session";
    } else {
      keycloakLogout = "unconfirmed";
      unconfirmed = { reason: "no_hint" };
    }
    if (keycloakLogout === "ended") {
      logger.log({ message: "Sign-out ended the Keycloak session", sessionId, keycloakSid });
    } else if (unconfirmed !== undefined) {
      logger.warn({
        message: "Sign-out could not confirm that the Keycloak session ended",
        sessionId,
        keycloakSid,
        ...unconfirmed,
      });
    }

    if (localFailed) {
      throw new APIError("SERVICE_UNAVAILABLE", {
        code: SIGN_OUT_INCOMPLETE,
        message: "The session could not be ended",
        keycloakLogout,
      });
    }
    returned.keycloakLogout = keycloakLogout;
  });
