import { performance } from "node:perf_hooks";

import type { Account, BetterAuthOptions, GenericEndpointContext } from "better-auth";
import { APIError } from "better-auth/api";

import { encryptToken } from "../encrypt-token.js";
import { loginLifetimesOf, type Lifetimes } from "../keycloak-token.js";
import type { AuthLogger } from "../logger.js";
import { CALLBACK_ENDPOINT, callbackStartOf } from "./callback-start.js";
import {
  GRANT_ID_TOKEN_MISSING,
  GRANT_NOT_CAPTURED,
  GRANT_NOT_CREATED,
  GRANT_REFRESH_EXPIRY_MISSING,
  GRANT_SID_MISSING,
  GRANT_UNSUPPORTED_LOGIN,
  type GrantErrorCode,
} from "./grant-errors.js";
import type { GrantStore } from "./grant-store.js";

/** The account columns that never hold a value: the grant keeps them instead. */
export const TOKEN_FIELDS = [
  "accessToken",
  "refreshToken",
  "idToken",
  "accessTokenExpiresAt",
  "refreshTokenExpiresAt",
] as const;

const STRIPPED = {
  accessToken: null,
  refreshToken: null,
  idToken: null,
  accessTokenExpiresAt: null,
  refreshTokenExpiresAt: null,
};

/** What the account hook of one callback hands the session hook of the same request. */
type Captured =
  | {
      accessToken: string;
      refreshToken: string;
      /** The token response's lifetimes; null when it lacked a usable one. */
      lifetimes: Lifetimes | null;
      /** Plaintext; encrypted by the session hook before it is stored. */
      idToken: string;
      sid: string;
      sub: string;
    }
  | { failure: GrantErrorCode };

/** A claim is usable only if it is a non-blank string. */
const claim = (value: unknown) =>
  typeof value === "string" && value.trim() !== "" ? value : undefined;

/**
 * The `sid` and `sub` claims of an ID token, read without verifying it.
 * Better Auth verified the signature against the discovery JWKS when
 * discovery succeeded, and the token came from the token endpoint over TLS
 * with client authentication; these claims are correlation keys for
 * back-channel logout, not an authorization input.
 */
export function idTokenClaims(idToken: string): { sid?: string; sub?: string } {
  try {
    const payload: unknown = JSON.parse(
      Buffer.from(idToken.split(".")[1] ?? "", "base64url").toString("utf8"),
    );
    if (typeof payload !== "object" || payload === null) {
      return {};
    }
    const { sid, sub } = payload as Record<string, unknown>;
    return { sid: claim(sid), sub: claim(sub) };
  } catch {
    return {};
  }
}

/**
 * The lifetimes `keycloakAccountSubject` registered under the write's
 * `refreshTokenExpiresAt`, when both are usable.
 */
function lifetimesOf(data: Partial<Account>): Lifetimes | null {
  const lifetimes = loginLifetimesOf(data.refreshTokenExpiresAt);
  if (lifetimes === undefined) {
    return null;
  }
  const { accessExpiresIn, refreshExpiresIn } = lifetimes;
  return accessExpiresIn !== null && refreshExpiresIn !== null
    ? { accessExpiresIn, refreshExpiresIn }
    : null;
}

function capture(data: Partial<Account>, accessToken: string, refreshToken: string): Captured {
  const idToken = claim(data.idToken);
  if (idToken === undefined) {
    return { failure: GRANT_ID_TOKEN_MISSING };
  }
  const { sid, sub } = idTokenClaims(idToken);
  if (sid === undefined || sub === undefined) {
    return { failure: GRANT_SID_MISSING };
  }
  return {
    accessToken,
    refreshToken,
    lifetimes: lifetimesOf(data),
    idToken,
    sid,
    sub,
  };
}

const MESSAGES: Record<GrantErrorCode, string> = {
  [GRANT_NOT_CAPTURED]: "The login returned no tokens to keep",
  [GRANT_NOT_CREATED]: "The session grant could not be stored",
  [GRANT_ID_TOKEN_MISSING]: "The login returned no ID token",
  [GRANT_SID_MISSING]: "The ID token has no sid or sub claim",
  [GRANT_REFRESH_EXPIRY_MISSING]: "The login returned no refresh expiry to bound the session by",
  [GRANT_UNSUPPORTED_LOGIN]: "Sessions are created only by the Keycloak callback",
};

/**
 * The database hooks that keep every session's provider tokens on its own
 * `session_grant` row and none on the `account` row, which stays the identity
 * link only.
 *
 * - Both account `before` hooks (first login creates the row, a repeat login
 *   updates it, an existing user without one links it) take the tokens out of
 *   the write, on every path. Inside the Keycloak callback they also put what
 *   the grant needs in a `WeakMap` keyed by the request's endpoint context,
 *   which every hook of one request receives; anywhere else the tokens are
 *   dropped.
 * - `session.create.before` bounds the new session's `expiresAt` by the
 *   realm's refresh lifetime (a provisional value on the application clock).
 * - `session.create.after` writes the grant once the session has its id, with
 *   both deadlines anchored at the callback's start (`callback-start.ts`) and
 *   written as database time, then sets the session's `expiresAt` to the
 *   grant's refresh deadline, so the two carry one value. A session created
 *   by any other request is deleted and the request refused, as is a callback
 *   whose tokens could not be captured or stored, or whose token response
 *   carried no usable `refresh_expires_in` or `expires_in` (a session with no
 *   realm bound), so no session is ever issued without a bounded grant.
 *   Better Auth's callback turns the coded `APIError` into
 *   `/api/auth/error?error=<code>` with no session cookie.
 * - `session.update.before` clamps any later `expiresAt` to the grant's
 *   refresh deadline. Better Auth's own slide is off
 *   (`disableSessionRefresh`) and the refresher owns `expiresAt`, so this is
 *   the backstop for any route that still updates a session.
 *
 * A session made with no request context (the internal adapter called
 * directly) is left alone. Ending a session needs no hook: the grant's
 * foreign key cascades every delete of the session row.
 */
export function grantHooks(
  store: GrantStore,
  logger: AuthLogger,
): NonNullable<BetterAuthOptions["databaseHooks"]> {
  const captured = new WeakMap<GenericEndpointContext, Captured>();

  const stripAccountTokens = async (
    data: Partial<Account>,
    context: GenericEndpointContext | null | undefined,
  ) => {
    if (!TOKEN_FIELDS.some((field) => field in data)) {
      return undefined;
    }
    if (context?.path === CALLBACK_ENDPOINT) {
      const { accessToken, refreshToken } = data;
      if (accessToken && refreshToken) {
        captured.set(context, capture(data, accessToken, refreshToken));
      }
    } else if (data.accessToken || data.refreshToken || data.idToken) {
      logger.debug({
        message: `Dropped provider tokens from an account write outside the Keycloak callback (${context?.path ?? "no request"})`,
      });
    }
    return { data: { ...STRIPPED } };
  };

  return {
    account: {
      create: { before: stripAccountTokens },
      update: { before: stripAccountTokens },
    },
    session: {
      create: {
        before: async (data, context) => {
          const entry = context ? captured.get(context) : undefined;
          const start = callbackStartOf(context?.context);
          if (
            entry === undefined ||
            "failure" in entry ||
            entry.lifetimes === null ||
            start === undefined ||
            !(data.expiresAt instanceof Date)
          ) {
            // Incomplete: `create.after` is about to refuse the login.
            return undefined;
          }
          const bound =
            Date.now() + entry.lifetimes.refreshExpiresIn * 1000 - (performance.now() - start);
          return { data: { expiresAt: new Date(Math.min(data.expiresAt.getTime(), bound)) } };
        },
        after: async (session, context) => {
          if (!context) {
            return;
          }
          const entry = captured.get(context);
          captured.delete(context);

          // Deletes the session, then gives the error to throw.
          const refusal = async (
            code: GrantErrorCode,
            status: "UNAUTHORIZED" | "INTERNAL_SERVER_ERROR",
          ) => {
            await context.context.internalAdapter.deleteSession(session.token);
            return new APIError(status, { code, message: MESSAGES[code] });
          };

          if (context.path !== CALLBACK_ENDPOINT) {
            throw await refusal(GRANT_UNSUPPORTED_LOGIN, "UNAUTHORIZED");
          }
          if (entry === undefined) {
            throw await refusal(GRANT_NOT_CAPTURED, "INTERNAL_SERVER_ERROR");
          }
          if ("failure" in entry) {
            throw await refusal(entry.failure, "UNAUTHORIZED");
          }
          if (entry.lifetimes === null) {
            logger.error({
              message:
                "Keycloak answered a login without a positive refresh_expires_in or expires_in; " +
                "the realm contract requires both, so the login was refused",
              sessionId: session.id,
              keycloakSid: entry.sid,
            });
            throw await refusal(GRANT_REFRESH_EXPIRY_MISSING, "UNAUTHORIZED");
          }
          const startedAt = callbackStartOf(context.context);
          if (startedAt === undefined) {
            logger.error({
              message: `No callback start was recorded for session ${session.id}; the before hook is missing`,
            });
            throw await refusal(GRANT_NOT_CAPTURED, "INTERNAL_SERVER_ERROR");
          }

          const idToken = await encryptToken(entry.idToken, context.context);
          let grant: Awaited<ReturnType<GrantStore["insert"]>>;
          try {
            grant = await store.insert(
              {
                sessionId: session.id,
                keycloakSid: entry.sid,
                keycloakSubject: entry.sub,
                accessToken: entry.accessToken,
                refreshToken: entry.refreshToken,
                idToken,
              },
              { startedAt, lifetimes: entry.lifetimes },
            );
          } catch (err) {
            // The message and code only: a database error's `detail` can
            // quote the failing row, tokens included.
            const reason = err instanceof Error ? err.message : "unknown error";
            logger.error({
              message: `Could not store the session grant for session ${session.id}: ${reason}`,
              code: (err as { code?: unknown } | undefined)?.code,
            });
            throw await refusal(GRANT_NOT_CREATED, "INTERNAL_SERVER_ERROR");
          }
          // The session and the grant carry one deadline, in database time.
          // `insert` always writes it; a store that did not is refused.
          const deadline = grant.refreshTokenExpiresAt;
          if (deadline === null) {
            throw await refusal(GRANT_NOT_CREATED, "INTERNAL_SERVER_ERROR");
          }
          await context.context.internalAdapter.updateSession(session.token, {
            expiresAt: deadline,
          });
          logger.log({
            message: `Stored the session grant for session ${session.id}`,
            sessionId: session.id,
            keycloakSid: entry.sid,
            accessExpiresAt: grant.accessTokenExpiresAt?.toISOString() ?? null,
            refreshExpiresAt: grant.refreshTokenExpiresAt?.toISOString() ?? null,
          });
        },
      },
      update: {
        before: async (data, context) => {
          if (!(data.expiresAt instanceof Date)) {
            return undefined;
          }
          const sessionId = context?.context.session?.session.id;
          if (sessionId === undefined) {
            logger.debug({
              message: `Left a session expiry update unclamped: no session in its context (${context?.path ?? "no request"})`,
            });
            return undefined;
          }
          const deadline = (await store.findBySessionId(sessionId))?.refreshTokenExpiresAt;
          return deadline && data.expiresAt.getTime() > deadline.getTime()
            ? { data: { expiresAt: deadline } }
            : undefined;
        },
      },
    },
  };
}
