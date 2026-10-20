import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  jwtVerify,
  type JWTVerifyGetKey,
  type JWTVerifyResult,
  type RemoteJWKSet,
} from "jose";

import { StartupError } from "../callback-path.js";
import type { GrantStore } from "../grants/grant-store.js";
import type { AuthLogger } from "../logger.js";
import { isPlainObject } from "../plain-object.js";

/** The receiver's route under the base path, unless configured otherwise. */
export const BACKCHANNEL_LOGOUT_ROUTE = "/backchannel-logout";

/** The `events` member that makes a JWT a logout token (OIDC Back-Channel Logout 1.0, 2.4). */
export const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

/** 400: the logout token was refused; the logged `reason` says why. */
export const LOGOUT_TOKEN_INVALID = "logout_token_invalid";

/** 503: the realm's keys could not be read, so the token could not be judged. */
export const LOGOUT_TOKEN_UNVERIFIABLE = "logout_token_unverifiable";

/** Why a logout token was refused, as logged; the answer is always `logout_token_invalid`. */
export type LogoutTokenRejection =
  | "body_not_form"
  | "token_missing"
  | "malformed"
  | "alg_not_allowed"
  | "signature"
  | "unknown_key"
  | "issuer"
  | "audience"
  | "iat_missing"
  | "iat_stale"
  | "iat_future"
  | "exp_missing"
  | "expired"
  | "events_missing"
  | "nonce_present"
  | "subject_missing"
  | "jti_missing";

/** Why the realm's keys were not available, as logged; the answer is `logout_token_unverifiable`. */
export type KeyResolutionReason =
  | "key_refresh_cooling"
  | "jwks_timeout"
  | "jwks_status"
  | "jwks_malformed"
  | "jwks_unreachable"
  | "jwks_backoff";

/** A verified logout token: at least one of `sid` and `sub`. */
export interface LogoutClaims {
  sid?: string;
  sub?: string;
  jti: string;
  /** The JWS header's `alg`, `typ` and `kid`, for the debug log. */
  header: { alg?: string; typ?: string; kid?: string };
}

export type LogoutTokenResult =
  | LogoutClaims
  | { rejected: LogoutTokenRejection }
  | { unverifiable: KeyResolutionReason };

/**
 * How long after a successful JWKS fetch an unknown `kid` waits before it may
 * trigger another. Keycloak signs with a new key the moment it becomes active
 * and never retries a logout, so a long cooldown loses the first logouts after
 * a rotation; one second bounds that loss, and bounds what random `kid`s on
 * this unthrottled route can cost, to one fetch per second per replica.
 */
export const KEY_REFETCH_COOLDOWN_MS = 1_000;

/** How long a fetched key set is used before it is fetched again. */
export const KEY_CACHE_MAX_AGE_MS = 600_000;

/**
 * How long after a failed fetch the resolver uses only the keys it has. jose
 * moves its cooldown only on a success, so without this an outage would cost
 * one fetch per request.
 */
export const KEY_FETCH_BACKOFF_MS = 1_000;

/** Keycloak's signature algorithms; never `none` or an HMAC. */
const ALGORITHMS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
];

/** The realm's key set at its fixed JWKS endpoint, independent of startup discovery. */
export const realmKeys = (issuer: string) =>
  createRemoteJWKSet(new URL(`${issuer}/protocol/openid-connect/certs`), {
    cooldownDuration: KEY_REFETCH_COOLDOWN_MS,
    cacheMaxAge: KEY_CACHE_MAX_AGE_MS,
  });

/** The key set could not be read: a dependency failure, not a bad token. */
export class KeyResolutionFailure extends Error {
  constructor(readonly reason: KeyResolutionReason) {
    super(`the realm keys could not be resolved (${reason})`);
    this.name = "KeyResolutionFailure";
  }
}

/**
 * No key matched the token's header. `cooling` is whether the remote set was
 * inside its cooldown when the lookup began, so it could not refetch.
 */
export class UnknownKey extends Error {
  constructor(readonly cooling: boolean) {
    super("no key of the realm matches the token");
    this.name = "UnknownKey";
  }
}

/**
 * jose's error code. Compared by value rather than class: a fetch error comes
 * from another realm under Jest, and a jose bump keeps its codes stable.
 */
const codeOf = (err: unknown) => {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : undefined;
};

/** Why a key set fetch failed, from what jose threw. */
function failureReason(err: unknown): KeyResolutionReason {
  switch (codeOf(err)) {
    case "ERR_JWKS_TIMEOUT":
      return "jwks_timeout";
    case "ERR_JWKS_INVALID":
    case "ERR_JWK_INVALID":
    case "ERR_JOSE_NOT_SUPPORTED":
      return "jwks_malformed";
    case "ERR_JOSE_GENERIC":
      // jose's two generic errors here: a non-200 answer, or a body that is not JSON.
      return (err as Error).message.includes("200 OK") ? "jwks_status" : "jwks_malformed";
    default:
      // A refused connection, a DNS failure or a TLS error, all fetch `TypeError`s.
      return "jwks_unreachable";
  }
}

/**
 * The key resolver `jwtVerify` calls, around the remote set:
 *
 * - An unknown `kid` is an `UnknownKey` tagged with the remote set's cooldown
 *   as it was on entry. A refetch restarts the cooldown, so reading it after
 *   the miss would call every unknown key "cooling".
 * - Any other failure is a `KeyResolutionFailure`, and starts a backoff
 *   during which only the cached set is consulted. The failing request itself
 *   also falls back to the cached set (jose keeps a stale set after its
 *   `cacheMaxAge`), so a known key keeps verifying through an outage; only a
 *   key this replica has never seen is lost.
 */
export function createKeyResolver(
  remote: RemoteJWKSet,
  backoffMs = KEY_FETCH_BACKOFF_MS,
): JWTVerifyGetKey {
  let failedUntil = 0;

  const fromCache = async (
    header: Parameters<JWTVerifyGetKey>[0],
    token: Parameters<JWTVerifyGetKey>[1],
    reason: KeyResolutionReason,
  ) => {
    const jwks = remote.jwks();
    if (jwks === undefined) {
      throw new KeyResolutionFailure(reason);
    }
    try {
      return await createLocalJWKSet(jwks)(header, token);
    } catch (err) {
      if (codeOf(err) === "ERR_JWKS_MULTIPLE_MATCHING_KEYS") {
        throw err;
      }
      throw new KeyResolutionFailure(reason);
    }
  };

  return async (header, token) => {
    if (Date.now() < failedUntil) {
      return fromCache(header, token, "jwks_backoff");
    }
    const cooling = remote.coolingDown;
    try {
      return await remote(header, token);
    } catch (err) {
      const code = codeOf(err);
      if (code === "ERR_JWKS_NO_MATCHING_KEY") {
        throw new UnknownKey(cooling);
      }
      if (code === "ERR_JWKS_MULTIPLE_MATCHING_KEYS") {
        throw err;
      }
      failedUntil = Date.now() + backoffMs;
      return fromCache(header, token, failureReason(err));
    }
  };
}

/** A failed claim check, by the claim jose names and why it failed. */
function claimRejection(err: unknown): LogoutTokenRejection {
  const { claim, reason } = err as { claim?: string; reason?: string };
  if (claim === "iss") {
    return "issuer";
  }
  if (claim === "aud") {
    return "audience";
  }
  if (reason === "missing") {
    switch (claim) {
      case "iat":
        return "iat_missing";
      case "exp":
        return "exp_missing";
      case "jti":
        return "jti_missing";
    }
  }
  if (claim === "iat" && reason === "check_failed") {
    return "iat_future";
  }
  // A claim of the wrong type, or a future `nbf`, which Keycloak never sends.
  return "malformed";
}

/** What `jwtVerify` threw, as a refusal; undefined for anything that is not jose's. */
function rejectionOf(err: unknown): LogoutTokenRejection | undefined {
  const code = codeOf(err);
  switch (code) {
    case "ERR_JOSE_ALG_NOT_ALLOWED":
      return "alg_not_allowed";
    case "ERR_JWS_SIGNATURE_VERIFICATION_FAILED":
      return "signature";
    // Keycloak always sets `kid`, so a token that several keys could verify
    // is not one it issued.
    case "ERR_JWKS_MULTIPLE_MATCHING_KEYS":
      return "unknown_key";
    case "ERR_JWT_EXPIRED":
      return (err as { claim?: string }).claim === "iat" ? "iat_stale" : "expired";
    case "ERR_JWT_CLAIM_VALIDATION_FAILED":
      return claimRejection(err);
  }
  return code?.startsWith("ERR_J") ? "malformed" : undefined;
}

/** A claim that, when present, must be a non-blank string. */
const presentClaim = (payload: Record<string, unknown>, name: string) => {
  if (!Object.prototype.hasOwnProperty.call(payload, name)) {
    return { present: false } as const;
  }
  const value = payload[name];
  return typeof value === "string" && value.trim() !== ""
    ? ({ present: true, value } as const)
    : ({ present: true, value: undefined } as const);
};

export interface LogoutTokenValidatorOptions {
  /** The realm's issuer, without a trailing slash. */
  issuer: string;
  /** The audience: Interlock's client id. */
  clientId: string;
  /** The realm's key set; `realmKeys(issuer)` unless a spec supplies one. */
  getKey?: RemoteJWKSet;
}

/**
 * Validates a logout token as OIDC Back-Channel Logout 1.0 section 2.6 asks:
 * a JWT signed by the realm (an asymmetric algorithm only), for this client,
 * issued within five minutes and not expired (60 s of skew either way), with
 * a `jti`, the back-channel logout event, no `nonce`, and a `sid`, a `sub` or
 * both. No `jti` is remembered: `exp` and the five-minute `iat` bound limit a
 * replay instead. The JWS header `typ` is not enforced; `events` and the
 * absent `nonce` already tell a logout token from an ID token.
 */
export function createLogoutTokenValidator({
  issuer,
  clientId,
  getKey = realmKeys(issuer),
}: LogoutTokenValidatorOptions) {
  const resolve = createKeyResolver(getKey);

  return async (token: string): Promise<LogoutTokenResult> => {
    let verified: JWTVerifyResult;
    try {
      verified = await jwtVerify(token, resolve, {
        issuer,
        audience: clientId,
        algorithms: ALGORITHMS,
        clockTolerance: 60,
        maxTokenAge: "5 minutes",
        requiredClaims: ["iat", "exp", "jti"],
      });
    } catch (err) {
      if (err instanceof KeyResolutionFailure) {
        return { unverifiable: err.reason };
      }
      if (err instanceof UnknownKey) {
        return err.cooling ? { unverifiable: "key_refresh_cooling" } : { rejected: "unknown_key" };
      }
      const rejected = rejectionOf(err);
      if (rejected === undefined) {
        throw err;
      }
      return { rejected };
    }

    const payload = verified.payload as Record<string, unknown>;
    const { events } = payload;
    if (!isPlainObject(events) || !isPlainObject(events[BACKCHANNEL_LOGOUT_EVENT])) {
      return { rejected: "events_missing" };
    }
    if (Object.prototype.hasOwnProperty.call(payload, "nonce")) {
      return { rejected: "nonce_present" };
    }
    const jti = presentClaim(payload, "jti");
    if (jti.value === undefined) {
      return { rejected: "jti_missing" };
    }
    const sid = presentClaim(payload, "sid");
    const sub = presentClaim(payload, "sub");
    if (!sid.present && !sub.present) {
      return { rejected: "subject_missing" };
    }
    if ((sid.present && sid.value === undefined) || (sub.present && sub.value === undefined)) {
      return { rejected: "malformed" };
    }
    const { alg, typ, kid } = verified.protectedHeader;
    return { sid: sid.value, sub: sub.value, jti: jti.value, header: { alg, typ, kid } };
  };
}

export interface BackchannelLogoutOptions extends LogoutTokenValidatorOptions {
  /** The route under Better Auth's base path, from `KEYCLOAK_BACKCHANNEL_LOGOUT_PATH`. */
  route: string;
  /** Where every refusal and every ended session is reported; never the token. */
  logger: AuthLogger;
}

/**
 * Keycloak's back-channel logout receiver, as a Better Auth plugin route
 * (`POST <basePath><route>`), so every app that mounts Better Auth's handler
 * serves it at the same shape of path.
 *
 * Keycloak posts `logout_token=<JWS>` as a form, with no cookie and no
 * `Origin`, treats any 2xx as delivered, and never retries. The route
 * therefore accepts form bodies only (better-call answers 415 to anything
 * else before the handler runs), answers 200 `{ ended }` for any valid token,
 * including one that matched nothing (idempotent), 400 `logout_token_invalid`
 * for a refused token, and 503 `logout_token_unverifiable` when the realm's
 * keys could not be read, so a failed delivery never reads as a bad token.
 * Every handler answer carries `Cache-Control: no-store`.
 *
 * A token with `sid` ends the sessions of that Keycloak session only; one
 * with only `sub` ends every grant-backed session of the subject, which the
 * contract does not expect (it asks for session-bound tokens) and is logged
 * as a deviation. The token is never logged or echoed.
 */
export function backchannelLogout(
  grants: GrantStore,
  { route, logger, ...validatorOptions }: BackchannelLogoutOptions,
): BetterAuthPlugin {
  const validate = createLogoutTokenValidator(validatorOptions);

  const refuse = (reason: LogoutTokenRejection): never => {
    logger.warn({ message: "Refused a back-channel logout token", reason });
    throw new APIError("BAD_REQUEST", {
      code: LOGOUT_TOKEN_INVALID,
      message: "The logout token was not accepted",
    });
  };

  const unavailable = (reason: KeyResolutionReason): never => {
    logger.error({
      message: "Could not verify a back-channel logout token: the realm keys were not available",
      reason,
    });
    throw new APIError("SERVICE_UNAVAILABLE", {
      code: LOGOUT_TOKEN_UNVERIFIABLE,
      message: "The logout token could not be verified",
    });
  };

  return {
    id: "backchannel-logout",
    endpoints: {
      backchannelLogout: createAuthEndpoint(
        route,
        {
          method: "POST",
          metadata: {
            // better-call lets an endpoint override the router's JSON-only list.
            allowedMediaTypes: ["application/x-www-form-urlencoded"],
            // `Cache-Control: no-store` on every answer the handler gives.
            noStore: true,
            openapi: {
              operationId: "backchannelLogout",
              description: "Receive an OpenID Connect back-channel logout token from Keycloak",
              responses: {
                "200": { description: "The token was valid; `ended` sessions were ended" },
                "400": { description: "The logout token was refused" },
                "503": { description: "The realm's keys could not be read" },
              },
            },
          },
        },
        async (ctx) => {
          // No body schema: a schema failure would be better-call's own
          // answer, before the handler and without `no-store`. An empty
          // body reaches the handler as none at all: a form with no fields.
          const body: unknown = ctx.body ?? {};
          if (!isPlainObject(body)) {
            return refuse("body_not_form");
          }
          const token = body.logout_token;
          if (typeof token !== "string" || token === "") {
            return refuse("token_missing");
          }

          const result = await validate(token);
          if ("rejected" in result) {
            return refuse(result.rejected);
          }
          if ("unverifiable" in result) {
            return unavailable(result.unverifiable);
          }

          const { sid, sub, jti, header } = result;
          logger.debug({
            message: "Back-channel logout token header",
            alg: header.alg,
            typ: header.typ,
            kid: header.kid,
          });
          let ended: string[];
          if (sid !== undefined) {
            ended = await grants.endSessionsBySid(sid);
            logger.log({
              message: "Back-channel logout ended the sessions of a Keycloak session",
              keycloakSid: sid,
              subject: sub,
              endedSessions: ended,
              logoutJti: jti,
            });
          } else if (sub !== undefined) {
            ended = await grants.endSessionsBySubject(sub);
            logger.warn({
              message:
                "Back-channel logout token carried no sid; ended every session of the subject (contract deviation)",
              subject: sub,
              endedSessions: ended,
              logoutJti: jti,
            });
          } else {
            // The validator refuses a token with neither claim; this keeps
            // that true should it ever change.
            return refuse("subject_missing");
          }
          return ctx.json({ ended: ended.length });
        },
      ),
    },
  };
}

/** An endpoint path as a matcher for concrete paths: a `:param` segment matches any one segment. */
const matcherOf = (path: string) =>
  new RegExp(
    `^${path
      .split("/")
      .map((segment) =>
        segment.startsWith(":") ? "[^/]+" : segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
      )
      .join("/")}$`,
  );

/**
 * Fails startup unless the receiver is the only endpoint at its route. The
 * exposure hook allows a path whatever endpoint serves it, so a
 * `KEYCLOAK_BACKCHANNEL_LOGOUT_PATH` of `/api/auth/list-sessions` would expose
 * Better Auth's own `GET /list-sessions`, and one that a parameter route
 * matches (`/callback/keycloak`) would shadow that route. A Better Auth bump
 * that adds a route at the receiver's path stops here too.
 */
export function assertReceiverRoute(auth: { api: object }, route: string) {
  const receiver: unknown = Reflect.get(auth.api, "backchannelLogout");
  const receiverPath: unknown =
    receiver && typeof receiver === "function" ? Reflect.get(receiver, "path") : undefined;
  if (receiverPath !== route) {
    throw new StartupError(`The back-channel logout receiver is not served at ${route}`);
  }
  const others = Object.entries(auth.api)
    .filter(([name]) => name !== "backchannelLogout")
    .map(([, endpoint]): unknown => Reflect.get(endpoint as object, "path"))
    .filter((path): path is string => typeof path === "string" && matcherOf(path).test(route));
  if (others.length > 0) {
    throw new StartupError(
      `KEYCLOAK_BACKCHANNEL_LOGOUT_PATH ends in ${route}, which Better Auth also serves ` +
        `(${others.join(", ")}); choose a path no other auth route uses`,
    );
  }
}
