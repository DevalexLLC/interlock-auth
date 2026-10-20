/**
 * The responses a refresh outcome maps to, which a BFF (Interlock's session
 * guard) sends rather than inventing its own, and the one body of every dependency
 * failure. The contract every BFF and WebSocket refusal keeps: a 401
 * `session_invalid` means the session ended (its cookies cleared, and a
 * `reason` only on the response that ended it); a 503 `dependency_failure`
 * means the session is intact and a dependency is not, so it is never a
 * logout; a 502 means the upstream answered with something Interlock will
 * not relay.
 */

/** Why a session ended, as the refresher saw it. */
export type EndedReason =
  /** The session had no grant (from before 2.4, or a crash between the two inserts). */
  | "no_grant"
  /** Someone else ended it: a sign-out, or a concurrent successor that carries the reason. */
  | "ended_elsewhere"
  /** This caller ended a dispatched refresh with no known outcome (README step 6). */
  | "refresh_indeterminate"
  /** The realm's refresh deadline passed. */
  | "refresh_expired"
  /** Keycloak refused the refresh token. */
  | "invalid_grant";

/** Why the session is intact but its token could not be produced now. */
export type UnavailableReason = "refresh_in_progress" | "keycloak_unreachable" | "database";

/**
 * Every reason a 503 `dependency_failure` carries: the refresher's, the
 * upstream's (not reachable, past `UPSTREAM_TIMEOUT_MS`, or at its in-flight
 * limit), and the WebSocket route's own `upstream_unavailable` (a server
 * shutting down, or a socket whose upstream dropped).
 */
export type DependencyFailureReason =
  | UnavailableReason
  | "upstream_unreachable"
  | "upstream_timeout"
  | "upstream_busy"
  | "upstream_unavailable";

/** The session 401. Only the response that ended a session at step 6 carries a reason. */
export const SESSION_INVALID = {
  status: 401,
  code: "session_invalid",
  message: "The session is no longer valid",
} as const;

/** A dependency failed; the session is still valid, so this is not a logout. */
export const DEPENDENCY_FAILURE = {
  status: 503,
  code: "dependency_failure",
  message: "A dependency of the session is unavailable; retry shortly",
} as const;

export interface SessionInvalidBody {
  code: typeof SESSION_INVALID.code;
  message: string;
  reason?: "refresh_indeterminate";
}

export interface DependencyFailureBody {
  code: typeof DEPENDENCY_FAILURE.code;
  message: string;
  reason: DependencyFailureReason;
}

/** The one body of a dependency failure, whoever sends it. */
export const dependencyFailureBody = (reason: DependencyFailureReason): DependencyFailureBody => ({
  code: DEPENDENCY_FAILURE.code,
  message: DEPENDENCY_FAILURE.message,
  reason,
});

export type RefreshResponse =
  | { status: typeof SESSION_INVALID.status; body: SessionInvalidBody }
  | { status: typeof DEPENDENCY_FAILURE.status; body: DependencyFailureBody };

/**
 * The response for an outcome that is not `ok`. Every `ended` is the session
 * 401 (with the session cookie cleared by the caller); only
 * `refresh_indeterminate` adds the reason, which re-enters login once.
 */
export function refreshResponse(
  outcome:
    | { kind: "ended"; reason: EndedReason }
    | { kind: "unavailable"; reason: UnavailableReason },
): RefreshResponse {
  if (outcome.kind === "unavailable") {
    return { status: DEPENDENCY_FAILURE.status, body: dependencyFailureBody(outcome.reason) };
  }
  return {
    status: SESSION_INVALID.status,
    body: {
      code: SESSION_INVALID.code,
      message: SESSION_INVALID.message,
      ...(outcome.reason === "refresh_indeterminate" ? { reason: outcome.reason } : {}),
    },
  };
}
