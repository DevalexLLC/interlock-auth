import type { AuthLogger } from "../logger.js";

/**
 * The structured log events of a refresh, one record each. R7's measurement
 * is `refresh.indeterminate` divided by `refresh.dispatched` over a window.
 *
 * Every dispatched attempt gets exactly one terminal event, `succeeded`,
 * `invalid_grant` or `indeterminate` (by the holder, or by a successor that
 * ended the attempt after its lease expired, matched by `leaseHolder`),
 * unless a sign-out ended the session during the request; `lease_lost` is
 * never terminal. That holds for a live process; a crash between a commit
 * and its log line can drop one.
 */
export type RefreshEventName =
  /** The token request is about to be written, under a dispatched mark. */
  | "refresh.dispatched"
  /** Keycloak rotated the tokens and they were stored (or arrived exhausted). */
  | "refresh.succeeded"
  /** Keycloak refused the refresh token; the session ended. */
  | "refresh.invalid_grant"
  /** The outcome of a dispatched request is unknown; the session ended without replay. */
  | "refresh.indeterminate"
  /** The request provably never left; the lease was released. Never follows `dispatched`. */
  | "refresh.unsent"
  /** A late holder found its attempt already ended by a successor or a sign-out. */
  | "refresh.lease_lost"
  /** A caller took over an expired lease whose holder died before dispatch. */
  | "refresh.lease_recovered"
  /** A caller claimed a grant whose token an upstream rejected, due or not. */
  | "refresh.forced"
  /** A caller stopped waiting for another holder. */
  | "refresh.waited"
  /** A Postgres error; the caller answered `unavailable(database)`. */
  | "refresh.error";

/** What every event carries. */
export interface RefreshEventBase {
  sessionId: string;
  /** The attempt the event is about. */
  leaseHolder: string | null;
  /** Since the first read of the caller's refresh. */
  durationMs: number;
}

/**
 * Extra fields, named clear of the logger's redacted fragments (`token`,
 * `secret`, `password`, `credential`), so they reach the log as values;
 * never a token or a ciphertext.
 */
export interface RefreshEventFields {
  accessExpiresAt?: string;
  refreshExpiresAt?: string;
  remainingSeconds?: number;
  by?: "holder" | "successor";
  cause?: string;
  recoveredFrom?: string;
  result?: "ok" | "ended" | "timed_out";
  code?: string;
  /** An error's message, never its `detail`. */
  error?: string;
}

const MESSAGES: Record<RefreshEventName, string> = {
  "refresh.dispatched": "Dispatched a token refresh",
  "refresh.succeeded": "Stored a refreshed grant",
  "refresh.invalid_grant": "Keycloak refused the refresh token; ended the session",
  "refresh.indeterminate": "A token refresh had no known outcome; ended the session",
  "refresh.unsent": "A token refresh was never sent; released the lease",
  "refresh.lease_lost": "A token refresh outlived its lease; the attempt was already ended",
  "refresh.lease_recovered": "Recovered a refresh lease whose holder never dispatched",
  "refresh.forced": "Refreshing a token an upstream rejected",
  "refresh.waited": "Stopped waiting for another token refresh",
  "refresh.error": "A token refresh failed on the database",
};

/** Logs one refresh event; `refresh.error` at error level, the rest at `log`. */
export function emitRefreshEvent(
  logger: AuthLogger,
  event: RefreshEventName,
  base: RefreshEventBase,
  fields: RefreshEventFields = {},
) {
  const record = {
    message: `${MESSAGES[event]} for session ${base.sessionId}`,
    event,
    ...base,
    durationMs: Math.round(base.durationMs),
    ...fields,
  };
  if (event === "refresh.error") {
    logger.error(record);
  } else {
    logger.log(record);
  }
}
