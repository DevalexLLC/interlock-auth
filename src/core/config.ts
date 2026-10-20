import {
  COMPLETE_BUDGET_MS,
  LEASE_MARGIN_MS,
  POOL_CONNECTION_TIMEOUT_MS,
  STATEMENT_TIMEOUT_MS,
} from "./constants.js";

export const COOKIE_NAME_POLICIES = ["host", "secure"] as const;

export type CookieNamePolicy = (typeof COOKIE_NAME_POLICIES)[number];

/**
 * One entry of `BETTER_AUTH_SECRETS`. The version travels with every value Better Auth encrypts
 * or signs, so retiring an old secret never renumbers the ones still in use.
 */
export interface VersionedSecret {
  version: number;
  value: string;
}

/**
 * The configuration `createKeycloakAuthOptions` reads, already validated by the host. Interlock's
 * own configuration extends it, so its loader's output passes through as it is.
 */
export interface KeycloakAuthConfig {
  /** `url` is the public base URL; `secrets` are newest first. */
  betterAuth: { url: string; secrets: VersionedSecret[] };
  keycloak: {
    /** The realm's issuer; a trailing slash is ignored. */
    issuer: string;
    clientId: string;
    clientSecret: string;
    /** The back-channel logout receiver's full path, under `AUTH_BASE_PATH`. */
    backchannelLogoutPath: string;
  };
  /** Exact origins, `scheme://host[:port]`, that Better Auth's origin check accepts. */
  trustedOrigins: string[];
  cookieNamePolicy: CookieNamePolicy;
}

/** How the refresher bounds a token refresh; all milliseconds (`grants/refresh.ts`). */
export interface RefreshConfig {
  /** The deadline on the token request. */
  requestTimeoutMs: number;
  /** How long a claimed refresh lease lasts; renewed when the request is dispatched. */
  leaseMs: number;
  /** How long a caller that lost the claim waits for the holder. */
  waitMs: number;
  /** How early before an expiry a refresh is due. */
  leewayMs: number;
}

export const REFRESH_DEFAULTS: RefreshConfig = {
  requestTimeoutMs: 5000,
  leaseMs: 13000,
  waitMs: 5000,
  leewayMs: 60000,
};

/** The smallest leeway: a deadline judged outside it cannot pass before the caller answers. */
const MIN_LEEWAY_MS = 1000;

/**
 * What a lease must cover from dispatch on: the token request, a wait for a pool connection, the
 * `complete` transaction's budget, the one statement that may be executing when that budget runs
 * out, and a margin.
 */
export const leaseBound = (requestTimeoutMs: number) =>
  requestTimeoutMs +
  POOL_CONNECTION_TIMEOUT_MS +
  COMPLETE_BUDGET_MS +
  STATEMENT_TIMEOUT_MS +
  LEASE_MARGIN_MS;

/**
 * The longest a waiter can take to give up: its wait plus the one read that may be in flight at
 * the deadline (a pool wait and a statement).
 */
export const waitBound = (waitMs: number) =>
  waitMs + POOL_CONNECTION_TIMEOUT_MS + STATEMENT_TIMEOUT_MS;

/**
 * The longest one refresh run can take within its budgets: a wait for another holder's lease,
 * then its own dispatch through to the stored tokens. The host's shutdown waits this long for runs
 * still in flight before it ends the pool (the README's database host contract), so the
 * termination grace must allow it.
 */
export const drainBound = ({
  waitMs,
  requestTimeoutMs,
}: Pick<RefreshConfig, "waitMs" | "requestTimeoutMs">) =>
  waitBound(waitMs) + leaseBound(requestTimeoutMs);

/**
 * Checks the refresh bounds; returns the problems. The messages name the `REFRESH_*` variables,
 * the package's configuration vocabulary for a host that reads them from its environment.
 */
export function refreshBoundProblems({
  requestTimeoutMs,
  leaseMs,
  waitMs,
  leewayMs,
}: RefreshConfig) {
  const problems: string[] = [];
  if (leaseMs < leaseBound(requestTimeoutMs)) {
    problems.push(
      `REFRESH_LEASE_MS must be at least REFRESH_REQUEST_TIMEOUT_MS + ${leaseBound(0)} ` +
        `(the pool wait, the completion budget, one statement and a margin): ${leaseBound(requestTimeoutMs)}`,
    );
  }
  if (waitBound(waitMs) >= leaseMs) {
    problems.push(
      `REFRESH_WAIT_MS + ${waitBound(0)} (one pool wait and one statement) must be less than REFRESH_LEASE_MS`,
    );
  }
  if (leewayMs < MIN_LEEWAY_MS) {
    problems.push(`REFRESH_LEEWAY_MS must be at least ${MIN_LEEWAY_MS}`);
  }
  return problems;
}
