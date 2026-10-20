import { randomUUID } from "node:crypto";
import { hostname } from "node:os";
import { performance } from "node:perf_hooks";
import { setTimeout as sleep } from "node:timers/promises";

import { decryptOAuthToken } from "better-auth/oauth2";

import { leaseBound, type KeycloakAuthConfig, type RefreshConfig } from "../config.js";
import { LEASE_MARGIN_MS, POOL_CONNECTION_TIMEOUT_MS, STATEMENT_TIMEOUT_MS } from "../constants.js";
import { InFlightWork } from "../database/in-flight-work.js";
import { encryptToken } from "../encrypt-token.js";
import {
  httpTransport,
  refreshTokens,
  type RefreshResult,
  type TokenTransport,
} from "../keycloak-token.js";
import type { AuthLogger } from "../logger.js";
import {
  AmbiguousCommitError,
  CompletionBudgetError,
  type CompleteResult,
  type GrantStore,
  type StoredGrant,
} from "./grant-store.js";
import {
  emitRefreshEvent,
  type RefreshEventFields,
  type RefreshEventName,
} from "./refresh-events.js";
import type { EndedReason, UnavailableReason } from "./refresh-responses.js";

/** The resolved Better Auth context the token helpers need (`await auth.$context`). */
export type AuthContext = Parameters<typeof decryptOAuthToken>[1];

/**
 * What `refreshIfDue` concluded. `ok` carries the grant as read (or as
 * stored), with the access token's and session's remaining lives in database time at
 * `observedAt` (`performance.now()`, never later than the read it is from).
 */
export type RefreshOutcome =
  | {
      kind: "ok";
      refreshed: boolean;
      grant: StoredGrant;
      accessRemainingMs: number;
      refreshRemainingMs: number;
      observedAt: number;
    }
  | { kind: "ended"; reason: EndedReason }
  | { kind: "unavailable"; reason: UnavailableReason };

/**
 * What `resolveAccessToken` concluded; `ok` carries the plaintext token and
 * its usable lifetime, capped by the session's remaining life.
 */
export type AccessTokenOutcome =
  | { kind: "ok"; accessToken: string; refreshed: boolean; expiresInMs: number }
  | { kind: "ended"; reason: EndedReason }
  | { kind: "unavailable"; reason: UnavailableReason };

/** What a caller may tell `refreshIfDue`. */
export interface RefreshOptions {
  /**
   * The plaintext access token an upstream just rejected. While the grant
   * still holds this token it is due, whatever its deadlines say; once
   * another caller has rotated it, the replacement is judged by the normal
   * rule, so it is used as it is unless it is due itself.
   */
  rejectedAccessToken?: string;
}

/** What a caller may tell `resolveAccessToken`. */
export interface ResolveOptions extends RefreshOptions {
  /**
   * How many refreshes the call may dispatch, across its attempts: 2 by
   * default (a refresh whose result arrives with no life left is followed by
   * one more), 1 for the recovery after an upstream rejected the token.
   */
  refreshBudget?: number;
}

/** The refreshes one call may still dispatch, shared by its attempts. */
interface Budget {
  left: number;
}

/** At most this many reads per call; each round returns, waits, or sees `version` change. */
export const MAX_ROUNDS = 6;

/** How often a waiter re-reads the grant it waits on. */
export const WAIT_POLL_MS = 250;

const ended = (reason: EndedReason) => ({ kind: "ended", reason }) as const;
const unavailable = (reason: UnavailableReason) => ({ kind: "unavailable", reason }) as const;

/** A read that lost its race against the caller's budget. */
class ReadTimeoutError extends Error {
  readonly code = "read_timeout";
  constructor() {
    super("a grant read did not settle within its budget");
    this.name = "ReadTimeoutError";
  }
}

/** One caller's refresh, for the event fields and the shared deadline. */
class Run {
  readonly start = performance.now();
  /** The wait budget; every read is raced against what is left of it. */
  readonly waitDeadline: number;
  holder: string | null = null;

  constructor(
    readonly sessionId: string,
    waitMs: number,
    readonly options: RefreshOptions,
    readonly budget: Budget,
    private readonly logger: AuthLogger,
  ) {
    this.waitDeadline = this.start + waitMs;
  }

  emit(event: RefreshEventName, fields: RefreshEventFields = {}, leaseHolder = this.holder) {
    emitRefreshEvent(
      this.logger,
      event,
      { sessionId: this.sessionId, leaseHolder, durationMs: performance.now() - this.start },
      fields,
    );
  }
}

const holderId = () => `${hostname()}#${process.pid}#${randomUUID()}`;

/** What is left of a deadline at `now`; a missing deadline has nothing left. */
const msLeft = (deadline: Date | null, now: Date) =>
  deadline === null ? 0 : deadline.getTime() - now.getTime();

const errorCode = (err: unknown) => {
  const code = (err as { code?: unknown } | undefined)?.code;
  return typeof code === "string" ? code : err instanceof Error ? err.name : "error";
};

const errorMessage = (err: unknown) => (err instanceof Error ? err.message : "unknown error");

/** The `ok` outcome of a stored refresh, after its `refresh.succeeded` event. */
function succeeded(run: Run, grant: StoredGrant, now: Date, observedAt: number) {
  run.emit("refresh.succeeded", {
    accessExpiresAt: grant.accessTokenExpiresAt?.toISOString(),
    refreshExpiresAt: grant.refreshTokenExpiresAt?.toISOString(),
    remainingSeconds: Math.max(0, Math.floor(msLeft(grant.refreshTokenExpiresAt, now) / 1000)),
  });
  return {
    kind: "ok",
    refreshed: true,
    grant,
    accessRemainingMs: msLeft(grant.accessTokenExpiresAt, now),
    refreshRemainingMs: msLeft(grant.refreshTokenExpiresAt, now),
    observedAt,
  } as const;
}

/** The Keycloak client the refresher authenticates as, and how it bounds a refresh. */
export interface GrantRefresherConfig {
  keycloak: Pick<KeycloakAuthConfig["keycloak"], "issuer" | "clientId" | "clientSecret">;
  refresh: RefreshConfig;
}

/** The refresher's collaborators besides the grant store. */
export interface GrantRefresherOptions {
  /** Where the refresh events (`refresh-events.ts`) go. */
  logger: AuthLogger;
  /** The token request's transport; `httpTransport` unless a test passes its own. */
  transport?: TokenTransport;
  /**
   * Where each run is counted, so the host's shutdown ends the pool only
   * after them. A refresher built without one counts its runs for no one.
   */
  inFlight?: InFlightWork;
}

/**
 * The refresh lease state machine of the `interlock` README's "Session-scoped
 * grants", per grant, in Postgres. Every write is a compare-and-swap on the version
 * the caller read, and every lease comparison is database time, so replicas
 * coordinate without agreeing on a clock. See `refreshIfDue` for the steps.
 *
 * In Interlock, the BFF's session resolution is its one request-time caller:
 * it resolves access tokens through `resolveAccessToken`, and forces one
 * refresh with `rejectedAccessToken` after an upstream rejected the token.
 * Both paths map the outcomes to `refresh-responses.ts`.
 */
export class GrantRefresher {
  private readonly keycloak: GrantRefresherConfig["keycloak"];
  private readonly settings: RefreshConfig;
  private readonly logger: AuthLogger;
  private readonly transport: TokenTransport;
  private readonly inFlight: InFlightWork;
  private readonly tokenUrl: string;
  /** What must still be left of the lease when the mark is acknowledged. */
  private readonly dispatchBudgetMs: number;

  constructor(
    private readonly grants: GrantStore,
    { keycloak, refresh }: GrantRefresherConfig,
    { logger, transport = httpTransport, inFlight = new InFlightWork() }: GrantRefresherOptions,
  ) {
    this.keycloak = keycloak;
    this.settings = refresh;
    this.logger = logger;
    this.transport = transport;
    this.inFlight = inFlight;
    this.tokenUrl = `${keycloak.issuer.replace(/\/+$/, "")}/protocol/openid-connect/token`;
    this.dispatchBudgetMs = leaseBound(refresh.requestTimeoutMs) - LEASE_MARGIN_MS;
  }

  /**
   * The decrypted access token, refreshed first if it is due, provided some
   * of both its life and the session's life remains after decryption. If
   * either deadline passed during the read, completion or decryption, run
   * the refresher once more to revalidate the current row (never end it from
   * a stale outcome). If that result is exhausted too, the caller gets
   * `unavailable(keycloak_unreachable)` rather than a dead token.
   *
   * `refreshBudget` bounds the Keycloak requests across both attempts. Once
   * it is spent, an attempt still revalidates the row (and ends the session
   * or waits on a lease exactly as before) but never claims: a grant that is
   * due then is `unavailable(keycloak_unreachable)`.
   */
  async resolveAccessToken(
    sessionId: string,
    auth: AuthContext,
    { refreshBudget = 2, ...options }: ResolveOptions = {},
  ): Promise<AccessTokenOutcome> {
    const budget: Budget = { left: refreshBudget };
    for (let attempt = 0; attempt < 2; attempt++) {
      const outcome = await this.inFlight.track(this.run(sessionId, auth, options, budget));
      if (outcome.kind !== "ok") {
        return outcome;
      }
      const accessToken = await decryptOAuthToken(outcome.grant.accessToken, auth);
      const remaining =
        Math.min(outcome.accessRemainingMs, outcome.refreshRemainingMs) -
        (performance.now() - outcome.observedAt);
      if (remaining > 0) {
        return {
          kind: "ok",
          accessToken,
          refreshed: outcome.refreshed,
          expiresInMs: remaining,
        };
      }
    }
    return unavailable("keycloak_unreachable");
  }

  /**
   * Refreshes the session's grant if it is due, coordinating with every
   * other caller through the lease. Each round, in this order (README steps
   * in parentheses):
   *
   * 1. Read. No row: the session has no grant and is ended.
   * 2. A live lease: wait for it, whatever the deadlines say, because its
   *    holder may be extending the session at Keycloak right now.
   * 3. An expired, dispatched lease (step 6, as a successor): end the session.
   * 4. The refresh deadline passed: end the session.
   * 5. Not due, and not the token an upstream rejected: `ok`.
   * 6. An expired, unmarked lease (step 5): recover it by claiming.
   * 7. No lease: claim. 8. Mark it dispatched. 9. Send, then store, end, or
   *    release, by what the response proves.
   *
   * A lost compare-and-swap anywhere starts the next round. The rejected
   * token is compared as plaintext, never by `version`, which every lease
   * write bumps without touching the tokens.
   *
   * The run is counted in `inFlight` until it settles: once dispatched, a
   * refresh must store its rotated tokens whether or not its caller is still
   * there, and shutdown ends the pool only after the count reaches zero.
   */
  async refreshIfDue(
    sessionId: string,
    auth: AuthContext,
    options: RefreshOptions = {},
  ): Promise<RefreshOutcome> {
    return this.inFlight.track(this.run(sessionId, auth, options, { left: 1 }));
  }

  private async run(
    sessionId: string,
    auth: AuthContext,
    options: RefreshOptions,
    budget: Budget,
  ): Promise<RefreshOutcome> {
    const run = new Run(sessionId, this.settings.waitMs, options, budget, this.logger);
    try {
      return await this.rounds(run, auth);
    } catch (err) {
      // The message and code only: a database error's `detail` can quote the row.
      run.emit("refresh.error", { code: errorCode(err), error: errorMessage(err) });
      return unavailable("database");
    }
  }

  private async rounds(run: Run, auth: AuthContext): Promise<RefreshOutcome> {
    const { sessionId } = run;
    for (let round = 0; round < MAX_ROUNDS; round++) {
      // Taken before the read is sent, so it is never later than the
      // database's `now`, and the remaining life is never overstated.
      const observedAt = performance.now();
      const read = await this.read(run);
      if (read === undefined) {
        if (round > 0) {
          return ended("ended_elsewhere");
        }
        // A grant is inserted by the callback that created the session,
        // before its cookie exists, so no caller sees a session that is
        // still about to get one: no compare-and-swap is needed.
        await this.grants.endSession(sessionId);
        return ended("no_grant");
      }
      const { grant, now } = read;
      const leaseExpired = grant.leaseExpiresAt !== null && grant.leaseExpiresAt <= now;

      if (grant.leaseHolder !== null && !leaseExpired) {
        const waited = await this.wait(run, grant);
        if (waited === "gone") {
          return ended("ended_elsewhere");
        }
        if (waited === "timed_out") {
          return unavailable("refresh_in_progress");
        }
        continue;
      }

      if (grant.leaseHolder !== null && grant.dispatched) {
        if (
          await this.grants.endIf(sessionId, { kind: "expiredDispatched", version: grant.version })
        ) {
          run.emit(
            "refresh.indeterminate",
            { by: "successor", cause: "lease_expired" },
            grant.leaseHolder,
          );
          return ended("refresh_indeterminate");
        }
        continue;
      }

      if (grant.refreshTokenExpiresAt !== null && grant.refreshTokenExpiresAt <= now) {
        if (
          await this.grants.endIf(sessionId, { kind: "expiredRefresh", version: grant.version })
        ) {
          return ended("refresh_expired");
        }
        continue;
      }

      const { rejectedAccessToken } = run.options;
      const forced =
        rejectedAccessToken !== undefined &&
        (await decryptOAuthToken(grant.accessToken, auth)) === rejectedAccessToken;
      if (!forced && !this.isDue(grant, now)) {
        return {
          kind: "ok",
          refreshed: false,
          grant,
          accessRemainingMs: msLeft(grant.accessTokenExpiresAt, now),
          refreshRemainingMs: msLeft(grant.refreshTokenExpiresAt, now),
          observedAt,
        };
      }
      if (run.budget.left <= 0) {
        // The call has made every request it may; the token is unusable as it is.
        return unavailable("keycloak_unreachable");
      }

      // Decrypted before the claim, so a failure leaves no lease behind.
      const refreshToken = await decryptOAuthToken(grant.refreshToken, auth);
      const holder = holderId();
      const claimed = await this.grants.claim(
        sessionId,
        grant.version,
        holder,
        this.settings.leaseMs,
      );
      if (claimed === undefined) {
        continue;
      }
      run.holder = holder;
      if (grant.leaseHolder !== null) {
        run.emit("refresh.lease_recovered", { recoveredFrom: grant.leaseHolder });
      }
      if (forced) {
        run.emit("refresh.forced", { cause: "upstream_rejected" });
      }

      const outcome = await this.dispatch(run, claimed, holder, refreshToken, auth);
      if (outcome !== "retry") {
        return outcome;
      }
    }
    return unavailable("refresh_in_progress");
  }

  /**
   * Due when either deadline is missing (a grant from before 2.5 has no
   * refresh deadline) or within the effective leeway of the database clock:
   * `min(leewayMs, half the issued lifetime)`, so a leeway at or above a
   * token's lifetime cannot make a fresh token due the moment it is issued.
   */
  private isDue(grant: StoredGrant, now: Date) {
    const { accessTokenExpiresAt, refreshTokenExpiresAt, updatedAt } = grant;
    if (accessTokenExpiresAt === null || refreshTokenExpiresAt === null) {
      return true;
    }
    const within = (expiresAt: Date) =>
      expiresAt.getTime() - now.getTime() <=
      Math.min(this.settings.leewayMs, (expiresAt.getTime() - updatedAt.getTime()) / 2);
    return within(accessTokenExpiresAt) || within(refreshTokenExpiresAt);
  }

  /**
   * Waits for another caller's live lease, polling on the database's clock,
   * until the row is gone, it changed (cleared, or a new version), the lease
   * expired, or the shared deadline passed with the lease still held. Each
   * sleep is clipped to the time left, so the last poll runs at the deadline.
   */
  private async wait(run: Run, seen: StoredGrant): Promise<"changed" | "gone" | "timed_out"> {
    const result = (value: "changed" | "gone" | "timed_out") => {
      run.emit(
        "refresh.waited",
        { result: value === "changed" ? "ok" : value === "gone" ? "ended" : "timed_out" },
        seen.leaseHolder,
      );
      return value;
    };
    for (;;) {
      const left = run.waitDeadline - performance.now();
      if (left <= 0) {
        return result("timed_out");
      }
      await sleep(Math.min(WAIT_POLL_MS, left));
      const read = await this.read(run);
      if (read === undefined) {
        return result("gone");
      }
      const { grant, now } = read;
      if (
        grant.version !== seen.version ||
        grant.leaseHolder === null ||
        grant.leaseExpiresAt === null ||
        grant.leaseExpiresAt <= now
      ) {
        return result("changed");
      }
    }
  }

  /**
   * A read raced against what is left of the wait budget plus one pool wait
   * and one statement. Neither pool timeout bounds an established connection
   * that stops answering; a read that loses the race is abandoned (a single
   * autocommit SELECT, so its connection comes back clean whenever it does).
   */
  private async read(run: Run, budgetMs = Math.max(0, run.waitDeadline - performance.now())) {
    return raceRead(
      this.grants.read(run.sessionId),
      budgetMs + POOL_CONNECTION_TIMEOUT_MS + STATEMENT_TIMEOUT_MS,
    );
  }

  /** Steps 8 and 9 for a grant `holder` claimed. `retry` starts the next round. */
  private async dispatch(
    run: Run,
    claimed: StoredGrant,
    holder: string,
    refreshToken: string,
    auth: AuthContext,
  ): Promise<RefreshOutcome | "retry"> {
    const { sessionId } = run;
    const markStart = performance.now();
    const version = await this.grants.markDispatched(
      sessionId,
      claimed.version,
      holder,
      this.settings.leaseMs,
    );
    if (version === undefined) {
      // The lease expired before the mark (step 6 next round) or changed.
      return "retry";
    }
    // The renewed lease started when Postgres ran the mark; the round trip
    // bounds how much of it is already gone.
    if (this.settings.leaseMs - (performance.now() - markStart) < this.dispatchBudgetMs) {
      if (await this.grants.release(sessionId, version, holder)) {
        run.emit("refresh.unsent", { cause: "mark_latency" });
      } else {
        run.emit("refresh.lease_lost");
      }
      return unavailable("database");
    }

    run.budget.left -= 1;
    const result = await refreshTokens({
      tokenUrl: this.tokenUrl,
      clientId: this.keycloak.clientId,
      clientSecret: this.keycloak.clientSecret,
      refreshToken,
      timeoutMs: this.settings.requestTimeoutMs,
      transport: this.transport,
      onSent: () => run.emit("refresh.dispatched"),
      logger: this.logger,
    }).catch((err: unknown): RefreshResult => ({ kind: "indeterminate", cause: errorCode(err) }));

    switch (result.kind) {
      case "ok":
        return this.store(run, version, holder, result, auth);
      case "invalid_grant":
        return this.endHeld(run, version, holder, () => {
          run.emit("refresh.invalid_grant");
          return ended("invalid_grant");
        });
      case "unsent":
        if (await this.grants.release(sessionId, version, holder)) {
          run.emit("refresh.unsent", { cause: result.cause });
          return unavailable("keycloak_unreachable");
        }
        run.emit("refresh.lease_lost");
        return ended("ended_elsewhere");
    }
    return this.endIndeterminate(run, version, holder, result.cause);
  }

  /**
   * The holder ends its own dispatched attempt (README step 6, at once rather
   * than for the next caller). Only a matching end is this caller's outcome;
   * otherwise a successor or a sign-out already ended it.
   */
  private async endHeld(run: Run, version: number, holder: string, matched: () => RefreshOutcome) {
    if (await this.grants.endIf(run.sessionId, { kind: "heldBy", version, holder })) {
      return matched();
    }
    run.emit("refresh.lease_lost");
    return ended("ended_elsewhere");
  }

  private async endIndeterminate(run: Run, version: number, holder: string, cause: string) {
    return this.endHeld(run, version, holder, () => {
      run.emit("refresh.indeterminate", { by: "holder", cause });
      return ended("refresh_indeterminate");
    });
  }

  /** Step 9 on `ok`: encrypt, then `complete` with the anchor and the lifetimes. */
  private async store(
    run: Run,
    version: number,
    holder: string,
    result: Extract<RefreshResult, { kind: "ok" }>,
    auth: AuthContext,
  ): Promise<RefreshOutcome> {
    const { tokens } = result;
    const encrypted = {
      accessToken: await encryptToken(tokens.accessToken, auth),
      refreshToken: await encryptToken(tokens.refreshToken, auth),
      ...(tokens.idToken === undefined
        ? {}
        : { idToken: await encryptToken(tokens.idToken, auth) }),
    };
    const observedAt = performance.now();
    let completed: CompleteResult;
    try {
      completed = await this.grants.complete({
        sessionId: run.sessionId,
        version,
        holder,
        tokens: encrypted,
        startedAt: result.sentAt,
        lifetimes: result.lifetimes,
      });
    } catch (err) {
      if (err instanceof CompletionBudgetError) {
        // Keycloak rotated the token and nothing was persisted: the holder's
        // own indeterminate outcome, so it carries the reason.
        return this.endIndeterminate(run, version, holder, "completion_budget");
      }
      if (err instanceof AmbiguousCommitError) {
        return this.resolveCommit(run, version, holder);
      }
      throw err;
    }

    switch (completed.status) {
      case "stored":
        return succeeded(run, completed.grant, completed.now, observedAt);
      case "exhausted":
        run.emit("refresh.succeeded", { remainingSeconds: 0 });
        return ended("refresh_expired");
    }
    run.emit("refresh.lease_lost");
    return ended("ended_elsewhere");
  }

  /**
   * `complete` sent COMMIT and heard nothing. Under Read Committed an
   * unchanged row is inconclusive (the commit may still be finishing), so
   * every conclusion is a compare-and-swap or a version the commit alone
   * could have produced: nothing but that commit clears the holder's own
   * mark, and a successor deletes the row rather than bumping it.
   */
  private async resolveCommit(run: Run, version: number, holder: string): Promise<RefreshOutcome> {
    const budget = this.settings.waitMs;
    const reread = async () => {
      const observedAt = performance.now();
      const read = await this.read(run, budget);
      if (read === undefined) {
        run.emit("refresh.lease_lost");
        return ended("ended_elsewhere");
      }
      if (read.grant.version > version) {
        return succeeded(run, read.grant, read.now, observedAt);
      }
      return undefined;
    };

    const first = await reread();
    if (first !== undefined) {
      return first;
    }
    // The session lock makes this wait behind a commit still finishing.
    if (await this.grants.endIf(run.sessionId, { kind: "heldBy", version, holder })) {
      run.emit("refresh.indeterminate", { by: "holder", cause: "ambiguous_commit" });
      return ended("refresh_indeterminate");
    }
    // Never answer from the unchanged read itself; leave the mark otherwise.
    return (await reread()) ?? unavailable("database");
  }
}

/** Races a read against a budget; a lost race rejects with `ReadTimeoutError`. */
async function raceRead<T>(read: Promise<T>, budgetMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new ReadTimeoutError()), budgetMs);
  });
  // An abandoned read that fails later must not become an unhandled rejection.
  read.catch(() => undefined);
  try {
    return await Promise.race([read, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The refresher over a grant store, with the token endpoint, client, and
 * refresh settings from the configuration, the logger, the real transport
 * unless a test passes its own, and the host's `InFlightWork` when the
 * pool's shutdown is to wait for its runs.
 */
export const createGrantRefresher = (
  grants: GrantStore,
  config: GrantRefresherConfig,
  options: GrantRefresherOptions,
) => new GrantRefresher(grants, config, options);
