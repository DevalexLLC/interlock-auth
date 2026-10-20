import { performance } from "node:perf_hooks";

import { sql, type Kysely, type Transaction } from "kysely";

import { COMPLETE_BUDGET_MS } from "../constants.js";
import type { Lifetimes } from "../keycloak-token.js";

/**
 * One session's provider tokens, a row of `session_grant`. The access and
 * refresh tokens are Better Auth's ciphertext; the ID token is encrypted the
 * same way. Nothing here decrypts.
 */
export interface Grant {
  sessionId: string;
  keycloakSid: string;
  keycloakSubject: string;
  accessToken: string;
  accessTokenExpiresAt: Date | null;
  refreshToken: string;
  /**
   * The realm's refresh deadline, from `refresh_expires_in`; the session's
   * `expiresAt` never outlives it. Null only on grants from before 2.5, which
   * the refresher refreshes before it ever reports them usable.
   */
  refreshTokenExpiresAt: Date | null;
  idToken: string;
}

/** A stored grant, with the columns the refresh lease uses. */
export interface StoredGrant extends Grant {
  leaseHolder: string | null;
  leaseExpiresAt: Date | null;
  dispatched: boolean;
  version: number;
  createdAt: Date;
  /** When the tokens were last written: only `insert` and `complete` set it. */
  updatedAt: Date;
}

/** What a login's grant holds before its deadlines are worked out. */
export type NewGrant = Omit<Grant, "accessTokenExpiresAt" | "refreshTokenExpiresAt">;

/**
 * When a token response's lifetimes started, as `performance.now()` (the
 * callback's start for a login, the moment before the request was written
 * for a refresh), with the lifetimes. The store turns these into database
 * time at the moment it reads the database's clock, so time spent before the
 * write (a pool wait, encryption) shortens the stored remainder instead of
 * extending the deadline.
 */
export interface LifetimeAnchor {
  startedAt: number;
  lifetimes: Lifetimes;
}

/** The new tokens of a refresh, already encrypted. */
export interface RefreshedGrantTokens {
  accessToken: string;
  refreshToken: string;
  /** Replaced only when the response carried one. */
  idToken?: string;
}

export interface CompleteInput extends LifetimeAnchor {
  sessionId: string;
  version: number;
  holder: string;
  tokens: RefreshedGrantTokens;
}

/**
 * - `stored`: the holder's compare-and-swap matched and the tokens, the
 *   deadlines and the session's `expiresAt` were written.
 * - `exhausted`: the refresh deadline had already passed by the time the
 *   database read its clock, so nothing was stored and the session was ended.
 * - `unmatched`: the session is gone or the holder lost its lease.
 */
export type CompleteResult =
  | { status: "stored"; grant: StoredGrant; now: Date }
  | { status: "exhausted" }
  | { status: "unmatched" };

/**
 * The conditions under which `endIf` ends a session, each a compare-and-swap
 * on the version the caller read:
 *
 * - `expiredRefresh`: the refresh deadline passed, and no lease is live or
 *   dispatched (an expired, unmarked lease is a holder that died before
 *   sending, so it does not protect the row).
 * - `expiredDispatched`: a dispatched lease expired (README step 6, by a successor).
 * - `heldBy`: the holder's own dispatched lease (step 6, by the holder).
 */
export type EndPredicate =
  | { kind: "expiredRefresh"; version: number }
  | { kind: "expiredDispatched"; version: number }
  | { kind: "heldBy"; version: number; holder: string };

/** `complete` ran out of `COMPLETE_BUDGET_MS` and rolled back; nothing was stored. */
export class CompletionBudgetError extends Error {
  constructor() {
    super("the refresh completion ran out of its budget and rolled back");
    this.name = "CompletionBudgetError";
  }
}

/**
 * `complete` sent its COMMIT and never heard back: the write may or may not
 * have landed, and only the database can say which.
 */
export class AmbiguousCommitError extends Error {
  constructor(readonly reason: unknown) {
    super("the refresh completion sent its commit and got no answer");
    this.name = "AmbiguousCommitError";
  }
}

/**
 * Where grants live. Every lease write is a compare-and-swap on
 * `("sessionId", version)` that increments `version`, and every time it
 * compares or writes is the database's `clock_timestamp()`, so replicas need
 * no clock agreement. Transactions that touch both tables lock the session
 * row first, as every `DELETE FROM session` (whose cascade then locks the
 * grant) does, so the two orders never meet.
 */
export interface GrantStore {
  /** A login's grant: deadlines anchored at the callback's start. Returns the stored row. */
  insert(grant: NewGrant, anchor: LifetimeAnchor): Promise<StoredGrant>;
  findBySessionId(sessionId: string): Promise<StoredGrant | undefined>;
  deleteBySessionId(sessionId: string): Promise<void>;
  /** The grant and the database's clock, read in one statement. */
  read(sessionId: string): Promise<{ grant: StoredGrant; now: Date } | undefined>;
  /** Takes the lease (and clears any mark) if the version still matches. */
  claim(
    sessionId: string,
    version: number,
    holder: string,
    leaseMs: number,
  ): Promise<StoredGrant | undefined>;
  /**
   * Marks the lease dispatched and renews it, if it is still the holder's and
   * still live. Returns the new version.
   */
  markDispatched(
    sessionId: string,
    version: number,
    holder: string,
    leaseMs: number,
  ): Promise<number | undefined>;
  /** Stores a refresh's tokens under the holder's lease (see `CompleteResult`). */
  complete(input: CompleteInput): Promise<CompleteResult>;
  /** Clears the holder's lease and mark; for a request that was never sent. */
  release(sessionId: string, version: number, holder: string): Promise<boolean>;
  /** Deletes the session (the grant cascades); idempotent. */
  endSession(sessionId: string): Promise<void>;
  /**
   * Deletes the session that holds this Better Auth session token (the grant
   * cascades). Idempotent, and it throws when the statement fails, so a
   * normal return proves no such session remains.
   */
  endSessionByToken(token: string): Promise<void>;
  /** Ends the session if its grant matches the predicate; whether this call ended it. */
  endIf(sessionId: string, predicate: EndPredicate): Promise<boolean>;
  /**
   * Ends every session whose grant carries this Keycloak `sid` (back-channel
   * logout); the ended session ids. Idempotent: no match is success. A
   * session without a grant cannot match.
   */
  endSessionsBySid(keycloakSid: string): Promise<string[]>;
  /**
   * Ends every grant-backed session of this Keycloak subject (a logout token
   * with no `sid`); the ended session ids. Idempotent, like `endSessionsBySid`.
   */
  endSessionsBySubject(keycloakSubject: string): Promise<string[]>;
}

interface GrantTables {
  session_grant: StoredGrant;
  session: { id: string; token: string; expiresAt: Date };
}

/** An absolute deadline from the database's `now`, less the time since the anchor. */
export const deadlineFrom = (now: Date, seconds: number, elapsedMs: number) =>
  new Date(now.getTime() + seconds * 1000 - elapsedMs);

/** Test-only seams of `KyselyGrantStore`. */
export interface KyselyGrantStoreOptions {
  completeBudgetMs?: number;
  /** Runs inside `complete`'s transaction before each statement after the lock. */
  beforeCompleteStep?: (trx: Transaction<unknown>, step: "grant" | "session") => Promise<void>;
  /** Runs after `complete`'s last statement, just before Kysely sends COMMIT. */
  beforeCommit?: () => Promise<void>;
}

/** The database's clock, read when the statement that carries it runs. */
const clock = sql<Date>`clock_timestamp()`;

/** A lease deadline `leaseMs` after the database's now. */
const leaseUntil = (leaseMs: number) =>
  sql<Date>`clock_timestamp() + ${leaseMs} * interval '1 millisecond'`;

/** The runtime store: `session_grant` in the host's schema, over the host's one pool. */
export class KyselyGrantStore implements GrantStore {
  private readonly db: Kysely<GrantTables>;

  constructor(
    db: Kysely<unknown>,
    private readonly schema: string,
    private readonly options: KyselyGrantStoreOptions = {},
  ) {
    this.db = db as Kysely<GrantTables>;
  }

  private get table() {
    return this.db.withSchema(this.schema);
  }

  async insert(grant: NewGrant, { startedAt, lifetimes }: LifetimeAnchor) {
    const { rows } = await sql<{ now: Date }>`SELECT clock_timestamp() AS now`.execute(this.db);
    const now = rows[0]?.now;
    if (now === undefined) {
      throw new Error("clock_timestamp() returned no row");
    }
    const elapsed = performance.now() - startedAt;
    // Every column given, the column defaults' values included: the table's
    // type marks none of them generated, so Kysely requires them all.
    return this.table
      .insertInto("session_grant")
      .values({
        ...grant,
        accessTokenExpiresAt: deadlineFrom(now, lifetimes.accessExpiresIn, elapsed),
        refreshTokenExpiresAt: deadlineFrom(now, lifetimes.refreshExpiresIn, elapsed),
        leaseHolder: null,
        leaseExpiresAt: null,
        dispatched: false,
        version: 1,
        createdAt: now,
        updatedAt: now,
      })
      .returningAll()
      .executeTakeFirstOrThrow();
  }

  async findBySessionId(sessionId: string) {
    return this.table
      .selectFrom("session_grant")
      .selectAll()
      .where("sessionId", "=", sessionId)
      .executeTakeFirst();
  }

  async deleteBySessionId(sessionId: string) {
    await this.table.deleteFrom("session_grant").where("sessionId", "=", sessionId).execute();
  }

  async read(sessionId: string) {
    const row = await this.table
      .selectFrom("session_grant")
      .selectAll()
      .select(clock.as("now"))
      .where("sessionId", "=", sessionId)
      .executeTakeFirst();
    if (row === undefined) {
      return undefined;
    }
    const { now, ...grant } = row;
    return { grant, now };
  }

  async claim(sessionId: string, version: number, holder: string, leaseMs: number) {
    return this.table
      .updateTable("session_grant")
      .set((eb) => ({
        leaseHolder: holder,
        leaseExpiresAt: leaseUntil(leaseMs),
        dispatched: false,
        version: eb("version", "+", 1),
      }))
      .where("sessionId", "=", sessionId)
      .where("version", "=", version)
      .returningAll()
      .executeTakeFirst();
  }

  async markDispatched(sessionId: string, version: number, holder: string, leaseMs: number) {
    const row = await this.table
      .updateTable("session_grant")
      .set((eb) => ({
        dispatched: true,
        leaseExpiresAt: leaseUntil(leaseMs),
        version: eb("version", "+", 1),
      }))
      .where("sessionId", "=", sessionId)
      .where("version", "=", version)
      .where("leaseHolder", "=", holder)
      .where("leaseExpiresAt", ">", clock)
      .returning("version")
      .executeTakeFirst();
    return row?.version;
  }

  async complete({ sessionId, version, holder, tokens, startedAt, lifetimes }: CompleteInput) {
    const budgetMs = this.options.completeBudgetMs ?? COMPLETE_BUDGET_MS;
    let committing = false;
    try {
      return await this.db.transaction().execute(async (trx) => {
        const begun = performance.now();
        // The budget cannot interrupt a statement in flight or Kysely's
        // COMMIT; it stops the next statement, and Kysely then rolls back on
        // the same connection.
        const step = async (name: "grant" | "session") => {
          await this.options.beforeCompleteStep?.(trx as Transaction<unknown>, name);
          if (performance.now() - begun > budgetMs) {
            throw new CompletionBudgetError();
          }
        };
        const table = trx.withSchema(this.schema);

        const locked = await table
          .selectFrom("session")
          .select(clock.as("now"))
          .where("id", "=", sessionId)
          .forUpdate()
          .executeTakeFirst();
        if (locked === undefined) {
          return { status: "unmatched" } as const;
        }
        const { now } = locked;
        const elapsed = performance.now() - startedAt;
        const accessTokenExpiresAt = deadlineFrom(now, lifetimes.accessExpiresIn, elapsed);
        const refreshTokenExpiresAt = deadlineFrom(now, lifetimes.refreshExpiresIn, elapsed);

        await step("grant");
        if (refreshTokenExpiresAt.getTime() <= now.getTime()) {
          // Keycloak built the response with seconds of realm lifetime left,
          // and they ran out before it could be stored.
          const ended = await this.endUnder(trx, sessionId, { kind: "heldBy", version, holder });
          committing = true;
          return { status: ended ? "exhausted" : "unmatched" } as const;
        }
        const grant = await table
          .updateTable("session_grant")
          .set((eb) => ({
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            ...(tokens.idToken === undefined ? {} : { idToken: tokens.idToken }),
            accessTokenExpiresAt,
            refreshTokenExpiresAt,
            updatedAt: now,
            leaseHolder: null,
            leaseExpiresAt: null,
            dispatched: false,
            version: eb("version", "+", 1),
          }))
          .where("sessionId", "=", sessionId)
          .where("version", "=", version)
          .where("leaseHolder", "=", holder)
          .returningAll()
          .executeTakeFirst();
        if (grant === undefined) {
          return { status: "unmatched" } as const;
        }

        await step("session");
        await table
          .updateTable("session")
          .set({ expiresAt: refreshTokenExpiresAt })
          .where("id", "=", sessionId)
          .execute();
        await this.options.beforeCommit?.();
        committing = true;
        return { status: "stored", grant, now } as const;
      });
    } catch (err) {
      // The callback finished, so the error came from COMMIT itself.
      if (committing) {
        throw new AmbiguousCommitError(err);
      }
      throw err;
    }
  }

  async release(sessionId: string, version: number, holder: string) {
    const { numUpdatedRows } = await this.table
      .updateTable("session_grant")
      .set((eb) => ({
        leaseHolder: null,
        leaseExpiresAt: null,
        dispatched: false,
        version: eb("version", "+", 1),
      }))
      .where("sessionId", "=", sessionId)
      .where("version", "=", version)
      .where("leaseHolder", "=", holder)
      .executeTakeFirst();
    return Number(numUpdatedRows) > 0;
  }

  async endSession(sessionId: string) {
    await this.table.deleteFrom("session").where("id", "=", sessionId).execute();
  }

  async endSessionByToken(token: string) {
    await this.table.deleteFrom("session").where("token", "=", token).execute();
  }

  async endIf(sessionId: string, predicate: EndPredicate) {
    return this.db.transaction().execute(async (trx) => this.endUnder(trx, sessionId, predicate));
  }

  async endSessionsBySid(keycloakSid: string) {
    return this.endSessionsWhere("keycloakSid", keycloakSid);
  }

  async endSessionsBySubject(keycloakSubject: string) {
    return this.endSessionsWhere("keycloakSubject", keycloakSubject);
  }

  /**
   * One statement: deletes the sessions whose grant matches, so each session
   * row is locked before its grant, as the cascade always does.
   */
  private async endSessionsWhere(column: "keycloakSid" | "keycloakSubject", value: string) {
    const rows = await this.table
      .deleteFrom("session")
      .where("id", "in", (eb) =>
        eb.selectFrom("session_grant").select("sessionId").where(column, "=", value),
      )
      .returning("id")
      .execute();
    return rows.map((row) => row.id);
  }

  /** `endIf`'s statements, inside a transaction the caller owns. */
  private async endUnder(
    trx: Transaction<GrantTables>,
    sessionId: string,
    predicate: EndPredicate,
  ) {
    const table = trx.withSchema(this.schema);
    const locked = await table
      .selectFrom("session")
      .select("id")
      .where("id", "=", sessionId)
      .forUpdate()
      .executeTakeFirst();
    if (locked === undefined) {
      return false;
    }
    const now = clock;
    const { numDeletedRows } = await table
      .deleteFrom("session_grant")
      .where("sessionId", "=", sessionId)
      .where("version", "=", predicate.version)
      .where((eb) => {
        if (predicate.kind === "expiredRefresh") {
          return eb.and([
            eb("refreshTokenExpiresAt", "<=", now),
            eb.or([
              eb("leaseHolder", "is", null),
              eb.and([eb("dispatched", "=", false), eb("leaseExpiresAt", "<=", now)]),
            ]),
          ]);
        }
        if (predicate.kind === "expiredDispatched") {
          return eb.and([eb("dispatched", "=", true), eb("leaseExpiresAt", "<=", now)]);
        }
        return eb.and([eb("leaseHolder", "=", predicate.holder), eb("dispatched", "=", true)]);
      })
      .executeTakeFirst();
    if (Number(numDeletedRows) === 0) {
      return false;
    }
    await table.deleteFrom("session").where("id", "=", sessionId).execute();
    return true;
  }
}
