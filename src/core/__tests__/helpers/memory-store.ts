import { performance } from "node:perf_hooks";

import { memoryAdapter } from "better-auth/adapters/memory";
import { getAuthTables } from "better-auth/db";

import { createKeycloakAuthOptions } from "../../auth.options.js";
import type { KeycloakAuthConfig } from "../../config.js";
import {
  deadlineFrom,
  type CompleteInput,
  type CompleteResult,
  type EndPredicate,
  type GrantStore,
  type LifetimeAnchor,
  type NewGrant,
  type StoredGrant,
} from "../../grants/grant-store.js";
import type { AuthLogger } from "../../logger.js";
import { testLogger } from "./config.js";

/** One row of a memory adapter table. */
export type MemoryRow = Record<string, unknown>;

/**
 * The memory adapter's tables, by model name, for specs that inspect rows. `session` and `account`
 * are always there; any other model may not be.
 */
export interface MemoryTables {
  session: MemoryRow[];
  account: MemoryRow[];
  [model: string]: MemoryRow[];
}

/**
 * `session_grant` in memory, for unit specs, with the compare-and-swap semantics of
 * `KyselyGrantStore` (Interlock's Postgres refresh suite holds the two to the same
 * cases on Postgres). Its "database" clock is its own: the real monotonic time plus an offset
 * specs move with `advance`, independent of `Date.now()`, so a spec can skew the application
 * clock alone.
 *
 * Session rows live in `tables.session`: Better Auth's memory tables when `createMemoryAuthSetup`
 * attaches them, or rows a spec adds with `addSession`. Ending a session deletes both rows, as the
 * foreign key's cascade does; a grant whose session row is gone reads as absent.
 *
 * A copy of Interlock's own memory store, made strict; the two drift unless both are
 * changed together.
 */
export class MemoryGrantStore implements GrantStore {
  rows: StoredGrant[] = [];
  tables: MemoryTables = { session: [], account: [] };
  private offset = 0;

  /** The store's clock, as `clock_timestamp()` would read it. */
  now() {
    return new Date(Math.floor(performance.timeOrigin + performance.now() + this.offset));
  }

  /** Moves the store's clock; `Date.now()` is untouched. */
  advance(ms: number) {
    this.offset += ms;
  }

  addSession(id: string, expiresAt = new Date(this.now().getTime() + 7 * 86400_000)) {
    this.tables.session.push({ id, token: `token-${id}`, expiresAt });
  }

  session(id: string) {
    return this.tables.session.find((row) => row.id === id);
  }

  private row(sessionId: string) {
    const row = this.rows.find((r) => r.sessionId === sessionId);
    if (row !== undefined && this.session(sessionId) === undefined) {
      this.rows = this.rows.filter((r) => r !== row);
      return undefined;
    }
    return row;
  }

  private dropSession(sessionId: string) {
    this.tables.session = this.tables.session.filter((row) => row.id !== sessionId);
    this.rows = this.rows.filter((row) => row.sessionId !== sessionId);
  }

  async insert(grant: NewGrant, { startedAt, lifetimes }: LifetimeAnchor) {
    if (this.rows.some((row) => row.sessionId === grant.sessionId)) {
      throw new Error(`duplicate session grant ${grant.sessionId}`);
    }
    const now = this.now();
    const elapsed = performance.now() - startedAt;
    const row: StoredGrant = {
      ...grant,
      accessTokenExpiresAt: deadlineFrom(now, lifetimes.accessExpiresIn, elapsed),
      refreshTokenExpiresAt: deadlineFrom(now, lifetimes.refreshExpiresIn, elapsed),
      leaseHolder: null,
      leaseExpiresAt: null,
      dispatched: false,
      version: 1,
      createdAt: now,
      updatedAt: now,
    };
    this.rows.push(row);
    return { ...row };
  }

  async findBySessionId(sessionId: string) {
    const row = this.row(sessionId);
    return row && { ...row };
  }

  async deleteBySessionId(sessionId: string) {
    this.rows = this.rows.filter((row) => row.sessionId !== sessionId);
  }

  async read(sessionId: string) {
    const row = this.row(sessionId);
    return row && { grant: { ...row }, now: this.now() };
  }

  async claim(sessionId: string, version: number, holder: string, leaseMs: number) {
    const row = this.row(sessionId);
    if (row?.version !== version) {
      return undefined;
    }
    Object.assign(row, {
      leaseHolder: holder,
      leaseExpiresAt: new Date(this.now().getTime() + leaseMs),
      dispatched: false,
      version: version + 1,
    });
    return { ...row };
  }

  async markDispatched(sessionId: string, version: number, holder: string, leaseMs: number) {
    const row = this.row(sessionId);
    const now = this.now();
    if (
      row?.version !== version ||
      row.leaseHolder !== holder ||
      row.leaseExpiresAt === null ||
      row.leaseExpiresAt <= now
    ) {
      return undefined;
    }
    Object.assign(row, {
      dispatched: true,
      leaseExpiresAt: new Date(now.getTime() + leaseMs),
      version: version + 1,
    });
    return row.version;
  }

  async complete({
    sessionId,
    version,
    holder,
    tokens,
    startedAt,
    lifetimes,
  }: CompleteInput): Promise<CompleteResult> {
    const session = this.session(sessionId);
    if (session === undefined) {
      return { status: "unmatched" };
    }
    const now = this.now();
    const elapsed = performance.now() - startedAt;
    const accessTokenExpiresAt = deadlineFrom(now, lifetimes.accessExpiresIn, elapsed);
    const refreshTokenExpiresAt = deadlineFrom(now, lifetimes.refreshExpiresIn, elapsed);
    if (refreshTokenExpiresAt.getTime() <= now.getTime()) {
      const ended = await this.endIf(sessionId, { kind: "heldBy", version, holder });
      return { status: ended ? "exhausted" : "unmatched" };
    }
    const row = this.row(sessionId);
    if (row?.version !== version || row.leaseHolder !== holder) {
      return { status: "unmatched" };
    }
    Object.assign(row, {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      ...(tokens.idToken === undefined ? {} : { idToken: tokens.idToken }),
      accessTokenExpiresAt,
      refreshTokenExpiresAt,
      updatedAt: now,
      leaseHolder: null,
      leaseExpiresAt: null,
      dispatched: false,
      version: version + 1,
    });
    session.expiresAt = refreshTokenExpiresAt;
    return { status: "stored", grant: { ...row }, now };
  }

  async release(sessionId: string, version: number, holder: string) {
    const row = this.row(sessionId);
    if (row?.version !== version || row.leaseHolder !== holder) {
      return false;
    }
    Object.assign(row, {
      leaseHolder: null,
      leaseExpiresAt: null,
      dispatched: false,
      version: version + 1,
    });
    return true;
  }

  async endSession(sessionId: string) {
    this.dropSession(sessionId);
  }

  async endSessionByToken(token: string) {
    for (const row of this.tables.session.filter((session) => session.token === token)) {
      this.dropSession(String(row.id));
    }
  }

  async endIf(sessionId: string, predicate: EndPredicate) {
    const row = this.row(sessionId);
    const now = this.now();
    if (row === undefined || row.version !== predicate.version) {
      return false;
    }
    const leaseExpired = row.leaseExpiresAt !== null && row.leaseExpiresAt <= now;
    let matches: boolean;
    if (predicate.kind === "expiredRefresh") {
      matches =
        row.refreshTokenExpiresAt !== null &&
        row.refreshTokenExpiresAt <= now &&
        (row.leaseHolder === null || (!row.dispatched && leaseExpired));
    } else if (predicate.kind === "expiredDispatched") {
      matches = row.dispatched && leaseExpired;
    } else {
      matches = row.leaseHolder === predicate.holder && row.dispatched;
    }
    if (matches) {
      this.dropSession(sessionId);
    }
    return matches;
  }

  async endSessionsBySid(keycloakSid: string) {
    return this.endSessionsWhere((row) => row.keycloakSid === keycloakSid);
  }

  async endSessionsBySubject(keycloakSubject: string) {
    return this.endSessionsWhere((row) => row.keycloakSubject === keycloakSubject);
  }

  private endSessionsWhere(matches: (row: StoredGrant) => boolean) {
    const ended = this.rows
      .filter((row) => matches(row) && this.session(row.sessionId) !== undefined)
      .map((row) => row.sessionId);
    for (const sessionId of ended) {
      this.dropSession(sessionId);
    }
    return ended;
  }
}

/**
 * The package's Better Auth options on an in-memory store, for specs that build a real instance
 * without Postgres, with the tables and the grant store returned so specs can inspect them. Every
 * table is seeded, because the memory adapter throws `Model <name> not found` on the first query
 * of a table it was not given. Each call returns a fresh store.
 */
export function createMemoryAuthSetup(
  config: KeycloakAuthConfig,
  grants: GrantStore = new MemoryGrantStore(),
  logger: AuthLogger = testLogger(),
) {
  const authTables = getAuthTables(
    createKeycloakAuthOptions(config, { database: memoryAdapter({}), grants, logger }),
  );
  const tables: MemoryTables = {
    session: [],
    account: [],
    ...Object.fromEntries(Object.keys(authTables).map((table) => [table, []])),
  };
  if (grants instanceof MemoryGrantStore) {
    grants.tables = tables;
  }
  return {
    options: createKeycloakAuthOptions(config, {
      database: memoryAdapter(tables),
      grants,
      logger,
    }),
    tables,
    grants,
    logger,
  };
}

/** The options alone, for specs that only need a real instance. */
export const createMemoryAuthOptions = (config: KeycloakAuthConfig, logger?: AuthLogger) =>
  createMemoryAuthSetup(config, undefined, logger).options;
