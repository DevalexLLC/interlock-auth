import { performance } from "node:perf_hooks";
import { setTimeout as sleep } from "node:timers/promises";

import { betterAuth } from "better-auth";
import { decryptOAuthToken } from "better-auth/oauth2";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { RefreshConfig } from "../../config.js";
import { encryptToken } from "../../encrypt-token.js";
import {
  AmbiguousCommitError,
  CompletionBudgetError,
  type CompleteInput,
  type StoredGrant,
} from "../../grants/grant-store.js";
import {
  DEPENDENCY_FAILURE,
  refreshResponse,
  SESSION_INVALID,
} from "../../grants/refresh-responses.js";
import {
  createGrantRefresher,
  MAX_ROUNDS,
  type AuthContext,
  type RefreshOutcome,
} from "../../grants/refresh.js";
import type { LogRecord } from "../../logger.js";
import { defined, TEST_CONFIG, testLogger, type TestLogger } from "../helpers/config.js";
import { FakeKeycloak, fakeTransport, SUBJECT } from "../helpers/fake-keycloak.js";
import { createMemoryAuthOptions, MemoryGrantStore } from "../helpers/memory-store.js";

/** Short values that still meet the configuration's bounds. */
const SETTINGS: RefreshConfig = {
  requestTimeoutMs: 200,
  leaseMs: 8200,
  waitMs: 400,
  leewayMs: 60000,
};

/** A refresh event's record (`refresh-events.ts`). */
type Event = LogRecord & { event: string; sessionId: string; leaseHolder: string | null };

/** The terminal events of a dispatched attempt (refresh-events.ts). */
const TERMINAL = new Set(["refresh.succeeded", "refresh.invalid_grant", "refresh.indeterminate"]);

const lease = (
  store: MemoryGrantStore,
  msFromNow: number,
  holder = "dead#1#x",
  dispatched = false,
) => ({
  leaseHolder: holder,
  leaseExpiresAt: new Date(store.now().getTime() + msFromNow),
  dispatched,
});

const grantOf = (store: MemoryGrantStore, id = "s1") => store.rows.find((r) => r.sessionId === id);

// Move both the monotonic clock and MemoryGrantStore's clock without
// sleeping, so expiry during an awaited operation is deterministic.
const clock = () => {
  const now = performance.now.bind(performance);
  let elapsed = 0;
  vi.spyOn(performance, "now").mockImplementation(() => now() + elapsed);
  return (ms: number) => {
    elapsed += ms;
  };
};

const expiredOnArrival = (keycloak: FakeKeycloak) => {
  keycloak.onRefresh = () => {
    keycloak.nextRefresh = { delayMs: 1100, fields: { expires_in: 1 } };
  };
  keycloak.nextRefresh = { delayMs: 1100, fields: { expires_in: 1 } };
};

/** `complete` that runs `effect` and then reports a lost COMMIT acknowledgement. */
const ambiguous = (store: MemoryGrantStore, effect: (input: CompleteInput) => Promise<unknown>) => {
  store.complete = async (input) => {
    await effect(input);
    throw new AmbiguousCommitError(new Error("Connection terminated"));
  };
};

/**
 * The state machine of section D on `MemoryGrantStore`, whose clock is its
 * own, with Keycloak faked behind the two-phase transport. Every timestamp
 * a test sets is the store's time.
 */
describe("GrantRefresher", () => {
  let ctx: AuthContext;
  let logger: TestLogger;

  beforeAll(async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
    ctx = await betterAuth(createMemoryAuthOptions(TEST_CONFIG)).$context;
    vi.restoreAllMocks();
  });

  beforeEach(() => {
    logger = testLogger();
  });

  afterEach(() => vi.restoreAllMocks());

  /** Every refresh event, in the order it was logged, whatever the level. */
  const events = (): Event[] =>
    [logger.log, logger.error]
      .flatMap((level) =>
        level.mock.calls.map(([record], i) => ({
          record,
          order: level.mock.invocationCallOrder[i] ?? 0,
        })),
      )
      .toSorted((a, b) => a.order - b.order)
      .map(({ record }) => record)
      .filter((record): record is Event => typeof record.event === "string");

  const names = () => events().map((e) => e.event);

  const setup = (settings: Partial<RefreshConfig> = {}) => {
    const store = new MemoryGrantStore();
    const keycloak = new FakeKeycloak();
    const make = () =>
      createGrantRefresher(
        store,
        { keycloak: TEST_CONFIG.keycloak, refresh: { ...SETTINGS, ...settings } },
        { logger, transport: fakeTransport(keycloak) },
      );
    return { store, keycloak, refresher: make(), make };
  };

  /**
   * A session with a grant, timed in ms from the store's now: by default a
   * fresh access token (300 s of 300 s left) and 1800 s of realm deadline.
   */
  const seed = async (
    store: MemoryGrantStore,
    {
      id = "s1",
      accessMs = 300_000,
      refreshMs = 1_800_000 as number | null,
      issuedMs = 0,
      ...row
    }: Partial<StoredGrant> & {
      id?: string;
      accessMs?: number;
      refreshMs?: number | null;
      issuedMs?: number;
    } = {},
  ) => {
    const now = store.now().getTime();
    store.addSession(id);
    store.rows.push({
      sessionId: id,
      keycloakSid: "sid-1",
      keycloakSubject: SUBJECT,
      accessToken: await encryptToken("access-0", ctx),
      refreshToken: await encryptToken("refresh-0", ctx),
      idToken: await encryptToken("id-0", ctx),
      accessTokenExpiresAt: new Date(now + accessMs),
      refreshTokenExpiresAt: refreshMs === null ? null : new Date(now + refreshMs),
      leaseHolder: null,
      leaseExpiresAt: null,
      dispatched: false,
      version: 1,
      createdAt: new Date(now - issuedMs),
      updatedAt: new Date(now - issuedMs),
      ...row,
    });
    return id;
  };

  /** Due: 30 s left of a 300 s access token, inside the 60 s leeway. */
  const DUE = { accessMs: 30_000, issuedMs: 270_000 };

  /** `grantOf`, for a grant the case knows is there. */
  const rowOf = (store: MemoryGrantStore, id = "s1") => defined(grantOf(store, id), `grant ${id}`);
  const decrypt = async (value: string) => decryptOAuthToken(value, ctx);

  /** Exactly one terminal event per dispatched attempt, by `leaseHolder`. */
  const expectOneTerminalPerDispatch = () => {
    for (const dispatched of events().filter((e) => e.event === "refresh.dispatched")) {
      const terminals = events().filter(
        (e) => TERMINAL.has(e.event) && e.leaseHolder === dispatched.leaseHolder,
      );
      expect(terminals).toHaveLength(1);
    }
  };

  describe("a grant that is not due", () => {
    it("should answer ok without calling Keycloak", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store);

      const outcome = await refresher.refreshIfDue("s1", ctx);

      expect(outcome).toMatchObject({ kind: "ok", refreshed: false });
      expect(keycloak.refreshes).toBe(0);
      expect(names()).toEqual([]);
    });

    it("should hand back the decrypted access token with its remaining life", async () => {
      const { store, refresher } = setup();
      await seed(store);

      const outcome = await refresher.resolveAccessToken("s1", ctx);

      expect(outcome).toMatchObject({ kind: "ok", accessToken: "access-0", refreshed: false });
      expect(outcome.kind === "ok" && outcome.expiresInMs).toBeGreaterThan(299_000);
    });
  });

  describe("a due grant", () => {
    it("should refresh once, store the new tokens and move the session to the new deadline", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, DUE);
      // The mark is in place before the request leaves.
      let markedWhenSent: boolean | undefined;
      keycloak.onRefresh = () => {
        markedWhenSent = rowOf(store).dispatched;
      };
      const before = store.now().getTime();

      const outcome = await refresher.refreshIfDue("s1", ctx);
      const grant = rowOf(store);

      expect(outcome).toMatchObject({ kind: "ok", refreshed: true });
      expect(keycloak.refreshedWith).toEqual(["refresh-0"]);
      expect(markedWhenSent).toBe(true);
      await expect(decrypt(grant.accessToken)).resolves.toBe("access-refreshed-1");
      await expect(decrypt(grant.refreshToken)).resolves.toBe("refresh-refreshed-1");
      await expect(decrypt(grant.idToken)).resolves.toBe(
        keycloak.idTokens[keycloak.idTokens.length - 1],
      );
      expect(grant).toMatchObject({ leaseHolder: null, leaseExpiresAt: null, dispatched: false });
      // claim, mark, complete
      expect(grant.version).toBe(4);
      expect(defined(grant.refreshTokenExpiresAt).getTime() - before).toBeGreaterThan(1_799_000);
      expect(defined(grant.refreshTokenExpiresAt).getTime() - before).toBeLessThanOrEqual(
        1_800_000 + 50,
      );
      expect(defined(store.session("s1")).expiresAt).toEqual(grant.refreshTokenExpiresAt);
      expect(names()).toEqual(["refresh.dispatched", "refresh.succeeded"]);
      const [dispatched, succeeded] = events();
      expect(succeeded).toMatchObject({
        sessionId: "s1",
        leaseHolder: defined(dispatched).leaseHolder,
        refreshExpiresAt: defined(grant.refreshTokenExpiresAt).toISOString(),
        accessExpiresAt: defined(grant.accessTokenExpiresAt).toISOString(),
      });
      expect(defined(dispatched).leaseHolder).toMatch(/^.+#\d+#[0-9a-f-]{36}$/);

      // A second call has nothing to do.
      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({ refreshed: false });
      expect(keycloak.refreshes).toBe(1);
    });

    it("should refresh a 2.4 grant that has no refresh deadline before calling it usable", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, { refreshMs: null });

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({ refreshed: true });
      expect(keycloak.refreshes).toBe(1);
      expect(rowOf(store).refreshTokenExpiresAt).toBeInstanceOf(Date);
    });

    it("should refresh when the realm deadline is inside the leeway though the access token is fresh", async () => {
      const { store, keycloak, refresher } = setup();
      // 30 s left of an 1800 s realm deadline; 300 s of access left.
      await seed(store, { refreshMs: 30_000, issuedMs: 1_770_000 });

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({ refreshed: true });
      expect(keycloak.refreshes).toBe(1);
    });

    // The cap: a leeway at or above the token's lifetime would make every
    // fresh token due, and the waiter would refresh again.
    it("should make one request for two callers when the leeway exceeds the token lifetime", async () => {
      const { store, keycloak, make } = setup({ leewayMs: 300_000 });
      await seed(store, DUE);
      keycloak.nextRefresh = { delayMs: 50 };

      const outcomes = await Promise.all([
        make().refreshIfDue("s1", ctx),
        make().refreshIfDue("s1", ctx),
      ]);

      expect(outcomes.map((o) => o.kind)).toEqual(["ok", "ok"]);
      expect(keycloak.refreshes).toBe(1);
      expect(names().filter((n) => n === "refresh.waited")).toEqual(["refresh.waited"]);
      expect(events().find((e) => e.event === "refresh.waited")).toMatchObject({ result: "ok" });
    });
  });

  describe("the session deadline", () => {
    it("should end a session whose stored refresh deadline has passed, without Keycloak", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, { refreshMs: -1 });

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "ended",
        reason: "refresh_expired",
      });
      expect(store.session("s1")).toBeUndefined();
      expect(grantOf(store)).toBeUndefined();
      expect(keycloak.refreshes).toBe(0);
    });

    it("should end a session with no grant", async () => {
      const { store, refresher } = setup();
      store.addSession("bare");

      await expect(refresher.refreshIfDue("bare", ctx)).resolves.toEqual({
        kind: "ended",
        reason: "no_grant",
      });
      expect(store.session("bare")).toBeUndefined();
    });

    // The version predicate: a stale deadline never deletes a renewed session.
    it("should not end a session a holder renewed between the read and the delete", async () => {
      const { store, refresher } = setup();
      await seed(store, { refreshMs: -1 });
      const endIf = store.endIf.bind(store);
      store.endIf = async (sessionId, predicate) => {
        const row = rowOf(store, sessionId);
        // The holder's completion commits first.
        Object.assign(row, {
          version: row.version + 3,
          refreshTokenExpiresAt: new Date(store.now().getTime() + 1_800_000),
          accessTokenExpiresAt: new Date(store.now().getTime() + 300_000),
          updatedAt: store.now(),
        });
        store.endIf = endIf;
        return endIf(sessionId, predicate);
      };

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({
        kind: "ok",
        refreshed: false,
      });
      expect(store.session("s1")).toBeDefined();
    });

    // A holder that dispatched just before the deadline may be extending the
    // session at Keycloak; the caller arriving after it waits.
    it("should wait for a holder dispatched just before the deadline, not end the session", async () => {
      const { store, keycloak, make } = setup({
        requestTimeoutMs: 1000,
        leaseMs: 9000,
        waitMs: 1000,
      });
      await seed(store, { refreshMs: 150, issuedMs: 1_799_850 });
      keycloak.nextRefresh = { delayMs: 400 };

      const holder = make().refreshIfDue("s1", ctx);
      await sleep(100);
      expect(rowOf(store).dispatched).toBe(true);
      await sleep(100);
      // The stored deadline has passed; the lease is live.
      expect(defined(rowOf(store).refreshTokenExpiresAt).getTime()).toBeLessThan(
        store.now().getTime(),
      );
      const late = await make().refreshIfDue("s1", ctx);

      expect(await holder).toMatchObject({ kind: "ok", refreshed: true });
      expect(late).toMatchObject({ kind: "ok", refreshed: false });
      expect(store.session("s1")).toBeDefined();
      expect(keycloak.refreshes).toBe(1);
    });
  });

  describe("Keycloak answers", () => {
    it("should end the session on invalid_grant", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, DUE);
      keycloak.nextRefresh = { invalidGrant: true };

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "ended",
        reason: "invalid_grant",
      });
      expect(store.session("s1")).toBeUndefined();
      expect(names()).toEqual(["refresh.dispatched", "refresh.invalid_grant"]);
    });

    it("should release the lease on a request that was never sent", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, DUE);
      keycloak.nextRefresh = { connectFail: "ECONNREFUSED" };

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "unavailable",
        reason: "keycloak_unreachable",
      });
      const grant = rowOf(store);
      expect(grant).toMatchObject({ leaseHolder: null, dispatched: false, version: 4 });
      await expect(decrypt(grant.refreshToken)).resolves.toBe("refresh-0");
      expect(keycloak.refreshes).toBe(0);
      expect(names()).toEqual(["refresh.unsent"]);
      expect(events()[0]).toMatchObject({ cause: "ECONNREFUSED" });

      // The stored token is unused, so the next caller refreshes normally.
      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({ refreshed: true });
      expect(keycloak.refreshedWith).toEqual(["refresh-0"]);
    });

    it("should be unsent when the deadline passes while connecting", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, DUE);
      keycloak.nextRefresh = { connectDelayMs: 500 };

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({
        reason: "keycloak_unreachable",
      });
      expect(names()).toEqual(["refresh.unsent"]);
    });

    it.each([
      ["a lost answer", { sentFail: "ECONNRESET" }, "ECONNRESET"],
      ["the deadline after sending", { hang: true }, "timeout"],
      ["a 5xx", { status: 502 }, "502"],
      ["invalid_client", { status: 401, error: "invalid_client" }, "401"],
      [
        "a 200 without refresh_expires_in",
        { fields: { refresh_expires_in: undefined } },
        "malformed_response",
      ],
    ])("should end the session without replay on %s", async (_case, next, cause) => {
      const { store, keycloak, refresher } = setup();
      await seed(store, DUE);
      keycloak.nextRefresh = next;

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "ended",
        reason: "refresh_indeterminate",
      });
      expect(store.session("s1")).toBeUndefined();
      expect(keycloak.refreshes).toBe(1);
      expect(names()).toEqual(["refresh.dispatched", "refresh.indeterminate"]);
      expect(events()[1]).toMatchObject({ by: "holder", cause });
    });
  });

  describe("concurrent callers", () => {
    it("should make one request for two callers; the loser waits and uses the result", async () => {
      const { store, keycloak, make } = setup();
      await seed(store, DUE);
      keycloak.nextRefresh = { delayMs: 100 };

      const outcomes = await Promise.all([
        make().refreshIfDue("s1", ctx),
        make().refreshIfDue("s1", ctx),
      ]);

      expect(outcomes.map((o) => o.kind === "ok" && o.refreshed)).toEqual(
        expect.arrayContaining([false, true]),
      );
      expect(keycloak.refreshes).toBe(1);
      expect(names().toSorted()).toEqual([
        "refresh.dispatched",
        "refresh.succeeded",
        "refresh.waited",
      ]);
    });

    it("should give up waiting on a live lease after the wait bound, leaving the session intact", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, { ...DUE, ...lease(store, 8000, "live#1#x", true) });
      const start = performance.now();

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "unavailable",
        reason: "refresh_in_progress",
      });
      const took = performance.now() - start;
      expect(took).toBeGreaterThanOrEqual(SETTINGS.waitMs - 5);
      expect(took).toBeLessThan(SETTINGS.waitMs + 300);
      expect(store.session("s1")).toBeDefined();
      expect(keycloak.refreshes).toBe(0);
      expect(events()).toEqual([
        expect.objectContaining({
          event: "refresh.waited",
          result: "timed_out",
          leaseHolder: "live#1#x",
        }),
      ]);
    });

    // A waiter that arrives late in a lease is never held past the lease's end.
    it("should leave the wait when the lease of a holder that died expires, and recover it", async () => {
      const { store, keycloak, refresher } = setup({ waitMs: 2000 });
      await seed(store, { ...DUE, ...lease(store, 150) });
      const start = performance.now();

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({ refreshed: true });
      expect(performance.now() - start).toBeLessThan(1000);
      expect(keycloak.refreshes).toBe(1);
      expect(names()).toEqual([
        "refresh.waited",
        "refresh.lease_recovered",
        "refresh.dispatched",
        "refresh.succeeded",
      ]);
      expect(events()[1]).toMatchObject({ recoveredFrom: "dead#1#x" });
    });

    it("should record one recovery when two callers read one expired, unmarked lease", async () => {
      const { store, keycloak, make } = setup();
      await seed(store, { ...DUE, ...lease(store, -1) });
      keycloak.nextRefresh = { delayMs: 50 };

      const outcomes = await Promise.all([
        make().refreshIfDue("s1", ctx),
        make().refreshIfDue("s1", ctx),
      ]);

      expect(outcomes.map((o) => o.kind)).toEqual(["ok", "ok"]);
      expect(keycloak.refreshes).toBe(1);
      expect(names().filter((n) => n === "refresh.lease_recovered")).toHaveLength(1);
    });

    // README step 6, by a successor: the dead holder's attempt ends with the reason.
    it("should end a session whose dispatched lease expired, without replay", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, { ...DUE, ...lease(store, -1, "dead#1#x", true) });

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "ended",
        reason: "refresh_indeterminate",
      });
      expect(store.session("s1")).toBeUndefined();
      expect(keycloak.refreshes).toBe(0);
      expect(events()).toEqual([
        expect.objectContaining({
          event: "refresh.indeterminate",
          by: "successor",
          leaseHolder: "dead#1#x",
        }),
      ]);
    });

    it("should give the reason to exactly one of two successors", async () => {
      const { store, make } = setup();
      await seed(store, { ...DUE, ...lease(store, -1, "dead#1#x", true) });

      const outcomes = await Promise.all([
        make().refreshIfDue("s1", ctx),
        make().refreshIfDue("s1", ctx),
      ]);

      expect(outcomes).toEqual(
        expect.arrayContaining([
          { kind: "ended", reason: "refresh_indeterminate" },
          { kind: "ended", reason: "ended_elsewhere" },
        ]),
      );
      expect(names()).toEqual(["refresh.indeterminate"]);
    });

    // Keycloak is never called under an expired lease.
    it("should recover its own lease when it expires between the claim and the mark", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, DUE);
      const claim = store.claim.bind(store);
      store.claim = async (...args) => {
        const row = await claim(...args);
        store.claim = claim;
        store.advance(SETTINGS.leaseMs + 1);
        return row;
      };

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({ refreshed: true });
      expect(keycloak.refreshes).toBe(1);
      expect(names()).toEqual([
        "refresh.lease_recovered",
        "refresh.dispatched",
        "refresh.succeeded",
      ]);
      const [recovered, dispatched] = events();
      expect(defined(recovered).recoveredFrom).not.toBe(defined(dispatched).leaseHolder);
    });

    it("should stop after a bounded number of rounds", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, DUE);
      let reads = 0;
      const read = store.read.bind(store);
      store.read = async (id) => {
        reads += 1;
        return read(id);
      };
      store.claim = async () => undefined;

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "unavailable",
        reason: "refresh_in_progress",
      });
      expect(reads).toBe(MAX_ROUNDS);
      expect(keycloak.refreshes).toBe(0);
    });
  });

  describe("a holder that outlives its lease", () => {
    /**
     * Right after the mark, the holder pauses past its lease and a successor
     * ends the attempt (step 6); then the holder carries on with `next`.
     */
    const pausedHolder = async (next: FakeKeycloak["nextRefresh"]) => {
      const { store, keycloak, make } = setup();
      await seed(store, DUE);
      let successor: RefreshOutcome | undefined;
      const mark = store.markDispatched.bind(store);
      store.markDispatched = async (...args) => {
        const version = await mark(...args);
        store.markDispatched = mark;
        store.advance(SETTINGS.leaseMs + 1);
        successor = await make().refreshIfDue("s1", ctx);
        keycloak.nextRefresh = next;
        return version;
      };
      const holder = await make().refreshIfDue("s1", ctx);
      return { holder, successor, store, keycloak };
    };

    it.each([
      ["a success", {}],
      ["invalid_grant", { invalidGrant: true }],
      ["an unsent failure", { connectFail: "ECONNREFUSED" }],
      ["a timeout", { hang: true }],
    ])("should report only lease_lost when it comes back with %s", async (_case, next) => {
      const { holder, successor, store } = await pausedHolder(next);

      expect(successor).toEqual({ kind: "ended", reason: "refresh_indeterminate" });
      expect(holder).toEqual({ kind: "ended", reason: "ended_elsewhere" });
      expect(store.session("s1")).toBeUndefined();
      const all = events();
      const indeterminate = all.filter((e) => e.event === "refresh.indeterminate");
      const lost = all.filter((e) => e.event === "refresh.lease_lost");
      expect(indeterminate).toEqual([expect.objectContaining({ by: "successor" })]);
      expect(lost).toHaveLength(1);
      expect(defined(lost[0]).leaseHolder).toBe(defined(indeterminate[0]).leaseHolder);
      expect(
        all.filter((e) =>
          ["refresh.succeeded", "refresh.invalid_grant", "refresh.unsent"].includes(e.event),
        ),
      ).toEqual([]);
      expectOneTerminalPerDispatch();
    });

    it("should answer plain, never with the reason, when a sign-out ended the session during the request", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, DUE);
      keycloak.nextRefresh = { hang: true };
      keycloak.onRefresh = async () => store.endSession("s1");

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "ended",
        reason: "ended_elsewhere",
      });
      expect(names()).toEqual(["refresh.dispatched", "refresh.lease_lost"]);
    });
  });

  describe("clocks", () => {
    it.each([
      ["ahead", 10 * 60_000],
      ["behind", -10 * 60_000],
    ])(
      "should judge due on the store clock while the application clock is %s",
      async (_case, skew) => {
        const { store, keycloak, refresher } = setup();
        await seed(store, { id: "fresh" });
        await seed(store, { id: "due", ...DUE });
        const real = Date.now.bind(Date);
        vi.spyOn(Date, "now").mockImplementation(() => real() + skew);

        await expect(refresher.refreshIfDue("fresh", ctx)).resolves.toMatchObject({
          refreshed: false,
        });
        await expect(refresher.refreshIfDue("due", ctx)).resolves.toMatchObject({
          refreshed: true,
        });
        expect(keycloak.refreshes).toBe(1);
      },
    );

    it("should not lengthen the deadlines when the wall clock steps back during the request", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, DUE);
      const before = store.now().getTime();
      keycloak.onRefresh = () => {
        const real = Date.now.bind(Date);
        vi.spyOn(Date, "now").mockImplementation(() => real() - 3_600_000);
      };

      await refresher.refreshIfDue("s1", ctx);
      const after = store.now().getTime();
      const deadline = defined(rowOf(store).refreshTokenExpiresAt).getTime();

      expect(deadline).toBeGreaterThanOrEqual(before + 1_800_000 - 1);
      expect(deadline).toBeLessThanOrEqual(after + 1_800_000);
    });

    // Keycloak built the response with one second of realm lifetime left,
    // and it was delivered after that second ran out.
    it("should end the session when the refresh lifetime is exhausted on arrival", async () => {
      const { store, keycloak, refresher } = setup({ requestTimeoutMs: 3000, leaseMs: 11000 });
      await seed(store, DUE);
      keycloak.nextRefresh = { delayMs: 1200, fields: { refresh_expires_in: 1 } };

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "ended",
        reason: "refresh_expired",
      });
      expect(store.session("s1")).toBeUndefined();
      expect(grantOf(store)).toBeUndefined();
      expect(names()).toEqual(["refresh.dispatched", "refresh.succeeded"]);
      expect(events()[1]).toMatchObject({ remainingSeconds: 0 });
    }, 10000);

    it("should store an exhausted access token and refresh it again on the next call", async () => {
      const { store, keycloak, refresher } = setup({ requestTimeoutMs: 3000, leaseMs: 11000 });
      await seed(store, DUE);
      keycloak.nextRefresh = { delayMs: 1200, fields: { expires_in: 1 } };

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({ refreshed: true });
      expect(defined(rowOf(store).accessTokenExpiresAt).getTime()).toBeLessThanOrEqual(
        store.now().getTime(),
      );
      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({ refreshed: true });
      expect(keycloak.refreshes).toBe(2);
    }, 10000);

    it("should never hand back an access token with no life left", async () => {
      const { store, keycloak, refresher } = setup({ requestTimeoutMs: 3000, leaseMs: 11000 });
      await seed(store, DUE);
      keycloak.onRefresh = () => {
        keycloak.nextRefresh = { delayMs: 1100, fields: { expires_in: 1 } };
      };
      keycloak.nextRefresh = { delayMs: 1100, fields: { expires_in: 1 } };

      await expect(refresher.resolveAccessToken("s1", ctx)).resolves.toEqual({
        kind: "unavailable",
        reason: "keycloak_unreachable",
      });
      expect(keycloak.refreshes).toBe(2);
    }, 10000);
  });

  describe("token validity at handoff", () => {
    it("should cap the usable token lifetime at the session deadline", async () => {
      const { store, refresher } = setup();
      await seed(store, { refreshMs: 120_000 });

      const outcome = await refresher.resolveAccessToken("s1", ctx);

      expect(outcome.kind).toBe("ok");
      expect(outcome.kind === "ok" && outcome.expiresInMs).toBeGreaterThan(119_000);
      expect(outcome.kind === "ok" && outcome.expiresInMs).toBeLessThanOrEqual(120_000);
    });

    it.each([false, true])(
      "should revalidate a session that expires during completion (ambiguous commit: %s)",
      async (lostCommit) => {
        const advance = clock();
        const { store, keycloak, refresher } = setup();
        await seed(store, DUE);
        keycloak.nextRefresh = { fields: { refresh_expires_in: 1 } };
        const complete = store.complete.bind(store);
        store.complete = async (input) => {
          const result = await complete(input);
          advance(2000);
          if (lostCommit) {
            throw new AmbiguousCommitError(new Error("Connection terminated"));
          }
          return result;
        };

        await expect(refresher.resolveAccessToken("s1", ctx)).resolves.toEqual({
          kind: "ended",
          reason: "refresh_expired",
        });
        expect(store.session("s1")).toBeUndefined();
        expect(keycloak.refreshes).toBe(1);
        expectOneTerminalPerDispatch();
      },
    );

    it.each([
      [
        "access",
        expect.objectContaining({ kind: "ok", accessToken: "access-refreshed-1" }),
        { kept: true, refreshes: 1 },
      ],
      ["session", { kind: "ended", reason: "refresh_expired" }, { kept: false, refreshes: 0 }],
    ] as const)(
      "should revalidate when the %s deadline passes during decryption",
      async (deadline, expected, { kept, refreshes }) => {
        const advance = clock();
        const { store, keycloak, refresher } = setup();
        await seed(store, {
          accessMs: deadline === "access" ? 1000 : 300_000,
          refreshMs: deadline === "session" ? 1000 : 1_800_000,
        });
        let delayed = false;
        const auth = { ...ctx };
        Object.defineProperty(auth, "secretConfig", {
          get() {
            if (!delayed) {
              delayed = true;
              advance(1500);
            }
            return ctx.secretConfig;
          },
        });

        const outcome = await refresher.resolveAccessToken("s1", auth);

        expect(outcome).toEqual(expected);
        expect(store.session("s1") !== undefined).toBe(kept);
        expect(keycloak.refreshes).toBe(refreshes);
      },
    );
  });

  describe("a token an upstream rejected", () => {
    const REJECTED = { rejectedAccessToken: "access-0", refreshBudget: 1 };

    it("should refresh a grant that still holds it, though it is not due", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store);

      const outcome = await refresher.resolveAccessToken("s1", ctx, REJECTED);

      expect(outcome).toMatchObject({
        kind: "ok",
        accessToken: "access-refreshed-1",
        refreshed: true,
      });
      expect(keycloak.refreshes).toBe(1);
      expect(names()).toEqual(["refresh.forced", "refresh.dispatched", "refresh.succeeded"]);
      const [forced, dispatched] = events();
      expect(forced).toMatchObject({ sessionId: "s1", cause: "upstream_rejected" });
      expect(defined(forced).leaseHolder).toBe(defined(dispatched).leaseHolder);
      expect(grantOf(store)).toMatchObject({ leaseHolder: null, dispatched: false });
      expect(await decrypt(rowOf(store).accessToken)).toBe("access-refreshed-1");
      expectOneTerminalPerDispatch();
    });

    it("should hand back a replacement another caller stored, without calling Keycloak", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store);

      const outcome = await refresher.resolveAccessToken("s1", ctx, {
        rejectedAccessToken: "access-before",
        refreshBudget: 1,
      });

      expect(outcome).toMatchObject({ kind: "ok", accessToken: "access-0", refreshed: false });
      expect(keycloak.refreshes).toBe(0);
      expect(names()).toEqual([]);
    });

    it.each([
      ["due", DUE],
      ["expired", { accessMs: -1000, issuedMs: 301_000 }],
    ])(
      "should refresh a replacement that is %s once, through the normal claim",
      async (_, timing) => {
        const { store, keycloak, refresher } = setup();
        await seed(store, timing);

        const outcome = await refresher.resolveAccessToken("s1", ctx, {
          rejectedAccessToken: "access-before",
          refreshBudget: 1,
        });

        expect(outcome).toMatchObject({
          kind: "ok",
          accessToken: "access-refreshed-1",
          refreshed: true,
        });
        expect(keycloak.refreshes).toBe(1);
        expect(names()).toEqual(["refresh.dispatched", "refresh.succeeded"]);
      },
    );

    it("should wait on a live lease and use the token its holder stored", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, lease(store, 5000, "other#1#x", true));
      const replacement = await encryptToken("access-9", ctx);
      setTimeout(() => {
        Object.assign(rowOf(store), {
          accessToken: replacement,
          leaseHolder: null,
          leaseExpiresAt: null,
          dispatched: false,
          version: rowOf(store).version + 1,
          updatedAt: store.now(),
        });
      }, 100);

      const outcome = await refresher.resolveAccessToken("s1", ctx, REJECTED);

      expect(outcome).toMatchObject({ kind: "ok", accessToken: "access-9", refreshed: false });
      expect(keycloak.refreshes).toBe(0);
      expect(names()).toEqual(["refresh.waited"]);
    });

    it("should give up on a live lease after the wait bound, leaving the session intact", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, lease(store, 5000, "other#1#x", true));

      await expect(refresher.resolveAccessToken("s1", ctx, REJECTED)).resolves.toEqual({
        kind: "unavailable",
        reason: "refresh_in_progress",
      });
      expect(keycloak.refreshes).toBe(0);
      expect(store.session("s1")).toBeDefined();
    });

    it("should end the session on invalid_grant", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store);
      keycloak.nextRefresh = { invalidGrant: true };

      await expect(refresher.resolveAccessToken("s1", ctx, REJECTED)).resolves.toEqual({
        kind: "ended",
        reason: "invalid_grant",
      });
      expect(store.session("s1")).toBeUndefined();
      expect(names()).toEqual(["refresh.forced", "refresh.dispatched", "refresh.invalid_grant"]);
    });

    it("should release the lease and keep the session when the request was never sent", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store);
      keycloak.nextRefresh = { connectFail: "ECONNREFUSED" };

      await expect(refresher.resolveAccessToken("s1", ctx, REJECTED)).resolves.toEqual({
        kind: "unavailable",
        reason: "keycloak_unreachable",
      });
      expect(keycloak.refreshes).toBe(0);
      expect(grantOf(store)).toMatchObject({ leaseHolder: null, dispatched: false });
      expect(await decrypt(rowOf(store).accessToken)).toBe("access-0");
      expect(names()).toEqual(["refresh.forced", "refresh.unsent"]);
    });

    it("should end the session with the reason when the outcome is unknown", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store);
      keycloak.nextRefresh = { sentFail: "ECONNRESET" };

      await expect(refresher.resolveAccessToken("s1", ctx, REJECTED)).resolves.toEqual({
        kind: "ended",
        reason: "refresh_indeterminate",
      });
      expect(store.session("s1")).toBeUndefined();
    });
  });

  describe("the refresh budget", () => {
    // The default budget's two requests are pinned by 'should never hand
    // back an access token with no life left' above.
    it("should make one request with a budget of one when the result has no life left", async () => {
      const { store, keycloak, refresher } = setup({ requestTimeoutMs: 3000, leaseMs: 11000 });
      await seed(store, DUE);
      expiredOnArrival(keycloak);

      await expect(refresher.resolveAccessToken("s1", ctx, { refreshBudget: 1 })).resolves.toEqual({
        kind: "unavailable",
        reason: "keycloak_unreachable",
      });
      expect(keycloak.refreshes).toBe(1);
      expect(grantOf(store)).toMatchObject({ leaseHolder: null, dispatched: false });
    }, 10000);

    it("should make one request for a forced refresh whose result has no life left", async () => {
      const { store, keycloak, refresher } = setup({ requestTimeoutMs: 3000, leaseMs: 11000 });
      await seed(store);
      expiredOnArrival(keycloak);

      await expect(
        refresher.resolveAccessToken("s1", ctx, {
          rejectedAccessToken: "access-0",
          refreshBudget: 1,
        }),
      ).resolves.toEqual({ kind: "unavailable", reason: "keycloak_unreachable" });
      expect(keycloak.refreshes).toBe(1);
    }, 10000);

    it("should never claim with no budget, but still revalidate the row", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, { id: "due", ...DUE });
      await seed(store, { id: "fresh" });
      await seed(store, { id: "expired", refreshMs: -1000 });

      await expect(refresher.resolveAccessToken("due", ctx, { refreshBudget: 0 })).resolves.toEqual(
        { kind: "unavailable", reason: "keycloak_unreachable" },
      );
      await expect(
        refresher.resolveAccessToken("fresh", ctx, { refreshBudget: 0 }),
      ).resolves.toMatchObject({ kind: "ok", accessToken: "access-0" });
      await expect(
        refresher.resolveAccessToken("expired", ctx, { refreshBudget: 0 }),
      ).resolves.toEqual({ kind: "ended", reason: "refresh_expired" });
      await expect(
        refresher.resolveAccessToken("missing", ctx, { refreshBudget: 0 }),
      ).resolves.toEqual({ kind: "ended", reason: "no_grant" });
      expect(keycloak.refreshes).toBe(0);
      expect(grantOf(store, "due")).toMatchObject({ leaseHolder: null });
    });

    describe("spent between the two attempts", () => {
      it("should still end a session whose refresh deadline passed", async () => {
        const advance = clock();
        const { store, keycloak, refresher } = setup();
        await seed(store);
        keycloak.nextRefresh = { fields: { expires_in: 1, refresh_expires_in: 1 } };
        const complete = store.complete.bind(store);
        store.complete = async (input) => {
          const result = await complete(input);
          advance(2000);
          return result;
        };

        await expect(
          refresher.resolveAccessToken("s1", ctx, {
            rejectedAccessToken: "access-0",
            refreshBudget: 1,
          }),
        ).resolves.toEqual({ kind: "ended", reason: "refresh_expired" });
        expect(keycloak.refreshes).toBe(1);
        expect(store.session("s1")).toBeUndefined();
      });

      it("should still end a session whose row vanished", async () => {
        const advance = clock();
        const { store, keycloak, refresher } = setup();
        await seed(store);
        keycloak.nextRefresh = { fields: { expires_in: 1 } };
        const complete = store.complete.bind(store);
        store.complete = async (input) => {
          const result = await complete(input);
          advance(2000);
          await store.endSession("s1");
          return result;
        };

        await expect(
          refresher.resolveAccessToken("s1", ctx, {
            rejectedAccessToken: "access-0",
            refreshBudget: 1,
          }),
        ).resolves.toMatchObject({ kind: "ended" });
        expect(keycloak.refreshes).toBe(1);
        expect(store.session("s1")).toBeUndefined();
      });
    });
  });

  describe("the database", () => {
    it("should release without sending when the mark is acknowledged too late", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, DUE);
      const mark = store.markDispatched.bind(store);
      store.markDispatched = async (...args) => {
        const version = await mark(...args);
        await sleep(1100);
        return version;
      };

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "unavailable",
        reason: "database",
      });
      expect(keycloak.refreshes).toBe(0);
      expect(grantOf(store)).toMatchObject({ leaseHolder: null, dispatched: false });
      expect(events()).toEqual([
        expect.objectContaining({ event: "refresh.unsent", cause: "mark_latency" }),
      ]);
    });

    it("should answer unavailable(database) and log no row detail on a Postgres error", async () => {
      const { store, refresher } = setup();
      await seed(store, DUE);
      store.claim = async () => {
        throw Object.assign(new Error("connection lost"), {
          code: "08006",
          detail: "row (access-0)",
        });
      };

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "unavailable",
        reason: "database",
      });
      expect(events()).toEqual([
        expect.objectContaining({
          event: "refresh.error",
          code: "08006",
          error: "connection lost",
        }),
      ]);
      expect(JSON.stringify(logger.error.mock.calls)).not.toContain("row (access-0)");
    });

    it("should answer unavailable(database) when a read never settles", async () => {
      const { store, refresher } = setup({ waitMs: 100, leaseMs: 8200 });
      await seed(store, DUE);
      store.read = async () => new Promise(() => undefined);
      const start = performance.now();

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "unavailable",
        reason: "database",
      });
      // The wait plus one pool wait and one statement.
      expect(performance.now() - start).toBeLessThan(100 + 4000 + 300);
    }, 10000);

    it("should end its own attempt with the reason when the completion runs out of budget", async () => {
      const { store, keycloak, refresher } = setup();
      await seed(store, DUE);
      store.complete = async () => {
        throw new CompletionBudgetError();
      };

      await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
        kind: "ended",
        reason: "refresh_indeterminate",
      });
      expect(keycloak.refreshes).toBe(1);
      expect(names()).toEqual(["refresh.dispatched", "refresh.indeterminate"]);
      expect(events()[1]).toMatchObject({ by: "holder", cause: "completion_budget" });
    });

    describe("an ambiguous commit", () => {
      it("should answer ok when the commit landed", async () => {
        const { store, refresher } = setup();
        await seed(store, DUE);
        const complete = store.complete.bind(store);
        ambiguous(store, complete);

        await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({
          kind: "ok",
          refreshed: true,
        });
        await expect(decrypt(rowOf(store).refreshToken)).resolves.toBe("refresh-refreshed-1");
        expect(names()).toEqual(["refresh.dispatched", "refresh.succeeded"]);
      });

      it("should end its own attempt with the reason when the commit never landed", async () => {
        const { store, refresher } = setup();
        await seed(store, DUE);
        ambiguous(store, async () => undefined);

        await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
          kind: "ended",
          reason: "refresh_indeterminate",
        });
        expect(events()[1]).toMatchObject({
          event: "refresh.indeterminate",
          cause: "ambiguous_commit",
        });
      });

      it("should answer ok when the commit lands between the re-read and the termination", async () => {
        const { store, refresher } = setup();
        await seed(store, DUE);
        const complete = store.complete.bind(store);
        let landing: CompleteInput;
        ambiguous(store, async (input) => {
          landing = input;
        });
        const endIf = store.endIf.bind(store);
        store.endIf = async (...args) => {
          await complete(landing);
          return endIf(...args);
        };

        await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({
          kind: "ok",
          refreshed: true,
        });
        expect(store.session("s1")).toBeDefined();
        expect(names()).toEqual(["refresh.dispatched", "refresh.succeeded"]);
      });

      it("should answer plain when a successor ended the session meanwhile", async () => {
        const { store, refresher } = setup();
        await seed(store, DUE);
        ambiguous(store, async () => store.endSession("s1"));

        await expect(refresher.refreshIfDue("s1", ctx)).resolves.toEqual({
          kind: "ended",
          reason: "ended_elsewhere",
        });
        expect(names()).toEqual(["refresh.dispatched", "refresh.lease_lost"]);
      });
    });

    // A commit and the log line that reports it are two steps.
    describe("a crash window", () => {
      it("after the mark committed leaves only the successor’s indeterminate", async () => {
        const { store, keycloak, make } = setup();
        await seed(store, DUE);
        const mark = store.markDispatched.bind(store);
        store.markDispatched = async (...args) => {
          await mark(...args);
          store.markDispatched = mark;
          throw new Error("process died");
        };

        await expect(make().refreshIfDue("s1", ctx)).resolves.toMatchObject({ reason: "database" });
        store.advance(SETTINGS.leaseMs + 1);
        await expect(make().refreshIfDue("s1", ctx)).resolves.toEqual({
          kind: "ended",
          reason: "refresh_indeterminate",
        });
        expect(keycloak.refreshes).toBe(0);
        expect(names()).toEqual(["refresh.error", "refresh.indeterminate"]);
      });

      it("after the completion committed leaves a dispatched attempt with no terminal event", async () => {
        const { store, refresher } = setup();
        await seed(store, DUE);
        const complete = store.complete.bind(store);
        store.complete = async (input) => {
          await complete(input);
          throw new Error("process died");
        };

        await expect(refresher.refreshIfDue("s1", ctx)).resolves.toMatchObject({
          reason: "database",
        });
        expect(names()).toEqual(["refresh.dispatched", "refresh.error"]);
        await expect(decrypt(rowOf(store).refreshToken)).resolves.toBe("refresh-refreshed-1");
      });
    });
  });
});

describe("refreshResponse", () => {
  it("should give the reason only to the response that ended the session at step 6", () => {
    expect(refreshResponse({ kind: "ended", reason: "refresh_indeterminate" })).toEqual({
      status: SESSION_INVALID.status,
      body: {
        code: SESSION_INVALID.code,
        message: SESSION_INVALID.message,
        reason: "refresh_indeterminate",
      },
    });
    for (const reason of [
      "no_grant",
      "ended_elsewhere",
      "refresh_expired",
      "invalid_grant",
    ] as const) {
      expect(refreshResponse({ kind: "ended", reason })).toEqual({
        status: 401,
        body: { code: SESSION_INVALID.code, message: SESSION_INVALID.message },
      });
    }
  });

  it.each(["refresh_in_progress", "keycloak_unreachable", "database"] as const)(
    "should answer %s as a dependency failure, not a 401",
    (reason) => {
      expect(refreshResponse({ kind: "unavailable", reason })).toEqual({
        status: DEPENDENCY_FAILURE.status,
        body: { code: DEPENDENCY_FAILURE.code, message: DEPENDENCY_FAILURE.message, reason },
      });
    },
  );
});
